// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM Certificate Chain Handling
//!
//! This module implements parsing and validation of SPDM certificate chains
//! according to DSP0274 specification.
//!
//! # SPDM Certificate Chain Format
//!
//! The SPDM certificate chain has a specific header format followed by certificates:
//!
//! ```text
//! struct spdm_cert_chain_t {
//!     uint16_t length;              // Total length in bytes
//!     uint16_t reserved;            // Must be 0
//!     uint8_t root_hash[hash_size]; // Hash of root certificate
//!     uint8_t certificates[];       // Concatenated DER certificates
//! }
//! ```
//!
//! # References
//! - DSP0274 Section 10.6.1 - Certificate Chain Format

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use crate::certificate::Certificate;
use crate::error::{ChainError, Error, Result};
use crate::validator::{CertificateChain, ValidationOptions, Validator};

use super::algorithm_verification::SpdmBaseHashAlgo;
use super::validator::{SpdmCertificateRole, SpdmValidator};

// =============================================================================
// SPDM Certificate Chain Header
// =============================================================================

/// SPDM Certificate Chain Header (DSP0274 Section 10.6.1)
///
/// This header precedes the certificate chain in SPDM messages.
/// It includes the total length and a hash of the root certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmCertChainHeader {
    /// Total length of the certificate chain (including this header)
    pub length: u16,

    /// Reserved field (must be 0)
    pub reserved: u16,

    /// Hash of the root certificate
    /// The size depends on the negotiated hash algorithm:
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    /// - SHA3-256: 32 bytes
    /// - SHA3-384: 48 bytes
    /// - SHA3-512: 64 bytes
    pub root_hash: Vec<u8>,
}

impl SpdmCertChainHeader {
    /// Minimum header size (without root hash)
    pub const MIN_SIZE: usize = 4;

    /// Create a new SPDM certificate chain header
    ///
    /// # Arguments
    /// * `length` - Total length of the certificate chain in bytes (including header)
    /// * `root_hash` - Hash of the root certificate using negotiated hash algorithm
    ///
    /// # Example
    /// ```ignore
    /// let root_hash = vec![0u8; 32]; // SHA-256 hash
    /// let header = SpdmCertChainHeader::new(500, root_hash);
    /// assert_eq!(header.length, 500);
    /// ```
    pub fn new(length: u16, root_hash: Vec<u8>) -> Self {
        Self {
            length,
            reserved: 0,
            root_hash,
        }
    }

    /// Parse an SPDM certificate chain header from bytes
    ///
    /// # Arguments
    /// - `data`: The raw header bytes
    /// - `hash_size`: Expected size of the root hash (based on negotiated algorithm)
    ///
    /// # Returns
    /// - `Ok((header, remaining_bytes))` on success
    /// - `Err(Error)` if parsing fails
    pub fn from_bytes(data: &[u8], hash_size: usize) -> Result<(Self, &[u8])> {
        let expected_header_size = Self::MIN_SIZE + hash_size;

        if data.len() < expected_header_size {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::format!(
                    "Certificate chain too short: expected at least {} bytes, got {}",
                    expected_header_size,
                    data.len()
                ),
            )));
        }

        // Parse length (little-endian)
        let length = u16::from_le_bytes([data[0], data[1]]);

        // Parse reserved field (must be 0)
        let reserved = u16::from_le_bytes([data[2], data[3]]);
        if reserved != 0 {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::format!("Reserved field must be 0, got {}", reserved),
            )));
        }

        // Extract root hash
        let root_hash = data[4..4 + hash_size].to_vec();

        // Remaining bytes are the certificates
        let remaining = &data[expected_header_size..];

        Ok((
            Self {
                length,
                reserved,
                root_hash,
            },
            remaining,
        ))
    }

    /// Serialize the header to bytes
    ///
    /// # Returns
    /// A vector containing the serialized header in little-endian format:
    /// - Bytes 0-1: length (u16, little-endian)
    /// - Bytes 2-3: reserved (u16, always 0)
    /// - Remaining bytes: root hash
    ///
    /// # Example
    /// ```ignore
    /// let header = SpdmCertChainHeader::new(100, vec![0u8; 32]);
    /// let bytes = header.to_bytes();
    /// assert_eq!(bytes.len(), 36); // 4 + 32
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.reserved.to_le_bytes());
        bytes.extend_from_slice(&self.root_hash);
        bytes
    }

    /// Get the expected hash size for a given hash algorithm
    ///
    /// # Arguments
    /// * `algo` - The SPDM hash algorithm
    ///
    /// # Returns
    /// The hash size in bytes:
    /// - SHA-256/SHA3-256/SM3-256: 32 bytes
    /// - SHA-384/SHA3-384: 48 bytes
    /// - SHA-512/SHA3-512: 64 bytes
    ///
    /// # Example
    /// ```ignore
    /// use spdm_x509::spdm::{SpdmCertChainHeader, SpdmBaseHashAlgo};
    /// assert_eq!(SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256), 32);
    /// ```
    pub fn hash_size_for_algo(algo: SpdmBaseHashAlgo) -> usize {
        match algo {
            SpdmBaseHashAlgo::Sha256 | SpdmBaseHashAlgo::Sha3_256 | SpdmBaseHashAlgo::Sm3_256 => 32,
            SpdmBaseHashAlgo::Sha384 | SpdmBaseHashAlgo::Sha3_384 => 48,
            SpdmBaseHashAlgo::Sha512 | SpdmBaseHashAlgo::Sha3_512 => 64,
        }
    }
}

impl fmt::Display for SpdmCertChainHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SpdmCertChainHeader {{ length: {}, root_hash: {} bytes }}",
            self.length,
            self.root_hash.len()
        )
    }
}

// =============================================================================
// Certificate Chain Parsing
// =============================================================================

/// Parse an SPDM certificate chain from raw bytes
///
/// # Arguments
/// - `data`: The raw certificate chain data (including header)
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok((header, certificates))` containing the parsed header and certificate list
/// - `Err(Error)` if parsing fails
///
/// # Example
/// ```ignore
/// use spdm_x509::spdm::chain::{parse_spdm_cert_chain, SpdmBaseHashAlgo};
///
/// let chain_data = include_bytes!("spdm_chain.bin");
/// let base_hash_algo = 1 << 0; // SHA-256
/// let (header, certs) = parse_spdm_cert_chain(chain_data, base_hash_algo)?;
/// println!("Chain has {} certificates", certs.len());
/// ```
pub fn parse_spdm_cert_chain(
    data: &[u8],
    base_hash_algo: u32,
) -> Result<(SpdmCertChainHeader, Vec<Certificate>)> {
    // Determine the hash size from the negotiated algorithm
    // We use the first algorithm from the bitfield
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    if hash_algos.is_empty() {
        return Err(Error::ValidationError(alloc::string::String::from(
            "No hash algorithm negotiated",
        )));
    }

    let hash_size = SpdmCertChainHeader::hash_size_for_algo(hash_algos[0]);

    // Parse the header
    let (header, cert_data) = SpdmCertChainHeader::from_bytes(data, hash_size)?;

    // Verify the length field matches the actual data
    if (header.length as usize) != data.len() {
        return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
            alloc::format!(
                "Chain length mismatch: header says {}, actual {}",
                header.length,
                data.len()
            ),
        )));
    }

    // Parse concatenated certificates
    let certificates = parse_concatenated_certificates(cert_data)?;

    if certificates.is_empty() {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    Ok((header, certificates))
}

/// Parse concatenated DER-encoded certificates
///
/// Certificates in an SPDM chain are concatenated without delimiters.
/// Each certificate is a DER SEQUENCE, so we can parse them sequentially.
fn parse_concatenated_certificates(mut data: &[u8]) -> Result<Vec<Certificate>> {
    let mut certificates = Vec::new();

    while !data.is_empty() {
        // Try to decode a certificate
        // We need to find the end of the DER-encoded certificate
        let cert = Certificate::from_der(data).map_err(|e| {
            Error::ParseError(crate::error::ParseError::InvalidDer(alloc::format!(
                "Failed to parse certificate in chain: {:?}",
                e
            )))
        })?;

        // Calculate how many bytes the certificate consumed
        let cert_der = cert.to_der().map_err(|e| {
            Error::ParseError(crate::error::ParseError::InvalidDer(alloc::format!(
                "Failed to re-encode certificate: {:?}",
                e
            )))
        })?;

        // Advance the data pointer
        if cert_der.len() > data.len() {
            return Err(Error::ParseError(crate::error::ParseError::InvalidDer(
                alloc::string::String::from("Certificate DER length exceeds remaining data"),
            )));
        }
        data = &data[cert_der.len()..];

        certificates.push(cert);
    }

    Ok(certificates)
}

// =============================================================================
// Certificate Chain Validation
// =============================================================================

/// Validate an SPDM certificate chain with SPDM-specific rules
///
/// This performs standard X.509 chain validation plus SPDM-specific checks:
/// - Verifies the root certificate hash matches the header
/// - Validates all certificates in the chain
/// - Ensures proper certificate ordering (root -> intermediate -> leaf)
///
/// # Arguments
/// - `header`: The parsed SPDM certificate chain header
/// - `certificates`: The list of certificates in the chain
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
/// - `options`: Validation options
///
/// # Returns
/// - `Ok(())` if validation succeeds
/// - `Err(Error)` if validation fails
pub fn validate_spdm_cert_chain(
    header: &SpdmCertChainHeader,
    certificates: &[Certificate],
    base_hash_algo: u32,
    options: &ValidationOptions,
) -> Result<()> {
    if certificates.is_empty() {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    // Verify the root certificate hash
    verify_root_cert_hash(&certificates[0], &header.root_hash, base_hash_algo)?;

    // Create a CertificateChain for standard validation
    let chain = CertificateChain::new(certificates.to_vec());

    // Perform standard X.509 chain validation
    let validator = Validator::new();
    validator.validate_chain(&chain, options)?;

    Ok(())
}

/// Verify that the hash of the root certificate matches the header
fn verify_root_cert_hash(
    root_cert: &Certificate,
    expected_hash: &[u8],
    base_hash_algo: u32,
) -> Result<()> {
    // Get the DER encoding of the root certificate
    let root_der = root_cert.to_der().map_err(|e| {
        Error::ParseError(crate::error::ParseError::InvalidDer(alloc::format!(
            "Failed to encode root certificate: {:?}",
            e
        )))
    })?;

    // Compute the hash using the negotiated algorithm
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    if hash_algos.is_empty() {
        return Err(Error::ValidationError(alloc::string::String::from(
            "No hash algorithm negotiated",
        )));
    }

    let computed_hash = compute_hash(&root_der, hash_algos[0])?;

    // Compare the hashes
    if computed_hash != expected_hash {
        return Err(Error::ValidationError(alloc::string::String::from(
            "Root certificate hash mismatch",
        )));
    }

    Ok(())
}

/// Compute hash of data using the specified SPDM hash algorithm
#[cfg_attr(not(feature = "std"), allow(unused_variables))]
fn compute_hash(data: &[u8], algo: SpdmBaseHashAlgo) -> Result<Vec<u8>> {
    // Note: In a real implementation, this would use a crypto library
    // For now, we'll use ring's digest functions

    #[cfg(feature = "std")]
    {
        use ring::digest;

        let algorithm = match algo {
            SpdmBaseHashAlgo::Sha256 => &digest::SHA256,
            SpdmBaseHashAlgo::Sha384 => &digest::SHA384,
            SpdmBaseHashAlgo::Sha512 => &digest::SHA512,
            _ => {
                return Err(Error::AlgorithmError(
                    crate::error::AlgorithmError::Unsupported(alloc::format!(
                        "Hash algorithm not supported: {:?}",
                        algo
                    )),
                ));
            }
        };

        let hash = digest::digest(algorithm, data);
        Ok(hash.as_ref().to_vec())
    }

    #[cfg(not(feature = "std"))]
    {
        // In no_std mode, we can't use ring directly
        // This would need to be implemented using a no_std crypto library
        Err(Error::AlgorithmError(
            crate::error::AlgorithmError::Unsupported(alloc::string::String::from(
                "Hash computation not available in no_std mode",
            )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdm_cert_chain_header_size() {
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256),
            32
        );
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha384),
            48
        );
        assert_eq!(
            SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha512),
            64
        );
    }

    #[test]
    fn test_header_serialization() {
        let header = SpdmCertChainHeader::new(100, vec![0u8; 32]);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 4 + 32);
        assert_eq!(bytes[0], 100);
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], 0); // reserved
        assert_eq!(bytes[3], 0); // reserved
    }

    #[test]
    fn test_header_parsing() {
        let mut data = vec![0u8; 36]; // 4 byte header + 32 byte hash
        data[0] = 36; // length low byte
        data[1] = 0; // length high byte
        data[2] = 0; // reserved low byte
        data[3] = 0; // reserved high byte
                     // Hash bytes are all zeros

        let (header, remaining) = SpdmCertChainHeader::from_bytes(&data, 32).unwrap();

        assert_eq!(header.length, 36);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.root_hash.len(), 32);
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_header_parsing_invalid_reserved() {
        let mut data = vec![0u8; 36];
        data[0] = 36;
        data[2] = 1; // reserved should be 0

        let result = SpdmCertChainHeader::from_bytes(&data, 32);
        assert!(result.is_err());
    }
}

// =============================================================================
// spdmlib-compatible Functions (for spdm-rs integration)
// =============================================================================

/// Gets a certificate from a DER certificate chain by index
///
/// This function is **directly compatible** with spdmlib interface.
/// It parses concatenated DER certificates and returns byte offsets
/// for the requested certificate.
///
/// # Arguments
/// * `cert_chain` - Buffer containing concatenated DER certificates
/// * `index` - Certificate index (0=first, -1=last/leaf)
///
/// # Returns
/// * `Ok((start_offset, end_offset))` - Byte offsets of the certificate
/// * `Err` - If certificate doesn't exist or format is invalid
///
/// # Format
/// Each DER certificate starts with:
/// - Tag: 0x30 (SEQUENCE)
/// - Length: Variable encoding (0x81, 0x82 for long form)
/// - Content: Certificate data
///
/// # Example
/// ```ignore
/// // Get the leaf certificate (last in chain)
/// let (offset, end) = get_cert_from_cert_chain(cert_chain, -1)?;
/// let leaf_cert_der = &cert_chain[offset..end];
///
/// // Get first certificate
/// let (offset, end) = get_cert_from_cert_chain(cert_chain, 0)?;
/// let first_cert_der = &cert_chain[offset..end];
/// ```
pub fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> Result<(usize, usize)> {
    let mut offset = 0usize;
    let mut cert_index = 0isize;
    let chain_size = cert_chain.len();

    // Handle empty chain
    if chain_size < 4 {
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    loop {
        // Need at least 4 bytes for tag + length header
        if offset + 4 > chain_size {
            break;
        }

        // Check DER SEQUENCE tag (0x30)
        if cert_chain[offset] != 0x30 {
            return Err(Error::ValidationError(alloc::format!(
                "Invalid DER tag at offset {}: expected 0x30, got 0x{:02x}",
                offset,
                cert_chain[offset]
            )));
        }

        // Parse DER length encoding
        let cert_len = if cert_chain[offset + 1] == 0x82 {
            // Long form: 2 bytes for length
            if offset + 4 > chain_size {
                return Err(Error::ValidationError(
                    "Certificate chain truncated in length field".into(),
                ));
            }
            let len = ((cert_chain[offset + 2] as usize) << 8) | (cert_chain[offset + 3] as usize);
            len + 4 // Include tag + length encoding
        } else if cert_chain[offset + 1] == 0x81 {
            // Long form: 1 byte for length
            if offset + 3 > chain_size {
                return Err(Error::ValidationError(
                    "Certificate chain truncated in length field".into(),
                ));
            }
            let len = cert_chain[offset + 2] as usize;
            len + 3
        } else if cert_chain[offset + 1] & 0x80 == 0 {
            // Short form
            (cert_chain[offset + 1] as usize) + 2
        } else {
            return Err(Error::ValidationError(alloc::format!(
                "Unsupported DER length encoding: 0x{:02x}",
                cert_chain[offset + 1]
            )));
        };

        // Validate length
        if offset + cert_len > chain_size {
            return Err(Error::ValidationError(alloc::format!(
                "Certificate length {} exceeds chain size at offset {}",
                cert_len,
                offset
            )));
        }

        // Check if this is the requested certificate
        if cert_index == index {
            return Ok((offset, offset + cert_len));
        }

        // Check for last certificate (index == -1)
        if (offset + cert_len == chain_size) && (index == -1) {
            return Ok((offset, offset + cert_len));
        }

        // Move to next certificate
        cert_index += 1;
        offset += cert_len;

        // Safety check
        if cert_index > 100 {
            return Err(Error::ValidationError(
                "Certificate chain too long (>100 certificates)".into(),
            ));
        }
    }

    Err(Error::ValidationError(alloc::format!(
        "Certificate index {} not found in chain",
        index
    )))
}

/// Validates a DER certificate chain according to DSP0274
///
/// This function is **directly compatible** with spdmlib interface.
/// It parses and validates a concatenated DER certificate chain.
///
/// # Arguments
/// * `cert_chain` - Buffer containing concatenated DER certificates
///
/// # Returns
/// * `Ok(())` - If validation succeeds
/// * `Err` - If validation fails
///
/// # Validation Steps
/// 1. Parse individual certificates from the chain
/// 2. Build a CertificateChain structure
/// 3. Validate using standard X.509 validator
/// 4. Check signatures, validity periods, and extensions
///
/// # Example
/// ```ignore
/// let cert_chain = /* concatenated DER certificates */;
/// verify_cert_chain(cert_chain)?;
/// ```
pub fn verify_cert_chain(cert_chain: &[u8]) -> Result<()> {
    log::trace!("verify_cert_chain: chain_len={}", cert_chain.len());

    // Parse all certificates from the chain
    let mut certificates = Vec::new();
    let mut cert_index = 0isize;

    loop {
        match get_cert_from_cert_chain(cert_chain, cert_index) {
            Ok((start, end)) => {
                log::trace!(
                    "verify_cert_chain: parsed cert {} at [{}, {})",
                    cert_index,
                    start,
                    end
                );
                let cert_der = &cert_chain[start..end];
                let cert = Certificate::from_der(cert_der)?;
                log::trace!(
                    "verify_cert_chain: cert {} subject={:?}",
                    cert_index,
                    cert.tbs_certificate.subject
                );
                log::trace!(
                    "verify_cert_chain: cert {} issuer={:?}",
                    cert_index,
                    cert.tbs_certificate.issuer
                );
                certificates.push(cert);
                cert_index += 1;
            }
            Err(e) => {
                log::trace!(
                    "verify_cert_chain: no more certs at index {} (error: {:?})",
                    cert_index,
                    e
                );
                break;
            }
        }

        if cert_index > 100 {
            log::error!("verify_cert_chain: chain too long (>100)");
            return Err(Error::ValidationError(
                "Certificate chain too long (>100 certificates)".into(),
            ));
        }
    }

    if certificates.is_empty() {
        log::error!("verify_cert_chain: empty chain");
        return Err(Error::ChainError(ChainError::EmptyChain));
    }

    log::trace!(
        "verify_cert_chain: parsed {} certificates, building chain",
        certificates.len()
    );

    // IMPORTANT: SPDM certificate chains are ordered root -> intermediate -> leaf
    // but the X.509 validator expects leaf -> intermediate -> root
    // So we must reverse the chain before validation
    certificates.reverse();
    log::trace!("verify_cert_chain: reversed chain for validation (leaf -> root)");

    // Build certificate chain
    let chain = CertificateChain::new(certificates);

    // Use SPDM validator with EKU validation (matching webpki behavior)
    // The leaf certificate in SPDM is the responder certificate
    let spdm_validator = SpdmValidator::new();

    // In no_std environment, skip time validation (no system clock available)
    #[cfg(not(feature = "std"))]
    let options = ValidationOptions::default().skip_time_validation();

    #[cfg(feature = "std")]
    let options = ValidationOptions::default();

    log::trace!("verify_cert_chain: validating chain with standard X.509 validator");

    // First, perform standard X.509 chain validation
    let validator = Validator::new();
    validator.validate_chain(&chain, &options)?;

    log::trace!("verify_cert_chain: validating leaf certificate EKU (Responder role)");

    // Then, validate SPDM EKU on the leaf certificate (first in reversed chain)
    // The leaf certificate is a Responder certificate in SPDM protocol
    if !chain.is_empty() {
        match spdm_validator
            .validate_spdm_eku(&chain.certificates[0], SpdmCertificateRole::Responder)
        {
            Ok(_) => {
                log::trace!("verify_cert_chain: SPDM EKU validation successful");
            }
            Err(e) => {
                log::error!("verify_cert_chain: SPDM EKU validation failed: {:?}", e);
                return Err(e);
            }
        }
    }

    log::trace!("verify_cert_chain: validation successful");
    Ok(())
}
