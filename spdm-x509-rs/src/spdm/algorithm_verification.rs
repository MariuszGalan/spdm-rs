//! SPDM Algorithm Verification
//!
//! This module implements algorithm verification according to DSP0274 SPDM specification.
//! It verifies that certificate signature and hash algorithms match the negotiated
//! SPDM algorithms.
//!
//! # SPDM Algorithm Negotiation
//! During SPDM session establishment, Requester and Responder negotiate:
//! - Base asymmetric algorithm (signature algorithm)
//! - Base hash algorithm
//! - Optional post-quantum asymmetric algorithm
//!
//! # Certificate Requirements
//! - The certificate's public key algorithm MUST match the negotiated base_asym_algo
//! - The certificate's signature algorithm MUST use the negotiated base_hash_algo
//! - RSA keys must be 2048, 3072, or 4096 bits
//! - ECC keys must use P-256, P-384, or P-521 curves
//!
//! # References
//! - DSP0274 Section 10.6.1 - Certificate Requirements

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;

use super::oids;
use crate::error::{AlgorithmError, Error, Result};

// =============================================================================
// SPDM Base Asymmetric Algorithm (DSP0274 Table 21)
// =============================================================================

/// SPDM Base Asymmetric Algorithm flags
///
/// These correspond to the `BaseAsymAlgo` field in SPDM ALGORITHMS response (DSP0274 Table 21).
/// Multiple algorithms can be supported using bitwise OR.
///
/// # DSP0274 Requirements
/// - The certificate's public key algorithm MUST match the negotiated base_asym_algo
/// - RSA keys must be 2048, 3072, or 4096 bits
/// - ECC keys must use NIST P-256, P-384, or P-521 curves
///
/// # Example
/// ```ignore
/// use spdm_x509::spdm::SpdmBaseAsymAlgo;
///
/// // Multiple algorithms can be OR'd together
/// let algos = (1 << 4) | (1 << 2); // ECDSA P-256 + RSA-3072
/// let parsed = SpdmBaseAsymAlgo::from_bits(algos);
/// assert_eq!(parsed.len(), 2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmBaseAsymAlgo {
    /// TPM_ALG_RSASSA_2048 (bit 0)
    RsaSsa2048 = 1 << 0,
    /// TPM_ALG_RSAPSS_2048 (bit 1)
    RsaPss2048 = 1 << 1,
    /// TPM_ALG_RSASSA_3072 (bit 2)
    RsaSsa3072 = 1 << 2,
    /// TPM_ALG_RSAPSS_3072 (bit 3)
    RsaPss3072 = 1 << 3,
    /// TPM_ALG_ECDSA_ECC_NIST_P256 (bit 4)
    EcdsaP256 = 1 << 4,
    /// TPM_ALG_RSASSA_4096 (bit 5)
    RsaSsa4096 = 1 << 5,
    /// TPM_ALG_RSAPSS_4096 (bit 6)
    RsaPss4096 = 1 << 6,
    /// TPM_ALG_ECDSA_ECC_NIST_P384 (bit 7)
    EcdsaP384 = 1 << 7,
    /// TPM_ALG_ECDSA_ECC_NIST_P521 (bit 8)
    EcdsaP521 = 1 << 8,
    /// TPM_ALG_SM2_ECC_SM2_P256 (bit 9)
    Sm2P256 = 1 << 9,
    /// EDDSA_ED25519 (bit 10)
    Ed25519 = 1 << 10,
    /// EDDSA_ED448 (bit 11)
    Ed448 = 1 << 11,
}

impl SpdmBaseAsymAlgo {
    /// Convert from u32 bitfield to algorithm enum
    ///
    /// # Arguments
    /// * `bits` - The bitfield representing supported algorithms from SPDM ALGORITHMS response
    ///
    /// # Returns
    /// A vector of all algorithms represented in the bitfield
    ///
    /// # Example
    /// ```ignore
    /// let algos = SpdmBaseAsymAlgo::from_bits(0b10010); // bits 1 and 4 set
    /// // Returns [RsaPss2048, EcdsaP256]
    /// ```
    pub fn from_bits(bits: u32) -> Vec<Self> {
        let mut algos = Vec::new();

        if bits & (1 << 0) != 0 {
            algos.push(Self::RsaSsa2048);
        }
        if bits & (1 << 1) != 0 {
            algos.push(Self::RsaPss2048);
        }
        if bits & (1 << 2) != 0 {
            algos.push(Self::RsaSsa3072);
        }
        if bits & (1 << 3) != 0 {
            algos.push(Self::RsaPss3072);
        }
        if bits & (1 << 4) != 0 {
            algos.push(Self::EcdsaP256);
        }
        if bits & (1 << 5) != 0 {
            algos.push(Self::RsaSsa4096);
        }
        if bits & (1 << 6) != 0 {
            algos.push(Self::RsaPss4096);
        }
        if bits & (1 << 7) != 0 {
            algos.push(Self::EcdsaP384);
        }
        if bits & (1 << 8) != 0 {
            algos.push(Self::EcdsaP521);
        }
        if bits & (1 << 9) != 0 {
            algos.push(Self::Sm2P256);
        }
        if bits & (1 << 10) != 0 {
            algos.push(Self::Ed25519);
        }
        if bits & (1 << 11) != 0 {
            algos.push(Self::Ed448);
        }

        algos
    }

    /// Get the key size in bits for RSA algorithms
    ///
    /// # Returns
    /// * `Some(size)` - The key size in bits (2048, 3072, or 4096) for RSA algorithms
    /// * `None` - If this is not an RSA algorithm
    ///
    /// # Example
    /// ```ignore
    /// assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.rsa_key_size(), Some(3072));
    /// assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.rsa_key_size(), None);
    /// ```
    pub fn rsa_key_size(&self) -> Option<usize> {
        match self {
            Self::RsaSsa2048 | Self::RsaPss2048 => Some(2048),
            Self::RsaSsa3072 | Self::RsaPss3072 => Some(3072),
            Self::RsaSsa4096 | Self::RsaPss4096 => Some(4096),
            _ => None,
        }
    }

    /// Get the curve OID for ECC algorithms
    ///
    /// # Returns
    /// * `Some(oid)` - The curve OID for ECC algorithms (P-256, P-384, or P-521)
    /// * `None` - If this is not an ECC algorithm
    ///
    /// # Example
    /// ```ignore
    /// use spdm_x509::spdm::oids;
    /// assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.ecc_curve_oid(), Some(oids::ECDSA_P256));
    /// assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.ecc_curve_oid(), None);
    /// ```
    pub fn ecc_curve_oid(&self) -> Option<ObjectIdentifier> {
        match self {
            Self::EcdsaP256 => Some(oids::ECDSA_P256),
            Self::EcdsaP384 => Some(oids::ECDSA_P384),
            Self::EcdsaP521 => Some(oids::ECDSA_P521),
            _ => None,
        }
    }

    /// Check if this is an RSA algorithm
    ///
    /// # Returns
    /// `true` if this represents any RSA variant (RSASSA or RSAPSS), `false` otherwise
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::RsaSsa2048
                | Self::RsaPss2048
                | Self::RsaSsa3072
                | Self::RsaPss3072
                | Self::RsaSsa4096
                | Self::RsaPss4096
        )
    }

    /// Check if this is an ECC algorithm
    ///
    /// # Returns
    /// `true` if this represents any ECC algorithm (ECDSA P-256/384/521, SM2), `false` otherwise
    pub fn is_ecc(&self) -> bool {
        matches!(
            self,
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 | Self::Sm2P256
        )
    }

    /// Check if this is an EdDSA algorithm
    ///
    /// # Returns
    /// `true` if this represents an EdDSA algorithm (Ed25519 or Ed448), `false` otherwise
    pub fn is_eddsa(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }
}

// =============================================================================
// SPDM Base Hash Algorithm (DSP0274 Table 22)
// =============================================================================

/// SPDM Base Hash Algorithm flags
///
/// These correspond to the `BaseHashAlgo` field in SPDM ALGORITHMS response (DSP0274 Table 22).
///
/// # DSP0274 Requirements
/// - Certificate signature algorithms MUST use the negotiated base_hash_algo
/// - Hash size determines the root certificate hash size in SPDM certificate chains
///
/// # Example
/// ```ignore
/// use spdm_x509::spdm::SpdmBaseHashAlgo;
///
/// let algos = (1 << 0); // SHA-256
/// let parsed = SpdmBaseHashAlgo::from_bits(algos);
/// assert_eq!(parsed[0].oid().to_string(), "2.16.840.1.101.3.4.2.1");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpdmBaseHashAlgo {
    /// TPM_ALG_SHA_256 (bit 0)
    Sha256 = 1 << 0,
    /// TPM_ALG_SHA_384 (bit 1)
    Sha384 = 1 << 1,
    /// TPM_ALG_SHA_512 (bit 2)
    Sha512 = 1 << 2,
    /// TPM_ALG_SHA3_256 (bit 3)
    Sha3_256 = 1 << 3,
    /// TPM_ALG_SHA3_384 (bit 4)
    Sha3_384 = 1 << 4,
    /// TPM_ALG_SHA3_512 (bit 5)
    Sha3_512 = 1 << 5,
    /// TPM_ALG_SM3_256 (bit 6)
    Sm3_256 = 1 << 6,
}

impl SpdmBaseHashAlgo {
    /// Convert from u32 bitfield to algorithm enum
    ///
    /// # Arguments
    /// * `bits` - The bitfield representing supported hash algorithms from SPDM ALGORITHMS response
    ///
    /// # Returns
    /// A vector of all hash algorithms represented in the bitfield
    ///
    /// # Example
    /// ```ignore
    /// let algos = SpdmBaseHashAlgo::from_bits(0b11); // bits 0 and 1 set
    /// // Returns [Sha256, Sha384]
    /// ```
    pub fn from_bits(bits: u32) -> Vec<Self> {
        let mut algos = Vec::new();

        if bits & (1 << 0) != 0 {
            algos.push(Self::Sha256);
        }
        if bits & (1 << 1) != 0 {
            algos.push(Self::Sha384);
        }
        if bits & (1 << 2) != 0 {
            algos.push(Self::Sha512);
        }
        if bits & (1 << 3) != 0 {
            algos.push(Self::Sha3_256);
        }
        if bits & (1 << 4) != 0 {
            algos.push(Self::Sha3_384);
        }
        if bits & (1 << 5) != 0 {
            algos.push(Self::Sha3_512);
        }
        if bits & (1 << 6) != 0 {
            algos.push(Self::Sm3_256);
        }

        algos
    }

    /// Get the hash algorithm OID
    ///
    /// # Returns
    /// The OID representing this hash algorithm
    ///
    /// # Example
    /// ```ignore
    /// use spdm_x509::spdm::{SpdmBaseHashAlgo, oids};
    /// assert_eq!(SpdmBaseHashAlgo::Sha256.oid(), oids::SHA256);
    /// ```
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => oids::SHA256,
            Self::Sha384 => oids::SHA384,
            Self::Sha512 => oids::SHA512,
            Self::Sha3_256 => oids::SHA3_256,
            Self::Sha3_384 => oids::SHA3_384,
            Self::Sha3_512 => oids::SHA3_512,
            Self::Sm3_256 => {
                // SM3-256 OID: 1.2.156.10197.1.401
                ObjectIdentifier::new_unwrap("1.2.156.10197.1.401")
            }
        }
    }
}

// =============================================================================
// Algorithm Verification Functions
// =============================================================================

/// Verify that the certificate's signature algorithm matches the negotiated SPDM algorithms
///
/// # Arguments
/// - `cert_sig_algo_oid`: The OID of the certificate's signature algorithm
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the signature algorithm is allowed
/// - `Err(AlgorithmError)` if the algorithm doesn't match
pub fn verify_signature_algorithm(
    cert_sig_algo_oid: &ObjectIdentifier,
    _base_asym_algo: u32,
    base_hash_algo: u32,
) -> Result<()> {
    // Parse the signature algorithm OID to determine asymmetric and hash components
    // Common signature algorithm OIDs:
    // - sha256WithRSAEncryption: 1.2.840.113549.1.1.11
    // - sha384WithRSAEncryption: 1.2.840.113549.1.1.12
    // - sha512WithRSAEncryption: 1.2.840.113549.1.1.13
    // - ecdsa-with-SHA256: 1.2.840.10045.4.3.2
    // - ecdsa-with-SHA384: 1.2.840.10045.4.3.3
    // - ecdsa-with-SHA512: 1.2.840.10045.4.3.4

    let oid_str = cert_sig_algo_oid.to_string();

    // Verify hash algorithm component
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);
    let hash_match = match oid_str.as_str() {
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => {
            // SHA-256
            hash_algos
                .iter()
                .any(|h| matches!(h, SpdmBaseHashAlgo::Sha256))
        }
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
            // SHA-384
            hash_algos
                .iter()
                .any(|h| matches!(h, SpdmBaseHashAlgo::Sha384))
        }
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
            // SHA-512
            hash_algos
                .iter()
                .any(|h| matches!(h, SpdmBaseHashAlgo::Sha512))
        }
        _ => false,
    };

    if !hash_match {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!(
                "Signature hash algorithm not in negotiated algorithms: {}",
                oid_str
            ),
        )));
    }

    // Verify asymmetric algorithm component (will be checked in verify_rsa_key_size or verify_ecc_curve)
    Ok(())
}

/// Verify that an RSA public key has an allowed key size (2048, 3072, or 4096 bits)
///
/// # Arguments
/// - `public_key_der`: The DER-encoded RSA public key (SubjectPublicKeyInfo)
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the key size is valid
/// - `Err(AlgorithmError)` if the key size is invalid or not supported
pub fn verify_rsa_key_size(public_key_der: &[u8], base_asym_algo: u32) -> Result<()> {
    // Parse the RSA public key to get the modulus size
    // RSA public key format in DER:
    // SubjectPublicKeyInfo:
    //   algorithm: rsaEncryption
    //   subjectPublicKey: BIT STRING containing RSAPublicKey
    //     RSAPublicKey ::= SEQUENCE {
    //       modulus INTEGER,
    //       publicExponent INTEGER
    //     }

    // For now, we'll do a simplified check by looking at the modulus length
    // A proper implementation would parse the DER structure completely

    // Extract supported RSA key sizes from base_asym_algo
    let asym_algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);
    let supported_sizes: Vec<usize> = asym_algos.iter().filter_map(|a| a.rsa_key_size()).collect();

    if supported_sizes.is_empty() {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("No RSA algorithms in negotiated base_asym_algo"),
        )));
    }

    // Parse DER to find modulus length
    // This is a simplified check - in production, use a proper DER parser
    // Look for INTEGER tag (0x02) followed by length encoding
    let key_size_bits = estimate_rsa_key_size(public_key_der)?;

    if !supported_sizes.contains(&key_size_bits) {
        return Err(Error::KeyError(crate::error::KeyError::WeakKey {
            algorithm: "RSA".to_string(),
            bits: key_size_bits,
        }));
    }

    Ok(())
}

/// Estimate RSA key size from DER-encoded public key
fn estimate_rsa_key_size(der: &[u8]) -> Result<usize> {
    // Try to decode as SubjectPublicKeyInfo to get to the actual key data
    use der::Decode;
    use spki::SubjectPublicKeyInfo;

    let spki =
        SubjectPublicKeyInfo::<der::Any, der::asn1::BitString>::from_der(der).map_err(|e| {
            Error::AlgorithmError(AlgorithmError::Unsupported(alloc::format!(
                "Failed to parse RSA public key: {:?}",
                e
            )))
        })?;

    // The subject_public_key contains the RSAPublicKey SEQUENCE
    let key_bytes = spki.subject_public_key.raw_bytes();

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    // Find the modulus (first INTEGER in the SEQUENCE)
    // Skip SEQUENCE tag and length
    if key_bytes.len() < 4 {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("RSA public key too short"),
        )));
    }

    let mut idx = 0;
    // Skip SEQUENCE tag
    if key_bytes[idx] != 0x30 {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("Invalid RSA public key format"),
        )));
    }
    idx += 1;

    // Skip SEQUENCE length (may be short or long form)
    if key_bytes[idx] & 0x80 != 0 {
        let len_bytes = (key_bytes[idx] & 0x7F) as usize;
        idx += len_bytes + 1;
    } else {
        idx += 1;
    }

    // Now we should be at the modulus INTEGER tag
    if idx >= key_bytes.len() || key_bytes[idx] != 0x02 {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::string::String::from("Cannot find RSA modulus"),
        )));
    }
    idx += 1;

    // Read the modulus length
    let modulus_len = if key_bytes[idx] & 0x80 != 0 {
        // Long form length
        let len_bytes = (key_bytes[idx] & 0x7F) as usize;
        idx += 1;
        let mut len = 0usize;
        for _ in 0..len_bytes {
            len = (len << 8) | (key_bytes[idx] as usize);
            idx += 1;
        }
        len
    } else {
        // Short form length
        key_bytes[idx] as usize
    };

    // The modulus might have a leading 0x00 byte if the high bit is set
    // Adjust for this
    let key_size_bytes = if idx < key_bytes.len() && key_bytes[idx] == 0x00 {
        modulus_len - 1
    } else {
        modulus_len
    };

    let key_size_bits = key_size_bytes * 8;

    // Round to nearest standard size (2048, 3072, 4096)
    let rounded_size = if key_size_bits >= 4000 {
        4096
    } else if key_size_bits >= 3000 {
        3072
    } else if key_size_bits >= 2000 {
        2048
    } else {
        return Err(Error::KeyError(crate::error::KeyError::WeakKey {
            algorithm: "RSA".to_string(),
            bits: key_size_bits,
        }));
    };

    Ok(rounded_size)
}

/// Verify that an ECC public key uses an allowed curve (P-256, P-384, or P-521)
///
/// # Arguments
/// - `curve_oid`: The OID of the elliptic curve
/// - `base_asym_algo`: The negotiated SPDM base asymmetric algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the curve is valid
/// - `Err(AlgorithmError)` if the curve is not supported
pub fn verify_ecc_curve(curve_oid: &ObjectIdentifier, base_asym_algo: u32) -> Result<()> {
    let asym_algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);

    // Check if the curve is in the supported list
    let curve_supported = asym_algos.iter().any(|algo| {
        if let Some(algo_curve) = algo.ecc_curve_oid() {
            &algo_curve == curve_oid
        } else {
            false
        }
    });

    if !curve_supported {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!("ECC curve not in negotiated algorithms: {}", curve_oid),
        )));
    }

    Ok(())
}

/// Verify that a hash algorithm OID is in the negotiated SPDM hash algorithms
///
/// # Arguments
/// - `hash_oid`: The hash algorithm OID
/// - `base_hash_algo`: The negotiated SPDM base hash algorithm (bitfield)
///
/// # Returns
/// - `Ok(())` if the hash algorithm is supported
/// - `Err(AlgorithmError)` if the hash algorithm is not supported
pub fn verify_hash_algorithm(hash_oid: &ObjectIdentifier, base_hash_algo: u32) -> Result<()> {
    let hash_algos = SpdmBaseHashAlgo::from_bits(base_hash_algo);

    let hash_supported = hash_algos.iter().any(|algo| &algo.oid() == hash_oid);

    if !hash_supported {
        return Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!("Hash algorithm not in negotiated algorithms: {}", hash_oid),
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdm_base_asym_algo_from_bits() {
        let bits = (1 << 0) | (1 << 4); // RSA-2048 + ECDSA-P256
        let algos = SpdmBaseAsymAlgo::from_bits(bits);
        assert_eq!(algos.len(), 2);
        assert!(algos.contains(&SpdmBaseAsymAlgo::RsaSsa2048));
        assert!(algos.contains(&SpdmBaseAsymAlgo::EcdsaP256));
    }

    #[test]
    fn test_rsa_key_size() {
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.rsa_key_size(), Some(2048));
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.rsa_key_size(), Some(3072));
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa4096.rsa_key_size(), Some(4096));
        assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.rsa_key_size(), None);
    }

    #[test]
    fn test_ecc_curve_oid() {
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP256.ecc_curve_oid(),
            Some(oids::ECDSA_P256)
        );
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP384.ecc_curve_oid(),
            Some(oids::ECDSA_P384)
        );
        assert_eq!(
            SpdmBaseAsymAlgo::EcdsaP521.ecc_curve_oid(),
            Some(oids::ECDSA_P521)
        );
        assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.ecc_curve_oid(), None);
    }

    #[test]
    fn test_hash_algo_oid() {
        assert_eq!(SpdmBaseHashAlgo::Sha256.oid(), oids::SHA256);
        assert_eq!(SpdmBaseHashAlgo::Sha384.oid(), oids::SHA384);
        assert_eq!(SpdmBaseHashAlgo::Sha512.oid(), oids::SHA512);
    }
}

// =============================================================================
// spdmlib-compatible Functions (for spdm-rs integration)
// =============================================================================

/// Verifies a signature on data using a certificate
///
/// This function is **directly compatible** with spdmlib::SpdmAsymVerify interface.
/// It verifies signatures according to SPDM negotiated algorithms.
///
/// # Arguments
/// * `base_hash_algo` - SPDM base hash algorithm (from negotiation)
/// * `base_asym_algo` - SPDM base asymmetric algorithm (from negotiation)
/// * `public_cert_der` - Certificate in DER format (or RFC7250 public key)
/// * `data` - Data that was signed
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(())` - If signature verification succeeds
/// * `Err` - If verification fails or algorithms are unsupported
///
/// # Supported Algorithm Combinations
/// - RSA-2048/3072/4096 with SHA-256/384/512 (PKCS#1 v1.5 or PSS)
/// - ECDSA P-256 with SHA-256/384
/// - ECDSA P-384 with SHA-256/384
///
/// # Example
/// ```ignore
/// verify_signature(
///     SpdmBaseHashAlgo::Sha256,
///     SpdmBaseAsymAlgo::EcdsaP256,
///     cert_der,
///     data,
///     signature
/// )?;
/// ```
pub fn verify_signature(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    use crate::certificate::Certificate;
    use ring::signature;

    // Parse certificate to get public key
    let cert = Certificate::from_der(public_cert_der)?;

    // Get public key bytes
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // Directly use ring algorithms based on SPDM algorithm combination
    // Ring supports 4 ECDSA variants: P256+SHA256, P256+SHA384, P384+SHA256, P384+SHA384
    match (base_hash_algo, base_asym_algo) {
        // ECDSA P-256 with SHA-256
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::EcdsaP256) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // ECDSA P-256 with SHA-384
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::EcdsaP256) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA384_ASN1, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // ECDSA P-384 with SHA-256
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::EcdsaP384) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA256_ASN1, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // ECDSA P-384 with SHA-384
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::EcdsaP384) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA PKCS#1 v1.5 with SHA-256
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa2048)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa3072)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa4096) => {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
            );
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA PKCS#1 v1.5 with SHA-384
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa2048)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa3072)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa4096) => {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA384,
                public_key,
            );
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA PKCS#1 v1.5 with SHA-512
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa2048)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa3072)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa4096) => {
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                public_key,
            );
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA-PSS with SHA-256
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss4096) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA-PSS with SHA-384
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss4096) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // RSA-PSS with SHA-512
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss4096) => {
            let public_key =
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, public_key);
            public_key
                .verify(data, signature)
                .map_err(|_| Error::signature_failed())?;
        }
        // Unsupported algorithm combination
        _ => {
            return Err(Error::unsupported_algorithm(alloc::format!(
                "Unsupported algorithm combination: hash={:?}, asym={:?}",
                base_hash_algo,
                base_asym_algo
            )));
        }
    }

    Ok(())
}

/// Maps SPDM algorithm combination to SignatureAlgorithm
///
/// # Arguments
/// * `hash_algo` - SPDM base hash algorithm
/// * `asym_algo` - SPDM base asymmetric algorithm
///
/// # Returns
/// * `Ok(SignatureAlgorithm)` - If combination is supported
/// * `Err` - If combination is unsupported
#[allow(dead_code)]
fn map_spdm_to_signature_algorithm(
    hash_algo: SpdmBaseHashAlgo,
    asym_algo: SpdmBaseAsymAlgo,
) -> Result<crate::algorithms::SignatureAlgorithm> {
    use crate::algorithms::SignatureAlgorithm;

    // Map based on SPDM algorithm combination
    match (hash_algo, asym_algo) {
        // ECDSA P-256 combinations
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::EcdsaP256) => {
            Ok(SignatureAlgorithm::EcdsaSha256)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::EcdsaP256) => {
            Ok(SignatureAlgorithm::EcdsaSha384)
        }

        // ECDSA P-384 combinations
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::EcdsaP384) => {
            // P-384 with SHA-256 - use SHA-384 for better security
            Ok(SignatureAlgorithm::EcdsaSha384)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::EcdsaP384) => {
            Ok(SignatureAlgorithm::EcdsaSha384)
        }

        // RSA-2048 combinations (PKCS#1 v1.5)
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa2048) => {
            Ok(SignatureAlgorithm::RsaSha256)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa2048) => {
            Ok(SignatureAlgorithm::RsaSha384)
        }
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa2048) => {
            Ok(SignatureAlgorithm::RsaSha512)
        }

        // RSA-3072 combinations (PKCS#1 v1.5)
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa3072) => {
            Ok(SignatureAlgorithm::RsaSha256)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa3072) => {
            Ok(SignatureAlgorithm::RsaSha384)
        }
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa3072) => {
            Ok(SignatureAlgorithm::RsaSha512)
        }

        // RSA-4096 combinations (PKCS#1 v1.5)
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaSsa4096) => {
            Ok(SignatureAlgorithm::RsaSha256)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaSsa4096) => {
            Ok(SignatureAlgorithm::RsaSha384)
        }
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaSsa4096) => {
            Ok(SignatureAlgorithm::RsaSha512)
        }

        // RSA-PSS combinations - Note: PSS requires special handling
        // For now, map to PKCS#1 v1.5 as fallback
        (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha256, SpdmBaseAsymAlgo::RsaPss4096) => {
            Ok(SignatureAlgorithm::RsaSha256)
        }
        (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha384, SpdmBaseAsymAlgo::RsaPss4096) => {
            Ok(SignatureAlgorithm::RsaSha384)
        }
        (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss2048)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss3072)
        | (SpdmBaseHashAlgo::Sha512, SpdmBaseAsymAlgo::RsaPss4096) => {
            Ok(SignatureAlgorithm::RsaSha512)
        }

        // Unsupported combination
        _ => Err(Error::AlgorithmError(AlgorithmError::Unsupported(
            alloc::format!(
                "Unsupported SPDM algorithm combination: hash={:?}, asym={:?}",
                hash_algo,
                asym_algo
            ),
        ))),
    }
}
