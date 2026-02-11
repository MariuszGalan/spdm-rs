// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Certificate validation and chain verification.
//!
//! This module provides certificate validation functionality including:
//! - Signature verification
//! - Validity period checking
//! - Certificate chain validation
//! - Extension validation
//!
//! # Example
//!
//! ```ignore
//! use spdm_x509::{Certificate, Validator, ValidationOptions};
//!
//! let cert = Certificate::from_der(cert_der)?;
//! let validator = Validator::new();
//! let options = ValidationOptions::default();
//!
//! validator.validate(&cert, &options)?;
//! ```

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "ring-backend")]
use crate::algorithms::RingBackend;
use crate::algorithms::{CryptoBackend, SignatureAlgorithm};
use crate::certificate::Certificate;
use crate::error::{Error, Result};
use crate::extensions::{
    BasicConstraints, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE, KEY_USAGE,
    SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER, TCG_PLATFORM_CERTIFICATE,
};
#[cfg(feature = "spdm")]
use crate::extensions::{HARDWARE_IDENTITY, SPDM_EXTENSION};
use crate::time_utils::Time;
use const_oid::ObjectIdentifier;

// ============================================================================
// Validation Options
// ============================================================================

/// Options for certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Whether to check the certificate validity period
    pub check_time: bool,

    /// Whether to verify the certificate signature
    pub check_signature: bool,

    /// Whether to validate extensions
    pub check_extensions: bool,

    /// Maximum allowed certificate chain depth
    pub max_chain_depth: usize,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            check_time: true,
            check_signature: true,
            check_extensions: true,
            max_chain_depth: 10,
        }
    }
}

impl ValidationOptions {
    /// Create a new ValidationOptions with all checks enabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable time validation (useful for testing)
    pub fn skip_time_validation(mut self) -> Self {
        self.check_time = false;
        self
    }

    /// Disable signature validation (useful for parsing-only scenarios)
    pub fn skip_signature_validation(mut self) -> Self {
        self.check_signature = false;
        self
    }

    /// Set the maximum chain depth
    pub fn with_max_chain_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth;
        self
    }
}

// ============================================================================
// Validator
// ============================================================================

/// Certificate validator.
pub struct Validator<B: CryptoBackend> {
    /// Crypto backend for signature verification
    backend: B,
    /// Cache of known extension OIDs for fast lookup
    known_extensions: Vec<ObjectIdentifier>,
}

#[cfg(feature = "ring-backend")]
impl Validator<RingBackend> {
    /// Create a new Validator with the Ring backend
    pub fn new() -> Self {
        Self::with_backend(RingBackend)
    }
}

impl<B: CryptoBackend> Validator<B> {
    /// Create a new Validator with a specific backend
    pub fn with_backend(backend: B) -> Self {
        let mut known_extensions = vec![
            BASIC_CONSTRAINTS,
            KEY_USAGE,
            EXTENDED_KEY_USAGE,
            SUBJECT_ALT_NAME,
            AUTHORITY_KEY_IDENTIFIER,
            SUBJECT_KEY_IDENTIFIER,
            // TCG extensions
            TCG_PLATFORM_CERTIFICATE,
        ];

        #[cfg(feature = "spdm")]
        {
            known_extensions.push(HARDWARE_IDENTITY);
            known_extensions.push(SPDM_EXTENSION);
        }

        Self {
            backend,
            known_extensions,
        }
    }

    /// Validate a single certificate.
    ///
    /// This performs basic validation checks on the certificate:
    /// - Validity period (if enabled)
    /// - Signature (if enabled and issuer is provided)
    /// - Extensions (if enabled)
    pub fn validate(&self, cert: &Certificate, options: &ValidationOptions) -> Result<()> {
        // 1. Check validity period
        if options.check_time {
            self.validate_time(cert)?;
        }

        // 2. Validate extensions
        if options.check_extensions {
            self.validate_extensions(cert)?;
        }

        // Note: Signature verification requires the issuer's public key,
        // so it's done in validate_chain() or with verify_signature()
        Ok(())
    }

    /// Verify certificate signature against issuer's public key.
    ///
    /// This can be used to verify a certificate's signature when the issuer
    /// certificate is available.
    pub fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        log::trace!("verify_signature: starting signature verification");
        log::trace!("cert subject: {:?}", cert.tbs_certificate.subject);
        log::trace!("issuer subject: {:?}", issuer.tbs_certificate.subject);

        // Get the curve OID from the issuer's public key (for ECDSA)
        log::trace!(
            "verify_signature: issuer public key algorithm = {:?}",
            issuer.tbs_certificate.subject_public_key_info.algorithm.oid
        );

        let curve_oid = if let Some(params) = &issuer
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
        {
            log::trace!(
                "verify_signature: algorithm has parameters, value length = {}",
                params.value().len()
            );
            // Decode the parameters as an ObjectIdentifier
            match params.decode_as::<ObjectIdentifier>() {
                Ok(oid) => {
                    log::trace!(
                        "verify_signature: successfully decoded curve OID = {:?}",
                        oid
                    );
                    Some(oid)
                }
                Err(e) => {
                    log::trace!("verify_signature: failed to decode curve OID: {:?}", e);
                    None
                }
            }
        } else {
            log::trace!("verify_signature: no algorithm parameters found");
            None
        };

        if let Some(ref curve) = curve_oid {
            log::trace!("verify_signature: detected curve OID = {:?}", curve);
        }

        // Get the signature algorithm with curve information
        let sig_algo = match SignatureAlgorithm::from_oid_with_curve(
            &cert.signature_algorithm.oid,
            curve_oid.as_ref(),
        ) {
            Ok(algo) => {
                log::trace!("verify_signature: signature algorithm = {:?}", algo);
                algo
            }
            Err(e) => {
                log::error!(
                    "verify_signature: unsupported signature algorithm OID: {:?}",
                    cert.signature_algorithm.oid
                );
                return Err(e);
            }
        };

        // Get the TBS certificate bytes (the data that was signed)
        let tbs_bytes = match cert.tbs_certificate.to_der() {
            Ok(bytes) => {
                log::trace!("verify_signature: TBS bytes length = {}", bytes.len());
                bytes
            }
            Err(e) => {
                log::error!(
                    "verify_signature: failed to encode TBS certificate: {:?}",
                    e
                );
                return Err(e);
            }
        };

        // Get the signature value (remove padding bit count from BitString)
        let signature = cert.signature_value.raw_bytes();
        log::trace!("verify_signature: signature length = {}", signature.len());
        log::trace!(
            "verify_signature: signature (first 32 bytes) = {:02x?}",
            &signature[..signature.len().min(32)]
        );

        // Get the public key from issuer
        let public_key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        log::trace!(
            "verify_signature: public key length = {}",
            public_key_bytes.len()
        );
        log::trace!(
            "verify_signature: public key algorithm OID = {:?}",
            issuer.tbs_certificate.subject_public_key_info.algorithm.oid
        );

        // Verify signature using crypto backend
        log::trace!("verify_signature: calling crypto backend verification...");
        match self
            .backend
            .verify_signature(sig_algo, &tbs_bytes, signature, public_key_bytes)
        {
            Ok(_) => {
                log::trace!("verify_signature: SUCCESS signature verification SUCCESS");
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "verify_signature: FAILED signature verification FAILED: {:?}",
                    e
                );
                Err(e)
            }
        }
    }

    /// Validate certificate time validity.
    fn validate_time(&self, cert: &Certificate) -> Result<()> {
        // Get current time
        let now = Self::get_current_time()?;

        let validity = &cert.tbs_certificate.validity;

        // Check if current time is before the validity period
        if now.is_before(&validity.not_before) {
            return Err(Error::TimeError(crate::error::TimeError::NotYetValid));
        }

        // Check if current time is after the validity period
        if now.is_after(&validity.not_after) {
            return Err(Error::TimeError(crate::error::TimeError::Expired));
        }

        Ok(())
    }

    /// Get current time as a Time value.
    ///
    /// In no_std environments, this should be implemented by the platform.
    /// For now, we use a simple implementation.
    fn get_current_time() -> Result<Time> {
        // In a real implementation, this would get the current system time
        // For no_std, this would need to be provided by the platform
        #[cfg(feature = "std")]
        {
            use der::asn1::GeneralizedTime;
            use der::DateTime;

            // Get current UTC time
            let now = std::time::SystemTime::now();
            let duration = now
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::TimeError(crate::error::TimeError::InvalidTime))?;

            // Convert to DateTime
            let dt = DateTime::from_unix_duration(duration)
                .map_err(|_| Error::TimeError(crate::error::TimeError::InvalidTime))?;

            // Convert to GeneralizedTime
            let gen_time = GeneralizedTime::from_date_time(dt);
            Ok(Time::GeneralizedTime(gen_time))
        }

        #[cfg(not(feature = "std"))]
        {
            // In no_std environments, the platform must provide the current time
            // For now, return an error
            Err(Error::ValidationError(
                "Current time not available in no_std environment".into(),
            ))
        }
    }

    /// Validate certificate extensions.
    fn validate_extensions(&self, cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()), // No extensions to validate
        };

        log::trace!(
            "validate_extensions: checking {} extensions",
            extensions.extensions.len()
        );

        // Validate each extension
        for ext in &extensions.extensions {
            log::trace!(
                "validate_extensions: extension OID={}, critical={}",
                ext.extn_id,
                ext.critical
            );

            // Check critical extensions are recognized
            if ext.critical {
                // Check if this is a known extension
                if !self.known_extensions.contains(&ext.extn_id) {
                    // Unknown critical extension - must reject per RFC 5280
                    log::error!(
                        "validate_extensions: UNKNOWN critical extension: {}",
                        ext.extn_id
                    );
                    return Err(Error::ExtensionError(
                        crate::error::ExtensionError::UnknownCriticalExtension(
                            ext.extn_id.to_string(),
                        ),
                    ));
                }
                log::trace!(
                    "validate_extensions: critical extension {} is recognized",
                    ext.extn_id
                );

                // Validate specific extensions that require processing
                if ext.extn_id == BASIC_CONSTRAINTS {
                    self.validate_basic_constraints(cert)?;
                }
            }
        }

        Ok(())
    }

    /// Validate Basic Constraints extension.
    fn validate_basic_constraints(&self, cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        // Find and parse Basic Constraints
        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                // Basic Constraints validation is context-dependent
                // For now, just verify it parses correctly
                // In chain validation, we check pathLen constraints
                let _ = bc;
                return Ok(());
            }
        }

        Ok(())
    }

    /// Validate a certificate chain.
    ///
    /// This validates an entire certificate chain from leaf to root:
    /// - Each certificate is validated individually
    /// - Each certificate is verified against its issuer
    /// - Chain constraints are checked (path length, etc.)
    pub fn validate_chain(
        &self,
        chain: &CertificateChain,
        options: &ValidationOptions,
    ) -> Result<()> {
        log::trace!(
            "validate_chain: starting validation, chain_len={}",
            chain.len()
        );

        // Check chain is not empty
        if chain.is_empty() {
            log::error!("validate_chain: chain is empty");
            return Err(Error::ChainError(crate::error::ChainError::EmptyChain));
        }

        // Check chain depth
        if chain.len() > options.max_chain_depth {
            log::error!(
                "validate_chain: chain too long, len={} > max={}",
                chain.len(),
                options.max_chain_depth
            );
            return Err(Error::ChainError(crate::error::ChainError::ChainTooLong));
        }

        // Validate each certificate in the chain
        for (idx, cert) in chain.certificates.iter().enumerate() {
            log::trace!(
                "validate_chain: validating cert {} (subject={:?})",
                idx,
                cert.tbs_certificate.subject
            );

            // Validate the certificate itself
            match self.validate(cert, options) {
                Ok(_) => log::trace!("validate_chain: cert {} validation OK", idx),
                Err(e) => {
                    log::error!("validate_chain: cert {} validation failed: {:?}", idx, e);
                    return Err(e);
                }
            }

            // For non-root certificates, verify signature against issuer
            if idx + 1 < chain.len() {
                let issuer = &chain.certificates[idx + 1];
                log::trace!(
                    "validate_chain: cert {} has issuer cert {} (subject={:?})",
                    idx,
                    idx + 1,
                    issuer.tbs_certificate.subject
                );

                // Verify issuer name matches subject of next cert
                if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
                    log::error!("validate_chain: ISSUER MISMATCH at cert {}", idx);
                    log::error!("  cert.issuer={:?}", cert.tbs_certificate.issuer);
                    log::error!("  issuer.subject={:?}", issuer.tbs_certificate.subject);
                    return Err(Error::ChainError(crate::error::ChainError::IssuerMismatch));
                }
                log::trace!("validate_chain: cert {} issuer name matches", idx);

                // Verify signature if enabled
                if options.check_signature {
                    log::trace!(
                        "validate_chain: verifying signature for cert {} against issuer {}",
                        idx,
                        idx + 1
                    );
                    match self.verify_signature(cert, issuer) {
                        Ok(_) => {
                            log::trace!("validate_chain: cert {} signature verification OK", idx)
                        }
                        Err(e) => {
                            log::error!(
                                "validate_chain: cert {} signature verification FAILED: {:?}",
                                idx,
                                e
                            );
                            return Err(e);
                        }
                    }
                }

                // Verify issuer is a CA (if it has Basic Constraints)
                log::trace!("validate_chain: checking if cert {} issuer is CA", idx);
                match self.verify_issuer_is_ca(issuer, idx) {
                    Ok(_) => log::trace!("validate_chain: cert {} issuer is valid CA", idx),
                    Err(e) => {
                        log::error!(
                            "validate_chain: cert {} issuer CA check FAILED: {:?}",
                            idx,
                            e
                        );
                        return Err(e);
                    }
                }
            } else {
                // For root certificate, verify it's self-signed
                log::trace!(
                    "validate_chain: cert {} is root, checking self-signature",
                    idx
                );
                if options.check_signature {
                    match self.verify_signature(cert, cert) {
                        Ok(_) => {
                            log::trace!("validate_chain: root cert self-signature OK")
                        }
                        Err(e) => {
                            log::error!("validate_chain: root cert self-signature failed: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }

        // Validate path length constraints
        log::trace!("validate_chain: checking path length constraints");
        match self.validate_path_length_constraints(chain) {
            Ok(_) => log::trace!("validate_chain: path length constraints OK"),
            Err(e) => {
                log::error!("validate_chain: path length constraints failed: {:?}", e);
                return Err(e);
            }
        }

        log::trace!("validate_chain: SUCCESS all validations passed");
        Ok(())
    }

    /// Verify that an issuer certificate is a CA.
    fn verify_issuer_is_ca(&self, issuer: &Certificate, depth: usize) -> Result<()> {
        let extensions = match &issuer.tbs_certificate.extensions {
            Some(exts) => exts,
            None => {
                // No extensions means v1/v2 certificate - assume it's not a CA
                return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
            }
        };

        // Find Basic Constraints extension
        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                if !bc.ca {
                    return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
                }

                // Check pathLenConstraint
                if let Some(path_len) = bc.path_len_constraint {
                    if depth > path_len as usize {
                        return Err(Error::ChainError(
                            crate::error::ChainError::PathLengthExceeded,
                        ));
                    }
                }

                return Ok(());
            }
        }

        // Basic Constraints not found - issuer is not a CA
        Err(Error::ChainError(crate::error::ChainError::IssuerNotCA))
    }

    /// Validate path length constraints in the chain.
    fn validate_path_length_constraints(&self, chain: &CertificateChain) -> Result<()> {
        // Track the minimum path length constraint
        let mut min_path_len: Option<usize> = None;

        // Iterate through CA certificates (all except the leaf)
        for (idx, cert) in chain.certificates.iter().enumerate().skip(1) {
            let extensions = match &cert.tbs_certificate.extensions {
                Some(exts) => exts,
                None => continue,
            };

            // Find Basic Constraints
            for ext in &extensions.extensions {
                if ext.extn_id == BASIC_CONSTRAINTS {
                    use der::Decode;
                    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(Error::Asn1)?;

                    if let Some(path_len) = bc.path_len_constraint {
                        let remaining_certs = chain.len() - idx - 1;
                        if remaining_certs > path_len as usize {
                            return Err(Error::ChainError(
                                crate::error::ChainError::PathLengthExceeded,
                            ));
                        }

                        // Update minimum path length
                        match min_path_len {
                            Some(current) => {
                                min_path_len = Some(core::cmp::min(current, path_len as usize))
                            }
                            None => min_path_len = Some(path_len as usize),
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "ring-backend")]
impl Default for Validator<RingBackend> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Certificate Chain
// ============================================================================

/// A certificate chain, ordered from leaf (end-entity) to root (trust anchor).
#[derive(Debug, Clone)]
pub struct CertificateChain {
    /// The certificates in the chain, from leaf to root
    pub certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Create a new certificate chain
    pub fn new(certificates: Vec<Certificate>) -> Self {
        Self { certificates }
    }

    /// Create a chain with a single certificate
    pub fn single(cert: Certificate) -> Self {
        Self {
            certificates: alloc::vec![cert],
        }
    }

    /// Add a certificate to the chain
    pub fn push(&mut self, cert: Certificate) {
        self.certificates.push(cert);
    }

    /// Get the leaf (end-entity) certificate
    pub fn leaf(&self) -> Option<&Certificate> {
        self.certificates.first()
    }

    /// Get the root (trust anchor) certificate
    pub fn root(&self) -> Option<&Certificate> {
        self.certificates.last()
    }

    /// Get the chain length
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Get an iterator over the certificates
    pub fn iter(&self) -> core::slice::Iter<'_, Certificate> {
        self.certificates.iter()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options() {
        let opts = ValidationOptions::default();
        assert!(opts.check_time);
        assert!(opts.check_signature);
        assert!(opts.check_extensions);
        assert_eq!(opts.max_chain_depth, 10);

        let opts = ValidationOptions::new()
            .skip_time_validation()
            .skip_signature_validation()
            .with_max_chain_depth(5);
        assert!(!opts.check_time);
        assert!(!opts.check_signature);
        assert_eq!(opts.max_chain_depth, 5);
    }

    #[test]
    fn test_validator_creation() {
        let _validator = Validator::new();
        let _validator2 = Validator::default();
    }
}
