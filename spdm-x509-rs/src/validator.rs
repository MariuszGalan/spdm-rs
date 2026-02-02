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

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet as HashSet;
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::HashSet;

use crate::algorithms::SignatureAlgorithm;
use crate::certificate::Certificate;
use crate::error::{Error, Result};
use crate::extensions::{
    BasicConstraints, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE, KEY_USAGE,
    SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER,
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
pub struct Validator {
    /// Cache of known extension OIDs for fast lookup
    known_extensions: HashSet<ObjectIdentifier>,
}

impl Validator {
    /// Create a new Validator
    pub fn new() -> Self {
        let mut known_extensions = HashSet::new();
        known_extensions.insert(BASIC_CONSTRAINTS);
        known_extensions.insert(KEY_USAGE);
        known_extensions.insert(EXTENDED_KEY_USAGE);
        known_extensions.insert(SUBJECT_ALT_NAME);
        known_extensions.insert(AUTHORITY_KEY_IDENTIFIER);
        known_extensions.insert(SUBJECT_KEY_IDENTIFIER);

        #[cfg(feature = "spdm")]
        {
            known_extensions.insert(HARDWARE_IDENTITY);
            known_extensions.insert(SPDM_EXTENSION);
        }

        Self { known_extensions }
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
        // Get the signature algorithm
        let sig_algo = SignatureAlgorithm::from_oid(&cert.signature_algorithm.algorithm)?;

        // Get the TBS certificate bytes (the data that was signed)
        let tbs_bytes = cert.tbs_certificate.to_der()?;

        // Get the signature value (remove padding bit count from BitString)
        let signature = cert.signature_value.raw_bytes();

        // Get the public key from issuer
        let public_key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        // Verify signature using ring
        sig_algo.verify_signature(&tbs_bytes, signature, public_key_bytes)?;

        Ok(())
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

        // Validate each extension
        for ext in &extensions.extensions {
            // Check critical extensions are recognized
            if ext.critical {
                // Use O(1) HashSet lookup instead of multiple comparisons
                if !self.known_extensions.contains(&ext.extn_id) {
                    // Unknown critical extension - must reject per RFC 5280
                    return Err(Error::ExtensionError(
                        crate::error::ExtensionError::UnknownCriticalExtension(
                            ext.extn_id.to_string(),
                        ),
                    ));
                }

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
        // Check chain is not empty
        if chain.is_empty() {
            return Err(Error::ChainError(crate::error::ChainError::EmptyChain));
        }

        // Check chain depth
        if chain.len() > options.max_chain_depth {
            return Err(Error::ChainError(crate::error::ChainError::ChainTooLong));
        }

        // Validate each certificate in the chain
        for (idx, cert) in chain.certificates.iter().enumerate() {
            // Validate the certificate itself
            self.validate(cert, options)?;

            // For non-root certificates, verify signature against issuer
            if idx + 1 < chain.len() {
                let issuer = &chain.certificates[idx + 1];

                // Verify issuer name matches subject of next cert
                if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
                    return Err(Error::ChainError(crate::error::ChainError::IssuerMismatch));
                }

                // Verify signature if enabled
                if options.check_signature {
                    self.verify_signature(cert, issuer)?;
                }

                // Verify issuer is a CA (if it has Basic Constraints)
                self.verify_issuer_is_ca(issuer, idx)?;
            } else {
                // For root certificate, verify it's self-signed
                if options.check_signature {
                    self.verify_signature(cert, cert)?;
                }
            }
        }

        // Validate path length constraints
        self.validate_path_length_constraints(chain)?;

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

impl Default for Validator {
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
