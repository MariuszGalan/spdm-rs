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

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::certificate::Certificate;
use crate::chain::CertificateChain;
#[cfg(feature = "ring-backend")]
use crate::crypto_backend::RingBackend;
use crate::crypto_backend::{CryptoBackend, SignatureAlgorithm};
use crate::error::{Error, Result};
use crate::time::Time;
use crate::x509::extensions::{
    BasicConstraints, AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE, KEY_USAGE,
    SUBJECT_ALT_NAME, SUBJECT_KEY_IDENTIFIER, TCG_PLATFORM_CERTIFICATE,
};
use crate::x509::extensions::{HARDWARE_IDENTITY, SPDM_EXTENSION};
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
            check_time: !cfg!(feature = "no-time-check"),
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

        known_extensions.push(HARDWARE_IDENTITY);
        known_extensions.push(SPDM_EXTENSION);

        Self {
            backend,
            known_extensions,
        }
    }

    /// Validate a single certificate.
    pub fn validate(&self, cert: &Certificate, options: &ValidationOptions) -> Result<()> {
        if options.check_time {
            self.validate_time(cert)?;
        }

        if options.check_extensions {
            self.validate_extensions(cert)?;
        }

        Ok(())
    }

    /// Verify certificate signature against issuer's public key.
    pub fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        log::trace!("verify_signature: starting signature verification");
        log::trace!("cert subject: {:?}", cert.tbs_certificate.subject);
        log::trace!("issuer subject: {:?}", issuer.tbs_certificate.subject);

        let curve_oid = if let Some(params) = &issuer
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
        {
            match params.decode_as::<ObjectIdentifier>() {
                Ok(oid) => {
                    log::trace!("verify_signature: decoded curve OID = {:?}", oid);
                    Some(oid)
                }
                Err(e) => {
                    log::trace!("verify_signature: failed to decode curve OID: {:?}", e);
                    None
                }
            }
        } else {
            None
        };

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

        let signature = cert.signature_value.raw_bytes();
        log::trace!("verify_signature: signature length = {}", signature.len());

        let public_key_bytes = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        log::trace!(
            "verify_signature: public key length = {}",
            public_key_bytes.len()
        );

        match self
            .backend
            .verify_signature(sig_algo, &tbs_bytes, signature, public_key_bytes)
        {
            Ok(_) => {
                log::trace!("verify_signature: SUCCESS");
                Ok(())
            }
            Err(e) => {
                log::error!("verify_signature: FAILED: {:?}", e);
                Err(e)
            }
        }
    }

    /// Validate certificate time validity.
    fn validate_time(&self, cert: &Certificate) -> Result<()> {
        let now = Self::get_current_time()?;
        let validity = &cert.tbs_certificate.validity;

        if now.is_before(&validity.not_before) {
            return Err(Error::TimeError(crate::error::TimeError::NotYetValid));
        }

        if now.is_after(&validity.not_after) {
            return Err(Error::TimeError(crate::error::TimeError::Expired));
        }

        Ok(())
    }

    /// Get current time as a Time value.
    fn get_current_time() -> Result<Time> {
        crate::time::current_time()
            .map_err(|_| Error::TimeError(crate::error::TimeError::InvalidTime))
    }

    /// Validate certificate extensions.
    fn validate_extensions(&self, cert: &Certificate) -> Result<()> {
        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => return Ok(()),
        };

        log::trace!(
            "validate_extensions: checking {} extensions",
            extensions.extensions.len()
        );

        for ext in &extensions.extensions {
            log::trace!(
                "validate_extensions: extension OID={}, critical={}",
                ext.extn_id,
                ext.critical
            );

            if ext.critical {
                if !self.known_extensions.contains(&ext.extn_id) {
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

        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;
                let _ = bc;
                return Ok(());
            }
        }

        Ok(())
    }

    /// Validate a certificate chain.
    pub fn validate_chain(
        &self,
        chain: &CertificateChain,
        options: &ValidationOptions,
    ) -> Result<()> {
        log::trace!(
            "validate_chain: starting validation, chain_len={}",
            chain.len()
        );

        if chain.is_empty() {
            return Err(Error::ChainError(crate::error::ChainError::EmptyChain));
        }

        if chain.len() > options.max_chain_depth {
            return Err(Error::ChainError(crate::error::ChainError::ChainTooLong));
        }

        for (idx, cert) in chain.certificates.iter().enumerate() {
            log::trace!(
                "validate_chain: validating cert {} (subject={:?})",
                idx,
                cert.tbs_certificate.subject
            );

            self.validate(cert, options)?;

            if idx + 1 < chain.len() {
                let issuer = &chain.certificates[idx + 1];

                if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
                    log::error!("validate_chain: ISSUER MISMATCH at cert {}", idx);
                    return Err(Error::ChainError(crate::error::ChainError::IssuerMismatch));
                }

                if options.check_signature {
                    self.verify_signature(cert, issuer)?;
                }

                self.verify_issuer_is_ca(issuer, idx)?;
            } else {
                // Root certificate - verify self-signed
                if options.check_signature {
                    self.verify_signature(cert, cert)?;
                }
            }
        }

        self.validate_path_length_constraints(chain)?;

        log::trace!("validate_chain: SUCCESS all validations passed");
        Ok(())
    }

    /// Verify that an issuer certificate is a CA.
    fn verify_issuer_is_ca(&self, issuer: &Certificate, depth: usize) -> Result<()> {
        let extensions = match &issuer.tbs_certificate.extensions {
            Some(exts) => exts,
            None => {
                return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
            }
        };

        for ext in &extensions.extensions {
            if ext.extn_id == BASIC_CONSTRAINTS {
                use der::Decode;
                let bc =
                    BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(Error::Asn1)?;

                if !bc.ca {
                    return Err(Error::ChainError(crate::error::ChainError::IssuerNotCA));
                }

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

        Err(Error::ChainError(crate::error::ChainError::IssuerNotCA))
    }

    /// Validate path length constraints in the chain.
    fn validate_path_length_constraints(&self, chain: &CertificateChain) -> Result<()> {
        for (idx, cert) in chain.certificates.iter().enumerate().skip(1) {
            let extensions = match &cert.tbs_certificate.extensions {
                Some(exts) => exts,
                None => continue,
            };

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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_options() {
        let opts = ValidationOptions::default();
        assert_eq!(opts.check_time, !cfg!(feature = "no-time-check"));
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
