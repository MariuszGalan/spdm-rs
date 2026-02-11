// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! X.509 Certificate Validator
//!
//! A no_std compatible X.509 certificate validator for system usage.
//! Uses `der` crate for ASN.1 parsing and `ring` for cryptographic operations.
//!
//! # Features
//! - Parse X.509 v3 certificates from DER/PEM
//! - Validate certificate signatures using RSA and ECDSA
//! - Check validity periods
//! - Process and validate extensions (Basic Constraints, Key Usage, etc.)
//! - Certificate chain validation
//!
//! # Example
//! ```no_run
//! use spdm_x509::{Certificate, Validator, ValidationOptions};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cert_der = include_bytes!("../examples/test_cert.der");
//! let cert = Certificate::from_der(cert_der)?;
//!
//! let validator = Validator::new();
//! let options = ValidationOptions::default();
//! validator.validate(&cert, &options)?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod algorithms;
pub mod certificate;
pub mod error;
pub mod extensions;
pub mod name;
pub mod time_utils;
pub mod validator;

#[cfg(feature = "spdm")]
pub mod spdm;

pub use certificate::Certificate;
pub use error::{Error, Result};
pub use extensions::{BasicConstraints, ExtendedKeyUsage, Extension, Extensions, KeyUsage};
pub use validator::{CertificateChain, ValidationOptions, Validator};

#[cfg(feature = "spdm")]
pub use spdm::{
    parse_spdm_cert_chain, validate_spdm_cert_chain, SpdmBaseAsymAlgo, SpdmBaseHashAlgo,
    SpdmCertificateModel, SpdmCertificateRole, SpdmValidator,
};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{Certificate, Error, Result, ValidationOptions, Validator};

    #[cfg(feature = "spdm")]
    pub use crate::spdm::{SpdmCertificateModel, SpdmCertificateRole, SpdmValidator};
}

/// Re-exports for spdmlib compatibility
///
/// This module provides direct compatibility with spdmlib (spdm-rs) interfaces.
/// It re-exports functions that match spdmlib's expected signatures for:
/// - Certificate chain parsing: `get_cert_from_cert_chain`
/// - Certificate chain validation: `verify_cert_chain`
/// - Signature verification: `verify_signature`
///
/// # Usage in spdm-rs
/// ```ignore
/// use spdm_x509::spdmlib::{get_cert_from_cert_chain, verify_cert_chain, verify_signature};
///
/// // Parse certificate from chain
/// let (offset, len) = get_cert_from_cert_chain(cert_chain, -1)?;
/// let leaf_cert = &cert_chain[offset..offset+len];
///
/// // Verify entire chain
/// verify_cert_chain(cert_chain)?;
///
/// // Verify signature
/// verify_signature(hash_algo, asym_algo, cert, data, signature)?;
/// ```
#[cfg(feature = "spdm")]
pub mod spdmlib {
    // Re-export certificate chain functions
    pub use crate::spdm::chain::{get_cert_from_cert_chain, verify_cert_chain};

    // Re-export signature verification
    pub use crate::spdm::algorithm_verification::verify_signature;

    // Re-export SPDM algorithm types (needed by verify_signature)
    pub use crate::spdm::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo};

    // Re-export SPDM validator for advanced usage
    pub use crate::spdm::SpdmValidator;
}
