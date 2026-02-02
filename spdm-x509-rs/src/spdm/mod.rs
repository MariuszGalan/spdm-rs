//! SPDM (Security Protocol and Data Model) support
//!
//! This module provides SPDM-specific certificate validation according to
//! DMTF DSP0274 specification.
//!
//! # Features
//! - SPDM certificate chain parsing and validation
//! - Algorithm negotiation support (hash and asymmetric algorithms)
//! - Certificate role verification (Requester/Responder)
//! - RFC7250 raw public key support
//! - Direct compatibility with spdmlib interfaces

pub mod algorithm_verification;
pub mod chain;
pub mod oids;
pub mod validator;

// Re-export main types
pub use algorithm_verification::{
    verify_ecc_curve, verify_hash_algorithm, verify_rsa_key_size, verify_signature,
    verify_signature_algorithm, SpdmBaseAsymAlgo, SpdmBaseHashAlgo,
};
pub use chain::{
    get_cert_from_cert_chain, parse_spdm_cert_chain, validate_spdm_cert_chain, verify_cert_chain,
    SpdmCertChainHeader,
};
pub use validator::{SpdmCertificateModel, SpdmCertificateRole, SpdmValidator};

// Re-export OIDs for convenience
pub use oids::*;
