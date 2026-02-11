// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Cryptographic backend abstraction for signature verification
//!
//! This module provides a trait-based abstraction for different cryptographic backends,
//! allowing x509lib to work with multiple crypto implementations (ring, mbedtls, etc.).

extern crate alloc;

use crate::error::{Error, Result};
use const_oid::ObjectIdentifier;

#[cfg(feature = "ring-backend")]
mod ring;
#[cfg(feature = "ring-backend")]
pub use self::ring::*;

#[cfg(feature = "mbedtls-backend")]
mod mbedtls;
#[cfg(feature = "mbedtls-backend")]
pub use self::mbedtls::*;

/// Signature algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with P-256 curve and SHA-256
    EcdsaP256Sha256,
    /// ECDSA with P-256 curve and SHA-384
    EcdsaP256Sha384,
    /// ECDSA with P-384 curve and SHA-256
    EcdsaP384Sha256,
    /// ECDSA with P-384 curve and SHA-384
    EcdsaP384Sha384,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// RSA PSS with SHA-384
    RsaPssSha384,
    /// RSA PSS with SHA-512
    RsaPssSha512,
}

impl SignatureAlgorithm {
    /// Convert an OID and curve OID to a SignatureAlgorithm
    /// For ECDSA, the curve must be provided from the public key algorithm parameters
    pub fn from_oid_with_curve(
        sig_oid: &ObjectIdentifier,
        curve_oid: Option<&ObjectIdentifier>,
    ) -> Result<Self> {
        // ECDSA with SHA-256
        const ECDSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
        // ECDSA with SHA-384
        const ECDSA_WITH_SHA384: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        // RSA with SHA-256
        const RSA_WITH_SHA256: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        // RSA with SHA-384
        const RSA_WITH_SHA384: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
        // RSA with SHA-512
        const RSA_WITH_SHA512: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
        // RSA PSS
        const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

        // EC curve OIDs
        const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

        match *sig_oid {
            ECDSA_WITH_SHA256 => {
                // Determine curve from public key
                match curve_oid {
                    Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha256),
                    Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha256),
                    _ => Ok(SignatureAlgorithm::EcdsaP256Sha256), // Default to P-256
                }
            }
            ECDSA_WITH_SHA384 => {
                // Determine curve from public key
                match curve_oid {
                    Some(&SECP256R1) => Ok(SignatureAlgorithm::EcdsaP256Sha384),
                    Some(&SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha384),
                    _ => Ok(SignatureAlgorithm::EcdsaP256Sha384), // Default to P-256
                }
            }
            RSA_WITH_SHA256 => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
            RSA_WITH_SHA384 => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
            RSA_WITH_SHA512 => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
            RSA_PSS => {
                // RSA PSS requires parsing algorithm parameters to determine hash
                // For now, we'll default to SHA-256
                Ok(SignatureAlgorithm::RsaPssSha256)
            }
            _ => Err(Error::unsupported_algorithm(alloc::format!(
                "OID: {}", sig_oid
            ))),
        }
    }

    /// Convert an OID to a SignatureAlgorithm (without curve information)
    /// This is a convenience method that calls from_oid_with_curve with None
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        Self::from_oid_with_curve(oid, None)
    }
}

/// Crypto backend trait for signature verification
///
/// Implementations of this trait provide the cryptographic operations needed
/// for X.509 certificate validation, allowing different crypto libraries to be used.
pub trait CryptoBackend {
    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signature algorithm to use
    /// * `tbs_data` - The "to be signed" data (typically the TBS certificate)
    /// * `signature` - The signature bytes (must be in ASN.1 DER format for ECDSA)
    /// * `public_key` - The public key bytes (SubjectPublicKeyInfo format)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the signature is valid
    /// * `Err(Error)` if the signature is invalid or an error occurred
    fn verify_signature(
        &self,
        algorithm: SignatureAlgorithm,
        tbs_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<()>;
}
