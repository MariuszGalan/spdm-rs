//! Cryptographic algorithm definitions and OID mappings for X.509 certificates.
//!
//! This module provides:
//! - OID constants for signature, public key, and hash algorithms
//! - AlgorithmIdentifier struct for parsing DER-encoded algorithm identifiers
//! - SignatureAlgorithm enum matching ring's capabilities
//! - Conversions between OIDs and algorithm types

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use const_oid::ObjectIdentifier;
use core::fmt;
use der::{Decode, Sequence};

// =============================================================================
// Signature Algorithm OIDs (RFC 5480, RFC 4055)
// =============================================================================

/// sha256WithRSAEncryption - RSA signature with SHA-256
/// OID: 1.2.840.113549.1.1.11
pub const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// sha384WithRSAEncryption - RSA signature with SHA-384
/// OID: 1.2.840.113549.1.1.12
pub const SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

/// sha512WithRSAEncryption - RSA signature with SHA-512
/// OID: 1.2.840.113549.1.1.13
pub const SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// ecdsa-with-SHA256 - ECDSA signature with SHA-256
/// OID: 1.2.840.10045.4.3.2
pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA384 - ECDSA signature with SHA-384
/// OID: 1.2.840.10045.4.3.3
pub const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// ecdsa-with-SHA512 - ECDSA signature with SHA-512
/// OID: 1.2.840.10045.4.3.4
pub const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

// =============================================================================
// Public Key Algorithm OIDs
// =============================================================================

/// rsaEncryption - RSA public key
/// OID: 1.2.840.113549.1.1.1
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// id-ecPublicKey - Elliptic Curve public key
/// OID: 1.2.840.10045.2.1
pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// =============================================================================
// Hash Algorithm OIDs
// =============================================================================

/// id-sha256 - SHA-256 hash algorithm
/// OID: 2.16.840.1.101.3.4.2.1
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// id-sha384 - SHA-384 hash algorithm
/// OID: 2.16.840.1.101.3.4.2.2
pub const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// id-sha512 - SHA-512 hash algorithm
/// OID: 2.16.840.1.101.3.4.2.3
pub const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// =============================================================================
// Elliptic Curve OIDs (for EC public keys)
// =============================================================================

/// secp256r1 / prime256v1 / P-256
/// OID: 1.2.840.10045.3.1.7
pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// secp384r1 / P-384
/// OID: 1.3.132.0.34
pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// secp521r1 / P-521
/// OID: 1.3.132.0.35
pub const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

// =============================================================================
// AlgorithmIdentifier Structure
// =============================================================================

/// AlgorithmIdentifier as defined in RFC 5280
///
/// ```text
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///      algorithm               OBJECT IDENTIFIER,
///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID
    pub algorithm: ObjectIdentifier,

    /// Optional algorithm parameters (typically NULL for signature algorithms)
    #[asn1(optional = "true")]
    pub parameters: Option<der::Any>,
}

impl AlgorithmIdentifier {
    /// Create a new AlgorithmIdentifier with the given OID and no parameters
    pub fn new(algorithm: ObjectIdentifier) -> Self {
        Self {
            algorithm,
            parameters: None,
        }
    }

    /// Create a new AlgorithmIdentifier with the given OID and parameters
    pub fn new_with_params(algorithm: ObjectIdentifier, parameters: der::Any) -> Self {
        Self {
            algorithm,
            parameters: Some(parameters),
        }
    }

    /// Parse an AlgorithmIdentifier from DER-encoded bytes
    pub fn from_der(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::decode(&mut der::SliceReader::new(bytes)?)
    }

    /// Convert to a SignatureAlgorithm if this represents a supported signature algorithm
    pub fn to_signature_algorithm(&self) -> Result<SignatureAlgorithm, AlgorithmError> {
        SignatureAlgorithm::from_oid(&self.algorithm)
    }
}

// =============================================================================
// SignatureAlgorithm Enum
// =============================================================================

/// Signature algorithms supported by ring
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaSha256,

    /// RSA PKCS#1 v1.5 with SHA-384
    RsaSha384,

    /// RSA PKCS#1 v1.5 with SHA-512
    RsaSha512,

    /// ECDSA with SHA-256 (P-256, P-384, or P-521 curves)
    EcdsaSha256,

    /// ECDSA with SHA-384 (P-256, P-384, or P-521 curves)
    EcdsaSha384,

    /// ECDSA with SHA-512 (P-256, P-384, or P-521 curves)
    EcdsaSha512,
}

impl SignatureAlgorithm {
    /// Convert an OID to a SignatureAlgorithm
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self, AlgorithmError> {
        match *oid {
            SHA256_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha256),
            SHA384_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha384),
            SHA512_WITH_RSA_ENCRYPTION => Ok(Self::RsaSha512),
            ECDSA_WITH_SHA256 => Ok(Self::EcdsaSha256),
            ECDSA_WITH_SHA384 => Ok(Self::EcdsaSha384),
            ECDSA_WITH_SHA512 => Ok(Self::EcdsaSha512),
            _ => Err(AlgorithmError::UnsupportedAlgorithm(oid.to_string())),
        }
    }

    /// Get the OID for this signature algorithm
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::RsaSha256 => SHA256_WITH_RSA_ENCRYPTION,
            Self::RsaSha384 => SHA384_WITH_RSA_ENCRYPTION,
            Self::RsaSha512 => SHA512_WITH_RSA_ENCRYPTION,
            Self::EcdsaSha256 => ECDSA_WITH_SHA256,
            Self::EcdsaSha384 => ECDSA_WITH_SHA384,
            Self::EcdsaSha512 => ECDSA_WITH_SHA512,
        }
    }

    /// Get the name of this signature algorithm
    pub fn name(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "RSA-SHA256",
            Self::RsaSha384 => "RSA-SHA384",
            Self::RsaSha512 => "RSA-SHA512",
            Self::EcdsaSha256 => "ECDSA-SHA256",
            Self::EcdsaSha384 => "ECDSA-SHA384",
            Self::EcdsaSha512 => "ECDSA-SHA512",
        }
    }

    /// Get the ring verification algorithm for RSA signatures
    pub fn ring_rsa_verification_algorithm(
        &self,
    ) -> Result<&'static ring::signature::RsaParameters, AlgorithmError> {
        match self {
            Self::RsaSha256 => Ok(&ring::signature::RSA_PKCS1_2048_8192_SHA256),
            Self::RsaSha384 => Ok(&ring::signature::RSA_PKCS1_2048_8192_SHA384),
            Self::RsaSha512 => Ok(&ring::signature::RSA_PKCS1_2048_8192_SHA512),
            _ => Err(AlgorithmError::NotRsaAlgorithm),
        }
    }

    /// Get the ring verification algorithm for ECDSA signatures
    pub fn ring_ecdsa_verification_algorithm(
        &self,
    ) -> Result<&'static ring::signature::EcdsaVerificationAlgorithm, AlgorithmError> {
        match self {
            Self::EcdsaSha256 => Ok(&ring::signature::ECDSA_P256_SHA256_ASN1),
            Self::EcdsaSha384 => Ok(&ring::signature::ECDSA_P384_SHA384_ASN1),
            // Note: ring supports ECDSA with P-256 and P-384, but not P-521 with SHA-512
            Self::EcdsaSha512 => Err(AlgorithmError::UnsupportedByRing(
                "ECDSA-SHA512".to_string(),
            )),
            _ => Err(AlgorithmError::NotEcdsaAlgorithm),
        }
    }

    /// Check if this is an RSA algorithm
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512)
    }

    /// Check if this is an ECDSA algorithm
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512
        )
    }

    /// Verify a signature using ring.
    ///
    /// # Arguments
    /// * `message` - The message that was signed (typically the TBS certificate DER)
    /// * `signature` - The signature bytes
    /// * `public_key` - The DER-encoded public key
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), AlgorithmError> {
        use ring::signature;

        if self.is_rsa() {
            // RSA verification
            let params = self.ring_rsa_verification_algorithm()?;
            let public_key = signature::UnparsedPublicKey::new(params, public_key);
            public_key.verify(message, signature).map_err(|_| {
                AlgorithmError::UnsupportedAlgorithm("RSA verification failed".to_string())
            })?;
            Ok(())
        } else if self.is_ecdsa() {
            // ECDSA verification
            let alg = self.ring_ecdsa_verification_algorithm()?;
            let public_key = signature::UnparsedPublicKey::new(alg, public_key);
            public_key.verify(message, signature).map_err(|_| {
                AlgorithmError::UnsupportedAlgorithm("ECDSA verification failed".to_string())
            })?;
            Ok(())
        } else {
            Err(AlgorithmError::UnsupportedAlgorithm(
                "Unknown signature algorithm".to_string(),
            ))
        }
    }
}

// =============================================================================
// Public Key Algorithm Enum
// =============================================================================

/// Public key algorithm types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA public key
    Rsa,

    /// Elliptic Curve public key
    EllipticCurve,
}

impl PublicKeyAlgorithm {
    /// Convert an OID to a PublicKeyAlgorithm
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self, AlgorithmError> {
        match *oid {
            RSA_ENCRYPTION => Ok(Self::Rsa),
            EC_PUBLIC_KEY => Ok(Self::EllipticCurve),
            _ => Err(AlgorithmError::UnsupportedAlgorithm(oid.to_string())),
        }
    }

    /// Get the OID for this public key algorithm
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::Rsa => RSA_ENCRYPTION,
            Self::EllipticCurve => EC_PUBLIC_KEY,
        }
    }
}

// =============================================================================
// Elliptic Curve Identifiers
// =============================================================================

/// Supported elliptic curves
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EllipticCurve {
    /// NIST P-256 / secp256r1 / prime256v1
    P256,

    /// NIST P-384 / secp384r1
    P384,

    /// NIST P-521 / secp521r1
    P521,
}

impl EllipticCurve {
    /// Convert an OID to an EllipticCurve
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self, AlgorithmError> {
        match *oid {
            SECP256R1 => Ok(Self::P256),
            SECP384R1 => Ok(Self::P384),
            SECP521R1 => Ok(Self::P521),
            _ => Err(AlgorithmError::UnsupportedCurve(oid.to_string())),
        }
    }

    /// Get the OID for this elliptic curve
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::P256 => SECP256R1,
            Self::P384 => SECP384R1,
            Self::P521 => SECP521R1,
        }
    }

    /// Get the name of this curve
    pub fn name(&self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors related to algorithm operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmError {
    /// Unsupported algorithm OID
    UnsupportedAlgorithm(String),

    /// Unsupported elliptic curve
    UnsupportedCurve(String),

    /// Algorithm is not supported by ring
    UnsupportedByRing(String),

    /// Algorithm is not an RSA algorithm
    NotRsaAlgorithm,

    /// Algorithm is not an ECDSA algorithm
    NotEcdsaAlgorithm,
}

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(oid) => write!(f, "Unsupported algorithm: {}", oid),
            Self::UnsupportedCurve(oid) => write!(f, "Unsupported elliptic curve: {}", oid),
            Self::UnsupportedByRing(alg) => write!(f, "Algorithm not supported by ring: {}", alg),
            Self::NotRsaAlgorithm => write!(f, "Algorithm is not an RSA algorithm"),
            Self::NotEcdsaAlgorithm => write!(f, "Algorithm is not an ECDSA algorithm"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AlgorithmError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm_from_oid() {
        assert_eq!(
            SignatureAlgorithm::from_oid(&SHA256_WITH_RSA_ENCRYPTION).unwrap(),
            SignatureAlgorithm::RsaSha256
        );
        assert_eq!(
            SignatureAlgorithm::from_oid(&ECDSA_WITH_SHA256).unwrap(),
            SignatureAlgorithm::EcdsaSha256
        );
    }

    #[test]
    fn test_signature_algorithm_to_oid() {
        assert_eq!(
            SignatureAlgorithm::RsaSha256.to_oid(),
            SHA256_WITH_RSA_ENCRYPTION
        );
        assert_eq!(SignatureAlgorithm::EcdsaSha384.to_oid(), ECDSA_WITH_SHA384);
    }

    #[test]
    fn test_signature_algorithm_name() {
        assert_eq!(SignatureAlgorithm::RsaSha256.name(), "RSA-SHA256");
        assert_eq!(SignatureAlgorithm::EcdsaSha512.name(), "ECDSA-SHA512");
    }

    #[test]
    fn test_public_key_algorithm_from_oid() {
        assert_eq!(
            PublicKeyAlgorithm::from_oid(&RSA_ENCRYPTION).unwrap(),
            PublicKeyAlgorithm::Rsa
        );
        assert_eq!(
            PublicKeyAlgorithm::from_oid(&EC_PUBLIC_KEY).unwrap(),
            PublicKeyAlgorithm::EllipticCurve
        );
    }

    #[test]
    fn test_elliptic_curve_from_oid() {
        assert_eq!(
            EllipticCurve::from_oid(&SECP256R1).unwrap(),
            EllipticCurve::P256
        );
        assert_eq!(
            EllipticCurve::from_oid(&SECP384R1).unwrap(),
            EllipticCurve::P384
        );
    }

    #[test]
    fn test_algorithm_identifier_creation() {
        let alg_id = AlgorithmIdentifier::new(SHA256_WITH_RSA_ENCRYPTION);
        assert_eq!(alg_id.algorithm, SHA256_WITH_RSA_ENCRYPTION);
        assert!(alg_id.parameters.is_none());
    }

    #[test]
    fn test_algorithm_identifier_to_signature_algorithm() {
        let alg_id = AlgorithmIdentifier::new(ECDSA_WITH_SHA384);
        assert_eq!(
            alg_id.to_signature_algorithm().unwrap(),
            SignatureAlgorithm::EcdsaSha384
        );
    }

    #[test]
    fn test_is_rsa() {
        assert!(SignatureAlgorithm::RsaSha256.is_rsa());
        assert!(!SignatureAlgorithm::EcdsaSha256.is_rsa());
    }

    #[test]
    fn test_is_ecdsa() {
        assert!(SignatureAlgorithm::EcdsaSha384.is_ecdsa());
        assert!(!SignatureAlgorithm::RsaSha384.is_ecdsa());
    }
}
