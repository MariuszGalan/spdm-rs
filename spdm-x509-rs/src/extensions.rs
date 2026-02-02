//! X.509 v3 Certificate Extensions.
//!
//! This module provides support for parsing and validating X.509 v3 extensions
//! as defined in RFC 5280. Extensions provide additional information about the
//! certificate and its usage.
//!
//! # Common Extensions
//!
//! - Basic Constraints - Identifies whether the subject is a CA
//! - Key Usage - Defines the purpose of the key
//! - Extended Key Usage - Defines extended purposes
//! - Subject Alternative Name - Alternative names for the subject
//! - Authority Key Identifier - Identifies the issuing CA's public key
//! - Subject Key Identifier - Identifies the subject's public key
//!
//! # Example
//!
//! ```ignore
//! use spdm_x509::extensions::{Extension, BasicConstraints};
//!
//! // Parse an extension
//! let ext = Extension::from_der(der_bytes)?;
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use const_oid::ObjectIdentifier;
use der::{Decode, DecodeValue, Encode, Header, Reader, Sequence};

// Re-export Extension and Extensions from certificate module
pub use crate::certificate::{Extension, Extensions};

// ============================================================================
// Extension OIDs - RFC 5280 Section 4.2
// ============================================================================

/// Basic Constraints - 2.5.29.19
pub const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// Key Usage - 2.5.29.15
pub const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// Extended Key Usage - 2.5.29.37
pub const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Subject Alternative Name - 2.5.29.17
pub const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// Authority Key Identifier - 2.5.29.35
pub const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// Subject Key Identifier - 2.5.29.14
pub const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

// ============================================================================
// SPDM Extension OIDs - DSP0274 (DMTF SPDM Specification)
// ============================================================================
// Re-exported from spdm::oids when SPDM feature is enabled
#[cfg(feature = "spdm")]
pub use crate::spdm::oids::{
    DEVICE_INFO, DMTF_BASE, HARDWARE_IDENTITY, MUTABLE_CERTIFICATE, SPDM_BASE, SPDM_EXTENSION,
    SPDM_REQUESTER_AUTH, SPDM_RESPONDER_AUTH,
};

// ============================================================================
// Basic Constraints - RFC 5280 Section 4.2.1.9
// ============================================================================

/// Basic Constraints extension.
///
/// ```asn1
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct BasicConstraints {
    /// Whether the subject is a CA
    #[asn1(default = "default_false")]
    pub ca: bool,

    /// Maximum depth of valid certification paths
    #[asn1(optional = "true")]
    pub path_len_constraint: Option<u32>,
}

fn default_false() -> bool {
    false
}

impl BasicConstraints {
    /// Create a new BasicConstraints for a non-CA certificate
    pub fn new_end_entity() -> Self {
        Self {
            ca: false,
            path_len_constraint: None,
        }
    }

    /// Create a new BasicConstraints for a CA certificate
    pub fn new_ca(path_len: Option<u32>) -> Self {
        Self {
            ca: true,
            path_len_constraint: path_len,
        }
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }
}

// ============================================================================
// Key Usage - RFC 5280 Section 4.2.1.3
// ============================================================================

/// Key Usage bit flags.
///
/// ```asn1
/// KeyUsage ::= BIT STRING {
///     digitalSignature        (0),
///     nonRepudiation          (1),
///     keyEncipherment         (2),
///     dataEncipherment        (3),
///     keyAgreement            (4),
///     keyCertSign             (5),
///     cRLSign                 (6),
///     encipherOnly            (7),
///     decipherOnly            (8)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    /// Digital signature
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// Non-repudiation (content commitment)
    pub const NON_REPUDIATION: u16 = 1 << 1;
    /// Key encipherment
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    /// Data encipherment
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    /// Key agreement
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    /// Certificate signing
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    /// CRL signing
    pub const CRL_SIGN: u16 = 1 << 6;
    /// Encipher only
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    /// Decipher only
    pub const DECIPHER_ONLY: u16 = 1 << 8;

    /// Create a new KeyUsage from bit flags
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }

    /// Check if a specific usage is enabled
    pub fn has(&self, usage: u16) -> bool {
        (self.bits & usage) != 0
    }

    /// Parse from DER-encoded BIT STRING
    pub fn from_der(bytes: &[u8]) -> Result<Self, der::Error> {
        let bit_string = der::asn1::BitString::from_der(bytes)?;
        let raw_bytes = bit_string.raw_bytes();

        let bits = match raw_bytes.len() {
            1 => u16::from_be_bytes([0, raw_bytes[0]]),
            2 => u16::from_be_bytes([raw_bytes[0], raw_bytes[1]]),
            _ => 0,
        };

        Ok(Self { bits })
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut usages = Vec::new();
        if self.has(Self::DIGITAL_SIGNATURE) {
            usages.push("digitalSignature");
        }
        if self.has(Self::NON_REPUDIATION) {
            usages.push("nonRepudiation");
        }
        if self.has(Self::KEY_ENCIPHERMENT) {
            usages.push("keyEncipherment");
        }
        if self.has(Self::DATA_ENCIPHERMENT) {
            usages.push("dataEncipherment");
        }
        if self.has(Self::KEY_AGREEMENT) {
            usages.push("keyAgreement");
        }
        if self.has(Self::KEY_CERT_SIGN) {
            usages.push("keyCertSign");
        }
        if self.has(Self::CRL_SIGN) {
            usages.push("cRLSign");
        }
        if self.has(Self::ENCIPHER_ONLY) {
            usages.push("encipherOnly");
        }
        if self.has(Self::DECIPHER_ONLY) {
            usages.push("decipherOnly");
        }

        write!(f, "{}", usages.join(", "))
    }
}

// ============================================================================
// Extended Key Usage - RFC 5280 Section 4.2.1.12
// ============================================================================

/// Extended Key Usage OIDs
pub mod extended_key_usage_oids {
    use const_oid::ObjectIdentifier;

    /// TLS Web Server Authentication - 1.3.6.1.5.5.7.3.1
    pub const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    /// TLS Web Client Authentication - 1.3.6.1.5.5.7.3.2
    pub const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

    /// Code Signing - 1.3.6.1.5.5.7.3.3
    pub const CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

    /// Email Protection - 1.3.6.1.5.5.7.3.4
    pub const EMAIL_PROTECTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");

    /// Time Stamping - 1.3.6.1.5.5.7.3.8
    pub const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

    /// OCSP Signing - 1.3.6.1.5.5.7.3.9
    pub const OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
}

/// Extended Key Usage extension.
///
/// ```asn1
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
/// KeyPurposeId ::= OBJECT IDENTIFIER
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKeyUsage {
    /// List of key purpose OIDs
    pub key_purposes: Vec<ObjectIdentifier>,
}

// Manual Decode implementation for SEQUENCE OF
impl<'a> DecodeValue<'a> for ExtendedKeyUsage {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let mut key_purposes = Vec::new();
            while !reader.is_finished() {
                key_purposes.push(ObjectIdentifier::decode(reader)?);
            }
            Ok(Self { key_purposes })
        })
    }
}

// Manual Encode implementation for SEQUENCE OF
impl Encode for ExtendedKeyUsage {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let mut len = der::Length::ZERO;
        for oid in &self.key_purposes {
            len = (len + oid.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        for oid in &self.key_purposes {
            oid.encode(encoder)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ExtendedKeyUsage {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::decode(reader)?;
        Self::decode_value(reader, header)
    }
}

impl ExtendedKeyUsage {
    /// Create a new ExtendedKeyUsage
    pub fn new(key_purposes: Vec<ObjectIdentifier>) -> Self {
        Self { key_purposes }
    }

    /// Parse from the extension value bytes
    pub fn from_extension(ext: &Extension) -> Result<Self, der::Error> {
        Self::from_der(ext.value())
    }

    /// Check if a specific purpose is present
    pub fn has_purpose(&self, oid: &ObjectIdentifier) -> bool {
        self.key_purposes.iter().any(|p| p == oid)
    }

    /// Check if this certificate can be used for TLS server authentication
    pub fn is_server_auth(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::SERVER_AUTH)
    }

    /// Check if this certificate can be used for TLS client authentication
    pub fn is_client_auth(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::CLIENT_AUTH)
    }

    /// Check if this certificate can be used for code signing
    pub fn is_code_signing(&self) -> bool {
        self.has_purpose(&extended_key_usage_oids::CODE_SIGNING)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_constraints() {
        let bc_ee = BasicConstraints::new_end_entity();
        assert!(!bc_ee.ca);
        assert_eq!(bc_ee.path_len_constraint, None);

        let bc_ca = BasicConstraints::new_ca(Some(3));
        assert!(bc_ca.ca);
        assert_eq!(bc_ca.path_len_constraint, Some(3));
    }

    #[test]
    fn test_key_usage() {
        let ku = KeyUsage::new(
            KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT | KeyUsage::KEY_CERT_SIGN,
        );

        assert!(ku.has(KeyUsage::DIGITAL_SIGNATURE));
        assert!(ku.has(KeyUsage::KEY_ENCIPHERMENT));
        assert!(ku.has(KeyUsage::KEY_CERT_SIGN));
        assert!(!ku.has(KeyUsage::CRL_SIGN));
        assert!(!ku.has(KeyUsage::DATA_ENCIPHERMENT));
    }

    #[test]
    fn test_extended_key_usage() {
        let eku = ExtendedKeyUsage::new(vec![
            extended_key_usage_oids::SERVER_AUTH,
            extended_key_usage_oids::CLIENT_AUTH,
        ]);

        assert!(eku.is_server_auth());
        assert!(eku.is_client_auth());
        assert!(!eku.is_code_signing());
    }
}
