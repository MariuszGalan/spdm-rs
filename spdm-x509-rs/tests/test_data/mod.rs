//! Test Data for SPDM Certificate Validation
//!
//! This module contains test certificate data as byte arrays for use in tests.
//! The certificates are based on DSP0274 SPDM specification requirements.

/// Sample ECDSA P-256 DeviceCert certificate (self-signed for testing)
///
/// Certificate details:
/// - Algorithm: ECDSA with SHA-256
/// - Curve: P-256 (secp256r1)
/// - Model: DeviceCert (contains Hardware Identity OID)
/// - EKU: SPDM Responder Auth
/// - Basic Constraints: cA=FALSE
pub const DEVICE_CERT_ECDSA_P256: &[u8] = &[
    // This is a simplified DER-encoded certificate structure
    // In real tests, you would use actual certificates generated with OpenSSL or similar tools
    0x30, 0x82, 0x01, 0xE0, // SEQUENCE, length 480 bytes
    0x30, 0x82, 0x01, 0x86, // tbsCertificate SEQUENCE
    0xA0, 0x03, 0x02, 0x01, 0x02, // version [0] EXPLICIT Version (v3)
    0x02, 0x01, 0x01, // serialNumber INTEGER 1
];

/// Sample SPDM certificate chain with header
///
/// Format:
/// - 4 bytes: header (length + reserved)
/// - 32 bytes: SHA-256 root hash
/// - Remaining: concatenated DER certificates
pub const SPDM_CERT_CHAIN_SAMPLE: &[u8] = &[
    // Header
    0x00, 0x02, // length = 512 (little-endian)
    0x00, 0x00, // reserved
    // SHA-256 root hash (32 bytes of zeros for testing)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Valid SPDM Requester Auth OID in DER encoding
pub const SPDM_REQUESTER_AUTH_DER: &[u8] = &[
    0x06, 0x0B, // OID tag, length 11
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, // 1.3.6.1.4.1.412.274.1
];

/// Valid SPDM Responder Auth OID in DER encoding
pub const SPDM_RESPONDER_AUTH_DER: &[u8] = &[
    0x06, 0x0B, // OID tag, length 11
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x03, // 1.3.6.1.4.1.412.274.3
];

/// Hardware Identity OID in DER encoding
pub const HARDWARE_IDENTITY_DER: &[u8] = &[
    0x06, 0x0B, // OID tag, length 11
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x04, // 1.3.6.1.4.1.412.274.4
];

/// Minimal valid DER certificate structure for parsing tests
///
/// This is a bare minimum X.509 v3 certificate that can be parsed.
/// Real certificates would be much larger and include all required fields.
pub fn minimal_cert_template() -> Vec<u8> {
    vec![
        0x30, 0x82, 0x01, 0x00, // SEQUENCE (Certificate)
        // tbsCertificate
        0x30, 0x81, 0xFD, // SEQUENCE
        0xA0, 0x03, 0x02, 0x01, 0x02, // version [0] EXPLICIT Version (v3 = 2)
        0x02, 0x01,
        0x01, // serialNumber INTEGER 1
              // ... additional fields would follow in a real certificate
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_constants_are_not_empty() {
        assert!(!DEVICE_CERT_ECDSA_P256.is_empty());
        assert!(!SPDM_REQUESTER_AUTH_DER.is_empty());
        assert!(!SPDM_RESPONDER_AUTH_DER.is_empty());
        assert!(!HARDWARE_IDENTITY_DER.is_empty());
    }

    #[test]
    fn test_spdm_chain_header_structure() {
        assert_eq!(SPDM_CERT_CHAIN_SAMPLE[0], 0x00);
        assert_eq!(SPDM_CERT_CHAIN_SAMPLE[1], 0x02);
        assert_eq!(SPDM_CERT_CHAIN_SAMPLE[2], 0x00); // reserved
        assert_eq!(SPDM_CERT_CHAIN_SAMPLE[3], 0x00); // reserved
    }

    #[test]
    fn test_minimal_cert_template() {
        let cert = minimal_cert_template();
        assert!(!cert.is_empty());
        assert_eq!(cert[0], 0x30); // SEQUENCE tag
    }
}
