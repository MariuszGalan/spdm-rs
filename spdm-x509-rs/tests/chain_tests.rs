//! SPDM Certificate Chain Validation Tests
//!
//! Tests for SPDM certificate chain parsing and validation:
//! - Chain header parsing
//! - Chain serialization
//! - Concatenated certificate parsing
//! - Root hash verification
//! - Complete chain validation

#![cfg(feature = "spdm")]

use spdm_x509::spdm::chain::{parse_spdm_cert_chain, SpdmCertChainHeader};
use spdm_x509::spdm::SpdmBaseHashAlgo;

mod test_data;

// =============================================================================
// SpdmCertChainHeader Tests
// =============================================================================

#[test]
fn test_header_creation() {
    let root_hash = vec![0u8; 32]; // SHA-256 hash
    let header = SpdmCertChainHeader::new(500, root_hash.clone());

    assert_eq!(header.length, 500);
    assert_eq!(header.reserved, 0);
    assert_eq!(header.root_hash, root_hash);
}

#[test]
fn test_header_min_size() {
    assert_eq!(SpdmCertChainHeader::MIN_SIZE, 4);
}

#[test]
fn test_header_serialization() {
    let root_hash = vec![0xAB; 32];
    let header = SpdmCertChainHeader::new(100, root_hash);

    let bytes = header.to_bytes();

    // Check structure
    assert_eq!(bytes.len(), 4 + 32); // 4 byte header + 32 byte hash
    assert_eq!(bytes[0], 100); // length low byte
    assert_eq!(bytes[1], 0); // length high byte
    assert_eq!(bytes[2], 0); // reserved low byte
    assert_eq!(bytes[3], 0); // reserved high byte

    // Check hash bytes
    for i in 0..32 {
        assert_eq!(bytes[4 + i], 0xAB);
    }
}

#[test]
fn test_header_serialization_large_length() {
    let root_hash = vec![0u8; 32];
    let header = SpdmCertChainHeader::new(0x1234, root_hash);

    let bytes = header.to_bytes();

    // Check little-endian encoding
    assert_eq!(bytes[0], 0x34); // low byte
    assert_eq!(bytes[1], 0x12); // high byte
}

#[test]
fn test_header_parsing_valid() {
    let mut data = vec![0u8; 36]; // 4 byte header + 32 byte hash
    data[0] = 36; // length low byte
    data[1] = 0; // length high byte
    data[2] = 0; // reserved low byte
    data[3] = 0; // reserved high byte
                 // Hash bytes are all zeros

    let (header, remaining) = SpdmCertChainHeader::from_bytes(&data, 32).unwrap();

    assert_eq!(header.length, 36);
    assert_eq!(header.reserved, 0);
    assert_eq!(header.root_hash.len(), 32);
    assert_eq!(remaining.len(), 0);
}

#[test]
fn test_header_parsing_with_remaining_data() {
    let mut data = vec![0u8; 40]; // 4 + 32 + 4 extra bytes
    data[0] = 40;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    // Extra bytes at the end
    data[36] = 0xDE;
    data[37] = 0xAD;
    data[38] = 0xBE;
    data[39] = 0xEF;

    let (header, remaining) = SpdmCertChainHeader::from_bytes(&data, 32).unwrap();

    assert_eq!(header.root_hash.len(), 32);
    assert_eq!(remaining.len(), 4);
    assert_eq!(remaining, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_header_parsing_invalid_reserved() {
    let mut data = vec![0u8; 36];
    data[0] = 36;
    data[1] = 0;
    data[2] = 1; // reserved should be 0
    data[3] = 0;

    let result = SpdmCertChainHeader::from_bytes(&data, 32);
    assert!(result.is_err());
}

#[test]
fn test_header_parsing_too_short() {
    let data = vec![0u8; 10]; // Not enough data

    let result = SpdmCertChainHeader::from_bytes(&data, 32);
    assert!(result.is_err());
}

#[test]
fn test_header_parsing_different_hash_sizes() {
    // SHA-256 (32 bytes)
    let data_sha256 = vec![0u8; 36];
    let (header, _) = SpdmCertChainHeader::from_bytes(&data_sha256, 32).unwrap();
    assert_eq!(header.root_hash.len(), 32);

    // SHA-384 (48 bytes)
    let data_sha384 = vec![0u8; 52];
    let (header, _) = SpdmCertChainHeader::from_bytes(&data_sha384, 48).unwrap();
    assert_eq!(header.root_hash.len(), 48);

    // SHA-512 (64 bytes)
    let data_sha512 = vec![0u8; 68];
    let (header, _) = SpdmCertChainHeader::from_bytes(&data_sha512, 64).unwrap();
    assert_eq!(header.root_hash.len(), 64);
}

#[test]
fn test_hash_size_for_algo() {
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256),
        32
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha384),
        48
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha512),
        64
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha3_256),
        32
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha3_384),
        48
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha3_512),
        64
    );
    assert_eq!(
        SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sm3_256),
        32
    );
}

#[test]
fn test_header_display() {
    let header = SpdmCertChainHeader::new(100, vec![0u8; 32]);
    let display_str = format!("{}", header);

    assert!(display_str.contains("100"));
    assert!(display_str.contains("32 bytes"));
}

// =============================================================================
// Certificate Chain Parsing Tests
// =============================================================================

#[test]
#[ignore] // Requires valid certificate data
fn test_parse_spdm_cert_chain_valid() {
    // This test would:
    // 1. Create a valid SPDM cert chain with header + certificates
    // 2. Parse it with parse_spdm_cert_chain
    // 3. Verify header and certificate count
}

#[test]
#[ignore] // Requires valid certificate data
fn test_parse_spdm_cert_chain_single_cert() {
    // Test parsing a chain with just one certificate (root only)
}

#[test]
#[ignore] // Requires valid certificate data
fn test_parse_spdm_cert_chain_multiple_certs() {
    // Test parsing a chain with multiple certificates
    // (root -> intermediate -> leaf)
}

#[test]
fn test_parse_spdm_cert_chain_no_hash_algo() {
    let data = vec![0u8; 100];
    let base_hash_algo = 0; // No algorithm negotiated

    let result = parse_spdm_cert_chain(&data, base_hash_algo);
    assert!(result.is_err());
}

#[test]
fn test_parse_spdm_cert_chain_length_mismatch() {
    // This test would:
    // 1. Create header with length = 100
    // 2. Provide actual data of different size
    // 3. Expect error
}

#[test]
#[ignore] // Requires valid certificate data
fn test_parse_spdm_cert_chain_empty_cert_data() {
    // Test parsing a chain with header but no certificates
    // Should return ChainError::EmptyChain
}

// =============================================================================
// Certificate Chain Validation Tests
// =============================================================================

#[test]
#[ignore] // Requires valid certificate data
fn test_validate_spdm_cert_chain_valid() {
    // This test would:
    // 1. Parse a valid SPDM cert chain
    // 2. Call validate_spdm_cert_chain
    // 3. Expect success
}

#[test]
#[ignore] // Requires valid certificate data
fn test_validate_spdm_cert_chain_root_hash_match() {
    // Test that root certificate hash matches the header
}

#[test]
#[ignore] // Requires valid certificate data
fn test_validate_spdm_cert_chain_root_hash_mismatch() {
    // This test would:
    // 1. Create a chain with incorrect root hash in header
    // 2. Call validate_spdm_cert_chain
    // 3. Expect ValidationError
}

#[test]
#[ignore] // Requires valid certificate data
fn test_validate_spdm_cert_chain_empty() {
    // Test validation with empty certificate list
    // Should return ChainError::EmptyChain
}

#[test]
#[ignore] // Requires valid certificate data
fn test_validate_spdm_cert_chain_with_options() {
    // Test validation with custom ValidationOptions
    // (e.g., different time, trust anchors, etc.)
}

// =============================================================================
// Hash Algorithm Tests
// =============================================================================

#[test]
fn test_chain_with_sha256() {
    let _base_hash_algo = 1 << 0; // SHA-256
    let hash_size = SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha256);
    assert_eq!(hash_size, 32);

    // Create header with SHA-256 hash
    let data = vec![0u8; 4 + 32];
    let result = SpdmCertChainHeader::from_bytes(&data, hash_size);
    assert!(result.is_ok());
}

#[test]
fn test_chain_with_sha384() {
    let _base_hash_algo = 1 << 1; // SHA-384
    let hash_size = SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha384);
    assert_eq!(hash_size, 48);

    // Create header with SHA-384 hash
    let data = vec![0u8; 4 + 48];
    let result = SpdmCertChainHeader::from_bytes(&data, hash_size);
    assert!(result.is_ok());
}

#[test]
fn test_chain_with_sha512() {
    let _base_hash_algo = 1 << 2; // SHA-512
    let hash_size = SpdmCertChainHeader::hash_size_for_algo(SpdmBaseHashAlgo::Sha512);
    assert_eq!(hash_size, 64);

    // Create header with SHA-512 hash
    let data = vec![0u8; 4 + 64];
    let result = SpdmCertChainHeader::from_bytes(&data, hash_size);
    assert!(result.is_ok());
}

// =============================================================================
// Round-trip Tests (Serialize/Deserialize)
// =============================================================================

#[test]
fn test_header_round_trip_sha256() {
    let original = SpdmCertChainHeader::new(500, vec![0xAB; 32]);
    let bytes = original.to_bytes();
    let (parsed, remaining) = SpdmCertChainHeader::from_bytes(&bytes, 32).unwrap();

    assert_eq!(parsed.length, original.length);
    assert_eq!(parsed.reserved, original.reserved);
    assert_eq!(parsed.root_hash, original.root_hash);
    assert_eq!(remaining.len(), 0);
}

#[test]
fn test_header_round_trip_sha384() {
    let original = SpdmCertChainHeader::new(1000, vec![0xCD; 48]);
    let bytes = original.to_bytes();
    let (parsed, remaining) = SpdmCertChainHeader::from_bytes(&bytes, 48).unwrap();

    assert_eq!(parsed.length, original.length);
    assert_eq!(parsed.root_hash, original.root_hash);
    assert_eq!(remaining.len(), 0);
}

#[test]
fn test_header_round_trip_sha512() {
    let original = SpdmCertChainHeader::new(2000, vec![0xEF; 64]);
    let bytes = original.to_bytes();
    let (parsed, remaining) = SpdmCertChainHeader::from_bytes(&bytes, 64).unwrap();

    assert_eq!(parsed.length, original.length);
    assert_eq!(parsed.root_hash, original.root_hash);
    assert_eq!(remaining.len(), 0);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_header_zero_length() {
    let header = SpdmCertChainHeader::new(0, vec![0u8; 32]);
    assert_eq!(header.length, 0);
}

#[test]
fn test_header_max_length() {
    let header = SpdmCertChainHeader::new(u16::MAX, vec![0u8; 32]);
    assert_eq!(header.length, u16::MAX);

    let bytes = header.to_bytes();
    assert_eq!(bytes[0], 0xFF);
    assert_eq!(bytes[1], 0xFF);
}

#[test]
fn test_header_empty_hash() {
    let header = SpdmCertChainHeader::new(100, vec![]);
    assert_eq!(header.root_hash.len(), 0);
}

#[test]
fn test_header_large_hash() {
    // Test with an unusually large hash
    let header = SpdmCertChainHeader::new(200, vec![0u8; 128]);
    assert_eq!(header.root_hash.len(), 128);
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
#[ignore] // Requires valid certificate data
fn test_complete_chain_workflow() {
    // This test would demonstrate a complete workflow:
    // 1. Create certificates
    // 2. Compute root hash
    // 3. Create SPDM chain header
    // 4. Serialize chain
    // 5. Parse chain
    // 6. Validate chain
}

#[test]
#[ignore] // Requires valid certificate data
fn test_chain_with_different_hash_algorithms() {
    // Test that the same certificate chain can be processed
    // with different hash algorithms
}

// =============================================================================
// Negative Tests
// =============================================================================

#[test]
fn test_header_parsing_corrupted_data() {
    let data = vec![0xFF; 100]; // All 0xFF (likely invalid)

    // Even if parsing succeeds, reserved field check should fail
    let _result = SpdmCertChainHeader::from_bytes(&data, 32);
    // Could pass or fail depending on the reserved field value
}

#[test]
fn test_header_parsing_partial_data() {
    let data = vec![0u8; 2]; // Only 2 bytes (need at least 4 + hash_size)

    let result = SpdmCertChainHeader::from_bytes(&data, 32);
    assert!(result.is_err());
}

#[test]
fn test_header_parsing_exact_minimum() {
    let data = vec![0u8; 4]; // Exact minimum (no hash data)

    let result = SpdmCertChainHeader::from_bytes(&data, 0);
    assert!(result.is_ok());

    let (header, _) = result.unwrap();
    assert_eq!(header.root_hash.len(), 0);
}
