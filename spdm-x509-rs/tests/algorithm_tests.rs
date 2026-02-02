//! SPDM Algorithm Verification Tests
//!
//! Tests for algorithm verification according to DSP0274 specification:
//! - ECDSA P-256, P-384, P-521 verification
//! - RSA-2048, RSA-3072, RSA-4096 verification
//! - Hash algorithm verification (SHA-256, SHA-384, SHA-512)
//! - Signature algorithm verification

#![cfg(feature = "spdm")]

use const_oid::ObjectIdentifier;
use spdm_x509::spdm::oids;
use spdm_x509::spdm::{
    verify_ecc_curve, verify_hash_algorithm, verify_signature_algorithm, SpdmBaseAsymAlgo,
    SpdmBaseHashAlgo,
};

// =============================================================================
// SpdmBaseAsymAlgo Tests
// =============================================================================

#[test]
fn test_base_asym_algo_from_bits_single() {
    // Test single algorithm
    let bits = 1 << 4; // ECDSA P-256
    let algos = SpdmBaseAsymAlgo::from_bits(bits);
    assert_eq!(algos.len(), 1);
    assert_eq!(algos[0], SpdmBaseAsymAlgo::EcdsaP256);
}

#[test]
fn test_base_asym_algo_from_bits_multiple() {
    // Test multiple algorithms
    let bits = (1 << 0) | (1 << 4) | (1 << 7); // RSA-2048 + ECDSA P-256 + ECDSA P-384
    let algos = SpdmBaseAsymAlgo::from_bits(bits);
    assert_eq!(algos.len(), 3);
    assert!(algos.contains(&SpdmBaseAsymAlgo::RsaSsa2048));
    assert!(algos.contains(&SpdmBaseAsymAlgo::EcdsaP256));
    assert!(algos.contains(&SpdmBaseAsymAlgo::EcdsaP384));
}

#[test]
fn test_base_asym_algo_from_bits_all() {
    // Test all algorithms
    let bits = 0xFFF; // All 12 bits set
    let algos = SpdmBaseAsymAlgo::from_bits(bits);
    assert_eq!(algos.len(), 12);
}

#[test]
fn test_base_asym_algo_from_bits_none() {
    // Test no algorithms
    let bits = 0;
    let algos = SpdmBaseAsymAlgo::from_bits(bits);
    assert_eq!(algos.len(), 0);
}

#[test]
fn test_rsa_key_sizes() {
    assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.rsa_key_size(), Some(2048));
    assert_eq!(SpdmBaseAsymAlgo::RsaPss2048.rsa_key_size(), Some(2048));
    assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.rsa_key_size(), Some(3072));
    assert_eq!(SpdmBaseAsymAlgo::RsaPss3072.rsa_key_size(), Some(3072));
    assert_eq!(SpdmBaseAsymAlgo::RsaSsa4096.rsa_key_size(), Some(4096));
    assert_eq!(SpdmBaseAsymAlgo::RsaPss4096.rsa_key_size(), Some(4096));
}

#[test]
fn test_rsa_key_size_for_non_rsa() {
    // Non-RSA algorithms should return None
    assert_eq!(SpdmBaseAsymAlgo::EcdsaP256.rsa_key_size(), None);
    assert_eq!(SpdmBaseAsymAlgo::EcdsaP384.rsa_key_size(), None);
    assert_eq!(SpdmBaseAsymAlgo::EcdsaP521.rsa_key_size(), None);
    assert_eq!(SpdmBaseAsymAlgo::Ed25519.rsa_key_size(), None);
}

#[test]
fn test_ecc_curve_oids() {
    assert_eq!(
        SpdmBaseAsymAlgo::EcdsaP256.ecc_curve_oid(),
        Some(oids::ECDSA_P256)
    );
    assert_eq!(
        SpdmBaseAsymAlgo::EcdsaP384.ecc_curve_oid(),
        Some(oids::ECDSA_P384)
    );
    assert_eq!(
        SpdmBaseAsymAlgo::EcdsaP521.ecc_curve_oid(),
        Some(oids::ECDSA_P521)
    );
}

#[test]
fn test_ecc_curve_oid_for_non_ecc() {
    // Non-ECC algorithms should return None
    assert_eq!(SpdmBaseAsymAlgo::RsaSsa2048.ecc_curve_oid(), None);
    assert_eq!(SpdmBaseAsymAlgo::RsaSsa3072.ecc_curve_oid(), None);
    assert_eq!(SpdmBaseAsymAlgo::Ed25519.ecc_curve_oid(), None);
}

#[test]
fn test_is_rsa() {
    assert!(SpdmBaseAsymAlgo::RsaSsa2048.is_rsa());
    assert!(SpdmBaseAsymAlgo::RsaPss2048.is_rsa());
    assert!(SpdmBaseAsymAlgo::RsaSsa3072.is_rsa());
    assert!(SpdmBaseAsymAlgo::RsaPss3072.is_rsa());
    assert!(SpdmBaseAsymAlgo::RsaSsa4096.is_rsa());
    assert!(SpdmBaseAsymAlgo::RsaPss4096.is_rsa());

    assert!(!SpdmBaseAsymAlgo::EcdsaP256.is_rsa());
    assert!(!SpdmBaseAsymAlgo::Ed25519.is_rsa());
}

#[test]
fn test_is_ecc() {
    assert!(SpdmBaseAsymAlgo::EcdsaP256.is_ecc());
    assert!(SpdmBaseAsymAlgo::EcdsaP384.is_ecc());
    assert!(SpdmBaseAsymAlgo::EcdsaP521.is_ecc());
    assert!(SpdmBaseAsymAlgo::Sm2P256.is_ecc());

    assert!(!SpdmBaseAsymAlgo::RsaSsa2048.is_ecc());
    assert!(!SpdmBaseAsymAlgo::Ed25519.is_ecc());
}

#[test]
fn test_is_eddsa() {
    assert!(SpdmBaseAsymAlgo::Ed25519.is_eddsa());
    assert!(SpdmBaseAsymAlgo::Ed448.is_eddsa());

    assert!(!SpdmBaseAsymAlgo::EcdsaP256.is_eddsa());
    assert!(!SpdmBaseAsymAlgo::RsaSsa2048.is_eddsa());
}

// =============================================================================
// SpdmBaseHashAlgo Tests
// =============================================================================

#[test]
fn test_base_hash_algo_from_bits_single() {
    let bits = 1 << 0; // SHA-256
    let algos = SpdmBaseHashAlgo::from_bits(bits);
    assert_eq!(algos.len(), 1);
    assert_eq!(algos[0], SpdmBaseHashAlgo::Sha256);
}

#[test]
fn test_base_hash_algo_from_bits_multiple() {
    let bits = (1 << 0) | (1 << 1) | (1 << 2); // SHA-256 + SHA-384 + SHA-512
    let algos = SpdmBaseHashAlgo::from_bits(bits);
    assert_eq!(algos.len(), 3);
    assert!(algos.contains(&SpdmBaseHashAlgo::Sha256));
    assert!(algos.contains(&SpdmBaseHashAlgo::Sha384));
    assert!(algos.contains(&SpdmBaseHashAlgo::Sha512));
}

#[test]
fn test_base_hash_algo_from_bits_all() {
    let bits = 0x7F; // All 7 bits set
    let algos = SpdmBaseHashAlgo::from_bits(bits);
    assert_eq!(algos.len(), 7);
}

#[test]
fn test_base_hash_algo_from_bits_none() {
    let bits = 0;
    let algos = SpdmBaseHashAlgo::from_bits(bits);
    assert_eq!(algos.len(), 0);
}

#[test]
fn test_hash_algo_oids() {
    assert_eq!(SpdmBaseHashAlgo::Sha256.oid(), oids::SHA256);
    assert_eq!(SpdmBaseHashAlgo::Sha384.oid(), oids::SHA384);
    assert_eq!(SpdmBaseHashAlgo::Sha512.oid(), oids::SHA512);
    assert_eq!(SpdmBaseHashAlgo::Sha3_256.oid(), oids::SHA3_256);
    assert_eq!(SpdmBaseHashAlgo::Sha3_384.oid(), oids::SHA3_384);
    assert_eq!(SpdmBaseHashAlgo::Sha3_512.oid(), oids::SHA3_512);
}

#[test]
fn test_hash_algo_oid_strings() {
    assert_eq!(
        SpdmBaseHashAlgo::Sha256.oid().to_string(),
        "2.16.840.1.101.3.4.2.1"
    );
    assert_eq!(
        SpdmBaseHashAlgo::Sha384.oid().to_string(),
        "2.16.840.1.101.3.4.2.2"
    );
    assert_eq!(
        SpdmBaseHashAlgo::Sha512.oid().to_string(),
        "2.16.840.1.101.3.4.2.3"
    );
}

// =============================================================================
// Signature Algorithm Verification Tests
// =============================================================================

#[test]
fn test_verify_signature_algorithm_sha256_with_rsa() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
    let base_asym_algo = 1 << 0; // RSA-2048
    let base_hash_algo = 1 << 0; // SHA-256

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_signature_algorithm_sha384_with_rsa() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"); // sha384WithRSAEncryption
    let base_asym_algo = 1 << 2; // RSA-3072
    let base_hash_algo = 1 << 1; // SHA-384

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_signature_algorithm_sha512_with_rsa() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"); // sha512WithRSAEncryption
    let base_asym_algo = 1 << 5; // RSA-4096
    let base_hash_algo = 1 << 2; // SHA-512

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_signature_algorithm_sha256_with_ecdsa() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
    let base_asym_algo = 1 << 4; // ECDSA P-256
    let base_hash_algo = 1 << 0; // SHA-256

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_signature_algorithm_sha384_with_ecdsa() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"); // ecdsa-with-SHA384
    let base_asym_algo = 1 << 7; // ECDSA P-384
    let base_hash_algo = 1 << 1; // SHA-384

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_signature_algorithm_hash_mismatch() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
    let base_asym_algo = 1 << 0; // RSA-2048
    let base_hash_algo = 1 << 1; // SHA-384 (mismatch!)

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_err());
}

#[test]
fn test_verify_signature_algorithm_unsupported() {
    let sig_algo_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5"); // Unknown algorithm
    let base_asym_algo = 1 << 0;
    let base_hash_algo = 1 << 0;

    let result = verify_signature_algorithm(&sig_algo_oid, base_asym_algo, base_hash_algo);
    assert!(result.is_err());
}

// =============================================================================
// ECC Curve Verification Tests
// =============================================================================

#[test]
fn test_verify_ecc_curve_p256() {
    let base_asym_algo = 1 << 4; // ECDSA P-256
    let result = verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_ecc_curve_p384() {
    let base_asym_algo = 1 << 7; // ECDSA P-384
    let result = verify_ecc_curve(&oids::ECDSA_P384, base_asym_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_ecc_curve_p521() {
    let base_asym_algo = 1 << 8; // ECDSA P-521
    let result = verify_ecc_curve(&oids::ECDSA_P521, base_asym_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_ecc_curve_multiple_algos() {
    let base_asym_algo = (1 << 4) | (1 << 7); // ECDSA P-256 + P-384

    // Both curves should be accepted
    assert!(verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo).is_ok());
    assert!(verify_ecc_curve(&oids::ECDSA_P384, base_asym_algo).is_ok());

    // P-521 should be rejected
    assert!(verify_ecc_curve(&oids::ECDSA_P521, base_asym_algo).is_err());
}

#[test]
fn test_verify_ecc_curve_not_negotiated() {
    let base_asym_algo = 1 << 0; // RSA-2048 (no ECC)
    let result = verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo);
    assert!(result.is_err());
}

// =============================================================================
// Hash Algorithm Verification Tests
// =============================================================================

#[test]
fn test_verify_hash_algorithm_sha256() {
    let base_hash_algo = 1 << 0; // SHA-256
    let result = verify_hash_algorithm(&oids::SHA256, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_hash_algorithm_sha384() {
    let base_hash_algo = 1 << 1; // SHA-384
    let result = verify_hash_algorithm(&oids::SHA384, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_hash_algorithm_sha512() {
    let base_hash_algo = 1 << 2; // SHA-512
    let result = verify_hash_algorithm(&oids::SHA512, base_hash_algo);
    assert!(result.is_ok());
}

#[test]
fn test_verify_hash_algorithm_multiple() {
    let base_hash_algo = (1 << 0) | (1 << 1) | (1 << 2); // SHA-256 + SHA-384 + SHA-512

    assert!(verify_hash_algorithm(&oids::SHA256, base_hash_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA384, base_hash_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA512, base_hash_algo).is_ok());
}

#[test]
fn test_verify_hash_algorithm_not_negotiated() {
    let base_hash_algo = 1 << 0; // SHA-256 only
    let result = verify_hash_algorithm(&oids::SHA384, base_hash_algo);
    assert!(result.is_err());
}

// =============================================================================
// RSA Key Size Verification Tests
// =============================================================================

#[test]
#[ignore] // Requires valid RSA public key DER data
fn test_verify_rsa_key_size_2048() {
    // This test would:
    // 1. Create or load a 2048-bit RSA public key in DER format
    // 2. Verify it against base_asym_algo with RSA-2048 enabled
    // 3. Expect success
}

#[test]
#[ignore] // Requires valid RSA public key DER data
fn test_verify_rsa_key_size_3072() {
    // This test would verify a 3072-bit RSA key
}

#[test]
#[ignore] // Requires valid RSA public key DER data
fn test_verify_rsa_key_size_4096() {
    // This test would verify a 4096-bit RSA key
}

#[test]
#[ignore] // Requires valid RSA public key DER data
fn test_verify_rsa_key_size_mismatch() {
    // This test would:
    // 1. Create a 2048-bit RSA public key
    // 2. Try to verify against base_asym_algo with only RSA-3072 enabled
    // 3. Expect KeyError::WeakKey
}

#[test]
#[ignore] // Requires valid RSA public key DER data
fn test_verify_rsa_key_size_too_small() {
    // This test would:
    // 1. Create a 1024-bit RSA public key (below minimum)
    // 2. Try to verify
    // 3. Expect KeyError::WeakKey
}

// =============================================================================
// Algorithm Combination Tests
// =============================================================================

#[test]
fn test_typical_p256_sha256_combination() {
    // Common combination: ECDSA P-256 with SHA-256
    let base_asym_algo = 1 << 4; // ECDSA P-256
    let base_hash_algo = 1 << 0; // SHA-256

    let sig_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
    assert!(verify_signature_algorithm(&sig_oid, base_asym_algo, base_hash_algo).is_ok());
    assert!(verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA256, base_hash_algo).is_ok());
}

#[test]
fn test_typical_p384_sha384_combination() {
    // Common combination: ECDSA P-384 with SHA-384
    let base_asym_algo = 1 << 7; // ECDSA P-384
    let base_hash_algo = 1 << 1; // SHA-384

    let sig_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"); // ecdsa-with-SHA384
    assert!(verify_signature_algorithm(&sig_oid, base_asym_algo, base_hash_algo).is_ok());
    assert!(verify_ecc_curve(&oids::ECDSA_P384, base_asym_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA384, base_hash_algo).is_ok());
}

#[test]
fn test_typical_rsa3072_sha256_combination() {
    // Common combination: RSA-3072 with SHA-256
    let base_asym_algo = 1 << 2; // RSA-3072
    let base_hash_algo = 1 << 0; // SHA-256

    let sig_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
    assert!(verify_signature_algorithm(&sig_oid, base_asym_algo, base_hash_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA256, base_hash_algo).is_ok());
}

// =============================================================================
// Edge Cases and Error Conditions
// =============================================================================

#[test]
fn test_no_algorithms_negotiated() {
    let base_asym_algo = 0; // No algorithms
    let base_hash_algo = 0; // No algorithms

    // All verifications should fail
    assert!(verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo).is_err());
    assert!(verify_hash_algorithm(&oids::SHA256, base_hash_algo).is_err());
}

#[test]
fn test_all_algorithms_negotiated() {
    let base_asym_algo = 0xFFF; // All asymmetric algorithms
    let base_hash_algo = 0x7F; // All hash algorithms

    // All common verifications should succeed
    assert!(verify_ecc_curve(&oids::ECDSA_P256, base_asym_algo).is_ok());
    assert!(verify_ecc_curve(&oids::ECDSA_P384, base_asym_algo).is_ok());
    assert!(verify_ecc_curve(&oids::ECDSA_P521, base_asym_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA256, base_hash_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA384, base_hash_algo).is_ok());
    assert!(verify_hash_algorithm(&oids::SHA512, base_hash_algo).is_ok());
}
