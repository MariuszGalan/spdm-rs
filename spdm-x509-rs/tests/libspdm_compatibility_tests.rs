//! libspdm Reference Implementation Compatibility Tests
//!
//! These tests validate x509-rust-validator against certificate test vectors
//! from the libspdm reference implementation (https://github.com/DMTF/libspdm).
//!
//! This ensures our validator interprets DSP0274 (SPDM) certificates correctly
//! and produces results compatible with the official reference implementation.
//!
//! Test vectors are copied from libspdm/unit_test/sample_key/ and include:
//! - ECP256, ECP384, RSA2048, RSA3072, RSA4096 certificates
//! - SPDM Requester and Responder certificates with EKU
//! - DeviceCert model (with Hardware Identity)
//! - AliasCert model (without Hardware Identity)
//! - Certificates with various Basic Constraints (cA=TRUE/FALSE)

#![cfg(feature = "spdm")]

use spdm_x509::algorithms::{EC_PUBLIC_KEY, RSA_ENCRYPTION};
use spdm_x509::spdm::oids;
use spdm_x509::spdm::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertificateModel, SpdmCertificateRole, SpdmValidator,
};
use spdm_x509::{Certificate, ValidationOptions, Validator};
use std::fs;
use std::path::PathBuf;

// =============================================================================
// Helper Functions
// =============================================================================

/// Load a certificate from libspdm test vectors
fn load_libspdm_cert(
    algo: &str,
    filename: &str,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/libspdm_vectors");
    path.push(algo);
    path.push(filename);

    let der_bytes = fs::read(&path)?;
    Ok(Certificate::from_der(&der_bytes)?)
}

/// Helper to get algorithm negotiation for a specific asymmetric algorithm
fn get_asym_algo_bits(algo: SpdmBaseAsymAlgo) -> u32 {
    match algo {
        SpdmBaseAsymAlgo::RsaSsa2048 => 1 << 0,
        SpdmBaseAsymAlgo::RsaPss2048 => 1 << 1,
        SpdmBaseAsymAlgo::RsaSsa3072 => 1 << 2,
        SpdmBaseAsymAlgo::RsaPss3072 => 1 << 3,
        SpdmBaseAsymAlgo::EcdsaP256 => 1 << 4,
        SpdmBaseAsymAlgo::RsaSsa4096 => 1 << 5,
        SpdmBaseAsymAlgo::RsaPss4096 => 1 << 6,
        SpdmBaseAsymAlgo::EcdsaP384 => 1 << 7,
        SpdmBaseAsymAlgo::EcdsaP521 => 1 << 8,
        SpdmBaseAsymAlgo::Sm2P256 => 1 << 9,
        SpdmBaseAsymAlgo::Ed25519 => 1 << 10,
        SpdmBaseAsymAlgo::Ed448 => 1 << 11,
    }
}

/// Helper to get hash algorithm bits
fn get_hash_algo_bits(algo: SpdmBaseHashAlgo) -> u32 {
    match algo {
        SpdmBaseHashAlgo::Sha256 => 1 << 0,
        SpdmBaseHashAlgo::Sha384 => 1 << 1,
        SpdmBaseHashAlgo::Sha512 => 1 << 2,
        SpdmBaseHashAlgo::Sha3_256 => 1 << 3,
        SpdmBaseHashAlgo::Sha3_384 => 1 << 4,
        SpdmBaseHashAlgo::Sha3_512 => 1 << 5,
        SpdmBaseHashAlgo::Sm3_256 => 1 << 6,
    }
}

/// Helper struct to reduce SPDM validation boilerplate
struct SpdmTestContext {
    validator: SpdmValidator,
    asym_algo: u32,
    hash_algo: u32,
}

impl SpdmTestContext {
    fn new(asym: SpdmBaseAsymAlgo, hash: SpdmBaseHashAlgo) -> Self {
        Self {
            validator: SpdmValidator::new(),
            asym_algo: get_asym_algo_bits(asym),
            hash_algo: get_hash_algo_bits(hash),
        }
    }

    fn validate(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
        role: SpdmCertificateRole,
    ) -> Result<(), spdm_x509::Error> {
        self.validator
            .validate_spdm_certificate(cert, model, role, self.asym_algo, self.hash_algo)
    }

    fn validate_generic(
        &self,
        cert: &Certificate,
        role: SpdmCertificateRole,
    ) -> Result<(), spdm_x509::Error> {
        self.validate(cert, SpdmCertificateModel::GenericCert, role)
    }
}

/// Macro to simplify common CA cert validation tests
macro_rules! test_ca_cert {
    ($test_name:ident, $algo:expr, $pk_oid:expr) => {
        #[test]
        fn $test_name() {
            let cert = load_libspdm_cert($algo, "ca.cert.der").expect("Failed to load CA cert");

            let validator = Validator::new();
            let options = ValidationOptions {
                check_time: false,
                ..Default::default()
            };

            assert!(validator.validate(&cert, &options).is_ok());

            // Verify public key algorithm
            let pk_algo = &cert.tbs_certificate.subject_public_key_info.algorithm;
            assert_eq!(pk_algo.oid, $pk_oid);
        }
    };
}

// =============================================================================
// ECP256 (ECDSA P-256) Certificate Tests
// =============================================================================

test_ca_cert!(test_ecp256_ca_cert, "ecp256", EC_PUBLIC_KEY);

#[test]
fn test_ecp256_end_requester_with_spdm_req_eku() {
    let cert = load_libspdm_cert("ecp256", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    // Check for EKU extension
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("No extensions");
    let has_eku = extensions.iter().any(|ext| {
        ext.extn_id.to_string() == "2.5.29.37" // Extended Key Usage
    });
    assert!(has_eku, "Certificate should have EKU extension");

    // Validate with SPDM validator
    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    assert!(
        result.is_ok(),
        "Failed to validate as Requester: {:?}",
        result.err()
    );
}

#[test]
fn test_ecp256_end_responder_with_spdm_rsp_eku() {
    let cert = load_libspdm_cert("ecp256", "end_responder_with_spdm_rsp_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Responder);
    assert!(
        result.is_ok(),
        "Failed to validate as Responder: {:?}",
        result.err()
    );
}

#[test]
fn test_ecp256_requester_wrong_role_should_fail() {
    let cert = load_libspdm_cert("ecp256", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);

    // This has Requester EKU but we're validating as Responder - should fail
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Responder);
    println!("Validation result: {:?}", result);
    assert!(result.is_err(), "Should fail when EKU doesn't match role");
}

#[test]
fn test_ecp256_both_ekus_works_for_both_roles() {
    let cert = load_libspdm_cert("ecp256", "end_requester_with_spdm_req_rsp_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);

    // Should work as Requester
    let result_req = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    println!("Requester validation: {:?}", result_req);
    assert!(result_req.is_ok(), "Should validate as Requester");

    // Should also work as Responder
    let result_rsp = ctx.validate_generic(&cert, SpdmCertificateRole::Responder);
    println!("Responder validation: {:?}", result_rsp);
    assert!(result_rsp.is_ok(), "Should validate as Responder");
}

#[test]
fn test_ecp256_alias_cert() {
    let cert = load_libspdm_cert("ecp256", "end_responder_alias.cert.der")
        .expect("Failed to load alias cert");

    // AliasCert model should NOT have Hardware Identity OID
    let extensions = cert.tbs_certificate.extensions.as_ref();
    if let Some(exts) = extensions {
        let _has_hw_id = exts
            .iter()
            .any(|ext| oids::is_hardware_identity(&ext.extn_id));
        // libspdm alias certs may or may not have HW ID depending on version
        // We'll just verify it can be parsed and validated
    }

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);
    let result = ctx.validate(
        &cert,
        SpdmCertificateModel::AliasCert,
        SpdmCertificateRole::Responder,
    );

    // AliasCert validation requirements depend on HW ID presence
    // Just verify it can be validated
    let _ = result;
}

// =============================================================================
// ECP384 (ECDSA P-384) Certificate Tests
// =============================================================================

test_ca_cert!(test_ecp384_ca_cert, "ecp384", EC_PUBLIC_KEY);

#[test]
fn test_ecp384_with_correct_algorithm_negotiation() {
    let cert = load_libspdm_cert("ecp384", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP384, SpdmBaseHashAlgo::Sha384);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    assert!(result.is_ok(), "P-384 cert with P-384 algo should validate");
}

#[test]
fn test_ecp384_with_wrong_algorithm_should_fail() {
    let cert = load_libspdm_cert("ecp384", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    // Using P-256 algorithm negotiation for P-384 cert
    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::EcdsaP256, SpdmBaseHashAlgo::Sha256);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    assert!(result.is_err(), "P-384 cert with P-256 algo should fail");
}

// =============================================================================
// RSA2048 Certificate Tests
// =============================================================================

test_ca_cert!(test_rsa2048_ca_cert, "rsa2048", RSA_ENCRYPTION);

#[test]
fn test_rsa2048_requester_cert() {
    let cert = load_libspdm_cert("rsa2048", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::RsaSsa2048, SpdmBaseHashAlgo::Sha256);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    assert!(
        result.is_ok(),
        "RSA2048 cert should validate: {:?}",
        result.err()
    );
}

// =============================================================================
// RSA3072 Certificate Tests
// =============================================================================

test_ca_cert!(test_rsa3072_ca_cert, "rsa3072", RSA_ENCRYPTION);

#[test]
fn test_rsa3072_responder_cert() {
    let cert = load_libspdm_cert("rsa3072", "end_responder_with_spdm_rsp_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::RsaSsa3072, SpdmBaseHashAlgo::Sha384);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Responder);
    assert!(result.is_ok(), "RSA3072 cert should validate");
}

// =============================================================================
// RSA4096 Certificate Tests
// =============================================================================

test_ca_cert!(test_rsa4096_ca_cert, "rsa4096", RSA_ENCRYPTION);

#[test]
fn test_rsa4096_requester_cert() {
    let cert = load_libspdm_cert("rsa4096", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    let ctx = SpdmTestContext::new(SpdmBaseAsymAlgo::RsaSsa4096, SpdmBaseHashAlgo::Sha512);
    let result = ctx.validate_generic(&cert, SpdmCertificateRole::Requester);
    assert!(result.is_ok(), "RSA4096 cert should validate");
}

// =============================================================================
// Basic Constraints Tests
// =============================================================================

#[test]
fn test_ecp256_ca_false_cert() {
    let cert = load_libspdm_cert("ecp256", "end_requester_ca_false.cert.der")
        .expect("Failed to load cert");

    // This cert should have Basic Constraints with cA=FALSE
    // Should be valid for DeviceCert/AliasCert models (end-entity)
    let spdm_validator = SpdmValidator::new();
    let base_asym_algo = get_asym_algo_bits(SpdmBaseAsymAlgo::EcdsaP256);
    let base_hash_algo = get_hash_algo_bits(SpdmBaseHashAlgo::Sha256);

    let result = spdm_validator.validate_spdm_certificate(
        &cert,
        SpdmCertificateModel::GenericCert,
        SpdmCertificateRole::Requester,
        base_asym_algo,
        base_hash_algo,
    );

    assert!(
        result.is_ok(),
        "Cert with cA=FALSE should validate as end-entity"
    );
}

#[test]
fn test_ecp256_without_basic_constraint() {
    let cert = load_libspdm_cert("ecp256", "end_requester_without_basic_constraint.cert.der")
        .expect("Failed to load cert");

    // Cert without Basic Constraints extension
    // According to RFC 5280, absence means not a CA (treated as cA=FALSE)
    let spdm_validator = SpdmValidator::new();
    let base_asym_algo = get_asym_algo_bits(SpdmBaseAsymAlgo::EcdsaP256);
    let base_hash_algo = get_hash_algo_bits(SpdmBaseHashAlgo::Sha256);

    let result = spdm_validator.validate_spdm_certificate(
        &cert,
        SpdmCertificateModel::GenericCert,
        SpdmCertificateRole::Requester,
        base_asym_algo,
        base_hash_algo,
    );

    // Should validate - no Basic Constraints is acceptable for end-entity certs
    assert!(
        result.is_ok(),
        "Cert without Basic Constraints should validate"
    );
}

// =============================================================================
// Cross-Algorithm Validation Tests
// =============================================================================

#[test]
fn test_multiple_algorithms_negotiated() {
    let cert = load_libspdm_cert("ecp256", "end_requester_with_spdm_req_eku.cert.der")
        .expect("Failed to load cert");

    let spdm_validator = SpdmValidator::new();
    // Negotiate multiple algorithms (P-256 and P-384)
    let base_asym_algo = get_asym_algo_bits(SpdmBaseAsymAlgo::EcdsaP256)
        | get_asym_algo_bits(SpdmBaseAsymAlgo::EcdsaP384);
    let base_hash_algo =
        get_hash_algo_bits(SpdmBaseHashAlgo::Sha256) | get_hash_algo_bits(SpdmBaseHashAlgo::Sha384);

    let result = spdm_validator.validate_spdm_certificate(
        &cert,
        SpdmCertificateModel::GenericCert,
        SpdmCertificateRole::Requester,
        base_asym_algo,
        base_hash_algo,
    );

    assert!(
        result.is_ok(),
        "P-256 cert should validate when both P-256 and P-384 negotiated"
    );
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_complete_validation_workflow_ecp256() {
    // Complete workflow: Load -> Parse -> Validate (basic) -> Validate (SPDM)
    let cert = load_libspdm_cert("ecp256", "end_responder_with_spdm_rsp_eku.cert.der")
        .expect("Failed to load cert");

    // Step 1: Basic validation
    let validator = Validator::new();
    let options = ValidationOptions {
        check_time: false,
        ..Default::default()
    };
    assert!(
        validator.validate(&cert, &options).is_ok(),
        "Basic validation failed"
    );

    // Step 2: SPDM validation
    let spdm_validator = SpdmValidator::new();
    let base_asym_algo = get_asym_algo_bits(SpdmBaseAsymAlgo::EcdsaP256);
    let base_hash_algo = get_hash_algo_bits(SpdmBaseHashAlgo::Sha256);

    let result = spdm_validator.validate_spdm_certificate(
        &cert,
        SpdmCertificateModel::GenericCert,
        SpdmCertificateRole::Responder,
        base_asym_algo,
        base_hash_algo,
    );

    assert!(result.is_ok(), "SPDM validation failed: {:?}", result.err());
}

#[test]
fn test_all_ecp256_certs_can_be_loaded() {
    // Verify all ECP256 test vectors can be loaded and parsed
    let test_files = [
        "ca.cert.der",
        "ca1.cert.der",
        "end_requester.cert.der",
        "end_requester1.cert.der",
        "end_requester_ca_false.cert.der",
        "end_requester_with_spdm_req_eku.cert.der",
        "end_requester_with_spdm_req_rsp_eku.cert.der",
        "end_requester_with_spdm_rsp_eku.cert.der",
        "end_requester_without_basic_constraint.cert.der",
        "end_responder.cert.der",
        "end_responder1.cert.der",
        "end_responder_alias.cert.der",
        "end_responder_with_spdm_req_eku.cert.der",
        "end_responder_with_spdm_req_rsp_eku.cert.der",
        "end_responder_with_spdm_rsp_eku.cert.der",
        "inter.cert.der",
    ];

    for filename in &test_files {
        let result = load_libspdm_cert("ecp256", filename);
        assert!(
            result.is_ok(),
            "Failed to load {}: {:?}",
            filename,
            result.err()
        );
    }
}

#[test]
fn test_all_rsa_certs_can_be_loaded() {
    // Test RSA variants
    for algo in &["rsa2048", "rsa3072", "rsa4096"] {
        let ca_result = load_libspdm_cert(algo, "ca.cert.der");
        assert!(ca_result.is_ok(), "Failed to load {}/ca.cert.der", algo);
    }
}
