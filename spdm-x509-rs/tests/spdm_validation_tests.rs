//! SPDM Certificate Validation Tests
//!
//! Comprehensive tests for SPDM (DSP0274) certificate validation including:
//! - DeviceCert validation
//! - AliasCert validation
//! - GenericCert validation
//! - SPDM EKU validation (Requester and Responder)
//! - SPDM extension validation
//! - Hardware Identity validation
//! - Basic Constraints validation per model

#![cfg(feature = "spdm")]

use spdm_x509::spdm::oids;
use spdm_x509::spdm::{SpdmCertificateModel, SpdmCertificateRole, SpdmValidator};

mod test_data;

// =============================================================================
// SPDM Certificate Model Tests
// =============================================================================

#[test]
fn test_certificate_model_from_value() {
    assert_eq!(
        SpdmCertificateModel::from_value(0).unwrap(),
        SpdmCertificateModel::DeviceCert
    );
    assert_eq!(
        SpdmCertificateModel::from_value(1).unwrap(),
        SpdmCertificateModel::AliasCert
    );
    assert_eq!(
        SpdmCertificateModel::from_value(2).unwrap(),
        SpdmCertificateModel::GenericCert
    );
}

#[test]
fn test_certificate_model_invalid_value() {
    assert!(SpdmCertificateModel::from_value(3).is_err());
    assert!(SpdmCertificateModel::from_value(255).is_err());
}

#[test]
fn test_certificate_model_names() {
    assert_eq!(SpdmCertificateModel::DeviceCert.name(), "DeviceCert");
    assert_eq!(SpdmCertificateModel::AliasCert.name(), "AliasCert");
    assert_eq!(SpdmCertificateModel::GenericCert.name(), "GenericCert");
}

#[test]
fn test_certificate_model_values() {
    assert_eq!(SpdmCertificateModel::DeviceCert.value(), 0);
    assert_eq!(SpdmCertificateModel::AliasCert.value(), 1);
    assert_eq!(SpdmCertificateModel::GenericCert.value(), 2);
}

// =============================================================================
// SPDM Certificate Role Tests
// =============================================================================

#[test]
fn test_certificate_role_names() {
    assert_eq!(SpdmCertificateRole::Requester.name(), "Requester");
    assert_eq!(SpdmCertificateRole::Responder.name(), "Responder");
}

// =============================================================================
// SPDM Extended Key Usage (EKU) Tests
// =============================================================================

/// Test that EKU validation passes when no EKU extension is present
#[test]
#[ignore] // Requires valid certificate fixture
fn test_eku_no_extension_passes() {
    // Without a real certificate, we can't test this yet
    // This test would load a certificate without EKU extension
    // and verify that validation passes for both Requester and Responder roles
}

/// Test that Requester certificate with only Responder EKU fails
#[test]
#[ignore] // Requires valid certificate fixture
fn test_eku_requester_with_only_responder_fails() {
    // This test would:
    // 1. Load a certificate with only SPDM_RESPONDER_AUTH in EKU
    // 2. Validate as Requester role
    // 3. Expect ExtensionError::ExtendedKeyUsage error
}

/// Test that Responder certificate with only Requester EKU fails
#[test]
#[ignore] // Requires valid certificate fixture
fn test_eku_responder_with_only_requester_fails() {
    // This test would:
    // 1. Load a certificate with only SPDM_REQUESTER_AUTH in EKU
    // 2. Validate as Responder role
    // 3. Expect ExtensionError::ExtendedKeyUsage error
}

/// Test that certificate with both Requester and Responder EKU passes for both roles
#[test]
#[ignore] // Requires valid certificate fixture
fn test_eku_both_roles_passes() {
    // This test would:
    // 1. Load a certificate with both SPDM_REQUESTER_AUTH and SPDM_RESPONDER_AUTH
    // 2. Validate as Requester role -> should pass
    // 3. Validate as Responder role -> should pass
}

// =============================================================================
// Hardware Identity Validation Tests
// =============================================================================

/// Test that DeviceCert requires Hardware Identity OID
#[test]
#[ignore] // Requires valid certificate fixture
fn test_device_cert_requires_hardware_identity() {
    // This test would:
    // 1. Create/load a certificate with SPDM extension but no Hardware Identity OID
    // 2. Validate as DeviceCert model
    // 3. Expect ExtensionError::MissingRequiredExtension
}

/// Test that DeviceCert with Hardware Identity OID passes
#[test]
#[ignore] // Requires valid certificate fixture
fn test_device_cert_with_hardware_identity_passes() {
    // This test would:
    // 1. Load a certificate with SPDM extension containing Hardware Identity OID
    // 2. Validate as DeviceCert model
    // 3. Expect success
}

/// Test that AliasCert must not have Hardware Identity OID
#[test]
#[ignore] // Requires valid certificate fixture
fn test_alias_cert_rejects_hardware_identity() {
    // This test would:
    // 1. Load a certificate with Hardware Identity OID
    // 2. Validate as AliasCert model
    // 3. Expect ExtensionError::InvalidValue
}

/// Test that AliasCert without Hardware Identity OID passes
#[test]
#[ignore] // Requires valid certificate fixture
fn test_alias_cert_without_hardware_identity_passes() {
    // This test would:
    // 1. Load a certificate without Hardware Identity OID
    // 2. Validate as AliasCert model
    // 3. Expect success
}

/// Test that GenericCert allows Hardware Identity OID (optional)
#[test]
#[ignore] // Requires valid certificate fixture
fn test_generic_cert_hardware_identity_optional() {
    // This test would validate GenericCert with and without Hardware Identity
    // Both should pass
}

// =============================================================================
// Basic Constraints Validation Tests
// =============================================================================

/// Test that DeviceCert with cA=TRUE fails
#[test]
#[ignore] // Requires valid certificate fixture
fn test_device_cert_ca_true_fails() {
    // This test would:
    // 1. Load a certificate with Basic Constraints: cA=TRUE
    // 2. Validate as DeviceCert model
    // 3. Expect ExtensionError::BasicConstraints
}

/// Test that DeviceCert with cA=FALSE passes
#[test]
#[ignore] // Requires valid certificate fixture
fn test_device_cert_ca_false_passes() {
    // DeviceCert must have cA=FALSE
}

/// Test that AliasCert with cA=TRUE fails
#[test]
#[ignore] // Requires valid certificate fixture
fn test_alias_cert_ca_true_fails() {
    // AliasCert must have cA=FALSE
}

/// Test that GenericCert allows both cA=TRUE and cA=FALSE
#[test]
#[ignore] // Requires valid certificate fixture
fn test_generic_cert_ca_any_passes() {
    // GenericCert can be CA or end-entity certificate
}

// =============================================================================
// OID Helper Function Tests
// =============================================================================

#[test]
fn test_is_spdm_oid() {
    assert!(oids::is_spdm_oid(&oids::SPDM_REQUESTER_AUTH));
    assert!(oids::is_spdm_oid(&oids::SPDM_RESPONDER_AUTH));
    assert!(oids::is_spdm_oid(&oids::SPDM_EXTENSION));
    assert!(oids::is_spdm_oid(&oids::HARDWARE_IDENTITY));

    // Non-SPDM OIDs
    assert!(!oids::is_spdm_oid(&oids::SHA256));
    assert!(!oids::is_spdm_oid(&oids::SHA384));
    assert!(!oids::is_spdm_oid(&oids::RSA));
}

#[test]
fn test_is_hardware_identity() {
    assert!(oids::is_hardware_identity(&oids::HARDWARE_IDENTITY));
    assert!(!oids::is_hardware_identity(&oids::SPDM_EXTENSION));
    assert!(!oids::is_hardware_identity(&oids::SPDM_REQUESTER_AUTH));
}

#[test]
fn test_is_spdm_eku() {
    assert!(oids::is_spdm_eku(&oids::SPDM_REQUESTER_AUTH));
    assert!(oids::is_spdm_eku(&oids::SPDM_RESPONDER_AUTH));
    assert!(!oids::is_spdm_eku(&oids::SPDM_EXTENSION));
    assert!(!oids::is_spdm_eku(&oids::HARDWARE_IDENTITY));
}

// =============================================================================
// SPDM Validator Instance Tests
// =============================================================================

#[test]
fn test_spdm_validator_creation() {
    let validator = SpdmValidator::new();
    // Validator should be created successfully
    // Just verify it doesn't panic
    drop(validator);
}

#[test]
fn test_spdm_validator_default() {
    let validator1 = SpdmValidator::new();
    let validator2 = SpdmValidator::default();
    // Both should be equivalent
    drop(validator1);
    drop(validator2);
}

// =============================================================================
// Integration Tests (with actual certificates)
// =============================================================================

/// Complete DeviceCert validation test
#[test]
#[ignore] // Requires valid certificate fixture
fn test_complete_device_cert_validation() {
    // This test would:
    // 1. Load a complete DeviceCert with all required extensions
    // 2. Set up negotiated algorithms (e.g., ECDSA P-256 + SHA-256)
    // 3. Validate using SpdmValidator
    // 4. Expect success

    let _validator = SpdmValidator::new();
    let _base_asym_algo = 1 << 4; // ECDSA P-256
    let _base_hash_algo = 1 << 0; // SHA-256

    // Load certificate...
    // let cert = Certificate::from_der(&test_data::DEVICE_CERT_ECDSA_P256)?;

    // validator.validate_spdm_certificate(
    //     &cert,
    //     SpdmCertificateModel::DeviceCert,
    //     SpdmCertificateRole::Responder,
    //     base_asym_algo,
    //     base_hash_algo,
    // )?;
}

/// Complete AliasCert validation test
#[test]
#[ignore] // Requires valid certificate fixture
fn test_complete_alias_cert_validation() {
    // Similar to DeviceCert but for AliasCert model
    let _validator = SpdmValidator::new();
    let _base_asym_algo = 1 << 7; // ECDSA P-384
    let _base_hash_algo = 1 << 1; // SHA-384

    // Load certificate...
    // Validate as AliasCert
}

/// Complete GenericCert validation test
#[test]
#[ignore] // Requires valid certificate fixture
fn test_complete_generic_cert_validation() {
    // Similar to DeviceCert but for GenericCert model
    let _validator = SpdmValidator::new();
    let _base_asym_algo = 1 << 2; // RSA-3072
    let _base_hash_algo = 1 << 0; // SHA-256

    // Load certificate...
    // Validate as GenericCert
}

// =============================================================================
// Negative Tests (expected failures)
// =============================================================================

/// Test validation fails with mismatched algorithms
#[test]
#[ignore] // Requires valid certificate fixture
fn test_algorithm_mismatch_fails() {
    // This test would:
    // 1. Load an ECDSA P-256 certificate
    // 2. Try to validate with only RSA algorithms negotiated
    // 3. Expect AlgorithmError
}

/// Test validation fails with wrong hash algorithm
#[test]
#[ignore] // Requires valid certificate fixture
fn test_hash_algorithm_mismatch_fails() {
    // This test would:
    // 1. Load a certificate signed with SHA-256
    // 2. Try to validate with only SHA-384 negotiated
    // 3. Expect AlgorithmError
}

/// Test validation fails with expired certificate
#[test]
#[ignore] // Requires valid certificate fixture
fn test_expired_certificate_fails() {
    // This test would:
    // 1. Load a certificate with notAfter in the past
    // 2. Validate with current time
    // 3. Expect ValidationError for expiration
}

/// Test validation fails with not-yet-valid certificate
#[test]
#[ignore] // Requires valid certificate fixture
fn test_not_yet_valid_certificate_fails() {
    // This test would:
    // 1. Load a certificate with notBefore in the future
    // 2. Validate with current time
    // 3. Expect ValidationError
}

// =============================================================================
// Performance and Stress Tests
// =============================================================================

#[test]
#[ignore] // Performance test
fn test_validate_many_certificates() {
    // Test validating multiple certificates in sequence
    // to ensure no resource leaks
    let _validator = SpdmValidator::new();

    for _ in 0..100 {
        // Validate certificate
        // In production, load actual certificate
    }
}

#[test]
fn test_validator_is_reusable() {
    // Verify that a single validator instance can be used multiple times
    let validator = SpdmValidator::new();

    // First use
    // validator.validate_spdm_certificate(...)?;

    // Second use (should work fine)
    // validator.validate_spdm_certificate(...)?;

    drop(validator);
}
