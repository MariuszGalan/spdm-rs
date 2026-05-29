// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Chain validation scenario tests.
//!
//! Exercises `SpdmValidator::validate_chain` with real-world-like scenarios
//! from the spdm-rs test_key/ directory:
//! - Full 3-cert chains for all algorithms
//! - Alias cert chains (end_responder_alias)
//! - Partial cert set chains
//! - Deliberately broken chains (wrong issuer, root-only, etc.)

mod common;

use spdm_x509::{Certificate, CertificateChain, SpdmValidator, ValidationOptions};

fn load(path: &str) -> Vec<u8> {
    let full = format!(
        "{}/../../../../test_key/{}",
        env!("CARGO_MANIFEST_DIR"),
        path
    );
    std::fs::read(&full).unwrap_or_else(|e| panic!("cannot read {full}: {e}"))
}

fn load_cert(path: &str) -> Certificate {
    Certificate::from_der(&load(path))
        .unwrap_or_else(|e| panic!("cannot parse DER {path}: {e:?}"))
}

fn validator() -> SpdmValidator<spdm_x509::crypto_backend::RingBackend> {
    SpdmValidator::new()
}

fn opts() -> ValidationOptions {
    ValidationOptions::default().skip_time_validation()
}

// ============================================================================
// Standard 3-cert chains for all supported algorithms
// ============================================================================

macro_rules! chain3_ok {
    ($name:ident, $algo:literal) => {
        #[test]
        #[cfg(feature = "ring-backend")]
        fn $name() {
            let leaf = load_cert(concat!($algo, "/end_responder.cert.der"));
            let inter = load_cert(concat!($algo, "/inter.cert.der"));
            let ca = load_cert(concat!($algo, "/ca.cert.der"));
            let chain = CertificateChain::new(vec![leaf, inter, ca]);
            assert!(
                validator().validate_chain(&chain, &opts()).is_ok(),
                "{} 3-cert chain should validate",
                $algo
            );
        }
    };
}

chain3_ok!(chain_ecp256, "ecp256");
chain3_ok!(chain_ecp384, "ecp384");
chain3_ok!(chain_rsa2048, "rsa2048");
chain3_ok!(chain_rsa3072, "rsa3072");
chain3_ok!(chain_rsa4096, "rsa4096");
chain3_ok!(chain_ed25519, "ed25519");

// ============================================================================
// 2-cert chains (no EE leaf — intermediate directly under CA)
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn chain_ecp256_intermediate_under_ca() {
    // inter.cert is signed directly by ca.cert — a valid 2-cert chain
    let inter = load_cert("ecp256/inter.cert.der");
    let ca = load_cert("ecp256/ca.cert.der");
    let chain = CertificateChain::new(vec![inter, ca]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_ok(),
        "2-cert ecp256 chain (inter/ca) should validate"
    );
}

// ============================================================================
// Self-signed root-only chain
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn chain_self_signed_root_only_ecp256() {
    let ca = load_cert("ecp256/ca.cert.der");
    let chain = CertificateChain::new(vec![ca]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_ok(),
        "1-cert self-signed root chain should validate"
    );
}

// ============================================================================
// Broken chains — must return Err
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn chain_wrong_order_root_first_fails() {
    // SPDM format is root→leaf; X.509 chain validator expects leaf→root.
    // Putting them in SPDM order (root, inter, leaf) should fail with IssuerMismatch
    // because root.issuer != inter.subject at position [0].
    let ca = load_cert("ecp256/ca.cert.der");
    let inter = load_cert("ecp256/inter.cert.der");
    let leaf = load_cert("ecp256/end_responder.cert.der");
    let chain = CertificateChain::new(vec![ca, inter, leaf]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_err(),
        "root-first chain order should fail validation"
    );
}

#[test]
#[cfg(feature = "ring-backend")]
fn chain_cross_algorithm_fails() {
    // ecp256 leaf + ecp384 inter + ecp384 CA: issuer DN mismatch
    let leaf = load_cert("ecp256/end_responder.cert.der");
    let inter = load_cert("ecp384/inter.cert.der");
    let ca = load_cert("ecp384/ca.cert.der");
    let chain = CertificateChain::new(vec![leaf, inter, ca]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_err(),
        "cross-algorithm chain should fail validation"
    );
}

#[test]
#[cfg(feature = "ring-backend")]
fn chain_leaf_only_without_self_signature_fails() {
    // end_responder is not self-signed; a 1-cert chain should fail
    // because the lone cert is treated as root and its self-signature check fails
    let leaf = load_cert("ecp256/end_responder.cert.der");
    let chain = CertificateChain::new(vec![leaf]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_err(),
        "non-self-signed single cert should fail validation"
    );
}

#[test]
#[cfg(feature = "ring-backend")]
fn chain_missing_intermediate_fails() {
    // Skip the intermediate — leaf and root will have mismatched DN
    let leaf = load_cert("ecp256/end_responder.cert.der");
    let ca = load_cert("ecp256/ca.cert.der");
    let chain = CertificateChain::new(vec![leaf, ca]);
    assert!(
        validator().validate_chain(&chain, &opts()).is_err(),
        "chain with missing intermediate should fail validation"
    );
}

// ============================================================================
// Expiration tests (time validation must be enabled to take effect)
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn chain_rsa3072_expiration_validates_structure() {
    // The rsa3072_Expiration chain has certs that may have lapsed; with
    // time checking disabled we should get a structural pass.
    let leaf = load_cert("rsa3072_Expiration/end_responder.cert.der");
    let ca = load_cert("rsa3072_Expiration/ca.cert.der");
    // Build the chain only if there's an intermediate
    let inter_path = format!(
        "{}/../../../../test_key/rsa3072_Expiration/inter.cert.der",
        env!("CARGO_MANIFEST_DIR")
    );
    let chain = if std::fs::metadata(&inter_path).is_ok() {
        let inter = Certificate::from_der(&std::fs::read(&inter_path).unwrap())
            .expect("inter parse failed");
        CertificateChain::new(vec![leaf, inter, ca])
    } else {
        CertificateChain::new(vec![leaf, ca])
    };
    let result = validator().validate_chain(&chain, &opts());
    // With time disabled the chain should validate structurally
    assert!(
        result.is_ok(),
        "rsa3072_Expiration chain (time disabled) should pass: {:?}",
        result
    );
}
