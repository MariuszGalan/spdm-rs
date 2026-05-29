// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Tests using certificate fixtures shipped with the webpki project.
//!
//! These tests use the exact same DER files that webpki's own integration
//! tests rely on (in external/webpki/tests/), but exercise the spdm_x509
//! parser and validator instead of webpki's API.
//!
//! Purpose: verify that spdm_x509 can parse well-known, real-world
//! certificate fixtures without panicking or producing spurious errors.

mod common;

use spdm_x509::Certificate;

// ============================================================================
// Parser smoke-tests — webpki edge-case certificates
// ============================================================================

/// X.509 v1 certificate — no extensions field, version tag may differ.
/// spdm_x509 should parse it without panicking (result may be Ok or Err).
#[test]
fn cert_v1_does_not_panic() {
    let der = include_bytes!("../../../../../external/webpki/tests/cert_v1.der");
    let _ = Certificate::from_der(der);
}

/// Certificate with no extensions field present.
#[test]
fn cert_without_extensions_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/cert_without_extensions.der");
    // This cert has no extensions — expect either Ok or a well-defined Err
    let _ = Certificate::from_der(der);
}

/// Certificate with an empty extensions SEQUENCE.
#[test]
fn cert_with_empty_extensions_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/cert_with_empty_extensions.der");
    let _ = Certificate::from_der(der);
}

// ============================================================================
// Signature algorithm algorithm-ID edge-cases
// ============================================================================

/// DER files from webpki/tests/signatures/ with unusual/invalid algorithm OIDs.
/// spdm_x509 must parse these without panicking; whether they validate is
/// secondary (the files themselves are end-entity certs without a chain).

macro_rules! parse_no_panic {
    ($name:ident, $path:expr) => {
        #[test]
        fn $name() {
            let der = include_bytes!(concat!("../../../../../external/webpki/tests/signatures/", $path));
            let _ = Certificate::from_der(der);
        }
    };
}

parse_no_panic!(alg_ecdh_secp256r1, "alg-ecdh-secp256r1.der");
parse_no_panic!(alg_ecmqv_secp256r1, "alg-ecmqv-secp256r1.der");
parse_no_panic!(alg_id_ecpublickey_params_null, "alg-id-ecpublickey-params-null.der");
parse_no_panic!(alg_rsa_null_params, "alg-rsa-null-params.der");
parse_no_panic!(alg_rsae_bad_params, "alg-rsae-bad-params.der");
parse_no_panic!(alg_rsae_sha1, "alg-rsae-sha1.der");
parse_no_panic!(alg_rsapss_defaults, "alg-rsapss-defaults.der");
parse_no_panic!(alg_rsapss_salt23, "alg-rsapss-salt23.der");
parse_no_panic!(alg_rsapss_sha256_mgf1_sha256_salt10, "alg-rsapss-sha256-mgf1-sha256-salt10.der");
parse_no_panic!(alg_rsapss_sha256_mgf1_sha512_salt33, "alg-rsapss-sha256-mgf1-sha512-salt33.der");

// ============================================================================
// ECDSA end-entity certificates — should parse successfully
// ============================================================================

#[test]
fn ecdsa_p256_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/ecdsa_p256.ee.der");
    Certificate::from_der(der).expect("ecdsa_p256 EE cert should parse");
}

#[test]
fn ecdsa_p384_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/ecdsa_p384.ee.der");
    Certificate::from_der(der).expect("ecdsa_p384 EE cert should parse");
}

#[test]
fn ecdsa_p521_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/ecdsa_p521.ee.der");
    Certificate::from_der(der).expect("ecdsa_p521 EE cert should parse");
}

// ============================================================================
// RSA end-entity certificates — should parse successfully
// ============================================================================

#[test]
fn rsa_2048_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/rsa_2048.ee.der");
    Certificate::from_der(der).expect("rsa_2048 EE cert should parse");
}

#[test]
fn rsa_3072_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/rsa_3072.ee.der");
    Certificate::from_der(der).expect("rsa_3072 EE cert should parse");
}

#[test]
fn rsa_4096_ee_parses() {
    let der = include_bytes!("../../../../../external/webpki/tests/signatures/rsa_4096.ee.der");
    Certificate::from_der(der).expect("rsa_4096 EE cert should parse");
}

// ============================================================================
// Netflix certificate chain
// ============================================================================
//
// The Netflix chain uses a Verisign X.509 v1 root CA (ca.der).  v1 certs have
// no BasicConstraints extension, which spdm_x509's chain validator currently
// requires on issuers.  The test below verifies individual cert parsing only.

#[test]
fn netflix_certs_parse() {
    let ca = include_bytes!("../../../../../external/webpki/tests/netflix/ca.der");
    let inter = include_bytes!("../../../../../external/webpki/tests/netflix/inter.der");
    let ee = include_bytes!("../../../../../external/webpki/tests/netflix/ee.der");

    // v1 root may or may not parse depending on strictness — must not panic
    let _ = Certificate::from_der(ca);
    Certificate::from_der(inter).expect("Netflix intermediate should parse");
    Certificate::from_der(ee).expect("Netflix end-entity should parse");
}
