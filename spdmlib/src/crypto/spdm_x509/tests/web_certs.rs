// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Real-world web certificate parsing tests.
//!
//! Parses TLS leaf certificates from well-known web services (Amazon, GitHub,
//! Google, YouTube) stored in test_key/test_web_cert/. These are single DER
//! certificates without a full chain.
//!
//! Purpose: verify that spdm_x509's parser handles real-world X.509 v3
//! certificates without panicking. These are TLS leaf certs — they will NOT
//! pass SPDM chain validation (no SPDM EKU, no SPDM chain header) — but they
//! must parse successfully.
//!
//! Mirrors webpki's tests/amazon.rs approach of parsing real cert chains.

mod common;

use spdm_x509::Certificate;

fn load(path: &str) -> Vec<u8> {
    let full = format!(
        "{}/../../../../test_key/{}",
        env!("CARGO_MANIFEST_DIR"),
        path
    );
    std::fs::read(&full).unwrap_or_else(|e| panic!("cannot read {full}: {e}"))
}

// ============================================================================
// Individual web certificate parse tests
// ============================================================================

/// Amazon root/intermediate certificate (DER-encoded .cer file).
#[test]
fn amazon_cert_parses() {
    let der = load("test_web_cert/Amazon.cer");
    let cert = Certificate::from_der(&der).expect("Amazon.cer should parse as DER certificate");
    // Sanity-check version — should be v3
    assert_eq!(
        cert.tbs_certificate.version,
        spdm_x509::certificate::Version::V3,
        "Amazon cert should be X.509 v3"
    );
}

/// GitHub leaf certificate.
#[test]
fn github_cert_parses() {
    let der = load("test_web_cert/GitHub.cer");
    let cert = Certificate::from_der(&der).expect("GitHub.cer should parse as DER certificate");
    assert_eq!(
        cert.tbs_certificate.version,
        spdm_x509::certificate::Version::V3,
        "GitHub cert should be X.509 v3"
    );
}

/// Google certificate.
#[test]
fn google_cert_parses() {
    let der = load("test_web_cert/Google.cer");
    let cert = Certificate::from_der(&der).expect("Google.cer should parse as DER certificate");
    assert_eq!(
        cert.tbs_certificate.version,
        spdm_x509::certificate::Version::V3,
        "Google cert should be X.509 v3"
    );
}

/// YouTube certificate.
#[test]
fn youtube_cert_parses() {
    let der = load("test_web_cert/YouTube.cer");
    let cert = Certificate::from_der(&der).expect("YouTube.cer should parse as DER certificate");
    assert_eq!(
        cert.tbs_certificate.version,
        spdm_x509::certificate::Version::V3,
        "YouTube cert should be X.509 v3"
    );
}

// ============================================================================
// Metadata checks — web certs must have extensions
// ============================================================================

#[test]
fn web_certs_have_extensions() {
    for name in ["Amazon", "GitHub", "Google", "YouTube"] {
        let der = load(&format!("test_web_cert/{name}.cer"));
        let cert = Certificate::from_der(&der)
            .unwrap_or_else(|e| panic!("{name}.cer parse failed: {e:?}"));
        assert!(
            cert.tbs_certificate.extensions.is_some(),
            "{name} cert must have extensions (all modern TLS certs do)"
        );
    }
}

/// Re-encoding a parsed web cert should round-trip without data loss.
#[test]
fn web_certs_round_trip() {
    for name in ["Amazon", "GitHub", "Google", "YouTube"] {
        let der = load(&format!("test_web_cert/{name}.cer"));
        let cert = Certificate::from_der(&der)
            .unwrap_or_else(|e| panic!("{name}.cer parse failed: {e:?}"));
        let re_encoded = cert.to_der().unwrap_or_else(|e| panic!("{name} re-encode failed: {e:?}"));
        assert_eq!(
            der, re_encoded,
            "{name} cert DER round-trip should be lossless"
        );
    }
}
