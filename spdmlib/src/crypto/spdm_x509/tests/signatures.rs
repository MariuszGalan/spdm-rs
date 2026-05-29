// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Table-driven signature verification tests.
//!
//! Mirrors the table-driven pattern from webpki's tests/signatures.rs but
//! uses static DER fixtures from the spdm-rs test_key/ directory.
//!
//! Each row in CHAIN_CASES specifies a full certificate chain
//! (leaf → intermediate → root) and whether it should validate successfully.

mod common;

use spdm_x509::{Certificate, CertificateChain, SpdmValidator, ValidationOptions};

struct ChainCase {
    name: &'static str,
    leaf_der: &'static [u8],
    inter_der: &'static [u8],
    ca_der: &'static [u8],
    expect_ok: bool,
}

macro_rules! chain_case {
    ($name:expr, $algo:expr, $ok:expr) => {
        ChainCase {
            name: $name,
            leaf_der: include_bytes!(concat!(
                "../../../../../test_key/",
                $algo,
                "/end_responder.cert.der"
            )),
            inter_der: include_bytes!(concat!(
                "../../../../../test_key/",
                $algo,
                "/inter.cert.der"
            )),
            ca_der: include_bytes!(concat!(
                "../../../../../test_key/",
                $algo,
                "/ca.cert.der"
            )),
            expect_ok: $ok,
        }
    };
}

/// Full 3-cert chains: each algorithm's leaf → inter → ca.
static CHAIN_CASES: &[ChainCase] = &[
    chain_case!("ecp256 full chain", "ecp256", true),
    chain_case!("ecp384 full chain", "ecp384", true),
    chain_case!("rsa2048 full chain", "rsa2048", true),
    chain_case!("rsa3072 full chain", "rsa3072", true),
    chain_case!("rsa4096 full chain", "rsa4096", true),
    chain_case!("ed25519 full chain", "ed25519", true),
    // ecp521 uses ECDSA-SHA384 on P-521 which ring does not support
    chain_case!("ecp521 full chain (ring unsupported)", "ecp521", false),
];

/// Self-signed CA certificates (1-cert chain exercising self-signature check).
static SELF_SIGNED_CASES: &[(&str, &[u8])] = &[
    (
        "ecp256 CA self-signed",
        include_bytes!("../../../../../test_key/ecp256/ca.cert.der"),
    ),
    (
        "ecp384 CA self-signed",
        include_bytes!("../../../../../test_key/ecp384/ca.cert.der"),
    ),
    (
        "rsa2048 CA self-signed",
        include_bytes!("../../../../../test_key/rsa2048/ca.cert.der"),
    ),
    (
        "rsa3072 CA self-signed",
        include_bytes!("../../../../../test_key/rsa3072/ca.cert.der"),
    ),
    (
        "rsa4096 CA self-signed",
        include_bytes!("../../../../../test_key/rsa4096/ca.cert.der"),
    ),
    (
        "ed25519 CA self-signed",
        include_bytes!("../../../../../test_key/ed25519/ca.cert.der"),
    ),
];

/// Negative test: mix leaf from one algorithm with CA from a different algorithm.
/// The issuer DN won't match, so validation must return Err.
static CROSS_ALGO_CASES: &[(&str, &[u8], &[u8], &[u8])] = &[
    (
        "cross-algo: ecp256 leaf + ecp384 CA",
        include_bytes!("../../../../../test_key/ecp256/end_responder.cert.der"),
        include_bytes!("../../../../../test_key/ecp256/inter.cert.der"),
        include_bytes!("../../../../../test_key/ecp384/ca.cert.der"),
    ),
    (
        "cross-algo: rsa2048 leaf + rsa3072 CA",
        include_bytes!("../../../../../test_key/rsa2048/end_responder.cert.der"),
        include_bytes!("../../../../../test_key/rsa2048/inter.cert.der"),
        include_bytes!("../../../../../test_key/rsa3072/ca.cert.der"),
    ),
];

#[test]
#[cfg(feature = "ring-backend")]
fn signature_verification_table() {
    let mut failures = Vec::new();
    let validator = SpdmValidator::new();
    let opts = ValidationOptions::default().skip_time_validation();

    // ── Full 3-cert chain tests ────────────────────────────────────────────
    for tc in CHAIN_CASES {
        let leaf = match Certificate::from_der(tc.leaf_der) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("FAIL [{}]: parse leaf: {e:?}", tc.name));
                continue;
            }
        };
        let inter = match Certificate::from_der(tc.inter_der) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("FAIL [{}]: parse inter: {e:?}", tc.name));
                continue;
            }
        };
        let ca = match Certificate::from_der(tc.ca_der) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("FAIL [{}]: parse ca: {e:?}", tc.name));
                continue;
            }
        };

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let result = validator.validate_chain(&chain, &opts);
        if result.is_ok() != tc.expect_ok {
            failures.push(format!(
                "FAIL [{}]: expected {} but got {:?}",
                tc.name,
                if tc.expect_ok { "OK" } else { "Err" },
                result
            ));
        }
    }

    // ── Self-signed CA tests (1-cert chain) ────────────────────────────────
    for (name, der) in SELF_SIGNED_CASES {
        let cert = match Certificate::from_der(der) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("FAIL [{name}]: parse: {e:?}"));
                continue;
            }
        };
        let chain = CertificateChain::new(vec![cert]);
        let result = validator.validate_chain(&chain, &opts);
        if result.is_err() {
            failures.push(format!("FAIL [{name}]: expected OK but got {:?}", result));
        }
    }

    // ── Cross-algorithm negative tests ─────────────────────────────────────
    for (name, leaf_der, inter_der, ca_der) in CROSS_ALGO_CASES {
        let Ok(leaf) = Certificate::from_der(leaf_der) else { continue };
        let Ok(inter) = Certificate::from_der(inter_der) else { continue };
        let Ok(ca) = Certificate::from_der(ca_der) else { continue };

        let chain = CertificateChain::new(vec![leaf, inter, ca]);
        let result = validator.validate_chain(&chain, &opts);
        if result.is_ok() {
            failures.push(format!("FAIL [{name}]: expected Err but validation succeeded"));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} signature test(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

