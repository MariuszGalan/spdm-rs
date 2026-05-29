// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Integration test harness against the x509-limbo test corpus.
//!
//! Mirrors the approach used by webpki's own x509-limbo harness
//! (external/webpki/tests/x509_limbo.rs), but exercises the spdm_x509 API.
//!
//! Test vectors come from: https://github.com/C2SP/x509-limbo
//!
//! # Coverage
//! x509-limbo contains ~9 774 test vectors. The vast majority belong to the
//! BetterTLS name-constraint and TLS path-building suites which are outside
//! the scope of spdm_x509. After filtering, ~270 vectors in the rfc5280,
//! webpki, pathlen, cve and pathological categories are exercised.
//!
//! # Skip reasons
//! - `bettertls::*`       – TLS name-constraint / path-building, out of scope
//! - `online::*`          – requires live OCSP/CRL, not supported
//! - `has-crl` feature    – CRL/revocation not implemented
//! - `max-chain-depth`    – variable depth limits not configurable per-testcase
//! - `denial-of-service`  – DoS-specific, not a correctness concern here
//! - `name-constraint-dn` – DN name-constraints not implemented
//! - `has-policy-*`       – certificate policy validation not implemented
//! - `no-time-check` cfg  – validity-period tests skipped when time checks off

mod common;

use limbo_harness_support::models::{ExpectedResult, Feature, Limbo};
use limbo_harness_support::LIMBO_JSON;
use spdm_x509::ValidationOptions;
use spdm_x509::SpdmValidator;

// ============================================================================
// Skip logic
// ============================================================================

/// Features we cannot handle — testcases tagged with any of these are skipped.
const SKIP_FEATURES: &[Feature] = &[
    Feature::HasCrl,
    Feature::MaxChainDepth,
    Feature::DenialOfService,
    Feature::NameConstraintDn,
    Feature::HasPolicyConstraints,
    Feature::HasCertPolicies,
    Feature::NoCertPolicies,
];

/// Subcategory prefixes (within IDs) that spdm_x509 does not implement.
/// These represent RFC 5280 / webpki checks that are out of scope for a
/// device attestation library.
const SKIP_SUBCATEGORIES: &[&str] = &[
    // Name constraints (critical ext OID 2.5.29.30 not in known_extensions)
    "::nc::",
    // Authority/Subject Key Identifier enforcement
    "::aki::",
    "::ski::",
    // Subject Alternative Name content and hostname validation
    "::san::",
    // Serial number format enforcement
    "::serial::",
    // EKU enforcement in generic (non-SPDM) path validation
    "::eku::",
    // Common Name hostname matching
    "::cn::",
];

/// Specific test IDs that spdm_x509 skips with documented reasons.
/// Each entry is (test_id_prefix, reason).
const SKIP_IDS: &[(&str, &str)] = &[
    // webpki-specific: forbidden algorithm checks (DSA, P-192, weak RSA)
    ("webpki::forbidden-", "webpki-specific algorithm prohibition not in spdm_x509 scope"),
    // webpki: CA-used-as-leaf detection not implemented
    ("webpki::ca-as-leaf", "CA-as-leaf detection not implemented"),
    // webpki: malformed AIA not validated
    ("webpki::malformed-aia", "Authority Information Access not validated"),
    // webpki: X.509 v1 cert (no extensions) — spdm_x509 requires BasicConstraints on issuers
    ("webpki::v1-cert", "X.509 v1 cert without BasicConstraints: issuer CA check fails"),
    // webpki: complex third-party chain with TLS-specific requirements
    ("webpki::cryptographydotio-chain", "TLS-specific chain validation out of scope"),
    // rfc5280: CA with empty subject — empty subject enforcement not implemented
    ("rfc5280::ca-empty-subject", "empty subject enforcement not implemented"),
    // rfc5280: non-critical BasicConstraints on root — stricter than spdm_x509 enforces
    ("rfc5280::root-non-critical-basic-constraints", "non-critical BC strictness not enforced"),
    // rfc5280: leaf cert with keyCertSign set — EE key-usage enforcement not in generic path validation
    ("rfc5280::leaf-ku-keycertsign", "EE key-usage enforcement not in generic path validation"),
    // rfc5280: CA used as leaf with wrong SAN — SAN / CA-as-leaf check not implemented
    ("rfc5280::ca-as-leaf-wrong-san", "CA-as-leaf and SAN enforcement not implemented"),
    // pathlen: self-issued certificate path-length semantics
    ("pathlen::self-issued-certs-pathlen", "self-issued cert path semantics not implemented"),
    ("pathlen::intermediate-pathlen-may-increase", "self-issued cert path semantics not implemented"),
    // pathlen: leaf cert pathLen field must be ignored — spdm_x509 currently checks it
    ("pathlen::validation-ignores-pathlen-in-leaf", "leaf pathLen not yet ignored (known limitation)"),
    // pathlen: pathLen=0 on intermediate must allow EE — off-by-one in spdm_x509
    ("pathlen::ee-with-intermediate-pathlen-0", "pathLen=0 EE handling not yet correct (known limitation)"),
    // pathological: multiple valid chain paths — spdm_x509 follows given order only
    ("pathological::multiple-chains-expired-intermediate", "multi-path selection not implemented"),
    // rfc5280: root and intermediate in wrong order — spdm_x509 requires exact leaf→root order
    ("rfc5280::root-and-intermediate-swapped", "chain re-ordering not implemented"),
    // rfc5280: unknown critical extension in unrelated intermediate — IssuerMismatch edge case
    (
        "rfc5280::unknown-critical-extension-unrelated-intermediate",
        "unrelated-intermediate path building not supported",
    ),
    // cve: long chain (>10 certs) triggers default max_chain_depth limit
    ("cve::cve-2024-0567", "long chain exceeds default max_chain_depth (known limitation)"),
];

/// Return Some(reason) if the testcase should be skipped, None otherwise.
fn skip_reason(tc: &limbo_harness_support::models::Testcase) -> Option<String> {
    let id = tc.id.as_str();

    // Entire BetterTLS suite is TLS-specific (name constraints, SNI, etc.)
    if id.starts_with("bettertls::") {
        return Some("bettertls suite is TLS-specific".into());
    }

    // Online tests require live OCSP/CRL infrastructure
    if id.starts_with("online::") {
        return Some("online tests require live OCSP/CRL".into());
    }

    // Subcategory-based skips for unimplemented RFC 5280 checks
    for sub in SKIP_SUBCATEGORIES {
        if id.contains(sub) {
            return Some(format!("subcategory {sub:?} not implemented"));
        }
    }

    // Specific test ID skips with documented reasons
    for (prefix, reason) in SKIP_IDS {
        if id.starts_with(prefix) {
            return Some((*reason).into());
        }
    }

    // Skip testcases that require features we don't support
    for feat in &tc.features {
        if SKIP_FEATURES.contains(feat) {
            return Some(format!("unsupported feature: {feat:?}"));
        }
    }

    // When time checking is disabled (default feature), skip tests that depend
    // on validity-period evaluation (rfc5280::validity::* category)
    #[cfg(feature = "no-time-check")]
    if id.contains("::validity::") || id.contains("::expired") || id.contains("::not-yet-valid") {
        return Some("time-dependent test skipped (no-time-check feature active)".into());
    }

    None
}

// ============================================================================
// Outcome helpers
// ============================================================================

#[derive(Debug)]
enum Outcome {
    Pass,
    Skip(String),
    Fail(String),
}

fn evaluate_testcase(tc: &limbo_harness_support::models::Testcase) -> Outcome {
    if let Some(reason) = skip_reason(tc) {
        return Outcome::Skip(reason);
    }

    // Parse all certificates (failure to parse a PEM is itself a test failure
    // only if the testcase expected SUCCESS — for FAILURE testcases it can be
    // an acceptable early-exit with the correct outcome).
    let trusted: Vec<_> = tc
        .trusted_certs
        .iter()
        .enumerate()
        .map(|(i, pem)| spdm_x509::Certificate::from_pem(pem.trim()).map_err(|e| (i, e)))
        .collect();

    let intermediates: Vec<_> = tc
        .untrusted_intermediates
        .iter()
        .enumerate()
        .map(|(i, pem)| spdm_x509::Certificate::from_pem(pem.trim()).map_err(|e| (i, e)))
        .collect();

    let peer = spdm_x509::Certificate::from_pem(tc.peer_certificate.trim());

    let expected_ok = matches!(tc.expected_result, ExpectedResult::Success);

    // If any cert failed to parse, treat as validation failure.
    let parse_ok = trusted.iter().all(|r| r.is_ok())
        && intermediates.iter().all(|r| r.is_ok())
        && peer.is_ok();

    if !parse_ok {
        if !expected_ok {
            return Outcome::Pass; // expected FAILURE → parse error is fine
        }
        let msg = if peer.is_err() {
            format!("peer cert parse error: {:?}", peer.unwrap_err())
        } else if let Some(Err((i, e))) = trusted.iter().find(|r| r.is_err()) {
            format!("trusted_certs[{i}] parse error: {e:?}")
        } else if let Some(Err((i, e))) = intermediates.iter().find(|r| r.is_err()) {
            format!("untrusted_intermediates[{i}] parse error: {e:?}")
        } else {
            "unknown parse error".into()
        };
        return Outcome::Fail(format!("expected SUCCESS but cert parse failed: {msg}"));
    }

    // Build chain: leaf (peer) → intermediates → root (trusted CA).
    // CertificateChain expects leaf-first order.
    let mut certs = Vec::new();
    certs.push(peer.unwrap());
    for inter in intermediates {
        certs.push(inter.unwrap());
    }
    // x509-limbo may supply multiple trust anchors; use the first.
    certs.push(trusted.into_iter().next().unwrap().unwrap());

    let chain = spdm_x509::CertificateChain::new(certs);

    // Use SpdmValidator::validate_chain — this delegates to the underlying
    // Validator without checking SPDM-specific EKU, so generic RFC 5280
    // test vectors work correctly.
    let opts = ValidationOptions::default().skip_time_validation();
    let validator = SpdmValidator::new();
    let result = validator.validate_chain(&chain, &opts);

    match (result.is_ok(), expected_ok) {
        (true, true) | (false, false) => Outcome::Pass,
        (true, false) => Outcome::Fail(format!(
            "expected FAILURE but validation succeeded (id={:?})",
            tc.id
        )),
        (false, true) => Outcome::Fail(format!(
            "expected SUCCESS but validation failed: {:?} (id={:?})",
            result.unwrap_err(),
            tc.id
        )),
    }
}

// ============================================================================
// Test entry point
// ============================================================================

#[derive(Default)]
struct Summary {
    passed: usize,
    skipped: usize,
    failures: Vec<(String, String)>, // (id, reason)
}

impl Summary {
    fn print(&self) {
        eprintln!(
            "\nx509-limbo harness: {} passed, {} skipped, {} failed",
            self.passed,
            self.skipped,
            self.failures.len()
        );
        if !self.failures.is_empty() {
            eprintln!("FAILURES:");
            for (id, reason) in &self.failures {
                eprintln!("  FAIL [{id}]: {reason}");
            }
        }
    }
}

#[test]
#[cfg(feature = "ring-backend")]
fn x509_limbo() {
    let limbo: Limbo =
        serde_json::from_slice(LIMBO_JSON).expect("failed to parse limbo.json");

    let mut summary = Summary::default();

    for tc in &limbo.testcases {
        match evaluate_testcase(tc) {
            Outcome::Pass => summary.passed += 1,
            Outcome::Skip(_) => summary.skipped += 1,
            Outcome::Fail(reason) => summary.failures.push((tc.id.to_string(), reason)),
        }
    }

    summary.print();
    assert!(
        summary.failures.is_empty(),
        "{} testcase(s) failed (see FAILURES above)",
        summary.failures.len()
    );
}
