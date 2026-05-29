// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! SPDM certificate chain end-to-end integration tests.
//!
//! Tests `parse_spdm_cert_chain` and `validate_spdm_cert_chain` using real
//! certchain fixtures from test_key/ and programmatically constructed chains.
//!
//! The `bundle_responder.certchain.der` files in test_key/ are concatenated
//! DER certs (no SPDM header). Integration tests here build proper SPDM
//! certchain payloads (with header + root hash) programmatically.

mod common;

use spdm_x509::{
    parse_spdm_cert_chain, validate_spdm_cert_chain,
    verify_cert_chain, verify_cert_chain_with_options,
    ValidationOptions, SpdmBaseHashAlgo, SpdmBaseAsymAlgo,
};

fn load(path: &str) -> Vec<u8> {
    let full = format!(
        "{}/../../../../test_key/{}",
        env!("CARGO_MANIFEST_DIR"),
        path
    );
    std::fs::read(&full).unwrap_or_else(|e| panic!("cannot read {full}: {e}"))
}

/// Build a minimal SPDM cert chain payload:
///   [u16 length LE] [u16 reserved=0] [root_hash] [root_der] [inter_der] [leaf_der]
///
/// `hash_algo` bitfield must have exactly one bit set.
fn build_spdm_chain(root_der: &[u8], inter_der: &[u8], leaf_der: &[u8], hash_algo: u32) -> Vec<u8> {
    let hash_size = match hash_algo {
        0x01 => 32,  // SHA-256
        0x02 => 48,  // SHA-384
        0x04 => 64,  // SHA-512
        _ => panic!("unsupported hash algo 0x{hash_algo:02x}"),
    };

    let root_hash = compute_spdm_root_hash(root_der, hash_algo, hash_size);

    // SPDM cert chain order: root → intermediate → leaf
    let certs = if inter_der.is_empty() {
        [root_der, leaf_der].concat()
    } else {
        [root_der, inter_der, leaf_der].concat()
    };

    let header_size = 4 + hash_size; // 2 length + 2 reserved + hash
    let total_len = (header_size + certs.len()) as u16;

    let mut out = Vec::with_capacity(total_len as usize);
    out.extend_from_slice(&total_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&root_hash);
    out.extend_from_slice(&certs);
    out
}

/// Compute a SHA-256/384/512 hash of DER bytes using ring directly.
fn compute_spdm_root_hash(der: &[u8], _hash_algo: u32, hash_size: usize) -> Vec<u8> {
    use ring::digest;
    let alg = match hash_size {
        32 => &digest::SHA256,
        48 => &digest::SHA384,
        64 => &digest::SHA512,
        _ => panic!("unsupported hash size {hash_size}"),
    };
    digest::digest(alg, der).as_ref().to_vec()
}

// ============================================================================
// verify_cert_chain with concatenated DER files
// ============================================================================

/// `bundle_responder.certchain.der` are simple concatenated DER certs.
/// `verify_cert_chain` expects them in SPDM order (root → leaf) and validates
/// SPDM EKU on the leaf.
macro_rules! verify_bundle {
    ($name:ident, $algo:literal) => {
        #[test]
        #[cfg(feature = "ring-backend")]
        fn $name() {
            let chain = load(concat!($algo, "/bundle_responder.certchain.der"));
            let result = verify_cert_chain(&chain);
            assert!(
                result.is_ok(),
                "{} verify_cert_chain failed: {:?}",
                $algo,
                result
            );
        }
    };
}

verify_bundle!(verify_bundle_ecp256, "ecp256");
verify_bundle!(verify_bundle_ecp384, "ecp384");
verify_bundle!(verify_bundle_rsa2048, "rsa2048");
verify_bundle!(verify_bundle_rsa3072, "rsa3072");
verify_bundle!(verify_bundle_rsa4096, "rsa4096");
verify_bundle!(verify_bundle_ed25519, "ed25519");

// ============================================================================
// verify_cert_chain with algorithm constraints
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn verify_bundle_with_algo_constraint_ecp256() {
    let chain = load("ecp256/bundle_responder.certchain.der");
    let asym = SpdmBaseAsymAlgo::EcdsaP256 as u32;
    let hash = SpdmBaseHashAlgo::Sha256 as u32;
    let result = verify_cert_chain_with_options(&chain, Some(asym), Some(hash));
    assert!(
        result.is_ok(),
        "ecp256 chain with P256/SHA-256 constraint failed: {:?}",
        result
    );
}

#[test]
#[cfg(feature = "ring-backend")]
fn verify_bundle_wrong_algo_constraint_fails() {
    let chain = load("ecp256/bundle_responder.certchain.der");
    // Claim ecp384 algo for an ecp256 cert chain → should fail
    let asym = SpdmBaseAsymAlgo::EcdsaP384 as u32;
    let hash = SpdmBaseHashAlgo::Sha384 as u32;
    let result = verify_cert_chain_with_options(&chain, Some(asym), Some(hash));
    assert!(
        result.is_err(),
        "ecp256 chain with P384/SHA-384 constraint should fail"
    );
}

// ============================================================================
// parse_spdm_cert_chain — error cases
// ============================================================================

#[test]
fn parse_spdm_cert_chain_empty_fails() {
    assert!(parse_spdm_cert_chain(&[], 0x01).is_err());
}

#[test]
fn parse_spdm_cert_chain_no_algo_fails() {
    let data = vec![0u8; 64];
    assert!(parse_spdm_cert_chain(&data, 0).is_err());
}

#[test]
fn parse_spdm_cert_chain_multiple_algos_fails() {
    let data = vec![0u8; 64];
    // SHA-256 | SHA-384 = 0x01 | 0x02 = 0x03
    assert!(parse_spdm_cert_chain(&data, 0x03).is_err());
}

#[test]
fn parse_spdm_cert_chain_truncated_header_fails() {
    // Header must be >= 4 + hash_size bytes; send only 3 bytes for SHA-256
    let data = vec![0u8; 3];
    assert!(parse_spdm_cert_chain(&data, 0x01).is_err());
}

// ============================================================================
// parse_spdm_cert_chain + validate_spdm_cert_chain with real certs
// ============================================================================

#[test]
#[cfg(feature = "ring-backend")]
fn parse_and_validate_spdm_chain_ecp256_sha256() {
    let root = load("ecp256/ca.cert.der");
    let inter = load("ecp256/inter.cert.der");
    let leaf = load("ecp256/end_responder.cert.der");

    let chain_bytes = build_spdm_chain(&root, &inter, &leaf, 0x01); // SHA-256

    let (header, certs) = parse_spdm_cert_chain(&chain_bytes, 0x01)
        .expect("parse_spdm_cert_chain ecp256 SHA-256 failed");

    assert_eq!(header.root_hash.len(), 32);
    assert_eq!(certs.len(), 3, "expected root + inter + leaf = 3 certs");

    let opts = ValidationOptions::default().skip_time_validation();
    validate_spdm_cert_chain(&header, &certs, 0x01, &opts)
        .expect("validate_spdm_cert_chain ecp256 failed");
}

#[test]
#[cfg(feature = "ring-backend")]
fn parse_and_validate_spdm_chain_ecp384_sha384() {
    let root = load("ecp384/ca.cert.der");
    let inter = load("ecp384/inter.cert.der");
    let leaf = load("ecp384/end_responder.cert.der");

    let chain_bytes = build_spdm_chain(&root, &inter, &leaf, 0x02); // SHA-384

    let (header, certs) = parse_spdm_cert_chain(&chain_bytes, 0x02)
        .expect("parse_spdm_cert_chain ecp384 SHA-384 failed");

    assert_eq!(header.root_hash.len(), 48);

    let opts = ValidationOptions::default().skip_time_validation();
    validate_spdm_cert_chain(&header, &certs, 0x02, &opts)
        .expect("validate_spdm_cert_chain ecp384 failed");
}

#[test]
#[cfg(feature = "ring-backend")]
fn parse_and_validate_spdm_chain_rsa2048_sha256() {
    let root = load("rsa2048/ca.cert.der");
    let inter = load("rsa2048/inter.cert.der");
    let leaf = load("rsa2048/end_responder.cert.der");

    let chain_bytes = build_spdm_chain(&root, &inter, &leaf, 0x01);

    let (header, certs) = parse_spdm_cert_chain(&chain_bytes, 0x01)
        .expect("parse_spdm_cert_chain rsa2048 failed");

    let opts = ValidationOptions::default().skip_time_validation();
    validate_spdm_cert_chain(&header, &certs, 0x01, &opts)
        .expect("validate_spdm_cert_chain rsa2048 failed");
}

#[test]
#[cfg(feature = "ring-backend")]
fn parse_spdm_chain_wrong_root_hash_fails() {
    let root = load("ecp256/ca.cert.der");
    let inter = load("ecp256/inter.cert.der");
    let leaf = load("ecp256/end_responder.cert.der");

    let mut chain_bytes = build_spdm_chain(&root, &inter, &leaf, 0x01);

    // Corrupt the root hash (bytes 4..36)
    for b in &mut chain_bytes[4..36] {
        *b ^= 0xFF;
    }

    let (header, certs) =
        parse_spdm_cert_chain(&chain_bytes, 0x01).expect("parse should still work");

    let opts = ValidationOptions::default().skip_time_validation();
    let result = validate_spdm_cert_chain(&header, &certs, 0x01, &opts);
    assert!(
        result.is_err(),
        "validate with wrong root hash should fail"
    );
}
