// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Shared helpers for integration tests.

use spdm_x509::{Certificate, CertificateChain};

/// Decode a PEM-encoded certificate into a `Certificate`.
///
/// Panics with a descriptive message if decoding fails.
pub fn cert_from_pem(label: &str, pem: &str) -> Certificate {
    Certificate::from_pem(pem.trim())
        .unwrap_or_else(|e| panic!("failed to parse PEM cert {label}: {e:?}"))
}

/// Decode a DER-encoded certificate into a `Certificate`.
pub fn cert_from_der(label: &str, der: &[u8]) -> Certificate {
    Certificate::from_der(der)
        .unwrap_or_else(|e| panic!("failed to parse DER cert {label}: {e:?}"))
}

/// Build a `CertificateChain` (leaf → … → root order) from PEM strings.
///
/// `peer` is the end-entity certificate.
/// `intermediates` are ordered from closest to the peer towards the root.
/// `root` is the trust anchor.
pub fn build_chain_from_pem(peer: &str, intermediates: &[&str], root: &str) -> CertificateChain {
    let mut certs = Vec::with_capacity(1 + intermediates.len() + 1);
    certs.push(cert_from_pem("peer", peer));
    for (i, inter) in intermediates.iter().enumerate() {
        certs.push(cert_from_pem(&format!("intermediate[{i}]"), inter));
    }
    certs.push(cert_from_pem("root", root));
    CertificateChain::new(certs)
}

/// Build a `CertificateChain` (leaf → … → root order) from DER byte slices.
pub fn build_chain_from_der(
    peer: &[u8],
    intermediates: &[&[u8]],
    root: &[u8],
) -> CertificateChain {
    let mut certs = Vec::with_capacity(1 + intermediates.len() + 1);
    certs.push(cert_from_der("peer", peer));
    for (i, inter) in intermediates.iter().enumerate() {
        certs.push(cert_from_der(&format!("intermediate[{i}]"), inter));
    }
    certs.push(cert_from_der("root", root));
    CertificateChain::new(certs)
}
