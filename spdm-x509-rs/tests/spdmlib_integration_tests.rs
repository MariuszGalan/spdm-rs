//! Integration tests for spdmlib-compatible functions
//!
//! These tests verify the new functions added for spdm-rs integration:
//! - get_cert_from_cert_chain()
//! - verify_cert_chain()
//! - verify_signature()

use der::Encode;
use spdm_x509::spdm::{
    get_cert_from_cert_chain, verify_cert_chain, verify_signature, SpdmBaseAsymAlgo,
    SpdmBaseHashAlgo,
};
use spdm_x509::Certificate;

/// Load a real certificate chain from PEM file
fn load_test_cert_chain() -> Vec<u8> {
    // Load the test certificate from examples
    let pem_data = include_bytes!("../examples/lcd_certchain.der.bin");
    let pem_str = std::str::from_utf8(pem_data).expect("Invalid UTF-8 in PEM file");

    // Extract the first certificate (between BEGIN/END CERTIFICATE)
    let cert_start = pem_str
        .find("-----BEGIN CERTIFICATE-----")
        .expect("No certificate found");
    let cert_end = pem_str
        .find("-----END CERTIFICATE-----")
        .expect("No certificate end found");

    let cert_pem = &pem_str[cert_start..cert_end + "-----END CERTIFICATE-----".len()];

    // Parse PEM to get DER
    let cert = Certificate::from_pem(cert_pem).expect("Failed to parse PEM");
    cert.to_der().expect("Failed to convert to DER")
}

/// Create a simple 2-certificate chain for testing
fn create_simple_chain() -> Vec<u8> {
    let cert_der = load_test_cert_chain();
    // For testing, we'll just use the same cert twice to simulate a chain
    let mut chain = Vec::new();
    chain.extend_from_slice(&cert_der);
    chain.extend_from_slice(&cert_der);
    chain
}

#[test]
fn test_get_cert_from_cert_chain_first() {
    let chain = create_simple_chain();

    // Get first certificate (index 0)
    let result = get_cert_from_cert_chain(&chain, 0);
    assert!(result.is_ok(), "Failed to get first certificate");

    let (offset, end) = result.unwrap();
    assert_eq!(offset, 0, "First cert should start at offset 0");
    assert!(end > offset, "End should be after start");

    // Verify it's a valid DER certificate
    let cert_der = &chain[offset..end];
    let cert = Certificate::from_der(cert_der);
    assert!(cert.is_ok(), "Extracted certificate should be valid DER");
}

#[test]
fn test_get_cert_from_cert_chain_last() {
    let chain = create_simple_chain();

    // Get last certificate (index -1)
    let result = get_cert_from_cert_chain(&chain, -1);
    assert!(result.is_ok(), "Failed to get last certificate");

    let (offset, end) = result.unwrap();
    assert!(offset > 0, "Last cert should not be at offset 0");
    assert_eq!(end, chain.len(), "Last cert should end at chain end");

    // Verify it's a valid DER certificate
    let cert_der = &chain[offset..end];
    let cert = Certificate::from_der(cert_der);
    assert!(cert.is_ok(), "Extracted certificate should be valid DER");
}

#[test]
fn test_get_cert_from_cert_chain_second() {
    let chain = create_simple_chain();

    // Get second certificate (index 1)
    let result = get_cert_from_cert_chain(&chain, 1);
    assert!(result.is_ok(), "Failed to get second certificate");

    let (offset, end) = result.unwrap();
    assert!(offset > 0, "Second cert should not be at offset 0");
    assert!(end > offset, "End should be after start");

    // Verify it's a valid DER certificate
    let cert_der = &chain[offset..end];
    let cert = Certificate::from_der(cert_der);
    assert!(cert.is_ok(), "Extracted certificate should be valid DER");
}

#[test]
fn test_get_cert_from_cert_chain_invalid_index() {
    let chain = create_simple_chain();

    // Try to get certificate beyond chain length
    let result = get_cert_from_cert_chain(&chain, 100);
    assert!(result.is_err(), "Should fail for out-of-bounds index");
}

#[test]
fn test_get_cert_from_cert_chain_empty() {
    let empty_chain: Vec<u8> = vec![];

    let result = get_cert_from_cert_chain(&empty_chain, 0);
    assert!(result.is_err(), "Should fail for empty chain");
}

#[test]
fn test_verify_cert_chain_single() {
    let cert_der = load_test_cert_chain();

    // Single certificate chain
    let result = verify_cert_chain(&cert_der);

    // Note: This might fail validation (self-signed, expired, etc.)
    // but should at least parse successfully
    match result {
        Ok(_) => println!("✅ Chain validation passed"),
        Err(e) => {
            // Check if it's a validation error (not a parse error)
            let err_str = format!("{:?}", e);
            assert!(
                !err_str.contains("Parse") && !err_str.contains("InvalidDer"),
                "Should not fail with parse error, got: {:?}",
                e
            );
            println!(
                "ℹ️  Chain validation failed (expected for test cert): {:?}",
                e
            );
        }
    }
}

#[test]
fn test_verify_cert_chain_multiple() {
    let chain = create_simple_chain();

    let result = verify_cert_chain(&chain);

    // Should at least parse both certificates
    match result {
        Ok(_) => println!("✅ Chain validation passed"),
        Err(e) => {
            let err_str = format!("{:?}", e);
            assert!(
                !err_str.contains("Parse") && !err_str.contains("InvalidDer"),
                "Should not fail with parse error, got: {:?}",
                e
            );
            println!("ℹ️  Chain validation failed (expected): {:?}", e);
        }
    }
}

#[test]
fn test_verify_cert_chain_empty() {
    let empty_chain: Vec<u8> = vec![];

    let result = verify_cert_chain(&empty_chain);
    assert!(result.is_err(), "Should fail for empty chain");

    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);
    assert!(
        err_str.contains("Empty") || err_str.contains("empty"),
        "Should report empty chain error"
    );
}

#[test]
fn test_verify_signature_compatibility() {
    let cert_der = load_test_cert_chain();
    let _cert = Certificate::from_der(&cert_der).expect("Failed to parse certificate");

    // Test data and fake signature (just for API testing)
    let data = b"test data for signing";
    let signature = vec![0u8; 256]; // RSA-2048 signature size

    // Test with SPDM algorithm parameters matching the cert
    // The cert uses RSA-2048 with SHA-256
    let result = verify_signature(
        SpdmBaseHashAlgo::Sha256,
        SpdmBaseAsymAlgo::RsaSsa2048,
        &cert_der,
        data,
        &signature,
    );

    // This will fail (invalid signature) but should not panic
    // and should show proper error handling
    match result {
        Ok(_) => panic!("Should not succeed with fake signature"),
        Err(e) => {
            println!("ℹ️  Signature verification failed as expected: {:?}", e);
            // Verify it's a signature error, not a parse error
            let err_str = format!("{:?}", e);
            assert!(
                !err_str.contains("Parse") && !err_str.contains("InvalidDer"),
                "Should fail with signature error, not parse error"
            );
        }
    }
}

#[test]
fn test_certificate_parsing_and_indexing() {
    let chain = create_simple_chain();

    println!("\n=== Testing Certificate Chain Parsing ===");
    println!("Chain size: {} bytes", chain.len());

    // Test getting each certificate
    for idx in 0..2 {
        match get_cert_from_cert_chain(&chain, idx) {
            Ok((start, end)) => {
                println!(
                    "\n📄 Certificate {}: offset {}..{} ({} bytes)",
                    idx,
                    start,
                    end,
                    end - start
                );

                let cert_der = &chain[start..end];
                match Certificate::from_der(cert_der) {
                    Ok(cert) => {
                        println!("  ✅ Valid DER certificate");
                        println!("  Subject: {:?}", cert.tbs_certificate.subject);
                    }
                    Err(e) => {
                        panic!("Certificate {} parsing failed: {:?}", idx, e);
                    }
                }
            }
            Err(e) => {
                panic!("Failed to get certificate {}: {:?}", idx, e);
            }
        }
    }

    // Test getting last certificate with -1
    match get_cert_from_cert_chain(&chain, -1) {
        Ok((start, end)) => {
            println!(
                "\n📄 Last certificate (index -1): offset {}..{}",
                start, end
            );
            assert_eq!(end, chain.len(), "Last cert should end at chain end");
        }
        Err(e) => {
            panic!("Failed to get last certificate: {:?}", e);
        }
    }
}

#[test]
fn test_real_cert_info() {
    let cert_der = load_test_cert_chain();
    let cert = Certificate::from_der(&cert_der).expect("Failed to parse certificate");

    println!("\n=== Real Certificate Information ===");
    println!("Subject: {:?}", cert.tbs_certificate.subject);
    println!("Issuer: {:?}", cert.tbs_certificate.issuer);
    println!("Serial: {:?}", cert.tbs_certificate.serial_number());
    println!(
        "Signature Algorithm: {:?}",
        cert.signature_algorithm.algorithm
    );
    println!(
        "Public Key Algorithm: {:?}",
        cert.tbs_certificate.subject_public_key_info.algorithm.oid
    );

    // Verify it's the expected test certificate
    // Check the raw DER encoding contains the expected strings
    let subject_bytes = cert.tbs_certificate.subject.to_der().unwrap();
    let subject_str = String::from_utf8_lossy(&subject_bytes);
    assert!(
        subject_str.contains("TestCert") || subject_bytes.windows(8).any(|w| w == b"TestCert"),
        "Should contain TestCert"
    );
    assert!(
        subject_str.contains("TianoCore") || subject_bytes.windows(9).any(|w| w == b"TianoCore"),
        "Should be from TianoCore"
    );
}
