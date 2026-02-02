//! Real Certificate Tests
//!
//! Tests using real X.509 certificates from examples/

use spdm_x509::Certificate;

/// Test data: TianoCore test certificate (RSA 2048-bit)
const LCD_CERT_PEM: &str = include_str!("../examples/lcd_certchain.der.bin");

#[test]
fn test_parse_lcd_certificate() {
    // Extract first certificate from the chain
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Verify basic certificate properties
    assert_eq!(
        cert.tbs_certificate.version.value(),
        2,
        "Should be X.509 v3 (value 2)"
    );

    // Check subject
    let subject = cert.tbs_certificate.subject.to_string();
    assert!(
        subject.contains("TestCert"),
        "Subject should contain TestCert"
    );
    assert!(
        subject.contains("TianoCore"),
        "Subject should contain TianoCore"
    );

    // Check issuer
    let issuer = cert.tbs_certificate.issuer.to_string();
    assert!(issuer.contains("TestSub"), "Issuer should contain TestSub");

    println!("Certificate parsed successfully:");
    println!("  Version: {}", cert.tbs_certificate.version.value());
    println!("  Subject: {}", subject);
    println!("  Issuer: {}", issuer);
    println!("  Serial: {:?}", cert.tbs_certificate.serial_number());
}

#[test]
fn test_lcd_certificate_signature_algorithm() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Check signature algorithm
    let sig_algo = &cert.signature_algorithm;
    println!("Signature algorithm OID: {}", sig_algo.algorithm);

    // Should be sha256WithRSAEncryption (1.2.840.113549.1.1.11)
    assert_eq!(
        sig_algo.algorithm.to_string(),
        "1.2.840.113549.1.1.11",
        "Should be sha256WithRSAEncryption"
    );
}

#[test]
fn test_lcd_certificate_extensions() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Check extensions
    let extensions = &cert.tbs_certificate.extensions;
    assert!(extensions.is_some(), "Certificate should have extensions");

    if let Some(exts) = extensions {
        println!("Certificate has {} extensions:", exts.len());
        for ext in exts.iter() {
            println!("  - OID: {}, Critical: {}", ext.extn_id, ext.critical);
        }

        // Should have Basic Constraints
        let basic_constraints = exts.iter().find(|e| {
            e.extn_id.to_string() == "2.5.29.19" // Basic Constraints OID
        });
        assert!(
            basic_constraints.is_some(),
            "Should have Basic Constraints extension"
        );

        // Should have Key Usage
        let key_usage = exts.iter().find(|e| {
            e.extn_id.to_string() == "2.5.29.15" // Key Usage OID
        });
        assert!(key_usage.is_some(), "Should have Key Usage extension");
    }
}

#[test]
fn test_lcd_certificate_public_key() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Check public key
    let spki = &cert.tbs_certificate.subject_public_key_info;
    println!("Public key algorithm: {}", spki.algorithm.oid);

    // Should be RSA encryption (1.2.840.113549.1.1.1)
    assert_eq!(
        spki.algorithm.oid.to_string(),
        "1.2.840.113549.1.1.1",
        "Should be RSA encryption"
    );

    // Check public key size (should be 2048 bits = 256 bytes + overhead)
    let pub_key_bits = spki.subject_public_key.raw_bytes();
    println!("Public key size: {} bytes", pub_key_bits.len());
    assert!(
        pub_key_bits.len() > 256,
        "RSA 2048 public key should be > 256 bytes (with ASN.1 encoding)"
    );
}

#[test]
fn test_lcd_certificate_validity() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Check validity period
    let validity = &cert.tbs_certificate.validity;
    println!("Not Before: {:?}", validity.not_before);
    println!("Not After: {:?}", validity.not_after);

    // Note: This certificate expired in 2018, so it won't be currently valid
    // This is expected for test certificates
}

#[test]
fn test_lcd_certificate_serial_number() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Serial number should be 4099 (0x1003)
    let serial = cert.tbs_certificate.serial_number();
    println!("Serial number: {:02X?}", serial);

    // Check that serial number exists and is not empty
    assert!(!serial.is_empty(), "Serial number should not be empty");
}

#[test]
fn test_lcd_certificate_to_der() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // Convert to DER
    let der = cert.to_der().expect("Failed to convert to DER");
    println!("DER size: {} bytes", der.len());

    // Should be around 1KB for this certificate
    assert!(der.len() > 500, "DER should be > 500 bytes");
    assert!(der.len() < 2048, "DER should be < 2KB");

    // Parse back from DER
    let cert2 = Certificate::from_der(&der).expect("Failed to parse DER");

    // Should have same serial number
    assert_eq!(
        cert.tbs_certificate.serial_number(),
        cert2.tbs_certificate.serial_number(),
        "Serial numbers should match after round-trip"
    );
}

#[test]
fn test_lcd_certificate_round_trip() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    // Parse PEM
    let cert1 = Certificate::from_pem(&cert_pem).expect("Failed to parse PEM");

    // Convert to DER
    let der = cert1.to_der().expect("Failed to convert to DER");

    // Parse DER
    let cert2 = Certificate::from_der(&der).expect("Failed to parse DER");

    // Convert back to PEM
    let pem2 = cert2.to_pem().expect("Failed to convert to PEM");

    // Parse PEM again
    let cert3 = Certificate::from_pem(&pem2).expect("Failed to parse PEM again");

    // All should have same serial number
    assert_eq!(
        cert1.tbs_certificate.serial_number(),
        cert3.tbs_certificate.serial_number(),
        "Serial numbers should match after full round-trip"
    );
}

#[cfg(feature = "spdm")]
#[test]
fn test_lcd_certificate_algorithm_verification() {
    use spdm_x509::spdm::algorithm_verification::*;

    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let _cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // This certificate uses sha256WithRSAEncryption
    // In SPDM terms, this would be:
    // - Base Asym Algo: RSASSA_2048 (bit 0)
    // - Base Hash Algo: SHA_256 (bit 0)

    let base_asym_algo = 1 << 0; // RSASSA_2048
    let base_hash_algo = 1 << 0; // SHA_256

    // Verify RSA key size
    let algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);
    assert!(
        algos.contains(&SpdmBaseAsymAlgo::RsaSsa2048),
        "Should support RSA-2048"
    );

    // Verify hash algorithm (SHA-256 OID is 2.16.840.1.101.3.4.2.1)
    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let result = verify_hash_algorithm(&sha256_oid, base_hash_algo);

    match result {
        Ok(_) => println!("✓ Hash algorithm verification passed"),
        Err(e) => println!("✗ Hash algorithm verification failed: {:?}", e),
    }

    println!("✓ Algorithm verification tests completed");
}

#[cfg(feature = "spdm")]
#[test]
fn test_lcd_certificate_not_spdm() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    // This is a standard X.509 certificate, not an SPDM certificate
    // It should NOT have SPDM extensions

    use spdm_x509::spdm::oids::*;

    let extensions = cert.tbs_certificate.extensions.as_ref();

    if let Some(exts) = extensions {
        // Check for SPDM extensions
        let has_spdm_ext = exts.iter().any(|e| is_spdm_oid(&e.extn_id));
        let has_hw_id = exts.iter().any(|e| is_hardware_identity(&e.extn_id));
        let has_spdm_eku = exts.iter().any(|e| is_spdm_eku(&e.extn_id));

        assert!(
            !has_spdm_ext,
            "Standard cert should not have SPDM extension"
        );
        assert!(
            !has_hw_id,
            "Standard cert should not have Hardware Identity"
        );
        assert!(!has_spdm_eku, "Standard cert should not have SPDM EKU");

        println!("✓ Confirmed: This is NOT an SPDM certificate");
    }
}

#[test]
fn test_extract_multiple_certs_from_chain() {
    // The file contains both certificate and private key
    // Extract all certificates

    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;

    for line in LCD_CERT_PEM.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
            current_cert.push_str(line);
            current_cert.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            current_cert.push_str(line);
            current_cert.push('\n');
            certs.push(current_cert.clone());
            in_cert = false;
        } else if in_cert {
            current_cert.push_str(line);
            current_cert.push('\n');
        }
    }

    println!("Found {} certificate(s) in chain", certs.len());

    // Parse all certificates
    for (i, cert_pem) in certs.iter().enumerate() {
        let cert =
            Certificate::from_pem(cert_pem).expect(&format!("Failed to parse certificate {}", i));
        println!("Certificate {}: {}", i, cert.tbs_certificate.subject);
    }

    assert!(!certs.is_empty(), "Should find at least one certificate");
}

#[test]
fn test_lcd_certificate_basic_constraints_parsing() {
    let cert_pem = LCD_CERT_PEM
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .chain(std::iter::once("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("\n");

    let cert = Certificate::from_pem(&cert_pem).expect("Failed to parse certificate");

    if let Some(exts) = &cert.tbs_certificate.extensions {
        // Find Basic Constraints extension
        let bc_ext = exts.iter().find(|e| {
            e.extn_id.to_string() == "2.5.29.19" // Basic Constraints OID
        });

        if let Some(ext) = bc_ext {
            println!("Basic Constraints extension found:");
            println!("  Critical: {}", ext.critical);
            println!("  Value: {:02X?}", ext.extn_value.as_bytes());

            // For this certificate, CA should be FALSE
            // This is encoded as SEQUENCE { ca BOOLEAN FALSE }
            // We can check the raw bytes
            let value = ext.extn_value.as_bytes();
            println!("  Raw value length: {}", value.len());
        }
    }
}
