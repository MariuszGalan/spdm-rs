//! Example of using spdm-x509-rs library in your Rust code
//!
//! This example demonstrates:
//! - Loading and parsing certificates
//! - Basic certificate validation
//! - Signature verification
//! - Chain validation
//! - Extension checking
//!
//! Run with: cargo run --example usage_example

use spdm_x509::{Certificate, ValidationOptions, Validator};
use std::fs;

fn main() {
    println!("=== X.509 Validator Library Usage Examples ===\n");

    // Example 1: Load and parse a certificate from DER format
    example_1_basic_parsing();

    // Example 2: Validate certificate with options
    example_2_validation_with_options();

    // Example 3: Verify certificate signature
    example_3_signature_verification();

    // Example 4: Check certificate extensions
    example_4_extensions();

    // Example 5: Error handling
    example_5_error_handling();
}

/// Example 1: Basic certificate parsing from DER/PEM
fn example_1_basic_parsing() {
    println!("📝 Example 1: Basic Certificate Parsing\n");

    // Load certificate from DER file
    let cert_path = "examples/lcd_certchain.der.bin";
    match fs::read(cert_path) {
        Ok(cert_bytes) => {
            // Parse DER-encoded certificate
            match Certificate::from_der(&cert_bytes) {
                Ok(cert) => {
                    println!("✓ Certificate parsed successfully");
                    println!("  Subject: {}", cert.tbs_certificate.subject);
                    println!("  Issuer:  {}", cert.tbs_certificate.issuer);
                    println!(
                        "  Serial:  {}",
                        hex::encode(cert.tbs_certificate.serial_number())
                    );
                    println!("  Version: {}\n", cert.tbs_certificate.version);
                }
                Err(e) => eprintln!("✗ Parse error: {}\n", e),
            }
        }
        Err(e) => eprintln!("✗ File read error: {}\n", e),
    }

    // Parse PEM-encoded certificate
    println!("  PEM parsing example:");
    let pem_cert = r#"-----BEGIN CERTIFICATE-----
MIICertificateDataHere...
-----END CERTIFICATE-----"#;

    match Certificate::from_pem(pem_cert) {
        Ok(_cert) => println!("  ✓ PEM certificate parsed\n"),
        Err(e) => println!("  ✗ PEM parse failed (expected - invalid data): {}\n", e),
    }
}

/// Example 2: Certificate validation with custom options
fn example_2_validation_with_options() {
    println!("🔍 Example 2: Certificate Validation with Options\n");

    let cert_path = "examples/lcd_certchain.der.bin";
    if let Ok(cert_bytes) = fs::read(cert_path) {
        if let Ok(cert) = Certificate::from_der(&cert_bytes) {
            let validator = Validator::new();

            // Option A: Full validation (time + extensions)
            println!("  Option A: Skip time validation (for old certs)");
            let options = ValidationOptions::default()
                .skip_time_validation()
                .skip_signature_validation();

            match validator.validate(&cert, &options) {
                Ok(_) => println!("  ✓ Certificate structure is valid\n"),
                Err(e) => println!("  ✗ Validation failed: {}\n", e),
            }

            // Option B: Only structure validation
            println!("  Option B: Full validation with time check");
            let options = ValidationOptions::default().skip_signature_validation(); // Skip signature - no issuer cert

            match validator.validate(&cert, &options) {
                Ok(_) => println!("  ✓ Certificate is currently valid\n"),
                Err(e) => println!("  ⚠ Validation issue: {} (expected - cert expired)\n", e),
            }
        }
    }
}

/// Example 3: Signature verification (requires issuer certificate)
fn example_3_signature_verification() {
    println!("🔐 Example 3: Signature Verification\n");

    let cert_path = "examples/lcd_certchain.der.bin";
    if let Ok(cert_bytes) = fs::read(cert_path) {
        if let Ok(cert) = Certificate::from_der(&cert_bytes) {
            // Check if certificate is self-signed
            let is_self_signed = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
            println!("  Self-signed: {}", is_self_signed);

            if is_self_signed {
                // For self-signed certificates, verify signature with own public key
                let validator = Validator::new();
                match validator.verify_signature(&cert, &cert) {
                    Ok(_) => println!("  ✓ Self-signature verified successfully\n"),
                    Err(e) => println!("  ✗ Signature verification failed: {}\n", e),
                }
            } else {
                println!("  ℹ Not self-signed - need issuer certificate for verification");
                println!("  Example:");
                println!("    let issuer_cert = Certificate::from_der(issuer_bytes)?;");
                println!("    validator.verify_signature(&cert, &issuer_cert)?;\n");
            }
        }
    }
}

/// Example 4: Working with certificate extensions
fn example_4_extensions() {
    println!("📋 Example 4: Certificate Extensions\n");

    let cert_path = "examples/lcd_certchain.der.bin";
    if let Ok(cert_bytes) = fs::read(cert_path) {
        if let Ok(cert) = Certificate::from_der(&cert_bytes) {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                println!("  Found {} extension(s):", extensions.extensions.len());

                for ext in &extensions.extensions {
                    let critical = if ext.critical { " (CRITICAL)" } else { "" };
                    println!("    - {}{}", ext.extn_id, critical);

                    // Check for specific extensions
                    use spdm_x509::extensions::*;

                    if ext.extn_id == BASIC_CONSTRAINTS {
                        use der::Decode;
                        if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                            println!(
                                "      → Basic Constraints: CA={}, pathLen={:?}",
                                bc.ca, bc.path_len_constraint
                            );
                        }
                    } else if ext.extn_id == KEY_USAGE {
                        println!("      → Key Usage extension detected");
                    } else if ext.extn_id == EXTENDED_KEY_USAGE {
                        println!("      → Extended Key Usage extension detected");
                    }
                }
                println!();
            } else {
                println!("  No extensions found\n");
            }
        }
    }
}

/// Example 5: Comprehensive error handling
fn example_5_error_handling() {
    println!("⚠️  Example 5: Error Handling\n");

    // Example: Handling parse errors
    let invalid_der = vec![0x00, 0x01, 0x02];
    match Certificate::from_der(&invalid_der) {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  ✓ Parse error caught: {}", e),
    }

    // Example: Handling validation errors
    let cert_path = "examples/lcd_certchain.der.bin";
    if let Ok(cert_bytes) = fs::read(cert_path) {
        if let Ok(cert) = Certificate::from_der(&cert_bytes) {
            let validator = Validator::new();
            let options = ValidationOptions::default().skip_signature_validation();

            match validator.validate(&cert, &options) {
                Ok(_) => println!("  Certificate valid"),
                Err(e) => {
                    use spdm_x509::error::Error;
                    match e {
                        Error::TimeError(time_err) => {
                            println!("  ✓ Time validation error caught: {:?}", time_err);
                        }
                        Error::ExtensionError(ext_err) => {
                            println!("  Extension error: {:?}", ext_err);
                        }
                        Error::ChainError(chain_err) => {
                            println!("  Chain error: {:?}", chain_err);
                        }
                        _ => println!("  Other error: {}", e),
                    }
                }
            }
        }
    }

    println!();
}

/// Bonus: Complete usage pattern in a function
#[allow(dead_code)]
fn complete_certificate_check(cert_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load certificate
    let cert_bytes = fs::read(cert_path)?;

    // 2. Parse certificate (try DER, fallback to PEM)
    let cert = match Certificate::from_der(&cert_bytes) {
        Ok(c) => c,
        Err(_) => {
            // Try PEM if DER fails
            let pem_str = std::str::from_utf8(&cert_bytes)?;
            Certificate::from_pem(pem_str)?
        }
    };

    // 3. Create validator with options
    let validator = Validator::new();
    let options = ValidationOptions::default()
        .skip_signature_validation() // Skip if no issuer cert
        .with_max_chain_depth(10);

    // 4. Validate
    validator.validate(&cert, &options)?;

    // 5. Extract information
    println!("Certificate valid!");
    println!("  Subject: {}", cert.tbs_certificate.subject);
    println!(
        "  Valid from: {:?}",
        cert.tbs_certificate.validity.not_before
    );
    println!(
        "  Valid to:   {:?}",
        cert.tbs_certificate.validity.not_after
    );

    Ok(())
}
