//! Simple example of validating an X.509 certificate
//!
//! Usage: cargo run --example validate_cert <cert.der>

use std::env;
use std::fs;
use spdm_x509::{Certificate, ValidationOptions, Validator};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <certificate.der>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  cargo run --example validate_cert examples/lcd_certchain.der.bin");
        std::process::exit(1);
    }

    let cert_path = &args[1];

    // Read certificate file
    let cert_bytes = match fs::read(cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading certificate file '{}': {}", cert_path, e);
            std::process::exit(1);
        }
    };

    println!("Certificate file: {}", cert_path);
    println!("File size: {} bytes\n", cert_bytes.len());

    // Parse certificate
    let cert = match Certificate::from_der(&cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing certificate: {}", e);
            std::process::exit(1);
        }
    };

    println!("✓ Certificate parsed successfully\n");

    // Display basic certificate information
    println!("Certificate Information:");
    println!("  Version: {}", cert.tbs_certificate.version);
    println!(
        "  Serial Number: {}",
        hex::encode(cert.tbs_certificate.serial_number())
    );
    println!("  Subject: {}", cert.tbs_certificate.subject);
    println!("  Issuer: {}", cert.tbs_certificate.issuer);
    println!("  Validity:");
    println!(
        "    Not Before: {:?}",
        cert.tbs_certificate.validity.not_before
    );
    println!(
        "    Not After:  {:?}",
        cert.tbs_certificate.validity.not_after
    );
    println!(
        "  Signature Algorithm: {}",
        cert.signature_algorithm.algorithm
    );

    // Validate certificate
    let validator = Validator::new();
    let options = ValidationOptions::default()
        .skip_time_validation() // Skip time validation for now
        .skip_signature_validation(); // Skip signature validation (needs issuer)

    match validator.validate(&cert, &options) {
        Ok(_) => println!("\n✓ Certificate validation passed"),
        Err(e) => {
            eprintln!("\n✗ Certificate validation failed: {}", e);
            std::process::exit(1);
        }
    }
}
