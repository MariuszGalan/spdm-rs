//! Debug tool to test certificate parsing
//!
//! Usage: cargo run --example debug_parse <cert.der>

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <certificate.der>", args[0]);
        std::process::exit(1);
    }

    let cert_path = &args[1];
    let cert_bytes = fs::read(cert_path).expect("Failed to read file");

    println!("File: {}", cert_path);
    println!("Size: {} bytes", cert_bytes.len());
    println!("\nFirst 32 bytes (hex):");
    for (i, byte) in cert_bytes.iter().take(32).enumerate() {
        if i % 16 == 0 {
            print!("\n{:04x}: ", i);
        }
        print!("{:02x} ", byte);
    }
    println!("\n");

    // Try to parse
    println!("Attempting to parse as Certificate...");

    match spdm_x509::Certificate::from_der(&cert_bytes) {
        Ok(cert) => {
            println!("✓ Successfully parsed!");
            println!("Subject: {}", cert.tbs_certificate.subject);
            println!("Issuer: {}", cert.tbs_certificate.issuer);
        }
        Err(e) => {
            println!("✗ Parse failed: {}", e);

            // Try parsing just the outer SEQUENCE
            println!("\nTrying to decode as raw SEQUENCE...");
            use der::{Reader, SliceReader};
            let reader = SliceReader::new(&cert_bytes).expect("Failed to create reader");
            match reader.peek_header() {
                Ok(header) => {
                    println!("  Tag: {:?}", header.tag);
                    println!("  Length: {:?}", header.length);
                }
                Err(e) => println!("  Failed to peek header: {}", e),
            }
        }
    }
}
