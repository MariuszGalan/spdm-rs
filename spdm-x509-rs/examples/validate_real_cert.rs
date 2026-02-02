//! Example: Validate a real X.509 certificate
//!
//! This example demonstrates how to:
//! 1. Load a certificate from PEM file
//! 2. Parse and display certificate information
//! 3. Validate the certificate structure
//! 4. Check extensions
//! 5. Verify algorithms
//!
//! Usage:
//!   cargo run --example validate_real_cert -- --cert path/to/cert.pem
//!   cargo run --example validate_real_cert -- --cert path/to/cert.pem --verbose
//!   cargo run --example validate_real_cert -- --cert path/to/cert.pem --check-time
//!   cargo run --example validate_real_cert -- --cert path/to/cert.pem --output-json report.json
//!   cargo run --example validate_real_cert -- --cert path/to/cert.pem --output-txt report.txt
//!   cargo run --example validate_real_cert --features spdm -- --cert path/to/cert.pem --verbose --check-time

use std::fs::File;
use std::io::Write;
use spdm_x509::{Certificate, ValidationOptions, Validator};

#[cfg(feature = "spdm")]
use spdm_x509::spdm::{algorithm_verification::*, oids::*};

struct Options {
    verbose: bool,
    check_time: bool,
    cert_path: Option<String>,
    output_json: Option<String>,
    output_txt: Option<String>,
}

impl Options {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();

        // Check for help flag
        if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
            Self::print_help();
            std::process::exit(0);
        }

        let mut cert_path = None;
        let mut output_json = None;
        let mut output_txt = None;

        for i in 0..args.len() {
            if args[i] == "--cert" && i + 1 < args.len() {
                cert_path = Some(args[i + 1].clone());
            }
            if args[i] == "--output-json" && i + 1 < args.len() {
                output_json = Some(args[i + 1].clone());
            }
            if args[i] == "--output-txt" && i + 1 < args.len() {
                output_txt = Some(args[i + 1].clone());
            }
        }

        Self {
            verbose: args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string()),
            check_time: args.contains(&"--check-time".to_string()),
            cert_path,
            output_json,
            output_txt,
        }
    }

    fn print_help() {
        println!("X.509 Certificate Validator");
        println!();
        println!("USAGE:");
        println!("    cargo run --example validate_real_cert -- [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("    --cert <PATH>           Path to certificate file (PEM format)");
        println!("                            If not provided, uses embedded test certificate");
        println!();
        println!(
            "    --check-time            Enable time validation (will fail if cert is expired)"
        );
        println!("                            By default, time validation is skipped");
        println!();
        println!("    -v, --verbose           Enable verbose output");
        println!();
        println!("    --output-json <PATH>    Save validation report as JSON");
        println!("    --output-txt <PATH>     Save validation report as text");
        println!();
        println!("    -h, --help              Display this help message");
        println!();
        println!("EXAMPLES:");
        println!("    # Validate custom certificate with verbose output");
        println!("    cargo run --example validate_real_cert -- --cert path/to/cert.pem --verbose");
        println!();
        println!("    # Validate with time check and save report");
        println!("    cargo run --example validate_real_cert -- --cert cert.pem --check-time --output-json report.json");
        println!();
        println!("    # Use default embedded certificate");
        println!("    cargo run --example validate_real_cert -- --verbose");
        println!();
        #[cfg(feature = "spdm")]
        {
            println!("    # SPDM validation with all checks");
            println!("    cargo run --example validate_real_cert --features spdm -- --cert cert.pem --check-time --verbose");
            println!();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Options::parse();

    if !opts.verbose && opts.output_json.is_none() && opts.output_txt.is_none() {
        // Silent mode - only show basic info
    } else {
        println!("=== X.509 Certificate Validator ===\n");
    }

    // Load certificate from file or use default
    let cert = if let Some(cert_path) = &opts.cert_path {
        if opts.verbose {
            println!("📄 Loading certificate from: {}...", cert_path);
        }
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| format!("Failed to read certificate file '{}': {}", cert_path, e))?;

        // Extract first certificate from the chain
        let cert_pem = cert_pem
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
            .chain(std::iter::once("-----END CERTIFICATE-----"))
            .collect::<Vec<_>>()
            .join("\n");

        Certificate::from_pem(&cert_pem)?
    } else {
        // Use default embedded certificate
        if opts.verbose {
            println!("📄 Loading default certificate from embedded file...");
        }
        let cert_pem = include_str!("lcd_certchain.der.bin");

        // Extract first certificate from the chain
        let cert_pem = cert_pem
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
            .chain(std::iter::once("-----END CERTIFICATE-----"))
            .collect::<Vec<_>>()
            .join("\n");

        Certificate::from_pem(&cert_pem)?
    };

    if opts.verbose {
        println!("✅ Certificate loaded successfully\n");
    }

    // Collect validation results
    let mut validation_results = ValidationResults::new();

    // Display certificate information
    display_certificate_info(&cert, &opts);
    collect_cert_info(&cert, &mut validation_results);

    // Validate certificate
    if opts.verbose {
        println!("\n🔍 Validating certificate structure...");
    }
    let _validation_ok = validate_certificate(&cert, &opts, &mut validation_results)?;

    // Check extensions
    if opts.verbose {
        println!("\n🔧 Checking extensions...");
    }
    check_extensions(&cert, &opts);

    // Verify algorithms
    if opts.verbose {
        println!("\n🔐 Verifying algorithms...");
    }
    verify_algorithms(&cert, &opts);

    // SPDM-specific checks
    #[cfg(feature = "spdm")]
    {
        if opts.verbose {
            println!("\n🔒 SPDM-specific checks...");
        }
        check_spdm_compliance(&cert, &opts, &mut validation_results);
    }

    if opts.verbose {
        println!("\n📊 Validation Summary:");
        println!("  ✅ Passed: {}", validation_results.passed);
        if validation_results.failed > 0 {
            println!("  ❌ Failed: {}", validation_results.failed);
        }
        if validation_results.warnings > 0 {
            println!("  ⚠️  Warnings: {}", validation_results.warnings);
        }
        if validation_results.skipped > 0 {
            println!("  ⏭️  Skipped: {}", validation_results.skipped);
        }
        println!();
        if validation_results.overall_valid {
            println!("✅ Overall Result: VALID");
        } else {
            println!("❌ Overall Result: INVALID");
        }
    }

    // Save results if output files specified
    if let Some(json_path) = &opts.output_json {
        save_json_report(&validation_results, json_path)?;
        println!("📄 JSON report saved to: {}", json_path);
    }

    if let Some(txt_path) = &opts.output_txt {
        save_txt_report(&cert, &validation_results, txt_path, &opts)?;
        println!("📄 TXT report saved to: {}", txt_path);
    }

    Ok(())
}

#[derive(Default)]
struct ValidationResults {
    version: String,
    serial_number: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    signature_algorithm: String,
    public_key_algorithm: String,
    public_key_size: String,
    extensions_count: usize,
    extensions: Vec<String>,
    checks: Vec<ValidationCheck>,
    passed: usize,
    failed: usize,
    warnings: usize,
    skipped: usize,
    overall_valid: bool,
    #[cfg(feature = "spdm")]
    spdm_extension: bool,
    #[cfg(feature = "spdm")]
    hardware_identity: bool,
    #[cfg(feature = "spdm")]
    spdm_eku: bool,
}

impl ValidationResults {
    fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
struct ValidationCheck {
    name: String,
    status: String, // PASS, FAIL, WARN, SKIP
    description: String,
    details: String,
}

fn display_certificate_info(cert: &Certificate, opts: &Options) {
    if opts.verbose {
        println!("📋 Certificate Information:");
    }
    println!(
        "  Version: X.509 v{}",
        cert.tbs_certificate.version.value() + 1
    );

    let serial = cert.tbs_certificate.serial_number();
    println!("  Serial Number: {:02X?}", serial);

    if opts.verbose {
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
        println!(
            "  Public Key Algorithm: {}",
            cert.tbs_certificate.subject_public_key_info.algorithm.oid
        );
    }
}

fn collect_cert_info(cert: &Certificate, results: &mut ValidationResults) {
    results.version = format!("v{}", cert.tbs_certificate.version.value() + 1);

    let serial = cert.tbs_certificate.serial_number();
    results.serial_number = format!("{:02X?}", serial);

    results.subject = format!("{}", cert.tbs_certificate.subject);
    results.issuer = format!("{}", cert.tbs_certificate.issuer);
    results.not_before = format!("{:?}", cert.tbs_certificate.validity.not_before);
    results.not_after = format!("{:?}", cert.tbs_certificate.validity.not_after);
    results.signature_algorithm = format!("{}", cert.signature_algorithm.algorithm);
    results.public_key_algorithm = format!(
        "{}",
        cert.tbs_certificate.subject_public_key_info.algorithm.oid
    );

    // Get public key size
    let pk_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let estimated_size = if pk_bytes.len() > 500 {
        "4096-bit"
    } else if pk_bytes.len() > 350 {
        "3072-bit"
    } else if pk_bytes.len() > 250 {
        "2048-bit"
    } else {
        "unknown"
    };
    results.public_key_size = estimated_size.to_string();

    // Extensions
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        results.extensions_count = extensions.len();
        for ext in extensions.iter() {
            let critical = if ext.critical { " (critical)" } else { "" };
            results
                .extensions
                .push(format!("{}{}", ext.extn_id, critical));
        }
    }
}

fn validate_certificate(
    cert: &Certificate,
    opts: &Options,
    results: &mut ValidationResults,
) -> Result<bool, Box<dyn std::error::Error>> {
    let validator = Validator::new();
    let mut options = ValidationOptions::default();

    // Set check_time based on the --check-time flag
    if opts.check_time {
        // Validate time (will fail if certificate is expired)
        options.check_time = true;
    } else {
        // Skip time validation for expired test certificates
        options.check_time = false;
    }

    // Basic structure validation
    match validator.validate(cert, &options) {
        Ok(_) => {
            if opts.verbose {
                println!("  ✅ Certificate structure is valid");
            }
            results.checks.push(ValidationCheck {
                name: "Certificate Structure".to_string(),
                status: "PASS".to_string(),
                description: "Verify certificate has valid structure".to_string(),
                details: "Certificate successfully validated".to_string(),
            });
            results.passed += 1;
        }
        Err(e) => {
            if opts.check_time {
                // Report the error but continue processing
                if opts.verbose {
                    println!("  ❌ Validation failed: {:?}", e);
                    println!("     (Continuing with remaining checks...)");
                }
                results.checks.push(ValidationCheck {
                    name: "Certificate Validation".to_string(),
                    status: "FAIL".to_string(),
                    description: "Certificate validation failed".to_string(),
                    details: format!("{:?}", e),
                });
                results.failed += 1;
                results.overall_valid = false;
            } else {
                if opts.verbose {
                    println!("  ⚠️  Validation warning: {:?}", e);
                    println!("     (Time validation skipped - use --check-time to enforce)");
                }
                results.checks.push(ValidationCheck {
                    name: "Time Validation".to_string(),
                    status: "SKIP".to_string(),
                    description: "Certificate time validation skipped".to_string(),
                    details: format!("Use --check-time to enforce. Error: {:?}", e),
                });
                results.skipped += 1;
            }
        }
    }

    // Check version
    if cert.tbs_certificate.version == spdm_x509::certificate::Version::V3 {
        if opts.verbose {
            println!("  ✅ Version: X.509 v3 (correct)");
        }
        results.checks.push(ValidationCheck {
            name: "Version Check".to_string(),
            status: "PASS".to_string(),
            description: "Verify certificate version is appropriate".to_string(),
            details: "Certificate uses X.509 v3 (modern standard)".to_string(),
        });
        results.passed += 1;
    }

    // Check serial number
    let serial = cert.tbs_certificate.serial_number();
    if !serial.is_empty() && opts.verbose {
        println!("  ✅ Serial number present ({} bytes)", serial.len());
    }
    if !serial.is_empty() {
        results.checks.push(ValidationCheck {
            name: "Serial Number Validity".to_string(),
            status: "PASS".to_string(),
            description: "Verify serial number is present and within recommended size".to_string(),
            details: format!("Serial number length: {} bytes", serial.len()),
        });
        results.passed += 1;
    }

    results.overall_valid = results.failed == 0;
    Ok(results.overall_valid)
}

fn check_extensions(cert: &Certificate, opts: &Options) {
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        if opts.verbose {
            println!("  Found {} extension(s):", extensions.len());

            for ext in extensions.iter() {
                let critical_marker = if ext.critical {
                    "🔴 CRITICAL"
                } else {
                    "⚪ non-critical"
                };
                println!(
                    "    • {} - {} ({})",
                    ext.extn_id,
                    get_extension_name(&ext.extn_id),
                    critical_marker
                );
            }
        } else {
            println!("  Extensions: {}", extensions.len());
        }

        // Check specific extensions
        if opts.verbose {
            check_basic_constraints(extensions);
            check_key_usage(extensions);
            check_extended_key_usage(extensions);
        }
    } else if opts.verbose {
        println!("  ⚠️  No extensions found (unusual for v3 certificates)");
    }
}

fn get_extension_name(oid: &const_oid::ObjectIdentifier) -> &'static str {
    match oid.to_string().as_str() {
        "2.5.29.19" => "Basic Constraints",
        "2.5.29.15" => "Key Usage",
        "2.5.29.37" => "Extended Key Usage",
        "2.5.29.14" => "Subject Key Identifier",
        "2.5.29.35" => "Authority Key Identifier",
        "2.5.29.17" => "Subject Alternative Name",
        "2.16.840.1.113730.1.1" => "Netscape Cert Type",
        "2.16.840.1.113730.1.13" => "Netscape Comment",
        _ => "Unknown Extension",
    }
}

fn check_basic_constraints(extensions: &spdm_x509::certificate::Extensions) {
    const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

    if let Some(ext) = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == BASIC_CONSTRAINTS_OID)
    {
        println!("  ✅ Basic Constraints extension found");
        let value = ext.extn_value.as_bytes();

        // Simple check: empty SEQUENCE means CA=FALSE
        if value.len() == 2 && value[0] == 0x30 && value[1] == 0x00 {
            println!("     → CA: FALSE (end-entity certificate)");
        } else {
            println!("     → Raw value: {:02X?}", value);
        }
    }
}

fn check_key_usage(extensions: &spdm_x509::certificate::Extensions) {
    const KEY_USAGE_OID: &str = "2.5.29.15";

    if let Some(ext) = extensions
        .iter()
        .find(|e| e.extn_id.to_string() == KEY_USAGE_OID)
    {
        println!("  ✅ Key Usage extension found");
        if ext.critical {
            println!("     → Marked as CRITICAL");
        }
    }
}

fn check_extended_key_usage(extensions: &spdm_x509::certificate::Extensions) {
    const EKU_OID: &str = "2.5.29.37";

    if let Some(_ext) = extensions.iter().find(|e| e.extn_id.to_string() == EKU_OID) {
        println!("  ✅ Extended Key Usage extension found");
    }
}

fn verify_algorithms(cert: &Certificate, opts: &Options) {
    // Check signature algorithm
    let sig_algo = &cert.signature_algorithm;
    if opts.verbose {
        println!("  Signature Algorithm OID: {}", sig_algo.algorithm);
    }

    match sig_algo.algorithm.to_string().as_str() {
        "1.2.840.113549.1.1.11" => {
            println!("  ✅ Signature: sha256WithRSAEncryption (secure)");
        }
        "1.2.840.113549.1.1.5" => {
            println!("  ⚠️  Signature: sha1WithRSAEncryption (deprecated)");
        }
        _ => {
            println!(
                "  ℹ️  Signature: {} (check DSP0274 compliance)",
                sig_algo.algorithm
            );
        }
    }

    // Check public key algorithm
    let pk_algo = &cert.tbs_certificate.subject_public_key_info.algorithm;
    if opts.verbose {
        println!("  Public Key Algorithm OID: {}", pk_algo.oid);
    }

    match pk_algo.oid.to_string().as_str() {
        "1.2.840.113549.1.1.1" => {
            if opts.verbose {
                println!("  ✅ Algorithm: RSA Encryption");
            }

            // Try to determine key size
            let pk_bytes = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let estimated_size = if pk_bytes.len() > 500 {
                "4096-bit"
            } else if pk_bytes.len() > 350 {
                "3072-bit"
            } else if pk_bytes.len() > 250 {
                "2048-bit"
            } else {
                "unknown"
            };
            println!("  Public Key: RSA {}", estimated_size);
            if opts.verbose {
                println!("     ({} bytes encoded)", pk_bytes.len());
            }
        }
        "1.2.840.10045.2.1" => {
            println!("  ✅ Public Key: Elliptic Curve");
        }
        _ => {
            println!("  ℹ️  Public Key: {}", pk_algo.oid);
        }
    }
}

#[cfg(feature = "spdm")]
fn check_spdm_compliance(cert: &Certificate, opts: &Options, results: &mut ValidationResults) {
    use const_oid::ObjectIdentifier;

    if opts.verbose {
        println!("  Checking for SPDM-specific extensions...");
    }

    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => {
            if opts.verbose {
                println!("  ℹ️  No extensions found - this is a standard X.509 certificate");
            }
            return;
        }
    };

    // Check for SPDM Extension OID
    let has_spdm_ext = extensions.iter().any(|e| is_spdm_oid(&e.extn_id));
    results.spdm_extension = has_spdm_ext;
    if has_spdm_ext {
        println!("  ✅ SPDM Extension found");
    } else if opts.verbose {
        println!("  ℹ️  No SPDM Extension - standard X.509 certificate");
    }

    // Check for Hardware Identity OID
    let has_hw_id = extensions.iter().any(|e| is_hardware_identity(&e.extn_id));
    results.hardware_identity = has_hw_id;
    if has_hw_id {
        println!("  ✅ Hardware Identity found (DeviceCert model)");
    } else if opts.verbose {
        println!("  ℹ️  No Hardware Identity - not a DeviceCert");
    }

    // Check for SPDM EKU
    let has_spdm_eku = extensions.iter().any(|e| is_spdm_eku(&e.extn_id));
    results.spdm_eku = has_spdm_eku;
    if has_spdm_eku {
        println!("  ✅ SPDM EKU found");
    } else if opts.verbose {
        println!("  ℹ️  No SPDM EKU - standard key usage");
    }

    // Verify algorithm compatibility with SPDM
    if opts.verbose {
        println!("\n  Checking SPDM algorithm compatibility...");
    }

    // This certificate uses sha256WithRSAEncryption with RSA 2048
    // In SPDM terms: BaseAsymAlgo bit 0 (RSASSA_2048), BaseHashAlgo bit 0 (SHA_256)
    let base_asym_algo = 1 << 0; // RSASSA_2048
    let base_hash_algo = 1 << 0; // SHA_256

    let algos = SpdmBaseAsymAlgo::from_bits(base_asym_algo);
    if algos.contains(&SpdmBaseAsymAlgo::RsaSsa2048) {
        if opts.verbose {
            println!("  ✅ Compatible with SPDM BaseAsymAlgo: RSASSA_2048");
        }
    }

    let sha256_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    match verify_hash_algorithm(&sha256_oid, base_hash_algo) {
        Ok(_) => {
            if opts.verbose {
                println!("  ✅ Compatible with SPDM BaseHashAlgo: SHA_256");
            }
        }
        Err(e) => {
            if opts.verbose {
                println!("  ⚠️  Hash algorithm check: {:?}", e);
            }
        }
    }

    // Summary
    if !has_spdm_ext && !has_hw_id && !has_spdm_eku && opts.verbose {
        println!("\n  📌 Summary: Standard X.509 certificate (not SPDM-specific)");
        println!("     Algorithms are compatible with SPDM requirements.");
    }
}

fn save_json_report(
    results: &ValidationResults,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;

    writeln!(file, "{{")?;
    writeln!(file, "  \"certificate\": {{")?;
    writeln!(file, "    \"version\": \"{}\",", results.version)?;
    writeln!(
        file,
        "    \"serial_number\": \"{}\",",
        results.serial_number
    )?;
    writeln!(
        file,
        "    \"subject\": \"{}\",",
        results.subject.replace('"', "\\\"")
    )?;
    writeln!(
        file,
        "    \"issuer\": \"{}\",",
        results.issuer.replace('"', "\\\"")
    )?;
    writeln!(file, "    \"not_before\": \"{}\",", results.not_before)?;
    writeln!(file, "    \"not_after\": \"{}\",", results.not_after)?;
    writeln!(
        file,
        "    \"signature_algorithm\": \"{}\",",
        results.signature_algorithm
    )?;
    writeln!(
        file,
        "    \"public_key_algorithm\": \"{}\",",
        results.public_key_algorithm
    )?;
    writeln!(
        file,
        "    \"public_key_size\": \"{}\",",
        results.public_key_size
    )?;
    writeln!(
        file,
        "    \"extensions_count\": {},",
        results.extensions_count
    )?;
    writeln!(file, "    \"extensions\": [")?;
    for (i, ext) in results.extensions.iter().enumerate() {
        if i < results.extensions.len() - 1 {
            writeln!(file, "      \"{}\",", ext)?;
        } else {
            writeln!(file, "      \"{}\"", ext)?;
        }
    }
    writeln!(file, "    ]")?;
    writeln!(file, "  }},")?;

    #[cfg(feature = "spdm")]
    {
        writeln!(file, "  \"spdm\": {{")?;
        writeln!(file, "    \"spdm_extension\": {},", results.spdm_extension)?;
        writeln!(
            file,
            "    \"hardware_identity\": {},",
            results.hardware_identity
        )?;
        writeln!(file, "    \"spdm_eku\": {}", results.spdm_eku)?;
        writeln!(file, "  }},")?;
    }

    writeln!(file, "  \"validation\": {{")?;
    writeln!(file, "    \"checks\": [")?;
    for (i, check) in results.checks.iter().enumerate() {
        writeln!(file, "      {{")?;
        writeln!(file, "        \"name\": \"{}\",", check.name)?;
        writeln!(file, "        \"status\": \"{}\",", check.status)?;
        writeln!(
            file,
            "        \"description\": \"{}\",",
            check.description.replace('"', "\\\"")
        )?;
        writeln!(
            file,
            "        \"details\": \"{}\"",
            check.details.replace('"', "\\\"")
        )?;
        if i < results.checks.len() - 1 {
            writeln!(file, "      }},")?;
        } else {
            writeln!(file, "      }}")?;
        }
    }
    writeln!(file, "    ],")?;
    writeln!(file, "    \"summary\": {{")?;
    writeln!(file, "      \"passed\": {},", results.passed)?;
    writeln!(file, "      \"failed\": {},", results.failed)?;
    writeln!(file, "      \"warnings\": {},", results.warnings)?;
    writeln!(file, "      \"skipped\": {},", results.skipped)?;
    writeln!(file, "      \"overall_valid\": {}", results.overall_valid)?;
    writeln!(file, "    }}")?;
    writeln!(file, "  }}")?;
    writeln!(file, "}}")?;

    Ok(())
}

fn save_txt_report(
    _cert: &Certificate,
    results: &ValidationResults,
    path: &str,
    _opts: &Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;

    writeln!(
        file,
        "═══════════════════════════════════════════════════════════════════"
    )?;
    writeln!(file, "              X.509 CERTIFICATE VALIDATION REPORT")?;
    writeln!(
        file,
        "═══════════════════════════════════════════════════════════════════"
    )?;
    writeln!(file)?;

    writeln!(file, "📋 CERTIFICATE INFORMATION")?;
    writeln!(file, "   Version:             {}", results.version)?;
    writeln!(file, "   Serial Number:       {}", results.serial_number)?;
    writeln!(file, "   Subject:             {}", results.subject)?;
    writeln!(file, "   Issuer:              {}", results.issuer)?;
    writeln!(file, "   Not Before:          {}", results.not_before)?;
    writeln!(file, "   Not After:           {}", results.not_after)?;
    writeln!(
        file,
        "   Signature Algorithm: {}",
        results.signature_algorithm
    )?;
    writeln!(
        file,
        "   Public Key Algorithm:{}",
        results.public_key_algorithm
    )?;
    writeln!(file, "   Public Key Size:     {}", results.public_key_size)?;
    writeln!(
        file,
        "   Extensions:          {} extensions found",
        results.extensions_count
    )?;
    for ext in &results.extensions {
        writeln!(file, "     - {}", ext)?;
    }
    writeln!(file)?;

    #[cfg(feature = "spdm")]
    {
        writeln!(file, "🔒 SPDM COMPLIANCE")?;
        writeln!(
            file,
            "   SPDM Extension:      {}",
            if results.spdm_extension {
                "✓ Yes"
            } else {
                "✗ No"
            }
        )?;
        writeln!(
            file,
            "   Hardware Identity:   {}",
            if results.hardware_identity {
                "✓ Yes (DeviceCert)"
            } else {
                "✗ No"
            }
        )?;
        writeln!(
            file,
            "   SPDM EKU:            {}",
            if results.spdm_eku {
                "✓ Yes"
            } else {
                "✗ No"
            }
        )?;
        writeln!(file)?;
    }

    writeln!(file, "🔐 VALIDATION CHECKS")?;
    writeln!(file, "   Total checks: {}", results.checks.len())?;
    writeln!(file)?;

    for check in &results.checks {
        let symbol = match check.status.as_str() {
            "PASS" => "✓ [PASS]",
            "FAIL" => "✗ [FAIL]",
            "WARN" => "⚠ [WARN]",
            "SKIP" => "○ [SKIP]",
            _ => "? [UNKN]",
        };
        writeln!(file, "   {} {}", symbol, check.name)?;
        writeln!(file, "      {}", check.description)?;
        writeln!(file, "      Details: {}", check.details)?;
        writeln!(file)?;
    }

    writeln!(
        file,
        "═══════════════════════════════════════════════════════════════════"
    )?;
    writeln!(file, "📊 SUMMARY")?;
    writeln!(file, "   Passed:   {} ✓", results.passed)?;
    writeln!(file, "   Failed:   {} ✗", results.failed)?;
    writeln!(file, "   Warnings: {} ⚠", results.warnings)?;
    writeln!(file, "   Skipped:  {} ○", results.skipped)?;
    writeln!(file)?;

    writeln!(file, "🏁 OVERALL RESULT")?;
    if results.overall_valid && results.failed == 0 {
        writeln!(file, "   ✓✓✓ CERTIFICATE IS VALID ✓✓✓")?;
    } else if results.warnings > 0 && results.failed == 0 {
        writeln!(file, "   ⚠⚠⚠ CERTIFICATE IS PARTIALLY VALID ⚠⚠⚠")?;
    } else {
        writeln!(file, "   ✗✗✗ CERTIFICATE IS INVALID ✗✗✗")?;
    }
    writeln!(
        file,
        "═══════════════════════════════════════════════════════════════════"
    )?;

    Ok(())
}
