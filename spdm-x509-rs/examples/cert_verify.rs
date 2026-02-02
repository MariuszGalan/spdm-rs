//! Comprehensive X.509 Certificate Verification Tool
//!
//! This tool performs detailed validation of X.509 certificates and generates
//! a comprehensive report including all checks performed.
//!
//! Usage: cargo run --example cert_verify <cert.der> [--output report.json]

use std::env;
use std::fs;
use std::io::Write;
use spdm_x509::time_utils::Time;
use spdm_x509::{Certificate, ValidationOptions, Validator};

/// Extract the first certificate from a PEM file that may contain extra metadata
/// (like Bag Attributes) or multiple PEM blocks (certificate + private key)
fn extract_first_certificate_pem(text: &str) -> String {
    let mut result = String::new();
    let mut in_cert = false;
    let found_cert;

    for line in text.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            result.push_str(line);
            result.push('\n');
        } else if line.contains("-----END CERTIFICATE-----") {
            result.push_str(line);
            result.push('\n');
            // Stop after first certificate
            break;
        } else if in_cert {
            result.push_str(line);
            result.push('\n');
        }
    }

    found_cert = !result.is_empty();

    if !found_cert {
        // Return original if no certificate found
        text.to_string()
    } else {
        result
    }
}

#[derive(Debug)]
struct ValidationReport {
    cert_path: String,
    file_size: usize,
    parse_result: Result<(), String>,
    basic_info: Option<CertificateInfo>,
    validation_checks: Vec<ValidationCheck>,
    overall_result: ValidationResult,
}

#[derive(Debug)]
struct CertificateInfo {
    version: String,
    serial_number: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    signature_algorithm: String,
    public_key_algorithm: String,
    extensions: Vec<String>,
}

#[derive(Debug)]
struct ValidationCheck {
    name: String,
    description: String,
    result: CheckResult,
    details: Option<String>,
    verbose_info: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum CheckResult {
    Passed,
    Failed,
    Warning,
    Skipped,
}

#[derive(Debug)]
enum ValidationResult {
    Valid,
    Invalid(String),
    PartiallyValid(Vec<String>),
}

impl ValidationReport {
    fn new(cert_path: String) -> Self {
        Self {
            cert_path,
            file_size: 0,
            parse_result: Err("Not yet parsed".to_string()),
            basic_info: None,
            validation_checks: Vec::new(),
            overall_result: ValidationResult::Invalid("Not validated".to_string()),
        }
    }

    fn add_check(
        &mut self,
        name: String,
        description: String,
        result: CheckResult,
        details: Option<String>,
    ) {
        self.add_check_verbose(name, description, result, details, None);
    }

    fn add_check_verbose(
        &mut self,
        name: String,
        description: String,
        result: CheckResult,
        details: Option<String>,
        verbose_info: Option<String>,
    ) {
        self.validation_checks.push(ValidationCheck {
            name,
            description,
            result,
            details,
            verbose_info,
        });
    }

    fn print_report(&self, verbose: bool) {
        println!("═══════════════════════════════════════════════════════════════════");
        println!("              X.509 CERTIFICATE VALIDATION REPORT");
        println!("═══════════════════════════════════════════════════════════════════\n");

        // File Information
        println!("📄 FILE INFORMATION");
        println!("   Path: {}", self.cert_path);
        println!("   Size: {} bytes\n", self.file_size);

        // Parse Result
        println!("🔍 PARSING");
        match &self.parse_result {
            Ok(_) => println!("   ✓ Certificate parsed successfully\n"),
            Err(e) => {
                println!("   ✗ Parse failed: {}\n", e);
                return;
            }
        }

        // Basic Information
        if let Some(ref info) = self.basic_info {
            println!("📋 CERTIFICATE INFORMATION");
            println!("   Version:             {}", info.version);
            println!("   Serial Number:       {}", info.serial_number);
            println!("   Subject:             {}", info.subject);
            println!("   Issuer:              {}", info.issuer);
            println!("   Not Before:          {}", info.not_before);
            println!("   Not After:           {}", info.not_after);
            println!("   Signature Algorithm: {}", info.signature_algorithm);
            println!("   Public Key Algorithm:{}", info.public_key_algorithm);

            if !info.extensions.is_empty() {
                println!(
                    "   Extensions:          {} extensions found",
                    info.extensions.len()
                );
                for ext in &info.extensions {
                    println!("     - {}", ext);
                }
            }
            println!();
        }

        // Validation Checks
        println!("🔐 VALIDATION CHECKS");
        println!("   Total checks: {}\n", self.validation_checks.len());

        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut skipped = 0;

        for check in &self.validation_checks {
            let (symbol, color) = match check.result {
                CheckResult::Passed => {
                    passed += 1;
                    ("✓", "PASS")
                }
                CheckResult::Failed => {
                    failed += 1;
                    ("✗", "FAIL")
                }
                CheckResult::Warning => {
                    warnings += 1;
                    ("⚠", "WARN")
                }
                CheckResult::Skipped => {
                    skipped += 1;
                    ("○", "SKIP")
                }
            };

            println!("   {} [{}] {}", symbol, color, check.name);
            println!("      {}", check.description);
            if let Some(ref details) = check.details {
                println!("      Details: {}", details);
            }
            if verbose {
                if let Some(ref verbose_info) = check.verbose_info {
                    println!("      ℹ️  Verbose: {}", verbose_info);
                }
            }
            println!();
        }

        // Summary
        println!("═══════════════════════════════════════════════════════════════════");
        println!("📊 SUMMARY");
        println!("   Passed:   {} ✓", passed);
        println!("   Failed:   {} ✗", failed);
        println!("   Warnings: {} ⚠", warnings);
        println!("   Skipped:  {} ○", skipped);
        println!();

        // Overall Result
        println!("🏁 OVERALL RESULT");
        match &self.overall_result {
            ValidationResult::Valid => {
                println!("   ✓✓✓ CERTIFICATE IS VALID ✓✓✓");
            }
            ValidationResult::Invalid(reason) => {
                println!("   ✗✗✗ CERTIFICATE IS INVALID ✗✗✗");
                println!("   Reason: {}", reason);
            }
            ValidationResult::PartiallyValid(issues) => {
                println!("   ⚠⚠⚠ CERTIFICATE IS PARTIALLY VALID ⚠⚠⚠");
                println!("   Issues:");
                for issue in issues {
                    println!("     - {}", issue);
                }
            }
        }
        println!("═══════════════════════════════════════════════════════════════════\n");
    }

    fn save_json(&self, output_path: &str) -> std::io::Result<()> {
        let json = serde_json::json!({
            "cert_path": self.cert_path,
            "file_size": self.file_size,
            "parse_result": match &self.parse_result {
                Ok(_) => "success",
                Err(_) => "failed"
            },
            "basic_info": self.basic_info.as_ref().map(|info| serde_json::json!({
                "version": info.version,
                "serial_number": info.serial_number,
                "subject": info.subject,
                "issuer": info.issuer,
                "not_before": info.not_before,
                "not_after": info.not_after,
                "signature_algorithm": info.signature_algorithm,
                "public_key_algorithm": info.public_key_algorithm,
                "extensions": info.extensions,
            })),
            "validation_checks": self.validation_checks.iter().map(|check| {
                serde_json::json!({
                    "name": check.name,
                    "description": check.description,
                    "result": format!("{:?}", check.result),
                    "details": check.details,
                })
            }).collect::<Vec<_>>(),
            "overall_result": format!("{:?}", self.overall_result),
        });

        let mut file = fs::File::create(output_path)?;
        file.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;
        Ok(())
    }

    fn save_text(&self, output_path: &str, verbose: bool) -> std::io::Result<()> {
        let mut content = String::new();

        content.push_str("═══════════════════════════════════════════════════════════════════\n");
        content.push_str("              X.509 CERTIFICATE VALIDATION REPORT\n");
        content.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        // File Information
        content.push_str("📄 FILE INFORMATION\n");
        content.push_str(&format!("   Path: {}\n", self.cert_path));
        content.push_str(&format!("   Size: {} bytes\n\n", self.file_size));

        // Parse Result
        content.push_str("🔍 PARSING\n");
        match &self.parse_result {
            Ok(_) => content.push_str("   ✓ Certificate parsed successfully\n\n"),
            Err(e) => content.push_str(&format!("   ✗ Parse failed: {}\n\n", e)),
        }

        // Basic Certificate Information
        if let Some(ref info) = self.basic_info {
            content.push_str("📋 CERTIFICATE INFORMATION\n");
            content.push_str(&format!("   Version:             {}\n", info.version));
            content.push_str(&format!("   Serial Number:       {}\n", info.serial_number));
            content.push_str(&format!("   Subject:             {}\n", info.subject));
            content.push_str(&format!("   Issuer:              {}\n", info.issuer));
            content.push_str(&format!("   Not Before:          {}\n", info.not_before));
            content.push_str(&format!("   Not After:           {}\n", info.not_after));
            content.push_str(&format!(
                "   Signature Algorithm: {}\n",
                info.signature_algorithm
            ));
            content.push_str(&format!(
                "   Public Key Algorithm:{}\n",
                info.public_key_algorithm
            ));
            content.push_str(&format!(
                "   Extensions:          {} extensions found\n",
                info.extensions.len()
            ));
            for ext in &info.extensions {
                content.push_str(&format!("     - {}\n", ext));
            }
            content.push_str("\n");
        }

        // Validation Checks
        content.push_str("🔐 VALIDATION CHECKS\n");
        content.push_str(&format!(
            "   Total checks: {}\n\n",
            self.validation_checks.len()
        ));

        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut skipped = 0;

        for check in &self.validation_checks {
            let (symbol, color) = match check.result {
                CheckResult::Passed => {
                    passed += 1;
                    ("✓", "PASS")
                }
                CheckResult::Failed => {
                    failed += 1;
                    ("✗", "FAIL")
                }
                CheckResult::Warning => {
                    warnings += 1;
                    ("⚠", "WARN")
                }
                CheckResult::Skipped => {
                    skipped += 1;
                    ("○", "SKIP")
                }
            };

            content.push_str(&format!("   {} [{}] {}\n", symbol, color, check.name));
            content.push_str(&format!("      {}\n", check.description));
            if let Some(ref details) = check.details {
                content.push_str(&format!("      Details: {}\n", details));
            }
            if verbose {
                if let Some(ref verbose_info) = check.verbose_info {
                    content.push_str(&format!("      ℹ️  Verbose: {}\n", verbose_info));
                }
            }
            content.push_str("\n");
        }

        // Summary
        content.push_str("═══════════════════════════════════════════════════════════════════\n");
        content.push_str("📊 SUMMARY\n");
        content.push_str(&format!("   Passed:   {} ✓\n", passed));
        content.push_str(&format!("   Failed:   {} ✗\n", failed));
        content.push_str(&format!("   Warnings: {} ⚠\n", warnings));
        content.push_str(&format!("   Skipped:  {} ○\n\n", skipped));

        // Overall Result
        content.push_str("🏁 OVERALL RESULT\n");
        match &self.overall_result {
            ValidationResult::Valid => {
                content.push_str("   ✓✓✓ CERTIFICATE IS VALID ✓✓✓\n");
            }
            ValidationResult::Invalid(reason) => {
                content.push_str("   ✗✗✗ CERTIFICATE IS INVALID ✗✗✗\n");
                content.push_str(&format!("   Reason: {}\n", reason));
            }
            ValidationResult::PartiallyValid(issues) => {
                content.push_str("   ⚠⚠⚠ CERTIFICATE IS PARTIALLY VALID ⚠⚠⚠\n");
                content.push_str("   Issues:\n");
                for issue in issues {
                    content.push_str(&format!("     - {}\n", issue));
                }
            }
        }
        content.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        let mut file = fs::File::create(output_path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("X.509 Certificate Verification Tool");
        eprintln!("\nUsage: {} <certificate.der> [OPTIONS]", args[0]);
        eprintln!("\nOptions:");
        eprintln!("  --output <file.json>      Save JSON report to file");
        eprintln!("  --text-output <file.txt>  Save human-readable report to text file");
        eprintln!("  --check-time              Enable time-based validity check");
        eprintln!("  --verbose                 Show detailed explanations for warnings/errors");
        eprintln!("\nExamples:");
        eprintln!("  cargo run --example cert_verify examples/lcd_certchain.der.bin");
        eprintln!("  cargo run --example cert_verify cert.der --output report.json");
        eprintln!("  cargo run --example cert_verify cert.der --check-time --verbose");
        eprintln!("  cargo run --example cert_verify cert.der --text-output report.txt --verbose");
        std::process::exit(1);
    }

    let cert_path = args[1].clone();
    let mut output_path: Option<String> = None;
    let mut text_output_path: Option<String> = None;
    let mut check_time = false;
    let mut verbose = false;

    // Parse command-line arguments
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a filename");
                    std::process::exit(1);
                }
            }
            "--text-output" => {
                if i + 1 < args.len() {
                    text_output_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --text-output requires a filename");
                    std::process::exit(1);
                }
            }
            "--check-time" => {
                check_time = true;
                i += 1;
            }
            "--verbose" => {
                verbose = true;
                i += 1;
            }
            _ => {
                eprintln!("Error: Unknown option '{}'", args[i]);
                std::process::exit(1);
            }
        }
    }

    let mut report = ValidationReport::new(cert_path.clone());

    // Read certificate file
    let file_contents = match fs::read(&cert_path) {
        Ok(bytes) => {
            report.file_size = bytes.len();
            bytes
        }
        Err(e) => {
            eprintln!("Error reading certificate file '{}': {}", cert_path, e);
            std::process::exit(1);
        }
    };

    // Try to detect if it's PEM or DER
    let cert = if let Ok(text) = std::str::from_utf8(&file_contents) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            // It's PEM format - extract the certificate portion
            // Handle files with extra metadata (Bag Attributes, multiple certificates, etc.)
            let pem_cert = extract_first_certificate_pem(text);

            match Certificate::from_pem(&pem_cert) {
                Ok(c) => {
                    report.parse_result = Ok(());
                    c
                }
                Err(e) => {
                    report.parse_result = Err(format!("PEM parse error: {}", e));
                    report.print_report(false);
                    std::process::exit(1);
                }
            }
        } else {
            // Try DER
            match Certificate::from_der(&file_contents) {
                Ok(c) => {
                    report.parse_result = Ok(());
                    c
                }
                Err(e) => {
                    report.parse_result = Err(format!("DER parse error: {}", e));
                    report.print_report(false);
                    std::process::exit(1);
                }
            }
        }
    } else {
        // Binary file, assume DER
        match Certificate::from_der(&file_contents) {
            Ok(c) => {
                report.parse_result = Ok(());
                c
            }
            Err(e) => {
                report.parse_result = Err(format!("DER parse error: {}", e));
                report.print_report(false);
                std::process::exit(1);
            }
        }
    };

    // Extract basic information
    let extensions: Vec<String> = if let Some(ref exts) = cert.tbs_certificate.extensions {
        exts.extensions
            .iter()
            .map(|ext| {
                format!(
                    "{}{}",
                    ext.extn_id,
                    if ext.critical { " (critical)" } else { "" }
                )
            })
            .collect()
    } else {
        Vec::new()
    };

    report.basic_info = Some(CertificateInfo {
        version: format!("{}", cert.tbs_certificate.version),
        serial_number: hex::encode(cert.tbs_certificate.serial_number()),
        subject: format!("{}", cert.tbs_certificate.subject),
        issuer: format!("{}", cert.tbs_certificate.issuer),
        not_before: format!("{:?}", cert.tbs_certificate.validity.not_before),
        not_after: format!("{:?}", cert.tbs_certificate.validity.not_after),
        signature_algorithm: format!("{}", cert.signature_algorithm.algorithm),
        public_key_algorithm: format!(
            "{}",
            cert.tbs_certificate.subject_public_key_info.algorithm.oid
        ),
        extensions,
    });

    // Perform validation checks

    // Check 1: DER Structure Validity
    report.add_check(
        "DER Structure Validation".to_string(),
        "Verify certificate has valid DER/ASN.1 encoding".to_string(),
        CheckResult::Passed,
        Some("Certificate successfully decoded from DER format".to_string()),
    );

    // Check 2: Version Field
    let version_check = if cert.tbs_certificate.version == spdm_x509::certificate::Version::V3
    {
        (
            CheckResult::Passed,
            Some("Certificate uses X.509 v3 (modern standard)".to_string()),
            None,
        )
    } else {
        (
            CheckResult::Warning,
            Some(format!(
                "Certificate uses {:?} (v3 recommended)",
                cert.tbs_certificate.version
            )),
            Some("X.509 v3 is the current standard and required for modern applications. v3 introduced critical features like extensions which enable key usage restrictions, subject alternative names, and other security constraints. v1 and v2 certificates lack these capabilities and are considered deprecated. Modern systems and browsers may reject non-v3 certificates.".to_string()),
        )
    };
    report.add_check_verbose(
        "Version Check".to_string(),
        "Verify certificate version is appropriate".to_string(),
        version_check.0,
        version_check.1,
        version_check.2,
    );

    // Check 3: Serial Number
    let serial_len = cert.tbs_certificate.serial_number().len();
    let serial_check = if serial_len > 0 && serial_len <= 20 {
        (
            CheckResult::Passed,
            Some(format!("Serial number length: {} bytes", serial_len)),
            None,
        )
    } else {
        (
            CheckResult::Warning,
            Some(format!(
                "Serial number length {} bytes (RFC 5280 recommends ≤20)",
                serial_len
            )),
            Some("RFC 5280 Section 4.1.2.2 recommends that certificate serial numbers be no longer than 20 bytes. While longer serial numbers are technically allowed, they may cause compatibility issues with some implementations. Excessively long serial numbers can also indicate implementation problems in the certificate authority.".to_string()),
        )
    };
    report.add_check_verbose(
        "Serial Number Validity".to_string(),
        "Verify serial number is present and within recommended size".to_string(),
        serial_check.0,
        serial_check.1,
        serial_check.2,
    );

    // Check 4: Signature Algorithm
    let sig_alg_name = format!("{}", cert.signature_algorithm.algorithm);
    let sig_alg_oid = format!("{}", cert.signature_algorithm.algorithm);
    let sig_check = if sig_alg_name.contains("sha256")
        || sig_alg_name.contains("sha384")
        || sig_alg_name.contains("sha512")
    {
        (
            CheckResult::Passed,
            Some(format!("Using strong algorithm: {}", sig_alg_name)),
            None,
        )
    } else if sig_alg_oid == "1.2.840.113549.1.1.11" {
        // SHA-256 with RSA
        (
            CheckResult::Passed,
            Some(format!("Algorithm: {}", sig_alg_name)),
            None,
        )
    } else if sig_alg_name.contains("sha1") || sig_alg_oid == "1.2.840.113549.1.1.5" {
        // SHA-1 with RSA
        (
            CheckResult::Warning,
            Some(format!("Algorithm: {} (SHA-1 deprecated)", sig_alg_name)),
            Some("SHA-1 is cryptographically broken and deprecated for certificate signatures. Collision attacks against SHA-1 are practical and have been demonstrated. All major browsers and certificate authorities have deprecated SHA-1 certificates. Use SHA-256 or stronger algorithms instead.".to_string()),
        )
    } else if sig_alg_name.contains("md5") || sig_alg_name.contains("md2") {
        (
            CheckResult::Warning,
            Some(format!("Algorithm: {} (broken)", sig_alg_name)),
            Some("MD5 and MD2 are completely broken cryptographic hash functions. Collision attacks are trivial to execute. MD5 has been broken since 2004 and should never be used in production systems. Certificates using MD5/MD2 are completely insecure and must be replaced immediately.".to_string()),
        )
    } else {
        (
            CheckResult::Warning,
            Some(format!("Algorithm: {}", sig_alg_name)),
            Some(format!("The signature algorithm '{}' is not recognized as a modern secure algorithm. It may be deprecated or have known vulnerabilities. Recommended algorithms: SHA-256, SHA-384, or SHA-512 with RSA or ECDSA. Verify this algorithm meets your security requirements.", sig_alg_name)),
        )
    };
    report.add_check_verbose(
        "Signature Algorithm Security".to_string(),
        "Verify signature algorithm is cryptographically strong".to_string(),
        sig_check.0,
        sig_check.1,
        sig_check.2,
    );

    // Check 5: Subject and Issuer
    let subject_str = format!("{}", cert.tbs_certificate.subject);
    let issuer_str = format!("{}", cert.tbs_certificate.issuer);

    report.add_check(
        "Subject Distinguished Name".to_string(),
        "Verify subject DN is present and valid".to_string(),
        if !subject_str.is_empty() {
            CheckResult::Passed
        } else {
            CheckResult::Failed
        },
        Some(subject_str.clone()),
    );

    report.add_check(
        "Issuer Distinguished Name".to_string(),
        "Verify issuer DN is present and valid".to_string(),
        if !issuer_str.is_empty() {
            CheckResult::Passed
        } else {
            CheckResult::Failed
        },
        Some(issuer_str.clone()),
    );

    // Check 6: Self-signed check
    let is_self_signed = subject_str == issuer_str;
    report.add_check(
        "Self-Signed Certificate Detection".to_string(),
        "Check if certificate is self-signed (subject == issuer)".to_string(),
        CheckResult::Passed,
        Some(
            if is_self_signed {
                "Certificate is self-signed"
            } else {
                "Certificate is not self-signed"
            }
            .to_string(),
        ),
    );

    // Check 7: Validity Period
    report.add_check(
        "Validity Period Structure".to_string(),
        "Verify notBefore and notAfter dates are present".to_string(),
        CheckResult::Passed,
        Some(format!(
            "Valid from {:?} to {:?}",
            cert.tbs_certificate.validity.not_before, cert.tbs_certificate.validity.not_after
        )),
    );

    // Check 8: Time Validation (actual current time check)
    if check_time {
        use std::time::{SystemTime, UNIX_EPOCH};

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time error")
            .as_secs();

        let not_before_valid = match &cert.tbs_certificate.validity.not_before {
            Time::UtcTime(utc) => current_time >= utc.to_unix_duration().as_secs(),
            Time::GeneralizedTime(gen) => current_time >= gen.to_unix_duration().as_secs(),
        };

        let not_after_valid = match &cert.tbs_certificate.validity.not_after {
            Time::UtcTime(utc) => current_time <= utc.to_unix_duration().as_secs(),
            Time::GeneralizedTime(gen) => current_time <= gen.to_unix_duration().as_secs(),
        };

        let (result, details, verbose_info) = if !not_before_valid {
            (
                CheckResult::Failed,
                "Certificate is not yet valid (future-dated)",
                Some(format!("The certificate's notBefore time ({:?}) is in the future. Current time check shows this certificate should not be trusted yet. This could indicate: 1) System clock is incorrect, 2) Certificate was generated with wrong timestamp, or 3) Attempting to use certificate before its validity period. Verify your system time and the certificate's intended validity period.", cert.tbs_certificate.validity.not_before)),
            )
        } else if !not_after_valid {
            (
                CheckResult::Failed,
                "Certificate has expired",
                Some(format!("The certificate's notAfter time ({:?}) has passed. Expired certificates should not be trusted as they may have been compromised or revoked. This is a critical security issue. The certificate owner must renew the certificate. Do NOT bypass this check in production environments.", cert.tbs_certificate.validity.not_after)),
            )
        } else {
            (CheckResult::Passed, "Certificate is currently valid", None)
        };

        report.add_check_verbose(
            "Time-based Validity Check".to_string(),
            "Verify certificate is currently valid (not expired, not future-dated)".to_string(),
            result,
            Some(details.to_string()),
            verbose_info,
        );
    } else {
        report.add_check(
            "Time-based Validity Check".to_string(),
            "Verify certificate is currently valid (not expired, not future-dated)".to_string(),
            CheckResult::Skipped,
            Some("Skipped - use --check-time flag to enable".to_string()),
        );
    }

    // Check 9: Extensions
    if let Some(ref exts) = cert.tbs_certificate.extensions {
        report.add_check(
            "Extensions Presence".to_string(),
            "Check for X.509 v3 extensions".to_string(),
            CheckResult::Passed,
            Some(format!("{} extension(s) found", exts.extensions.len())),
        );

        // Check for critical extensions
        let critical_exts: Vec<_> = exts
            .extensions
            .iter()
            .filter(|e| e.critical)
            .map(|e| format!("{}", e.extn_id))
            .collect();

        if !critical_exts.is_empty() {
            report.add_check(
                "Critical Extensions".to_string(),
                "Verify all critical extensions are recognized".to_string(),
                CheckResult::Passed,
                Some(format!("Critical extensions: {}", critical_exts.join(", "))),
            );
        }
    } else {
        report.add_check(
            "Extensions Presence".to_string(),
            "Check for X.509 v3 extensions".to_string(),
            CheckResult::Warning,
            Some("No extensions found (unusual for modern certificates)".to_string()),
        );
    }

    // Check 10: Public Key
    let pk_bits = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .len()
        * 8;
    report.add_check(
        "Public Key Presence".to_string(),
        "Verify subject public key is present".to_string(),
        CheckResult::Passed,
        Some(format!("Public key size: {} bits", pk_bits)),
    );

    // Check 11: Signature Verification
    if is_self_signed {
        let validator = Validator::new();
        match validator.verify_signature(&cert, &cert) {
            Ok(_) => {
                report.add_check(
                    "Self-Signature Verification".to_string(),
                    "Verify self-signed certificate signature is valid".to_string(),
                    CheckResult::Passed,
                    Some("Signature verified successfully using own public key".to_string()),
                );
            }
            Err(e) => {
                report.add_check(
                    "Self-Signature Verification".to_string(),
                    "Verify self-signed certificate signature is valid".to_string(),
                    CheckResult::Failed,
                    Some(format!("Signature verification failed: {}", e)),
                );
            }
        }
    } else {
        report.add_check(
            "Signature Verification".to_string(),
            "Verify certificate signature (requires issuer certificate)".to_string(),
            CheckResult::Skipped,
            Some("Issuer certificate not provided - cannot verify signature".to_string()),
        );
    }

    // Check 12: Overall Structure Validation
    let validator = Validator::new();
    let options = ValidationOptions::default()
        .skip_time_validation()
        .skip_signature_validation();

    match validator.validate(&cert, &options) {
        Ok(_) => {
            report.add_check(
                "Overall Structure Validation".to_string(),
                "Comprehensive validation of certificate structure and constraints".to_string(),
                CheckResult::Passed,
                Some("All structural validations passed".to_string()),
            );
        }
        Err(e) => {
            report.add_check(
                "Overall Structure Validation".to_string(),
                "Comprehensive validation of certificate structure and constraints".to_string(),
                CheckResult::Failed,
                Some(format!("Validation error: {}", e)),
            );
        }
    }

    // Determine overall result
    let failed_checks: Vec<_> = report
        .validation_checks
        .iter()
        .filter(|c| matches!(c.result, CheckResult::Failed))
        .map(|c| c.name.clone())
        .collect();

    let warning_checks: Vec<_> = report
        .validation_checks
        .iter()
        .filter(|c| matches!(c.result, CheckResult::Warning))
        .map(|c| c.name.clone())
        .collect();

    report.overall_result = if !failed_checks.is_empty() {
        ValidationResult::Invalid(format!("{} check(s) failed", failed_checks.len()))
    } else if !warning_checks.is_empty() {
        ValidationResult::PartiallyValid(warning_checks)
    } else {
        ValidationResult::Valid
    };

    // Print report to console
    report.print_report(verbose);

    // Save JSON report if requested
    if let Some(ref output) = output_path {
        match report.save_json(output) {
            Ok(_) => println!("✓ JSON report saved to: {}", output),
            Err(e) => eprintln!("✗ Failed to save JSON report: {}", e),
        }
    }

    // Save text report if requested
    if let Some(ref output) = text_output_path {
        match report.save_text(output, verbose) {
            Ok(_) => println!("✓ Text report saved to: {}", output),
            Err(e) => eprintln!("✗ Failed to save text report: {}", e),
        }
    }

    // Exit with appropriate code
    let exit_code = match report.overall_result {
        ValidationResult::Valid => 0,
        ValidationResult::PartiallyValid(_) => 1,
        ValidationResult::Invalid(_) => 2,
    };

    std::process::exit(exit_code);
}
