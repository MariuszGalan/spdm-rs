//! SPDM Certificate Validation Tool
//!
//! This tool validates X.509 certificates according to SPDM (DSP0274) specification.
//! It allows testing certificates with different SPDM models and roles.
//!
//! Usage:
//!   cargo run --features spdm --example validate_spdm_cert <cert.der> [OPTIONS]
//!
//! Examples:
//!   # Validate as DeviceCert Responder
//!   cargo run --features spdm --example validate_spdm_cert examples/test_cert.der
//!
//!   # Validate as AliasCert Requester with specific algorithms
//!   cargo run --features spdm --example validate_spdm_cert cert.pem \
//!     --model alias --role requester --asym ecdsa-p256 --hash sha256
//!
//!   # Validate with all details
//!   cargo run --features spdm --example validate_spdm_cert cert.der \
//!     --model device --role responder --verbose

use std::env;
use std::fs;
use std::process;

#[cfg(feature = "spdm")]
use spdm_x509::spdm::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertificateModel, SpdmCertificateRole, SpdmValidator,
};
use spdm_x509::validator::ValidationOptions;
use spdm_x509::Certificate;

#[cfg(feature = "spdm")]
fn parse_model(s: &str) -> Result<SpdmCertificateModel, String> {
    match s.to_lowercase().as_str() {
        "device" | "devicecert" | "0" => Ok(SpdmCertificateModel::DeviceCert),
        "alias" | "aliascert" | "1" => Ok(SpdmCertificateModel::AliasCert),
        "generic" | "genericcert" | "2" => Ok(SpdmCertificateModel::GenericCert),
        _ => Err(format!("Invalid model: {}. Use: device, alias, or generic", s)),
    }
}

#[cfg(feature = "spdm")]
fn parse_role(s: &str) -> Result<SpdmCertificateRole, String> {
    match s.to_lowercase().as_str() {
        "requester" | "req" => Ok(SpdmCertificateRole::Requester),
        "responder" | "resp" => Ok(SpdmCertificateRole::Responder),
        _ => Err(format!(
            "Invalid role: {}. Use: requester or responder",
            s
        )),
    }
}

#[cfg(feature = "spdm")]
fn parse_asym_algo(s: &str) -> Result<u32, String> {
    match s.to_lowercase().as_str() {
        "rsa2048" | "rsa-2048" => Ok(1 << 0),
        "rsa3072" | "rsa-3072" => Ok(1 << 1),
        "rsa4096" | "rsa-4096" => Ok(1 << 2),
        "ecdsa-p256" | "p256" => Ok(1 << 4),
        "ecdsa-p384" | "p384" => Ok(1 << 7),
        "ecdsa-p521" | "p521" => Ok(1 << 8),
        "all" => Ok(0xFFFF),
        _ => Err(format!(
            "Invalid asymmetric algorithm: {}. Use: rsa2048, rsa3072, rsa4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, or all",
            s
        )),
    }
}

#[cfg(feature = "spdm")]
fn parse_hash_algo(s: &str) -> Result<u32, String> {
    match s.to_lowercase().as_str() {
        "sha256" | "sha-256" => Ok(1 << 0),
        "sha384" | "sha-384" => Ok(1 << 1),
        "sha512" | "sha-512" => Ok(1 << 2),
        "all" => Ok(0xFFFF),
        _ => Err(format!(
            "Invalid hash algorithm: {}. Use: sha256, sha384, sha512, or all",
            s
        )),
    }
}

#[cfg(feature = "spdm")]
struct Config {
    cert_path: String,
    model: SpdmCertificateModel,
    role: SpdmCertificateRole,
    base_asym_algo: u32,
    base_hash_algo: u32,
    verbose: bool,
    skip_time: bool,
    output_file: Option<String>,
}

#[cfg(feature = "spdm")]
impl Default for Config {
    fn default() -> Self {
        Self {
            cert_path: String::new(),
            model: SpdmCertificateModel::DeviceCert,
            role: SpdmCertificateRole::Responder,
            base_asym_algo: 0xFFFF, // All algorithms
            base_hash_algo: 0xFFFF, // All algorithms
            verbose: false,
            skip_time: false,
            output_file: None,
        }
    }
}

#[cfg(feature = "spdm")]
fn print_usage(program: &str) {
    eprintln!("SPDM Certificate Validation Tool");
    eprintln!();
    eprintln!("Usage: {} <certificate> [OPTIONS]", program);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <certificate>          Path to certificate file (DER or PEM format)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --model <MODEL>        Certificate model: device, alias, generic");
    eprintln!("                         (default: device)");
    eprintln!("  --role <ROLE>          Certificate role: requester, responder");
    eprintln!("                         (default: responder)");
    eprintln!("  --asym <ALGO>          Asymmetric algorithm: rsa2048, rsa3072, rsa4096,");
    eprintln!("                         ecdsa-p256, ecdsa-p384, ecdsa-p521, all");
    eprintln!("                         (default: all)");
    eprintln!("  --hash <ALGO>          Hash algorithm: sha256, sha384, sha512, all");
    eprintln!("                         (default: all)");
    eprintln!("  --verbose, -v          Show detailed information");
    eprintln!("  --skip-time            Skip time validation");
    eprintln!("  --output, -o <FILE>    Save results to file (JSON or TXT based on extension)");
    eprintln!("  --help, -h             Show this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} cert.der", program);
    eprintln!("  {} cert.der --output report.json", program);
    eprintln!("  {} cert.der --output report.txt", program);
    eprintln!("  {} cert.pem --model alias --role requester", program);
    eprintln!("  {} cert.der --asym ecdsa-p256 --hash sha256 -v", program);
}

#[cfg(feature = "spdm")]
fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();

    // Check for help first, before anything else
    if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
        return Err("help".to_string());
    }

    let mut config = Config::default();
    config.cert_path = args[1].clone();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--model" | "-m" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --model".to_string());
                }
                config.model = parse_model(&args[i])?;
            }
            "--role" | "-r" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --role".to_string());
                }
                config.role = parse_role(&args[i])?;
            }
            "--asym" | "-a" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --asym".to_string());
                }
                config.base_asym_algo = parse_asym_algo(&args[i])?;
            }
            "--hash" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --hash".to_string());
                }
                config.base_hash_algo = parse_hash_algo(&args[i])?;
            }
            "--verbose" | "-v" => {
                config.verbose = true;
            }
            "--skip-time" => {
                config.skip_time = true;
            }
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --output".to_string());
                }
                config.output_file = Some(args[i].clone());
            }
            arg => {
                return Err(format!("Unknown option: {}", arg));
            }
        }
        i += 1;
    }

    Ok(config)
}

#[cfg(feature = "spdm")]
fn load_certificate(path: &str) -> Result<Certificate, String> {
    // Read file
    let cert_bytes = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Try to parse as DER first
    if let Ok(cert) = Certificate::from_der(&cert_bytes) {
        return Ok(cert);
    }

    // Try as PEM
    let pem_str = String::from_utf8(cert_bytes.clone())
        .map_err(|_| "File is not valid UTF-8 and not valid DER".to_string())?;

    // Extract first certificate from PEM (handle files with extra data)
    let pem_clean = extract_first_certificate_pem(&pem_str);

    Certificate::from_pem(&pem_clean).map_err(|e| format!("Failed to parse certificate: {}", e))
}

#[cfg(feature = "spdm")]
fn extract_first_certificate_pem(text: &str) -> String {
    let mut result = String::new();
    let mut in_cert = false;

    for line in text.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            result.push_str(line);
            result.push('\n');
        } else if line.contains("-----END CERTIFICATE-----") {
            result.push_str(line);
            result.push('\n');
            break;
        } else if in_cert {
            result.push_str(line);
            result.push('\n');
        }
    }

    if result.is_empty() {
        text.to_string()
    } else {
        result
    }
}

#[cfg(feature = "spdm")]
fn print_certificate_info(cert: &Certificate, verbose: bool) {
    println!("Certificate Information:");
    println!("  Version: {}", cert.tbs_certificate.version);
    println!(
        "  Serial: {}",
        hex::encode(cert.tbs_certificate.serial_number())
    );
    println!("  Subject: {}", cert.tbs_certificate.subject);
    println!("  Issuer: {}", cert.tbs_certificate.issuer);

    if verbose {
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

        if let Some(exts) = &cert.tbs_certificate.extensions {
            println!("  Extensions ({}):", exts.extensions.len());
            for ext in &exts.extensions {
                println!(
                    "    {} (critical: {})",
                    ext.extn_id, ext.critical
                );
            }
        }
    }
    println!();
}

#[cfg(feature = "spdm")]
fn algo_names(asym: u32, hash: u32) -> (Vec<String>, Vec<String>) {
    let asym_algos = SpdmBaseAsymAlgo::from_bits(asym);
    let hash_algos = SpdmBaseHashAlgo::from_bits(hash);

    let asym_names: Vec<String> = asym_algos.iter().map(|a| format!("{:?}", a)).collect();
    let hash_names: Vec<String> = hash_algos.iter().map(|h| format!("{:?}", h)).collect();

    (asym_names, hash_names)
}

#[cfg(feature = "spdm")]
fn save_results_json(
    config: &Config,
    cert: &Certificate,
    success: bool,
    error_msg: Option<&str>,
    output_path: &str,
) -> std::io::Result<()> {
    use std::io::Write;

    let (asym_names, hash_names) = algo_names(config.base_asym_algo, config.base_hash_algo);

    let json = format!(
        r#"{{
  "certificate_path": "{}",
  "validation": {{
    "success": {},
    "error": {},
    "model": "{}",
    "model_value": {},
    "role": "{}",
    "asymmetric_algorithms": {},
    "hash_algorithms": {}
  }},
  "certificate_info": {{
    "version": "{}",
    "serial": "{}",
    "subject": "{}",
    "issuer": "{}",
    "not_before": "{:?}",
    "not_after": "{:?}",
    "signature_algorithm": "{}"
  }}
}}"#,
        config.cert_path,
        success,
        error_msg
            .map(|e| format!("\"{}\"", e.replace('"', "\\\"")))
            .unwrap_or_else(|| "null".to_string()),
        config.model.name(),
        config.model.value(),
        config.role.name(),
        serde_json(&asym_names),
        serde_json(&hash_names),
        cert.tbs_certificate.version,
        hex::encode(cert.tbs_certificate.serial_number()),
        cert.tbs_certificate.subject.to_string().replace('"', "\\\""),
        cert.tbs_certificate.issuer.to_string().replace('"', "\\\""),
        cert.tbs_certificate.validity.not_before,
        cert.tbs_certificate.validity.not_after,
        cert.signature_algorithm.algorithm
    );

    let mut file = fs::File::create(output_path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

#[cfg(feature = "spdm")]
fn serde_json(vec: &[String]) -> String {
    let items: Vec<String> = vec.iter().map(|s| format!("\"{}\"", s)).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(feature = "spdm")]
fn save_results_txt(
    config: &Config,
    cert: &Certificate,
    success: bool,
    error_msg: Option<&str>,
    output_path: &str,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::time::SystemTime;

    let (asym_names, hash_names) = algo_names(config.base_asym_algo, config.base_hash_algo);

    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => format!("{} seconds since UNIX epoch", d.as_secs()),
        Err(_) => "unknown".to_string(),
    };

    let content = format!(
        r#"SPDM CERTIFICATE VALIDATION REPORT
=====================================

Certificate Path: {}
Validation Time: {}

VALIDATION RESULT
-----------------
Status: {}
Model: {} ({})
Role: {}
{}

CERTIFICATE INFORMATION
-----------------------
Version: {}
Serial Number: {}
Subject: {}
Issuer: {}
Not Before: {:?}
Not After: {:?}
Signature Algorithm: {}

SPDM PARAMETERS
---------------
Asymmetric Algorithms: {}
Hash Algorithms: {}
"#,
        config.cert_path,
        timestamp,
        if success { "PASSED ✓" } else { "FAILED ✗" },
        config.model.name(),
        config.model.value(),
        config.role.name(),
        error_msg
            .map(|e| format!("Error: {}", e))
            .unwrap_or_else(|| String::new()),
        cert.tbs_certificate.version,
        hex::encode(cert.tbs_certificate.serial_number()),
        cert.tbs_certificate.subject,
        cert.tbs_certificate.issuer,
        cert.tbs_certificate.validity.not_before,
        cert.tbs_certificate.validity.not_after,
        cert.signature_algorithm.algorithm,
        asym_names.join(", "),
        hash_names.join(", ")
    );

    let mut file = fs::File::create(output_path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(feature = "spdm")]
fn main() {
    let config = match parse_args() {
        Ok(cfg) => cfg,
        Err(msg) => {
            if msg == "help" {
                print_usage(&env::args().next().unwrap());
                process::exit(0);
            } else {
                eprintln!("Error: {}", msg);
                eprintln!();
                print_usage(&env::args().next().unwrap());
                process::exit(1);
            }
        }
    };

    // Load certificate
    println!("Loading certificate: {}", config.cert_path);
    let cert = match load_certificate(&config.cert_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };
    println!("✓ Certificate loaded successfully\n");

    // Print certificate info
    print_certificate_info(&cert, config.verbose);

    // Print validation parameters
    println!("SPDM Validation Parameters:");
    println!("  Model: {} ({})", config.model.name(), config.model.value());
    println!("  Role: {}", config.role.name());

    let (asym_names, hash_names) = algo_names(config.base_asym_algo, config.base_hash_algo);
    println!("  Asymmetric Algorithms: {}", asym_names.join(", "));
    println!("  Hash Algorithms: {}", hash_names.join(", "));
    if config.skip_time {
        println!("  Time Validation: SKIPPED");
    }
    println!();

    // Perform SPDM validation
    println!("Performing SPDM validation...");
    let validator = SpdmValidator::new();

    // Create validation options based on config
    let mut options = ValidationOptions::default();
    if config.skip_time {
        options.check_time = false;
    }

    match validator.validate_spdm_certificate_with_options(
        &cert,
        config.model,
        config.role,
        config.base_asym_algo,
        config.base_hash_algo,
        &options,
    ) {
        Ok(_) => {
            println!("✓ SPDM validation PASSED");
            println!();
            println!("The certificate is valid for:");
            println!("  - Model: {}", config.model.name());
            println!("  - Role: {}", config.role.name());

            // Save results to file if requested
            if let Some(ref output_path) = config.output_file {
                println!();
                print!("Saving results to {}... ", output_path);
                let result = if output_path.ends_with(".json") {
                    save_results_json(&config, &cert, true, None, output_path)
                } else {
                    save_results_txt(&config, &cert, true, None, output_path)
                };

                match result {
                    Ok(_) => println!("✓ Done"),
                    Err(e) => eprintln!("✗ Failed: {}", e),
                }
            }

            process::exit(0);
        }
        Err(e) => {
            let error_message = format!("{}", e);
            
            eprintln!("✗ SPDM validation FAILED");
            eprintln!();
            eprintln!("Error: {}", error_message);
            eprintln!();
            eprintln!("The certificate does not meet SPDM requirements for:");
            eprintln!("  - Model: {}", config.model.name());
            eprintln!("  - Role: {}", config.role.name());

            // Save results to file if requested
            if let Some(ref output_path) = config.output_file {
                eprintln!();
                eprint!("Saving results to {}... ", output_path);
                let result = if output_path.ends_with(".json") {
                    save_results_json(&config, &cert, false, Some(&error_message), output_path)
                } else {
                    save_results_txt(&config, &cert, false, Some(&error_message), output_path)
                };

                match result {
                    Ok(_) => eprintln!("✓ Done"),
                    Err(e) => eprintln!("✗ Failed: {}", e),
                }
            }

            process::exit(1);
        }
    }
}

#[cfg(not(feature = "spdm"))]
fn main() {
    eprintln!("Error: This example requires the 'spdm' feature to be enabled.");
    eprintln!();
    eprintln!("Build with:");
    eprintln!("  cargo run --features spdm --example validate_spdm_cert");
    std::process::exit(1);
}
