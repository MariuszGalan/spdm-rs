//! Practical X.509 Validator Usage Examples
//!
//! This demonstrates how to use spdm-x509-rs in your Rust applications.
//! Run with: cargo run --example library_usage

use spdm_x509::{Certificate, ValidationOptions, Validator};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         X.509 Validator - Library Usage Guide              ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    example_1_basic_api();
    example_2_validation_options();
    example_3_extension_access();
    example_4_error_handling();
    example_5_integration_pattern();
}

/// Example 1: Basic API Usage
fn example_1_basic_api() {
    println!("📚 EXAMPLE 1: Basic API Usage");
    println!("─────────────────────────────────────────────────────────────\n");

    // Sample self-signed certificate (base64-encoded DER)
    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----"#;

    // Parse certificate from PEM
    match Certificate::from_pem(cert_pem) {
        Ok(cert) => {
            println!("✅ Certificate parsed successfully!\n");

            println!("📋 Basic Information:");
            println!("   Subject:  {}", cert.tbs_certificate.subject);
            println!("   Issuer:   {}", cert.tbs_certificate.issuer);
            println!("   Version:  {}", cert.tbs_certificate.version);
            println!(
                "   Serial:   {}",
                hex::encode(cert.tbs_certificate.serial_number())
            );

            println!("\n⏰ Validity Period:");
            println!(
                "   Not Before: {:?}",
                cert.tbs_certificate.validity.not_before
            );
            println!(
                "   Not After:  {:?}",
                cert.tbs_certificate.validity.not_after
            );

            println!("\n🔑 Public Key:");
            let pk_size = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
                .len()
                * 8;
            println!(
                "   Algorithm: {}",
                cert.tbs_certificate.subject_public_key_info.algorithm.oid
            );
            println!("   Size:      {} bits", pk_size);
        }
        Err(e) => {
            eprintln!("❌ Parse error: {}", e);
        }
    }

    println!("\n");
}

/// Example 2: Validation with Different Options
fn example_2_validation_options() {
    println!("⚙️  EXAMPLE 2: Validation Options");
    println!("─────────────────────────────────────────────────────────────\n");

    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----"#;

    if let Ok(cert) = Certificate::from_pem(cert_pem) {
        let validator = Validator::new();

        // Option 1: Skip time validation (for expired test certificates)
        println!("🔧 Option 1: Structure validation only (skip time)");
        let options = ValidationOptions::default()
            .skip_time_validation()
            .skip_signature_validation();

        match validator.validate(&cert, &options) {
            Ok(_) => println!("   ✅ Certificate structure is valid\n"),
            Err(e) => println!("   ❌ Validation failed: {}\n", e),
        }

        // Option 2: Full validation
        println!("🔧 Option 2: Full validation (with time check)");
        let options = ValidationOptions::default().skip_signature_validation();

        match validator.validate(&cert, &options) {
            Ok(_) => println!("   ✅ Certificate is fully valid\n"),
            Err(e) => println!("   ⚠️  Expected failure (expired): {}\n", e),
        }

        // Option 3: Custom chain depth
        println!("🔧 Option 3: Custom chain depth limit");
        let options = ValidationOptions::default()
            .skip_time_validation()
            .skip_signature_validation()
            .with_max_chain_depth(5);

        match validator.validate(&cert, &options) {
            Ok(_) => println!("   ✅ Validated with max chain depth: 5\n"),
            Err(e) => println!("   ❌ Error: {}\n", e),
        }
    }

    println!();
}

/// Example 3: Accessing Certificate Extensions
fn example_3_extension_access() {
    println!("📋 EXAMPLE 3: Extension Access");
    println!("─────────────────────────────────────────────────────────────\n");

    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----"#;

    if let Ok(cert) = Certificate::from_pem(cert_pem) {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            println!(
                "📝 Certificate has {} extension(s):\n",
                extensions.extensions.len()
            );

            use der::Decode;
            use spdm_x509::extensions::*;

            for (i, ext) in extensions.extensions.iter().enumerate() {
                let critical_mark = if ext.critical {
                    "⚠️  CRITICAL"
                } else {
                    "   "
                };
                println!("   {}. {} [{}]", i + 1, ext.extn_id, critical_mark);

                // Parse specific extensions
                if ext.extn_id == BASIC_CONSTRAINTS {
                    if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        println!("      → CA: {}", bc.ca);
                        if let Some(path_len) = bc.path_len_constraint {
                            println!("      → Path Length: {}", path_len);
                        }
                    }
                } else if ext.extn_id == KEY_USAGE {
                    println!("      → Key Usage (binary data)");
                } else if ext.extn_id == SUBJECT_KEY_IDENTIFIER {
                    println!("      → Subject Key Identifier");
                }
            }
        } else {
            println!("ℹ️  No extensions found");
        }
    }

    println!("\n");
}

/// Example 4: Error Handling Patterns
fn example_4_error_handling() {
    println!("⚠️  EXAMPLE 4: Error Handling");
    println!("─────────────────────────────────────────────────────────────\n");

    // Test 1: Invalid DER data
    println!("🧪 Test: Invalid DER data");
    let invalid_der = vec![0xFF, 0xAB, 0xCD];
    match Certificate::from_der(&invalid_der) {
        Ok(_) => println!("   Unexpected success"),
        Err(e) => println!("   ✅ Caught error: {}\n", e),
    }

    // Test 2: Invalid PEM format
    println!("🧪 Test: Invalid PEM format");
    let invalid_pem = "Not a certificate";
    match Certificate::from_pem(invalid_pem) {
        Ok(_) => println!("   Unexpected success"),
        Err(e) => println!("   ✅ Caught error: {}\n", e),
    }

    // Test 3: Validation errors with pattern matching
    println!("🧪 Test: Expired certificate validation");
    let expired_cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----"#;

    if let Ok(cert) = Certificate::from_pem(expired_cert_pem) {
        let validator = Validator::new();
        let options = ValidationOptions::default().skip_signature_validation();

        match validator.validate(&cert, &options) {
            Ok(_) => println!("   Certificate valid"),
            Err(e) => {
                use spdm_x509::error::Error;
                match e {
                    Error::TimeError(ref time_err) => {
                        println!("   ✅ Time error detected: {:?}", time_err);
                        println!("      This is expected for an expired certificate");
                    }
                    Error::ExtensionError(_) => {
                        println!("   Extension validation failed");
                    }
                    _ => {
                        println!("   Other error: {}", e);
                    }
                }
            }
        }
    }

    println!("\n");
}

/// Example 5: Integration Pattern for Production Use
fn example_5_integration_pattern() {
    println!("🏗️  EXAMPLE 5: Production Integration Pattern");
    println!("─────────────────────────────────────────────────────────────\n");

    println!("Example function that you would use in production:\n");
    println!("```rust");
    println!("fn validate_certificate_file(path: &str) -> Result<CertInfo, AppError> {{");
    println!("    // 1. Read file");
    println!("    let bytes = std::fs::read(path)?;");
    println!();
    println!("    // 2. Try DER first, fallback to PEM");
    println!("    let cert = Certificate::from_der(&bytes)");
    println!("        .or_else(|_| {{");
    println!("            let pem = std::str::from_utf8(&bytes)?;");
    println!("            Certificate::from_pem(pem)");
    println!("        }})?;");
    println!();
    println!("    // 3. Validate with appropriate options");
    println!("    let validator = Validator::new();");
    println!("    let options = ValidationOptions::default()");
    println!("        .skip_signature_validation(); // Or provide issuer");
    println!();
    println!("    validator.validate(&cert, &options)?;");
    println!();
    println!("    // 4. Extract needed information");
    println!("    Ok(CertInfo {{");
    println!("        subject: cert.tbs_certificate.subject.to_string(),");
    println!("        issuer: cert.tbs_certificate.issuer.to_string(),");
    println!("        serial: hex::encode(cert.tbs_certificate.serial_number()),");
    println!("        not_before: cert.tbs_certificate.validity.not_before,");
    println!("        not_after: cert.tbs_certificate.validity.not_after,");
    println!("    }})");
    println!("}}");
    println!("```\n");

    println!("Key points:");
    println!("  ✓ Always handle both DER and PEM formats");
    println!("  ✓ Use ValidationOptions to control what is checked");
    println!("  ✓ Extract only the information you need");
    println!("  ✓ Use proper error types in your application");
    println!();
}
