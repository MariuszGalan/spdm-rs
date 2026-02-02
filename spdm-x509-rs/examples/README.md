# X.509 Certificate Verification Suite

Comprehensive test suite for validating X.509 certificates with detailed reporting.

## Tools

### 1. SPDM Certificate Validator (`validate_spdm_cert`)

Validates certificates according to SPDM (DSP0274) specification requirements.

**Features:**
- ✅ **SPDM Model Validation**: DeviceCert, AliasCert, GenericCert
- ✅ **Role Verification**: Requester/Responder EKU validation
- ✅ **Algorithm Negotiation**: Tests SPDM base asymmetric and hash algorithms
- ✅ **Hardware Identity**: Validates Hardware Identity OID requirements
- ✅ **Basic Constraints**: Model-specific constraint checking

**Usage:**
```bash
# Basic usage - validate as DeviceCert Responder
cargo run --features spdm --example validate_spdm_cert your_cert.der

# Validate as AliasCert Requester
cargo run --features spdm --example validate_spdm_cert cert.pem \
  --model alias --role requester

# Validate with specific algorithms
cargo run --features spdm --example validate_spdm_cert cert.der \
  --asym ecdsa-p256 --hash sha256 --verbose
```

**Options:**
- `--model <MODEL>`: Certificate model (device, alias, generic) - default: device
- `--role <ROLE>`: Certificate role (requester, responder) - default: responder
- `--asym <ALGO>`: Asymmetric algorithm (rsa2048, rsa3072, rsa4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, all)
- `--hash <ALGO>`: Hash algorithm (sha256, sha384, sha512, all)
- `--verbose, -v`: Show detailed certificate information
- `--skip-time`: Skip time validation
- `--help, -h`: Show help message

**Examples:**
```bash
# Device certificate for responder with ECDSA P-256
cargo run --features spdm --example validate_spdm_cert device.der \
  --model device --role responder --asym ecdsa-p256

# Alias certificate for requester with RSA 3072
cargo run --features spdm --example validate_spdm_cert alias.pem \
  --model alias --role requester --asym rsa3072 --hash sha384

# Generic certificate with verbose output
cargo run --features spdm --example validate_spdm_cert generic.der \
  --model generic --verbose
```

### 2. Standard X.509 Validator (`cert_verify`)

Comprehensive X.509 certificate validation with detailed reporting.

**Features:**
- ✅ **Automatic Format Detection**: Handles both DER and PEM formats automatically
- ✅ **Comprehensive Validation**: 14 different validation checks
- ✅ **Detailed Reporting**: Both human-readable console output and machine-readable JSON
- ✅ **Self-Signed Detection**: Automatically verifies self-signed certificates
- ✅ **Extension Analysis**: Parses and validates all X.509 v3 extensions
- ✅ **Security Checks**: Validates cryptographic algorithm strength
- ✅ **Structure Validation**: Complete ASN.1/DER encoding verification

```bash
cargo run --example cert_verify <certificate_file>
```

**Example:**
```bash
cargo run --example cert_verify examples/test_cert.der
```

### Generate JSON Report

```bash
cargo run --example cert_verify <certificate_file> --output report.json
```

**Example:**
```bash
cargo run --example cert_verify examples/test_cert.der --output cert_report.json
```

## Validation Checks Performed

The verification tool performs the following checks:

### 1. **DER Structure Validation**
   - Verifies the certificate has valid ASN.1/DER encoding
   - Ensures all fields are properly formatted

### 2. **Version Check**
   - Validates certificate version (v1, v2, or v3)
   - Warns if not using modern v3 standard

### 3. **Serial Number Validity**
   - Checks serial number presence
   - Validates serial number length (RFC 5280 recommends ≤20 bytes)

### 4. **Signature Algorithm Security**
   - Verifies use of cryptographically strong algorithms
   - Flags weak or deprecated algorithms (MD5, SHA1)
   - Validates SHA-256, SHA-384, or SHA-512 usage

### 5. **Subject Distinguished Name**
   - Verifies subject DN is present and properly formatted
   - Parses all RDN components (CN, O, OU, C, ST, L, etc.)

### 6. **Issuer Distinguished Name**
   - Verifies issuer DN is present and properly formatted
   - Validates DN structure

### 7. **Self-Signed Certificate Detection**
   - Automatically detects if certificate is self-signed
   - For self-signed certificates, verifies signature using own public key

### 8. **Validity Period Structure**
   - Checks notBefore and notAfter dates are present
   - Validates time format (UTCTime or GeneralizedTime)

### 9. **Time-based Validity Check**
   - Verifies certificate is currently valid (not expired)
   - Checks certificate is not future-dated
   - *Note: Currently skipped in no_std environments*

### 10. **Extensions Presence**
   - Checks for X.509 v3 extensions
   - Lists all extensions found

### 11. **Critical Extensions**
   - Verifies all critical extensions are recognized
   - Ensures unknown critical extensions are flagged

### 12. **Public Key Presence**
   - Validates subject public key is present
   - Reports public key size in bits

### 13. **Signature Verification**
   - For self-signed: Verifies signature using own public key
   - For CA-signed: Requires issuer certificate (skipped if not provided)

### 14. **Overall Structure Validation**
   - Comprehensive validation using the validator module
   - Checks all constraints and relationships

## Output Format

### Console Output

The tool generates a comprehensive, formatted report:

```
═══════════════════════════════════════════════════════════════════
              X.509 CERTIFICATE VALIDATION REPORT
═══════════════════════════════════════════════════════════════════

📄 FILE INFORMATION
   Path: examples/test_cert.der
   Size: 1071 bytes

🔍 PARSING
   ✓ Certificate parsed successfully

📋 CERTIFICATE INFORMATION
   Version:             v3
   Serial Number:       1003
   Subject:             emailAddress=edkii@tianocore.org, CN=TestCert...
   Issuer:              emailAddress=edkii@tianocore.org, CN=TestSub...
   ...

🔐 VALIDATION CHECKS
   Total checks: 14

   ✓ [PASS] DER Structure Validation
   ✓ [PASS] Version Check
   ...

═══════════════════════════════════════════════════════════════════
📊 SUMMARY
   Passed:   11 ✓
   Failed:   0 ✗
   Warnings: 1 ⚠
   Skipped:  2 ○

🏁 OVERALL RESULT
   ✓✓✓ CERTIFICATE IS VALID ✓✓✓
═══════════════════════════════════════════════════════════════════
```

### JSON Output

When `--output` is specified, a machine-readable JSON report is generated:

```json
{
  "cert_path": "examples/test_cert.der",
  "file_size": 1071,
  "parse_result": "success",
  "basic_info": {
    "version": "v3",
    "serial_number": "1003",
    "subject": "emailAddress=edkii@tianocore.org, CN=TestCert...",
    "issuer": "emailAddress=edkii@tianocore.org, CN=TestSub...",
    ...
  },
  "validation_checks": [
    {
      "name": "DER Structure Validation",
      "description": "Verify certificate has valid DER/ASN.1 encoding",
      "result": "Passed",
      "details": "Certificate successfully decoded from DER format"
    },
    ...
  ],
  "overall_result": "Valid"
}
```

## Exit Codes

The tool returns different exit codes based on validation results:

- **0**: Certificate is valid (all checks passed)
- **1**: Certificate is partially valid (warnings present)
- **2**: Certificate is invalid (one or more checks failed)

## Check Result Types

- ✓ **PASS**: Check completed successfully
- ✗ **FAIL**: Check failed, certificate is invalid
- ⚠ **WARN**: Check passed with warnings
- ○ **SKIP**: Check was skipped (e.g., requires additional input)

## Supported Certificate Formats

### DER (Distinguished Encoding Rules)
- Binary format
- Direct ASN.1 encoding
- File extensions: `.der`, `.cer`, `.crt`

### PEM (Privacy Enhanced Mail)
- Base64-encoded DER with headers
- Text format with `-----BEGIN CERTIFICATE-----` header
- File extensions: `.pem`, `.crt`, `.cer`

The tool automatically detects the format.

## Examples

### Test Certificate Provided

A test certificate is included in `examples/test_cert.der`:

```bash
# View validation report
cargo run --example cert_verify examples/test_cert.der

# Generate JSON report
cargo run --example cert_verify examples/test_cert.der --output report.json
```

### Simple Validation Example

For a quick check without detailed reporting:

```bash
cargo run --example validate_cert examples/test_cert.der
```

## Integration with Other Tools

### Using in Scripts

The exit codes make it easy to use in shell scripts:

```bash
#!/bin/bash
if cargo run --quiet --example cert_verify cert.der --output result.json; then
    echo "Certificate is valid"
else
    echo "Certificate validation failed"
    cat result.json
fi
```

### Parsing JSON Output

The JSON output can be parsed by other tools:

```bash
# Extract serial number using jq
cat result.json | jq '.basic_info.serial_number'

# Check if any validations failed
cat result.json | jq '[.validation_checks[] | select(.result == "Failed")] | length'
```

## Extending the Validator

To add custom validation checks, edit `examples/cert_verify.rs`:

1. Add your check after the existing checks
2. Use `report.add_check()` to register the check
3. Provide: name, description, result (Passed/Failed/Warning/Skipped), and optional details

Example:

```rust
// Check for specific extension
if let Some(ref exts) = cert.tbs_certificate.extensions {
    let has_san = exts.extensions.iter()
        .any(|e| e.extn_id.to_string() == "2.5.29.17");

    report.add_check(
        "Subject Alternative Name".to_string(),
        "Check for SAN extension".to_string(),
        if has_san { CheckResult::Passed } else { CheckResult::Warning },
        Some(format!("SAN present: {}", has_san)),
    );
}
```

## Troubleshooting

### "Parse failed" Error

If you get a parse error:
1. Verify the file contains a valid X.509 certificate
2. Check the file format (DER or PEM)
3. Try converting with OpenSSL:
   ```bash
   # Convert PEM to DER
   openssl x509 -in cert.pem -outform DER -out cert.der

   # Convert DER to PEM
   openssl x509 -in cert.der -inform DER -out cert.pem
   ```

### "Signature Verification" Skipped

This is normal for CA-signed certificates. To verify:
1. Provide the issuer (CA) certificate
2. Or use OpenSSL for full chain verification:
   ```bash
   openssl verify -CAfile ca.pem cert.pem
   ```

### Self-Signed Certificate Warnings

Self-signed certificates will show warnings. This is expected for:
- Test certificates
- Root CA certificates
- Development certificates

## See Also

- [`examples/validate_cert.rs`](validate_cert.rs) - Simple validation example
- [`examples/debug_parse.rs`](debug_parse.rs) - ASN.1 parsing debug tool
- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 Certificate Specification
- [Main README](../README.md) - Project overview and library usage
