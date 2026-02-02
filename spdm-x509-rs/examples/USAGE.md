# validate_real_cert - Usage

Example of validating a real X.509 certificate with command-line options support.

## Command Line Options

### `--verbose` / `-v`

Displays detailed certificate information:
- Complete Subject and Issuer data
- Details of all extensions
- Signature and public key information

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der --verbose
```

### `--verify-time`

Enables certificate validity verification (checks Not Before/Not After dates).
Without this option, an expired certificate will be accepted (useful for test certificates).

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der --verify-time
```

### `--output <FILE>` / `-o <FILE>`

Saves validation results to a file in JSON or TXT format.

**JSON format** contains structured data for programmatic processing.
**TXT format** contains a formatted report similar to verbose output with additional details.

```bash
# JSON output
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -o report.json

# TXT output
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -o report.txt
```

## Usage Examples

### Basic Validation (Concise Mode)

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der
```

Output:
```
Loading certificate: cert.der
✓ Certificate loaded successfully
✓ Certificate validation PASSED
```

### Verbose Mode

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der --verbose
# or short form:
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -v
```

Output:
```
Loading certificate: cert.der
✓ Certificate loaded successfully

Certificate Information:
  Version: v3
  Serial: 35c04db5c18de3a0
  Subject: CN=Example Certificate
  Issuer: CN=Test CA
  Validity:
    Not Before: 2025-01-01 00:00:00 UTC
    Not After:  2035-12-31 23:59:59 UTC
  Signature Algorithm: 1.2.840.10045.4.3.3 (ecdsa-with-SHA384)
  Public Key Algorithm: 1.2.840.10045.2.1 (EC Public Key)
  Extensions (5):
    2.5.29.19 (critical: true) - Basic Constraints
    2.5.29.15 (critical: true) - Key Usage
    ...

✓ Certificate validation PASSED
```

### Certificate Validity Verification

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der --verify-time
```

Output (for expired certificate):
```
Loading certificate: cert.der
✓ Certificate loaded successfully
✗ Certificate validation FAILED
Error: Certificate has expired
```

### SPDM Validation (Verbose Mode)

For certificates with SPDM-specific validation:

```bash
cargo run -p spdm-x509-rs --features spdm --example validate_real_cert cert.der -v
```

Additional output:
```
SPDM Extensions:
  Hardware Identity: Present
  Device Info: 1.3.6.1.4.1.311.102.3.1
  ...
```

### JSON Output

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -o report.json
```

Output:
```json
{
  "file": "cert.der",
  "valid": true,
  "certificate": {
    "version": "v3",
    "serial": "35c04db5c18de3a0",
    "subject": "CN=Example Certificate",
    "issuer": "CN=Test CA",
    "not_before": "2025-01-01T00:00:00Z",
    "not_after": "2035-12-31T23:59:59Z",
    "signature_algorithm": "1.2.840.10045.4.3.3",
    "public_key_algorithm": "1.2.840.10045.2.1",
    "extensions": [
      {
        "oid": "2.5.29.19",
        "critical": true,
        "name": "Basic Constraints"
      },
      ...
    ]
  }
}
```

### TXT Output

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -o report.txt
```

Output:
```
Certificate Validation Report
============================
File: cert.der
Status: VALID

Certificate Information
----------------------
Version:               v3
Serial Number:         35c04db5c18de3a0
Subject:               CN=Example Certificate
Issuer:                CN=Test CA
...
```

### Combining Options

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der \
  --verbose \
  --verify-time \
  --output report.json
```

## Mode Differences

| Feature              | Basic | Verbose | JSON | TXT |
|---------------------|-------|---------|------|-----|
| Load status         | ✅     | ✅       | ✅    | ✅   |
| Validation result   | ✅     | ✅       | ✅    | ✅   |
| Version             | ❌     | ✅       | ✅    | ✅   |
| Serial number       | ❌     | ✅       | ✅    | ✅   |
| Subject/Issuer      | ❌     | ✅       | ✅    | ✅   |
| Validity dates      | ❌     | ✅       | ✅    | ✅   |
| Extension count     | ✅ (number only) | ✅ (details) | ✅ (list) | ✅ (list) |
| Extension list      | ❌     | ✅       | ✅    | ✅   |
| Signature algorithm | ❌     | ✅       | ✅    | ✅   |
| Public key algorithm| ❌     | ✅       | ✅    | ✅   |
| Structured data     | ❌     | ❌       | ✅    | ❌   |
| Validation details  | ❌     | ❌       | ✅    | ✅   |

## Output Interpretation

### Success
The certificate is structurally correct and passed all checks.

### Failure
There was an issue with the certificate. Check the error message for details:
- **Failed to read file**: File not found or unreadable
- **Failed to parse certificate**: Invalid DER/PEM format
- **Certificate has expired**: Past the Not After date (only with `--verify-time`)
- **Certificate not yet valid**: Before the Not Before date (only with `--verify-time`)
- **Invalid signature algorithm**: Unsupported or malformed signature algorithm
- **Missing required extensions**: Certificate lacks mandatory extensions

## Examples with Different Formats

### DER Certificate

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.der -v
```

### PEM Certificate

```bash
cargo run -p spdm-x509-rs --example validate_real_cert cert.pem -v
```

### Certificate Chain (Multiple Certs)

For certificates containing chains, only the first certificate is validated:

```bash
cargo run -p spdm-x509-rs --example validate_real_cert chain.pem -v
```

## Additional Resources

- [SPDM Testing Guide](SPDM_TESTING.md) - For SPDM-specific validation
- [Quick Reference](../SPDM_TESTING_QUICK.md) - Quick command reference
- [README](README.md) - Overview of all examples
