# SPDM Certificate Testing Guide

This document describes how to test SPDM certificates using the `validate_spdm_cert` tool.

## Basic Usage

### Quick Start

```bash
# Auto-detect certificate model (tries: device → alias → generic)
./validate_spdm.sh your_certificate.der

# Or with cargo (from workspace root)
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert your_certificate.der

# Validate PEM certificate
./validate_spdm.sh certificate.pem
```

**Auto-detection mode:**
If you don't specify `--model`, the script automatically:
1. Tries `device` (requires Hardware Identity OID)
2. If fails → tries `alias` (without Hardware Identity OID)  
3. If fails → tries `generic` (standard X.509)
4. Reports the detected certificate type

### Help

```bash
./validate_spdm.sh --help
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert -- --help
```

## Validation Options

### Certificate Model (`--model`)

SPDM defines three certificate models:

```bash
# DeviceCert - contains Hardware Identity OID
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --model device

# AliasCert - does NOT contain Hardware Identity OID
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --model alias

# GenericCert - standard X.509 certificate
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --model generic
```

### Certificate Role (`--role`)

```bash
# Responder - responds to SPDM requests
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --role responder

# Requester - initiates SPDM communication
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --role requester
```

### Asymmetric Algorithms (`--asym`)

Test compatibility with negotiated SPDM algorithms:

```bash
# RSA
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym rsa2048
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym rsa3072
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym rsa4096

# ECDSA
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym ecdsa-p256
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym ecdsa-p384
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym ecdsa-p521

# All algorithms (default)
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --asym all
```

### Hash Algorithms (`--hash`)

```bash
# SHA-256
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --hash sha256

# SHA-384
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --hash sha384

# SHA-512
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --hash sha512

# All algorithms (default)
cargo run -p spdm-x509-rs --features spdm --example validate_spdm_cert cert.der --hash all
```

## Example Scenarios

### Scenario 1: DeviceCert with ECDSA P-256

Validate device certificate with ECDSA P-256 as Responder:

```bash
./validate_spdm.sh device_cert.der \
  --model device \
  --role responder \
  --asym ecdsa-p256 \
  --hash sha256 \
  --verbose
```

Expected output:
- Certificate model: DeviceCert (0)
- Hardware Identity OID must be present
- ECDSA P-256 algorithm validation
- SHA-256 hash validation

### Scenario 2: AliasCert with RSA 3072

Validate alias certificate with RSA 3072 as Requester:

```bash
./validate_spdm.sh alias_cert.pem \
  --model alias \
  --role requester \
  --asym rsa3072 \
  --hash sha384
```

Expected output:
- Certificate model: AliasCert (1)
- Hardware Identity OID must NOT be present
- RSA 3072 key size validation
- SHA-384 hash validation

### Scenario 3: Auto-detection

Let the tool automatically detect certificate type:

```bash
./validate_spdm.sh unknown_cert.der --verbose
```

The tool will:
1. Try DeviceCert validation
2. If fails, try AliasCert validation
3. If fails, try GenericCert validation
4. Report the first successful model

## Using the Helper Script

The `validate_spdm.sh` script provides a user-friendly interface:

```bash
# Auto-detect with verbose output
./validate_spdm.sh cert.der -v

# Explicit model with JSON output
./validate_spdm.sh cert.der --model device --output results.json

# Multiple options
./validate_spdm.sh cert.der \
  --model alias \
  --role requester \
  --asym ecdsa-p384 \
  --hash sha384 \
  --verbose \
  --skip-time
```

### Script Options

- `--model <MODEL>`: Certificate model (device, alias, generic)
- `--role <ROLE>`: Certificate role (requester, responder)
- `--asym <ALGO>`: Asymmetric algorithm
- `--hash <ALGO>`: Hash algorithm
- `--verbose, -v`: Show detailed information
- `--skip-time`: Skip time validation (useful for expired test certificates)
- `--output, -o FILE`: Save results to file (JSON or TXT)
- `--help, -h`: Show help

## Understanding the Output

### Success Output

```
═══════════════════════════════════════════
✓ VALIDATION PASSED
Certificate Type: DEVICE
═══════════════════════════════════════════
```

The certificate is structurally correct and passed all checks.

### Failure Output

```
═══════════════════════════════════════════
✗ VALIDATION FAILED
═══════════════════════════════════════════
Error: Certificate validation failed
```

Check the detailed error message to identify the issue.

### Verbose Output

With `--verbose` flag, you get:
- Certificate information (subject, issuer, validity)
- Extension details
- Signature algorithm
- Public key algorithm
- SPDM validation parameters
- Detailed validation results

## Testing with libspdm Test Vectors

The repository includes test certificates from libspdm:

```bash
# Test ECP256 certificates
./validate_spdm.sh tests/libspdm_vectors/ecp256/ca.cert.der --model generic
./validate_spdm.sh tests/libspdm_vectors/ecp256/end_responder.cert.der --model device

# Test RSA certificates
./validate_spdm.sh tests/libspdm_vectors/rsa3072/ca.cert.der --model generic
./validate_spdm.sh tests/libspdm_vectors/rsa3072/end_requester.cert.der --model alias

# Test with specific algorithms
./validate_spdm.sh tests/libspdm_vectors/ecp384/end_responder.cert.der \
  --model device \
  --asym ecdsa-p384 \
  --hash sha384
```

## Running Automated Tests

```bash
# All SPDM tests
cargo test -p spdm-x509-rs --features spdm spdm

# Validation tests
cargo test -p spdm-x509-rs --features spdm spdm_validation

# libspdm compatibility tests
cargo test -p spdm-x509-rs --features spdm libspdm_compatibility

# All tests
cargo test -p spdm-x509-rs --all-features
```

## Troubleshooting

### Certificate Fails All Models

If a certificate fails device, alias, and generic models:
1. Check if it's a valid X.509 certificate
2. Verify the signature algorithm is supported
3. Check for required extensions (Basic Constraints, Key Usage)

### Hardware Identity OID Issues

- DeviceCert requires Hardware Identity OID (2.23.133.5.4.4)
- AliasCert must NOT have Hardware Identity OID
- GenericCert doesn't check for Hardware Identity OID

### Time Validation Failures

For expired test certificates, use `--skip-time`:

```bash
./validate_spdm.sh expired_cert.der --skip-time
```

### Algorithm Mismatch

Ensure the certificate's algorithms match the negotiated SPDM algorithms:

```bash
# For ECDSA P-256 certificate, use:
./validate_spdm.sh cert.der --asym ecdsa-p256 --hash sha256

# Not:
./validate_spdm.sh cert.der --asym rsa3072  # Will fail
```

## Additional Resources

- [SPDM Specification DSP0274](../../specification/DSP0274_1.4.0.pdf)
- [Quick Reference](../SPDM_TESTING_QUICK.md)
- [API Documentation](../docs/SPDM.md)
- [Test Documentation](../docs/TESTING.md)
