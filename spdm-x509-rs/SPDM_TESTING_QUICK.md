# SPDM Certificate Testing - Quick Reference

## Basic Usage

### Auto-detection Mode (RECOMMENDED)

```bash
# Script automatically detects certificate type
./validate_spdm.sh <certificate.der>

# Tries in order: device → alias → generic
# Reports detected type
```

### Validation with Specific Model

```bash
# With command line arguments
cargo run --features spdm --example validate_spdm_cert <certificate.der> --model <MODEL>

# Or use helper script
./validate_spdm.sh <certificate.der> --model <MODEL>
```

## Options

- `--model <MODEL>`: Certificate model: `device`, `alias`, `generic` (default: `device`)
- `--role <ROLE>`: Certificate role: `requester`, `responder` (default: `responder`)
- `--asym <ALGO>`: Asymmetric algorithm: `rsa2048`, `rsa3072`, `rsa4096`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `all`
- `--hash <ALGO>`: Hash algorithm: `sha256`, `sha384`, `sha512`, `all`
- `--verbose, -v`: Show detailed information
- `--help, -h`: Show help

## Examples

### DeviceCert with ECDSA P-256

```bash
cargo run --features spdm --example validate_spdm_cert device.der \
  --model device --role responder --asym ecdsa-p256 --hash sha256
```

### AliasCert with RSA 3072

```bash
cargo run --features spdm --example validate_spdm_cert alias.pem \
  --model alias --role requester --asym rsa3072 --hash sha384
```

### Using the Script

```bash
./validate_spdm.sh cert.der --model device --role responder -v
```

## Documentation

- Full guide: [examples/SPDM_TESTING.md](examples/SPDM_TESTING.md)
- Test documentation: [docs/TESTING.md](docs/TESTING.md)
- Usage examples: [examples/README.md](examples/README.md)

## Certificate Formats

Supported formats:
- DER (`.der`, `.crt`)
- PEM (`.pem`)

## Automated Tests

```bash
# All SPDM tests
cargo test --features spdm spdm

# SPDM validation tests
cargo test --features spdm spdm_validation

# All tests
cargo test --all-features
```
