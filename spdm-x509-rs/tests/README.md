# Integration Tests

This directory contains integration tests for the spdm-x509-rs library.

## Test Files

- `certificate_parsing.rs` - Tests for DER and PEM certificate parsing
- `chain_validation.rs` - Tests for certificate chain validation  
- `signature_verification.rs` - Tests for cryptographic signature verification

## Running Tests

```bash
# Run all tests
cargo test

# Run only integration tests
cargo test --test '*'

# Run a specific test file
cargo test --test certificate_parsing
```

## Test Data

Test data files are located in `tests/data/`. See `tests/data/README.md` for instructions
on generating test certificates.

Most tests are marked with `#[ignore]` until actual test certificate files are provided.
To run ignored tests:

```bash
cargo test -- --ignored
```
