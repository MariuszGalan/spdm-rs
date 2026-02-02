# Test Certificate Data

This directory contains test X.509 certificates in DER and PEM formats for integration testing.

## Required Test Files

To run the integration tests, you need to provide the following certificate files:

- `rsa_cert.der` - RSA-2048 certificate with SHA-256 signature
- `rsa_cert.pem` - Same certificate in PEM format
- `root_ca.der` - Self-signed root CA certificate
- `intermediate_ca.der` - Intermediate CA certificate (signed by root)
- `leaf_cert.der` - End-entity certificate (signed by intermediate or root)
- `ecdsa_p256_cert.der` - ECDSA P-256 certificate
- `ecdsa_root_ca.der` - ECDSA root CA

## Generating Test Certificates

You can generate test certificates using OpenSSL:

\`\`\`bash
# Generate RSA root CA
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \\
    -keyout root_ca.key -out root_ca.pem \\
    -subj "/CN=Test Root CA"
openssl x509 -in root_ca.pem -outform DER -out root_ca.der

# Generate ECDSA root CA
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_root_ca.key
openssl req -new -x509 -days 3650 -key ecdsa_root_ca.key \\
    -out ecdsa_root_ca.pem -subj "/CN=Test ECDSA Root CA"
openssl x509 -in ecdsa_root_ca.pem -outform DER -out ecdsa_root_ca.der
\`\`\`

## Current Status

The test files are placeholders. To run the full test suite, generate actual certificates
or modify the tests to use `#[ignore]` attributes.
