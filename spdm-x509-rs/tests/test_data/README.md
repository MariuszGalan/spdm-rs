# Test Data Directory

This directory contains test certificate data for SPDM validation tests.

## Overview

The test data is primarily provided as byte arrays in the `mod.rs` file to enable testing without external file dependencies. This approach allows tests to run in any environment without needing to manage separate certificate files.

## Test Data Structures

### Certificate Templates

- **DEVICE_CERT_ECDSA_P256**: Sample DeviceCert with ECDSA P-256
- **ALIAS_CERT_ECDSA_P384**: Sample AliasCert with ECDSA P-384
- **GENERIC_CERT_RSA_3072**: Sample GenericCert with RSA-3072

### SPDM Chain Data

- **SPDM_CERT_CHAIN_SAMPLE**: Sample SPDM certificate chain with header and certificates

### OID Constants

- **SPDM_REQUESTER_AUTH_DER**: SPDM Requester Auth OID (1.3.6.1.4.1.412.274.1)
- **SPDM_RESPONDER_AUTH_DER**: SPDM Responder Auth OID (1.3.6.1.4.1.412.274.3)
- **HARDWARE_IDENTITY_DER**: Hardware Identity OID (1.3.6.1.4.1.412.274.4)

### Curve and Hash OIDs

- **ECDSA_P256_CURVE_DER**: P-256 curve OID
- **ECDSA_P384_CURVE_DER**: P-384 curve OID
- **SHA256_OID_DER**: SHA-256 OID
- **SHA384_OID_DER**: SHA-384 OID

### SPDM Extensions

- **SPDM_EXTENSION_WITH_HW_ID**: SPDM extension containing Hardware Identity OID
- **SPDM_EXTENSION_WITHOUT_HW_ID**: SPDM extension without Hardware Identity OID

## Generating Real Test Certificates

For comprehensive testing with real certificates, you can generate them using OpenSSL or similar tools. Here's an example workflow:

### Generate ECDSA P-256 DeviceCert

```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out device_key.pem

# Create certificate signing request
openssl req -new -key device_key.pem -out device.csr \
  -subj "/CN=Test Device/O=Test Org/C=US"

# Generate self-signed certificate with SPDM extensions
# Note: You'll need to manually add SPDM-specific extensions
openssl x509 -req -in device.csr -signkey device_key.pem \
  -out device_cert.pem -days 365

# Convert to DER
openssl x509 -in device_cert.pem -outform DER -out device_cert.der
```

### Generate RSA-3072 GenericCert (CA)

```bash
# Generate private key
openssl genrsa -out ca_key.pem 3072

# Generate self-signed CA certificate
openssl req -new -x509 -key ca_key.pem -out ca_cert.pem -days 3650 \
  -subj "/CN=Test CA/O=Test Org/C=US" \
  -extensions v3_ca

# Convert to DER
openssl x509 -in ca_cert.pem -outform DER -out ca_cert.der
```

### Adding SPDM Extensions

SPDM-specific extensions (EKU OIDs, SPDM extension, Hardware Identity) need to be added using custom OpenSSL configuration. Example:

```ini
# spdm_ext.cnf
[spdm_ext]
extendedKeyUsage = 1.3.6.1.4.1.412.274.3  # SPDM Responder Auth
basicConstraints = CA:FALSE
1.3.6.1.4.1.412.274.2 = ASN1:SEQUENCE:spdm_extension_seq

[spdm_extension_seq]
field1 = OID:1.3.6.1.4.1.412.274.4  # Hardware Identity
```

Then use with OpenSSL:

```bash
openssl x509 -req -in device.csr -signkey device_key.pem \
  -out device_cert.pem -days 365 -extfile spdm_ext.cnf -extensions spdm_ext
```

## Using Test Data in Tests

```rust
use crate::test_data;

#[test]
fn test_with_device_cert() {
    let cert_der = test_data::DEVICE_CERT_ECDSA_P256;
    let cert = Certificate::from_der(cert_der).unwrap();
    // ... test logic
}
```

## Current Limitations

The current test data consists of minimal certificate structures suitable for basic parsing and structure tests. For comprehensive validation tests including signature verification, you'll need to:

1. Generate real certificates with valid signatures
2. Include all required X.509 fields
3. Add SPDM-specific extensions with proper ASN.1 encoding
4. Create complete certificate chains

## Future Enhancements

Planned improvements to test data:

1. **Complete Certificate Templates**: Full DER-encoded certificates with all required fields
2. **Certificate Chains**: Multi-level chains (Root CA → Intermediate CA → Leaf)
3. **Invalid Certificates**: Intentionally malformed certificates for negative testing
4. **Algorithm Variations**: Certificates for all supported algorithms
5. **Time-based Tests**: Certificates with various validity periods

## Resources

- [DSP0274 SPDM Specification](https://www.dmtf.org/dsp/DSP0274)
- [RFC 5280 - X.509 Certificate Profile](https://tools.ietf.org/html/rfc5280)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [ASN.1 Playground](https://lapo.it/asn1js/) - For inspecting and creating ASN.1 structures
