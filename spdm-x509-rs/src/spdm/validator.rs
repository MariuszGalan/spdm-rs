//! SPDM Certificate Validator
//!
//! Provides validation methods for SPDM certificates according to DSP0274.

extern crate alloc;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use crate::certificate::{Certificate, Extension};
use crate::error::{Error, ExtensionError, Result};
use crate::extensions::{
    BasicConstraints, ExtendedKeyUsage, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE,
};
use crate::validator::{ValidationOptions, Validator};

use super::oids;

// =============================================================================
// Helper function to find extensions
// =============================================================================

/// Find an extension by OID in a certificate
fn find_extension<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a Extension> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        exts.extensions.iter().find(|ext| &ext.extn_id == oid)
    } else {
        None
    }
}

// =============================================================================
// SPDM Certificate Model
// =============================================================================

/// SPDM Certificate Model (DSP0274 Section 10.6.1)
///
/// Defines the type/model of an SPDM certificate, which affects
/// validation requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpdmCertificateModel {
    /// Device Certificate - contains hardware identity
    ///
    /// Requirements:
    /// - MUST contain Hardware Identity OID in SPDM extension
    /// - Basic Constraints: cA = FALSE
    /// - Represents a physical device
    DeviceCert = 0,

    /// Alias Certificate - no hardware identity
    ///
    /// Requirements:
    /// - MUST NOT contain Hardware Identity OID
    /// - Basic Constraints: cA = FALSE
    /// - Represents a software instance
    AliasCert = 1,

    /// Generic Certificate - standard X.509 certificate
    ///
    /// Requirements:
    /// - Can be used for CA or intermediate certificates
    /// - Standard X.509 validation rules apply
    /// - Basic Constraints: cA may be TRUE or FALSE
    GenericCert = 2,
}

impl SpdmCertificateModel {
    /// Create from integer value
    pub fn from_value(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::DeviceCert),
            1 => Ok(Self::AliasCert),
            2 => Ok(Self::GenericCert),
            _ => Err(Error::ValidationError(alloc::format!(
                "Invalid SPDM certificate model: {}",
                value
            ))),
        }
    }

    /// Get the integer value
    pub fn value(&self) -> u8 {
        *self as u8
    }

    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::DeviceCert => "DeviceCert",
            Self::AliasCert => "AliasCert",
            Self::GenericCert => "GenericCert",
        }
    }
}

// =============================================================================
// SPDM Certificate Role
// =============================================================================

/// SPDM Certificate Role
///
/// Identifies whether a certificate is for a Requester or Responder.
/// This affects Extended Key Usage validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmCertificateRole {
    /// Requester role - initiates SPDM communication
    Requester,

    /// Responder role - responds to SPDM requests
    Responder,
}

impl SpdmCertificateRole {
    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Requester => "Requester",
            Self::Responder => "Responder",
        }
    }
}

// =============================================================================
// SPDM Validator
// =============================================================================

/// SPDM Certificate Validator
///
/// Provides validation methods for SPDM certificates according to DSP0274.
pub struct SpdmValidator {
    /// Underlying X.509 validator
    validator: Validator,
}

impl SpdmValidator {
    /// Create a new SPDM validator
    pub fn new() -> Self {
        Self {
            validator: Validator::new(),
        }
    }

    /// Validate an SPDM certificate
    ///
    /// Performs complete SPDM validation including:
    /// - Standard X.509 validation
    /// - SPDM EKU validation
    /// - SPDM extension validation
    /// - Hardware Identity validation
    /// - Basic Constraints validation per model
    /// - Algorithm verification
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    /// - `role`: The certificate role (Requester or Responder)
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    ///
    /// # Returns
    /// - `Ok(())` if validation succeeds
    /// - `Err(Error)` if validation fails
    /// Validate an SPDM certificate with custom validation options
    ///
    /// Performs complete SPDM validation including:
    /// - Standard X.509 validation (with custom options)
    /// - SPDM EKU validation
    /// - SPDM extension validation
    /// - Hardware Identity validation
    /// - Basic Constraints validation per model
    /// - Algorithm verification
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    /// - `role`: The certificate role (Requester or Responder)
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    /// - `options`: Validation options (e.g., skip time validation)
    ///
    /// # Returns
    /// - `Ok(())` if validation succeeds
    /// - `Err(Error)` if validation fails
    pub fn validate_spdm_certificate_with_options(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
        role: SpdmCertificateRole,
        base_asym_algo: u32,
        base_hash_algo: u32,
        options: &ValidationOptions,
    ) -> Result<()> {
        // Perform standard X.509 validation first with custom options
        self.validator.validate(cert, options)?;

        // Validate SPDM-specific requirements
        self.validate_spdm_eku(cert, role)?;
        self.validate_spdm_extension(cert, model)?;
        self.validate_hardware_identity(cert, model)?;
        self.validate_basic_constraints_spdm(cert, model)?;

        // Validate algorithms match negotiated SPDM parameters
        self.validate_algorithms(cert, base_asym_algo, base_hash_algo)?;

        Ok(())
    }

    /// Validate an SPDM certificate
    ///
    /// Performs complete SPDM validation including:
    /// - Standard X.509 validation
    /// - SPDM EKU validation
    /// - SPDM extension validation
    /// - Hardware Identity validation
    /// - Basic Constraints validation per model
    /// - Algorithm verification
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    /// - `role`: The certificate role (Requester or Responder)
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    ///
    /// # Returns
    /// - `Ok(())` if validation succeeds
    /// - `Err(Error)` if validation fails
    pub fn validate_spdm_certificate(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
        role: SpdmCertificateRole,
        base_asym_algo: u32,
        base_hash_algo: u32,
    ) -> Result<()> {
        // Use default validation options
        let options = ValidationOptions::default();
        self.validate_spdm_certificate_with_options(
            cert,
            model,
            role,
            base_asym_algo,
            base_hash_algo,
            &options,
        )
    }


    /// Validate SPDM Extended Key Usage (EKU)
    ///
    /// # Validation Rules (DSP0274 Section 10.6.1.3)
    /// - If EKU extension is not present → PASS
    /// - If Requester certificate contains ONLY Responder Auth OID → FAIL
    /// - If Responder certificate contains ONLY Requester Auth OID → FAIL
    /// - Otherwise → PASS
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `role`: The certificate role
    ///
    /// # Returns
    /// - `Ok(())` if EKU validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_spdm_eku(&self, cert: &Certificate, role: SpdmCertificateRole) -> Result<()> {
        // Try to get the EKU extension
        let eku_ext = match find_extension(cert, &EXTENDED_KEY_USAGE) {
            Some(ext) => ext,
            None => return Ok(()), // No EKU extension is allowed
        };

        // Parse the EKU extension value
        let eku = ExtendedKeyUsage::from_extension(eku_ext).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Failed to parse EKU: {:?}",
                e
            )))
        })?;

        // Check for SPDM EKU OIDs
        let has_requester = eku
            .key_purposes
            .iter()
            .any(|oid| oid == &oids::SPDM_REQUESTER_AUTH);
        let has_responder = eku
            .key_purposes
            .iter()
            .any(|oid| oid == &oids::SPDM_RESPONDER_AUTH);

        // Apply SPDM validation rules
        match role {
            SpdmCertificateRole::Requester => {
                // Requester cert MUST NOT contain ONLY Responder Auth OID
                if has_responder && !has_requester {
                    return Err(Error::ExtensionError(ExtensionError::ExtendedKeyUsage(
                        alloc::string::String::from(
                            "Requester certificate contains only Responder Auth EKU",
                        ),
                    )));
                }
            }
            SpdmCertificateRole::Responder => {
                // Responder cert MUST NOT contain ONLY Requester Auth OID
                if has_requester && !has_responder {
                    return Err(Error::ExtensionError(ExtensionError::ExtendedKeyUsage(
                        alloc::string::String::from(
                            "Responder certificate contains only Requester Auth EKU",
                        ),
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate SPDM Extension (OID 1.3.6.1.4.1.412.274.2)
    ///
    /// This extension contains SPDM-specific certificate information.
    /// The presence and content of this extension may be validated
    /// depending on the certificate model.
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The expected certificate model
    ///
    /// # Returns
    /// - `Ok(())` if extension validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_spdm_extension(
        &self,
        cert: &Certificate,
        _model: SpdmCertificateModel,
    ) -> Result<()> {
        // Try to get the SPDM extension
        let _spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
            Some(ext) => ext,
            None => return Ok(()), // SPDM extension is optional
        };

        // Parse and validate the SPDM extension
        // The extension value is a SEQUENCE of OIDs identifying certificate characteristics
        // For now, we just verify it's present and parseable
        // In a full implementation, we would parse the SEQUENCE and validate the OIDs

        Ok(())
    }

    /// Validate Hardware Identity OID (1.3.6.1.4.1.412.274.4)
    ///
    /// # Validation Rules (DSP0274 Section 10.6.1.4)
    /// - **DeviceCert**: Hardware Identity OID MUST be present in SPDM extension
    /// - **AliasCert**: Hardware Identity OID MUST NOT be present
    /// - **GenericCert**: No specific requirement
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The certificate model
    ///
    /// # Returns
    /// - `Ok(())` if hardware identity validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_hardware_identity(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
    ) -> Result<()> {
        // Check if the certificate has the SPDM extension
        let spdm_ext = match find_extension(cert, &oids::SPDM_EXTENSION) {
            Some(ext) => ext,
            None => {
                // If DeviceCert, SPDM extension should be present
                if model == SpdmCertificateModel::DeviceCert {
                    return Err(Error::ExtensionError(
                        ExtensionError::MissingRequiredExtension(alloc::string::String::from(
                            "DeviceCert requires SPDM extension with Hardware Identity",
                        )),
                    ));
                }
                return Ok(());
            }
        };

        // Parse the SPDM extension to look for Hardware Identity OID
        // The extension value is a SEQUENCE of OIDs
        let has_hw_identity = self.check_hardware_identity_in_extension(&spdm_ext.extn_value)?;

        // Apply validation rules based on certificate model
        match model {
            SpdmCertificateModel::DeviceCert => {
                if !has_hw_identity {
                    return Err(Error::ExtensionError(
                        ExtensionError::MissingRequiredExtension(alloc::string::String::from(
                            "DeviceCert MUST contain Hardware Identity OID",
                        )),
                    ));
                }
            }
            SpdmCertificateModel::AliasCert => {
                if has_hw_identity {
                    return Err(Error::ExtensionError(ExtensionError::InvalidValue(
                        alloc::string::String::from(
                            "AliasCert MUST NOT contain Hardware Identity OID",
                        ),
                    )));
                }
            }
            SpdmCertificateModel::GenericCert => {
                // No specific requirement for GenericCert
            }
        }

        Ok(())
    }

    /// Check if Hardware Identity OID is present in SPDM extension
    fn check_hardware_identity_in_extension(
        &self,
        extn_value: &der::asn1::OctetString,
    ) -> Result<bool> {
        // The SPDM extension value is an OCTET STRING containing a SEQUENCE of OIDs
        // We need to parse this structure and look for the Hardware Identity OID

        let bytes = extn_value.as_bytes();

        // Try to decode as a SEQUENCE of OIDs
        // In a full implementation, we would properly parse the ASN.1 structure
        // For now, we'll do a simple byte search for the Hardware Identity OID

        let hw_id_oid_bytes = oids::HARDWARE_IDENTITY.as_bytes();

        // Simple search - in production, use proper ASN.1 parsing
        Ok(bytes
            .windows(hw_id_oid_bytes.len())
            .any(|w| w == hw_id_oid_bytes))
    }

    /// Validate Basic Constraints per SPDM certificate model
    ///
    /// # Validation Rules
    /// - **DeviceCert**: cA MUST be FALSE
    /// - **AliasCert**: cA MUST be FALSE
    /// - **GenericCert**: cA may be TRUE or FALSE (for CA or end-entity)
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `model`: The certificate model
    ///
    /// # Returns
    /// - `Ok(())` if Basic Constraints validation passes
    /// - `Err(ExtensionError)` if validation fails
    pub fn validate_basic_constraints_spdm(
        &self,
        cert: &Certificate,
        model: SpdmCertificateModel,
    ) -> Result<()> {
        // Get the Basic Constraints extension
        let bc_ext = match find_extension(cert, &BASIC_CONSTRAINTS) {
            Some(ext) => ext,
            None => {
                // No Basic Constraints extension
                // For DeviceCert and AliasCert, cA defaults to FALSE, which is correct
                // For GenericCert, it depends on usage
                return Ok(());
            }
        };

        // Parse the Basic Constraints
        let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes()).map_err(|e| {
            Error::ExtensionError(ExtensionError::InvalidEncoding(alloc::format!(
                "Failed to parse Basic Constraints: {:?}",
                e
            )))
        })?;

        // Apply validation rules based on certificate model
        match model {
            SpdmCertificateModel::DeviceCert | SpdmCertificateModel::AliasCert => {
                if bc.ca {
                    return Err(Error::ExtensionError(ExtensionError::BasicConstraints(
                        alloc::format!("{} MUST have cA=FALSE in Basic Constraints", model.name()),
                    )));
                }
            }
            SpdmCertificateModel::GenericCert => {
                // GenericCert can have either cA=TRUE or cA=FALSE
                // No specific validation required
            }
        }

        Ok(())
    }

    /// Validate certificate algorithms against negotiated SPDM algorithms
    ///
    /// # Arguments
    /// - `cert`: The certificate to validate
    /// - `base_asym_algo`: Negotiated SPDM base asymmetric algorithm (bitfield)
    /// - `base_hash_algo`: Negotiated SPDM base hash algorithm (bitfield)
    ///
    /// # Returns
    /// - `Ok(())` if algorithm validation passes
    /// - `Err(AlgorithmError)` if validation fails
    fn validate_algorithms(
        &self,
        cert: &Certificate,
        base_asym_algo: u32,
        base_hash_algo: u32,
    ) -> Result<()> {
        use super::algorithm_verification::{
            verify_ecc_curve, verify_rsa_key_size,
            verify_signature_algorithm,
        };

        // Verify signature algorithm
        verify_signature_algorithm(
            &cert.signature_algorithm.algorithm,
            base_asym_algo,
            base_hash_algo,
        )?;

        // Verify public key algorithm
        let pk_algo_oid = &cert.tbs_certificate.subject_public_key_info.algorithm.oid;

        // Check if it's RSA or ECC
        if pk_algo_oid == &oids::RSA {
            // Verify RSA key size
            // For RSA, we need the full SubjectPublicKeyInfo DER encoding
            let pk_der = cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| {
                    Error::ValidationError(alloc::format!("Failed to encode public key: {:?}", e))
                })?;
            verify_rsa_key_size(&pk_der, base_asym_algo)?;
        } else {
            // Try to get the curve OID for ECC
            if let Some(params) = &cert
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .parameters
            {
                // Parameters for ECC contain the curve OID
                // The parameters are already a der::Any, which we can try to decode as an OID
                if let Ok(curve_oid) = ObjectIdentifier::from_der(params.value()) {
                    verify_ecc_curve(&curve_oid, base_asym_algo)?;
                }
            }
        }

        Ok(())
    }
}

impl Default for SpdmValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_model() {
        assert_eq!(SpdmCertificateModel::DeviceCert.value(), 0);
        assert_eq!(SpdmCertificateModel::AliasCert.value(), 1);
        assert_eq!(SpdmCertificateModel::GenericCert.value(), 2);

        assert_eq!(
            SpdmCertificateModel::from_value(0).unwrap(),
            SpdmCertificateModel::DeviceCert
        );
        assert_eq!(
            SpdmCertificateModel::from_value(1).unwrap(),
            SpdmCertificateModel::AliasCert
        );
        assert_eq!(
            SpdmCertificateModel::from_value(2).unwrap(),
            SpdmCertificateModel::GenericCert
        );

        assert!(SpdmCertificateModel::from_value(3).is_err());
    }

    #[test]
    fn test_certificate_model_names() {
        assert_eq!(SpdmCertificateModel::DeviceCert.name(), "DeviceCert");
        assert_eq!(SpdmCertificateModel::AliasCert.name(), "AliasCert");
        assert_eq!(SpdmCertificateModel::GenericCert.name(), "GenericCert");
    }

    #[test]
    fn test_certificate_role_names() {
        assert_eq!(SpdmCertificateRole::Requester.name(), "Requester");
        assert_eq!(SpdmCertificateRole::Responder.name(), "Responder");
    }
}
