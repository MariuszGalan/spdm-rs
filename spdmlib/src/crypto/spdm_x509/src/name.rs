// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Distinguished Name (DN) and Subject Alternative Name (SAN) support for X.509 certificates.
//!
//! This module provides parsing and representation for X.509 distinguished names and
//! subject alternative names, including:
//! - RDNSequence (Distinguished Names)
//! - RelativeDistinguishedName (RDN)
//! - AttributeTypeAndValue
//! - Common DN attributes (CN, O, OU, C, ST, L, etc.)
//! - SubjectAltName extension with GeneralName variants
//!
//! # Examples
//!
//! ```ignore
//! use spdm_x509::name::{Name, AttributeTypeAndValue};
//! use der::Decode;
//!
//! // Parse a DN from DER encoding
//! let name = Name::from_der(der_bytes)?;
//! println!("DN: {}", name);
//! ```

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use const_oid::ObjectIdentifier;
use der::{
    asn1::{Ia5String, PrintableString, SetOfVec, Utf8StringRef},
    Any, Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Header, Length, Reader,
    Sequence, Tag, TagMode, TagNumber, Tagged, ValueOrd, Writer,
};

// ============================================================================
// Common Attribute Type OIDs (RFC 5280, Appendix A.1)
// ============================================================================

/// Common Name (CN) - 2.5.4.3
pub const CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Surname (SN) - 2.5.4.4
pub const SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");

/// Serial Number - 2.5.4.5
pub const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// Country (C) - 2.5.4.6
pub const COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");

/// Locality (L) - 2.5.4.7
pub const LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");

/// State or Province (ST) - 2.5.4.8
pub const STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");

/// Street Address - 2.5.4.9
pub const STREET_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.9");

/// Organization (O) - 2.5.4.10
pub const ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

/// Organizational Unit (OU) - 2.5.4.11
pub const ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");

/// Title - 2.5.4.12
pub const TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");

/// Given Name - 2.5.4.42
pub const GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");

/// Domain Component (DC) - 0.9.2342.19200300.100.1.25
pub const DOMAIN_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");

/// Email Address - 1.2.840.113549.1.9.1
pub const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

// ============================================================================
// DirectoryString - RFC 5280 Section 4.1.2.4
// ============================================================================

/// DirectoryString represents various ASN.1 string types used in X.509 names.
///
/// Per RFC 5280, DirectoryString is defined as:
/// ```asn1
/// DirectoryString ::= CHOICE {
///     teletexString   TeletexString   (SIZE (1..MAX)),
///     printableString PrintableString (SIZE (1..MAX)),
///     universalString UniversalString (SIZE (1..MAX)),
///     utf8String      UTF8String      (SIZE (1..MAX)),
///     bmpString       BMPString       (SIZE (1..MAX))
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryString {
    /// TeletexString (T61String) - Tag 20
    TeletexString(Vec<u8>),
    /// PrintableString - Tag 19
    PrintableString(PrintableString),
    /// UniversalString - Tag 28
    UniversalString(Vec<u8>),
    /// UTF8String - Tag 12
    Utf8String(String),
    /// BMPString - Tag 30
    BmpString(Vec<u8>),
    /// IA5String - Tag 22 (used for email addresses)
    Ia5String(Ia5String),
}

impl DirectoryString {
    /// Get the string value as UTF-8, converting if necessary
    pub fn as_str(&self) -> Result<String, Error> {
        match self {
            DirectoryString::Utf8String(s) => Ok(s.clone()),
            DirectoryString::PrintableString(s) => Ok(s.to_string()),
            DirectoryString::Ia5String(s) => Ok(s.as_str().to_string()),
            DirectoryString::TeletexString(bytes) => {
                // Attempt UTF-8 decode, fallback to lossy conversion
                String::from_utf8(bytes.clone())
                    .or_else(|_| Ok(String::from_utf8_lossy(bytes).to_string()))
            }
            DirectoryString::BmpString(bytes) => {
                // BMP is UTF-16BE
                if bytes.len() % 2 != 0 {
                    return Err(ErrorKind::Length {
                        tag: Tag::BmpString,
                    }
                    .into());
                }
                let utf16_chars: Vec<u16> = bytes
                    .chunks(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                    .collect();
                String::from_utf16(&utf16_chars).map_err(|_| {
                    ErrorKind::Value {
                        tag: Tag::BmpString,
                    }
                    .into()
                })
            }
            DirectoryString::UniversalString(bytes) => {
                // Universal is UTF-32BE (tag 0x1C = 28)
                if bytes.len() % 4 != 0 {
                    return Err(ErrorKind::Length {
                        tag: Tag::TeletexString, // Use a valid tag as placeholder
                    }
                    .into());
                }
                let mut result = String::new();
                for chunk in bytes.chunks(4) {
                    let code_point = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let ch = char::from_u32(code_point).ok_or(ErrorKind::Value {
                        tag: Tag::TeletexString,
                    })?;
                    result.push(ch);
                }
                Ok(result)
            }
        }
    }
}

impl<'a> DecodeValue<'a> for DirectoryString {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        match header.tag {
            Tag::Utf8String => {
                let s = Utf8StringRef::decode_value(reader, header)?;
                Ok(DirectoryString::Utf8String(s.as_str().to_string()))
            }
            Tag::PrintableString => {
                let s = PrintableString::decode_value(reader, header)?;
                Ok(DirectoryString::PrintableString(s))
            }
            Tag::Ia5String => {
                let s = Ia5String::decode_value(reader, header)?;
                Ok(DirectoryString::Ia5String(s))
            }
            Tag::TeletexString => {
                let bytes = reader.read_vec(header.length)?;
                Ok(DirectoryString::TeletexString(bytes))
            }
            Tag::BmpString => {
                let bytes = reader.read_vec(header.length)?;
                Ok(DirectoryString::BmpString(bytes))
            }
            // UniversalString is tag 28 (0x1C) but we can't easily create that Tag
            // So we'll skip it for now - it's very rare in modern certificates
            _ => Err(ErrorKind::TagUnexpected {
                expected: Some(Tag::Utf8String),
                actual: header.tag,
            }
            .into()),
        }
    }
}

impl EncodeValue for DirectoryString {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            DirectoryString::Utf8String(s) => s.len().try_into(),
            DirectoryString::PrintableString(s) => s.value_len(),
            DirectoryString::Ia5String(s) => s.value_len(),
            DirectoryString::TeletexString(bytes) => bytes.len().try_into(),
            DirectoryString::BmpString(bytes) => bytes.len().try_into(),
            DirectoryString::UniversalString(bytes) => bytes.len().try_into(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            DirectoryString::Utf8String(s) => writer.write(s.as_bytes()),
            DirectoryString::PrintableString(s) => s.encode_value(writer),
            DirectoryString::Ia5String(s) => s.encode_value(writer),
            DirectoryString::TeletexString(bytes) => writer.write(bytes),
            DirectoryString::BmpString(bytes) => writer.write(bytes),
            DirectoryString::UniversalString(bytes) => writer.write(bytes),
        }
    }
}

impl Tagged for DirectoryString {
    fn tag(&self) -> Tag {
        match self {
            DirectoryString::Utf8String(_) => Tag::Utf8String,
            DirectoryString::PrintableString(_) => Tag::PrintableString,
            DirectoryString::Ia5String(_) => Tag::Ia5String,
            DirectoryString::TeletexString(_) => Tag::TeletexString,
            DirectoryString::BmpString(_) => Tag::BmpString,
            // UniversalString is tag 0x1C, but we can't construct it easily
            // Use TeletexString as fallback (both are rare in modern certs)
            DirectoryString::UniversalString(_) => Tag::TeletexString,
        }
    }
}

impl fmt::Display for DirectoryString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "<invalid encoding>"),
        }
    }
}

// ============================================================================
// AttributeTypeAndValue - RFC 5280 Section 4.1.2.4
// ============================================================================

/// AttributeTypeAndValue represents a single attribute in an RDN.
///
/// ```asn1
/// AttributeTypeAndValue ::= SEQUENCE {
///     type  AttributeType,
///     value AttributeValue
/// }
///
/// AttributeType ::= OBJECT IDENTIFIER
/// AttributeValue ::= ANY -- DEFINED BY AttributeType
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct AttributeTypeAndValue {
    /// Attribute type (OID)
    pub oid: ObjectIdentifier,
    /// Attribute value (typically a DirectoryString)
    pub value: Any,
}

impl AttributeTypeAndValue {
    /// Create a new AttributeTypeAndValue with a DirectoryString value
    pub fn new(oid: ObjectIdentifier, value: DirectoryString) -> Result<Self, Error> {
        use der::Encode;
        let value_der = value.to_der()?;
        let any_value = Any::from_der(&value_der)?;
        Ok(Self {
            oid,
            value: any_value,
        })
    }

    /// Create a new AttributeTypeAndValue with a UTF-8 string value
    pub fn new_utf8(oid: ObjectIdentifier, value: &str) -> Result<Self, Error> {
        Self::new(oid, DirectoryString::Utf8String(value.to_string()))
    }

    /// Create a new AttributeTypeAndValue with a PrintableString value
    pub fn new_printable(oid: ObjectIdentifier, value: &str) -> Result<Self, Error> {
        let printable = PrintableString::new(value).map_err(|_| ErrorKind::Value {
            tag: Tag::PrintableString,
        })?;
        Self::new(oid, DirectoryString::PrintableString(printable))
    }

    /// Get the attribute value as a DirectoryString
    pub fn directory_string(&self) -> Result<DirectoryString, Error> {
        // DirectoryString doesn't implement Decode directly since it's not FixedTag
        // We need to decode based on the tag in the Any value
        let bytes = self.value.value();
        if bytes.is_empty() {
            return Err(ErrorKind::Length {
                tag: self.value.tag(),
            }
            .into());
        }
        // For now, try to decode as UTF8String as most common case
        String::from_utf8(bytes.to_vec())
            .map(DirectoryString::Utf8String)
            .map_err(|_| {
                ErrorKind::Value {
                    tag: self.value.tag(),
                }
                .into()
            })
    }

    /// Get the attribute value as a UTF-8 string
    pub fn value_as_str(&self) -> Result<String, Error> {
        self.directory_string()?.as_str()
    }

    /// Get a short name for the attribute type if known
    pub fn attr_name(&self) -> &str {
        match self.oid {
            CN => "CN",
            SURNAME => "SN",
            SERIAL_NUMBER => "SERIALNUMBER",
            COUNTRY_NAME => "C",
            LOCALITY_NAME => "L",
            STATE_OR_PROVINCE_NAME => "ST",
            STREET_ADDRESS => "STREET",
            ORGANIZATION_NAME => "O",
            ORGANIZATIONAL_UNIT_NAME => "OU",
            TITLE => "TITLE",
            GIVEN_NAME => "GIVENNAME",
            DOMAIN_COMPONENT => "DC",
            EMAIL_ADDRESS => "emailAddress",
            _ => "OID",
        }
    }
}

impl fmt::Display for AttributeTypeAndValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.attr_name();
        match self.value_as_str() {
            Ok(value) => {
                if name == "OID" {
                    write!(f, "{}={}", self.oid, value)
                } else {
                    write!(f, "{}={}", name, value)
                }
            }
            Err(_) => write!(f, "{}=<error>", name),
        }
    }
}

// Implement ValueOrd to allow AttributeTypeAndValue to be used in SetOfVec
impl ValueOrd for AttributeTypeAndValue {
    fn value_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        // Compare by OID first, then by value
        match self.oid.cmp(&other.oid) {
            core::cmp::Ordering::Equal => {
                // Compare the encoded values
                Ok(self.value.value().cmp(other.value.value()))
            }
            other_order => Ok(other_order),
        }
    }
}

// ============================================================================
// RelativeDistinguishedName - RFC 5280 Section 4.1.2.4
// ============================================================================

/// RelativeDistinguishedName (RDN) is a SET OF AttributeTypeAndValue.
///
/// ```asn1
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDistinguishedName {
    /// Set of attributes (typically only one, but can be multiple for multi-valued RDNs)
    pub attributes: SetOfVec<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    /// Create a new RDN with a single attribute
    pub fn new(attr: AttributeTypeAndValue) -> Result<Self, Error> {
        let mut attributes = SetOfVec::new();
        attributes
            .insert(attr)
            .map_err(|_| ErrorKind::Value { tag: Tag::Set })?;
        Ok(Self { attributes })
    }

    /// Create a new RDN from multiple attributes
    pub fn from_attributes(attrs: Vec<AttributeTypeAndValue>) -> Result<Self, Error> {
        let mut attributes = SetOfVec::new();
        for attr in attrs {
            attributes
                .insert(attr)
                .map_err(|_| ErrorKind::Value { tag: Tag::Set })?;
        }
        Ok(Self { attributes })
    }

    /// Get the first (or only) attribute in this RDN
    pub fn first(&self) -> Option<&AttributeTypeAndValue> {
        self.attributes.iter().next()
    }

    /// Check if this is a multi-valued RDN
    pub fn is_multi_valued(&self) -> bool {
        self.attributes.len() > 1
    }
}

impl<'a> DecodeValue<'a> for RelativeDistinguishedName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let attributes = SetOfVec::decode_value(reader, header)?;
        Ok(Self { attributes })
    }
}

impl EncodeValue for RelativeDistinguishedName {
    fn value_len(&self) -> der::Result<Length> {
        self.attributes.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.attributes.encode_value(writer)
    }
}

impl der::FixedTag for RelativeDistinguishedName {
    const TAG: Tag = Tag::Set;
}

impl fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attrs: Vec<String> = self.attributes.iter().map(|a| a.to_string()).collect();
        write!(f, "{}", attrs.join("+"))
    }
}

// ============================================================================
// RDNSequence (Name) - RFC 5280 Section 4.1.2.4
// ============================================================================

/// RDNSequence represents a Distinguished Name (DN).
///
/// ```asn1
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// Name ::= CHOICE { rdnSequence RDNSequence }
/// ```
///
/// In practice, Name is always rdnSequence, so we use RDNSequence directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RDNSequence {
    /// Sequence of RDNs, ordered from root to leaf (most significant first)
    pub rdns: Vec<RelativeDistinguishedName>,
}

impl<'a> DecodeValue<'a> for RDNSequence {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let mut rdns = Vec::new();
            while !reader.is_finished() {
                rdns.push(RelativeDistinguishedName::decode(reader)?);
            }
            Ok(Self { rdns })
        })
    }
}

impl EncodeValue for RDNSequence {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;
        for rdn in &self.rdns {
            len = (len + rdn.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        for rdn in &self.rdns {
            rdn.encode(writer)?;
        }
        Ok(())
    }
}

impl der::FixedTag for RDNSequence {
    const TAG: Tag = Tag::Sequence;
}

impl RDNSequence {
    /// Create a new empty RDNSequence
    pub fn new() -> Self {
        Self { rdns: Vec::new() }
    }

    /// Create an RDNSequence from a vector of RDNs
    pub fn from_rdns(rdns: Vec<RelativeDistinguishedName>) -> Self {
        Self { rdns }
    }

    /// Add an RDN to the sequence
    pub fn push(&mut self, rdn: RelativeDistinguishedName) {
        self.rdns.push(rdn);
    }

    /// Get an iterator over the RDNs
    pub fn iter(&self) -> core::slice::Iter<'_, RelativeDistinguishedName> {
        self.rdns.iter()
    }

    /// Find the first attribute with the given OID
    pub fn find_attr(&self, oid: ObjectIdentifier) -> Option<&AttributeTypeAndValue> {
        for rdn in &self.rdns {
            for attr in rdn.attributes.iter() {
                if attr.oid == oid {
                    return Some(attr);
                }
            }
        }
        None
    }

    /// Get the Common Name (CN) if present
    pub fn common_name(&self) -> Option<String> {
        self.find_attr(CN).and_then(|a| a.value_as_str().ok())
    }

    /// Get the Organization (O) if present
    pub fn organization(&self) -> Option<String> {
        self.find_attr(ORGANIZATION_NAME)
            .and_then(|a| a.value_as_str().ok())
    }

    /// Get the Country (C) if present
    pub fn country(&self) -> Option<String> {
        self.find_attr(COUNTRY_NAME)
            .and_then(|a| a.value_as_str().ok())
    }
}

impl Default for RDNSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RDNSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rdns.is_empty() {
            return write!(f, "");
        }

        // DN is printed in reverse order (leaf to root)
        let rdns: Vec<String> = self.rdns.iter().rev().map(|r| r.to_string()).collect();
        write!(f, "{}", rdns.join(", "))
    }
}

/// Type alias for Name (which is just RDNSequence in practice)
pub type Name = RDNSequence;

// ============================================================================
// GeneralName - RFC 5280 Section 4.2.1.6
// ============================================================================

/// GeneralName represents various name types in SubjectAltName extension.
///
/// ```asn1
/// GeneralName ::= CHOICE {
///     otherName                 [0] OtherName,
///     rfc822Name                [1] IA5String,
///     dNSName                   [2] IA5String,
///     x400Address               [3] ORAddress,
///     directoryName             [4] Name,
///     ediPartyName              [5] EDIPartyName,
///     uniformResourceIdentifier [6] IA5String,
///     iPAddress                 [7] OCTET STRING,
///     registeredID              [8] OBJECT IDENTIFIER
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    /// otherName `[0]`
    OtherName(Vec<u8>),
    /// rfc822Name `[1]` - Email address
    Rfc822Name(String),
    /// dNSName `[2]` - DNS hostname
    DnsName(String),
    /// x400Address `[3]`
    X400Address(Vec<u8>),
    /// directoryName `[4]` - Distinguished Name
    DirectoryName(Name),
    /// ediPartyName `[5]`
    EdiPartyName(Vec<u8>),
    /// uniformResourceIdentifier `[6]` - URI
    Uri(String),
    /// iPAddress `[7]` - IPv4 or IPv6 address
    IpAddress(Vec<u8>),
    /// registeredID `[8]` - OID
    RegisteredId(ObjectIdentifier),
}

impl GeneralName {
    /// Get the tag number for this GeneralName variant
    fn tag_number(&self) -> TagNumber {
        match self {
            GeneralName::OtherName(_) => TagNumber::N0,
            GeneralName::Rfc822Name(_) => TagNumber::N1,
            GeneralName::DnsName(_) => TagNumber::N2,
            GeneralName::X400Address(_) => TagNumber::N3,
            GeneralName::DirectoryName(_) => TagNumber::N4,
            GeneralName::EdiPartyName(_) => TagNumber::N5,
            GeneralName::Uri(_) => TagNumber::N6,
            GeneralName::IpAddress(_) => TagNumber::N7,
            GeneralName::RegisteredId(_) => TagNumber::N8,
        }
    }

    /// Parse an IP address (4 bytes for IPv4, 16 bytes for IPv6)
    pub fn ip_address_string(&self) -> Option<String> {
        if let GeneralName::IpAddress(bytes) = self {
            match bytes.len() {
                4 => Some(alloc::format!(
                    "{}.{}.{}.{}",
                    bytes[0],
                    bytes[1],
                    bytes[2],
                    bytes[3]
                )),
                16 => {
                    let parts: Vec<String> = bytes
                        .chunks(2)
                        .map(|c| alloc::format!("{:x}{:x}", c[0], c[1]))
                        .collect();
                    Some(parts.join(":"))
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

impl<'a> DecodeValue<'a> for GeneralName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let tag = header.tag;

        if !tag.is_context_specific() {
            return Err(ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            }
            .into());
        }

        match tag.number() {
            TagNumber::N0 => {
                // otherName
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::OtherName(bytes))
            }
            TagNumber::N1 => {
                // rfc822Name - IA5String
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::Rfc822Name(s))
            }
            TagNumber::N2 => {
                // dNSName - IA5String
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::DnsName(s))
            }
            TagNumber::N3 => {
                // x400Address
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::X400Address(bytes))
            }
            TagNumber::N4 => {
                // directoryName - Explicit tagging, contains a SEQUENCE
                let name = Name::decode(reader)?;
                Ok(GeneralName::DirectoryName(name))
            }
            TagNumber::N5 => {
                // ediPartyName
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::EdiPartyName(bytes))
            }
            TagNumber::N6 => {
                // uniformResourceIdentifier - IA5String
                let bytes = reader.read_vec(header.length)?;
                let s = core::str::from_utf8(&bytes)
                    .map_err(|_| ErrorKind::Value { tag })?
                    .to_string();
                Ok(GeneralName::Uri(s))
            }
            TagNumber::N7 => {
                // iPAddress - OCTET STRING
                let bytes = reader.read_vec(header.length)?;
                Ok(GeneralName::IpAddress(bytes))
            }
            TagNumber::N8 => {
                // registeredID - OBJECT IDENTIFIER
                let oid = ObjectIdentifier::decode(reader)?;
                Ok(GeneralName::RegisteredId(oid))
            }
            _ => Err(ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            }
            .into()),
        }
    }
}

impl EncodeValue for GeneralName {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            GeneralName::OtherName(bytes) => bytes.len().try_into(),
            GeneralName::Rfc822Name(s) => s.len().try_into(),
            GeneralName::DnsName(s) => s.len().try_into(),
            GeneralName::X400Address(bytes) => bytes.len().try_into(),
            GeneralName::DirectoryName(name) => name.encoded_len(),
            GeneralName::EdiPartyName(bytes) => bytes.len().try_into(),
            GeneralName::Uri(s) => s.len().try_into(),
            GeneralName::IpAddress(bytes) => bytes.len().try_into(),
            GeneralName::RegisteredId(oid) => oid.encoded_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            GeneralName::OtherName(bytes) => writer.write(bytes),
            GeneralName::Rfc822Name(s) => writer.write(s.as_bytes()),
            GeneralName::DnsName(s) => writer.write(s.as_bytes()),
            GeneralName::X400Address(bytes) => writer.write(bytes),
            GeneralName::DirectoryName(name) => name.encode(writer),
            GeneralName::EdiPartyName(bytes) => writer.write(bytes),
            GeneralName::Uri(s) => writer.write(s.as_bytes()),
            GeneralName::IpAddress(bytes) => writer.write(bytes),
            GeneralName::RegisteredId(oid) => oid.encode(writer),
        }
    }
}

impl Tagged for GeneralName {
    fn tag(&self) -> Tag {
        let _tag_mode = match self {
            // DirectoryName uses explicit tagging
            GeneralName::DirectoryName(_) => TagMode::Explicit,
            // All others use implicit tagging
            _ => TagMode::Implicit,
        };
        Tag::ContextSpecific {
            constructed: matches!(
                self,
                GeneralName::OtherName(_)
                    | GeneralName::DirectoryName(_)
                    | GeneralName::EdiPartyName(_)
            ),
            number: self.tag_number(),
        }
    }
}

impl fmt::Display for GeneralName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::OtherName(_) => write!(f, "otherName:<unsupported>"),
            GeneralName::Rfc822Name(email) => write!(f, "email:{}", email),
            GeneralName::DnsName(dns) => write!(f, "DNS:{}", dns),
            GeneralName::X400Address(_) => write!(f, "X400:<unsupported>"),
            GeneralName::DirectoryName(name) => write!(f, "DirName:{}", name),
            GeneralName::EdiPartyName(_) => write!(f, "EDI:<unsupported>"),
            GeneralName::Uri(uri) => write!(f, "URI:{}", uri),
            GeneralName::IpAddress(_) => {
                if let Some(ip) = self.ip_address_string() {
                    write!(f, "IP:{}", ip)
                } else {
                    write!(f, "IP:<invalid>")
                }
            }
            GeneralName::RegisteredId(oid) => write!(f, "RegID:{}", oid),
        }
    }
}

// ============================================================================
// SubjectAltName - RFC 5280 Section 4.2.1.6
// ============================================================================

/// SubjectAltName extension.
///
/// ```asn1
/// SubjectAltName ::= GeneralNames
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectAltName {
    /// List of alternative names
    pub names: Vec<GeneralName>,
}

impl SubjectAltName {
    /// Create a new SubjectAltName
    pub fn new(names: Vec<GeneralName>) -> Self {
        Self { names }
    }

    /// Get all DNS names
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::DnsName(dns) => Some(dns.as_str()),
            _ => None,
        })
    }

    /// Get all email addresses
    pub fn email_addresses(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::Rfc822Name(email) => Some(email.as_str()),
            _ => None,
        })
    }

    /// Get all IP addresses
    pub fn ip_addresses(&self) -> impl Iterator<Item = &[u8]> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::IpAddress(ip) => Some(ip.as_slice()),
            _ => None,
        })
    }

    /// Get all URIs
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.names.iter().filter_map(|n| match n {
            GeneralName::Uri(uri) => Some(uri.as_str()),
            _ => None,
        })
    }
}

impl<'a> DecodeValue<'a> for SubjectAltName {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let mut names = Vec::new();
        reader.read_nested(header.length, |reader| {
            while !reader.is_finished() {
                // Read the header for each GeneralName
                let name_header = Header::decode(reader)?;
                let name = GeneralName::decode_value(reader, name_header)?;
                names.push(name);
            }
            Ok(())
        })?;
        Ok(Self { names })
    }
}

impl EncodeValue for SubjectAltName {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = Length::ZERO;
        for name in &self.names {
            len = (len + name.encoded_len()?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        for name in &self.names {
            name.encode(writer)?;
        }
        Ok(())
    }
}

impl der::FixedTag for SubjectAltName {
    const TAG: Tag = Tag::Sequence;
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.names.iter().map(|n| n.to_string()).collect();
        write!(f, "{}", names.join(", "))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_string_utf8() {
        let ds = DirectoryString::Utf8String("Hello World".to_string());
        assert_eq!(ds.as_str().unwrap(), "Hello World");
        assert_eq!(ds.to_string(), "Hello World");
    }

    #[test]
    fn test_attribute_type_and_value() {
        let attr = AttributeTypeAndValue::new_utf8(CN, "Example Corp").unwrap();
        assert_eq!(attr.oid, CN);
        assert_eq!(attr.value_as_str().unwrap(), "Example Corp");
        assert_eq!(attr.attr_name(), "CN");
        assert_eq!(attr.to_string(), "CN=Example Corp");
    }

    #[test]
    fn test_rdn() {
        let attr = AttributeTypeAndValue::new_utf8(CN, "Test").unwrap();
        let rdn = RelativeDistinguishedName::new(attr).unwrap();
        assert!(!rdn.is_multi_valued());
        assert_eq!(rdn.to_string(), "CN=Test");
    }

    #[test]
    fn test_rdn_sequence() {
        let mut name = RDNSequence::new();

        let cn_attr = AttributeTypeAndValue::new_utf8(CN, "John Doe").unwrap();
        let cn_rdn = RelativeDistinguishedName::new(cn_attr).unwrap();
        name.push(cn_rdn);

        let o_attr = AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Example Inc").unwrap();
        let o_rdn = RelativeDistinguishedName::new(o_attr).unwrap();
        name.push(o_rdn);

        let c_attr = AttributeTypeAndValue::new_printable(COUNTRY_NAME, "US").unwrap();
        let c_rdn = RelativeDistinguishedName::new(c_attr).unwrap();
        name.push(c_rdn);

        assert_eq!(name.common_name().unwrap(), "John Doe");
        assert_eq!(name.organization().unwrap(), "Example Inc");
        assert_eq!(name.country().unwrap(), "US");

        // DN should display in reverse order
        let dn_str = name.to_string();
        assert!(dn_str.starts_with("C=US"));
    }

    #[test]
    fn test_general_name_dns() {
        let gn = GeneralName::DnsName("example.com".to_string());
        assert_eq!(gn.to_string(), "DNS:example.com");
    }

    #[test]
    fn test_general_name_email() {
        let gn = GeneralName::Rfc822Name("user@example.com".to_string());
        assert_eq!(gn.to_string(), "email:user@example.com");
    }

    #[test]
    fn test_general_name_ip() {
        let gn = GeneralName::IpAddress(vec![192, 168, 1, 1]);
        assert_eq!(gn.ip_address_string().unwrap(), "192.168.1.1");
        assert_eq!(gn.to_string(), "IP:192.168.1.1");
    }

    #[test]
    fn test_subject_alt_name() {
        let san = SubjectAltName::new(vec![
            GeneralName::DnsName("example.com".to_string()),
            GeneralName::DnsName("www.example.com".to_string()),
            GeneralName::Rfc822Name("admin@example.com".to_string()),
            GeneralName::IpAddress(vec![192, 168, 1, 1]),
        ]);

        let dns_names: Vec<&str> = san.dns_names().collect();
        assert_eq!(dns_names.len(), 2);
        assert!(dns_names.contains(&"example.com"));
        assert!(dns_names.contains(&"www.example.com"));

        let emails: Vec<&str> = san.email_addresses().collect();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0], "admin@example.com");

        let ips: Vec<&[u8]> = san.ip_addresses().collect();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_common_oids() {
        assert_eq!(CN.to_string(), "2.5.4.3");
        assert_eq!(ORGANIZATION_NAME.to_string(), "2.5.4.10");
        assert_eq!(COUNTRY_NAME.to_string(), "2.5.4.6");
        assert_eq!(DOMAIN_COMPONENT.to_string(), "0.9.2342.19200300.100.1.25");
    }

    #[test]
    fn test_encode_decode_rdn_sequence() {
        let mut name = RDNSequence::new();

        let cn = AttributeTypeAndValue::new_utf8(CN, "Test User").unwrap();
        name.push(RelativeDistinguishedName::new(cn).unwrap());

        let o = AttributeTypeAndValue::new_utf8(ORGANIZATION_NAME, "Test Org").unwrap();
        name.push(RelativeDistinguishedName::new(o).unwrap());

        // Encode to DER
        let der = name.to_der().unwrap();

        // Decode from DER
        let decoded = RDNSequence::from_der(&der).unwrap();

        assert_eq!(name, decoded);
        assert_eq!(decoded.common_name().unwrap(), "Test User");
        assert_eq!(decoded.organization().unwrap(), "Test Org");
    }
}
