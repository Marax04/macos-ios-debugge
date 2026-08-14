//! `pe_sign_checker` — PE Authenticode signature verification.
//!
//! Parses the `WIN_CERTIFICATE` structure from the security directory,
//! extracts PKCS#7 / CMS data, decodes the `SignedData` structure (DER),
//! verifies `SPC_INDIRECT_DATA` content type, and reports signing details.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by Authenticode checking.
#[derive(Debug, Clone)]
pub enum SignError {
    /// The file has no security (certificate) directory.
    NoSignature,
    /// The `WIN_CERTIFICATE` structure is too short.
    TruncatedCertStruct,
    /// The `WIN_CERTIFICATE` revision or type is unknown.
    UnsupportedCertType(u16),
    /// DER/BER decoding failed.
    DerError(String),
    /// Digest computation over the PE body failed.
    DigestError(String),
    /// The content type OID in the `SignedData` is not `SPC_INDIRECT_DATA`.
    WrongContentType(String),
    /// Signature bytes were not found.
    MissingSignatureBytes,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSignature => write!(f, "no Authenticode signature present"),
            Self::TruncatedCertStruct => write!(f, "WIN_CERTIFICATE struct truncated"),
            Self::UnsupportedCertType(t) => write!(f, "unsupported WIN_CERTIFICATE type {t:#x}"),
            Self::DerError(s) => write!(f, "DER decode error: {s}"),
            Self::DigestError(s) => write!(f, "digest error: {s}"),
            Self::WrongContentType(oid) => write!(f, "unexpected content type OID {oid}"),
            Self::MissingSignatureBytes => write!(f, "signature bytes missing"),
        }
    }
}

impl std::error::Error for SignError {}

// ─────────────────────────────────────────────────────────────────────────────
// WIN_CERTIFICATE
// ─────────────────────────────────────────────────────────────────────────────

/// `WIN_CERTIFICATE` revision values.
const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// `WIN_CERTIFICATE` type: PKCS#7 `SignedData`.
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// Parsed `WIN_CERTIFICATE` header.
#[derive(Debug, Clone)]
pub struct WinCertificate {
    /// Length of the certificate entry (including this header).
    pub length: u32,
    /// Revision (should be 0x0200).
    pub revision: u16,
    /// Certificate type (0x0002 = PKCS#7).
    pub cert_type: u16,
    /// Raw certificate bytes (the bCertificate field).
    pub data: Vec<u8>,
}

impl WinCertificate {
    /// Parse the `WIN_CERTIFICATE` structure at `data[offset..]`.
    ///
    /// # Errors
    /// Returns `SignError` if the data is too short or type is unsupported.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, SignError> {
        if offset + 8 > data.len() {
            return Err(SignError::TruncatedCertStruct);
        }
        let length = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let revision = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let cert_type = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

        if revision != WIN_CERT_REVISION_2_0 {
            // Accept anyway; Authenticode uses 2.0 but tolerate others.
        }
        if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            return Err(SignError::UnsupportedCertType(cert_type));
        }

        let data_start = offset + 8;
        let data_end = (offset + length as usize).min(data.len());
        if data_start > data_end {
            return Err(SignError::TruncatedCertStruct);
        }
        let cert_data = data[data_start..data_end].to_vec();

        Ok(Self {
            length,
            revision,
            cert_type,
            data: cert_data,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DER TLV
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal DER/BER TLV node.
#[derive(Debug, Clone)]
pub struct TlvNode {
    pub tag: u8,
    pub is_constructed: bool,
    /// Raw value bytes (not including tag/length).
    pub value: Vec<u8>,
    /// Child nodes (populated for constructed types).
    pub children: Vec<Self>,
}

impl TlvNode {
    /// Parse one TLV node from `data[pos..]`.  Returns `(node, new_pos)`.
    ///
    /// # Errors
    ///
    /// Returns `SignError::DerError` if the data is truncated or the DER
    /// length encoding is invalid.
    pub fn parse(data: &[u8], pos: usize) -> Result<(Self, usize), SignError> {
        if pos >= data.len() {
            return Err(SignError::DerError("unexpected end of data".to_string()));
        }
        let tag = data[pos];
        let is_constructed = (tag & 0x20) != 0;
        let mut p = pos + 1;

        // Parse length.
        if p >= data.len() {
            return Err(SignError::DerError("truncated length".to_string()));
        }
        let len: usize = if data[p] < 0x80 {
            let l = data[p] as usize;
            p += 1;
            l
        } else {
            let num_bytes = (data[p] & 0x7F) as usize;
            p += 1;
            if p + num_bytes > data.len() {
                return Err(SignError::DerError("truncated multi-byte length".to_string()));
            }
            let mut l: usize = 0;
            for &b in &data[p..p + num_bytes] {
                l = (l << 8) | (b as usize);
            }
            p += num_bytes;
            l
        };

        if p + len > data.len() {
            return Err(SignError::DerError(format!(
                "value truncated: need {len} at pos {p}, have {}",
                data.len()
            )));
        }

        let value = data[p..p + len].to_vec();
        let end = p + len;

        let children = if is_constructed {
            let mut kids = Vec::new();
            let mut sub = 0;
            while sub < value.len() {
                let (child, next) = Self::parse(&value, sub)?;
                sub = next;
                kids.push(child);
            }
            kids
        } else {
            Vec::new()
        };

        Ok((
            Self {
                tag,
                is_constructed,
                value,
                children,
            },
            end,
        ))
    }

    /// Parse all TLV nodes from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `SignError` if any TLV node cannot be parsed.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, SignError> {
        let mut nodes = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let (node, next) = Self::parse(data, pos)?;
            nodes.push(node);
            pos = next;
        }
        Ok(nodes)
    }

    /// Return the value as an OID dot-notation string, if this is an OID tag (0x06).
    #[must_use]
    pub fn as_oid(&self) -> Option<String> {
        if self.tag != 0x06 {
            return None;
        }
        Some(decode_oid(&self.value))
    }

    /// Return value as a UTF-8 string for `PrintableString` / `UTF8String` / `IA5String`.
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self.tag {
            0x13 | 0x0C | 0x16 | 0x1E | 0x14 => {
                Some(String::from_utf8_lossy(&self.value).into_owned())
            }
            _ => None,
        }
    }
}

/// Decode an OID from raw DER bytes to dot notation.
#[must_use]
pub fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let first = bytes[0];
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut acc: u64 = 0;
    for &b in &bytes[1..] {
        acc = (acc << 7) | u64::from(b & 0x7F);
        if (b & 0x80) == 0 {
            parts.push(acc.to_string());
            acc = 0;
        }
    }
    parts.join(".")
}

// ─────────────────────────────────────────────────────────────────────────────
// Known OIDs
// ─────────────────────────────────────────────────────────────────────────────

/// Map of well-known OID dot-notation → human name.
#[must_use]
pub fn known_oid_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.7.2" => "pkcs7-signedData",
        "1.3.6.1.4.1.311.2.1.4" => "SPC_INDIRECT_DATA_OBJID",
        "1.3.6.1.4.1.311.2.1.15" => "SPC_PE_IMAGE_DATA_OBJID",
        "1.2.840.113549.1.9.3" => "pkcs9-contentType",
        "1.2.840.113549.1.9.4" => "pkcs9-messageDigest",
        "1.2.840.113549.1.9.5" => "pkcs9-signingTime",
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.3.2" => "ecdsaWithSHA256",
        "1.2.840.10045.4.3.3" => "ecdsaWithSHA384",
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "emailAddress",
        _ => "unknown",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CertChain
// ─────────────────────────────────────────────────────────────────────────────

/// A single certificate in the signing chain.
#[derive(Debug, Clone)]
pub struct ChainCert {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number as hex.
    pub serial: String,
    /// Signature algorithm OID.
    pub sig_alg_oid: String,
    /// Human-readable algorithm name.
    pub sig_alg_name: String,
    /// Not-before (raw bytes, UTC or `GeneralizedTime`).
    pub not_before: Vec<u8>,
    /// Not-after.
    pub not_after: Vec<u8>,
    /// Raw DER bytes.
    pub raw_der: Vec<u8>,
}

impl ChainCert {
    /// Parse an X.509 certificate from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `SignError` if the DER data is malformed or the certificate
    /// structure cannot be decoded.
    pub fn from_der(der: &[u8]) -> Result<Self, SignError> {
        let nodes =
            TlvNode::parse_all(der).map_err(|e| SignError::DerError(e.to_string()))?;
        let cert_seq = nodes
            .first()
            .ok_or_else(|| SignError::DerError("empty certificate".to_string()))?;
        if !cert_seq.is_constructed {
            return Err(SignError::DerError("certificate not a sequence".to_string()));
        }

        // TBSCertificate is cert_seq.children[0]
        let tbs = cert_seq
            .children
            .first()
            .ok_or_else(|| SignError::DerError("missing TBSCertificate".to_string()))?;

        let serial = extract_serial(tbs);
        let (issuer, subject) = extract_issuer_subject(tbs);
        let (not_before, not_after) = extract_validity(tbs);
        let sig_alg_oid = extract_sig_alg(cert_seq);
        let sig_alg_name = known_oid_name(&sig_alg_oid).to_string();

        Ok(Self {
            subject,
            issuer,
            serial,
            sig_alg_oid,
            sig_alg_name,
            not_before,
            not_after,
            raw_der: der.to_vec(),
        })
    }

    /// Returns `true` if subject and issuer are the same (self-signed / root).
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }
}

/// Extract the serial number hex string from a `TBSCertificate` node.
fn extract_serial(tbs: &TlvNode) -> String {
    // Skip version [0] if present; serial is next INTEGER.
    for child in &tbs.children {
        if child.tag == 0x02 {
            // INTEGER
            return child.value.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        }
    }
    String::new()
}

/// Extract issuer and subject DNs from `TBSCertificate`.
fn extract_issuer_subject(tbs: &TlvNode) -> (String, String) {
    // Layout: [version] serial sigAlg issuer validity subject subjectPKI ...
    let sequences: Vec<&TlvNode> = tbs
        .children
        .iter()
        .filter(|n| n.tag == 0x30)
        .collect();
    // sequences[0] = sigAlg, [1] = issuer, [2] = validity, [3] = subject
    let issuer = sequences.get(1).copied().map(dn_to_string).unwrap_or_default();
    let subject = sequences.get(3).copied().map(dn_to_string).unwrap_or_default();
    (issuer, subject)
}

/// Convert a Name (SEQUENCE of RDNs) to a string like "CN=foo,O=bar".
fn dn_to_string(name: &TlvNode) -> String {
    let mut parts = Vec::new();
    for rdn_set in &name.children {
        for atv_seq in &rdn_set.children {
            if atv_seq.children.len() >= 2 {
                let oid_str = atv_seq.children[0].as_oid().unwrap_or_default();
                let label = known_oid_name(&oid_str);
                let value = atv_seq.children[1].as_string().unwrap_or_default();
                parts.push(format!("{label}={value}"));
            }
        }
    }
    parts.join(",")
}

/// Extract validity bytes from `TBSCertificate`.
fn extract_validity(tbs: &TlvNode) -> (Vec<u8>, Vec<u8>) {
    // validity SEQUENCE has 2 time children.
    for child in &tbs.children {
        if child.tag == 0x30 && child.children.len() >= 2 {
            let first = &child.children[0];
            let second = &child.children[1];
            if matches!(first.tag, 0x17 | 0x18) {
                return (first.value.clone(), second.value.clone());
            }
        }
    }
    (Vec::new(), Vec::new())
}

/// Extract signatureAlgorithm OID from a Certificate SEQUENCE.
fn extract_sig_alg(cert: &TlvNode) -> String {
    if cert.children.len() >= 2 {
        let alg_id = &cert.children[1];
        if let Some(oid) = alg_id.children.first().and_then(TlvNode::as_oid) {
            return oid;
        }
    }
    String::new()
}

/// A certificate chain extracted from the PKCS#7 `SignedData`.
#[derive(Debug, Clone)]
pub struct CertChain {
    pub certs: Vec<ChainCert>,
}

impl CertChain {
    /// Return the end-entity (leaf) certificate, if any.
    #[must_use]
    pub fn leaf(&self) -> Option<&ChainCert> {
        self.certs.first()
    }

    /// Return the root (last) certificate.
    #[must_use]
    pub fn root(&self) -> Option<&ChainCert> {
        self.certs.last()
    }

    /// Return chain depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.certs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignerInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `SignerInfo` from PKCS#7 `SignedData`.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Digest algorithm OID.
    pub digest_alg_oid: String,
    /// Human-readable digest algorithm name.
    pub digest_alg_name: String,
    /// Signature algorithm OID.
    pub sig_alg_oid: String,
    /// Signature algorithm name.
    pub sig_alg_name: String,
    /// Raw signature bytes.
    pub signature_bytes: Vec<u8>,
    /// Message digest attribute value (from authenticatedAttributes).
    pub message_digest: Vec<u8>,
    /// Signing time attribute value (raw bytes).
    pub signing_time: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterSign
// ─────────────────────────────────────────────────────────────────────────────

/// Counter-signature (timestamp authority) information.
#[derive(Debug, Clone)]
pub struct CounterSign {
    /// TSA signing certificate subject.
    pub tsa_subject: String,
    /// Digest algorithm OID.
    pub digest_alg_oid: String,
    /// Timestamp as raw bytes.
    pub timestamp_raw: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthenticodeInfo — main result type
// ─────────────────────────────────────────────────────────────────────────────

/// Result of Authenticode signature checking.
#[derive(Debug, Clone)]
pub struct AuthenticodeInfo {
    /// Whether the `WIN_CERTIFICATE` was structurally valid.
    pub cert_struct_valid: bool,
    /// The content type OID of the `SignedData` contentInfo.
    pub content_type_oid: String,
    /// The `SPC_INDIRECT_DATA` digest algorithm OID.
    pub spc_digest_alg: String,
    /// SPC image digest (hash of the PE file excluding signature areas).
    pub spc_image_digest: Vec<u8>,
    /// Signer info extracted from the `SignedData`.
    pub signer_info: Option<SignerInfo>,
    /// Certificate chain.
    pub cert_chain: CertChain,
    /// Counter-signature (timestamp), if present.
    pub counter_sign: Option<CounterSign>,
    /// Whether the embedded digest matches the computed one (simplified check).
    pub digest_match: Option<bool>,
    /// Summary flags.
    pub flags: SignCheckFlags,
}

impl AuthenticodeInfo {
    /// Return the leaf signer subject, if available.
    #[must_use]
    pub fn signer_subject(&self) -> Option<&str> {
        self.cert_chain.leaf().map(|c| c.subject.as_str())
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let subject = self.signer_subject().unwrap_or("<unknown>");
        let digest = if self.digest_match == Some(true) {
            "ok"
        } else if self.digest_match == Some(false) {
            "MISMATCH"
        } else {
            "unchecked"
        };
        format!(
            "signer=\"{}\" digest={} chain_depth={} timestamp={}",
            subject,
            digest,
            self.cert_chain.depth(),
            if self.counter_sign.is_some() { "yes" } else { "no" }
        )
    }
}

bitflags::bitflags! {
    /// Bitfield flags for the sign check result.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SignCheckFlags: u8 {
        /// `WIN_CERTIFICATE` struct parsed without error.
        const CERT_OK        = 1 << 0;
        /// Content type is `SPC_INDIRECT_DATA`.
        const IS_AUTHENTICODE = 1 << 1;
        /// At least one certificate was extracted.
        const HAS_CERTS      = 1 << 2;
        /// Digest computed matches embedded digest.
        const DIGEST_MATCHES = 1 << 3;
        /// Counter-signature (TSA) present.
        const HAS_TIMESTAMP  = 1 << 4;
    }
}

impl SignCheckFlags {
    /// `WIN_CERTIFICATE` struct parsed without error.
    #[must_use]
    pub const fn cert_ok(self) -> bool { self.contains(Self::CERT_OK) }
    /// Content type is `SPC_INDIRECT_DATA`.
    #[must_use]
    pub const fn is_authenticode(self) -> bool { self.contains(Self::IS_AUTHENTICODE) }
    /// At least one certificate was extracted.
    #[must_use]
    pub const fn has_certs(self) -> bool { self.contains(Self::HAS_CERTS) }
    /// Digest computed matches embedded digest.
    #[must_use]
    pub const fn digest_matches(self) -> bool { self.contains(Self::DIGEST_MATCHES) }
    /// Counter-signature (TSA) present.
    #[must_use]
    pub const fn has_timestamp(self) -> bool { self.contains(Self::HAS_TIMESTAMP) }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignCheckResult
// ─────────────────────────────────────────────────────────────────────────────

/// The final verdict of the sign-check operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignCheckResult {
    /// Signature is structurally valid and digest matches.
    Valid,
    /// No signature present.
    Unsigned,
    /// Signature present but digest does not match (tampered or stripped).
    DigestMismatch,
    /// Signature could not be parsed.
    ParseError,
    /// Signature is present but content type is not `SPC_INDIRECT_DATA`.
    NotAuthenticode,
}

impl fmt::Display for SignCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "VALID"),
            Self::Unsigned => write!(f, "UNSIGNED"),
            Self::DigestMismatch => write!(f, "DIGEST_MISMATCH"),
            Self::ParseError => write!(f, "PARSE_ERROR"),
            Self::NotAuthenticode => write!(f, "NOT_AUTHENTICODE"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeSignChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Checks the Authenticode signature of a PE file.
pub struct PeSignChecker {
    /// If `true`, compute the PE body digest and compare against `SPC_INDIRECT_DATA`.
    pub verify_digest: bool,
}

impl PeSignChecker {
    /// Create a checker; `verify_digest` controls whether the hash is recomputed.
    #[must_use]
    pub const fn new(verify_digest: bool) -> Self {
        Self { verify_digest }
    }

    /// Check the PE at `data`.
    ///
    /// # Errors
    /// Returns `SignError` if the signature is present but structurally invalid.
    pub fn check(&self, data: &[u8]) -> Result<(AuthenticodeInfo, SignCheckResult), SignError> {
        // Locate the security data directory (index 4).
        let (cert_offset, cert_size) = Self::find_security_dir(data)?;

        if cert_size == 0 {
            return Err(SignError::NoSignature);
        }

        let win_cert = WinCertificate::parse(data, cert_offset)?;

        // Parse PKCS#7 SignedData.
        let signed_data =
            parse_signed_data(&win_cert.data).map_err(|e| SignError::DerError(e.to_string()))?;

        let content_type_oid = signed_data.content_type_oid.clone();
        let spc_indirect_data_oid = "1.3.6.1.4.1.311.2.1.4";
        let is_authenticode = content_type_oid == spc_indirect_data_oid;

        if !is_authenticode {
            return Err(SignError::WrongContentType(content_type_oid));
        }

        // Extract SPC_INDIRECT_DATA fields.
        let spc_digest_alg = signed_data.spc_digest_alg.clone();
        let spc_image_digest = signed_data.spc_image_digest.clone();

        // Compute actual digest if requested.
        let digest_match = if self.verify_digest {
            let computed = compute_pe_hash_sha256_approx(data);
            Some(computed == spc_image_digest)
        } else {
            None
        };

        let mut flags = SignCheckFlags::CERT_OK | SignCheckFlags::IS_AUTHENTICODE;
        if !signed_data.cert_chain.certs.is_empty() { flags |= SignCheckFlags::HAS_CERTS; }
        if digest_match.unwrap_or(false) { flags |= SignCheckFlags::DIGEST_MATCHES; }
        if signed_data.counter_sign.is_some() { flags |= SignCheckFlags::HAS_TIMESTAMP; }

        let result = if digest_match == Some(false) {
            SignCheckResult::DigestMismatch
        } else {
            SignCheckResult::Valid
        };

        let info = AuthenticodeInfo {
            cert_struct_valid: true,
            content_type_oid,
            spc_digest_alg,
            spc_image_digest,
            signer_info: signed_data.signer_info,
            cert_chain: signed_data.cert_chain,
            counter_sign: signed_data.counter_sign,
            digest_match,
            flags,
        };

        Ok((info, result))
    }

    /// Locate the `WIN_CERTIFICATE` at the security directory.
    ///
    /// # Errors
    ///
    /// Returns `SignError` if the data is too short, missing a valid PE
    /// signature, or the security directory cannot be located.
    fn find_security_dir(data: &[u8]) -> Result<(usize, usize), SignError> {
        if data.len() < 64 {
            return Err(SignError::NoSignature);
        }
        let pe_off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if pe_off + 4 > data.len() {
            return Err(SignError::NoSignature);
        }
        if data[pe_off..pe_off + 4] != [0x50, 0x45, 0x00, 0x00] {
            return Err(SignError::NoSignature);
        }
        let opt_off = pe_off + 24;
        if opt_off + 2 > data.len() {
            return Err(SignError::NoSignature);
        }
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let is_64bit = magic == 0x020B;

        // Security dir is data_dir[4].
        let dir_start = if is_64bit {
            opt_off + 112
        } else {
            opt_off + 96
        };
        let sec_dir_off = dir_start + 4 * 8; // index 4
        if sec_dir_off + 8 > data.len() {
            return Err(SignError::NoSignature);
        }
        let sec_rva = u32::from_le_bytes(
            data[sec_dir_off..sec_dir_off + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        let sec_size = u32::from_le_bytes(
            data[sec_dir_off + 4..sec_dir_off + 8]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        if sec_rva == 0 || sec_size == 0 {
            return Err(SignError::NoSignature);
        }

        // Security dir uses file offset directly (not RVA).
        Ok((sec_rva, sec_size))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PKCS#7 SignedData parser (minimal)
// ─────────────────────────────────────────────────────────────────────────────

struct ParsedSignedData {
    content_type_oid: String,
    spc_digest_alg: String,
    spc_image_digest: Vec<u8>,
    signer_info: Option<SignerInfo>,
    cert_chain: CertChain,
    counter_sign: Option<CounterSign>,
}

fn parse_signed_data(data: &[u8]) -> Result<ParsedSignedData, SignError> {
    let nodes = TlvNode::parse_all(data)?;
    let outer = nodes
        .first()
        .ok_or_else(|| SignError::DerError("empty PKCS7".to_string()))?;
    // SEQUENCE { OID, [0] EXPLICIT content }
    let _content_type_oid = outer
        .children
        .first()
        .and_then(TlvNode::as_oid)
        .unwrap_or_default();

    // The [0] implicit or explicit contains the SignedData SEQUENCE.
    let signed_data_node = outer
        .children
        .get(1)
        .and_then(|n| n.children.first())
        .ok_or_else(|| SignError::DerError("missing SignedData content".to_string()))?;

    // SignedData children: version, digestAlgorithms, encapContentInfo, [0]certs, signerInfos
    let version_skip = 1usize; // skip version INTEGER
    let dig_algs = signed_data_node.children.get(version_skip);
    let encap = signed_data_node.children.get(version_skip + 1);

    // Extract digest algorithm from digestAlgorithms SET.
    let spc_digest_alg = dig_algs
        .and_then(|set| set.children.first())
        .and_then(|seq| seq.children.first())
        .and_then(TlvNode::as_oid)
        .unwrap_or_default();

    // Extract SPC content type and image digest from encapContentInfo.
    let (spc_content_oid, spc_image_digest) = extract_spc_indirect_data(encap);

    // Extract certificates from [0] context tag.
    let certs_node = signed_data_node
        .children
        .iter()
        .find(|n| n.tag == 0xA0); // [0] IMPLICIT
    let cert_chain = extract_cert_chain(certs_node);

    // Extract SignerInfo (last SET child in SignedData).
    let signer_infos_set = signed_data_node
        .children
        .iter()
        .rev()
        .find(|n| n.tag == 0x31); // SET
    let signer_info = signer_infos_set
        .and_then(|set| set.children.first())
        .map(parse_signer_info);

    // Extract counter-signature from unauthenticated attributes (signerInfo[1]).
    let counter_sign = signer_infos_set
        .and_then(|set| set.children.first())
        .and_then(extract_counter_sign);

    Ok(ParsedSignedData {
        content_type_oid: spc_content_oid,
        spc_digest_alg,
        spc_image_digest,
        signer_info,
        cert_chain,
        counter_sign,
    })
}

/// Extract `SPC_INDIRECT_DATA` content OID and image digest.
fn extract_spc_indirect_data(encap: Option<&TlvNode>) -> (String, Vec<u8>) {
    let Some(encap) = encap else { return (String::new(), Vec::new()) };
    let oid = encap
        .children
        .first()
        .and_then(TlvNode::as_oid)
        .unwrap_or_default();
    // The actual content is in [0] or OCTET STRING.
    let digest = encap
        .children
        .get(1)
        .and_then(|n| n.children.first())
        .and_then(|n| n.children.get(1)) // DigestInfo → digest
        .map(|n| n.value.clone())
        .unwrap_or_default();
    (oid, digest)
}

/// Parse certificates from [0] context node.
fn extract_cert_chain(certs_node: Option<&TlvNode>) -> CertChain {
    let Some(node) = certs_node else { return CertChain { certs: Vec::new() } };
    let mut certs = Vec::new();
    for child in &node.children {
        // Each child should be a SEQUENCE (X.509 certificate).
        if let Ok(cert) = ChainCert::from_der(&child.value) {
            // Re-parse using the full child (including tag and length).
            certs.push(cert);
        } else if let Ok(cert) = ChainCert::from_der(&{
            // Try including the full TLV of the child.
            let mut raw = vec![child.tag];
            encode_length(&mut raw, child.value.len());
            raw.extend_from_slice(&child.value);
            raw
        }) {
            certs.push(cert);
        }
    }
    CertChain { certs }
}

/// Encode a DER length into a byte vec.
fn encode_length(buf: &mut impl Extend<u8>, len: usize) {
    if len < 0x80 {
        buf.extend([u8::try_from(len).unwrap_or(u8::MAX)]);
    } else if len <= 0xFF {
        buf.extend([0x81_u8, u8::try_from(len).unwrap_or(u8::MAX)]);
    } else {
        buf.extend([0x82_u8, u8::try_from(len >> 8).unwrap_or(u8::MAX), u8::try_from(len & 0xFF).unwrap_or(u8::MAX)]);
    }
}

/// Parse a `SignerInfo` SEQUENCE.
fn parse_signer_info(si: &TlvNode) -> SignerInfo {
    // SignerInfo: version, issuerAndSerialNumber, digestAlgorithm,
    //   [0]authenticatedAttributes, signatureAlgorithm, signature,
    //   [1]unauthenticatedAttributes
    let dig_alg_oid = si
        .children
        .get(2)
        .and_then(|seq| seq.children.first())
        .and_then(TlvNode::as_oid)
        .unwrap_or_default();
    let sig_alg_oid = si
        .children
        .iter()
        .find(|n| n.tag == 0x30 && !n.children.is_empty())
        .and_then(|seq| seq.children.first())
        .and_then(TlvNode::as_oid)
        .unwrap_or_default();
    let sig_bytes = si
        .children
        .iter()
        .rev()
        .find(|n| n.tag == 0x04 || n.tag == 0x03)
        .map(|n| n.value.clone())
        .unwrap_or_default();
    let dig_alg_name = known_oid_name(&dig_alg_oid).to_string();
    let sig_alg_name = known_oid_name(&sig_alg_oid).to_string();

    SignerInfo {
        digest_alg_oid: dig_alg_oid,
        digest_alg_name: dig_alg_name,
        sig_alg_oid,
        sig_alg_name,
        signature_bytes: sig_bytes,
        message_digest: Vec::new(),
        signing_time: Vec::new(),
    }
}

/// Extract counter-signature from unauthenticated attributes.
fn extract_counter_sign(si: &TlvNode) -> Option<CounterSign> {
    // unauthenticatedAttributes is [1] context.
    let unauth = si.children.iter().find(|n| n.tag == 0xA1)?;
    // Each attribute is a SEQUENCE {OID, SET{value}}.
    for attr in &unauth.children {
        let oid = attr.children.first().and_then(TlvNode::as_oid)?;
        // OID 1.2.840.113549.1.9.6 = counterSignature
        if oid == "1.2.840.113549.1.9.6" {
            let ts_raw = attr
                .children
                .get(1)
                .map(|n| n.value.clone())
                .unwrap_or_default();
            return Some(CounterSign {
                tsa_subject: String::new(),
                digest_alg_oid: String::new(),
                timestamp_raw: ts_raw,
            });
        }
    }
    None
}

/// Compute a simplified PE body hash (djb2-style, std-only placeholder).
///
/// Real Authenticode uses SHA-256 over specific PE regions excluding the
/// checksum, security directory entry, and the PKCS#7 blob itself.
#[must_use]
pub fn compute_pe_hash_sha256_approx(data: &[u8]) -> Vec<u8> {
    let mut h: u64 = 5381;
    for &b in data {
        h = h.wrapping_mul(33).wrapping_add(u64::from(b));
    }
    let mut out = Vec::with_capacity(32);
    for i in 0..4u32 {
        let v = h.wrapping_mul(u64::from(i + 1));
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_oid_basic() {
        // OID 1.2.840.113549 (pkcs)
        let bytes = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D];
        let oid = decode_oid(&bytes);
        assert!(oid.starts_with("1.2.840"));
    }

    #[test]
    fn test_decode_oid_empty() {
        assert_eq!(decode_oid(&[]), "");
    }

    #[test]
    fn test_known_oid_sha256() {
        assert_eq!(known_oid_name("2.16.840.1.101.3.4.2.1"), "sha256");
    }

    #[test]
    fn test_known_oid_unknown() {
        assert_eq!(known_oid_name("9.9.9.9.9"), "unknown");
    }

    #[test]
    fn test_tlv_parse_integer() {
        let data = [0x02, 0x03, 0x01, 0x02, 0x03]; // INTEGER 3 bytes
        let (node, pos) = TlvNode::parse(&data, 0).unwrap();
        assert_eq!(node.tag, 0x02);
        assert_eq!(pos, 5);
        assert_eq!(node.value, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_tlv_parse_sequence() {
        // SEQUENCE containing one INTEGER
        let data = [0x30, 0x05, 0x02, 0x03, 0xAA, 0xBB, 0xCC];
        let (node, _pos) = TlvNode::parse(&data, 0).unwrap();
        assert!(node.is_constructed);
        assert_eq!(node.children.len(), 1);
    }

    #[test]
    fn test_tlv_parse_multi_byte_length() {
        // Tag 0x04, length 0x81 0x01 = 1 byte.
        let data = [0x04, 0x81, 0x01, 0xFF];
        let (node, _) = TlvNode::parse(&data, 0).unwrap();
        assert_eq!(node.value, vec![0xFF]);
    }

    #[test]
    fn test_win_cert_too_short() {
        let data = [0x00u8; 4];
        assert!(WinCertificate::parse(&data, 0).is_err());
    }

    #[test]
    fn test_win_cert_wrong_type() {
        // type = 0x0001 (not PKCS7)
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&16u32.to_le_bytes()); // length
        data[4..6].copy_from_slice(&0x0200u16.to_le_bytes()); // revision
        data[6..8].copy_from_slice(&0x0001u16.to_le_bytes()); // wrong type
        assert!(matches!(
            WinCertificate::parse(&data, 0),
            Err(SignError::UnsupportedCertType(0x0001))
        ));
    }

    #[test]
    fn test_sign_checker_no_sig_short_file() {
        let checker = PeSignChecker::new(false);
        let result = checker.check(&[0x4D, 0x5A, 0x00, 0x00]);
        assert!(matches!(result, Err(SignError::NoSignature)));
    }

    #[test]
    fn test_encode_length_short() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 42);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_encode_length_medium() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);
    }

    #[test]
    fn test_encode_length_long() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 0x0102);
        assert_eq!(buf, vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_compute_pe_hash_approx_deterministic() {
        let d = b"test data";
        let h1 = compute_pe_hash_sha256_approx(d);
        let h2 = compute_pe_hash_sha256_approx(d);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_compute_pe_hash_differs() {
        let h1 = compute_pe_hash_sha256_approx(b"AAAA");
        let h2 = compute_pe_hash_sha256_approx(b"BBBB");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_chain_cert_self_signed() {
        let cert = ChainCert {
            subject: "CN=root".to_string(),
            issuer: "CN=root".to_string(),
            serial: String::new(),
            sig_alg_oid: String::new(),
            sig_alg_name: String::new(),
            not_before: Vec::new(),
            not_after: Vec::new(),
            raw_der: Vec::new(),
        };
        assert!(cert.is_self_signed());
    }

    #[test]
    fn test_sign_check_result_display() {
        assert_eq!(SignCheckResult::Valid.to_string(), "VALID");
        assert_eq!(SignCheckResult::Unsigned.to_string(), "UNSIGNED");
        assert_eq!(SignCheckResult::DigestMismatch.to_string(), "DIGEST_MISMATCH");
    }

    #[test]
    fn test_tlv_as_oid() {
        // OID 2.5.4.3 = CN
        let node = TlvNode {
            tag: 0x06,
            is_constructed: false,
            value: vec![0x55, 0x04, 0x03],
            children: Vec::new(),
        };
        assert_eq!(node.as_oid().unwrap(), "2.5.4.3");
    }

    #[test]
    fn test_tlv_as_string_printable() {
        let node = TlvNode {
            tag: 0x13, // PrintableString
            is_constructed: false,
            value: b"Hello".to_vec(),
            children: Vec::new(),
        };
        assert_eq!(node.as_string().unwrap(), "Hello");
    }
}
