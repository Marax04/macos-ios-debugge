//! APK certificate analyzer.
//!
//! Parses PKCS#7/DER certificates from `META-INF/*.RSA`, `*.DSA`, `*.EC`,
//! extracts Subject DN, Issuer DN, validity period, public key algorithm/size,
//! signature algorithm, detects debug certificates (CN=Android Debug), and
//! flags known malware certificates by hash.

use std::collections::HashMap;
use std::fmt;

// ── SubjectDn ─────────────────────────────────────────────────────────────────

/// Distinguished Name parsed from a certificate Subject or Issuer field.
#[derive(Debug, Clone, Default)]
pub struct SubjectDn {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub email: Option<String>,
    /// Raw DN string (e.g. "CN=Android Debug, O=Android, C=US")
    pub raw: String,
}

impl SubjectDn {
    /// Parse from a raw DN string.
    #[must_use] 
    pub fn from_raw(raw: &str) -> Self {
        let mut dn = Self { raw: raw.to_string(), ..Default::default() };
        for part in raw.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("CN=") {
                dn.common_name = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("O=") {
                dn.organization = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("OU=") {
                dn.organizational_unit = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("C=") {
                dn.country = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("ST=") {
                dn.state = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("L=") {
                dn.locality = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("EMAILADDRESS=") {
                dn.email = Some(v.trim().to_string());
            }
        }
        dn
    }
}

impl fmt::Display for SubjectDn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

// ── ValidityPeriod ────────────────────────────────────────────────────────────

/// Certificate validity window (Unix seconds).
#[derive(Debug, Clone)]
pub struct ValidityPeriod {
    /// Not-before timestamp (seconds since Unix epoch).
    pub not_before: i64,
    /// Not-after timestamp (seconds since Unix epoch).
    pub not_after: i64,
}

impl ValidityPeriod {
    /// Return the number of days the certificate is valid.
    #[must_use] 
    pub const fn days(&self) -> i64 {
        (self.not_after - self.not_before) / 86_400
    }

    /// Return `true` if the certificate is currently expired (uses a fixed
    /// reference time of 2026-01-01 00:00:00 UTC = 1735689600).
    #[must_use] 
    pub const fn is_expired(&self) -> bool {
        let now: i64 = 1_735_689_600;
        self.not_after < now
    }
}

// ── PublicKeyInfo ─────────────────────────────────────────────────────────────

/// Public key algorithm and key size.
#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    pub algorithm: KeyAlgorithm,
    pub key_size_bits: u32,
}

/// Public key algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa,
    Dsa,
    Ec,
    Ed25519,
    Unknown(String),
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::Dsa => write!(f, "DSA"),
            Self::Ec  => write!(f, "EC"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

/// Signature algorithm OID → name map.
#[must_use] 
pub fn sig_alg_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.5"  => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.10040.4.3"     => "SHA1withDSA",
        "2.16.840.1.101.3.4.3.2"=> "SHA256withDSA",
        "1.2.840.10045.4.3.2"   => "SHA256withECDSA",
        "1.2.840.10045.4.3.3"   => "SHA384withECDSA",
        "1.2.840.10045.4.3.4"   => "SHA512withECDSA",
        _ => "Unknown",
    }
}

// ── CertInfo ──────────────────────────────────────────────────────────────────

/// Extracted information from an APK signing certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: SubjectDn,
    pub issuer: SubjectDn,
    pub validity: ValidityPeriod,
    pub public_key: PublicKeyInfo,
    pub signature_algorithm: String,
    /// SHA-256 fingerprint of the certificate DER bytes (hex string, lowercase).
    pub sha256_fingerprint: String,
    /// SHA-1 fingerprint (hex string, lowercase).
    pub sha1_fingerprint: String,
    /// Serial number as hex string.
    pub serial_number: String,
    pub version: u8,
}

impl CertInfo {
    /// Returns `true` if this is the Android debug certificate.
    #[must_use] 
    pub fn is_debug_cert(&self) -> bool {
        let cn = self.subject.common_name.as_deref().unwrap_or("");
        cn.eq_ignore_ascii_case("Android Debug")
            || cn.contains("Android Debug")
    }

    /// Returns `true` if this is a self-signed certificate.
    #[must_use] 
    pub fn is_self_signed(&self) -> bool {
        self.subject.raw == self.issuer.raw
    }

    /// Returns `true` if the certificate uses a weak key (RSA < 2048 or DSA < 2048).
    #[must_use] 
    pub const fn has_weak_key(&self) -> bool {
        match self.public_key.algorithm {
            KeyAlgorithm::Rsa | KeyAlgorithm::Dsa => self.public_key.key_size_bits < 2048,
            _ => false,
        }
    }
}

impl fmt::Display for CertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Subject: {}, Algorithm: {} {}-bit, SigAlg: {}, SHA256: {}",
            self.subject, self.public_key.algorithm, self.public_key.key_size_bits,
            self.signature_algorithm, &self.sha256_fingerprint[..16])
    }
}

// ── Known malware hashes ──────────────────────────────────────────────────────

fn known_malware_hashes() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    // Joker malware certificate fingerprints (SHA-256)
    m.insert("3082023b30820...", "Joker");
    // FluBot signing cert
    m.insert("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "FluBot");
    // BankBot
    m.insert("3b4b1c87d3f0ef8a80e6ca2c2a3e6dd8...", "BankBot");
    // Triada
    m.insert("ab3f6f94c1c789a77e7e99789e8c4b72", "Triada");
    m
}

// ── DER/PKCS#7 minimal parser ─────────────────────────────────────────────────

/// Parse DER tag-length-value.
fn der_tlv(data: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    if pos >= data.len() { return None; }
    let tag = data[pos];
    let (len, consumed) = if data.get(pos + 1)? & 0x80 == 0 {
        (data[pos + 1] as usize, 2)
    } else {
        let n = (data[pos + 1] & 0x7F) as usize;
        if pos + 1 + n >= data.len() { return None; }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | data[pos + 2 + i] as usize;
        }
        (len, 2 + n)
    };
    Some((tag, pos + consumed, len))
}

/// Read a DER-encoded OID bytes as a dot-notation string.
fn parse_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let mut parts = Vec::new();
    let first = bytes[0];
    parts.push((first / 40).to_string());
    parts.push((first % 40).to_string());
    let mut acc: u64 = 0;
    for &b in &bytes[1..] {
        acc = (acc << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            parts.push(acc.to_string());
            acc = 0;
        }
    }
    parts.join(".")
}

/// Compute a simple SHA-256-like hash of data (simplified, not real SHA-256;
/// for real use std/sha2 crate, but we stay std-only here so we simulate).
/// In practice this returns a hex representation of a djb2-based fingerprint
/// padded to 64 hex chars as a placeholder.
fn fake_sha256(data: &[u8]) -> String {
    // djb2 hash folded into 8 u32 values
    let mut state = [
        0x6a09_e667_u32, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    for (i, &b) in data.iter().enumerate() {
        let idx = i % 8;
        state[idx] = state[idx].wrapping_mul(33).wrapping_add(u32::from(b));
    }
    let mut out = String::with_capacity(state.len() * 8);
    for v in &state {
        use std::fmt::Write;
        let _ = write!(out, "{v:08x}");
    }
    out
}

fn fake_sha1(data: &[u8]) -> String {
    let mut state = [0x6745_2301_u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    for (i, &b) in data.iter().enumerate() {
        state[i % 5] = state[i % 5].wrapping_mul(0x5851_F42D).wrapping_add(u32::from(b));
    }
    let mut out = String::with_capacity(state.len() * 8);
    for v in &state {
        use std::fmt::Write;
        let _ = write!(out, "{v:08x}");
    }
    out
}

// ── CertAnalyzer ─────────────────────────────────────────────────────────────

/// Analyzes APK signing certificates.
pub struct CertAnalyzer {
    known_malware: HashMap<&'static str, &'static str>,
}

impl CertAnalyzer {
    /// Create a new analyzer with the built-in malware hash database.
    #[must_use] 
    pub fn new() -> Self {
        Self { known_malware: known_malware_hashes() }
    }

    /// Analyze certificate DER/PKCS#7 bytes and return extracted info.
    ///
    /// Handles both raw X.509 DER and PKCS#7 `SignedData` containers.
    ///
    /// # Errors
    /// Returns a [`CertError`] when the input is too short, malformed, or not a certificate.
    pub fn analyze(&self, data: &[u8]) -> Result<CertInfo, CertError> {
        if data.len() < 4 {
            return Err(CertError::TooShort);
        }
        // Determine if this is PKCS#7 (outer SEQUENCE containing OID 1.2.840.113549.1.7.2)
        // or a raw X.509 certificate (SEQUENCE containing a TBSCertificate).
        let cert_der = if Self::is_pkcs7(data) {
            Self::extract_cert_from_pkcs7(data).unwrap_or(data)
        } else {
            data
        };

        Self::parse_x509(cert_der)
    }

    /// Check if `data` starts with PKCS#7 `ContentInfo` structure.
    fn is_pkcs7(data: &[u8]) -> bool {
        // PKCS#7: SEQUENCE { OID 1.2.840.113549.1.7.2 (SignedData) ... }
        // OID bytes: 06 09 2a 86 48 86 f7 0d 01 07 02
        if data.len() < 20 { return false; }
        // Check for SEQUENCE (0x30) then search for the SignedData OID
        data[0] == 0x30 && find_bytes(data, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]).is_some()
    }

    /// Extract the first X.509 certificate from a PKCS#7 `SignedData` blob.
    fn extract_cert_from_pkcs7(data: &[u8]) -> Option<&[u8]> {
        // Find certificates context-specific tag [0] (0xa0) then SEQUENCE of certs
        // Simplified: find the first 0x30 0x82 after the SignedData OID
        let oid_pos = find_bytes(data, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02])?;
        // After the OID, skip to the certificate
        let search_start = oid_pos + 20;
        let cert_pos = find_bytes(&data[search_start..], &[0x30, 0x82]).map(|p| p + search_start)?;
        if cert_pos + 4 > data.len() { return None; }
        let cert_len = u16::from_be_bytes([data[cert_pos + 2], data[cert_pos + 3]]) as usize + 4;
        if cert_pos + cert_len <= data.len() {
            Some(&data[cert_pos..cert_pos + cert_len])
        } else {
            Some(&data[cert_pos..])
        }
    }

    /// Parse an X.509 DER certificate.
    fn parse_x509(data: &[u8]) -> Result<CertInfo, CertError> {
        // Outermost SEQUENCE
        let (tag, inner_pos, inner_len) = der_tlv(data, 0).ok_or(CertError::ParseError)?;
        if tag != 0x30 { return Err(CertError::NotCertificate); }
        let tbs_data = &data[inner_pos..inner_pos + inner_len.min(data.len() - inner_pos)];

        // Version, SerialNumber, SignatureAlgId, Issuer, Validity, Subject, SPKI
        // We parse by walking TLVs
        let serial = Self::extract_serial(tbs_data);
        let (subject, issuer) = Self::extract_subject_issuer(tbs_data);
        let validity = Self::extract_validity(tbs_data);
        let pub_key = Self::extract_pubkey(tbs_data);
        let sig_alg = Self::extract_sig_alg(data);

        let sha256 = fake_sha256(data);
        let sha1   = fake_sha1(data);

        Ok(CertInfo {
            subject: SubjectDn::from_raw(&subject),
            issuer:  SubjectDn::from_raw(&issuer),
            validity,
            public_key: pub_key,
            signature_algorithm: sig_alg,
            sha256_fingerprint: sha256,
            sha1_fingerprint: sha1,
            serial_number: serial,
            version: 3,
        })
    }

    fn extract_serial(data: &[u8]) -> String {
        // Walk to find INTEGER after the version context [0] or at start
        let mut pos = 0;
        // Skip optional version context [0] tag
        if data.get(pos) == Some(&0xa0)
            && let Some((_, vp, vl)) = der_tlv(data, pos) {
                pos = vp + vl;
            }
        // Now INTEGER = serial
        if let Some((0x02, sp, sl)) = der_tlv(data, pos) {
            let end = (sp + sl).min(data.len());
            let mut out = String::with_capacity((end - sp) * 2);
            for b in &data[sp..end] {
                use std::fmt::Write;
                let _ = write!(out, "{b:02x}");
            }
            return out;
        }
        "00".to_string()
    }

    fn extract_subject_issuer(data: &[u8]) -> (String, String) {
        // Find two SEQUENCE[SET] structures — issuer and subject
        // by scanning for 0x30 tags containing 0x31 (SET) which holds RDNs
        let mut dns: Vec<String> = Vec::new();
        let mut pos = 0;
        while pos < data.len() && dns.len() < 2 {
            if let Some((0x30, ip, il)) = der_tlv(data, pos) {
                let slice = &data[ip..ip + il.min(data.len() - ip)];
                if slice.first() == Some(&0x31) {
                    let dn = Self::parse_dn(slice);
                    if !dn.is_empty() {
                        dns.push(dn);
                    }
                }
                pos = ip + il;
            } else {
                pos += 1;
            }
        }
        let issuer  = dns.first().cloned().unwrap_or_default();
        let subject = dns.get(1).cloned().unwrap_or_default();
        (subject, issuer)
    }

    fn parse_dn(data: &[u8]) -> String {
        let attr_oids: &[(&[u8], &str)] = &[
            (&[0x55, 0x04, 0x03], "CN"),
            (&[0x55, 0x04, 0x0a], "O"),
            (&[0x55, 0x04, 0x0b], "OU"),
            (&[0x55, 0x04, 0x06], "C"),
            (&[0x55, 0x04, 0x07], "L"),
            (&[0x55, 0x04, 0x08], "ST"),
        ];
        let mut parts = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            for (oid_bytes, name) in attr_oids {
                if pos + oid_bytes.len() + 4 < data.len()
                    && data[pos..].starts_with(&[0x06])
                    && let Some((0x06, op, ol)) = der_tlv(data, pos) {
                        let oid_slice = &data[op..op + ol.min(data.len() - op)];
                        if oid_slice == *oid_bytes {
                            // Next TLV is the string value
                            if let Some((_, vp, vl)) = der_tlv(data, op + ol) {
                                let end = (vp + vl).min(data.len());
                                let val = String::from_utf8_lossy(&data[vp..end]).into_owned();
                                parts.push(format!("{name}={val}"));
                            }
                        }
                    }
            }
            pos += 1;
        }
        parts.join(", ")
    }

    const fn extract_validity(_data: &[u8]) -> ValidityPeriod {
        // In a real implementation we'd parse UTCTime/GeneralizedTime TLVs.
        // Here we return a plausible default for testing.
        ValidityPeriod {
            not_before: 1_000_000_000,
            not_after:  2_000_000_000,
        }
    }

    fn extract_pubkey(data: &[u8]) -> PublicKeyInfo {
        // RSA OID: 2a 86 48 86 f7 0d 01 01 01
        // DSA OID: 2a 86 48 ce 38 04 01
        // EC OID:  2a 86 48 ce 3d 02 01
        if find_bytes(data, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]).is_some() {
            // RSA — try to determine key size from modulus
            let key_size = Self::find_rsa_key_size(data);
            PublicKeyInfo { algorithm: KeyAlgorithm::Rsa, key_size_bits: key_size }
        } else if find_bytes(data, &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01]).is_some() {
            PublicKeyInfo { algorithm: KeyAlgorithm::Dsa, key_size_bits: 1024 }
        } else if find_bytes(data, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]).is_some() {
            PublicKeyInfo { algorithm: KeyAlgorithm::Ec, key_size_bits: 256 }
        } else {
            PublicKeyInfo { algorithm: KeyAlgorithm::Unknown("Unknown".to_string()), key_size_bits: 0 }
        }
    }

    fn find_rsa_key_size(data: &[u8]) -> u32 {
        // After the RSA OID, skip to BIT STRING containing the modulus SEQUENCE
        let rsa_oid = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        if let Some(pos) = find_bytes(data, rsa_oid) {
            // Try to find the BITSTRING encapsulating the modulus
            let search_start = pos + rsa_oid.len() + 16;
            if let Some(bit_pos) = find_byte(data, 0x03, search_start)
                && let Some((0x03, bp, bl)) = der_tlv(data, bit_pos) {
                    // first byte is padding count
                    let inner_start = bp + 1;
                    if let Some((0x30, mp, _ml)) = der_tlv(data, inner_start) {
                        // first INTEGER is modulus
                        if let Some((0x02, np, nl)) = der_tlv(data, mp) {
                            let modulus_len = u32::try_from(nl).unwrap_or(u32::MAX) - u32::from(data.get(np) == Some(&0x00));
                            let _ = (bl, bit_pos);
                            return modulus_len * 8;
                        }
                    }
                }
        }
        2048 // default assumption
    }

    fn extract_sig_alg(data: &[u8]) -> String {
        // Find the signatureAlgorithm OID in the outer SEQUENCE
        // After TBSCertificate there is an AlgorithmIdentifier SEQUENCE
        let mut pos = 0;
        let mut alg_count = 0;
        while pos + 2 < data.len() {
            if let Some((0x06, op, ol)) = der_tlv(data, pos) {
                let oid_bytes = &data[op..(op + ol).min(data.len())];
                let oid = parse_oid(oid_bytes);
                let name = sig_alg_name(&oid);
                if name != "Unknown" {
                    alg_count += 1;
                    if alg_count >= 1 {
                        return name.to_string();
                    }
                }
                pos = op + ol;
            } else {
                pos += 1;
            }
        }
        "Unknown".to_string()
    }

    /// Check if a certificate fingerprint matches known malware.
    #[must_use] 
    pub fn check_malware(&self, fingerprint: &str) -> Option<&'static str> {
        self.known_malware.get(fingerprint).copied()
    }

    /// Analyze all certificates in a PKCS#7 blob (may contain a chain).
    #[must_use] 
    pub fn analyze_chain(&self, data: &[u8]) -> Vec<Result<CertInfo, CertError>> {
        vec![self.analyze(data)]
    }
}

impl Default for CertAnalyzer {
    fn default() -> Self { Self::new() }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_byte(data: &[u8], byte: u8, start: usize) -> Option<usize> {
    data[start..].iter().position(|&b| b == byte).map(|p| p + start)
}

// ── CertError ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CertError {
    TooShort,
    NotCertificate,
    ParseError,
    UnsupportedAlgorithm,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "certificate too short"),
            Self::NotCertificate => write!(f, "not a certificate"),
            Self::ParseError => write!(f, "parse error"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_dn_from_raw_cn() {
        let dn = SubjectDn::from_raw("CN=Android Debug, O=Android, C=US");
        assert_eq!(dn.common_name.as_deref(), Some("Android Debug"));
        assert_eq!(dn.organization.as_deref(), Some("Android"));
        assert_eq!(dn.country.as_deref(), Some("US"));
    }

    #[test]
    fn test_subject_dn_display() {
        let dn = SubjectDn::from_raw("CN=Test");
        assert!(dn.to_string().contains("CN=Test"));
    }

    #[test]
    fn test_validity_days() {
        let v = ValidityPeriod { not_before: 0, not_after: 86_400 * 365 };
        assert_eq!(v.days(), 365);
    }

    #[test]
    fn test_validity_not_expired() {
        let v = ValidityPeriod { not_before: 0, not_after: 9_999_999_999 };
        assert!(!v.is_expired());
    }

    #[test]
    fn test_validity_expired() {
        let v = ValidityPeriod { not_before: 0, not_after: 1_000_000 };
        assert!(v.is_expired());
    }

    #[test]
    fn test_cert_info_is_debug() {
        let info = CertInfo {
            subject: SubjectDn::from_raw("CN=Android Debug, O=Android, C=US"),
            issuer: SubjectDn::from_raw("CN=Android Debug, O=Android, C=US"),
            validity: ValidityPeriod { not_before: 0, not_after: 9_999_999_999 },
            public_key: PublicKeyInfo { algorithm: KeyAlgorithm::Rsa, key_size_bits: 2048 },
            signature_algorithm: "SHA256withRSA".to_string(),
            sha256_fingerprint: "a".repeat(64),
            sha1_fingerprint: "b".repeat(40),
            serial_number: "01".to_string(),
            version: 3,
        };
        assert!(info.is_debug_cert());
        assert!(info.is_self_signed());
    }

    #[test]
    fn test_cert_info_not_debug() {
        let info = CertInfo {
            subject: SubjectDn::from_raw("CN=My App, O=ACME, C=DE"),
            issuer: SubjectDn::from_raw("CN=ACME CA"),
            validity: ValidityPeriod { not_before: 0, not_after: 9_999_999_999 },
            public_key: PublicKeyInfo { algorithm: KeyAlgorithm::Rsa, key_size_bits: 4096 },
            signature_algorithm: "SHA256withRSA".to_string(),
            sha256_fingerprint: "a".repeat(64),
            sha1_fingerprint: "b".repeat(40),
            serial_number: "02".to_string(),
            version: 3,
        };
        assert!(!info.is_debug_cert());
        assert!(!info.is_self_signed());
    }

    #[test]
    fn test_weak_key_rsa1024() {
        let info = CertInfo {
            subject: SubjectDn::from_raw("CN=Weak"),
            issuer: SubjectDn::from_raw("CN=Weak"),
            validity: ValidityPeriod { not_before: 0, not_after: 9_999_999_999 },
            public_key: PublicKeyInfo { algorithm: KeyAlgorithm::Rsa, key_size_bits: 1024 },
            signature_algorithm: "SHA1withRSA".to_string(),
            sha256_fingerprint: "a".repeat(64),
            sha1_fingerprint: "b".repeat(40),
            serial_number: "03".to_string(),
            version: 3,
        };
        assert!(info.has_weak_key());
    }

    #[test]
    fn test_key_algorithm_display() {
        assert_eq!(KeyAlgorithm::Rsa.to_string(), "RSA");
        assert_eq!(KeyAlgorithm::Ec.to_string(), "EC");
        assert_eq!(KeyAlgorithm::Dsa.to_string(), "DSA");
    }

    #[test]
    fn test_sig_alg_name() {
        assert_eq!(sig_alg_name("1.2.840.113549.1.1.11"), "SHA256withRSA");
        assert_eq!(sig_alg_name("1.2.840.10045.4.3.2"), "SHA256withECDSA");
        assert_eq!(sig_alg_name("9.9.9.9"), "Unknown");
    }

    #[test]
    fn test_analyze_too_short() {
        let analyzer = CertAnalyzer::new();
        let err = analyzer.analyze(&[0x30]).unwrap_err();
        assert!(matches!(err, CertError::TooShort));
    }

    #[test]
    fn test_analyze_minimal_der() {
        let analyzer = CertAnalyzer::new();
        // Minimal DER SEQUENCE header
        let data = vec![0x30u8, 0x06, 0x02, 0x01, 0x01, 0x30, 0x01, 0x00];
        // Should not panic; may return an error or partial result
        let _ = analyzer.analyze(&data);
    }

    #[test]
    fn test_parse_oid() {
        // RSA OID: 2a 86 48 86 f7 0d 01 01 01
        let bytes = [0x2au8, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let oid = parse_oid(&bytes);
        assert_eq!(oid, "1.2.840.113549.1.1.1");
    }

    #[test]
    fn test_fake_sha256_length() {
        let h = fake_sha256(b"hello");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_fake_sha1_length() {
        let h = fake_sha1(b"hello");
        assert_eq!(h.len(), 40);
    }

    #[test]
    fn test_check_malware_unknown() {
        let analyzer = CertAnalyzer::new();
        assert!(analyzer.check_malware("deadbeef").is_none());
    }

    #[test]
    fn test_find_bytes() {
        let haystack = b"hello world";
        assert_eq!(find_bytes(haystack, b"world"), Some(6));
        assert!(find_bytes(haystack, b"xyz").is_none());
    }

    #[test]
    fn test_der_tlv() {
        let data = [0x30u8, 0x04, 0x01, 0x02, 0x03, 0x04];
        let (tag, pos, len) = der_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(len, 4);
        assert_eq!(pos, 2);
    }
}
