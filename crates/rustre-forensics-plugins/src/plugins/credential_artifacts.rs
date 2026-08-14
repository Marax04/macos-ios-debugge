//! Credential extraction patterns: LSASS credential patterns, SAM hash format,
//! Kerberos ticket structure, and DPAPI blob detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid LSASS signature at offset {0}")]
    InvalidLsassSignature(usize),
    #[error("DPAPI blob too short: {0} bytes")]
    DpapiBlobTooShort(usize),
    #[error("Kerberos ticket parse error: {0}")]
    KerberosError(String),
    #[error("hash format error: {0}")]
    HashFormatError(String),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
}

// ─── NTLM hash formats ────────────────────────────────────────────────────────

/// An NTLM hash (16 bytes / 32 hex chars).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtlmHash([u8; 16]);

impl NtlmHash {
    pub const EMPTY: Self = Self([
        0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89,
        0xc0,
    ]);
    pub const EMPTY_LM: Self = Self([
        0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04,
        0xee,
    ]);

    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// Parse a GUID from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the slice is shorter than 16 bytes.
    pub fn from_slice(s: &[u8]) -> Result<Self, CredentialError> {
        if s.len() < 16 {
            return Err(CredentialError::Truncated(s.len()));
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&s[..16]);
        Ok(Self(b))
    }

 ///
 /// # Errors
 ///
 /// Returns an error if the operation fails.
    pub fn from_hex(hex: &str) -> Result<Self, CredentialError> {
        if hex.len() != 32 {
            return Err(CredentialError::HashFormatError(format!(
                "expected 32 chars, got {}",
                hex.len()
            )));
        }
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| CredentialError::HashFormatError(e.to_string()))?;
        }
        Ok(Self(b))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns `true` if this hash represents a blank password.
    /// Comparison is performed in constant time to avoid timing side-channels.
    #[must_use]
    pub fn is_blank_password(&self) -> bool {
        self.0.ct_eq(&Self::EMPTY.0).into()
    }
    /// Returns `true` if the LM hash indicates LM is disabled.
    /// Comparison is performed in constant time to avoid timing side-channels.
    #[must_use]
    pub fn is_lm_disabled(&self) -> bool {
        self.0.ct_eq(&Self::EMPTY_LM.0).into()
    }
}

// ─── SAM hash formats ─────────────────────────────────────────────────────────

/// Format of an NTDS.dit or SAM dumped hash line.
/// `username:rid:lm_hash:nt_hash:::`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsdumpLine {
    pub username: String,
    pub rid: u32,
    pub lm_hash: String,
    pub nt_hash: String,
    pub extra: Vec<String>,
}

impl SecretsdumpLine {
    /// Parse a secretsdump-format line.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            return None;
        }
        let username = parts[0].to_string();
        let rid: u32 = parts[1].parse().ok()?;
        let lm_hash = parts[2].to_string();
        let nt_hash = parts[3].to_string();
        let extra: Vec<String> = parts[4..].iter().map(ToString::to_string).collect();
        Some(Self {
            username,
            rid,
            lm_hash,
            nt_hash,
            extra,
        })
    }

    /// Returns `true` if the account has a non-blank NT hash.
    /// Comparison against the known-blank sentinel is performed in constant time
    /// to avoid timing side-channels.
    #[must_use]
    pub fn has_valid_nt_hash(&self) -> bool {
        const BLANK_NT: &[u8] = b"31d6cfe0d16ae931b73c59d7e0c089c0";
        if self.nt_hash.len() != 32 {
            return false;
        }
        // ct_eq returns 1 when equal; we want `true` when NOT equal to blank.
        let is_blank: bool = self.nt_hash.as_bytes().ct_eq(BLANK_NT).into();
        !is_blank
    }

    /// Returns `true` if LM hashes are enabled for this account.
    /// Comparison against the known-disabled sentinel is performed in constant time.
    #[must_use]
    pub fn lm_enabled(&self) -> bool {
        const DISABLED_LM: &[u8] = b"aad3b435b51404eeaad3b435b51404ee";
        if self.lm_hash.len() != 32 {
            return false;
        }
        let is_disabled: bool = self.lm_hash.as_bytes().ct_eq(DISABLED_LM).into();
        !is_disabled
    }
}

// ─── LSASS credential structures ─────────────────────────────────────────────

/// Source of a credential found in LSASS memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LsassCredentialSource {
    /// wdigest (cleartext, legacy).
    WDigest,
    /// Kerberos TGT/TGS tickets.
    Kerberos,
    /// `MSV1_0` (NTLM).
    Msv1_0,
    /// NTLM challenge/response.
    Ntlm,
    /// Credman (Windows Credential Manager).
    Credman,
    /// `LiveSSP`.
    LiveSsp,
    /// `CloudAP`.
    CloudAp,
    /// TSPKG (Terminal Server).
    TsPkg,
    Unknown(String),
}

impl LsassCredentialSource {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::WDigest => "wdigest",
            Self::Kerberos => "kerberos",
            Self::Msv1_0 => "msv1_0",
            Self::Ntlm => "ntlm",
            Self::Credman => "credman",
            Self::LiveSsp => "livessp",
            Self::CloudAp => "cloudap",
            Self::TsPkg => "tspkg",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// A credential extracted from LSASS memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsassCredential {
    pub source: LsassCredentialSource,
    pub username: String,
    pub domain: String,
    /// NT hash (if available).
    pub nt_hash: Option<NtlmHash>,
    /// LM hash (if available).
    pub lm_hash: Option<NtlmHash>,
    /// Cleartext password (if wdigest/tspkg, may be empty).
    pub cleartext: Option<String>,
    /// Kerberos ticket data (raw bytes).
    pub kerberos_ticket: Option<Vec<u8>>,
    /// Virtual address in LSASS process memory.
    pub address: u64,
    /// Session ID.
    pub session_id: u32,
    /// LUID (logon session identifier).
    pub luid: u64,
}

impl LsassCredential {
    /// Returns `true` if cleartext credentials were recovered.
    #[must_use]
    pub fn has_cleartext(&self) -> bool {
        self.cleartext.as_ref().is_some_and(|s| !s.is_empty())
    }

    /// Returns a severity score 0–3 (higher = more critical).
    #[must_use]
    pub fn severity(&self) -> u8 {
        if self.has_cleartext() {
            return 3;
        }
        if self
            .nt_hash
            .as_ref()
            .is_some_and(|h| !h.is_blank_password())
        {
            return 2;
        }
        if self.kerberos_ticket.is_some() {
            return 2;
        }
        1
    }
}

// ─── LSASS memory scanner ─────────────────────────────────────────────────────

/// Pattern scanner for LSASS credential structures in a memory dump.
pub struct LsassScanner;

impl LsassScanner {
    /// Mimikatz sekurlsa structure marker (simplified sentinel for testing).
    const WDIGEST_MARKER: &'static [u8] = b"wdigest";
    const KERBEROS_MARKER: &'static [u8] = b"kerberos";
    const NTLM_MARKER: &'static [u8] = b"NTLM";
    const MSV_MARKER: &'static [u8] = b"msv1_0";

    /// Marker bytes used to locate the Kerberos credential block in LSASS.
    #[must_use]
    pub const fn kerberos_marker() -> &'static [u8] {
        Self::KERBEROS_MARKER
    }

    /// Marker bytes used to locate the `msv1_0` credential block in LSASS.
    #[must_use]
    pub const fn msv_marker() -> &'static [u8] {
        Self::MSV_MARKER
    }

    /// Scan a memory dump for wdigest credential patterns.
    /// In real LSASS, wdigest stores credentials in a linked list of
    /// `_WDIGEST_LIST_ENTRY` structures with RC4-encrypted password blobs.
    #[must_use]
    pub fn scan_wdigest(data: &[u8]) -> Vec<LsassCredential> {
        let mut creds = Vec::new();
        let mut pos = 0usize;
        while pos + Self::WDIGEST_MARKER.len() < data.len() {
            if data[pos..].starts_with(Self::WDIGEST_MARKER) {
                // Look for adjacent username/password patterns
                let window = &data[pos..pos.min(data.len() - 1) + 256.min(data.len() - pos)];
                let username = extract_adjacent_string(window, 0, 128);
                if !username.is_empty() {
                    creds.push(LsassCredential {
                        source: LsassCredentialSource::WDigest,
                        username,
                        domain: String::new(),
                        nt_hash: None,
                        lm_hash: None,
                        cleartext: None,
                        kerberos_ticket: None,
                        address: pos as u64,
                        session_id: 0,
                        luid: 0,
                    });
                }
                pos += Self::WDIGEST_MARKER.len();
            } else {
                pos += 1;
            }
        }
        creds
    }

    /// Scan for NT hash patterns: 16-byte blocks that look like NTLM hashes.
    #[must_use]
    pub fn scan_nt_hashes(data: &[u8]) -> Vec<(u64, NtlmHash)> {
        let mut hashes = Vec::new();
        // Look for the NTLM marker followed by hash data
        let mut pos = 0usize;
        while pos + Self::NTLM_MARKER.len() + 20 <= data.len() {
            if data[pos..].starts_with(Self::NTLM_MARKER) {
                let hash_off = pos + Self::NTLM_MARKER.len() + 4;
                if hash_off + 16 <= data.len()
                    && let Ok(h) = NtlmHash::from_slice(&data[hash_off..])
                        && !h.is_blank_password() {
                            hashes.push((pos as u64, h));
                        }
                pos += Self::NTLM_MARKER.len();
            } else {
                pos += 1;
            }
        }
        hashes
    }

    /// Comprehensive LSASS scan combining all sub-scanners.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<LsassCredential> {
        let mut all = Self::scan_wdigest(data);
        let nt_hashes = Self::scan_nt_hashes(data);
        for (addr, hash) in nt_hashes {
            all.push(LsassCredential {
                source: LsassCredentialSource::Msv1_0,
                username: String::new(),
                domain: String::new(),
                nt_hash: Some(hash),
                lm_hash: None,
                cleartext: None,
                kerberos_ticket: None,
                address: addr,
                session_id: 0,
                luid: 0,
            });
        }
        all
    }
}

fn extract_adjacent_string(data: &[u8], start: usize, max_len: usize) -> String {
    let mut run = Vec::new();
    for &b in &data[start..start + max_len.min(data.len() - start)] {
        if b.is_ascii_graphic() || b == b' ' {
            run.push(b);
        } else if !run.is_empty() {
            break;
        }
    }
    String::from_utf8_lossy(&run).to_string()
}

// ─── Kerberos ticket structures ───────────────────────────────────────────────

/// Kerberos ticket type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KerberosTicketType {
    Tgt, // Ticket-Granting Ticket
    Tgs, // Ticket-Granting Service ticket
    St,  // Service ticket
}

impl KerberosTicketType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Tgt => "TGT",
            Self::Tgs => "TGS",
            Self::St => "ST",
        }
    }
}

/// An extracted Kerberos ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicket {
    pub ticket_type: KerberosTicketType,
    pub service_name: String,
    pub client_name: String,
    pub realm: String,
    pub start_time: i64,
    pub end_time: i64,
    pub renew_until: i64,
    pub encryption_type: KerberosEncryptionType,
    pub flags: KerberosTicketFlags,
    pub raw_ticket: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Kerberos encryption types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KerberosEncryptionType {
    DesCbcMd5 = 3,
    DesCbcCrc = 1,
    Rc4Hmac = 23,
    Aes128CtsHmacSha1 = 17,
    Aes256CtsHmacSha1 = 18,
    Unknown,
}

impl KerberosEncryptionType {
    #[must_use]
    pub const fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::DesCbcCrc,
            3 => Self::DesCbcMd5,
            17 => Self::Aes128CtsHmacSha1,
            18 => Self::Aes256CtsHmacSha1,
            23 => Self::Rc4Hmac,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::DesCbcCrc => "des-cbc-crc",
            Self::DesCbcMd5 => "des-cbc-md5",
            Self::Rc4Hmac => "rc4-hmac",
            Self::Aes128CtsHmacSha1 => "aes128-cts-hmac-sha1-96",
            Self::Aes256CtsHmacSha1 => "aes256-cts-hmac-sha1-96",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` if this encryption type is considered weak.
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        matches!(self, Self::DesCbcCrc | Self::DesCbcMd5 | Self::Rc4Hmac)
    }
}

/// Kerberos ticket flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicketFlags {
    pub forwardable: bool,
    pub forwarded: bool,
    pub proxiable: bool,
    pub pre_authent: bool,
    pub renewable: bool,
    pub initial: bool,
    pub ok_as_delegate: bool,
}

impl KerberosTicketFlags {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        Self {
            forwardable: v & 0x4000_0000 != 0,
            forwarded: v & 0x2000_0000 != 0,
            proxiable: v & 0x1000_0000 != 0,
            pre_authent: v & 0x0020_0000 != 0,
            renewable: v & 0x0080_0000 != 0,
            initial: v & 0x0040_0000 != 0,
            ok_as_delegate: v & 0x0010_0000 != 0,
        }
    }
}

/// Scanner for Kerberos ticket data in memory.
pub struct KerberosTicketScanner;

impl KerberosTicketScanner {
    /// ASN.1 application tag for a `KRB_AP_REQ` (ticket in flight): 0x6E.
    const AP_REQ_TAG: u8 = 0x6E;
    /// ASN.1 application tag for a `KRB_TGS_REQ`: 0x6C.
    const TGS_REQ_TAG: u8 = 0x6C;
    /// ASN.1 SEQUENCE tag.
    const SEQUENCE_TAG: u8 = 0x30;

    /// ASN.1 SEQUENCE tag exposed for callers walking raw ticket bodies.
    #[must_use]
    pub const fn sequence_tag() -> u8 {
        Self::SEQUENCE_TAG
    }

    /// Scan for Kerberos ticket ASN.1 structures in raw bytes.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<KerberosTicket> {
        let mut tickets = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            if data[pos] == Self::AP_REQ_TAG || data[pos] == Self::TGS_REQ_TAG {
                let ticket_type = if data[pos] == Self::AP_REQ_TAG {
                    KerberosTicketType::Tgs
                } else {
                    KerberosTicketType::Tgt
                };
                // Read the BER/DER length
                if let Some((len, hdr_bytes)) = ber_length(&data[pos + 1..]) {
                    let total = 1 + hdr_bytes + len;
                    let end = (pos + total).min(data.len());
                    let raw = data[pos..end].to_vec();
                    // Extract realm/service name from adjacent strings
                    let (realm, svc, client) = extract_principal_names(&raw);
                    tickets.push(KerberosTicket {
                        ticket_type,
                        service_name: svc,
                        client_name: client,
                        realm,
                        start_time: 0,
                        end_time: 0,
                        renew_until: 0,
                        encryption_type: KerberosEncryptionType::Unknown,
                        flags: KerberosTicketFlags::from_u32(0),
                        raw_ticket: raw,
                        session_key: vec![],
                    });
                    pos += total;
                    continue;
                }
            }
            pos += 1;
        }
        tickets
    }
}

fn ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else {
        let n = (data[0] & 0x7F) as usize;
        if n > 4 || data.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + n))
    }
}

fn extract_principal_names(data: &[u8]) -> (String, String, String) {
    // Heuristic: find ASCII strings that look like realm/service names
    let mut strings = Vec::new();
    let mut run = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() && b != b'\x00' {
            run.push(b);
        } else {
            if run.len() >= 3 {
                strings.push(String::from_utf8_lossy(&run).to_string());
            }
            run.clear();
        }
    }
    let realm = strings
        .iter()
        .find(|s| s.contains('.') && s.to_uppercase() == *(*s))
        .cloned()
        .unwrap_or_default();
    let svc = strings
        .iter()
        .find(|s| s.starts_with("host/") || s.starts_with("krbtgt") || s.contains('/'))
        .cloned()
        .unwrap_or_default();
    let client = strings
        .iter()
        .find(|s| !s.is_empty() && *s != &realm && *s != &svc)
        .cloned()
        .unwrap_or_default();
    (realm, svc, client)
}

// ─── DPAPI blob detection ─────────────────────────────────────────────────────

/// DPAPI blob version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpapiVersion {
    V1,
    V2,
    Unknown(u32),
}

impl DpapiVersion {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::V1,
            2 => Self::V2,
            n => Self::Unknown(n),
        }
    }
}

/// A DPAPI blob descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiBlob {
    pub version: DpapiVersion,
    /// Provider GUID.
    pub provider_guid: [u8; 16],
    /// Master key GUID — identifies which master key to use for decryption.
    pub mk_guid: [u8; 16],
    /// Salt bytes for the decryption KDF.
    pub salt: Vec<u8>,
    /// HMAC / signature bytes.
    pub hmac: Vec<u8>,
    /// Encrypted data.
    pub cipher_text: Vec<u8>,
    /// Encryption algorithm OID.
    pub cipher_alg_id: u32,
    /// HMAC algorithm OID.
    pub hmac_alg_id: u32,
    /// Description string (optional).
    pub description: String,
    /// Address in memory.
    pub address: u64,
}

impl DpapiBlob {
    /// DPAPI blob header magic: version=1 + `CRYPTPROTECT_DEFAULT_PROVIDER` GUID.
    pub const DPAPI_MAGIC: &'static [u8; 4] = &[0x01, 0x00, 0x00, 0x00];
    pub const PROVIDER_GUID: [u8; 16] = [
        0xdf, 0x9d, 0x8a, 0x08, 0xbf, 0xbb, 0xd0, 0x11, 0x8c, 0x7d, 0x00, 0xaa, 0x00, 0x3c, 0x29,
        0x05,
    ];

    /// Returns `true` if the blob is protected with the default provider.
    #[must_use]
    pub fn is_default_provider(&self) -> bool {
        self.provider_guid == Self::PROVIDER_GUID
    }

    /// Returns `true` if this blob is likely a Chrome/Edge encrypted cookie or password.
    #[must_use]
    pub fn is_browser_credential(&self) -> bool {
        // Chrome v80+ uses AES-GCM via DPAPI with a specific description
        self.description.to_lowercase().contains("chrome")
            || self.description.to_lowercase().contains("edge")
            || self.cipher_text.starts_with(b"v10")
            || self.cipher_text.starts_with(b"v11")
    }
}

/// Scanner for DPAPI blobs in memory dumps.
pub struct DpapiScanner;

impl DpapiScanner {
    /// Scan `data` for DPAPI blobs and return them.
    ///
    /// # Panics
    ///
    /// Panics if internal byte-array conversion fails (indicates data corruption).
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<DpapiBlob> {
        let mut blobs = Vec::new();
        let mut pos = 0usize;
        while pos + 36 <= data.len() {
            // DPAPI header: DWORD version + GUID (16 bytes) + GUID (16 bytes) ...
            if &data[pos..pos + 4] == DpapiBlob::DPAPI_MAGIC {
                if pos + 36 <= data.len() {
                    let version = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let mut provider = [0u8; 16];
                    provider.copy_from_slice(&data[pos + 4..pos + 20]);
                    let mut mk = [0u8; 16];
                    mk.copy_from_slice(&data[pos + 20..pos + 36]);
                    // Salt follows after an optional description
                    let desc_start = pos + 36;
                    let desc = extract_adjacent_string(data, desc_start, 64);
                    // Salt length at offset 36 + desc_len + 2 (simplified)
                    let cipher_start = (pos + 36 + desc.len()).min(data.len());
                    let cipher_end = cipher_start + 256.min(data.len() - cipher_start);
                    blobs.push(DpapiBlob {
                        version: DpapiVersion::from_u32(version),
                        provider_guid: provider,
                        mk_guid: mk,
                        salt: vec![],
                        hmac: vec![],
                        cipher_text: data[cipher_start..cipher_end].to_vec(),
                        cipher_alg_id: 0,
                        hmac_alg_id: 0,
                        description: desc,
                        address: pos as u64,
                    });
                    pos += 36;
                } else {
                    pos += 4;
                }
            } else {
                pos += 4;
            }
        }
        blobs
    }

    /// Find master key GUIDs in DPAPI master key files.
    /// Master key files are stored under:
    /// `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`
    #[must_use]
    pub fn find_masterkey_guids(data: &[u8]) -> Vec<String> {
        let mut guids = Vec::new();
        let mut pos = 0usize;
        while pos + 36 <= data.len() {
            // GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
            let slice = &data[pos..pos + 36];
            if slice[8] == b'-'
                && slice[13] == b'-'
                && slice[18] == b'-'
                && slice[23] == b'-'
                && slice[..8].iter().all(u8::is_ascii_hexdigit)
                && slice[9..13].iter().all(u8::is_ascii_hexdigit)
                && slice[14..18].iter().all(u8::is_ascii_hexdigit)
                && slice[19..23].iter().all(u8::is_ascii_hexdigit)
                && slice[24..36].iter().all(u8::is_ascii_hexdigit)
            {
                if let Ok(s) = std::str::from_utf8(slice) {
                    guids.push(s.to_string());
                }
                pos += 36;
            } else {
                pos += 1;
            }
        }
        guids.sort();
        guids.dedup();
        guids
    }
}

// ─── Credential summary ───────────────────────────────────────────────────────

/// Summary of all credentials found in an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub lsass_credentials: Vec<LsassCredential>,
    pub kerberos_tickets: Vec<KerberosTicket>,
    pub dpapi_blobs: Vec<DpapiBlob>,
    pub hash_lines: Vec<SecretsdumpLine>,
}

impl CredentialSummary {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lsass_credentials: Vec::new(),
            kerberos_tickets: Vec::new(),
            dpapi_blobs: Vec::new(),
            hash_lines: Vec::new(),
        }
    }

    /// Total number of distinct credentials found.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.lsass_credentials.len() + self.kerberos_tickets.len() + self.dpapi_blobs.len()
    }

    /// Return all credentials with cleartext passwords.
    #[must_use]
    pub fn cleartext_creds(&self) -> Vec<&LsassCredential> {
        self.lsass_credentials
            .iter()
            .filter(|c| c.has_cleartext())
            .collect()
    }

    /// Build a summary row map for plugin output.
    #[must_use]
    pub fn to_row_map(&self) -> HashMap<String, String> {
        let mut m = HashMap::with_capacity(5);
        m.insert(
            "lsass_cred_count".into(),
            self.lsass_credentials.len().to_string(),
        );
        m.insert(
            "kerberos_ticket_count".into(),
            self.kerberos_tickets.len().to_string(),
        );
        m.insert(
            "dpapi_blob_count".into(),
            self.dpapi_blobs.len().to_string(),
        );
        m.insert(
            "cleartext_count".into(),
            self.cleartext_creds().len().to_string(),
        );
        m.insert("hash_line_count".into(), self.hash_lines.len().to_string());
        m
    }

    /// Scan a raw byte slice and populate all credential fields.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut s = Self::new();
        s.lsass_credentials = LsassScanner::scan(data);
        s.kerberos_tickets = KerberosTicketScanner::scan(data);
        s.dpapi_blobs = DpapiScanner::scan(data);
        s
    }
}

impl Default for CredentialSummary {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlm_hash_empty() {
        let h = NtlmHash::EMPTY;
        assert!(h.is_blank_password());
        assert!(!h.is_lm_disabled());
        assert_eq!(h.to_hex(), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn ntlm_hash_lm_disabled() {
        let h = NtlmHash::EMPTY_LM;
        assert!(h.is_lm_disabled());
    }

    #[test]
    fn ntlm_hash_from_hex() {
        let h = NtlmHash::from_hex("31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        assert!(h.is_blank_password());
    }

    #[test]
    fn ntlm_hash_from_hex_invalid() {
        assert!(NtlmHash::from_hex("tooshort").is_err());
        assert!(NtlmHash::from_hex("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }

    #[test]
    fn secretsdump_line_parse() {
        let line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
        let parsed = SecretsdumpLine::parse(line).unwrap();
        assert_eq!(parsed.username, "Administrator");
        assert_eq!(parsed.rid, 500);
        assert!(!parsed.has_valid_nt_hash()); // blank NT hash
        assert!(!parsed.lm_enabled()); // LM disabled
    }

    #[test]
    fn secretsdump_line_with_hash() {
        let line =
            "alice:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::";
        let parsed = SecretsdumpLine::parse(line).unwrap();
        assert_eq!(parsed.username, "alice");
        assert!(parsed.has_valid_nt_hash());
    }

    #[test]
    fn secretsdump_line_parse_invalid() {
        assert!(SecretsdumpLine::parse("notenoughfields").is_none());
    }

    #[test]
    fn kerberos_encryption_type() {
        assert_eq!(
            KerberosEncryptionType::from_i32(23),
            KerberosEncryptionType::Rc4Hmac
        );
        assert_eq!(
            KerberosEncryptionType::from_i32(18),
            KerberosEncryptionType::Aes256CtsHmacSha1
        );
        assert!(KerberosEncryptionType::Rc4Hmac.is_weak());
        assert!(!KerberosEncryptionType::Aes256CtsHmacSha1.is_weak());
    }

    #[test]
    fn kerberos_ticket_flags() {
        let f = KerberosTicketFlags::from_u32(0x4000_0000 | 0x0080_0000);
        assert!(f.forwardable);
        assert!(f.renewable);
        assert!(!f.forwarded);
    }

    #[test]
    fn kerberos_scanner_empty() {
        let data = vec![0u8; 256];
        let tickets = KerberosTicketScanner::scan(&data);
        assert!(tickets.is_empty());
    }

    #[test]
    fn dpapi_scanner_finds_blob() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(DpapiBlob::DPAPI_MAGIC);
        data[4..20].copy_from_slice(&DpapiBlob::PROVIDER_GUID);
        // mk_guid at 20..36 (zeroed)
        let blobs = DpapiScanner::scan(&data);
        assert!(!blobs.is_empty());
        assert!(blobs[0].is_default_provider());
    }

    #[test]
    fn dpapi_guid_extraction() {
        let _data = b"some garbage {550e8400-e29b-41d4-a716-446655440000} more garbage";
        // Won't find a raw GUID without braces; test with raw format
        let raw = b"550e8400-e29b-41d4-a716-446655440000 done";
        let guids = DpapiScanner::find_masterkey_guids(raw);
        assert_eq!(guids.len(), 1);
        assert_eq!(guids[0], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn lsass_scanner_empty() {
        let data = vec![0u8; 512];
        let creds = LsassScanner::scan(&data);
        assert!(creds.is_empty());
    }

    #[test]
    fn credential_summary_from_bytes_empty() {
        let summary = CredentialSummary::from_bytes(&[0u8; 512]);
        assert_eq!(summary.total_count(), 0);
    }

    #[test]
    fn credential_summary_row_map() {
        let s = CredentialSummary::default();
        let row = s.to_row_map();
        assert!(row.contains_key("lsass_cred_count"));
        assert!(row.contains_key("kerberos_ticket_count"));
    }

    #[test]
    fn lsass_credential_severity() {
        let c = LsassCredential {
            source: LsassCredentialSource::WDigest,
            username: "admin".into(),
            domain: "corp".into(),
            nt_hash: None,
            lm_hash: None,
            cleartext: Some("Password123!".into()),
            kerberos_ticket: None,
            address: 0,
            session_id: 1,
            luid: 0x3e7,
        };
        assert_eq!(c.severity(), 3);
        assert!(c.has_cleartext());
    }

    #[test]
    fn dpapi_version_from_u32() {
        assert_eq!(DpapiVersion::from_u32(1), DpapiVersion::V1);
        assert_eq!(DpapiVersion::from_u32(2), DpapiVersion::V2);
        assert_eq!(DpapiVersion::from_u32(99), DpapiVersion::Unknown(99));
    }
}
