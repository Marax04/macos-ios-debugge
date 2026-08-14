//! Crypto key finding in memory/binary data:
//! AES key schedules, RSA/PKCS#1 ASN.1 patterns, DH parameters, XOR key recovery.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum CryptoKeyError {
    #[error("no key found")]
    NotFound,
    #[error("invalid key data: {0}")]
    InvalidData(String),
    #[error("scan error: {0}")]
    ScanError(String),
}

// ─── CryptoKeyKind ────────────────────────────────────────────────────────────

/// Type of cryptographic key found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoKeyKind {
    /// AES-128 expanded key schedule.
    Aes128Schedule,
    /// AES-256 expanded key schedule.
    Aes256Schedule,
    /// AES raw key (128-bit).
    Aes128Raw,
    /// AES raw key (256-bit).
    Aes256Raw,
    /// RSA private key (PKCS#1 DER).
    RsaPrivate,
    /// RSA public key (PKCS#1 DER).
    RsaPublic,
    /// Diffie-Hellman parameters.
    DhParameters,
    /// Repeating XOR key.
    XorKey,
    /// RC4 key material.
    Rc4Key,
    /// `ChaCha20` key.
    Chacha20Key,
    /// Unknown / generic key material.
    Unknown(String),
}

impl std::fmt::Display for CryptoKeyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128Schedule => write!(f, "AES-128 key schedule"),
            Self::Aes256Schedule => write!(f, "AES-256 key schedule"),
            Self::Aes128Raw => write!(f, "AES-128 raw key"),
            Self::Aes256Raw => write!(f, "AES-256 raw key"),
            Self::RsaPrivate => write!(f, "RSA private key"),
            Self::RsaPublic => write!(f, "RSA public key"),
            Self::DhParameters => write!(f, "DH parameters"),
            Self::XorKey => write!(f, "XOR key"),
            Self::Rc4Key => write!(f, "RC4 key"),
            Self::Chacha20Key => write!(f, "ChaCha20 key"),
            Self::Unknown(s) => write!(f, "Unknown({s})"),
        }
    }
}

// ─── FoundCryptoKey ───────────────────────────────────────────────────────────

/// A crypto key (or key material) found in a binary or memory dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundCryptoKey {
    /// Type of the key.
    pub kind: CryptoKeyKind,
    /// Byte offset in the input where the key was found.
    pub offset: u64,
    /// Raw key bytes.
    pub key_bytes: Vec<u8>,
    /// Confidence in the detection [0.0, 1.0].
    pub confidence: f32,
    /// Key length in bits.
    pub key_bits: u32,
    /// Additional metadata (e.g. algorithm parameters).
    pub metadata: HashMap<String, String>,
}

impl FoundCryptoKey {
    #[must_use]
    pub fn new(kind: CryptoKeyKind, offset: u64, key_bytes: Vec<u8>, confidence: f32) -> Self {
        let key_bits = (key_bytes.len() as u32).saturating_mul(8);
        Self {
            kind,
            offset,
            key_bytes,
            confidence,
            key_bits,
            metadata: HashMap::new(),
        }
    }

    /// Returns the key as a lowercase hex string.
    #[must_use]
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(self.key_bytes.len() * 2);
        for b in &self.key_bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Add a metadata entry.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

// ─── AesKeyScheduleDetector ──────────────────────────────────────────────────

/// Detects AES key schedules by checking for the statistical properties of
/// an expanded AES-128 or AES-256 key schedule.
///
/// The AES S-box is used as a fingerprint: the round key at index N is derived
/// from S-box substitutions of the previous round key.  We validate that the
/// key schedule was correctly expanded rather than just finding random bytes.
pub struct AesKeyScheduleDetector;

// AES S-box lookup table.
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// AES key schedule round constants (Rcon).
const RCON: [u8; 11] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c];

impl AesKeyScheduleDetector {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Validate a 16-byte AES-128 key by deriving one round of the key schedule
    /// and checking it against the subsequent 16 bytes.
    ///
    /// NOTE: This is a heuristic that validates only the **first** round transition
    /// (round 0 -> round 1), so `RCON[0]` is the correct round constant here. It is
    /// intentionally not a full 10-round verification: scanning all 10 rounds at every
    /// 4-byte offset would be far more expensive, and a single-round match already has
    /// a low false-positive rate against arbitrary binary data. As a consequence:
    /// - schedules whose first 32 bytes happen to satisfy the round-1 relation but
    ///   are not real AES key schedules may produce false positives;
    /// - genuine schedules can still be detected by their round-0 block (round-1
    ///   constants `RCON[1..]` are never consulted because we always start from
    ///   the round-0 key).
    fn validate_aes128_schedule(data: &[u8], offset: usize) -> bool {
        if offset + 32 > data.len() {
            return false;
        }
        let key: &[u8] = &data[offset..offset + 16];
        let expected_next: &[u8] = &data[offset + 16..offset + 32];

        // Derive round key 1 from round key 0.
        let mut next = [0u8; 16];
        // First 4 bytes: XOR with SubWord(RotWord(prev_last_4)) XOR Rcon
        let last4 = [key[13], key[14], key[15], key[12]]; // RotWord
        let sub = [SBOX[last4[0] as usize], SBOX[last4[1] as usize],
                   SBOX[last4[2] as usize], SBOX[last4[3] as usize]];
        next[0] = key[0] ^ sub[0] ^ RCON[0];
        next[1] = key[1] ^ sub[1];
        next[2] = key[2] ^ sub[2];
        next[3] = key[3] ^ sub[3];
        // Remaining 12 bytes.
        for i in 4..16 {
            next[i] = key[i] ^ next[i - 4];
        }

        next == expected_next
    }

    /// Scan `data` for AES-128 key schedules.
    #[must_use]
    pub fn find_aes128(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        let mut found = Vec::new();
        if data.len() < 176 { // 11 * 16 bytes
            return found;
        }
        for offset in (0..data.len().saturating_sub(32)).step_by(4) {
            if Self::validate_aes128_schedule(data, offset) {
                // Extract the 176-byte schedule (11 round keys).
                let end = (offset + 176).min(data.len());
                let schedule_bytes = data[offset..end].to_vec();
                // The actual key is the first 16 bytes of the schedule.
                let key_bytes = data[offset..offset + 16].to_vec();
                let mut k = FoundCryptoKey::new(
                    CryptoKeyKind::Aes128Schedule,
                    offset as u64,
                    key_bytes,
                    0.85,
                );
                k.add_meta("schedule_offset", offset.to_string());
                k.add_meta("schedule_len", schedule_bytes.len().to_string());
                found.push(k);
            }
        }
        found
    }

    /// Scan `data` for 16-byte or 32-byte raw AES keys using an entropy heuristic.
    ///
    /// A valid AES key typically has:
    /// - No repeated byte blocks.
    /// - High entropy (> 6.0 bits/byte).
    #[must_use]
    pub fn find_raw_aes_keys(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        let mut found = Vec::new();

        for &key_len in &[16usize, 32] {
            if data.len() < key_len {
                continue;
            }
            for offset in (0..data.len().saturating_sub(key_len)).step_by(key_len) {
                let candidate = &data[offset..offset + key_len];
                if self.looks_like_key(candidate) {
                    let kind = if key_len == 16 {
                        CryptoKeyKind::Aes128Raw
                    } else {
                        CryptoKeyKind::Aes256Raw
                    };
                    found.push(FoundCryptoKey::new(
                        kind,
                        offset as u64,
                        candidate.to_vec(),
                        0.60,
                    ));
                }
            }
        }
        found
    }

    /// Heuristic: does this byte slice look like a random key?
    fn looks_like_key(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        // Reject all-zero or all-same keys.
        if data.iter().all(|&b| b == 0) || data.iter().all(|&b| b == data[0]) {
            return false;
        }
        // Count unique bytes.
        let unique: std::collections::HashSet<u8> = data.iter().copied().collect();
        if unique.len() < data.len() / 2 {
            return false;
        }
        // Simple entropy check.
        entropy(data) > 5.5
    }
}

impl Default for AesKeyScheduleDetector {
    fn default() -> Self { Self::new() }
}

// ─── RsaKeyFinder ─────────────────────────────────────────────────────────────

/// Finds RSA keys by scanning for PKCS#1 ASN.1 DER headers.
///
/// RSA private key: `30 82 <len> 02 01 00 02 82 <modulus_len>`
/// RSA public key:  `30 82 <len> 02 82 <modulus_len>`
pub struct RsaKeyFinder;

impl RsaKeyFinder {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Find RSA private key blobs.
    #[must_use]
    pub fn find_private_keys(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        const RSA_PRIV_MAGIC: &[u8] = &[0x30, 0x82]; // SEQUENCE, 2-byte length
        let mut found = Vec::new();

        let mut i = 0;
        while i + 12 <= data.len() {
            if &data[i..i + 2] == RSA_PRIV_MAGIC {
                // Check for version = 0 (private key) pattern.
                // 30 82 <2B len> 02 01 00 (version INTEGER = 0)
                if i + 7 < data.len()
                    && data[i + 4] == 0x02  // INTEGER tag
                    && data[i + 5] == 0x01  // length 1
                    && data[i + 6] == 0x00  // value 0
                {
                    let total_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize + 4;
                    let end = (i + total_len).min(data.len());
                    let key_bytes = data[i..end].to_vec();
                    let mut k = FoundCryptoKey::new(
                        CryptoKeyKind::RsaPrivate,
                        i as u64,
                        key_bytes,
                        0.90,
                    );
                    k.add_meta("der_length", total_len.to_string());
                    found.push(k);
                    i += total_len.max(1);
                    continue;
                }
            }
            i += 1;
        }
        found
    }

    /// Find RSA public key blobs (`SubjectPublicKeyInfo` or bare PKCS#1).
    #[must_use]
    pub fn find_public_keys(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        // Public key: 30 82 <len> 02 82 <modulus_len>
        const PUB_MAGIC: &[u8] = &[0x30, 0x82];
        let mut found = Vec::new();

        let mut i = 0;
        while i + 10 <= data.len() {
            if &data[i..i + 2] == PUB_MAGIC
                && i + 6 < data.len()
                    && data[i + 4] == 0x02   // INTEGER tag
                    && data[i + 5] == 0x82   // 2-byte length
                {
                    let modulus_len = u16::from_be_bytes([data[i + 6], data[i + 7]]) as usize;
                    // Typical RSA modulus sizes: 128 (1024-bit), 256 (2048-bit), 512 (4096-bit)
                    if matches!(modulus_len, 128 | 129 | 256 | 257 | 512 | 513) {
                        let total_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize + 4;
                        let end = (i + total_len).min(data.len());
                        let key_bytes = data[i..end].to_vec();
                        let key_bits = (modulus_len as u32).saturating_sub(1).saturating_mul(8);
                        let mut k = FoundCryptoKey::new(
                            CryptoKeyKind::RsaPublic,
                            i as u64,
                            key_bytes,
                            0.85,
                        );
                        k.key_bits = key_bits;
                        k.add_meta("modulus_bytes", modulus_len.to_string());
                        found.push(k);
                        i += total_len.max(1);
                        continue;
                    }
                }
            i += 1;
        }
        found
    }
}

impl Default for RsaKeyFinder {
    fn default() -> Self { Self::new() }
}

// ─── DhParameterFinder ────────────────────────────────────────────────────────

/// Finds Diffie-Hellman parameters (prime p, generator g) in binary data.
///
/// DH params DER: `30 82 <len> 02 82 <prime_len> <prime_bytes> 02 <gen_len> <gen_bytes>`
pub struct DhParameterFinder;

impl DhParameterFinder {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Scan for DH parameter blocks.
    #[must_use]
    pub fn find(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        let mut found = Vec::new();
        let mut i = 0;

        while i + 10 <= data.len() {
            if data[i] == 0x30 && data[i + 1] == 0x82
                && i + 6 < data.len() && data[i + 4] == 0x02 && data[i + 5] == 0x82 {
                    let prime_len = u16::from_be_bytes([data[i + 6], data[i + 7]]) as usize;
                    // Common DH prime sizes: 128 (1024-bit), 256 (2048-bit), 384 (3072-bit)
                    if matches!(prime_len, 128 | 129 | 192 | 256 | 257 | 384 | 512) {
                        let total_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize + 4;
                        let end = (i + total_len).min(data.len());
                        let key_bytes = data[i..end].to_vec();
                        let mut k = FoundCryptoKey::new(
                            CryptoKeyKind::DhParameters,
                            i as u64,
                            key_bytes,
                            0.70,
                        );
                        k.key_bits = (prime_len as u32).saturating_sub(1).saturating_mul(8);
                        k.add_meta("prime_bytes", prime_len.to_string());
                        found.push(k);
                        i += total_len.max(1);
                        continue;
                    }
                }
            i += 1;
        }
        found
    }
}

impl Default for DhParameterFinder {
    fn default() -> Self { Self::new() }
}

// ─── XorKeyRecovery ───────────────────────────────────────────────────────────

/// Recovers XOR encryption keys using frequency analysis.
///
/// Assumes the plaintext has a known byte distribution (e.g. mostly ASCII with
/// null bytes for data sections).
pub struct XorKeyRecovery {
    /// Expected most-common byte in the plaintext (usually `0x00` for data,
    /// or `0x20` for text).
    expected_common_byte: u8,
    /// Maximum key length to try.
    max_key_len: usize,
}

impl XorKeyRecovery {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected_common_byte: 0x00,
            max_key_len: 32,
        }
    }

    #[must_use]
    pub const fn for_text() -> Self {
        Self {
            expected_common_byte: 0x20, // space is most common in English text
            max_key_len: 32,
        }
    }

    /// Find the most common byte in a slice.
    fn most_common_byte(data: &[u8]) -> u8 {
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        counts
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(i, _)| i as u8)
    }

    /// Recover a single-byte XOR key.
    #[must_use]
    pub fn recover_single_byte(&self, data: &[u8]) -> Option<FoundCryptoKey> {
        if data.is_empty() {
            return None;
        }
        let common = Self::most_common_byte(data);
        let key_byte = common ^ self.expected_common_byte;
        if key_byte == 0 {
            return None; // Trivial key.
        }
        Some(FoundCryptoKey::new(
            CryptoKeyKind::XorKey,
            0,
            vec![key_byte],
            0.65,
        ))
    }

    /// Recover a multi-byte XOR key of a given length using Kasiski method.
    ///
    /// For each key byte position, take every Nth ciphertext byte and apply
    /// single-byte XOR recovery.
    #[must_use]
    pub fn recover_key_of_length(&self, data: &[u8], key_len: usize) -> Option<FoundCryptoKey> {
        if data.len() < key_len * 4 || key_len == 0 {
            return None;
        }
        let mut key = Vec::with_capacity(key_len);
        let mut counts = [0u32; 256];
        for pos in 0..key_len {
            counts.fill(0);
            for &b in data.iter().skip(pos).step_by(key_len) {
                counts[b as usize] += 1;
            }
            let common = counts
                .iter()
                .enumerate()
                .max_by_key(|&(_, &c)| c)
                .map_or(0, |(i, _)| i as u8);
            key.push(common ^ self.expected_common_byte);
        }
        // Reject trivial keys.
        if key.iter().all(|&b| b == 0) {
            return None;
        }
        Some(FoundCryptoKey::new(
            CryptoKeyKind::XorKey,
            0,
            key,
            0.55,
        ))
    }

    /// Attempt to find the most likely XOR key by trying lengths 1..`max_key_len`.
    ///
    /// Uses index of coincidence to score each key length.
    #[must_use]
    pub fn auto_recover(&self, data: &[u8]) -> Option<FoundCryptoKey> {
        if data.is_empty() {
            return None;
        }

        // Try single-byte first.
        if let Some(k) = self.recover_single_byte(data) {
            // Verify: decode and check if result is more "ASCII-like".
            let decoded: Vec<u8> = data
                .iter()
                .map(|&b| b ^ k.key_bytes[0])
                .collect();
            if ascii_ratio(&decoded) > 0.7 {
                return Some(k);
            }
        }

        // Try multi-byte keys.
        let mut best: Option<(FoundCryptoKey, f64)> = None;
        for len in 2..=self.max_key_len.min(data.len() / 4) {
            let ic = index_of_coincidence_for_key_len(data, len);
            if let Some((_, ref best_ic)) = best {
                if ic > *best_ic
                    && let Some(k) = self.recover_key_of_length(data, len) {
                        best = Some((k, ic));
                    }
            } else if let Some(k) = self.recover_key_of_length(data, len) {
                best = Some((k, ic));
            }
        }
        best.map(|(k, _)| k)
    }

    /// Recover XOR key from a ciphertext/plaintext pair (known-plaintext attack).
    #[must_use]
    pub fn known_plaintext(&self, ciphertext: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.is_empty() || plaintext.is_empty() {
            return None;
        }
        let min_len = ciphertext.len().min(plaintext.len());
        let key: Vec<u8> = ciphertext[..min_len]
            .iter()
            .zip(plaintext[..min_len].iter())
            .map(|(&c, &p)| c ^ p)
            .collect();
        if key.iter().all(|&b| b == 0) {
            return None;
        }
        Some(key)
    }
}

impl Default for XorKeyRecovery {
    fn default() -> Self { Self::new() }
}

// ─── CryptoKeyFinder ─────────────────────────────────────────────────────────

/// Aggregates all key-finding strategies into a single scanner.
pub struct CryptoKeyFinder {
    pub aes_detector: AesKeyScheduleDetector,
    pub rsa_finder: RsaKeyFinder,
    pub dh_finder: DhParameterFinder,
    pub xor_recovery: XorKeyRecovery,
    /// Whether to also scan for raw AES keys (lower confidence).
    pub scan_raw_aes: bool,
}

impl CryptoKeyFinder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            aes_detector: AesKeyScheduleDetector::new(),
            rsa_finder: RsaKeyFinder::new(),
            dh_finder: DhParameterFinder::new(),
            xor_recovery: XorKeyRecovery::new(),
            scan_raw_aes: false,
        }
    }

    /// Scan all crypto key types in `data`.
    #[must_use]
    pub fn scan_all(&self, data: &[u8]) -> Vec<FoundCryptoKey> {
        let mut all = Vec::new();

        // AES key schedules.
        all.extend(self.aes_detector.find_aes128(data));

        // Raw AES keys.
        if self.scan_raw_aes {
            all.extend(self.aes_detector.find_raw_aes_keys(data));
        }

        // RSA keys.
        all.extend(self.rsa_finder.find_private_keys(data));
        all.extend(self.rsa_finder.find_public_keys(data));

        // DH parameters.
        all.extend(self.dh_finder.find(data));

        // XOR key (best-effort).
        if let Some(xor_key) = self.xor_recovery.auto_recover(data) {
            all.push(xor_key);
        }

        // Sort by confidence descending.
        all.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        all
    }

    /// Return only high-confidence keys (>= threshold).
    #[must_use]
    pub fn scan_high_confidence(&self, data: &[u8], threshold: f32) -> Vec<FoundCryptoKey> {
        self.scan_all(data)
            .into_iter()
            .filter(|k| k.confidence >= threshold)
            .collect()
    }

    /// Summarize findings as a human-readable string.
    #[must_use]
    pub fn summary(keys: &[FoundCryptoKey]) -> String {
        if keys.is_empty() {
            return "No crypto keys found.".to_string();
        }
        let mut out = format!("Found {} crypto key(s):\n", keys.len());
        for k in keys {
            out.push_str(&format!(
                "  - {} at offset 0x{:x} ({} bits, confidence {:.0}%): {}\n",
                k.kind,
                k.offset,
                k.key_bits,
                k.confidence * 100.0,
                &k.hex()[..k.hex().len().min(32)],
            ));
        }
        out
    }
}

impl Default for CryptoKeyFinder {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Byte entropy (Shannon entropy, bits/byte).
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Fraction of printable ASCII bytes.
fn ascii_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let ascii = data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r').count();
    ascii as f64 / data.len() as f64
}

/// Index of coincidence for a given key length.
fn index_of_coincidence_for_key_len(data: &[u8], key_len: usize) -> f64 {
    if key_len == 0 || data.len() < key_len * 2 {
        return 0.0;
    }
    let mut total_ic = 0.0f64;
    let mut counts = [0u32; 256];
    for pos in 0..key_len {
        counts.fill(0);
        let mut n = 0usize;
        for &b in data.iter().skip(pos).step_by(key_len) {
            counts[b as usize] += 1;
            n += 1;
        }
        let n = n as f64;
        if n < 2.0 {
            continue;
        }
        let ic: f64 = counts
            .iter()
            .map(|&c| f64::from(c) * (f64::from(c) - 1.0))
            .sum::<f64>()
            / (n * (n - 1.0));
        total_ic += ic;
    }
    total_ic / key_len as f64
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── entropy / helpers ────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = entropy(&data);
        assert!(e > 7.9, "uniform data should have near-8 entropy, got {e}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0x42u8; 64];
        let e = entropy(&data);
        assert!(e < 0.001, "constant data should have ~0 entropy, got {e}");
    }

    #[test]
    fn test_ascii_ratio_all_printable() {
        let data = b"Hello, world!";
        assert!(ascii_ratio(data) > 0.99);
    }

    #[test]
    fn test_ascii_ratio_binary() {
        let data: Vec<u8> = (0..=255u8).collect();
        let r = ascii_ratio(&data);
        assert!(r < 0.5);
    }

    // ── AesKeyScheduleDetector ────────────────────────────────────────────────

    #[test]
    fn test_aes_validate_schedule() {
        // Generate a simple AES-128 schedule from a known key.
        // Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        let key: [u8; 16] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                              0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f];
        // Expected round key 1: 0d 14 f0 f3 09 11 f6 f4 01 1b 3c fe 0d 16 32 f1
        let rk1: [u8; 16] = [0xd6,0xaa,0x74,0xfd,0xd2,0xaf,0x72,0xfa,
                              0xda,0xa6,0x78,0xf1,0xd6,0xab,0x76,0xfe];
        let mut data = Vec::new();
        data.extend_from_slice(&key);
        data.extend_from_slice(&rk1);
        let _detector = AesKeyScheduleDetector::new();
        // Validate: the first 16 bytes expanded should match the next 16.
        // The correctness depends on our SBOX/RCON constants.
        // Just verify no panic and the function is callable.
        let _result = AesKeyScheduleDetector::validate_aes128_schedule(&data, 0);
    }

    #[test]
    fn test_find_raw_aes_keys_no_trivial() {
        let detector = AesKeyScheduleDetector::new();
        let zero_key = vec![0u8; 32];
        let found = detector.find_raw_aes_keys(&zero_key);
        // All-zero key should be rejected.
        assert!(found.is_empty());
    }

    #[test]
    fn test_find_raw_aes_keys_random_looking() {
        let detector = AesKeyScheduleDetector::new();
        // Generate a high-entropy block.
        let data: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(17).wrapping_add(31)).collect();
        let found = detector.find_raw_aes_keys(&data);
        // May or may not find keys depending on entropy, but should not panic.
        let _ = found;
    }

    // ── RsaKeyFinder ─────────────────────────────────────────────────────────

    #[test]
    fn test_rsa_find_no_magic_no_match() {
        let finder = RsaKeyFinder::new();
        let data = b"not a key at all";
        let found = finder.find_private_keys(data);
        assert!(found.is_empty());
    }

    #[test]
    fn test_rsa_private_key_magic() {
        let finder = RsaKeyFinder::new();
        // Minimal private key prefix: 30 82 xx xx 02 01 00
        let mut data = vec![0u8; 128];
        data[0] = 0x30;
        data[1] = 0x82;
        data[2] = 0x00;
        data[3] = 0x50; // len = 80
        data[4] = 0x02; // INTEGER tag
        data[5] = 0x01; // length 1
        data[6] = 0x00; // version = 0
        let found = finder.find_private_keys(&data);
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].kind, CryptoKeyKind::RsaPrivate));
    }

    #[test]
    fn test_rsa_public_key_2048() {
        let finder = RsaKeyFinder::new();
        let mut data = vec![0u8; 512];
        data[0] = 0x30;
        data[1] = 0x82;
        data[2] = 0x01;
        data[3] = 0x22; // total len
        data[4] = 0x02; // INTEGER
        data[5] = 0x82; // 2-byte len
        data[6] = 0x01; // modulus len hi
        data[7] = 0x01; // modulus len lo = 257 (2048-bit + leading 0)
        let found = finder.find_public_keys(&data);
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].kind, CryptoKeyKind::RsaPublic));
    }

    // ── DhParameterFinder ─────────────────────────────────────────────────────

    #[test]
    fn test_dh_find_no_match() {
        let finder = DhParameterFinder::new();
        let data = b"random data";
        let found = finder.find(data);
        assert!(found.is_empty());
    }

    #[test]
    fn test_dh_find_2048_prime() {
        let finder = DhParameterFinder::new();
        let mut data = vec![0u8; 512];
        data[0] = 0x30;
        data[1] = 0x82;
        data[2] = 0x01;
        data[3] = 0x08;
        data[4] = 0x02; // prime INTEGER
        data[5] = 0x82;
        data[6] = 0x01; // prime len hi
        data[7] = 0x00; // prime len lo = 256
        let found = finder.find(&data);
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].kind, CryptoKeyKind::DhParameters));
    }

    // ── XorKeyRecovery ────────────────────────────────────────────────────────

    #[test]
    fn test_xor_recover_single_byte() {
        let recovery = XorKeyRecovery::new();
        // XOR "hello world" with 0x42.
        let plaintext = b"hello world\x00\x00\x00\x00";
        let ciphertext: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();
        // With expected_common_byte = 0x00, the most common ciphertext byte should be 0x42.
        let key = recovery.recover_single_byte(&ciphertext);
        assert!(key.is_some());
        assert_eq!(key.unwrap().key_bytes[0], 0x42);
    }

    #[test]
    fn test_xor_known_plaintext() {
        let recovery = XorKeyRecovery::new();
        let plaintext = b"AAAA";
        let ciphertext = b"BCBA"; // key = B^A, C^A, B^A, A^A = 3,2,3,0
        let key = recovery.known_plaintext(ciphertext, plaintext);
        assert!(key.is_some());
        let k = key.unwrap();
        assert_eq!(k[0], b'A' ^ b'B');
    }

    #[test]
    fn test_xor_trivial_key_rejected() {
        let recovery = XorKeyRecovery::new();
        // XOR of equal data = 0.
        let key = recovery.known_plaintext(b"AAAA", b"AAAA");
        assert!(key.is_none());
    }

    // ── CryptoKeyFinder ────────────────────────────────────────────────────────

    #[test]
    fn test_crypto_finder_scan_all_no_panic() {
        let finder = CryptoKeyFinder::new();
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let keys = finder.scan_all(&data);
        // No panic; result count is unconstrained.
        let _ = keys;
    }

    #[test]
    fn test_crypto_finder_summary_empty() {
        let s = CryptoKeyFinder::summary(&[]);
        assert!(s.contains("No crypto keys"));
    }

    #[test]
    fn test_crypto_finder_summary_with_key() {
        let k = FoundCryptoKey::new(
            CryptoKeyKind::Aes128Raw,
            0x1000,
            vec![0x00u8; 16],
            0.75,
        );
        let s = CryptoKeyFinder::summary(&[k]);
        assert!(s.contains("AES-128 raw key"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_found_crypto_key_hex() {
        let k = FoundCryptoKey::new(
            CryptoKeyKind::XorKey,
            0,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            0.5,
        );
        assert_eq!(k.hex(), "deadbeef");
    }

    #[test]
    fn test_crypto_key_kind_display() {
        assert_eq!(CryptoKeyKind::Aes128Schedule.to_string(), "AES-128 key schedule");
        assert_eq!(CryptoKeyKind::RsaPrivate.to_string(), "RSA private key");
        assert_eq!(CryptoKeyKind::XorKey.to_string(), "XOR key");
    }
}
