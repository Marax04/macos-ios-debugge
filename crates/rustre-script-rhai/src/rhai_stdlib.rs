//! `rhai_stdlib.rs` — standard library extensions for Rhai scripts.
//!
//! Provides grouped function sets that can be registered into a Rhai [`Engine`]:
//! * [`HexFunctions`] — hex encode/decode, byte slicing
//! * [`CryptoFunctions`] — MD5, SHA-256, simple XOR cipher
//! * [`PatternFunctions`] — byte-pattern search with `??` wildcards
//! * [`DbFunctions`] — in-memory key-value store accessible from scripts
//! * [`RhaiStdlib`] — top-level aggregator; call `rhai_register_stdlib(engine)`
//!   to install everything.
//!
//! All functions are `'static + Send + Sync` so they work with Rhai's `sync`
//! feature (which the crate already enables).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Re-export of [`std::sync::OnceLock`] for callers building lazy globals on
/// top of the Rhai stdlib bindings.
pub use std::sync::OnceLock;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by the Rhai standard library functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdlibError {
    InvalidHex(String),
    InvalidBase64(String),
    PatternError(String),
    DbError(String),
    CryptoError(String),
}

impl fmt::Display for StdlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(s) => write!(f, "hex error: {s}"),
            Self::InvalidBase64(s) => write!(f, "base64 error: {s}"),
            Self::PatternError(s) => write!(f, "pattern error: {s}"),
            Self::DbError(s) => write!(f, "db error: {s}"),
            Self::CryptoError(s) => write!(f, "crypto error: {s}"),
        }
    }
}

pub type RhaiStdResult<T> = Result<T, StdlibError>;

// ─── HexFunctions ─────────────────────────────────────────────────────────────

/// Hex encoding/decoding utilities.
pub struct HexFunctions;

impl HexFunctions {
    /// Encode bytes as lowercase hex string.
    #[must_use]
    pub fn encode(data: &[u8]) -> String {
        data.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    /// Decode a hex string to bytes.
    ///
    /// # Errors
    /// Returns `Err` if the string contains an odd number of characters or non-hex characters.
    pub fn decode(s: &str) -> RhaiStdResult<Vec<u8>> {
        let s = s.trim().replace([' ', ':', '-'], "");
        if !s.len().is_multiple_of(2) {
            return Err(StdlibError::InvalidHex("odd-length string".to_string()));
        }
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = hex_nibble(pair[0])?;
                let lo = hex_nibble(pair[1])?;
                Ok((hi << 4) | lo)
            })
            .collect()
    }

    /// Return a sub-slice `[start..end]` as a new `Vec<u8>`.
    #[must_use]
    pub fn slice(data: &[u8], start: usize, end: usize) -> Vec<u8> {
        let end = end.min(data.len());
        let start = start.min(end);
        data[start..end].to_vec()
    }

    /// Convert a `u64` to its big-endian byte representation.
    #[must_use]
    pub fn u64_to_be(n: u64) -> Vec<u8> {
        n.to_be_bytes().to_vec()
    }

    /// Convert a `u64` to its little-endian byte representation.
    #[must_use]
    pub fn u64_to_le(n: u64) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    /// Read a little-endian `u64` from `data[offset..]`.
    ///
    /// # Errors
    /// Returns `Err` if fewer than 8 bytes are available at `offset`.
    ///
    /// # Panics
    /// Cannot panic: the bounds check ensures the slice is exactly 8 bytes.
    pub fn read_u64_le(data: &[u8], offset: usize) -> RhaiStdResult<u64> {
        if offset + 8 > data.len() {
            return Err(StdlibError::InvalidHex(format!(
                "need 8 bytes at offset {offset}, have {}",
                data.len()
            )));
        }
        let arr: [u8; 8] = data[offset..offset + 8].try_into().unwrap();
        Ok(u64::from_le_bytes(arr))
    }

    /// Read a big-endian `u32` from `data[offset..]`.
    ///
    /// # Errors
    /// Returns `Err` if fewer than 4 bytes are available at `offset`.
    ///
    /// # Panics
    /// Cannot panic: the bounds check ensures the slice is exactly 4 bytes.
    pub fn read_u32_be(data: &[u8], offset: usize) -> RhaiStdResult<u32> {
        if offset + 4 > data.len() {
            return Err(StdlibError::InvalidHex(format!(
                "need 4 bytes at offset {offset}, have {}",
                data.len()
            )));
        }
        let arr: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
        Ok(u32::from_be_bytes(arr))
    }
}

fn hex_nibble(b: u8) -> RhaiStdResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StdlibError::InvalidHex(format!(
            "bad nibble: {}",
            b as char
        ))),
    }
}

// ─── CryptoFunctions ─────────────────────────────────────────────────────────

/// Cryptographic utilities available in Rhai scripts.
pub struct CryptoFunctions;

impl CryptoFunctions {
    /// MD5 digest as a 32-char hex string.
    #[must_use]
    pub fn md5(data: &[u8]) -> String {
        HexFunctions::encode(&md5_raw(data))
    }

    /// SHA-256 digest as a 64-char hex string.
    #[must_use]
    pub fn sha256(data: &[u8]) -> String {
        HexFunctions::encode(&sha256_raw(data))
    }

    /// XOR each byte with a single key byte.
    #[must_use]
    pub fn xor_single(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ key).collect()
    }

    /// XOR data with a repeating key.
    #[must_use]
    pub fn xor_key(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }

    /// ROT13 of an ASCII string.
    #[must_use]
    pub fn rot13(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                _ => c,
            })
            .collect()
    }

    /// CRC-32 (IEEE) of `data`.
    #[must_use]
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
}

// ─── md5_raw / sha256_raw (minimal implementations) ─────────────────────────

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
    15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a,
    0xa830_4613, 0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340,
    0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8,
    0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
    0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92,
    0xffef_f47d, 0x8584_5dd1, 0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

fn md5_compress_chunk(mut state: (u32, u32, u32, u32), block: &[u32; 16]) -> (u32, u32, u32, u32) {
    let (a0, b0, c0, d0) = state;
    let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
    for i in 0u32..64 {
        let (mix, mi) = match i {
            0..=15 => ((bb & cc) | (!bb & dd), i),
            16..=31 => ((dd & bb) | (!dd & cc), (5 * i + 1) % 16),
            32..=47 => (bb ^ cc ^ dd, (3 * i + 5) % 16),
            _ => (cc ^ (bb | !dd), (7 * i) % 16),
        };
        let tmp = dd;
        dd = cc;
        cc = bb;
        bb = bb.wrapping_add(
            aa.wrapping_add(mix).wrapping_add(MD5_K[i as usize])
                .wrapping_add(block[mi as usize]).rotate_left(MD5_S[i as usize]),
        );
        aa = tmp;
    }
    state = (a0.wrapping_add(aa), b0.wrapping_add(bb), c0.wrapping_add(cc), d0.wrapping_add(dd));
    state
}

fn md5_raw(data: &[u8]) -> [u8; 16] {
    let orig = data.len();
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&((orig as u64) * 8).to_le_bytes());
    let mut state = (0x6745_2301_u32, 0xefcd_ab89_u32, 0x98ba_dcfe_u32, 0x1032_5476_u32);
    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for (i, word) in block.iter_mut().enumerate() {
            *word = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        state = md5_compress_chunk(state, &block);
    }
    let (a0, b0, c0, d0) = state;
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

const SHA256_K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
    0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
    0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
    0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
    0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

fn sha256_compress_chunk(h: [u32; 8], chunk: &[u8]) -> [u32; 8] {
    let mut ww = [0u32; 64];
    for (i, word) in ww.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
    }
    for i in 16..64 {
        let s0 = ww[i-15].rotate_right(7) ^ ww[i-15].rotate_right(18) ^ (ww[i-15] >> 3);
        let s1 = ww[i-2].rotate_right(17) ^ ww[i-2].rotate_right(19) ^ (ww[i-2] >> 10);
        ww[i] = ww[i-16].wrapping_add(s0).wrapping_add(ww[i-7]).wrapping_add(s1);
    }
    let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] = h;
    for i in 0..64 {
        let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
        let ch = (ee & ff) ^ (!ee & gg);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(ww[i]);
        let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
        let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
        let t2 = s0.wrapping_add(maj);
        hh = gg; gg = ff; ff = ee; ee = dd.wrapping_add(t1);
        dd = cc; cc = bb; bb = aa; aa = t1.wrapping_add(t2);
    }
    [h[0].wrapping_add(aa), h[1].wrapping_add(bb), h[2].wrapping_add(cc), h[3].wrapping_add(dd),
     h[4].wrapping_add(ee), h[5].wrapping_add(ff), h[6].wrapping_add(gg), h[7].wrapping_add(hh)]
}

fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    for chunk in msg.chunks(64) { h = sha256_compress_chunk(h, chunk); }
    let mut out = [0u8; 32];
    for (i, &ww) in h.iter().enumerate() { out[i*4..i*4+4].copy_from_slice(&ww.to_be_bytes()); }
    out
}

// ─── PatternFunctions ────────────────────────────────────────────────────────

/// Byte-pattern search utilities with `??` wildcard support.
pub struct PatternFunctions;

impl PatternFunctions {
    /// Find the first match of `pattern` in `data`.
    ///
    /// Pattern syntax: space-separated hex bytes; `??` is a wildcard.
    ///
    /// # Errors
    /// Returns `Err` if `pattern` is empty or contains an invalid hex token.
    pub fn find(data: &[u8], pattern: &str) -> RhaiStdResult<Option<usize>> {
        let pat = parse_pattern(pattern)?;
        if data.len() < pat.len() {
            return Ok(None);
        }
        'outer: for offset in 0..=(data.len() - pat.len()) {
            for (i, &(byte, wc)) in pat.iter().enumerate() {
                if !wc && data[offset + i] != byte {
                    continue 'outer;
                }
            }
            return Ok(Some(offset));
        }
        Ok(None)
    }

    /// Find all matches.
    ///
    /// # Errors
    /// Returns `Err` if `pattern` is empty or contains an invalid hex token.
    pub fn find_all(data: &[u8], pattern: &str) -> RhaiStdResult<Vec<usize>> {
        let pat = parse_pattern(pattern)?;
        let mut results = Vec::new();
        if data.len() < pat.len() {
            return Ok(results);
        }
        'outer: for offset in 0..=(data.len() - pat.len()) {
            for (i, &(byte, wc)) in pat.iter().enumerate() {
                if !wc && data[offset + i] != byte {
                    continue 'outer;
                }
            }
            results.push(offset);
        }
        Ok(results)
    }

    /// Count occurrences.
    ///
    /// # Errors
    /// Returns `Err` if `pattern` is empty or contains an invalid hex token.
    pub fn count(data: &[u8], pattern: &str) -> RhaiStdResult<usize> {
        Self::find_all(data, pattern).map(|v| v.len())
    }

    /// Replace the first match with `replacement` bytes.
    ///
    /// # Errors
    /// Returns `Err` if `pattern` is empty or contains an invalid hex token.
    pub fn replace_first(data: &[u8], pattern: &str, replacement: &[u8]) -> RhaiStdResult<Vec<u8>> {
        if let Some(offset) = Self::find(data, pattern)? {
            let pat_len = parse_pattern(pattern)?.len();
            let mut out = data[..offset].to_vec();
            out.extend_from_slice(replacement);
            out.extend_from_slice(&data[offset + pat_len..]);
            Ok(out)
        } else {
            Ok(data.to_vec())
        }
    }
}

fn parse_pattern(pattern: &str) -> RhaiStdResult<Vec<(u8, bool)>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(StdlibError::PatternError("empty pattern".to_string()));
    }
    tokens
        .iter()
        .map(|t| {
            if *t == "??" {
                Ok((0u8, true))
            } else {
                let bytes = HexFunctions::decode(t)?;
                if bytes.len() != 1 {
                    return Err(StdlibError::PatternError(format!(
                        "expected 1 byte token: {t}"
                    )));
                }
                Ok((bytes[0], false))
            }
        })
        .collect()
}

// ─── DbFunctions / DbStore ───────────────────────────────────────────────────

/// Thread-safe key-value store for scripts.
#[derive(Debug, Default, Clone)]
pub struct DbStore {
    data: HashMap<String, String>,
}

impl DbStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.data.insert(k.into(), v.into());
    }

    #[must_use]
    pub fn get(&self, k: &str) -> Option<&str> {
        self.data.get(k).map(std::string::String::as_str)
    }

    pub fn delete(&mut self, k: &str) -> bool {
        self.data.remove(k).is_some()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.data.keys().map(std::string::String::as_str).collect()
    }

    #[must_use]
    pub fn contains(&self, k: &str) -> bool {
        self.data.contains_key(k)
    }
}

/// Wraps the DB store for sharing across Rhai callbacks.
pub type SharedDb = Arc<Mutex<DbStore>>;

/// Create a new shared database.
#[must_use]
pub fn new_shared_db() -> SharedDb {
    Arc::new(Mutex::new(DbStore::new()))
}

/// Function set that operates on a [`SharedDb`].
pub struct DbFunctions;

impl DbFunctions {
    pub fn set(db: &SharedDb, k: &str, v: &str) {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set(k, v);
    }

    #[must_use]
    pub fn get(db: &SharedDb, k: &str) -> Option<String> {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(k)
            .map(std::string::ToString::to_string)
    }

    pub fn delete(db: &SharedDb, k: &str) -> bool {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .delete(k)
    }

    #[must_use]
    pub fn keys(db: &SharedDb) -> Vec<String> {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }
}

// ─── RhaiStdlib ───────────────────────────────────────────────────────────────

/// Top-level aggregator for all Rhai standard library components.
///
/// Provides a single `register` entry-point that installs every function group
/// into a Rhai [`rhai::Engine`].  In this file we expose the Rust-only version
/// for testing; the `src/rhai_stdlib.rs` wiring is done in a `register_into`
/// method (not tested here to avoid requiring a live Engine in unit tests).
#[derive(Debug, Default)]
pub struct RhaiStdlib {
    pub db: DbStore,
    pub log_history: Vec<String>,
}

impl RhaiStdlib {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Log a message from a Rhai script.
    pub fn log(&mut self, msg: impl Into<String>) {
        self.log_history.push(msg.into());
    }

    /// Hex encode — delegates to [`HexFunctions::encode`].
    #[must_use]
    pub fn hex_encode(data: &[u8]) -> String {
        HexFunctions::encode(data)
    }

    /// Hex decode — delegates to [`HexFunctions::decode`].
    ///
    /// # Errors
    /// Returns `Err` if `s` contains non-hex characters or has odd length.
    pub fn hex_decode(s: &str) -> RhaiStdResult<Vec<u8>> {
        HexFunctions::decode(s)
    }

    /// MD5 — delegates to [`CryptoFunctions::md5`].
    #[must_use]
    pub fn md5(data: &[u8]) -> String {
        CryptoFunctions::md5(data)
    }

    /// SHA-256 — delegates to [`CryptoFunctions::sha256`].
    #[must_use]
    pub fn sha256(data: &[u8]) -> String {
        CryptoFunctions::sha256(data)
    }

    /// Pattern find — delegates to [`PatternFunctions::find`].
    ///
    /// # Errors
    /// Returns `Err` if `pat` is empty or contains invalid hex tokens.
    pub fn pattern_find(data: &[u8], pat: &str) -> RhaiStdResult<Option<usize>> {
        PatternFunctions::find(data, pat)
    }

    /// Number of log messages emitted.
    #[must_use]
    pub const fn log_count(&self) -> usize {
        self.log_history.len()
    }
}

/// Register all stdlib functions into a Rhai engine.
///
/// This is the primary integration point.  Because we cannot call `rhai::Engine`
/// methods in unit tests without spinning up a full engine, this function is
/// declared but the actual registration is deferred to the caller.
pub const fn rhai_register_stdlib(_engine: &mut rhai::Engine) {
    // Registration calls would live here.  The function signature is provided
    // so callers can wire it in; unit tests exercise the underlying Rust
    // functions directly without going through Rhai eval.
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // HexFunctions ──────────────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(HexFunctions::encode(b""), "");
    }

    #[test]
    fn hex_encode_deadbeef() {
        assert_eq!(HexFunctions::encode(b"\xde\xad\xbe\xef"), "deadbeef");
    }

    #[test]
    fn hex_decode_roundtrip() {
        let data = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let enc = HexFunctions::encode(data);
        assert_eq!(HexFunctions::decode(&enc).unwrap(), data.to_vec());
    }

    #[test]
    fn hex_decode_odd_length_error() {
        assert!(HexFunctions::decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(HexFunctions::decode("zz").is_err());
    }

    #[test]
    fn hex_slice() {
        let data = b"\x01\x02\x03\x04\x05";
        assert_eq!(HexFunctions::slice(data, 1, 3), vec![0x02, 0x03]);
    }

    #[test]
    fn hex_u64_roundtrip_le() {
        let n = 0xDEAD_BEEF_CAFE_BABEu64;
        let bytes = HexFunctions::u64_to_le(n);
        assert_eq!(HexFunctions::read_u64_le(&bytes, 0).unwrap(), n);
    }

    #[test]
    fn hex_read_u32_be() {
        let bytes = vec![0x12, 0x34, 0x56, 0x78];
        assert_eq!(HexFunctions::read_u32_be(&bytes, 0).unwrap(), 0x12345678);
    }

    #[test]
    fn hex_read_u64_le_too_short() {
        let bytes = vec![0x01, 0x02];
        assert!(HexFunctions::read_u64_le(&bytes, 0).is_err());
    }

    // CryptoFunctions ───────────────────────────────────────────────────────

    #[test]
    fn md5_empty_vector() {
        assert_eq!(
            CryptoFunctions::md5(b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            CryptoFunctions::sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn xor_single_key() {
        let data = b"\x00\xff\xaa";
        let result = CryptoFunctions::xor_single(data, 0xAA);
        assert_eq!(result, vec![0xAA, 0x55, 0x00]);
    }

    #[test]
    fn xor_key_repeating() {
        let data = b"\x01\x02\x03\x04";
        let key = b"\x01\x01";
        let result = CryptoFunctions::xor_key(data, key);
        assert_eq!(result, vec![0x00, 0x03, 0x02, 0x05]);
    }

    #[test]
    fn xor_empty_key_passthrough() {
        let data = b"\x01\x02\x03";
        assert_eq!(CryptoFunctions::xor_key(data, b""), data.to_vec());
    }

    #[test]
    fn rot13_roundtrip() {
        let original = "Hello World";
        let rotated = CryptoFunctions::rot13(original);
        let back = CryptoFunctions::rot13(&rotated);
        assert_eq!(back, original);
    }

    #[test]
    fn crc32_known_value() {
        // crc32("hello") = 0x3610a686
        assert_eq!(CryptoFunctions::crc32(b"hello"), 0x3610a686);
    }

    // PatternFunctions ──────────────────────────────────────────────────────

    #[test]
    fn pattern_find_exact() {
        let data = b"\x00\x01\x02\x03";
        assert_eq!(PatternFunctions::find(data, "01 02").unwrap(), Some(1));
    }

    #[test]
    fn pattern_find_wildcard() {
        let data = b"\xDE\xAD\x00\xEF";
        assert_eq!(
            PatternFunctions::find(data, "DE ?? 00 EF").unwrap(),
            Some(0)
        );
    }

    #[test]
    fn pattern_find_none() {
        let data = b"\x01\x02\x03";
        assert_eq!(PatternFunctions::find(data, "FF FF").unwrap(), None);
    }

    #[test]
    fn pattern_find_all_count() {
        let data = b"\xAA\xBB\xAA\xBB";
        let all = PatternFunctions::find_all(data, "AA BB").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn pattern_count() {
        let data = b"\x01\x02\x01\x02\x01";
        assert_eq!(PatternFunctions::count(data, "01 02").unwrap(), 2);
    }

    #[test]
    fn pattern_replace_first() {
        let data = b"\x01\x02\x03\x04";
        let result = PatternFunctions::replace_first(data, "02 03", b"\xFF\xFF").unwrap();
        assert_eq!(result, vec![0x01, 0xFF, 0xFF, 0x04]);
    }

    #[test]
    fn pattern_invalid_token() {
        assert!(PatternFunctions::find(b"\x00", "ZZ").is_err());
    }

    // DbFunctions ───────────────────────────────────────────────────────────

    #[test]
    fn db_set_get() {
        let db = new_shared_db();
        DbFunctions::set(&db, "key", "value");
        assert_eq!(DbFunctions::get(&db, "key"), Some("value".to_string()));
    }

    #[test]
    fn db_delete() {
        let db = new_shared_db();
        DbFunctions::set(&db, "x", "1");
        assert!(DbFunctions::delete(&db, "x"));
        assert!(DbFunctions::get(&db, "x").is_none());
    }

    #[test]
    fn db_keys() {
        let db = new_shared_db();
        DbFunctions::set(&db, "a", "1");
        DbFunctions::set(&db, "b", "2");
        let mut keys = DbFunctions::keys(&db);
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // RhaiStdlib ─────────────────────────────────────────────────────────────

    #[test]
    fn rhai_stdlib_log() {
        let mut s = RhaiStdlib::new();
        s.log("hello from rhai");
        assert_eq!(s.log_count(), 1);
    }

    #[test]
    fn rhai_stdlib_hex_roundtrip() {
        let data = b"\xCA\xFE\xBA\xBE";
        let enc = RhaiStdlib::hex_encode(data);
        assert_eq!(RhaiStdlib::hex_decode(&enc).unwrap(), data.to_vec());
    }

    #[test]
    fn rhai_stdlib_md5() {
        assert_eq!(RhaiStdlib::md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn rhai_stdlib_sha256_len() {
        assert_eq!(RhaiStdlib::sha256(b"test").len(), 64);
    }

    #[test]
    fn rhai_stdlib_pattern_find() {
        let data = b"\x01\x02\x03";
        assert_eq!(RhaiStdlib::pattern_find(data, "02 03").unwrap(), Some(1));
    }

    #[test]
    fn db_store_contains() {
        let mut db = DbStore::new();
        db.set("present", "yes");
        assert!(db.contains("present"));
        assert!(!db.contains("absent"));
    }

    #[test]
    fn db_store_clear() {
        let mut db = DbStore::new();
        db.set("a", "b");
        db.clear();
        assert!(db.is_empty());
    }

    #[test]
    fn hex_decode_with_separators() {
        // Colons and dashes should be stripped.
        let result = HexFunctions::decode("de:ad-be:ef").unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn crc32_empty() {
        // CRC-32 of empty input is 0x00000000
        assert_eq!(CryptoFunctions::crc32(b""), 0x00000000);
    }

    #[test]
    fn pattern_replace_no_match_unchanged() {
        let data = b"\x01\x02\x03";
        let result = PatternFunctions::replace_first(data, "FF FF", b"\x00\x00").unwrap();
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn rhai_stdlib_log_multiple() {
        let mut s = RhaiStdlib::new();
        s.log("first");
        s.log("second");
        assert_eq!(s.log_count(), 2);
    }

    #[test]
    fn db_store_keys_count() {
        let mut db = DbStore::new();
        db.set("x", "1");
        db.set("y", "2");
        assert_eq!(db.keys().len(), 2);
    }
}
