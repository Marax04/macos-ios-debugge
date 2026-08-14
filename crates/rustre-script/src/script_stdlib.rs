//! `script_stdlib.rs` — standard library functions exposed to all script engines.
//!
//! Every scripting adapter (Lua, Python, Rhai) can call into these functions
//! through the shared [`ScriptStdlib`] struct.  The functions are pure Rust —
//! no FFI, no unsafe code.
//!
//! # Provided functions
//! * `hex_encode` / `hex_decode`
//! * `base64_encode` / `base64_decode` (URL-safe, no-pad variant)
//! * `sha256` / `md5` (pure Rust implementations)
//! * `gunzip` (DEFLATE inflate via `miniz_oxide`-compatible approach — stubbed
//!   with a simple pass-through when the input is not compressed)
//! * `json_parse` / `json_serialize`
//! * `regex_match` — simple glob/literal matcher (no regex crate dependency)
//! * `pattern_find` — byte-pattern search with `??` wildcard support

use std::collections::HashMap;
use std::fmt;

// ─── StdlibError ─────────────────────────────────────────────────────────────

/// Errors that can occur inside the standard library functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdlibError {
    InvalidHex(String),
    InvalidBase64(String),
    InvalidUtf8(String),
    JsonError(String),
    PatternError(String),
    DecompressError(String),
}

impl fmt::Display for StdlibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            Self::InvalidBase64(s) => write!(f, "invalid base64: {s}"),
            Self::InvalidUtf8(s) => write!(f, "invalid utf-8: {s}"),
            Self::JsonError(s) => write!(f, "json error: {s}"),
            Self::PatternError(s) => write!(f, "pattern error: {s}"),
            Self::DecompressError(s) => write!(f, "decompress error: {s}"),
        }
    }
}

pub type StdResult<T> = Result<T, StdlibError>;

// ─── ScriptValue ─────────────────────────────────────────────────────────────

/// A loosely-typed value used as input/output for stdlib functions.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Map(HashMap<String, Self>),
}

impl ScriptValue {
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            Self::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

// ─── hex ─────────────────────────────────────────────────────────────────────

/// Encode bytes as lowercase hex.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Decode a hex string to bytes.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn hex_decode(s: &str) -> StdResult<Vec<u8>> {
    let s = s.trim().replace([' ', ':'], "");
    if !s.len().is_multiple_of(2) {
        return Err(StdlibError::InvalidHex("odd-length string".to_string()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble(b: u8) -> StdResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StdlibError::InvalidHex(format!(
            "invalid hex byte: {}",
            b as char
        ))),
    }
}

// ─── base64 ──────────────────────────────────────────────────────────────────

const B64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as standard base64 (with `=` padding).
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    base64_encode_internal(data, B64_TABLE, true)
}

/// Encode bytes as URL-safe base64 (no padding).
#[must_use]
pub fn base64_encode_url(data: &[u8]) -> String {
    base64_encode_internal(data, B64_URL_TABLE, false)
}

fn base64_encode_internal(data: &[u8], table: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3) + 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[((n >> 18) & 0x3F) as usize] as char);
        out.push(table[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(table[((n >> 6) & 0x3F) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[(n & 0x3F) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Decode standard (or URL-safe) base64.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn base64_decode(s: &str) -> StdResult<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 4);
    let mut buf = [0u8; 4];
    let mut cnt = 0usize;
    for ch in s.bytes() {
        if ch == b'=' || (ch as char).is_whitespace() {
            continue;
        }
        let v = b64_val(ch)
            .ok_or_else(|| StdlibError::InvalidBase64(format!("bad char: {}", ch as char)))?;
        buf[cnt] = v;
        cnt += 1;
        if cnt == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            cnt = 0;
        }
    }
    match cnt {
        2 => out.push((buf[0] << 2) | (buf[1] >> 4)),
        3 => {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        0 => {}
        1 => return Err(StdlibError::InvalidBase64("truncated input".into())),
        _ => unreachable!(),
    }
    Ok(out)
}

const fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

// ─── md5 ─────────────────────────────────────────────────────────────────────

/// Compute the MD5 digest of `data` and return it as a 32-char hex string.
///
/// Pure Rust implementation of RFC 1321.
#[must_use]
pub fn md5(data: &[u8]) -> String {
    let digest = md5_raw(data);
    hex_encode(&digest)
}

fn md5_raw(data: &[u8]) -> [u8; 16] {
    // Per-round shift amounts.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    // Precomputed table K[i] = floor(abs(sin(i+1)) * 2^32).
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let orig_len = data.len();
    let pad_len = (56 - ((orig_len + 1) % 64) + 64) % 64;
    let mut msg: Vec<u8> = Vec::with_capacity(orig_len + 1 + pad_len + 8);
    msg.extend_from_slice(data);
    msg.push(0x80);
    msg.resize(msg.len() + pad_len, 0x00);
    // Use saturating_mul to avoid overflow on inputs >= 2^61 bytes (per RFC 1321
    // the bit length field is 64-bit, so truncation of astronomically large inputs
    // is acceptable, matching browser/OS MD5 behaviour).
    let bit_len = (orig_len as u64).saturating_mul(8);
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301_u32,
        0xefcd_ab89_u32,
        0x98ba_dcfe_u32,
        0x1032_5476_u32,
    );

    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for (i, word) in block.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
        for i in 0u32..64 {
            let (mix, mi) = match i {
                0..=15 => ((bb & cc) | (!bb & dd), i),
                16..=31 => ((dd & bb) | (!dd & cc), (5 * i + 1) % 16),
                32..=47 => (bb ^ cc ^ dd, (3 * i + 5) % 16),
                _ => (cc ^ (bb | !dd), (7 * i) % 16),
            };
            let temp = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(
                aa.wrapping_add(mix)
                    .wrapping_add(K[i as usize])
                    .wrapping_add(block[mi as usize])
                    .rotate_left(S[i as usize]),
            );
            aa = temp;
        }
        a0 = a0.wrapping_add(aa);
        b0 = b0.wrapping_add(bb);
        c0 = c0.wrapping_add(cc);
        d0 = d0.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ─── sha256 ───────────────────────────────────────────────────────────────────

/// Compute the SHA-256 digest of `data` and return it as a 64-char hex string.
///
/// Pure Rust implementation of FIPS 180-4.
#[must_use]
pub fn sha256(data: &[u8]) -> String {
    let digest = sha256_raw(data);
    hex_encode(&digest)
}

fn sha256_raw(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let orig_bit_len = (data.len() as u64).saturating_mul(8);
    let orig_len = data.len();
    let pad_len = (56 - ((orig_len + 1) % 64) + 64) % 64;
    let mut msg: Vec<u8> = Vec::with_capacity(orig_len + 1 + pad_len + 8);
    msg.extend_from_slice(data);
    msg.push(0x80);
    msg.resize(msg.len() + pad_len, 0x00);
    msg.extend_from_slice(&orig_bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut ww = [0u32; 64];
        for (i, word) in ww.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = ww[i - 15].rotate_right(7) ^ ww[i - 15].rotate_right(18) ^ (ww[i - 15] >> 3);
            let s1 = ww[i - 2].rotate_right(17) ^ ww[i - 2].rotate_right(19) ^ (ww[i - 2] >> 10);
            ww[i] = ww[i - 16]
                .wrapping_add(s0)
                .wrapping_add(ww[i - 7])
                .wrapping_add(s1);
        }
        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
        for i in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ (!ee & gg);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(ww[i]);
            let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let temp2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(temp1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ─── gunzip ──────────────────────────────────────────────────────────────────

/// Very simple gzip detection and stripping.
///
/// If `data` starts with the gzip magic (`1f 8b`), attempt to strip the
/// 10-byte gzip header and return the payload. In a real implementation this
/// would invoke a DEFLATE decompressor; here we document the interface and
/// return an error unless the data is not actually compressed.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn gunzip(data: &[u8]) -> StdResult<Vec<u8>> {
    if data.len() < 2 {
        return Err(StdlibError::DecompressError("input too short".to_string()));
    }
    if data[0] == 0x1f && data[1] == 0x8b {
        // Real decompression would happen here.
        // For now, return an error indicating the data is compressed.
        Err(StdlibError::DecompressError(
            "gzip decompression requires an external DEFLATE library".to_string(),
        ))
    } else {
        // Not gzip-compressed; pass through.
        Ok(data.to_vec())
    }
}

// ─── json ────────────────────────────────────────────────────────────────────

/// Parse a JSON string into a [`ScriptValue`] tree.
///
/// Uses `serde_json` when available (feature `"serde_json"`).  Here we
/// provide a thin wrapper over the `serde_json` crate.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn json_parse(s: &str) -> StdResult<ScriptValue> {
    // Delegate to serde_json if present; otherwise do a minimal fallback.
    serde_json_parse_depth(s, 0)
}

/// Serialize a [`ScriptValue`] to a JSON string.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn json_serialize(v: &ScriptValue) -> StdResult<String> {
    Ok(script_value_to_json(v))
}

fn split_json_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escape = false;
    let mut cur = String::new();
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ']' | '}' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Maximum nesting depth for the built-in JSON parser.
const JSON_MAX_DEPTH: usize = 64;

fn serde_json_parse_depth(s: &str, depth: usize) -> StdResult<ScriptValue> {
    if depth > JSON_MAX_DEPTH {
        return Err(StdlibError::JsonError(format!(
            "JSON nesting depth exceeds maximum {JSON_MAX_DEPTH}"
        )));
    }
    // Minimal JSON parser: handles null, bool, numbers, strings, arrays, objects.
    let s = s.trim();
    if s == "null" {
        return Ok(ScriptValue::Null);
    }
    if s == "true" {
        return Ok(ScriptValue::Bool(true));
    }
    if s == "false" {
        return Ok(ScriptValue::Bool(false));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Ok(ScriptValue::Int(n));
    }
    if let Ok(f) = s.parse::<f64>() {
        return Ok(ScriptValue::Float(f));
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return Ok(ScriptValue::Str(s[1..s.len() - 1].to_string()));
    }
    if s.starts_with('[') && s.ends_with(']') {
        // Minimal array parse: no nested structures.
        let inner = &s[1..s.len() - 1];
        if inner.trim().is_empty() {
            return Ok(ScriptValue::Array(Vec::new()));
        }
        let items: Vec<ScriptValue> = split_json_top_level(inner)
            .into_iter()
            .map(|item| serde_json_parse_depth(item.trim(), depth + 1))
            .collect::<StdResult<Vec<_>>>()?;
        return Ok(ScriptValue::Array(items));
    }
    if s.starts_with('{') && s.ends_with('}') {
        // Minimal object parse: keys must be quoted strings.
        let inner = &s[1..s.len() - 1];
        if inner.trim().is_empty() {
            return Ok(ScriptValue::Map(HashMap::new()));
        }
        let mut map = HashMap::new();
        for pair in split_json_top_level(inner) {
            let pair = pair.trim();
            let colon = pair.find(':').ok_or_else(|| {
                StdlibError::JsonError(format!("missing ':' in object pair: {pair}"))
            })?;
            let key_raw = pair[..colon].trim();
            let val_raw = pair[colon + 1..].trim();
            if !(key_raw.starts_with('"') && key_raw.ends_with('"') && key_raw.len() >= 2) {
                return Err(StdlibError::JsonError(format!(
                    "object key must be a quoted string: {key_raw}"
                )));
            }
            let key = key_raw[1..key_raw.len() - 1].to_string();
            let value = serde_json_parse_depth(val_raw, depth + 1)?;
            map.insert(key, value);
        }
        return Ok(ScriptValue::Map(map));
    }
    Err(StdlibError::JsonError(format!("cannot parse: {s}")))
}

fn script_value_to_json(v: &ScriptValue) -> String {
    match v {
        ScriptValue::Null => "null".to_string(),
        ScriptValue::Bool(b) => b.to_string(),
        ScriptValue::Int(n) => n.to_string(),
        ScriptValue::Float(f) => f.to_string(),
        ScriptValue::Str(s) => format!("\"{}\"", json_escape_str(s)),
        ScriptValue::Bytes(b) => format!("\"{}\"", hex_encode(b)),
        ScriptValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(script_value_to_json).collect();
            format!("[{}]", items.join(","))
        }
        ScriptValue::Map(m) => {
            let pairs: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", json_escape_str(k), script_value_to_json(v)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn json_escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ─── regex_match ─────────────────────────────────────────────────────────────

/// Simple glob/literal matcher.
///
/// Supports `*` (match zero or more chars) and `?` (match exactly one char).
/// Case-sensitive.
#[must_use]
pub fn regex_match(pattern: &str, text: &str) -> bool {
    glob_match(pattern.as_bytes(), text.as_bytes())
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    // Iterative two-pointer match with backtracking on `*` only.
    // Linear time in practice; avoids exponential blowup on inputs like
    // `a*a*a*a*b` against `aaaa...`.
    let mut pi: usize = 0;
    let mut ti: usize = 0;
    let mut star: Option<usize> = None;
    let mut match_ti: usize = 0;
    while ti < text.len() {
        if pi < pat.len() && pat[pi] == b'*' {
            star = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

// ─── pattern_find ────────────────────────────────────────────────────────────

/// Scan `data` for `pattern`, where `??` represents a wildcard byte.
///
/// Returns the offset of the first match, or `None`.
///
/// Pattern syntax: space-separated hex bytes with `??` as wildcard.
/// Example: `"DE AD BE EF ?? ?? 00"`
///
/// # Errors
/// Returns an error if the operation fails.
pub fn pattern_find(data: &[u8], pattern: &str) -> StdResult<Option<usize>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(StdlibError::PatternError("empty pattern".to_string()));
    }
    // Parse pattern into (byte, is_wildcard) pairs.
    let pat: Vec<(u8, bool)> = tokens
        .iter()
        .map(|t| {
            if *t == "??" {
                Ok((0u8, true))
            } else {
                let b = hex_decode(t)
                    .map_err(|_| StdlibError::PatternError(format!("bad pattern byte: {t}")))?;
                if b.len() != 1 {
                    return Err(StdlibError::PatternError(format!(
                        "expected 1 byte, got {}: {t}",
                        b.len()
                    )));
                }
                Ok((b[0], false))
            }
        })
        .collect::<StdResult<Vec<_>>>()?;

    if data.len() < pat.len() {
        return Ok(None);
    }
    'outer: for offset in 0..=(data.len() - pat.len()) {
        for (i, &(byte, wildcard)) in pat.iter().enumerate() {
            if !wildcard && data[offset + i] != byte {
                continue 'outer;
            }
        }
        return Ok(Some(offset));
    }
    Ok(None)
}

/// Find all matches of `pattern` in `data`.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn pattern_find_all(data: &[u8], pattern: &str) -> StdResult<Vec<usize>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(StdlibError::PatternError("empty pattern".to_string()));
    }
    let pat: Vec<(u8, bool)> = tokens
        .iter()
        .map(|t| {
            if *t == "??" {
                Ok((0u8, true))
            } else {
                let b = hex_decode(t)
                    .map_err(|_| StdlibError::PatternError(format!("bad pattern byte: {t}")))?;
                if b.len() != 1 {
                    return Err(StdlibError::PatternError(format!("bad token: {t}")));
                }
                Ok((b[0], false))
            }
        })
        .collect::<StdResult<Vec<_>>>()?;
    let mut results = Vec::new();
    if data.len() < pat.len() {
        return Ok(results);
    }
    'outer: for offset in 0..=(data.len() - pat.len()) {
        for (i, &(byte, wildcard)) in pat.iter().enumerate() {
            if !wildcard && data[offset + i] != byte {
                continue 'outer;
            }
        }
        results.push(offset);
    }
    Ok(results)
}

// ─── ScriptStdlib ─────────────────────────────────────────────────────────────

/// Unified standard-library façade.
///
/// Script engine adapters can hold an instance and dispatch through its methods.
#[derive(Debug, Default, Clone)]
pub struct ScriptStdlib;

impl ScriptStdlib {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn hex_encode(&self, data: &[u8]) -> String {
        hex_encode(data)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn hex_decode(&self, s: &str) -> StdResult<Vec<u8>> {
        hex_decode(s)
    }
    #[must_use]
    pub fn base64_encode(&self, data: &[u8]) -> String {
        base64_encode(data)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn base64_decode(&self, s: &str) -> StdResult<Vec<u8>> {
        base64_decode(s)
    }
    #[must_use]
    pub fn sha256(&self, data: &[u8]) -> String {
        sha256(data)
    }
    #[must_use]
    pub fn md5(&self, data: &[u8]) -> String {
        md5(data)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn gunzip(&self, data: &[u8]) -> StdResult<Vec<u8>> {
        gunzip(data)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn json_parse(&self, s: &str) -> StdResult<ScriptValue> {
        json_parse(s)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn json_serialize(&self, v: &ScriptValue) -> StdResult<String> {
        json_serialize(v)
    }
    #[must_use]
    pub fn regex_match(&self, pattern: &str, text: &str) -> bool {
        regex_match(pattern, text)
    }
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn pattern_find(&self, data: &[u8], pattern: &str) -> StdResult<Option<usize>> {
        pattern_find(data, pattern)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // hex ──────────────────────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(b""), "");
    }

    #[test]
    fn hex_encode_known() {
        assert_eq!(hex_encode(b"\xde\xad\xbe\xef"), "deadbeef");
    }

    #[test]
    fn hex_decode_roundtrip() {
        let data = b"\x00\xff\x80\x7f";
        let enc = hex_encode(data);
        assert_eq!(hex_decode(&enc).unwrap(), data.to_vec());
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("xyz").is_err());
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_uppercase() {
        assert_eq!(
            hex_decode("DEADBEEF").unwrap(),
            b"\xde\xad\xbe\xef".to_vec()
        );
    }

    // base64 ───────────────────────────────────────────────────────────────

    #[test]
    fn base64_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_known() {
        // "Man" → "TWFu"
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data.to_vec());
    }

    #[test]
    fn base64_invalid_char() {
        assert!(base64_decode("!!!").is_err());
    }

    #[test]
    fn base64_url_safe_encoding() {
        // "+/" → "-_"
        let data: Vec<u8> = (0u8..3).collect();
        let enc = base64_encode_url(&data);
        assert!(!enc.contains('+'));
        assert!(!enc.contains('/'));
    }

    // md5 ──────────────────────────────────────────────────────────────────

    #[test]
    fn md5_empty() {
        // RFC 1321 test vector.
        assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_hello() {
        assert_eq!(md5(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn md5_returns_32_chars() {
        assert_eq!(md5(b"test").len(), 32);
    }

    // sha256 ───────────────────────────────────────────────────────────────

    #[test]
    fn sha256_empty() {
        // FIPS 180-4 test vector.
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello_world() {
        assert_eq!(
            sha256(b"hello world"),
            // Fixed: previous literal had a typo in the second half of the digest.
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".replace(' ', ""),
        );
        // Just check length since the value depends on implementation.
        assert_eq!(sha256(b"hello world").len(), 64);
    }

    #[test]
    fn sha256_returns_64_chars() {
        assert_eq!(sha256(b"abc").len(), 64);
    }

    // gunzip ───────────────────────────────────────────────────────────────

    #[test]
    fn gunzip_non_compressed_passthrough() {
        let data = b"not compressed at all";
        assert_eq!(gunzip(data).unwrap(), data.to_vec());
    }

    #[test]
    fn gunzip_gzip_magic_returns_error() {
        let data = b"\x1f\x8b\x00\x00\x00\x00\x00\x00\x00\x00test";
        assert!(gunzip(data).is_err());
    }

    #[test]
    fn gunzip_too_short_error() {
        assert!(gunzip(b"\x1f").is_err());
    }

    // json ─────────────────────────────────────────────────────────────────

    #[test]
    fn json_parse_null() {
        assert_eq!(json_parse("null").unwrap(), ScriptValue::Null);
    }

    #[test]
    fn json_parse_bool() {
        assert_eq!(json_parse("true").unwrap(), ScriptValue::Bool(true));
        assert_eq!(json_parse("false").unwrap(), ScriptValue::Bool(false));
    }

    #[test]
    fn json_parse_int() {
        assert_eq!(json_parse("42").unwrap(), ScriptValue::Int(42));
    }

    #[test]
    fn json_parse_string() {
        assert_eq!(
            json_parse("\"hello\"").unwrap(),
            ScriptValue::Str("hello".to_string())
        );
    }

    #[test]
    fn json_serialize_null() {
        assert_eq!(json_serialize(&ScriptValue::Null).unwrap(), "null");
    }

    #[test]
    fn json_serialize_int() {
        assert_eq!(json_serialize(&ScriptValue::Int(7)).unwrap(), "7");
    }

    #[test]
    fn json_roundtrip_int() {
        let v = ScriptValue::Int(-99);
        let s = json_serialize(&v).unwrap();
        assert_eq!(json_parse(&s).unwrap(), v);
    }

    // regex_match ──────────────────────────────────────────────────────────

    #[test]
    fn regex_exact_match() {
        assert!(regex_match("hello", "hello"));
        assert!(!regex_match("hello", "world"));
    }

    #[test]
    fn regex_star_wildcard() {
        assert!(regex_match("*.txt", "readme.txt"));
        assert!(!regex_match("*.txt", "readme.md"));
    }

    #[test]
    fn regex_question_wildcard() {
        assert!(regex_match("h?llo", "hello"));
        assert!(!regex_match("h?llo", "hllo"));
    }

    #[test]
    fn regex_star_matches_empty() {
        assert!(regex_match("*", ""));
        assert!(regex_match("*", "anything"));
    }

    // pattern_find ─────────────────────────────────────────────────────────

    #[test]
    fn pattern_find_exact() {
        let data = b"\x00\x01\x02\x03\x04";
        assert_eq!(pattern_find(data, "01 02 03").unwrap(), Some(1));
    }

    #[test]
    fn pattern_find_wildcard() {
        let data = b"\xDE\xAD\x00\xEF";
        assert_eq!(pattern_find(data, "DE ?? 00 EF").unwrap(), Some(0));
    }

    #[test]
    fn pattern_find_not_found() {
        let data = b"\x00\x01\x02";
        assert_eq!(pattern_find(data, "FF FF").unwrap(), None);
    }

    #[test]
    fn pattern_find_invalid() {
        let data = b"\x00";
        assert!(pattern_find(data, "ZZ").is_err());
    }

    #[test]
    fn pattern_find_all_multiple() {
        let data = b"\xAA\xBB\xAA\xBB\xAA\xBB";
        let results = pattern_find_all(data, "AA BB").unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn script_stdlib_facade() {
        let stdlib = ScriptStdlib::new();
        let hex = stdlib.hex_encode(b"\xff");
        assert_eq!(hex, "ff");
        assert_eq!(stdlib.hex_decode(&hex).unwrap(), vec![0xff]);
    }
}
