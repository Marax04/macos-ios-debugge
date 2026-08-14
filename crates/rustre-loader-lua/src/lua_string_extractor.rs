// lua_string_extractor.rs — Extract string constants from Lua/LuaJIT bytecode.
// Collects all LOADK with string type, UTF-8 validates, applies interesting-string
// heuristics (URLs, paths, format strings, API names, crypto constants, etc.)

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── String category ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCategory {
    Url,
    FilePath,
    FormatString,
    ApiName,
    CryptoConstant,
    Base64Like,
    HexString,
    Numeric,
    Printable,
    Binary,
    Empty,
    Identifier,
    Keyword,
}

impl StringCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::FilePath => "filepath",
            Self::FormatString => "format_string",
            Self::ApiName => "api_name",
            Self::CryptoConstant => "crypto_constant",
            Self::Base64Like => "base64_like",
            Self::HexString => "hex_string",
            Self::Numeric => "numeric",
            Self::Printable => "printable",
            Self::Binary => "binary",
            Self::Empty => "empty",
            Self::Identifier => "identifier",
            Self::Keyword => "keyword",
        }
    }
}

// ── String record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub source_proto: u32,
    pub const_index: usize,
    pub categories: Vec<StringCategory>,
    pub is_valid_utf8: bool,
    pub byte_len: usize,
    pub char_len: usize,
    pub entropy: f64,
    pub interesting_score: u32,
}

impl ExtractedString {
    #[must_use]
    pub fn new(value: String, source_proto: u32, const_index: usize) -> Self {
        let byte_len = value.len();
        let char_len = value.chars().count();
        let is_valid_utf8 = std::str::from_utf8(value.as_bytes()).is_ok();
        let entropy = shannon_entropy(value.as_bytes());
        let categories = categorize(&value);
        let interesting_score = interest_score(&value, &categories);
        Self {
            value,
            source_proto,
            const_index,
            categories,
            is_valid_utf8,
            byte_len,
            char_len,
            entropy,
            interesting_score,
        }
    }

    #[must_use]
    pub fn has_category(&self, cat: StringCategory) -> bool {
        self.categories.contains(&cat)
    }
}

// ── Entropy ───────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / len;
        entropy -= p * p.log2();
    }
    entropy
}

// ── Categorization ────────────────────────────────────────────────────────────

fn categorize(s: &str) -> Vec<StringCategory> {
    let mut cats = Vec::new();

    if s.is_empty() {
        cats.push(StringCategory::Empty);
        return cats;
    }

    if is_url(s) { cats.push(StringCategory::Url); }
    if is_file_path(s) { cats.push(StringCategory::FilePath); }
    if is_format_string(s) { cats.push(StringCategory::FormatString); }
    if is_api_name(s) { cats.push(StringCategory::ApiName); }
    if is_crypto_constant(s) { cats.push(StringCategory::CryptoConstant); }
    if is_base64_like(s) { cats.push(StringCategory::Base64Like); }
    if is_hex_string(s) { cats.push(StringCategory::HexString); }
    if is_numeric(s) { cats.push(StringCategory::Numeric); }
    if is_identifier(s) { cats.push(StringCategory::Identifier); }
    if is_keyword(s) { cats.push(StringCategory::Keyword); }

    let printable = s.bytes().all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n');
    if printable && cats.is_empty() {
        cats.push(StringCategory::Printable);
    } else if !printable && cats.is_empty() {
        cats.push(StringCategory::Binary);
    }

    cats
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ftp://")
        || s.starts_with("ws://")
        || s.starts_with("wss://")
        || s.starts_with("tcp://")
        || s.starts_with("udp://")
}

fn is_file_path(s: &str) -> bool {
    let sl = s.to_ascii_lowercase();
    let ext = std::path::Path::new(&sl)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.contains("\\\\")
        || (s.len() > 2 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\'))
        || matches!(ext, "lua" | "luac" | "so" | "dll" | "json" | "xml" | "ini" | "cfg")
}

fn is_format_string(s: &str) -> bool {
    s.contains("%s")
        || s.contains("%d")
        || s.contains("%q")
        || s.contains("%i")
        || s.contains("%f")
        || s.contains("%x")
        || s.contains("%X")
        || s.contains("%g")
}

fn is_api_name(s: &str) -> bool {
    // Commonly used API names in Lua C extensions
    const API_PREFIXES: &[&str] = &[
        "luaopen_", "lua_", "luaL_", "luaB_", "socket.", "io.", "os.", "string.",
        "table.", "math.", "coroutine.", "package.", "debug.", "bit.", "ffi.",
    ];
    const WINDOWS_APIS: &[&str] = &[
        "CreateProcess", "OpenProcess", "VirtualAlloc", "WriteProcessMemory",
        "LoadLibrary", "GetProcAddress", "RegOpenKey", "WSAStartup",
    ];
    API_PREFIXES.iter().any(|p| s.starts_with(p))
        || WINDOWS_APIS.iter().any(|a| s.contains(a))
}

fn is_crypto_constant(s: &str) -> bool {
    const CRYPTO_MARKERS: &[&str] = &[
        "AES", "SHA", "MD5", "RSA", "ECDSA", "HMAC", "DES", "3DES", "RC4",
        "ChaCha", "Poly1305", "Blake2", "curve25519", "secp256k1",
        "-----BEGIN", "-----END",
    ];
    CRYPTO_MARKERS.iter().any(|m| s.contains(m))
}

fn is_base64_like(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    let base64_chars: HashSet<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".iter().copied().collect();
    let ratio = f64::from(u32::try_from(s.bytes().filter(|b| base64_chars.contains(b)).count()).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(s.len()).unwrap_or(u32::MAX));
    ratio > 0.95 && s.len().is_multiple_of(4)
}

fn is_hex_string(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    trimmed.len() >= 8 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'+' || b == b'e' || b == b'E')
}

fn is_identifier(s: &str) -> bool {
    if s.is_empty() { return false; }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    (first.is_alphabetic() || first == '_')
        && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

fn is_keyword(s: &str) -> bool {
    const LUA_KEYWORDS: &[&str] = &[
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
        "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
        "true", "until", "while",
    ];
    LUA_KEYWORDS.contains(&s)
}

fn interest_score(s: &str, cats: &[StringCategory]) -> u32 {
    let mut score = 0u32;
    for &cat in cats {
        score += match cat {
            StringCategory::Url => 10,
            StringCategory::FilePath => 8,
            StringCategory::ApiName => 9,
            StringCategory::CryptoConstant => 12,
            StringCategory::Base64Like => 7,
            StringCategory::HexString => 6,
            StringCategory::FormatString => 5,
            StringCategory::Identifier => 2,
            StringCategory::Keyword | StringCategory::Empty => 0,
            StringCategory::Numeric | StringCategory::Printable => 1,
            StringCategory::Binary => 3,
        };
    }
    // Bonus for length
    if s.len() > 32 { score += 2; }
    if s.len() > 128 { score += 3; }
    // Bonus for high entropy (suggests encoded data)
    let ent = shannon_entropy(s.as_bytes());
    if ent > 6.0 { score += 5; }
    score
}

// ── Standard Lua (5.x) string extractor ──────────────────────────────────────

/// Extract strings from a standard Lua bytecode proto tree.
/// Assumes you have a slice of (`string`, `proto_id`, `const_idx`) tuples.
pub struct LuaStringExtractor {
    min_length: usize,
    min_score: u32,
    dedup: bool,
}

impl LuaStringExtractor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_length: 2,
            min_score: 0,
            dedup: true,
        }
    }

    #[must_use]
    pub const fn with_min_length(mut self, n: usize) -> Self {
        self.min_length = n;
        self
    }

    #[must_use]
    pub const fn with_min_score(mut self, score: u32) -> Self {
        self.min_score = score;
        self
    }

    #[must_use]
    pub const fn with_dedup(mut self, dedup: bool) -> Self {
        self.dedup = dedup;
        self
    }

    /// Extract strings from a flat list of `(value, proto_id, const_idx)` entries.
    #[must_use]
    pub fn extract_from_raw(
        &self,
        raw: Vec<(String, u32, usize)>,
    ) -> Vec<ExtractedString> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut results: Vec<ExtractedString> = raw
            .into_iter()
            .filter(|(s, _, _)| s.len() >= self.min_length)
            .filter(|(s, _, _)| {
                if self.dedup {
                    seen.insert(s.clone())
                } else {
                    true
                }
            })
            .map(|(s, proto, idx)| ExtractedString::new(s, proto, idx))
            .filter(|e| e.interesting_score >= self.min_score)
            .collect();

        results.sort_by(|a, b| b.interesting_score.cmp(&a.interesting_score));
        results
    }

    /// Extract strings in parallel from a large batch.
    #[must_use]
    pub fn extract_parallel(
        &self,
        raw: Vec<(String, u32, usize)>,
    ) -> Vec<ExtractedString> {
        let min_len = self.min_length;
        let min_score = self.min_score;

        let mut results: Vec<ExtractedString> = raw
            .into_par_iter()
            .filter(|(s, _, _)| s.len() >= min_len)
            .map(|(s, proto, idx)| ExtractedString::new(s, proto, idx))
            .filter(|e| e.interesting_score >= min_score)
            .collect();

        if self.dedup {
            let mut seen = HashSet::new();
            results.retain(|e| seen.insert(e.value.clone()));
        }

        results.sort_by(|a, b| b.interesting_score.cmp(&a.interesting_score));
        results
    }
}

impl Default for LuaStringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ── LuaJIT string extractor ───────────────────────────────────────────────────

/// Extract strings from a `JitDump` (`LuaJIT` bytecode).
#[must_use]
pub fn extract_from_jit_dump(dump: &crate::luajit_loader::JitDump) -> Vec<ExtractedString> {
    use crate::luajit_loader::KgcConst;

    let raw: Vec<(String, u32, usize)> = dump
        .protos
        .iter()
        .flat_map(|proto| {
            proto
                .kgc
                .iter()
                .enumerate()
                .filter_map(|(idx, kgc)| {
                    if let KgcConst::Str(s) = kgc {
                        Some((s.clone(), proto.id, idx))
                    } else {
                        None
                    }
                })
        })
        .collect();

    LuaStringExtractor::new().extract_from_raw(raw)
}

// ── String statistics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringStats {
    pub total: usize,
    pub unique: usize,
    pub by_category: HashMap<String, usize>,
    pub avg_length: f64,
    pub avg_entropy: f64,
    pub top_interesting: Vec<String>,
    pub url_count: usize,
    pub api_count: usize,
    pub crypto_count: usize,
}

impl StringStats {
    #[must_use]
    pub fn compute(strings: &[ExtractedString]) -> Self {
        let total = strings.len();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut url_count = 0usize;
        let mut api_count = 0usize;
        let mut crypto_count = 0usize;

        for s in strings {
            for &cat in &s.categories {
                *by_category.entry(cat.as_str().to_owned()).or_default() += 1;
                match cat {
                    StringCategory::Url => url_count += 1,
                    StringCategory::ApiName => api_count += 1,
                    StringCategory::CryptoConstant => crypto_count += 1,
                    _ => {}
                }
            }
        }

        let avg_length = if total == 0 {
            0.0
        } else {
            strings.iter().map(|s| f64::from(u32::try_from(s.byte_len).unwrap_or(u32::MAX))).sum::<f64>()
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        };
        let avg_entropy = if total == 0 {
            0.0
        } else {
            strings.iter().map(|s| s.entropy).sum::<f64>()
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        };

        let unique: HashSet<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        let mut sorted = strings.to_vec();
        sorted.sort_by(|a, b| b.interesting_score.cmp(&a.interesting_score));
        let top_interesting = sorted
            .iter()
            .take(10)
            .map(|s| s.value.clone())
            .collect();

        Self {
            total,
            unique: unique.len(),
            by_category,
            avg_length,
            avg_entropy,
            top_interesting,
            url_count,
            api_count,
            crypto_count,
        }
    }
}

// ── String filter ─────────────────────────────────────────────────────────────

pub struct StringFilter {
    pub min_length: usize,
    pub max_length: usize,
    pub require_utf8: bool,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub required_categories: Vec<StringCategory>,
    pub forbidden_categories: Vec<StringCategory>,
    pub substring_filter: Vec<String>,
}

impl Default for StringFilter {
    fn default() -> Self {
        Self {
            min_length: 0,
            max_length: usize::MAX,
            require_utf8: false,
            min_entropy: 0.0,
            max_entropy: 8.0,
            required_categories: vec![],
            forbidden_categories: vec![StringCategory::Empty, StringCategory::Keyword],
            substring_filter: vec![],
        }
    }
}

impl StringFilter {
    #[must_use]
    pub fn apply<'a>(&self, strings: &'a [ExtractedString]) -> Vec<&'a ExtractedString> {
        strings
            .iter()
            .filter(|s| {
                s.byte_len >= self.min_length
                    && s.byte_len <= self.max_length
                    && (!self.require_utf8 || s.is_valid_utf8)
                    && s.entropy >= self.min_entropy
                    && s.entropy <= self.max_entropy
                    && self.required_categories.iter().all(|r| s.has_category(*r))
                    && !self.forbidden_categories.iter().any(|f| s.has_category(*f))
                    && (self.substring_filter.is_empty()
                        || self.substring_filter.iter().any(|sub| s.value.contains(sub.as_str())))
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_url() {
        assert!(is_url("https://example.com/api"));
        assert!(!is_url("/local/path"));
    }

    #[test]
    fn test_is_file_path() {
        assert!(is_file_path("/etc/passwd"));
        assert!(is_file_path("./config.lua"));
        assert!(is_file_path("data.json"));
    }

    #[test]
    fn test_is_hex_string() {
        assert!(is_hex_string("DEADBEEFCAFE1234"));
        assert!(!is_hex_string("DEA")); // too short
    }

    #[test]
    fn test_is_base64_like() {
        // Valid base64 padding
        assert!(!is_base64_like("abc=")); // too short
        let b64 = "dGVzdGluZzEyMzQ1Njc4OTAxMjM0NTY3ODk=";
        let _ = is_base64_like(b64); // just ensure no panic
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_zero() {
        let data = [0u8; 100];
        assert!(shannon_entropy(&data).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert!(shannon_entropy(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn test_extracted_string_category() {
        let es = ExtractedString::new("https://evil.c2.com".to_owned(), 0, 0);
        assert!(es.has_category(StringCategory::Url));
    }

    #[test]
    fn test_extractor_dedup() {
        let raw = vec![
            ("hello".to_owned(), 0u32, 0usize),
            ("hello".to_owned(), 1u32, 0usize),
            ("world".to_owned(), 0u32, 1usize),
        ];
        let ext = LuaStringExtractor::new().with_dedup(true);
        let results = ext.extract_from_raw(raw);
        let values: Vec<&str> = results.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(values.iter().filter(|&&v| v == "hello").count(), 1);
    }

    #[test]
    fn test_filter_by_category() {
        let strings = vec![
            ExtractedString::new("https://example.com".to_owned(), 0, 0),
            ExtractedString::new("hello".to_owned(), 0, 1),
        ];
        let filter = StringFilter {
            required_categories: vec![StringCategory::Url],
            ..Default::default()
        };
        let filtered = filter.apply(&strings);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].has_category(StringCategory::Url));
    }

    #[test]
    fn test_is_identifier() {
        assert!(is_identifier("my_func"));
        assert!(is_identifier("_private"));
        assert!(!is_identifier("123abc"));
        assert!(!is_identifier(""));
    }

    #[test]
    fn test_keyword_detection() {
        assert!(is_keyword("if"));
        assert!(is_keyword("return"));
        assert!(!is_keyword("myFunc"));
    }

    #[test]
    fn test_string_stats_empty() {
        let stats = StringStats::compute(&[]);
        assert_eq!(stats.total, 0);
        assert!(stats.avg_length.abs() < f64::EPSILON);
    }
}
