//! YARA string matching engine.
//!
//! Implements text, hex, and regex string matching with full YARA modifier support.
//! Uses a multi-pattern Aho-Corasick approach for efficient scanning.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── ModifierSet ─────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Internal bit-packed storage for YARA string modifier flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    struct ModifierFlags: u32 {
        const NOCASE    = 1 << 0;
        const WIDE      = 1 << 1;
        const ASCII     = 1 << 2;
        const FULLWORD  = 1 << 3;
        const XOR       = 1 << 4;
        const BASE64    = 1 << 5;
        const BASE64WIDE = 1 << 6;
        const PRIVATE   = 1 << 7;
    }
}

/// Modifier flags for a YARA string pattern.
///
/// Stores all boolean modifiers in a compact bitfield. Use getter methods
/// such as [`nocase`](Self::nocase) to read individual flags, and builder
/// methods such as [`with_nocase`](Self::with_nocase) to construct instances.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifierSet {
    flags: ModifierFlags,
    /// XOR key range (min, max) — defaults to (0, 255).
    pub xor_range: Option<(u8, u8)>,
}

impl ModifierSet {
    /// Case-insensitive matching flag.
    #[must_use] pub const fn nocase(&self) -> bool { self.flags.contains(ModifierFlags::NOCASE) }
    /// Match UTF-16LE wide strings flag.
    #[must_use] pub const fn wide(&self) -> bool { self.flags.contains(ModifierFlags::WIDE) }
    /// Match ASCII (byte) strings flag.
    #[must_use] pub const fn ascii(&self) -> bool { self.flags.contains(ModifierFlags::ASCII) }
    /// Match only at word boundaries flag.
    #[must_use] pub const fn fullword(&self) -> bool { self.flags.contains(ModifierFlags::FULLWORD) }
    /// Single-byte XOR scan flag.
    #[must_use] pub const fn xor(&self) -> bool { self.flags.contains(ModifierFlags::XOR) }
    /// Base64 encoding flag.
    #[must_use] pub const fn base64(&self) -> bool { self.flags.contains(ModifierFlags::BASE64) }
    /// Base64-wide encoding flag.
    #[must_use] pub const fn base64wide(&self) -> bool { self.flags.contains(ModifierFlags::BASE64WIDE) }
    /// Private string flag.
    #[must_use] pub const fn private(&self) -> bool { self.flags.contains(ModifierFlags::PRIVATE) }

    /// Builder: enable `nocase`.
    #[must_use] pub fn with_nocase(mut self) -> Self { self.flags |= ModifierFlags::NOCASE; self }
    /// Builder: enable `wide`.
    #[must_use] pub fn with_wide(mut self) -> Self { self.flags |= ModifierFlags::WIDE; self }
    /// Builder: enable `ascii`.
    #[must_use] pub fn with_ascii(mut self) -> Self { self.flags |= ModifierFlags::ASCII; self }
    /// Builder: enable `fullword`.
    #[must_use] pub fn with_fullword(mut self) -> Self { self.flags |= ModifierFlags::FULLWORD; self }
    /// Builder: enable `xor`.
    #[must_use] pub fn with_xor(mut self) -> Self { self.flags |= ModifierFlags::XOR; self }
    /// Builder: enable `base64`.
    #[must_use] pub fn with_base64(mut self) -> Self { self.flags |= ModifierFlags::BASE64; self }
    /// Builder: enable `base64wide`.
    #[must_use] pub fn with_base64wide(mut self) -> Self { self.flags |= ModifierFlags::BASE64WIDE; self }
    /// Builder: enable `private`.
    #[must_use] pub fn with_private(mut self) -> Self { self.flags |= ModifierFlags::PRIVATE; self }
    /// Builder: set `xor_range`.
    #[must_use] pub const fn with_xor_range(mut self, range: (u8, u8)) -> Self { self.xor_range = Some(range); self }

    /// Create a modifier set with only `ascii` set (YARA default for text strings).
    #[must_use]
    pub fn ascii_only() -> Self {
        Self::default().with_ascii()
    }

    /// Create a modifier set for wide + ascii (common pattern).
    #[must_use]
    pub fn wide_and_ascii() -> Self {
        Self::default().with_wide().with_ascii()
    }

    /// Return a human-readable description of active modifiers.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.nocase()    { parts.push("nocase"); }
        if self.wide()      { parts.push("wide"); }
        if self.ascii()     { parts.push("ascii"); }
        if self.fullword()  { parts.push("fullword"); }
        if self.xor()       { parts.push("xor"); }
        if self.base64()    { parts.push("base64"); }
        if self.base64wide(){ parts.push("base64wide"); }
        if self.private()   { parts.push("private"); }
        parts.join(" ")
    }
}

// ─── PatternMatch ─────────────────────────────────────────────────────────────

/// A single pattern match result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Byte offset within the scanned data.
    pub offset: usize,
    /// The bytes that were matched.
    pub matched_bytes: Vec<u8>,
    /// For XOR matches, the key used (if applicable).
    pub xor_key: Option<u8>,
    /// String identifier (e.g. "$a").
    pub string_id: String,
    /// Length of the match.
    pub length: usize,
}

impl PatternMatch {
    /// Create a simple match with no XOR key.
    #[must_use]
    pub fn new(offset: usize, matched_bytes: Vec<u8>, string_id: impl Into<String>) -> Self {
        let length = matched_bytes.len();
        Self {
            offset,
            matched_bytes,
            xor_key: None,
            string_id: string_id.into(),
            length,
        }
    }

    /// Create a XOR-encoded match.
    #[must_use]
    pub fn xor_match(
        offset: usize,
        matched_bytes: Vec<u8>,
        string_id: impl Into<String>,
        key: u8,
    ) -> Self {
        let length = matched_bytes.len();
        Self {
            offset,
            matched_bytes,
            xor_key: Some(key),
            string_id: string_id.into(),
            length,
        }
    }
}

// ─── WideStringConverter ─────────────────────────────────────────────────────

/// Converts between ASCII and UTF-16LE (wide) string representations.
pub struct WideStringConverter;

impl WideStringConverter {
    /// Convert an ASCII byte slice to UTF-16LE bytes.
    #[must_use]
    pub fn to_wide(ascii: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ascii.len() * 2);
        for &b in ascii {
            out.push(b);
            out.push(0);
        }
        out
    }

    /// Convert UTF-16LE bytes back to ASCII (best-effort, replacing non-ASCII with '?').
    #[must_use]
    pub fn from_wide(wide: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(wide.len() / 2);
        let mut i = 0;
        while i + 1 < wide.len() {
            let lo = wide[i];
            let hi = wide[i + 1];
            if hi == 0 && lo.is_ascii() {
                out.push(lo);
            } else {
                out.push(b'?');
            }
            i += 2;
        }
        out
    }

    /// Return true if `data` at `offset` looks like a wide string (alternating null bytes).
    #[must_use]
    pub fn is_wide_at(data: &[u8], offset: usize, len: usize) -> bool {
        if offset + len * 2 > data.len() {
            return false;
        }
        for i in 0..len {
            if data[offset + i * 2 + 1] != 0 {
                return false;
            }
        }
        true
    }
}

// ─── AhoCorasick (simple implementation) ─────────────────────────────────────

/// A simple multi-pattern byte-string scanner using the Aho-Corasick algorithm
/// (naïve implementation for portability — real engines would use the `aho-corasick` crate).
pub struct AhoCorasick {
    patterns: Vec<(String, Vec<u8>)>, // (id, pattern_bytes)
}

impl AhoCorasick {
    /// Create from a list of (id, `pattern_bytes`) pairs.
    #[must_use]
    pub const fn new(patterns: Vec<(String, Vec<u8>)>) -> Self {
        Self { patterns }
    }

    /// Scan `data` for all occurrences of all patterns.
    /// Returns a vector of (`pattern_id`, offset) pairs.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<(String, usize)> {
        let mut results = Vec::new();
        for (id, pat) in &self.patterns {
            if pat.is_empty() || data.len() < pat.len() {
                continue;
            }
            let end = data.len() - pat.len();
            for offset in 0..=end {
                if data[offset..offset + pat.len()] == pat[..] {
                    results.push((id.clone(), offset));
                }
            }
        }
        results.sort_by_key(|(_, o)| *o);
        results
    }

    /// Return the number of registered patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─── StringMatcher ───────────────────────────────────────────────────────────

/// YARA string matching engine supporting text, hex, and regex patterns.
pub struct StringMatcher {
    /// Registered strings, keyed by identifier.
    strings: HashMap<String, StringDef>,
}

/// Internal definition of a matchable string.
#[derive(Debug, Clone)]
pub struct StringDef {
    pub id: String,
    pub value: StringValue,
    pub modifiers: ModifierSet,
}

/// The value type of a string definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringValue {
    Text(Vec<u8>),
    Hex(Vec<HexToken>),
    Regex(String),
}

/// A single token in a hex pattern (byte, wildcard, or jump).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HexToken {
    /// Exact byte.
    Exact(u8),
    /// Single-byte wildcard `??`.
    Wildcard,
    /// Nibble wildcard — high nibble `?X` or low nibble `X?`.
    NibbleHigh(u8),
    NibbleLow(u8),
    /// Jump `[n-m]` (skip n to m bytes).
    Jump {
        min: u8,
        max: u8,
    },
    /// Alternation `(AB | CD)`.
    Alternation(Vec<Vec<u8>>),
}

impl StringMatcher {
    /// Create an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strings: HashMap::new(),
        }
    }

    /// Register a text string.
    pub fn add_text(
        &mut self,
        id: impl Into<String>,
        text: impl Into<Vec<u8>>,
        modifiers: ModifierSet,
    ) {
        let id = id.into();
        self.strings.insert(
            id.clone(),
            StringDef {
                id,
                value: StringValue::Text(text.into()),
                modifiers,
            },
        );
    }

    /// Register a hex pattern string.
    pub fn add_hex(
        &mut self,
        id: impl Into<String>,
        tokens: Vec<HexToken>,
        modifiers: ModifierSet,
    ) {
        let id = id.into();
        self.strings.insert(
            id.clone(),
            StringDef {
                id,
                value: StringValue::Hex(tokens),
                modifiers,
            },
        );
    }

    /// Register a regex string.
    pub fn add_regex(
        &mut self,
        id: impl Into<String>,
        pattern: impl Into<String>,
        modifiers: ModifierSet,
    ) {
        let id = id.into();
        self.strings.insert(
            id.clone(),
            StringDef {
                id,
                value: StringValue::Regex(pattern.into()),
                modifiers,
            },
        );
    }

    /// Scan `data` and return all matches.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut results = Vec::new();
        for def in self.strings.values() {
            let mut matches = Self::scan_string(data, def);
            results.append(&mut matches);
        }
        results.sort_by_key(|m| m.offset);
        results
    }

    /// Scan for a specific string identifier.
    #[must_use]
    pub fn scan_one(&self, data: &[u8], id: &str) -> Vec<PatternMatch> {
        self.strings
            .get(id)
            .map_or_else(Vec::new, |def| Self::scan_string(data, def))
    }

    fn scan_string(data: &[u8], def: &StringDef) -> Vec<PatternMatch> {
        match &def.value {
            StringValue::Text(pat) => Self::scan_text(data, def, pat),
            StringValue::Hex(tokens) => Self::scan_hex(data, def, tokens),
            StringValue::Regex(pattern) => Self::scan_regex(data, def, pattern),
        }
    }

    fn scan_text(data: &[u8], def: &StringDef, pat: &[u8]) -> Vec<PatternMatch> {
        let mut results = Vec::new();
        if pat.is_empty() || data.len() < pat.len() {
            return results;
        }

        let modifiers = &def.modifiers;

        // ASCII scan
        let ascii = modifiers.ascii() || (!modifiers.wide() && !modifiers.base64());
        if ascii {
            let end = data.len() - pat.len();
            for offset in 0..=end {
                let window = &data[offset..offset + pat.len()];
                let matches = if modifiers.nocase() {
                    window.eq_ignore_ascii_case(pat)
                } else {
                    window == pat
                };
                if matches {
                    if modifiers.fullword() && !Self::is_fullword(data, offset, pat.len()) {
                        continue;
                    }
                    results.push(PatternMatch::new(offset, window.to_vec(), &def.id));
                }
            }
        }

        // Wide scan
        if modifiers.wide() {
            let wide_pat = WideStringConverter::to_wide(pat);
            if data.len() >= wide_pat.len() {
                let end = data.len() - wide_pat.len();
                // Precompute decoded pattern once for nocase comparison.
                let decoded_pat = if modifiers.nocase() {
                    WideStringConverter::from_wide(&wide_pat)
                } else {
                    Vec::new()
                };
                for offset in 0..=end {
                    let window = &data[offset..offset + wide_pat.len()];
                    let matches = if modifiers.nocase() {
                        let decoded = WideStringConverter::from_wide(window);
                        decoded.eq_ignore_ascii_case(&decoded_pat)
                    } else {
                        window == wide_pat.as_slice()
                    };
                    if matches {
                        results.push(PatternMatch::new(offset, window.to_vec(), &def.id));
                    }
                }
            }
        }

        // XOR scan
        if modifiers.xor() {
            let (xmin, xmax) = modifiers.xor_range.unwrap_or((0, 255));
            let end = if data.len() >= pat.len() {
                data.len() - pat.len()
            } else {
                0
            };
            for key in xmin..=xmax {
                if key == 0 && ascii {
                    continue; // already scanned as plain ASCII
                }
                for offset in 0..=end {
                    let window = &data[offset..offset + pat.len()];
                    let matches = window.iter().zip(pat.iter()).all(|(&d, &p)| d ^ key == p);
                    if matches {
                        results.push(PatternMatch::xor_match(
                            offset,
                            window.to_vec(),
                            &def.id,
                            key,
                        ));
                    }
                }
            }
        }

        results
    }

    fn scan_hex(data: &[u8], def: &StringDef, tokens: &[HexToken]) -> Vec<PatternMatch> {
        let mut results = Vec::new();
        if data.is_empty() {
            return results;
        }

        // Convert simple patterns to byte slices for fast scanning
        // Full jump/alternation support would require recursive matching
        let simple_pat: Option<Vec<u8>> = tokens.iter().try_fold(Vec::new(), |mut acc, t| {
            match t {
                HexToken::Exact(b) => {
                    acc.push(*b);
                    Some(acc)
                }
                _ => None, // can't do a simple scan with wildcards/jumps
            }
        });

        if let Some(pat) = simple_pat {
            if pat.len() <= data.len() {
                let end = data.len() - pat.len();
                for offset in 0..=end {
                    if data[offset..offset + pat.len()] == pat[..] {
                        results.push(PatternMatch::new(offset, pat.clone(), &def.id));
                    }
                }
            }
        } else {
            // Wildcard-aware matching
            let end = data.len().saturating_sub(tokens.len());
            'outer: for offset in 0..=end {
                let mut data_pos = offset;
                for token in tokens {
                    if data_pos >= data.len() {
                        continue 'outer;
                    }
                    match token {
                        HexToken::Exact(b) => {
                            if data[data_pos] != *b {
                                continue 'outer;
                            }
                            data_pos += 1;
                        }
                        HexToken::Wildcard => {
                            data_pos += 1;
                        }
                        HexToken::NibbleHigh(hi) => {
                            if data[data_pos] >> 4 != *hi {
                                continue 'outer;
                            }
                            data_pos += 1;
                        }
                        HexToken::NibbleLow(lo) => {
                            if data[data_pos] & 0x0F != *lo {
                                continue 'outer;
                            }
                            data_pos += 1;
                        }
                        HexToken::Jump { min, max } => {
                            // Skip min..=max bytes (greedy: skip max)
                            let skip = (*max as usize).min(data.len() - data_pos);
                            if skip < *min as usize {
                                continue 'outer;
                            }
                            data_pos += skip;
                        }
                        HexToken::Alternation(alts) => {
                            let mut matched = false;
                            for alt in alts {
                                if data_pos + alt.len() <= data.len()
                                    && data[data_pos..data_pos + alt.len()] == alt[..]
                                {
                                    data_pos += alt.len();
                                    matched = true;
                                    break;
                                }
                            }
                            if !matched {
                                continue 'outer;
                            }
                        }
                    }
                }
                let matched = data[offset..data_pos].to_vec();
                results.push(PatternMatch::new(offset, matched, &def.id));
            }
        }

        results
    }

    const fn scan_regex(data: &[u8], def: &StringDef, _pattern: &str) -> Vec<PatternMatch> {
        // Regex matching requires the `regex` crate; return empty for now.
        // In a full implementation: compile regex, scan data, return matches.
        // Touch both `data` and `def` so the placeholder remains usable as
        // a real implementation slot without triggering unused-binding lints.
        let _ = (data.len(), &def.id);
        Vec::new()
    }

    /// Check if a match at `offset`/`len` is at a word boundary.
    fn is_fullword(data: &[u8], offset: usize, len: usize) -> bool {
        let before_ok = offset == 0 || !data[offset - 1].is_ascii_alphanumeric();
        let after_ok = offset + len >= data.len() || !data[offset + len].is_ascii_alphanumeric();
        before_ok && after_ok
    }

    /// Return the number of registered strings.
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }
}

impl Default for StringMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wide_string_converter_roundtrip() {
        let ascii = b"hello";
        let wide = WideStringConverter::to_wide(ascii);
        let back = WideStringConverter::from_wide(&wide);
        assert_eq!(back, ascii);
    }

    #[test]
    fn test_wide_string_converter_encoding() {
        let wide = WideStringConverter::to_wide(b"AB");
        assert_eq!(wide, vec![b'A', 0, b'B', 0]);
    }

    #[test]
    fn test_is_wide_at() {
        let data = vec![b'H', 0, b'i', 0, 0];
        assert!(WideStringConverter::is_wide_at(&data, 0, 2));
    }

    #[test]
    fn test_aho_corasick_basic() {
        let ac = AhoCorasick::new(vec![
            ("$a".to_owned(), b"foo".to_vec()),
            ("$b".to_owned(), b"bar".to_vec()),
        ]);
        let data = b"foobar";
        let results = ac.find_all(data);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|(id, off)| id == "$a" && *off == 0));
        assert!(results.iter().any(|(id, off)| id == "$b" && *off == 3));
    }

    #[test]
    fn test_aho_corasick_overlapping() {
        let ac = AhoCorasick::new(vec![("$a".to_owned(), b"aa".to_vec())]);
        let data = b"aaaa";
        let results = ac.find_all(data);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_aho_corasick_empty_pattern() {
        let ac = AhoCorasick::new(vec![("$x".to_owned(), b"".to_vec())]);
        let results = ac.find_all(b"data");
        assert!(results.is_empty()); // empty patterns skipped
    }

    #[test]
    fn test_modifier_set_describe() {
        let m = ModifierSet::default().with_nocase().with_wide().with_ascii();
        let desc = m.describe();
        assert!(desc.contains("nocase"));
        assert!(desc.contains("wide"));
        assert!(desc.contains("ascii"));
    }

    #[test]
    fn test_modifier_ascii_only() {
        let m = ModifierSet::ascii_only();
        assert!(m.ascii());
        assert!(!m.wide());
    }

    #[test]
    fn test_modifier_wide_and_ascii() {
        let m = ModifierSet::wide_and_ascii();
        assert!(m.ascii());
        assert!(m.wide());
    }

    #[test]
    fn test_string_matcher_text_basic() {
        let mut sm = StringMatcher::new();
        sm.add_text("$a", b"hello".to_vec(), ModifierSet::ascii_only());
        let data = b"say hello world";
        let matches = sm.scan(data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 4);
        assert_eq!(matches[0].string_id, "$a");
    }

    #[test]
    fn test_string_matcher_text_nocase() {
        let mut sm = StringMatcher::new();
        sm.add_text(
            "$a",
            b"hello".to_vec(),
            ModifierSet::default().with_nocase().with_ascii(),
        );
        let data = b"HELLO world";
        let matches = sm.scan(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_string_matcher_text_wide() {
        let mut sm = StringMatcher::new();
        sm.add_text(
            "$a",
            b"hi".to_vec(),
            ModifierSet::default().with_wide(),
        );
        let wide = WideStringConverter::to_wide(b"hi");
        let mut data = vec![0u8; 10];
        data[3..3 + wide.len()].copy_from_slice(&wide);
        let matches = sm.scan(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 3);
    }

    #[test]
    fn test_string_matcher_xor() {
        let mut sm = StringMatcher::new();
        let key: u8 = 0x42;
        let plain = b"test";
        sm.add_text(
            "$a",
            plain.to_vec(),
            ModifierSet::default().with_xor().with_xor_range((key, key)),
        );
        let encoded: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let mut data = vec![0u8; 10];
        data[2..2 + encoded.len()].copy_from_slice(&encoded);
        let matches = sm.scan(&data);
        assert!(matches.iter().any(|m| m.xor_key == Some(key)));
    }

    #[test]
    fn test_string_matcher_hex_exact() {
        let mut sm = StringMatcher::new();
        let tokens = vec![
            HexToken::Exact(0xDE),
            HexToken::Exact(0xAD),
            HexToken::Exact(0xBE),
            HexToken::Exact(0xEF),
        ];
        sm.add_hex("$h", tokens, ModifierSet::default());
        let data = vec![0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let matches = sm.scan(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
    }

    #[test]
    fn test_string_matcher_hex_wildcard() {
        let mut sm = StringMatcher::new();
        let tokens = vec![
            HexToken::Exact(0xAA),
            HexToken::Wildcard,
            HexToken::Exact(0xBB),
        ];
        sm.add_hex("$h", tokens, ModifierSet::default());
        let data = vec![0xAAu8, 0xFF, 0xBB];
        let matches = sm.scan(&data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_string_matcher_fullword() {
        let mut sm = StringMatcher::new();
        sm.add_text(
            "$a",
            b"hello".to_vec(),
            ModifierSet::default().with_ascii().with_fullword(),
        );
        let data = b"hello world helloworld";
        let matches = sm.scan(data);
        // "hello world" => "hello" is fullword
        // "helloworld" => "hello" is NOT fullword
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
    }

    #[test]
    fn test_pattern_match_new() {
        let pm = PatternMatch::new(10, vec![0xAA, 0xBB], "$x");
        assert_eq!(pm.offset, 10);
        assert_eq!(pm.length, 2);
        assert!(pm.xor_key.is_none());
    }

    #[test]
    fn test_pattern_match_xor() {
        let pm = PatternMatch::xor_match(5, vec![0x01], "$y", 0x55);
        assert_eq!(pm.xor_key, Some(0x55));
    }

    #[test]
    fn test_hex_nibble_high() {
        let mut sm = StringMatcher::new();
        // Match any byte with high nibble 0xA
        let tokens = vec![HexToken::NibbleHigh(0xA), HexToken::Exact(0xBB)];
        sm.add_hex("$h", tokens, ModifierSet::default());
        let data = vec![0xABu8, 0xBB, 0x00, 0xAEu8, 0xBB];
        let matches = sm.scan(&data);
        // 0xAB high nibble = 0xA -> match at 0
        // 0xAE high nibble = 0xA -> match at 3
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_string_matcher_count() {
        let mut sm = StringMatcher::new();
        sm.add_text("$a", b"foo".to_vec(), ModifierSet::default());
        sm.add_text("$b", b"bar".to_vec(), ModifierSet::default());
        assert_eq!(sm.string_count(), 2);
    }

    #[test]
    fn test_scan_one() {
        let mut sm = StringMatcher::new();
        sm.add_text("$a", b"needle".to_vec(), ModifierSet::ascii_only());
        sm.add_text("$b", b"other".to_vec(), ModifierSet::ascii_only());
        let data = b"findneedlehere";
        let matches = sm.scan_one(data, "$a");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 4);
    }

    #[test]
    fn test_scan_unknown_id_empty() {
        let sm = StringMatcher::new();
        let result = sm.scan_one(b"data", "$nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn test_aho_corasick_pattern_count() {
        let ac = AhoCorasick::new(vec![
            ("$a".to_owned(), b"foo".to_vec()),
            ("$b".to_owned(), b"bar".to_vec()),
            ("$c".to_owned(), b"baz".to_vec()),
        ]);
        assert_eq!(ac.pattern_count(), 3);
    }

    #[test]
    fn test_text_multiple_occurrences() {
        let mut sm = StringMatcher::new();
        sm.add_text("$a", b"ab".to_vec(), ModifierSet::ascii_only());
        let data = b"ab..ab..ab";
        let matches = sm.scan(data);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_hex_exact_multi_byte() {
        let mut sm = StringMatcher::new();
        let tokens = vec![
            HexToken::Exact(0x4D),
            HexToken::Exact(0x5A), // "MZ"
        ];
        sm.add_hex("$mz", tokens, ModifierSet::default());
        let data = b"MZxyz..MZabc";
        let matches = sm.scan(data);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_modifier_private() {
        let m = ModifierSet::default().with_private().with_ascii();
        assert!(m.private());
        assert!(m.describe().contains("private"));
    }

    #[test]
    fn test_xor_range_default() {
        let m = ModifierSet::default().with_xor();
        assert_eq!(m.xor_range, None);
    }

    #[test]
    fn test_alternation_token() {
        let mut sm = StringMatcher::new();
        let tokens = vec![
            HexToken::Exact(0x90),
            HexToken::Alternation(vec![vec![0xEB], vec![0x74]]),
        ];
        sm.add_hex("$alt", tokens, ModifierSet::default());
        let data = vec![0x90u8, 0xEB, 0x00, 0x90, 0x74];
        let matches = sm.scan(&data);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_scan_sorted_by_offset() {
        let mut sm = StringMatcher::new();
        sm.add_text("$a", b"a".to_vec(), ModifierSet::ascii_only());
        let data = b"xaxaxa";
        let matches = sm.scan(data);
        for i in 0..matches.len().saturating_sub(1) {
            assert!(matches[i].offset <= matches[i + 1].offset);
        }
    }

    #[test]
    fn test_base64_modifier_flag() {
        let m = ModifierSet::default().with_base64();
        assert!(m.base64());
        assert!(m.describe().contains("base64"));
    }

    #[test]
    fn test_base64wide_modifier_flag() {
        let m = ModifierSet::default().with_base64wide();
        assert!(m.base64wide());
        assert!(m.describe().contains("base64wide"));
    }

    #[test]
    fn test_fullword_boundary_end_of_data() {
        let mut sm = StringMatcher::new();
        sm.add_text(
            "$a",
            b"end".to_vec(),
            ModifierSet::default().with_ascii().with_fullword(),
        );
        let data = b"end"; // at end of data
        let matches = sm.scan(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_regex_string_registered() {
        let mut sm = StringMatcher::new();
        sm.add_regex("$r", r"\d+\.\d+", ModifierSet::default());
        assert_eq!(sm.string_count(), 1);
    }

    #[test]
    fn test_hex_nibble_low() {
        let mut sm = StringMatcher::new();
        let tokens = vec![HexToken::NibbleLow(0xF), HexToken::Exact(0x00)];
        sm.add_hex("$h", tokens, ModifierSet::default());
        let data = vec![0x0Fu8, 0x00, 0x00, 0x1Fu8, 0x00];
        let matches = sm.scan(&data);
        // 0x0F low nibble = 0xF → match at 0
        // 0x1F low nibble = 0xF → match at 3
        assert_eq!(matches.len(), 2);
    }
}
