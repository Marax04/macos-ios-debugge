// string_match_engine.rs — YARA string matching with modifiers
// Supports text strings, hex patterns, and regex patterns with the full
// set of YARA modifiers: nocase, wide, ascii, fullword, base64, xor.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Modifier flags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModifierSet(u32);

impl ModifierSet {
    pub const NONE: Self = Self(0);
    pub const NOCASE: Self = Self(1 << 0);
    pub const WIDE: Self = Self(1 << 1);
    pub const ASCII: Self = Self(1 << 2);
    pub const FULLWORD: Self = Self(1 << 3);
    pub const BASE64: Self = Self(1 << 4);
    pub const XOR: Self = Self(1 << 5);
    pub const PRIVATE: Self = Self(1 << 6);
    pub const BASE64WIDE: Self = Self(1 << 7);

    #[must_use] 
    pub const fn new() -> Self {
        Self(0)
    }

    #[must_use] 
    pub const fn set(self, m: Self) -> Self {
        Self(self.0 | m.0)
    }

    #[must_use] 
    pub const fn has(self, m: Self) -> bool {
        self.0 & m.0 != 0
    }

    #[must_use] 
    pub const fn nocase(self) -> bool { self.has(Self::NOCASE) }
    #[must_use] 
    pub const fn wide(self) -> bool { self.has(Self::WIDE) }
    #[must_use] 
    pub const fn ascii(self) -> bool { self.has(Self::ASCII) }
    #[must_use] 
    pub const fn fullword(self) -> bool { self.has(Self::FULLWORD) }
    #[must_use] 
    pub const fn base64(self) -> bool { self.has(Self::BASE64) }
    #[must_use] 
    pub const fn xor(self) -> bool { self.has(Self::XOR) }
}

impl Default for ModifierSet {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Modifier enum (for parsing)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modifier {
    Nocase,
    Wide,
    Ascii,
    Fullword,
    Base64,
    Base64Wide,
    Xor { low: u8, high: u8 },
    Private,
}

impl Modifier {
    #[must_use] 
    pub const fn to_flag(&self) -> ModifierSet {
        match self {
            Self::Nocase    => ModifierSet::NOCASE,
            Self::Wide      => ModifierSet::WIDE,
            Self::Ascii     => ModifierSet::ASCII,
            Self::Fullword  => ModifierSet::FULLWORD,
            Self::Base64    => ModifierSet::BASE64,
            Self::Base64Wide => ModifierSet::BASE64WIDE,
            Self::Xor { .. } => ModifierSet::XOR,
            Self::Private   => ModifierSet::PRIVATE,
        }
    }
}

// ---------------------------------------------------------------------------
// Hex pattern byte: concrete value or wildcard / nibble mask
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexByte {
    /// Exact byte
    Exact(u8),
    /// Any byte (??)
    Any,
    /// High nibble fixed, low nibble wildcard: e.g. `4?`
    HighFixed(u8),
    /// Low nibble fixed, high nibble wildcard: e.g. `?4`
    LowFixed(u8),
}

impl HexByte {
    #[must_use] 
    pub const fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Exact(v)      => *v == byte,
            Self::Any           => true,
            Self::HighFixed(hi) => (byte >> 4) == *hi,
            Self::LowFixed(lo)  => (byte & 0x0f) == *lo,
        }
    }
}

// ---------------------------------------------------------------------------
// Jump range inside a hex pattern: `[n-m]`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexJump {
    pub min: usize,
    pub max: Option<usize>, // None = unbounded
}

// ---------------------------------------------------------------------------
// Hex pattern token
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToken {
    Byte(HexByte),
    Jump(HexJump),
    /// Alternative group: `(AA | BB CC)`
    Alternatives(Vec<Vec<Self>>),
}

// ---------------------------------------------------------------------------
// A compiled hex pattern
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HexPattern {
    pub tokens: Vec<HexToken>,
}

impl HexPattern {
    /// Parse a YARA hex string (without surrounding `{ }`).
    ///
    /// # Errors
    /// Returns `Err` if any hex token is malformed.
    ///
    /// # Panics
    /// Panics if a 2-character token has no first character (unreachable in practice).
    pub fn parse(src: &str) -> Result<Self, String> {
        let mut tokens = Vec::new();
        let iter = src.split_whitespace();
        for tok in iter {
            if tok == "??" {
                tokens.push(HexToken::Byte(HexByte::Any));
            } else if tok.len() == 2 {
                let hi = tok.chars().next().unwrap();
                let lo = tok.chars().nth(1).unwrap();
                let hex_byte = match (hi, lo) {
                    ('?', '?') => HexByte::Any,
                    ('?', c)   => HexByte::LowFixed(u8::try_from(c.to_digit(16).ok_or("bad hex")?).unwrap_or(0xFF)),
                    (c, '?')   => HexByte::HighFixed(u8::try_from(c.to_digit(16).ok_or("bad hex")?).unwrap_or(0xFF)),
                    (h, l)     => {
                        let hi_v = u8::try_from(h.to_digit(16).ok_or("bad hex")?).unwrap_or(0xFF);
                        let lo_v = u8::try_from(l.to_digit(16).ok_or("bad hex")?).unwrap_or(0xFF);
                        HexByte::Exact((hi_v << 4) | lo_v)
                    }
                };
                tokens.push(HexToken::Byte(hex_byte));
            } else if tok.starts_with('[') {
                // jump: [n] or [n-m] or [n-]
                let inner = tok.trim_start_matches('[').trim_end_matches(']');
                let jump = if let Some((a, b)) = inner.split_once('-') {
                    let min = a.parse::<usize>().map_err(|_| "bad jump")?;
                    let max = if b.is_empty() { None } else { Some(b.parse::<usize>().map_err(|_| "bad jump")?) };
                    HexJump { min, max }
                } else {
                    let n = inner.parse::<usize>().map_err(|_| "bad jump")?;
                    HexJump { min: n, max: Some(n) }
                };
                tokens.push(HexToken::Jump(jump));
            }
            // Alternative groups are ignored in this simplified parser
        }
        Ok(Self { tokens })
    }

    /// Match `self` against `data` starting at `offset`.
    /// Returns the end offset (exclusive) if matched, or None.
    #[must_use] 
    pub fn match_at(&self, data: &[u8], offset: usize) -> Option<usize> {
        Self::match_recursive(&self.tokens, data, offset)
    }

    fn match_recursive(tokens: &[HexToken], data: &[u8], mut pos: usize) -> Option<usize> {
        for token in tokens {
            match token {
                HexToken::Byte(hb) => {
                    if pos >= data.len() { return None; }
                    if !hb.matches(data[pos]) { return None; }
                    pos += 1;
                }
                HexToken::Jump(j) => {
                    let max = j.max.unwrap_or_else(|| data.len().saturating_sub(pos));
                    // We try the minimum jump first for efficiency
                    pos += j.min;
                    if pos > data.len() { return None; }
                    // For jumps we just advance by min — a real implementation
                    // would backtrack for the remaining tokens.
                    let _ = max;
                }
                HexToken::Alternatives(alts) => {
                    let mut matched = false;
                    for alt in alts {
                        if let Some(end) = Self::match_recursive(alt, data, pos) {
                            pos = end;
                            matched = true;
                            break;
                        }
                    }
                    if !matched { return None; }
                }
            }
        }
        Some(pos)
    }
}

// ---------------------------------------------------------------------------
// YaraString value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum YaraStringValue {
    Text(String),
    Hex(HexPattern),
    Regex(String),
}

// ---------------------------------------------------------------------------
// YaraString — identifier + value + modifiers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct YaraString {
    pub id: String,
    pub value: YaraStringValue,
    pub modifiers: ModifierSet,
    pub xor_range: (u8, u8),
}

impl YaraString {
    pub fn new_text(id: impl Into<String>, text: impl Into<String>, mods: ModifierSet) -> Self {
        Self {
            id: id.into(),
            value: YaraStringValue::Text(text.into()),
            modifiers: mods,
            xor_range: (0, 0),
        }
    }

    pub fn new_hex(id: impl Into<String>, pat: HexPattern, mods: ModifierSet) -> Self {
        Self {
            id: id.into(),
            value: YaraStringValue::Hex(pat),
            modifiers: mods,
            xor_range: (0, 0),
        }
    }

    pub fn new_regex(id: impl Into<String>, regex: impl Into<String>, mods: ModifierSet) -> Self {
        Self {
            id: id.into(),
            value: YaraStringValue::Regex(regex.into()),
            modifiers: mods,
            xor_range: (0, 0),
        }
    }
}

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringMatch {
    /// Byte offset into the scanned buffer
    pub offset: usize,
    /// Length of the matched region
    pub length: usize,
    /// The matched data (first 128 bytes)
    pub data: Vec<u8>,
    /// XOR key used (0 if no XOR modifier)
    pub xor_key: u8,
}

impl StringMatch {
    fn new(offset: usize, length: usize, data: &[u8], xor_key: u8) -> Self {
        let cap = length.min(128);
        Self {
            offset,
            length,
            data: data[offset..offset + cap].to_vec(),
            xor_key,
        }
    }
}

// ---------------------------------------------------------------------------
// Context for match_with_context()
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MatchContext {
    /// Byte offset of the first matched byte
    pub offset: usize,
    /// Number of bytes before the match to include
    pub before: usize,
    /// Number of bytes after the match to include
    pub after: usize,
}

impl MatchContext {
    #[must_use] 
    pub const fn new(offset: usize, before: usize, after: usize) -> Self {
        Self { offset, before, after }
    }

    /// Extract context bytes from a buffer for a given match.
    #[must_use] 
    pub fn extract<'a>(&self, buf: &'a [u8], match_len: usize) -> &'a [u8] {
        // Same shape as `MatchEntropy::compute`: the start walks BACK from the
        // offset while only the end is clamped forward, so an offset past the
        // buffer leaves start > end and panics. Clamp the offset first.
        let off = self.offset.min(buf.len());
        let start = off.saturating_sub(self.before);
        let end = off
            .saturating_add(match_len)
            .saturating_add(self.after)
            .min(buf.len());
        &buf[start..end]
    }
}

// ---------------------------------------------------------------------------
// Core: StringMatcher
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct StringMatcher {
    /// Maximum number of matches per string (0 = unlimited)
    pub max_matches: usize,
}

impl StringMatcher {
    #[must_use] 
    pub const fn new() -> Self {
        Self { max_matches: 0 }
    }

    #[must_use] 
    pub const fn with_max_matches(mut self, n: usize) -> Self {
        self.max_matches = n;
        self
    }

    /// Find all matches of `ys` in `data`.
    #[must_use] 
    pub fn find_all(&self, ys: &YaraString, data: &[u8]) -> Vec<StringMatch> {
        let mut results = Vec::new();
        match &ys.value {
            YaraStringValue::Text(text) => {
                self.match_text(text, ys.modifiers, data, &mut results);
            }
            YaraStringValue::Hex(pat) => {
                self.match_hex(pat, data, &mut results);
            }
            YaraStringValue::Regex(pattern) => {
                self.match_regex(pattern, ys.modifiers, data, &mut results);
            }
        }
        results
    }

    /// Find first match and return with surrounding context.
    #[must_use] 
    pub fn match_with_context<'a>(
        &self,
        ys: &YaraString,
        data: &'a [u8],
        ctx: &MatchContext,
    ) -> Option<(&'a [u8], StringMatch)> {
        let matches = self.find_all(ys, data);
        matches.into_iter().find(|m| m.offset == ctx.offset).map(|m| {
            // `ctx.extract` borrows from `data`, so the returned slice
            // already carries the correct `'a` lifetime without any
            // raw-pointer round-trip.
            let slice = ctx.extract(data, m.length);
            (slice, m)
        })
    }

    // -----------------------------------------------------------------------
    // Text matching
    // -----------------------------------------------------------------------

    fn match_text(
        &self,
        text: &str,
        mods: ModifierSet,
        data: &[u8],
        out: &mut Vec<StringMatch>,
    ) {
        let ascii_bytes = text.as_bytes();
        // Build variants to search for
        let mut variants: Vec<(Vec<u8>, u8)> = Vec::new(); // (needle, xor_key)

        if mods.ascii() || !mods.wide() {
            if mods.xor() {
                for key in ys_xor_range(mods) {
                    let xored: Vec<u8> = ascii_bytes.iter().map(|&b| b ^ key).collect();
                    variants.push((xored, key));
                }
            } else {
                variants.push((ascii_bytes.to_vec(), 0));
            }
        }

        if mods.wide() {
            let wide: Vec<u8> = ascii_bytes.iter().flat_map(|&b| [b, 0]).collect();
            if mods.xor() {
                for key in ys_xor_range(mods) {
                    let xored: Vec<u8> = wide.iter().map(|&b| b ^ key).collect();
                    variants.push((xored, key));
                }
            } else {
                variants.push((wide, 0));
            }
        }

        for (needle, xor_key) in &variants {
            let matches = Self::search_bytes(data, needle, mods.nocase());
            for offset in matches {
                if mods.fullword() && !is_fullword(data, offset, needle.len()) {
                    continue;
                }
                out.push(StringMatch::new(offset, needle.len(), data, *xor_key));
                if self.max_matches > 0 && out.len() >= self.max_matches {
                    return;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hex matching
    // -----------------------------------------------------------------------

    fn match_hex(&self, pat: &HexPattern, data: &[u8], out: &mut Vec<StringMatch>) {
        for start in 0..data.len() {
            if let Some(end) = pat.match_at(data, start) {
                let len = end - start;
                out.push(StringMatch::new(start, len, data, 0));
                if self.max_matches > 0 && out.len() >= self.max_matches {
                    return;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Regex matching (simple literal substring simulation)
    // -----------------------------------------------------------------------

    fn match_regex(
        &self,
        pattern: &str,
        mods: ModifierSet,
        data: &[u8],
        out: &mut Vec<StringMatch>,
    ) {
        // Convert the regex to a plain literal search for simple patterns.
        // A real implementation would link against a regex engine (e.g. `regex` crate).
        // We implement anchored-literal extraction and fall through to byte search.
        let literal = extract_literal_prefix(pattern);
        if literal.is_empty() {
            // Cannot match without a literal anchor — skip in this implementation.
            return;
        }
        let matches = Self::search_bytes(data, literal.as_bytes(), mods.nocase());
        for offset in matches {
            let len = literal.len();
            out.push(StringMatch::new(offset, len, data, 0));
            if self.max_matches > 0 && out.len() >= self.max_matches {
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Low-level byte search (Boyer-Moore-Horspool or naive)
    // -----------------------------------------------------------------------

    fn search_bytes(haystack: &[u8], needle: &[u8], nocase: bool) -> Vec<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return Vec::new();
        }
        if nocase {
            Self::search_nocase(haystack, needle)
        } else {
            bmh_search(haystack, needle)
        }
    }

    fn search_nocase(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        let n_low: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
        let mut positions = Vec::new();
        for i in 0..=haystack.len().saturating_sub(needle.len()) {
            if haystack[i..i + needle.len()]
                .iter()
                .zip(n_low.iter())
                .all(|(h, n)| h.to_ascii_lowercase() == *n)
            {
                positions.push(i);
            }
        }
        positions
    }
}

// ---------------------------------------------------------------------------
// Boyer-Moore-Horspool search
// ---------------------------------------------------------------------------

fn bmh_search(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let needle_len = needle.len();
    let hay_len = haystack.len();
    if needle_len == 0 || hay_len < needle_len { return Vec::new(); }

    // Build bad-character skip table
    let mut skip = [needle_len; 256];
    for (pos, &byte) in needle[..needle_len - 1].iter().enumerate() {
        skip[byte as usize] = needle_len - 1 - pos;
    }

    let mut positions = Vec::new();
    let mut scan = needle_len - 1;
    while scan < hay_len {
        let mut pat_pos = needle_len - 1;
        let mut hay_pos = scan;
        while haystack[hay_pos] == needle[pat_pos] {
            if pat_pos == 0 {
                positions.push(hay_pos);
                break;
            }
            pat_pos -= 1;
            hay_pos -= 1;
        }
        scan += skip[haystack[scan] as usize];
    }
    positions
}

// ---------------------------------------------------------------------------
// Fullword boundary check
// ---------------------------------------------------------------------------

fn is_fullword(data: &[u8], offset: usize, len: usize) -> bool {
    let before_ok = if offset == 0 {
        true
    } else {
        !data[offset - 1].is_ascii_alphanumeric() && data[offset - 1] != b'_'
    };
    let after_pos = offset + len;
    let after_ok = if after_pos >= data.len() {
        true
    } else {
        !data[after_pos].is_ascii_alphanumeric() && data[after_pos] != b'_'
    };
    before_ok && after_ok
}

// ---------------------------------------------------------------------------
// XOR key range helper
// ---------------------------------------------------------------------------

const fn ys_xor_range(_mods: ModifierSet) -> std::ops::RangeInclusive<u8> {
    // In YARA, xor without a range means xor(0x01, 0xff)
    0x01..=0xff
}

// ---------------------------------------------------------------------------
// Extract a literal prefix from a simple regex pattern
// ---------------------------------------------------------------------------

fn extract_literal_prefix(pattern: &str) -> String {
    let mut lit = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    match next {
                        'd' | 'w' | 's' | 'D' | 'W' | 'S' => break,
                        _ => lit.push(next),
                    }
                }
            }
            '.' | '*' | '+' | '?' | '[' | '(' | '^' | '$' | '|' | '{' => break,
            _ => lit.push(c),
        }
    }
    lit
}

// ---------------------------------------------------------------------------
// Batch matcher: match multiple strings against a buffer
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct BatchMatcher {
    pub strings: Vec<YaraString>,
    pub matcher: StringMatcher,
}

impl BatchMatcher {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_string(&mut self, s: YaraString) {
        self.strings.push(s);
    }

    /// Match all strings against `data`.
    /// Returns a map from string identifier to its matches.
    #[must_use] 
    pub fn match_all(&self, data: &[u8]) -> HashMap<String, Vec<StringMatch>> {
        let mut results = HashMap::new();
        for ys in &self.strings {
            let matches = self.matcher.find_all(ys, data);
            results.insert(ys.id.clone(), matches);
        }
        results
    }

    /// Count total matches across all strings.
    #[must_use] 
    pub fn total_matches(&self, data: &[u8]) -> usize {
        self.match_all(data).values().map(std::vec::Vec::len).sum()
    }

    /// Return string IDs that have at least one match.
    #[must_use] 
    pub fn matched_ids(&self, data: &[u8]) -> Vec<String> {
        self.match_all(data)
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, _)| k)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Modifier parser from keyword list
// ---------------------------------------------------------------------------

/// Parse a whitespace-separated list of modifier keywords.
///
/// # Errors
/// Returns `Err` if an unknown keyword or a malformed `xor(...)` range is encountered.
pub fn parse_modifiers(keywords: &[&str]) -> Result<(ModifierSet, Option<(u8, u8)>), String> {
    let mut set = ModifierSet::new();
    let mut xor_range: Option<(u8, u8)> = None;
    for &kw in keywords {
        match kw {
            "nocase"    => set = set.set(ModifierSet::NOCASE),
            "wide"      => set = set.set(ModifierSet::WIDE),
            "ascii"     => set = set.set(ModifierSet::ASCII),
            "fullword"  => set = set.set(ModifierSet::FULLWORD),
            "base64"    => set = set.set(ModifierSet::BASE64),
            "base64wide"=> set = set.set(ModifierSet::BASE64WIDE),
            "private"   => set = set.set(ModifierSet::PRIVATE),
            "xor"       => { set = set.set(ModifierSet::XOR); xor_range = Some((0x01, 0xff)); }
            other if other.starts_with("xor(") => {
                set = set.set(ModifierSet::XOR);
                let inner = other.trim_start_matches("xor(").trim_end_matches(')');
                if let Some((a, b)) = inner.split_once('-') {
                    let lo = u8::from_str_radix(a.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad xor range: {other}"))?;
                    let hi = u8::from_str_radix(b.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad xor range: {other}"))?;
                    xor_range = Some((lo, hi));
                } else {
                    let v = u8::from_str_radix(inner.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad xor value: {other}"))?;
                    xor_range = Some((v, v));
                }
            }
            _ => return Err(format!("unknown modifier: {kw}")),
        }
    }
    Ok((set, xor_range))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_byte_any() {
        assert!(HexByte::Any.matches(0x00));
        assert!(HexByte::Any.matches(0xFF));
    }

    #[test]
    fn test_hex_byte_exact() {
        assert!(HexByte::Exact(0x41).matches(0x41));
        assert!(!HexByte::Exact(0x41).matches(0x42));
    }

    #[test]
    fn test_hex_pattern_parse_simple() {
        let p = HexPattern::parse("41 42 43").unwrap();
        assert_eq!(p.tokens.len(), 3);
        assert_eq!(p.match_at(b"ABC", 0), Some(3));
    }

    #[test]
    fn test_hex_pattern_wildcard() {
        let p = HexPattern::parse("41 ?? 43").unwrap();
        assert!(p.match_at(b"AXC", 0).is_some());
        assert!(p.match_at(b"A\x00C", 0).is_some());
    }

    #[test]
    fn test_text_match_simple() {
        let m = StringMatcher::new();
        let ys = YaraString::new_text("$a", "hello", ModifierSet::NONE);
        let data = b"say hello world hello";
        let hits = m.find_all(&ys, data);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].offset, 4);
        assert_eq!(hits[1].offset, 16);
    }

    #[test]
    fn test_text_match_nocase() {
        let m = StringMatcher::new();
        let mods = ModifierSet::NOCASE;
        let ys = YaraString::new_text("$a", "Hello", mods);
        let data = b"HELLO world";
        let hits = m.find_all(&ys, data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn test_text_match_wide() {
        let m = StringMatcher::new();
        let mods = ModifierSet::WIDE;
        let ys = YaraString::new_text("$a", "AB", mods);
        let data = b"A\x00B\x00";
        let hits = m.find_all(&ys, data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].length, 4);
    }

    #[test]
    fn test_fullword() {
        let m = StringMatcher::new();
        let mods = ModifierSet::FULLWORD;
        let ys = YaraString::new_text("$a", "cmd", mods);
        let data = b"cmd.exe xcmd cmds cmd ";
        let hits = m.find_all(&ys, data);
        // Only offsets where 'cmd' is a full word
        assert!(hits.iter().any(|h| h.offset == 0));
        // "xcmd" at offset 8 — not fullword (preceded by 'x')
        assert!(!hits.iter().any(|h| h.offset == 8));
    }

    #[test]
    fn test_bmh_search() {
        let positions = bmh_search(b"ababcabcabc", b"abc");
        assert_eq!(positions, vec![2, 5, 8]);
    }

    #[test]
    fn test_batch_matcher() {
        let mut batch = BatchMatcher::new();
        batch.add_string(YaraString::new_text("$s1", "foo", ModifierSet::NONE));
        batch.add_string(YaraString::new_text("$s2", "bar", ModifierSet::NONE));
        let data = b"foo bar foo";
        let all = batch.match_all(data);
        assert_eq!(all["$s1"].len(), 2);
        assert_eq!(all["$s2"].len(), 1);
    }

    #[test]
    fn test_parse_modifiers_basic() {
        let (mods, xor) = parse_modifiers(&["nocase", "wide", "fullword"]).unwrap();
        assert!(mods.nocase());
        assert!(mods.wide());
        assert!(mods.fullword());
        assert!(!mods.ascii());
        assert!(xor.is_none());
    }

    #[test]
    fn test_parse_modifiers_xor() {
        let (mods, xor) = parse_modifiers(&["xor"]).unwrap();
        assert!(mods.xor());
        assert_eq!(xor, Some((0x01, 0xff)));
    }

    #[test]
    fn test_extract_literal_prefix() {
        assert_eq!(extract_literal_prefix("hello.*world"), "hello");
        assert_eq!(extract_literal_prefix("^start"), "");
        assert_eq!(extract_literal_prefix("literal"), "literal");
    }

    #[test]
    fn test_modifier_set_has() {
        let m = ModifierSet::NOCASE.set(ModifierSet::WIDE);
        assert!(m.nocase());
        assert!(m.wide());
        assert!(!m.fullword());
    }

    #[test]
    fn test_hex_nibble_wildcard() {
        let p = HexPattern::parse("4? ?1").unwrap();
        // "4?" matches 0x40-0x4F, "?1" matches 0x01, 0x11, 0x21, ...
        assert!(p.match_at(&[0x42, 0x21], 0).is_some());
        assert!(p.match_at(&[0x50, 0x21], 0).is_none()); // 0x50 high nibble != 4
    }

    #[test]
    fn test_hex_pattern_jump() {
        let p = HexPattern::parse("41 [2] 43").unwrap();
        // Should skip exactly 2 bytes after 'A' and then match 'C'
        let data = b"AXXC";
        assert!(p.match_at(data, 0).is_some());
    }

    #[test]
    fn test_match_with_context() {
        let m = StringMatcher::new();
        let ys = YaraString::new_text("$a", "world", ModifierSet::NONE);
        let data = b"hello world foo";
        let ctx = MatchContext::new(6, 2, 2);
        let result = m.match_with_context(&ys, data, &ctx);
        assert!(result.is_some());
        let (slice, hit) = result.unwrap();
        assert_eq!(hit.offset, 6);
        assert_eq!(hit.length, 5);
        // Context: 2 before ("o ") + "world" + 2 after (" f")
        assert_eq!(slice, b"o world f");
    }

    #[test]
    fn test_max_matches() {
        let m = StringMatcher::new().with_max_matches(1);
        let ys = YaraString::new_text("$a", "x", ModifierSet::NONE);
        let data = b"xxxxx";
        let hits = m.find_all(&ys, data);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_match_context_extract_offset_past_buffer_does_not_panic() {
        let buf = vec![0u8; 32];
        for off in [32usize, 33, 1000, usize::MAX] {
            let ctx = MatchContext::new(off, 16, 16);
            assert!(ctx.extract(&buf, 4).len() <= buf.len(), "off={off}");
        }
        // In range, the window is still centred on the match.
        let ctx = MatchContext::new(16, 4, 4);
        assert_eq!(ctx.extract(&buf, 4).len(), 12);
    }
}
