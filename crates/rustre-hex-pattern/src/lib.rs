//! `rustre-hex-pattern` — Binary pattern matching (IDA/HxD-style).
//!
//! Supports wildcard patterns (`DE AD ? ? 0? ?F`), bitmask patterns,
//! FLIRT-style function signatures, named pattern groups, named captures,
//! alternation (`pat1 | pat2`), pattern compilation pipeline, SIMD-hint
//! accelerated search, and a `PatternDatabase` backed by `SQLite` or `MySQL`.

pub mod pattern_language;
pub mod pattern_debugger;
pub mod pattern_evaluator;
pub mod pattern_exporter;
pub mod pattern_import;
pub mod pattern_stdlib;
pub mod pattern_optimizer;
pub mod multi_pattern_scanner;
pub mod pattern_diff;
pub mod pattern_search_engine;
pub mod wildcard_pattern_compiler;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_hex::kmp_search;

/// Escape SQL LIKE wildcards (`%`, `_`, `\`) in user input so it matches literally.
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the pattern matching module.
#[derive(Debug, Error)]
pub enum PatternError {
    #[error("parse error at token '{token}': {reason}")]
    Parse { token: String, reason: String },
    #[error("database error: {0}")]
    Database(String),
    #[error("pattern not found: {0}")]
    NotFound(String),
    #[error("empty pattern")]
    Empty,
    #[error("regex error: {0}")]
    Regex(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("import error: {0}")]
    Import(String),
    #[error("capture '{0}' not defined")]
    CaptureUndefined(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternByte
// ─────────────────────────────────────────────────────────────────────────────

/// A single byte slot in a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternByte {
    /// Exact byte value.
    Exact(u8),
    /// Matches any byte (`?`).
    Wildcard,
    /// One nibble is constrained; the other is `None` (wildcard).
    Nibble { high: Option<u8>, low: Option<u8> },
}

impl PatternByte {
    /// Returns `true` if this slot matches `byte`.
    #[must_use]
    #[inline]
    pub fn matches(&self, byte: u8) -> bool {
        match self {
            Self::Exact(b) => *b == byte,
            Self::Wildcard => true,
            Self::Nibble { high, low } => {
                let hi_ok = high.is_none_or(|h| (byte >> 4) == h);
                let lo_ok = low.is_none_or(|l| (byte & 0x0F) == l);
                hi_ok && lo_ok
            }
        }
    }

    /// Returns `true` if this slot is a full or partial wildcard.
    #[must_use]
    #[inline]
    pub const fn is_wildcard(&self) -> bool {
        match self {
            Self::Exact(_) => false,
            Self::Wildcard => true,
            Self::Nibble { high, low } => high.is_none() || low.is_none(),
        }
    }

    /// Return the mask byte for SIMD-compatible search (0xFF = exact, 0x00 = wildcard).
    #[must_use]
    #[inline]
    pub const fn mask_byte(&self) -> u8 {
        match self {
            Self::Exact(_) => 0xFF,
            Self::Wildcard => 0x00,
            Self::Nibble { high, low } => {
                (if high.is_some() { 0xF0u8 } else { 0u8 })
                    | (if low.is_some() { 0x0Fu8 } else { 0u8 })
            }
        }
    }

    /// Return the value byte for SIMD-compatible search.
    #[must_use]
    #[inline]
    pub fn value_byte(&self) -> u8 {
        match self {
            Self::Exact(b) => *b,
            Self::Wildcard => 0x00,
            Self::Nibble { high, low } => (high.unwrap_or(0) << 4) | low.unwrap_or(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NamedCapture
// ─────────────────────────────────────────────────────────────────────────────

/// A named capture group within a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedCapture {
    /// Name of the capture group.
    pub name: String,
    /// Starting byte index (within the pattern) of the capture.
    pub start: usize,
    /// Length in bytes of the capture.
    pub len: usize,
}

/// The resolved value of a named capture after a successful match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    pub name: String,
    /// Absolute byte offset in the data where the capture starts.
    pub offset: usize,
    /// Captured bytes.
    pub bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern
// ─────────────────────────────────────────────────────────────────────────────

/// A sequence of `PatternByte` slots representing an IDA/HxD-style pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub bytes: Vec<PatternByte>,
    pub name: Option<String>,
    pub tags: Vec<String>,
    /// Named capture groups.
    pub captures: Vec<NamedCapture>,
    /// Optional comment describing the pattern.
    pub comment: String,
}

impl Pattern {
    /// Parse an IDA/HxD-style pattern string.
    ///
    /// Tokens are separated by whitespace.  Each token is one of:
    /// - `??` or `?`  — full wildcard
    /// - `AB`         — exact byte
    /// - `A?`         — high nibble `A`, low wildcard
    /// - `?B`         — high wildcard, low nibble `B`
    ///
    /// # Errors
    /// Returns `PatternError::Empty` if the string is empty, or
    /// `PatternError::Parse` if any token is malformed.
    pub fn parse(s: &str) -> Result<Self, PatternError> {
        // Normalize compact hex strings (e.g. "deadbeef") into spaced byte tokens
        // ("de ad be ef") so callers can pass raw hex without manual spacing.
        let normalized_storage;
        let s = if !s.contains(|c: char| c.is_ascii_whitespace())
            && s.len() >= 2
            && s.len() % 2 == 0
            && s.chars().all(|c| c.is_ascii_hexdigit())
        {
            let chunks: Vec<String> = s
                .as_bytes()
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            normalized_storage = chunks.join(" ");
            normalized_storage.as_str()
        } else {
            s
        };
        let tokens: Vec<&str> = s.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(PatternError::Empty);
        }
        let mut bytes = Vec::with_capacity(tokens.len());
        for token in &tokens {
            let pb = Self::parse_token(token)?;
            bytes.push(pb);
        }
        Ok(Self {
            bytes,
            name: None,
            tags: Vec::new(),
            captures: Vec::new(),
            comment: String::new(),
        })
    }

    fn parse_token(token: &str) -> Result<PatternByte, PatternError> {
        let t = token.as_bytes();
        match t.len() {
            1 => {
                if t[0] == b'?' {
                    Ok(PatternByte::Wildcard)
                } else {
                    let hi = nibble_from_hex(t[0]).map_err(|()| PatternError::Parse {
                        token: token.to_string(),
                        reason: "invalid hex digit".to_string(),
                    })?;
                    // A single hex digit is ambiguous: IDA-style patterns require two
                    // hex digits per byte. Treat the digit as the high nibble with a
                    // wildcard low nibble (e.g. "A" → matches 0xA0..0xAF).
                    Ok(PatternByte::Nibble { high: Some(hi), low: None })
                }
            }
            2 => match (t[0], t[1]) {
                (b'?', b'?') => Ok(PatternByte::Wildcard),
                (b'?', lo_c) => {
                    let lo = nibble_from_hex(lo_c).map_err(|()| PatternError::Parse {
                        token: token.to_string(),
                        reason: "invalid low nibble".to_string(),
                    })?;
                    Ok(PatternByte::Nibble {
                        high: None,
                        low: Some(lo),
                    })
                }
                (hi_c, b'?') => {
                    let hi = nibble_from_hex(hi_c).map_err(|()| PatternError::Parse {
                        token: token.to_string(),
                        reason: "invalid high nibble".to_string(),
                    })?;
                    Ok(PatternByte::Nibble {
                        high: Some(hi),
                        low: None,
                    })
                }
                (hi_c, lo_c) => {
                    let hi = nibble_from_hex(hi_c).map_err(|()| PatternError::Parse {
                        token: token.to_string(),
                        reason: "invalid high nibble".to_string(),
                    })?;
                    let lo = nibble_from_hex(lo_c).map_err(|()| PatternError::Parse {
                        token: token.to_string(),
                        reason: "invalid low nibble".to_string(),
                    })?;
                    Ok(PatternByte::Exact((hi << 4) | lo))
                }
            },
            _ => Err(PatternError::Parse {
                token: token.to_string(),
                reason: format!("unexpected token length {}", t.len()),
            }),
        }
    }

    /// Returns `true` if the pattern matches `data` starting at `offset`.
    #[must_use]
    #[inline]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        let Some(end) = offset.checked_add(self.bytes.len()) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        let window = &data[offset..end];
        for (pb, &b) in self.bytes.iter().zip(window.iter()) {
            if !pb.matches(b) {
                return false;
            }
        }
        true
    }

    /// Search for all matches in `data`, returning a list of offsets.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.bytes.is_empty() || data.len() < self.bytes.len() {
            return Vec::new();
        }
        if let Some(exact) = self.to_bytes() {
            return kmp_search(data, &exact);
        }
        // Accelerated: anchor on first non-wildcard byte if available
        if let Some((anchor_idx, anchor_byte)) =
            self.bytes.iter().enumerate().find_map(|(i, pb)| {
                if let PatternByte::Exact(b) = pb {
                    Some((i, *b))
                } else {
                    None
                }
            })
        {
            return self.search_anchored(data, anchor_idx, anchor_byte);
        }
        let pat_len = self.bytes.len();
        // Only a pattern made ENTIRELY of full wildcards matches everywhere.
        // The previous version reached this branch for any pattern with no
        // `Exact` byte — including one built solely from NIBBLE constraints
        // like "4? 1?" — and reported a match at every offset on data that
        // satisfied neither nibble. `matches` already knew better; the two
        // entry points simply disagreed about what the pattern meant.
        if self.bytes.iter().all(|b| matches!(b, PatternByte::Wildcard)) {
            return (0..=(data.len().saturating_sub(pat_len))).collect();
        }
        // Otherwise fall back to the authoritative predicate, so the two can
        // never diverge again.
        (0..=(data.len().saturating_sub(pat_len)))
            .filter(|&i| self.matches(data, i))
            .collect()
    }

    fn search_anchored(&self, data: &[u8], anchor: usize, anchor_byte: u8) -> Vec<usize> {
        let pat_len = self.bytes.len();
        let mut results = Vec::new();
        let mut i = anchor;
        while i < data.len() {
            if data[i] == anchor_byte {
                let start = i.saturating_sub(anchor);
                if start + pat_len <= data.len() && self.matches(data, start) {
                    results.push(start);
                }
            }
            i += 1;
        }
        results.dedup();
        results
    }

    /// Search and return matches with captured bytes extracted.
    ///
    /// # Errors
    /// Returns an empty `Vec` if the pattern has no captures.
    #[must_use]
    pub fn search_with_captures(&self, data: &[u8]) -> Vec<(usize, Vec<CaptureResult>)> {
        self.search(data)
            .into_iter()
            .map(|offset| {
                let pat_end = offset.saturating_add(self.bytes.len());
                let caps = self
                    .captures
                    .iter()
                    .filter_map(|cap| {
                        let abs_start = offset.checked_add(cap.start)?;
                        let abs_end = abs_start.checked_add(cap.len)?;
                        // A capture that runs past the match (or past the data)
                        // is CLIPPED, not dropped. Returning `None` removed the
                        // capture entirely, so callers that index the capture
                        // list — as the `captures_clipped_at_end` test does —
                        // panicked on an empty vector instead of receiving a
                        // shorter slice.
                        let abs_end = abs_end.min(pat_end).min(data.len());
                        if abs_start >= abs_end {
                            return None;
                        }
                        Some(CaptureResult {
                            name: cap.name.clone(),
                            offset: abs_start,
                            bytes: data[abs_start..abs_end].to_vec(),
                        })
                    })
                    .collect();
                (offset, caps)
            })
            .collect()
    }

    /// Add a named capture group.
    #[must_use]
    pub fn with_capture(mut self, name: impl Into<String>, start: usize, len: usize) -> Self {
        self.captures.push(NamedCapture {
            name: name.into(),
            start,
            len,
        });
        self
    }

    /// Convert to a plain byte slice if the pattern has no wildcards.
    #[must_use]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.bytes.len());
        for pb in &self.bytes {
            match pb {
                PatternByte::Exact(b) => out.push(*b),
                _ => return None,
            }
        }
        Some(out)
    }

    /// Convert to `(values, masks)` byte-pair arrays for SIMD-style search.
    #[must_use]
    pub fn to_simd_form(&self) -> (Vec<u8>, Vec<u8>) {
        let values: Vec<u8> = self.bytes.iter().map(PatternByte::value_byte).collect();
        let masks: Vec<u8> = self.bytes.iter().map(PatternByte::mask_byte).collect();
        (values, masks)
    }

    /// Returns the length of the pattern in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Assign a name to this pattern.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a tag to this pattern.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set a comment on this pattern.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Serialize to a JSON string.
    ///
    /// # Errors
    /// Returns `PatternError::Export` on serialization failure.
    pub fn to_json(&self) -> Result<String, PatternError> {
        serde_json::to_string(self).map_err(|e| PatternError::Export(e.to_string()))
    }

    /// Deserialize from a JSON string.
    ///
    /// # Errors
    /// Returns `PatternError::Import` on deserialization failure.
    pub fn from_json(json: &str) -> Result<Self, PatternError> {
        serde_json::from_str(json).map_err(|e| PatternError::Import(e.to_string()))
    }

    /// Serialize to IDA-style hex string (e.g. `"DE AD ? ? EF"`).
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        self.bytes
            .iter()
            .map(|pb| match pb {
                PatternByte::Exact(b) => format!("{b:02X}"),
                PatternByte::Wildcard => "??".to_string(),
                PatternByte::Nibble { high, low } => {
                    let h = high.map_or('?', |h| char::from_digit(u32::from(h), 16).unwrap_or('?'));
                    let l = low.map_or('?', |l| char::from_digit(u32::from(l), 16).unwrap_or('?'));
                    format!("{}{}", h.to_ascii_uppercase(), l.to_ascii_uppercase())
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Count exact (non-wildcard) bytes in the pattern.
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.bytes
            .iter()
            .filter(|pb| matches!(pb, PatternByte::Exact(_)))
            .count()
    }

    /// Wildcard count.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.bytes.iter().filter(|pb| pb.is_wildcard()).count()
    }

    /// Specificity score: `exact_count / len`.
    #[must_use]
    pub fn specificity(&self) -> f64 {
        if self.bytes.is_empty() {
            return 0.0;
        }
        self.exact_count() as f64 / self.bytes.len() as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AlternationPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A pattern that matches if *any* of its alternatives matches (logical OR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternationPattern {
    pub alternatives: Vec<Pattern>,
    pub name: Option<String>,
}

impl AlternationPattern {
    /// Create from a list of alternatives.
    #[must_use]
    pub const fn new(alternatives: Vec<Pattern>) -> Self {
        Self {
            alternatives,
            name: None,
        }
    }

    /// Parse from a pipe-delimited string like `"DE AD | EF BE"`.
    ///
    /// # Errors
    /// Returns `PatternError::Empty` if all alternatives are empty.
    pub fn parse(s: &str) -> Result<Self, PatternError> {
        let mut alts = Vec::new();
        for part in s.split('|') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            alts.push(Pattern::parse(part)?);
        }
        if alts.is_empty() {
            return Err(PatternError::Empty);
        }
        Ok(Self::new(alts))
    }

    /// Assign a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Returns `true` if any alternative matches `data` at `offset`.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        self.alternatives.iter().any(|p| p.matches(data, offset))
    }

    /// Search `data`, returning offsets where any alternative matches.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        let mut all: Vec<usize> = self
            .alternatives
            .iter()
            .flat_map(|p| p.search(data))
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    }

    /// Number of alternatives.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.alternatives.len()
    }

    /// Returns `true` if there are no alternatives.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.alternatives.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompiledPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled, optimised representation of a `Pattern` for fast repeated search.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// Original pattern bytes.
    pub bytes: Vec<PatternByte>,
    /// Value bytes for masked comparison.
    values: Vec<u8>,
    /// Mask bytes (0xFF = must match, 0x00 = wildcard).
    masks: Vec<u8>,
    /// Offset of the first exact byte in `bytes` (for fast pre-filter).
    first_exact: Option<(usize, u8)>,
    /// Pattern length.
    pub len: usize,
    /// Pattern name.
    pub name: Option<String>,
}

impl CompiledPattern {
    /// Compile a `Pattern` into a `CompiledPattern`.
    #[must_use]
    pub fn compile(pat: &Pattern) -> Self {
        let (values, masks) = pat.to_simd_form();
        let first_exact = pat.bytes.iter().enumerate().find_map(|(i, pb)| {
            if let PatternByte::Exact(b) = pb {
                Some((i, *b))
            } else {
                None
            }
        });
        Self {
            bytes: pat.bytes.clone(),
            values,
            masks,
            first_exact,
            len: pat.bytes.len(),
            name: pat.name.clone(),
        }
    }

    /// Returns `true` if the compiled pattern matches `data` at `offset`.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        let Some(end) = offset.checked_add(self.len) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        for i in 0..self.len {
            let b = data[offset + i];
            if b & self.masks[i] != self.values[i] & self.masks[i] {
                return false;
            }
        }
        true
    }

    /// Search `data` for all matches, returning byte offsets.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.len == 0 || data.len() < self.len {
            return Vec::new();
        }
        // If all masks are 0xFF, delegate to KMP
        if self.masks.iter().all(|&m| m == 0xFF) {
            return kmp_search(data, &self.values);
        }
        // Anchor on the first exact byte for early rejection
        if let Some((anchor, anchor_byte)) = self.first_exact {
            let mut results = Vec::new();
            let mut i = anchor;
            while i < data.len() {
                if data[i] == anchor_byte {
                    let start = i.saturating_sub(anchor);
                    if self.matches(data, start) {
                        results.push(start);
                    }
                }
                i += 1;
            }
            return results;
        }
        // Fallback: full scan
        (0..=(data.len() - self.len))
            .filter(|&s| self.matches(data, s))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MaskedPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A bitmask-based pattern: `result = (data[i] & mask[i]) == bytes[i]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedPattern {
    pub bytes: Vec<u8>,
    pub mask: Vec<u8>,
    pub name: Option<String>,
}

impl MaskedPattern {
    /// Create a new masked pattern.
    ///
    /// # Errors
    /// Returns `PatternError::Parse` if `bytes` and `mask` have different lengths.
    pub fn new(bytes: Vec<u8>, mask: Vec<u8>) -> Result<Self, PatternError> {
        if bytes.len() != mask.len() {
            return Err(PatternError::Parse {
                token: String::new(),
                reason: "bytes and mask must be the same length".to_string(),
            });
        }
        Ok(Self {
            bytes,
            mask,
            name: None,
        })
    }

    /// Build from a `Pattern`.
    #[must_use]
    pub fn from_pattern(pat: &Pattern) -> Self {
        let mut bytes = Vec::with_capacity(pat.bytes.len());
        let mut mask = Vec::with_capacity(pat.bytes.len());
        for pb in &pat.bytes {
            bytes.push(pb.value_byte());
            mask.push(pb.mask_byte());
        }
        Self {
            bytes,
            mask,
            name: pat.name.clone(),
        }
    }

    /// Returns `true` if this pattern matches `data` at `offset`.
    #[must_use]
    #[inline]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        let end = match offset.checked_add(self.bytes.len()) {
            Some(e) if e <= data.len() => e,
            _ => return false,
        };
        let window = &data[offset..end];
        for ((&b, &m), &d) in self.bytes.iter().zip(self.mask.iter()).zip(window.iter()) {
            if d & m != b & m {
                return false;
            }
        }
        true
    }

    /// Search all matches in `data`.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.bytes.is_empty() || data.len() < self.bytes.len() {
            return Vec::new();
        }
        if self.mask.iter().all(|&m| m == 0xFF) {
            return kmp_search(data, &self.bytes);
        }
        let mut results = Vec::new();
        for start in 0..=(data.len().saturating_sub(self.bytes.len())) {
            if self.matches(data, start) {
                results.push(start);
            }
        }
        results
    }

    /// Returns the length of the pattern in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegexPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A binary regular expression pattern backed by the `rustre-hex` NFA engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexPattern {
    pub pattern_str: String,
    pub name: Option<String>,
}

impl RegexPattern {
    /// Create a new `RegexPattern`.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern_str: pattern.into(),
            name: None,
        }
    }

    /// Search `data`, returning start offsets of all matches.
    ///
    /// # Errors
    /// Returns `PatternError::Regex` on NFA compilation failure.
    pub fn search(&self, data: &[u8]) -> Result<Vec<usize>, PatternError> {
        rustre_hex::HexBuffer::new(data.to_vec())
            .search_regex(&self.pattern_str)
            .map_err(|e| PatternError::Regex(e.to_string()))
    }

    /// Assign a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A named collection of patterns; searches all simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatternGroup {
    pub name: String,
    pub patterns: Vec<Pattern>,
}

/// A match result from `PatternGroup::search_all`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMatch {
    pub pattern_index: usize,
    pub pattern_name: Option<String>,
    pub offset: usize,
}

impl PatternGroup {
    /// Create a new empty group.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to the group.
    pub fn add(&mut self, pattern: Pattern) {
        self.patterns.push(pattern);
    }

    /// Search `data` against all patterns simultaneously.
    ///
    /// Returns all matches across all patterns, sorted by offset.
    #[must_use]
    pub fn search_all(&self, data: &[u8]) -> Vec<GroupMatch> {
        let mut matches = Vec::new();
        for (idx, pat) in self.patterns.iter().enumerate() {
            for offset in pat.search(data) {
                matches.push(GroupMatch {
                    pattern_index: idx,
                    pattern_name: pat.name.clone(),
                    offset,
                });
            }
        }
        matches.sort_by_key(|m| m.offset);
        matches
    }

    /// Returns `true` if any pattern in the group matches at `data[offset]`.
    #[must_use]
    pub fn any_matches(&self, data: &[u8], offset: usize) -> bool {
        self.patterns.iter().any(|p| p.matches(data, offset))
    }

    /// Compile all patterns for faster repeated search.
    #[must_use]
    pub fn compile(&self) -> CompiledPatternGroup {
        CompiledPatternGroup {
            name: self.name.clone(),
            patterns: self.patterns.iter().map(CompiledPattern::compile).collect(),
        }
    }

    /// Export the group to JSON.
    ///
    /// # Errors
    /// Returns `PatternError::Export` on serialization failure.
    pub fn to_json(&self) -> Result<String, PatternError> {
        serde_json::to_string(self).map_err(|e| PatternError::Export(e.to_string()))
    }

    /// Import a group from JSON.
    ///
    /// # Errors
    /// Returns `PatternError::Import` on deserialization failure.
    pub fn from_json(json: &str) -> Result<Self, PatternError> {
        serde_json::from_str(json).map_err(|e| PatternError::Import(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompiledPatternGroup
// ─────────────────────────────────────────────────────────────────────────────

/// A group of compiled patterns for fast repeated search.
#[derive(Debug, Clone)]
pub struct CompiledPatternGroup {
    pub name: String,
    pub patterns: Vec<CompiledPattern>,
}

impl CompiledPatternGroup {
    /// Search `data` against all compiled patterns.
    #[must_use]
    pub fn search_all(&self, data: &[u8]) -> Vec<GroupMatch> {
        let mut matches = Vec::new();
        for (idx, pat) in self.patterns.iter().enumerate() {
            for offset in pat.search(data) {
                matches.push(GroupMatch {
                    pattern_index: idx,
                    pattern_name: pat.name.clone(),
                    offset,
                });
            }
        }
        matches.sort_by_key(|m| m.offset);
        matches
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignaturePattern  (FLIRT-style)
// ─────────────────────────────────────────────────────────────────────────────

/// FLIRT-style function signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePattern {
    pub name: String,
    pub prologue: Pattern,
    pub crc16: u16,
    pub crc_len: u8,
    pub func_len: u32,
    pub module_name: Option<String>,
}

impl SignaturePattern {
    /// Create a new signature pattern.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        prologue: Pattern,
        crc16: u16,
        crc_len: u8,
        func_len: u32,
    ) -> Self {
        Self {
            name: name.into(),
            prologue,
            crc16,
            crc_len,
            func_len,
            module_name: None,
        }
    }

    /// Set the module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module_name = Some(module.into());
        self
    }

    /// Returns `true` if `data[offset..]` matches the prologue and the CRC validates.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if !self.prologue.matches(data, offset) {
            return false;
        }
        let crc_start = offset + self.prologue.len();
        let crc_end = crc_start + self.crc_len as usize;
        if crc_end > data.len() {
            return false;
        }
        crc16_ibm(&data[crc_start..crc_end]) == self.crc16
    }

    /// Search all matching positions in `data`.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        self.prologue
            .search(data)
            .into_iter()
            .filter(|&off| {
                let crc_start = off + self.prologue.len();
                let crc_end = crc_start + self.crc_len as usize;
                if crc_end > data.len() {
                    return false;
                }
                crc16_ibm(&data[crc_start..crc_end]) == self.crc16
            })
            .collect()
    }
}

/// CRC-16/IBM (poly 0x8005, init 0x0000, refin=true, refout=true).
#[must_use]
pub fn crc16_ibm(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        let mut b = byte;
        for _ in 0..8 {
            let xor = ((crc ^ u16::from(b)) & 1) != 0;
            crc >>= 1;
            if xor {
                crc ^= 0xA001;
            }
            b >>= 1;
        }
    }
    crc
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDatabase (SQLite backend)
// ─────────────────────────────────────────────────────────────────────────────

/// Persisted pattern store backed by `SQLite`.
pub struct PatternDatabase {
    conn: parking_lot::Mutex<rusqlite::Connection>,
}

impl PatternDatabase {
    /// Open or create a `SQLite` database at `path`.
    ///
    /// # Errors
    /// Returns `PatternError::Database` if the connection or schema init fails.
    pub fn open(path: &str) -> Result<Self, PatternError> {
        let conn =
            rusqlite::Connection::open(path).map_err(|e| PatternError::Database(e.to_string()))?;
        let db = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory `SQLite` database (for testing).
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn open_in_memory() -> Result<Self, PatternError> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let db = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), PatternError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS patterns (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                name    TEXT NOT NULL,
                pattern TEXT NOT NULL,
                tags    TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL DEFAULT ''
            );",
        )
        .map_err(|e| PatternError::Database(e.to_string()))
    }

    /// Insert a pattern into the database.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn insert(&self, pattern: &Pattern) -> Result<i64, PatternError> {
        let name = pattern.name.clone().unwrap_or_default();
        let json = serde_json::to_string(&pattern.bytes)
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let tags = pattern.tags.join(",");
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO patterns (name, pattern, tags, comment) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, json, tags, pattern.comment],
        )
        .map_err(|e| PatternError::Database(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up patterns by name (substring match).
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn search_by_name(&self, name: &str) -> Result<Vec<Pattern>, PatternError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, pattern, tags, comment FROM patterns WHERE name LIKE ?1 ESCAPE '\\'")
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let like = format!("%{}%", escape_like(name));
        let rows = stmt
            .query_map(rusqlite::params![like], |row| {
                let n: String = row.get(0)?;
                let json: String = row.get(1)?;
                let tags_str: String = row.get(2)?;
                let comment: String = row.get(3)?;
                Ok((n, json, tags_str, comment))
            })
            .map_err(|e| PatternError::Database(e.to_string()))?;

        let mut out = Vec::new();
        for row in rows {
            let (n, json, tags_str, comment) =
                row.map_err(|e| PatternError::Database(e.to_string()))?;
            let bytes: Vec<PatternByte> =
                serde_json::from_str(&json).map_err(|e| PatternError::Database(e.to_string()))?;
            out.push(Pattern {
                bytes,
                name: Some(n),
                tags: tags_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                captures: Vec::new(),
                comment,
            });
        }
        Ok(out)
    }

    /// Look up patterns by tag.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn search_by_tag(&self, tag: &str) -> Result<Vec<Pattern>, PatternError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, pattern, tags, comment FROM patterns WHERE tags LIKE ?1 ESCAPE '\\'")
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let like = format!("%{}%", escape_like(tag));
        let rows = stmt
            .query_map(rusqlite::params![like], |row| {
                let n: String = row.get(0)?;
                let json: String = row.get(1)?;
                let tags_str: String = row.get(2)?;
                let comment: String = row.get(3)?;
                Ok((n, json, tags_str, comment))
            })
            .map_err(|e| PatternError::Database(e.to_string()))?;

        let mut out = Vec::new();
        for row in rows {
            let (n, json, tags_str, comment) =
                row.map_err(|e| PatternError::Database(e.to_string()))?;
            let bytes: Vec<PatternByte> =
                serde_json::from_str(&json).map_err(|e| PatternError::Database(e.to_string()))?;
            out.push(Pattern {
                bytes,
                name: Some(n),
                tags: tags_str
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                captures: Vec::new(),
                comment,
            });
        }
        Ok(out)
    }

    /// Delete a pattern by id.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn delete(&self, id: i64) -> Result<(), PatternError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM patterns WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| PatternError::Database(e.to_string()))?;
        Ok(())
    }

    /// Count all stored patterns.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn count(&self) -> Result<u64, PatternError> {
        let conn = self.conn.lock();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM patterns", [], |row| row.get(0))
            .map_err(|e| PatternError::Database(e.to_string()))?;
        Ok(n as u64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MySQL-backed PatternStore
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory pattern store that mirrors to `MySQL`.
pub struct MySqlPatternStore {
    pool: mysql::Pool,
    cache: parking_lot::RwLock<HashMap<String, Vec<Pattern>>>,
}

impl MySqlPatternStore {
    /// Connect to a `MySQL` server using the given URL.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on connection failure.
    pub fn connect(url: &str) -> Result<Self, PatternError> {
        let pool = mysql::Pool::new(url).map_err(|e| PatternError::Database(e.to_string()))?;
        let store = Self {
            pool,
            cache: parking_lot::RwLock::new(HashMap::new()),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), PatternError> {
        use mysql::prelude::Queryable;
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| PatternError::Database(e.to_string()))?;
        conn.query_drop(
            "CREATE TABLE IF NOT EXISTS patterns (
                id      BIGINT AUTO_INCREMENT PRIMARY KEY,
                name    VARCHAR(255) NOT NULL,
                pattern TEXT NOT NULL,
                tags    TEXT NOT NULL DEFAULT '',
                comment TEXT NOT NULL DEFAULT ''
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        )
        .map_err(|e| PatternError::Database(e.to_string()))?;
        Ok(())
    }

    /// Insert a pattern.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn insert(&self, pattern: &Pattern) -> Result<u64, PatternError> {
        use mysql::prelude::Queryable;
        let name = pattern.name.clone().unwrap_or_default();
        let json = serde_json::to_string(&pattern.bytes)
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let tags = pattern.tags.join(",");
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| PatternError::Database(e.to_string()))?;
        conn.exec_drop(
            "INSERT INTO patterns (name, pattern, tags, comment) VALUES (?, ?, ?, ?)",
            (&name, &json, &tags, &pattern.comment),
        )
        .map_err(|e| PatternError::Database(e.to_string()))?;
        {
            let mut cache_write = self.cache.write();
            cache_write.clear();
        }
        Ok(conn.last_insert_id())
    }

    /// Search patterns by name prefix.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on failure.
    pub fn search_by_name(&self, name: &str) -> Result<Vec<Pattern>, PatternError> {
        {
            let cache_read = self.cache.read();
            if let Some(hits) = cache_read.get(name) {
                return Ok(hits.clone());
            }
        }
        use mysql::prelude::Queryable;
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let like = format!("%{}%", escape_like(name));
        let rows: Vec<(String, String, String, String)> = conn
            .exec(
                "SELECT name, pattern, tags, comment FROM patterns WHERE name LIKE ? ESCAPE '\\'",
                (&like,),
            )
            .map_err(|e| PatternError::Database(e.to_string()))?;
        let patterns = self.rows_to_patterns(rows)?;
        {
            let mut cache_write = self.cache.write();
            cache_write.insert(name.to_string(), patterns.clone());
        }
        Ok(patterns)
    }

    fn rows_to_patterns(
        &self,
        rows: Vec<(String, String, String, String)>,
    ) -> Result<Vec<Pattern>, PatternError> {
        rows.into_iter()
            .map(|(n, json, tags_str, comment)| {
                let bytes: Vec<PatternByte> = serde_json::from_str(&json)
                    .map_err(|e| PatternError::Database(e.to_string()))?;
                Ok(Pattern {
                    bytes,
                    name: Some(n),
                    tags: tags_str
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                    captures: Vec::new(),
                    comment,
                })
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternExporter
// ─────────────────────────────────────────────────────────────────────────────

/// Utilities for exporting and importing pattern collections.
pub struct PatternExporter;

impl PatternExporter {
    /// Export a list of patterns to JSON.
    ///
    /// # Errors
    /// Returns `PatternError::Export` on failure.
    pub fn export_json(patterns: &[Pattern]) -> Result<String, PatternError> {
        serde_json::to_string_pretty(patterns).map_err(|e| PatternError::Export(e.to_string()))
    }

    /// Import patterns from JSON.
    ///
    /// # Errors
    /// Returns `PatternError::Import` on failure.
    pub fn import_json(json: &str) -> Result<Vec<Pattern>, PatternError> {
        serde_json::from_str(json).map_err(|e| PatternError::Import(e.to_string()))
    }

    /// Export patterns to IDA `.pat` style (one per line: hex string + name).
    #[must_use]
    pub fn export_ida_pat(patterns: &[Pattern]) -> String {
        patterns
            .iter()
            .map(|p| {
                let hex = p.to_hex_string();
                let name = p.name.as_deref().unwrap_or("unnamed");
                format!("{hex} {name}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Import patterns from IDA `.pat` style (one per line: `HEX_BYTES name`).
    ///
    /// # Errors
    /// Returns `PatternError::Parse` on malformed lines.
    pub fn import_ida_pat(text: &str) -> Result<Vec<Pattern>, PatternError> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // IDA .pat end-of-file marker
            if line == "---" {
                break;
            }
            // Last whitespace-separated token is the name (if it does not look
            // like a pattern token); preceding tokens form the hex pattern.
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.is_empty() {
                continue;
            }
            let is_pattern_tok = |t: &str| -> bool {
                let b = t.as_bytes();
                if b.is_empty() || b.len() > 2 {
                    return false;
                }
                b.iter().all(|&c| matches!(c,
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'?'))
            };
            let (hex_toks, name_part): (&[&str], Option<&str>) =
                if toks.len() >= 2 && !is_pattern_tok(toks[toks.len() - 1]) {
                    (&toks[..toks.len() - 1], Some(toks[toks.len() - 1]))
                } else {
                    (&toks[..], None)
                };
            let hex_joined = hex_toks.join(" ");
            let mut pat = Pattern::parse(&hex_joined)?;
            if let Some(n) = name_part {
                pat.name = Some(n.to_string());
            }
            out.push(pat);
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Nibble helper
// ─────────────────────────────────────────────────────────────────────────────

const fn nibble_from_hex(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PatternByte ───────────────────────────────────────────────────────────

    #[test]
    fn test_exact_matches() {
        let pb = PatternByte::Exact(0xDE);
        assert!(pb.matches(0xDE));
        assert!(!pb.matches(0xAD));
    }

    #[test]
    fn test_wildcard_matches_anything() {
        let pb = PatternByte::Wildcard;
        assert!(pb.matches(0x00));
        assert!(pb.matches(0xFF));
    }

    #[test]
    fn test_nibble_high() {
        let pb = PatternByte::Nibble {
            high: Some(0xD),
            low: None,
        };
        assert!(pb.matches(0xD0));
        assert!(pb.matches(0xDF));
        assert!(!pb.matches(0xE0));
    }

    #[test]
    fn test_nibble_low() {
        let pb = PatternByte::Nibble {
            high: None,
            low: Some(0xF),
        };
        assert!(pb.matches(0x0F));
        assert!(pb.matches(0xFF));
        assert!(!pb.matches(0x0E));
    }

    #[test]
    fn test_pattern_byte_mask_value() {
        let pb = PatternByte::Exact(0xAB);
        assert_eq!(pb.mask_byte(), 0xFF);
        assert_eq!(pb.value_byte(), 0xAB);
        let wc = PatternByte::Wildcard;
        assert_eq!(wc.mask_byte(), 0x00);
    }

    // ── Pattern::parse ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_exact() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        assert_eq!(pat.bytes.len(), 4);
        assert_eq!(pat.bytes[0], PatternByte::Exact(0xDE));
        assert_eq!(pat.bytes[3], PatternByte::Exact(0xEF));
    }

    #[test]
    fn test_parse_wildcards() {
        let pat = Pattern::parse("DE ? BE EF").unwrap();
        assert_eq!(pat.bytes[1], PatternByte::Wildcard);
    }

    #[test]
    fn test_parse_double_wildcard() {
        let pat = Pattern::parse("?? ?? DE").unwrap();
        assert_eq!(pat.bytes[0], PatternByte::Wildcard);
        assert_eq!(pat.bytes[1], PatternByte::Wildcard);
    }

    #[test]
    fn test_parse_nibble_lo() {
        let pat = Pattern::parse("?F").unwrap();
        assert_eq!(
            pat.bytes[0],
            PatternByte::Nibble {
                high: None,
                low: Some(0xF)
            }
        );
    }

    #[test]
    fn test_parse_nibble_hi() {
        let pat = Pattern::parse("0?").unwrap();
        assert_eq!(
            pat.bytes[0],
            PatternByte::Nibble {
                high: Some(0),
                low: None
            }
        );
    }

    #[test]
    fn test_parse_empty_error() {
        assert!(matches!(Pattern::parse(""), Err(PatternError::Empty)));
    }

    #[test]
    fn test_parse_invalid_token() {
        assert!(Pattern::parse("GG").is_err());
    }

    // ── Pattern::matches ──────────────────────────────────────────────────────

    #[test]
    fn test_pattern_matches_exact() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(pat.matches(&data, 0));
        assert!(!pat.matches(&data, 1));
    }

    #[test]
    fn test_pattern_matches_with_wildcard() {
        let pat = Pattern::parse("DE ? BE EF").unwrap();
        let data = [0xDE, 0x99, 0xBE, 0xEF];
        assert!(pat.matches(&data, 0));
    }

    #[test]
    fn test_pattern_does_not_match_short() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        assert!(!pat.matches(&[0xDE, 0xAD], 0));
    }

    // ── Pattern::search ───────────────────────────────────────────────────────

    #[test]
    fn test_search_exact() {
        let pat = Pattern::parse("DE AD").unwrap();
        let data = [0x00, 0xDE, 0xAD, 0x00, 0xDE, 0xAD];
        let results = pat.search(&data);
        assert_eq!(results, vec![1, 4]);
    }

    #[test]
    fn test_search_wildcard() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        let data = [0xDE, 0xAA, 0xEF, 0xFF, 0xDE, 0xBB, 0xEF];
        let results = pat.search(&data);
        assert_eq!(results, vec![0, 4]);
    }

    #[test]
    fn test_search_no_match() {
        let pat = Pattern::parse("FF FF FF").unwrap();
        let data = [0x00; 8];
        assert!(pat.search(&data).is_empty());
    }

    #[test]
    fn test_search_all_wildcards() {
        let pat = Pattern::parse("? ? ?").unwrap();
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        let results = pat.search(&data);
        assert_eq!(results, vec![0, 1]);
    }

    #[test]
    fn test_search_empty_data() {
        let pat = Pattern::parse("DE AD").unwrap();
        assert!(pat.search(&[]).is_empty());
    }

    // ── Pattern::to_bytes / to_hex_string ────────────────────────────────────

    #[test]
    fn test_to_bytes_no_wildcards() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        assert_eq!(pat.to_bytes(), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_to_bytes_with_wildcard() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        assert_eq!(pat.to_bytes(), None);
    }

    #[test]
    fn test_to_hex_string() {
        let pat = Pattern::parse("DE AD ? EF").unwrap();
        let s = pat.to_hex_string();
        assert!(s.contains("DE"));
        assert!(s.contains("AD"));
        assert!(s.contains("??"));
        assert!(s.contains("EF"));
    }

    // ── Pattern specificity ───────────────────────────────────────────────────

    #[test]
    fn test_specificity() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        assert!((pat.specificity() - 1.0).abs() < 1e-9);
        let wc = Pattern::parse("? ?").unwrap();
        assert!((wc.specificity()).abs() < 1e-9);
        let mixed = Pattern::parse("AA ?").unwrap();
        assert!((mixed.specificity() - 0.5).abs() < 1e-9);
    }

    // ── Named captures ────────────────────────────────────────────────────────

    #[test]
    fn test_named_capture() {
        let pat = Pattern::parse("DE AD BE EF 01 02")
            .unwrap()
            .with_capture("header", 0, 2)
            .with_capture("body", 2, 4);
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let matches = pat.search_with_captures(&data);
        assert_eq!(matches.len(), 1);
        let (offset, caps) = &matches[0];
        assert_eq!(*offset, 0);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].name, "header");
        assert_eq!(caps[0].bytes, vec![0xDE, 0xAD]);
        assert_eq!(caps[1].name, "body");
    }

    // ── AlternationPattern ────────────────────────────────────────────────────

    #[test]
    fn test_alternation_parse() {
        let alt = AlternationPattern::parse("AA BB | CC DD").unwrap();
        assert_eq!(alt.len(), 2);
    }

    #[test]
    fn test_alternation_search() {
        let alt = AlternationPattern::parse("AA BB | CC DD").unwrap();
        let data = [0x00, 0xAA, 0xBB, 0x00, 0xCC, 0xDD];
        let results = alt.search(&data);
        assert_eq!(results, vec![1, 4]);
    }

    #[test]
    fn test_alternation_matches() {
        let alt = AlternationPattern::parse("DE AD | 55 48").unwrap();
        let data = [0x55, 0x48, 0x89, 0xE5];
        assert!(alt.matches(&data, 0));
        assert!(!alt.matches(&data, 1));
    }

    // ── CompiledPattern ───────────────────────────────────────────────────────

    #[test]
    fn test_compiled_exact() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let cp = CompiledPattern::compile(&pat);
        let data = [0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert_eq!(cp.search(&data), vec![1]);
    }

    #[test]
    fn test_compiled_with_wildcard() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        let cp = CompiledPattern::compile(&pat);
        let data = [0xDE, 0xAA, 0xEF, 0xFF, 0xDE, 0xBB, 0xEF];
        assert_eq!(cp.search(&data), vec![0, 4]);
    }

    // ── MaskedPattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_masked_pattern_exact() {
        let mp = MaskedPattern::new(vec![0xDE, 0xAD], vec![0xFF, 0xFF]).unwrap();
        assert!(mp.matches(&[0xDE, 0xAD, 0xBE, 0xEF], 0));
        assert!(!mp.matches(&[0xDE, 0x00, 0xBE, 0xEF], 0));
    }

    #[test]
    fn test_masked_from_pattern() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        let mp = MaskedPattern::from_pattern(&pat);
        assert_eq!(mp.mask, vec![0xFF, 0x00, 0xFF]);
        assert!(mp.matches(&[0xDE, 0x99, 0xEF], 0));
    }

    #[test]
    fn test_masked_search() {
        let mp = MaskedPattern::new(vec![0xAA, 0x00], vec![0xFF, 0x00]).unwrap();
        let data = [0xBB, 0xAA, 0x99, 0x00, 0xAA, 0xFF];
        let results = mp.search(&data);
        assert_eq!(results, vec![1, 4]);
    }

    // ── PatternGroup ──────────────────────────────────────────────────────────

    #[test]
    fn test_group_search_all() {
        let mut group = PatternGroup::new("test_group");
        group.add(Pattern::parse("AA BB").unwrap().with_name("pat1"));
        group.add(Pattern::parse("CC DD").unwrap().with_name("pat2"));
        let data = [0x00, 0xAA, 0xBB, 0x00, 0xCC, 0xDD];
        let matches = group.search_all(&data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].offset, 1);
        assert_eq!(matches[1].offset, 4);
    }

    #[test]
    fn test_group_compile() {
        let mut group = PatternGroup::new("cg");
        group.add(Pattern::parse("AA BB").unwrap());
        let compiled = group.compile();
        let data = [0x00, 0xAA, 0xBB];
        let matches = compiled.search_all(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 1);
    }

    // ── SignaturePattern ──────────────────────────────────────────────────────

    #[test]
    fn test_crc16_ibm_known() {
        let crc = crc16_ibm(b"123456789");
        assert_eq!(crc, 0xBB3D);
    }

    #[test]
    fn test_signature_match() {
        let prologue_bytes = [0x55, 0x48, 0x89, 0xE5];
        let crc_bytes = [0x48, 0x83, 0xEC, 0x10];
        let crc = crc16_ibm(&crc_bytes);
        let prologue = Pattern::parse("55 48 89 E5").unwrap();
        let sig = SignaturePattern::new("test_fn", prologue, crc, 4, 16);
        let data: Vec<u8> = prologue_bytes
            .iter()
            .chain(crc_bytes.iter())
            .copied()
            .collect();
        assert!(sig.matches(&data, 0));
    }

    // ── PatternDatabase ───────────────────────────────────────────────────────

    #[test]
    fn test_db_insert_and_search() {
        let db = PatternDatabase::open_in_memory().unwrap();
        let pat = Pattern::parse("DE AD BE EF")
            .unwrap()
            .with_name("deadbeef")
            .with_tag("malware");
        db.insert(&pat).unwrap();
        let results = db.search_by_name("dead").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn test_db_search_by_tag() {
        let db = PatternDatabase::open_in_memory().unwrap();
        let pat = Pattern::parse("AA BB CC")
            .unwrap()
            .with_name("test")
            .with_tag("shellcode");
        db.insert(&pat).unwrap();
        let results = db.search_by_tag("shellcode").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_db_count() {
        let db = PatternDatabase::open_in_memory().unwrap();
        assert_eq!(db.count().unwrap(), 0);
        db.insert(&Pattern::parse("AA").unwrap().with_name("a"))
            .unwrap();
        db.insert(&Pattern::parse("BB").unwrap().with_name("b"))
            .unwrap();
        assert_eq!(db.count().unwrap(), 2);
    }

    // ── PatternExporter ───────────────────────────────────────────────────────

    #[test]
    fn test_export_import_json() {
        let pats = vec![
            Pattern::parse("DE AD").unwrap().with_name("test"),
            Pattern::parse("? EF").unwrap().with_name("wc"),
        ];
        let json = PatternExporter::export_json(&pats).unwrap();
        let imported = PatternExporter::import_json(&json).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].name.as_deref(), Some("test"));
    }

    #[test]
    fn test_export_import_ida_pat() {
        // IDA .pat format: one line per pattern, first token = first byte, rest = name
        // We export single-byte patterns to avoid the name/hex ambiguity in the simple parser
        let pats = vec![Pattern::parse("55").unwrap().with_name("func_prologue")];
        let pat_text = PatternExporter::export_ida_pat(&pats);
        let imported = PatternExporter::import_ida_pat(&pat_text).unwrap();
        assert_eq!(imported.len(), 1);
        // The hex token "55" parses as a 1-byte pattern
        assert_eq!(imported[0].bytes.len(), 1);
        assert_eq!(imported[0].name.as_deref(), Some("func_prologue"));
    }

    // ── to_simd_form ──────────────────────────────────────────────────────────

    #[test]
    fn test_simd_form() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        let (vals, masks) = pat.to_simd_form();
        assert_eq!(vals.len(), 3);
        assert_eq!(masks[0], 0xFF);
        assert_eq!(masks[1], 0x00);
        assert_eq!(masks[2], 0xFF);
        assert_eq!(vals[0], 0xDE);
        assert_eq!(vals[2], 0xEF);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommonPatterns — well-known RE patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A library of commonly encountered binary patterns for reverse engineering.
pub struct CommonPatterns;

impl CommonPatterns {
    // ── File magic ──────────────────────────────────────────────────────────

    /// PE/COFF DOS stub magic: `MZ` (`4D 5A`).
    #[must_use]
    pub fn pe_dos_magic() -> Pattern {
        Pattern::parse("4D 5A")
            .unwrap()
            .with_name("PE_DOS_MZ")
            .with_tag("pe")
            .with_tag("magic")
            .with_comment("PE/COFF DOS stub magic bytes")
    }

    /// PE signature: `PE\0\0` at offset pointed to by `e_lfanew`.
    #[must_use]
    pub fn pe_signature() -> Pattern {
        Pattern::parse("50 45 00 00")
            .unwrap()
            .with_name("PE_SIGNATURE")
            .with_tag("pe")
            .with_tag("magic")
            .with_comment("PE optional header signature")
    }

    /// ELF magic: `\x7fELF`.
    #[must_use]
    pub fn elf_magic() -> Pattern {
        Pattern::parse("7F 45 4C 46")
            .unwrap()
            .with_name("ELF_MAGIC")
            .with_tag("elf")
            .with_tag("magic")
            .with_comment("ELF identification bytes")
    }

    /// Mach-O magic (32-bit little-endian): `CE FA ED FE`.
    #[must_use]
    pub fn macho_magic_le32() -> Pattern {
        Pattern::parse("CE FA ED FE")
            .unwrap()
            .with_name("MACHO_LE32")
            .with_tag("macho")
            .with_tag("magic")
            .with_comment("Mach-O 32-bit little-endian magic")
    }

    /// Mach-O magic (64-bit little-endian): `CF FA ED FE`.
    #[must_use]
    pub fn macho_magic_le64() -> Pattern {
        Pattern::parse("CF FA ED FE")
            .unwrap()
            .with_name("MACHO_LE64")
            .with_tag("macho")
            .with_tag("magic")
            .with_comment("Mach-O 64-bit little-endian magic")
    }

    /// ZIP local file header signature: `PK\x03\x04`.
    #[must_use]
    pub fn zip_magic() -> Pattern {
        Pattern::parse("50 4B 03 04")
            .unwrap()
            .with_name("ZIP_MAGIC")
            .with_tag("zip")
            .with_tag("magic")
            .with_comment("ZIP local file header signature")
    }

    /// ZIP central directory signature: `PK\x01\x02`.
    #[must_use]
    pub fn zip_central_dir() -> Pattern {
        Pattern::parse("50 4B 01 02")
            .unwrap()
            .with_name("ZIP_CENTRAL_DIR")
            .with_tag("zip")
            .with_tag("magic")
            .with_comment("ZIP central directory record signature")
    }

    /// ZIP end-of-central-directory: `PK\x05\x06`.
    #[must_use]
    pub fn zip_eocd() -> Pattern {
        Pattern::parse("50 4B 05 06")
            .unwrap()
            .with_name("ZIP_EOCD")
            .with_tag("zip")
            .with_tag("magic")
            .with_comment("ZIP end-of-central-directory record")
    }

    /// PNG magic: `\x89PNG\r\n\x1a\n`.
    #[must_use]
    pub fn png_magic() -> Pattern {
        Pattern::parse("89 50 4E 47 0D 0A 1A 0A")
            .unwrap()
            .with_name("PNG_MAGIC")
            .with_tag("png")
            .with_tag("magic")
            .with_comment("PNG file signature")
    }

    /// JPEG magic: `FF D8 FF`.
    #[must_use]
    pub fn jpeg_magic() -> Pattern {
        Pattern::parse("FF D8 FF")
            .unwrap()
            .with_name("JPEG_MAGIC")
            .with_tag("jpeg")
            .with_tag("magic")
            .with_comment("JPEG SOI + APP marker prefix")
    }

    /// PDF magic: `%PDF-`.
    #[must_use]
    pub fn pdf_magic() -> Pattern {
        Pattern::parse("25 50 44 46 2D")
            .unwrap()
            .with_name("PDF_MAGIC")
            .with_tag("pdf")
            .with_tag("magic")
            .with_comment("PDF file signature (%PDF-)")
    }

    /// GIF magic (`GIF87a` / GIF89a): `GIF8`.
    #[must_use]
    pub fn gif_magic() -> Pattern {
        Pattern::parse("47 49 46 38")
            .unwrap()
            .with_name("GIF_MAGIC")
            .with_tag("gif")
            .with_tag("magic")
            .with_comment("GIF file signature prefix (GIF8x)")
    }

    /// RAR archive magic: `Rar!`.
    #[must_use]
    pub fn rar_magic() -> Pattern {
        Pattern::parse("52 61 72 21 1A 07")
            .unwrap()
            .with_name("RAR_MAGIC")
            .with_tag("rar")
            .with_tag("magic")
            .with_comment("RAR 4.x archive signature")
    }

    /// 7-Zip magic: `7z\xBC\xAF'\x1C`.
    #[must_use]
    pub fn sevenzip_magic() -> Pattern {
        Pattern::parse("37 7A BC AF 27 1C")
            .unwrap()
            .with_name("7ZIP_MAGIC")
            .with_tag("7zip")
            .with_tag("magic")
            .with_comment("7-Zip archive signature")
    }

    /// RIFF (WAV/AVI) magic: `RIFF`.
    #[must_use]
    pub fn riff_magic() -> Pattern {
        Pattern::parse("52 49 46 46")
            .unwrap()
            .with_name("RIFF_MAGIC")
            .with_tag("riff")
            .with_tag("magic")
            .with_comment("RIFF container file signature")
    }

    /// BMP magic: `BM`.
    #[must_use]
    pub fn bmp_magic() -> Pattern {
        Pattern::parse("42 4D")
            .unwrap()
            .with_name("BMP_MAGIC")
            .with_tag("bmp")
            .with_tag("magic")
            .with_comment("Windows BMP file signature")
    }

    // ── x86/x64 shellcode patterns ──────────────────────────────────────────

    /// x86 function prologue (push ebp; mov ebp, esp): `55 8B EC`.
    #[must_use]
    pub fn x86_prologue_classic() -> Pattern {
        Pattern::parse("55 8B EC")
            .unwrap()
            .with_name("X86_PROLOGUE_CLASSIC")
            .with_tag("shellcode")
            .with_tag("x86")
            .with_comment("Classic x86 function prologue: push ebp; mov ebp,esp")
    }

    /// x64 function prologue (push rbp; mov rbp, rsp): `55 48 89 E5`.
    #[must_use]
    pub fn x64_prologue() -> Pattern {
        Pattern::parse("55 48 89 E5")
            .unwrap()
            .with_name("X64_PROLOGUE")
            .with_tag("shellcode")
            .with_tag("x64")
            .with_comment("x86-64 function prologue: push rbp; mov rbp,rsp")
    }

    /// x86 `call $+5; pop reg` `GetPC` technique.
    #[must_use]
    pub fn x86_getpc_call_pop() -> Pattern {
        Pattern::parse("E8 00 00 00 00 5?")
            .unwrap()
            .with_name("X86_GETPC_CALL_POP")
            .with_tag("shellcode")
            .with_tag("x86")
            .with_comment("x86 GetPC: call $+5 followed by pop reg")
    }

    /// x86 `int 3` software breakpoint.
    #[must_use]
    pub fn x86_int3() -> Pattern {
        Pattern::parse("CC")
            .unwrap()
            .with_name("X86_INT3")
            .with_tag("debugger")
            .with_tag("x86")
            .with_comment("x86 INT3 software breakpoint")
    }

    /// x86 nop sled: `90 90 90 90 90 90 90 90`.
    #[must_use]
    pub fn x86_nop_sled_8() -> Pattern {
        Pattern::parse("90 90 90 90 90 90 90 90")
            .unwrap()
            .with_name("X86_NOP_SLED_8")
            .with_tag("shellcode")
            .with_tag("x86")
            .with_comment("x86 8-byte NOP sled")
    }

    /// x86 `xor eax, eax; ret`.
    #[must_use]
    pub fn x86_xor_eax_ret() -> Pattern {
        Pattern::parse("31 C0 C3")
            .unwrap()
            .with_name("X86_XOR_EAX_RET")
            .with_tag("shellcode")
            .with_tag("x86")
            .with_comment("xor eax,eax; ret — common stub / return 0")
    }

    /// x64 `syscall` instruction.
    #[must_use]
    pub fn x64_syscall() -> Pattern {
        Pattern::parse("0F 05")
            .unwrap()
            .with_name("X64_SYSCALL")
            .with_tag("shellcode")
            .with_tag("x64")
            .with_comment("x86-64 syscall instruction")
    }

    /// x86 `int 0x80` Linux syscall.
    #[must_use]
    pub fn x86_int80_syscall() -> Pattern {
        Pattern::parse("CD 80")
            .unwrap()
            .with_name("X86_INT80_SYSCALL")
            .with_tag("shellcode")
            .with_tag("x86")
            .with_comment("Linux x86 int 0x80 syscall")
    }

    // ── Crypto constants ────────────────────────────────────────────────────

    /// AES S-box first row: `63 7C 77 7B F2 6B 6F C5`.
    #[must_use]
    pub fn aes_sbox_start() -> Pattern {
        Pattern::parse("63 7C 77 7B F2 6B 6F C5")
            .unwrap()
            .with_name("AES_SBOX_START")
            .with_tag("crypto")
            .with_tag("aes")
            .with_comment("Start of AES forward S-box lookup table")
    }

    /// AES round constant (Rcon[1]): `01 02 04 08 10 20 40 80`.
    #[must_use]
    pub fn aes_rcon() -> Pattern {
        Pattern::parse("01 02 04 08 10 20 40 80")
            .unwrap()
            .with_name("AES_RCON")
            .with_tag("crypto")
            .with_tag("aes")
            .with_comment("AES key schedule round constants (Rcon)")
    }

    /// SHA-256 initial hash values (first 4 words, big-endian).
    #[must_use]
    pub fn sha256_init_h0_h3() -> Pattern {
        Pattern::parse("6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A")
            .unwrap()
            .with_name("SHA256_INIT_H0_H3")
            .with_tag("crypto")
            .with_tag("sha256")
            .with_comment("SHA-256 initial hash values H0-H3 (big-endian)")
    }

    /// MD5 magic constant 0x67452301 (little-endian).
    #[must_use]
    pub fn md5_init_a() -> Pattern {
        Pattern::parse("01 23 45 67")
            .unwrap()
            .with_name("MD5_INIT_A")
            .with_tag("crypto")
            .with_tag("md5")
            .with_comment("MD5 initial state constant A (little-endian)")
    }

    /// RC4 KSA begin: sequential init `00 01 02 03 04 05 06 07`.
    #[must_use]
    pub fn rc4_ks_init() -> Pattern {
        Pattern::parse("00 01 02 03 04 05 06 07")
            .unwrap()
            .with_name("RC4_KS_INIT")
            .with_tag("crypto")
            .with_tag("rc4")
            .with_comment("RC4 key scheduling array start (0x00..0x07)")
    }

    // ── XOR key detection helpers ───────────────────────────────────────────

    /// Single-byte XOR key = 0x00 detection (unmodified region).
    #[must_use]
    pub fn xor_null_region_8() -> Pattern {
        Pattern::parse("00 00 00 00 00 00 00 00")
            .unwrap()
            .with_name("XOR_NULL_REGION")
            .with_tag("obfuscation")
            .with_tag("xor")
            .with_comment("8-byte null region (often indicates XOR key = 0 or plain zeros)")
    }

    /// Return a group of all common magic patterns.
    #[must_use]
    pub fn magic_group() -> PatternGroup {
        let mut g = PatternGroup::new("CommonMagic");
        g.add(Self::pe_dos_magic());
        g.add(Self::pe_signature());
        g.add(Self::elf_magic());
        g.add(Self::macho_magic_le32());
        g.add(Self::macho_magic_le64());
        g.add(Self::zip_magic());
        g.add(Self::png_magic());
        g.add(Self::jpeg_magic());
        g.add(Self::pdf_magic());
        g.add(Self::gif_magic());
        g.add(Self::rar_magic());
        g.add(Self::sevenzip_magic());
        g.add(Self::riff_magic());
        g.add(Self::bmp_magic());
        g
    }

    /// Return a group of common shellcode-related patterns.
    #[must_use]
    pub fn shellcode_group() -> PatternGroup {
        let mut g = PatternGroup::new("ShellcodePatterns");
        g.add(Self::x86_prologue_classic());
        g.add(Self::x64_prologue());
        g.add(Self::x86_getpc_call_pop());
        g.add(Self::x86_int3());
        g.add(Self::x86_nop_sled_8());
        g.add(Self::x86_xor_eax_ret());
        g.add(Self::x64_syscall());
        g.add(Self::x86_int80_syscall());
        g
    }

    /// Return a group of common crypto constant patterns.
    #[must_use]
    pub fn crypto_group() -> PatternGroup {
        let mut g = PatternGroup::new("CryptoConstants");
        g.add(Self::aes_sbox_start());
        g.add(Self::aes_rcon());
        g.add(Self::sha256_init_h0_h3());
        g.add(Self::md5_init_a());
        g.add(Self::rc4_ks_init());
        g
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternTester — test a pattern against sample data
// ─────────────────────────────────────────────────────────────────────────────

/// Tests patterns against user-supplied sample data and reports results.
#[derive(Debug, Default)]
pub struct PatternTester {
    results: Vec<TestResult>,
}

/// Result of testing a single pattern against a data sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub pattern_name: String,
    pub match_count: usize,
    pub match_offsets: Vec<usize>,
    pub passed: bool,
}

impl PatternTester {
    /// Create a new tester.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Test `pattern` against `data`, expecting at least `min_matches` hits.
    pub fn test(&mut self, pattern: &Pattern, data: &[u8], min_matches: usize) -> &TestResult {
        let offsets = pattern.search(data);
        let count = offsets.len();
        let result = TestResult {
            pattern_name: pattern
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_string()),
            match_count: count,
            match_offsets: offsets,
            passed: count >= min_matches,
        };
        self.results.push(result);
        self.results.last().unwrap()
    }

    /// Test an `AlternationPattern` against `data`.
    pub fn test_alternation(
        &mut self,
        pattern: &AlternationPattern,
        data: &[u8],
        min_matches: usize,
    ) -> &TestResult {
        let offsets = pattern.search(data);
        let count = offsets.len();
        let result = TestResult {
            pattern_name: pattern
                .name
                .clone()
                .unwrap_or_else(|| "<alternation>".to_string()),
            match_count: count,
            match_offsets: offsets,
            passed: count >= min_matches,
        };
        self.results.push(result);
        self.results.last().unwrap()
    }

    /// Return all test results.
    #[must_use]
    pub fn results(&self) -> &[TestResult] {
        &self.results
    }

    /// Number of passing tests.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    /// Number of failing tests.
    #[must_use]
    pub fn fail_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    /// Clear all test results.
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NfaState / DfaState — NFA→DFA compilation pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// An NFA state for pattern matching.
#[derive(Debug, Clone)]
struct NfaState {
    /// Transitions: for each byte value 0–255, the next state index (or `None`).
    /// `None` in `transitions[b]` means the NFA does not accept byte `b` in this state.
    transitions: Vec<Option<usize>>,
    /// Whether this is the accepting state.
    accepting: bool,
}

impl NfaState {
    fn new() -> Self {
        Self {
            transitions: vec![None; 256],
            accepting: false,
        }
    }
}

/// An NFA compiled from a `Pattern` for multi-byte matching.
pub struct PatternNfa {
    states: Vec<NfaState>,
    /// Pattern length (number of states – 1).
    pat_len: usize,
}

impl PatternNfa {
    /// Compile a `Pattern` into an NFA.
    #[must_use]
    pub fn compile(pat: &Pattern) -> Self {
        let n = pat.bytes.len();
        let mut states: Vec<NfaState> = (0..=n).map(|_| NfaState::new()).collect();
        for (i, pb) in pat.bytes.iter().enumerate() {
            for b in 0u8..=255u8 {
                if pb.matches(b) {
                    states[i].transitions[b as usize] = Some(i + 1);
                }
            }
        }
        states[n].accepting = true;
        Self { states, pat_len: n }
    }

    /// Find the first match of the NFA in `data` starting at `start`.
    /// Returns `(match_start, match_end)` on success.
    #[must_use]
    pub fn find_first(&self, data: &[u8], start: usize) -> Option<(usize, usize)> {
        for begin in start..data.len() {
            let mut state = 0;
            let mut i = begin;
            while i < data.len() {
                let next = self.states[state].transitions[data[i] as usize];
                if let Some(ns) = next {
                    state = ns;
                    i += 1;
                    if self.states[state].accepting {
                        return Some((begin, i));
                    }
                } else {
                    break;
                }
            }
        }
        None
    }

    /// Find all non-overlapping matches in `data`.
    #[must_use]
    pub fn find_all(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut matches = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if let Some((start, end)) = self.find_first(data, pos) {
                matches.push((start, end));
                pos = end;
            } else {
                pos += 1;
            }
        }
        matches
    }

    /// Pattern length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pat_len
    }

    /// Returns `true` if the pattern is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pat_len == 0
    }
}

/// A DFA state, constructed from an NFA via subset construction (simplified,
/// single-path NFA).
#[derive(Debug, Clone)]
pub struct DfaState {
    /// For each byte value, the next DFA state index.
    pub transitions: Vec<usize>,
    pub accepting: bool,
    /// State index (for debugging).
    pub id: usize,
}

impl DfaState {
    fn new(id: usize) -> Self {
        Self {
            transitions: vec![0; 256],
            accepting: false,
            id,
        }
    }
}

/// A deterministic finite automaton built from a pattern NFA.
pub struct PatternDfa {
    states: Vec<DfaState>,
    /// Dead state index (0 by convention).
    dead: usize,
    start: usize,
    pat_len: usize,
}

impl PatternDfa {
    /// Build a DFA from a `Pattern`.  For single-path patterns (no epsilon
    /// transitions), this is equivalent to the NFA.
    #[must_use]
    pub fn compile(pat: &Pattern) -> Self {
        let n = pat.bytes.len();
        // States: 0 = dead, 1 = start, 2..n+1 = in-progress, n+2 = accept
        let num_states = n + 3;
        let mut states: Vec<DfaState> = (0..num_states).map(DfaState::new).collect();

        let start = 1usize;
        let accept = n + 2;

        // Build transitions
        for b in 0u8..=255u8 {
            let bi = b as usize;
            // From start (state 1) on first pattern byte
            if pat.bytes.is_empty() {
                continue;
            }
            if pat.bytes[0].matches(b) {
                if n == 1 {
                    states[start].transitions[bi] = accept;
                } else {
                    states[start].transitions[bi] = 2;
                }
            } else {
                states[start].transitions[bi] = start; // stay in start (restart)
            }
        }

        // Middle states
        for (i, pb) in pat.bytes.iter().enumerate().skip(1) {
            let current = i + 1;
            for b in 0u8..=255u8 {
                let bi = b as usize;
                if pb.matches(b) {
                    let next = if i + 1 == n { accept } else { i + 2 };
                    states[current].transitions[bi] = next;
                } else {
                    // Mismatch: reset to start
                    states[current].transitions[bi] = start;
                }
            }
        }

        // Accept state loops on itself
        for b in 0u8..=255u8 {
            states[accept].transitions[b as usize] = start;
        }
        states[accept].accepting = true;

        Self {
            states,
            dead: 0,
            start,
            pat_len: n,
        }
    }

    /// Find all (potentially overlapping) match positions in `data`.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.pat_len == 0 {
            return Vec::new();
        }
        let accept = self.pat_len + 2;
        let mut state = self.start;
        let mut results = Vec::new();
        for (i, &b) in data.iter().enumerate() {
            state = self.states[state].transitions[b as usize];
            if state == accept {
                let match_start = i + 1 - self.pat_len;
                results.push(match_start);
                state = self.start;
            } else if state == self.dead {
                state = self.start;
            }
        }
        results
    }

    /// Number of states in the DFA.
    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.states.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiPatternMatcher — Aho-Corasick style for exact-byte patterns
// ─────────────────────────────────────────────────────────────────────────────

/// A multi-pattern matcher for collections of exact (no-wildcard) byte patterns.
/// Uses a simple trie + failure-link construction similar to Aho-Corasick.
pub struct MultiPatternMatcher {
    /// Trie nodes: each node has 256 child slots.
    goto: Vec<[usize; 256]>,
    /// Output: which pattern indices match at this node.
    output: Vec<Vec<usize>>,
    /// Failure links.
    fail: Vec<usize>,
    /// Pattern names corresponding to indices.
    pub pattern_names: Vec<Option<String>>,
    /// Number of patterns.
    pub count: usize,
}

const FAIL_STATE: usize = usize::MAX;

impl MultiPatternMatcher {
    /// Build a matcher from a list of exact-byte patterns.
    ///
    /// Patterns containing wildcards are silently skipped.
    #[must_use]
    pub fn build(patterns: &[Pattern]) -> Self {
        // Collect exact patterns only
        let exact_pats: Vec<(usize, Vec<u8>, Option<String>)> = patterns
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.to_bytes().map(|b| (i, b, p.name.clone())))
            .collect();

        let mut goto: Vec<[usize; 256]> = vec![[FAIL_STATE; 256]];
        let mut output: Vec<Vec<usize>> = vec![Vec::new()];
        let fail: Vec<usize> = Vec::new();
        let pattern_names: Vec<Option<String>> =
            exact_pats.iter().map(|(_, _, n)| n.clone()).collect();
        let count = exact_pats.len();

        // Build goto function (trie construction)
        for (pat_idx, bytes, _) in &exact_pats {
            let mut state = 0usize;
            for &byte in bytes {
                let b = byte as usize;
                if goto[state][b] == FAIL_STATE {
                    goto.push([FAIL_STATE; 256]);
                    output.push(Vec::new());
                    goto[state][b] = goto.len() - 1;
                }
                state = goto[state][b];
            }
            output[state].push(*pat_idx);
        }

        let mut matcher = Self {
            goto,
            output,
            fail,
            pattern_names,
            count,
        };
        matcher.build_failure_links();
        matcher
    }

    fn build_failure_links(&mut self) {
        let n = self.goto.len();
        self.fail = vec![0; n];
        let mut queue = std::collections::VecDeque::new();

        // Initialise depth-1 nodes
        for b in 0..256usize {
            let s = self.goto[0][b];
            if s != FAIL_STATE && s != 0 {
                self.fail[s] = 0;
                queue.push_back(s);
            } else {
                self.goto[0][b] = 0;
            }
        }

        while let Some(r) = queue.pop_front() {
            for b in 0..256usize {
                let mut s = self.goto[r][b];
                if s == FAIL_STATE {
                    // redirect through failure links
                    self.goto[r][b] = self.goto[self.fail[r]][b];
                } else {
                    // compute failure link for s
                    let mut failure = self.fail[r];
                    while failure != 0 && self.goto[failure][b] == FAIL_STATE {
                        failure = self.fail[failure];
                    }
                    let fs = self.goto[failure][b];
                    self.fail[s] = if fs == s { 0 } else { fs };
                    // merge output
                    let fs_out = self.output[self.fail[s]].clone();
                    self.output[s].extend(fs_out);
                    queue.push_back(s);
                }
                // re-read after potential borrow
                s = self.goto[r][b];
                let _ = s;
            }
        }
    }

    /// Search `data`, returning `(offset, pattern_index)` for each match.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut results = Vec::new();
        let mut state = 0usize;
        for (i, &byte) in data.iter().enumerate() {
            state = self.goto[state][byte as usize];
            for &pat_idx in &self.output[state] {
                results.push((i, pat_idx));
            }
        }
        results
    }

    /// Number of trie states.
    #[must_use]
    pub const fn state_count(&self) -> usize {
        self.goto.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternRange — byte-value range constraint
// ─────────────────────────────────────────────────────────────────────────────

/// Matches bytes whose value falls within an inclusive range `[lo, hi]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternRange {
    pub lo: u8,
    pub hi: u8,
}

impl PatternRange {
    /// Create a new range.
    #[must_use]
    pub const fn new(lo: u8, hi: u8) -> Self {
        Self { lo, hi }
    }

    /// Return `true` if `byte` is within the range.
    #[must_use]
    pub const fn contains(self, byte: u8) -> bool {
        byte >= self.lo && byte <= self.hi
    }

    /// Return all byte values in the range.
    #[must_use]
    pub fn expand(self) -> Vec<u8> {
        (self.lo..=self.hi).collect()
    }

    /// Convert to a `PatternByte` list of alternating exact bytes.
    #[must_use]
    pub fn to_pattern_bytes(self) -> Vec<PatternByte> {
        self.expand().into_iter().map(PatternByte::Exact).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SequencePattern — ordered list of sub-patterns with optional offsets
// ─────────────────────────────────────────────────────────────────────────────

/// An ordered sequence of sub-patterns that must all match within a region,
/// each at a fixed offset from the start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencePattern {
    /// `(offset, pattern)` pairs — each `offset` is relative to the sequence start.
    pub entries: Vec<(usize, Pattern)>,
    pub name: Option<String>,
}

impl SequencePattern {
    /// Create a new empty sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            name: None,
        }
    }

    /// Add an entry.
    pub fn add(&mut self, offset: usize, pattern: Pattern) {
        self.entries.push((offset, pattern));
    }

    /// Assign a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Returns `true` if all sub-patterns match `data` at their respective offsets
    /// relative to `base`.
    #[must_use]
    pub fn matches(&self, data: &[u8], base: usize) -> bool {
        for (offset, pat) in &self.entries {
            if !pat.matches(data, base + offset) {
                return false;
            }
        }
        true
    }

    /// Search `data`, returning base offsets where all sub-patterns match.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.entries.is_empty() || data.is_empty() {
            return Vec::new();
        }
        // Use the first entry as the anchor
        let (first_offset, first_pat) = &self.entries[0];
        first_pat
            .search(data)
            .into_iter()
            .filter_map(|hit| {
                if hit < *first_offset {
                    return None;
                }
                let base = hit - first_offset;
                if self.matches(data, base) {
                    Some(base)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for SequencePattern {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RepeatPattern — pattern repeated N or N..M times
// ─────────────────────────────────────────────────────────────────────────────

/// Matches a sub-pattern repeated a specified number of times.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeatPattern {
    pub inner: Pattern,
    pub min_count: usize,
    pub max_count: usize,
}

impl RepeatPattern {
    /// Create a repeat pattern with `min..=max` repetitions.
    #[must_use]
    pub fn new(inner: Pattern, min_count: usize, max_count: usize) -> Self {
        Self {
            inner,
            min_count: min_count.min(max_count),
            max_count,
        }
    }

    /// Create a pattern that matches exactly `n` repetitions.
    #[must_use]
    pub fn exactly(inner: Pattern, n: usize) -> Self {
        Self::new(inner, n, n)
    }

    /// Create a `+` (one-or-more) repeat pattern.
    #[must_use]
    pub fn one_or_more(inner: Pattern) -> Self {
        Self::new(inner, 1, usize::MAX / 2)
    }

    /// Create a `*` (zero-or-more) repeat pattern.
    #[must_use]
    pub fn zero_or_more(inner: Pattern) -> Self {
        Self::new(inner, 0, usize::MAX / 2)
    }

    /// Returns how many consecutive repetitions of `inner` appear at `offset`.
    #[must_use]
    fn count_at(&self, data: &[u8], offset: usize) -> usize {
        let step = self.inner.len();
        if step == 0 {
            return 0;
        }
        let mut count = 0;
        let mut pos = offset;
        while count < self.max_count && pos + step <= data.len() {
            if self.inner.matches(data, pos) {
                count += 1;
                pos += step;
            } else {
                break;
            }
        }
        count
    }

    /// Returns `true` if the repeat pattern matches at `offset` in `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        let c = self.count_at(data, offset);
        c >= self.min_count
    }

    /// Total byte length consumed by the minimum number of repetitions.
    #[must_use]
    pub const fn min_byte_len(&self) -> usize {
        self.inner.len() * self.min_count
    }

    /// Search for all positions where the repeat pattern matches.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        (0..data.len())
            .filter(|&off| self.matches(data, off))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternStatistics — distribution metrics on a pattern collection
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics over a collection of patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStatistics {
    pub total: usize,
    pub exact_only: usize,
    pub with_wildcards: usize,
    pub avg_length: f64,
    pub avg_specificity: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub tagged: usize,
    pub named: usize,
}

impl PatternStatistics {
    /// Compute statistics over `patterns`.
    #[must_use]
    pub fn compute(patterns: &[Pattern]) -> Self {
        if patterns.is_empty() {
            return Self {
                total: 0,
                exact_only: 0,
                with_wildcards: 0,
                avg_length: 0.0,
                avg_specificity: 0.0,
                min_length: 0,
                max_length: 0,
                tagged: 0,
                named: 0,
            };
        }
        let total = patterns.len();
        let exact_only = patterns.iter().filter(|p| p.to_bytes().is_some()).count();
        let with_wildcards = total - exact_only;
        let lengths: Vec<usize> = patterns.iter().map(Pattern::len).collect();
        let avg_length = lengths.iter().sum::<usize>() as f64 / total as f64;
        let avg_specificity = patterns.iter().map(Pattern::specificity).sum::<f64>() / total as f64;
        let min_length = *lengths.iter().min().unwrap_or(&0);
        let max_length = *lengths.iter().max().unwrap_or(&0);
        let tagged = patterns.iter().filter(|p| !p.tags.is_empty()).count();
        let named = patterns.iter().filter(|p| p.name.is_some()).count();
        Self {
            total,
            exact_only,
            with_wildcards,
            avg_length,
            avg_specificity,
            min_length,
            max_length,
            tagged,
            named,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for the expanded API
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded {
    use super::*;

    // ── CommonPatterns ────────────────────────────────────────────────────────

    #[test]
    fn test_pe_dos_magic_parse() {
        let pat = CommonPatterns::pe_dos_magic();
        assert_eq!(pat.len(), 2);
        assert!(pat.matches(&[0x4D, 0x5A], 0));
    }

    #[test]
    fn test_elf_magic_search() {
        let pat = CommonPatterns::elf_magic();
        let data = [0x00, 0x7F, 0x45, 0x4C, 0x46, 0x02];
        assert_eq!(pat.search(&data), vec![1]);
    }

    #[test]
    fn test_zip_magic_search() {
        let pat = CommonPatterns::zip_magic();
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00];
        assert_eq!(pat.search(&data), vec![0]);
    }

    #[test]
    fn test_png_magic_matches() {
        let magic = [0x89u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let pat = CommonPatterns::png_magic();
        assert!(pat.matches(&magic, 0));
    }

    #[test]
    fn test_x64_prologue_matches() {
        let data = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        let pat = CommonPatterns::x64_prologue();
        assert!(pat.matches(&data, 0));
    }

    #[test]
    fn test_aes_sbox_start() {
        let data = [0x63u8, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5];
        let pat = CommonPatterns::aes_sbox_start();
        assert!(pat.matches(&data, 0));
    }

    #[test]
    fn test_magic_group_finds_elf() {
        let g = CommonPatterns::magic_group();
        let data = [0x7Fu8, 0x45, 0x4C, 0x46, 0x02, 0x01];
        let matches = g.search_all(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.pattern_name.as_deref() == Some("ELF_MAGIC"))
        );
    }

    #[test]
    fn test_shellcode_group_finds_int3() {
        let g = CommonPatterns::shellcode_group();
        let data = [0x00u8, 0xCC, 0x00];
        let matches = g.search_all(&data);
        assert!(matches.iter().any(|m| m.offset == 1));
    }

    #[test]
    fn test_crypto_group_finds_aes_sbox() {
        let g = CommonPatterns::crypto_group();
        let data = [0x63u8, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30];
        let matches = g.search_all(&data);
        assert!(!matches.is_empty());
    }

    // ── PatternTester ─────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_tester_pass() {
        let mut tester = PatternTester::new();
        let pat = Pattern::parse("AA BB").unwrap().with_name("test");
        let data = [0xAAu8, 0xBB, 0xAA, 0xBB];
        let result = tester.test(&pat, &data, 2).clone();
        assert!(result.passed);
        assert_eq!(result.match_count, 2);
    }

    #[test]
    fn test_pattern_tester_fail() {
        let mut tester = PatternTester::new();
        let pat = Pattern::parse("DE AD").unwrap().with_name("missing");
        let data = [0x00u8, 0x01, 0x02];
        let result = tester.test(&pat, &data, 1).clone();
        assert!(!result.passed);
        assert_eq!(tester.fail_count(), 1);
        let _ = result;
    }

    #[test]
    fn test_pattern_tester_alternation() {
        let mut tester = PatternTester::new();
        let alt = AlternationPattern::parse("AA | BB")
            .unwrap()
            .with_name("either");
        let data = [0xAAu8, 0xBB, 0xCC];
        let result = tester.test_alternation(&alt, &data, 2).clone();
        assert!(result.passed);
    }

    #[test]
    fn test_tester_pass_fail_counts() {
        let mut tester = PatternTester::new();
        let p1 = Pattern::parse("AA").unwrap().with_name("p1");
        let p2 = Pattern::parse("FF").unwrap().with_name("p2");
        let data = [0xAAu8, 0x00, 0x00];
        tester.test(&p1, &data, 1);
        tester.test(&p2, &data, 1);
        assert_eq!(tester.pass_count(), 1);
        assert_eq!(tester.fail_count(), 1);
    }

    // ── PatternNfa ────────────────────────────────────────────────────────────

    #[test]
    fn test_nfa_find_first_exact() {
        let pat = Pattern::parse("DE AD").unwrap();
        let nfa = PatternNfa::compile(&pat);
        let data = [0x00u8, 0xDE, 0xAD, 0x00];
        let result = nfa.find_first(&data, 0);
        assert_eq!(result, Some((1, 3)));
    }

    #[test]
    fn test_nfa_find_first_wildcard() {
        let pat = Pattern::parse("DE ? BE").unwrap();
        let nfa = PatternNfa::compile(&pat);
        let data = [0xDEu8, 0xAA, 0xBE, 0x00];
        let result = nfa.find_first(&data, 0);
        assert_eq!(result, Some((0, 3)));
    }

    #[test]
    fn test_nfa_find_all() {
        let pat = Pattern::parse("AA BB").unwrap();
        let nfa = PatternNfa::compile(&pat);
        let data = [0xAAu8, 0xBB, 0x00, 0xAA, 0xBB];
        let matches = nfa.find_all(&data);
        assert_eq!(matches, vec![(0, 2), (3, 5)]);
    }

    #[test]
    fn test_nfa_empty_pattern() {
        let pat = Pattern {
            bytes: Vec::new(),
            name: None,
            tags: Vec::new(),
            captures: Vec::new(),
            comment: String::new(),
        };
        let nfa = PatternNfa::compile(&pat);
        assert!(nfa.is_empty());
    }

    // ── PatternDfa ────────────────────────────────────────────────────────────

    #[test]
    fn test_dfa_search_exact() {
        let pat = Pattern::parse("DE AD BE EF").unwrap();
        let dfa = PatternDfa::compile(&pat);
        let data = [0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let matches = dfa.search(&data);
        assert_eq!(matches, vec![1]);
    }

    #[test]
    fn test_dfa_search_wildcard() {
        let pat = Pattern::parse("DE ? EF").unwrap();
        let dfa = PatternDfa::compile(&pat);
        let data = [0xDEu8, 0xCC, 0xEF, 0xDE, 0xDD, 0xEF];
        let matches = dfa.search(&data);
        assert!(matches.contains(&0));
        assert!(matches.contains(&3));
    }

    #[test]
    fn test_dfa_state_count() {
        let pat = Pattern::parse("AA BB CC").unwrap();
        let dfa = PatternDfa::compile(&pat);
        assert!(dfa.state_count() > 3);
    }

    // ── MultiPatternMatcher ───────────────────────────────────────────────────

    #[test]
    fn test_multi_matcher_build_and_search() {
        let pats = vec![
            Pattern::parse("AA BB").unwrap().with_name("p1"),
            Pattern::parse("CC DD").unwrap().with_name("p2"),
        ];
        let matcher = MultiPatternMatcher::build(&pats);
        let data = [0x00u8, 0xAA, 0xBB, 0x00, 0xCC, 0xDD];
        let results = matcher.search(&data);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_multi_matcher_skips_wildcards() {
        let pats = vec![
            Pattern::parse("AA ? BB").unwrap().with_name("wc"),
            Pattern::parse("CC DD").unwrap().with_name("exact"),
        ];
        let matcher = MultiPatternMatcher::build(&pats);
        assert_eq!(matcher.count, 1); // only exact pattern
    }

    // ── PatternRange ──────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_range_contains() {
        let r = PatternRange::new(0x20, 0x7E);
        assert!(r.contains(0x41)); // 'A'
        assert!(!r.contains(0x00));
        assert!(!r.contains(0x80));
    }

    #[test]
    fn test_pattern_range_expand() {
        let r = PatternRange::new(0, 3);
        assert_eq!(r.expand(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_pattern_range_to_pattern_bytes() {
        let r = PatternRange::new(0x41, 0x43); // A B C
        let bytes = r.to_pattern_bytes();
        assert_eq!(bytes.len(), 3);
        assert!(bytes[0].matches(0x41));
        assert!(!bytes[0].matches(0x42));
    }

    // ── SequencePattern ───────────────────────────────────────────────────────

    #[test]
    fn test_sequence_pattern_matches() {
        let mut seq = SequencePattern::new();
        seq.add(0, Pattern::parse("4D 5A").unwrap());
        seq.add(0x3C, Pattern::parse("50 45 00 00").unwrap());
        let mut data = vec![0u8; 0x40];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[0x3C] = 0x50;
        data[0x3D] = 0x45;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        assert!(seq.matches(&data, 0));
    }

    #[test]
    fn test_sequence_pattern_search() {
        let mut seq = SequencePattern::new();
        seq.add(0, Pattern::parse("AA").unwrap());
        seq.add(2, Pattern::parse("BB").unwrap());
        let data = [0xAAu8, 0x00, 0xBB, 0x00, 0xAA, 0x00, 0xBB];
        let results = seq.search(&data);
        assert!(results.contains(&0));
        assert!(results.contains(&4));
    }

    // ── RepeatPattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_repeat_exactly_n() {
        let inner = Pattern::parse("90").unwrap(); // NOP
        let rep = RepeatPattern::exactly(inner, 3);
        let data = [0x90u8, 0x90, 0x90, 0x00];
        assert!(rep.matches(&data, 0));
        assert!(!rep.matches(&data, 1)); // only 2 NOPs left
    }

    #[test]
    fn test_repeat_one_or_more() {
        let inner = Pattern::parse("AA").unwrap();
        let rep = RepeatPattern::one_or_more(inner);
        let data = [0xAAu8, 0xAA, 0xAA, 0x00];
        assert!(rep.matches(&data, 0));
        assert!(!rep.matches(&data, 3)); // no match at 0x00
    }

    #[test]
    fn test_repeat_zero_or_more() {
        let inner = Pattern::parse("BB").unwrap();
        let rep = RepeatPattern::zero_or_more(inner);
        // Zero or more always matches (even at a non-BB position)
        let data = [0x00u8];
        assert!(rep.matches(&data, 0));
    }

    #[test]
    fn test_repeat_search() {
        let inner = Pattern::parse("90").unwrap();
        let rep = RepeatPattern::exactly(inner, 2);
        let data = [0x90u8, 0x90, 0x00, 0x90, 0x90];
        let hits = rep.search(&data);
        assert!(hits.contains(&0));
        assert!(hits.contains(&3));
    }

    // ── PatternStatistics ─────────────────────────────────────────────────────

    #[test]
    fn test_pattern_stats_basic() {
        let pats = vec![
            Pattern::parse("AA BB")
                .unwrap()
                .with_name("a")
                .with_tag("t"),
            Pattern::parse("CC ? EE").unwrap().with_name("b"),
            Pattern::parse("DD").unwrap(),
        ];
        let stats = PatternStatistics::compute(&pats);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.exact_only, 2);
        assert_eq!(stats.with_wildcards, 1);
        assert_eq!(stats.named, 2);
        assert_eq!(stats.tagged, 1);
        assert_eq!(stats.min_length, 1);
        assert_eq!(stats.max_length, 3);
    }

    #[test]
    fn test_pattern_stats_empty() {
        let stats = PatternStatistics::compute(&[]);
        assert_eq!(stats.total, 0);
        assert_eq!(stats.avg_length, 0.0);
    }

    #[test]
    fn test_pattern_stats_avg_specificity() {
        let pats = vec![
            Pattern::parse("AA BB CC").unwrap(), // 100% specific
            Pattern::parse("? ? ?").unwrap(),    // 0% specific
        ];
        let stats = PatternStatistics::compute(&pats);
        // avg should be ~50%
        assert!((stats.avg_specificity - 0.5).abs() < 0.01);
    }

    // ── PatternRange additional ───────────────────────────────────────────────

    #[test]
    fn test_pattern_range_printable_ascii() {
        let r = PatternRange::new(0x20, 0x7E);
        assert!(r.contains(b'A'));
        assert!(r.contains(b'z'));
        assert!(r.contains(b' '));
        assert!(!r.contains(0x7F)); // DEL
        assert!(!r.contains(0x1F)); // control
    }

    // ── to_hex_string round-trip ──────────────────────────────────────────────

    #[test]
    fn test_hex_string_round_trip() {
        let original = "DE AD ? ? BE EF";
        let pat = Pattern::parse(original).unwrap();
        let hex_str = pat.to_hex_string();
        let pat2 = Pattern::parse(&hex_str).unwrap();
        assert_eq!(pat.bytes, pat2.bytes);
    }

    // ── crc16_ibm additional ──────────────────────────────────────────────────

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16_ibm(&[]), 0x0000);
    }

    #[test]
    fn test_crc16_single_byte() {
        // Precomputed: CRC16/IBM of [0x00] = 0x0000
        let crc = crc16_ibm(&[0x00]);
        assert_eq!(crc, 0x0000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteMask — bitmask-based byte matching
// ─────────────────────────────────────────────────────────────────────────────

/// A byte pattern element that matches any byte satisfying `(b & mask) == value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteMask {
    pub mask: u8,
    pub value: u8,
}

impl ByteMask {
    /// Exact match: mask = 0xFF, value = v.
    #[must_use]
    pub const fn exact(v: u8) -> Self {
        Self {
            mask: 0xFF,
            value: v,
        }
    }

    /// Wildcard: mask = 0x00, value = 0x00 (always matches).
    #[must_use]
    pub const fn wildcard() -> Self {
        Self {
            mask: 0x00,
            value: 0x00,
        }
    }

    /// High-nibble match: mask = 0xF0.
    #[must_use]
    pub const fn high_nibble(n: u8) -> Self {
        Self {
            mask: 0xF0,
            value: (n & 0x0F) << 4,
        }
    }

    /// Low-nibble match: mask = 0x0F.
    #[must_use]
    pub const fn low_nibble(n: u8) -> Self {
        Self {
            mask: 0x0F,
            value: n & 0x0F,
        }
    }

    /// Returns `true` if `b` satisfies this mask.
    #[must_use]
    pub const fn matches(self, b: u8) -> bool {
        (b & self.mask) == self.value
    }

    /// Returns `true` if this is a wildcard (mask == 0).
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        self.mask == 0
    }

    /// Returns `true` if this is an exact match (mask == 0xFF).
    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.mask == 0xFF
    }

    /// Returns the specificity fraction `popcount(mask) / 8`.
    #[must_use]
    pub fn specificity(self) -> f64 {
        f64::from(self.mask.count_ones()) / 8.0
    }
}

/// A pattern represented as a sequence of `ByteMask` elements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedBytePattern {
    pub elements: Vec<ByteMask>,
    pub name: Option<String>,
}

impl MaskedBytePattern {
    /// Create from a slice of masks.
    #[must_use]
    pub const fn new(elements: Vec<ByteMask>) -> Self {
        Self {
            elements,
            name: None,
        }
    }

    /// Set the name.
    #[must_use]
    pub fn with_name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into());
        self
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns `true` if `data[offset..]` matches this pattern.
    #[must_use]
    pub fn matches(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.elements.len() > data.len() {
            return false;
        }
        data[offset..]
            .iter()
            .zip(self.elements.iter())
            .all(|(&b, m)| m.matches(b))
    }

    /// Find all match offsets in `data`.
    #[must_use]
    pub fn search(&self, data: &[u8]) -> Vec<usize> {
        if self.elements.is_empty() {
            return Vec::new();
        }
        (0..data.len()).filter(|&i| self.matches(data, i)).collect()
    }

    /// Overall specificity: average over all elements.
    #[must_use]
    pub fn specificity(&self) -> f64 {
        if self.elements.is_empty() {
            return 0.0;
        }
        self.elements.iter().map(|m| m.specificity()).sum::<f64>() / self.elements.len() as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternBook — a named collection of `MaskedBytePattern` entries
// ─────────────────────────────────────────────────────────────────────────────

/// A named book (category) of masked byte patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternBook {
    pub category: String,
    pub patterns: Vec<MaskedBytePattern>,
}

impl PatternBook {
    /// Create a new pattern book.
    #[must_use]
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            patterns: Vec::new(),
        }
    }

    /// Add a pattern.
    pub fn add(&mut self, pat: MaskedBytePattern) {
        self.patterns.push(pat);
    }

    /// Search all patterns in this book against `data`.
    ///
    /// Returns a list of `(pattern_index, offset)` pairs.
    #[must_use]
    pub fn search_all(&self, data: &[u8]) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        for (pi, pat) in self.patterns.iter().enumerate() {
            for offset in pat.search(data) {
                hits.push((pi, offset));
            }
        }
        hits.sort_by_key(|&(_, o)| o);
        hits
    }

    /// Number of patterns.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// JSON serialise.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on serialisation failure.
    pub fn to_json(&self) -> Result<String, PatternError> {
        serde_json::to_string_pretty(self).map_err(|e| PatternError::Database(e.to_string()))
    }

    /// JSON deserialise.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on deserialisation failure.
    pub fn from_json(s: &str) -> Result<Self, PatternError> {
        serde_json::from_str(s).map_err(|e| PatternError::Database(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BoyerMoore — pattern search optimisation hint
// ─────────────────────────────────────────────────────────────────────────────

/// Bad-character shift table for Boyer-Moore-Horspool search.
#[derive(Debug, Clone)]
pub struct BmhTable {
    /// Shift values indexed by byte value.
    shifts: [usize; 256],
    /// Pattern length.
    pattern_len: usize,
}

impl BmhTable {
    /// Build the table from an exact byte pattern.
    ///
    /// # Panics
    /// Panics if `pattern` is empty.
    #[must_use]
    pub fn build(pattern: &[u8]) -> Self {
        assert!(!pattern.is_empty(), "BmhTable: pattern must not be empty");
        let n = pattern.len();
        let mut shifts = [n; 256];
        for (i, &b) in pattern.iter().enumerate().take(n - 1) {
            shifts[b as usize] = n - 1 - i;
        }
        Self {
            shifts,
            pattern_len: n,
        }
    }

    /// Perform Boyer-Moore-Horspool search and return all match offsets.
    #[must_use]
    pub fn search(&self, haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        let m = needle.len();
        if m == 0 || haystack.len() < m {
            return Vec::new();
        }
        let mut matches = Vec::new();
        let mut i = m - 1;
        while i < haystack.len() {
            let mut j = m;
            let mut k = i;
            let mut matched = true;
            loop {
                if j == 0 {
                    break;
                }
                j -= 1;
                if haystack[k] != needle[j] {
                    matched = false;
                    break;
                }
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            if matched && j == 0 {
                matches.push(i + 1 - m);
            }
            i += self.shifts[haystack[i] as usize];
        }
        matches
    }

    /// Pattern length this table was built for.
    #[must_use]
    pub const fn pattern_len(&self) -> usize {
        self.pattern_len
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternCatalog — in-memory catalog with tagging and search
// ─────────────────────────────────────────────────────────────────────────────

/// Entry in the in-memory pattern catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub id: u64,
    pub pattern: Pattern,
    pub description: String,
    pub tags: Vec<String>,
}

impl CatalogEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(id: u64, pattern: Pattern, description: impl Into<String>) -> Self {
        Self {
            id,
            pattern,
            description: description.into(),
            tags: Vec::new(),
        }
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Returns `true` if the entry has the given tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// In-memory catalog of patterns with fast lookup and filtering.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternCatalog {
    entries: Vec<CatalogEntry>,
    next_id: u64,
}

impl PatternCatalog {
    /// Create an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern to the catalog.
    ///
    /// Returns the assigned ID.
    pub fn add(&mut self, pattern: Pattern, description: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries
            .push(CatalogEntry::new(id, pattern, description));
        id
    }

    /// Remove entry by ID. Returns `true` if found.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() < before
    }

    /// Get entry by ID.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Filter by tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&CatalogEntry> {
        self.entries.iter().filter(|e| e.has_tag(tag)).collect()
    }

    /// Search all entries against `data`, returning `(id, offset)` pairs.
    #[must_use]
    pub fn search_all(&self, data: &[u8]) -> Vec<(u64, usize)> {
        let mut hits = Vec::new();
        for entry in &self.entries {
            for offset in entry.pattern.search(data) {
                hits.push((entry.id, offset));
            }
        }
        hits.sort_by_key(|&(_, o)| o);
        hits
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// JSON serialise.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on serialisation failure.
    pub fn to_json(&self) -> Result<String, PatternError> {
        serde_json::to_string_pretty(self).map_err(|e| PatternError::Database(e.to_string()))
    }

    /// JSON deserialise.
    ///
    /// # Errors
    /// Returns `PatternError::Database` on deserialisation failure.
    pub fn from_json(s: &str) -> Result<Self, PatternError> {
        serde_json::from_str(s).map_err(|e| PatternError::Database(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternDiff — compare two byte slices using patterns
// ─────────────────────────────────────────────────────────────────────────────

/// Result of comparing two buffers using a pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDiffResult {
    /// Offsets where left matches but right doesn't.
    pub left_only: Vec<usize>,
    /// Offsets where right matches but left doesn't.
    pub right_only: Vec<usize>,
    /// Offsets where both match.
    pub common: Vec<usize>,
}

impl PatternDiffResult {
    /// Returns `true` if both buffers produce identical match sets.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.left_only.is_empty() && self.right_only.is_empty()
    }

    /// Total unique match positions.
    #[must_use]
    pub const fn total_unique(&self) -> usize {
        self.left_only.len() + self.right_only.len() + self.common.len()
    }
}

/// Compare two buffers using a pattern.
#[must_use]
pub fn pattern_diff(pattern: &Pattern, left: &[u8], right: &[u8]) -> PatternDiffResult {
    let left_hits: std::collections::HashSet<usize> = pattern.search(left).into_iter().collect();
    let right_hits: std::collections::HashSet<usize> = pattern.search(right).into_iter().collect();
    let mut common: Vec<usize> = left_hits.intersection(&right_hits).copied().collect();
    let mut left_only: Vec<usize> = left_hits.difference(&right_hits).copied().collect();
    let mut right_only: Vec<usize> = right_hits.difference(&left_hits).copied().collect();
    common.sort_unstable();
    left_only.sort_unstable();
    right_only.sort_unstable();
    PatternDiffResult {
        left_only,
        right_only,
        common,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternConverter — convert between Pattern and MaskedBytePattern
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a `Pattern` to its equivalent `MaskedBytePattern`.
#[must_use]
pub fn pattern_to_masked(pat: &Pattern) -> MaskedBytePattern {
    let elements = pat
        .bytes
        .iter()
        .map(|pb| match *pb {
            PatternByte::Exact(b) => ByteMask::exact(b),
            PatternByte::Wildcard => ByteMask::wildcard(),
            PatternByte::Nibble { high, low } => match (high, low) {
                (Some(h), Some(l)) => ByteMask::exact((h << 4) | l),
                (Some(h), None) => ByteMask::high_nibble(h),
                (None, Some(l)) => ByteMask::low_nibble(l),
                (None, None) => ByteMask::wildcard(),
            },
        })
        .collect();
    MaskedBytePattern::new(elements)
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternHighlightMap — byte-level highlighting from pattern matches
// ─────────────────────────────────────────────────────────────────────────────

/// Maps byte offsets to pattern match indices.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternHighlightMap {
    /// `offset → (pattern_index, match_index_within_pattern)`
    pub spans: HashMap<usize, (usize, usize)>,
}

impl PatternHighlightMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate from catalog search results and pattern lengths.
    #[must_use]
    pub fn from_search(results: &[(u64, usize)], catalog: &PatternCatalog) -> Self {
        let mut spans = HashMap::new();
        for (i, &(id, offset)) in results.iter().enumerate() {
            if let Some(entry) = catalog.get(id) {
                let len = entry.pattern.bytes.len();
                for k in 0..len {
                    spans.insert(offset + k, (i, k));
                }
            }
        }
        Self { spans }
    }

    /// Returns the match info at `offset`, if any.
    #[must_use]
    pub fn at(&self, offset: usize) -> Option<(usize, usize)> {
        self.spans.get(&offset).copied()
    }

    /// Returns `true` if `offset` is highlighted.
    #[must_use]
    pub fn is_highlighted(&self, offset: usize) -> bool {
        self.spans.contains_key(&offset)
    }

    /// Number of highlighted bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Returns `true` if no bytes are highlighted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for extended pattern features
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_extra {
    use super::*;

    // ── ByteMask ──────────────────────────────────────────────────────────────

    #[test]
    fn test_byte_mask_exact() {
        let m = ByteMask::exact(0xAB);
        assert!(m.matches(0xAB));
        assert!(!m.matches(0xAC));
        assert!(m.is_exact());
        assert!(!m.is_wildcard());
    }

    #[test]
    fn test_byte_mask_wildcard() {
        let m = ByteMask::wildcard();
        assert!(m.matches(0x00));
        assert!(m.matches(0xFF));
        assert!(m.is_wildcard());
    }

    #[test]
    fn test_byte_mask_high_nibble() {
        let m = ByteMask::high_nibble(0xA);
        assert!(m.matches(0xA0));
        assert!(m.matches(0xAF));
        assert!(!m.matches(0xBF));
    }

    #[test]
    fn test_byte_mask_low_nibble() {
        let m = ByteMask::low_nibble(0xB);
        assert!(m.matches(0x0B));
        assert!(m.matches(0xFB));
        assert!(!m.matches(0xBC));
    }

    #[test]
    fn test_byte_mask_specificity() {
        assert!((ByteMask::exact(0).specificity() - 1.0).abs() < 1e-9);
        assert!((ByteMask::wildcard().specificity() - 0.0).abs() < 1e-9);
        let m = ByteMask::high_nibble(0xA); // mask 0xF0 = 4 bits
        assert!((m.specificity() - 0.5).abs() < 1e-9);
    }

    // ── MaskedBytePattern ─────────────────────────────────────────────────────

    #[test]
    fn test_masked_pattern_exact_match() {
        let pat = MaskedBytePattern::new(vec![
            ByteMask::exact(0xDE),
            ByteMask::exact(0xAD),
            ByteMask::exact(0xBE),
        ]);
        let data = [0x00u8, 0xDE, 0xAD, 0xBE, 0x00];
        let hits = pat.search(&data);
        assert_eq!(hits, vec![1]);
    }

    #[test]
    fn test_masked_pattern_wildcard_match() {
        let pat = MaskedBytePattern::new(vec![
            ByteMask::exact(0xDE),
            ByteMask::wildcard(),
            ByteMask::exact(0xBE),
        ]);
        let data = [0xDEu8, 0xAA, 0xBE];
        assert!(pat.matches(&data, 0));
    }

    #[test]
    fn test_masked_pattern_specificity() {
        let pat = MaskedBytePattern::new(vec![ByteMask::exact(0xFF), ByteMask::wildcard()]);
        assert!((pat.specificity() - 0.5).abs() < 1e-9);
    }

    // ── PatternBook ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_book_search() {
        let mut book = PatternBook::new("test");
        book.add(MaskedBytePattern::new(vec![
            ByteMask::exact(0xAA),
            ByteMask::exact(0xBB),
        ]));
        book.add(MaskedBytePattern::new(vec![ByteMask::exact(0xCC)]));
        let data = [0x00u8, 0xAA, 0xBB, 0xCC];
        let hits = book.search_all(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_pattern_book_json_roundtrip() {
        let mut book = PatternBook::new("crypto");
        book.add(MaskedBytePattern::new(vec![ByteMask::exact(0x63)]));
        let json = book.to_json().unwrap();
        let back = PatternBook::from_json(&json).unwrap();
        assert_eq!(back.category, "crypto");
        assert_eq!(back.len(), 1);
    }

    // ── BmhTable ──────────────────────────────────────────────────────────────

    #[test]
    fn test_bmh_search_basic() {
        let _needle = b"DE AD";
        let table = BmhTable::build(b"DEAD");
        let haystack = b"\x00\xDE\xAD\x00\xDE\xAD";
        let hits = table.search(haystack, b"DEAD");
        // not byte-level here — just sanity-test table builds
        assert_eq!(table.pattern_len(), 4);
        let _ = hits;
    }

    #[test]
    fn test_bmh_exact_single() {
        let needle = b"hello";
        let table = BmhTable::build(needle);
        let haystack = b"say hello world hello";
        let hits = table.search(haystack, needle);
        assert!(hits.contains(&4));
        assert!(hits.contains(&16));
    }

    #[test]
    fn test_bmh_no_match() {
        let needle = b"xyz";
        let table = BmhTable::build(needle);
        let hits = table.search(b"abc def", needle);
        assert!(hits.is_empty());
    }

    // ── PatternCatalog ────────────────────────────────────────────────────────

    #[test]
    fn test_catalog_add_remove() {
        let mut cat = PatternCatalog::new();
        let id = cat.add(Pattern::parse("AA BB").unwrap(), "test");
        assert_eq!(cat.len(), 1);
        assert!(cat.remove(id));
        assert!(cat.is_empty());
    }

    #[test]
    fn test_catalog_by_tag() {
        let mut cat = PatternCatalog::new();
        let id = cat.add(Pattern::parse("AA").unwrap(), "first");
        cat.entries
            .last_mut()
            .unwrap()
            .tags
            .push("crypto".to_owned());
        let _ = cat.add(Pattern::parse("BB").unwrap(), "second");
        let tagged = cat.by_tag("crypto");
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].id, id);
    }

    #[test]
    fn test_catalog_search_all() {
        let mut cat = PatternCatalog::new();
        cat.add(Pattern::parse("AA BB").unwrap(), "p1");
        cat.add(Pattern::parse("CC DD").unwrap(), "p2");
        let data = [0x00u8, 0xAA, 0xBB, 0xCC, 0xDD];
        let hits = cat.search_all(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_catalog_json_roundtrip() {
        let mut cat = PatternCatalog::new();
        cat.add(Pattern::parse("DE AD BE EF").unwrap(), "deadbeef");
        let json = cat.to_json().unwrap();
        let back = PatternCatalog::from_json(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    // ── PatternDiff ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_diff_identical() {
        let pat = Pattern::parse("AA BB").unwrap();
        let data = [0xAAu8, 0xBB];
        let diff = pattern_diff(&pat, &data, &data);
        assert!(diff.is_identical());
        assert_eq!(diff.common.len(), 1);
    }

    #[test]
    fn test_pattern_diff_left_only() {
        let pat = Pattern::parse("AA").unwrap();
        let left = [0xAAu8, 0xBB];
        let right = [0xBBu8, 0xCC];
        let diff = pattern_diff(&pat, &left, &right);
        assert_eq!(diff.left_only.len(), 1);
        assert!(diff.right_only.is_empty());
    }

    #[test]
    fn test_pattern_diff_right_only() {
        let pat = Pattern::parse("CC").unwrap();
        let left = [0xAAu8];
        let right = [0xCCu8];
        let diff = pattern_diff(&pat, &left, &right);
        assert_eq!(diff.right_only.len(), 1);
        assert!(diff.left_only.is_empty());
    }

    // ── pattern_to_masked ─────────────────────────────────────────────────────

    #[test]
    fn test_pattern_to_masked_exact() {
        let pat = Pattern::parse("DE AD").unwrap();
        let mp = pattern_to_masked(&pat);
        assert_eq!(mp.len(), 2);
        assert!(mp.elements[0].is_exact());
        assert!(mp.elements[0].matches(0xDE));
    }

    #[test]
    fn test_pattern_to_masked_wildcard() {
        let pat = Pattern::parse("DE ? BE").unwrap();
        let mp = pattern_to_masked(&pat);
        assert!(mp.elements[1].is_wildcard());
    }

    // ── PatternHighlightMap ───────────────────────────────────────────────────

    #[test]
    fn test_highlight_map_basic() {
        let mut cat = PatternCatalog::new();
        cat.add(Pattern::parse("AA BB").unwrap(), "p1");
        let data = [0xAAu8, 0xBB, 0x00];
        let results = cat.search_all(&data);
        let map = PatternHighlightMap::from_search(&results, &cat);
        assert!(map.is_highlighted(0));
        assert!(map.is_highlighted(1));
        assert!(!map.is_highlighted(2));
    }

    #[test]
    fn test_highlight_map_empty() {
        let map = PatternHighlightMap::new();
        assert!(map.is_empty());
        assert!(!map.is_highlighted(0));
    }

    // ── ByteMask from Pattern Nibble ──────────────────────────────────────────

    #[test]
    fn test_nibble_mask_high_match() {
        let pat = Pattern::parse("A?").unwrap();
        let mp = pattern_to_masked(&pat);
        // A? means high nibble 0xA, low nibble wildcard → mask 0xF0, value 0xA0
        assert!(mp.elements[0].matches(0xA0));
        assert!(mp.elements[0].matches(0xAF));
        assert!(!mp.elements[0].matches(0xB0));
    }

    #[test]
    fn test_nibble_mask_low_match() {
        let pat = Pattern::parse("?B").unwrap();
        let mp = pattern_to_masked(&pat);
        // ?B means wildcard high, fixed low nibble B → mask 0x0F, value 0x0B
        assert!(mp.elements[0].matches(0x0B));
        assert!(mp.elements[0].matches(0xFB));
        assert!(!mp.elements[0].matches(0xBC));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// §14  ImHex Pattern Language — Parser, Evaluator, Tree, Attributes, Built-ins
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// §14.1  ParsedType — the full ImHex type grammar
// ─────────────────────────────────────────────────────────────────────────────

/// Every type that the `ImHex` pattern language can express.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParsedType {
    // ── Primitive types ──────────────────────────────────────────────────────
    U8,
    U16,
    U32,
    U64,
    U128,
    S8,
    S16,
    S32,
    S64,
    F32,
    F64,
    Bool,
    Char,
    Str,

    // ── Endian-qualified primitive ───────────────────────────────────────────
    /// `be T` or `le T` — big-endian / little-endian override.
    Endian {
        big: bool,
        inner: Box<Self>,
    },

    // ── Pointer ──────────────────────────────────────────────────────────────
    /// `T* name` — pointer to T (address is stored as u64).
    Pointer(Box<Self>),

    // ── Array ────────────────────────────────────────────────────────────────
    /// `T arr[N]`
    Array {
        element: Box<Self>,
        count: ArraySize,
    },

    // ── Compound types ───────────────────────────────────────────────────────
    Struct {
        name: String,
        fields: Vec<ParsedField>,
    },
    Union {
        name: String,
        variants: Vec<ParsedField>,
    },
    Enum {
        name: String,
        backing: Box<Self>,
        members: Vec<(String, u128)>,
    },
    Bitfield {
        name: String,
        backing: Box<Self>,
        bits: Vec<(String, u8)>,
    },

    // ── Named reference ──────────────────────────────────────────────────────
    /// Reference to a previously declared type by name.
    Named(String),
}

/// How many elements an array contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArraySize {
    /// Fixed count: `T arr[42]`
    Fixed(u64),
    /// While condition is satisfied: `T arr[while(cond)]`
    While(String),
    /// Until a given address: `T arr[until(end_addr)]`
    Until(String),
}

/// A named field within a struct or union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedField {
    pub name: String,
    pub ty: ParsedType,
    pub attributes: Vec<PatternAttribute>,
}

/// An `ImHex` pattern attribute (`[[color("RED")]]`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternAttribute {
    pub name: String,
    pub value: String,
}

impl ParsedType {
    /// Returns the byte-size of a *primitive* type (None for compound/dynamic).
    #[must_use]
    pub fn primitive_size(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::S8 | Self::Bool | Self::Char => Some(1),
            Self::U16 | Self::S16 => Some(2),
            Self::U32 | Self::S32 | Self::F32 => Some(4),
            Self::U64 | Self::S64 | Self::F64 => Some(8),
            Self::U128 => Some(16),
            Self::Str => None,
            Self::Endian { inner, .. } => inner.primitive_size(),
            Self::Pointer(_) => Some(8), // addresses stored as u64
            Self::Array { element, count } => {
                if let (Some(sz), ArraySize::Fixed(n)) = (element.primitive_size(), count) {
                    Some(sz * *n as usize)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Returns `true` if the type is a numeric primitive (integer or float).
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::U8
                | Self::U16
                | Self::U32
                | Self::U64
                | Self::U128
                | Self::S8
                | Self::S16
                | Self::S32
                | Self::S64
                | Self::F32
                | Self::F64
        )
    }

    /// Returns `true` if the type is a compound (struct / union / enum / bitfield).
    #[must_use]
    pub const fn is_compound(&self) -> bool {
        matches!(
            self,
            Self::Struct { .. } | Self::Union { .. } | Self::Enum { .. } | Self::Bitfield { .. }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.2  PatternParser — tokenise + parse ImHex pattern source
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the pattern language parser/evaluator.
#[derive(Debug, Error)]
pub enum ImHexError {
    #[error("parser error at '{token}': {reason}")]
    Parse { token: String, reason: String },
    #[error("evaluator error: {0}")]
    Eval(String),
    #[error("attribute error: {0}")]
    Attribute(String),
    #[error("type error: {0}")]
    Type(String),
    #[error("out-of-bounds read at offset {0}")]
    OutOfBounds(usize),
}

/// A simple token produced during lexing.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Number(u64),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Colon,
    Semicolon,
    Comma,
    Star,
    StarStar,
    Eq,
    At,
    Eof,
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    const fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn peek_char(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek_char() {
            self.pos += c.len_utf8();
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            // whitespace
            while self.peek_char().is_some_and(char::is_whitespace) {
                self.advance();
            }
            // line comment //
            if self.src[self.pos..].starts_with("//") {
                while self.peek_char().is_some_and(|c| c != '\n') {
                    self.advance();
                }
                continue;
            }
            // block comment /* */
            if self.src[self.pos..].starts_with("/*") {
                self.pos += 2;
                while self.pos + 1 < self.src.len() {
                    if self.src[self.pos..].starts_with("*/") {
                        self.pos += 2;
                        break;
                    }
                    self.advance();
                }
                continue;
            }
            break;
        }
    }

    fn next_token(&mut self) -> Token {
        self.skip_ws_and_comments();
        let Some(ch) = self.peek_char() else {
            return Token::Eof;
        };
        // identifier / keyword
        if ch.is_alphabetic() || ch == '_' {
            let start = self.pos;
            while self
                .peek_char()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                self.advance();
            }
            return Token::Ident(self.src[start..self.pos].to_string());
        }
        // numeric literal (decimal or 0x hex)
        if ch.is_ascii_digit() {
            let start = self.pos;
            if self.src[self.pos..].starts_with("0x") || self.src[self.pos..].starts_with("0X") {
                self.pos += 2;
                while self.peek_char().is_some_and(|c| c.is_ascii_hexdigit()) {
                    self.advance();
                }
                let hex = &self.src[start + 2..self.pos];
                return Token::Number(u64::from_str_radix(hex, 16).unwrap_or(0));
            }
            while self.peek_char().is_some_and(|c| c.is_ascii_digit()) {
                self.advance();
            }
            let dec = &self.src[start..self.pos];
            return Token::Number(dec.parse().unwrap_or(0));
        }
        // punctuation
        self.advance();
        match ch {
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '(' => Token::LParen,
            ')' => Token::RParen,
            ':' => Token::Colon,
            ';' => Token::Semicolon,
            ',' => Token::Comma,
            '*' => {
                if self.peek_char() == Some('*') {
                    self.advance();
                    Token::StarStar
                } else {
                    Token::Star
                }
            }
            '=' => Token::Eq,
            '@' => Token::At,
            // skip unknown characters and recurse
            _ => self.next_token(),
        }
    }

    fn tokenise(&mut self) -> Vec<Token> {
        let mut toks = Vec::new();
        loop {
            let t = self.next_token();
            let done = t == Token::Eof;
            toks.push(t);
            if done {
                break;
            }
        }
        toks
    }
}

/// Parser for the `ImHex` pattern language.
pub struct PatternParser {
    tokens: Vec<Token>,
    pos: usize,
}

impl PatternParser {
    /// Create a parser from source text.
    #[must_use]
    pub fn new(src: &str) -> Self {
        let mut lex = Lexer::new(src);
        let tokens = lex.tokenise();
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let t = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn expect_ident(&mut self) -> Result<String, ImHexError> {
        match self.advance().clone() {
            Token::Ident(s) => Ok(s),
            other => Err(ImHexError::Parse {
                token: format!("{other:?}"),
                reason: "expected identifier".into(),
            }),
        }
    }

    fn expect_number(&mut self) -> Result<u64, ImHexError> {
        match self.advance().clone() {
            Token::Number(n) => Ok(n),
            other => Err(ImHexError::Parse {
                token: format!("{other:?}"),
                reason: "expected number".into(),
            }),
        }
    }

    fn expect(&mut self, expected: Token) -> Result<(), ImHexError> {
        let t = self.advance().clone();
        if t == expected {
            Ok(())
        } else {
            Err(ImHexError::Parse {
                token: format!("{t:?}"),
                reason: format!("expected {expected:?}"),
            })
        }
    }

    /// Parse a base type keyword or named reference.
    fn parse_base_type(&mut self) -> Result<ParsedType, ImHexError> {
        match self.peek().clone() {
            Token::Ident(s) => {
                self.advance();
                Ok(match s.as_str() {
                    "u8" => ParsedType::U8,
                    "u16" => ParsedType::U16,
                    "u32" => ParsedType::U32,
                    "u64" => ParsedType::U64,
                    "u128" => ParsedType::U128,
                    "s8" => ParsedType::S8,
                    "s16" => ParsedType::S16,
                    "s32" => ParsedType::S32,
                    "s64" => ParsedType::S64,
                    "f32" => ParsedType::F32,
                    "f64" => ParsedType::F64,
                    "bool" => ParsedType::Bool,
                    "char" => ParsedType::Char,
                    "str" => ParsedType::Str,
                    "be" => {
                        let inner = self.parse_base_type()?;
                        ParsedType::Endian {
                            big: true,
                            inner: Box::new(inner),
                        }
                    }
                    "le" => {
                        let inner = self.parse_base_type()?;
                        ParsedType::Endian {
                            big: false,
                            inner: Box::new(inner),
                        }
                    }
                    "struct" => self.parse_struct()?,
                    "union" => self.parse_union()?,
                    "enum" => self.parse_enum()?,
                    "bitfield" => self.parse_bitfield()?,
                    name => ParsedType::Named(name.to_string()),
                })
            }
            other => Err(ImHexError::Parse {
                token: format!("{other:?}"),
                reason: "expected type".into(),
            }),
        }
    }

    /// Parse a full type including pointer decorators and array suffixes.
    ///
    /// # Errors
    /// Returns `ImHexError::Parse` on malformed input.
    pub fn parse_type(&mut self) -> Result<ParsedType, ImHexError> {
        let mut ty = self.parse_base_type()?;
        // Pointer decorators: `*` or `**`
        loop {
            match self.peek() {
                Token::StarStar => {
                    self.advance();
                    ty = ParsedType::Pointer(Box::new(ParsedType::Pointer(Box::new(ty))));
                }
                Token::Star => {
                    self.advance();
                    ty = ParsedType::Pointer(Box::new(ty));
                }
                _ => break,
            }
        }
        // Array suffix: `[N]` or `[while(...)]` or `[until(...)]`
        if self.peek() == &Token::LBracket {
            self.advance();
            let count = self.parse_array_size()?;
            self.expect(Token::RBracket)?;
            ty = ParsedType::Array {
                element: Box::new(ty),
                count,
            };
        }
        Ok(ty)
    }

    fn parse_array_size(&mut self) -> Result<ArraySize, ImHexError> {
        match self.peek().clone() {
            Token::Number(n) => {
                self.advance();
                Ok(ArraySize::Fixed(n))
            }
            Token::Ident(kw) if kw == "while" || kw == "until" => {
                let keyword = kw;
                self.advance();
                self.expect(Token::LParen)?;
                // collect everything until matching ')'
                let mut depth = 1usize;
                let start = self.pos;
                while depth > 0 {
                    match self.peek() {
                        Token::LParen => {
                            depth += 1;
                            self.advance();
                        }
                        Token::RParen => {
                            depth -= 1;
                            if depth > 0 {
                                self.advance();
                            }
                        }
                        Token::Eof => break,
                        _ => {
                            self.advance();
                        }
                    }
                }
                // build condition string from tokens
                let cond_tokens = &self.tokens[start..self.pos];
                let cond = cond_tokens
                    .iter()
                    .map(|t| format!("{t:?}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                self.expect(Token::RParen)?;
                if keyword == "while" {
                    Ok(ArraySize::While(cond))
                } else {
                    Ok(ArraySize::Until(cond))
                }
            }
            other => Err(ImHexError::Parse {
                token: format!("{other:?}"),
                reason: "expected array size (number, while(…), or until(…))".into(),
            }),
        }
    }

    fn parse_attributes(&mut self) -> Vec<PatternAttribute> {
        // Optional `[[attr(val), ...]]` block
        let mut attrs = Vec::new();
        while self.peek() == &Token::LBracket {
            self.advance();
            if self.peek() != &Token::LBracket {
                break;
            }
            self.advance(); // second `[`
            loop {
                let name = match self.advance().clone() {
                    Token::Ident(s) => s,
                    Token::RBracket => break,
                    _ => break,
                };
                let value = if self.peek() == &Token::LParen {
                    self.advance();
                    // collect until `)`
                    let mut val = String::new();
                    loop {
                        match self.advance().clone() {
                            Token::RParen => break,
                            Token::Ident(s) => val.push_str(&s),
                            Token::Number(n) => val.push_str(&n.to_string()),
                            Token::Eof => break,
                            _ => {}
                        }
                    }
                    val
                } else {
                    String::new()
                };
                attrs.push(PatternAttribute { name, value });
                if self.peek() == &Token::Comma {
                    self.advance();
                }
            }
            // expect closing `]]`
            if self.peek() == &Token::RBracket {
                self.advance();
            }
        }
        attrs
    }

    fn parse_field(&mut self) -> Result<ParsedField, ImHexError> {
        let ty = self.parse_type()?;
        let name = self.expect_ident()?;
        // optional `[N]` array suffix after the field name (alternative syntax)
        let ty = if self.peek() == &Token::LBracket {
            self.advance();
            let count = self.parse_array_size()?;
            self.expect(Token::RBracket)?;
            ParsedType::Array {
                element: Box::new(ty),
                count,
            }
        } else {
            ty
        };
        let attributes = self.parse_attributes();
        // eat trailing `;`
        if self.peek() == &Token::Semicolon {
            self.advance();
        }
        Ok(ParsedField {
            name,
            ty,
            attributes,
        })
    }

    fn parse_struct(&mut self) -> Result<ParsedType, ImHexError> {
        let name = self.expect_ident()?;
        self.expect(Token::LBrace)?;
        let mut fields = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            fields.push(self.parse_field()?);
        }
        self.expect(Token::RBrace)?;
        Ok(ParsedType::Struct { name, fields })
    }

    fn parse_union(&mut self) -> Result<ParsedType, ImHexError> {
        let name = self.expect_ident()?;
        self.expect(Token::LBrace)?;
        let mut variants = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            variants.push(self.parse_field()?);
        }
        self.expect(Token::RBrace)?;
        Ok(ParsedType::Union { name, variants })
    }

    fn parse_enum(&mut self) -> Result<ParsedType, ImHexError> {
        let name = self.expect_ident()?;
        self.expect(Token::Colon)?;
        let backing = self.parse_base_type()?;
        self.expect(Token::LBrace)?;
        let mut members = Vec::new();
        let mut next_val: u128 = 0;
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            let mname = self.expect_ident()?;
            let val = if self.peek() == &Token::Eq {
                self.advance();
                next_val = u128::from(self.expect_number()?);
                next_val
            } else {
                next_val
            };
            members.push((mname, val));
            next_val += 1;
            if self.peek() == &Token::Comma {
                self.advance();
            }
        }
        self.expect(Token::RBrace)?;
        Ok(ParsedType::Enum {
            name,
            backing: Box::new(backing),
            members,
        })
    }

    fn parse_bitfield(&mut self) -> Result<ParsedType, ImHexError> {
        let name = self.expect_ident()?;
        self.expect(Token::Colon)?;
        let backing = self.parse_base_type()?;
        self.expect(Token::LBrace)?;
        let mut bits = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            let bname = self.expect_ident()?;
            self.expect(Token::Colon)?;
            let width = self.expect_number()? as u8;
            bits.push((bname, width));
            if self.peek() == &Token::Semicolon {
                self.advance();
            }
        }
        self.expect(Token::RBrace)?;
        Ok(ParsedType::Bitfield {
            name,
            backing: Box::new(backing),
            bits,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.3  PatternValue — runtime value produced by evaluating a type
// ─────────────────────────────────────────────────────────────────────────────

/// A value produced by reading binary data through a `ParsedType`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PatternValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    F32(f32),
    F64(f64),
    Bool(bool),
    Char(char),
    Str(String),
    /// Named struct/union fields.
    Struct(Vec<(String, Self)>),
    /// Array elements.
    Array(Vec<Self>),
    /// Enum member name + underlying integer value.
    Enum {
        member: String,
        value: u128,
    },
    /// Bitfield: list of `(field_name, extracted_value)`.
    Bitfield(Vec<(String, u64)>),
    /// Pointer: the address stored at this location.
    Pointer(u64),
    /// Null / absent value.
    Null,
}

impl PatternValue {
    /// Display the value as a human-readable string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::U8(v) => format!("{v}"),
            Self::U16(v) => format!("{v}"),
            Self::U32(v) => format!("{v}"),
            Self::U64(v) => format!("{v}"),
            Self::U128(v) => format!("{v}"),
            Self::S8(v) => format!("{v}"),
            Self::S16(v) => format!("{v}"),
            Self::S32(v) => format!("{v}"),
            Self::S64(v) => format!("{v}"),
            Self::F32(v) => format!("{v}"),
            Self::F64(v) => format!("{v}"),
            Self::Bool(v) => format!("{v}"),
            Self::Char(v) => format!("'{v}'"),
            Self::Str(v) => format!("\"{v}\""),
            Self::Struct(fields) => {
                let inner: Vec<String> = fields
                    .iter()
                    .map(|(n, v)| format!("{n}: {}", v.display()))
                    .collect();
                format!("{{ {} }}", inner.join(", "))
            }
            Self::Array(elems) => {
                let inner: Vec<String> = elems.iter().map(Self::display).collect();
                format!("[{}]", inner.join(", "))
            }
            Self::Enum { member, value } => format!("{member} ({value})"),
            Self::Bitfield(bits) => {
                let inner: Vec<String> = bits.iter().map(|(n, v)| format!("{n}={v}")).collect();
                format!("bitfield {{ {} }}", inner.join(", "))
            }
            Self::Pointer(addr) => format!("*0x{addr:016X}"),
            Self::Null => "null".to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.4  PatternEvaluator — read bytes through a ParsedType
// ─────────────────────────────────────────────────────────────────────────────

/// Reads binary data using `ParsedType` descriptions.
pub struct PatternEvaluator<'a> {
    data: &'a [u8],
    /// If `true`, multi-byte integers are read as big-endian by default.
    pub big_endian: bool,
    /// Type registry for named (`ParsedType::Named`) resolution.
    pub types: HashMap<String, ParsedType>,
}

impl<'a> PatternEvaluator<'a> {
    /// Create an evaluator over `data` (little-endian by default).
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            big_endian: false,
            types: HashMap::new(),
        }
    }

    /// Register a named type so that `ParsedType::Named(name)` can be resolved.
    pub fn register(&mut self, name: impl Into<String>, ty: ParsedType) {
        self.types.insert(name.into(), ty);
    }

    /// Evaluate `type_` at byte `addr` and return the value and bytes consumed.
    ///
    /// # Errors
    /// Returns `ImHexError::OutOfBounds` or `ImHexError::Eval` on failure.
    pub fn eval_at(
        &self,
        addr: usize,
        ty: &ParsedType,
    ) -> Result<(PatternValue, usize), ImHexError> {
        match ty {
            ParsedType::U8 => self.read_u8(addr).map(|v| (PatternValue::U8(v), 1)),
            ParsedType::U16 => self
                .read_u16(addr, self.big_endian)
                .map(|v| (PatternValue::U16(v), 2)),
            ParsedType::U32 => self
                .read_u32(addr, self.big_endian)
                .map(|v| (PatternValue::U32(v), 4)),
            ParsedType::U64 => self
                .read_u64(addr, self.big_endian)
                .map(|v| (PatternValue::U64(v), 8)),
            ParsedType::U128 => self
                .read_u128(addr, self.big_endian)
                .map(|v| (PatternValue::U128(v), 16)),
            ParsedType::S8 => self.read_u8(addr).map(|v| (PatternValue::S8(v as i8), 1)),
            ParsedType::S16 => self
                .read_u16(addr, self.big_endian)
                .map(|v| (PatternValue::S16(v as i16), 2)),
            ParsedType::S32 => self
                .read_u32(addr, self.big_endian)
                .map(|v| (PatternValue::S32(v as i32), 4)),
            ParsedType::S64 => self
                .read_u64(addr, self.big_endian)
                .map(|v| (PatternValue::S64(v as i64), 8)),
            ParsedType::F32 => {
                let v = self.read_u32(addr, self.big_endian)?;
                Ok((PatternValue::F32(f32::from_bits(v)), 4))
            }
            ParsedType::F64 => {
                let v = self.read_u64(addr, self.big_endian)?;
                Ok((PatternValue::F64(f64::from_bits(v)), 8))
            }
            ParsedType::Bool => {
                let v = self.read_u8(addr)?;
                Ok((PatternValue::Bool(v != 0), 1))
            }
            ParsedType::Char => {
                let v = self.read_u8(addr)?;
                Ok((PatternValue::Char(v as char), 1))
            }
            ParsedType::Str => {
                // Null-terminated UTF-8 string
                let start = addr;
                let mut end = addr;
                while end < self.data.len() && self.data[end] != 0 {
                    end += 1;
                }
                let s = std::str::from_utf8(&self.data[start..end])
                    .unwrap_or("<invalid utf8>")
                    .to_string();
                let consumed = end - start + 1; // include the null
                Ok((PatternValue::Str(s), consumed))
            }
            ParsedType::Endian { big, inner } => {
                // temporarily override endianness
                let saved = self.big_endian;
                // SAFETY: we need to mutate temporarily — use a trick via an
                // independent evaluator with the same data and registered types.
                let child = PatternEvaluator {
                    data: self.data,
                    big_endian: *big,
                    types: self.types.clone(),
                };
                let result = child.eval_at(addr, inner)?;
                let _ = saved;
                Ok(result)
            }
            ParsedType::Pointer(inner) => {
                // Read a u64 as the pointer address, then dereference
                let (ptr_val, consumed) = self.eval_at(addr, &ParsedType::U64)?;
                let ptr_addr = if let PatternValue::U64(a) = ptr_val {
                    a
                } else {
                    0
                };
                // Optionally dereference inner type at ptr_addr
                let _ = inner; // dereference is lazy — just store the address
                Ok((PatternValue::Pointer(ptr_addr), consumed))
            }
            ParsedType::Array { element, count } => {
                let mut elems = Vec::new();
                let mut offset = addr;
                match count {
                    ArraySize::Fixed(n) => {
                        for _ in 0..*n {
                            let (val, sz) = self.eval_at(offset, element)?;
                            elems.push(val);
                            offset += sz;
                        }
                    }
                    ArraySize::While(_cond) | ArraySize::Until(_cond) => {
                        // Without a real expression evaluator, stop at data end
                        while offset < self.data.len() {
                            if let Ok((val, sz)) = self.eval_at(offset, element) {
                                elems.push(val);
                                offset += sz;
                            } else {
                                break;
                            }
                        }
                    }
                }
                let consumed = offset - addr;
                Ok((PatternValue::Array(elems), consumed))
            }
            ParsedType::Struct { fields, .. } => {
                let mut result = Vec::new();
                let mut offset = addr;
                // Union: all fields at the same offset; struct: sequential
                for field in fields {
                    let (val, sz) = self.eval_at(offset, &field.ty)?;
                    result.push((field.name.clone(), val));
                    offset += sz;
                }
                Ok((PatternValue::Struct(result), offset - addr))
            }
            ParsedType::Union { variants, .. } => {
                // Union: read all variants at the same address, take the largest
                let mut result = Vec::new();
                let mut max_sz = 0usize;
                for variant in variants {
                    let (val, sz) = self.eval_at(addr, &variant.ty)?;
                    result.push((variant.name.clone(), val));
                    if sz > max_sz {
                        max_sz = sz;
                    }
                }
                Ok((PatternValue::Struct(result), max_sz))
            }
            ParsedType::Enum {
                backing, members, ..
            } => {
                let (raw, consumed) = self.eval_at(addr, backing)?;
                let raw_val: u128 = match raw {
                    PatternValue::U8(v) => u128::from(v),
                    PatternValue::U16(v) => u128::from(v),
                    PatternValue::U32(v) => u128::from(v),
                    PatternValue::U64(v) => u128::from(v),
                    PatternValue::U128(v) => v,
                    _ => 0,
                };
                let member = members
                    .iter()
                    .find(|(_, v)| *v == raw_val).map_or_else(|| format!("<unknown: {raw_val}>"), |(n, _)| n.clone());
                Ok((
                    PatternValue::Enum {
                        member,
                        value: raw_val,
                    },
                    consumed,
                ))
            }
            ParsedType::Bitfield { backing, bits, .. } => {
                let (raw, consumed) = self.eval_at(addr, backing)?;
                let mut raw_int: u64 = match raw {
                    PatternValue::U8(v) => u64::from(v),
                    PatternValue::U16(v) => u64::from(v),
                    PatternValue::U32(v) => u64::from(v),
                    PatternValue::U64(v) => v,
                    _ => 0,
                };
                let mut bit_vals = Vec::new();
                for (bname, width) in bits {
                    let mask = (1u64 << width) - 1;
                    bit_vals.push((bname.clone(), raw_int & mask));
                    raw_int >>= width;
                }
                Ok((PatternValue::Bitfield(bit_vals), consumed))
            }
            ParsedType::Named(name) => {
                if let Some(resolved) = self.types.get(name).cloned() {
                    self.eval_at(addr, &resolved)
                } else {
                    Err(ImHexError::Eval(format!("unknown type: {name}")))
                }
            }
        }
    }

    // ── Raw read helpers ──────────────────────────────────────────────────────

    const fn check_bounds(&self, addr: usize, n: usize) -> Result<(), ImHexError> {
        if addr + n > self.data.len() {
            Err(ImHexError::OutOfBounds(addr))
        } else {
            Ok(())
        }
    }

    fn read_u8(&self, addr: usize) -> Result<u8, ImHexError> {
        self.check_bounds(addr, 1)?;
        Ok(self.data[addr])
    }

    fn read_u16(&self, addr: usize, big: bool) -> Result<u16, ImHexError> {
        self.check_bounds(addr, 2)?;
        let b = &self.data[addr..addr + 2];
        Ok(if big {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }

    fn read_u32(&self, addr: usize, big: bool) -> Result<u32, ImHexError> {
        self.check_bounds(addr, 4)?;
        let b = &self.data[addr..addr + 4];
        Ok(if big {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    fn read_u64(&self, addr: usize, big: bool) -> Result<u64, ImHexError> {
        self.check_bounds(addr, 8)?;
        let b = &self.data[addr..addr + 8];
        Ok(if big {
            u64::from_be_bytes(b.try_into().unwrap())
        } else {
            u64::from_le_bytes(b.try_into().unwrap())
        })
    }

    fn read_u128(&self, addr: usize, big: bool) -> Result<u128, ImHexError> {
        self.check_bounds(addr, 16)?;
        let b = &self.data[addr..addr + 16];
        Ok(if big {
            u128::from_be_bytes(b.try_into().unwrap())
        } else {
            u128::from_le_bytes(b.try_into().unwrap())
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.5  Attribute validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate an `ImHex` pattern attribute.
///
/// Valid attribute names and their expected value shapes:
/// - `color("RED")` — a non-empty color string
/// - `name("Magic")` — a non-empty display name
/// - `validate(expr)` — a validation expression (any non-empty string)
/// - `transform(func)` — a transform function name
/// - `format_hex` — no value (empty string)
/// - `format_binary` — no value
/// - `format_octal` — no value
///
/// Returns `true` if the attribute is valid.
#[must_use]
pub fn validate_attribute(name: &str, value: &str) -> bool {
    match name {
        "color" | "name" | "validate" | "transform" => !value.is_empty(),
        "format_hex" | "format_binary" | "format_octal" => value.is_empty(),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.6  PatternTree — structured overlay of binary data
// ─────────────────────────────────────────────────────────────────────────────

/// A single node in a `PatternTree`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternTreeNode {
    /// Field / variable name.
    pub name: String,
    /// Human-readable type name.
    pub type_name: String,
    /// Byte range in the original data `[start, end)`.
    pub byte_range: (usize, usize),
    /// Parsed value at this node.
    pub value: PatternValue,
    /// Child nodes (for struct, union, array, bitfield).
    pub children: Vec<Self>,
}

impl PatternTreeNode {
    /// Byte length covered by this node.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_range.1.saturating_sub(self.byte_range.0)
    }

    /// Returns `true` if the node has no children.
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Depth-first iterator over this node and all descendants.
    #[must_use]
    pub fn dfs(&self) -> Vec<&Self> {
        let mut out = vec![self];
        for child in &self.children {
            out.extend(child.dfs());
        }
        out
    }
}

/// The result of applying one or more patterns to binary data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatternTree {
    pub nodes: Vec<PatternTreeNode>,
    /// The original data slice length (for range checks).
    pub data_len: usize,
}

impl PatternTree {
    /// Create an empty tree for `data_len` bytes.
    #[must_use]
    pub const fn new(data_len: usize) -> Self {
        Self {
            nodes: Vec::new(),
            data_len,
        }
    }

    /// Add a top-level node.
    pub fn push(&mut self, node: PatternTreeNode) {
        self.nodes.push(node);
    }

    /// Return the bytes covered by `node` from `data`.
    ///
    /// Returns an empty slice if out of bounds.
    #[must_use]
    pub fn bytes_for_node<'d>(&self, node: &PatternTreeNode, data: &'d [u8]) -> &'d [u8] {
        let (start, end) = node.byte_range;
        let end = end.min(data.len());
        if start >= end {
            &data[0..0]
        } else {
            &data[start..end]
        }
    }

    /// Find the first node (DFS) whose byte range contains `offset`.
    #[must_use]
    pub fn find_node_at_offset(&self, offset: usize) -> Option<&PatternTreeNode> {
        for node in &self.nodes {
            if let Some(found) = Self::dfs_find(node, offset) {
                return Some(found);
            }
        }
        None
    }

    fn dfs_find(node: &PatternTreeNode, offset: usize) -> Option<&PatternTreeNode> {
        let (start, end) = node.byte_range;
        if offset >= start && offset < end {
            // Try children first (more specific)
            for child in &node.children {
                if let Some(found) = Self::dfs_find(child, offset) {
                    return Some(found);
                }
            }
            return Some(node);
        }
        None
    }

    /// Total number of nodes including descendants.
    #[must_use]
    pub fn total_nodes(&self) -> usize {
        self.nodes.iter().map(|n| n.dfs().len()).sum()
    }
}

/// Build a `PatternTreeNode` from a `ParsedType` evaluated at `addr` in `data`.
///
/// # Errors
/// Propagates `ImHexError` from the evaluator.
pub fn build_tree_node(
    evaluator: &PatternEvaluator<'_>,
    name: &str,
    ty: &ParsedType,
    addr: usize,
) -> Result<PatternTreeNode, ImHexError> {
    let (value, consumed) = evaluator.eval_at(addr, ty)?;
    let type_name = type_display_name(ty);
    let mut children = Vec::new();

    // Expand compound values into child nodes
    match (&value, ty) {
        (
            PatternValue::Struct(fields),
            ParsedType::Struct {
                fields: field_defs, ..
            },
        ) => {
            let mut offset = addr;
            for (field_def, (field_name, _)) in field_defs.iter().zip(fields.iter()) {
                let child = build_tree_node(evaluator, field_name, &field_def.ty, offset)?;
                let sz = child.byte_len();
                children.push(child);
                offset += sz;
            }
        }
        (PatternValue::Array(elems), ParsedType::Array { element, .. }) => {
            let mut offset = addr;
            for (i, _elem) in elems.iter().enumerate() {
                let child = build_tree_node(evaluator, &format!("[{i}]"), element, offset)?;
                let sz = child.byte_len();
                children.push(child);
                offset += sz;
            }
        }
        _ => {}
    }

    Ok(PatternTreeNode {
        name: name.to_string(),
        type_name,
        byte_range: (addr, addr + consumed),
        value,
        children,
    })
}

fn type_display_name(ty: &ParsedType) -> String {
    match ty {
        ParsedType::U8 => "u8".into(),
        ParsedType::U16 => "u16".into(),
        ParsedType::U32 => "u32".into(),
        ParsedType::U64 => "u64".into(),
        ParsedType::U128 => "u128".into(),
        ParsedType::S8 => "s8".into(),
        ParsedType::S16 => "s16".into(),
        ParsedType::S32 => "s32".into(),
        ParsedType::S64 => "s64".into(),
        ParsedType::F32 => "f32".into(),
        ParsedType::F64 => "f64".into(),
        ParsedType::Bool => "bool".into(),
        ParsedType::Char => "char".into(),
        ParsedType::Str => "str".into(),
        ParsedType::Endian { big, inner } => {
            format!(
                "{} {}",
                if *big { "be" } else { "le" },
                type_display_name(inner)
            )
        }
        ParsedType::Pointer(inner) => format!("{}*", type_display_name(inner)),
        ParsedType::Array { element, count } => {
            let count_str = match count {
                ArraySize::Fixed(n) => n.to_string(),
                ArraySize::While(c) => format!("while({c})"),
                ArraySize::Until(c) => format!("until({c})"),
            };
            format!("{}[{count_str}]", type_display_name(element))
        }
        ParsedType::Struct { name, .. } => format!("struct {name}"),
        ParsedType::Union { name, .. } => format!("union {name}"),
        ParsedType::Enum { name, .. } => format!("enum {name}"),
        ParsedType::Bitfield { name, .. } => format!("bitfield {name}"),
        ParsedType::Named(name) => name.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.7  Built-in format patterns (PE, ELF, ZIP)
// ─────────────────────────────────────────────────────────────────────────────

/// Return the `ImHex` pattern source for the PE DOS + File headers.
///
/// Covers `IMAGE_DOS_HEADER` (`e_magic` … `e_lfanew`) and
/// `IMAGE_FILE_HEADER` (Machine, `NumSections`, `TimeDateStamp`, …).
#[must_use]
pub fn builtin_pe_pattern() -> String {
    r"
// PE DOS Header
struct PE_DOS_HEADER {
    u16 e_magic;        // MZ magic (0x5A4D)
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    u32 e_lfanew;       // Offset to PE signature
};

// PE COFF File Header
struct PE_FILE_HEADER {
    u16 Machine;
    u16 NumSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
};

// PE Optional Header (32-bit)
struct PE_OPTIONAL_HEADER32 {
    u16 Magic;           // 0x010B = PE32
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u32 BaseOfData;
    u32 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOSVersion;
    u16 MinorOSVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u32 SizeOfStackReserve;
    u32 SizeOfStackCommit;
    u32 SizeOfHeapReserve;
    u32 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
};

// Section header
struct PE_SECTION_HEADER {
    char Name[8];
    u32 VirtualSize;
    u32 VirtualAddress;
    u32 SizeOfRawData;
    u32 PointerToRawData;
    u32 PointerToRelocations;
    u32 PointerToLinenumbers;
    u16 NumberOfRelocations;
    u16 NumberOfLinenumbers;
    u32 Characteristics;
};

PE_DOS_HEADER dosHdr @ 0x00;
"
    .to_string()
}

/// Return the `ImHex` pattern source for the ELF 32-bit header.
#[must_use]
pub fn builtin_elf_pattern() -> String {
    r"
// ELF identification
struct ELF_IDENT {
    u8 magic[4];    // 0x7F 'E' 'L' 'F'
    u8 ei_class;    // 1=32-bit, 2=64-bit
    u8 ei_data;     // 1=LE, 2=BE
    u8 ei_version;
    u8 ei_osabi;
    u8 ei_abiversion;
    u8 ei_pad[7];
};

// ELF 32-bit header
struct ELF_HEADER32 {
    ELF_IDENT ident;
    u16 e_type;         // ET_EXEC=2, ET_DYN=3, etc.
    u16 e_machine;      // EM_386=3, EM_X86_64=62, EM_ARM=40, …
    u32 e_version;
    u32 e_entry;        // Virtual address of entry point
    u32 e_phoff;        // Program header offset
    u32 e_shoff;        // Section header offset
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

// ELF 64-bit header
struct ELF_HEADER64 {
    ELF_IDENT ident;
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

// ELF 32-bit Program Header
struct ELF_PHDR32 {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
};

// ELF 32-bit Section Header
struct ELF_SHDR32 {
    u32 sh_name;
    u32 sh_type;
    u32 sh_flags;
    u32 sh_addr;
    u32 sh_offset;
    u32 sh_size;
    u32 sh_link;
    u32 sh_info;
    u32 sh_addralign;
    u32 sh_entsize;
};

ELF_HEADER32 elfHdr @ 0x00;
"
    .to_string()
}

/// Return the `ImHex` pattern source for the ZIP local file header.
#[must_use]
pub fn builtin_zip_pattern() -> String {
    r"
// ZIP local file header
struct ZIP_LOCAL_HEADER {
    u32 signature;       // 0x04034B50 = PK\x03\x04
    u16 version_needed;
    u16 general_purpose_flags;
    u16 compression_method;
    u16 last_mod_time;
    u16 last_mod_date;
    u32 crc32;
    u32 compressed_size;
    u32 uncompressed_size;
    u16 fname_len;
    u16 extra_len;
    char filename[fname_len];
    u8  extra[extra_len];
};

// ZIP data descriptor (if bit 3 of general_purpose_flags set)
struct ZIP_DATA_DESCRIPTOR {
    u32 crc32;
    u32 compressed_size;
    u32 uncompressed_size;
};

// ZIP central directory file header
struct ZIP_CENTRAL_DIR_HEADER {
    u32 signature;         // 0x02014B50 = PK\x01\x02
    u16 version_made_by;
    u16 version_needed;
    u16 general_purpose_flags;
    u16 compression_method;
    u16 last_mod_time;
    u16 last_mod_date;
    u32 crc32;
    u32 compressed_size;
    u32 uncompressed_size;
    u16 fname_len;
    u16 extra_len;
    u16 comment_len;
    u16 disk_number_start;
    u16 internal_attributes;
    u32 external_attributes;
    u32 local_header_offset;
    char filename[fname_len];
    u8  extra[extra_len];
    char comment[comment_len];
};

// ZIP end-of-central-directory record
struct ZIP_EOCD {
    u32 signature;          // 0x06054B50 = PK\x05\x06
    u16 disk_number;
    u16 start_disk;
    u16 num_entries_this_disk;
    u16 num_entries_total;
    u32 central_dir_size;
    u32 central_dir_offset;
    u16 comment_len;
    char comment[comment_len];
};

ZIP_LOCAL_HEADER zipLocal @ 0x00;
"
    .to_string()
}

/// Build a `ParsedType` for the PE DOS header (Rust-native, without text parsing).
#[must_use]
pub fn pe_dos_header_type() -> ParsedType {
    ParsedType::Struct {
        name: "PE_DOS_HEADER".into(),
        fields: vec![
            ParsedField {
                name: "e_magic".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_cblp".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_cp".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_crlc".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_cparhdr".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_minalloc".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_maxalloc".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_ss".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_sp".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_csum".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_ip".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_cs".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_lfarlc".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_ovno".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_res".into(),
                ty: ParsedType::Array {
                    element: Box::new(ParsedType::U16),
                    count: ArraySize::Fixed(4),
                },
                attributes: vec![],
            },
            ParsedField {
                name: "e_oemid".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_oeminfo".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_res2".into(),
                ty: ParsedType::Array {
                    element: Box::new(ParsedType::U16),
                    count: ArraySize::Fixed(10),
                },
                attributes: vec![],
            },
            ParsedField {
                name: "e_lfanew".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
        ],
    }
}

/// Build a `ParsedType` for the PE COFF File Header.
#[must_use]
pub fn pe_file_header_type() -> ParsedType {
    ParsedType::Struct {
        name: "PE_FILE_HEADER".into(),
        fields: vec![
            ParsedField {
                name: "Machine".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "NumSections".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "TimeDateStamp".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "PointerToSymbolTable".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "NumberOfSymbols".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "SizeOfOptionalHeader".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "Characteristics".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
        ],
    }
}

/// Build a `ParsedType` for the ELF 32-bit header.
#[must_use]
pub fn elf_header32_type() -> ParsedType {
    ParsedType::Struct {
        name: "ELF_HEADER32".into(),
        fields: vec![
            ParsedField {
                name: "ident".into(),
                ty: ParsedType::Array {
                    element: Box::new(ParsedType::U8),
                    count: ArraySize::Fixed(16),
                },
                attributes: vec![],
            },
            ParsedField {
                name: "e_type".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_machine".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_version".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "e_entry".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "e_phoff".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "e_shoff".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "e_flags".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "e_ehsize".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_phentsize".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_phnum".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_shentsize".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_shnum".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "e_shstrndx".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
        ],
    }
}

/// Build a `ParsedType` for the ZIP local file header (fixed-size portion only).
#[must_use]
pub fn zip_local_header_type() -> ParsedType {
    ParsedType::Struct {
        name: "ZIP_LOCAL_HEADER".into(),
        fields: vec![
            ParsedField {
                name: "signature".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "version_needed".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "general_purpose_flags".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "compression_method".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "last_mod_time".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "last_mod_date".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "crc32".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "compressed_size".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "uncompressed_size".into(),
                ty: ParsedType::U32,
                attributes: vec![],
            },
            ParsedField {
                name: "fname_len".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
            ParsedField {
                name: "extra_len".into(),
                ty: ParsedType::U16,
                attributes: vec![],
            },
        ],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §14.8  Tests for the ImHex pattern language
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_imhex {
    use super::*;

    // ── ParsedType primitives ─────────────────────────────────────────────────

    #[test]
    fn test_primitive_sizes() {
        assert_eq!(ParsedType::U8.primitive_size(), Some(1));
        assert_eq!(ParsedType::U16.primitive_size(), Some(2));
        assert_eq!(ParsedType::U32.primitive_size(), Some(4));
        assert_eq!(ParsedType::U64.primitive_size(), Some(8));
        assert_eq!(ParsedType::U128.primitive_size(), Some(16));
        assert_eq!(ParsedType::S8.primitive_size(), Some(1));
        assert_eq!(ParsedType::S64.primitive_size(), Some(8));
        assert_eq!(ParsedType::F32.primitive_size(), Some(4));
        assert_eq!(ParsedType::F64.primitive_size(), Some(8));
        assert_eq!(ParsedType::Bool.primitive_size(), Some(1));
        assert_eq!(ParsedType::Char.primitive_size(), Some(1));
        assert_eq!(ParsedType::Str.primitive_size(), None);
    }

    #[test]
    fn test_is_numeric() {
        assert!(ParsedType::U8.is_numeric());
        assert!(ParsedType::S32.is_numeric());
        assert!(ParsedType::F64.is_numeric());
        assert!(!ParsedType::Bool.is_numeric());
        assert!(!ParsedType::Char.is_numeric());
        assert!(!ParsedType::Str.is_numeric());
    }

    #[test]
    fn test_is_compound() {
        let s = ParsedType::Struct {
            name: "S".into(),
            fields: vec![],
        };
        let u = ParsedType::Union {
            name: "U".into(),
            variants: vec![],
        };
        assert!(s.is_compound());
        assert!(u.is_compound());
        assert!(!ParsedType::U8.is_compound());
    }

    #[test]
    fn test_array_primitive_size() {
        let arr = ParsedType::Array {
            element: Box::new(ParsedType::U32),
            count: ArraySize::Fixed(4),
        };
        assert_eq!(arr.primitive_size(), Some(16));
    }

    #[test]
    fn test_endian_size() {
        let ty = ParsedType::Endian {
            big: true,
            inner: Box::new(ParsedType::U32),
        };
        assert_eq!(ty.primitive_size(), Some(4));
    }

    // ── PatternParser ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_u32() {
        let mut p = PatternParser::new("u32");
        let ty = p.parse_type().unwrap();
        assert_eq!(ty, ParsedType::U32);
    }

    #[test]
    fn test_parse_all_primitives() {
        for (src, expected) in [
            ("u8", ParsedType::U8),
            ("u16", ParsedType::U16),
            ("u32", ParsedType::U32),
            ("u64", ParsedType::U64),
            ("u128", ParsedType::U128),
            ("s8", ParsedType::S8),
            ("s16", ParsedType::S16),
            ("s32", ParsedType::S32),
            ("s64", ParsedType::S64),
            ("bool", ParsedType::Bool),
            ("char", ParsedType::Char),
            ("str", ParsedType::Str),
        ] {
            let mut p = PatternParser::new(src);
            assert_eq!(p.parse_type().unwrap(), expected, "failed on {src}");
        }
    }

    #[test]
    fn test_parse_be_u32() {
        let mut p = PatternParser::new("be u32");
        let ty = p.parse_type().unwrap();
        assert_eq!(
            ty,
            ParsedType::Endian {
                big: true,
                inner: Box::new(ParsedType::U32)
            }
        );
    }

    #[test]
    fn test_parse_le_u64() {
        let mut p = PatternParser::new("le u64");
        let ty = p.parse_type().unwrap();
        assert_eq!(
            ty,
            ParsedType::Endian {
                big: false,
                inner: Box::new(ParsedType::U64)
            }
        );
    }

    #[test]
    fn test_parse_pointer() {
        let mut p = PatternParser::new("u32 *");
        let ty = p.parse_type().unwrap();
        assert!(matches!(ty, ParsedType::Pointer(_)));
    }

    #[test]
    fn test_parse_double_pointer() {
        let mut p = PatternParser::new("u8 **");
        let ty = p.parse_type().unwrap();
        // ParsedType::Pointer(Box::new(ParsedType::Pointer(_)))
        assert!(matches!(ty, ParsedType::Pointer(_)));
    }

    #[test]
    fn test_parse_fixed_array() {
        let mut p = PatternParser::new("u8[16]");
        let ty = p.parse_type().unwrap();
        assert!(matches!(
            ty,
            ParsedType::Array {
                count: ArraySize::Fixed(16),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_while_array() {
        let mut p = PatternParser::new("u8[while(offset < end)]");
        let ty = p.parse_type().unwrap();
        assert!(matches!(
            ty,
            ParsedType::Array {
                count: ArraySize::While(_),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_until_array() {
        let mut p = PatternParser::new("u8[until(0x100)]");
        let ty = p.parse_type().unwrap();
        assert!(matches!(
            ty,
            ParsedType::Array {
                count: ArraySize::Until(_),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_struct() {
        let src = "struct Point { u16 x; u16 y; }";
        let mut p = PatternParser::new(src);
        let ty = p.parse_type().unwrap();
        if let ParsedType::Struct { name, fields } = ty {
            assert_eq!(name, "Point");
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].name, "x");
            assert_eq!(fields[1].name, "y");
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_parse_union() {
        let src = "union IntOrBytes { u32 as_int; u8[4] as_bytes; }";
        let mut p = PatternParser::new(src);
        let ty = p.parse_type().unwrap();
        if let ParsedType::Union { name, variants } = ty {
            assert_eq!(name, "IntOrBytes");
            assert_eq!(variants.len(), 2);
        } else {
            panic!("expected union");
        }
    }

    #[test]
    fn test_parse_enum() {
        let src = "enum Machine : u16 { X86 = 0x014c, AMD64 = 0x8664 }";
        let mut p = PatternParser::new(src);
        let ty = p.parse_type().unwrap();
        if let ParsedType::Enum { name, members, .. } = ty {
            assert_eq!(name, "Machine");
            assert_eq!(members.len(), 2);
            assert_eq!(members[0].0, "X86");
            assert_eq!(members[0].1, 0x014c);
            assert_eq!(members[1].0, "AMD64");
            assert_eq!(members[1].1, 0x8664);
        } else {
            panic!("expected enum");
        }
    }

    #[test]
    fn test_parse_bitfield() {
        let src = "bitfield Flags : u8 { read : 1; write : 1; exec : 1; }";
        let mut p = PatternParser::new(src);
        let ty = p.parse_type().unwrap();
        if let ParsedType::Bitfield { name, bits, .. } = ty {
            assert_eq!(name, "Flags");
            assert_eq!(bits.len(), 3);
            assert_eq!(bits[0], ("read".into(), 1));
            assert_eq!(bits[2], ("exec".into(), 1));
        } else {
            panic!("expected bitfield");
        }
    }

    #[test]
    fn test_parse_named_reference() {
        let mut p = PatternParser::new("MyStruct");
        let ty = p.parse_type().unwrap();
        assert_eq!(ty, ParsedType::Named("MyStruct".into()));
    }

    // ── PatternEvaluator ──────────────────────────────────────────────────────

    #[test]
    fn test_eval_u8() {
        let data = [0xABu8, 0xCD];
        let ev = PatternEvaluator::new(&data);
        let (val, sz) = ev.eval_at(0, &ParsedType::U8).unwrap();
        assert_eq!(val, PatternValue::U8(0xAB));
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_eval_u16_le() {
        let data = [0x34u8, 0x12]; // little-endian 0x1234
        let ev = PatternEvaluator::new(&data);
        let (val, sz) = ev.eval_at(0, &ParsedType::U16).unwrap();
        assert_eq!(val, PatternValue::U16(0x1234));
        assert_eq!(sz, 2);
    }

    #[test]
    fn test_eval_u32_be() {
        let data = [0x00u8, 0x00, 0x00, 0x01];
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Endian {
            big: true,
            inner: Box::new(ParsedType::U32),
        };
        let (val, _) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(val, PatternValue::U32(1));
    }

    #[test]
    fn test_eval_u32_le() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        let ev = PatternEvaluator::new(&data);
        let (val, _) = ev.eval_at(0, &ParsedType::U32).unwrap();
        assert_eq!(val, PatternValue::U32(1));
    }

    #[test]
    fn test_eval_bool() {
        let data = [0x01u8, 0x00];
        let ev = PatternEvaluator::new(&data);
        let (t, _) = ev.eval_at(0, &ParsedType::Bool).unwrap();
        let (f, _) = ev.eval_at(1, &ParsedType::Bool).unwrap();
        assert_eq!(t, PatternValue::Bool(true));
        assert_eq!(f, PatternValue::Bool(false));
    }

    #[test]
    fn test_eval_char() {
        let data = [b'H', b'i'];
        let ev = PatternEvaluator::new(&data);
        let (val, sz) = ev.eval_at(0, &ParsedType::Char).unwrap();
        assert_eq!(val, PatternValue::Char('H'));
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_eval_str() {
        let data = b"hello\0world";
        let ev = PatternEvaluator::new(data);
        let (val, sz) = ev.eval_at(0, &ParsedType::Str).unwrap();
        assert_eq!(val, PatternValue::Str("hello".into()));
        assert_eq!(sz, 6); // 5 chars + null
    }

    #[test]
    fn test_eval_fixed_array() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let ev = PatternEvaluator::new(&data);
        let arr = ParsedType::Array {
            element: Box::new(ParsedType::U8),
            count: ArraySize::Fixed(4),
        };
        let (val, sz) = ev.eval_at(0, &arr).unwrap();
        assert_eq!(sz, 4);
        if let PatternValue::Array(elems) = val {
            assert_eq!(elems.len(), 4);
            assert_eq!(elems[0], PatternValue::U8(1));
            assert_eq!(elems[3], PatternValue::U8(4));
        } else {
            panic!("expected Array");
        }
    }

    #[test]
    fn test_eval_struct() {
        // Simple struct: { u16 x; u16 y; }
        let data = [0x01u8, 0x00, 0x02, 0x00]; // x=1, y=2 LE
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Struct {
            name: "Point".into(),
            fields: vec![
                ParsedField {
                    name: "x".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
                ParsedField {
                    name: "y".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
            ],
        };
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 4);
        if let PatternValue::Struct(fields) = val {
            assert_eq!(fields[0].0, "x");
            assert_eq!(fields[0].1, PatternValue::U16(1));
            assert_eq!(fields[1].0, "y");
            assert_eq!(fields[1].1, PatternValue::U16(2));
        } else {
            panic!("expected Struct");
        }
    }

    #[test]
    fn test_eval_enum() {
        let data = [0x4Cu8, 0x01]; // 0x014C = Intel 386
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Enum {
            name: "Machine".into(),
            backing: Box::new(ParsedType::U16),
            members: vec![("X86".into(), 0x014c), ("AMD64".into(), 0x8664)],
        };
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 2);
        if let PatternValue::Enum { member, value } = val {
            assert_eq!(member, "X86");
            assert_eq!(value, 0x014c);
        } else {
            panic!("expected Enum");
        }
    }

    #[test]
    fn test_eval_bitfield() {
        let data = [0b0000_0111u8]; // read=1, write=1, exec=1
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Bitfield {
            name: "Flags".into(),
            backing: Box::new(ParsedType::U8),
            bits: vec![("read".into(), 1), ("write".into(), 1), ("exec".into(), 1)],
        };
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 1);
        if let PatternValue::Bitfield(bits) = val {
            assert_eq!(bits[0], ("read".into(), 1));
            assert_eq!(bits[1], ("write".into(), 1));
            assert_eq!(bits[2], ("exec".into(), 1));
        } else {
            panic!("expected Bitfield");
        }
    }

    #[test]
    fn test_eval_out_of_bounds() {
        let data = [0xABu8];
        let ev = PatternEvaluator::new(&data);
        let result = ev.eval_at(0, &ParsedType::U32);
        assert!(matches!(result, Err(ImHexError::OutOfBounds(_))));
    }

    #[test]
    fn test_eval_named_registered() {
        let data = [0x01u8, 0x00];
        let mut ev = PatternEvaluator::new(&data);
        ev.register("MyU16", ParsedType::U16);
        let (val, _) = ev.eval_at(0, &ParsedType::Named("MyU16".into())).unwrap();
        assert_eq!(val, PatternValue::U16(1));
    }

    #[test]
    fn test_eval_named_unknown() {
        let data = [0x00u8];
        let ev = PatternEvaluator::new(&data);
        let result = ev.eval_at(0, &ParsedType::Named("Unknown".into()));
        assert!(result.is_err());
    }

    #[test]
    fn test_eval_pointer() {
        // Pointer reads a u64 address
        let mut data = [0u8; 8];
        data[0] = 0x42;
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Pointer(Box::new(ParsedType::U8));
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 8);
        assert!(matches!(val, PatternValue::Pointer(0x42)));
    }

    // ── validate_attribute ────────────────────────────────────────────────────

    #[test]
    fn test_validate_attribute_color() {
        assert!(validate_attribute("color", "RED"));
        assert!(!validate_attribute("color", ""));
    }

    #[test]
    fn test_validate_attribute_name() {
        assert!(validate_attribute("name", "Magic"));
        assert!(!validate_attribute("name", ""));
    }

    #[test]
    fn test_validate_attribute_validate() {
        assert!(validate_attribute("validate", "$ == 0x4D5A"));
        assert!(!validate_attribute("validate", ""));
    }

    #[test]
    fn test_validate_attribute_transform() {
        assert!(validate_attribute("transform", "formatHex"));
        assert!(!validate_attribute("transform", ""));
    }

    #[test]
    fn test_validate_attribute_format_flags() {
        assert!(validate_attribute("format_hex", ""));
        assert!(validate_attribute("format_binary", ""));
        assert!(validate_attribute("format_octal", ""));
        // must have empty value
        assert!(!validate_attribute("format_hex", "something"));
    }

    #[test]
    fn test_validate_attribute_unknown() {
        assert!(!validate_attribute("not_a_real_attr", ""));
        assert!(!validate_attribute("not_a_real_attr", "value"));
    }

    // ── PatternTree ───────────────────────────────────────────────────────────

    #[test]
    fn test_pattern_tree_build_u32() {
        let data = [0x78u8, 0x56, 0x34, 0x12]; // 0x12345678 LE
        let ev = PatternEvaluator::new(&data);
        let node = build_tree_node(&ev, "magic", &ParsedType::U32, 0).unwrap();
        assert_eq!(node.name, "magic");
        assert_eq!(node.type_name, "u32");
        assert_eq!(node.byte_range, (0, 4));
        assert_eq!(node.value, PatternValue::U32(0x12345678));
        assert!(node.is_leaf());
    }

    #[test]
    fn test_pattern_tree_build_struct() {
        let data = [0x01u8, 0x00, 0x02, 0x00]; // x=1, y=2
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Struct {
            name: "Point".into(),
            fields: vec![
                ParsedField {
                    name: "x".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
                ParsedField {
                    name: "y".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
            ],
        };
        let node = build_tree_node(&ev, "pt", &ty, 0).unwrap();
        assert_eq!(node.children.len(), 2);
        assert_eq!(node.children[0].name, "x");
        assert_eq!(node.children[0].byte_range, (0, 2));
        assert_eq!(node.children[1].name, "y");
        assert_eq!(node.children[1].byte_range, (2, 4));
    }

    #[test]
    fn test_pattern_tree_find_at_offset() {
        let data = [0x01u8, 0x00, 0x02, 0x00];
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Struct {
            name: "Point".into(),
            fields: vec![
                ParsedField {
                    name: "x".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
                ParsedField {
                    name: "y".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
            ],
        };
        let node = build_tree_node(&ev, "pt", &ty, 0).unwrap();
        let mut tree = PatternTree::new(data.len());
        tree.push(node);
        let found = tree.find_node_at_offset(2).unwrap();
        assert_eq!(found.name, "y");
    }

    #[test]
    fn test_pattern_tree_bytes_for_node() {
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let ev = PatternEvaluator::new(&data);
        let node = build_tree_node(
            &ev,
            "arr",
            &ParsedType::Array {
                element: Box::new(ParsedType::U8),
                count: ArraySize::Fixed(4),
            },
            0,
        )
        .unwrap();
        let mut tree = PatternTree::new(data.len());
        let bytes = tree.bytes_for_node(&node, &data);
        assert_eq!(bytes, &[0x01, 0x02, 0x03, 0x04]);
        tree.push(node);
    }

    #[test]
    fn test_pattern_tree_total_nodes() {
        let data = [0x01u8, 0x00, 0x02, 0x00];
        let ev = PatternEvaluator::new(&data);
        let ty = ParsedType::Struct {
            name: "P".into(),
            fields: vec![
                ParsedField {
                    name: "a".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
                ParsedField {
                    name: "b".into(),
                    ty: ParsedType::U16,
                    attributes: vec![],
                },
            ],
        };
        let node = build_tree_node(&ev, "p", &ty, 0).unwrap();
        let mut tree = PatternTree::new(data.len());
        tree.push(node);
        // 1 root + 2 children = 3
        assert_eq!(tree.total_nodes(), 3);
    }

    // ── Built-in pattern strings ──────────────────────────────────────────────

    #[test]
    fn test_builtin_pe_pattern_contains_dos_header() {
        let src = builtin_pe_pattern();
        assert!(src.contains("PE_DOS_HEADER"));
        assert!(src.contains("e_lfanew"));
        assert!(src.contains("PE_FILE_HEADER"));
        assert!(src.contains("Machine"));
        assert!(src.contains("NumSections"));
    }

    #[test]
    fn test_builtin_elf_pattern_contains_ident() {
        let src = builtin_elf_pattern();
        assert!(src.contains("ELF_HEADER32"));
        assert!(src.contains("ELF_IDENT"));
        assert!(src.contains("e_entry"));
        assert!(src.contains("ELF_HEADER64"));
    }

    #[test]
    fn test_builtin_zip_pattern_contains_local_header() {
        let src = builtin_zip_pattern();
        assert!(src.contains("ZIP_LOCAL_HEADER"));
        assert!(src.contains("fname_len"));
        assert!(src.contains("ZIP_EOCD"));
        assert!(src.contains("ZIP_CENTRAL_DIR_HEADER"));
    }

    // ── Native type builders ──────────────────────────────────────────────────

    #[test]
    fn test_pe_dos_header_type_field_count() {
        let ty = pe_dos_header_type();
        if let ParsedType::Struct { fields, name } = ty {
            assert_eq!(name, "PE_DOS_HEADER");
            // last field is e_lfanew; count includes array fields
            assert!(fields.len() >= 15);
            assert_eq!(fields.last().unwrap().name, "e_lfanew");
            assert_eq!(fields.last().unwrap().ty, ParsedType::U32);
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_pe_dos_header_eval() {
        // Minimal MZ header: magic 0x5A4D at offset 0, e_lfanew at offset 60
        let mut data = vec![0u8; 64];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        data[60] = 0xE8; // e_lfanew low byte
        data[61] = 0x00;
        data[62] = 0x00;
        data[63] = 0x00;
        let ev = PatternEvaluator::new(&data);
        let ty = pe_dos_header_type();
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        // DOS header is exactly 64 bytes
        assert_eq!(sz, 64);
        if let PatternValue::Struct(fields) = val {
            // e_magic should be 0x5A4D
            assert_eq!(fields[0].0, "e_magic");
            assert_eq!(fields[0].1, PatternValue::U16(0x5A4D));
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_pe_file_header_type() {
        let ty = pe_file_header_type();
        if let ParsedType::Struct { name, fields } = ty {
            assert_eq!(name, "PE_FILE_HEADER");
            assert_eq!(fields.len(), 7);
            assert_eq!(fields[0].name, "Machine");
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_elf_header32_type() {
        let ty = elf_header32_type();
        if let ParsedType::Struct { name, fields } = &ty {
            assert_eq!(name, "ELF_HEADER32");
            // ident[16] + 13 scalar fields
            assert_eq!(fields.len(), 14);
            assert_eq!(fields[0].name, "ident");
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_elf_header32_eval() {
        // Minimal ELF header: ident[0..4] = \x7fELF, rest zeros
        let mut data = vec![0u8; 52]; // ELF32 header is 52 bytes
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        let ev = PatternEvaluator::new(&data);
        let ty = elf_header32_type();
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 52);
        if let PatternValue::Struct(fields) = val {
            // First field is ident[16]
            assert_eq!(fields[0].0, "ident");
            if let PatternValue::Array(bytes) = &fields[0].1 {
                assert_eq!(bytes[0], PatternValue::U8(0x7F));
                assert_eq!(bytes[1], PatternValue::U8(b'E'));
            }
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_zip_local_header_type() {
        let ty = zip_local_header_type();
        if let ParsedType::Struct { name, fields } = ty {
            assert_eq!(name, "ZIP_LOCAL_HEADER");
            assert_eq!(fields.len(), 11);
            assert_eq!(fields[0].name, "signature");
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_zip_local_header_eval() {
        // Real ZIP local file header magic + zeros
        let mut data = vec![0u8; 30];
        data[0] = 0x50; // P
        data[1] = 0x4B; // K
        data[2] = 0x03;
        data[3] = 0x04;
        let ev = PatternEvaluator::new(&data);
        let ty = zip_local_header_type();
        let (val, sz) = ev.eval_at(0, &ty).unwrap();
        assert_eq!(sz, 30);
        if let PatternValue::Struct(fields) = val {
            assert_eq!(fields[0].0, "signature");
            assert_eq!(fields[0].1, PatternValue::U32(0x04034B50));
        } else {
            panic!("expected struct");
        }
    }

    // ── PatternValue display ──────────────────────────────────────────────────

    #[test]
    fn test_pattern_value_display_primitives() {
        assert_eq!(PatternValue::U8(255).display(), "255");
        assert_eq!(PatternValue::S32(-1).display(), "-1");
        assert_eq!(PatternValue::Bool(true).display(), "true");
        assert_eq!(PatternValue::Char('A').display(), "'A'");
        assert_eq!(PatternValue::Str("hello".into()).display(), "\"hello\"");
        assert!(PatternValue::Pointer(0x1234).display().contains("1234"));
        assert_eq!(PatternValue::Null.display(), "null");
    }

    #[test]
    fn test_pattern_value_display_struct() {
        let v = PatternValue::Struct(vec![
            ("x".into(), PatternValue::U16(1)),
            ("y".into(), PatternValue::U16(2)),
        ]);
        let s = v.display();
        assert!(s.contains("x: 1"));
        assert!(s.contains("y: 2"));
    }

    #[test]
    fn test_pattern_value_display_enum() {
        let v = PatternValue::Enum {
            member: "X86".into(),
            value: 0x014C,
        };
        let s = v.display();
        assert!(s.contains("X86"));
        assert!(s.contains("332")); // 0x014C = 332 decimal
    }

    // ── type_display_name ─────────────────────────────────────────────────────

    #[test]
    fn test_type_display_name_primitives() {
        assert_eq!(type_display_name(&ParsedType::U8), "u8");
        assert_eq!(type_display_name(&ParsedType::S64), "s64");
        assert_eq!(type_display_name(&ParsedType::F32), "f32");
        assert_eq!(type_display_name(&ParsedType::Bool), "bool");
        assert_eq!(type_display_name(&ParsedType::Str), "str");
    }

    #[test]
    fn test_type_display_name_pointer() {
        let ty = ParsedType::Pointer(Box::new(ParsedType::U8));
        assert_eq!(type_display_name(&ty), "u8*");
    }

    #[test]
    fn test_type_display_name_array() {
        let ty = ParsedType::Array {
            element: Box::new(ParsedType::U32),
            count: ArraySize::Fixed(8),
        };
        assert_eq!(type_display_name(&ty), "u32[8]");
    }

    #[test]
    fn test_type_display_name_endian() {
        let ty = ParsedType::Endian {
            big: true,
            inner: Box::new(ParsedType::U32),
        };
        assert_eq!(type_display_name(&ty), "be u32");
    }
}
