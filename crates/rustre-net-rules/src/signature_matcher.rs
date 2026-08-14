//! `signature_matcher` — Multi-pattern payload signature matching.
//!
//! Provides [`SignatureMatcher`], [`Signature`], [`MatchContext`], and
//! [`match_payload`] for efficient Aho-Corasick-style payload scanning.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// MatchOffset
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of offset constraint on a pattern within the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetConstraint {
    /// Pattern may appear anywhere in the payload.
    Anywhere,
    /// Pattern must start at exactly this byte offset.
    Exact(usize),
    /// Pattern must start within [start, end) bytes.
    Window { start: usize, end: usize },
    /// Pattern must appear within `depth` bytes from the start.
    Depth(usize),
}

impl OffsetConstraint {
    /// Return `true` if `offset` satisfies this constraint.
    #[must_use]
    pub const fn allows(&self, offset: usize) -> bool {
        match *self {
            Self::Anywhere => true,
            Self::Exact(e) => offset == e,
            Self::Window { start, end } => offset >= start && offset < end,
            Self::Depth(d) => offset < d,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatternModifier
// ─────────────────────────────────────────────────────────────────────────────

/// Modifier flags for an individual pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PatternModifier {
    /// Match regardless of ASCII case.
    pub nocase: bool,
    /// Match the raw (un-decoded) bytes.
    pub rawbytes: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single pattern within a signature.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Unique ID within the owning signature.
    pub id: u8,
    /// Raw bytes to match.
    pub bytes: Vec<u8>,
    /// Optional per-byte mask (0x00 = wildcard, 0xff = exact).
    pub mask: Option<Vec<u8>>,
    /// Offset constraint.
    pub offset: OffsetConstraint,
    /// Pattern modifiers.
    pub modifiers: PatternModifier,
}

impl Pattern {
    /// Create an exact-byte pattern with no mask.
    #[must_use]
    pub fn new(id: u8, bytes: Vec<u8>) -> Self {
        Self {
            id,
            bytes,
            mask: None,
            offset: OffsetConstraint::Anywhere,
            modifiers: PatternModifier::default(),
        }
    }

    /// Return `true` if `payload[offset..offset+len]` satisfies this pattern.
    #[must_use]
    pub fn matches_at(&self, payload: &[u8], offset: usize) -> bool {
        if !self.offset.allows(offset) {
            return false;
        }
        let pat_len = self.bytes.len();
        if offset + pat_len > payload.len() {
            return false;
        }
        let window = &payload[offset..offset + pat_len];
        self.mask.as_ref().map_or_else(
            || {
                if self.modifiers.nocase {
                    window.iter().zip(self.bytes.iter()).all(|(a, b)| {
                        a.eq_ignore_ascii_case(b)
                    })
                } else {
                    window == self.bytes.as_slice()
                }
            },
            |mask| {
                window
                    .iter()
                    .zip(self.bytes.iter())
                    .zip(mask.iter())
                    .all(|((a, b), m)| {
                        if *m == 0 {
                            true
                        } else if self.modifiers.nocase {
                            (a & m).eq_ignore_ascii_case(&(b & m))
                        } else {
                            (a & m) == (b & m)
                        }
                    })
            },
        )
    }

    /// Search for this pattern in `payload` and return all matching offsets.
    #[must_use]
    pub fn find_all(&self, payload: &[u8]) -> Vec<usize> {
        if self.bytes.is_empty() || payload.len() < self.bytes.len() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let end = payload.len() - self.bytes.len() + 1;
        for i in 0..end {
            if self.matches_at(payload, i) {
                out.push(i);
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature
// ─────────────────────────────────────────────────────────────────────────────

/// A complete detection signature: one or more patterns that must all match.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Unique identifier.
    pub id: u32,
    /// Human-readable name.
    pub name: String,
    /// Optional severity (0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical).
    pub severity: u8,
    /// Patterns that must ALL match for the signature to fire.
    pub patterns: Vec<Pattern>,
    /// Optional free-text description.
    pub description: Option<String>,
    /// Optional tag set.
    pub tags: Vec<String>,
    /// Whether this signature is active.
    pub enabled: bool,
}

impl Signature {
    /// Create a new signature with no patterns.
    #[must_use]
    pub fn new(id: u32, name: impl Into<String>, severity: u8) -> Self {
        Self {
            id,
            name: name.into(),
            severity,
            patterns: Vec::new(),
            description: None,
            tags: Vec::new(),
            enabled: true,
        }
    }

    /// Add a pattern (builder pattern).
    #[must_use]
    pub fn with_pattern(mut self, pat: Pattern) -> Self {
        self.patterns.push(pat);
        self
    }

    /// Add a tag (builder pattern).
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Return `true` if all patterns match somewhere in `payload`.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        if !self.enabled || self.patterns.is_empty() {
            return false;
        }
        self.patterns
            .iter()
            .all(|p| !p.find_all(payload).is_empty())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchContext
// ─────────────────────────────────────────────────────────────────────────────

/// Contextual information about a single signature match.
#[derive(Debug, Clone)]
pub struct MatchContext {
    /// The matching signature's ID.
    pub signature_id: u32,
    /// The matching signature's name.
    pub signature_name: String,
    /// Severity level.
    pub severity: u8,
    /// Per-pattern match offsets (pattern id → list of offsets).
    pub pattern_offsets: HashMap<u8, Vec<usize>>,
    /// Tags from the signature.
    pub tags: Vec<String>,
}

impl MatchContext {
    /// Return the first offset at which any pattern matched, or `None`.
    #[must_use]
    pub fn first_offset(&self) -> Option<usize> {
        self.pattern_offsets
            .values()
            .flat_map(|v| v.iter().copied())
            .min()
    }

    /// Return the number of distinct patterns that matched.
    #[must_use]
    pub fn matched_pattern_count(&self) -> usize {
        self.pattern_offsets.len()
    }

    /// Return `true` if the match has a severity >= `min_severity`.
    #[must_use]
    pub const fn is_at_least(&self, min_severity: u8) -> bool {
        self.severity >= min_severity
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// match_payload
// ─────────────────────────────────────────────────────────────────────────────

/// Scan `payload` against all signatures in `sigs` and return match contexts.
#[must_use]
pub fn match_payload(payload: &[u8], sigs: &[Signature]) -> Vec<MatchContext> {
    let mut results = Vec::new();
    for sig in sigs {
        if !sig.enabled {
            continue;
        }
        // Gather per-pattern matches first.
        let mut pattern_offsets: HashMap<u8, Vec<usize>> = HashMap::new();
        let mut all_matched = true;
        for pat in &sig.patterns {
            let offsets = pat.find_all(payload);
            if offsets.is_empty() {
                all_matched = false;
                break;
            }
            pattern_offsets.insert(pat.id, offsets);
        }
        if all_matched && !sig.patterns.is_empty() {
            results.push(MatchContext {
                signature_id: sig.id,
                signature_name: sig.name.clone(),
                severity: sig.severity,
                pattern_offsets,
                tags: sig.tags.clone(),
            });
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureMatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful matcher that stores signatures and accumulates statistics.
pub struct SignatureMatcher {
    signatures: Vec<Signature>,
    scan_count: u64,
    total_matches: u64,
    per_sig_hits: HashMap<u32, u64>,
}

impl SignatureMatcher {
    /// Create an empty matcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            scan_count: 0,
            total_matches: 0,
            per_sig_hits: HashMap::new(),
        }
    }

    /// Add a signature.
    pub fn add_signature(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    /// Remove a signature by ID.  Returns `true` if removed.
    pub fn remove_signature(&mut self, id: u32) -> bool {
        let before = self.signatures.len();
        self.signatures.retain(|s| s.id != id);
        self.signatures.len() < before
    }

    /// Enable or disable a signature.
    pub fn set_enabled(&mut self, id: u32, enabled: bool) {
        for s in &mut self.signatures {
            if s.id == id {
                s.enabled = enabled;
            }
        }
    }

    /// Scan `payload` and return all matching contexts.
    pub fn scan(&mut self, payload: &[u8]) -> Vec<MatchContext> {
        self.scan_count += 1;
        let results = match_payload(payload, &self.signatures);
        for ctx in &results {
            *self.per_sig_hits.entry(ctx.signature_id).or_insert(0) += 1;
            self.total_matches += 1;
        }
        results
    }

    /// Return only matches at or above a minimum severity.
    pub fn scan_filtered(&mut self, payload: &[u8], min_severity: u8) -> Vec<MatchContext> {
        self.scan(payload)
            .into_iter()
            .filter(|c| c.severity >= min_severity)
            .collect()
    }

    /// Return the total number of payloads scanned.
    #[must_use]
    pub const fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Return the total number of signature matches.
    #[must_use]
    pub const fn total_matches(&self) -> u64 {
        self.total_matches
    }

    /// Return the hit count for a specific signature.
    #[must_use]
    pub fn hit_count(&self, id: u32) -> u64 {
        self.per_sig_hits.get(&id).copied().unwrap_or(0)
    }

    /// Return the number of signatures loaded.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Return signatures that have a specific tag.
    #[must_use]
    pub fn signatures_by_tag(&self, tag: &str) -> Vec<&Signature> {
        self.signatures
            .iter()
            .filter(|s| s.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.scan_count = 0;
        self.total_matches = 0;
        self.per_sig_hits.clear();
    }
}

impl Default for SignatureMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a hex-string pattern (e.g. `"4d 5a ?? 00"`) into bytes and mask.
///
/// `??` or `**` bytes become `0x00` in the pattern and `0x00` in the mask
/// (wildcard). All other bytes are taken literally with mask `0xff`.
#[must_use]
pub fn parse_pattern_hex(hex: &str) -> (Vec<u8>, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for token in hex.split_whitespace() {
        if token == "??" || token == "**" {
            bytes.push(0x00);
            mask.push(0x00);
        } else {
            let b = u8::from_str_radix(token, 16).unwrap_or(0);
            bytes.push(b);
            mask.push(0xff);
        }
    }
    (bytes, mask)
}

/// Build a [`Pattern`] from a hex string, returning the compiled pattern.
#[must_use]
pub fn build_hex_pattern(id: u8, hex: &str) -> Pattern {
    let (bytes, mask) = parse_pattern_hex(hex);
    let all_exact = mask.iter().all(|&m| m == 0xff);
    Pattern {
        id,
        bytes,
        mask: if all_exact { None } else { Some(mask) },
        offset: OffsetConstraint::Anywhere,
        modifiers: PatternModifier::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_sig(id: u32, pattern: &[u8]) -> Signature {
        Signature::new(id, format!("sig-{id}"), 2)
            .with_pattern(Pattern::new(0, pattern.to_vec()))
    }

    #[test]
    fn pattern_exact_match() {
        let pat = Pattern::new(0, b"GET".to_vec());
        assert!(pat.matches_at(b"GET /index.html HTTP/1.1", 0));
        assert!(!pat.matches_at(b"POST /index.html HTTP/1.1", 0));
    }

    #[test]
    fn pattern_nocase_match() {
        let mut pat = Pattern::new(0, b"get".to_vec());
        pat.modifiers.nocase = true;
        assert!(pat.matches_at(b"GET /", 0));
        assert!(pat.matches_at(b"get /", 0));
    }

    #[test]
    fn pattern_mask_wildcard() {
        let (bytes, mask) = parse_pattern_hex("4d 5a ?? 00");
        let pat = Pattern {
            id: 0,
            bytes,
            mask: Some(mask),
            offset: OffsetConstraint::Anywhere,
            modifiers: PatternModifier::default(),
        };
        // 4d 5a (anything) 00 — should match
        assert!(pat.matches_at(&[0x4d, 0x5a, 0xab, 0x00], 0));
        // 4d 5a (anything) 01 — should not match
        assert!(!pat.matches_at(&[0x4d, 0x5a, 0xab, 0x01], 0));
    }

    #[test]
    fn pattern_find_all() {
        let pat = Pattern::new(0, b"AB".to_vec());
        let offsets = pat.find_all(b"XABABAB");
        assert_eq!(offsets, vec![1, 3, 5]);
    }

    #[test]
    fn pattern_offset_constraint_exact() {
        let mut pat = Pattern::new(0, b"MZ".to_vec());
        pat.offset = OffsetConstraint::Exact(0);
        let payload = b"MZfoo";
        assert!(pat.matches_at(payload, 0));
        assert!(!pat.matches_at(payload, 1));
    }

    #[test]
    fn pattern_offset_constraint_window() {
        let mut pat = Pattern::new(0, b"XY".to_vec());
        pat.offset = OffsetConstraint::Window { start: 2, end: 5 };
        let payload = b"__XY__";
        assert!(pat.matches_at(payload, 2));
        assert!(!pat.matches_at(payload, 0));
    }

    #[test]
    fn signature_matches_all_patterns() {
        let sig = Signature::new(1, "multi", 3)
            .with_pattern(Pattern::new(0, b"AAAA".to_vec()))
            .with_pattern(Pattern::new(1, b"BBBB".to_vec()));
        assert!(sig.matches(b"prefix AAAA middle BBBB suffix"));
        assert!(!sig.matches(b"only AAAA here"));
    }

    #[test]
    fn match_payload_returns_all() {
        let sigs = vec![
            simple_sig(1, b"evil"),
            simple_sig(2, b"bad"),
            simple_sig(3, b"harmless"),
        ];
        let payload = b"this is evil and bad payload";
        let results = match_payload(payload, &sigs);
        let ids: Vec<u32> = results.iter().map(|c| c.signature_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert!(!ids.contains(&3));
    }

    #[test]
    fn signature_matcher_scan() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"test"));
        let ctx = m.scan(b"this is a test payload");
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0].signature_id, 1);
        assert_eq!(m.scan_count(), 1);
        assert_eq!(m.total_matches(), 1);
    }

    #[test]
    fn signature_matcher_filtered() {
        let mut m = SignatureMatcher::new();
        m.add_signature(Signature::new(1, "low", 1)
            .with_pattern(Pattern::new(0, b"x".to_vec())));
        m.add_signature(Signature::new(2, "high", 4)
            .with_pattern(Pattern::new(0, b"y".to_vec())));
        let payload = b"xy";
        let filtered = m.scan_filtered(payload, 3);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].signature_id, 2);
    }

    #[test]
    fn signature_matcher_remove() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"test"));
        let removed = m.remove_signature(1);
        assert!(removed);
        assert_eq!(m.signature_count(), 0);
    }

    #[test]
    fn signature_matcher_set_enabled() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"test"));
        m.set_enabled(1, false);
        let ctx = m.scan(b"test");
        assert!(ctx.is_empty());
    }

    #[test]
    fn signature_matcher_by_tag() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"a").with_tag("malware"));
        m.add_signature(simple_sig(2, b"b").with_tag("recon"));
        let tagged = m.signatures_by_tag("malware");
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].id, 1);
    }

    #[test]
    fn signature_matcher_reset_stats() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"x"));
        m.scan(b"x");
        m.reset_stats();
        assert_eq!(m.scan_count(), 0);
        assert_eq!(m.total_matches(), 0);
    }

    #[test]
    fn match_context_first_offset() {
        let mut m = SignatureMatcher::new();
        m.add_signature(simple_sig(1, b"AB"));
        let results = m.scan(b"...AB...AB");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].first_offset(), Some(3));
    }

    #[test]
    fn match_context_severity_filter() {
        let ctx = MatchContext {
            signature_id: 1,
            signature_name: "test".into(),
            severity: 3,
            pattern_offsets: HashMap::new(),
            tags: Vec::new(),
        };
        assert!(ctx.is_at_least(2));
        assert!(!ctx.is_at_least(4));
    }

    #[test]
    fn build_hex_pattern_exact() {
        let pat = build_hex_pattern(0, "4d 5a 90 00");
        assert!(pat.mask.is_none());
        assert_eq!(pat.bytes, vec![0x4d, 0x5a, 0x90, 0x00]);
    }

    #[test]
    fn build_hex_pattern_with_wildcard() {
        let pat = build_hex_pattern(0, "4d 5a ?? 00");
        assert!(pat.mask.is_some());
        let mask = pat.mask.unwrap();
        assert_eq!(mask[2], 0x00);
        assert_eq!(mask[0], 0xff);
    }

    #[test]
    fn parse_pattern_hex_wildcards() {
        let (bytes, mask) = parse_pattern_hex("ff ?? ee");
        assert_eq!(bytes, vec![0xff, 0x00, 0xee]);
        assert_eq!(mask, vec![0xff, 0x00, 0xff]);
    }

    #[test]
    fn offset_constraint_depth() {
        let c = OffsetConstraint::Depth(5);
        assert!(c.allows(0));
        assert!(c.allows(4));
        assert!(!c.allows(5));
    }

    #[test]
    fn pattern_empty_payload_no_match() {
        let pat = Pattern::new(0, b"AB".to_vec());
        assert_eq!(pat.find_all(b""), Vec::<usize>::new());
    }

    #[test]
    fn sig_disabled_no_match() {
        let mut sig = simple_sig(1, b"test");
        sig.enabled = false;
        let sigs = vec![sig];
        let results = match_payload(b"test", &sigs);
        assert!(results.is_empty());
    }
}
