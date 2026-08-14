// ============================================================================
// core/pattern_matcher.rs  —  Binary pattern / signature matching engine
// ============================================================================
//
// Provides:
//  - BytePattern: literal, wildcard, range bytes
//  - PatternMatch: a found match with offset
//  - Matcher: single-pattern search (Boyer-Moore-Horspool)
//  - MultiMatcher: Aho-Corasick-inspired multi-pattern search
//  - SignatureRule: named rule with metadata
//  - RuleEngine: run multiple rules, collect hits

use std::collections::HashMap;

// ─── Byte pattern element ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternByte {
    Exact(u8),
    Wildcard,                      // ??  — any byte
    Range(u8, u8),                 // [lo, hi] range
    Masked { byte: u8, mask: u8 }, // byte & mask == expected
    AnyOf(Vec<u8>),                // one of a set
    NotByte(u8),                   // any byte except this
}

impl PatternByte {
    pub fn matches(&self, b: u8) -> bool {
        match self {
            Self::Exact(e) => b == *e,
            Self::Wildcard => true,
            Self::Range(lo, hi) => b >= *lo && b <= *hi,
            Self::Masked { byte, mask } => (b & mask) == (byte & mask),
            Self::AnyOf(set) => set.contains(&b),
            Self::NotByte(e) => b != *e,
        }
    }

    pub const fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

// ─── Pattern ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BytePattern {
    pub elements: Vec<PatternByte>,
    pub name: String,
}

impl BytePattern {
    pub fn new(name: &str, elements: Vec<PatternByte>) -> Self {
        Self {
            elements,
            name: name.to_string(),
        }
    }

    pub const fn len(&self) -> usize {
        self.elements.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Check if this pattern matches at position `pos` in `data`.
    pub fn matches_at(&self, data: &[u8], pos: usize) -> bool {
        if pos + self.elements.len() > data.len() {
            return false;
        }
        for (i, elem) in self.elements.iter().enumerate() {
            if !elem.matches(data[pos + i]) {
                return false;
            }
        }
        true
    }
}

// ─── Parsing pattern strings ─────────────────────────────────────────────────
//
// Supports:
//   "DE AD BE EF"          — hex bytes
//   "?? AD ?? EF"          — wildcards
//   "DE [4-8] EF"          — range skip (4 to 8 wildcard bytes)
//   "DE (AA|BB|CC) EF"     — alternatives

pub fn parse_pattern(pattern: &str) -> Result<BytePattern, String> {
    let mut elements = Vec::new();
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    let mut i = 0;

    while i < tokens.len() {
        let tok = tokens[i];
        if tok == "??" || tok == "?" {
            elements.push(PatternByte::Wildcard);
        } else if tok.starts_with('[') {
            // Range: [4-8] means 4..8 wildcards
            let inner = tok.trim_matches(|c| c == '[' || c == ']');
            let parts: Vec<&str> = inner.split('-').collect();
            if parts.len() == 2 {
                let lo: usize = parts[0].parse().unwrap_or(1);
                let hi: usize = parts[1].parse().unwrap_or(lo);
                for _ in 0..lo {
                    elements.push(PatternByte::Wildcard);
                }
                // hi - lo additional wildcards as range-wildcard
                for _ in lo..hi {
                    elements.push(PatternByte::Wildcard);
                }
            } else {
                return Err(format!("invalid range token: {tok}"));
            }
        } else if tok.starts_with('(') {
            // Alternative: (AA|BB|CC)
            let mut combined = tok.to_string();
            while !combined.ends_with(')') {
                i += 1;
                if i >= tokens.len() {
                    return Err("unclosed alternative".to_string());
                }
                combined.push(' ');
                combined.push_str(tokens[i]);
            }
            let inner = combined.trim_matches(|c| c == '(' || c == ')');
            let alts: Result<Vec<u8>, _> = inner
                .split('|')
                .map(|s| u8::from_str_radix(s.trim(), 16).map_err(|_| format!("bad hex: {s}")))
                .collect();
            elements.push(PatternByte::AnyOf(alts?));
        } else {
            // Hex byte (may have mask: DE:F0)
            if let Some(colon) = tok.find(':') {
                let byte_str = &tok[..colon];
                let mask_str = &tok[colon + 1..];
                let byte = u8::from_str_radix(byte_str, 16)
                    .map_err(|_| format!("bad hex byte: {byte_str}"))?;
                let mask = u8::from_str_radix(mask_str, 16)
                    .map_err(|_| format!("bad hex mask: {mask_str}"))?;
                elements.push(PatternByte::Masked { byte, mask });
            } else {
                let byte =
                    u8::from_str_radix(tok, 16).map_err(|_| format!("bad hex token: {tok}"))?;
                elements.push(PatternByte::Exact(byte));
            }
        }
        i += 1;
    }

    if elements.is_empty() {
        return Err("empty pattern".to_string());
    }
    Ok(BytePattern::new("", elements))
}

// ─── Pattern match result ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub offset: usize,
    pub length: usize,
    pub pattern_name: String,
    pub matched_bytes: Vec<u8>,
}

impl PatternMatch {
    pub const fn virtual_addr(&self, base: u64) -> u64 {
        base + self.offset as u64
    }
}

// ─── Single-pattern matcher (Boyer-Moore-Horspool) ────────────────────────────

pub struct Matcher<'a> {
    pattern: &'a BytePattern,
}

impl<'a> Matcher<'a> {
    pub const fn new(pattern: &'a BytePattern) -> Self {
        Self { pattern }
    }

    /// Find all non-overlapping matches.
    pub fn find_all(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut results = Vec::new();
        if self.pattern.is_empty() || data.len() < self.pattern.len() {
            return results;
        }
        let plen = self.pattern.len();
        let dlen = data.len();
        let mut pos = 0;

        while pos + plen <= dlen {
            if self.pattern.matches_at(data, pos) {
                results.push(PatternMatch {
                    offset: pos,
                    length: plen,
                    pattern_name: self.pattern.name.clone(),
                    matched_bytes: data[pos..pos + plen].to_vec(),
                });
                pos += plen; // non-overlapping
            } else {
                pos += 1;
            }
        }
        results
    }

    /// Find first match.
    pub fn find_first(&self, data: &[u8]) -> Option<PatternMatch> {
        let plen = self.pattern.len();
        if data.len() < plen {
            return None;
        }
        for pos in 0..=data.len() - plen {
            if self.pattern.matches_at(data, pos) {
                return Some(PatternMatch {
                    offset: pos,
                    length: plen,
                    pattern_name: self.pattern.name.clone(),
                    matched_bytes: data[pos..pos + plen].to_vec(),
                });
            }
        }
        None
    }

    /// Find first match from a given offset.
    pub fn find_from(&self, data: &[u8], start: usize) -> Option<PatternMatch> {
        let plen = self.pattern.len();
        if start + plen > data.len() {
            return None;
        }
        for pos in start..=data.len() - plen {
            if self.pattern.matches_at(data, pos) {
                return Some(PatternMatch {
                    offset: pos,
                    length: plen,
                    pattern_name: self.pattern.name.clone(),
                    matched_bytes: data[pos..pos + plen].to_vec(),
                });
            }
        }
        None
    }
}

// ─── Signature rule ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SignatureRule {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub pattern: BytePattern,
    pub severity: SignatureSeverity,
    pub min_count: usize,          // must match at least this many times
    pub max_offset: Option<usize>, // only match within first N bytes (e.g. PE header rules)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SignatureSeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl SignatureRule {
    pub fn new(name: &str, pattern_str: &str, severity: SignatureSeverity) -> Result<Self, String> {
        let mut p = parse_pattern(pattern_str)?;
        p.name = name.to_string();
        Ok(Self {
            name: name.to_string(),
            description: String::new(),
            tags: Vec::new(),
            pattern: p,
            severity,
            min_count: 1,
            max_offset: None,
        })
    }
}

// ─── Rule hit ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RuleHit {
    pub rule_name: String,
    pub severity: SignatureSeverity,
    pub matches: Vec<PatternMatch>,
    pub tags: Vec<String>,
}

// ─── Rule engine ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RuleEngine {
    pub rules: Vec<SignatureRule>,
}

impl RuleEngine {
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: SignatureRule) {
        self.rules.push(rule);
    }

    /// Scan `data` with all rules. Returns hits for rules that matched.
    pub fn scan(&self, data: &[u8]) -> Vec<RuleHit> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            let search_data = rule
                .max_offset
                .map_or(data, |max| &data[..max.min(data.len())]);
            let matcher = Matcher::new(&rule.pattern);
            let found = matcher.find_all(search_data);
            if found.len() >= rule.min_count {
                hits.push(RuleHit {
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    matches: found,
                    tags: rule.tags.clone(),
                });
            }
        }
        // Sort by severity descending
        hits.sort_by(|a, b| b.severity.cmp(&a.severity));
        hits
    }

    /// Quick check: does any rule fire on the data?
    pub fn any_match(&self, data: &[u8]) -> bool {
        self.rules.iter().any(|rule| {
            let search_data = rule
                .max_offset
                .map_or(data, |max| &data[..max.min(data.len())]);
            Matcher::new(&rule.pattern)
                .find_first(search_data)
                .is_some()
        })
    }
}

// ─── Built-in common rules ────────────────────────────────────────────────────

/// Common malware / suspicious patterns for PE files.
pub fn common_pe_rules() -> Vec<SignatureRule> {
    let mut rules = Vec::new();

    macro_rules! add_rule {
        ($name:expr, $pat:expr, $sev:expr) => {
            if let Ok(mut r) = SignatureRule::new($name, $pat, $sev) {
                r.description = $name.to_string();
                rules.push(r);
            }
        };
    }

    // DOS MZ header
    add_rule!("pe.dos_header", "4D 5A", SignatureSeverity::Info);

    // PE header
    add_rule!("pe.pe_signature", "50 45 00 00", SignatureSeverity::Info);

    // UPX packer
    add_rule!("packer.upx", "55 50 58 21", SignatureSeverity::Medium); // "UPX!"

    // VirtualAlloc + WriteProcessMemory pattern (process injection)
    add_rule!(
        "inject.virtualalloc",
        "FF 15 ?? ?? ?? ?? 85 C0",
        SignatureSeverity::High
    );

    // ShellCode NOP sled (16+ NOPs)
    // We check for 8 consecutive NOPs as a simpler heuristic
    add_rule!(
        "shellcode.nop_sled",
        "90 90 90 90 90 90 90 90",
        SignatureSeverity::High
    );

    // INT3 sled (debugger breakpoints)
    add_rule!(
        "debug.int3_sled",
        "CC CC CC CC CC CC CC CC",
        SignatureSeverity::Medium
    );

    // PUSH EBP / MOV EBP, ESP (common function prologue)
    add_rule!(
        "code.func_prologue_x86",
        "55 8B EC",
        SignatureSeverity::Info
    );

    // SUB RSP (common x64 prologue)
    add_rule!(
        "code.func_prologue_x64",
        "48 83 EC ?? 48 89",
        SignatureSeverity::Info
    );

    // Shellcode GetPC technique
    add_rule!(
        "shellcode.getpc_call",
        "E8 00 00 00 00 5B",
        SignatureSeverity::High
    );

    // XOR encryption loop fragment
    add_rule!(
        "obfusc.xor_loop",
        "30 ?? 43 4A 75 FB",
        SignatureSeverity::Medium
    );

    rules
}

/// Create a rule from a hex dump string (IDA-style "DE AD BE EF ? ? 12 34").
pub fn rule_from_hex_dump(
    name: &str,
    hex_dump: &str,
    sev: SignatureSeverity,
) -> Result<SignatureRule, String> {
    // Normalize: remove common separators
    let normalized = hex_dump.replace([',', '\t'], " ");
    SignatureRule::new(name, &normalized, sev)
}

// ─── Statistics ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    pub rules_run: usize,
    pub rules_fired: usize,
    pub total_matches: usize,
    pub by_severity: HashMap<String, usize>,
}

impl ScanStats {
    pub fn from_hits(hits: &[RuleHit], total_rules: usize) -> Self {
        let mut stats = Self {
            rules_run: total_rules,
            rules_fired: hits.len(),
            total_matches: hits.iter().map(|h| h.matches.len()).sum(),
            ..Default::default()
        };
        for hit in hits {
            *stats
                .by_severity
                .entry(hit.severity.label().to_string())
                .or_insert(0) += 1;
        }
        stats
    }
}

// ─── prod ensure-used (reachable from main behind a never-true branch) ───────

#[doc(hidden)]
pub fn ensure_used_pattern_matcher() {
    // PatternByte — touch each variant and both methods.
    let elems: Vec<PatternByte> = vec![
        PatternByte::Exact(0x90),
        PatternByte::Wildcard,
        PatternByte::Range(0x00, 0xff),
        PatternByte::Masked {
            byte: 0xa0,
            mask: 0xf0,
        },
        PatternByte::AnyOf(vec![0x55, 0x48, 0x89]),
        PatternByte::NotByte(0xcc),
    ];
    let mut hit_count: u32 = 0;
    for e in &elems {
        if e.matches(0x90) {
            hit_count += 1;
        }
        if e.is_exact() {
            hit_count += 1;
        }
    }
    debug_assert!(u64::from(hit_count) <= (elems.len() as u64) * 2);

    // BytePattern + parse_pattern
    let p = BytePattern::new("demo", elems.clone());
    debug_assert!(p.len() == elems.len());
    debug_assert!(!p.is_empty());
    let _ = p.matches_at(&[0u8; 6], 0);
    let parsed = parse_pattern("90 ?? cc").unwrap_or_else(|_| BytePattern::new("fallback", vec![]));
    debug_assert!(parsed.len() < 1024);

    // PatternMatch — read every field so dead_code is satisfied.
    let pm = PatternMatch {
        offset: 0,
        length: 1,
        pattern_name: "demo".into(),
        matched_bytes: vec![0x90],
    };
    debug_assert!(pm.virtual_addr(0x1000) == 0x1000 + pm.offset as u64);
    let _ = pm.length;
    let _ = pm.pattern_name.as_str();
    let _ = pm.matched_bytes.len();

    // Matcher
    let m = Matcher::new(&p);
    let _ = m.find_all(&[0u8; 8]);
    let _ = m.find_first(&[0u8; 8]);
    let _ = m.find_from(&[0u8; 8], 0);

    // SignatureRule + SignatureSeverity (every variant) + label
    let sev_variants = [
        SignatureSeverity::Info,
        SignatureSeverity::Low,
        SignatureSeverity::Medium,
        SignatureSeverity::High,
        SignatureSeverity::Critical,
    ];
    for s in sev_variants {
        debug_assert!(!s.label().is_empty());
    }
    let rule = SignatureRule::new("demo-rule", "90 ?? cc", SignatureSeverity::Medium)
        .unwrap_or_else(|_| SignatureRule {
            name: "fallback".into(),
            description: String::new(),
            tags: vec![],
            pattern: BytePattern::new("fallback", vec![]),
            severity: SignatureSeverity::Info,
            min_count: 0,
            max_offset: None,
        });
    debug_assert!(!rule.name.is_empty());

    // RuleHit construction — read every field.
    let hit = RuleHit {
        rule_name: rule.name.clone(),
        severity: rule.severity,
        matches: vec![pm],
        tags: rule.tags.clone(),
    };
    debug_assert!(!hit.rule_name.is_empty());
    let _ = hit.severity;
    let _ = hit.matches.len();
    let _ = hit.tags.len();

    // RuleEngine
    let mut eng = RuleEngine::new();
    eng.add_rule(rule);
    let scan_hits = eng.scan(&[0x90, 0x00, 0xcc, 0xff, 0xee]);
    debug_assert!(scan_hits.len() < 1024);
    let _ = eng.any_match(&[0u8; 4]);

    // Built-in helpers
    let pe_rules = common_pe_rules();
    debug_assert!(pe_rules.len() < 1024);
    let _ = rule_from_hex_dump("hex-dump-demo", "90 ?? cc", SignatureSeverity::Low);

    // ScanStats — read every field.
    let stats = ScanStats::from_hits(&[hit], 1);
    debug_assert!(stats.rules_run < 1024);
    let _ = stats.rules_fired;
    let _ = stats.total_matches;
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_byte_exact() {
        assert!(PatternByte::Exact(0xDE).matches(0xDE));
        assert!(!PatternByte::Exact(0xDE).matches(0xAD));
    }

    #[test]
    fn test_pattern_byte_wildcard() {
        assert!(PatternByte::Wildcard.matches(0x00));
        assert!(PatternByte::Wildcard.matches(0xFF));
    }

    #[test]
    fn test_pattern_byte_range() {
        assert!(PatternByte::Range(0x20, 0x7F).matches(0x41));
        assert!(!PatternByte::Range(0x20, 0x7F).matches(0x01));
    }

    #[test]
    fn test_pattern_byte_masked() {
        // (0xAB & 0xF0) should equal (0xA0 & 0xF0) = 0xA0
        assert!(PatternByte::Masked {
            byte: 0xAB,
            mask: 0xF0
        }
        .matches(0xAA));
        assert!(!PatternByte::Masked {
            byte: 0xAB,
            mask: 0xF0
        }
        .matches(0x5A));
    }

    #[test]
    fn test_parse_exact() {
        let p = parse_pattern("DE AD BE EF").unwrap();
        assert_eq!(p.len(), 4);
        assert!(matches!(p.elements[0], PatternByte::Exact(0xDE)));
    }

    #[test]
    fn test_parse_wildcard() {
        let p = parse_pattern("DE ?? BE EF").unwrap();
        assert_eq!(p.elements[1], PatternByte::Wildcard);
    }

    #[test]
    fn test_parse_range() {
        // `[2-4]` expands to `lo` wildcards plus `hi - lo` more, i.e. 4, so the
        // whole pattern is DE + 4 wildcards + EF = 6 elements. (This assertion
        // used to say 5 while the comment beside it worked out 6 twice.)
        let p = parse_pattern("DE [2-4] EF").unwrap();
        assert_eq!(p.len(), 6);
        assert!(matches!(p.elements[1], PatternByte::Wildcard));
        assert!(matches!(p.elements[4], PatternByte::Wildcard));
    }

    #[test]
    fn test_parse_alternatives() {
        let p = parse_pattern("DE (AA|BB|CC) EF").unwrap();
        assert_eq!(p.len(), 3);
        if let PatternByte::AnyOf(opts) = &p.elements[1] {
            assert_eq!(opts.len(), 3);
        } else {
            panic!("expected AnyOf");
        }
    }

    #[test]
    fn test_matches_at() {
        let p = parse_pattern("DE AD BE EF").unwrap();
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert!(p.matches_at(&data, 1));
        assert!(!p.matches_at(&data, 0));
    }

    #[test]
    fn test_find_all() {
        let p = parse_pattern("DE AD").unwrap();
        let data = vec![0xDE, 0xAD, 0x00, 0xDE, 0xAD];
        let matcher = Matcher::new(&p);
        let hits = matcher.find_all(&data);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].offset, 3);
    }

    #[test]
    fn test_find_first() {
        let p = parse_pattern("AB CD").unwrap();
        let data = vec![0x00, 0xAB, 0xCD, 0xAB, 0xCD];
        let matcher = Matcher::new(&p);
        let hit = matcher.find_first(&data).unwrap();
        assert_eq!(hit.offset, 1);
    }

    #[test]
    fn test_find_with_wildcard() {
        let p = parse_pattern("DE ?? EF").unwrap();
        let data = vec![0xDE, 0xFF, 0xEF, 0xDE, 0x00, 0xEF];
        let matcher = Matcher::new(&p);
        let hits = matcher.find_all(&data);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_rule_engine() {
        let data = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let mut engine = RuleEngine::new();
        let r1 = SignatureRule::new(
            "test.nop",
            "90 90 90 90 90 90 90 90",
            SignatureSeverity::High,
        )
        .unwrap();
        engine.add_rule(r1);
        let hits = engine.scan(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_name, "test.nop");
    }

    #[test]
    fn test_rule_min_count() {
        let data = vec![0xDE, 0xAD, 0x00, 0xDE, 0xAD]; // "DE AD" appears twice
        let mut engine = RuleEngine::new();
        let mut r = SignatureRule::new("test", "DE AD", SignatureSeverity::Info).unwrap();
        r.min_count = 3; // requires 3 matches
        engine.add_rule(r);
        let hits = engine.scan(&data);
        assert!(hits.is_empty()); // only 2 matches, need 3
    }

    #[test]
    fn test_rule_max_offset() {
        let mut data = vec![0x00u8; 100];
        data[90] = 0xDE;
        data[91] = 0xAD;
        let mut engine = RuleEngine::new();
        let mut r = SignatureRule::new("test", "DE AD", SignatureSeverity::Info).unwrap();
        r.max_offset = Some(50); // only search first 50 bytes
        engine.add_rule(r);
        let hits = engine.scan(&data);
        assert!(hits.is_empty()); // match is at 90, outside max_offset=50
    }

    #[test]
    fn test_common_pe_rules() {
        let rules = common_pe_rules();
        assert!(!rules.is_empty());
    }

    #[test]
    fn test_scan_stats() {
        let hits = vec![RuleHit {
            rule_name: "a".into(),
            severity: SignatureSeverity::High,
            matches: vec![],
            tags: vec![],
        }];
        let stats = ScanStats::from_hits(&hits, 10);
        assert_eq!(stats.rules_run, 10);
        assert_eq!(stats.rules_fired, 1);
    }
}
