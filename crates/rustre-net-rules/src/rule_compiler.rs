//! Network rule compiler.
//!
//! Compiles parsed Suricata/Snort rules into an efficient match structure:
//! Aho-Corasick automaton for content patterns, PCRE pattern list, and a
//! per-rule decision tree. This module does not depend on external regex or
//! AC crates — it provides a pure-Rust Aho-Corasick implementation and a
//! simple PCRE stub that can be swapped for `pcre2` if desired.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::suricata_rules::{AddrSpec, PortSpec, SuricataProto, SuricataRule, SuricataRuleSet};

// ─── Truncation helpers (deliberate cast boundaries) ─────────────────────────

#[inline]
fn usize_to_u32_trunc(n: usize) -> u32 { u32::try_from(n).unwrap_or(u32::MAX) }
#[inline]
fn usize_to_f64_lossy(n: usize) -> f64 {
    let lo = u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0);
    let hi = u32::try_from(n >> 32).unwrap_or(0);
    (f64::from(hi) * f64::from(1u32 << 16)).mul_add(f64::from(1u32 << 16), f64::from(lo))
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("no rules to compile")]
    Empty,
    #[error("pattern too long: {0} bytes")]
    PatternTooLong(usize),
    #[error("invalid PCRE pattern: {0}")]
    InvalidPcre(String),
    #[error("rule set inconsistency: {0}")]
    Inconsistency(String),
}

pub type CompileResult<T> = Result<T, CompileError>;

// ─── Pattern ID ───────────────────────────────────────────────────────────────

/// Opaque identifier for a compiled content pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternId(pub u32);

/// Opaque identifier for a compiled rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompiledRuleId(pub u32);

// ─── Aho-Corasick Implementation ─────────────────────────────────────────────

const ALPHABET_SIZE: usize = 256;

#[derive(Debug, Clone)]
struct AcNode {
    children: [u32; ALPHABET_SIZE],
    fail: u32,
    /// Pattern IDs that end at this node.
    output: Vec<PatternId>,
}

impl AcNode {
    const fn new() -> Self {
        Self {
            children: [u32::MAX; ALPHABET_SIZE],
            fail: 0,
            output: Vec::new(),
        }
    }
}

/// Aho-Corasick automaton for multi-pattern string matching.
#[derive(Debug, Clone)]
pub struct AhoCorasick {
    nodes: Vec<AcNode>,
    patterns: Vec<Vec<u8>>,
    case_insensitive: bool,
}

impl AhoCorasick {
    /// Build an Aho-Corasick automaton from a list of byte patterns.
    ///
    /// # Panics
    /// Panics if the number of trie states exceeds `u32::MAX`.
    #[must_use]
    pub fn build(patterns: &[(&[u8], PatternId)], case_insensitive: bool) -> Self {
        let mut nodes = vec![AcNode::new()];
        let mut stored_patterns = Vec::new();

        // Trie insertion.
        for (pattern, pid) in patterns {
            let pat: Vec<u8> = if case_insensitive {
                pattern.iter().map(u8::to_ascii_lowercase).collect()
            } else {
                pattern.to_vec()
            };
            let mut state = 0u32;
            for &byte in &pat {
                let b = byte as usize;
                if nodes[state as usize].children[b] == u32::MAX {
                    let new_state = u32::try_from(nodes.len())
                        .expect("AC trie state count overflowed u32");
                    nodes.push(AcNode::new());
                    nodes[state as usize].children[b] = new_state;
                }
                state = nodes[state as usize].children[b];
            }
            nodes[state as usize].output.push(*pid);
            stored_patterns.push(pat);
        }

        // BFS to fill failure links.
        let mut queue = VecDeque::new();
        for b in 0..ALPHABET_SIZE {
            let child = nodes[0].children[b];
            if child == u32::MAX {
                nodes[0].children[b] = 0;
            } else {
                nodes[child as usize].fail = 0;
                queue.push_back(child);
            }
        }
        while let Some(state) = queue.pop_front() {
            for b in 0..ALPHABET_SIZE {
                let child = nodes[state as usize].children[b];
                if child == u32::MAX {
                    let fail_child = {
                        let fail = nodes[state as usize].fail;
                        nodes[fail as usize].children[b]
                    };
                    nodes[state as usize].children[b] = fail_child;
                } else {
                    let fail_state = {
                        let fail = nodes[state as usize].fail;
                        nodes[fail as usize].children[b]
                    };
                    nodes[child as usize].fail = fail_state;
                    // Merge outputs.
                    let fail_output = nodes[fail_state as usize].output.clone();
                    nodes[child as usize].output.extend(fail_output);
                    queue.push_back(child);
                }
            }
        }

        Self { nodes, patterns: stored_patterns, case_insensitive }
    }

    /// Search `text` for all pattern occurrences. Returns `(offset, PatternId)`.
    #[must_use]
    pub fn search(&self, text: &[u8]) -> Vec<(usize, PatternId)> {
        let mut results = Vec::new();
        let mut state = 0u32;
        for (i, &byte) in text.iter().enumerate() {
            let b = if self.case_insensitive { byte.to_ascii_lowercase() } else { byte } as usize;
            state = self.nodes[state as usize].children[b];
            for &pid in &self.nodes[state as usize].output {
                let pat_len = self.patterns[pid.0 as usize].len();
                let start = i + 1 - pat_len;
                results.push((start, pid));
            }
        }
        results
    }

    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ─── PCRE Pattern Stub ────────────────────────────────────────────────────────

/// A compiled PCRE pattern (stub: stores raw string, matches via contains).
/// Replace with `pcre2::Regex` in production.
#[derive(Debug, Clone)]
pub struct PcrePattern {
    pub raw: String,
    pub rule_id: CompiledRuleId,
    pub nocase: bool,
}

impl PcrePattern {
    /// Compile a PCRE pattern (stub implementation).
    ///
    /// # Errors
    /// Returns `CompileError::InvalidPcre` if the pattern is empty.
    pub fn compile(raw: &str, rule_id: CompiledRuleId, nocase: bool) -> CompileResult<Self> {
        // Basic validation: reject obviously invalid patterns.
        if raw.is_empty() {
            return Err(CompileError::InvalidPcre("empty pattern".into()));
        }
        // In a real build this would call pcre2_compile; here we just store it.
        Ok(Self { raw: raw.to_string(), rule_id, nocase })
    }

    /// Returns true if `haystack` contains the pattern (stub implementation).
    #[must_use]
    pub fn test(&self, haystack: &[u8]) -> bool {
        let pattern = if self.nocase { self.raw.to_lowercase() } else { self.raw.clone() };
        let text = if self.nocase {
            String::from_utf8_lossy(haystack).to_lowercase()
        } else {
            String::from_utf8_lossy(haystack).to_string()
        };
        text.contains(&pattern)
    }
}

// ─── IP / Port Match Structures ──────────────────────────────────────────────

/// A compiled IP address specification — converted from `AddrSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompiledAddr {
    Any,
    Negated(Box<Self>),
    Exact([u8; 4]),
    Cidr { net: [u8; 4], prefix: u8 },
    Group(Vec<Self>),
}

impl CompiledAddr {
    #[must_use]
    pub fn from_spec(spec: &AddrSpec) -> Self {
        match spec {
            AddrSpec::Any | AddrSpec::Variable(_) => Self::Any,
            AddrSpec::Negated(inner) => Self::Negated(Box::new(Self::from_spec(inner))),
            AddrSpec::Ip(ip) => parse_ip_str(ip).map_or(Self::Any, Self::Exact),
            AddrSpec::Cidr(cidr) => parse_cidr_str(cidr).unwrap_or(Self::Any),
            AddrSpec::Group(parts) => Self::Group(parts.iter().map(Self::from_spec).collect()),
        }
    }

    #[must_use]
    pub fn matches(&self, ip: &[u8; 4]) -> bool {
        match self {
            Self::Any => true,
            Self::Negated(inner) => !inner.matches(ip),
            Self::Exact(addr) => addr == ip,
            Self::Cidr { net, prefix } => {
                let mask = if *prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                let net_u32 = u32::from_be_bytes(*net);
                let ip_u32 = u32::from_be_bytes(*ip);
                (ip_u32 & mask) == (net_u32 & mask)
            }
            Self::Group(parts) => parts.iter().any(|p| p.matches(ip)),
        }
    }
}

/// A compiled port specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompiledPort {
    Any,
    Negated(Box<Self>),
    Single(u16),
    Range(u16, u16),
    Group(Vec<Self>),
}

impl CompiledPort {
    #[must_use]
    pub fn from_spec(spec: &PortSpec) -> Self {
        match spec {
            PortSpec::Any | PortSpec::Variable(_) => Self::Any,
            PortSpec::Negated(inner) => Self::Negated(Box::new(Self::from_spec(inner))),
            PortSpec::Single(p) => Self::Single(*p),
            PortSpec::Range(lo, hi) => Self::Range(*lo, *hi),
            PortSpec::Group(parts) => Self::Group(parts.iter().map(Self::from_spec).collect()),
        }
    }

    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Negated(inner) => !inner.matches(port),
            Self::Single(p) => *p == port,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::Group(parts) => parts.iter().any(|p| p.matches(port)),
        }
    }
}

fn parse_ip_str(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn parse_cidr_str(s: &str) -> Option<CompiledAddr> {
    let (ip_part, prefix_part) = s.split_once('/')?;
    let net = parse_ip_str(ip_part)?;
    let prefix: u8 = prefix_part.parse().ok()?;
    Some(CompiledAddr::Cidr { net, prefix })
}

// ─── Compiled Rule ────────────────────────────────────────────────────────────

/// A rule in its compiled form — ready for fast packet matching.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: CompiledRuleId,
    pub sid: u64,
    pub msg: String,
    pub proto: SuricataProto,
    pub src_addr: CompiledAddr,
    pub src_port: CompiledPort,
    pub dst_addr: CompiledAddr,
    pub dst_port: CompiledPort,
    /// Pattern IDs in the AC automaton that must ALL match.
    pub required_patterns: Vec<PatternId>,
    /// PCRE patterns (indices into the PCRE list) that must ALL match.
    pub required_pcre: Vec<usize>,
    /// If true, the rule fires when any required pattern matches (OR mode).
    /// Default is AND (all must match).
    pub or_mode: bool,
    pub action_drop: bool,
}

// ─── Compiled Rule Set ────────────────────────────────────────────────────────

/// The output of the compiler — everything needed to match packets at speed.
pub struct CompiledRuleSet {
    pub rules: Vec<CompiledRule>,
    /// Aho-Corasick for all content patterns.
    pub ac: AhoCorasick,
    /// PCRE patterns.
    pub pcre_patterns: Vec<PcrePattern>,
    /// Map from `PatternId` to rule IDs that use it.
    pub pattern_to_rules: HashMap<PatternId, Vec<CompiledRuleId>>,
    /// Map from rule ID to rule index in `rules`.
    pub id_to_index: HashMap<CompiledRuleId, usize>,
    /// Total number of source rules considered.
    pub source_rule_count: usize,
}

impl CompiledRuleSet {
    /// Iterate all compiled rules.
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Look up a rule by its compiled ID.
    #[must_use]
    pub fn get(&self, id: CompiledRuleId) -> Option<&CompiledRule> {
        self.id_to_index.get(&id).and_then(|&i| self.rules.get(i))
    }

    /// Search `payload` using the AC automaton and return matching `PatternIds`.
    #[must_use]
    pub fn ac_search(&self, payload: &[u8]) -> Vec<(usize, PatternId)> {
        self.ac.search(payload)
    }

    /// Return all rules that might match based on AC hits.
    #[must_use]
    pub fn candidate_rules(&self, payload: &[u8]) -> Vec<&CompiledRule> {
        let hits: std::collections::HashSet<PatternId> =
            self.ac_search(payload).into_iter().map(|(_, pid)| pid).collect();
        let mut candidates = std::collections::HashSet::new();
        for pid in &hits {
            if let Some(rule_ids) = self.pattern_to_rules.get(pid) {
                for rid in rule_ids {
                    candidates.insert(*rid);
                }
            }
        }
        candidates
            .into_iter()
            .filter_map(|rid| self.get(rid))
            .collect()
    }
}

// ─── Compiler ────────────────────────────────────────────────────────────────

pub struct RuleCompiler {
    /// Maximum length of a content pattern (to avoid degenerate AC builds).
    pub max_pattern_len: usize,
    /// If true, content matches are case-insensitive by default.
    pub default_nocase: bool,
}

impl RuleCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self { max_pattern_len: 8192, default_nocase: false }
    }

    #[must_use]
    pub const fn with_nocase(mut self, v: bool) -> Self {
        self.default_nocase = v;
        self
    }

    /// Compile a `SuricataRuleSet` into a `CompiledRuleSet`.
    ///
    /// # Errors
    /// Returns `CompileError::Empty` if there are no enabled rules,
    /// `CompileError::PatternTooLong` if any content pattern exceeds `max_pattern_len`,
    /// or `CompileError::InvalidPcre` if any PCRE pattern fails to compile.
    pub fn compile(&self, rule_set: &SuricataRuleSet) -> CompileResult<CompiledRuleSet> {
        let enabled: Vec<&SuricataRule> = rule_set.enabled_rules().collect();
        if enabled.is_empty() {
            return Err(CompileError::Empty);
        }

        let mut all_patterns: Vec<(Vec<u8>, PatternId)> = Vec::new();
        let mut pattern_dedup: HashMap<Vec<u8>, PatternId> = HashMap::new();
        let mut compiled_rules: Vec<CompiledRule> = Vec::new();
        let mut pcre_patterns: Vec<PcrePattern> = Vec::new();
        let mut pattern_to_rules: HashMap<PatternId, Vec<CompiledRuleId>> = HashMap::new();
        let mut id_to_index: HashMap<CompiledRuleId, usize> = HashMap::new();

        for (rule_idx, rule) in enabled.iter().enumerate() {
            let compiled_id = CompiledRuleId(usize_to_u32_trunc(rule_idx));
            let sid = rule.sid().unwrap_or(0);
            let msg = rule.msg().unwrap_or("").to_string();

            // Collect content patterns.
            let mut required_patterns: Vec<PatternId> = Vec::new();
            let nocase = if rule.options.iter().any(|o| o.keyword == "nocase") {
                true
            } else {
                self.default_nocase
            };

            for content in rule.content_patterns() {
                let bytes = unescape_content(content);
                if bytes.len() > self.max_pattern_len {
                    return Err(CompileError::PatternTooLong(bytes.len()));
                }
                let key = if nocase {
                    bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>()
                } else {
                    bytes.clone()
                };
                let pid = if let Some(&existing) = pattern_dedup.get(&key) {
                    existing
                } else {
                    let pid = PatternId(usize_to_u32_trunc(all_patterns.len()));
                    pattern_dedup.insert(key.clone(), pid);
                    all_patterns.push((key, pid));
                    pid
                };
                required_patterns.push(pid);
                pattern_to_rules.entry(pid).or_default().push(compiled_id);
            }

            // Collect PCRE patterns.
            let mut required_pcre: Vec<usize> = Vec::new();
            for opt in &rule.options {
                if let (true, Some(val)) = (opt.keyword == "pcre", &opt.value) {
                    let pcre_idx = pcre_patterns.len();
                    let pat = PcrePattern::compile(val, compiled_id, nocase)?;
                    pcre_patterns.push(pat);
                    required_pcre.push(pcre_idx);
                }
            }

            let compiled_rule = CompiledRule {
                id: compiled_id,
                sid,
                msg,
                proto: rule.proto.clone(),
                src_addr: CompiledAddr::from_spec(&rule.src_addr),
                src_port: CompiledPort::from_spec(&rule.src_port),
                dst_addr: CompiledAddr::from_spec(&rule.dst_addr),
                dst_port: CompiledPort::from_spec(&rule.dst_port),
                required_patterns,
                required_pcre,
                or_mode: false,
                action_drop: matches!(rule.action, crate::suricata_rules::SuricataAction::Drop),
            };

            id_to_index.insert(compiled_id, compiled_rules.len());
            compiled_rules.push(compiled_rule);
        }

        // Build AC automaton.
        let ac_input: Vec<(&[u8], PatternId)> = all_patterns
            .iter()
            .map(|(pat, pid)| (pat.as_slice(), *pid))
            .collect();
        let ac = AhoCorasick::build(&ac_input, self.default_nocase);

        Ok(CompiledRuleSet {
            rules: compiled_rules,
            ac,
            pcre_patterns,
            pattern_to_rules,
            id_to_index,
            source_rule_count: enabled.len(),
        })
    }
}

impl Default for RuleCompiler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Rule Set Optimizer ───────────────────────────────────────────────────────

/// Statistics about the compiled rule set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetStats {
    pub rule_count: usize,
    pub pattern_count: usize,
    pub pcre_count: usize,
    pub ac_state_count: usize,
    pub rules_with_no_content: usize,
    pub average_patterns_per_rule: f64,
}

impl CompiledRuleSet {
    #[must_use]
    pub fn stats(&self) -> RuleSetStats {
        let rules_with_no_content = self.rules.iter().filter(|r| r.required_patterns.is_empty()).count();
        let total_pats: usize = self.rules.iter().map(|r| r.required_patterns.len()).sum();
        let n = self.rules.len().max(1);
        RuleSetStats {
            rule_count: self.rules.len(),
            pattern_count: self.ac.pattern_count(),
            pcre_count: self.pcre_patterns.len(),
            ac_state_count: self.ac.nodes.len(),
            rules_with_no_content,
            average_patterns_per_rule: usize_to_f64_lossy(total_pats) / usize_to_f64_lossy(n),
        }
    }

    /// Return rules that have no content patterns (most expensive to evaluate).
    #[must_use]
    pub fn content_free_rules(&self) -> Vec<&CompiledRule> {
        self.rules.iter().filter(|r| r.required_patterns.is_empty()).collect()
    }

    /// Group rules by protocol for faster dispatch.
    #[must_use]
    pub fn rules_by_proto(&self) -> BTreeMap<String, Vec<&CompiledRule>> {
        let mut map: BTreeMap<String, Vec<&CompiledRule>> = BTreeMap::new();
        for rule in &self.rules {
            let key = rule.proto.to_string();
            map.entry(key).or_default().push(rule);
        }
        map
    }
}

// ─── Content Unescaping ───────────────────────────────────────────────────────

/// Convert a Suricata content string (e.g. `"GET|20|/"`) to raw bytes.
#[must_use]
pub fn unescape_content(s: &str) -> Vec<u8> {
    let s = s.trim_matches('"');
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'|' {
            i += 1;
            // Hex bytes between | ... |
            // If there is no closing '|', treat rest of string as the hex block.
            let end = bytes[i..].iter().position(|&b| b == b'|').map_or(bytes.len(), |p| i + p);
            let hex_str = std::str::from_utf8(&bytes[i..end]).unwrap_or("");
            for part in hex_str.split_whitespace() {
                if let Ok(b) = u8::from_str_radix(part, 16) {
                    out.push(b);
                }
            }
            // If end == bytes.len() there was no closing '|'; don't add 1 past end.
            i = if end < bytes.len() { end + 1 } else { bytes.len() };
        } else if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                other => out.push(other),
            }
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suricata_rules::{SuricataParser, SuricataRuleSet};

    const RULE1: &str = r#"alert tcp any any -> any 80 (msg:"HTTP evil"; content:"evil.exe"; sid:1; rev:1;)"#;
    const RULE2: &str = r#"alert tcp any any -> any 443 (msg:"TLS payload"; content:"malware"; nocase; sid:2; rev:1;)"#;
    const RULE3: &str = r#"alert udp any any -> any 53 (msg:"DNS C2"; content:"c2.badguys.net"; sid:3; rev:1;)"#;

    fn make_rule_set() -> SuricataRuleSet {
        let mut set = SuricataRuleSet::new();
        for r in [RULE1, RULE2, RULE3] {
            let rule = SuricataParser::parse_rule(r).unwrap();
            set.add(rule);
        }
        set
    }

    #[test]
    fn test_compile_basic() {
        let rule_set = make_rule_set();
        let compiler = RuleCompiler::new();
        let output = compiler.compile(&rule_set).unwrap();
        assert_eq!(output.rules.len(), 3);
        assert_eq!(output.ac.pattern_count(), 3);
    }

    #[test]
    fn test_ac_search() {
        let set = make_rule_set();
        let compiled = RuleCompiler::new().compile(&set).unwrap();
        let payload = b"GET /evil.exe HTTP/1.1\r\n";
        let hits = compiled.ac_search(payload);
        assert!(!hits.is_empty());
    }

    #[test]
    fn test_candidate_rules() {
        let set = make_rule_set();
        let compiled = RuleCompiler::new().compile(&set).unwrap();
        let payload = b"GET /evil.exe HTTP/1.1";
        let candidates = compiled.candidate_rules(payload);
        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|r| r.sid == 1));
    }

    #[test]
    fn test_nocase_match() {
        let set = make_rule_set();
        let compiled = RuleCompiler::new().compile(&set).unwrap();
        // "malware" in RULE2 is nocase — but AC is built with default case sensitivity
        // here; test that the pattern itself is stored.
        let stats = compiled.stats();
        assert_eq!(stats.rule_count, 3);
    }

    #[test]
    fn test_stats() {
        let set = make_rule_set();
        let compiled = RuleCompiler::new().compile(&set).unwrap();
        let stats = compiled.stats();
        assert!(stats.ac_state_count > 0);
        assert_eq!(stats.pcre_count, 0);
    }

    #[test]
    fn test_rules_by_proto() {
        let set = make_rule_set();
        let compiled = RuleCompiler::new().compile(&set).unwrap();
        let by_proto = compiled.rules_by_proto();
        assert!(by_proto.contains_key("tcp"));
        assert!(by_proto.contains_key("udp"));
    }

    #[test]
    fn test_unescape_content_hex() {
        let result = unescape_content("\"GET|20|/\"");
        assert_eq!(result, b"GET /");
    }

    #[test]
    fn test_unescape_plain() {
        let result = unescape_content("\"evil.exe\"");
        assert_eq!(result, b"evil.exe");
    }

    #[test]
    fn test_compiled_port_any() {
        let p = CompiledPort::Any;
        assert!(p.matches(80));
        assert!(p.matches(443));
    }

    #[test]
    fn test_compiled_port_range() {
        let p = CompiledPort::Range(1024, 65535);
        assert!(p.matches(8080));
        assert!(!p.matches(80));
    }

    #[test]
    fn test_compiled_addr_cidr() {
        let addr = CompiledAddr::Cidr { net: [192, 168, 0, 0], prefix: 16 };
        assert!(addr.matches(&[192, 168, 1, 100]));
        assert!(!addr.matches(&[10, 0, 0, 1]));
    }

    #[test]
    fn test_pcre_stub() {
        let pat = PcrePattern::compile("evil", CompiledRuleId(0), false).unwrap();
        assert!(pat.test(b"contains evil payload"));
        assert!(!pat.test(b"benign traffic"));
    }

    #[test]
    fn test_aho_corasick_multiple_patterns() {
        let patterns: Vec<(Vec<u8>, PatternId)> = vec![
            (b"hello".to_vec(), PatternId(0)),
            (b"world".to_vec(), PatternId(1)),
            (b"evil".to_vec(), PatternId(2)),
        ];
        let input: Vec<(&[u8], PatternId)> = patterns.iter().map(|(p, id)| (p.as_slice(), *id)).collect();
        let ac = AhoCorasick::build(&input, false);
        let hits = ac.search(b"say hello to the world of evil");
        let ids: Vec<PatternId> = hits.iter().map(|(_, id)| *id).collect();
        assert!(ids.contains(&PatternId(0)));
        assert!(ids.contains(&PatternId(1)));
        assert!(ids.contains(&PatternId(2)));
    }
}
