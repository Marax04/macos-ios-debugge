//! `string_xref` — String cross-reference analysis.
//!
//! Tracks which code locations reference which strings, clusters strings used
//! together, detects localization patterns, and identifies encrypted strings.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::FoundString;

pub type StringRecord = FoundString;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StringXref {
    pub string_addr: u64,
    pub from_addr: u64,
    pub from_function: Option<u64>,
    pub text: String,
}

#[must_use]
pub fn string_xrefs(
    strings: &[StringRecord],
    code_refs: &[(u64, u64)],
    fn_lookup: Option<&HashMap<u64, u64>>,
) -> Vec<StringXref> {
    let mut by_addr: HashMap<u64, &StringRecord> = HashMap::with_capacity(strings.len());
    for s in strings {
        by_addr.insert(s.address.0, s);
    }
    let mut out = Vec::new();
    for &(from_addr, target) in code_refs {
        if let Some(s) = by_addr.get(&target) {
            let from_function = fn_lookup.and_then(|m| m.get(&from_addr).copied());
            out.push(StringXref {
                string_addr: target,
                from_addr,
                from_function,
                text: s.value.clone(),
            });
        }
    }
    out
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum XrefError {
    #[error("string not found at {0:#x}")]
    StringNotFound(u64),
    #[error("insufficient data: {0}")]
    InsufficientData(String),
}

// ─── StringAccessType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringAccessType {
    /// Direct load/reference in code.
    DirectLoad,
    /// Passed as an argument to a function.
    ArgumentPassed,
    /// Returned from a function.
    Returned,
    /// Stored to a variable.
    Stored,
    /// Compared (e.g. strcmp).
    Compared,
    /// Printed / written to output.
    Printed,
}

// ─── StringRef ────────────────────────────────────────────────────────────────

/// A cross-reference between a string and a code location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringRef {
    /// Address of the string data.
    pub string_addr: u64,
    /// Address in code that references the string.
    pub code_addr: u64,
    /// How the string is accessed at this site.
    pub access_type: StringAccessType,
    /// Which function contains this reference.
    pub function_addr: Option<u64>,
    /// The actual string content (cached).
    pub content: Option<String>,
}

impl StringRef {
    #[must_use] 
    pub const fn new(string_addr: u64, code_addr: u64, access_type: StringAccessType) -> Self {
        Self {
            string_addr,
            code_addr,
            access_type,
            function_addr: None,
            content: None,
        }
    }

    #[must_use] 
    pub const fn in_function(mut self, fn_addr: u64) -> Self {
        self.function_addr = Some(fn_addr);
        self
    }

    #[must_use]
    pub fn with_content(mut self, s: impl Into<String>) -> Self {
        self.content = Some(s.into());
        self
    }
}

// ─── StringCallGraph ─────────────────────────────────────────────────────────

/// Maps functions to the strings they reference.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StringCallGraph {
    /// `function_addr` → set of string addresses referenced.
    pub fn_to_strings: HashMap<u64, HashSet<u64>>,
    /// `string_addr` → set of function addresses that reference it.
    pub string_to_fns: HashMap<u64, HashSet<u64>>,
}

impl StringCallGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reference from function to string.
    pub fn add_ref(&mut self, fn_addr: u64, string_addr: u64) {
        self.fn_to_strings
            .entry(fn_addr)
            .or_default()
            .insert(string_addr);
        self.string_to_fns
            .entry(string_addr)
            .or_default()
            .insert(fn_addr);
    }

    /// Get all strings referenced by a function.
    #[must_use] 
    pub fn strings_in_function(&self, fn_addr: u64) -> &HashSet<u64> {
        static EMPTY: std::sync::OnceLock<HashSet<u64>> = std::sync::OnceLock::new();
        self.fn_to_strings
            .get(&fn_addr)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Get all functions that reference a string.
    #[must_use] 
    pub fn functions_using_string(&self, string_addr: u64) -> &HashSet<u64> {
        static EMPTY: std::sync::OnceLock<HashSet<u64>> = std::sync::OnceLock::new();
        self.string_to_fns
            .get(&string_addr)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Strings referenced by exactly one function (unique to that function).
    #[must_use] 
    pub fn unique_strings(&self) -> Vec<u64> {
        self.string_to_fns
            .iter()
            .filter(|(_, fns)| fns.len() == 1)
            .map(|(&addr, _)| addr)
            .collect()
    }

    /// Most referenced strings (by number of functions).
    #[must_use] 
    pub fn most_referenced(&self, top_n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self
            .string_to_fns
            .iter()
            .map(|(&addr, fns)| (addr, fns.len()))
            .collect();
        // `string_to_fns` is a HashMap, so equal reference counts are ordered
        // arbitrarily — and `truncate` turns that into a difference in CONTENT:
        // which of the equally-referenced strings make the top N would change
        // between runs on the same binary. Break the tie on the address.
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(top_n);
        pairs
    }
}

// ─── StringCluster ───────────────────────────────────────────────────────────

/// A cluster of strings that are used together (co-occur in the same function or code path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringCluster {
    pub id: usize,
    /// String addresses in the cluster.
    pub members: Vec<u64>,
    /// Representative string content (most common or shortest).
    pub representative: Option<String>,
    /// Functions that use all strings in the cluster.
    pub common_functions: HashSet<u64>,
    /// Cluster label inferred from content.
    pub label: Option<String>,
}

impl StringCluster {
    #[must_use] 
    pub fn new(id: usize) -> Self {
        Self {
            id,
            members: Vec::new(),
            representative: None,
            common_functions: HashSet::new(),
            label: None,
        }
    }

    pub fn add_member(&mut self, addr: u64) {
        self.members.push(addr);
    }

    #[must_use] 
    pub const fn size(&self) -> usize {
        self.members.len()
    }
}

/// Groups co-occurring strings into clusters.
pub struct StringClusterBuilder {
    min_co_occurrence: usize,
}

impl StringClusterBuilder {
    #[must_use] 
    pub const fn new(min_co_occurrence: usize) -> Self {
        Self { min_co_occurrence }
    }

    /// Build clusters from a string call graph.
    #[must_use] 
    pub fn build(
        &self,
        graph: &StringCallGraph,
        string_contents: &HashMap<u64, String>,
    ) -> Vec<StringCluster> {
        let mut clusters = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut cluster_id = 0;

        // Iterate functions in sorted-address order: cluster ids, membership
        // and representatives must not depend on HashMap iteration order.
        let mut fn_addrs: Vec<u64> = graph.fn_to_strings.keys().copied().collect();
        fn_addrs.sort_unstable();
        for fn_addr in fn_addrs {
            let strings = &graph.fn_to_strings[&fn_addr];
            if strings.len() < self.min_co_occurrence {
                continue;
            }
            let mut new_members: Vec<u64> = strings
                .iter()
                .filter(|&&s| !visited.contains(&s))
                .copied()
                .collect();
            // HashSet iteration order is random; sort so the representative
            // (first member) is deterministic.
            new_members.sort_unstable();
            if new_members.is_empty() {
                continue;
            }
            let mut cluster = StringCluster::new(cluster_id);
            cluster_id += 1;
            for &m in &new_members {
                visited.insert(m);
                cluster.add_member(m);
            }
            cluster.common_functions.insert(fn_addr);
            // Try to infer a label from the string contents.
            if let Some(&first) = new_members.first()
                && let Some(content) = string_contents.get(&first) {
                    cluster.representative = Some(content.clone());
                    cluster.label = Self::infer_label(content);
                }
            clusters.push(cluster);
        }
        clusters
    }

    fn infer_label(content: &str) -> Option<String> {
        let lower = content.to_lowercase();
        if lower.contains("error") || lower.contains("err") {
            Some("error_strings".into())
        } else if lower.contains("debug") || lower.contains("log") {
            Some("debug_strings".into())
        } else if lower.contains("http") || lower.contains("url") {
            Some("network_strings".into())
        } else if lower.contains("key") || lower.contains("password") || lower.contains("secret") {
            Some("credential_strings".into())
        } else if lower.contains("format") || lower.contains("%s") || lower.contains("%d") {
            Some("format_strings".into())
        } else {
            None
        }
    }
}

// ─── LocalizedStrings ────────────────────────────────────────────────────────

/// Localization pattern indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocalizationPattern {
    /// String ID like "`IDS_BUTTON_OK`".
    StringIdTable,
    /// .po / gettext format.
    Gettext,
    /// Resource bundle (Java-style).
    ResourceBundle,
    /// ICU `MessageFormat`.
    IcuMessage,
    /// Custom table lookup.
    CustomTable,
}

/// Detects localization patterns in strings.
pub struct LocalizedStrings;

impl LocalizedStrings {
    /// Detect localization patterns in a list of string contents.
    #[must_use] 
    pub fn detect(strings: &[(u64, &str)]) -> Vec<(u64, LocalizationPattern)> {
        let mut results = Vec::new();
        for &(addr, content) in strings {
            if let Some(pattern) = Self::classify(content) {
                results.push((addr, pattern));
            }
        }
        results
    }

    fn classify(content: &str) -> Option<LocalizationPattern> {
        // String ID tables: ALL_CAPS with underscores.
        if content
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
            && content.contains('_')
            && content.len() >= 4
        {
            return Some(LocalizationPattern::StringIdTable);
        }
        // Gettext: contains format markers.
        if content.starts_with("msgid") || content.starts_with("msgstr") {
            return Some(LocalizationPattern::Gettext);
        }
        // ICU MessageFormat: {0}, {1}, etc.
        if content.contains('{') && content.contains('}') {
            // Look for {0} or {name} ICU markers.
            let re_like = content.split('{').skip(1).any(|s| {
                s.split('}').next().is_some_and(|inner| {
                    inner
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == ',')
                })
            });
            if re_like {
                return Some(LocalizationPattern::IcuMessage);
            }
        }
        // Resource bundle: "module.key" dot-notation.
        if content.matches('.').count() >= 2 && !content.contains(' ') && content.len() < 80 {
            return Some(LocalizationPattern::ResourceBundle);
        }
        None
    }
}

// ─── CryptedStringDetector ────────────────────────────────────────────────────

/// Confidence level for encrypted-string detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CryptStringConfidence {
    Low,
    Medium,
    High,
}

/// Evidence of an encrypted string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptedStringEvidence {
    pub addr: u64,
    pub length: usize,
    pub confidence: CryptStringConfidence,
    pub reason: String,
    pub decryption_hint: Option<String>,
}

/// Detects potentially encrypted/obfuscated strings.
pub struct CryptedStringDetector {
    entropy_threshold: f64,
    min_length: usize,
}

impl CryptedStringDetector {
    #[must_use] 
    pub const fn new(entropy_threshold: f64, min_length: usize) -> Self {
        Self {
            entropy_threshold,
            min_length,
        }
    }

    #[must_use] 
    pub const fn with_defaults() -> Self {
        Self::new(5.5, 8)
    }

    /// Scan raw bytes for potentially encrypted strings.
    #[must_use] 
    pub fn scan(&self, data: &[u8], base_addr: u64) -> Vec<CryptedStringEvidence> {
        let mut results = Vec::new();
        if data.len() < self.min_length {
            return results;
        }

        let window = self.min_length.max(16);
        if data.len() < window {
            return results;
        }
        for start in (0..=data.len().saturating_sub(window)).step_by(4) {
            let chunk = &data[start..start + window];
            let entropy = shannon_entropy(chunk);
            if entropy >= self.entropy_threshold {
                // Check: not printable ASCII (that would just be a normal string).
                let p_count = chunk.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
                let p_len = chunk.len().max(1);
                if p_count * 5 < p_len * 4 {
                    let printable_ratio = f64::from(u32::try_from(p_count).unwrap_or(u32::MAX))
                        / f64::from(u32::try_from(p_len).unwrap_or(u32::MAX));
                    let reason = format!(
                        "High entropy ({:.2} bits), low printable ratio ({:.0}%)",
                        entropy,
                        printable_ratio * 100.0
                    );
                    results.push(CryptedStringEvidence {
                        addr: base_addr + start as u64,
                        length: window,
                        confidence: if entropy >= 7.0 {
                            CryptStringConfidence::High
                        } else if entropy >= 6.0 {
                            CryptStringConfidence::Medium
                        } else {
                            CryptStringConfidence::Low
                        },
                        reason,
                        decryption_hint: None,
                    });
                }
            }
        }
        results
    }

    /// Detect XOR-encoded strings by looking for repeating key patterns.
    #[must_use] 
    pub fn detect_xor_strings(&self, data: &[u8], base_addr: u64) -> Vec<CryptedStringEvidence> {
        let mut results = Vec::new();
        if data.len() < self.min_length {
            return results;
        }

        // English letter-frequency weights for score disambiguation between keys
        // that all produce 100% printable output.
        const FREQ: [u32; 26] = [
            8, 1, 3, 4, 13, 2, 2, 6, 7, 1,
            1, 4, 2, 7, 8,  2, 1, 6, 6, 9,
            3, 1, 2, 1, 2,  1,
        ];
        let freq_score = |decoded: &[u8]| -> u64 {
            decoded.iter().map(|&b| {
                if b.is_ascii_alphabetic() {
                    u64::from(FREQ[(b.to_ascii_lowercase() - b'a') as usize])
                } else if b == b' ' {
                    10
                } else {
                    0
                }
            }).sum()
        };

        // Try XOR with single-byte keys; pick the highest-scoring candidate.
        let mut best: Option<(u8, u64)> = None;
        for key in 1u8..=255 {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let d_count = decoded.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
            let d_len = decoded.len().max(1);
            if d_count * 20 > d_len * 17 && decoded.len() >= self.min_length {
                let s = freq_score(&decoded);
                if best.is_none_or(|(_, bs)| s > bs) {
                    best = Some((key, s));
                }
            }
        }
        if let Some((key, _)) = best {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let d_count = decoded.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
            let d_len = decoded.len().max(1);
            let printable_ratio = f64::from(u32::try_from(d_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(d_len).unwrap_or(u32::MAX));
            results.push(CryptedStringEvidence {
                addr: base_addr,
                length: data.len(),
                confidence: CryptStringConfidence::High,
                reason: format!(
                    "XOR key 0x{:02x} decodes to {:.0}% printable ASCII",
                    key,
                    printable_ratio * 100.0
                ),
                decryption_hint: Some(format!("xor_key=0x{key:02x}")),
            });
        }
        results
    }
}

/// Compute Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    crate::classify::shannon_entropy(data)
}

// ─── StringXrefAnalyzer ──────────────────────────────────────────────────────

/// Top-level string cross-reference analyser.
pub struct StringXrefAnalyzer {
    pub call_graph: StringCallGraph,
    pub refs: Vec<StringRef>,
    string_contents: HashMap<u64, String>,
}

impl StringXrefAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            call_graph: StringCallGraph::new(),
            refs: Vec::new(),
            string_contents: HashMap::new(),
        }
    }

    /// Register a string with its content.
    pub fn register_string(&mut self, addr: u64, content: impl Into<String>) {
        self.string_contents.insert(addr, content.into());
    }

    /// Add a string cross-reference.
    pub fn add_ref(&mut self, xref: StringRef) {
        if let Some(fn_addr) = xref.function_addr {
            self.call_graph.add_ref(fn_addr, xref.string_addr);
        }
        self.refs.push(xref);
    }

    /// Get all references to a specific string.
    #[must_use] 
    pub fn refs_to_string(&self, string_addr: u64) -> Vec<&StringRef> {
        self.refs
            .iter()
            .filter(|r| r.string_addr == string_addr)
            .collect()
    }

    /// Get all string references from a function.
    #[must_use] 
    pub fn refs_in_function(&self, fn_addr: u64) -> Vec<&StringRef> {
        self.refs
            .iter()
            .filter(|r| r.function_addr == Some(fn_addr))
            .collect()
    }

    /// Build string clusters.
    #[must_use] 
    pub fn build_clusters(&self, min_co_occurrence: usize) -> Vec<StringCluster> {
        let builder = StringClusterBuilder::new(min_co_occurrence);
        builder.build(&self.call_graph, &self.string_contents)
    }

    /// Detect localization patterns in registered strings.
    #[must_use] 
    pub fn detect_localization(&self) -> Vec<(u64, LocalizationPattern)> {
        // Sort by address so the output order does not depend on HashMap
        // iteration order.
        let mut pairs: Vec<(u64, &str)> = self
            .string_contents
            .iter()
            .map(|(&addr, s)| (addr, s.as_str()))
            .collect();
        pairs.sort_unstable_by_key(|&(addr, _)| addr);
        LocalizedStrings::detect(&pairs)
    }

    /// Get the content of a registered string.
    #[must_use] 
    pub fn string_content(&self, addr: u64) -> Option<&str> {
        self.string_contents.get(&addr).map(std::string::String::as_str)
    }

    /// Total number of unique strings.
    #[must_use] 
    pub fn string_count(&self) -> usize {
        self.string_contents.len()
    }

    /// Total number of cross-references.
    #[must_use]
    pub const fn xref_count(&self) -> usize {
        self.refs.len()
    }

    /// Serialise all cross-references to a JSON string.
    ///
    /// Returns an error if serialisation fails (which should not happen for
    /// well-formed data, but is propagated for robustness).
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.refs)
    }

    /// Serialise all cross-references to a pretty-printed JSON string.
    pub fn to_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.refs)
    }
}

impl Default for StringXrefAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_ref_builder() {
        let r = StringRef::new(0x1000, 0x2000, StringAccessType::DirectLoad)
            .in_function(0x1500)
            .with_content("hello");
        assert_eq!(r.string_addr, 0x1000);
        assert_eq!(r.code_addr, 0x2000);
        assert_eq!(r.function_addr, Some(0x1500));
        assert_eq!(r.content.as_deref(), Some("hello"));
    }

    #[test]
    fn string_call_graph_add_ref() {
        let mut g = StringCallGraph::new();
        g.add_ref(0x100, 0x200);
        g.add_ref(0x100, 0x300);
        assert_eq!(g.strings_in_function(0x100).len(), 2);
        assert_eq!(g.functions_using_string(0x200).len(), 1);
    }

    #[test]
    fn string_call_graph_unique_strings() {
        let mut g = StringCallGraph::new();
        g.add_ref(0xA, 0x1);
        g.add_ref(0xB, 0x1);
        g.add_ref(0xA, 0x2); // 0x2 used in only fn A
        let unique = g.unique_strings();
        assert!(unique.contains(&0x2));
    }

    #[test]
    fn string_call_graph_most_referenced() {
        let mut g = StringCallGraph::new();
        g.add_ref(0xF1, 0x51);
        g.add_ref(0xF2, 0x51);
        g.add_ref(0xF3, 0x51);
        g.add_ref(0xF1, 0x52);
        let top = g.most_referenced(1);
        assert_eq!(top[0].0, 0x51);
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn string_cluster_builder() {
        let mut g = StringCallGraph::new();
        g.add_ref(0xF1, 0x51);
        g.add_ref(0xF1, 0x52);
        g.add_ref(0xF1, 0x53);
        let mut contents = HashMap::new();
        contents.insert(0x51u64, "error: something failed".to_string());
        let builder = StringClusterBuilder::new(2);
        let clusters = builder.build(&g, &contents);
        assert!(!clusters.is_empty());
    }

    #[test]
    fn string_cluster_label_error() {
        let label = StringClusterBuilder::infer_label("Error: file not found");
        assert_eq!(label, Some("error_strings".into()));
    }

    #[test]
    fn string_cluster_label_network() {
        let label = StringClusterBuilder::infer_label("https://example.com/api");
        assert_eq!(label, Some("network_strings".into()));
    }

    #[test]
    fn localized_string_id_table() {
        let patterns = LocalizedStrings::detect(&[(0x1000, "IDS_BUTTON_OK")]);
        assert!(!patterns.is_empty());
        assert_eq!(patterns[0].1, LocalizationPattern::StringIdTable);
    }

    #[test]
    fn localized_icu_message() {
        let patterns =
            LocalizedStrings::detect(&[(0x2000, "Hello {name}, you have {count} messages")]);
        assert!(!patterns.is_empty());
        assert_eq!(patterns[0].1, LocalizationPattern::IcuMessage);
    }

    #[test]
    fn localized_no_pattern() {
        let patterns = LocalizedStrings::detect(&[(0x3000, "just a regular string")]);
        assert!(patterns.is_empty());
    }

    #[test]
    fn crypted_string_detector_high_entropy() {
        let detector = CryptedStringDetector::with_defaults();
        // Random-looking bytes (high entropy).
        let data: Vec<u8> = (0u8..=255).cycle().take(64).collect();
        let results = detector.scan(&data, 0x1000);
        // High entropy, 50% non-printable → may flag some windows.
        // Just ensure no panic.
        let _ = results;
    }

    #[test]
    fn crypted_string_detector_xor() {
        let detector = CryptedStringDetector::with_defaults();
        // XOR "Hello World, this is a test!" with key 0x42.
        let plaintext = b"Hello World, this is a test message!";
        let encrypted: Vec<u8> = plaintext.iter().map(|&b| b ^ 0x42).collect();
        let results = detector.detect_xor_strings(&encrypted, 0x4000);
        assert!(!results.is_empty());
        assert!(
            results[0]
                .decryption_hint
                .as_deref()
                .is_some_and(|h| h.contains("0x42"))
        );
    }

    #[test]
    fn crypted_string_confidence_ordering() {
        assert!(CryptStringConfidence::High > CryptStringConfidence::Medium);
        assert!(CryptStringConfidence::Medium > CryptStringConfidence::Low);
    }

    #[test]
    fn string_xref_analyzer_add_and_query() {
        let mut analyzer = StringXrefAnalyzer::new();
        analyzer.register_string(0x1000, "test string");
        let xref =
            StringRef::new(0x1000, 0x2000, StringAccessType::ArgumentPassed).in_function(0x1500);
        analyzer.add_ref(xref);

        assert_eq!(analyzer.xref_count(), 1);
        assert_eq!(analyzer.string_count(), 1);
        let refs = analyzer.refs_to_string(0x1000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn string_xref_analyzer_refs_in_function() {
        let mut analyzer = StringXrefAnalyzer::new();
        for i in 0..5u64 {
            analyzer.register_string(0x1000 + i, format!("str{i}"));
            let xref = StringRef::new(0x1000 + i, 0x2000 + i, StringAccessType::DirectLoad)
                .in_function(0xF000);
            analyzer.add_ref(xref);
        }
        let refs = analyzer.refs_in_function(0xF000);
        assert_eq!(refs.len(), 5);
    }

    #[test]
    fn string_xref_analyzer_detect_localization() {
        let mut analyzer = StringXrefAnalyzer::new();
        analyzer.register_string(0x1000, "IDS_MAIN_TITLE");
        analyzer.register_string(0x2000, "IDS_ERROR_GENERIC");
        let l = analyzer.detect_localization();
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn string_xref_analyzer_default() {
        let analyzer = StringXrefAnalyzer::default();
        assert_eq!(analyzer.xref_count(), 0);
    }

    #[test]
    fn shannon_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn shannon_entropy_zero() {
        let data = vec![0u8; 256];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn string_call_graph_empty_function() {
        let g = StringCallGraph::new();
        assert!(g.strings_in_function(0x999).is_empty());
    }

    #[test]
    fn xref_error_display() {
        let e = XrefError::StringNotFound(0xDEAD);
        assert!(e.to_string().contains("dead"));
    }

    #[test]
    fn string_cluster_size() {
        let mut c = StringCluster::new(0);
        c.add_member(0x1);
        c.add_member(0x2);
        assert_eq!(c.size(), 2);
    }

    fn mk_str(addr: u64, value: &str) -> StringRecord {
        use crate::StringEncoding;
        use rustre_core::address::Address;
        FoundString {
            address: Address::new(addr),
            length: value.len(),
            encoding: StringEncoding::Ascii,
            value: value.to_string(),
            char_count: value.chars().count(),
            is_null_terminated: true,
            xref_count: 0,
        }
    }

    #[test]
    fn string_xrefs_basic_match() {
        let strings = vec![mk_str(0x4000, "hello"), mk_str(0x4010, "world")];
        let code_refs = vec![(0x1000u64, 0x4000u64), (0x1010u64, 0x4010u64), (0x1020u64, 0x9999u64)];
        let xrefs = string_xrefs(&strings, &code_refs, None);
        assert_eq!(xrefs.len(), 2);
        assert_eq!(xrefs[0].string_addr, 0x4000);
        assert_eq!(xrefs[0].from_addr, 0x1000);
        assert_eq!(xrefs[0].text, "hello");
        assert!(xrefs[0].from_function.is_none());
        assert_eq!(xrefs[1].text, "world");
    }

    #[test]
    fn string_xrefs_with_function_lookup() {
        let strings = vec![mk_str(0x4000, "msg")];
        let code_refs = vec![(0x1000u64, 0x4000u64), (0x1100u64, 0x4000u64)];
        let mut fn_map: HashMap<u64, u64> = HashMap::new();
        fn_map.insert(0x1000, 0xF000);
        fn_map.insert(0x1100, 0xF100);
        let xrefs = string_xrefs(&strings, &code_refs, Some(&fn_map));
        assert_eq!(xrefs.len(), 2);
        assert_eq!(xrefs[0].from_function, Some(0xF000));
        assert_eq!(xrefs[1].from_function, Some(0xF100));
    }

    #[test]
    fn string_xrefs_empty_inputs() {
        let strings: Vec<StringRecord> = Vec::new();
        let code_refs: Vec<(u64, u64)> = Vec::new();
        assert!(string_xrefs(&strings, &code_refs, None).is_empty());

        let strings = vec![mk_str(0x4000, "x")];
        assert!(string_xrefs(&strings, &[], None).is_empty());

        let code_refs = vec![(0x1u64, 0x2u64)];
        assert!(string_xrefs(&[], &code_refs, None).is_empty());
    }

    #[test]
    fn localized_resource_bundle() {
        // "com.example.app.title" — dot-separated key
        let patterns = LocalizedStrings::detect(&[(0x4000, "com.example.app.main.title")]);
        assert!(!patterns.is_empty());
        assert_eq!(patterns[0].1, LocalizationPattern::ResourceBundle);
    }
}
