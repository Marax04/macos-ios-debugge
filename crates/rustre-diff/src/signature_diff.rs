//! Signature-based binary diff.
//!
//! Compares function signatures (name/prototype/size/hash) between two
//! binaries to identify identical, renamed, modified, added, and deleted
//! functions.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignatureDiffError {
    #[error("no functions in binary A")]
    EmptyA,
    #[error("no functions in binary B")]
    EmptyB,
    #[error("hash algorithm not supported: {0}")]
    UnsupportedHash(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionSignature
// ─────────────────────────────────────────────────────────────────────────────

/// Signature of a single function used for diff matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Virtual address of the function.
    pub address: u64,
    /// Symbolic name.
    pub name: String,
    /// Function prototype (may be empty if unknown).
    pub prototype: String,
    /// Size in bytes.
    pub size: usize,
    /// Hash of function bytes (hex string).
    pub hash: String,
    /// Number of basic blocks.
    pub block_count: usize,
    /// Number of call instructions.
    pub call_count: usize,
    /// Estimated cyclomatic complexity.
    pub complexity: u32,
    /// Whether the function is a library stub.
    pub is_library: bool,
    /// Tags/labels (e.g. "crypto", "network").
    pub tags: Vec<String>,
}

impl FunctionSignature {
    /// Create a minimal signature.
    #[must_use]
    pub fn new(
        address: u64,
        name: impl Into<String>,
        size: usize,
        hash: impl Into<String>,
    ) -> Self {
        Self {
            address,
            name: name.into(),
            prototype: String::new(),
            size,
            hash: hash.into(),
            block_count: 0,
            call_count: 0,
            complexity: 1,
            is_library: false,
            tags: Vec::new(),
        }
    }

    /// Compute a simple rolling hash over `bytes` (FNV-1a).
    #[must_use]
    pub fn hash_bytes(bytes: &[u8]) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{h:016x}")
    }

    /// Return `true` if this signature is identical to another (same hash + size).
    #[must_use]
    pub fn is_byte_identical(&self, other: &Self) -> bool {
        self.hash == other.hash && self.size == other.size
    }

    /// Structural similarity [0.0, 1.0] based on `block_count` / `call_count` / complexity.
    #[must_use]
    pub fn structural_similarity(&self, other: &Self) -> f64 {
        let block_sim = norm_sim(
            f64::from(u32::try_from(self.block_count).unwrap_or(u32::MAX)),
            f64::from(u32::try_from(other.block_count).unwrap_or(u32::MAX)),
        );
        let call_sim = norm_sim(
            f64::from(u32::try_from(self.call_count).unwrap_or(u32::MAX)),
            f64::from(u32::try_from(other.call_count).unwrap_or(u32::MAX)),
        );
        let cx_sim = norm_sim(f64::from(self.complexity), f64::from(other.complexity));
        let sz_sim = norm_sim(
            f64::from(u32::try_from(self.size).unwrap_or(u32::MAX)),
            f64::from(u32::try_from(other.size).unwrap_or(u32::MAX)),
        );
        (block_sim + call_sim + cx_sim + sz_sim) / 4.0
    }
}

fn norm_sim(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        return 1.0;
    }
    let max = a.max(b);
    if max == 0.0 {
        return 1.0;
    }
    1.0 - (a - b).abs() / max
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureMatchKind
// ─────────────────────────────────────────────────────────────────────────────

/// How a function from A relates to a function in B.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureMatchKind {
    /// Byte-for-byte identical (same hash and size).
    Identical,
    /// Same name but different bytes (function body changed).
    Modified,
    /// Different name but same or very similar bytes (rename / refactor).
    Renamed,
    /// Similar structure (same block count / call count) but different bytes.
    StructurallyMatched,
    /// Function exists in B but not in A.
    Added,
    /// Function exists in A but not in B.
    Deleted,
}

impl std::fmt::Display for SignatureMatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Identical => "IDENTICAL",
            Self::Modified => "MODIFIED",
            Self::Renamed => "RENAMED",
            Self::StructurallyMatched => "STRUCTURAL",
            Self::Added => "ADDED",
            Self::Deleted => "DELETED",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A single match between a function in A and a function in B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub kind: SignatureMatchKind,
    /// Function in A (None for Added functions).
    pub func_a: Option<FunctionSignature>,
    /// Function in B (None for Deleted functions).
    pub func_b: Option<FunctionSignature>,
    /// Similarity score [0.0, 1.0].
    pub similarity: f64,
    /// Notes about the match.
    pub notes: Vec<String>,
}

impl SignatureMatch {
    const fn identical(a: FunctionSignature, b: FunctionSignature) -> Self {
        Self {
            kind: SignatureMatchKind::Identical,
            func_a: Some(a),
            func_b: Some(b),
            similarity: 1.0,
            notes: Vec::new(),
        }
    }
    const fn modified(a: FunctionSignature, b: FunctionSignature, sim: f64) -> Self {
        Self {
            kind: SignatureMatchKind::Modified,
            func_a: Some(a),
            func_b: Some(b),
            similarity: sim,
            notes: Vec::new(),
        }
    }
    const fn renamed(a: FunctionSignature, b: FunctionSignature, sim: f64) -> Self {
        Self {
            kind: SignatureMatchKind::Renamed,
            func_a: Some(a),
            func_b: Some(b),
            similarity: sim,
            notes: Vec::new(),
        }
    }
    const fn structural(a: FunctionSignature, b: FunctionSignature, sim: f64) -> Self {
        Self {
            kind: SignatureMatchKind::StructurallyMatched,
            func_a: Some(a),
            func_b: Some(b),
            similarity: sim,
            notes: Vec::new(),
        }
    }
    const fn added(b: FunctionSignature) -> Self {
        Self {
            kind: SignatureMatchKind::Added,
            func_a: None,
            func_b: Some(b),
            similarity: 0.0,
            notes: Vec::new(),
        }
    }
    const fn deleted(a: FunctionSignature) -> Self {
        Self {
            kind: SignatureMatchKind::Deleted,
            func_a: Some(a),
            func_b: None,
            similarity: 0.0,
            notes: Vec::new(),
        }
    }
}

impl std::fmt::Display for SignatureMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name_a = self.func_a.as_ref().map_or("-", |s| s.name.as_str());
        let name_b = self.func_b.as_ref().map_or("-", |s| s.name.as_str());
        write!(
            f,
            "{:11} {:30} → {:30} ({:.0}%)",
            self.kind,
            name_a,
            name_b,
            self.similarity * 100.0
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in an export table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub ordinal: Option<u32>,
    pub address: u64,
    pub is_forwarder: bool,
    pub forwarder_target: Option<String>,
}

impl ExportEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, ordinal: Option<u32>, address: u64) -> Self {
        Self {
            name: name.into(),
            ordinal,
            address,
            is_forwarder: false,
            forwarder_target: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportTableDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Diff between two export tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTableDiff {
    pub added: Vec<ExportEntry>,
    pub deleted: Vec<ExportEntry>,
    pub renamed: Vec<(ExportEntry, ExportEntry)>,
    pub unchanged: Vec<ExportEntry>,
}

impl ExportTableDiff {
    /// Compute the diff between two export entry lists.
    #[must_use]
    pub fn compute(a: &[ExportEntry], b: &[ExportEntry]) -> Self {
        // Export names originate from the binary (attacker-controlled); use
        // AHashMap to prevent hash-collision DoS.
        let map_a: AHashMap<String, &ExportEntry> = a.iter().map(|e| (e.name.clone(), e)).collect();
        let map_b: AHashMap<String, &ExportEntry> = b.iter().map(|e| (e.name.clone(), e)).collect();

        let mut added = Vec::new();
        let mut deleted = Vec::new();
        let mut unchanged = Vec::new();

        for e in a {
            if map_b.contains_key(&e.name) {
                unchanged.push(e.clone());
            } else {
                deleted.push(e.clone());
            }
        }
        for e in b {
            if !map_a.contains_key(&e.name) {
                added.push(e.clone());
            }
        }

        // Simple ordinal-based rename detection.
        let renamed = Vec::new(); // stub

        Self {
            added,
            deleted,
            renamed,
            unchanged,
        }
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Exports: +{} added, -{} deleted, {} renamed, {} unchanged",
            self.added.len(),
            self.deleted.len(),
            self.renamed.len(),
            self.unchanged.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureDiffReport
// ─────────────────────────────────────────────────────────────────────────────

/// Full diff report between two binary's function signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDiffReport {
    pub matches: Vec<SignatureMatch>,
    pub stats: SignatureDiffStats,
    pub export_diff: Option<ExportTableDiff>,
}

impl SignatureDiffReport {
    /// Filter matches by kind.
    #[must_use]
    pub fn filter_kind(&self, kind: SignatureMatchKind) -> Vec<&SignatureMatch> {
        self.matches.iter().filter(|m| m.kind == kind).collect()
    }

    /// Render the report to a plain-text table.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "Signature Diff Report\n{}\n{}\n",
            "=".repeat(80),
            self.stats,
        );
        out.push_str(&"-".repeat(80));
        out.push('\n');
        for m in &self.matches {
            use std::fmt::Write as _;
            writeln!(out, "{m}").unwrap_or_default();
        }
        if let Some(ed) = &self.export_diff {
            use std::fmt::Write as _;
            write!(out, "\n{}\n", ed.summary()).unwrap_or_default();
        }
        out
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a string error message on failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureDiffStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a signature diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDiffStats {
    pub total_a: usize,
    pub total_b: usize,
    pub identical: usize,
    pub modified: usize,
    pub renamed: usize,
    pub structural: usize,
    pub added: usize,
    pub deleted: usize,
    pub similarity_pct: f64,
}

impl std::fmt::Display for SignatureDiffStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "A:{} B:{} | identical:{} modified:{} renamed:{} structural:{} added:{} deleted:{} | sim:{:.1}%",
            self.total_a,
            self.total_b,
            self.identical,
            self.modified,
            self.renamed,
            self.structural,
            self.added,
            self.deleted,
            self.similarity_pct,
        )
    }
}

impl SignatureDiffStats {
    fn from_matches(matches: &[SignatureMatch], total_a: usize, total_b: usize) -> Self {
        let identical = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::Identical)
            .count();
        let modified = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::Modified)
            .count();
        let renamed = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::Renamed)
            .count();
        let structural = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::StructurallyMatched)
            .count();
        let added = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::Added)
            .count();
        let deleted = matches
            .iter()
            .filter(|m| m.kind == SignatureMatchKind::Deleted)
            .count();
        let denom = f64::from(u32::try_from(total_a.max(total_b).max(1)).unwrap_or(u32::MAX));
        let similarity_pct = (f64::from(u32::try_from(identical + renamed).unwrap_or(u32::MAX)) / denom) * 100.0;
        Self {
            total_a,
            total_b,
            identical,
            modified,
            renamed,
            structural,
            added,
            deleted,
            similarity_pct,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureDiff — the main engine
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the signature diff engine.
#[derive(Debug, Clone)]
pub struct SignatureDiffConfig {
    /// Minimum structural similarity to consider a match.
    pub min_structural_similarity: f64,
    /// Whether to attempt name-based matching before structural.
    pub name_match_first: bool,
    /// Skip library stubs.
    pub skip_library: bool,
    /// Maximum number of functions to compare (safety limit).
    pub max_functions: usize,
}

impl Default for SignatureDiffConfig {
    fn default() -> Self {
        Self {
            min_structural_similarity: 0.7,
            name_match_first: true,
            skip_library: false,
            max_functions: 100_000,
        }
    }
}

/// Signature-based binary differ.
pub struct SignatureDiff {
    config: SignatureDiffConfig,
}

impl SignatureDiff {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SignatureDiffConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: SignatureDiffConfig) -> Self {
        Self { config }
    }

    /// Compare two sets of function signatures and produce a diff report.
    ///
    /// # Errors
    /// Returns [`SignatureDiffError`] if either set is empty.
    pub fn compare(
        &self,
        funcs_a: &[FunctionSignature],
        funcs_b: &[FunctionSignature],
    ) -> Result<SignatureDiffReport, SignatureDiffError> {
        if funcs_a.is_empty() {
            return Err(SignatureDiffError::EmptyA);
        }
        if funcs_b.is_empty() {
            return Err(SignatureDiffError::EmptyB);
        }

        let a = if self.config.skip_library {
            funcs_a
                .iter()
                .filter(|f| !f.is_library)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            funcs_a.to_vec()
        };
        let b = if self.config.skip_library {
            funcs_b
                .iter()
                .filter(|f| !f.is_library)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            funcs_b.to_vec()
        };

        let mut matches = Vec::new();
        let mut matched_b: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // Pass 1: exact hash match.
        // Both hash strings and function names come from the binary being
        // analysed (untrusted); use AHashMap to prevent hash-collision DoS.
        let hash_map_b: AHashMap<String, usize> = b
            .iter()
            .enumerate()
            .map(|(i, f)| (f.hash.clone(), i))
            .collect();
        let name_map_b: AHashMap<String, usize> = b
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i))
            .collect();

        for fa in &a {
            if let Some(&bi) = hash_map_b.get(&fa.hash) {
                let fb = &b[bi];
                if fa.name == fb.name {
                    matches.push(SignatureMatch::identical(fa.clone(), fb.clone()));
                } else {
                    matches.push(SignatureMatch::renamed(fa.clone(), fb.clone(), 1.0));
                }
                matched_b.insert(bi);
                continue;
            }

            // Pass 2: name match → modified.
            if self.config.name_match_first
                && let Some(&bi) = name_map_b.get(&fa.name)
                    && !matched_b.contains(&bi) {
                        let fb = &b[bi];
                        let sim = fa.structural_similarity(fb);
                        matches.push(SignatureMatch::modified(fa.clone(), fb.clone(), sim));
                        matched_b.insert(bi);
                        continue;
                    }

            // Pass 3: structural match.
            let mut best: Option<(usize, f64)> = None;
            for (bi, fb) in b.iter().enumerate() {
                if matched_b.contains(&bi) {
                    continue;
                }
                let sim = fa.structural_similarity(fb);
                if sim >= self.config.min_structural_similarity
                    && best.is_none_or(|(_, bs)| sim > bs) {
                        best = Some((bi, sim));
                    }
            }
            if let Some((bi, sim)) = best {
                matches.push(SignatureMatch::structural(fa.clone(), b[bi].clone(), sim));
                matched_b.insert(bi);
            } else {
                // Deleted from B.
                matches.push(SignatureMatch::deleted(fa.clone()));
            }
        }

        // Pass 4: unmatched B functions → added.
        for (bi, fb) in b.iter().enumerate() {
            if !matched_b.contains(&bi) {
                matches.push(SignatureMatch::added(fb.clone()));
            }
        }

        let stats = SignatureDiffStats::from_matches(&matches, a.len(), b.len());
        Ok(SignatureDiffReport {
            matches,
            stats,
            export_diff: None,
        })
    }

    /// Compare export tables and attach to an existing report.
    pub fn attach_export_diff(
        &self,
        report: &mut SignatureDiffReport,
        exports_a: &[ExportEntry],
        exports_b: &[ExportEntry],
    ) {
        report.export_diff = Some(ExportTableDiff::compute(exports_a, exports_b));
    }
}

impl Default for SignatureDiff {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str, addr: u64, size: usize, hash: &str) -> FunctionSignature {
        FunctionSignature::new(addr, name, size, hash)
    }

    fn sig_with_blocks(
        name: &str,
        addr: u64,
        size: usize,
        hash: &str,
        blocks: usize,
        calls: usize,
    ) -> FunctionSignature {
        let mut s = sig(name, addr, size, hash);
        s.block_count = blocks;
        s.call_count = calls;
        s
    }

    // -- FunctionSignature ---------------------------------------------------

    #[test]
    fn test_hash_bytes() {
        let h1 = FunctionSignature::hash_bytes(&[0xAA, 0xBB]);
        let h2 = FunctionSignature::hash_bytes(&[0xAA, 0xBB]);
        assert_eq!(h1, h2);
        let h3 = FunctionSignature::hash_bytes(&[0xCC]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_is_byte_identical() {
        let a = sig("foo", 0x1000, 100, "aabbcc");
        let b = sig("foo", 0x2000, 100, "aabbcc");
        assert!(a.is_byte_identical(&b));
    }

    #[test]
    fn test_is_byte_identical_false_different_hash() {
        let a = sig("foo", 0x1000, 100, "aabb");
        let b = sig("foo", 0x2000, 100, "ccdd");
        assert!(!a.is_byte_identical(&b));
    }

    #[test]
    fn test_structural_similarity_identical() {
        let a = sig_with_blocks("foo", 0x1000, 100, "x", 5, 3);
        let b = sig_with_blocks("bar", 0x2000, 100, "y", 5, 3);
        assert!((a.structural_similarity(&b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_structural_similarity_different() {
        let a = sig_with_blocks("foo", 0x1000, 100, "x", 5, 3);
        let b = sig_with_blocks("bar", 0x2000, 10, "y", 1, 0);
        assert!(a.structural_similarity(&b) < 1.0);
    }

    // -- SignatureDiff -------------------------------------------------------

    #[test]
    fn test_identical_match() {
        let diff = SignatureDiff::new();
        let a = vec![sig("main", 0x1000, 100, "aabb")];
        let b = vec![sig("main", 0x2000, 100, "aabb")];
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.filter_kind(SignatureMatchKind::Identical).len(), 1);
    }

    #[test]
    fn test_renamed_match() {
        let diff = SignatureDiff::new();
        let a = vec![sig("old_name", 0x1000, 100, "aabb")];
        let b = vec![sig("new_name", 0x2000, 100, "aabb")];
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.filter_kind(SignatureMatchKind::Renamed).len(), 1);
    }

    #[test]
    fn test_modified_match() {
        let diff = SignatureDiff::new();
        let a = vec![sig("foo", 0x1000, 100, "aabb")];
        let b = vec![sig("foo", 0x2000, 100, "ccdd")];
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.filter_kind(SignatureMatchKind::Modified).len(), 1);
    }

    #[test]
    fn test_deleted_function() {
        let diff = SignatureDiff::new();
        let a = vec![
            sig("foo", 0x1000, 100, "aabb"),
            sig("bar", 0x2000, 50, "ccdd"),
        ];
        let b = vec![sig("foo", 0x1000, 100, "aabb")];
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.filter_kind(SignatureMatchKind::Deleted).len(), 1);
    }

    #[test]
    fn test_added_function() {
        let diff = SignatureDiff::new();
        let a = vec![sig("foo", 0x1000, 100, "aabb")];
        let b = vec![
            sig("foo", 0x1000, 100, "aabb"),
            sig("new_func", 0x2000, 50, "eeff"),
        ];
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.filter_kind(SignatureMatchKind::Added).len(), 1);
    }

    #[test]
    fn test_empty_a_error() {
        let diff = SignatureDiff::new();
        assert!(matches!(
            diff.compare(&[], &[sig("x", 0, 0, "")]),
            Err(SignatureDiffError::EmptyA)
        ));
    }

    #[test]
    fn test_empty_b_error() {
        let diff = SignatureDiff::new();
        assert!(matches!(
            diff.compare(&[sig("x", 0, 0, "")], &[]),
            Err(SignatureDiffError::EmptyB)
        ));
    }

    #[test]
    fn test_stats_total() {
        let diff = SignatureDiff::new();
        let a: Vec<_> = (0..5)
            .map(|i| sig(&format!("f{i}"), i * 0x100, 50, &format!("{i:04x}")))
            .collect();
        let b = a.clone();
        let report = diff.compare(&a, &b).unwrap();
        assert_eq!(report.stats.identical, 5);
    }

    #[test]
    fn test_report_to_text() {
        let diff = SignatureDiff::new();
        let a = vec![sig("main", 0x1000, 100, "aabb")];
        let b = vec![sig("main", 0x2000, 100, "aabb")];
        let report = diff.compare(&a, &b).unwrap();
        let text = report.to_text();
        assert!(text.contains("Signature Diff Report"));
    }

    #[test]
    fn test_report_to_json() {
        let diff = SignatureDiff::new();
        let a = vec![sig("main", 0x1000, 100, "aabb")];
        let b = vec![sig("main", 0x2000, 100, "aabb")];
        let report = diff.compare(&a, &b).unwrap();
        let json = report.to_json().unwrap();
        assert!(json.contains("matches"));
    }

    // -- ExportTableDiff ----------------------------------------------------

    #[test]
    fn test_export_diff_added() {
        let a = vec![ExportEntry::new("func_a", Some(1), 0x1000)];
        let b = vec![
            ExportEntry::new("func_a", Some(1), 0x1000),
            ExportEntry::new("func_b", Some(2), 0x2000),
        ];
        let ed = ExportTableDiff::compute(&a, &b);
        assert_eq!(ed.added.len(), 1);
        assert_eq!(ed.deleted.len(), 0);
    }

    #[test]
    fn test_export_diff_deleted() {
        let a = vec![
            ExportEntry::new("func_a", Some(1), 0x1000),
            ExportEntry::new("func_b", Some(2), 0x2000),
        ];
        let b = vec![ExportEntry::new("func_a", Some(1), 0x1000)];
        let ed = ExportTableDiff::compute(&a, &b);
        assert_eq!(ed.deleted.len(), 1);
        assert_eq!(ed.added.len(), 0);
    }

    #[test]
    fn test_export_diff_unchanged() {
        let exports = vec![ExportEntry::new("x", None, 0)];
        let ed = ExportTableDiff::compute(&exports, &exports);
        assert_eq!(ed.unchanged.len(), 1);
    }

    #[test]
    fn test_export_diff_summary() {
        let a = vec![ExportEntry::new("a", None, 0)];
        let b = vec![ExportEntry::new("b", None, 1)];
        let ed = ExportTableDiff::compute(&a, &b);
        let s = ed.summary();
        assert!(s.contains("added"));
    }

    // -- SignatureMatchKind display ------------------------------------------

    #[test]
    fn test_match_kind_display() {
        assert_eq!(SignatureMatchKind::Identical.to_string(), "IDENTICAL");
        assert_eq!(SignatureMatchKind::Deleted.to_string(), "DELETED");
    }

    #[test]
    fn test_match_display() {
        let m = SignatureMatch::added(sig("new_func", 0, 0, ""));
        let s = format!("{m}");
        assert!(s.contains("ADDED"));
    }

    #[test]
    fn test_stats_similarity_all_identical() {
        let diff = SignatureDiff::new();
        let funcs: Vec<_> = (0..10)
            .map(|i| sig(&format!("f{i}"), i * 0x100, 100, &format!("{i:04x}")))
            .collect();
        let report = diff.compare(&funcs, &funcs).unwrap();
        assert!(report.stats.similarity_pct > 90.0);
    }
}
