//! Patch analysis: binary-level change detection and severity assessment.
//!
//! [`PatchAnalyzer`] compares two binary snapshots and produces a
//! [`PatchReport`] with per-function change records, severity scores,
//! and CVE-style security markers.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Re-exported map type used by patch analysis lookups.
pub type PatchMap<K, V> = HashMap<K, V>;

// ─────────────────────────────────────────────────────────────────────────────
// BinarySnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of a binary: function addresses + names + byte lengths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySnapshot {
    pub path: String,
    pub version: String,
    pub functions: Vec<FunctionRecord>,
    pub build_id: Option<String>,
    pub architecture: String,
    pub total_code_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub address: u64,
    pub name: String,
    pub size_bytes: u32,
    pub signature_hash: u64,
    pub body_hash: u64,
    pub is_exported: bool,
    pub is_plt: bool,
}

impl FunctionRecord {
    #[must_use] 
    pub const fn is_thunk(&self) -> bool {
        self.size_bytes < 16
    }
}

impl BinarySnapshot {
    pub fn new(path: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            version: version.into(),
            functions: Vec::new(),
            build_id: None,
            architecture: "x86_64".into(),
            total_code_bytes: 0,
        }
    }

    pub fn add_function(&mut self, rec: FunctionRecord) {
        self.total_code_bytes += u64::from(rec.size_bytes);
        self.functions.push(rec);
    }

    #[must_use] 
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }
    #[must_use] 
    pub fn exported_functions(&self) -> Vec<&FunctionRecord> {
        self.functions.iter().filter(|f| f.is_exported).collect()
    }
    #[must_use] 
    pub fn by_name(&self, name: &str) -> Option<&FunctionRecord> {
        self.functions.iter().find(|f| f.name == name)
    }
    #[must_use] 
    pub fn names(&self) -> HashSet<&str> {
        self.functions.iter().map(|f| f.name.as_str()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChangeKind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    /// Function added in new binary.
    Added,
    /// Function removed in new binary.
    Removed,
    /// Function body changed (hash mismatch).
    Modified,
    /// Function signature changed (name/export status).
    SignatureChanged,
    /// No change.
    Unchanged,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Added => "+",
            Self::Removed => "-",
            Self::Modified => "~",
            Self::SignatureChanged => "S",
            Self::Unchanged => "=",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChangeSeverity
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChangeSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ChangeSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionChangeRecord
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionChangeRecord {
    pub name: String,
    pub old_address: Option<u64>,
    pub new_address: Option<u64>,
    pub old_size: Option<u32>,
    pub new_size: Option<u32>,
    pub kind: ChangeKind,
    pub severity: ChangeSeverity,
    pub size_delta: i64,
    pub is_security_relevant: bool,
    pub notes: Vec<String>,
}

impl FunctionChangeRecord {
    #[must_use] 
    pub const fn size_increased(&self) -> bool {
        self.size_delta > 0
    }
    #[must_use] 
    pub const fn size_decreased(&self) -> bool {
        self.size_delta < 0
    }
    #[must_use] 
    pub const fn was_exported(&self) -> bool {
        self.old_address.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecurityHeuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Security-relevant function name patterns.
pub struct SecurityHeuristics {
    pub sensitive_prefixes: Vec<String>,
    pub sensitive_suffixes: Vec<String>,
    pub exact_names: HashSet<String>,
}

impl Default for SecurityHeuristics {
    fn default() -> Self {
        let prefixes = vec![
            "auth_".into(),
            "check_".into(),
            "verify_".into(),
            "validate_".into(),
            "crypto_".into(),
            "ssl_".into(),
            "tls_".into(),
            "aes_".into(),
            "hash_".into(),
            "sign_".into(),
            "encrypt_".into(),
            "decrypt_".into(),
        ];
        let suffixes = vec![
            "_check".into(),
            "_validate".into(),
            "_verify".into(),
            "_auth".into(),
            "_sign".into(),
            "_hash".into(),
        ];
        let mut exact = HashSet::new();
        for name in &[
            "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "gets", "scanf",
            "malloc", "realloc", "free",
        ] {
            exact.insert(name.to_string());
        }
        Self {
            sensitive_prefixes: prefixes,
            sensitive_suffixes: suffixes,
            exact_names: exact,
        }
    }
}

impl SecurityHeuristics {
    #[must_use] 
    pub fn is_security_relevant(&self, name: &str) -> bool {
        let lo = name.to_lowercase();
        if self.exact_names.contains(&lo) {
            return true;
        }
        for p in &self.sensitive_prefixes {
            if lo.starts_with(p.as_str()) {
                return true;
            }
        }
        for s in &self.sensitive_suffixes {
            if lo.ends_with(s.as_str()) {
                return true;
            }
        }
        false
    }

    #[must_use] 
    pub fn score_severity(&self, rec: &FunctionChangeRecord) -> ChangeSeverity {
        if rec.is_security_relevant {
            return if rec.kind == ChangeKind::Removed {
                ChangeSeverity::Critical
            } else {
                ChangeSeverity::High
            };
        }
        match rec.kind {
            ChangeKind::Removed => ChangeSeverity::High,
            ChangeKind::Added | ChangeKind::Unchanged => ChangeSeverity::Info,
            ChangeKind::Modified => {
                if rec.size_delta.unsigned_abs() > 512 {
                    ChangeSeverity::Medium
                } else {
                    ChangeSeverity::Low
                }
            }
            ChangeKind::SignatureChanged => ChangeSeverity::Medium,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchReport
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchReport {
    pub old_version: String,
    pub new_version: String,
    pub changes: Vec<FunctionChangeRecord>,
    pub analysis_duration_ms: u64,
}

impl PatchReport {
    #[must_use] 
    pub fn added_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Added)
            .count()
    }
    #[must_use] 
    pub fn removed_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Removed)
            .count()
    }
    #[must_use] 
    pub fn modified_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Modified)
            .count()
    }
    #[must_use] 
    pub fn security_relevant_count(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| c.is_security_relevant)
            .count()
    }
    #[must_use] 
    pub fn max_severity(&self) -> ChangeSeverity {
        self.changes
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(ChangeSeverity::Info)
    }
    #[must_use] 
    pub fn by_severity(&self, sev: ChangeSeverity) -> Vec<&FunctionChangeRecord> {
        self.changes.iter().filter(|c| c.severity == sev).collect()
    }
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "+{}/-{}/~{} functions, {} security-relevant, max severity: {}",
            self.added_count(),
            self.removed_count(),
            self.modified_count(),
            self.security_relevant_count(),
            self.max_severity()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct PatchAnalyzer {
    pub heuristics: SecurityHeuristics,
}


impl PatchAnalyzer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn analyze(&self, old: &BinarySnapshot, new: &BinarySnapshot) -> PatchReport {
        let old_names = old.names();
        let new_names = new.names();
        let mut changes = Vec::new();

        // Added
        for name in new_names.difference(&old_names) {
            let Some(nf) = new.by_name(name) else { continue };
            let sec = self.heuristics.is_security_relevant(name);
            let mut rec = FunctionChangeRecord {
                name: name.to_string(),
                old_address: None,
                new_address: Some(nf.address),
                old_size: None,
                new_size: Some(nf.size_bytes),
                kind: ChangeKind::Added,
                severity: ChangeSeverity::Info,
                size_delta: i64::from(nf.size_bytes),
                is_security_relevant: sec,
                notes: Vec::new(),
            };
            rec.severity = self.heuristics.score_severity(&rec);
            changes.push(rec);
        }

        // Removed
        for name in old_names.difference(&new_names) {
            let Some(of) = old.by_name(name) else { continue };
            let sec = self.heuristics.is_security_relevant(name);
            let mut rec = FunctionChangeRecord {
                name: name.to_string(),
                old_address: Some(of.address),
                new_address: None,
                old_size: Some(of.size_bytes),
                new_size: None,
                kind: ChangeKind::Removed,
                severity: ChangeSeverity::Info,
                size_delta: -i64::from(of.size_bytes),
                is_security_relevant: sec,
                notes: Vec::new(),
            };
            rec.severity = self.heuristics.score_severity(&rec);
            changes.push(rec);
        }

        // Modified or unchanged
        for name in old_names.intersection(&new_names) {
            let (Some(of), Some(nf)) = (old.by_name(name), new.by_name(name)) else { continue };
            let sec = self.heuristics.is_security_relevant(name);
            let kind = if of.body_hash != nf.body_hash {
                ChangeKind::Modified
            } else if of.signature_hash != nf.signature_hash {
                ChangeKind::SignatureChanged
            } else {
                ChangeKind::Unchanged
            };
            let size_delta = i64::from(nf.size_bytes) - i64::from(of.size_bytes);
            let mut rec = FunctionChangeRecord {
                name: name.to_string(),
                old_address: Some(of.address),
                new_address: Some(nf.address),
                old_size: Some(of.size_bytes),
                new_size: Some(nf.size_bytes),
                kind,
                severity: ChangeSeverity::Info,
                size_delta,
                is_security_relevant: sec,
                notes: Vec::new(),
            };
            if kind != ChangeKind::Unchanged {
                rec.severity = self.heuristics.score_severity(&rec);
                changes.push(rec);
            }
        }

        PatchReport {
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            changes,
            analysis_duration_ms: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str, addr: u64, body_hash: u64) -> FunctionRecord {
        FunctionRecord {
            address: addr,
            name: name.to_string(),
            size_bytes: 64,
            signature_hash: 0,
            body_hash,
            is_exported: true,
            is_plt: false,
        }
    }

    fn snap(ver: &str, funcs: Vec<FunctionRecord>) -> BinarySnapshot {
        let mut s = BinarySnapshot::new("test.bin", ver);
        for f in funcs {
            s.add_function(f);
        }
        s
    }

    // --- BinarySnapshot ---

    #[test]
    fn snapshot_function_count() {
        let s = snap("1.0", vec![make_func("foo", 0x1000, 1)]);
        assert_eq!(s.function_count(), 1);
    }

    #[test]
    fn snapshot_by_name() {
        let s = snap("1.0", vec![make_func("bar", 0x2000, 2)]);
        assert!(s.by_name("bar").is_some());
        assert!(s.by_name("baz").is_none());
    }

    #[test]
    fn snapshot_total_code_bytes() {
        let s = snap("1.0", vec![make_func("a", 0, 0), make_func("b", 64, 1)]);
        assert_eq!(s.total_code_bytes, 128);
    }

    #[test]
    fn function_record_is_thunk() {
        let mut f = make_func("f", 0, 0);
        f.size_bytes = 8;
        assert!(f.is_thunk());
    }

    // --- ChangeKind ---

    #[test]
    fn change_kind_display() {
        assert_eq!(format!("{}", ChangeKind::Added), "+");
        assert_eq!(format!("{}", ChangeKind::Removed), "-");
    }

    // --- ChangeSeverity ---

    #[test]
    fn change_severity_ord() {
        assert!(ChangeSeverity::Critical > ChangeSeverity::High);
    }

    #[test]
    fn change_severity_display() {
        assert_eq!(format!("{}", ChangeSeverity::Medium), "MEDIUM");
    }

    // --- SecurityHeuristics ---

    #[test]
    fn security_heuristics_memcpy() {
        let h = SecurityHeuristics::default();
        assert!(h.is_security_relevant("memcpy"));
    }

    #[test]
    fn security_heuristics_auth_prefix() {
        let h = SecurityHeuristics::default();
        assert!(h.is_security_relevant("auth_user"));
    }

    #[test]
    fn security_heuristics_not_relevant() {
        let h = SecurityHeuristics::default();
        assert!(!h.is_security_relevant("compute_checksum_foo"));
    }

    #[test]
    fn security_heuristics_severity_critical_removed() {
        let h = SecurityHeuristics::default();
        let rec = FunctionChangeRecord {
            name: "memcpy".into(),
            old_address: Some(0),
            new_address: None,
            old_size: Some(64),
            new_size: None,
            kind: ChangeKind::Removed,
            severity: ChangeSeverity::Info,
            size_delta: -64,
            is_security_relevant: true,
            notes: vec![],
        };
        assert_eq!(h.score_severity(&rec), ChangeSeverity::Critical);
    }

    // --- PatchAnalyzer ---

    #[test]
    fn patch_analyzer_added_function() {
        let old = snap("1.0", vec![]);
        let new = snap("1.1", vec![make_func("new_func", 0x1000, 1)]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert_eq!(report.added_count(), 1);
    }

    #[test]
    fn patch_analyzer_removed_function() {
        let old = snap("1.0", vec![make_func("old_func", 0x1000, 1)]);
        let new = snap("1.1", vec![]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert_eq!(report.removed_count(), 1);
    }

    #[test]
    fn patch_analyzer_modified_function() {
        let old = snap("1.0", vec![make_func("changed", 0x1000, 1)]);
        let new = snap("1.1", vec![make_func("changed", 0x1000, 2)]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert_eq!(report.modified_count(), 1);
    }

    #[test]
    fn patch_analyzer_unchanged_not_reported() {
        let f = make_func("stable", 0x1000, 42);
        let old = snap("1.0", vec![f.clone()]);
        let new = snap("1.1", vec![f]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert_eq!(report.changes.len(), 0);
    }

    #[test]
    fn patch_analyzer_security_relevant_memcpy() {
        let old = snap("1.0", vec![make_func("memcpy", 0, 0)]);
        let new = snap("1.1", vec![make_func("memcpy", 0, 1)]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert_eq!(report.security_relevant_count(), 1);
    }

    // --- PatchReport ---

    #[test]
    fn patch_report_max_severity() {
        let old = snap("1.0", vec![make_func("memcpy", 0, 0)]);
        let new = snap("1.1", vec![]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        assert!(report.max_severity() >= ChangeSeverity::High);
    }

    #[test]
    fn patch_report_summary_contains_counts() {
        let old = snap("1.0", vec![make_func("a", 0, 0)]);
        let new = snap("1.1", vec![make_func("a", 0, 1)]);
        let report = PatchAnalyzer::new().analyze(&old, &new);
        let s = report.summary();
        assert!(s.contains('~'));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChangeClassification — semantic change type labelling
// ─────────────────────────────────────────────────────────────────────────────

/// Semantic classification of a function-level change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeClassification {
    /// A defect fix — defensive check added, size narrowed, or error path added.
    BugFix,
    /// New functionality added (function grew significantly, new callees).
    FeatureAdd,
    /// Internal restructuring without behavioural change.
    Refactor,
    /// Security-related hardening (bounds check, sanitisation, overflow guard).
    SecurityPatch,
    /// Could not determine; classify manually.
    Unknown,
}

impl fmt::Display for ChangeClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BugFix        => f.write_str("BugFix"),
            Self::FeatureAdd    => f.write_str("FeatureAdd"),
            Self::Refactor      => f.write_str("Refactor"),
            Self::SecurityPatch => f.write_str("SecurityPatch"),
            Self::Unknown       => f.write_str("Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CveIndicator — individual CVE-style security indicators
// ─────────────────────────────────────────────────────────────────────────────

/// One CVE-relevant pattern detected in a function change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveIndicator {
    /// A bounds / size check appears to have been added.
    BoundsSizeCheckAdded,
    /// Input sanitisation logic was added.
    SanitizationAdded,
    /// Integer overflow mitigation detected.
    IntegerOverflowFix,
    /// A `free` / dealloc path was fixed.
    UseAfterFreeFix,
    /// Format string handling changed in a printf-family function.
    FormatStringFix,
    /// NULL pointer guard added.
    NullPointerGuard,
    /// Stack canary / stack protection change.
    StackProtectionChange,
    /// Function removed — attack surface reduction.
    AttackSurfaceReduction,
}

impl fmt::Display for CveIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BoundsSizeCheckAdded   => "bounds/size check added",
            Self::SanitizationAdded      => "input sanitization added",
            Self::IntegerOverflowFix     => "integer overflow fix",
            Self::UseAfterFreeFix        => "use-after-free fix",
            Self::FormatStringFix        => "format string fix",
            Self::NullPointerGuard       => "null pointer guard added",
            Self::StackProtectionChange  => "stack protection change",
            Self::AttackSurfaceReduction => "attack surface reduction (fn removed)",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnrichedChangeRecord
// ─────────────────────────────────────────────────────────────────────────────

/// `FunctionChangeRecord` enriched with classification and CVE indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedChangeRecord {
    #[serde(flatten)]
    pub base: FunctionChangeRecord,
    pub classification: ChangeClassification,
    pub cve_indicators: Vec<CveIndicator>,
    /// One-line human-readable summary.
    pub human_summary: String,
}

impl EnrichedChangeRecord {
    fn build_summary(&self) -> String {
        let b = &self.base;
        let class = self.classification;
        match b.kind {
            ChangeKind::Added => {
                format!("[+] `{}` added ({}B)", b.name, b.new_size.unwrap_or(0))
            }
            ChangeKind::Removed => {
                let extra = if self.cve_indicators.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", self.cve_indicators.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
                };
                format!("[-] `{}` removed{}", b.name, extra)
            }
            ChangeKind::Modified => {
                let delta_str = if b.size_delta >= 0 {
                    format!("+{}", b.size_delta)
                } else {
                    b.size_delta.to_string()
                };
                let inds = if self.cve_indicators.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", self.cve_indicators.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
                };
                format!("[~] `{}` modified ({} bytes, {class}{inds})", b.name, delta_str)
            }
            ChangeKind::SignatureChanged => {
                format!("[S] `{}` signature changed ({class})", b.name)
            }
            ChangeKind::Unchanged => {
                format!("[=] `{}` unchanged", b.name)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChangeClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Derives `ChangeClassification` and `CveIndicator`s from a
/// `FunctionChangeRecord`.
pub struct ChangeClassifier {
    sec: SecurityHeuristics,
    mem_fns: HashSet<String>,
    fmt_fns: HashSet<String>,
    arith_patterns: Vec<String>,
}

impl Default for ChangeClassifier {
    fn default() -> Self { Self::new() }
}

impl ChangeClassifier {
    #[must_use]
    pub fn new() -> Self {
        let mem_fns: HashSet<String> = [
            "memcpy", "memmove", "memset", "memcmp",
            "strcpy", "strncpy", "strcat", "strncat",
            "sprintf", "snprintf", "gets", "read", "recv",
            "malloc", "calloc", "realloc", "free",
        ].iter().copied().map(str::to_string).collect();

        let fmt_fns: HashSet<String> = [
            "printf", "fprintf", "sprintf", "snprintf",
            "wprintf", "vprintf", "vsprintf", "vsnprintf",
        ].iter().copied().map(str::to_string).collect();

        let arith_patterns = vec![
            "add".into(), "mul".into(), "overflow".into(),
            "shift".into(), "arith".into(), "calc".into(), "compute".into(),
        ];

        Self { sec: SecurityHeuristics::default(), mem_fns, fmt_fns, arith_patterns }
    }

    /// Borrow the [`SecurityHeuristics`] configuration this classifier was
    /// built with. Exposed so callers can persist or tweak the heuristic
    /// thresholds (e.g. CVE-report tooling) without rebuilding the classifier.
    #[must_use]
    pub const fn security_heuristics(&self) -> &SecurityHeuristics { &self.sec }

    /// Classify a single record; returns (classification, `cve_indicators`).
    #[must_use]
    pub fn classify(&self, rec: &FunctionChangeRecord) -> (ChangeClassification, Vec<CveIndicator>) {
        let mut indicators: Vec<CveIndicator> = Vec::new();
        let name_lo = rec.name.to_lowercase();

        if rec.kind == ChangeKind::Removed && rec.is_security_relevant {
            indicators.push(CveIndicator::AttackSurfaceReduction);
        }

        if rec.kind == ChangeKind::Modified && rec.size_delta > 0 {
            if self.mem_fns.contains(&name_lo) || name_lo.contains("buf") || name_lo.contains("len") {
                indicators.push(CveIndicator::BoundsSizeCheckAdded);
            }
            if name_lo.contains("sanit") || name_lo.contains("escape") || name_lo.contains("encod") {
                indicators.push(CveIndicator::SanitizationAdded);
            }
            if self.arith_patterns.iter().any(|p| name_lo.contains(p.as_str())) {
                indicators.push(CveIndicator::IntegerOverflowFix);
            }
            if self.fmt_fns.contains(&name_lo) {
                indicators.push(CveIndicator::FormatStringFix);
            }
            if rec.size_delta < 64 && (name_lo.contains("check") || name_lo.contains("valid")) {
                indicators.push(CveIndicator::NullPointerGuard);
            }
        }

        if rec.kind == ChangeKind::Modified
            && (name_lo.contains("free") || name_lo.contains("release"))
        {
            indicators.push(CveIndicator::UseAfterFreeFix);
        }

        if rec.kind == ChangeKind::Modified
            && (name_lo.contains("stack") || name_lo.contains("canary") || name_lo.contains("guard"))
        {
            indicators.push(CveIndicator::StackProtectionChange);
        }

        let class = Self::derive_class(rec, &indicators);
        (class, indicators)
    }

    const fn derive_class(rec: &FunctionChangeRecord, indicators: &[CveIndicator]) -> ChangeClassification {
        if !indicators.is_empty() && rec.is_security_relevant {
            return ChangeClassification::SecurityPatch;
        }
        if !indicators.is_empty() {
            return ChangeClassification::BugFix;
        }
        match rec.kind {
            ChangeKind::Added => ChangeClassification::FeatureAdd,
            ChangeKind::Removed | ChangeKind::Unchanged => ChangeClassification::Unknown,
            ChangeKind::Modified => {
                if rec.size_delta > 256 {
                    ChangeClassification::FeatureAdd
                } else if rec.size_delta.unsigned_abs() < 64 {
                    ChangeClassification::Refactor
                } else {
                    ChangeClassification::BugFix
                }
            }
            ChangeKind::SignatureChanged => ChangeClassification::Refactor,
        }
    }

    /// Enrich a batch of change records.
    #[must_use]
    pub fn enrich(&self, records: Vec<FunctionChangeRecord>) -> Vec<EnrichedChangeRecord> {
        records.into_iter().map(|rec| {
            let (classification, cve_indicators) = self.classify(&rec);
            let mut enriched = EnrichedChangeRecord {
                base: rec, classification, cve_indicators,
                human_summary: String::new(),
            };
            enriched.human_summary = enriched.build_summary();
            enriched
        }).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EnrichedPatchReport
// ─────────────────────────────────────────────────────────────────────────────

/// `PatchReport` enriched with per-function classification, CVE indicators,
/// and human-readable summaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedPatchReport {
    pub old_version: String,
    pub new_version: String,
    pub changes: Vec<EnrichedChangeRecord>,
    pub analysis_duration_ms: u64,
}

impl EnrichedPatchReport {
    /// Build from a raw `PatchReport`.
    #[must_use]
    pub fn from_report(report: PatchReport) -> Self {
        let classifier = ChangeClassifier::new();
        Self {
            old_version: report.old_version,
            new_version: report.new_version,
            analysis_duration_ms: report.analysis_duration_ms,
            changes: classifier.enrich(report.changes),
        }
    }

    /// Number of security-patch-classified changes.
    #[must_use]
    pub fn security_patch_count(&self) -> usize {
        self.changes.iter().filter(|c| c.classification == ChangeClassification::SecurityPatch).count()
    }

    /// Number of changes that have at least one CVE indicator.
    #[must_use]
    pub fn cve_indicator_count(&self) -> usize {
        self.changes.iter().filter(|c| !c.cve_indicators.is_empty()).count()
    }

    /// All unique CVE indicators present in the report.
    #[must_use]
    pub fn all_cve_indicators(&self) -> Vec<&CveIndicator> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for c in &self.changes {
            for ind in &c.cve_indicators {
                let key = format!("{ind:?}");
                if seen.insert(key) { out.push(ind); }
            }
        }
        out
    }

    /// Multi-line human-readable patch summary.
    #[must_use]
    pub fn human_readable_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Patch Analysis: {} → {}", self.old_version, self.new_version));
        lines.push(format!(
            "  {} functions changed ({} security patches, {} CVE indicators)",
            self.changes.len(), self.security_patch_count(), self.cve_indicator_count(),
        ));
        lines.push(String::new());

        let mut by_class: HashMap<String, Vec<&EnrichedChangeRecord>> = HashMap::new();
        for c in &self.changes {
            by_class.entry(c.classification.to_string()).or_default().push(c);
        }
        for (class, recs) in &by_class {
            lines.push(format!("  [{class}]"));
            for r in recs.iter().take(10) {
                lines.push(format!("    {}", r.human_summary));
                for ind in &r.cve_indicators {
                    lines.push(format!("      ! {ind}"));
                }
            }
            if recs.len() > 10 {
                lines.push(format!("    ... and {} more", recs.len() - 10));
            }
        }
        lines.join("\n")
    }

    /// Markdown-formatted summary.
    #[must_use]
    pub fn markdown_summary(&self) -> String {
        let mut md = Vec::new();
        md.push(format!("## Patch Analysis: `{}` → `{}`\n", self.old_version, self.new_version));
        md.push(format!(
            "| Metric | Count |\n|--------|-------|\n\
             | Functions changed | {} |\n\
             | Security patches | {} |\n\
             | CVE indicators | {} |\n",
            self.changes.len(), self.security_patch_count(), self.cve_indicator_count(),
        ));

        let security: Vec<&EnrichedChangeRecord> = self.changes.iter()
            .filter(|c| !c.cve_indicators.is_empty())
            .collect();

        if !security.is_empty() {
            md.push("\n### Security-Relevant Changes\n".to_string());
            for c in &security {
                md.push(format!("- `{}`: {}", c.base.name, c.human_summary));
                for ind in &c.cve_indicators {
                    md.push(format!("  - **{ind}**"));
                }
            }
        }
        md.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for enrichment / CVE indicators
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod enriched_tests {
    use super::*;

    fn make_modified(name: &str, old_size: u32, new_size: u32) -> FunctionChangeRecord {
        let sec = SecurityHeuristics::default().is_security_relevant(name);
        let delta = i64::from(new_size) - i64::from(old_size);
        FunctionChangeRecord {
            name: name.to_string(),
            old_address: Some(0x1000), new_address: Some(0x1000),
            old_size: Some(old_size), new_size: Some(new_size),
            kind: ChangeKind::Modified, severity: ChangeSeverity::Medium,
            size_delta: delta, is_security_relevant: sec, notes: Vec::new(),
        }
    }

    fn make_removed(name: &str) -> FunctionChangeRecord {
        let sec = SecurityHeuristics::default().is_security_relevant(name);
        FunctionChangeRecord {
            name: name.to_string(),
            old_address: Some(0x2000), new_address: None,
            old_size: Some(64), new_size: None,
            kind: ChangeKind::Removed, severity: ChangeSeverity::High,
            size_delta: -64, is_security_relevant: sec, notes: Vec::new(),
        }
    }

    #[test]
    fn test_bounds_check_memcpy() {
        let c = ChangeClassifier::new();
        let (_, inds) = c.classify(&make_modified("memcpy", 100, 180));
        assert!(inds.contains(&CveIndicator::BoundsSizeCheckAdded));
    }

    #[test]
    fn test_sanitization_indicator() {
        let c = ChangeClassifier::new();
        let (_, inds) = c.classify(&make_modified("sanitize_input", 80, 140));
        assert!(inds.contains(&CveIndicator::SanitizationAdded));
    }

    #[test]
    fn test_integer_overflow_indicator() {
        let c = ChangeClassifier::new();
        let (_, inds) = c.classify(&make_modified("compute_add", 40, 80));
        assert!(inds.iter().any(|i| *i == CveIndicator::IntegerOverflowFix));
    }

    #[test]
    fn test_attack_surface_reduction() {
        let c = ChangeClassifier::new();
        let (_, inds) = c.classify(&make_removed("auth_check_user"));
        assert!(inds.contains(&CveIndicator::AttackSurfaceReduction));
    }

    #[test]
    fn test_uaf_indicator() {
        let c = ChangeClassifier::new();
        let (_, inds) = c.classify(&make_modified("object_free_safe", 60, 90));
        assert!(inds.contains(&CveIndicator::UseAfterFreeFix));
    }

    #[test]
    fn test_security_patch_class() {
        let c = ChangeClassifier::new();
        let (class, _) = c.classify(&make_modified("memcpy", 100, 180));
        assert_eq!(class, ChangeClassification::SecurityPatch);
    }

    #[test]
    fn test_feature_add_class() {
        let c = ChangeClassifier::new();
        let mut rec = make_modified("new_feature_impl", 100, 500);
        rec.is_security_relevant = false;
        let (class, _) = c.classify(&rec);
        assert_eq!(class, ChangeClassification::FeatureAdd);
    }

    #[test]
    fn test_refactor_class() {
        let c = ChangeClassifier::new();
        let mut rec = make_modified("helper_sort", 200, 210);
        rec.is_security_relevant = false;
        let (class, _) = c.classify(&rec);
        assert_eq!(class, ChangeClassification::Refactor);
    }

    #[test]
    fn test_enriched_report_pipeline() {
        let patch = PatchReport {
            old_version: "1.0".into(), new_version: "1.1".into(),
            changes: vec![make_modified("memcpy", 100, 160)],
            analysis_duration_ms: 1,
        };
        let enriched = EnrichedPatchReport::from_report(patch);
        assert_eq!(enriched.changes.len(), 1);
        assert!(!enriched.changes[0].human_summary.is_empty());
    }

    #[test]
    fn test_markdown_summary_contains_header() {
        let patch = PatchReport {
            old_version: "1.0".into(), new_version: "1.1".into(),
            changes: vec![make_modified("memcpy", 100, 200)],
            analysis_duration_ms: 1,
        };
        let md = EnrichedPatchReport::from_report(patch).markdown_summary();
        assert!(md.contains("## Patch Analysis"));
    }

    #[test]
    fn test_human_readable_summary() {
        let patch = PatchReport {
            old_version: "2.0".into(), new_version: "2.1".into(),
            changes: vec![make_modified("strcpy", 50, 90)],
            analysis_duration_ms: 2,
        };
        let s = EnrichedPatchReport::from_report(patch).human_readable_summary();
        assert!(s.contains("Patch Analysis"));
    }
}
