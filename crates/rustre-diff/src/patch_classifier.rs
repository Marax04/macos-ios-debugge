//! Binary patch classifier.
//!
//! Analyses the output of `rustre-diff` and classifies a patch into one or
//! more `PatchType` categories, collecting `PatchEvidence` along the way.

pub use std::collections::HashSet;

// ── Patch types ───────────────────────────────────────────────────────────────

/// High-level classification of what a binary patch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PatchType {
    /// Corrects a logic or crash bug.
    BugFix,
    /// Closes a security vulnerability.
    SecurityFix,
    /// Adds new functionality.
    NewFeature,
    /// Internal restructuring without behaviour change.
    Refactor,
    /// Speed or size improvements.
    Optimization,
    /// Changes to packing, obfuscation, or anti-analysis layers.
    ObfuscationChange,
    /// Could not determine purpose.
    Unknown,
}

impl std::fmt::Display for PatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BugFix => "BugFix",
            Self::SecurityFix => "SecurityFix",
            Self::NewFeature => "NewFeature",
            Self::Refactor => "Refactor",
            Self::Optimization => "Optimization",
            Self::ObfuscationChange => "ObfuscationChange",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ── Evidence ──────────────────────────────────────────────────────────────────

/// One piece of evidence that contributed to a classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEvidence {
    /// Short machine-readable tag.
    pub kind: EvidenceKind,
    /// Human-readable description.
    pub description: String,
    /// Confidence weight in [0, 100].
    pub weight: u8,
}

impl PatchEvidence {
    pub fn new(kind: EvidenceKind, description: impl Into<String>, weight: u8) -> Self {
        Self {
            kind,
            description: description.into(),
            weight: weight.min(100),
        }
    }
}

/// Evidence categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    /// A syscall number or name changed.
    SyscallChange,
    /// An interesting string was added or removed.
    StringChange,
    /// A new function was added.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A string matching a CVE pattern was found.
    CvePattern,
    /// Bounds-check / sanity-check code was inserted.
    BoundsCheck,
    /// Cryptographic primitive changed.
    CryptoChange,
    /// Import table changed.
    ImportChange,
    /// Export table changed.
    ExportChange,
    /// Code size significantly changed without behaviour change.
    SizeChange,
    /// Obfuscation/packing layer detected.
    ObfuscationLayer,
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Patch input ───────────────────────────────────────────────────────────────

/// Summary of changes extracted from a binary diff, consumed by `PatchClassifier`.
#[derive(Debug, Clone, Default)]
pub struct PatchDelta {
    /// Functions present in B but not A.
    pub functions_added: Vec<String>,
    /// Functions present in A but not B.
    pub functions_removed: Vec<String>,
    /// Functions that exist in both but whose byte content changed.
    pub functions_changed: Vec<String>,
    /// Strings present in B but not A.
    pub strings_added: Vec<String>,
    /// Strings present in A but not B.
    pub strings_removed: Vec<String>,
    /// Imports present in B but not A.
    pub imports_added: Vec<String>,
    /// Imports present in A but not B.
    pub imports_removed: Vec<String>,
    /// Exports present in B but not A.
    pub exports_added: Vec<String>,
    /// Exports present in A but not B.
    pub exports_removed: Vec<String>,
    /// Size of binary A in bytes.
    pub size_a: usize,
    /// Size of binary B in bytes.
    pub size_b: usize,
}

impl PatchDelta {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Net change in number of functions.
    #[must_use]
    pub fn function_delta(&self) -> i64 {
        i64::try_from(self.functions_added.len()).unwrap_or(i64::MAX)
            - i64::try_from(self.functions_removed.len()).unwrap_or(i64::MAX)
    }

    /// Size change ratio (1.0 = identical).
    #[must_use]
    pub fn size_ratio(&self) -> f64 {
        if self.size_a == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.size_b).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.size_a).unwrap_or(u32::MAX))
    }
}

// ── Classification result ─────────────────────────────────────────────────────

/// The result of `PatchClassifier::classify`.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Primary classification (highest-confidence type).
    pub primary: PatchType,
    /// All types that have at least one piece of evidence.
    pub all_types: Vec<PatchType>,
    /// All collected evidence.
    pub evidence: Vec<PatchEvidence>,
    /// Overall confidence in the primary classification (0-100).
    pub confidence: u8,
}

impl ClassificationResult {
    const fn new(
        primary: PatchType,
        all_types: Vec<PatchType>,
        evidence: Vec<PatchEvidence>,
        confidence: u8,
    ) -> Self {
        Self {
            primary,
            all_types,
            evidence,
            confidence,
        }
    }

    /// Check whether a specific type was identified.
    #[must_use] 
    pub fn has_type(&self, t: PatchType) -> bool {
        self.all_types.contains(&t)
    }

    /// Aggregate weight for a specific type.
    #[must_use] 
    pub fn type_score(&self, t: PatchType) -> u32 {
        self.evidence
            .iter()
            .filter(|e| type_for_kind(e.kind).contains(&t))
            .map(|e| u32::from(e.weight))
            .sum()
    }

    /// All evidence pieces for a specific kind.
    #[must_use] 
    pub fn evidence_for(&self, kind: EvidenceKind) -> Vec<&PatchEvidence> {
        self.evidence.iter().filter(|e| e.kind == kind).collect()
    }
}

fn type_for_kind(k: EvidenceKind) -> Vec<PatchType> {
    match k {
        EvidenceKind::SyscallChange | EvidenceKind::BoundsCheck => vec![PatchType::SecurityFix, PatchType::BugFix],
        EvidenceKind::StringChange => vec![PatchType::BugFix, PatchType::NewFeature],
        EvidenceKind::FunctionAdded | EvidenceKind::ExportChange => vec![PatchType::NewFeature],
        EvidenceKind::FunctionRemoved => vec![PatchType::Refactor],
        EvidenceKind::CvePattern | EvidenceKind::CryptoChange => vec![PatchType::SecurityFix],
        EvidenceKind::ImportChange => vec![PatchType::NewFeature, PatchType::Refactor],
        EvidenceKind::SizeChange => vec![PatchType::Optimization, PatchType::ObfuscationChange],
        EvidenceKind::ObfuscationLayer => vec![PatchType::ObfuscationChange],
    }
}

// ── CVE / security pattern heuristics ────────────────────────────────────────

/// Patterns in function names and strings that suggest a CVE / security fix.
const CVE_PATTERNS: &[&str] = &[
    "CVE-",
    "cve-",
    "use-after-free",
    "use_after_free",
    "overflow",
    "underflow",
    "oob",
    "out_of_bounds",
    "out-of-bounds",
    "null_deref",
    "null-deref",
    "heap_spray",
    "heap-spray",
    "type_confusion",
    "type-confusion",
    "integer_overflow",
    "intov",
    "sanitize",
    "sanitization",
    "bounds_check",
    "bounds-check",
    "stack_canary",
    "stack canary",
];

const CRYPTO_PATTERNS: &[&str] = &[
    "aes", "rsa", "sha", "md5", "hmac", "encrypt", "decrypt", "cipher", "hash", "sign", "verify",
    "key", "tls", "ssl",
];

const OBFUSCATION_PATTERNS: &[&str] = &[
    "unpack",
    "unvmp",
    "themida",
    "vmprotect",
    "anti_debug",
    "antidebug",
    "anti-debug",
    "obfuscate",
    "packer",
    "stub",
];

fn matches_patterns(s: &str, patterns: &[&str]) -> bool {
    let lower = s.to_lowercase();
    // Lowercase the patterns too so callers can pass capitalised needles like
    // "Nt"/"Zw" and still match case-insensitively against the haystack.
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

// ── Classifier ────────────────────────────────────────────────────────────────

/// Classifies binary patches based on structural and string heuristics.
#[derive(Debug, Default)]
pub struct PatchClassifier {
    /// Minimum evidence weight required to include a type in the result.
    pub min_type_score: u32,
}

impl PatchClassifier {
    #[must_use] 
    pub const fn new() -> Self {
        Self { min_type_score: 10 }
    }

    #[must_use] 
    pub const fn with_min_score(min_type_score: u32) -> Self {
        Self { min_type_score }
    }

    /// Classify the given `PatchDelta` and return a `ClassificationResult`.
    #[must_use]
    pub fn classify(&self, delta: &PatchDelta) -> ClassificationResult {
        let mut evidence = Self::collect_function_evidence(delta);
        evidence.extend(Self::collect_string_evidence(delta));
        evidence.extend(Self::collect_import_evidence(delta));
        evidence.extend(Self::collect_other_evidence(delta));
        Self::score_and_build(evidence, self.min_type_score)
    }

    fn collect_function_evidence(delta: &PatchDelta) -> Vec<PatchEvidence> {
        let mut ev = Vec::new();
        for name in &delta.functions_added {
            ev.push(PatchEvidence::new(EvidenceKind::FunctionAdded, format!("new function: {name}"), 20));
            if matches_patterns(name, CVE_PATTERNS) {
                ev.push(PatchEvidence::new(EvidenceKind::CvePattern, format!("CVE-like function name: {name}"), 70));
            }
            if matches_patterns(name, OBFUSCATION_PATTERNS) {
                ev.push(PatchEvidence::new(EvidenceKind::ObfuscationLayer, format!("obfuscation-related function: {name}"), 60));
            }
            if matches_patterns(name, &["check", "validate", "verify", "bounds", "sanitize", "guard"]) {
                ev.push(PatchEvidence::new(EvidenceKind::BoundsCheck, format!("bounds/validation function: {name}"), 55));
            }
        }
        for name in &delta.functions_removed {
            ev.push(PatchEvidence::new(EvidenceKind::FunctionRemoved, format!("removed function: {name}"), 15));
        }
        for name in &delta.functions_changed {
            if matches_patterns(name, &["check", "validate", "verify", "bounds", "sanitize", "guard"]) {
                ev.push(PatchEvidence::new(EvidenceKind::BoundsCheck, format!("bounds/validation function: {name}"), 55));
            }
        }
        ev
    }

    fn collect_string_evidence(delta: &PatchDelta) -> Vec<PatchEvidence> {
        let mut ev = Vec::new();
        for s in &delta.strings_added {
            let weight = if matches_patterns(s, CVE_PATTERNS) { 80 } else { 20 };
            ev.push(PatchEvidence::new(EvidenceKind::StringChange, format!("added string: {s}"), weight));
            if matches_patterns(s, CVE_PATTERNS) {
                ev.push(PatchEvidence::new(EvidenceKind::CvePattern, format!("CVE pattern in added string: {s}"), 85));
            }
            if matches_patterns(s, OBFUSCATION_PATTERNS) {
                ev.push(PatchEvidence::new(EvidenceKind::ObfuscationLayer, format!("obfuscation string added: {s}"), 65));
            }
        }
        for s in &delta.strings_removed {
            ev.push(PatchEvidence::new(EvidenceKind::StringChange, format!("removed string: {s}"), 15));
        }
        ev
    }

    fn collect_import_evidence(delta: &PatchDelta) -> Vec<PatchEvidence> {
        let mut ev = Vec::new();
        for imp in &delta.imports_added {
            let w = if matches_patterns(imp, CVE_PATTERNS) { 60u8 }
                    else if matches_patterns(imp, CRYPTO_PATTERNS) { 50 }
                    else { 20 };
            if matches_patterns(imp, CRYPTO_PATTERNS) {
                ev.push(PatchEvidence::new(EvidenceKind::CryptoChange, format!("crypto import: {imp}"), 55));
            }
            ev.push(PatchEvidence::new(EvidenceKind::ImportChange, format!("added import: {imp}"), w));
            if matches_patterns(imp, &["Nt", "Zw", "syscall", "sysenter"]) {
                ev.push(PatchEvidence::new(EvidenceKind::SyscallChange, format!("syscall-related import added: {imp}"), 50));
            }
        }
        for imp in &delta.imports_removed {
            ev.push(PatchEvidence::new(EvidenceKind::ImportChange, format!("removed import: {imp}"), 10));
            if matches_patterns(imp, &["Nt", "Zw", "syscall", "sysenter"]) {
                ev.push(PatchEvidence::new(EvidenceKind::SyscallChange, format!("syscall-related import removed: {imp}"), 50));
            }
        }
        for exp in &delta.exports_added {
            ev.push(PatchEvidence::new(EvidenceKind::ExportChange, format!("added export: {exp}"), 25));
        }
        ev
    }

    fn collect_other_evidence(delta: &PatchDelta) -> Vec<PatchEvidence> {
        let mut ev = Vec::new();
        let ratio = delta.size_ratio();
        if !(0.85..=1.20).contains(&ratio) {
            ev.push(PatchEvidence::new(EvidenceKind::SizeChange, format!("size changed by {:.1}%", (ratio - 1.0) * 100.0), 30));
        }
        ev
    }

    fn score_and_build(evidence: Vec<PatchEvidence>, min_type_score: u32) -> ClassificationResult {
        let all_patch_types = [
            PatchType::BugFix, PatchType::SecurityFix, PatchType::NewFeature,
            PatchType::Refactor, PatchType::Optimization, PatchType::ObfuscationChange,
        ];
        let mut scored: Vec<(PatchType, u32)> = all_patch_types.iter().map(|&t| {
            let score = evidence.iter()
                .filter(|e| type_for_kind(e.kind).contains(&t))
                .map(|e| u32::from(e.weight))
                .sum();
            (t, score)
        }).collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1));
        let active_types: Vec<PatchType> = scored.iter()
            .filter(|(_, s)| *s >= min_type_score)
            .map(|(t, _)| *t)
            .collect();
        let (primary, confidence) = if let Some(&(t, score)) = scored.first() {
            let conf_u32 = (score.min(200) * 50 / 200) + 50;
            let conf = u8::try_from(conf_u32.min(100)).unwrap_or(100);
            (t, conf)
        } else {
            (PatchType::Unknown, 0)
        };
        let primary = if active_types.is_empty() { PatchType::Unknown } else { primary };
        ClassificationResult::new(primary, active_types, evidence, confidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn clf() -> PatchClassifier {
        PatchClassifier::new()
    }

    fn delta_with_functions(added: &[&str]) -> PatchDelta {
        let mut d = PatchDelta::new();
        d.functions_added = added.iter().map(std::string::ToString::to_string).collect();
        d.size_a = 10000;
        d.size_b = 10100;
        d
    }

    #[test]
    fn test_empty_delta_is_unknown() {
        let d = PatchDelta::new();
        let r = clf().classify(&d);
        assert_eq!(r.primary, PatchType::Unknown);
    }

    #[test]
    fn test_new_function_suggests_new_feature() {
        let d = delta_with_functions(&["new_awesome_feature"]);
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::NewFeature));
    }

    #[test]
    fn test_cve_pattern_in_function_suggests_security() {
        let d = delta_with_functions(&["fix_cve_2024_1234_overflow"]);
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::SecurityFix));
    }

    #[test]
    fn test_cve_string_suggests_security() {
        let mut d = PatchDelta::new();
        d.strings_added = vec!["CVE-2024-99999".to_string()];
        d.size_a = 5000;
        d.size_b = 5010;
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::SecurityFix));
    }

    #[test]
    fn test_bounds_check_function_suggests_security() {
        let d = delta_with_functions(&["validate_input_bounds"]);
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::SecurityFix) || r.has_type(PatchType::BugFix));
    }

    #[test]
    fn test_removed_function_suggests_refactor() {
        let mut d = PatchDelta::new();
        d.functions_removed = vec!["old_helper".to_string()];
        d.size_a = 8000;
        d.size_b = 7800;
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::Refactor));
    }

    #[test]
    fn test_size_change_adds_evidence() {
        let mut d = PatchDelta::new();
        d.size_a = 10000;
        d.size_b = 13000; // +30%
        let r = clf().classify(&d);
        let size_ev: Vec<_> = r.evidence_for(EvidenceKind::SizeChange);
        assert!(!size_ev.is_empty());
    }

    #[test]
    fn test_no_size_evidence_for_small_change() {
        let mut d = PatchDelta::new();
        d.size_a = 10000;
        d.size_b = 10050; // +0.5%
        let r = clf().classify(&d);
        assert!(r.evidence_for(EvidenceKind::SizeChange).is_empty());
    }

    #[test]
    fn test_crypto_import_adds_crypto_evidence() {
        let mut d = PatchDelta::new();
        d.imports_added = vec!["CryptEncrypt".to_string()];
        d.size_a = 5000;
        d.size_b = 5100;
        let r = clf().classify(&d);
        assert!(!r.evidence_for(EvidenceKind::CryptoChange).is_empty());
    }

    #[test]
    fn test_obfuscation_function_suggests_obfuscation_change() {
        let d = delta_with_functions(&["unpack_stub_entry"]);
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::ObfuscationChange));
    }

    #[test]
    fn test_classification_result_has_type() {
        let mut d = PatchDelta::new();
        d.functions_added = vec!["feature_x".into()];
        d.size_a = 1;
        d.size_b = 1;
        let r = clf().classify(&d);
        assert!(r.has_type(PatchType::NewFeature));
        assert!(!r.has_type(PatchType::Unknown));
    }

    #[test]
    fn test_patch_type_display() {
        assert_eq!(PatchType::SecurityFix.to_string(), "SecurityFix");
        assert_eq!(PatchType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_evidence_weight_capped_at_100() {
        let e = PatchEvidence::new(EvidenceKind::CvePattern, "test", 255);
        assert_eq!(e.weight, 100);
    }

    #[test]
    fn test_function_delta_positive() {
        let mut d = PatchDelta::new();
        d.functions_added = vec!["a".into(), "b".into()];
        d.functions_removed = vec!["c".into()];
        assert_eq!(d.function_delta(), 1);
    }

    #[test]
    fn test_size_ratio_zero_a() {
        let d = PatchDelta {
            size_a: 0,
            size_b: 100,
            ..Default::default()
        };
        assert_eq!(d.size_ratio(), 1.0);
    }

    #[test]
    fn test_type_score_nonzero_for_cve() {
        let mut d = PatchDelta::new();
        d.strings_added = vec!["CVE-2024-1234 buffer overflow fix".into()];
        d.size_a = 5000;
        d.size_b = 5010;
        let r = clf().classify(&d);
        assert!(r.type_score(PatchType::SecurityFix) > 0);
    }

    #[test]
    fn test_confidence_nonzero_with_evidence() {
        let d = delta_with_functions(&["security_fix_overflow_check"]);
        let r = clf().classify(&d);
        assert!(r.confidence > 0);
    }

    #[test]
    fn test_syscall_change_evidence() {
        let mut d = PatchDelta::new();
        d.imports_added = vec!["NtCreateFile".into()];
        d.size_a = 4000;
        d.size_b = 4100;
        let r = clf().classify(&d);
        assert!(!r.evidence_for(EvidenceKind::SyscallChange).is_empty());
    }
}
