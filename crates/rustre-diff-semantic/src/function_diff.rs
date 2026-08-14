//! Function-level diff: compare two versions of the same function and
//! characterize the nature of the change.

use std::collections::HashMap;
use std::fmt;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// DiffSeverity
// ─────────────────────────────────────────────────────────────────────────────

/// How significant the diff is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DiffSeverity {
    /// Identical — no change.
    None,
    /// Minor — cosmetic or trivial change.
    Minor,
    /// Moderate — logic adjustment with bounded impact.
    Moderate,
    /// Major — significant behavioral change.
    Major,
    /// Critical — security-relevant or ABI-breaking change.
    Critical,
}

impl fmt::Display for DiffSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Minor => "minor",
            Self::Moderate => "moderate",
            Self::Major => "major",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchCategory
// ─────────────────────────────────────────────────────────────────────────────

/// High-level categorization of what a patch does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchCategory {
    /// Bug fix.
    BugFix,
    /// Security patch (e.g. bounds check added).
    SecurityFix,
    /// Refactoring: behavior preserved, structure changed.
    Refactor,
    /// Performance optimization.
    Performance,
    /// New feature added.
    Feature,
    /// Documentation/comment only.
    Documentation,
    /// Unknown / unclassified.
    Unknown,
}

impl fmt::Display for PatchCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BugFix => "bug_fix",
            Self::SecurityFix => "security_fix",
            Self::Refactor => "refactor",
            Self::Performance => "performance",
            Self::Feature => "feature",
            Self::Documentation => "documentation",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type representation (for parameter / return type diffs)
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified type used for diffing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SimpleType {
    Void,
    Bool,
    Int {
        signed: bool,
        bits: u8,
    },
    Float {
        bits: u8,
    },
    Pointer(Box<Self>),
    Array {
        element: Box<Self>,
        count: usize,
    },
    Struct {
        name: String,
    },
    Enum {
        name: String,
    },
    Function {
        ret: Box<Self>,
        params: Vec<Self>,
    },
    Unknown,
}

impl SimpleType {
    #[must_use] 
    pub const fn int(bits: u8) -> Self {
        Self::Int { signed: true, bits }
    }
    #[must_use] 
    pub const fn uint(bits: u8) -> Self {
        Self::Int {
            signed: false,
            bits,
        }
    }
    #[must_use] 
    pub fn ptr(inner: Self) -> Self {
        Self::Pointer(Box::new(inner))
    }

    /// Returns true if the type is a pointer or array (memory-referencing).
    #[must_use] 
    pub const fn is_ptr_like(&self) -> bool {
        matches!(self, Self::Pointer(_) | Self::Array { .. })
    }

    /// Byte size hint (0 if unknown).
    #[must_use] 
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Bool => 1,
            Self::Int { bits, .. } | Self::Float { bits } => (*bits as usize).div_ceil(8),
            Self::Pointer(_) => 8,
            Self::Array { element, count } => element.byte_size() * count,
            _ => 0,
        }
    }
}

impl fmt::Display for SimpleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => f.write_str("void"),
            Self::Bool => f.write_str("bool"),
            Self::Int { signed, bits } => {
                write!(f, "{}{}", if *signed { "i" } else { "u" }, bits)
            }
            Self::Float { bits } => write!(f, "f{bits}"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Array { element, count } => write!(f, "{element}[{count}]"),
            Self::Struct { name } => write!(f, "struct {name}"),
            Self::Enum { name } => write!(f, "enum {name}"),
            Self::Function { ret, params } => {
                let param_strs: Vec<String> = params.iter().map(|p| format!("{p}")).collect();
                write!(f, "fn({}) -> {}", param_strs.join(", "), ret)
            }
            Self::Unknown => f.write_str("?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParameterDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Change in a single parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterDiff {
    /// Parameter index (0-based).
    pub index: usize,
    /// Old parameter name.
    pub old_name: Option<String>,
    /// New parameter name.
    pub new_name: Option<String>,
    /// Old type.
    pub old_type: SimpleType,
    /// New type.
    pub new_type: SimpleType,
}

impl ParameterDiff {
    #[must_use] 
    pub fn is_type_change(&self) -> bool {
        self.old_type != self.new_type
    }
    #[must_use] 
    pub fn is_name_change(&self) -> bool {
        self.old_name != self.new_name
    }

    /// Severity of this parameter change.
    #[must_use] 
    pub fn severity(&self) -> DiffSeverity {
        if !self.is_type_change() && !self.is_name_change() {
            DiffSeverity::None
        } else if !self.is_type_change() {
            DiffSeverity::Minor
        } else {
            // Pointer-width change, signedness change, etc. are severe.
            let old_ptr = self.old_type.is_ptr_like();
            let new_ptr = self.new_type.is_ptr_like();
            if old_ptr == new_ptr {
                DiffSeverity::Moderate
            } else {
                DiffSeverity::Critical
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LocalVarDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Change in a local variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalVarDiff {
    pub name: String,
    pub old_type: Option<SimpleType>,
    pub new_type: Option<SimpleType>,
    /// True if the variable was removed.
    pub removed: bool,
    /// True if the variable was added.
    pub added: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeChangeDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Records a change in the return type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeChangeDiff {
    pub old_ret: SimpleType,
    pub new_ret: SimpleType,
}

impl TypeChangeDiff {
    #[must_use] 
    pub fn severity(&self) -> DiffSeverity {
        if self.old_ret == self.new_ret {
            return DiffSeverity::None;
        }
        let old_void = matches!(self.old_ret, SimpleType::Void);
        let new_void = matches!(self.new_ret, SimpleType::Void);
        if old_void == new_void {
            DiffSeverity::Minor
        } else {
            DiffSeverity::Major
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionSignature
// ─────────────────────────────────────────────────────────────────────────────

/// A function's signature for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub address: u64,
    pub return_type: SimpleType,
    pub params: Vec<(Option<String>, SimpleType)>,
    pub is_variadic: bool,
    pub calling_convention: String,
}

impl FunctionSignature {
    pub fn new(name: impl Into<String>, address: u64) -> Self {
        Self {
            name: name.into(),
            address,
            return_type: SimpleType::Void,
            params: Vec::new(),
            is_variadic: false,
            calling_convention: "unknown".to_string(),
        }
    }

    #[must_use] 
    pub fn with_return(mut self, t: SimpleType) -> Self {
        self.return_type = t;
        self
    }

    #[must_use] 
    pub fn with_param(mut self, name: Option<&str>, t: SimpleType) -> Self {
        self.params.push((name.map(std::string::ToString::to_string), t));
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies what changed between two versions of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionDiffKind {
    /// Signature changed but body is similar.
    SignatureOnly,
    /// Body changed but signature is the same.
    BodyOnly,
    /// Both signature and body changed.
    Both,
    /// No changes detected.
    Unchanged,
}

impl fmt::Display for FunctionDiffKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SignatureOnly => "signature_only",
            Self::BodyOnly => "body_only",
            Self::Both => "both",
            Self::Unchanged => "unchanged",
        };
        f.write_str(s)
    }
}

/// Full function-level diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDiff {
    pub old_sig: FunctionSignature,
    pub new_sig: FunctionSignature,
    pub kind: FunctionDiffKind,
    pub param_diffs: Vec<ParameterDiff>,
    pub return_diff: Option<TypeChangeDiff>,
    pub local_var_diffs: Vec<LocalVarDiff>,
    /// Overall severity.
    pub severity: DiffSeverity,
    /// Body similarity score [0.0, 1.0].
    pub body_similarity: f64,
    /// Estimated patch category.
    pub patch_category: PatchCategory,
}

impl FunctionDiff {
    #[must_use] 
    pub fn is_unchanged(&self) -> bool {
        self.kind == FunctionDiffKind::Unchanged
    }

    #[must_use] 
    pub const fn has_signature_change(&self) -> bool {
        matches!(
            self.kind,
            FunctionDiffKind::SignatureOnly | FunctionDiffKind::Both
        )
    }

    #[must_use] 
    pub const fn has_body_change(&self) -> bool {
        matches!(
            self.kind,
            FunctionDiffKind::BodyOnly | FunctionDiffKind::Both
        )
    }

    /// Number of added parameters.
    #[must_use] 
    pub const fn added_params(&self) -> usize {
        // Parameters in new_sig but not in old_sig
        self.new_sig
            .params
            .len()
            .saturating_sub(self.old_sig.params.len())
    }

    /// Number of removed parameters.
    #[must_use] 
    pub const fn removed_params(&self) -> usize {
        self.old_sig
            .params
            .len()
            .saturating_sub(self.new_sig.params.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchCharacterizer
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristically characterizes what kind of patch a [`FunctionDiff`] represents.
pub struct PatchCharacterizer {
    /// Keywords in function names that suggest security relevance.
    pub security_keywords: Vec<String>,
    /// Keywords suggesting bug fixes.
    pub bugfix_keywords: Vec<String>,
}

impl Default for PatchCharacterizer {
    fn default() -> Self {
        Self {
            security_keywords: vec![
                "check".into(),
                "validate".into(),
                "verify".into(),
                "sanitize".into(),
                "auth".into(),
                "bounds".into(),
                "overflow".into(),
                "underflow".into(),
                "safe".into(),
            ],
            bugfix_keywords: vec![
                "fix".into(),
                "bug".into(),
                "error".into(),
                "handle".into(),
                "correct".into(),
                "patch".into(),
            ],
        }
    }
}

impl PatchCharacterizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Characterize the kind of patch.
    #[must_use] 
    pub fn characterize(&self, diff: &FunctionDiff) -> PatchCategory {
        let fname_lower = diff.new_sig.name.to_lowercase();

        // Security heuristics: if a bounds check was added (pointer param widened)
        let has_ptr_narrowing = diff.param_diffs.iter().any(|pd| {
            matches!(&pd.old_type, SimpleType::Pointer(_))
                && matches!(&pd.new_type, SimpleType::Int { .. })
        });
        let has_bounds_check_keyword = self
            .security_keywords
            .iter()
            .any(|kw| fname_lower.contains(kw.as_str()));

        if has_ptr_narrowing || has_bounds_check_keyword {
            return PatchCategory::SecurityFix;
        }

        // Bug fix heuristics
        if self
            .bugfix_keywords
            .iter()
            .any(|kw| fname_lower.contains(kw.as_str()))
        {
            return PatchCategory::BugFix;
        }

        // If signature changed but body is very similar → refactor
        if diff.has_signature_change() && diff.body_similarity > 0.85 {
            return PatchCategory::Refactor;
        }

        // High body similarity with no signature change → performance or refactor
        if !diff.has_signature_change() && diff.body_similarity > 0.90 {
            return PatchCategory::Performance;
        }

        // Low body similarity → feature or unknown
        if diff.body_similarity < 0.5 {
            return PatchCategory::Feature;
        }

        PatchCategory::Unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report across multiple function diffs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub binary_old: String,
    pub binary_new: String,
    pub function_diffs: Vec<FunctionDiff>,
    pub total_functions_old: usize,
    pub total_functions_new: usize,
}

impl DiffReport {
    pub fn new(old: impl Into<String>, new: impl Into<String>) -> Self {
        Self {
            binary_old: old.into(),
            binary_new: new.into(),
            function_diffs: Vec::new(),
            total_functions_old: 0,
            total_functions_new: 0,
        }
    }

    pub fn add(&mut self, diff: FunctionDiff) {
        self.function_diffs.push(diff);
    }

    #[must_use] 
    pub fn changed_count(&self) -> usize {
        self.function_diffs
            .iter()
            .filter(|d| !d.is_unchanged())
            .count()
    }

    #[must_use] 
    pub fn unchanged_count(&self) -> usize {
        self.function_diffs
            .iter()
            .filter(|d| d.is_unchanged())
            .count()
    }

    #[must_use] 
    pub fn critical_count(&self) -> usize {
        self.function_diffs
            .iter()
            .filter(|d| d.severity == DiffSeverity::Critical)
            .count()
    }

    #[must_use] 
    pub fn security_fix_count(&self) -> usize {
        self.function_diffs
            .iter()
            .filter(|d| d.patch_category == PatchCategory::SecurityFix)
            .count()
    }

    #[must_use] 
    pub fn average_body_similarity(&self) -> f64 {
        if self.function_diffs.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.function_diffs.iter().map(|d| d.body_similarity).sum();
        sum / count_as_f64(self.function_diffs.len())
    }

    /// Highest severity seen across all diffs.
    #[must_use] 
    pub fn max_severity(&self) -> DiffSeverity {
        self.function_diffs
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(DiffSeverity::None)
    }

    /// Functions grouped by patch category.
    #[must_use] 
    pub fn by_category(&self) -> HashMap<String, Vec<&FunctionDiff>> {
        let mut map: HashMap<String, Vec<&FunctionDiff>> = HashMap::new();
        for d in &self.function_diffs {
            map.entry(format!("{}", d.patch_category))
                .or_default()
                .push(d);
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a FunctionDiff from two signatures
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`FunctionDiff`] from two [`FunctionSignature`]s and a body similarity score.
#[must_use] 
pub fn diff_signatures(
    old: FunctionSignature,
    new: FunctionSignature,
    body_similarity: f64,
) -> FunctionDiff {
    // Compute param diffs
    let mut param_diffs = Vec::new();
    let max_params = old.params.len().max(new.params.len());
    for i in 0..max_params {
        let old_param = old.params.get(i);
        let new_param = new.params.get(i);
        match (old_param, new_param) {
            (Some((on, ot)), Some((nn, nt))) => {
                param_diffs.push(ParameterDiff {
                    index: i,
                    old_name: on.clone(),
                    new_name: nn.clone(),
                    old_type: ot.clone(),
                    new_type: nt.clone(),
                });
            }
            (Some((on, ot)), None) => {
                param_diffs.push(ParameterDiff {
                    index: i,
                    old_name: on.clone(),
                    new_name: None,
                    old_type: ot.clone(),
                    new_type: SimpleType::Unknown,
                });
            }
            (None, Some((nn, nt))) => {
                param_diffs.push(ParameterDiff {
                    index: i,
                    old_name: None,
                    new_name: nn.clone(),
                    old_type: SimpleType::Unknown,
                    new_type: nt.clone(),
                });
            }
            (None, None) => {}
        }
    }

    let return_diff = if old.return_type == new.return_type {
        None
    } else {
        Some(TypeChangeDiff {
            old_ret: old.return_type.clone(),
            new_ret: new.return_type.clone(),
        })
    };

    let sig_changed = !param_diffs
        .iter()
        .all(|pd| pd.severity() == DiffSeverity::None)
        || return_diff.is_some()
        || old.calling_convention != new.calling_convention;
    let body_changed = body_similarity < 1.0;

    let kind = match (sig_changed, body_changed) {
        (true, true) => FunctionDiffKind::Both,
        (true, false) => FunctionDiffKind::SignatureOnly,
        (false, true) => FunctionDiffKind::BodyOnly,
        (false, false) => FunctionDiffKind::Unchanged,
    };

    let max_param_severity = param_diffs
        .iter()
        .map(ParameterDiff::severity)
        .max()
        .unwrap_or(DiffSeverity::None);
    let ret_severity = return_diff
        .as_ref()
        .map_or(DiffSeverity::None, TypeChangeDiff::severity);
    let body_severity = if body_similarity >= 1.0 {
        DiffSeverity::None
    } else if body_similarity >= 0.9 {
        DiffSeverity::Minor
    } else if body_similarity >= 0.6 {
        DiffSeverity::Moderate
    } else if body_similarity >= 0.3 {
        DiffSeverity::Major
    } else {
        DiffSeverity::Critical
    };

    let severity = max_param_severity.max(ret_severity).max(body_severity);

    let char = PatchCharacterizer::new();
    let tmp = FunctionDiff {
        old_sig: old,
        new_sig: new,
        kind,
        param_diffs,
        return_diff,
        local_var_diffs: Vec::new(),
        severity,
        body_similarity,
        patch_category: PatchCategory::Unknown,
    };
    let category = char.characterize(&tmp);
    FunctionDiff {
        patch_category: category,
        ..tmp
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str, addr: u64) -> FunctionSignature {
        FunctionSignature::new(name, addr)
    }

    // --- DiffSeverity ---

    #[test]
    fn severity_ordering() {
        assert!(DiffSeverity::None < DiffSeverity::Minor);
        assert!(DiffSeverity::Minor < DiffSeverity::Critical);
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", DiffSeverity::Critical), "critical");
    }

    // --- PatchCategory ---

    #[test]
    fn patch_category_display() {
        assert_eq!(format!("{}", PatchCategory::SecurityFix), "security_fix");
    }

    // --- SimpleType ---

    #[test]
    fn simple_type_int_byte_size() {
        assert_eq!(SimpleType::int(64).byte_size(), 8);
        assert_eq!(SimpleType::int(32).byte_size(), 4);
    }

    #[test]
    fn simple_type_ptr_size() {
        assert_eq!(SimpleType::ptr(SimpleType::Void).byte_size(), 8);
    }

    #[test]
    fn simple_type_is_ptr_like() {
        assert!(SimpleType::ptr(SimpleType::Void).is_ptr_like());
        assert!(!SimpleType::int(32).is_ptr_like());
    }

    #[test]
    fn simple_type_display_int() {
        assert_eq!(format!("{}", SimpleType::int(32)), "i32");
    }

    #[test]
    fn simple_type_display_ptr() {
        assert_eq!(format!("{}", SimpleType::ptr(SimpleType::int(8))), "i8*");
    }

    #[test]
    fn simple_type_void_size_zero() {
        assert_eq!(SimpleType::Void.byte_size(), 0);
    }

    // --- ParameterDiff ---

    #[test]
    fn param_diff_no_change_severity_none() {
        let pd = ParameterDiff {
            index: 0,
            old_name: Some("x".into()),
            new_name: Some("x".into()),
            old_type: SimpleType::int(32),
            new_type: SimpleType::int(32),
        };
        assert_eq!(pd.severity(), DiffSeverity::None);
    }

    #[test]
    fn param_diff_name_change_minor() {
        let pd = ParameterDiff {
            index: 0,
            old_name: Some("a".into()),
            new_name: Some("b".into()),
            old_type: SimpleType::int(32),
            new_type: SimpleType::int(32),
        };
        assert_eq!(pd.severity(), DiffSeverity::Minor);
    }

    #[test]
    fn param_diff_ptr_to_int_critical() {
        let pd = ParameterDiff {
            index: 0,
            old_name: None,
            new_name: None,
            old_type: SimpleType::ptr(SimpleType::int(8)),
            new_type: SimpleType::int(64),
        };
        assert_eq!(pd.severity(), DiffSeverity::Critical);
    }

    // --- TypeChangeDiff ---

    #[test]
    fn type_change_same_type_none_severity() {
        let tcd = TypeChangeDiff {
            old_ret: SimpleType::int(32),
            new_ret: SimpleType::int(32),
        };
        assert_eq!(tcd.severity(), DiffSeverity::None);
    }

    #[test]
    fn type_change_void_to_int_major() {
        let tcd = TypeChangeDiff {
            old_ret: SimpleType::Void,
            new_ret: SimpleType::int(32),
        };
        assert_eq!(tcd.severity(), DiffSeverity::Major);
    }

    // --- diff_signatures ---

    #[test]
    fn diff_sigs_identical_is_unchanged() {
        let old = sig("foo", 0x1000)
            .with_return(SimpleType::int(32))
            .with_param(Some("x"), SimpleType::int(64));
        let new = sig("foo", 0x2000)
            .with_return(SimpleType::int(32))
            .with_param(Some("x"), SimpleType::int(64));
        let diff = diff_signatures(old, new, 1.0);
        assert_eq!(diff.kind, FunctionDiffKind::Unchanged);
    }

    #[test]
    fn diff_sigs_body_change_only() {
        let old = sig("bar", 0x1000).with_return(SimpleType::Void);
        let new = sig("bar", 0x2000).with_return(SimpleType::Void);
        let diff = diff_signatures(old, new, 0.5);
        assert_eq!(diff.kind, FunctionDiffKind::BodyOnly);
        assert!(diff.has_body_change());
    }

    #[test]
    fn diff_sigs_signature_change_only() {
        let old = sig("baz", 0x1000).with_return(SimpleType::int(32));
        let new = sig("baz", 0x2000).with_return(SimpleType::int(64));
        let diff = diff_signatures(old, new, 1.0);
        assert!(diff.has_signature_change());
    }

    #[test]
    fn diff_sigs_both_changed() {
        let old = sig("qux", 0x1000).with_return(SimpleType::Void);
        let new = sig("qux", 0x2000).with_return(SimpleType::int(32));
        let diff = diff_signatures(old, new, 0.3);
        assert_eq!(diff.kind, FunctionDiffKind::Both);
    }

    #[test]
    fn diff_sigs_added_param() {
        let old = sig("f", 0x1000);
        let new = sig("f", 0x2000).with_param(Some("n"), SimpleType::int(32));
        let diff = diff_signatures(old, new, 1.0);
        assert_eq!(diff.added_params(), 1);
    }

    // --- FunctionDiff ---

    #[test]
    fn function_diff_removed_params() {
        let old = sig("f", 0)
            .with_param(Some("a"), SimpleType::int(32))
            .with_param(Some("b"), SimpleType::int(32));
        let new = sig("f", 0).with_param(Some("a"), SimpleType::int(32));
        let diff = diff_signatures(old, new, 1.0);
        assert_eq!(diff.removed_params(), 1);
    }

    // --- DiffReport ---

    #[test]
    fn diff_report_changed_count() {
        let mut report = DiffReport::new("old", "new");
        let old = sig("f1", 0x1000);
        let new = sig("f1", 0x2000);
        let diff = diff_signatures(old, new, 0.5);
        report.add(diff);
        assert_eq!(report.changed_count(), 1);
    }

    #[test]
    fn diff_report_unchanged_count() {
        let mut report = DiffReport::new("old", "new");
        let old = sig("f1", 0x1000);
        let new = sig("f1", 0x2000);
        let diff = diff_signatures(old, new, 1.0);
        report.add(diff);
        assert_eq!(report.unchanged_count(), 1);
    }

    #[test]
    fn diff_report_average_similarity() {
        let mut report = DiffReport::new("a", "b");
        let d1 = diff_signatures(sig("a", 0), sig("a", 0), 0.8);
        let d2 = diff_signatures(sig("b", 0), sig("b", 0), 0.6);
        report.add(d1);
        report.add(d2);
        let avg = report.average_body_similarity();
        assert!((avg - 0.7).abs() < 1e-10);
    }

    #[test]
    fn diff_report_max_severity() {
        let mut report = DiffReport::new("a", "b");
        let d = diff_signatures(
            sig("f", 0).with_return(SimpleType::Void),
            sig("f", 0).with_return(SimpleType::int(32)),
            0.0,
        );
        report.add(d);
        assert!(report.max_severity() >= DiffSeverity::Major);
    }

    // --- PatchCharacterizer ---

    #[test]
    fn patch_characterizer_security_keyword() {
        let char = PatchCharacterizer::new();
        let old = sig("validate_input", 0);
        let new = sig("validate_input", 0);
        let diff = diff_signatures(old, new, 0.8);
        let cat = char.characterize(&diff);
        assert_eq!(cat, PatchCategory::SecurityFix);
    }

    #[test]
    fn patch_characterizer_performance_high_sim() {
        let char = PatchCharacterizer::new();
        let old = sig("fast_path", 0);
        let new = sig("fast_path", 0);
        let diff = diff_signatures(old, new, 0.95);
        let cat = char.characterize(&diff);
        assert_eq!(cat, PatchCategory::Performance);
    }

    #[test]
    fn patch_characterizer_feature_low_sim() {
        let char = PatchCharacterizer::new();
        let old = sig("new_feature", 0);
        let new = sig("new_feature", 0);
        let diff = diff_signatures(old, new, 0.1);
        let cat = char.characterize(&diff);
        assert_eq!(cat, PatchCategory::Feature);
    }
}
