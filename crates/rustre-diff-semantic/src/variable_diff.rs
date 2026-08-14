//! `variable_diff` — Diff variable usage across function versions.
//!
//! Tracks renames, type changes, scope changes, and lifetime differences
//! for local variables between two versions of a function.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// VarType
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified variable type representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VarType {
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float32,
    Float64,
    Bool,
    Pointer(Box<Self>),
    Array(Box<Self>, usize),
    Struct(String),
    Unknown,
    Named(String),
}

impl VarType {
    /// Returns `true` if the type is a pointer.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Returns `true` if the type is an integer of any width.
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Int8
                | Self::Int16
                | Self::Int32
                | Self::Int64
                | Self::UInt8
                | Self::UInt16
                | Self::UInt32
                | Self::UInt64
        )
    }

    /// Size in bytes for simple primitive types.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<usize> {
        match self {
            Self::Int8 | Self::UInt8 | Self::Bool => Some(1),
            Self::Int16 | Self::UInt16 => Some(2),
            Self::Int32 | Self::UInt32 | Self::Float32 => Some(4),
            Self::Int64 | Self::UInt64 | Self::Float64 => Some(8),
            _ => None,
        }
    }

    /// Returns a human-readable type string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Int8 => "i8".to_owned(),
            Self::Int16 => "i16".to_owned(),
            Self::Int32 => "i32".to_owned(),
            Self::Int64 => "i64".to_owned(),
            Self::UInt8 => "u8".to_owned(),
            Self::UInt16 => "u16".to_owned(),
            Self::UInt32 => "u32".to_owned(),
            Self::UInt64 => "u64".to_owned(),
            Self::Float32 => "f32".to_owned(),
            Self::Float64 => "f64".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::Pointer(inner) => format!("*{}", inner.display()),
            Self::Array(inner, n) => format!("[{}; {n}]", inner.display()),
            Self::Struct(name) => format!("struct {name}"),
            Self::Named(name) => name.clone(),
            Self::Unknown => "?".to_owned(),
        }
    }
}

impl std::fmt::Display for VarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarScope
// ─────────────────────────────────────────────────────────────────────────────

/// Scope / storage class of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarScope {
    /// Stack-allocated local variable.
    Local,
    /// Register variable (not memory-backed).
    Register,
    /// Function parameter.
    Parameter,
    /// Global or static.
    Global,
    /// Captured from enclosing scope.
    Captured,
}

impl std::fmt::Display for VarScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Local => "local",
            Self::Register => "register",
            Self::Parameter => "param",
            Self::Global => "global",
            Self::Captured => "captured",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarLifetime
// ─────────────────────────────────────────────────────────────────────────────

/// Approximate lifetime / live-range of a variable, expressed as instruction
/// offsets within the function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarLifetime {
    /// First instruction offset where the variable is defined.
    pub def_offset: u64,
    /// Last instruction offset where the variable is used.
    pub last_use_offset: u64,
}

impl VarLifetime {
    /// Create a new lifetime span.
    #[must_use]
    pub const fn new(def_offset: u64, last_use_offset: u64) -> Self {
        Self {
            def_offset,
            last_use_offset,
        }
    }

    /// Length of the live range.
    #[must_use]
    pub const fn span(&self) -> u64 {
        self.last_use_offset.saturating_sub(self.def_offset)
    }

    /// Returns `true` if `offset` falls within the live range.
    #[must_use]
    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.def_offset && offset <= self.last_use_offset
    }

    /// Returns `true` if this lifetime overlaps with `other`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.def_offset <= other.last_use_offset && other.def_offset <= self.last_use_offset
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Full description of a local variable in a function version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarDescriptor {
    /// Original (possibly decompiler-assigned) name.
    pub name: String,
    /// Variable type.
    pub var_type: VarType,
    /// Storage scope.
    pub scope: VarScope,
    /// Stack offset (for local variables; 0 if not applicable).
    pub stack_offset: i64,
    /// Register name (for register variables; empty otherwise).
    pub register: String,
    /// Live range.
    pub lifetime: Option<VarLifetime>,
    /// Number of times the variable is read.
    pub read_count: u32,
    /// Number of times the variable is written.
    pub write_count: u32,
}

impl VarDescriptor {
    /// Create a minimal descriptor with only a name and type.
    #[must_use]
    pub fn new(name: impl Into<String>, var_type: VarType) -> Self {
        Self {
            name: name.into(),
            var_type,
            scope: VarScope::Local,
            stack_offset: 0,
            register: String::new(),
            lifetime: None,
            read_count: 0,
            write_count: 0,
        }
    }

    /// Is this variable read-only (`write_count == 0`)?
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.write_count == 0
    }

    /// Is this variable write-only (`read_count == 0`)?
    #[must_use]
    pub const fn is_write_only(&self) -> bool {
        self.read_count == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeChangeKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of type change detected for a variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeChangeKind {
    /// The type widened (e.g. i32 → i64).
    Widened,
    /// The type narrowed (e.g. i64 → i32).
    Narrowed,
    /// Signedness changed (e.g. i32 → u32).
    SignednessFlipped,
    /// Pointer depth changed.
    PointerDepthChanged { old_depth: usize, new_depth: usize },
    /// Entirely unrelated type change.
    Unrelated,
    /// Named type changed to a different named type.
    NamedChange { old: String, new: String },
}

impl TypeChangeKind {
    /// Classify the change from `old` to `new`.
    #[must_use]
    pub fn classify(old: &VarType, new: &VarType) -> Self {
        if old == new {
            return Self::Unrelated; // no change, shouldn't be called
        }
        // Pointer depth change
        let old_depth = pointer_depth(old);
        let new_depth = pointer_depth(new);
        if old_depth != new_depth {
            return Self::PointerDepthChanged { old_depth, new_depth };
        }

        // Size-based widening / narrowing
        if let (Some(os), Some(ns)) = (old.size_bytes(), new.size_bytes()) {
            if os < ns && old.is_integer() && new.is_integer() {
                return Self::Widened;
            }
            if os > ns && old.is_integer() && new.is_integer() {
                return Self::Narrowed;
            }
        }

        // Signedness flip
        let signedness_pairs: &[(VarType, VarType)] = &[
            (VarType::Int8, VarType::UInt8),
            (VarType::Int16, VarType::UInt16),
            (VarType::Int32, VarType::UInt32),
            (VarType::Int64, VarType::UInt64),
        ];
        for (signed, unsigned) in signedness_pairs {
            if (old == signed && new == unsigned) || (old == unsigned && new == signed) {
                return Self::SignednessFlipped;
            }
        }

        // Named change
        if let (VarType::Named(a), VarType::Named(b)) = (old, new) {
            return Self::NamedChange { old: a.clone(), new: b.clone() };
        }

        Self::Unrelated
    }
}

fn pointer_depth(t: &VarType) -> usize {
    match t {
        VarType::Pointer(inner) => 1 + pointer_depth(inner),
        _ => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarChange
// ─────────────────────────────────────────────────────────────────────────────

/// A single change detected for a variable between two function versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VarChange {
    /// Variable was added in version B.
    Added(VarDescriptor),
    /// Variable was removed in version B.
    Removed(VarDescriptor),
    /// Variable was renamed.
    Renamed {
        old_name: String,
        new_name: String,
        descriptor: VarDescriptor,
    },
    /// Variable type changed.
    TypeChanged {
        name: String,
        old_type: VarType,
        new_type: VarType,
        change_kind: TypeChangeKind,
    },
    /// Variable scope changed.
    ScopeChanged {
        name: String,
        old_scope: VarScope,
        new_scope: VarScope,
    },
    /// Variable stack offset moved.
    OffsetShifted {
        name: String,
        old_offset: i64,
        new_offset: i64,
    },
    /// Variable live range changed.
    LifetimeChanged {
        name: String,
        old_lifetime: Option<VarLifetime>,
        new_lifetime: Option<VarLifetime>,
    },
}

impl VarChange {
    /// Returns a human-readable description.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Added(v) => format!("+ {} ({})", v.name, v.var_type),
            Self::Removed(v) => format!("- {} ({})", v.name, v.var_type),
            Self::Renamed { old_name, new_name, .. } => {
                format!("renamed {old_name} → {new_name}")
            }
            Self::TypeChanged { name, old_type, new_type, change_kind } => {
                format!("type of {name}: {old_type} → {new_type} ({change_kind:?})")
            }
            Self::ScopeChanged { name, old_scope, new_scope } => {
                format!("scope of {name}: {old_scope} → {new_scope}")
            }
            Self::OffsetShifted { name, old_offset, new_offset } => {
                format!("offset of {name}: {old_offset:#x} → {new_offset:#x}")
            }
            Self::LifetimeChanged { name, .. } => {
                format!("lifetime of {name} changed")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VariableDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Diff of local variable usage between two versions of a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableDiff {
    /// Address of the function in version A.
    pub func_addr_a: u64,
    /// Address of the function in version B.
    pub func_addr_b: u64,
    /// All detected changes.
    pub changes: Vec<VarChange>,
    /// Total variables in version A.
    pub vars_in_a: usize,
    /// Total variables in version B.
    pub vars_in_b: usize,
}

impl VariableDiff {
    /// Returns the number of changes.
    #[must_use]
    pub const fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` if no variable changes were detected.
    #[must_use]
    pub const fn is_unchanged(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns only the rename changes.
    #[must_use]
    pub fn renames(&self) -> Vec<&VarChange> {
        self.changes
            .iter()
            .filter(|c| matches!(c, VarChange::Renamed { .. }))
            .collect()
    }

    /// Returns only the type-change changes.
    #[must_use]
    pub fn type_changes(&self) -> Vec<&VarChange> {
        self.changes
            .iter()
            .filter(|c| matches!(c, VarChange::TypeChanged { .. }))
            .collect()
    }

    /// Produce a multi-line text summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![format!(
            "VariableDiff [{:#x} ↔ {:#x}]: {} change(s), vars A={} B={}",
            self.func_addr_a,
            self.func_addr_b,
            self.changes.len(),
            self.vars_in_a,
            self.vars_in_b,
        )];
        for change in &self.changes {
            lines.push(format!("  {}", change.description()));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VariableDiffer
// ─────────────────────────────────────────────────────────────────────────────

/// Compares variable lists from two function versions and produces a [`VariableDiff`].
pub struct VariableDiffer {
    /// Minimum name-similarity ratio (0.0–1.0) to consider two variables
    /// a rename candidate rather than an add/remove pair.
    pub rename_threshold: f64,
}

impl Default for VariableDiffer {
    fn default() -> Self {
        Self { rename_threshold: 0.5 }
    }
}

impl VariableDiffer {
    /// Create a differ with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a differ with a custom rename threshold.
    #[must_use]
    pub const fn with_rename_threshold(threshold: f64) -> Self {
        Self { rename_threshold: threshold }
    }

    /// Diff two variable lists.
    #[must_use]
    pub fn diff(
        &self,
        func_addr_a: u64,
        func_addr_b: u64,
        vars_a: &[VarDescriptor],
        vars_b: &[VarDescriptor],
    ) -> VariableDiff {
        let vars_in_a = vars_a.len();
        let vars_in_b = vars_b.len();
        let mut changes: Vec<VarChange> = Vec::new();

        // Build name-keyed maps.
        let map_a: HashMap<&str, &VarDescriptor> =
            vars_a.iter().map(|v| (v.name.as_str(), v)).collect();
        let map_b: HashMap<&str, &VarDescriptor> =
            vars_b.iter().map(|v| (v.name.as_str(), v)).collect();

        // Detect changes for variables present in A.
        for v_a in vars_a {
            if let Some(&v_b) = map_b.get(v_a.name.as_str()) {
                // Same name — check for property changes.
                if v_a.var_type != v_b.var_type {
                    let kind = TypeChangeKind::classify(&v_a.var_type, &v_b.var_type);
                    changes.push(VarChange::TypeChanged {
                        name: v_a.name.clone(),
                        old_type: v_a.var_type.clone(),
                        new_type: v_b.var_type.clone(),
                        change_kind: kind,
                    });
                }
                if v_a.scope != v_b.scope {
                    changes.push(VarChange::ScopeChanged {
                        name: v_a.name.clone(),
                        old_scope: v_a.scope,
                        new_scope: v_b.scope,
                    });
                }
                if v_a.stack_offset != v_b.stack_offset
                    && v_a.scope == VarScope::Local
                    && v_b.scope == VarScope::Local
                {
                    changes.push(VarChange::OffsetShifted {
                        name: v_a.name.clone(),
                        old_offset: v_a.stack_offset,
                        new_offset: v_b.stack_offset,
                    });
                }
                if v_a.lifetime != v_b.lifetime {
                    changes.push(VarChange::LifetimeChanged {
                        name: v_a.name.clone(),
                        old_lifetime: v_a.lifetime.clone(),
                        new_lifetime: v_b.lifetime.clone(),
                    });
                }
            } else {
                // Not in B — check for rename.
                // `find_rename_candidate` skips candidates ALREADY matched by name,
                // i.e. those present in A. Passing `map_b` — which holds every
                // variable of B — made it skip every candidate and return None
                // for any input whatsoever.
                let rename = self.find_rename_candidate(v_a, vars_b, &map_a);
                if let Some(new_name) = rename {
                    changes.push(VarChange::Renamed {
                        old_name: v_a.name.clone(),
                        new_name,
                        descriptor: v_a.clone(),
                    });
                } else {
                    changes.push(VarChange::Removed(v_a.clone()));
                }
            }
        }

        // Detect variables added in B (not present in A or matched as rename target).
        let rename_targets: Vec<String> = changes
            .iter()
            .filter_map(|c| {
                if let VarChange::Renamed { new_name, .. } = c {
                    Some(new_name.clone())
                } else {
                    None
                }
            })
            .collect();

        for v_b in vars_b {
            if !map_a.contains_key(v_b.name.as_str())
                && !rename_targets.contains(&v_b.name)
            {
                changes.push(VarChange::Added(v_b.clone()));
            }
        }

        VariableDiff {
            func_addr_a,
            func_addr_b,
            changes,
            vars_in_a,
            vars_in_b,
        }
    }

    /// Find a rename candidate for `var_a` among `vars_b` not already in `map_a`.
    fn find_rename_candidate(
        &self,
        var_a: &VarDescriptor,
        vars_b: &[VarDescriptor],
        map_a: &HashMap<&str, &VarDescriptor>,
    ) -> Option<String> {
        let mut best_score = self.rename_threshold;
        let mut best_name: Option<String> = None;
        for v_b in vars_b {
            if map_a.contains_key(v_b.name.as_str()) {
                continue; // already matched
            }
            // Heuristic: same type + similar name prefix.
            if v_b.var_type == var_a.var_type {
                let sim = name_similarity(&var_a.name, &v_b.name);
                if sim > best_score {
                    best_score = sim;
                    best_name = Some(v_b.name.clone());
                }
            }
        }
        best_name
    }
}

/// Compute a simple name similarity score: Jaccard on bigrams.
fn name_similarity(a: &str, b: &str) -> f64 {
    let bigrams_a: std::collections::HashSet<[char; 2]> = a
        .chars()
        .collect::<Vec<_>>()
        .windows(2)
        .map(|w| [w[0], w[1]])
        .collect();
    let bigrams_b: std::collections::HashSet<[char; 2]> = b
        .chars()
        .collect::<Vec<_>>()
        .windows(2)
        .map(|w| [w[0], w[1]])
        .collect();
    if bigrams_a.is_empty() && bigrams_b.is_empty() {
        return if a == b { 1.0 } else { 0.0 };
    }
    if bigrams_a.is_empty() || bigrams_b.is_empty() {
        return 0.0;
    }
    let intersection = bigrams_a.intersection(&bigrams_b).count();
    let union = bigrams_a.union(&bigrams_b).count();
    if union == 0 {
        1.0
    } else {
        count_as_f64(intersection) / count_as_f64(union)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn int32() -> VarType { VarType::Int32 }
    fn int64() -> VarType { VarType::Int64 }
    fn uint32() -> VarType { VarType::UInt32 }

    fn var(name: &str, ty: VarType) -> VarDescriptor {
        VarDescriptor::new(name, ty)
    }

    #[test]
    fn test_no_changes() {
        let a = vec![var("x", int32()), var("y", int32())];
        let b = vec![var("x", int32()), var("y", int32())];
        let d = VariableDiffer::new().diff(0x1000, 0x1000, &a, &b);
        assert!(d.is_unchanged());
    }

    #[test]
    fn test_type_widened() {
        let a = vec![var("x", int32())];
        let b = vec![var("x", int64())];
        let d = VariableDiffer::new().diff(0, 0, &a, &b);
        assert_eq!(d.change_count(), 1);
        let tc = &d.changes[0];
        assert!(matches!(tc, VarChange::TypeChanged { change_kind: TypeChangeKind::Widened, .. }));
    }

    #[test]
    fn test_type_signedness_flipped() {
        let a = vec![var("n", int32())];
        let b = vec![var("n", uint32())];
        let d = VariableDiffer::new().diff(0, 0, &a, &b);
        let tc = &d.changes[0];
        assert!(matches!(
            tc,
            VarChange::TypeChanged { change_kind: TypeChangeKind::SignednessFlipped, .. }
        ));
    }

    #[test]
    fn test_variable_added() {
        let a = vec![var("x", int32())];
        let b = vec![var("x", int32()), var("new_var", int64())];
        let d = VariableDiffer::new().diff(0, 0, &a, &b);
        assert!(d.changes.iter().any(|c| matches!(c, VarChange::Added(_))));
    }

    #[test]
    fn test_variable_removed() {
        let a = vec![var("x", int32()), var("old_var", int64())];
        let b = vec![var("x", int32())];
        let d = VariableDiffer::new().diff(0, 0, &a, &b);
        assert!(d.changes.iter().any(|c| matches!(c, VarChange::Removed(_))));
    }

    #[test]
    fn test_scope_change() {
        let mut v_a = var("p", int32());
        v_a.scope = VarScope::Local;
        let mut v_b = var("p", int32());
        v_b.scope = VarScope::Register;
        let d = VariableDiffer::new().diff(0, 0, &[v_a], &[v_b]);
        assert!(d.changes.iter().any(|c| matches!(c, VarChange::ScopeChanged { .. })));
    }

    #[test]
    fn test_offset_shift() {
        let mut v_a = var("buf", int32());
        v_a.stack_offset = -8;
        let mut v_b = var("buf", int32());
        v_b.stack_offset = -16;
        let d = VariableDiffer::new().diff(0, 0, &[v_a], &[v_b]);
        assert!(d.changes.iter().any(|c| matches!(c, VarChange::OffsetShifted { .. })));
    }

    #[test]
    fn test_lifetime_change() {
        let mut v_a = var("t", int32());
        v_a.lifetime = Some(VarLifetime::new(0, 10));
        let mut v_b = var("t", int32());
        v_b.lifetime = Some(VarLifetime::new(0, 20));
        let d = VariableDiffer::new().diff(0, 0, &[v_a], &[v_b]);
        assert!(d.changes.iter().any(|c| matches!(c, VarChange::LifetimeChanged { .. })));
    }

    #[test]
    fn test_var_type_display() {
        assert_eq!(VarType::Int32.display(), "i32");
        assert_eq!(VarType::Pointer(Box::new(VarType::UInt8)).display(), "*u8");
        assert_eq!(VarType::Array(Box::new(VarType::Int8), 4).display(), "[i8; 4]");
    }

    #[test]
    fn test_var_type_is_integer() {
        assert!(VarType::Int32.is_integer());
        assert!(!VarType::Float64.is_integer());
        assert!(!VarType::Pointer(Box::new(VarType::Int32)).is_integer());
    }

    #[test]
    fn test_var_type_size_bytes() {
        assert_eq!(VarType::Int32.size_bytes(), Some(4));
        assert_eq!(VarType::Int64.size_bytes(), Some(8));
        assert_eq!(VarType::Bool.size_bytes(), Some(1));
        assert_eq!(VarType::Unknown.size_bytes(), None);
    }

    #[test]
    fn test_var_lifetime_span() {
        let lt = VarLifetime::new(4, 20);
        assert_eq!(lt.span(), 16);
    }

    #[test]
    fn test_var_lifetime_contains() {
        let lt = VarLifetime::new(10, 20);
        assert!(lt.contains(15));
        assert!(!lt.contains(5));
        assert!(!lt.contains(25));
    }

    #[test]
    fn test_var_lifetime_overlaps() {
        let lt1 = VarLifetime::new(0, 10);
        let lt2 = VarLifetime::new(8, 20);
        let lt3 = VarLifetime::new(15, 25);
        assert!(lt1.overlaps(&lt2));
        assert!(!lt1.overlaps(&lt3));
    }

    #[test]
    fn test_type_change_kind_pointer_depth() {
        let old = VarType::Int32;
        let new = VarType::Pointer(Box::new(VarType::Int32));
        let k = TypeChangeKind::classify(&old, &new);
        assert!(matches!(k, TypeChangeKind::PointerDepthChanged { .. }));
    }

    #[test]
    fn test_diff_summary_contains_changes() {
        let a = vec![var("x", int32())];
        let b = vec![var("x", int64())];
        let d = VariableDiffer::new().diff(0x1000, 0x2000, &a, &b);
        let s = d.summary();
        assert!(s.contains("VariableDiff"));
        assert!(s.contains("1 change"));
    }

    #[test]
    fn test_var_change_description() {
        let c = VarChange::Added(var("new_v", int32()));
        assert!(c.description().contains("new_v"));
    }

    #[test]
    fn test_is_read_only() {
        let mut v = var("c", int32());
        v.read_count = 3;
        v.write_count = 0;
        assert!(v.is_read_only());
    }

    #[test]
    fn test_renames_filter() {
        let d = VariableDiff {
            func_addr_a: 0,
            func_addr_b: 0,
            changes: vec![
                VarChange::Renamed { old_name: "a".into(), new_name: "b".into(), descriptor: var("a", int32()) },
                VarChange::Added(var("c", int32())),
            ],
            vars_in_a: 1,
            vars_in_b: 2,
        };
        assert_eq!(d.renames().len(), 1);
        assert_eq!(d.type_changes().len(), 0);
    }
}
