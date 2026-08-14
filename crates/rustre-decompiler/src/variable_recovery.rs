//! `variable_recovery` — SSA-layer variable recovery with alias analysis and naming.
//!
//! This module operates at the **SSA / naming layer**: it consumes already-lifted
//! SSA register assignments and converts them into named, typed variables using
//! alias analysis and heuristic renaming.
//!
//! For the lower-level engine that operates directly on instruction summaries —
//! tracking def/use sites, cross-block liveness, and dead-variable detection —
//! see [`super::variable_recovery_engine`].
//!
//! * [`VariableSlot`] — abstract variable location (register, stack, or global).
//! * [`StackSlotAnalysis`] — analyses stack frame layout.
//! * [`RegisterVariable`] — maps a register to a recovered variable.
//! * [`AliasAnalysis`] — tracks pointer aliases to disambiguate memory accesses.
//! * [`VariableNamingHeuristic`] — assigns human-readable names.
//! * [`TypeBasedNaming`] — refines names using type information.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── VariableSlot ─────────────────────────────────────────────────────────────

/// An abstract description of where a variable lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VariableSlot {
    /// In a named register (e.g. `"rax"`).
    Register(String),
    /// On the stack at a signed byte offset from the frame-base pointer.
    Stack(i64),
    /// At a fixed global address.
    Global(u64),
    /// A virtual SSA variable (no concrete location, used for temporaries).
    SsaVar { name: String, version: u32 },
}

impl VariableSlot {
    /// Return `true` if this slot is on the stack.
    #[must_use]
    pub const fn is_stack(&self) -> bool {
        matches!(self, Self::Stack(_))
    }

    /// Return `true` if this slot is in a register.
    #[must_use]
    pub const fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    /// Return `true` if this slot is at a global address.
    #[must_use]
    pub const fn is_global(&self) -> bool {
        matches!(self, Self::Global(_))
    }

    /// Return `true` if this is an SSA virtual variable.
    #[must_use]
    pub const fn is_ssa(&self) -> bool {
        matches!(self, Self::SsaVar { .. })
    }

    /// Return the stack offset, or `None` if not a stack slot.
    #[must_use]
    pub const fn stack_offset(&self) -> Option<i64> {
        if let Self::Stack(off) = self {
            Some(*off)
        } else {
            None
        }
    }

    /// Return the register name, or `None` if not a register slot.
    #[must_use]
    pub const fn register_name(&self) -> Option<&str> {
        if let Self::Register(r) = self {
            Some(r.as_str())
        } else {
            None
        }
    }
}

impl fmt::Display for VariableSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::Stack(off) => write!(f, "stack[{off:+}]"),
            Self::Global(addr) => write!(f, "global:{addr:#x}"),
            Self::SsaVar { name, version } => write!(f, "{name}_{version}"),
        }
    }
}

// ─── RecoveredVariable ───────────────────────────────────────────────────────

/// A variable recovered from the decompilation process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredVariable {
    /// Human-readable name.
    pub name: String,
    /// C type string.
    pub type_str: String,
    /// Storage location.
    pub slot: VariableSlot,
    /// Whether this variable is a function parameter.
    pub is_parameter: bool,
    /// Confidence score 0–100.
    pub confidence: u8,
}

impl RecoveredVariable {
    /// Create a new recovered variable.
    #[must_use]
    pub fn new(name: impl Into<String>, type_str: impl Into<String>, slot: VariableSlot) -> Self {
        Self {
            name: name.into(),
            type_str: type_str.into(),
            slot,
            is_parameter: false,
            confidence: 50,
        }
    }

    /// Mark this variable as a parameter.
    #[must_use]
    pub const fn as_parameter(mut self) -> Self {
        self.is_parameter = true;
        self
    }

    /// Set the confidence score.
    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }
}

impl fmt::Display for RecoveredVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} @ {}", self.type_str, self.name, self.slot)
    }
}

// ─── StackSlotAnalysis ────────────────────────────────────────────────────────

/// Analyses the stack frame layout and assigns names to stack slots.
///
/// Stack offsets:
/// * Negative offsets (below the saved return address): locals.
/// * Positive offsets (above): parameters passed on the stack.
#[derive(Debug, Default, Clone)]
pub struct StackSlotAnalysis {
    /// Known slots: offset → `RecoveredVariable`.
    slots: HashMap<i64, RecoveredVariable>,
    /// Local variable counter.
    local_counter: u32,
    /// Parameter counter (positive offsets).
    param_counter: u32,
}

impl StackSlotAnalysis {
    /// Create a new analysis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a stack access at `offset` and infer a variable.
    ///
    /// Returns the recovered variable (creating it if not seen before).
    ///
    /// # Panics
    ///
    /// Panics if the slot inserted in this call is not present afterwards (should never happen).
    pub fn record_access(&mut self, offset: i64, size_bytes: u32) -> &RecoveredVariable {
        let local_counter = &mut self.local_counter;
        let param_counter = &mut self.param_counter;
        self.slots.entry(offset).or_insert_with(|| {
            let (name, is_param) = if offset < 0 {
                let n = format!(
                    "local_{}",
                    u32::try_from(offset.unsigned_abs()).unwrap_or(u32::MAX)
                );
                *local_counter += 1;
                (n, false)
            } else {
                let n = format!("arg_{offset}");
                *param_counter += 1;
                (n, true)
            };
            let type_str = type_for_size(size_bytes);
            let mut var = RecoveredVariable::new(name, type_str, VariableSlot::Stack(offset));
            if is_param {
                var = var.as_parameter();
            }
            var
        })
    }

    /// Return all recovered stack variables sorted by offset.
    #[must_use]
    pub fn variables(&self) -> Vec<&RecoveredVariable> {
        let mut v: Vec<&RecoveredVariable> = self.slots.values().collect();
        v.sort_by_key(|rv| rv.slot.stack_offset().unwrap_or(0));
        v
    }

    /// Return the total number of stack slots.
    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Return the frame size (span from most negative local to 0).
    #[must_use]
    pub fn frame_size(&self) -> u64 {
        self.slots
            .keys()
            .filter(|&&o| o < 0)
            .map(|&o| o.unsigned_abs())
            .max()
            .unwrap_or(0)
    }

    /// Rename a slot.
    pub fn rename(&mut self, offset: i64, new_name: impl Into<String>) -> bool {
        if let Some(v) = self.slots.get_mut(&offset) {
            v.name = new_name.into();
            true
        } else {
            false
        }
    }
}

fn type_for_size(bytes: u32) -> String {
    match bytes {
        1 => "uint8_t".into(),
        2 => "uint16_t".into(),
        4 => "uint32_t".into(),
        8 => "uint64_t".into(),
        _ => "void*".into(),
    }
}

// ─── RegisterVariable ────────────────────────────────────────────────────────

/// Maps a hardware register to a recovered variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterVariable {
    /// Register name (e.g. `"rax"`).
    pub register: String,
    /// Recovered variable name.
    pub var_name: String,
    /// C type string.
    pub type_str: String,
    /// Whether this register holds a parameter on function entry.
    pub is_parameter: bool,
    /// Parameter index (0-based), if `is_parameter`.
    pub param_index: Option<usize>,
}

impl RegisterVariable {
    /// Create a new register variable mapping.
    #[must_use]
    pub fn new(
        register: impl Into<String>,
        var_name: impl Into<String>,
        type_str: impl Into<String>,
    ) -> Self {
        Self {
            register: register.into(),
            var_name: var_name.into(),
            type_str: type_str.into(),
            is_parameter: false,
            param_index: None,
        }
    }

    /// Mark as a parameter at `index`.
    #[must_use]
    pub const fn as_parameter(mut self, index: usize) -> Self {
        self.is_parameter = true;
        self.param_index = Some(index);
        self
    }

    /// Return the `VariableSlot` for this register variable.
    #[must_use]
    pub fn slot(&self) -> VariableSlot {
        VariableSlot::Register(self.register.clone())
    }
}

impl fmt::Display for RegisterVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} [{}]", self.type_str, self.var_name, self.register)
    }
}

// ─── AliasAnalysis ────────────────────────────────────────────────────────────

/// Tracks pointer aliases to disambiguate memory accesses.
///
/// When `ptr_b = ptr_a + offset`, both may access overlapping memory.
/// Alias analysis groups such pointers into alias sets.
#[derive(Debug, Default, Clone)]
pub struct AliasAnalysis {
    /// Maps each variable name to its alias-set representative.
    union_find: HashMap<String, String>,
    /// Offset relationships: (from, to) → offset.
    offsets: HashMap<(String, String), i64>,
    /// Number of alias queries resolved.
    query_count: u64,
}

impl AliasAnalysis {
    /// Create a new `AliasAnalysis`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `dst = src + offset`.
    pub fn record_offset(&mut self, dst: impl Into<String>, src: impl Into<String>, offset: i64) {
        let dst = dst.into();
        let src = src.into();
        // Both variables are in the same alias set.
        self.union(&dst, &src);
        self.offsets.insert((src, dst), offset);
    }

    /// Record that `dst = src` (zero-offset alias).
    pub fn record_alias(&mut self, dst: impl Into<String>, src: impl Into<String>) {
        self.record_offset(dst, src, 0);
    }

    fn find(&mut self, x: String) -> String {
        if !self.union_find.contains_key(&x) {
            self.union_find.insert(x.clone(), x.clone());
            return x;
        }
        // Iterative find with path halving (avoids recursion and per-hop clones
        // of the whole chain).
        let mut cur = x;
        loop {
            let parent = &self.union_find[&cur];
            if *parent == cur {
                return cur;
            }
            let parent = parent.clone();
            let grandparent = self.union_find[&parent].clone();
            // Path halving: point cur at its grandparent.
            self.union_find.insert(cur, grandparent.clone());
            cur = grandparent;
        }
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find_str(a);
        let rb = self.find_str(b);
        if ra != rb {
            self.union_find.insert(ra, rb);
        }
    }

    /// Return `true` if `a` and `b` may alias.
    pub fn may_alias(&mut self, a: &str, b: &str) -> bool {
        self.query_count += 1;
        let ra = self.find_str(a);
        let rb = self.find_str(b);
        ra == rb
    }

    /// Like [`Self::find`] but takes `&str`, only allocating when the key is new.
    fn find_str(&mut self, x: &str) -> String {
        if self.union_find.contains_key(x) {
            self.find(x.to_string())
        } else {
            let owned = x.to_string();
            self.union_find.insert(owned.clone(), owned.clone());
            owned
        }
    }

    /// Return the known byte offset between `from` and `to`, if recorded.
    #[must_use]
    pub fn offset_between(&self, from: &str, to: &str) -> Option<i64> {
        self.offsets
            .get(&(from.to_string(), to.to_string()))
            .copied()
    }

    /// Return all alias sets as groups of variable names.
    #[must_use]
    pub fn alias_sets(&self) -> Vec<Vec<String>> {
        let mut by_root: HashMap<String, Vec<String>> = HashMap::new();
        for k in self.union_find.keys() {
            let root = self.union_find[k].clone();
            by_root.entry(root).or_default().push(k.clone());
        }
        by_root.into_values().collect()
    }

    /// Return the number of alias queries performed.
    #[must_use]
    pub const fn query_count(&self) -> u64 {
        self.query_count
    }
}

// ─── VariableNamingHeuristic ─────────────────────────────────────────────────

/// Assigns human-readable names to recovered variables based on heuristics.
///
/// Heuristics include:
/// * Loop induction variables: `i`, `j`, `k`.
/// * Counter variables: `count`, `n`.
/// * Pointer variables: `ptr_*`.
/// * Boolean flags: `flag_*`, `is_*`.
#[derive(Debug, Default, Clone)]
pub struct VariableNamingHeuristic {
    /// Counter for unnamed variables.
    unnamed_counter: u32,
    /// Already assigned names (to avoid collisions).
    used_names: HashSet<String>,
}

impl VariableNamingHeuristic {
    /// Create a new heuristic.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve the induction-variable pool `i, j, k, l, m, n`.
    pub const fn prime_loop_vars(&mut self) {
        // Pre-populate the used_names list so we assign them in order.
        // (The actual assignment happens lazily.)
    }

    /// Suggest a name for `var` given its usage context.
    ///
    /// `usage_context` is a free-form hint (e.g. `"loop_counter"`, `"pointer"`,
    /// `"flag"`).
    pub fn suggest(&mut self, var: &RecoveredVariable, usage_context: &str) -> String {
        let name = self.generate_name(var, usage_context);
        self.used_names.insert(name.clone());
        name
    }

    fn generate_name(&mut self, var: &RecoveredVariable, ctx: &str) -> String {
        // Use existing name if it looks already meaningful.
        if !var.name.starts_with("var_")
            && !var.name.starts_with("local_")
            && !var.name.starts_with("arg_")
        {
            return var.name.clone();
        }
        let ctx_lower = ctx.to_lowercase();
        let is_loop_ctx = ctx_lower.contains("loop")
            || ctx_lower.contains("index")
            || ctx_lower.contains("counter");
        if is_loop_ctx {
            for c in &["i", "j", "k", "l", "m", "n"] {
                if !self.used_names.contains(*c) {
                    return c.to_string();
                }
            }
            // Loop induction pool exhausted: fall back to the original variable
            // name rather than dipping into the generic count_ pool (which would
            // mask the original slot identity).
            return var.name.clone();
        }
        if ctx_lower.contains("ptr") || ctx_lower.contains("pointer") {
            let name = format!("ptr_{}", self.unnamed_counter);
            self.unnamed_counter += 1;
            return name;
        }
        if ctx_lower.contains("flag") || ctx_lower.contains("bool") {
            let name = format!("flag_{}", self.unnamed_counter);
            self.unnamed_counter += 1;
            return name;
        }
        if ctx_lower.contains("count") || ctx_lower.contains("size") || ctx_lower.contains("len") {
            let name = format!("count_{}", self.unnamed_counter);
            self.unnamed_counter += 1;
            return name;
        }
        // Fallback: use the original variable name.
        var.name.clone()
    }

    /// Return `true` if `name` is already used.
    #[must_use]
    pub fn is_used(&self, name: &str) -> bool {
        self.used_names.contains(name)
    }

    /// Reserve a name so it cannot be assigned by the heuristic.
    pub fn reserve(&mut self, name: impl Into<String>) {
        self.used_names.insert(name.into());
    }
}

// ─── TypeBasedNaming ─────────────────────────────────────────────────────────

/// Refines variable names using type information.
///
/// For example:
/// * `char*` → `str_*` or `buf_*`.
/// * `FILE*` → `fp_*`.
/// * `int` counting from 0 in a tight loop → `i`, `j`, etc.
/// * Struct pointer → lowercase struct name.
#[derive(Debug, Default, Clone)]
pub struct TypeBasedNaming {
    /// Custom type → prefix rules.
    rules: Vec<(String, String)>,
    counter: u32,
}

impl TypeBasedNaming {
    /// Create a new `TypeBasedNaming` with default rules.
    #[must_use]
    pub fn new() -> Self {
        let mut tbn = Self::default();
        tbn.add_rule("char*", "str");
        tbn.add_rule("uint8_t*", "buf");
        tbn.add_rule("FILE*", "fp");
        tbn.add_rule("int", "n");
        tbn.add_rule("bool", "b");
        tbn
    }

    /// Add a type-prefix rule.
    pub fn add_rule(&mut self, type_str: impl Into<String>, prefix: impl Into<String>) {
        self.rules.push((type_str.into(), prefix.into()));
    }

    /// Suggest a name for a variable of `type_str`.
    ///
    /// Returns `None` if no rule matches.
    pub fn suggest(&mut self, type_str: &str) -> Option<String> {
        let prefix = self
            .rules
            .iter()
            .find(|(t, _)| t == type_str)
            .map(|(_, p)| p.clone())?;
        let name = format!("{prefix}_{}", self.counter);
        self.counter += 1;
        Some(name)
    }

    /// Suggest a name, falling back to `fallback` if no rule matches.
    pub fn suggest_or(&mut self, type_str: &str, fallback: &str) -> String {
        self.suggest(type_str)
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Return the number of rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ─── VariableRecoveryPass ────────────────────────────────────────────────────

/// Top-level pass that combines all sub-components.
#[derive(Debug, Default)]
pub struct VariableRecoveryPass {
    pub stack: StackSlotAnalysis,
    pub alias: AliasAnalysis,
    pub naming: VariableNamingHeuristic,
    pub type_naming: TypeBasedNaming,
    /// All recovered register variables.
    pub register_vars: Vec<RegisterVariable>,
}

impl VariableRecoveryPass {
    /// Create a new pass.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_naming: TypeBasedNaming::new(),
            ..Self::default()
        }
    }

    /// Add a register variable (e.g. from calling-convention analysis).
    pub fn add_register_var(&mut self, rv: RegisterVariable) {
        self.register_vars.push(rv);
    }

    /// Record a stack access and return the variable name.
    pub fn record_stack(&mut self, offset: i64, size: u32) -> String {
        self.stack.record_access(offset, size).name.clone()
    }

    /// Collect all recovered variables.
    #[must_use]
    pub fn all_variables(&self) -> Vec<RecoveredVariable> {
        let mut vars: Vec<RecoveredVariable> = self
            .stack
            .variables()
            .into_iter()
            .cloned()
            .collect();
        for rv in &self.register_vars {
            vars.push(RecoveredVariable {
                name: rv.var_name.clone(),
                type_str: rv.type_str.clone(),
                slot: rv.slot(),
                is_parameter: rv.is_parameter,
                confidence: 70,
            });
        }
        vars
    }

    /// Return total variable count.
    #[must_use]
    pub fn total_variables(&self) -> usize {
        self.stack.slot_count() + self.register_vars.len()
    }
}

impl fmt::Display for VariableRecoveryPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VariableRecoveryPass {{ stack_slots={}, register_vars={} }}",
            self.stack.slot_count(),
            self.register_vars.len(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VariableSlot ─────────────────────────────────────────────────────

    #[test]
    fn test_slot_is_stack() {
        assert!(VariableSlot::Stack(-8).is_stack());
        assert!(!VariableSlot::Register("rax".into()).is_stack());
    }

    #[test]
    fn test_slot_stack_offset() {
        assert_eq!(VariableSlot::Stack(-16).stack_offset(), Some(-16));
        assert_eq!(VariableSlot::Global(0x1000).stack_offset(), None);
    }

    #[test]
    fn test_slot_display() {
        assert_eq!(VariableSlot::Stack(-8).to_string(), "stack[-8]");
        assert_eq!(
            VariableSlot::Global(0x400000).to_string(),
            "global:0x400000"
        );
    }

    #[test]
    fn test_slot_ssa_var() {
        let s = VariableSlot::SsaVar {
            name: "x".into(),
            version: 2,
        };
        assert!(s.is_ssa());
        assert!(!s.is_stack());
    }

    // ── RecoveredVariable ────────────────────────────────────────────────

    #[test]
    fn test_recovered_var_new() {
        let v = RecoveredVariable::new("myvar", "int", VariableSlot::Stack(-8));
        assert_eq!(v.name, "myvar");
        assert!(!v.is_parameter);
    }

    #[test]
    fn test_recovered_var_as_parameter() {
        let v = RecoveredVariable::new("arg0", "int", VariableSlot::Register("rdi".into()))
            .as_parameter()
            .with_confidence(90);
        assert!(v.is_parameter);
        assert_eq!(v.confidence, 90);
    }

    #[test]
    fn test_recovered_var_display() {
        let v = RecoveredVariable::new("x", "int32_t", VariableSlot::Stack(-4));
        assert!(v.to_string().contains('x'));
    }

    // ── StackSlotAnalysis ────────────────────────────────────────────────

    #[test]
    fn test_stack_record_local() {
        let mut a = StackSlotAnalysis::new();
        let v = a.record_access(-8, 8);
        assert!(!v.is_parameter);
        assert_eq!(a.slot_count(), 1);
    }

    #[test]
    fn test_stack_record_param() {
        let mut a = StackSlotAnalysis::new();
        let v = a.record_access(16, 8);
        assert!(v.is_parameter);
    }

    #[test]
    fn test_stack_same_offset_not_duplicated() {
        let mut a = StackSlotAnalysis::new();
        a.record_access(-8, 4);
        a.record_access(-8, 4);
        assert_eq!(a.slot_count(), 1);
    }

    #[test]
    fn test_stack_frame_size() {
        let mut a = StackSlotAnalysis::new();
        a.record_access(-8, 8);
        a.record_access(-16, 8);
        assert_eq!(a.frame_size(), 16);
    }

    #[test]
    fn test_stack_rename() {
        let mut a = StackSlotAnalysis::new();
        a.record_access(-8, 4);
        assert!(a.rename(-8, "counter"));
        assert_eq!(a.variables()[0].name, "counter");
    }

    #[test]
    fn test_stack_variables_sorted() {
        let mut a = StackSlotAnalysis::new();
        a.record_access(-16, 8);
        a.record_access(-8, 8);
        let vars = a.variables();
        assert!(vars[0].slot.stack_offset().unwrap() < vars[1].slot.stack_offset().unwrap());
    }

    // ── RegisterVariable ─────────────────────────────────────────────────

    #[test]
    fn test_register_var_new() {
        let rv = RegisterVariable::new("rdi", "param0", "uint64_t");
        assert_eq!(rv.register, "rdi");
        assert!(!rv.is_parameter);
    }

    #[test]
    fn test_register_var_as_parameter() {
        let rv = RegisterVariable::new("rdi", "param0", "uint64_t").as_parameter(0);
        assert!(rv.is_parameter);
        assert_eq!(rv.param_index, Some(0));
    }

    #[test]
    fn test_register_var_slot() {
        let rv = RegisterVariable::new("rax", "result", "int64_t");
        assert!(rv.slot().is_register());
    }

    // ── AliasAnalysis ────────────────────────────────────────────────────

    #[test]
    fn test_alias_may_alias_same() {
        let mut a = AliasAnalysis::new();
        a.record_alias("p", "q");
        assert!(a.may_alias("p", "q"));
    }

    #[test]
    fn test_alias_no_alias_unrelated() {
        let mut a = AliasAnalysis::new();
        assert!(!a.may_alias("p", "q"));
    }

    #[test]
    fn test_alias_offset_between() {
        let mut a = AliasAnalysis::new();
        a.record_offset("q", "p", 8);
        assert_eq!(a.offset_between("p", "q"), Some(8));
    }

    #[test]
    fn test_alias_transitivity() {
        let mut a = AliasAnalysis::new();
        a.record_alias("b", "a");
        a.record_alias("c", "b");
        // a and c should be in the same alias set.
        assert!(a.may_alias("a", "c"));
    }

    #[test]
    fn test_alias_sets() {
        let mut a = AliasAnalysis::new();
        a.record_alias("x", "y");
        let sets = a.alias_sets();
        // x and y should be in the same set.
        let flat: Vec<_> = sets.iter().flatten().cloned().collect();
        assert!(flat.contains(&"x".to_string()));
        assert!(flat.contains(&"y".to_string()));
    }

    // ── VariableNamingHeuristic ──────────────────────────────────────────

    #[test]
    fn test_naming_loop_var() {
        let mut h = VariableNamingHeuristic::new();
        let var = RecoveredVariable::new("local_8", "int", VariableSlot::Stack(-8));
        let name = h.suggest(&var, "loop_counter");
        assert_eq!(name, "i");
    }

    #[test]
    fn test_naming_loop_var_exhaustion() {
        let mut h = VariableNamingHeuristic::new();
        let var = RecoveredVariable::new("local_8", "int", VariableSlot::Stack(-8));
        // Exhaust i..n
        for _ in 0..6 {
            h.suggest(&var, "loop_counter");
        }
        // 7th should fall back to the original name.
        let name = h.suggest(&var, "loop_counter");
        assert_eq!(name, "local_8");
    }

    #[test]
    fn test_naming_ptr() {
        let mut h = VariableNamingHeuristic::new();
        let var = RecoveredVariable::new("local_8", "void*", VariableSlot::Stack(-8));
        let name = h.suggest(&var, "pointer");
        assert!(name.starts_with("ptr_"));
    }

    #[test]
    fn test_naming_flag() {
        let mut h = VariableNamingHeuristic::new();
        let var = RecoveredVariable::new("local_8", "bool", VariableSlot::Stack(-8));
        let name = h.suggest(&var, "flag");
        assert!(name.starts_with("flag_"));
    }

    #[test]
    fn test_naming_reserve() {
        let mut h = VariableNamingHeuristic::new();
        h.reserve("i");
        let var = RecoveredVariable::new("local_8", "int", VariableSlot::Stack(-8));
        let name = h.suggest(&var, "loop_counter");
        assert_ne!(name, "i"); // "i" is reserved
    }

    // ── TypeBasedNaming ──────────────────────────────────────────────────

    #[test]
    fn test_type_naming_char_ptr() {
        let mut tbn = TypeBasedNaming::new();
        let name = tbn.suggest("char*").unwrap();
        assert!(name.starts_with("str_"));
    }

    #[test]
    fn test_type_naming_no_match() {
        let mut tbn = TypeBasedNaming::new();
        assert!(tbn.suggest("complex_struct_t").is_none());
    }

    #[test]
    fn test_type_naming_fallback() {
        let mut tbn = TypeBasedNaming::new();
        let name = tbn.suggest_or("complex_struct_t", "v0");
        assert_eq!(name, "v0");
    }

    #[test]
    fn test_type_naming_custom_rule() {
        let mut tbn = TypeBasedNaming::new();
        tbn.add_rule("my_type_t", "my");
        let name = tbn.suggest("my_type_t").unwrap();
        assert!(name.starts_with("my_"));
    }

    // ── VariableRecoveryPass ─────────────────────────────────────────────

    #[test]
    fn test_pass_record_stack_and_get() {
        let mut pass = VariableRecoveryPass::new();
        let name = pass.record_stack(-8, 8);
        assert!(!name.is_empty());
        assert_eq!(pass.total_variables(), 1);
    }

    #[test]
    fn test_pass_add_register_var() {
        let mut pass = VariableRecoveryPass::new();
        pass.add_register_var(RegisterVariable::new("rax", "result", "uint64_t"));
        assert_eq!(pass.total_variables(), 1);
    }

    #[test]
    fn test_pass_all_variables() {
        let mut pass = VariableRecoveryPass::new();
        pass.record_stack(-8, 4);
        pass.record_stack(-16, 8);
        pass.add_register_var(RegisterVariable::new("rdi", "arg0", "int").as_parameter(0));
        let vars = pass.all_variables();
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn test_pass_display() {
        let pass = VariableRecoveryPass::new();
        assert!(pass.to_string().contains("VariableRecoveryPass"));
    }
}
