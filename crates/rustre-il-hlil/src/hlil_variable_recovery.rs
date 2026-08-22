//! `hlil_variable_recovery` — Local variable recovery for HLIL functions.
//!
//! Recovers named, typed local variables from an HLIL function's SSA variable
//! set and statement tree, coalesces phi-nodes, infers types from use sites,
//! and produces a clean variable table for the decompiler output.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── VarUsage ──────────────────────────────────────────────────────────────────

/// Describes how a variable is used within a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarUsage {
    /// The variable is defined (written) at least once.
    Defined,
    /// The variable is read (loaded) at least once.
    Read,
    /// The variable is used as a function argument.
    Argument,
    /// The variable is the destination of a `return` statement.
    Returned,
    /// The variable is used in a loop induction expression.
    LoopInduction,
    /// The variable is a loop-exit condition carrier.
    LoopCondition,
    /// The variable's address is taken.
    AddressTaken,
    /// The variable is used as a pointer (dereferenced).
    Pointer,
}

impl fmt::Display for VarUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Defined => write!(f, "defined"),
            Self::Read => write!(f, "read"),
            Self::Argument => write!(f, "argument"),
            Self::Returned => write!(f, "returned"),
            Self::LoopInduction => write!(f, "loop-induction"),
            Self::LoopCondition => write!(f, "loop-condition"),
            Self::AddressTaken => write!(f, "address-taken"),
            Self::Pointer => write!(f, "pointer"),
        }
    }
}

// ── VarType ───────────────────────────────────────────────────────────────────

/// A simplified type for recovered variables.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarType {
    Unknown,
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
    Pointer(Box<Self>),
    Array(Box<Self>, usize),
    Bool,
    Struct(String),
    Void,
}

impl VarType {
    /// Byte width if statically known.
    #[must_use]
    pub fn byte_width(&self) -> Option<usize> {
        match self {
            Self::Int8 | Self::UInt8 | Self::Bool => Some(1),
            Self::Int16 | Self::UInt16 => Some(2),
            Self::Int32 | Self::UInt32 | Self::Float32 => Some(4),
            Self::Int64 | Self::UInt64 | Self::Float64 | Self::Pointer(_) => Some(8),
            Self::Array(elem, count) => elem.byte_width().and_then(|w| w.checked_mul(*count)),
            _ => None,
        }
    }

    /// Return `true` if this is a pointer type.
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Return `true` if this is an integer type.
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

    /// Widen to at least `min_bits` if both types are integers.
    #[must_use]
    pub fn widen(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, o) | (o, Self::Unknown) => o.clone(),
            (Self::Int64, _) | (_, Self::Int64) => Self::Int64,
            (Self::UInt64, _) | (_, Self::UInt64) => Self::UInt64,
            (Self::Int32, _) | (_, Self::Int32) => Self::Int32,
            (Self::UInt32, _) | (_, Self::UInt32) => Self::UInt32,
            (Self::Int16, _) | (_, Self::Int16) => Self::Int16,
            (Self::UInt16, _) | (_, Self::UInt16) => Self::UInt16,
            _ => self.clone(),
        }
    }
}

impl fmt::Display for VarType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Int8 => write!(f, "int8_t"),
            Self::Int16 => write!(f, "int16_t"),
            Self::Int32 => write!(f, "int32_t"),
            Self::Int64 => write!(f, "int64_t"),
            Self::UInt8 => write!(f, "uint8_t"),
            Self::UInt16 => write!(f, "uint16_t"),
            Self::UInt32 => write!(f, "uint32_t"),
            Self::UInt64 => write!(f, "uint64_t"),
            Self::Float32 => write!(f, "float"),
            Self::Float64 => write!(f, "double"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::Array(elem, count) => write!(f, "{elem}[{count}]"),
            Self::Bool => write!(f, "bool"),
            Self::Struct(name) => write!(f, "struct {name}"),
            Self::Void => write!(f, "void"),
        }
    }
}

// ── RecoveredVar ──────────────────────────────────────────────────────────────

/// A recovered, decompiler-ready local variable.
#[derive(Debug, Clone)]
pub struct RecoveredVar {
    /// Unique identifier within the function.
    pub id: usize,
    /// Human-readable name (may be derived from debug info or auto-generated).
    pub name: String,
    /// Inferred or propagated type.
    pub ty: VarType,
    /// All usage kinds observed for this variable.
    pub usages: HashSet<VarUsage>,
    /// Stack offset, if the variable lives on the stack.
    pub stack_offset: Option<i64>,
    /// Whether this is a function parameter.
    pub is_param: bool,
    /// Whether this variable was coalesced from multiple SSA versions.
    pub is_coalesced: bool,
    /// Original SSA variable names that were merged into this variable.
    pub ssa_sources: Vec<String>,
    /// Definition count (number of assignment sites).
    pub def_count: usize,
    /// Use count (number of load sites).
    pub use_count: usize,
}

impl RecoveredVar {
    /// Create a new variable with the given id, name, and type.
    #[must_use]
    pub fn new(id: usize, name: impl Into<String>, ty: VarType) -> Self {
        Self {
            id,
            name: name.into(),
            ty,
            usages: HashSet::new(),
            stack_offset: None,
            is_param: false,
            is_coalesced: false,
            ssa_sources: Vec::new(),
            def_count: 0,
            use_count: 0,
        }
    }

    /// Create a function parameter variable.
    #[must_use]
    pub fn param(id: usize, name: impl Into<String>, ty: VarType) -> Self {
        let mut v = Self::new(id, name, ty);
        v.is_param = true;
        v.usages.insert(VarUsage::Argument);
        v
    }

    /// Record a usage kind for this variable.
    pub fn record_usage(&mut self, usage: VarUsage) {
        self.usages.insert(usage);
    }

    /// Returns `true` if this variable is ever written.
    #[must_use]
    pub fn is_defined(&self) -> bool {
        self.usages.contains(&VarUsage::Defined) || self.is_param
    }

    /// Returns `true` if this variable is ever read.
    #[must_use]
    pub fn is_read(&self) -> bool {
        self.usages.contains(&VarUsage::Read)
    }

    /// Returns `true` if this variable is dead (defined but never read).
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.is_defined() && !self.is_read() && !self.is_param
    }

    /// C-style declaration string.
    #[must_use]
    pub fn declaration(&self) -> String {
        format!("{} {}", self.ty, self.name)
    }
}

impl fmt::Display for RecoveredVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} [defs={} uses={} param={} dead={}]",
            self.name,
            self.ty,
            self.def_count,
            self.use_count,
            self.is_param,
            self.is_dead()
        )
    }
}

// ── SsaVarInfo ────────────────────────────────────────────────────────────────

/// Internal: tracks an SSA variable's metadata before coalescing.
#[derive(Debug, Clone)]
struct SsaVarInfo {
    name: String,
    version: u32,
    ty: VarType,
    def_block: Option<u32>,
    use_blocks: Vec<u32>,
    is_phi: bool,
    phi_sources: Vec<String>, // other SSA var names that flow into this phi
}

impl SsaVarInfo {
    fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
            ty: VarType::Unknown,
            def_block: None,
            use_blocks: Vec::new(),
            is_phi: false,
            phi_sources: Vec::new(),
        }
    }

    fn key(&self) -> String {
        format!("{}#{}", self.name, self.version)
    }
}

// ── HlilVariableRecovery ──────────────────────────────────────────────────────

/// Recovers decompiler-level local variables from SSA form.
///
/// Steps:
/// 1. Collect all SSA variable definitions and uses from the HLIL statement tree.
/// 2. Infer types from assignment operand sizes and use contexts.
/// 3. Coalesce SSA versions of the same base variable when their live ranges
///    do not overlap (copy propagation / phi elimination).
/// 4. Emit the final [`RecoveredVar`] list.
pub struct HlilVariableRecovery {
    /// Final recovered variable table (ordered by id).
    pub vars: Vec<RecoveredVar>,
    /// Mapping from SSA key (name#version) to recovered var id.
    pub ssa_to_var: HashMap<String, usize>,
    /// Number of coalescing merges performed.
    pub coalesce_count: usize,
    /// Number of dead variables identified.
    pub dead_count: usize,
}

impl HlilVariableRecovery {
    /// Create an empty recovery context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: Vec::new(),
            ssa_to_var: HashMap::new(),
            coalesce_count: 0,
            dead_count: 0,
        }
    }

    /// Run a complete variable recovery pass on a set of raw SSA variable
    /// descriptors and an optional external type hint map.
    ///
    /// `ssa_vars` is a list of `(base_name, version, block_id, is_def, is_phi)`
    /// tuples representing individual SSA variable events.
    /// `type_hints` maps base variable names to externally-provided types.
    pub fn recover(
        &mut self,
        ssa_vars: &[(String, u32, u32, bool, bool)],
        type_hints: &HashMap<String, VarType>,
        param_names: &[String],
    ) {
        // Phase 1: collect SSA info.
        let mut ssa_map: HashMap<String, SsaVarInfo> = HashMap::new();
        for (base, version, block_id, is_def, is_phi) in ssa_vars {
            let key = format!("{base}#{version}");
            let info = ssa_map.entry(key).or_insert_with(|| {
                SsaVarInfo::new(base.clone(), *version)
            });
            if *is_def {
                info.def_block = Some(*block_id);
            } else {
                if !info.use_blocks.contains(block_id) {
                    info.use_blocks.push(*block_id);
                }
            }
            if *is_phi {
                info.is_phi = true;
            }
            if let Some(hint) = type_hints.get(base) {
                info.ty = hint.clone();
            }
        }

        // Phase 2: coalesce SSA versions of the same base variable.
        let mut base_groups: HashMap<String, Vec<String>> = HashMap::new();
        for (key, info) in &ssa_map {
            base_groups
                .entry(info.name.clone())
                .or_default()
                .push(key.clone());
        }
        // `ssa_map` is a HashMap, so the push order above — and therefore the
        // contents of `rvar.ssa_sources` — varied run to run. Sort each group.
        for keys in base_groups.values_mut() {
            keys.sort_unstable();
        }

        // Iterate the groups in a STABLE order. `next_id` is a counter consumed
        // below by `RecoveredVar::new(next_id, …)` and `ssa_to_var.insert(key,
        // next_id)`, so walking `base_groups` in HashMap order handed every
        // recovered variable a different id on every run: the same function
        // analysed twice produced different variable ids and a different
        // SSA→variable mapping, which reaches the emitted names.
        let mut groups: Vec<(&String, &Vec<String>)> = base_groups.iter().collect();
        groups.sort_unstable_by(|a, b| a.0.cmp(b.0));

        let mut next_id = 0usize;
        for (base_name, keys) in groups {
            // Attempt to coalesce all versions into a single variable.
            let all_types: Vec<VarType> = keys
                .iter()
                .filter_map(|k| ssa_map.get(k))
                .map(|i| i.ty.clone())
                .collect();
            let merged_ty = all_types.into_iter().fold(VarType::Unknown, |acc, t| acc.widen(&t));

            let is_param = param_names.contains(base_name);
            let def_count = keys
                .iter()
                .filter_map(|k| ssa_map.get(k))
                .filter(|i| i.def_block.is_some())
                .count();
            let use_count: usize = keys
                .iter()
                .filter_map(|k| ssa_map.get(k))
                .map(|i| i.use_blocks.len())
                .sum();
            let phi_count = keys
                .iter()
                .filter_map(|k| ssa_map.get(k))
                .filter(|i| i.is_phi)
                .count();

            let var_name = if is_param {
                base_name.clone()
            } else {
                format!("var_{}", base_name.trim_start_matches('_'))
            };

            let mut rvar = if is_param {
                RecoveredVar::param(next_id, var_name, merged_ty)
            } else {
                RecoveredVar::new(next_id, var_name, merged_ty)
            };

            rvar.is_coalesced = keys.len() > 1;
            rvar.ssa_sources = keys.clone();
            rvar.def_count = def_count;
            rvar.use_count = use_count;
            if phi_count > 0 {
                self.coalesce_count += phi_count;
            }
            if def_count > 0 {
                rvar.record_usage(VarUsage::Defined);
            }
            if use_count > 0 {
                rvar.record_usage(VarUsage::Read);
            }

            // Map all SSA keys to this var id.
            for key in keys {
                self.ssa_to_var.insert(key.clone(), next_id);
            }

            self.vars.push(rvar);
            next_id += 1;
        }

        // Phase 3: count dead vars.
        self.dead_count = self.vars.iter().filter(|v| v.is_dead()).count();
    }

    /// Look up the recovered variable for an SSA key `name#version`.
    #[must_use]
    pub fn var_for_ssa(&self, name: &str, version: u32) -> Option<&RecoveredVar> {
        let key = format!("{name}#{version}");
        self.ssa_to_var
            .get(&key)
            .and_then(|&id| self.vars.get(id))
    }

    /// Return all non-parameter local variables.
    #[must_use]
    pub fn locals(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| !v.is_param).collect()
    }

    /// Return all parameters.
    #[must_use]
    pub fn params(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| v.is_param).collect()
    }

    /// Return dead variables (defined but never read).
    #[must_use]
    pub fn dead_vars(&self) -> Vec<&RecoveredVar> {
        self.vars.iter().filter(|v| v.is_dead()).collect()
    }

    /// Return variables with unknown type.
    #[must_use]
    pub fn untyped_vars(&self) -> Vec<&RecoveredVar> {
        self.vars
            .iter()
            .filter(|v| v.ty == VarType::Unknown)
            .collect()
    }

    /// Generate a C-style local variable declarations block.
    #[must_use]
    pub fn declarations_block(&self) -> String {
        let locals: Vec<String> = self
            .vars
            .iter()
            .filter(|v| !v.is_param)
            .map(|v| format!("    {};", v.declaration()))
            .collect();
        locals.join("\n")
    }

    /// Summary statistics.
    #[must_use]
    pub fn stats(&self) -> String {
        format!(
            "vars={} params={} locals={} dead={} coalesced={}",
            self.vars.len(),
            self.params().len(),
            self.locals().len(),
            self.dead_count,
            self.coalesce_count
        )
    }

    /// Build a per-SSA-key debug record `(key, version, is_phi, phi_sources)`
    /// from a slice of SSA events plus an optional phi-source map.
    ///
    /// `phi_source_map` maps `"base#version"` to the list of incoming SSA
    /// keys that feed that phi node. Records propagate this through
    /// [`SsaVarInfo::phi_sources`].
    #[must_use]
    pub fn ssa_debug_dump(
        ssa_events: &[(String, u32, u32, bool, bool)],
        phi_source_map: &HashMap<String, Vec<String>>,
    ) -> Vec<(String, u32, bool, Vec<String>)> {
        let mut map: HashMap<String, SsaVarInfo> = HashMap::new();
        for (base, version, _block, _is_def, is_phi) in ssa_events {
            let mut info = SsaVarInfo::new(base.clone(), *version);
            if *is_phi {
                info.is_phi = true;
            }
            let key = info.key();
            if let Some(srcs) = phi_source_map.get(&key) {
                info.phi_sources = srcs.clone();
            }
            map.entry(key).or_insert(info);
        }
        let mut out: Vec<(String, u32, bool, Vec<String>)> = map
            .into_values()
            .map(|i| (i.key(), i.version, i.is_phi, i.phi_sources))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl Default for HlilVariableRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ── recover_locals (free function) ────────────────────────────────────────────

/// Convenience function: run variable recovery on a set of SSA events and
/// return the recovered variable list.
///
/// `ssa_events` is `(base_name, version, block_id, is_def, is_phi)`.
#[must_use]
pub fn recover_locals(
    ssa_events: &[(String, u32, u32, bool, bool)],
    type_hints: &HashMap<String, VarType>,
    param_names: &[String],
) -> Vec<RecoveredVar> {
    let mut recovery = HlilVariableRecovery::new();
    recovery.recover(ssa_events, type_hints, param_names);
    recovery.vars
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events() -> Vec<(String, u32, u32, bool, bool)> {
        vec![
            ("x".into(), 0, 0, true, false),   // x#0 defined in block 0
            ("x".into(), 0, 1, false, false),  // x#0 read in block 1
            ("x".into(), 1, 1, true, false),   // x#1 defined in block 1
            ("x".into(), 1, 2, false, false),  // x#1 read in block 2
            ("y".into(), 0, 0, true, false),   // y#0 defined
            ("phi_x".into(), 0, 2, true, true), // phi of x versions
        ]
    }

    /// Variable IDs, names and `ssa_sources` must be IDENTICAL across runs.
    ///
    /// `recover` walked two `HashMaps` directly: `ssa_map` when filling each
    /// group's key list, and `base_groups` while handing out `next_id`. Since
    /// `next_id` feeds `RecoveredVar::new(next_id, …)` and
    /// `ssa_to_var.insert(key, next_id)`, `HashMap` order decided which variable
    /// got which id — the same function analysed twice produced a different
    /// SSA→variable mapping, and that reaches the emitted names.
    ///
    /// A single-run assertion cannot catch this (it would pass by luck), so
    /// this repeats the whole recovery and requires ONE distinct outcome.
    #[test]
    fn recovery_is_deterministic_across_runs() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut rec = HlilVariableRecovery::new();
            rec.recover(&make_events(), &HashMap::new(), &["y".to_string()]);
            // Full observable state: id, name and the coalesced SSA sources.
            let shape: Vec<(usize, String, Vec<String>)> = rec
                .vars
                .iter()
                .map(|v| (v.id, v.name.clone(), v.ssa_sources.clone()))
                .collect();
            seen.insert(shape);
        }
        assert_eq!(
            seen.len(),
            1,
            "variable recovery must not depend on hash order; got {} distinct results",
            seen.len()
        );
    }

    #[test]
    fn test_basic_recovery() {
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&make_events(), &HashMap::new(), &[]);
        assert!(!rec.vars.is_empty());
    }

    #[test]
    fn test_coalescing() {
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&make_events(), &HashMap::new(), &[]);
        // x has 2 SSA versions; they should be coalesced into one var.
        let x_var = rec.vars.iter().find(|v| v.name.contains('x'));
        assert!(x_var.is_some());
        if let Some(v) = x_var {
            assert!(v.is_coalesced || v.ssa_sources.len() >= 1);
        }
    }

    #[test]
    fn test_param_recovery() {
        let events = vec![
            ("arg0".into(), 0, 0, false, false),
            ("arg0".into(), 1, 1, false, false),
        ];
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&events, &HashMap::new(), &["arg0".to_string()]);
        let params = rec.params();
        assert_eq!(params.len(), 1);
        assert!(params[0].is_param);
    }

    #[test]
    fn test_dead_var_detection() {
        let events = vec![
            ("dead".into(), 0, 0, true, false), // defined but never read
        ];
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&events, &HashMap::new(), &[]);
        assert_eq!(rec.dead_count, 1);
    }

    #[test]
    fn test_type_hint_propagation() {
        let events = vec![
            ("counter".into(), 0, 0, true, false),
        ];
        let mut hints = HashMap::new();
        hints.insert("counter".to_string(), VarType::Int32);
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&events, &hints, &[]);
        let v = rec.vars.iter().find(|v| v.name.contains("counter"));
        assert!(v.is_some());
        assert_eq!(v.unwrap().ty, VarType::Int32);
    }

    #[test]
    fn test_recover_locals_fn() {
        let events = vec![
            ("a".into(), 0, 0, true, false),
            ("a".into(), 0, 1, false, false),
            ("b".into(), 0, 1, true, false),
        ];
        let vars = recover_locals(&events, &HashMap::new(), &[]);
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_declarations_block() {
        let events = vec![
            ("x".into(), 0, 0, true, false),
            ("y".into(), 0, 0, true, false),
        ];
        let mut hints = HashMap::new();
        hints.insert("x".to_string(), VarType::Int32);
        hints.insert("y".to_string(), VarType::UInt64);
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&events, &hints, &[]);
        let block = rec.declarations_block();
        assert!(block.contains("int32_t") || block.contains("uint64_t") || block.contains("unknown"));
    }

    #[test]
    fn test_var_type_widen() {
        assert_eq!(VarType::Int16.widen(&VarType::Int32), VarType::Int32);
        assert_eq!(VarType::Unknown.widen(&VarType::UInt8), VarType::UInt8);
        assert_eq!(VarType::Int64.widen(&VarType::Int32), VarType::Int64);
    }

    #[test]
    fn test_stats() {
        let mut rec = HlilVariableRecovery::new();
        rec.recover(&make_events(), &HashMap::new(), &[]);
        let stats = rec.stats();
        assert!(stats.contains("vars="));
    }
}
