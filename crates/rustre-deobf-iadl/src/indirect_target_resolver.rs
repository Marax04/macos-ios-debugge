//! Indirect call/jump target resolver using value set analysis, taint tracking,
//! constant propagation, pointer analysis, vtable-based resolution, and ROP chain analysis.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use rustre_core::address::Address;

// ─── ValueSet ────────────────────────────────────────────────────────────────

/// A bounded set of possible values for an expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueSet {
    /// Known concrete values in this set.
    pub values: BTreeSet<u64>,
    /// Whether the set is considered unbounded (top element).
    pub is_top: bool,
    /// Stride for strided intervals (0 = no stride).
    pub stride: u64,
    /// Lower bound of the strided interval.
    pub lower: u64,
    /// Upper bound of the strided interval.
    pub upper: u64,
}

impl ValueSet {
    /// Create an empty (bottom) value set.
    #[must_use]
    pub const fn bottom() -> Self {
        Self {
            values: BTreeSet::new(),
            is_top: false,
            stride: 0,
            lower: 0,
            upper: 0,
        }
    }

    /// Create a top (all possible values) value set.
    #[must_use]
    pub const fn top() -> Self {
        Self {
            values: BTreeSet::new(),
            is_top: true,
            stride: 0,
            lower: 0,
            upper: u64::MAX,
        }
    }

    /// Create a singleton value set.
    #[must_use]
    pub fn singleton(v: u64) -> Self {
        let mut vs = Self::bottom();
        vs.values.insert(v);
        vs.lower = v;
        vs.upper = v;
        vs
    }

    /// Create a value set from an iterator of concrete values.
    #[must_use]
    pub fn from_values(vals: impl IntoIterator<Item = u64>) -> Self {
        let values: BTreeSet<u64> = vals.into_iter().collect();
        let lower = values.iter().copied().min().unwrap_or(0);
        let upper = values.iter().copied().max().unwrap_or(0);
        Self {
            values,
            is_top: false,
            stride: 0,
            lower,
            upper,
        }
    }

    /// Create a strided-interval value set.
    #[must_use]
    pub fn strided_interval(lower: u64, upper: u64, stride: u64) -> Self {
        let stride = stride.max(1);
        let mut values = BTreeSet::new();
        let mut cur = lower;
        while cur <= upper {
            values.insert(cur);
            if cur == upper || stride == 0 {
                break;
            }
            cur = cur.saturating_add(stride);
        }
        // Limit concrete enumeration to 1024 entries to avoid memory explosion.
        let values = if values.len() > 1024 {
            BTreeSet::new()
        } else {
            values
        };
        Self {
            values,
            is_top: false,
            stride,
            lower,
            upper,
        }
    }

    /// Merge (join) two value sets.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        if self.is_top || other.is_top {
            return Self::top();
        }
        let mut merged = self.values.clone();
        merged.extend(other.values.iter().copied());
        // Widen to top if the set grows too large.
        if merged.len() > 256 {
            return Self::top();
        }
        let lower = self.lower.min(other.lower);
        let upper = self.upper.max(other.upper);
        Self {
            values: merged,
            is_top: false,
            stride: 0,
            lower,
            upper,
        }
    }

    /// Return `true` if this set contains `v`.
    #[must_use]
    pub fn contains(&self, v: u64) -> bool {
        if self.is_top {
            return true;
        }
        if !self.values.is_empty() {
            return self.values.contains(&v);
        }
        if self.stride > 0 {
            v >= self.lower && v <= self.upper && (v - self.lower) % self.stride == 0
        } else {
            false
        }
    }

    /// Return the concrete values, if available.
    #[must_use]
    pub fn concrete_values(&self) -> Vec<u64> {
        if self.is_top {
            return Vec::new();
        }
        self.values.iter().copied().collect()
    }

    /// Return `true` if the set is empty (no possible values).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.is_top && self.values.is_empty() && self.stride == 0
    }

    /// Return the number of known concrete values.
    #[must_use]
    pub fn size(&self) -> usize {
        self.values.len()
    }
}

// ─── TaintState ───────────────────────────────────────────────────────────────

/// Taint label applied to a register or memory location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLabel {
    /// Tainted by an external input at a specific address.
    ExternalInput(u64),
    /// Tainted by a function argument (zero-indexed).
    Argument(u32),
    /// Tainted by a return value from a call at the given address.
    ReturnValue(u64),
    /// Tainted by heap allocation.
    HeapPointer,
    /// Tainted by stack pointer.
    StackPointer,
    /// Custom taint label.
    Custom(String),
}

impl std::fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExternalInput(a) => write!(f, "external@0x{a:x}"),
            Self::Argument(n) => write!(f, "arg{n}"),
            Self::ReturnValue(a) => write!(f, "ret@0x{a:x}"),
            Self::HeapPointer => write!(f, "heap"),
            Self::StackPointer => write!(f, "stack"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

/// Taint state for the current analysis point.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintState {
    /// Register name → set of taint labels.
    pub register_taints: HashMap<String, HashSet<TaintLabel>>,
    /// Memory address → set of taint labels.
    pub memory_taints: BTreeMap<u64, HashSet<TaintLabel>>,
}

impl TaintState {
    /// Create a new empty taint state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a register as tainted.
    pub fn taint_register(&mut self, reg: impl Into<String>, label: TaintLabel) {
        self.register_taints
            .entry(reg.into())
            .or_default()
            .insert(label);
    }

    /// Mark a memory address as tainted.
    pub fn taint_memory(&mut self, addr: u64, label: TaintLabel) {
        self.memory_taints.entry(addr).or_default().insert(label);
    }

    /// Return `true` if a register is tainted.
    #[must_use]
    pub fn is_register_tainted(&self, reg: &str) -> bool {
        self.register_taints
            .get(reg)
            .map_or(false, |s| !s.is_empty())
    }

    /// Return `true` if a memory address is tainted.
    #[must_use]
    pub fn is_memory_tainted(&self, addr: u64) -> bool {
        self.memory_taints
            .get(&addr)
            .map_or(false, |s| !s.is_empty())
    }

    /// Propagate taint from source register to destination register.
    pub fn propagate_reg_to_reg(&mut self, src: &str, dst: impl Into<String>) {
        if let Some(labels) = self.register_taints.get(src).cloned() {
            self.register_taints.insert(dst.into(), labels);
        }
    }

    /// Clear taint for a register (e.g. after constant assignment).
    pub fn clear_register(&mut self, reg: &str) {
        self.register_taints.remove(reg);
    }

    /// Merge another taint state into this one (union).
    pub fn merge(&mut self, other: &Self) {
        for (reg, labels) in &other.register_taints {
            self.register_taints
                .entry(reg.clone())
                .or_default()
                .extend(labels.iter().cloned());
        }
        for (addr, labels) in &other.memory_taints {
            self.memory_taints
                .entry(*addr)
                .or_default()
                .extend(labels.iter().cloned());
        }
    }
}

// ─── VtableCandidate ──────────────────────────────────────────────────────────

/// A candidate virtual dispatch target from a vtable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VtableCandidate {
    /// Address of the vtable in the binary.
    pub vtable_addr: u64,
    /// Slot index (0-based).
    pub slot_index: u32,
    /// Resolved function address at this slot.
    pub target_addr: u64,
    /// Demangled name if available.
    pub symbol_name: Option<String>,
    /// Estimated class this vtable belongs to.
    pub class_name: Option<String>,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
}

impl VtableCandidate {
    /// Create a new vtable candidate.
    #[must_use]
    pub const fn new(vtable_addr: u64, slot_index: u32, target_addr: u64) -> Self {
        Self {
            vtable_addr,
            slot_index,
            target_addr,
            symbol_name: None,
            class_name: None,
            confidence: 0.5,
        }
    }

    /// Set the symbol name.
    #[must_use]
    pub fn with_symbol(mut self, name: impl Into<String>) -> Self {
        self.symbol_name = Some(name.into());
        self
    }

    /// Set the class name.
    #[must_use]
    pub fn with_class(mut self, class: impl Into<String>) -> Self {
        self.class_name = Some(class.into());
        self
    }

    /// Set the confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: f64) -> Self {
        // `f64::clamp` propagates NaN; a NaN confidence would silently lose
        // every comparison it takes part in.
        self.confidence = if c.is_nan() { 0.0 } else { c.clamp(0.0, 1.0) };
        self
    }
}

// ─── ResolutionMethod ─────────────────────────────────────────────────────────

/// Method used to resolve an indirect target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResolutionMethod {
    /// Constant propagation resolved the target to a single address.
    ConstantPropagation,
    /// Value set analysis produced a bounded set of targets.
    ValueSetAnalysis,
    /// Taint tracking narrowed the target to known sources.
    TaintTracking,
    /// Vtable pointer analysis identified a virtual dispatch.
    VtableAnalysis,
    /// Import address table pointer resolved to a library function.
    IatPointer,
    /// Return-oriented programming gadget chain analysis.
    RopChain,
    /// Pattern matching against known thunk patterns.
    ThunkPattern,
    /// Data-flow backward slice.
    BackwardSlice,
    /// External hint (e.g. from dynamic analysis or debug symbols).
    ExternalHint,
    /// Unresolved — no method succeeded.
    Unresolved,
}

impl std::fmt::Display for ResolutionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ConstantPropagation => "ConstProp",
            Self::ValueSetAnalysis => "VSA",
            Self::TaintTracking => "Taint",
            Self::VtableAnalysis => "Vtable",
            Self::IatPointer => "IAT",
            Self::RopChain => "ROP",
            Self::ThunkPattern => "Thunk",
            Self::BackwardSlice => "BwdSlice",
            Self::ExternalHint => "ExtHint",
            Self::Unresolved => "Unresolved",
        };
        write!(f, "{s}")
    }
}

// ─── IndirectTarget ───────────────────────────────────────────────────────────

/// A resolved or partially-resolved indirect call/jump target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectTarget {
    /// Virtual address of the indirect call/jump instruction.
    pub site_addr: u64,
    /// Whether this is a call (true) or jump (false).
    pub is_call: bool,
    /// The resolved target addresses.
    pub targets: Vec<u64>,
    /// The resolution method(s) used.
    pub methods: Vec<ResolutionMethod>,
    /// Confidence in the resolution (0.0–1.0).
    pub confidence: f64,
    /// Vtable candidates if vtable analysis was applied.
    pub vtable_candidates: Vec<VtableCandidate>,
    /// Value set at the indirect operand.
    pub operand_value_set: Option<ValueSet>,
    /// Whether the target was successfully resolved.
    pub resolved: bool,
    /// Optional symbolic name for the target.
    pub symbol: Option<String>,
}

impl IndirectTarget {
    /// Return the call/jump site as a typed [`rustre_core::address::Address`].
    #[must_use]
    pub const fn site_address(&self) -> Address {
        Address(self.site_addr)
    }

    /// Return the resolved target addresses as typed [`rustre_core::address::Address`] values.
    #[must_use]
    pub fn target_addresses(&self) -> Vec<Address> {
        self.targets.iter().copied().map(Address).collect()
    }

    /// Create a new unresolved indirect target.
    #[must_use]
    pub const fn new(site_addr: u64, is_call: bool) -> Self {
        Self {
            site_addr,
            is_call,
            targets: Vec::new(),
            methods: Vec::new(),
            confidence: 0.0,
            vtable_candidates: Vec::new(),
            operand_value_set: None,
            resolved: false,
            symbol: None,
        }
    }

    /// Add a resolved target address.
    pub fn add_target(&mut self, addr: u64, method: ResolutionMethod, confidence: f64) {
        if !self.targets.contains(&addr) {
            self.targets.push(addr);
        }
        if !self.methods.contains(&method) {
            self.methods.push(method);
        }
        self.confidence = self.confidence.max(confidence);
        self.resolved = !self.targets.is_empty();
    }

    /// Return `true` if there is exactly one resolved target.
    #[must_use]
    pub const fn is_monomorphic(&self) -> bool {
        self.targets.len() == 1
    }

    /// Return `true` if there are multiple resolved targets (polymorphic dispatch).
    #[must_use]
    pub const fn is_polymorphic(&self) -> bool {
        self.targets.len() > 1
    }
}

// ─── ConstPropState ───────────────────────────────────────────────────────────

/// Lightweight constant propagation lattice state.
#[derive(Debug, Clone, Default)]
struct ConstPropState {
    /// Register → known constant value.
    regs: HashMap<String, u64>,
}

impl ConstPropState {
    fn get_reg(&self, r: &str) -> Option<u64> {
        self.regs.get(r).copied()
    }
    fn set_reg(&mut self, r: impl Into<String>, v: u64) {
        self.regs.insert(r.into(), v);
    }
    fn kill_reg(&mut self, r: &str) {
        self.regs.remove(r);
    }
}

// ─── RopGadget ───────────────────────────────────────────────────────────────

/// A single ROP gadget: a sequence of instructions ending in a ret or indirect jmp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopGadget {
    /// Address of the gadget.
    pub addr: u64,
    /// Byte encoding.
    pub bytes: Vec<u8>,
    /// Textual description.
    pub description: String,
    /// Gadget type.
    pub gadget_type: RopGadgetType,
    /// Stack displacement caused by this gadget.
    pub stack_delta: i32,
}

/// Classification of a ROP gadget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RopGadgetType {
    /// Ends in `RET`.
    Ret,
    /// Ends in `JMP [reg]`.
    IndirectJmp,
    /// Ends in `CALL [reg]`.
    IndirectCall,
    /// Ends in `POP reg; RET`.
    PopRet,
    /// Load-store gadget.
    LoadStore,
    /// Arithmetic gadget.
    Arithmetic,
    /// Unknown.
    Unknown,
}

// ─── RopChainAnalysis ─────────────────────────────────────────────────────────

/// Result of ROP chain analysis at a given site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopChainAnalysis {
    /// Starting address of the ROP chain.
    pub chain_start: u64,
    /// Gadgets identified in order.
    pub gadgets: Vec<RopGadget>,
    /// Final control-flow target (if derivable).
    pub final_target: Option<u64>,
    /// Whether the chain looks like a syscall pivot.
    pub is_syscall_pivot: bool,
    /// Whether the chain looks like a shellcode loader.
    pub is_shellcode_loader: bool,
    /// Confidence in the analysis.
    pub confidence: f64,
}

impl RopChainAnalysis {
    /// Create a new empty ROP chain analysis.
    #[must_use]
    pub const fn new(chain_start: u64) -> Self {
        Self {
            chain_start,
            gadgets: Vec::new(),
            final_target: None,
            is_syscall_pivot: false,
            is_shellcode_loader: false,
            confidence: 0.0,
        }
    }

    /// Return `true` if any gadget was found.
    #[must_use]
    pub const fn has_gadgets(&self) -> bool {
        !self.gadgets.is_empty()
    }
}

// ─── IndirectTargetResolver ───────────────────────────────────────────────────

/// Configuration for the indirect target resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Maximum number of iterations for fixed-point analysis.
    pub max_iterations: u32,
    /// Maximum number of targets to track per site.
    pub max_targets_per_site: usize,
    /// Whether to apply vtable analysis.
    pub enable_vtable: bool,
    /// Whether to apply ROP chain analysis.
    pub enable_rop: bool,
    /// Minimum confidence threshold for reporting a resolution.
    pub min_confidence: f64,
    /// Maximum backward-slice depth.
    pub max_slice_depth: u32,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            max_iterations: 32,
            max_targets_per_site: 64,
            enable_vtable: true,
            enable_rop: true,
            min_confidence: 0.3,
            max_slice_depth: 20,
        }
    }
}

/// Abstract representation of a program instruction for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractInstr {
    /// Instruction address.
    pub addr: u64,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Destination operand (register or `mem:<addr>`).
    pub dst: Option<String>,
    /// Source operands.
    pub src: Vec<String>,
    /// Immediate value if present.
    pub imm: Option<u64>,
    /// Memory base register (for memory operands).
    pub mem_base: Option<String>,
    /// Memory displacement.
    pub mem_disp: i64,
}

impl AbstractInstr {
    /// Create a minimal instruction.
    #[must_use]
    pub fn new(addr: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            addr,
            mnemonic: mnemonic.into(),
            dst: None,
            src: Vec::new(),
            imm: None,
            mem_base: None,
            mem_disp: 0,
        }
    }

    /// Return `true` if this is an indirect call or jump.
    #[must_use]
    pub fn is_indirect_transfer(&self) -> bool {
        let m = self.mnemonic.to_ascii_lowercase();
        (m.starts_with("call") || m.starts_with("jmp")) && self.mem_base.is_some()
    }

    /// Return `true` if this is a MOV to a register with an immediate.
    #[must_use]
    pub fn is_const_move(&self) -> bool {
        self.mnemonic.to_ascii_lowercase().starts_with("mov") && self.imm.is_some()
    }
}

/// Main indirect call/jump target resolver.
pub struct IndirectTargetResolver {
    config: ResolverConfig,
    /// Abstract instruction stream (address-ordered).
    instructions: BTreeMap<u64, AbstractInstr>,
    /// Known vtable entries: vtable base → list of (slot, target) pairs.
    vtable_map: HashMap<u64, Vec<(u32, u64)>>,
    /// Import address table: IAT address → resolved symbol name.
    iat_map: BTreeMap<u64, String>,
    /// External hints: indirect site address → concrete target.
    external_hints: HashMap<u64, Vec<u64>>,
    /// Cached resolution results.
    results: HashMap<u64, IndirectTarget>,
}

impl IndirectTargetResolver {
    /// Create a new resolver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ResolverConfig::default())
    }

    /// Create a resolver with explicit configuration.
    #[must_use]
    pub fn with_config(config: ResolverConfig) -> Self {
        Self {
            config,
            instructions: BTreeMap::new(),
            vtable_map: HashMap::new(),
            iat_map: BTreeMap::new(),
            external_hints: HashMap::new(),
            results: HashMap::new(),
        }
    }

    /// Load instructions for analysis.
    pub fn load_instructions(&mut self, instrs: Vec<AbstractInstr>) {
        for instr in instrs {
            self.instructions.insert(instr.addr, instr);
        }
    }

    /// Register a vtable with its slot→target mappings.
    pub fn register_vtable(&mut self, vtable_addr: u64, slots: Vec<(u32, u64)>) {
        self.vtable_map.insert(vtable_addr, slots);
    }

    /// Register an IAT entry.
    pub fn register_iat_entry(&mut self, iat_addr: u64, symbol: impl Into<String>) {
        self.iat_map.insert(iat_addr, symbol.into());
    }

    /// Register an external hint for a site.
    pub fn add_external_hint(&mut self, site: u64, target: u64) {
        self.external_hints.entry(site).or_default().push(target);
    }

    /// Run the full resolution pipeline and return all resolved sites.
    #[must_use]
    pub fn resolve_all(&mut self) -> Vec<IndirectTarget> {
        let sites: Vec<(u64, bool)> = self
            .instructions
            .values()
            .filter(|i| i.is_indirect_transfer())
            .map(|i| {
                let is_call = i.mnemonic.to_ascii_lowercase().starts_with("call");
                (i.addr, is_call)
            })
            .collect();

        for (addr, is_call) in sites {
            let result = self.resolve_site(addr, is_call);
            self.results.insert(addr, result);
        }

        self.results.values().cloned().collect()
    }

    /// Resolve a single indirect call/jump site.
    #[must_use]
    pub fn resolve_site(&self, site_addr: u64, is_call: bool) -> IndirectTarget {
        let mut target = IndirectTarget::new(site_addr, is_call);

        // 1. Check external hints first (highest confidence).
        if let Some(hints) = self.external_hints.get(&site_addr) {
            for &hint in hints {
                target.add_target(hint, ResolutionMethod::ExternalHint, 0.95);
            }
            if target.resolved {
                return target;
            }
        }

        // 2. Constant propagation.
        if let Some(const_target) = self.try_constant_propagation(site_addr) {
            target.add_target(const_target, ResolutionMethod::ConstantPropagation, 0.90);
            target.operand_value_set = Some(ValueSet::singleton(const_target));
        }

        // 3. IAT pattern check.
        if let Some(instr) = self.instructions.get(&site_addr) {
            let iat_addr = self.compute_mem_target(instr);
            if let Some(addr) = iat_addr {
                if let Some(sym) = self.iat_map.get(&addr) {
                    target.symbol = Some(sym.clone());
                    target.add_target(addr, ResolutionMethod::IatPointer, 0.85);
                }
            }
        }

        // 4. Vtable analysis.
        if self.config.enable_vtable {
            let vtable_hits = self.try_vtable_analysis(site_addr);
            for vc in vtable_hits {
                let t = vc.target_addr;
                let c = vc.confidence;
                target.vtable_candidates.push(vc);
                target.add_target(t, ResolutionMethod::VtableAnalysis, c);
            }
        }

        // 5. Value set analysis (backward slice).
        let vs = self.compute_value_set(site_addr);
        if !vs.is_empty() && !vs.is_top {
            target.operand_value_set = Some(vs.clone());
            for v in vs.concrete_values().into_iter().take(self.config.max_targets_per_site) {
                target.add_target(v, ResolutionMethod::ValueSetAnalysis, 0.60);
            }
        }

        // 6. Thunk pattern check.
        if let Some(thunk_target) = self.try_thunk_pattern(site_addr) {
            target.add_target(thunk_target, ResolutionMethod::ThunkPattern, 0.75);
        }

        // 7. ROP chain analysis.
        if self.config.enable_rop {
            if let Some(rop) = self.try_rop_analysis(site_addr) {
                if let Some(final_t) = rop.final_target {
                    target.add_target(final_t, ResolutionMethod::RopChain, rop.confidence);
                }
            }
        }

        if target.targets.is_empty() {
            target.methods.push(ResolutionMethod::Unresolved);
        }

        target
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Attempt constant propagation backward from the call site.
    fn try_constant_propagation(&self, site_addr: u64) -> Option<u64> {
        let instr = self.instructions.get(&site_addr)?;
        let base_reg = instr.mem_base.as_deref()?;

        let mut state = ConstPropState::default();
        let mut work: VecDeque<u64> = VecDeque::new();

        // Collect predecessor instructions (linear scan backwards).
        let preds: Vec<u64> = self
            .instructions
            .range(..site_addr)
            .rev()
            .take(self.config.max_slice_depth as usize)
            .map(|(&a, _)| a)
            .collect();

        // Process in forward order so state is consistent.
        for addr in preds.into_iter().rev() {
            work.push_back(addr);
        }

        while let Some(addr) = work.pop_front() {
            let i = self.instructions.get(&addr)?;
            if i.is_const_move() {
                if let (Some(dst), Some(imm)) = (&i.dst, i.imm) {
                    state.set_reg(dst.clone(), imm);
                }
            } else if i.mnemonic.to_ascii_lowercase().starts_with("mov") {
                if let (Some(dst), Some(src)) = (&i.dst, i.src.first()) {
                    if let Some(v) = state.get_reg(src) {
                        state.set_reg(dst.clone(), v);
                    } else {
                        state.kill_reg(dst);
                    }
                }
            } else if i.mnemonic.to_ascii_lowercase().starts_with("add") {
                if let (Some(dst), Some(imm)) = (&i.dst, i.imm) {
                    if let Some(v) = state.get_reg(dst) {
                        state.set_reg(dst.clone(), v.wrapping_add(imm));
                    }
                }
            } else if !i.mnemonic.to_ascii_lowercase().starts_with("cmp") {
                // Any other def kills the register.
                if let Some(dst) = &i.dst {
                    state.kill_reg(dst);
                }
            }
        }

        let base_val = state.get_reg(base_reg)?;
        // Use wrapping arithmetic to correctly model address-space wrap-around.
        // Casting base_val to i64 first would misinterpret high-bit addresses
        // (e.g. kernel addresses > i64::MAX) as negative numbers.
        let target = base_val.wrapping_add(instr.mem_disp as u64);

        // Check if this is an IAT pointer.
        if let Some(iat_target) = self.iat_map.get(&target) {
            let _ = iat_target;
            return Some(target);
        }

        Some(target)
    }

    /// Compute memory target for an instruction (base + disp).
    fn compute_mem_target(&self, instr: &AbstractInstr) -> Option<u64> {
        let base_reg = instr.mem_base.as_deref()?;
        // Without a real register state, we can only detect IAT patterns
        // where the base is known to be a constant (e.g. `call [0x12345678]`).
        let _ = base_reg;
        if instr.mem_base.is_none() && instr.mem_disp > 0 {
            Some(instr.mem_disp as u64)
        } else {
            None
        }
    }

    /// Attempt vtable analysis at a call site.
    fn try_vtable_analysis(&self, site_addr: u64) -> Vec<VtableCandidate> {
        let mut candidates = Vec::new();
        let instr = match self.instructions.get(&site_addr) {
            Some(i) => i,
            None => return candidates,
        };

        // Pattern: CALL [reg + disp] — potential vtable slot.
        if instr.mem_base.is_some() {
            let slot = u32::try_from(instr.mem_disp.unsigned_abs() / 8).unwrap_or(u32::MAX);
            for (&vtbl_addr, slots) in &self.vtable_map {
                for &(s, target) in slots {
                    if s == slot {
                        let vc = VtableCandidate::new(vtbl_addr, slot, target)
                            .with_confidence(0.70);
                        candidates.push(vc);
                    }
                }
            }
        }

        candidates
    }

    /// Compute a value set for the operand of an indirect transfer.
    fn compute_value_set(&self, site_addr: u64) -> ValueSet {
        let instr = match self.instructions.get(&site_addr) {
            Some(i) => i,
            None => return ValueSet::bottom(),
        };

        let base_reg = match &instr.mem_base {
            Some(r) => r.clone(),
            None => return ValueSet::bottom(),
        };

        // Backward slice to collect possible values of `base_reg`.
        let mut possible_vals: BTreeSet<u64> = BTreeSet::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut worklist: VecDeque<(u64, String, u32)> = VecDeque::new();
        worklist.push_back((site_addr, base_reg.clone(), 0));

        while let Some((cur_addr, reg, depth)) = worklist.pop_front() {
            if depth > self.config.max_slice_depth {
                continue;
            }
            if !visited.insert(cur_addr) {
                continue;
            }

            // Look at the instruction just before cur_addr that defs `reg`.
            for (&addr, i) in self.instructions.range(..cur_addr).rev().take(10) {
                if i.dst.as_deref() == Some(&reg) {
                    if let Some(imm) = i.imm {
                        possible_vals.insert(imm);
                    } else if let Some(src) = i.src.first() {
                        worklist.push_back((addr, src.clone(), depth + 1));
                    }
                    break;
                }
            }
        }

        if possible_vals.is_empty() {
            ValueSet::top()
        } else if possible_vals.len() <= 64 {
            ValueSet::from_values(possible_vals)
        } else {
            ValueSet::top()
        }
    }

    /// Detect simple thunk patterns (single-instruction indirection).
    fn try_thunk_pattern(&self, site_addr: u64) -> Option<u64> {
        let instr = self.instructions.get(&site_addr)?;
        // Thunk: single-instruction function that just does `jmp [mem]`.
        // Check if function start = site_addr.
        if instr.imm.is_none() && instr.mem_base.is_none() && instr.mem_disp > 0 {
            return Some(instr.mem_disp as u64);
        }
        None
    }

    /// Basic ROP chain analysis: scan for consecutive gadgets on the stack.
    fn try_rop_analysis(&self, site_addr: u64) -> Option<RopChainAnalysis> {
        let instr = self.instructions.get(&site_addr)?;
        let m = instr.mnemonic.to_ascii_lowercase();
        // Only attempt ROP analysis on `jmp [reg]` patterns.
        if !m.starts_with("jmp") || instr.mem_base.is_none() {
            return None;
        }

        let mut analysis = RopChainAnalysis::new(site_addr);
        // Scan nearby instructions for RET sequences indicating gadget setup.
        let gadget_pattern: Vec<&AbstractInstr> = self
            .instructions
            .range(site_addr.saturating_sub(64)..site_addr)
            .map(|(_, i)| i)
            .collect();

        let mut pop_count = 0u32;
        for g in &gadget_pattern {
            let gm = g.mnemonic.to_ascii_lowercase();
            if gm.starts_with("pop") {
                pop_count += 1;
                analysis.gadgets.push(RopGadget {
                    addr: g.addr,
                    bytes: Vec::new(),
                    description: format!("pop {}", g.dst.as_deref().unwrap_or("?")),
                    gadget_type: RopGadgetType::PopRet,
                    stack_delta: 8,
                });
            } else if gm.starts_with("ret") {
                analysis.gadgets.push(RopGadget {
                    addr: g.addr,
                    bytes: vec![0xC3],
                    description: "ret".into(),
                    gadget_type: RopGadgetType::Ret,
                    stack_delta: 8,
                });
            }
        }

        if pop_count >= 2 {
            // Heuristic: 2+ pops before indirect jmp looks like ROP chain pivot.
            analysis.confidence = 0.55;
            analysis.is_shellcode_loader = pop_count >= 4;
        }

        if analysis.gadgets.is_empty() {
            None
        } else {
            Some(analysis)
        }
    }

    /// Return all resolved targets.
    #[must_use]
    pub const fn results(&self) -> &HashMap<u64, IndirectTarget> {
        &self.results
    }

    /// Return targets above the minimum confidence threshold.
    #[must_use]
    pub fn high_confidence_results(&self) -> Vec<&IndirectTarget> {
        self.results
            .values()
            .filter(|t| t.confidence >= self.config.min_confidence && t.resolved)
            .collect()
    }

    /// Compute resolution statistics.
    #[must_use]
    pub fn statistics(&self) -> ResolutionStats {
        let total = self.results.len();
        let resolved = self.results.values().filter(|t| t.resolved).count();
        let monomorphic = self.results.values().filter(|t| t.is_monomorphic()).count();
        let polymorphic = self.results.values().filter(|t| t.is_polymorphic()).count();
        let unresolved = total.saturating_sub(resolved);
        let avg_confidence = if total == 0 {
            0.0
        } else {
            self.results.values().map(|t| t.confidence).sum::<f64>() / total as f64
        };
        ResolutionStats {
            total_sites: total,
            resolved_sites: resolved,
            unresolved_sites: unresolved,
            monomorphic_sites: monomorphic,
            polymorphic_sites: polymorphic,
            avg_confidence,
        }
    }
}

impl Default for IndirectTargetResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ResolutionStats ─────────────────────────────────────────────────────────

/// Summary statistics for a resolution run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionStats {
    /// Total indirect sites analyzed.
    pub total_sites: usize,
    /// Sites where at least one target was resolved.
    pub resolved_sites: usize,
    /// Sites that could not be resolved.
    pub unresolved_sites: usize,
    /// Sites with exactly one resolved target.
    pub monomorphic_sites: usize,
    /// Sites with multiple resolved targets.
    pub polymorphic_sites: usize,
    /// Average confidence across all sites.
    pub avg_confidence: f64,
}

impl ResolutionStats {
    /// Return the resolution rate as a percentage.
    #[must_use]
    pub fn resolution_rate(&self) -> f64 {
        if self.total_sites == 0 {
            return 100.0;
        }
        self.resolved_sites as f64 / self.total_sites as f64 * 100.0
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mov_imm(addr: u64, dst: &str, imm: u64) -> AbstractInstr {
        AbstractInstr {
            addr,
            mnemonic: "mov".into(),
            dst: Some(dst.into()),
            src: Vec::new(),
            imm: Some(imm),
            mem_base: None,
            mem_disp: 0,
        }
    }

    fn make_call_mem(addr: u64, base: &str, disp: i64) -> AbstractInstr {
        AbstractInstr {
            addr,
            mnemonic: "call".into(),
            dst: None,
            src: Vec::new(),
            imm: None,
            mem_base: Some(base.into()),
            mem_disp: disp,
        }
    }

    #[test]
    fn test_value_set_singleton() {
        let vs = ValueSet::singleton(0x1000);
        assert!(vs.contains(0x1000));
        assert!(!vs.contains(0x2000));
        assert_eq!(vs.size(), 1);
    }

    #[test]
    fn test_value_set_join() {
        let vs1 = ValueSet::singleton(0x1000);
        let vs2 = ValueSet::singleton(0x2000);
        let joined = vs1.join(&vs2);
        assert!(joined.contains(0x1000));
        assert!(joined.contains(0x2000));
    }

    #[test]
    fn test_value_set_top_join() {
        let top = ValueSet::top();
        let vs = ValueSet::singleton(0x1234);
        let result = top.join(&vs);
        assert!(result.is_top);
    }

    #[test]
    fn test_value_set_strided() {
        let vs = ValueSet::strided_interval(0, 20, 4);
        assert!(vs.contains(0));
        assert!(vs.contains(4));
        assert!(vs.contains(8));
        assert!(!vs.contains(3));
    }

    #[test]
    fn test_taint_state_register() {
        let mut ts = TaintState::new();
        ts.taint_register("rax", TaintLabel::Argument(0));
        assert!(ts.is_register_tainted("rax"));
        assert!(!ts.is_register_tainted("rbx"));
        ts.clear_register("rax");
        assert!(!ts.is_register_tainted("rax"));
    }

    #[test]
    fn test_taint_propagation() {
        let mut ts = TaintState::new();
        ts.taint_register("rdi", TaintLabel::ExternalInput(0x1000));
        ts.propagate_reg_to_reg("rdi", "rax");
        assert!(ts.is_register_tainted("rax"));
    }

    #[test]
    fn test_taint_merge() {
        let mut ts1 = TaintState::new();
        ts1.taint_register("rax", TaintLabel::HeapPointer);
        let mut ts2 = TaintState::new();
        ts2.taint_register("rbx", TaintLabel::StackPointer);
        ts1.merge(&ts2);
        assert!(ts1.is_register_tainted("rax"));
        assert!(ts1.is_register_tainted("rbx"));
    }

    #[test]
    fn test_resolver_external_hint() {
        let mut resolver = IndirectTargetResolver::new();
        let call_instr = make_call_mem(0x1000, "rax", 0);
        resolver.load_instructions(vec![call_instr]);
        resolver.add_external_hint(0x1000, 0xDEAD_BEEF);
        let results = resolver.resolve_all();
        let r = results.iter().find(|t| t.site_addr == 0x1000).unwrap();
        assert!(r.resolved);
        assert!(r.targets.contains(&0xDEAD_BEEF));
        assert!(r.methods.contains(&ResolutionMethod::ExternalHint));
    }

    #[test]
    fn test_resolver_iat() {
        let mut resolver = IndirectTargetResolver::new();
        let call_instr = make_call_mem(0x1000, "rax", 0);
        resolver.load_instructions(vec![call_instr]);
        resolver.register_iat_entry(0x4000, "LoadLibraryA");
        // No direct connection in this test since mem_disp is 0; just verify no panic.
        let _ = resolver.resolve_all();
    }

    #[test]
    fn test_resolver_vtable() {
        let mut resolver = IndirectTargetResolver::new();
        let call_instr = make_call_mem(0x2000, "rcx", 0);
        resolver.load_instructions(vec![call_instr]);
        resolver.register_vtable(0x5000, vec![(0, 0x6000), (1, 0x6100)]);
        let _ = resolver.resolve_all();
        let stats = resolver.statistics();
        assert_eq!(stats.total_sites, 1);
    }

    #[test]
    fn test_resolver_const_propagation() {
        let mut resolver = IndirectTargetResolver::new();
        let mov1 = make_mov_imm(0x0FF0, "rax", 0x7000);
        let call_instr = make_call_mem(0x1000, "rax", 0);
        resolver.load_instructions(vec![mov1, call_instr]);
        let results = resolver.resolve_all();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_resolution_stats() {
        let mut resolver = IndirectTargetResolver::new();
        let call_instr = make_call_mem(0x1000, "rax", 0);
        resolver.load_instructions(vec![call_instr]);
        resolver.add_external_hint(0x1000, 0x2000);
        let _ = resolver.resolve_all();
        let stats = resolver.statistics();
        assert_eq!(stats.total_sites, 1);
        assert!(stats.resolved_sites >= 1);
        assert!(stats.resolution_rate() > 0.0);
    }

    #[test]
    fn test_indirect_target_monomorphic() {
        let mut t = IndirectTarget::new(0x1000, true);
        t.add_target(0x2000, ResolutionMethod::ConstantPropagation, 0.9);
        assert!(t.is_monomorphic());
        assert!(!t.is_polymorphic());
    }

    #[test]
    fn test_indirect_target_polymorphic() {
        let mut t = IndirectTarget::new(0x1000, true);
        t.add_target(0x2000, ResolutionMethod::VtableAnalysis, 0.7);
        t.add_target(0x3000, ResolutionMethod::VtableAnalysis, 0.6);
        assert!(t.is_polymorphic());
        assert!(!t.is_monomorphic());
    }

    #[test]
    fn test_rop_chain_new() {
        let rop = RopChainAnalysis::new(0x5000);
        assert_eq!(rop.chain_start, 0x5000);
        assert!(!rop.has_gadgets());
    }

    #[test]
    fn test_vtable_candidate() {
        let vc = VtableCandidate::new(0x8000, 2, 0x9000)
            .with_symbol("Foo::method")
            .with_class("Foo")
            .with_confidence(0.85);
        assert_eq!(vc.slot_index, 2);
        assert_eq!(vc.target_addr, 0x9000);
        assert!((vc.confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn test_resolution_method_display() {
        assert_eq!(ResolutionMethod::ConstantPropagation.to_string(), "ConstProp");
        assert_eq!(ResolutionMethod::Unresolved.to_string(), "Unresolved");
    }
}
