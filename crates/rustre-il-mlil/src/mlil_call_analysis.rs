//! `mlil_call_analysis` — MLIL call-site analysis and indirect call resolution.
//!
//! Provides `MlilCallAnalysis`, `CallSite`, `ArgumentMapping`,
//! `ReturnValueTracking`, `IndirectCallResolver`, `VirtualCallResolver`.

use crate::{MlilExpr, MlilFunction, MlilInstruction, SsaVar};
use ahash::{AHashMap as HashMap, AHashSet as HashSet};

// ── CallSite ──────────────────────────────────────────────────────────────────

/// A call site discovered during MLIL analysis.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Address of the call instruction.
    pub address: u64,
    /// Resolved callee address (if known).
    pub callee: Option<u64>,
    /// Call expression (may be indirect, register-based, etc.).
    pub target_expr: String,
    /// Arguments passed at this call site.
    pub args: Vec<CallArgument>,
    /// SSA variables receiving the return value.
    pub return_vars: Vec<SsaVar>,
    /// Is this an indirect call (through a register or memory pointer)?
    pub is_indirect: bool,
    /// Is this a virtual call (vtable dispatch)?
    pub is_virtual: bool,
}

impl CallSite {
    /// Create a direct call site.
    #[must_use]
    pub fn direct(address: u64, callee: u64, args: Vec<CallArgument>) -> Self {
        Self {
            address,
            callee: Some(callee),
            target_expr: format!("0x{callee:x}"),
            args,
            return_vars: Vec::new(),
            is_indirect: false,
            is_virtual: false,
        }
    }

    /// Create an indirect call site.
    #[must_use]
    pub fn indirect(address: u64, target_expr: impl Into<String>, args: Vec<CallArgument>) -> Self {
        Self {
            address,
            callee: None,
            target_expr: target_expr.into(),
            args,
            return_vars: Vec::new(),
            is_indirect: true,
            is_virtual: false,
        }
    }

    /// Mark this call as a virtual dispatch.
    #[must_use]
    pub const fn virtual_call(mut self) -> Self {
        self.is_virtual = true;
        self
    }

    /// Number of arguments.
    #[must_use]
    pub const fn arg_count(&self) -> usize {
        self.args.len()
    }

    /// Whether this call is resolved to a concrete callee.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        self.callee.is_some()
    }
}

/// An argument passed at a call site.
#[derive(Debug, Clone)]
pub struct CallArgument {
    /// Position (0-indexed).
    pub position: usize,
    /// MLIL expression for this argument.
    pub expr: String,
    /// Concrete value if known.
    pub concrete_value: Option<u64>,
}

impl CallArgument {
    #[must_use]
    pub fn new(position: usize, expr: impl Into<String>) -> Self {
        Self {
            position,
            expr: expr.into(),
            concrete_value: None,
        }
    }

    #[must_use]
    pub const fn with_value(mut self, v: u64) -> Self {
        self.concrete_value = Some(v);
        self
    }
}

// ── ArgumentMapping ───────────────────────────────────────────────────────────

/// Maps formal parameters to call-site arguments for a given callee.
#[derive(Debug, Clone)]
pub struct ArgumentMapping {
    pub callee: u64,
    /// Map from formal parameter index to the SSA variable supplying its value.
    pub param_to_var: HashMap<usize, SsaVar>,
    /// Map from formal parameter index to concrete value.
    pub param_to_value: HashMap<usize, u64>,
}

impl ArgumentMapping {
    #[must_use]
    pub fn new(callee: u64) -> Self {
        Self {
            callee,
            param_to_var: HashMap::new(),
            param_to_value: HashMap::new(),
        }
    }

    /// Record that parameter `param` is supplied by SSA variable `var`.
    pub fn map_param_var(&mut self, param: usize, var: SsaVar) {
        self.param_to_var.insert(param, var);
    }

    /// Record that parameter `param` has concrete value `v`.
    pub fn map_param_value(&mut self, param: usize, v: u64) {
        self.param_to_value.insert(param, v);
    }

    /// Get the SSA variable for a parameter.
    #[must_use]
    pub fn var_for_param(&self, param: usize) -> Option<&SsaVar> {
        self.param_to_var.get(&param)
    }

    /// Get the concrete value for a parameter.
    #[must_use]
    pub fn value_for_param(&self, param: usize) -> Option<u64> {
        self.param_to_value.get(&param).copied()
    }

    /// Count of mapped parameters.
    #[must_use]
    pub fn mapped_count(&self) -> usize {
        self.param_to_var.len() + self.param_to_value.len()
    }
}

// ── ReturnValueTracking ───────────────────────────────────────────────────────

/// Tracks where return values from calls flow.
#[derive(Debug, Clone)]
pub struct ReturnValueTracking {
    /// Map from call-site address to the SSA var receiving the return value.
    pub call_to_retvar: HashMap<u64, Vec<SsaVar>>,
    /// Map from callee to all SSA vars receiving its return across call sites.
    pub callee_to_vars: HashMap<u64, Vec<SsaVar>>,
    /// Whether any call's return value flows to a security-sensitive sink.
    pub flows_to_sink: HashSet<u64>,
}

impl ReturnValueTracking {
    #[must_use]
    pub fn new() -> Self {
        Self {
            call_to_retvar: HashMap::new(),
            callee_to_vars: HashMap::new(),
            flows_to_sink: HashSet::new(),
        }
    }

    /// Record that `call_addr`'s return flows into `var`.
    pub fn record(&mut self, call_addr: u64, callee: Option<u64>, var: SsaVar) {
        self.call_to_retvar
            .entry(call_addr)
            .or_default()
            .push(var.clone());
        if let Some(callee_addr) = callee {
            self.callee_to_vars
                .entry(callee_addr)
                .or_default()
                .push(var);
        }
    }

    /// Mark a call site as flowing to a sink.
    pub fn mark_sink(&mut self, call_addr: u64) {
        self.flows_to_sink.insert(call_addr);
    }

    /// Return all SSA vars that receive the return of a given callee.
    #[must_use]
    pub fn vars_from_callee(&self, callee: u64) -> &[SsaVar] {
        self.callee_to_vars
            .get(&callee)
            .map_or(&[], |v| v.as_slice())
    }

    /// Whether the return of call at `addr` flows to a sink.
    #[must_use]
    pub fn is_sink_flow(&self, addr: u64) -> bool {
        self.flows_to_sink.contains(&addr)
    }

    /// Total call sites tracked.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.call_to_retvar.len()
    }
}

impl Default for ReturnValueTracking {
    fn default() -> Self {
        Self::new()
    }
}

// ── IndirectCallResolver ──────────────────────────────────────────────────────

/// Resolves indirect calls by tracking register/variable values at call sites.
#[derive(Debug, Default)]
pub struct IndirectCallResolver {
    /// Map from call-site address to resolved callee candidates.
    pub resolutions: HashMap<u64, Vec<u64>>,
    /// Register state (simplified: last assigned value per register).
    reg_state: HashMap<String, u64>,
    /// Memory state (address → value).
    mem_state: HashMap<u64, u64>,
}

impl IndirectCallResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a register assignment in the current state.
    pub fn assign_reg(&mut self, reg: impl Into<String>, value: u64) {
        self.reg_state.insert(reg.into(), value);
    }

    /// Record a memory write.
    pub fn write_mem(&mut self, addr: u64, value: u64) {
        self.mem_state.insert(addr, value);
    }

    /// Attempt to resolve an indirect call target expression.
    #[must_use]
    pub fn resolve_expr(&self, expr: &MlilExpr) -> Option<u64> {
        match expr {
            MlilExpr::Const { value, .. } => Some(*value),
            MlilExpr::Var { var, .. } => self.reg_state.get(&var.name).copied(),
            MlilExpr::Load { addr, .. } => {
                let mem_addr = self.resolve_expr(addr)?;
                self.mem_state.get(&mem_addr).copied()
            }
            _ => None,
        }
    }

    /// Try to resolve all indirect calls in a function.
    pub fn resolve_function(&mut self, func: &MlilFunction) {
        for block in &func.blocks {
            for ai in &block.instrs {
                if let MlilInstruction::Call { dest, .. } = &ai.instr
                    && let Some(callee) = self.resolve_expr(dest) {
                        self.resolutions
                            .entry(ai.address.as_u64())
                            .or_default()
                            .push(callee);
                    }
                // Update state from assignments
                if let MlilInstruction::Assign { dest, src, .. } = &ai.instr
                    && let Some(v) = self.try_constant(src) {
                        self.reg_state.insert(dest.name.clone(), v);
                    }
            }
        }
    }

    const fn try_constant(&self, expr: &MlilExpr) -> Option<u64> {
        if let MlilExpr::Const { value, .. } = expr {
            Some(*value)
        } else {
            None
        }
    }

    /// Count of fully resolved indirect calls.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolutions.values().filter(|v| !v.is_empty()).count()
    }

    /// All unique callee targets discovered.
    #[must_use]
    pub fn all_targets(&self) -> Vec<u64> {
        let mut targets: Vec<u64> = self.resolutions.values().flatten().copied().collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }
}

// ── VirtualCallResolver ───────────────────────────────────────────────────────

/// Resolves virtual (vtable-based) function calls in C++ style binaries.
///
/// Recognizes the pattern: `load [obj_ptr + vtable_offset]` where the vtable
/// holds function pointers.
#[derive(Debug, Default)]
pub struct VirtualCallResolver {
    /// Map from (`vtable_addr`, `slot_index`) → concrete function address.
    pub vtable_entries: HashMap<(u64, usize), u64>,
    /// Map from class name → vtable address.
    pub class_vtables: HashMap<String, u64>,
    /// Resolved virtual calls: call-site address → callee candidates.
    pub resolved: HashMap<u64, Vec<u64>>,
}

impl VirtualCallResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a vtable for a class.
    pub fn register_class(&mut self, class_name: impl Into<String>, vtable_addr: u64) {
        self.class_vtables.insert(class_name.into(), vtable_addr);
    }

    /// Register a function pointer at vtable slot.
    pub fn register_entry(&mut self, vtable_addr: u64, slot: usize, func_addr: u64) {
        self.vtable_entries.insert((vtable_addr, slot), func_addr);
    }

    /// Try to resolve a virtual call given the vtable address and slot.
    #[must_use]
    pub fn resolve(&self, vtable_addr: u64, slot: usize) -> Option<u64> {
        self.vtable_entries.get(&(vtable_addr, slot)).copied()
    }

    /// Get all vtables for a class name.
    #[must_use]
    pub fn vtable_for(&self, class_name: &str) -> Option<u64> {
        self.class_vtables.get(class_name).copied()
    }

    /// Record a resolved virtual call.
    pub fn record_resolution(&mut self, call_addr: u64, callee: u64) {
        self.resolved.entry(call_addr).or_default().push(callee);
    }

    /// Count of registered vtable entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.vtable_entries.len()
    }

    /// All unique callees resolved via vtable dispatch.
    #[must_use]
    pub fn all_callees(&self) -> Vec<u64> {
        let mut callees: Vec<u64> = self.vtable_entries.values().copied().collect();
        callees.sort_unstable();
        callees.dedup();
        callees
    }

    /// Return all registered class names.
    #[must_use]
    pub fn class_names(&self) -> Vec<&str> {
        self.class_vtables.keys().map(std::string::String::as_str).collect()
    }

    /// Return all vtable addresses.
    #[must_use]
    pub fn vtable_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.vtable_entries.keys().map(|&(vt, _)| vt).collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// Maximum slot index registered for any vtable.
    #[must_use]
    pub fn max_slot(&self) -> Option<usize> {
        self.vtable_entries.keys().map(|&(_, slot)| slot).max()
    }
}

// ── CallChainAnalyzer ─────────────────────────────────────────────────────────

/// Tracks call chains: sequences of function calls from an entry point.
#[derive(Debug, Default)]
pub struct CallChainAnalyzer {
    /// Known call edges (caller → callees).
    pub edges: HashMap<u64, Vec<u64>>,
}

impl CallChainAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a direct call edge.
    pub fn add_edge(&mut self, caller: u64, callee: u64) {
        self.edges.entry(caller).or_default().push(callee);
    }

    /// Enumerate all call chains from `start` up to `max_depth`.
    #[must_use]
    pub fn enumerate_chains(&self, start: u64, max_depth: usize) -> Vec<Vec<u64>> {
        let mut result = Vec::new();
        self.dfs(start, &mut vec![start], max_depth, &mut result);
        result
    }

    fn dfs(&self, node: u64, current: &mut Vec<u64>, max_depth: usize, result: &mut Vec<Vec<u64>>) {
        if current.len() > max_depth {
            result.push(current.clone());
            return;
        }
        match self.edges.get(&node) {
            None => {
                result.push(current.clone());
            }
            Some(callees) if callees.is_empty() => {
                result.push(current.clone());
            }
            Some(callees) => {
                for &callee in callees {
                    if !current.contains(&callee) {
                        current.push(callee);
                        self.dfs(callee, current, max_depth, result);
                        current.pop();
                    }
                }
            }
        }
    }

    /// Longest chain from `start`.
    #[must_use]
    pub fn longest_chain(&self, start: u64) -> Vec<u64> {
        let chains = self.enumerate_chains(start, 50);
        chains
            .into_iter()
            .max_by_key(std::vec::Vec::len)
            .unwrap_or_default()
    }
}

// ── MlilCallAnalysis ──────────────────────────────────────────────────────────

/// Main call analysis engine for MLIL functions.
pub struct MlilCallAnalysis {
    pub call_sites: Vec<CallSite>,
    pub argument_mappings: Vec<ArgumentMapping>,
    pub return_tracking: ReturnValueTracking,
    pub indirect_resolver: IndirectCallResolver,
    pub virtual_resolver: VirtualCallResolver,
}

impl MlilCallAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            call_sites: Vec::new(),
            argument_mappings: Vec::new(),
            return_tracking: ReturnValueTracking::new(),
            indirect_resolver: IndirectCallResolver::new(),
            virtual_resolver: VirtualCallResolver::new(),
        }
    }

    /// Analyze an MLIL function to extract all call sites.
    pub fn analyze_function(&mut self, func: &MlilFunction) {
        for block in &func.blocks {
            for annotated in &block.instrs {
                if let MlilInstruction::Call {
                    dest,
                    args,
                    ret_vars,
                } = &annotated.instr
                {
                    let is_indirect = !matches!(dest, MlilExpr::Const { .. });
                    let call_args: Vec<CallArgument> = args
                        .iter()
                        .enumerate()
                        .map(|(i, arg)| {
                            let expr = format!("{arg:?}");
                            let concrete = if let MlilExpr::Const { value, .. } = arg {
                                Some(*value)
                            } else {
                                None
                            };
                            CallArgument {
                                position: i,
                                expr,
                                concrete_value: concrete,
                            }
                        })
                        .collect();

                    let callee = if let MlilExpr::Const { value, .. } = dest {
                        Some(*value)
                    } else {
                        None
                    };
                    let addr_u64 = annotated.address.as_u64();
                    let mut site = if is_indirect {
                        CallSite::indirect(addr_u64, format!("{dest:?}"), call_args)
                    } else {
                        CallSite::direct(addr_u64, callee.unwrap_or(0), call_args)
                    };
                    site.return_vars.clone_from(ret_vars);

                    // Record return value tracking
                    for var in &site.return_vars {
                        self.return_tracking.record(addr_u64, callee, var.clone());
                    }

                    self.call_sites.push(site);
                }
            }
        }

        // Run indirect resolver
        self.indirect_resolver.resolve_function(func);
    }

    /// Analyze multiple functions and merge results.
    pub fn analyze_functions(&mut self, funcs: &[MlilFunction]) {
        for func in funcs {
            self.analyze_function(func);
        }
    }

    /// Return the call site at a specific address, if any.
    #[must_use]
    pub fn site_at(&self, addr: u64) -> Option<&CallSite> {
        self.call_sites.iter().find(|s| s.address == addr)
    }

    /// Return all direct call sites.
    #[must_use]
    pub fn direct_calls(&self) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|s| !s.is_indirect).collect()
    }

    /// Return all indirect call sites.
    #[must_use]
    pub fn indirect_calls(&self) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|s| s.is_indirect).collect()
    }

    /// Return all virtual call sites.
    #[must_use]
    pub fn virtual_calls(&self) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|s| s.is_virtual).collect()
    }

    /// Total call site count.
    #[must_use]
    pub const fn total_calls(&self) -> usize {
        self.call_sites.len()
    }

    /// Collect all unique callee addresses from direct calls.
    #[must_use]
    pub fn all_callees(&self) -> Vec<u64> {
        let mut callees: Vec<u64> = self.call_sites.iter().filter_map(|s| s.callee).collect();
        callees.sort_unstable();
        callees.dedup();
        callees
    }

    /// Find call sites that call a specific callee.
    #[must_use]
    pub fn calls_to(&self, callee: u64) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|s| s.callee == Some(callee))
            .collect()
    }

    /// Build an argument mapping for the given call site.
    #[must_use]
    pub fn build_mapping(&self, site: &CallSite) -> Option<ArgumentMapping> {
        let callee = site.callee?;
        let mut mapping = ArgumentMapping::new(callee);
        for arg in &site.args {
            if let Some(v) = arg.concrete_value {
                mapping.map_param_value(arg.position, v);
            }
        }
        Some(mapping)
    }

    /// Return call sites with more than `n` arguments.
    #[must_use]
    pub fn calls_with_many_args(&self, n: usize) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|s| s.arg_count() > n)
            .collect()
    }
}

impl Default for MlilCallAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ── CallGraphBuilder ──────────────────────────────────────────────────────────

/// Builds a call graph from multiple analyzed functions.
#[derive(Debug, Default)]
pub struct CallGraphBuilder {
    /// Map from function entry address → set of callee addresses.
    pub edges: HashMap<u64, HashSet<u64>>,
    /// Map from function entry address → function name.
    pub names: HashMap<u64, String>,
}

impl CallGraphBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function name.
    pub fn register_name(&mut self, addr: u64, name: impl Into<String>) {
        self.names.insert(addr, name.into());
    }

    /// Add edges from a completed `MlilCallAnalysis`.
    pub fn add_from_analysis(&mut self, func_entry: u64, analysis: &MlilCallAnalysis) {
        for callee in analysis.all_callees() {
            self.edges.entry(func_entry).or_default().insert(callee);
        }
    }

    /// Return all callees of a function.
    #[must_use]
    pub fn callees_of(&self, func: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .edges
            .get(&func)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        v.sort_unstable();
        v
    }

    /// Return all callers of a function.
    #[must_use]
    pub fn callers_of(&self, func: u64) -> Vec<u64> {
        let mut callers: Vec<u64> = self
            .edges
            .iter()
            .filter(|(_, callees)| callees.contains(&func))
            .map(|(&caller, _)| caller)
            .collect();
        callers.sort_unstable();
        callers
    }

    /// Total number of distinct functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        let mut funcs: HashSet<u64> = self.edges.keys().copied().collect();
        for callees in self.edges.values() {
            funcs.extend(callees);
        }
        funcs.len()
    }

    /// Total call edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|s| s.len()).sum()
    }

    /// BFS reachability from a root function.
    #[must_use]
    pub fn reachable_from(&self, root: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(root);
        while let Some(f) = queue.pop_front() {
            if !visited.insert(f) {
                continue;
            }
            if let Some(callees) = self.edges.get(&f) {
                for &callee in callees {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// Check if `a` transitively calls `b`.
    #[must_use]
    pub fn calls_transitively(&self, a: u64, b: u64) -> bool {
        let reachable = self.reachable_from(a);
        reachable.contains(&b)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlilAnnotatedInstr, MlilBasicBlock, Size};
    use rustre_core::address::Address;

    fn ssa(name: &str, v: u32) -> SsaVar {
        SsaVar {
            name: name.into(),
            version: v,
        }
    }
    fn c_expr(v: u64) -> MlilExpr {
        MlilExpr::Const {
            value: v,
            size: Size::QWord,
        }
    }

    fn make_call_instr(addr: u64, target: u64, args: Vec<MlilExpr>) -> MlilAnnotatedInstr {
        MlilAnnotatedInstr {
            address: Address::new(addr),
            instr: MlilInstruction::Call {
                dest: c_expr(target),
                args,
                ret_vars: vec![ssa("rax", 1)],
            },
        }
    }

    fn make_indirect_call(addr: u64, reg_name: &str) -> MlilAnnotatedInstr {
        MlilAnnotatedInstr {
            address: Address::new(addr),
            instr: MlilInstruction::Call {
                dest: MlilExpr::Var {
                    var: ssa(reg_name, 0),
                    size: Size::QWord,
                },
                args: vec![],
                ret_vars: vec![],
            },
        }
    }

    fn simple_func(instrs: Vec<MlilAnnotatedInstr>) -> MlilFunction {
        let mut func = MlilFunction::new(Address::new(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x2000),
            instrs,
            predecessors: Vec::new(),
            successors: Vec::new(),
        });
        func
    }

    // ── CallSite ──────────────────────────────────────────────────────────────

    #[test]
    fn test_callsite_direct_fields() {
        let site = CallSite::direct(0x1000, 0x2000, vec![]);
        assert_eq!(site.address, 0x1000);
        assert_eq!(site.callee, Some(0x2000));
        assert!(!site.is_indirect);
        assert!(site.is_resolved());
    }

    #[test]
    fn test_callsite_indirect_fields() {
        let site = CallSite::indirect(0x1000, "rcx", vec![]);
        assert!(site.is_indirect);
        assert!(!site.is_resolved());
    }

    #[test]
    fn test_callsite_virtual_flag() {
        let site = CallSite::indirect(0x1000, "*[rcx+8]", vec![]).virtual_call();
        assert!(site.is_virtual);
    }

    #[test]
    fn test_callsite_arg_count() {
        let site = CallSite::direct(
            0x1000,
            0x2000,
            vec![CallArgument::new(0, "rdi"), CallArgument::new(1, "rsi")],
        );
        assert_eq!(site.arg_count(), 2);
    }

    // ── CallArgument ──────────────────────────────────────────────────────────

    #[test]
    fn test_call_argument_with_value() {
        let arg = CallArgument::new(0, "rdi").with_value(42);
        assert_eq!(arg.concrete_value, Some(42));
        assert_eq!(arg.position, 0);
    }

    // ── ArgumentMapping ───────────────────────────────────────────────────────

    #[test]
    fn test_argument_mapping_map_var() {
        let mut m = ArgumentMapping::new(0x2000);
        m.map_param_var(0, ssa("rdi", 1));
        assert!(m.var_for_param(0).is_some());
        assert_eq!(m.mapped_count(), 1);
    }

    #[test]
    fn test_argument_mapping_map_value() {
        let mut m = ArgumentMapping::new(0x2000);
        m.map_param_value(1, 0xFF);
        assert_eq!(m.value_for_param(1), Some(0xFF));
        assert_eq!(m.value_for_param(0), None);
    }

    // ── ReturnValueTracking ───────────────────────────────────────────────────

    #[test]
    fn test_retval_record_and_retrieve() {
        let mut rv = ReturnValueTracking::new();
        rv.record(0x1000, Some(0x2000), ssa("rax", 1));
        let vars = rv.vars_from_callee(0x2000);
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_retval_sink_tracking() {
        let mut rv = ReturnValueTracking::new();
        rv.mark_sink(0x1000);
        assert!(rv.is_sink_flow(0x1000));
        assert!(!rv.is_sink_flow(0x2000));
    }

    // ── IndirectCallResolver ──────────────────────────────────────────────────

    #[test]
    fn test_indirect_resolver_const() {
        let r = IndirectCallResolver::new();
        let result = r.resolve_expr(&c_expr(0xDEAD_BEEF));
        assert_eq!(result, Some(0xDEAD_BEEF));
    }

    #[test]
    fn test_indirect_resolver_reg() {
        let mut r = IndirectCallResolver::new();
        r.assign_reg("rcx", 0x4000);
        let expr = MlilExpr::Var {
            var: ssa("rcx", 0),
            size: Size::QWord,
        };
        assert_eq!(r.resolve_expr(&expr), Some(0x4000));
    }

    // ── VirtualCallResolver ───────────────────────────────────────────────────

    #[test]
    fn test_vtable_register_and_resolve() {
        let mut v = VirtualCallResolver::new();
        v.register_entry(0x5000, 0, 0x6000);
        v.register_entry(0x5000, 1, 0x6100);
        assert_eq!(v.resolve(0x5000, 0), Some(0x6000));
        assert_eq!(v.resolve(0x5000, 1), Some(0x6100));
        assert_eq!(v.resolve(0x5000, 2), None);
    }

    // ── MlilCallAnalysis ──────────────────────────────────────────────────────

    #[test]
    fn test_analysis_extract_direct_call() {
        let func = simple_func(vec![make_call_instr(0x1000, 0x2000, vec![])]);
        let mut analysis = MlilCallAnalysis::new();
        analysis.analyze_function(&func);
        assert_eq!(analysis.total_calls(), 1);
        assert_eq!(analysis.direct_calls().len(), 1);
        assert_eq!(analysis.direct_calls()[0].callee, Some(0x2000));
    }

    #[test]
    fn test_analysis_extract_indirect_call() {
        let func = simple_func(vec![make_indirect_call(0x1000, "rcx")]);
        let mut analysis = MlilCallAnalysis::new();
        analysis.analyze_function(&func);
        assert_eq!(analysis.indirect_calls().len(), 1);
    }

    #[test]
    fn test_analysis_all_callees_deduped() {
        let func = simple_func(vec![
            make_call_instr(0x1000, 0x2000, vec![]),
            make_call_instr(0x1010, 0x2000, vec![]),
            make_call_instr(0x1020, 0x3000, vec![]),
        ]);
        let mut analysis = MlilCallAnalysis::new();
        analysis.analyze_function(&func);
        let callees = analysis.all_callees();
        assert_eq!(callees.len(), 2);
    }

    // ── CallGraphBuilder ──────────────────────────────────────────────────────

    #[test]
    fn test_call_graph_callers_of() {
        let mut cgb = CallGraphBuilder::new();
        cgb.edges.entry(0x1000).or_default().insert(0x2000);
        cgb.edges.entry(0x3000).or_default().insert(0x2000);
        let callers = cgb.callers_of(0x2000);
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_call_graph_reachable_from() {
        let mut cgb = CallGraphBuilder::new();
        cgb.edges.entry(0x1000).or_default().insert(0x2000);
        cgb.edges.entry(0x2000).or_default().insert(0x3000);
        let reachable = cgb.reachable_from(0x1000);
        assert!(reachable.contains(&0x3000));
    }
}
