//! `interprocedural` — Interprocedural taint analysis.
//!
//! Provides:
//! - [`CallGraph`]: builds a directed call graph from LLIL instruction sequences.
//! - [`FuncTaintSummary`]: per-function taint summary (which args propagate to return,
//!   which args are sinks, which are sanitizers).
//! - [`IpaTaintAnalyzer`]: drives bottom-up summary computation + top-down
//!   propagation, handling transitive flows across 3+ call levels.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{EdgeRef, Topo};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_core::binary_view::BinaryView;

use crate::{
    FindingType, TaintExpr, TaintFinding, TaintId, TaintInstr, TaintReport, TaintState,
    TaintedValue, eval_taint, eval_value, taint_bits,
};

/// Re-export of the intra-procedural call summary type used by the
/// interprocedural analysis; callers can build summaries directly.
pub use crate::CallSummary;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IpaError {
    #[error("function {0:#x} not found in call graph")]
    FunctionNotFound(u64),
    #[error("call graph contains a cycle involving {0:#x}")]
    CycleDetected(u64),
    #[error("analysis depth limit {0} exceeded")]
    DepthLimitExceeded(usize),
    #[error("summary computation failed for {0:#x}: {1}")]
    SummaryError(u64, String),
}

// ─── CallSite ────────────────────────────────────────────────────────────────

/// A single call instruction observed in a function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// Resolved target address (0 if unresolved / indirect).
    pub target_addr: u64,
    /// Target function name, if known.
    pub target_name: Option<String>,
    /// Argument expressions at the call site.
    pub args: Vec<TaintExpr>,
}

// ─── FuncTaintSummary ─────────────────────────────────────────────────────────

/// Interprocedural taint summary for one function.
///
/// Captures:
/// - Which argument positions flow into the return value.
/// - Which argument positions are unconditionally sanitized (output is clean).
/// - Which argument positions are dangerous sinks (trigger a finding).
/// - The taint of the return value as a function of input arg taints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncTaintSummary {
    /// Function address.
    pub func_addr: u64,
    /// Optional name.
    pub name: Option<String>,
    /// `arg_to_return[i]` = `true` iff arg `i` may taint the return value.
    pub arg_to_return: Vec<bool>,
    /// `arg_sanitized[i]` = `true` iff arg `i` is sanitized before use.
    pub arg_sanitized: Vec<bool>,
    /// `arg_is_sink[i]` = type of finding if arg `i` reaches a dangerous sink.
    pub arg_is_sink: Vec<Option<FindingType>>,
    /// Whether this function always terminates (e.g. `exit`).
    pub never_returns: bool,
    /// Whether this summary was computed analytically (`false`) or is a stub.
    pub is_stub: bool,
    /// Which (`arg_idx`, `arg_idx`) pairs propagate taint between argument pointers.
    pub arg_to_arg: Vec<(usize, usize)>,
    /// Maximum call depth at which this summary was derived.
    pub derived_at_depth: usize,
}

impl FuncTaintSummary {
    /// Create a conservative stub: all args propagate to return.
    #[must_use]
    pub fn stub(func_addr: u64, num_args: usize) -> Self {
        Self {
            func_addr,
            name: None,
            arg_to_return: vec![true; num_args],
            arg_sanitized: vec![false; num_args],
            arg_is_sink: vec![None; num_args],
            never_returns: false,
            is_stub: true,
            arg_to_arg: Vec::new(),
            derived_at_depth: 0,
        }
    }

    /// Create a "clean return" summary: return value is never tainted.
    #[must_use]
    pub fn clean_return(func_addr: u64, num_args: usize) -> Self {
        Self {
            func_addr,
            name: None,
            arg_to_return: vec![false; num_args],
            arg_sanitized: vec![false; num_args],
            arg_is_sink: vec![None; num_args],
            never_returns: false,
            is_stub: false,
            arg_to_arg: Vec::new(),
            derived_at_depth: 0,
        }
    }

    /// Propagate `arg_taints` through this summary, returning the taint of
    /// the return value.
    #[must_use]
    pub fn propagate(&self, arg_taints: &[TaintId]) -> TaintId {
        arg_taints
            .iter()
            .enumerate()
            .filter(|(i, _)| self.arg_to_return.get(*i).copied().unwrap_or(true))
            .fold(taint_bits::NONE, |acc, (_, &t)| acc | t)
    }

    /// Return any findings triggered when `arg_taints` reach this function.
    #[must_use]
    pub fn check_sinks(&self, arg_taints: &[TaintId], call_addr: u64) -> Vec<TaintFinding> {
        let mut findings = Vec::new();
        for (i, sink_type) in self.arg_is_sink.iter().enumerate() {
            if let Some(ft) = sink_type {
                let t = arg_taints.get(i).copied().unwrap_or(taint_bits::NONE);
                if taint_bits::is_tainted(t) {
                    findings.push(TaintFinding::new(
                        ft.clone(),
                        call_addr,
                        t,
                        format!(
                            "Tainted arg[{i}] flows into sink in {:?}",
                            self.name.as_deref().unwrap_or("unknown")
                        ),
                    ));
                }
            }
        }
        findings
    }

    /// Return the display name.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("fn_{:#x}", self.func_addr))
    }
}

// ─── CallGraph ────────────────────────────────────────────────────────────────

/// Directed call graph: node = function address, edge = call relationship.
#[derive(Debug)]
pub struct CallGraph {
    /// Directed graph: each node stores the function address.
    pub graph: DiGraph<u64, CallSite>,
    /// Address → `NodeIndex` mapping.
    pub addr_to_node: HashMap<u64, NodeIndex>,
    /// Per-function: ordered list of LLIL instructions.
    pub func_bodies: HashMap<u64, Vec<TaintInstr>>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            addr_to_node: HashMap::new(),
            func_bodies: HashMap::new(),
        }
    }

    /// Ensure a function node exists and return its index.
    pub fn ensure_node(&mut self, func_addr: u64) -> NodeIndex {
        if let Some(&idx) = self.addr_to_node.get(&func_addr) {
            return idx;
        }
        let idx = self.graph.add_node(func_addr);
        self.addr_to_node.insert(func_addr, idx);
        idx
    }

    /// Register a function body (LLIL instructions).
    pub fn add_function(&mut self, func_addr: u64, instrs: Vec<TaintInstr>) {
        self.ensure_node(func_addr);
        self.func_bodies.insert(func_addr, instrs);
    }

    /// Add a call edge from `caller` to `callee_fn`, recording the call site.
    pub fn add_call_edge(&mut self, caller: u64, callee_fn: u64, site: CallSite) {
        let from = self.ensure_node(caller);
        let to = self.ensure_node(callee_fn);
        self.graph.add_edge(from, to, site);
    }

    /// Build the call graph by scanning LLIL instruction sequences.
    ///
    /// Extracts all `TaintInstr::Call` instructions from `func_bodies` and
    /// adds call edges. Unresolved (target = 0) calls are skipped.
    pub fn build_from_bodies(&mut self) {
        let funcs: Vec<(u64, Vec<TaintInstr>)> = self
            .func_bodies
            .iter()
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        for (caller_addr, instrs) in funcs {
            for instr in &instrs {
                if let TaintInstr::Call { target, args, addr } = instr {
                    // Attempt to resolve target as a concrete address string.
                    // In LLIL the target is a name; resolve via a stub numeric parse.
                    let target_addr = target.parse::<u64>().ok().unwrap_or(0);
                    if target_addr != 0 {
                        let site = CallSite {
                            call_addr: *addr,
                            target_addr,
                            target_name: Some(target.clone()),
                            args: args.clone(),
                        };
                        self.add_call_edge(caller_addr, target_addr, site);
                    }
                }
            }
        }
    }

    /// Return all callees (direct successors) of `func_addr`.
    #[must_use]
    pub fn callees(&self, func_addr: u64) -> Vec<u64> {
        let Some(&idx) = self.addr_to_node.get(&func_addr) else { return Vec::new() };
        self.graph
            .edges(idx)
            .map(|e| *self.graph.node_weight(e.target()).unwrap_or(&0))
            .collect()
    }

    /// Return all callers (direct predecessors) of `func_addr`.
    #[must_use]
    pub fn callers(&self, func_addr: u64) -> Vec<u64> {
        let Some(&idx) = self.addr_to_node.get(&func_addr) else { return Vec::new() };
        self.graph
            .edges_directed(idx, petgraph::Direction::Incoming)
            .map(|e| *self.graph.node_weight(e.source()).unwrap_or(&0))
            .collect()
    }

    /// Return the number of functions in the graph.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return `true` if `caller` directly calls `callee_fn`.
    #[must_use]
    pub fn has_direct_call(&self, caller: u64, callee_fn: u64) -> bool {
        let Some(&from) = self.addr_to_node.get(&caller) else { return false };
        let Some(&to) = self.addr_to_node.get(&callee_fn) else { return false };
        self.graph.contains_edge(from, to)
    }

    /// Compute a topological order of function addresses, **callers first**.
    ///
    /// Edges run caller → callee, so this emits roots (functions nobody calls)
    /// before the functions they call. For a bottom-up pass — where a callee's
    /// summary must already exist when its caller is processed — use
    /// [`CallGraph::reverse_topo_order`] instead.
    ///
    /// # Errors
    /// Returns [`IpaError::CycleDetected`] if the graph contains a cycle.
    pub fn topo_order(&self) -> Result<Vec<u64>, IpaError> {
        let mut order = Vec::new();
        let mut topo = Topo::new(&self.graph);
        while let Some(idx) = topo.next(&self.graph) {
            if let Some(&addr) = self.graph.node_weight(idx) {
                order.push(addr);
            }
        }
        if order.len() < self.graph.node_count() {
            // Not all nodes visited → cycle exists.
            return Err(IpaError::CycleDetected(0));
        }
        Ok(order)
    }

    /// Compute a **bottom-up** order of function addresses: leaves first.
    ///
    /// This is the order a summary-based interprocedural analysis needs — every
    /// callee is emitted before any of its callers, so its summary is already
    /// available when the caller is processed.
    ///
    /// # Errors
    /// Returns [`IpaError::CycleDetected`] if the graph contains a cycle.
    pub fn reverse_topo_order(&self) -> Result<Vec<u64>, IpaError> {
        let mut order = self.topo_order()?;
        order.reverse();
        Ok(order)
    }

    /// Return all transitive callees of `func_addr` (BFS).
    #[must_use]
    pub fn transitive_callees(&self, func_addr: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(func_addr);
        while let Some(f) = queue.pop_front() {
            if visited.insert(f) {
                for callee in self.callees(f) {
                    queue.push_back(callee);
                }
            }
        }
        visited.remove(&func_addr);
        visited
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ─── IpaConfig ────────────────────────────────────────────────────────────────

/// Configuration for interprocedural analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaConfig {
    /// Maximum call-chain depth before applying a stub summary.
    pub max_depth: usize,
    /// Whether to propagate taint through indirect calls conservatively.
    pub conservative_indirect_calls: bool,
    /// Whether to propagate call-site arg taints into callee in top-down pass.
    pub top_down_propagation: bool,
}

impl Default for IpaConfig {
    fn default() -> Self {
        Self {
            max_depth: 8,
            conservative_indirect_calls: true,
            top_down_propagation: true,
        }
    }
}

// ─── IpaTaintAnalyzer ─────────────────────────────────────────────────────────

/// Interprocedural taint analyzer.
///
/// Drives:
/// 1. Bottom-up summary computation (analyse leaves first, propagate summaries up).
/// 2. Top-down propagation (apply call-site arg taints from entry points downward).
/// 3. Transitive finding detection (flows across 3+ call levels).
pub struct IpaTaintAnalyzer {
    pub config: IpaConfig,
    /// Call graph.
    pub call_graph: CallGraph,
    /// Computed per-function summaries.
    pub summaries: HashMap<u64, FuncTaintSummary>,
    /// Cumulative findings across all functions.
    pub report: TaintReport,
    /// Pre-registered summaries (from external databases / stubs).
    pub external_summaries: HashMap<u64, FuncTaintSummary>,
    /// Name → address for external summaries.
    pub name_to_addr: HashMap<String, u64>,
}

impl IpaTaintAnalyzer {
    /// Create a new analyzer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: IpaConfig::default(),
            call_graph: CallGraph::new(),
            summaries: HashMap::new(),
            report: TaintReport::new(),
            external_summaries: HashMap::new(),
            name_to_addr: HashMap::new(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: IpaConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Register an external function summary.
    pub fn register_external(&mut self, summary: FuncTaintSummary) {
        let addr = summary.func_addr;
        if let Some(name) = &summary.name {
            self.name_to_addr.insert(name.clone(), addr);
        }
        self.external_summaries.insert(addr, summary);
    }

    /// Populate the analyzer with all functions known to a [`BinaryView`].
    ///
    /// For every function defined in the binary view, this method:
    /// - Registers the function address in the call graph so it participates in
    ///   bottom-up summary computation even if its body is not yet lifted.
    /// - Resolves and stores the function name so that `FuncTaintSummary::name`
    ///   is populated from the binary's symbol table rather than left as `None`.
    ///
    /// Call this before [`Self::analyze`] to get human-readable names in reports.
    pub fn populate_from_binary_view(&mut self, view: &BinaryView) {
        let functions = view.functions.read();
        let symbols = view.symbols.read();
        for func in functions.iter_functions() {
            let addr = func.address.0;
            // Ensure the function appears as a node in the call graph.
            self.call_graph.ensure_node(addr);
            // Pre-populate the name→address map from the binary's symbol table.
            self.name_to_addr.insert(func.name.clone(), addr);
            // If the symbol table also has a symbol at this address, record it.
            for sym in symbols.get_symbol_at(func.address) {
                self.name_to_addr.entry(sym.name.clone()).or_insert(addr);
            }
        }
    }

    /// Resolve a target name to its address using the populated name map,
    /// falling back to a numeric parse (for addresses expressed as hex strings).
    #[must_use]
    pub fn resolve_target_name(&self, name: &str) -> Option<u64> {
        if let Some(&addr) = self.name_to_addr.get(name) {
            return Some(addr);
        }
        // Numeric hex/decimal fallback (e.g. "0x401000" or "4198400").
        name.strip_prefix("0x")
            .or_else(|| name.strip_prefix("0X"))
            .map_or_else(|| name.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
    }

    /// Add a function to be analysed.
    pub fn add_function(&mut self, func_addr: u64, instrs: Vec<TaintInstr>) {
        self.call_graph.add_function(func_addr, instrs);
    }

    /// Build the internal call graph from registered function bodies.
    pub fn build_call_graph(&mut self) {
        self.call_graph.build_from_bodies();
    }

    /// Run the full interprocedural analysis.
    ///
    /// 1. Build call graph.
    /// 2. Bottom-up: compute summaries in topological order.
    /// 3. Top-down: propagate taint from entry points.
    ///
    /// # Errors
    /// Returns [`IpaError`] if the bottom-up or top-down pass fails.
    pub fn analyze(&mut self, entry_points: &[u64]) -> Result<(), IpaError> {
        self.build_call_graph();
        self.bottom_up_pass()?;
        if self.config.top_down_propagation {
            for &ep in entry_points {
                let init_state = TaintState::new();
                self.top_down_pass(ep, init_state, 0)?;
            }
        }
        Ok(())
    }

    /// Bottom-up pass: compute summaries for all functions in topological order.
    fn bottom_up_pass(&mut self) -> Result<(), IpaError> {
        // Leaves first: `topo_order` runs caller→callee, so using it here meant
        // every caller was summarised BEFORE its callees existed, and
        // `handle_call` fell back to the conservative branch instead of
        // propagating the callee's real summary.
        let order = self
            .call_graph
            .reverse_topo_order()
            .unwrap_or_else(|_| self.call_graph.addr_to_node.keys().copied().collect());

        for func_addr in order {
            if self.summaries.contains_key(&func_addr) {
                continue;
            }
            let summary = self.compute_summary_for(func_addr, 0)?;
            self.summaries.insert(func_addr, summary);
        }
        Ok(())
    }

    /// Compute a taint summary for `func_addr` at the given recursion `depth`.
    fn compute_summary_for(
        &mut self,
        func_addr: u64,
        depth: usize,
    ) -> Result<FuncTaintSummary, IpaError> {
        if depth > self.config.max_depth {
            return Ok(FuncTaintSummary::stub(func_addr, 6));
        }

        // Use external summary if available.
        if let Some(ext) = self.external_summaries.get(&func_addr) {
            return Ok(ext.clone());
        }

        let instrs = match self.call_graph.func_bodies.get(&func_addr) {
            Some(v) => v.clone(),
            None => return Ok(FuncTaintSummary::stub(func_addr, 6)),
        };

        // Symbolically run with each arg tainted independently.
        let max_args = 6;
        let mut arg_to_return = vec![false; max_args];
        let mut arg_is_sink: Vec<Option<FindingType>> = vec![None; max_args];

        for arg_idx in 0..max_args {
            let mut state = TaintState::new();
            // Mark one argument register as tainted.
            let reg = arg_register(arg_idx);
            state.taint_reg(reg, taint_bits::custom(arg_idx as u8));

            // Snapshot the finding count before analysing this argument so that
            // we can attribute only the *new* findings to the current arg_idx.
            let findings_before = self.report.findings.len();

            for instr in &instrs {
                self.step_with_summaries(instr, &mut state, depth + 1);
            }

            // Check if the taint propagated to the return value (rax).
            let ret_taint = state.reg_taint("rax");
            if taint_bits::has_bit(ret_taint, taint_bits::custom(arg_idx as u8)) {
                arg_to_return[arg_idx] = true;
            }

            // Check for any findings generated *during this arg_idx pass only*.
            if self.report.findings.len() > findings_before {
                let last = self.report.findings.last().expect("just checked len > before");
                arg_is_sink[arg_idx] = Some(last.finding_type.clone());
            }
        }

        Ok(FuncTaintSummary {
            func_addr,
            name: None,
            arg_to_return,
            arg_sanitized: vec![false; max_args],
            arg_is_sink,
            never_returns: false,
            is_stub: false,
            arg_to_arg: Vec::new(),
            derived_at_depth: depth,
        })
    }

    /// Top-down pass: propagate taint from an entry point downward.
    fn top_down_pass(
        &mut self,
        func_addr: u64,
        initial_state: TaintState,
        depth: usize,
    ) -> Result<(), IpaError> {
        if depth > self.config.max_depth {
            return Err(IpaError::DepthLimitExceeded(self.config.max_depth));
        }

        let instrs = match self.call_graph.func_bodies.get(&func_addr) {
            Some(v) => v.clone(),
            None => return Ok(()),
        };

        let mut state = initial_state;
        for instr in &instrs {
            self.step_with_summaries(instr, &mut state, depth + 1);

            // On a Call, recurse into the callee with the callee's initial state.
            if let TaintInstr::Call { target, args, addr } = instr {
                let target_addr = target.parse::<u64>().ok().unwrap_or(0);
                if target_addr != 0 && self.call_graph.func_bodies.contains_key(&target_addr) {
                    let mut callee_state = TaintState::new();
                    // Record the call site so the callee's report can attribute
                    // findings back to the caller.
                    callee_state.cf_taint.insert(*addr);
                    // Seed callee's argument registers with caller's arg taints.
                    for (i, arg_expr) in args.iter().enumerate() {
                        let t = eval_taint(arg_expr, &state);
                        let v = eval_value(arg_expr, &state);
                        let reg = arg_register(i);
                        callee_state.set_reg(reg, TaintedValue::new(v, t));
                    }
                    // Recursively analyse callee (ignore depth errors — just skip).
                    let _ = self.top_down_pass(target_addr, callee_state, depth + 1);
                }
            }
        }
        Ok(())
    }

    /// Step one LLIL instruction, using summaries for calls.
    fn step_with_summaries(&mut self, instr: &TaintInstr, state: &mut TaintState, depth: usize) {
        state.current_ticks += 1;
        match instr {
            TaintInstr::SetReg { reg, src, .. } => {
                let taint = eval_taint(src, state);
                let value = eval_value(src, state);
                state.set_reg(reg, TaintedValue::new(value, taint));
            }
            TaintInstr::Store { dest, val, .. } => {
                let addr_val = eval_value(dest, state);
                let val_taint = eval_taint(val, state);
                let addr_taint = eval_taint(dest, state);
                let value = eval_value(val, state);
                state.set_mem(addr_val, TaintedValue::new(value, val_taint | addr_taint));
            }
            TaintInstr::Call { target, args, addr } => {
                let arg_taints: Vec<TaintId> = args.iter().map(|a| eval_taint(a, state)).collect();

                // Resolve via target address or name.
                let target_addr = target.parse::<u64>().ok().unwrap_or(0);

                let ret_taint = self.handle_call(target, target_addr, &arg_taints, *addr, depth);
                state.set_reg("rax", TaintedValue::new(0, ret_taint));

                // Check for sink findings. The target may be a NAME rather than
                // a numeric address (external summaries registered by
                // `SummaryRegistry::with_libc` are keyed that way), in which
                // case `target.parse::<u64>()` fails and `target_addr` is 0:
                // resolving only by address meant `system`, `execve`, … never
                // produced a finding. `handle_call` already resolves by name
                // via `name_to_addr`; do the same here.
                let resolved_addr = self
                    .name_to_addr
                    .get(target.as_str())
                    .copied()
                    .unwrap_or(target_addr);
                if let Some(summary) = self
                    .summaries
                    .get(&resolved_addr)
                    .cloned()
                    .or_else(|| self.external_summaries.get(&resolved_addr).cloned())
                {
                    let findings = summary.check_sinks(&arg_taints, *addr);
                    for f in findings {
                        self.report.add_finding(f);
                    }
                }
            }
            TaintInstr::Branch { cond, addr } => {
                let taint = eval_taint(cond, state);
                if taint_bits::is_tainted(taint) {
                    state.cf_taint.insert(*addr);
                }
            }
            TaintInstr::Return { val, .. } => {
                if let Some(v) = val {
                    let taint = eval_taint(v, state);
                    state.set_reg("rax", TaintedValue::new(eval_value(v, state), taint));
                }
            }
            TaintInstr::Nop { .. } => {}
        }
    }

    /// Resolve and apply the taint summary for a call.
    fn handle_call(
        &mut self,
        target_name: &str,
        target_addr: u64,
        arg_taints: &[TaintId],
        call_addr: u64,
        depth: usize,
    ) -> TaintId {
        // Bail early if we have already recursed past the configured limit;
        // this also ensures `depth` participates in the analysis rather than
        // silently flowing past as a dead parameter.
        if depth >= self.config.max_depth {
            return arg_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t);
        }
        // 1. Try computed summary.
        if let Some(summary) = self.summaries.get(&target_addr).cloned() {
            return summary.propagate(arg_taints);
        }
        // 2. Try external summary.
        if let Some(summary) = self.external_summaries.get(&target_addr).cloned() {
            return summary.propagate(arg_taints);
        }
        // 3. Try name-based external summary.
        if let Some(&addr) = self.name_to_addr.get(target_name) && let Some(summary) = self.external_summaries.get(&addr).cloned() {
            return summary.propagate(arg_taints);
        }
        // 4. Conservative: union of all arg taints, attributed to the call site.
        if self.config.conservative_indirect_calls {
            let merged = arg_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t);
            if taint_bits::is_tainted(merged) {
                self.report.add_finding(TaintFinding {
                    finding_type: FindingType::Custom(format!(
                        "ConservativeIndirectCall:{target_name}"
                    )),
                    sink_addr: call_addr,
                    source_addr: call_addr,
                    taint_sources: merged,
                    path: vec![call_addr],
                    description: format!(
                        "conservative indirect-call taint to {target_name} at {call_addr:#x}"
                    ),
                });
            }
            return merged;
        }
        taint_bits::NONE
    }

    /// Return the findings collected.
    #[must_use]
    pub fn findings(&self) -> &[crate::TaintFinding] {
        &self.report.findings
    }

    /// Return the summary for a function address.
    #[must_use]
    pub fn summary_for(&self, func_addr: u64) -> Option<&FuncTaintSummary> {
        self.summaries.get(&func_addr)
    }

    /// Detect transitive taint flows: find all (source_fn, sink_fn) pairs where
    /// taint flows across 3+ call levels.
    #[must_use]
    pub fn find_transitive_flows(&self, min_depth: usize) -> Vec<(u64, u64, usize)> {
        let mut flows = Vec::new();
        for (&src, src_sum) in &self.summaries {
            if src_sum.is_stub {
                continue;
            }
            let callees = self.call_graph.transitive_callees(src);
            for callee in callees {
                // Compute the call-chain depth between src and callee.
                let chain_len = self.call_chain_length(src, callee);
                if chain_len >= min_depth && let Some(callee_sum) = self.summaries.get(&callee) && callee_sum.arg_is_sink.iter().any(|s| s.is_some()) {
                    flows.push((src, callee, chain_len));
                }
            }
        }
        flows
    }

    /// Approximate call-chain length from `src` to `dst` via BFS.
    fn call_chain_length(&self, src: u64, dst: u64) -> usize {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back((src, 0usize));
        while let Some((cur, depth)) = queue.pop_front() {
            if cur == dst {
                return depth;
            }
            if !visited.insert(cur) {
                continue;
            }
            for callee in self.call_graph.callees(cur) {
                queue.push_back((callee, depth + 1));
            }
        }
        usize::MAX
    }
}

impl Default for IpaTaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the x86-64 SysV calling convention register name for argument `idx`.
fn arg_register(idx: usize) -> &'static str {
    match idx {
        0 => "rdi",
        1 => "rsi",
        2 => "rdx",
        3 => "rcx",
        4 => "r8",
        5 => "r9",
        _ => "rdi",
    }
}

// ─── SummaryRegistry ─────────────────────────────────────────────────────────

/// A simple name-keyed registry of [`FuncTaintSummary`] values used to
/// pre-populate an [`IpaTaintAnalyzer`] with well-known function behaviours.
#[derive(Debug, Default)]
pub struct SummaryRegistry {
    entries: HashMap<String, FuncTaintSummary>,
}

impl SummaryRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a summary under its display name.
    pub fn register(&mut self, summary: FuncTaintSummary) {
        let key = summary.display_name();
        self.entries.insert(key, summary);
    }

    /// Look up a summary by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FuncTaintSummary> {
        self.entries.get(name)
    }

    /// Apply all registered summaries as external summaries to `analyzer`.
    pub fn apply_to(&self, analyzer: &mut IpaTaintAnalyzer) {
        for summary in self.entries.values() {
            analyzer.register_external(summary.clone());
        }
    }

    /// Return the number of registered summaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build a pre-populated registry with common libc / Win32 summaries.
    #[must_use]
    pub fn with_libc() -> Self {
        let mut reg = Self::new();
        const BASE: u64 = 0xFFFF_1000_0000;

        // strlen: clean return.
        let mut s = FuncTaintSummary::clean_return(BASE | 0x01, 1);
        s.name = Some("strlen".into());
        reg.register(s);

        // malloc: clean return (allocator).
        let mut s = FuncTaintSummary::clean_return(BASE | 0x02, 1);
        s.name = Some("malloc".into());
        reg.register(s);

        // memcpy: arg0 (dest) and arg1 (src) propagate to return; arg1→dest pointer.
        let mut s = FuncTaintSummary::stub(BASE | 0x03, 3);
        s.name = Some("memcpy".into());
        s.arg_to_return = vec![true, false, false]; // returns dest pointer
        s.arg_to_arg = vec![(1, 0)]; // src data flows into dest buffer
        reg.register(s);

        // sprintf: format string sink on arg1.
        let mut s = FuncTaintSummary::stub(BASE | 0x04, 3);
        s.name = Some("sprintf".into());
        s.arg_is_sink[1] = Some(FindingType::FormatString);
        reg.register(s);

        // system: arg0 is command injection sink.
        let mut s = FuncTaintSummary::stub(BASE | 0x05, 1);
        s.name = Some("system".into());
        s.arg_is_sink[0] = Some(FindingType::CommandInjection);
        s.arg_to_return = vec![false];
        reg.register(s);

        // atoi: sanitizer — clean return.
        let mut s = FuncTaintSummary::clean_return(BASE | 0x06, 1);
        s.name = Some("atoi".into());
        reg.register(s);

        reg
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaintInstr;

    fn make_instr_setreg(reg: &str, src_reg: &str, addr: u64) -> TaintInstr {
        TaintInstr::SetReg {
            reg: reg.into(),
            src: TaintExpr::Reg(src_reg.into()),
            addr,
        }
    }

    fn make_call(target: &str, args: Vec<TaintExpr>, addr: u64) -> TaintInstr {
        TaintInstr::Call {
            target: target.into(),
            args,
            addr,
        }
    }

    fn make_ret(reg: &str, addr: u64) -> TaintInstr {
        TaintInstr::Return {
            val: Some(TaintExpr::Reg(reg.into())),
            addr,
        }
    }

    #[test]
    fn test_call_graph_basic() {
        let mut cg = CallGraph::new();
        cg.ensure_node(0x1000);
        cg.ensure_node(0x2000);
        let site = CallSite {
            call_addr: 0x1010,
            target_addr: 0x2000,
            target_name: Some("callee".into()),
            args: vec![],
        };
        cg.add_call_edge(0x1000, 0x2000, site);
        assert!(cg.has_direct_call(0x1000, 0x2000));
        assert!(!cg.has_direct_call(0x2000, 0x1000));
    }

    #[test]
    fn test_call_graph_callees_callers() {
        let mut cg = CallGraph::new();
        cg.ensure_node(0x100);
        cg.ensure_node(0x200);
        cg.ensure_node(0x300);
        let site = |addr, tgt| CallSite {
            call_addr: addr,
            target_addr: tgt,
            target_name: None,
            args: vec![],
        };
        cg.add_call_edge(0x100, 0x200, site(0x110, 0x200));
        cg.add_call_edge(0x100, 0x300, site(0x120, 0x300));

        let callees = cg.callees(0x100);
        assert_eq!(callees.len(), 2);
        let callers = cg.callers(0x200);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], 0x100);
    }

    #[test]
    fn test_call_graph_transitive_callees() {
        let mut cg = CallGraph::new();
        let site = |s, t| CallSite {
            call_addr: s,
            target_addr: t,
            target_name: None,
            args: vec![],
        };
        cg.add_call_edge(0x1, 0x2, site(0x11, 0x2));
        cg.add_call_edge(0x2, 0x3, site(0x21, 0x3));
        cg.add_call_edge(0x3, 0x4, site(0x31, 0x4));

        let tc = cg.transitive_callees(0x1);
        assert!(tc.contains(&0x2));
        assert!(tc.contains(&0x3));
        assert!(tc.contains(&0x4));
        assert!(!tc.contains(&0x1));
    }

    #[test]
    fn test_call_graph_topo_order() {
        let mut cg = CallGraph::new();
        let site = |s, t| CallSite {
            call_addr: s,
            target_addr: t,
            target_name: None,
            args: vec![],
        };
        cg.add_call_edge(0xA, 0xB, site(0xA0, 0xB));
        cg.add_call_edge(0xB, 0xC, site(0xB0, 0xC));

        let order = cg.topo_order().unwrap();
        // In topo order for A→B→C, A comes before B comes before C.
        let pos_a = order.iter().position(|&x| x == 0xA).unwrap();
        let pos_b = order.iter().position(|&x| x == 0xB).unwrap();
        let pos_c = order.iter().position(|&x| x == 0xC).unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn test_func_taint_summary_propagate() {
        let mut sum = FuncTaintSummary::stub(0x100, 3);
        sum.arg_to_return = vec![true, false, true];
        let result = sum.propagate(&[
            taint_bits::USER_INPUT,
            taint_bits::NETWORK,
            taint_bits::FILE,
        ]);
        assert!(taint_bits::has_bit(result, taint_bits::USER_INPUT));
        assert!(!taint_bits::has_bit(result, taint_bits::NETWORK));
        assert!(taint_bits::has_bit(result, taint_bits::FILE));
    }

    #[test]
    fn test_func_taint_summary_clean_return() {
        let sum = FuncTaintSummary::clean_return(0x200, 3);
        let result = sum.propagate(&[
            taint_bits::USER_INPUT,
            taint_bits::NETWORK,
            taint_bits::FILE,
        ]);
        assert_eq!(result, taint_bits::NONE);
    }

    #[test]
    fn test_func_taint_summary_check_sinks() {
        let mut sum = FuncTaintSummary::stub(0x300, 2);
        sum.arg_is_sink[0] = Some(FindingType::CommandInjection);
        let findings = sum.check_sinks(&[taint_bits::USER_INPUT, taint_bits::NONE], 0x400);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FindingType::CommandInjection);
    }

    #[test]
    fn test_ipa_analyzer_simple_flow() {
        // callee: takes rdi, returns rdi via rax.
        // caller: marks rdi tainted, calls callee.
        let callee_addr = 0x2000u64;
        let caller_addr = 0x1000u64;

        let callee_body = vec![
            make_instr_setreg("rax", "rdi", 0x2001),
            make_ret("rax", 0x2010),
        ];

        let caller_body = vec![
            TaintInstr::SetReg {
                reg: "rdi".into(),
                src: TaintExpr::Reg("rdi".into()),
                addr: 0x1001,
            },
            make_call(
                &callee_addr.to_string(),
                vec![TaintExpr::Reg("rdi".into())],
                0x1010,
            ),
        ];

        let mut analyzer = IpaTaintAnalyzer::new();
        analyzer.add_function(callee_addr, callee_body);
        analyzer.add_function(caller_addr, caller_body);

        // Seed rdi in the entry state.
        let mut entry_state = TaintState::new();
        entry_state.taint_reg("rdi", taint_bits::USER_INPUT);

        let result = analyzer.analyze(&[caller_addr]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipa_analyzer_external_summary() {
        let mut analyzer = IpaTaintAnalyzer::new();
        let ext = FuncTaintSummary {
            func_addr: 0x9000,
            name: Some("ext_fn".into()),
            arg_to_return: vec![true],
            arg_sanitized: vec![false],
            arg_is_sink: vec![None],
            never_returns: false,
            is_stub: false,
            arg_to_arg: Vec::new(),
            derived_at_depth: 0,
        };
        analyzer.register_external(ext);

        let result = analyzer.handle_call("ext_fn", 0x9000, &[taint_bits::NETWORK], 0x100, 0);
        assert!(taint_bits::has_bit(result, taint_bits::NETWORK));
    }

    #[test]
    fn test_call_graph_function_count() {
        let mut cg = CallGraph::new();
        cg.ensure_node(0x1);
        cg.ensure_node(0x2);
        cg.ensure_node(0x3);
        assert_eq!(cg.function_count(), 3);
    }

    #[test]
    fn test_arg_register_mapping() {
        assert_eq!(arg_register(0), "rdi");
        assert_eq!(arg_register(1), "rsi");
        assert_eq!(arg_register(2), "rdx");
        assert_eq!(arg_register(3), "rcx");
        assert_eq!(arg_register(4), "r8");
        assert_eq!(arg_register(5), "r9");
    }

    #[test]
    fn test_ipa_config_default() {
        let cfg = IpaConfig::default();
        assert_eq!(cfg.max_depth, 8);
        assert!(cfg.conservative_indirect_calls);
        assert!(cfg.top_down_propagation);
    }

    #[test]
    fn test_call_site_build() {
        let site = CallSite {
            call_addr: 0x1000,
            target_addr: 0x2000,
            target_name: Some("printf".into()),
            args: vec![TaintExpr::Const(0x3000)],
        };
        assert_eq!(site.target_name.as_deref(), Some("printf"));
        assert_eq!(site.args.len(), 1);
    }
}
