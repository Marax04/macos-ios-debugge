//! Interprocedural VSA.
//!
//! Extends the intraprocedural [`crate::VsaAnalyzer`] with:
//!
//! * [`IpProgram`] / [`IpFunction`] — a multi-function program model whose
//!   instructions ([`IpInstr`]) wrap the intraprocedural [`VsaInstr`] and add
//!   direct / indirect call instructions.
//! * [`FunctionSummary`] — per-function input/output effects: which variables
//!   (registers) are *read before written* (i.e. caller-supplied inputs) and
//!   which are *written* together with the value-set they hold on return.
//! * [`CallGraphContext`] — the call graph, its Tarjan SCCs, and per-function
//!   cross-function reaching input states (the join of the states flowing into
//!   the function from every call site plus any externally supplied entry
//!   state).
//! * [`InterproceduralVsa`] — a summary-based worklist fixed-point over the
//!   call graph.  Functions in a non-trivial SCC (direct or mutual recursion)
//!   have their input states *widened* after a bounded number of updates so
//!   the analysis terminates.
//! * Backward slicing from indirect call sites: when the target variable of
//!   an indirect call is unknown inside the containing function, the slicer
//!   walks caller → caller until a constant / global value-set is found.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{ValueSet, VsaAnalyzer, VsaBlock, VsaCfg, VsaError, VsaInstr, VsaState};

// ────────────────────────────────────────────────────────────────────────────
// Program model
// ────────────────────────────────────────────────────────────────────────────

/// An instruction in an interprocedural function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpInstr {
    /// A plain intraprocedural instruction.
    Base(VsaInstr),
    /// A direct call to a named function.
    Call {
        /// Name of the callee function.
        callee: String,
    },
    /// An indirect call through the variable `target`.
    CallIndirect {
        /// Variable holding the call-target address.
        target: String,
    },
}

/// A basic block of [`IpInstr`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlock {
    /// Block index (0-based, must equal its position in the function).
    pub id: usize,
    /// Ordered instructions.
    pub instrs: Vec<IpInstr>,
}

/// A function in an interprocedural program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFunction {
    /// Unique function name.
    pub name: String,
    /// Basic blocks, indexed by id.
    pub blocks: Vec<IpBlock>,
    /// Successor lists, indexed by block id.
    pub successors: Vec<Vec<usize>>,
    /// Entry block id.
    pub entry: usize,
}

/// A whole-program collection of functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpProgram {
    /// All functions, keyed by name.
    pub functions: HashMap<String, IpFunction>,
    /// Names of program entry points (e.g. `main`); these receive the
    /// externally supplied initial state.
    pub entry_points: Vec<String>,
}

impl IpProgram {
    /// Create an empty program.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function to the program.
    pub fn add_function(&mut self, f: IpFunction) {
        self.functions.insert(f.name.clone(), f);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Function summaries
// ────────────────────────────────────────────────────────────────────────────

/// Per-function input/output effect summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Variables read before being written (caller-supplied inputs).
    pub reads: HashSet<String>,
    /// Variables written by the function, with the value-set they hold at
    /// function exit (join over all exit blocks).
    pub writes: HashMap<String, ValueSet>,
}

impl FunctionSummary {
    /// `true` if `self` is subsumed by `other` (used for fixed-point checks).
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        self.reads.is_subset(&other.reads)
            && self.writes.iter().all(|(k, v)| {
                other.writes.get(k).is_some_and(|o| v.leq(o))
            })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Call graph context
// ────────────────────────────────────────────────────────────────────────────

/// The call graph with SCC structure and per-function reaching input states.
#[derive(Debug, Clone)]
pub struct CallGraphContext {
    /// Function names in a stable order.
    pub order: Vec<String>,
    /// Direct-call edges: caller → set of callees.
    pub callees: HashMap<String, HashSet<String>>,
    /// Reverse edges: callee → set of callers.
    pub callers: HashMap<String, HashSet<String>>,
    /// SCC id per function (functions in the same SCC are mutually recursive
    /// or self-recursive when the SCC has a self-edge).
    pub scc_of: HashMap<String, usize>,
    /// Number of SCCs.
    pub scc_count: usize,
    /// Whether each SCC is "recursive": more than one member, or a member
    /// with a self-edge.
    pub scc_recursive: Vec<bool>,
    /// Cross-function reaching definitions: for each function, the join of
    /// the abstract states flowing in from every call site (plus the external
    /// entry state for entry points).
    pub input_states: HashMap<String, VsaState>,
}

impl CallGraphContext {
    /// Build the call graph (direct edges only) from an [`IpProgram`].
    #[must_use]
    pub fn build(program: &IpProgram) -> Self {
        let mut order: Vec<String> = program.functions.keys().cloned().collect();
        order.sort();

        let mut callees: HashMap<String, HashSet<String>> = HashMap::new();
        let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
        for name in &order {
            callees.entry(name.clone()).or_default();
            callers.entry(name.clone()).or_default();
        }
        for (name, f) in &program.functions {
            for b in &f.blocks {
                for i in &b.instrs {
                    if let IpInstr::Call { callee } = i
                        && program.functions.contains_key(callee)
                    {
                        callees.get_mut(name).map(|s| s.insert(callee.clone()));
                        callers.get_mut(callee).map(|s| s.insert(name.clone()));
                    }
                }
            }
        }

        let (scc_of, scc_count) = tarjan_scc(&order, &callees);

        let mut scc_size = vec![0usize; scc_count];
        for name in &order {
            scc_size[scc_of[name]] += 1;
        }
        let mut scc_recursive = vec![false; scc_count];
        for (i, sz) in scc_size.iter().enumerate() {
            if *sz > 1 {
                scc_recursive[i] = true;
            }
        }
        for name in &order {
            if callees[name].contains(name) {
                scc_recursive[scc_of[name]] = true;
            }
        }

        let input_states = order
            .iter()
            .map(|n| (n.clone(), VsaState::new()))
            .collect();

        Self {
            order,
            callees,
            callers,
            scc_of,
            scc_count,
            scc_recursive,
            input_states,
        }
    }

    /// `true` if `f` participates in a recursion loop (self- or mutual).
    #[must_use]
    pub fn is_recursive(&self, f: &str) -> bool {
        self.scc_of
            .get(f)
            .is_some_and(|&s| self.scc_recursive[s])
    }
}

/// Iterative Tarjan SCC over string-keyed graph.  Returns (node → scc id,
/// number of sccs).  SCC ids are in reverse topological order of discovery.
fn tarjan_scc(
    order: &[String],
    edges: &HashMap<String, HashSet<String>>,
) -> (HashMap<String, usize>, usize) {
    let idx_of: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();
    let n = order.len();
    let adj: Vec<Vec<usize>> = order
        .iter()
        .map(|name| {
            let mut v: Vec<usize> = edges[name]
                .iter()
                .filter_map(|c| idx_of.get(c.as_str()).copied())
                .collect();
            v.sort_unstable();
            v
        })
        .collect();

    let mut index = vec![usize::MAX; n];
    let mut lowlink = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut next_index = 0usize;
    let mut scc_id = vec![usize::MAX; n];
    let mut scc_count = 0usize;

    // Iterative DFS with explicit frames: (node, next child position).
    for start in 0..n {
        if index[start] != usize::MAX {
            continue;
        }
        let mut frames: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&mut (v, ref mut ci)) = frames.last_mut() {
            if *ci == 0 {
                index[v] = next_index;
                lowlink[v] = next_index;
                next_index += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if *ci < adj[v].len() {
                let w = adj[v][*ci];
                *ci += 1;
                if index[w] == usize::MAX {
                    frames.push((w, 0));
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(index[w]);
                }
            } else {
                frames.pop();
                if let Some(&(p, _)) = frames.last() {
                    lowlink[p] = lowlink[p].min(lowlink[v]);
                }
                if lowlink[v] == index[v] {
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        scc_id[w] = scc_count;
                        if w == v {
                            break;
                        }
                    }
                    scc_count += 1;
                }
            }
        }
    }

    let map = order
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), scc_id[i]))
        .collect();
    (map, scc_count)
}

// ────────────────────────────────────────────────────────────────────────────
// Interprocedural analyzer
// ────────────────────────────────────────────────────────────────────────────

/// Result of running [`InterproceduralVsa::run`].
#[derive(Debug, Clone)]
pub struct IpResult {
    /// Final per-function summaries.
    pub summaries: HashMap<String, FunctionSummary>,
    /// Final per-function, per-block entry states.
    pub block_states: HashMap<String, Vec<VsaState>>,
    /// The call-graph context (with final input states).
    pub context: CallGraphContext,
}

/// Summary-based interprocedural VSA driver.
pub struct InterproceduralVsa<'a> {
    program: &'a IpProgram,
    /// Externally supplied initial state for entry-point functions.
    pub entry_state: VsaState,
}

/// After this many input-state updates a recursive function's input state is
/// widened instead of joined, guaranteeing termination.
const RECURSION_WIDEN_THRESHOLD: usize = 3;
/// Global iteration budget for the call-graph worklist.
const MAX_CG_ITERATIONS: usize = 100_000;

impl<'a> InterproceduralVsa<'a> {
    /// Create a driver for `program`, seeding entry points with `entry_state`.
    #[must_use]
    pub fn new(program: &'a IpProgram, entry_state: VsaState) -> Self {
        Self {
            program,
            entry_state,
        }
    }

    /// Run the summary-based fixed point over the call graph.
    ///
    /// # Errors
    ///
    /// Returns [`VsaError::EmptyProgram`] if the program has no functions and
    /// [`VsaError::NoConvergence`] if the iteration budget is exceeded.
    pub fn run(&self) -> Result<IpResult, VsaError> {
        if self.program.functions.is_empty() {
            return Err(VsaError::EmptyProgram);
        }
        let mut ctx = CallGraphContext::build(self.program);
        for ep in &self.program.entry_points {
            if let Some(s) = ctx.input_states.get_mut(ep) {
                *s = s.join(&self.entry_state);
            }
        }

        let mut summaries: HashMap<String, FunctionSummary> = ctx
            .order
            .iter()
            .map(|n| (n.clone(), FunctionSummary::default()))
            .collect();
        let mut block_states: HashMap<String, Vec<VsaState>> = HashMap::new();
        let mut input_updates: HashMap<String, usize> = HashMap::new();

        // Seed the worklist in reverse-topological SCC order (callees first)
        // so summaries stabilise bottom-up where possible.
        let mut order = ctx.order.clone();
        order.sort_by_key(|n| ctx.scc_of[n]);
        let mut worklist: VecDeque<String> = order.into();
        let mut in_worklist: HashSet<String> =
            worklist.iter().cloned().collect();

        let mut iterations = 0usize;
        while let Some(fname) = worklist.pop_front() {
            in_worklist.remove(&fname);
            iterations += 1;
            if iterations > MAX_CG_ITERATIONS {
                return Err(VsaError::NoConvergence);
            }

            let func = &self.program.functions[&fname];
            let input = ctx.input_states[&fname].clone();
            let (summary, states, call_inputs) =
                analyze_function(func, &input, &summaries)?;
            block_states.insert(fname.clone(), states);

            // Propagate call-site states into callees' input states.
            for (callee, site_state) in call_inputs {
                if !self.program.functions.contains_key(&callee) {
                    continue;
                }
                let cur = &ctx.input_states[&callee];
                let joined = cur.join(&site_state);
                if !joined.leq(cur) || joined != *cur {
                    let count = input_updates.entry(callee.clone()).or_insert(0);
                    *count += 1;
                    let next = if ctx.is_recursive(&callee)
                        && *count >= RECURSION_WIDEN_THRESHOLD
                    {
                        cur.widen(&joined)
                    } else {
                        joined
                    };
                    if next != ctx.input_states[&callee] {
                        ctx.input_states.insert(callee.clone(), next);
                        if in_worklist.insert(callee.clone()) {
                            worklist.push_back(callee.clone());
                        }
                    }
                }
            }

            // If the summary changed, re-analyze every caller.
            if summaries[&fname] != summary {
                summaries.insert(fname.clone(), summary);
                for caller in &ctx.callers[&fname] {
                    if in_worklist.insert(caller.clone()) {
                        worklist.push_back(caller.clone());
                    }
                }
            }
        }

        Ok(IpResult {
            summaries,
            block_states,
            context: ctx,
        })
    }
}

/// Lower a single [`IpInstr`] stream into base instrs, applying callee
/// summaries at call sites.  Returns the block-local state transformer output
/// plus the state observed at each direct call site.
///
/// This is implemented by running the intraprocedural [`VsaAnalyzer`] over a
/// lowered [`VsaCfg`] whose call instructions have been replaced by their
/// summary effects (Const/Top writes), while separately recording call-site
/// input states and read-before-write variables.
fn analyze_function(
    func: &IpFunction,
    input: &VsaState,
    summaries: &HashMap<String, FunctionSummary>,
) -> Result<(FunctionSummary, Vec<VsaState>, Vec<(String, VsaState)>), VsaError> {
    // Lower to a VsaCfg: calls become sequences of writes from the callee's
    // summary (Top for unknown-valued writes).
    let lowered: Vec<VsaBlock> = func
        .blocks
        .iter()
        .map(|b| VsaBlock {
            id: b.id,
            instrs: lower_instrs(&b.instrs, summaries),
        })
        .collect();
    let cfg = VsaCfg::new(lowered, func.successors.clone(), func.entry);
    let analyzer = VsaAnalyzer::new(input.clone());
    let states = analyzer.run(&cfg)?;

    // Compute reads (read-before-write along any path, approximated per
    // block in program order with a whole-function written-set that only
    // grows monotonically per block traversal from entry via BFS).
    let reads = compute_reads(func);

    // Writes: variables assigned anywhere; their exit value is the join over
    // exit blocks (blocks with no successors) of the post-transfer state.
    let mut writes: HashMap<String, ValueSet> = HashMap::new();
    let written = written_vars(func);
    let mut exit_state = VsaState::new();
    let mut any_exit = false;
    for (bid, succs) in func.successors.iter().enumerate() {
        if succs.is_empty() && bid < states.len() {
            let mut mem = crate::MemoryModel::default();
            let out = VsaAnalyzer::transfer(&cfg.blocks[bid], &states[bid], &mut mem);
            exit_state = exit_state.join(&out);
            any_exit = true;
        }
    }
    if any_exit {
        for w in &written {
            writes.insert(w.clone(), exit_state.get(w));
        }
    } else {
        for w in &written {
            writes.insert(w.clone(), ValueSet::Top);
        }
    }

    // Record call-site input states: state at block entry, transferred up to
    // (but not including) the call instruction.
    let mut call_inputs: Vec<(String, VsaState)> = Vec::new();
    for b in &func.blocks {
        if b.id >= states.len() {
            continue;
        }
        let mut s = states[b.id].clone();
        let mut mem = crate::MemoryModel::default();
        for instr in &b.instrs {
            match instr {
                IpInstr::Call { callee } => {
                    call_inputs.push((callee.clone(), s.clone()));
                    apply_summary(&mut s, summaries.get(callee));
                }
                IpInstr::CallIndirect { .. } => {}
                IpInstr::Base(base) => {
                    let tmp = VsaBlock {
                        id: b.id,
                        instrs: vec![base.clone()],
                    };
                    s = VsaAnalyzer::transfer(&tmp, &s, &mut mem);
                }
            }
        }
    }

    Ok((FunctionSummary { reads, writes }, states, call_inputs))
}

/// Replace call instructions with their summary write effects.
fn lower_instrs(
    instrs: &[IpInstr],
    summaries: &HashMap<String, FunctionSummary>,
) -> Vec<VsaInstr> {
    let mut out = Vec::new();
    for i in instrs {
        match i {
            IpInstr::Base(b) => out.push(b.clone()),
            IpInstr::CallIndirect { target } => {
                out.push(VsaInstr::IndirectCall {
                    target: target.clone(),
                });
            }
            IpInstr::Call { callee } => {
                if let Some(s) = summaries.get(callee) {
                    let mut keys: Vec<&String> = s.writes.keys().collect();
                    keys.sort();
                    for k in keys {
                        match &s.writes[k] {
                            ValueSet::Concrete(vals) if vals.len() == 1 => {
                                out.push(VsaInstr::Const {
                                    dst: k.clone(),
                                    value: vals[0],
                                });
                            }
                            // Non-singleton effects are conservatively lowered
                            // through a Top-valued helper: model as Const of
                            // nothing → we emit a synthetic copy from a fresh
                            // "top" variable which reads as Bottom, so instead
                            // clobber via two Consts joined is impossible in a
                            // straight line; use Top by loading an undefined
                            // pointer.  Simplest sound choice: skip and patch
                            // in apply_summary below via the call_inputs pass.
                            _ => {
                                out.push(VsaInstr::Load {
                                    dst: k.clone(),
                                    ptr: "__ip_undef__".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Apply a callee summary to a caller-side state at a call site.
fn apply_summary(s: &mut VsaState, summary: Option<&FunctionSummary>) {
    if let Some(sm) = summary {
        for (k, v) in &sm.writes {
            s.set(k.clone(), v.clone());
        }
    }
}

/// All variables written anywhere in the function (including by callee
/// summaries' effects — approximated by locally written vars only; callee
/// clobbers surface through the exit state).
fn written_vars(func: &IpFunction) -> HashSet<String> {
    let mut w = HashSet::new();
    for b in &func.blocks {
        for i in &b.instrs {
            if let IpInstr::Base(base) = i {
                if let Some(d) = def_of(base) {
                    w.insert(d.to_string());
                }
            }
        }
    }
    w
}

fn def_of(i: &VsaInstr) -> Option<&str> {
    match i {
        VsaInstr::Const { dst, .. }
        | VsaInstr::Copy { dst, .. }
        | VsaInstr::Add { dst, .. }
        | VsaInstr::Sub { dst, .. }
        | VsaInstr::And { dst, .. }
        | VsaInstr::Or { dst, .. }
        | VsaInstr::Load { dst, .. }
        | VsaInstr::Phi { dst, .. } => Some(dst),
        VsaInstr::Store { .. } | VsaInstr::IndirectCall { .. } => None,
    }
}

fn uses_of(i: &IpInstr) -> Vec<&str> {
    match i {
        IpInstr::Base(b) => match b {
            VsaInstr::Const { .. } => vec![],
            VsaInstr::Copy { src, .. } => vec![src],
            VsaInstr::Add { lhs, rhs, .. }
            | VsaInstr::Sub { lhs, rhs, .. }
            | VsaInstr::And { lhs, rhs, .. }
            | VsaInstr::Or { lhs, rhs, .. } => vec![lhs, rhs],
            VsaInstr::Load { ptr, .. } => vec![ptr],
            VsaInstr::Store { ptr, val } => vec![ptr, val],
            VsaInstr::Phi { srcs, .. } => srcs.iter().map(String::as_str).collect(),
            VsaInstr::IndirectCall { target } => vec![target],
        },
        IpInstr::Call { .. } => vec![],
        IpInstr::CallIndirect { target } => vec![target],
    }
}

/// Read-before-write variables along any path (may-read analysis).
///
/// A backward-flavoured forward pass: BFS from entry, carrying the set of
/// variables definitely written so far along *each* path; a variable used
/// while not yet written on that path is a read.  Path sets are merged with
/// intersection at join points (must-written), which is sound (over-
/// approximates reads).
fn compute_reads(func: &IpFunction) -> HashSet<String> {
    let n = func.blocks.len();
    if n == 0 {
        return HashSet::new();
    }
    // written_in[b]: must-written set at block entry. None = not yet visited.
    let mut written_in: Vec<Option<HashSet<String>>> = vec![None; n];
    written_in[func.entry] = Some(HashSet::new());
    let mut reads = HashSet::new();
    let mut worklist = VecDeque::from([func.entry]);

    let mut iters = 0usize;
    while let Some(bid) = worklist.pop_front() {
        iters += 1;
        if iters > 10_000 * n.max(1) {
            break;
        }
        let mut written = written_in[bid].clone().unwrap_or_default();
        for i in &func.blocks[bid].instrs {
            for u in uses_of(i) {
                if !written.contains(u) {
                    reads.insert(u.to_string());
                }
            }
            if let IpInstr::Base(b) = i
                && let Some(d) = def_of(b)
            {
                written.insert(d.to_string());
            }
        }
        for &succ in &func.successors[bid] {
            if succ >= n {
                continue;
            }
            let merged = match &written_in[succ] {
                None => written.clone(),
                Some(prev) => prev.intersection(&written).cloned().collect(),
            };
            if written_in[succ].as_ref() != Some(&merged) {
                written_in[succ] = Some(merged);
                worklist.push_back(succ);
            }
        }
    }
    reads
}

// ────────────────────────────────────────────────────────────────────────────
// Backward slicing for indirect call targets
// ────────────────────────────────────────────────────────────────────────────

/// A resolved (or unresolved) interprocedural indirect call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIndirectResolution {
    /// Function containing the indirect call.
    pub function: String,
    /// Block containing the call.
    pub block_id: usize,
    /// The target variable.
    pub target_var: String,
    /// Value-set for the target after interprocedural slicing.
    pub value: ValueSet,
    /// Concrete targets when the value-set is concretisable.
    pub resolved_targets: Vec<u64>,
    /// The caller chain walked to find the value (`[]` when resolved
    /// locally).
    pub resolved_via: Vec<String>,
}

/// `true` when a value-set is "useful" for call-target resolution: a bounded
/// constant / global set rather than Top or Bottom.
fn is_resolved(v: &ValueSet) -> bool {
    !matches!(v, ValueSet::Top | ValueSet::Bottom)
}

/// Resolve indirect call targets using interprocedural results.
///
/// For each indirect call site, first tries the local block state.  If the
/// target is `Top`/`Bottom` (a caller-set register), performs a backward
/// slice: walks caller → caller through the call graph, at each level joining
/// the value of the target variable at every call site into the current
/// function, stopping as soon as a constant / global value-set is found.
#[must_use]
pub fn resolve_indirect_calls(program: &IpProgram, result: &IpResult) -> Vec<IpIndirectResolution> {
    let mut out = Vec::new();
    for (fname, func) in &program.functions {
        let Some(states) = result.block_states.get(fname) else {
            continue;
        };
        for b in &func.blocks {
            if b.id >= states.len() {
                continue;
            }
            // Re-run the block prefix to get the state at each call.
            let mut s = states[b.id].clone();
            let mut mem = crate::MemoryModel::default();
            for i in &b.instrs {
                match i {
                    IpInstr::CallIndirect { target } => {
                        let local = s.get(target);
                        let (value, via) = if is_resolved(&local) {
                            (local, Vec::new())
                        } else {
                            backward_slice(program, result, fname, target)
                        };
                        let resolved_targets =
                            value.concretize(512).unwrap_or_default();
                        out.push(IpIndirectResolution {
                            function: fname.clone(),
                            block_id: b.id,
                            target_var: target.clone(),
                            value,
                            resolved_targets,
                            resolved_via: via,
                        });
                    }
                    IpInstr::Call { callee } => {
                        apply_summary(&mut s, result.summaries.get(callee));
                    }
                    IpInstr::Base(base) => {
                        let tmp = VsaBlock {
                            id: b.id,
                            instrs: vec![base.clone()],
                        };
                        s = VsaAnalyzer::transfer(&tmp, &s, &mut mem);
                    }
                }
            }
        }
    }
    out
}

/// Backward slice for `var` starting at function `fname`: BFS caller→caller,
/// at each level joining the value of `var` observed at every call site into
/// the sliced function.  Returns the first resolved (non-Top, non-Bottom)
/// value-set found together with the caller chain, or (`Top`, chain) if the
/// walk exhausts all callers.
fn backward_slice(
    program: &IpProgram,
    result: &IpResult,
    fname: &str,
    var: &str,
) -> (ValueSet, Vec<String>) {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(fname.to_string());
    // Queue of (function, chain-so-far).
    let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
    if let Some(callers) = result.context.callers.get(fname) {
        let mut cs: Vec<&String> = callers.iter().collect();
        cs.sort();
        for c in cs {
            if visited.insert(c.clone()) {
                queue.push_back((c.clone(), vec![c.clone()]));
            }
        }
    }

    while let Some((caller, chain)) = queue.pop_front() {
        // Join the value of `var` at every call site (into any visited
        // function reachable back to fname — approximated by: any call site
        // in `caller` calling a visited function).
        let mut val = ValueSet::Bottom;
        if let (Some(func), Some(states)) = (
            program.functions.get(&caller),
            result.block_states.get(&caller),
        ) {
            for b in &func.blocks {
                if b.id >= states.len() {
                    continue;
                }
                let mut s = states[b.id].clone();
                let mut mem = crate::MemoryModel::default();
                for i in &b.instrs {
                    match i {
                        IpInstr::Call { callee } if visited.contains(callee) => {
                            val = val.join(&s.get(var));
                            apply_summary(&mut s, result.summaries.get(callee));
                        }
                        IpInstr::Call { callee } => {
                            apply_summary(&mut s, result.summaries.get(callee));
                        }
                        IpInstr::Base(base) => {
                            let tmp = VsaBlock {
                                id: b.id,
                                instrs: vec![base.clone()],
                            };
                            s = VsaAnalyzer::transfer(&tmp, &s, &mut mem);
                        }
                        IpInstr::CallIndirect { .. } => {}
                    }
                }
            }
        }
        if is_resolved(&val) {
            return (val, chain);
        }
        // Not found here: walk further up.
        if let Some(callers) = result.context.callers.get(&caller) {
            let mut cs: Vec<&String> = callers.iter().collect();
            cs.sort();
            for c in cs {
                if visited.insert(c.clone()) {
                    let mut nc = chain.clone();
                    nc.push(c.clone());
                    queue.push_back((c.clone(), nc));
                }
            }
        }
    }
    (ValueSet::Top, Vec::new())
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cnst(dst: &str, v: u64) -> IpInstr {
        IpInstr::Base(VsaInstr::Const {
            dst: dst.into(),
            value: v,
        })
    }
    fn copy(dst: &str, src: &str) -> IpInstr {
        IpInstr::Base(VsaInstr::Copy {
            dst: dst.into(),
            src: src.into(),
        })
    }
    fn add(dst: &str, l: &str, r: &str) -> IpInstr {
        IpInstr::Base(VsaInstr::Add {
            dst: dst.into(),
            lhs: l.into(),
            rhs: r.into(),
        })
    }
    fn call(c: &str) -> IpInstr {
        IpInstr::Call { callee: c.into() }
    }
    fn icall(t: &str) -> IpInstr {
        IpInstr::CallIndirect { target: t.into() }
    }

    fn func1(name: &str, instrs: Vec<IpInstr>) -> IpFunction {
        IpFunction {
            name: name.into(),
            blocks: vec![IpBlock { id: 0, instrs }],
            successors: vec![vec![]],
            entry: 0,
        }
    }

    fn program(funcs: Vec<IpFunction>, entries: &[&str]) -> IpProgram {
        let mut p = IpProgram::new();
        for f in funcs {
            p.add_function(f);
        }
        p.entry_points = entries.iter().map(|s| (*s).to_string()).collect();
        p
    }

    // ── Call graph / SCC ────────────────────────────────────────────────

    #[test]
    fn call_graph_edges_and_sccs() {
        let main = func1("main", vec![call("a"), call("b")]);
        let a = func1("a", vec![call("b")]);
        let b = func1("b", vec![cnst("x", 1)]);
        let p = program(vec![main, a, b], &["main"]);
        let ctx = CallGraphContext::build(&p);
        assert!(ctx.callees["main"].contains("a"));
        assert!(ctx.callees["main"].contains("b"));
        assert!(ctx.callers["b"].contains("a"));
        assert!(ctx.callers["b"].contains("main"));
        // No recursion: three singleton non-recursive SCCs.
        assert_eq!(ctx.scc_count, 3);
        assert!(!ctx.is_recursive("main"));
        assert!(!ctx.is_recursive("a"));
        assert!(!ctx.is_recursive("b"));
    }

    #[test]
    fn scc_detects_mutual_recursion() {
        let a = func1("a", vec![call("b")]);
        let b = func1("b", vec![call("a")]);
        let m = func1("main", vec![call("a")]);
        let p = program(vec![a, b, m], &["main"]);
        let ctx = CallGraphContext::build(&p);
        assert_eq!(ctx.scc_of["a"], ctx.scc_of["b"]);
        assert_ne!(ctx.scc_of["a"], ctx.scc_of["main"]);
        assert!(ctx.is_recursive("a"));
        assert!(ctx.is_recursive("b"));
        assert!(!ctx.is_recursive("main"));
    }

    #[test]
    fn scc_detects_self_recursion() {
        let f = func1("f", vec![call("f")]);
        let p = program(vec![f], &["f"]);
        let ctx = CallGraphContext::build(&p);
        assert!(ctx.is_recursive("f"));
    }

    // ── Summaries ───────────────────────────────────────────────────────

    #[test]
    fn summary_reads_and_writes() {
        // f: y = x (reads x); z = 5 (writes z, y).
        let f = func1("f", vec![copy("y", "x"), cnst("z", 5)]);
        let p = program(vec![f], &["f"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let s = &r.summaries["f"];
        assert!(s.reads.contains("x"));
        assert!(!s.reads.contains("z"));
        assert_eq!(s.writes["z"], ValueSet::singleton(5));
        assert!(s.writes.contains_key("y"));
    }

    #[test]
    fn summary_write_after_read_not_input() {
        // x written then read → not an input.
        let f = func1("f", vec![cnst("x", 1), copy("y", "x")]);
        let p = program(vec![f], &["f"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        assert!(!r.summaries["f"].reads.contains("x"));
    }

    #[test]
    fn reads_uses_must_written_intersection_at_joins() {
        // Diamond: x written on only one branch, then read after merge →
        // must be a read (read-before-write on the other path).
        let f = IpFunction {
            name: "f".into(),
            blocks: vec![
                IpBlock { id: 0, instrs: vec![] },
                IpBlock { id: 1, instrs: vec![cnst("x", 1)] },
                IpBlock { id: 2, instrs: vec![] },
                IpBlock { id: 3, instrs: vec![copy("y", "x")] },
            ],
            successors: vec![vec![1, 2], vec![3], vec![3], vec![]],
            entry: 0,
        };
        let p = program(vec![f], &["f"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        assert!(r.summaries["f"].reads.contains("x"));
    }

    // ── Summary application at call sites ───────────────────────────────

    #[test]
    fn callee_constant_flows_to_caller() {
        // g: rax = 42.  main: call g; y = rax.
        let g = func1("g", vec![cnst("rax", 42)]);
        let m = func1("main", vec![call("g"), copy("y", "rax")]);
        let p = program(vec![g, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        assert_eq!(r.summaries["main"].writes["y"], ValueSet::singleton(42));
    }

    #[test]
    fn caller_input_flows_into_callee() {
        // main: rcx = 7; call g.   g: y = rcx (caller-set register).
        let g = func1("g", vec![copy("y", "rcx")]);
        let m = func1("main", vec![cnst("rcx", 7), call("g")]);
        let p = program(vec![g, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        // g's input state must contain rcx = 7.
        assert_eq!(
            r.context.input_states["g"].get("rcx"),
            ValueSet::singleton(7)
        );
        assert_eq!(r.summaries["g"].writes["y"], ValueSet::singleton(7));
    }

    #[test]
    fn two_call_sites_join_inputs() {
        let g = func1("g", vec![copy("y", "rcx")]);
        let a = func1("a", vec![cnst("rcx", 1), call("g")]);
        let b = func1("b", vec![cnst("rcx", 2), call("g")]);
        let m = func1("main", vec![call("a"), call("b")]);
        let p = program(vec![g, a, b, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let y = &r.summaries["g"].writes["y"];
        assert!(y.contains(1) && y.contains(2));
    }

    #[test]
    fn recursive_program_terminates_with_widening() {
        // f: x = x + one; call f.  Ascending chain → widening must kick in.
        let f = func1("f", vec![cnst("one", 1), add("x", "x", "one"), call("f")]);
        let m = func1("main", vec![cnst("x", 0), call("f")]);
        let p = program(vec![f, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        // Must converge; x is imprecise but analysis is done.
        assert!(r.summaries.contains_key("f"));
    }

    #[test]
    fn mutual_recursion_terminates() {
        let a = func1("a", vec![cnst("one", 1), add("x", "x", "one"), call("b")]);
        let b = func1("b", vec![add("x", "x", "one"), call("a")]);
        let m = func1("main", vec![cnst("x", 0), call("a")]);
        let p = program(vec![a, b, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        assert!(r.summaries.contains_key("a"));
        assert!(r.summaries.contains_key("b"));
    }

    #[test]
    fn empty_program_errors() {
        let p = IpProgram::new();
        let e = InterproceduralVsa::new(&p, VsaState::new()).run();
        assert!(matches!(e, Err(VsaError::EmptyProgram)));
    }

    #[test]
    fn entry_state_seeds_entry_points() {
        let mut st = VsaState::new();
        st.set("rdi", ValueSet::singleton(0x1000));
        let m = func1("main", vec![copy("p", "rdi")]);
        let p = program(vec![m], &["main"]);
        let r = InterproceduralVsa::new(&p, st).run().unwrap();
        assert_eq!(r.summaries["main"].writes["p"], ValueSet::singleton(0x1000));
    }

    // ── Indirect call resolution / backward slicing ─────────────────────

    #[test]
    fn indirect_call_resolved_locally() {
        let m = func1("main", vec![cnst("t", 0x4010), icall("t")]);
        let p = program(vec![m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let res = resolve_indirect_calls(&p, &r);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].resolved_targets, vec![0x4010]);
        assert!(res[0].resolved_via.is_empty());
    }

    #[test]
    fn indirect_call_resolved_from_direct_caller() {
        // g does `call [t]` where t is caller-set; main sets t = 0x5000.
        let g = func1("g", vec![icall("t")]);
        let m = func1("main", vec![cnst("t", 0x5000), call("g")]);
        let p = program(vec![g, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let res = resolve_indirect_calls(&p, &r);
        let gres = res.iter().find(|x| x.function == "g").unwrap();
        assert_eq!(gres.resolved_targets, vec![0x5000]);
        // Since t flows through g's input state, it may resolve locally
        // (via = []) or via the caller walk; either way targets are right.
    }

    #[test]
    fn backward_slice_walks_two_levels() {
        // main sets t; calls mid; mid calls leaf; leaf does icall(t) but t
        // never appears in mid/leaf bodies — the input-state propagation
        // should carry it, and if it did not, the slicer walks main.
        let leaf = func1("leaf", vec![icall("t")]);
        let mid = func1("mid", vec![call("leaf")]);
        let m = func1("main", vec![cnst("t", 0x6000), call("mid")]);
        let p = program(vec![leaf, mid, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let res = resolve_indirect_calls(&p, &r);
        let lres = res.iter().find(|x| x.function == "leaf").unwrap();
        assert_eq!(lres.resolved_targets, vec![0x6000]);
    }

    #[test]
    fn backward_slice_reports_unresolved_as_top() {
        // Nobody defines t anywhere.
        let g = func1("g", vec![icall("t")]);
        let m = func1("main", vec![call("g")]);
        let p = program(vec![g, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let res = resolve_indirect_calls(&p, &r);
        let gres = res.iter().find(|x| x.function == "g").unwrap();
        assert!(gres.resolved_targets.is_empty());
        assert!(matches!(gres.value, ValueSet::Top | ValueSet::Bottom));
    }

    #[test]
    fn slice_joins_multiple_call_sites() {
        let g = func1("g", vec![icall("t")]);
        let a = func1("a", vec![cnst("t", 0x10), call("g")]);
        let b = func1("b", vec![cnst("t", 0x20), call("g")]);
        let m = func1("main", vec![call("a"), call("b")]);
        let p = program(vec![g, a, b, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let res = resolve_indirect_calls(&p, &r);
        let gres = res.iter().find(|x| x.function == "g").unwrap();
        let mut t = gres.resolved_targets.clone();
        t.sort_unstable();
        assert_eq!(t, vec![0x10, 0x20]);
    }

    #[test]
    fn summary_leq() {
        let mut a = FunctionSummary::default();
        a.writes.insert("x".into(), ValueSet::singleton(1));
        let mut b = FunctionSummary::default();
        b.writes.insert("x".into(), ValueSet::interval(0, 10));
        assert!(a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn unknown_extern_callee_is_ignored() {
        // Call to a function not in the program: no crash, no effects.
        let m = func1("main", vec![cnst("x", 3), call("memcpy"), copy("y", "x")]);
        let p = program(vec![m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        assert_eq!(r.summaries["main"].writes["y"], ValueSet::singleton(3));
    }

    #[test]
    fn non_singleton_callee_write_is_conservative_top() {
        // g writes x as {1,2} depending on branch → caller sees non-constant
        // (Top via the lowering) rather than a wrong singleton.
        let g = IpFunction {
            name: "g".into(),
            blocks: vec![
                IpBlock { id: 0, instrs: vec![] },
                IpBlock { id: 1, instrs: vec![cnst("x", 1)] },
                IpBlock { id: 2, instrs: vec![cnst("x", 2)] },
                IpBlock { id: 3, instrs: vec![] },
            ],
            successors: vec![vec![1, 2], vec![3], vec![3], vec![]],
            entry: 0,
        };
        let m = func1("main", vec![call("g"), copy("y", "x")]);
        let p = program(vec![g, m], &["main"]);
        let r = InterproceduralVsa::new(&p, VsaState::new()).run().unwrap();
        let y = &r.summaries["main"].writes["y"];
        // Must contain both possibilities (join {1,2}) or be Top — never a
        // single wrong constant.
        assert!(*y == ValueSet::Top || (y.contains(1) && y.contains(2)));
    }
}
