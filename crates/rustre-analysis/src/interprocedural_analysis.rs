//! Interprocedural analysis: call graph construction, function summaries,
//! bottom-up computation, top-down propagation, and call-site summaries.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// FunctionId
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a function in the interprocedural analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionId(pub u64);

impl FunctionId {
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
}

impl fmt::Display for FunctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fn@{:#x}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSite
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a single call site inside a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// The function that contains this call site.
    pub caller: FunctionId,
    /// The called function (None for indirect calls).
    pub callee: Option<FunctionId>,
    /// Whether this is a tail call.
    pub is_tail_call: bool,
    /// Whether this is an indirect call (computed target).
    pub is_indirect: bool,
    /// Confidence 0–100 for the resolved callee.
    pub confidence: u8,
}

impl CallSite {
    #[must_use]
    pub const fn direct(call_addr: u64, caller: FunctionId, target: FunctionId) -> Self {
        Self {
            call_addr,
            caller,
            callee: Some(target),
            is_tail_call: false,
            is_indirect: false,
            confidence: 100,
        }
    }

    #[must_use]
    pub const fn indirect(call_addr: u64, caller: FunctionId) -> Self {
        Self {
            call_addr,
            caller,
            callee: None,
            is_tail_call: false,
            is_indirect: true,
            confidence: 0,
        }
    }

    #[must_use]
    pub const fn with_tail_call(mut self) -> Self {
        self.is_tail_call = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Directed call graph: nodes are functions, edges are call sites.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// All known functions (nodes).
    functions: HashSet<FunctionId>,
    /// All call sites (edges).
    call_sites: Vec<CallSite>,
    /// Name table (optional).
    names: HashMap<FunctionId, String>,
}

impl CallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node.
    pub fn add_function(&mut self, id: FunctionId) {
        self.functions.insert(id);
    }

    /// Add a function with a name.
    pub fn add_named_function(&mut self, id: FunctionId, name: impl Into<String>) {
        self.functions.insert(id);
        self.names.insert(id, name.into());
    }

    /// Add a call site (edge).
    pub fn add_call_site(&mut self, cs: CallSite) {
        self.functions.insert(cs.caller);
        if let Some(callee) = cs.callee {
            self.functions.insert(callee);
        }
        self.call_sites.push(cs);
    }

    /// All direct callees of `caller`.
    #[must_use]
    pub fn callees_of(&self, caller: FunctionId) -> Vec<FunctionId> {
        // Dedup via the set, then SORT: returning raw `HashSet` iteration order
        // made every traversal built on this method vary between processes.
        let mut out: Vec<FunctionId> = self
            .call_sites
            .iter()
            .filter(|cs| cs.caller == caller && cs.callee.is_some())
            .filter_map(|cs| cs.callee)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        out.sort_unstable();
        out
    }

    /// All direct callers of `callee`.
    #[must_use]
    pub fn callers_of(&self, callee: FunctionId) -> Vec<FunctionId> {
        self.call_sites
            .iter()
            .filter(|cs| cs.callee == Some(callee))
            .map(|cs| cs.caller)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Number of functions in the graph.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of call edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.call_sites.len()
    }

    /// Return the name of a function, if available.
    #[must_use]
    pub fn name_of(&self, id: FunctionId) -> Option<&str> {
        self.names.get(&id).map(String::as_str)
    }

    /// Returns `true` if the graph contains a cycle (recursion exists).
    #[must_use]
    pub fn has_cycles(&self) -> bool {
        // Kahn's algorithm: topological sort; if it can't schedule everyone → cycle.
        let mut in_degree: HashMap<FunctionId, usize> =
            self.functions.iter().map(|&f| (f, 0)).collect();
        for cs in &self.call_sites {
            if let Some(callee) = cs.callee
                && callee != cs.caller {
                    *in_degree.entry(callee).or_insert(0) += 1;
                }
        }
        let mut queue: VecDeque<FunctionId> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&f, _)| f)
            .collect();
        let mut processed = 0usize;
        while let Some(f) = queue.pop_front() {
            processed += 1;
            for cs in self.call_sites.iter().filter(|cs| cs.caller == f) {
                if let Some(callee) = cs.callee
                    && callee != cs.caller
                    && let Some(d) = in_degree.get_mut(&callee) {
                        *d = d.saturating_sub(1);
                        if *d == 0 {
                            queue.push_back(callee);
                        }
                    }
            }
        }
        if processed < self.functions.len() {
            return true;
        }
        // Kahn's skips self-loops above (consistent with the in_degree build);
        // detect any remaining self-recursion explicitly.
        self.call_sites
            .iter()
            .any(|cs| cs.callee == Some(cs.caller))
    }

    /// Compute a bottom-up (post-order) traversal of the call graph.
    ///
    /// Returns functions in an order where callees appear before callers.
    /// If the graph has cycles some ordering will be imposed arbitrarily.
    #[must_use]
    pub fn bottom_up_order(&self) -> Vec<FunctionId> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        // Sorted roots, not raw `HashSet` iteration order: `RandomState` is
        // seeded per process, so identical input produced a different traversal
        // on every run — and with it a different population order for the
        // summary database, making any order-sensitive analysis downstream
        // irreproducible.
        let mut roots: Vec<FunctionId> = self.functions.iter().copied().collect();
        roots.sort_unstable();
        for root in roots {
            if !visited.contains(&root) {
                self.dfs_postorder(root, &mut visited, &mut order);
            }
        }
        order
    }

    fn dfs_postorder(
        &self,
        root: FunctionId,
        visited: &mut HashSet<FunctionId>,
        order: &mut Vec<FunctionId>,
    ) {
        // Iterative post-order DFS to avoid stack overflow on attacker-controlled
        // deep call graphs (dos-unbounded-recursion).
        // Stack entries: (node, iterator-index-into-callees, callees-snapshot).
        // When we first visit a node we push it; when all callees are done we emit it.
        if !visited.insert(root) {
            return;
        }
        // Each frame: (node, callees, next_callee_index)
        let mut stack: Vec<(FunctionId, Vec<FunctionId>, usize)> = vec![(
            root,
            self.callees_of(root),
            0,
        )];

        while let Some(frame) = stack.last_mut() {
            let (node, callees, idx) = frame;
            if *idx < callees.len() {
                let callee = callees[*idx];
                *idx += 1;
                if visited.insert(callee) {
                    let callee_callees = self.callees_of(callee);
                    stack.push((callee, callee_callees, 0));
                }
            } else {
                // All callees processed — emit this node.
                order.push(*node);
                stack.pop();
            }
        }
    }

    /// All direct call sites from a given caller.
    #[must_use]
    pub fn call_sites_from(&self, caller: FunctionId) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|cs| cs.caller == caller)
            .collect()
    }

    /// All call sites to a given callee.
    #[must_use]
    pub fn call_sites_to(&self, callee: FunctionId) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|cs| cs.callee == Some(callee))
            .collect()
    }

    /// Return all functions reachable from `start` via calls.
    #[must_use]
    pub fn reachable_from(&self, start: FunctionId) -> HashSet<FunctionId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(f) = queue.pop_front() {
            if visited.insert(f) {
                for callee in self.callees_of(f) {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract value lattice for summaries
// ─────────────────────────────────────────────────────────────────────────────

/// Simple lattice for interprocedural facts: Top ≥ any concrete value ≥ Bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstractValue {
    /// No information (initial state / uninitialised).
    Bottom,
    /// A set of possible concrete values.
    Values(HashSet<i64>),
    /// All possible values (unknown / non-constant).
    Top,
}

impl AbstractValue {
    #[must_use]
    pub fn singleton(v: i64) -> Self {
        Self::Values([v].into())
    }

    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Bottom, x) | (x, Self::Bottom) => x.clone(),
            (Self::Values(a), Self::Values(b)) => {
                let merged: HashSet<i64> = a.union(b).copied().collect();
                if merged.len() > 8 {
                    Self::Top
                } else {
                    Self::Values(merged)
                }
            }
        }
    }

    #[must_use]
    pub const fn is_bottom(&self) -> bool {
        matches!(self, Self::Bottom)
    }

    #[must_use]
    pub const fn is_top(&self) -> bool {
        matches!(self, Self::Top)
    }

    #[must_use]
    pub fn as_singleton(&self) -> Option<i64> {
        if let Self::Values(s) = self
            && s.len() == 1 {
                return s.iter().next().copied();
            }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionSummary
// ─────────────────────────────────────────────────────────────────────────────

/// A per-function analysis summary.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub id: FunctionId,
    /// Abstract values for each named "return slot" (e.g. register names).
    pub return_values: HashMap<String, AbstractValue>,
    /// Abstract values for each named "argument effect" (parameter mutations).
    pub arg_effects: HashMap<usize, AbstractValue>,
    /// Whether this function may modify global state.
    pub may_have_side_effects: bool,
    /// Whether this function may not return (e.g. noreturn attribute).
    pub may_not_return: bool,
    /// Whether the summary is final (fixpoint reached) or still in progress.
    pub is_final: bool,
}

impl FunctionSummary {
    #[must_use]
    pub fn empty(id: FunctionId) -> Self {
        Self {
            id,
            return_values: HashMap::new(),
            arg_effects: HashMap::new(),
            may_have_side_effects: false,
            may_not_return: false,
            is_final: false,
        }
    }

    /// Create a conservative (Top) summary.
    #[must_use]
    pub fn conservative(id: FunctionId) -> Self {
        let mut s = Self::empty(id);
        s.return_values.insert("rax".into(), AbstractValue::Top);
        s.may_have_side_effects = true;
        s.is_final = true;
        s
    }

    pub fn set_return(&mut self, slot: impl Into<String>, val: AbstractValue) {
        self.return_values.insert(slot.into(), val);
    }

    pub fn set_arg_effect(&mut self, idx: usize, val: AbstractValue) {
        self.arg_effects.insert(idx, val);
    }

    pub const fn mark_final(&mut self) {
        self.is_final = true;
    }

    /// Join another summary into `self`, widening facts.
    pub fn join_with(&mut self, other: &Self) {
        for (slot, val) in &other.return_values {
            let entry = self
                .return_values
                .entry(slot.clone())
                .or_insert(AbstractValue::Bottom);
            *entry = entry.join(val);
        }
        for (&idx, val) in &other.arg_effects {
            let entry = self.arg_effects.entry(idx).or_insert(AbstractValue::Bottom);
            *entry = entry.join(val);
        }
        self.may_have_side_effects |= other.may_have_side_effects;
        self.may_not_return |= other.may_not_return;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SummaryDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// Stores and retrieves `FunctionSummary` entries.
#[derive(Debug, Default)]
pub struct SummaryDatabase {
    summaries: HashMap<FunctionId, FunctionSummary>,
}

impl SummaryDatabase {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, summary: FunctionSummary) {
        self.summaries.insert(summary.id, summary);
    }

    #[must_use]
    pub fn get(&self, id: FunctionId) -> Option<&FunctionSummary> {
        self.summaries.get(&id)
    }

    #[must_use]
    pub fn get_mut(&mut self, id: FunctionId) -> Option<&mut FunctionSummary> {
        self.summaries.get_mut(&id)
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.summaries.len()
    }

    /// Return all final summaries.
    #[must_use]
    pub fn final_summaries(&self) -> Vec<&FunctionSummary> {
        self.summaries.values().filter(|s| s.is_final).collect()
    }

    /// Return all in-progress summaries.
    #[must_use]
    pub fn pending_summaries(&self) -> Vec<&FunctionSummary> {
        self.summaries.values().filter(|s| !s.is_final).collect()
    }

    /// Look up the return value abstract value for `slot` in a function.
    #[must_use]
    pub fn return_value(&self, id: FunctionId, slot: &str) -> AbstractValue {
        self.summaries
            .get(&id)
            .and_then(|s| s.return_values.get(slot).cloned())
            .unwrap_or(AbstractValue::Top)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSiteSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Context-specific information computed at each call site.
#[derive(Debug, Clone)]
pub struct CallSiteSummary {
    pub call_addr: u64,
    pub caller: FunctionId,
    pub callee: Option<FunctionId>,
    /// Abstract values of arguments at this specific call site.
    pub arg_values: Vec<AbstractValue>,
    /// Abstract value of the return value at this call site.
    pub return_value: AbstractValue,
    /// Whether this call is reachable.
    pub is_reachable: bool,
}

impl CallSiteSummary {
    #[must_use]
    pub const fn new(call_addr: u64, caller: FunctionId, target_callee: Option<FunctionId>) -> Self {
        Self {
            call_addr,
            caller,
            callee: target_callee,
            arg_values: Vec::new(),
            return_value: AbstractValue::Top,
            is_reachable: true,
        }
    }

    pub fn add_arg(&mut self, val: AbstractValue) {
        self.arg_values.push(val);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BottomUp analysis engine
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for a summary computation over a single function.
pub trait SummaryAnalysis: Send + Sync {
    /// Compute or refine the summary for `id`.
    ///
    /// `db` contains summaries of already-analyzed callees.
    fn analyze(
        &self,
        id: FunctionId,
        call_graph: &CallGraph,
        db: &SummaryDatabase,
    ) -> FunctionSummary;
}

/// Runs the bottom-up interprocedural analysis.
///
/// Functions are processed in bottom-up (callee-before-caller) order.
/// Recursive cycles get a conservative summary.
pub struct BottomUp<'a> {
    cg: &'a CallGraph,
    db: SummaryDatabase,
    analysis: Arc<dyn SummaryAnalysis>,
}

impl<'a> BottomUp<'a> {
    #[must_use]
    pub fn new(cg: &'a CallGraph, analysis: Arc<dyn SummaryAnalysis>) -> Self {
        Self {
            cg,
            db: SummaryDatabase::new(),
            analysis,
        }
    }

    /// Run the bottom-up pass and return the populated `SummaryDatabase`.
    #[must_use] 
    pub fn run(mut self) -> SummaryDatabase {
        let order = self.cg.bottom_up_order();
        for fid in order {
            let summary = self.analysis.analyze(fid, self.cg, &self.db);
            self.db.insert(summary);
        }
        self.db
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TopDown propagation
// ─────────────────────────────────────────────────────────────────────────────

/// Propagates call-site contexts top-down through the call graph.
pub struct TopDown<'a> {
    cg: &'a CallGraph,
    db: &'a SummaryDatabase,
    site_summaries: Vec<CallSiteSummary>,
}

impl<'a> TopDown<'a> {
    #[must_use]
    pub const fn new(cg: &'a CallGraph, db: &'a SummaryDatabase) -> Self {
        Self {
            cg,
            db,
            site_summaries: Vec::new(),
        }
    }

    /// Run top-down propagation starting from `entry` functions.
    #[must_use] 
    pub fn run(mut self, entries: &[FunctionId]) -> Vec<CallSiteSummary> {
        let mut worklist: VecDeque<FunctionId> = entries.iter().copied().collect();
        let mut processed = HashSet::new();

        while let Some(fid) = worklist.pop_front() {
            if !processed.insert(fid) {
                continue;
            }

            for cs in self.cg.call_sites_from(fid) {
                let mut css = CallSiteSummary::new(cs.call_addr, cs.caller, cs.callee);
                // Propagate return value from summary database.
                if let Some(callee) = cs.callee {
                    css.return_value = self.db.return_value(callee, "rax");
                    worklist.push_back(callee);
                }
                self.site_summaries.push(css);
            }
        }
        self.site_summaries
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterproceduralAnalysis — orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// High-level orchestrator combining call-graph construction, bottom-up
/// summary computation, and top-down propagation.
pub struct InterproceduralAnalysis {
    pub call_graph: CallGraph,
    pub db: SummaryDatabase,
    pub site_summaries: Vec<CallSiteSummary>,
}

impl fmt::Debug for InterproceduralAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterproceduralAnalysis")
            .field("functions", &self.call_graph.function_count())
            .field("call_edges", &self.call_graph.edge_count())
            .field("summaries", &self.db.count())
            .finish_non_exhaustive()
    }
}

impl InterproceduralAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
            db: SummaryDatabase::new(),
            site_summaries: Vec::new(),
        }
    }

    /// Run the full bottom-up + top-down pipeline.
    ///
    /// `analysis` is used for computing per-function summaries bottom-up.
    /// `entries` are the top-level entry points for the top-down pass.
    #[must_use]
    pub fn run(mut self, analysis: Arc<dyn SummaryAnalysis>, entries: &[FunctionId]) -> Self {
        // Bottom-up
        let bottom_up = BottomUp::new(&self.call_graph, analysis);
        self.db = bottom_up.run();

        // Top-down
        let top_down = TopDown::new(&self.call_graph, &self.db);
        self.site_summaries = top_down.run(entries);

        self
    }

    /// Return the summary for a function, if available.
    #[must_use]
    pub fn summary(&self, id: FunctionId) -> Option<&FunctionSummary> {
        self.db.get(id)
    }

    /// Return call-site summaries for a given caller.
    #[must_use]
    pub fn sites_for_caller(&self, caller: FunctionId) -> Vec<&CallSiteSummary> {
        self.site_summaries
            .iter()
            .filter(|s| s.caller == caller)
            .collect()
    }
}

impl Default for InterproceduralAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in conservative summary analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A summary analysis that assigns conservative (Top) summaries to all functions.
pub struct ConservativeAnalysis;

impl SummaryAnalysis for ConservativeAnalysis {
    fn analyze(&self, id: FunctionId, _cg: &CallGraph, _db: &SummaryDatabase) -> FunctionSummary {
        FunctionSummary::conservative(id)
    }
}

/// A summary analysis that propagates constant return values.
///
/// If a function has no callees and its "body" is a known constant assignment,
/// the summary reports that constant.  Otherwise falls back to conservative.
pub struct ConstantReturnAnalysis {
    /// Known constant return values for specific function addresses.
    known_constants: HashMap<FunctionId, i64>,
}

impl ConstantReturnAnalysis {
    #[must_use]
    pub const fn new(known: HashMap<FunctionId, i64>) -> Self {
        Self {
            known_constants: known,
        }
    }
}

impl SummaryAnalysis for ConstantReturnAnalysis {
    fn analyze(&self, id: FunctionId, cg: &CallGraph, db: &SummaryDatabase) -> FunctionSummary {
        if let Some(&c) = self.known_constants.get(&id) {
            let mut s = FunctionSummary::empty(id);
            s.set_return("rax", AbstractValue::singleton(c));
            s.mark_final();
            return s;
        }

        // If all callees have constant returns, try to propagate.
        let callees = cg.callees_of(id);
        if callees.is_empty() {
            return FunctionSummary::conservative(id);
        }

        let mut merged = AbstractValue::Bottom;
        for callee in &callees {
            let ret = db.return_value(*callee, "rax");
            merged = merged.join(&ret);
        }

        let mut s = FunctionSummary::empty(id);
        s.set_return("rax", merged);
        s.mark_final();
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fid(n: u64) -> FunctionId {
        FunctionId::new(n)
    }

    // ── FunctionId ────────────────────────────────────────────────────────────

    #[test]
    fn function_id_display() {
        let id = fid(0x1000);
        assert!(id.to_string().contains("0x1000"));
    }

    #[test]
    fn function_id_equality() {
        assert_eq!(fid(1), fid(1));
        assert_ne!(fid(1), fid(2));
    }

    // ── CallSite ──────────────────────────────────────────────────────────────

    #[test]
    fn call_site_direct() {
        let cs = CallSite::direct(0x1000, fid(1), fid(2));
        assert!(!cs.is_indirect);
        assert_eq!(cs.callee, Some(fid(2)));
        assert_eq!(cs.confidence, 100);
    }

    #[test]
    fn call_site_indirect() {
        let cs = CallSite::indirect(0x2000, fid(1));
        assert!(cs.is_indirect);
        assert_eq!(cs.callee, None);
    }

    #[test]
    fn call_site_tail_call() {
        let cs = CallSite::direct(0x1000, fid(1), fid(2)).with_tail_call();
        assert!(cs.is_tail_call);
    }

    // ── CallGraph ─────────────────────────────────────────────────────────────

    #[test]
    fn call_graph_function_count() {
        let mut cg = CallGraph::new();
        cg.add_function(fid(1));
        cg.add_function(fid(2));
        assert_eq!(cg.function_count(), 2);
    }

    #[test]
    fn call_graph_edge_count() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        assert_eq!(cg.edge_count(), 2);
    }

    #[test]
    fn call_graph_callees_of() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(1), fid(3)));
        let mut callees = cg.callees_of(fid(1));
        callees.sort();
        assert_eq!(callees, vec![fid(2), fid(3)]);
    }

    #[test]
    fn call_graph_callers_of() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(3)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        let mut callers = cg.callers_of(fid(3));
        callers.sort();
        assert_eq!(callers, vec![fid(1), fid(2)]);
    }

    #[test]
    fn call_graph_no_cycles_linear() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        assert!(!cg.has_cycles());
    }

    #[test]
    fn call_graph_detects_cycle() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(1))); // back-edge
        assert!(cg.has_cycles());
    }

    #[test]
    fn call_graph_self_loop_is_cycle() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(1))); // self-recursive
        assert!(cg.has_cycles());
    }

    #[test]
    fn call_graph_bottom_up_order_no_cycles() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        let order = cg.bottom_up_order();
        // Callee (fid(3)) must appear before fid(2) before fid(1).
        let pos = |id: FunctionId| order.iter().position(|&f| f == id).unwrap();
        assert!(pos(fid(3)) < pos(fid(2)));
        assert!(pos(fid(2)) < pos(fid(1)));
    }

    #[test]
    fn call_graph_name_of() {
        let mut cg = CallGraph::new();
        cg.add_named_function(fid(1), "main");
        assert_eq!(cg.name_of(fid(1)), Some("main"));
        assert_eq!(cg.name_of(fid(999)), None);
    }

    #[test]
    fn call_graph_reachable_from() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        let r = cg.reachable_from(fid(1));
        assert!(r.contains(&fid(1)));
        assert!(r.contains(&fid(2)));
        assert!(r.contains(&fid(3)));
    }

    // ── AbstractValue ─────────────────────────────────────────────────────────

    #[test]
    fn abstract_value_singleton() {
        let v = AbstractValue::singleton(42);
        assert_eq!(v.as_singleton(), Some(42));
    }

    #[test]
    fn abstract_value_join_bottom_identity() {
        let v = AbstractValue::singleton(1);
        let j = AbstractValue::Bottom.join(&v);
        assert_eq!(j, v);
    }

    #[test]
    fn abstract_value_join_top_absorbs() {
        let v = AbstractValue::singleton(1);
        let j = v.join(&AbstractValue::Top);
        assert!(j.is_top());
    }

    #[test]
    fn abstract_value_join_two_singletons() {
        let a = AbstractValue::singleton(1);
        let b = AbstractValue::singleton(2);
        let j = a.join(&b);
        assert!(matches!(j, AbstractValue::Values(_)));
        assert_eq!(j.as_singleton(), None);
    }

    #[test]
    fn abstract_value_join_widens_to_top_after_8() {
        let mut v = AbstractValue::singleton(0);
        for i in 1..=10i64 {
            v = v.join(&AbstractValue::singleton(i));
        }
        assert!(v.is_top());
    }

    // ── FunctionSummary ───────────────────────────────────────────────────────

    #[test]
    fn function_summary_empty() {
        let s = FunctionSummary::empty(fid(1));
        assert!(!s.is_final);
        assert!(s.return_values.is_empty());
    }

    #[test]
    fn function_summary_conservative() {
        let s = FunctionSummary::conservative(fid(1));
        assert!(s.is_final);
        assert!(s.may_have_side_effects);
        assert!(s.return_values["rax"].is_top());
    }

    #[test]
    fn function_summary_join_with() {
        let mut a = FunctionSummary::empty(fid(1));
        a.set_return("rax", AbstractValue::singleton(0));

        let mut b = FunctionSummary::empty(fid(1));
        b.set_return("rax", AbstractValue::singleton(1));

        a.join_with(&b);
        assert!(matches!(a.return_values["rax"], AbstractValue::Values(_)));
    }

    // ── SummaryDatabase ───────────────────────────────────────────────────────

    #[test]
    fn summary_db_insert_and_get() {
        let mut db = SummaryDatabase::new();
        let s = FunctionSummary::conservative(fid(1));
        db.insert(s);
        assert!(db.get(fid(1)).is_some());
        assert!(db.get(fid(99)).is_none());
    }

    #[test]
    fn summary_db_count() {
        let mut db = SummaryDatabase::new();
        db.insert(FunctionSummary::conservative(fid(1)));
        db.insert(FunctionSummary::conservative(fid(2)));
        assert_eq!(db.count(), 2);
    }

    #[test]
    fn summary_db_return_value_unknown() {
        let db = SummaryDatabase::new();
        assert!(db.return_value(fid(1), "rax").is_top());
    }

    // ── BottomUp ──────────────────────────────────────────────────────────────

    #[test]
    fn bottom_up_populates_all_functions() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));

        let analysis = Arc::new(ConservativeAnalysis);
        let bu = BottomUp::new(&cg, analysis);
        let db = bu.run();

        assert!(db.get(fid(1)).is_some());
        assert!(db.get(fid(2)).is_some());
        assert!(db.get(fid(3)).is_some());
    }

    #[test]
    fn bottom_up_constant_return_propagates() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));

        let known: HashMap<FunctionId, i64> = std::iter::once((fid(2), 42)).collect();
        let analysis = Arc::new(ConstantReturnAnalysis::new(known));
        let bu = BottomUp::new(&cg, analysis);
        let db = bu.run();

        let s2 = db.get(fid(2)).unwrap();
        assert_eq!(s2.return_values["rax"].as_singleton(), Some(42));
    }

    // ── TopDown ───────────────────────────────────────────────────────────────

    #[test]
    fn top_down_produces_site_summaries() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));

        let mut db = SummaryDatabase::new();
        db.insert(FunctionSummary::conservative(fid(2)));

        let td = TopDown::new(&cg, &db);
        let sites = td.run(&[fid(1)]);
        assert!(!sites.is_empty());
        assert_eq!(sites[0].caller, fid(1));
        assert_eq!(sites[0].callee, Some(fid(2)));
    }

    #[test]
    fn top_down_propagates_return_value() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(2)));

        let mut db = SummaryDatabase::new();
        let mut s = FunctionSummary::empty(fid(2));
        s.set_return("rax", AbstractValue::singleton(7));
        s.mark_final();
        db.insert(s);

        let td = TopDown::new(&cg, &db);
        let sites = td.run(&[fid(1)]);
        assert_eq!(sites[0].return_value.as_singleton(), Some(7));
    }

    // ── InterproceduralAnalysis ───────────────────────────────────────────────

    #[test]
    fn interprocedural_analysis_default_is_empty() {
        let ia = InterproceduralAnalysis::new();
        assert_eq!(ia.call_graph.function_count(), 0);
        assert_eq!(ia.db.count(), 0);
    }

    #[test]
    fn interprocedural_analysis_run_populates_db() {
        let mut ia = InterproceduralAnalysis::new();
        ia.call_graph
            .add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        ia = ia.run(Arc::new(ConservativeAnalysis), &[fid(1)]);
        assert!(ia.db.get(fid(1)).is_some());
        assert!(ia.db.get(fid(2)).is_some());
    }

    #[test]
    fn interprocedural_analysis_site_summaries() {
        let mut ia = InterproceduralAnalysis::new();
        ia.call_graph
            .add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        ia = ia.run(Arc::new(ConservativeAnalysis), &[fid(1)]);
        assert!(!ia.site_summaries.is_empty());
    }

    #[test]
    fn interprocedural_analysis_sites_for_caller() {
        let mut ia = InterproceduralAnalysis::new();
        ia.call_graph
            .add_call_site(CallSite::direct(0x100, fid(1), fid(2)));
        ia.call_graph
            .add_call_site(CallSite::direct(0x200, fid(1), fid(3)));
        ia = ia.run(Arc::new(ConservativeAnalysis), &[fid(1)]);
        let sites = ia.sites_for_caller(fid(1));
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn call_site_summary_construction() {
        let css = CallSiteSummary::new(0x1000, fid(1), Some(fid(2)));
        assert_eq!(css.call_addr, 0x1000);
        assert!(css.is_reachable);
    }

    #[test]
    fn call_site_summary_add_arg() {
        let mut css = CallSiteSummary::new(0x1000, fid(1), None);
        css.add_arg(AbstractValue::singleton(0));
        css.add_arg(AbstractValue::Top);
        assert_eq!(css.arg_values.len(), 2);
    }

    #[test]
    fn constant_return_analysis_known_fn() {
        let cg = CallGraph::new();
        let db = SummaryDatabase::new();
        let known: HashMap<FunctionId, i64> = std::iter::once((fid(1), 99)).collect();
        let analysis = ConstantReturnAnalysis::new(known);
        let s = analysis.analyze(fid(1), &cg, &db);
        assert_eq!(s.return_values["rax"].as_singleton(), Some(99));
    }

    #[test]
    fn call_graph_call_sites_to() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(0x100, fid(1), fid(3)));
        cg.add_call_site(CallSite::direct(0x200, fid(2), fid(3)));
        let sites = cg.call_sites_to(fid(3));
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn call_graph_empty_reachable() {
        let cg = CallGraph::new();
        let r = cg.reachable_from(fid(1));
        assert!(!r.contains(&fid(2)));
    }

    #[test]
    fn abstract_value_bottom_is_not_top() {
        let b = AbstractValue::Bottom;
        assert!(b.is_bottom());
        assert!(!b.is_top());
    }

    #[test]
    fn abstract_value_top_is_not_bottom() {
        let t = AbstractValue::Top;
        assert!(t.is_top());
        assert!(!t.is_bottom());
    }

    #[test]
    fn abstract_value_singleton_as_singleton() {
        let v = AbstractValue::singleton(99);
        assert_eq!(v.as_singleton(), Some(99));
    }

    #[test]
    fn function_summary_set_arg_effect() {
        let mut s = FunctionSummary::empty(fid(1));
        s.set_arg_effect(0, AbstractValue::singleton(42));
        assert_eq!(s.arg_effects[&0].as_singleton(), Some(42));
    }

    #[test]
    fn function_summary_mark_final() {
        let mut s = FunctionSummary::empty(fid(1));
        assert!(!s.is_final);
        s.mark_final();
        assert!(s.is_final);
    }

    #[test]
    fn summary_db_final_summaries() {
        let mut db = SummaryDatabase::new();
        let mut s1 = FunctionSummary::empty(fid(1));
        s1.mark_final();
        db.insert(s1);
        let s2 = FunctionSummary::empty(fid(2));
        db.insert(s2);
        assert_eq!(db.final_summaries().len(), 1);
        assert_eq!(db.pending_summaries().len(), 1);
    }

    #[test]
    fn summary_db_get_mut() {
        let mut db = SummaryDatabase::new();
        db.insert(FunctionSummary::empty(fid(1)));
        let s = db.get_mut(fid(1)).unwrap();
        s.mark_final();
        assert!(db.get(fid(1)).unwrap().is_final);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphBuilder — convenience builder that parses call records
// ─────────────────────────────────────────────────────────────────────────────

/// A raw call record: (`caller_addr`, `call_site_addr`, `callee_addr_or_None`).
#[derive(Debug, Clone)]
pub struct RawCallRecord {
    pub caller: u64,
    pub call_site: u64,
    pub callee: Option<u64>,
    pub is_tail_call: bool,
}

impl RawCallRecord {
    #[must_use]
    pub const fn direct(caller: u64, call_site: u64, target_fn: u64) -> Self {
        Self {
            caller,
            call_site,
            callee: Some(target_fn),
            is_tail_call: false,
        }
    }
    #[must_use]
    pub const fn indirect(caller: u64, call_site: u64) -> Self {
        Self {
            caller,
            call_site,
            callee: None,
            is_tail_call: false,
        }
    }
}

/// Builds a `CallGraph` from a list of `RawCallRecord`s.
pub struct CallGraphBuilder {
    records: Vec<RawCallRecord>,
    names: HashMap<u64, String>,
}

impl CallGraphBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            names: HashMap::new(),
        }
    }

    pub fn add_record(&mut self, rec: RawCallRecord) {
        self.records.push(rec);
    }

    pub fn add_name(&mut self, addr: u64, name: impl Into<String>) {
        self.names.insert(addr, name.into());
    }

    #[must_use] 
    pub fn build(self) -> CallGraph {
        let mut cg = CallGraph::new();
        for rec in &self.records {
            let caller = FunctionId::new(rec.caller);
            if let Some(n) = self.names.get(&rec.caller) {
                cg.add_named_function(caller, n.clone());
            } else {
                cg.add_function(caller);
            }
            if let Some(callee_addr) = rec.callee {
                let call_target = FunctionId::new(callee_addr);
                if let Some(n) = self.names.get(&callee_addr) {
                    cg.add_named_function(call_target, n.clone());
                } else {
                    cg.add_function(call_target);
                }
                let mut cs = CallSite::direct(rec.call_site, caller, call_target);
                if rec.is_tail_call {
                    cs = cs.with_tail_call();
                }
                cg.add_call_site(cs);
            } else {
                cg.add_call_site(CallSite::indirect(rec.call_site, caller));
            }
        }
        cg
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecursionDetector — identifies recursive functions
// ─────────────────────────────────────────────────────────────────────────────

/// Detects recursive and mutually-recursive function groups.
pub struct RecursionDetector;

impl RecursionDetector {
    /// Return a list of recursive groups (cycles in the call graph).
    ///
    /// Each group is a sorted `Vec<FunctionId>` of mutually recursive functions.
    /// Directly recursive functions appear in singleton groups.
    #[must_use]
    pub fn find_recursive_groups(cg: &CallGraph) -> Vec<Vec<FunctionId>> {
        // Use DFS with coloring: 0=unvisited, 1=in-stack, 2=done.
        let mut color: HashMap<FunctionId, u8> = HashMap::new();
        let mut stack: Vec<FunctionId> = Vec::new();
        let mut groups: Vec<Vec<FunctionId>> = Vec::new();

        let fns: Vec<FunctionId> = {
            let mut v: Vec<_> = cg.functions.iter().copied().collect();
            v.sort();
            v
        };

        for &start in &fns {
            if color.get(&start).copied().unwrap_or(0) == 0 {
                Self::dfs(start, cg, &mut color, &mut stack, &mut groups);
            }
        }
        groups
    }

    fn dfs(
        root: FunctionId,
        cg: &CallGraph,
        color: &mut HashMap<FunctionId, u8>,
        stack: &mut Vec<FunctionId>,
        groups: &mut Vec<Vec<FunctionId>>,
    ) {
        // Iterative DFS with explicit call-stack simulation to avoid stack overflow
        // on attacker-controlled deeply-nested call graphs (dos-unbounded-recursion).
        // Frame: (node, sorted-callees, next-callee-index)
        color.insert(root, 1);
        stack.push(root);

        // worklist: (node, callees, next_idx)
        let mut worklist: Vec<(FunctionId, Vec<FunctionId>, usize)> = {
            let mut callees = cg.callees_of(root);
            callees.sort();
            vec![(root, callees, 0)]
        };

        while let Some(frame) = worklist.last_mut() {
            let (node, callees, idx) = frame;
            if *idx < callees.len() {
                let callee = callees[*idx];
                *idx += 1;
                match color.get(&callee).copied().unwrap_or(0) {
                    0 => {
                        color.insert(callee, 1);
                        stack.push(callee);
                        let mut child_callees = cg.callees_of(callee);
                        child_callees.sort();
                        worklist.push((callee, child_callees, 0));
                    }
                    1 => {
                        // Back-edge → cycle found.
                        if let Some(pos) = stack.iter().position(|&f| f == callee) {
                            let mut cycle: Vec<FunctionId> = stack[pos..].to_vec();
                            cycle.sort();
                            groups.push(cycle);
                        }
                    }
                    _ => {}
                }
            } else {
                // All callees of `node` processed.
                stack.pop();
                color.insert(*node, 2);
                worklist.pop();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for the builders and detectors
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn call_graph_builder_direct() {
        let mut b = CallGraphBuilder::new();
        b.add_name(0x1000, "main");
        b.add_name(0x2000, "foo");
        b.add_record(RawCallRecord::direct(0x1000, 0x1010, 0x2000));
        let cg = b.build();
        assert_eq!(cg.function_count(), 2);
        assert_eq!(cg.name_of(FunctionId::new(0x1000)), Some("main"));
        assert_eq!(cg.name_of(FunctionId::new(0x2000)), Some("foo"));
    }

    #[test]
    fn call_graph_builder_indirect() {
        let mut b = CallGraphBuilder::new();
        b.add_record(RawCallRecord::indirect(0x1000, 0x1020));
        let cg = b.build();
        assert_eq!(cg.function_count(), 1);
        assert_eq!(cg.edge_count(), 1);
    }

    #[test]
    fn call_graph_builder_tail_call() {
        let mut b = CallGraphBuilder::new();
        let mut rec = RawCallRecord::direct(0x1000, 0x1050, 0x2000);
        rec.is_tail_call = true;
        b.add_record(rec);
        let cg = b.build();
        let sites = cg.call_sites_from(FunctionId::new(0x1000));
        assert!(sites[0].is_tail_call);
    }

    #[test]
    fn recursion_detector_simple_cycle() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(
            0x100,
            FunctionId::new(1),
            FunctionId::new(2),
        ));
        cg.add_call_site(CallSite::direct(
            0x200,
            FunctionId::new(2),
            FunctionId::new(1),
        ));
        let groups = RecursionDetector::find_recursive_groups(&cg);
        assert!(!groups.is_empty());
        let has_two = groups.iter().any(|g| g.len() == 2);
        assert!(has_two);
    }

    #[test]
    fn recursion_detector_no_cycle() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(
            0x100,
            FunctionId::new(1),
            FunctionId::new(2),
        ));
        let groups = RecursionDetector::find_recursive_groups(&cg);
        assert!(groups.is_empty());
    }

    #[test]
    fn recursion_detector_self_recursive() {
        let mut cg = CallGraph::new();
        cg.add_call_site(CallSite::direct(
            0x100,
            FunctionId::new(1),
            FunctionId::new(1),
        ));
        let groups = RecursionDetector::find_recursive_groups(&cg);
        // Self-loop produces a single-element cycle group.
        assert!(!groups.is_empty());
    }

    #[test]
    fn abstract_value_join_associative() {
        let a = AbstractValue::singleton(1);
        let b = AbstractValue::singleton(2);
        let c = AbstractValue::singleton(3);
        let ab_c = a.join(&b).join(&c);
        let a_bc = a.join(&b.join(&c));
        // Both should be equivalent (same set).
        if let (AbstractValue::Values(s1), AbstractValue::Values(s2)) = (&ab_c, &a_bc) {
            assert_eq!(s1, s2);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphSerializer — export/import call graphs as JSON-like records
// ─────────────────────────────────────────────────────────────────────────────

/// A serialisable representation of a call graph edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_site: u64,
    pub is_indirect: bool,
    pub is_tail_call: bool,
}

/// A serialisable representation of a call graph node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedNode {
    pub addr: u64,
    pub name: Option<String>,
}

/// Serialise a `CallGraph` to a list of nodes and edges.
#[must_use]
pub fn serialize_call_graph(cg: &CallGraph) -> (Vec<SerializedNode>, Vec<SerializedEdge>) {
    let mut nodes: Vec<SerializedNode> = cg
        .functions
        .iter()
        .map(|&f| SerializedNode {
            addr: f.0,
            name: cg.name_of(f).map(str::to_string),
        })
        .collect();
    nodes.sort_by_key(|n| n.addr);

    let mut edges: Vec<SerializedEdge> = cg
        .call_sites
        .iter()
        .filter_map(|cs| {
            let callee = cs.callee?;
            Some(SerializedEdge {
                caller: cs.caller.0,
                callee: callee.0,
                call_site: cs.call_addr,
                is_indirect: cs.is_indirect,
                is_tail_call: cs.is_tail_call,
            })
        })
        .collect();
    edges.sort_by_key(|e| (e.caller, e.callee));

    (nodes, edges)
}

/// Reconstruct a `CallGraph` from serialised nodes/edges.
#[must_use]
pub fn deserialize_call_graph(nodes: &[SerializedNode], edges: &[SerializedEdge]) -> CallGraph {
    let mut cg = CallGraph::new();
    for n in nodes {
        if let Some(ref name) = n.name {
            cg.add_named_function(FunctionId::new(n.addr), name.clone());
        } else {
            cg.add_function(FunctionId::new(n.addr));
        }
    }
    for e in edges {
        let cs = CallSite {
            call_addr: e.call_site,
            caller: FunctionId::new(e.caller),
            callee: Some(FunctionId::new(e.callee)),
            is_tail_call: e.is_tail_call,
            is_indirect: e.is_indirect,
            confidence: 100,
        };
        cg.add_call_site(cs);
    }
    cg
}

// ─────────────────────────────────────────────────────────────────────────────
// SummaryExporter — export summaries as human-readable text
// ─────────────────────────────────────────────────────────────────────────────

/// Formats a `FunctionSummary` as a human-readable string.
#[must_use]
pub fn format_summary(s: &FunctionSummary) -> String {
    use std::fmt::Write as _;
    let mut out = format!("fn@{:#x}:\n", s.id.0);
    for (slot, val) in &s.return_values {
        let val_str = match val {
            AbstractValue::Top => "top".to_string(),
            AbstractValue::Bottom => "bot".to_string(),
            AbstractValue::Values(v) => {
                let mut vals: Vec<String> = v.iter().map(std::string::ToString::to_string).collect();
                vals.sort();
                format!("{{{}}}", vals.join(", "))
            }
        };
        let _ = writeln!(out, "  ret[{slot}] = {val_str}");
    }
    if s.may_have_side_effects {
        out.push_str("  may_side_effect = true\n");
    }
    if s.may_not_return {
        out.push_str("  may_not_return = true\n");
    }
    out.push_str(if s.is_final {
        "  [final]\n"
    } else {
        "  [pending]\n"
    });
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional tests for serialisation and formatting
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn serialize_empty_graph() {
        let cg = CallGraph::new();
        let (nodes, edges) = serialize_call_graph(&cg);
        assert!(nodes.is_empty());
        assert!(edges.is_empty());
    }

    #[test]
    fn serialize_roundtrip() {
        let mut cg = CallGraph::new();
        cg.add_named_function(FunctionId::new(0x1000), "main");
        cg.add_named_function(FunctionId::new(0x2000), "foo");
        cg.add_call_site(CallSite::direct(
            0x1010,
            FunctionId::new(0x1000),
            FunctionId::new(0x2000),
        ));
        let (nodes, edges) = serialize_call_graph(&cg);
        let cg2 = deserialize_call_graph(&nodes, &edges);
        assert_eq!(cg2.function_count(), 2);
        assert_eq!(cg2.edge_count(), 1);
        assert_eq!(cg2.name_of(FunctionId::new(0x1000)), Some("main"));
    }

    #[test]
    fn serialize_preserves_names() {
        let mut cg = CallGraph::new();
        cg.add_named_function(FunctionId::new(0x400000), "entry");
        let (nodes, _) = serialize_call_graph(&cg);
        assert_eq!(nodes[0].name.as_deref(), Some("entry"));
    }

    #[test]
    fn format_summary_final() {
        let mut s = FunctionSummary::empty(FunctionId::new(0x1000));
        s.set_return("rax", AbstractValue::singleton(42));
        s.mark_final();
        let text = format_summary(&s);
        assert!(text.contains("final"));
        assert!(text.contains("42"));
    }

    #[test]
    fn format_summary_top() {
        let s = FunctionSummary::conservative(FunctionId::new(0x2000));
        let text = format_summary(&s);
        assert!(text.contains("top"));
    }

    #[test]
    fn format_summary_side_effect() {
        let s = FunctionSummary::conservative(FunctionId::new(0x3000));
        let text = format_summary(&s);
        assert!(text.contains("side_effect"));
    }
}
