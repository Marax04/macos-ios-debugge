//! `function_call_navigator` — Navigate call/return structure in execution traces.
//!
//! Provides [`FunctionCallNavigator`] which builds an index of all CALL/RET events
//! and supports call-tree traversal, caller/callee lookup, depth filtering, and
//! navigating to any invocation of a function.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Address, EntryKind, ExecutionTrace, StackFrame};

// ─── CallSite ────────────────────────────────────────────────────────────────

/// A single call site — one CALL instruction in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Trace index of the CALL instruction.
    pub call_idx: usize,
    /// Address of the CALL instruction.
    pub call_addr: Address,
    /// Address of the callee function entry.
    pub callee_addr: Address,
    /// Return address (instruction after the CALL).
    pub ret_addr: Address,
    /// Thread ID.
    pub tid: u32,
    /// Trace index where the matching RET was seen, if any.
    pub ret_idx: Option<usize>,
    /// Call depth at the time of this CALL (0 = outermost).
    pub depth: u32,
    /// Optional resolved symbol for the callee.
    pub callee_name: Option<String>,
}

impl CallSite {
    /// Whether this call site has a matched return.
    #[must_use]
    pub const fn has_return(&self) -> bool {
        self.ret_idx.is_some()
    }

    /// Number of trace entries between the CALL and the matching RET (inclusive).
    #[must_use]
    pub fn span(&self) -> Option<usize> {
        self.ret_idx.map(|r| r.saturating_sub(self.call_idx) + 1)
    }

    /// Display name: callee symbol or hex address.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.callee_name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.callee_addr))
    }
}

impl std::fmt::Display for CallSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallSite(idx={}, site=0x{:x} → {} depth={}{})",
            self.call_idx,
            self.call_addr,
            self.display_name(),
            self.depth,
            self.ret_idx.map_or_else(String::new, |r| format!(" ret_idx={r}"))
        )
    }
}

// ─── CallNavigation ──────────────────────────────────────────────────────────

/// Result of a navigation request — the trace index to move the cursor to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNavigation {
    /// The target trace index.
    pub target_idx: usize,
    /// The address at the target index.
    pub target_addr: Address,
    /// Description of what was navigated to.
    pub description: String,
}

impl CallNavigation {
    #[must_use]
    fn new(target_idx: usize, target_addr: Address, description: impl Into<String>) -> Self {
        Self {
            target_idx,
            target_addr,
            description: description.into(),
        }
    }
}

// ─── CallTreeNode ─────────────────────────────────────────────────────────────

/// A node in the call tree built from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNode {
    /// Callee function address.
    pub fn_addr: Address,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Trace index of the CALL.
    pub call_idx: usize,
    /// Trace index of the matching RET (if any).
    pub ret_idx: Option<usize>,
    /// Depth in the tree (root = 0).
    pub depth: u32,
    /// Child calls made within this function's scope.
    pub children: Vec<Self>,
}

impl CallTreeNode {
    /// Display name.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.fn_addr))
    }

    /// Total number of nodes in the subtree rooted here (inclusive).
    #[must_use]
    pub fn subtree_size(&self) -> usize {
        1 + self.children.iter().map(Self::subtree_size).sum::<usize>()
    }

    /// All descendant function addresses in DFS order.
    pub fn collect_addresses(&self, out: &mut Vec<Address>) {
        out.push(self.fn_addr);
        for child in &self.children {
            child.collect_addresses(out);
        }
    }

    /// Maximum depth of this subtree.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.children
            .iter()
            .map(Self::max_depth)
            .max()
            .map_or(self.depth, |d| d.max(self.depth))
    }
}

// ─── FunctionCallNavigator ────────────────────────────────────────────────────

/// Navigates the call graph implied by an execution trace.
///
/// Provides:
/// - All call sites for a given function address
/// - Jump to first/last/nth call of a function
/// - Find the enclosing function at any trace index
/// - Build a call tree
/// - Filter call sites by depth or thread
/// - Step to the next/previous call from the current cursor
pub struct FunctionCallNavigator {
    /// All call sites extracted from the trace.
    call_sites: Vec<CallSite>,
    /// Callee address → indices into `call_sites`.
    by_callee: HashMap<Address, Vec<usize>>,
    /// Caller address → indices into `call_sites`.
    by_caller: HashMap<Address, Vec<usize>>,
    /// Symbol table.
    symbols: HashMap<Address, String>,
    /// Total trace length.
    trace_len: usize,
    /// Root call-tree nodes (outermost calls).
    call_tree: Vec<CallTreeNode>,
    /// Statistics.
    stats: CallNavStats,
}

/// Summary statistics for the call navigator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallNavStats {
    /// Total CALL instructions encountered.
    pub total_calls: usize,
    /// Total RET instructions encountered.
    pub total_rets: usize,
    /// Maximum observed call depth.
    pub max_depth: u32,
    /// Number of unique callee addresses.
    pub unique_callees: usize,
    /// Number of calls with matched returns.
    pub matched_returns: usize,
}

impl FunctionCallNavigator {
    /// Build a navigator from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut call_sites: Vec<CallSite> = Vec::new();
        let mut callee_map: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut source_map: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut depth_stack: Vec<usize> = Vec::new(); // stack of call_sites indices
        let mut current_depth: u32 = 0;
        let mut total_rets = 0usize;
        let mut max_depth: u32 = 0;

        for entry in &trace.entries {
            match entry.kind {
                EntryKind::Call { target, ret_addr } => {
                    let site_idx = call_sites.len();
                    call_sites.push(CallSite {
                        call_idx: entry.idx,
                        call_addr: entry.pc,
                        callee_addr: target,
                        ret_addr,
                        tid: entry.tid,
                        ret_idx: None,
                        depth: current_depth,
                        callee_name: None,
                    });
                    callee_map.entry(target).or_default().push(site_idx);
                    source_map.entry(entry.pc).or_default().push(site_idx);
                    depth_stack.push(site_idx);
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                }
                EntryKind::Ret { .. } => {
                    total_rets += 1;
                    if let Some(site_idx) = depth_stack.pop() {
                        call_sites[site_idx].ret_idx = Some(entry.idx);
                        current_depth = current_depth.saturating_sub(1);
                    }
                }
                _ => {}
            }
        }

        let total_calls = call_sites.len();
        let matched_returns = call_sites.iter().filter(|s| s.ret_idx.is_some()).count();
        let unique_callees = callee_map.len();

        // Build call tree
        let call_tree = Self::build_call_tree(trace, &call_sites);

        let stats = CallNavStats {
            total_calls,
            total_rets,
            max_depth,
            unique_callees,
            matched_returns,
        };

        Self {
            call_sites,
            by_callee: callee_map,
            by_caller: source_map,
            symbols: HashMap::new(),
            trace_len: trace.len(),
            call_tree,
            stats,
        }
    }

    /// Total number of trace entries this navigator was built over.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.trace_len
    }

    /// Register a symbol name for a function address.
    pub fn add_symbol(&mut self, addr: Address, name: impl Into<String>) {
        let name = name.into();
        self.symbols.insert(addr, name.clone());
        // Back-fill existing call sites
        for site in &mut self.call_sites {
            if site.callee_addr == addr && site.callee_name.is_none() {
                site.callee_name = Some(name.clone());
            }
        }
    }

    // ── Query API ──────────────────────────────────────────────────────────

    /// All call sites for the function at `callee_addr`.
    #[must_use]
    pub fn call_sites_for(&self, callee_addr: Address) -> Vec<&CallSite> {
        self.by_callee
            .get(&callee_addr)
            .map(|idxs| idxs.iter().map(|&i| &self.call_sites[i]).collect())
            .unwrap_or_default()
    }

    /// All call sites made from a given caller address.
    #[must_use]
    pub fn call_sites_from(&self, caller_addr: Address) -> Vec<&CallSite> {
        self.by_caller
            .get(&caller_addr)
            .map(|idxs| idxs.iter().map(|&i| &self.call_sites[i]).collect())
            .unwrap_or_default()
    }

    /// All call sites, in trace order.
    #[must_use]
    pub fn all_call_sites(&self) -> &[CallSite] {
        &self.call_sites
    }

    /// Call sites at exactly `depth`.
    #[must_use]
    pub fn call_sites_at_depth(&self, depth: u32) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|s| s.depth == depth).collect()
    }

    /// Call sites for thread `tid`.
    #[must_use]
    pub fn call_sites_for_thread(&self, tid: u32) -> Vec<&CallSite> {
        self.call_sites.iter().filter(|s| s.tid == tid).collect()
    }

    // ── Navigation ─────────────────────────────────────────────────────────

    /// Navigate to the first call of `callee_addr` after `current_idx`.
    #[must_use]
    pub fn navigate_to_first_call(&self, callee_addr: Address) -> Option<CallNavigation> {
        let sites = self.call_sites_for(callee_addr);
        sites.first().map(|s| {
            CallNavigation::new(
                s.call_idx,
                s.call_addr,
                format!("First call to {}", self.resolve(callee_addr)),
            )
        })
    }

    /// Navigate to the last call of `callee_addr`.
    #[must_use]
    pub fn navigate_to_last_call(&self, callee_addr: Address) -> Option<CallNavigation> {
        let sites = self.call_sites_for(callee_addr);
        sites.last().map(|s| {
            CallNavigation::new(
                s.call_idx,
                s.call_addr,
                format!("Last call to {}", self.resolve(callee_addr)),
            )
        })
    }

    /// Navigate to the Nth call (0-based) of `callee_addr`.
    #[must_use]
    pub fn navigate_to_nth_call(&self, callee_addr: Address, n: usize) -> Option<CallNavigation> {
        let sites = self.call_sites_for(callee_addr);
        sites.get(n).map(|s| {
            CallNavigation::new(
                s.call_idx,
                s.call_addr,
                format!("Call #{n} to {}", self.resolve(callee_addr)),
            )
        })
    }

    /// Navigate to the return of the call at `call_idx`.
    #[must_use]
    pub fn navigate_to_return_of(&self, call_idx: usize) -> Option<CallNavigation> {
        let site = self.call_sites.iter().find(|s| s.call_idx == call_idx)?;
        let ret_idx = site.ret_idx?;
        Some(CallNavigation::new(
            ret_idx,
            0,
            format!("Return of call to {}", site.display_name()),
        ))
    }

    /// Find the call site enclosing `trace_idx` (deepest active frame at that point).
    #[must_use]
    pub fn enclosing_call(&self, trace_idx: usize) -> Option<&CallSite> {
        // Find all call sites whose call_idx <= trace_idx and whose ret_idx (if any) >= trace_idx
        self.call_sites
            .iter()
            .filter(|s| {
                s.call_idx <= trace_idx
                    && s.ret_idx.is_none_or(|r| r >= trace_idx)
            })
            .max_by_key(|s| s.depth)
    }

    /// Find the next call instruction strictly after `current_idx`.
    #[must_use]
    pub fn next_call_after(&self, current_idx: usize) -> Option<CallNavigation> {
        let site = self
            .call_sites
            .iter()
            .find(|s| s.call_idx > current_idx)?;
        Some(CallNavigation::new(
            site.call_idx,
            site.call_addr,
            format!("Next call → {}", site.display_name()),
        ))
    }

    /// Find the previous call instruction strictly before `current_idx`.
    #[must_use]
    pub fn prev_call_before(&self, current_idx: usize) -> Option<CallNavigation> {
        let site = self
            .call_sites
            .iter()
            .rev()
            .find(|s| s.call_idx < current_idx)?;
        Some(CallNavigation::new(
            site.call_idx,
            site.call_addr,
            format!("Previous call → {}", site.display_name()),
        ))
    }

    /// Navigate to the next call of the same function as the call at `call_idx`.
    #[must_use]
    pub fn navigate_to_next_invocation(&self, call_idx: usize) -> Option<CallNavigation> {
        let site = self.call_sites.iter().find(|s| s.call_idx == call_idx)?;
        let callee = site.callee_addr;
        let sites = self.call_sites_for(callee);
        let pos = sites.iter().position(|s| s.call_idx == call_idx)?;
        let next = sites.get(pos + 1)?;
        Some(CallNavigation::new(
            next.call_idx,
            next.call_addr,
            format!("Next invocation of {}", self.resolve(callee)),
        ))
    }

    /// Navigate to the previous invocation of the same function.
    #[must_use]
    pub fn navigate_to_prev_invocation(&self, call_idx: usize) -> Option<CallNavigation> {
        let site = self.call_sites.iter().find(|s| s.call_idx == call_idx)?;
        let callee = site.callee_addr;
        let sites = self.call_sites_for(callee);
        let pos = sites.iter().position(|s| s.call_idx == call_idx)?;
        let prev = pos.checked_sub(1).and_then(|i| sites.get(i))?;
        Some(CallNavigation::new(
            prev.call_idx,
            prev.call_addr,
            format!("Previous invocation of {}", self.resolve(callee)),
        ))
    }

    // ── Call tree ──────────────────────────────────────────────────────────

    /// Reference to the call tree.
    #[must_use]
    pub fn call_tree(&self) -> &[CallTreeNode] {
        &self.call_tree
    }

    /// All function addresses called anywhere in the trace, deduplicated.
    #[must_use]
    pub fn all_called_functions(&self) -> Vec<Address> {
        self.by_callee.keys().copied().collect()
    }

    /// Call frequency: how many times each function was called.
    #[must_use]
    pub fn call_frequency(&self) -> HashMap<Address, usize> {
        self.by_callee
            .iter()
            .map(|(addr, sites)| (*addr, sites.len()))
            .collect()
    }

    /// Top-N most called functions.
    #[must_use]
    pub fn top_callees(&self, n: usize) -> Vec<(Address, usize)> {
        let mut freq: Vec<(Address, usize)> = self.call_frequency().into_iter().collect();
        freq.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        freq.truncate(n);
        freq
    }

    /// Statistics.
    #[must_use]
    pub const fn stats(&self) -> &CallNavStats {
        &self.stats
    }

    /// Reconstruct the call stack (active frames) at `trace_idx`.
    #[must_use]
    pub fn call_stack_at(&self, trace_idx: usize) -> Vec<StackFrame> {
        let mut frames: Vec<&CallSite> = self
            .call_sites
            .iter()
            .filter(|s| {
                s.call_idx <= trace_idx && s.ret_idx.is_none_or(|r| r >= trace_idx)
            })
            .collect();
        frames.sort_by_key(|s| s.depth);
        frames
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let mut f = StackFrame::new(s.callee_addr, s.ret_addr, u32::try_from(i).unwrap_or(u32::MAX), s.call_idx);
                f.name.clone_from(&s.callee_name);
                f
            })
            .collect()
    }

    // ── Private ────────────────────────────────────────────────────────────

    fn resolve(&self, addr: Address) -> String {
        self.symbols
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("0x{addr:x}"))
    }

    fn build_call_tree(trace: &ExecutionTrace, call_sites: &[CallSite]) -> Vec<CallTreeNode> {
        // Build a list of root-level (depth == 0) nodes
        let mut roots: Vec<CallTreeNode> = Vec::new();
        let stack: Vec<usize> = Vec::new(); // indices into growing tree (breadth-first won't work; use flat vec)

        // Build using index-based recursion-avoidance
        let depth0: Vec<usize> = call_sites
            .iter()
            .enumerate()
            .filter(|(_, s)| s.depth == 0)
            .map(|(i, _)| i)
            .collect();

        for &root_idx in &depth0 {
            let site = &call_sites[root_idx];
            let node = Self::build_subtree(site, call_sites);
            roots.push(node);
        }
        let _ = stack;
        let _ = trace;
        roots
    }

    fn build_subtree(site: &CallSite, all_sites: &[CallSite]) -> CallTreeNode {
        // Find direct children: depth == site.depth + 1 and within our range
        let child_depth = site.depth + 1;
        let range_end = site.ret_idx.unwrap_or(usize::MAX);

        let children: Vec<CallTreeNode> = all_sites
            .iter()
            .filter(|s| {
                s.depth == child_depth
                    && s.call_idx > site.call_idx
                    && s.call_idx < range_end
            })
            .map(|s| Self::build_subtree(s, all_sites))
            .collect();

        CallTreeNode {
            fn_addr: site.callee_addr,
            name: site.callee_name.clone(),
            call_idx: site.call_idx,
            ret_idx: site.ret_idx,
            depth: site.depth,
            children,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceBuilder;

    fn simple_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test");
        b.insn(0x1000, 1, "push rbp");
        b.call(0x1001, 1, 0x2000, 0x1006); // call fn_a
        b.insn(0x2000, 1, "nop");
        b.call(0x2001, 1, 0x3000, 0x2006); // call fn_b from fn_a
        b.insn(0x3000, 1, "nop");
        b.ret(0x3005, 1, 0x2006); // ret from fn_b
        b.ret(0x2009, 1, 0x1006); // ret from fn_a
        b.insn(0x1006, 1, "pop rbp");
        b.build()
    }

    #[test]
    fn test_call_site_count() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        assert_eq!(nav.stats().total_calls, 2);
    }

    #[test]
    fn test_call_sites_for_callee() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let sites = nav.call_sites_for(0x2000);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].callee_addr, 0x2000);
    }

    #[test]
    fn test_call_site_ret_matching() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        assert_eq!(nav.stats().matched_returns, 2);
    }

    #[test]
    fn test_navigate_to_first_call() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let nav_result = nav.navigate_to_first_call(0x2000);
        assert!(nav_result.is_some());
    }

    #[test]
    fn test_navigate_to_last_call() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let result = nav.navigate_to_last_call(0x2000);
        assert!(result.is_some());
    }

    #[test]
    fn test_navigate_unknown_callee() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let result = nav.navigate_to_first_call(0xDEAD);
        assert!(result.is_none());
    }

    #[test]
    fn test_enclosing_call() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        // Index 4 is inside fn_b
        let enc = nav.enclosing_call(4);
        assert!(enc.is_some());
    }

    #[test]
    fn test_call_stack_at() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        // At index 4 (inside fn_b), we should have 2 frames (fn_a, fn_b)
        let stack = nav.call_stack_at(4);
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn test_symbol_resolution() {
        let trace = simple_trace();
        let mut nav = FunctionCallNavigator::build(&trace);
        nav.add_symbol(0x2000, "fn_a");
        let sites = nav.call_sites_for(0x2000);
        assert_eq!(sites[0].callee_name, Some("fn_a".to_string()));
    }

    #[test]
    fn test_next_call_after() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let result = nav.next_call_after(0);
        assert!(result.is_some());
    }

    #[test]
    fn test_prev_call_before() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let result = nav.prev_call_before(5);
        assert!(result.is_some());
    }

    #[test]
    fn test_call_frequency() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let freq = nav.call_frequency();
        assert_eq!(freq.get(&0x2000), Some(&1));
        assert_eq!(freq.get(&0x3000), Some(&1));
    }

    #[test]
    fn test_top_callees() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let top = nav.top_callees(2);
        assert!(!top.is_empty());
    }

    #[test]
    fn test_call_tree_built() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        // Outer call (depth 0) → fn_a
        assert!(!nav.call_tree().is_empty());
    }

    #[test]
    fn test_depth_filter() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        let d0 = nav.call_sites_at_depth(0);
        let d1 = nav.call_sites_at_depth(1);
        assert_eq!(d0.len(), 1);
        assert_eq!(d1.len(), 1);
    }

    #[test]
    fn test_max_depth() {
        let trace = simple_trace();
        let nav = FunctionCallNavigator::build(&trace);
        assert_eq!(nav.stats().max_depth, 2);
    }
}
