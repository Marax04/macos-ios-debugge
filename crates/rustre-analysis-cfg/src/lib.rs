//! `rustre-analysis-cfg`
//!
//! Control Flow Graph (CFG) analysis, basic block splitting, edge extraction,
//! dominator/post-dominator trees, natural loop detection, RPO traversal,
//! cyclomatic complexity, Graphviz DOT output, Lengauer-Tarjan algorithm,
//! CFG simplification, serialization, and layout.

pub mod back_edge;
pub mod basic_block_rec;
pub mod cfg_algorithms;
pub mod cfg_dominators;
pub mod cfg_reconstruction;
pub mod edges;
pub mod exception_cfg;
pub mod intervals;
pub mod irreducible_cfg;
pub mod seh;
pub mod tail_call;
pub mod jump_table;
pub mod lengauer_tarjan;
pub mod loop_analysis;
pub mod loop_detection;
pub mod path_query;
pub mod post_dominator;
pub mod reducibility_analysis;
pub mod simplify;
pub mod stream_cfg;
pub mod cfg_loop_analyzer;
pub mod cfg_simplifier;
#[cfg(test)]
mod soundness_fuzz;

/// Shared test-only PRNG for the crate's fuzz/property tests.
///
/// One definition instead of the per-module copies the test modules used to
/// carry. Two structs because the old copies had two distinct `range`
/// contracts (plain `% n` vs zero-guarded) — kept faithful so no test's
/// behaviour on n == 0 changes.
#[cfg(test)]
pub(crate) mod test_prng {
    /// One xorshift64 step: mutates the state in place and returns it.
    pub(crate) fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Deterministic xorshift PRNG (reproducible without a `rand` dependency).
    /// `range` is plain `% n` (panics on 0, like the former copies).
    pub(crate) struct Xorshift(pub(crate) u64);
    impl Xorshift {
        pub(crate) fn next(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
        pub(crate) fn range(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Variant with a `seed | 1` zero-guard and a zero-tolerant `range`.
    pub(crate) struct Xs(pub(crate) u64);
    impl Xs {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        pub(crate) fn next(&mut self) -> u64 {
            xorshift(&mut self.0)
        }
        pub(crate) fn range(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }
}

#[cfg(test)]
mod graph_law_props;

pub use edges::{FlowEdge, FlowEdgeKind, classify_terminator, compute_leaders, split_basic_blocks};
pub use jump_table::{
    JumpTable, JumpTableConfig, JumpTableKind, SwitchBound, SwitchStatement, decode_absolute_table,
    decode_relative_table,
};
pub use intervals::{
    DerivedSequence, Interval, IntervalAnalysis, IntervalGraph, IntervalLoop, IntervalLoopKind,
    StructuredRegion, StructuredRegionKind, compute_intervals, derived_sequence,
};
pub use lengauer_tarjan::{LtDomTree, compute_lt};
pub use seh::{
    CScopeEntry, MsvcFuncInfo, ParsedUnwindInfo, SehPersonality, find_runtime_function,
    parse_c_scope_table, parse_msvc_funcinfo, parse_pdata, parse_unwind_info,
    regions_from_c_scope_table, regions_from_msvc_funcinfo, seh_regions_for_function,
};
pub use stream_cfg::{StreamCfg, analyze_cfg_stream};
pub use tail_call::{TailCallKind, TailCallSite, detect_tail_calls};
pub use post_dominator::FullPostDomTree;
pub use simplify::{
    BlockPosition, CfgSimplifier, LoopNode, SimplifyResult, build_loop_nesting_forest, cfg_to_json,
    layout_cfg,
};

use rustre_core::address::Address;
use rustre_il_llil::LlilInstruction;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

// ────────────────────────────────────────────────────────────────────────────
// Typed error type
// ────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during CFG analysis operations.
#[derive(Debug, thiserror::Error)]
pub enum CfgError {
    /// The CFG has no blocks (empty instruction stream).
    #[error("CFG is empty: no basic blocks were produced")]
    EmptyCfg,

    /// An entry address was requested but is not present in the block map.
    #[error("entry address {0:?} is not a basic-block start")]
    InvalidEntry(Address),

    /// A block limit was exceeded during CFG reconstruction.
    #[error("block limit exceeded: found more than {limit} blocks")]
    BlockLimitExceeded { limit: usize },

    /// An internal invariant was violated (indicates a bug in this crate).
    #[error("internal CFG invariant violated: {0}")]
    InternalInvariant(String),
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Core data types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A maximal sequence of straight-line instructions —" no internal branches.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: Address,
    pub end: Address,
    pub instructions: Vec<LlilInstruction>,
}

/// The semantic role of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EdgeKind {
    Unconditional,
    TrueBranch,
    FalseBranch,
    Fallthrough,
}

/// A directed edge in the CFG.
#[derive(Debug, Clone)]
pub struct CfgEdge {
    pub from: Address,
    pub to: Address,
    pub kind: EdgeKind,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DominatorTree
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Dominator tree computed with Cooper et al. 2001 "A Simple, Fast Dominance
/// Algorithm".  `idom[n] == None` means `n` is the entry node (it dominates
/// itself but has no proper dominator).
#[derive(Debug, Clone, Default)]
pub struct DominatorTree {
    /// Immediate dominator of each reachable block.  Entry maps to `None`.
    pub idom: HashMap<Address, Option<Address>>,
    /// Children of each node in the dominator tree.
    pub children: HashMap<Address, Vec<Address>>,
    /// Dominance frontier sets.
    pub frontiers: HashMap<Address, Vec<Address>>,
}

impl DominatorTree {
    /// Build the dominator tree for a CFG described by `blocks`, `edges`, and
    /// `entry`.  Uses the Cooper/Harvey/Kennedy iterative bit-vector algorithm.
    #[must_use]
    pub fn compute(
        blocks: &HashMap<Address, BasicBlock>,
        edges: &[CfgEdge],
        entry: Address,
    ) -> Self {
        // 1. Collect reachable nodes in RPO order.
        let rpo = rpo_order(blocks, edges, entry);
        let n = rpo.len();
        if n == 0 {
            return Self::default();
        }

        // Map Address â†' RPO index for O(1) lookup.
        let index: HashMap<Address, usize> = rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // Build predecessor list in RPO-index space.
        let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
        for e in edges {
            if let (Some(&fi), Some(&ti)) = (index.get(&e.from), index.get(&e.to)) {
                preds[ti].push(fi);
            }
        }

        // idom[i] == usize::MAX means "undefined" (not yet computed).
        let undef: usize = usize::MAX;
        let mut idom = vec![undef; n];
        idom[0] = 0; // entry dominates itself

        // Intersect two fingers up the dominator tree (both are RPO indices).
        let intersect = |mut a: usize, mut b: usize, idom: &[usize]| -> usize {
            while a != b {
                while a > b {
                    a = idom[a];
                }
                while b > a {
                    b = idom[b];
                }
            }
            a
        };

        let mut changed = true;
        while changed {
            changed = false;
            // Process in RPO order, skipping the entry (index 0).
            for b in 1..n {
                let mut new_idom = undef;
                for &p in &preds[b] {
                    if idom[p] == undef {
                        continue;
                    }
                    if new_idom == undef {
                        new_idom = p;
                    } else {
                        new_idom = intersect(p, new_idom, &idom);
                    }
                }
                if new_idom != undef && idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        // Convert back to Address space.
        let mut idom_map: HashMap<Address, Option<Address>> = HashMap::new();
        for (i, &dom_i) in idom.iter().enumerate() {
            let node = rpo[i];
            if dom_i == undef {
                // Unreachable; skip.
                continue;
            }
            if i == 0 {
                idom_map.insert(node, None);
            } else {
                idom_map.insert(node, Some(rpo[dom_i]));
            }
        }

        // Build children map.
        //
        // `idom_map` is a HashMap, so iterating it directly (as this used
        // to) pushes each node's children in nondeterministic hash order.
        // That order is exposed publicly through `dominated_by`'s DFS, so
        // sort each child list for a reproducible result.
        let mut children: HashMap<Address, Vec<Address>> = HashMap::new();
        for addr in idom_map.keys() {
            children.entry(*addr).or_default();
        }
        for (&node, &parent_opt) in &idom_map {
            if let Some(parent) = parent_opt {
                children.entry(parent).or_default().push(node);
            }
        }
        for kids in children.values_mut() {
            kids.sort_by_key(|a| a.0);
        }

        // Compute dominance frontiers (standard algorithm).
        let mut frontiers: HashMap<Address, Vec<Address>> = HashMap::new();
        for addr in idom_map.keys() {
            frontiers.entry(*addr).or_default();
        }
        for e in edges {
            if !idom_map.contains_key(&e.from) || !idom_map.contains_key(&e.to) {
                continue;
            }
            // Walk up from `e.from` until we reach idom(e.to).
            // The depth guard (≤ n) prevents an infinite loop on a malformed
            // idom chain that should be impossible from correct input but could
            // arise from adversarial or fuzz-generated CFG data.
            let mut runner = e.from;
            let join = e.to;
            // `None` means `join` is the entry node. The walk must then
            // continue through (and include) the entry itself: mapping the
            // missing idom to `join` (as this used to do) stopped the walk
            // one node early on back edges to the entry, so the entry never
            // appeared in any frontier — e.g. for `0 -> 1 -> 0` the correct
            // DF(0) = DF(1) = {0} both came out empty (found by
            // soundness_fuzz::dominance_frontier_matches_definition_fuzz).
            let join_idom: Option<Address> = idom_map[&join];
            let max_steps = idom_map.len().saturating_add(1);
            let mut steps = 0usize;
            while Some(runner) != join_idom && steps < max_steps {
                steps += 1;
                let front = frontiers.entry(runner).or_default();
                if !front.contains(&join) {
                    front.push(join);
                }
                match idom_map[&runner] {
                    Some(p) => runner = p,
                    None => break, // reached entry
                }
            }
        }

        Self {
            idom: idom_map,
            children,
            frontiers,
        }
    }

    /// Returns `true` if `a` dominates `b` (including `a == b`).
    #[must_use]
    pub fn dominates(&self, a: Address, b: Address) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        while let Some(Some(parent)) = self.idom.get(&cur) {
            if *parent == a {
                return true;
            }
            if *parent == cur {
                return false; // cycle-guard for entry
            }
            cur = *parent;
        }
        false
    }

    /// Returns `true` if `a` strictly dominates `b` (`a` dominates `b` and `a != b`).
    #[must_use]
    pub fn strictly_dominates(&self, a: Address, b: Address) -> bool {
        a != b && self.dominates(a, b)
    }

    /// All nodes strictly dominated by `node` (i.e. `node` dominates them and
    /// they are not `node` itself).  Performs a DFS over the dominator tree.
    #[must_use]
    pub fn dominated_by(&self, node: Address) -> Vec<Address> {
        let mut result = Vec::new();
        let mut stack = Vec::new();
        if let Some(children) = self.children.get(&node) {
            stack.extend_from_slice(children);
        }
        while let Some(n) = stack.pop() {
            result.push(n);
            if let Some(ch) = self.children.get(&n) {
                stack.extend_from_slice(ch);
            }
        }
        result
    }

    /// Dominance frontier of `node`.
    #[must_use]
    pub fn dominance_frontier(&self, node: Address) -> &[Address] {
        self.frontiers.get(&node).map_or(&[], Vec::as_slice)
    }

    /// Depth of `node` in the dominator tree (entry = 0).
    #[must_use]
    pub fn depth(&self, node: Address) -> u32 {
        let mut d = 0u32;
        let mut cur = node;
        while let Some(Some(parent)) = self.idom.get(&cur) {
            d += 1;
            if *parent == cur {
                break;
            }
            cur = *parent;
        }
        d
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PostDominatorTree
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Post-dominator tree.  A node `a` post-dominates `b` iff every path from `b`
/// to any exit passes through `a`.
///
/// Computed by applying the Cooper et al. algorithm on the *reversed* CFG with
/// a virtual exit node that has edges from every "real" exit block.
#[derive(Debug, Clone, Default)]
pub struct PostDominatorTree {
    pub idom: HashMap<Address, Option<Address>>,
    pub children: HashMap<Address, Vec<Address>>,
}

/// Sentinel address used as the virtual exit node during post-dom computation.
const VIRTUAL_EXIT: Address = Address::new(u64::MAX);

impl PostDominatorTree {
    /// Build the post-dominator tree.
    #[must_use]
    pub fn compute(blocks: &HashMap<Address, BasicBlock>, edges: &[CfgEdge]) -> Self {
        if blocks.is_empty() {
            return Self::default();
        }

        // Identify "real" exit blocks (blocks with no successors in the CFG,
        // i.e. they end in Ret or indirect jump with no recorded successor).
        let mut has_successor: HashSet<Address> = HashSet::new();
        for e in edges {
            has_successor.insert(e.from);
        }

        // In the original CFG, add edges  real_exit â†' VIRTUAL_EXIT.
        // After reversing, these become  VIRTUAL_EXIT â†' real_exit,
        // making VIRTUAL_EXIT the single entry of the reversed graph.
        let mut virtual_edges: Vec<CfgEdge> = edges.to_vec();
        // `blocks` is a HashMap, so iterating it directly (as this used to)
        // appends the synthetic exit->VIRTUAL_EXIT edges in nondeterministic
        // order, which feeds the RPO/DFS underpinning `DominatorTree::compute`
        // below. Sort real-exit addresses first for reproducible output.
        let mut exit_addrs: Vec<Address> = blocks
            .keys()
            .copied()
            .filter(|a| !has_successor.contains(a))
            .collect();
        exit_addrs.sort_by_key(|a| a.0);
        for addr in exit_addrs {
            virtual_edges.push(CfgEdge {
                from: addr,
                to: VIRTUAL_EXIT,
                kind: EdgeKind::Unconditional,
            });
        }

        // Build a virtual block set so rpo_order can traverse it.
        let mut virtual_blocks = blocks.clone();
        virtual_blocks.insert(
            VIRTUAL_EXIT,
            BasicBlock {
                start: VIRTUAL_EXIT,
                end: VIRTUAL_EXIT,
                instructions: vec![],
            },
        );

        // Reverse the virtual edges to get the post-dominator graph:
        // now VIRTUAL_EXIT has outgoing edges to every real exit block.
        let rev_edges: Vec<CfgEdge> = virtual_edges
            .iter()
            .map(|e| CfgEdge {
                from: e.to,
                to: e.from,
                kind: e.kind,
            })
            .collect();

        // Build the dominator tree on the reversed graph rooted at VIRTUAL_EXIT.
        let dt = DominatorTree::compute(&virtual_blocks, &rev_edges, VIRTUAL_EXIT);

        // Strip out VIRTUAL_EXIT from the result.
        let idom: HashMap<Address, Option<Address>> = dt
            .idom
            .into_iter()
            .filter(|(k, _)| *k != VIRTUAL_EXIT)
            .map(|(k, v)| {
                let parent = v.and_then(|p| if p == VIRTUAL_EXIT { None } else { Some(p) });
                (k, parent)
            })
            .collect();

        // `idom` is a HashMap, so iterating it directly (as this used to)
        // pushes each node's children in nondeterministic hash order; sort
        // so `dominated_by`-style consumers get a reproducible result (see
        // the analogous fix in `DominatorTree::compute`).
        let mut children: HashMap<Address, Vec<Address>> = HashMap::new();
        for addr in idom.keys() {
            children.entry(*addr).or_default();
        }
        for (&node, &parent_opt) in &idom {
            if let Some(parent) = parent_opt {
                children.entry(parent).or_default().push(node);
            }
        }
        for kids in children.values_mut() {
            kids.sort_by_key(|a| a.0);
        }

        Self { idom, children }
    }

    /// Returns `true` if `a` post-dominates `b` (including `a == b`).
    #[must_use]
    pub fn post_dominates(&self, a: Address, b: Address) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            match self.idom.get(&cur) {
                Some(Some(parent)) => {
                    if *parent == a {
                        return true;
                    }
                    if *parent == cur {
                        return false;
                    }
                    cur = *parent;
                }
                _ => return false,
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// NaturalLoop
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A natural loop identified by a back edge `back_edge_src â†' header`.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// The loop header —" the target of the back edge, which dominates all
    /// blocks in the loop.
    pub header: Address,
    /// The block that has the back edge to `header`.
    pub back_edge_src: Address,
    /// All blocks in the loop body, including the header.
    pub body: HashSet<Address>,
    /// Blocks *outside* the loop that are successors of loop blocks.
    pub exits: Vec<Address>,
    /// `true` when no other natural loop is strictly nested inside this one.
    pub is_innermost: bool,
}

impl NaturalLoop {
    /// Whether `addr` belongs to this loop body.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.body.contains(&addr)
    }

    /// Number of blocks in the loop body.
    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }
}

/// Find all natural loops in `cfg` using its dominator tree.
///
/// A back edge is an edge `n â†' h` where `h` dominates `n`.  For each such
/// back edge, the natural loop body is computed by a reverse BFS from `n` up
/// to (and including) `h` using predecessor edges.
#[must_use]
pub fn find_natural_loops(cfg: &ControlFlowGraph) -> Vec<NaturalLoop> {
    let mut loops: Vec<NaturalLoop> = Vec::new();

    // Precompute predecessor/successor adjacency once, in O(E).  The reverse
    // BFS below used to call `cfg.predecessors`/`cfg.successors` — each an
    // O(E) full scan of all edges — once per visited node, which made this
    // function O(back_edges * body_size * E) overall (worst case O(V * E^2)).
    // With precomputed adjacency each lookup is O(1), so the whole function
    // is O(E + back_edges * body_size).
    let mut preds_map: HashMap<Address, Vec<Address>> = HashMap::new();
    let mut succs_map: HashMap<Address, Vec<Address>> = HashMap::new();
    for e in &cfg.edges {
        preds_map.entry(e.to).or_default().push(e.from);
        succs_map.entry(e.from).or_default().push(e.to);
    }
    let no_preds: Vec<Address> = Vec::new();
    let no_succs: Vec<Address> = Vec::new();

    for edge in &cfg.edges {
        if cfg.dom_tree.dominates(edge.to, edge.from) {
            // This is a back edge: edge.from â†' edge.to where edge.to dominates
            // edge.from.
            let header = edge.to;
            let back_src = edge.from;

            // Collect loop body via reverse BFS from back_src up to header.
            let mut body: HashSet<Address> = HashSet::new();
            body.insert(header);
            let mut worklist = vec![back_src];
            while let Some(node) = worklist.pop() {
                if body.insert(node) {
                    for &pred in preds_map.get(&node).unwrap_or(&no_preds) {
                        if !body.contains(&pred) {
                            worklist.push(pred);
                        }
                    }
                }
            }

            // Exits: successors of loop blocks that are outside the loop.
            //
            // `body` is a HashSet, so this loop visits blocks in an unspecified
            // order and `exits` came out in a different order between runs on
            // the SAME input — a real nondeterminism defect, found by
            // `definitional_natural_loops.rs` and parked there as `#[ignore]`.
            // The exit set carries no ordering semantics, so sorting is the
            // minimal fix and cannot change which addresses are reported.
            let mut exits: Vec<Address> = Vec::new();
            for &b in &body {
                for &succ in succs_map.get(&b).unwrap_or(&no_succs) {
                    if !body.contains(&succ) && !exits.contains(&succ) {
                        exits.push(succ);
                    }
                }
            }
            exits.sort_unstable();

            loops.push(NaturalLoop {
                header,
                back_edge_src: back_src,
                body,
                exits,
                is_innermost: false, // patched below
            });
        }
    }

    // Mark innermost loops: a loop is innermost iff no other loop's body is a
    // strict subset of its body.
    let n = loops.len();
    for i in 0..n {
        let mut innermost = true;
        for j in 0..n {
            if i == j {
                continue;
            }
            // Loop j is strictly nested inside loop i if j.body âŠ‚ i.body.
            if loops[j].body.is_subset(&loops[i].body) && loops[j].body != loops[i].body {
                innermost = false;
                break;
            }
        }
        loops[i].is_innermost = innermost;
    }

    loops
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgStats
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Summary statistics for a control flow graph.
#[derive(Debug, Clone)]
pub struct CfgStats {
    /// Number of basic blocks (same as `block_count`).
    pub node_count: usize,
    /// Number of basic blocks.
    pub block_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub max_loop_depth: u32,
    /// `McCabe` cyclomatic complexity: E âˆ' N + 2P  (P = connected components;
    /// for a connected CFG P = 1).
    pub cyclomatic_complexity: usize,
    /// Number of entry blocks (blocks with no incoming edges).
    pub entry_blocks: usize,
    /// Number of exit blocks (blocks whose last instruction is `Ret`).
    pub exit_blocks: usize,
}

impl CfgStats {
    /// Compute statistics for a fully-built `ControlFlowGraph`.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let block_count = cfg.blocks.len();
        let edge_count = cfg.edges.len();
        let loop_count = cfg.loops.len();

        // Max loop nesting depth: for each block in the CFG count how many
        // distinct loops contain it and take the maximum.
        //
        // Computed by tallying, once per (loop, member) pair, how many loops
        // contain each address — `O(sum of loop body sizes)` — rather than
        // the previous `O(block_count * loop_count)` cross product (each
        // `NaturalLoop::contains` is an O(1) hash lookup, but was invoked for
        // every block against every loop).
        let max_loop_depth = if cfg.blocks.is_empty() || cfg.loops.is_empty() {
            0
        } else {
            let mut depth: HashMap<Address, u32> = HashMap::new();
            for lp in &cfg.loops {
                for &addr in &lp.body {
                    *depth.entry(addr).or_insert(0) += 1;
                }
            }
            depth.values().copied().max().unwrap_or(0)
        };

        // Cyclomatic complexity: E - N + 2P.
        // We treat the entire CFG as one connected component (P = 1).
        let cyclomatic_complexity = edge_count.saturating_add(2).saturating_sub(block_count);

        // Entry blocks: no predecessors.
        let mut has_incoming: HashSet<Address> = HashSet::new();
        for e in &cfg.edges {
            has_incoming.insert(e.to);
        }
        let entry_blocks = cfg
            .blocks
            .keys()
            .filter(|a| !has_incoming.contains(a))
            .count();

        // Exit blocks: last instruction is Ret.
        let exit_blocks = cfg
            .blocks
            .values()
            .filter(|bb| {
                bb.instructions
                    .last()
                    .is_some_and(|i| matches!(i, LlilInstruction::Ret))
            })
            .count();

        Self {
            node_count: block_count,
            block_count,
            edge_count,
            loop_count,
            max_loop_depth,
            cyclomatic_complexity,
            entry_blocks,
            exit_blocks,
        }
    }

    /// A function is considered "complex" when its cyclomatic complexity
    /// exceeds 10 (a common threshold from `McCabe`'s original paper).
    #[must_use]
    pub const fn is_complex(&self) -> bool {
        self.cyclomatic_complexity > 10
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgDotPrinter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Generates a Graphviz DOT representation of a `ControlFlowGraph`.
#[derive(Debug, Clone)]
pub struct CfgDotPrinter {
    /// Embed instruction mnemonics inside each node label.
    pub show_instructions: bool,
    /// Color loop-body blocks with a distinct background.
    pub highlight_loops: bool,
    /// Draw back edges with a dashed style.
    pub highlight_back_edges: bool,
}

impl Default for CfgDotPrinter {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgDotPrinter {
    /// Create a printer with sensible defaults (instructions shown, loops and
    /// back edges highlighted).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            show_instructions: true,
            highlight_loops: true,
            highlight_back_edges: true,
        }
    }

    /// Render `cfg` to a DOT string.
    #[must_use]
    pub fn print(&self, cfg: &ControlFlowGraph) -> String {
        let mut out = String::from("digraph cfg {\n");
        out.push_str("    node [shape=box fontname=\"Courier\" fontsize=10];\n");
        out.push_str("    edge [fontsize=9];\n\n");

        // Build the set of loop-body addresses for fast lookup.
        let loop_blocks: HashSet<Address> = if self.highlight_loops {
            cfg.loops
                .iter()
                .flat_map(|lp| lp.body.iter().copied())
                .collect()
        } else {
            HashSet::new()
        };

        // Emit nodes.
        let mut addrs: Vec<Address> = cfg.blocks.keys().copied().collect();
        addrs.sort_by_key(|a| a.0);
        for addr in &addrs {
            let bb = &cfg.blocks[addr];
            let mut label = format!("0x{:X}", addr.0);
            if self.show_instructions {
                for inst in &bb.instructions {
                    write!(label, "\\l  {inst:?}").unwrap();
                }
                label.push_str("\\l");
            }
            let color = if self.highlight_loops && loop_blocks.contains(addr) {
                " style=filled fillcolor=lightyellow"
            } else {
                ""
            };
            writeln!(out, "    n{:x} [label=\"{label}\"{color}];", addr.0).unwrap();
        }

        out.push('\n');

        // Emit edges.
        for edge in &cfg.edges {
            let is_back = self.highlight_back_edges && cfg.is_back_edge(edge.from, edge.to);
            let style = if is_back {
                " style=dashed color=red"
            } else {
                ""
            };
            let edge_label = match edge.kind {
                EdgeKind::TrueBranch => " label=T",
                EdgeKind::FalseBranch => " label=F",
                EdgeKind::Unconditional => " label=jmp",
                EdgeKind::Fallthrough => " label=fall",
            };
            writeln!(
                out,
                "    n{:x} -> n{:x} [{edge_label}{style}];",
                edge.from.0, edge.to.0
            )
            .unwrap();
        }

        out.push_str("}\n");
        out
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ControlFlowGraph
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A fully-analyzed control flow graph, including dominator/post-dominator
/// trees and natural loop information.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<Address, BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry: Address,
    pub dom_tree: DominatorTree,
    pub loops: Vec<NaturalLoop>,
    pub post_dom_tree: PostDominatorTree,
}

impl ControlFlowGraph {
    /// All predecessor addresses of `addr`.
    #[must_use]
    pub fn predecessors(&self, addr: Address) -> Vec<Address> {
        self.edges
            .iter()
            .filter(|e| e.to == addr)
            .map(|e| e.from)
            .collect()
    }

    /// All successor addresses of `addr`.
    #[must_use]
    pub fn successors(&self, addr: Address) -> Vec<Address> {
        self.edges
            .iter()
            .filter(|e| e.from == addr)
            .map(|e| e.to)
            .collect()
    }

    /// Returns `true` when `from â†' to` is a back edge (i.e. `to` dominates
    /// `from` in the dominator tree).
    #[must_use]
    pub fn is_back_edge(&self, from: Address, to: Address) -> bool {
        self.dom_tree.dominates(to, from)
    }

    /// Returns `true` when `a` dominates `b`.
    #[must_use]
    pub fn dominates(&self, a: Address, b: Address) -> bool {
        self.dom_tree.dominates(a, b)
    }

    /// Returns `true` when `a` post-dominates `b`.
    #[must_use]
    pub fn post_dominates(&self, a: Address, b: Address) -> bool {
        self.post_dom_tree.post_dominates(a, b)
    }

    /// Immediate dominator of `addr`, or `None` for the entry block.
    #[must_use]
    pub fn immediate_dominator(&self, addr: Address) -> Option<Address> {
        self.dom_tree.idom.get(&addr).copied().flatten()
    }

    /// Dominance frontier of `addr`.
    #[must_use]
    pub fn dominance_frontier(&self, addr: Address) -> Vec<Address> {
        self.dom_tree.dominance_frontier(addr).to_vec()
    }

    /// Nodes in reverse post-order starting from the entry.
    #[must_use]
    pub fn reverse_post_order(&self) -> Vec<Address> {
        rpo_order(&self.blocks, &self.edges, self.entry)
    }

    /// Nodes in post-order (leaves first) starting from the entry.
    #[must_use]
    pub fn post_order(&self) -> Vec<Address> {
        let mut rpo = self.reverse_post_order();
        rpo.reverse();
        rpo
    }

    /// The set of blocks reachable from `start` (BFS).
    ///
    /// Builds a successor adjacency list once (`O(E)`) rather than calling
    /// [`Self::successors`] (an `O(E)` full scan of all edges) once per
    /// visited node, which would make this `O(V * E)` on graphs with many
    /// edges.
    #[must_use]
    pub fn reachable_from(&self, start: Address) -> HashSet<Address> {
        let mut visited = HashSet::new();
        if !self.blocks.contains_key(&start) {
            return visited;
        }
        let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
        for e in &self.edges {
            succs.entry(e.from).or_default().push(e.to);
        }
        let empty: Vec<Address> = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);
        while let Some(node) = queue.pop_front() {
            for &succ in succs.get(&node).unwrap_or(&empty) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Number of basic blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of CFG edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Convert to a `petgraph` directed graph where node weights are
    /// `Address` values and edge weights are `EdgeKind` values.
    #[must_use]
    pub fn to_petgraph(&self) -> petgraph::Graph<Address, EdgeKind> {
        let mut g = petgraph::Graph::new();

        // Insert nodes in deterministic order.
        let mut addrs: Vec<Address> = self.blocks.keys().copied().collect();
        addrs.sort_by_key(|a| a.0);

        let node_map: HashMap<Address, petgraph::graph::NodeIndex> =
            addrs.iter().map(|&a| (a, g.add_node(a))).collect();

        for edge in &self.edges {
            if let (Some(&fi), Some(&ti)) = (node_map.get(&edge.from), node_map.get(&edge.to)) {
                g.add_edge(fi, ti, edge.kind);
            }
        }

        g
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Free-standing convenience API
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Find all natural loops in `cfg` given an explicit pre-computed dominator
/// tree.
///
/// Callers should prefer [`find_natural_loops`] when the CFG's own `dom_tree`
/// is up-to-date.  Use this overload only when a separately-computed
/// `DominatorTree` (e.g. after a CFG mutation) must be authoritative, to
/// avoid silent inconsistency between two different trees.
///
/// Delegates to [`find_natural_loops`] via a temporary CFG that carries the
/// supplied `dt` as its dominator tree.
#[must_use]
pub fn natural_loops(cfg: &ControlFlowGraph, dt: &DominatorTree) -> Vec<NaturalLoop> {
    let tmp = ControlFlowGraph {
        blocks: cfg.blocks.clone(),
        edges: cfg.edges.clone(),
        entry: cfg.entry,
        dom_tree: dt.clone(),
        post_dom_tree: cfg.post_dom_tree.clone(),
        loops: Vec::new(),
    };
    find_natural_loops(&tmp)
}

/// Returns all back-edges `(from, to)` in `cfg` using the provided dominator
/// tree.  An edge `from â†' to` is a back-edge iff `to` dominates `from`.
///
/// Unlike [`ReducibilityTest::find_back_edges`] (which uses DFS coloring),
/// this function uses the pre-computed dominator tree directly.
#[must_use]
pub fn find_back_edges(cfg: &ControlFlowGraph, dt: &DominatorTree) -> Vec<(Address, Address)> {
    cfg.edges
        .iter()
        .filter(|e| dt.dominates(e.to, e.from))
        .map(|e| (e.from, e.to))
        .collect()
}

/// Returns `true` when `cfg` is reducible (every back-edge target dominates
/// its source in the dominator tree).
///
/// This is a convenience wrapper around [`ReducibilityTest::test`].
#[must_use]
pub fn is_reducible(cfg: &ControlFlowGraph) -> bool {
    ReducibilityTest::test(cfg).is_reducible()
}

/// `McCabe` cyclomatic complexity of `cfg`: `E âˆ' N + 2 Ã— connected_components`.
///
/// For a single-entry connected CFG the formula reduces to `E âˆ' N + 2`.
/// Returns `u32`; saturates at [`u32::MAX`] for pathologically large CFGs.
#[must_use]
pub fn cyclomatic_complexity(cfg: &ControlFlowGraph) -> u32 {
    // Count connected components via BFS from entry; all unreachable blocks
    // form additional trivial components.
    let reachable = cfg.reachable_from(cfg.entry);
    let total = cfg.blocks.len();
    let unreachable_components = total.saturating_sub(reachable.len());
    // P = 1 (for the reachable component) + number of unreachable singletons
    let p = 1usize + unreachable_components;
    let e = cfg.edges.len();
    let n = total;
    // E - N + 2P, saturating to u32
    let two_p = p.saturating_mul(2);
    let raw = e.saturating_add(two_p).saturating_sub(n);
    raw.min(u32::MAX as usize) as u32
}

/// Render `cfg` to a Graphviz DOT string using default printer settings
/// (instructions shown, loops highlighted, back-edges dashed in red).
///
/// This is a convenience wrapper around [`CfgDotPrinter::new().print(cfg)`].
#[must_use]
pub fn cfg_to_dot(cfg: &ControlFlowGraph) -> String {
    CfgDotPrinter::new().print(cfg)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// analyze_cfg  (public entry-point)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Build and fully analyse a `ControlFlowGraph` from a flat list of
/// `(address, instruction)` pairs.
///
/// The list must be sorted by address and cover exactly one function.
#[must_use]
pub fn analyze_cfg(instrs: &[(Address, LlilInstruction)]) -> ControlFlowGraph {
    // â"€â"€ 1. Identify basic-block leaders â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let mut leaders: HashSet<Address> = HashSet::new();
    if !instrs.is_empty() {
        leaders.insert(instrs[0].0);
    }

    for i in 0..instrs.len() {
        let (_, ref inst) = instrs[i];
        match inst {
            // `Jump(dest)` (tuple form emitted by `llil_builder`) and
            // `JumpDest { dest }` (struct form) are the same unconditional-
            // jump terminator; every other consumer in the workspace matches
            // both together. Missing `Jump` here used to fall through to the
            // `_ => {}` arm, silently failing to split the block after it.
            LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
                // Only insert a statically-known target address.
                if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                    leaders.insert(Address::new(*value));
                }
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].0);
                }
            }
            LlilInstruction::CondJump {
                true_dest,
                false_dest,
                ..
            } => {
                leaders.insert(*true_dest);
                leaders.insert(*false_dest);
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].0);
                }
            }
            LlilInstruction::JumpTo { targets, .. } => {
                for &t in targets {
                    leaders.insert(t);
                }
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].0);
                }
            }
            // `TailCall` is a terminator just like `Ret` (see
            // `edges::compute_leaders` / `tail_call.rs`); the instruction after
            // it starts a new basic block.
            LlilInstruction::Ret | LlilInstruction::TailCall { .. }
                if i + 1 < instrs.len() => {
                    leaders.insert(instrs[i + 1].0);
                }
            _ => {}
        }
    }

    let mut leader_list: Vec<Address> = leaders.into_iter().collect();
    leader_list.sort_by_key(|a| a.0);

    // â"€â"€ 2. Build basic blocks â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let mut blocks: HashMap<Address, BasicBlock> = HashMap::new();

    for i in 0..leader_list.len() {
        let start_addr = leader_list[i];
        let end_limit = leader_list.get(i + 1).copied();

        let mut block_instrs = Vec::new();
        let mut end_addr = start_addr;

        for &(addr, ref inst) in instrs {
            if addr >= start_addr && end_limit.is_none_or(|lim| addr < lim) {
                block_instrs.push(inst.clone());
                end_addr = addr;
            }
        }

        if !block_instrs.is_empty() {
            blocks.insert(
                start_addr,
                BasicBlock {
                    start: start_addr,
                    end: end_addr,
                    instructions: block_instrs,
                },
            );
        }
    }

    // â"€â"€ 3. Build CFG edges â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let mut edges: Vec<CfgEdge> = Vec::new();

    for i in 0..leader_list.len() {
        let start_addr = leader_list[i];
        if let Some(block) = blocks.get(&start_addr)
            && let Some(last_inst) = block.instructions.last()
        {
            match last_inst {
                LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => {
                    if let rustre_il_llil::LlilExpr::Const { value, .. } = dest {
                        edges.push(CfgEdge {
                            from: start_addr,
                            to: Address::new(*value),
                            kind: EdgeKind::Unconditional,
                        });
                    }
                    // Computed (non-const) jump: no edge added; analysis
                    // must be supplemented with indirect-target resolution.
                }
                LlilInstruction::CondJump {
                    true_dest,
                    false_dest,
                    ..
                } => {
                    edges.push(CfgEdge {
                        from: start_addr,
                        to: *true_dest,
                        kind: EdgeKind::TrueBranch,
                    });
                    edges.push(CfgEdge {
                        from: start_addr,
                        to: *false_dest,
                        kind: EdgeKind::FalseBranch,
                    });
                }
                LlilInstruction::Ret => {
                    // No outgoing edges for returns.
                }
                LlilInstruction::JumpTo { targets, .. } => {
                    for &t in targets {
                        edges.push(CfgEdge {
                            from: start_addr,
                            to: t,
                            kind: EdgeKind::Unconditional,
                        });
                    }
                }
                _ => {
                    if i + 1 < leader_list.len() {
                        edges.push(CfgEdge {
                            from: start_addr,
                            to: leader_list[i + 1],
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }
        }
    }

    // â"€â"€ 4. Determine entry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let entry = leader_list.first().copied().unwrap_or(Address::new(0));

    // â"€â"€ 5. Compute dominator tree â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let dom_tree = DominatorTree::compute(&blocks, &edges, entry);

    // â"€â"€ 6. Compute post-dominator tree â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);

    // â"€â"€ 7. Find natural loops (needs dom_tree) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    // We construct a temporary CFG (without loops/dom fields) to pass to the
    // helper, then attach the result.
    let mut cfg = ControlFlowGraph {
        blocks,
        edges,
        entry,
        dom_tree,
        post_dom_tree,
        loops: Vec::new(),
    };
    cfg.loops = find_natural_loops(&cfg);

    cfg
}

/// Like [`analyze_cfg`] but returns a typed [`anyhow::Result`] instead of
/// panicking on degenerate inputs.
///
/// Returns `Err` when `instrs` is empty (no blocks can be produced) or when
/// the derived entry address is not present in the resulting block map.
pub fn try_analyze_cfg(
    instrs: &[(Address, LlilInstruction)],
) -> anyhow::Result<ControlFlowGraph> {
    if instrs.is_empty() {
        anyhow::bail!(CfgError::EmptyCfg);
    }
    let cfg = analyze_cfg(instrs);
    if cfg.blocks.is_empty() {
        anyhow::bail!(CfgError::EmptyCfg);
    }
    if !cfg.blocks.contains_key(&cfg.entry) {
        anyhow::bail!(CfgError::InvalidEntry(cfg.entry));
    }
    Ok(cfg)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Internal helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Compute reverse post-order (RPO) of the nodes reachable from `entry` using
/// a depth-first search.
fn rpo_order(
    blocks: &HashMap<Address, BasicBlock>,
    edges: &[CfgEdge],
    entry: Address,
) -> Vec<Address> {
    if !blocks.contains_key(&entry) {
        return Vec::new();
    }

    // Build successor list.
    let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
    for b in blocks.keys() {
        succs.entry(*b).or_default();
    }
    for e in edges {
        if blocks.contains_key(&e.from) && blocks.contains_key(&e.to) {
            succs.entry(e.from).or_default().push(e.to);
        }
    }

    let mut visited: HashSet<Address> = HashSet::new();
    let mut post_order: Vec<Address> = Vec::new();

    // Iterative DFS to avoid stack overflow on large CFGs.
    // Each stack entry is (node, iterator-index into successors).
    let mut stack: Vec<(Address, usize)> = vec![(entry, 0)];
    visited.insert(entry);

    while let Some((node, idx)) = stack.last_mut() {
        let node = *node;
        let children = succs.get(&node).map_or(&[][..], Vec::as_slice);
        if *idx < children.len() {
            let child = children[*idx];
            *idx += 1;
            if visited.insert(child) {
                stack.push((child, 0));
            }
        } else {
            stack.pop();
            post_order.push(node);
        }
    }

    post_order.reverse();
    post_order
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ReducibilityTest  —" identifies irreducible CFGs (Tarjan 1973)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The result of a CFG reducibility test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReducibilityResult {
    /// The CFG is reducible: all loops have a single entry point.
    Reducible,
    /// The CFG is irreducible: at least one loop lacks a single entry.
    Irreducible {
        /// Pairs of back edges that form the irreducible structure.
        back_edges: Vec<(Address, Address)>,
    },
}

impl ReducibilityResult {
    /// Return `true` if the CFG is reducible.
    #[must_use]
    pub const fn is_reducible(&self) -> bool {
        matches!(self, Self::Reducible)
    }
}

/// Tests whether a CFG is reducible.
pub struct ReducibilityTest;

impl ReducibilityTest {
    /// Run the Havlak reducibility test on `cfg`.
    ///
    /// A CFG is reducible if and only if it has no irreducible back-edges —"
    /// i.e., every back-edge `(v, h)` in the DFS tree has `h` dominating `v`.
    #[must_use]
    pub fn test(cfg: &ControlFlowGraph) -> ReducibilityResult {
        if cfg.blocks.is_empty() {
            return ReducibilityResult::Reducible;
        }

        let entry = cfg.entry;
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, entry);
        let back_edges = Self::find_back_edges(cfg);

        let irreducible: Vec<(Address, Address)> = back_edges
            .into_iter()
            .filter(|(from, to)| {
                // A back-edge (fromâ†'to) is reducible iff `to` dominates `from`.
                !dom.dominates(*to, *from)
            })
            .collect();

        if irreducible.is_empty() {
            ReducibilityResult::Reducible
        } else {
            ReducibilityResult::Irreducible {
                back_edges: irreducible,
            }
        }
    }

    /// Collect all back edges via DFS.
    fn find_back_edges(cfg: &ControlFlowGraph) -> Vec<(Address, Address)> {
        let entry = cfg.entry;
        let mut visited = HashSet::new();
        let mut on_stack = HashSet::new();
        let mut back = Vec::new();

        // Build adjacency.
        let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
        for edge in &cfg.edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        Self::dfs(entry, &adj, &mut visited, &mut on_stack, &mut back);
        back
    }

    fn dfs(
        entry: Address,
        adj: &HashMap<Address, Vec<Address>>,
        visited: &mut HashSet<Address>,
        on_stack: &mut HashSet<Address>,
        back: &mut Vec<(Address, Address)>,
    ) {
        // Iterative DFS using an explicit stack to avoid stack overflow on deep CFGs.
        // Each entry: (node, index_into_successors).
        let mut work_stack: Vec<(Address, usize)> = vec![(entry, 0)];
        visited.insert(entry);
        on_stack.insert(entry);

        while let Some((node, idx)) = work_stack.last_mut() {
            let node = *node;
            let succs = adj.get(&node).map_or(&[][..], Vec::as_slice);
            if *idx < succs.len() {
                let succ = succs[*idx];
                *idx += 1;
                if on_stack.contains(&succ) {
                    back.push((node, succ));
                } else if visited.insert(succ) {
                    on_stack.insert(succ);
                    work_stack.push((succ, 0));
                }
            } else {
                work_stack.pop();
                on_stack.remove(&node);
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// DominanceFrontier  —" SSA-construction helper
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Dominance frontiers for every node in a CFG (Cytron et al. 1991).
///
/// The dominance frontier of node `n`, DF(n), is the set of nodes `y` such
/// that `n` dominates a predecessor of `y` but does not strictly dominate `y`.
/// These are exactly the nodes at which phi-functions must be placed for SSA.
#[derive(Debug, Clone, Default)]
pub struct DominanceFrontier {
    /// DF(n) for each node n.
    pub df: HashMap<Address, Vec<Address>>,
}

impl DominanceFrontier {
    /// Compute the dominance frontier from the dominator tree.
    ///
    /// Delegates to the authoritative frontier computation already stored in
    /// `dom.frontiers` (computed by [`DominatorTree::compute`]) so that both
    /// `DominanceFrontier` and `DominatorTree::dominance_frontier` always
    /// return consistent answers for the same node.
    ///
    /// The `edges` parameter is accepted for API compatibility but is not used;
    /// the dominator tree already encodes all necessary edge information.
    #[must_use]
    pub fn compute(dom: &DominatorTree, _edges: &[CfgEdge]) -> Self {
        // Clone the authoritative frontiers from the dominator tree so that
        // DominanceFrontier::frontier_of and DominatorTree::dominance_frontier
        // always agree on the same node.
        let df = dom.frontiers.clone();
        Self { df }
    }

    /// Return the dominance frontier of `node`.
    #[must_use]
    pub fn frontier_of(&self, node: Address) -> &[Address] {
        self.df.get(&node).map_or(&[], Vec::as_slice)
    }

    /// Compute the iterated dominance frontier (IDF) of a set of nodes.
    ///
    /// Used during SSA Ï†-node placement: IDF(S) = DF+(S).
    #[must_use]
    pub fn iterated_frontier(&self, seeds: &[Address]) -> Vec<Address> {
        let mut result: HashSet<Address> = HashSet::new();
        let mut worklist: Vec<Address> = seeds.to_vec();
        while let Some(n) = worklist.pop() {
            for &f in self.frontier_of(n) {
                if result.insert(f) {
                    worklist.push(f);
                }
            }
        }
        let mut v: Vec<Address> = result.into_iter().collect();
        v.sort_unstable_by_key(|a| a.0);
        v
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgMetrics  —" extended per-function metrics
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extended CFG-level metrics for a single function.
#[derive(Debug, Clone)]
pub struct CfgMetrics {
    /// Cyclomatic complexity (McCabe): E - N + 2P.
    pub cyclomatic_complexity: usize,
    /// Number of back edges (loop headers).
    pub back_edge_count: usize,
    /// Maximum nesting depth of loops.
    pub max_loop_depth: usize,
    /// Number of blocks with more than one predecessor (join points).
    pub join_count: usize,
    /// Number of blocks with more than one successor (branch points).
    pub branch_count: usize,
    /// Whether the CFG is reducible.
    pub is_reducible: bool,
    /// Number of nodes reachable from the entry block.
    pub reachable_count: usize,
    /// Number of edges.
    pub edge_count: usize,
}

impl CfgMetrics {
    /// Compute all metrics for `cfg`.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let n = cfg.blocks.len();
        let e = cfg.edges.len();
        let p = 1; // single connected component
        let cyclomatic_complexity = e.saturating_sub(n).saturating_add(2 * p);

        // Predecessor and successor counts per block
        let mut pred_count: HashMap<Address, usize> = HashMap::new();
        let mut succ_count: HashMap<Address, usize> = HashMap::new();
        for edge in &cfg.edges {
            *succ_count.entry(edge.from).or_default() += 1;
            *pred_count.entry(edge.to).or_default() += 1;
        }
        let join_count = pred_count.values().filter(|&&c| c > 1).count();
        let branch_count = succ_count.values().filter(|&&c| c > 1).count();

        // Back edge count
        let back_edges = ReducibilityTest::find_back_edges(cfg);
        let back_edge_count = back_edges.len();

        // Reducibility
        let is_reducible = ReducibilityTest::test(cfg).is_reducible();

        // Reachable count (BFS from entry).  Delegates to
        // `ControlFlowGraph::reachable_from`, which precomputes adjacency
        // once (`O(V + E)`) instead of rescanning all edges per visited node
        // (the previous inline BFS here was `O(V * E)`).
        let reachable_count = cfg.reachable_from(cfg.entry).len();

        // Max loop depth via SCC nesting (simplified: use loop count from natural loops)
        let loops = find_natural_loops(cfg);
        let max_loop_depth = compute_max_loop_depth(&loops);

        Self {
            cyclomatic_complexity,
            back_edge_count,
            max_loop_depth,
            join_count,
            branch_count,
            is_reducible,
            reachable_count,
            edge_count: e,
        }
    }
}

/// Compute the maximum nesting depth of natural loops.
///
/// Tallies loop membership counts in a single pass over all loop bodies
/// (`O(sum of loop body sizes)`) instead of, for every block visited, scanning
/// every loop's body again (the previous `.filter(|l| l.body.contains(..))`
/// per block made this `O(loop_count * sum of loop body sizes)`).
fn compute_max_loop_depth(loops: &[NaturalLoop]) -> usize {
    if loops.is_empty() {
        return 0;
    }
    let mut depth: HashMap<Address, usize> = HashMap::new();
    for lp in loops {
        for &addr in &lp.body {
            *depth.entry(addr).or_insert(0) += 1;
        }
    }
    depth.values().copied().max().unwrap_or(0)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgScc  —" strongly-connected components (Tarjan's SCC)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// One strongly-connected component of the CFG.
#[derive(Debug, Clone)]
pub struct SccComponent {
    /// The block addresses in this SCC.
    pub nodes: Vec<Address>,
    /// Whether this SCC contains more than one node or a self-loop (i.e. it is
    /// a loop in the CFG).
    pub is_loop: bool,
}

/// Strongly-connected component decomposition of a CFG (Tarjan 1972).
#[derive(Debug, Clone)]
pub struct CfgScc {
    /// SCCs in reverse topological order (post-order of condensation DAG).
    pub components: Vec<SccComponent>,
}

impl CfgScc {
    /// Compute SCCs for `cfg` using Tarjan's algorithm.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut index_counter = 0u32;
        let mut stack: Vec<Address> = Vec::new();
        let mut on_stack: HashSet<Address> = HashSet::new();
        let mut index: HashMap<Address, u32> = HashMap::new();
        let mut lowlink: HashMap<Address, u32> = HashMap::new();
        let mut components: Vec<SccComponent> = Vec::new();

        // Build adjacency.
        let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
        for edge in &cfg.edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        // `cfg.blocks` is a HashMap, so iterating it directly (as this used
        // to) picks DFS roots in nondeterministic hash order — the exact
        // same bug class as the `dfs_back_edges` root-pick fix in
        // `loop_analysis.rs`. That leaks straight into the public
        // `components` order (and the node order within each component),
        // so callers see a different SCC decomposition on every run. Sort
        // root candidates by address for a reproducible traversal.
        let mut roots: Vec<Address> = cfg.blocks.keys().copied().collect();
        roots.sort_by_key(|a| a.0);
        for node in roots {
            if !index.contains_key(&node) {
                tarjan_scc(
                    node,
                    &adj,
                    &mut index_counter,
                    &mut stack,
                    &mut on_stack,
                    &mut index,
                    &mut lowlink,
                    &mut components,
                );
            }
        }

        Self { components }
    }

    /// Return all SCCs that are loops (non-trivial SCCs).
    #[must_use]
    pub fn loops(&self) -> Vec<&SccComponent> {
        self.components.iter().filter(|c| c.is_loop).collect()
    }

    /// Return the number of SCCs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.components.len()
    }

    /// Return `true` if there are no SCCs.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
}

/// Iterative Tarjan SCC helper — avoids stack overflow on deep CFGs.
///
/// Implements Tarjan's SCC algorithm iteratively using an explicit work stack.
/// Each work-stack frame tracks the node and the current successor index so
/// that the algorithm can resume after "returning" from a recursive call.
fn tarjan_scc(
    root: Address,
    adj: &HashMap<Address, Vec<Address>>,
    counter: &mut u32,
    stack: &mut Vec<Address>,
    on_stack: &mut HashSet<Address>,
    index: &mut HashMap<Address, u32>,
    lowlink: &mut HashMap<Address, u32>,
    components: &mut Vec<SccComponent>,
) {
    // Work stack: (node, successor_index)
    // We push a frame when we first visit a node and advance the index as we
    // iterate over its successors, popping when all successors are done.
    let mut work: Vec<(Address, usize)> = Vec::new();

    // Initialise the root node.
    let root_idx = *counter;
    *counter += 1;
    index.insert(root, root_idx);
    lowlink.insert(root, root_idx);
    stack.push(root);
    on_stack.insert(root);
    work.push((root, 0));

    while let Some((v, succ_idx)) = work.last_mut() {
        let v = *v;
        let succs = adj.get(&v).map_or(&[][..], Vec::as_slice);

        if *succ_idx < succs.len() {
            let w = succs[*succ_idx];
            *succ_idx += 1;

            if let std::collections::hash_map::Entry::Vacant(e) = index.entry(w) {
                // Tree edge: visit w.
                let w_idx = *counter;
                *counter += 1;
                e.insert(w_idx);
                lowlink.insert(w, w_idx);
                stack.push(w);
                on_stack.insert(w);
                work.push((w, 0));
            } else if on_stack.contains(&w) {
                // Back/cross edge to a node on the SCC stack.
                let idx_w = *index.get(&w).unwrap_or(&u32::MAX);
                let ll_v = lowlink.get_mut(&v).unwrap();
                *ll_v = (*ll_v).min(idx_w);
            }
            // else: w is already fully processed (not on_stack) — ignore.
        } else {
            // All successors of v processed — pop v.
            work.pop();

            // Propagate lowlink to parent (if any).
            if let Some(&(parent, _)) = work.last() {
                let ll_v = *lowlink.get(&v).unwrap_or(&u32::MAX);
                let ll_p = lowlink.get_mut(&parent).unwrap();
                *ll_p = (*ll_p).min(ll_v);
            }

            // Check if v is an SCC root.
            if lowlink.get(&v) == index.get(&v) {
                let mut scc_nodes = Vec::new();
                loop {
                    let w = stack.pop().expect("stack invariant: SCC root must be on stack");
                    on_stack.remove(&w);
                    scc_nodes.push(w);
                    if w == v {
                        break;
                    }
                }
                let self_loop = adj.get(&v).is_some_and(|s| s.contains(&v));
                let is_loop = scc_nodes.len() > 1 || self_loop;
                components.push(SccComponent {
                    nodes: scc_nodes,
                    is_loop,
                });
            }
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgSerializer  —" JSON and compact text serialisation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Serialise a CFG to a compact JSON representation suitable for tooling.
///
/// The output is a JSON object with `entry`, `blocks`, and `edges` arrays.
#[must_use]
pub fn cfg_to_full_json(cfg: &ControlFlowGraph) -> String {
    let mut out = String::new();
    out.push_str("{\n  \"entry\": ");
    let _ = write!(out, "{}", cfg.entry.0);
    out.push_str(",\n  \"blocks\": [\n");

    let mut blocks: Vec<&Address> = cfg.blocks.keys().collect();
    blocks.sort_unstable();
    for (i, addr) in blocks.iter().enumerate() {
        let bb = &cfg.blocks[*addr];
        let _ = write!(
            out,
            "    {{\"addr\": {}, \"end\": {}, \"instr_count\": {}}}",
            addr.0,
            bb.end.0,
            bb.instructions.len()
        );
        if i + 1 < cfg.blocks.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("  ],\n  \"edges\": [\n");
    for (i, edge) in cfg.edges.iter().enumerate() {
        let kind_str = match edge.kind {
            EdgeKind::Unconditional => "unconditional",
            EdgeKind::TrueBranch => "true",
            EdgeKind::FalseBranch => "false",
            EdgeKind::Fallthrough => "fallthrough",
        };
        let _ = write!(
            out,
            "    {{\"from\": {}, \"to\": {}, \"kind\": \"{}\"}}",
            edge.from.0, edge.to.0, kind_str
        );
        if i + 1 < cfg.edges.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}");
    out
}

/// Generate an enhanced Graphviz DOT representation with dominator information.
#[must_use]
pub fn cfg_to_dot_annotated(cfg: &ControlFlowGraph, dom: &DominatorTree) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "digraph cfg {{");
    let _ = writeln!(out, "  node [shape=box fontname=\"Courier\"];");

    // Blocks
    let mut blocks: Vec<&Address> = cfg.blocks.keys().collect();
    blocks.sort_unstable();
    for addr in &blocks {
        let bb = &cfg.blocks[*addr];
        let idom_label = dom
            .idom
            .get(*addr)
            .copied()
            .flatten()
            .map_or("entry".to_string(), |d| format!("0x{:x}", d.0));
        let _ = writeln!(
            out,
            "  n{:x} [label=\"0x{:x}\\ninstrs={} idom={}\"];",
            addr.0,
            addr.0,
            bb.instructions.len(),
            idom_label
        );
    }

    // Edges
    for edge in &cfg.edges {
        let color = match edge.kind {
            EdgeKind::TrueBranch => "green",
            EdgeKind::FalseBranch => "red",
            EdgeKind::Unconditional | EdgeKind::Fallthrough => "black",
        };
        let _ = writeln!(
            out,
            "  n{:x} -> n{:x} [color={color}];",
            edge.from.0, edge.to.0
        );
    }
    let _ = writeln!(out, "}}");
    out
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// CfgAnalysisPass —" AnalysisPass implementation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An [`rustre_analysis::AnalysisPass`] that builds a [`ControlFlowGraph`] for
/// every known function in a [`BinaryView`] using [`analyze_cfg`].
///
/// Because function-level LLIL is not yet lifted by the pass itself, it
/// constructs a minimal single-block CFG from each function's address range
/// as a lightweight structural placeholder.  The results are stored in
/// [`CfgAnalysisPass::cfgs`] after [`run`](rustre_analysis::AnalysisPass::run)
/// completes.
pub struct CfgAnalysisPass {
    /// CFGs indexed by function entry address.
    cfgs: parking_lot::Mutex<HashMap<Address, ControlFlowGraph>>,
}

impl CfgAnalysisPass {
    /// Create a new, empty `CfgAnalysisPass`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfgs: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Access the CFGs built by the last [`run`] call.
    pub fn cfgs(&self) -> parking_lot::MutexGuard<'_, HashMap<Address, ControlFlowGraph>> {
        self.cfgs.lock()
    }
}

impl Default for CfgAnalysisPass {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CfgAnalysisPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CfgAnalysisPass")
            .field("cfg_count", &self.cfgs.lock().len())
            .finish_non_exhaustive()
    }
}

/// Build a stub `ControlFlowGraph` for a function whose LLIL has not been
/// lifted yet.  Creates a single basic block spanning the entire function
/// body (empty instruction list) so that structural information (entry, dom
/// tree) is still well-formed.
fn stub_cfg_for_function(start: Address, end: Address) -> ControlFlowGraph {
    let instrs: Vec<(Address, rustre_il_llil::LlilInstruction)> = vec![
        (start, rustre_il_llil::LlilInstruction::Nop),
        (end, rustre_il_llil::LlilInstruction::Ret),
    ];
    analyze_cfg(&instrs)
}

#[async_trait::async_trait]
impl rustre_analysis::AnalysisPass for CfgAnalysisPass {
    fn name(&self) -> &'static str {
        "cfg_analysis"
    }

    fn kind(&self) -> rustre_analysis::AnalysisKind {
        rustre_analysis::AnalysisKind::DataFlow
    }

    fn description(&self) -> &'static str {
        "Builds a control flow graph for every known function in the binary"
    }

    fn priority(&self) -> i32 {
        5
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &rustre_analysis::AnalysisConfig,
    ) -> Result<rustre_analysis::AnalysisResult, rustre_analysis::AnalysisError> {
        let start_time = std::time::Instant::now();
        let mut new_cfgs: HashMap<Address, ControlFlowGraph> = HashMap::new();
        let mut functions_found = 0usize;

        {
            let func_table = view.functions.read();
            for func in func_table.iter_functions() {
                let start = func.address;
                // Use end address if known; fall back to start + 1 so the stub
                // CFG is well-formed with at least one block.
                let end = func.end_address.unwrap_or_else(|| start + 1u64);
                let cfg = stub_cfg_for_function(start, end);
                new_cfgs.insert(start, cfg);
                functions_found += 1;
            }
        }

        // Also create stub CFGs for the binary's declared entry points if they
        // are not already covered by the function table.
        for &ep in &view.entry_points {
            if let std::collections::hash_map::Entry::Vacant(e) = new_cfgs.entry(ep) {
                let cfg = stub_cfg_for_function(ep, ep + 1u64);
                e.insert(cfg);
                functions_found += 1;
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;
        *self.cfgs.lock() = new_cfgs;

        Ok(rustre_analysis::AnalysisResult {
            kind: rustre_analysis::AnalysisKind::DataFlow,
            functions_found,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms,
            warnings: Vec::new(),
        })
    }
}

// ── BasicBlockRec / BlockKind / basic_blocks ──────────────────────────────

/// The semantic role of a basic block in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BlockKind {
    /// The function entry block (no predecessors).
    Entry,
    /// A block that terminates the function (no successors).
    Exit,
    /// A straight-line block with at most one successor.
    Normal,
    /// A block with two or more successors (conditional branch).
    Branch,
    /// Header of a natural loop (target of a back edge).
    LoopHeader,
}

/// A serialisable record describing one basic block and its CFG neighbourhood.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BasicBlockRec {
    /// Stable numeric identifier assigned in RPO order (entry = 0).
    pub id: u32,
    /// Address of the first instruction in this block.
    pub start_addr: u64,
    /// Address of the last instruction in this block.
    pub end_addr: u64,
    /// Byte span from `start_addr` to `end_addr`.
    pub size: u64,
    /// Semantic role of this block.
    pub kind: BlockKind,
    /// `id` values of CFG successors.
    pub successors: Vec<u32>,
    /// `id` values of CFG predecessors.
    pub predecessors: Vec<u32>,
}

/// Build a `Vec<BasicBlockRec>` for the function whose decoded instruction
/// stream is `instrs` and whose entry is `addr`.
///
/// Delegates to [`basic_blocks_for_instrs`], which is this module's
/// implementation and assigns block ids in reverse-post-order.
///
/// Note there is a second, similarly-named `basic_blocks` in
/// [`basic_block_rec`]. The two are NOT interchangeable and are deliberately
/// both kept: this one is reverse-post-order, that one is ascending
/// start-address order, and each has callers relying on its own ordering.
/// The `BasicBlockRec` / `BlockKind` types are duplicated between the two as
/// well (field-for-field identical); unifying them would first require
/// picking one ordering contract, which is a behaviour change, not a cleanup.
///
/// # History — this function used to fabricate its answer
///
/// It was previously `pub const fn basic_blocks(addr: u64) -> Vec<BasicBlockRec>`
/// and **always returned an empty `Vec`**, described as "the spec-mandated
/// single-argument entry point". An empty result is not "I don't know": it is
/// a well-formed answer meaning *this function has no basic blocks*, so every
/// caller was told something false with no way to detect it — the same
/// silent-wrongness class this workspace has been clearing elsewhere.
///
/// It could not have been implemented as specified: this crate deliberately
/// owns no disassembler, so an address alone is not enough to recover blocks.
/// Callers that only hold bytes must decode first (the MCP
/// `analysis_basic_blocks_path` wrapper does exactly that) and then call this.
#[must_use]
pub fn basic_blocks(addr: Address, instrs: &[(Address, LlilInstruction)]) -> Vec<BasicBlockRec> {
    basic_blocks_for_instrs(addr.0, instrs)
}

/// Build a `Vec<BasicBlockRec>` from a pre-decoded `(address, instruction)`
/// stream for one function whose entry is `entry`.
///
/// Internally calls [`analyze_cfg`] to produce the full CFG (dominator tree +
/// natural loops), then projects each block into a flat [`BasicBlockRec`].
/// Blocks are returned in reverse-post-order; the entry block has id = 0.
#[must_use]
pub fn basic_blocks_for_instrs(
    entry: u64,
    instrs: &[(Address, LlilInstruction)],
) -> Vec<BasicBlockRec> {
    let _ = entry;

    if instrs.is_empty() {
        return Vec::new();
    }

    let cfg = analyze_cfg(instrs);
    let rpo = cfg.reverse_post_order();

    let id_of: HashMap<Address, u32> = rpo
        .iter()
        .enumerate()
        .map(|(i, &a)| (a, i as u32))
        .collect();

    let loop_headers: HashSet<Address> = cfg.loops.iter().map(|lp| lp.header).collect();

    let mut has_pred: HashSet<Address> = HashSet::new();
    let mut has_succ: HashSet<Address> = HashSet::new();
    // Precompute successor/predecessor adjacency once (O(E)) rather than
    // calling `cfg.successors`/`cfg.predecessors` — each an O(E) scan of all
    // edges — once per block in the loop below, which made this function
    // O(V * E) on large functions.
    let mut succ_adj: HashMap<Address, Vec<Address>> = HashMap::new();
    let mut pred_adj: HashMap<Address, Vec<Address>> = HashMap::new();
    for e in &cfg.edges {
        has_pred.insert(e.to);
        has_succ.insert(e.from);
        succ_adj.entry(e.from).or_default().push(e.to);
        pred_adj.entry(e.to).or_default().push(e.from);
    }
    let no_addrs: Vec<Address> = Vec::new();

    let mut records: Vec<BasicBlockRec> = Vec::with_capacity(rpo.len());

    for block_addr in &rpo {
        let block_addr = *block_addr;
        let id = id_of[&block_addr];

        let bb = match cfg.blocks.get(&block_addr) {
            Some(b) => b,
            None => continue,
        };

        let mut succs: Vec<u32> = succ_adj
            .get(&block_addr)
            .unwrap_or(&no_addrs)
            .iter()
            .filter_map(|s| id_of.get(s).copied())
            .collect();
        succs.sort_unstable();

        let mut preds: Vec<u32> = pred_adj
            .get(&block_addr)
            .unwrap_or(&no_addrs)
            .iter()
            .filter_map(|p| id_of.get(p).copied())
            .collect();
        preds.sort_unstable();

        // Per spec ordering: Entry > Exit > Branch (≥2 succs) > LoopHeader > Normal.
        // We follow the user-supplied semantics literally: Entry = no preds,
        // Exit = no succs, Branch = ≥2 successors, LoopHeader = back-edge
        // from a descendant, otherwise Normal.
        let kind = if !has_pred.contains(&block_addr) {
            BlockKind::Entry
        } else if !has_succ.contains(&block_addr) {
            BlockKind::Exit
        } else if succs.len() >= 2 {
            BlockKind::Branch
        } else if loop_headers.contains(&block_addr) {
            BlockKind::LoopHeader
        } else {
            BlockKind::Normal
        };

        let size = if bb.end.0 >= bb.start.0 {
            (bb.end.0 - bb.start.0).max(1)
        } else {
            1
        };

        records.push(BasicBlockRec {
            id,
            start_addr: bb.start.0,
            end_addr: bb.end.0,
            size,
            kind,
            successors: succs,
            predecessors: preds,
        });
    }

    records
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_il_llil::{LlilExpr, Size};

    // â"€â"€ helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn const_expr(v: u64) -> LlilExpr {
        LlilExpr::Const {
            value: v,
            size: Size::QWord,
        }
    }

    /// `basic_blocks` must return the SAME blocks as the implementation it
    /// delegates to — it must not answer on its own.
    ///
    /// Until 2026-07-28 this function was `pub const fn basic_blocks(addr: u64)`
    /// and always returned an empty `Vec`, so it reported "this function has
    /// no basic blocks" for every input. An empty result is a well-formed
    /// answer, not an absence of one, so no caller could tell it apart from a
    /// genuine result — this test fails against that old body.
    #[test]
    fn basic_blocks_delegates_and_does_not_fabricate() {
        // Entry -> conditional -> two arms joining at a return: three blocks
        // at minimum, so an empty answer is unambiguously wrong.
        let instrs: Vec<(Address, LlilInstruction)> = vec![
            (a(0x1000), LlilInstruction::CondJump {
                cond: const_expr(1),
                true_dest: a(0x1010),
                false_dest: a(0x1020),
            }),
            (a(0x1010), LlilInstruction::Jump(const_expr(0x1030))),
            (a(0x1020), LlilInstruction::Jump(const_expr(0x1030))),
            (a(0x1030), LlilInstruction::Ret),
        ];

        let via_entry_point = basic_blocks(a(0x1000), &instrs);
        let via_impl = basic_blocks_for_instrs(0x1000, &instrs);

        assert!(
            !via_entry_point.is_empty(),
            "basic_blocks returned no blocks for a function that plainly has some"
        );
        assert_eq!(
            via_entry_point, via_impl,
            "basic_blocks must delegate, not compute its own answer"
        );
    }

    /// Build a bare CFG (no dom/loop info) from an explicit edge list plus a
    /// set of block addresses.  Useful for unit-testing sub-algorithms.
    fn make_cfg_raw(block_addrs: &[u64], raw_edges: &[(u64, u64)], entry: u64) -> ControlFlowGraph {
        let blocks: HashMap<Address, BasicBlock> = block_addrs
            .iter()
            .map(|&n| {
                let addr = a(n);
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: vec![],
                    },
                )
            })
            .collect();

        let edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();

        let entry_addr = a(entry);
        let dom_tree = DominatorTree::compute(&blocks, &edges, entry_addr);
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);

        let mut cfg = ControlFlowGraph {
            blocks,
            edges,
            entry: entry_addr,
            dom_tree,
            post_dom_tree,
            loops: Vec::new(),
        };
        cfg.loops = find_natural_loops(&cfg);
        cfg
    }

    // â"€â"€ 1. Basic block splitting â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_basic_block_split() {
        let instrs = vec![
            (a(0x1000), LlilInstruction::Nop),
            (
                a(0x1004),
                LlilInstruction::CondJump {
                    cond: const_expr(1),
                    true_dest: a(0x1010),
                    false_dest: a(0x1008),
                },
            ),
            (a(0x1008), LlilInstruction::Nop),
            (
                a(0x100c),
                LlilInstruction::JumpDest {
                    dest: const_expr(0x1010),
                },
            ),
            (a(0x1010), LlilInstruction::Ret),
        ];

        let cfg = analyze_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 3);
        assert!(cfg.blocks.contains_key(&a(0x1000)));
        assert!(cfg.blocks.contains_key(&a(0x1008)));
        assert!(cfg.blocks.contains_key(&a(0x1010)));
    }

    /// A `TailCall` is a terminator: the following instruction must start a new
    /// basic block, exactly as it does for `Ret`. Regression test — the leader
    /// scan used to drop `TailCall` into its catch-all arm, silently fusing the
    /// tail-call block with its successor while still returning a well-formed
    /// (undetectably wrong) CFG.
    #[test]
    fn tail_call_terminates_basic_block() {
        let instrs = vec![
            (a(0x1000), LlilInstruction::Nop),
            (
                a(0x1004),
                LlilInstruction::TailCall {
                    dest: const_expr(0x9000),
                },
            ),
            (a(0x1008), LlilInstruction::Nop),
            (a(0x100c), LlilInstruction::Ret),
        ];

        let cfg = analyze_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 2, "tail call must end its block");
        assert!(cfg.blocks.contains_key(&a(0x1000)));
        assert!(cfg.blocks.contains_key(&a(0x1008)));
        // Negative half: the tail-call block must NOT swallow the instructions
        // that follow it.
        assert_eq!(cfg.blocks[&a(0x1000)].end, a(0x1004));
        assert_eq!(cfg.blocks[&a(0x1000)].instructions.len(), 2);
    }

    // â"€â"€ 2. DominatorTree on a diamond CFG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    //
    //   A â†' B
    //   A â†' C
    //   B â†' D
    //   C â†' D

    #[test]
    fn test_dom_tree_diamond() {
        // A=0, B=1, C=2, D=3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let dt = &cfg.dom_tree;

        assert_eq!(dt.idom[&a(0)], None); // entry
        assert_eq!(dt.idom[&a(1)], Some(a(0)));
        assert_eq!(dt.idom[&a(2)], Some(a(0)));
        assert_eq!(dt.idom[&a(3)], Some(a(0)));

        assert!(dt.dominates(a(0), a(3)));
        assert!(!dt.dominates(a(1), a(3))); // B doesn't dominate D
        assert!(!dt.dominates(a(2), a(3))); // C doesn't dominate D
    }

    // â"€â"€ 3. DominatorTree on a loop CFG â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    //
    //   A â†' B â†' C â†' B (back edge Câ†'B)
    //            â""â†' D

    #[test]
    fn test_dom_tree_loop_back_edge() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (2, 3)], 0);
        let dt = &cfg.dom_tree;

        assert!(dt.dominates(a(1), a(2)));
        assert!(dt.dominates(a(0), a(3)));
        // Câ†'B is a back edge
        assert!(cfg.is_back_edge(a(2), a(1)));
    }

    // â"€â"€ 4. Dominance frontier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dominance_frontier_diamond() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let df_b = cfg.dominance_frontier(a(1));
        let df_c = cfg.dominance_frontier(a(2));
        assert!(df_b.contains(&a(3)), "DF(B) must contain D");
        assert!(df_c.contains(&a(3)), "DF(C) must contain D");
    }

    #[test]
    fn test_dominance_frontier_back_edge_to_entry() {
        // Regression (found by soundness_fuzz): 0 <-> 1. The frontier walk
        // used to map the entry's missing idom to the join itself and stop
        // one node early, so the entry never appeared in any frontier.
        // Correct: DF(0) = DF(1) = {0}.
        let cfg = make_cfg_raw(&[0, 1], &[(0, 1), (1, 0)], 0);
        assert_eq!(cfg.dominance_frontier(a(0)), vec![a(0)]);
        assert_eq!(cfg.dominance_frontier(a(1)), vec![a(0)]);
    }

    // â"€â"€ 5. Natural loops —" simple while â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    //
    //   entry â†' header â†' body â†' header (back)
    //           header â†' exit

    #[test]
    fn test_natural_loop_simple_while() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let loops = &cfg.loops;
        assert_eq!(loops.len(), 1);
        let lp = &loops[0];
        assert_eq!(lp.header, a(1));
        assert!(lp.body.contains(&a(1)));
        assert!(lp.body.contains(&a(2)));
        assert!(!lp.body.contains(&a(3)));
        assert!(lp.exits.contains(&a(3)));
    }

    // â"€â"€ 6. Natural loops —" nested â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    //
    //   0 â†' 1 â†' 2 â†' 3 â†' 2 (inner back edge)
    //   3 â†' 1 (outer back edge)
    //   1 â†' 4

    #[test]
    fn test_natural_loop_nested() {
        let cfg = make_cfg_raw(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let loops = &cfg.loops;
        // We expect two loops: inner (header=2) and outer (header=1).
        assert_eq!(loops.len(), 2);

        let inner = loops
            .iter()
            .find(|lp| lp.header == a(2))
            .expect("inner loop");
        let outer = loops
            .iter()
            .find(|lp| lp.header == a(1))
            .expect("outer loop");

        assert!(inner.is_innermost);
        assert!(!outer.is_innermost);
        assert!(outer.body.contains(&a(2)));
        assert!(outer.body.contains(&a(3)));
    }

    // â"€â"€ 7. RPO traversal â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_reverse_post_order() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let rpo = cfg.reverse_post_order();
        // entry must come first; D must come after B and C
        assert_eq!(rpo[0], a(0));
        let pos: HashMap<Address, usize> = rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();
        assert!(pos[&a(1)] < pos[&a(3)]);
        assert!(pos[&a(2)] < pos[&a(3)]);
    }

    // â"€â"€ 8. Reachable from â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_reachable_from() {
        // Disconnected graph: 0â†'1â†'2   and   3â†'4
        let cfg = make_cfg_raw(&[0, 1, 2, 3, 4], &[(0, 1), (1, 2), (3, 4)], 0);
        let reachable = cfg.reachable_from(a(0));
        assert!(reachable.contains(&a(0)));
        assert!(reachable.contains(&a(1)));
        assert!(reachable.contains(&a(2)));
        assert!(!reachable.contains(&a(3)));
        assert!(!reachable.contains(&a(4)));
    }

    // â"€â"€ 9. dominates() convenience on ControlFlowGraph â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_dominates() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        assert!(cfg.dominates(a(0), a(3)));
        assert!(!cfg.dominates(a(1), a(2)));
    }

    // â"€â"€ 10. CfgStats cyclomatic complexity â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_stats_cyclomatic() {
        // 4 nodes, 4 edges â†' complexity = 4 - 4 + 2 = 2
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let stats = CfgStats::compute(&cfg);
        assert_eq!(stats.block_count, 4);
        assert_eq!(stats.edge_count, 4);
        assert_eq!(stats.cyclomatic_complexity, 2);
        assert!(!stats.is_complex());
    }

    #[test]
    fn test_cfg_stats_max_loop_depth_nested() {
        // Same nested-loop shape as test_natural_loop_nested:
        // 0 -> 1 -> 2 -> 3 -> 2 (inner back edge), 3 -> 1 (outer back edge), 1 -> 4
        // Block 2 is contained in both the inner and outer loop bodies, so
        // max_loop_depth must be 2.
        let cfg = make_cfg_raw(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let stats = CfgStats::compute(&cfg);
        assert_eq!(stats.max_loop_depth, 2);

        let metrics = CfgMetrics::compute(&cfg);
        assert_eq!(metrics.max_loop_depth, 2);
    }

    // â"€â"€ 11. CfgDotPrinter produces valid DOT output â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dot_printer_output() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let dot = CfgDotPrinter::new().print(&cfg);
        assert!(
            dot.contains("digraph cfg {"),
            "must start with 'digraph cfg'"
        );
        assert!(dot.contains("->"), "must contain edge arrows");
        assert!(dot.ends_with("}\n"), "must end with closing brace");
    }

    // â"€â"€ 12. PostDominatorTree â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
    //
    //   A â†' B â†' D (ret)
    //   A â†' C â†' D

    #[test]
    fn test_post_dom_tree_diamond() {
        // In a diamond, D post-dominates A, B, C.
        // B post-dominates B only; C post-dominates C only.
        let blocks: HashMap<Address, BasicBlock> = [0u64, 1, 2, 3]
            .iter()
            .map(|&n| {
                let addr = a(n);
                let instructions = if n == 3 {
                    vec![LlilInstruction::Ret]
                } else {
                    vec![]
                };
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions,
                    },
                )
            })
            .collect();

        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(0),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
        ];

        let pdt = PostDominatorTree::compute(&blocks, &edges);

        // D post-dominates everything
        assert!(pdt.post_dominates(a(3), a(0)));
        assert!(pdt.post_dominates(a(3), a(1)));
        assert!(pdt.post_dominates(a(3), a(2)));
        // B does not post-dominate A (A could go via C)
        assert!(!pdt.post_dominates(a(1), a(0)));
    }

    // â"€â"€ 13. to_petgraph node/edge count â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_to_petgraph_counts() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let g = cfg.to_petgraph();
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.edge_count(), 4);
    }

    // â"€â"€ 14. analyze_cfg computes dom_tree and loops end-to-end â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_analyze_cfg_full_pipeline() {
        // Simple straight-line function: A â†' B â†' C(ret)
        let instrs = vec![
            (a(0x100), LlilInstruction::Nop),
            (
                a(0x104),
                LlilInstruction::JumpDest {
                    dest: const_expr(0x200),
                },
            ),
            (a(0x200), LlilInstruction::Nop),
            (
                a(0x204),
                LlilInstruction::JumpDest {
                    dest: const_expr(0x300),
                },
            ),
            (a(0x300), LlilInstruction::Ret),
        ];
        let cfg = analyze_cfg(&instrs);
        assert_eq!(cfg.blocks.len(), 3);
        assert_eq!(cfg.entry, a(0x100));
        // A dominates everything
        assert!(cfg.dominates(a(0x100), a(0x300)));
        // No loops
        assert!(cfg.loops.is_empty());
        // Stats
        let stats = CfgStats::compute(&cfg);
        assert_eq!(stats.exit_blocks, 1);
    }

    // â"€â"€ 15. DominatorTree::dominated_by â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dom_tree_dominated_by() {
        // Chain: 0 â†' 1 â†' 2 â†' 3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)], 0);
        let dominated = cfg.dom_tree.dominated_by(a(0));
        // Every node except 0 itself is dominated by 0
        assert!(dominated.contains(&a(1)));
        assert!(dominated.contains(&a(2)));
        assert!(dominated.contains(&a(3)));
        assert!(!dominated.contains(&a(0)));
    }

    #[test]
    fn test_dom_tree_children_sorted_for_fanout() {
        // Regression test: `DominatorTree::children` used to be built by
        // iterating `idom_map` (a HashMap), so a node with several
        // dominator-tree children could have them recorded in
        // nondeterministic order, leaking into `dominated_by`. Build a
        // 5-way fan-out from the entry (inserted out of numeric order via
        // the edge list) and confirm `dominated_by` always returns them
        // sorted by address, on every repeated call.
        let cfg = make_cfg_raw(
            &[0, 50, 10, 40, 20, 30],
            &[(0, 50), (0, 10), (0, 40), (0, 20), (0, 30)],
            0,
        );
        // `dominated_by` does a stack-based DFS with children pushed in
        // ascending order, so it pops (and returns) them in descending
        // order; the key invariant under test is that this is the *same*
        // order on every call, not hash-iteration-dependent.
        let first = cfg.dom_tree.dominated_by(a(0));
        assert_eq!(first, vec![a(50), a(40), a(30), a(20), a(10)]);
        for _ in 0..10 {
            let dominated = cfg.dom_tree.dominated_by(a(0));
            assert_eq!(dominated, first, "dominated_by must be deterministic");
        }
    }

    // â"€â"€ 16. DominatorTree::depth â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dom_tree_depth() {
        // Chain: 0 â†' 1 â†' 2 â†' 3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)], 0);
        assert_eq!(cfg.dom_tree.depth(a(0)), 0);
        assert_eq!(cfg.dom_tree.depth(a(1)), 1);
        assert_eq!(cfg.dom_tree.depth(a(2)), 2);
        assert_eq!(cfg.dom_tree.depth(a(3)), 3);
    }

    // â"€â"€ 17. NaturalLoop::contains and size â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_natural_loop_contains_and_size() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let lp = &cfg.loops[0];
        assert!(lp.contains(a(1)));
        assert!(lp.contains(a(2)));
        assert!(!lp.contains(a(0)));
        assert_eq!(lp.size(), 2);
    }

    // â"€â"€ 18. CfgStats entry_blocks â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_stats_entry_blocks() {
        // Diamond: 0 is the only entry (no predecessors).
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let stats = CfgStats::compute(&cfg);
        assert_eq!(stats.entry_blocks, 1);
    }

    // â"€â"€ 19. post_order is reverse of RPO â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_post_order_reverses_rpo() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)], 0);
        let rpo = cfg.reverse_post_order();
        let po = cfg.post_order();
        let mut rpo_rev = rpo.clone();
        rpo_rev.reverse();
        assert_eq!(rpo_rev, po);
    }

    // â"€â"€ 20. immediate_dominator returns None for entry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_immediate_dominator_entry_is_none() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        assert_eq!(cfg.immediate_dominator(a(0)), None);
        assert_eq!(cfg.immediate_dominator(a(1)), Some(a(0)));
        assert_eq!(cfg.immediate_dominator(a(2)), Some(a(1)));
    }

    // â"€â"€ ReducibilityTest tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_reducibility_simple_chain() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let r = ReducibilityTest::test(&cfg);
        assert!(r.is_reducible());
    }

    #[test]
    fn test_reducibility_self_loop_is_reducible() {
        // 0â†'1, 1â†'1 (self-loop on 1), 1â†'2
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 1), (1, 2)], 0);
        let r = ReducibilityTest::test(&cfg);
        assert!(r.is_reducible());
    }

    #[test]
    fn test_reducibility_empty_cfg() {
        let cfg = make_cfg_raw(&[], &[], 0);
        let r = ReducibilityTest::test(&cfg);
        assert!(r.is_reducible());
    }

    #[test]
    fn test_reducibility_diamond_is_reducible() {
        // 0 â†' 1, 0 â†' 2, 1 â†' 3, 2 â†' 3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let r = ReducibilityTest::test(&cfg);
        assert!(r.is_reducible());
    }

    // â"€â"€ DominatorTree strictly_dominates â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_strictly_dominates() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, a(0));
        assert!(dom.strictly_dominates(a(0), a(1)));
        assert!(dom.strictly_dominates(a(0), a(2)));
        assert!(!dom.strictly_dominates(a(0), a(0)));
        assert!(!dom.strictly_dominates(a(1), a(0)));
    }

    // â"€â"€ DominanceFrontier tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dominance_frontier_struct_diamond() {
        // Diamond: 0â†'1, 0â†'2, 1â†'3, 2â†'3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, a(0));
        let df = DominanceFrontier::compute(&dom, &cfg.edges);
        // Both 1 and 2 have 3 in their DF
        let df1 = df.frontier_of(a(1));
        let df2 = df.frontier_of(a(2));
        assert!(df1.contains(&a(3)));
        assert!(df2.contains(&a(3)));
    }

    #[test]
    fn test_dominance_frontier_chain_is_empty() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, a(0));
        let df = DominanceFrontier::compute(&dom, &cfg.edges);
        // In a simple chain every node strictly dominates its successor; no frontiers
        assert!(df.frontier_of(a(0)).is_empty());
    }

    #[test]
    fn test_iterated_frontier_diamond() {
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, a(0));
        let df = DominanceFrontier::compute(&dom, &cfg.edges);
        let idf = df.iterated_frontier(&[a(1), a(2)]);
        assert!(idf.contains(&a(3)));
    }

    // â"€â"€ CfgMetrics tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_metrics_chain() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let m = CfgMetrics::compute(&cfg);
        // N=3, E=2, P=1 â†' cyclomatic = max(E-N+2P, 1) = 2 (saturating_sub(3) = 0, +2*1 = 2)
        assert_eq!(m.cyclomatic_complexity, 2);
        assert_eq!(m.back_edge_count, 0);
        assert!(m.is_reducible);
        assert_eq!(m.reachable_count, 3);
        assert_eq!(m.edge_count, 2);
        assert_eq!(m.join_count, 0);
        assert_eq!(m.branch_count, 0);
    }

    #[test]
    fn test_cfg_metrics_diamond() {
        // Diamond: 0â†'1, 0â†'2, 1â†'3, 2â†'3
        let cfg = make_cfg_raw(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let m = CfgMetrics::compute(&cfg);
        // N=4, E=4 â†' cyclomatic = 4 - 4 + 2 = 2
        assert_eq!(m.cyclomatic_complexity, 2);
        assert_eq!(m.join_count, 1); // block 3 has 2 predecessors
        assert_eq!(m.branch_count, 1); // block 0 has 2 successors
        assert_eq!(m.reachable_count, 4);
    }

    // â"€â"€ CfgScc tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_scc_chain_all_trivial() {
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let scc = CfgScc::compute(&cfg);
        assert_eq!(scc.len(), 3);
        assert!(scc.loops().is_empty());
    }

    #[test]
    fn test_scc_self_loop() {
        let cfg = make_cfg_raw(&[0, 1], &[(0, 1), (1, 1)], 0);
        let scc = CfgScc::compute(&cfg);
        let loops = scc.loops();
        assert_eq!(loops.len(), 1);
    }

    #[test]
    fn test_scc_back_edge_forms_loop() {
        // 0â†'1â†'2, 2â†'1 (loop on 1-2)
        let cfg = make_cfg_raw(&[0, 1, 2], &[(0, 1), (1, 2), (2, 1)], 0);
        let scc = CfgScc::compute(&cfg);
        assert!(!scc.loops().is_empty());
    }

    #[test]
    fn test_scc_components_are_deterministic() {
        // Regression test: `CfgScc::compute` used to pick DFS roots by
        // iterating `cfg.blocks.keys()` (a HashMap) directly -- the exact
        // bug class fixed in `loop_analysis.rs::dfs_back_edges`. On a CFG
        // with multiple disconnected trivial components (so root order
        // actually matters) the component list must come out identically
        // on every call.
        let cfg = make_cfg_raw(
            &[0, 50, 10, 40, 20, 30],
            &[(0, 50), (50, 10), (10, 40)],
            0,
        );
        let first = CfgScc::compute(&cfg);
        let first_nodes: Vec<Vec<Address>> =
            first.components.iter().map(|c| c.nodes.clone()).collect();
        for _ in 0..10 {
            let again = CfgScc::compute(&cfg);
            let again_nodes: Vec<Vec<Address>> =
                again.components.iter().map(|c| c.nodes.clone()).collect();
            assert_eq!(again_nodes, first_nodes, "SCC decomposition must be deterministic");
        }
    }

    // â"€â"€ JSON and DOT output tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_cfg_to_full_json_valid() {
        let cfg = make_cfg_raw(&[0, 1], &[(0, 1)], 0);
        let json = cfg_to_full_json(&cfg);
        assert!(json.contains("entry"));
        assert!(json.contains("blocks"));
        assert!(json.contains("edges"));
    }

    #[test]
    fn test_cfg_to_dot_annotated_valid() {
        let cfg = make_cfg_raw(&[0, 1], &[(0, 1)], 0);
        let dom = DominatorTree::compute(&cfg.blocks, &cfg.edges, a(0));
        let dot = cfg_to_dot_annotated(&cfg, &dom);
        assert!(dot.contains("digraph cfg"));
        assert!(dot.contains("->"));
    }

    // ── basic_blocks() tests ──────────────────────────────────────────────

    /// Build a 3-block "diamond" function: entry branches to true/false, both
    /// fall into a join/exit block.
    ///
    ///   0x1000 (entry/branch): CondJump true=0x1008 false=0x100c
    ///   0x1008 (true arm):     Nop  → falls to 0x100c  (join)
    ///   0x100c (join/exit):    Ret
    #[test]
    fn test_basic_blocks_conditional_branch_three_blocks() {
        let instrs = vec![
            (
                a(0x1000),
                LlilInstruction::CondJump {
                    cond: const_expr(1),
                    true_dest: a(0x1008),
                    false_dest: a(0x100c),
                },
            ),
            (a(0x1008), LlilInstruction::Nop),
            (a(0x100c), LlilInstruction::Ret),
        ];

        let recs = basic_blocks_for_instrs(0x1000, &instrs);

        // Exactly three blocks.
        assert_eq!(recs.len(), 3, "expected 3 basic blocks, got {}", recs.len());

        // IDs are unique and cover 0..3.
        let mut ids: Vec<u32> = recs.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![0, 1, 2]);

        // Entry block (id 0) must be at 0x1000.
        let entry = recs.iter().find(|r| r.id == 0).unwrap();
        assert_eq!(entry.start_addr, 0x1000);
        // The entry block has two successors (branch) and no predecessors.
        assert_eq!(entry.successors.len(), 2, "entry should have 2 successors");
        assert!(entry.predecessors.is_empty(), "entry should have no predecessors");
        // Kind must be Branch (entry is also branch; LoopHeader takes priority
        // but there is none here; Entry takes priority over Branch, so check either).
        assert!(
            matches!(entry.kind, BlockKind::Entry | BlockKind::Branch),
            "entry kind should be Entry or Branch, got {:?}",
            entry.kind
        );

        // Exactly one Exit block.
        let exits: Vec<_> = recs.iter().filter(|r| r.kind == BlockKind::Exit).collect();
        assert_eq!(exits.len(), 1, "expected exactly 1 exit block");
        let exit_rec = exits[0];
        assert_eq!(exit_rec.start_addr, 0x100c);
        assert!(exit_rec.successors.is_empty(), "exit should have no successors");

        // The exit block has two predecessors (entry and true-arm).
        assert_eq!(
            exit_rec.predecessors.len(),
            2,
            "exit block should have 2 predecessors"
        );

        // The true-arm block (0x1008) should be Normal.
        let true_arm = recs.iter().find(|r| r.start_addr == 0x1008).unwrap();
        assert_eq!(true_arm.kind, BlockKind::Normal);
        assert_eq!(true_arm.predecessors.len(), 1);
        assert_eq!(true_arm.successors.len(), 1);
    }

    #[test]
    fn test_basic_blocks_empty_returns_empty() {
        let recs = basic_blocks_for_instrs(0, &[]);
        assert!(recs.is_empty());
        // The entry-point form on an empty stream: empty is the CORRECT answer
        // here because there are genuinely no instructions.
        //
        // This assertion used to read `basic_blocks(0)` against the old
        // single-argument stub and was commented "always empty without an
        // instruction stream" — it certified that the function returned
        // nothing for EVERY input, which is what made the fabrication look
        // intentional. `basic_blocks_delegates_and_does_not_fabricate` now
        // covers the non-empty case.
        let recs2 = basic_blocks(a(0), &[]);
        assert!(recs2.is_empty());
    }

    #[test]
    fn test_basic_blocks_single_ret() {
        let instrs = vec![(a(0x2000), LlilInstruction::Ret)];
        let recs = basic_blocks_for_instrs(0x2000, &instrs);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.id, 0);
        assert_eq!(r.start_addr, 0x2000);
        assert!(r.successors.is_empty());
        assert!(r.predecessors.is_empty());
        // Single block is both entry and exit; Entry takes priority.
        assert!(matches!(r.kind, BlockKind::Entry | BlockKind::Exit));
    }
}
