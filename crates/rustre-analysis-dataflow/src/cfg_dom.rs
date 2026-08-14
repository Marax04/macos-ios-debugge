//! `cfg_dom` — dominator-tree computation via the Lengauer-Tarjan algorithm.
//!
//! The Lengauer-Tarjan algorithm runs in near-linear time O(n α(n)) and is the
//! standard industrial algorithm for dominator computation.
//!
//! Reference: Lengauer, T.; Tarjan, R. E. (1979). "A fast algorithm for finding
//! dominators in a flowgraph." ACM TOPLAS 1(1):121–141.
//!
//! Audit note (dataflow-crate iteration 5): unlike most modules in this
//! crate, `Cfg`/`DomTree`/`lengauer_tarjan` ARE load-bearing *within* the
//! crate — `constant_propagation`, `def_use`, `du_chains`, `live_ranges`,
//! `reaching_defs`, and `value_range` all build on this module's `Cfg`/`BBId`.
//! However, grepping the whole workspace for `rustre_analysis_dataflow::`
//! usage shows none of those internal callers is itself reached from outside
//! this crate (the externally-used surface — `compute_dominators`,
//! `compute_dominators_from_edges`, `postorder`, `compute_dominance_frontiers`
//! — lives directly in `lib.rs` as independent, self-contained
//! implementations that do NOT call into this module). So this module is
//! real shared infrastructure, but the whole subgraph it anchors is
//! currently orphaned from the rest of the workspace.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Opaque basic-block identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
pub struct BBId(pub usize);

/// A control-flow graph represented as adjacency lists.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cfg {
    pub pred: Vec<Vec<BBId>>,
    pub succ: Vec<Vec<BBId>>,
    pub entry: BBId,
    pub exit: BBId,
}

impl Cfg {
    /// Create a CFG from a successor list.
    /// `n` = number of nodes; `succs[i]` = successors of node `i`.
    /// `entry` and `exit` mark the entry/exit basic blocks.
    ///
    /// Any successor target that is out of range (`>= n`, e.g. from
    /// adversarial/malformed input) is silently dropped — it is never added
    /// to `succ` or `pred` — so downstream algorithms that index blindly by
    /// `BBId` (e.g. `lengauer_tarjan`'s DFS) never see an out-of-bounds
    /// target and cannot panic on it.
    #[must_use]
    pub fn new(n: usize, succs: Vec<Vec<BBId>>, entry: BBId, exit: BBId) -> Self {
        let mut pred: Vec<Vec<BBId>> = vec![Vec::new(); n];
        let mut succ: Vec<Vec<BBId>> = vec![Vec::new(); n];
        for (src, dst_list) in succs.into_iter().enumerate() {
            if src >= n {
                break;
            }
            for dst in dst_list {
                if dst.0 < n {
                    pred[dst.0].push(BBId(src));
                    succ[src].push(dst);
                }
            }
        }
        Self {
            pred,
            succ,
            entry,
            exit,
        }
    }

    /// Number of basic blocks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.succ.len()
    }

    /// True when the CFG is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.succ.is_empty()
    }
}

// ── DomTree ───────────────────────────────────────────────────────────────────

/// Dominator tree produced by `lengauer_tarjan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomTree {
    /// `idom[v]` = immediate dominator of `v`; `None` for the entry node.
    pub idom: Vec<Option<BBId>>,
    /// `children[v]` = list of nodes immediately dominated by `v`.
    pub children: Vec<Vec<BBId>>,
    n: usize,
}

impl DomTree {
    /// Create a new dominator tree for an n-node CFG.
    #[must_use]
    fn new(n: usize) -> Self {
        Self {
            idom: vec![None; n],
            children: vec![Vec::new(); n],
            n,
        }
    }

    /// Check whether node `a` dominates node `b`.
    ///
    /// `a` dominates `b` iff `a` appears in the path from the entry to `b` in
    /// the dominator tree.
    #[must_use]
    pub fn dominates(&self, a: BBId, b: BBId) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            // `.get()` rather than indexing: `b` (and any ancestor `BBId`) may
            // be out of range for adversarial/malformed input; treat that as
            // "does not dominate" instead of panicking.
            match self.idom.get(cur.0) {
                Some(Some(p)) if *p == a => return true,
                Some(Some(p)) => cur = *p,
                _ => return false,
            }
        }
    }

    /// Compute the dominance frontier set for every node.
    ///
    /// DF(n) = { y | ∃ x ∈ pred(y): n dominates x AND n does not strictly
    ///                                 dominate y }
    ///
    /// Cooper et al. "A Simple, Fast Dominance Algorithm" (2001).
    ///
    /// # Single implementation
    /// This is a thin adapter over the crate's authoritative frontier
    /// routine, [`crate::compute_dominance_frontiers`]; it only translates
    /// between this module's `Cfg`/`DomTree`/`BBId` representation and that
    /// function's flat `(n, successors, idom)` arrays. It deliberately does
    /// **not** re-implement the walk.
    ///
    /// The previous private implementation here differed on one case: it
    /// guarded the runner walk with `runner != y`, which stopped one node
    /// short when `y` is the entry block and a back edge targets it, so the
    /// entry was silently omitted from its own dominance frontier. By the
    /// definition `DF(n) = { y | ∃x ∈ pred(y): n dom x ∧ n !sdom y }`, an
    /// entry that is also a loop header *is* in `DF(entry)` (it dominates the
    /// back edge's source but does not *strictly* dominate itself). The
    /// differential test `dom_differential::dominance_frontier_differential_lib_vs_cfg_dom`
    /// pins the agreement.
    #[must_use]
    pub fn dominance_frontier(&self, cfg: &Cfg) -> Vec<HashSet<BBId>> {
        let n = self.n;
        // `cfg_dom` uses `None` for the entry and for unreachable nodes;
        // the flat API uses the self-loop sentinel `idom[i] == i` for both.
        let idom: Vec<usize> = (0..n)
            .map(|i| self.idom.get(i).copied().flatten().map_or(i, |b| b.0))
            .collect();
        let successors: Vec<Vec<usize>> = (0..n)
            .map(|i| {
                cfg.succ
                    .get(i)
                    .map(|row| row.iter().map(|b| b.0).collect())
                    .unwrap_or_default()
            })
            .collect();

        crate::compute_dominance_frontiers(n, &successors, &idom)
            .into_iter()
            .map(|row| row.into_iter().map(BBId).collect())
            .collect()
    }

    /// Compute the iterated dominance frontier DF⁺(S) for a set S of nodes.
    #[must_use]
    pub fn iterated_dominance_frontier(&self, cfg: &Cfg, seed: &HashSet<BBId>) -> HashSet<BBId> {
        let df = self.dominance_frontier(cfg);
        let mut result: HashSet<BBId> = HashSet::new();
        let mut worklist: Vec<BBId> = seed.iter().copied().collect();

        while let Some(n) = worklist.pop() {
            for &y in &df[n.0] {
                if result.insert(y) {
                    worklist.push(y);
                }
            }
        }

        result
    }

    /// Compute the post-dominator tree (reverse CFG dominator tree).
    #[must_use]
    pub fn post_dominance_tree(cfg: &Cfg) -> Self {
        // Reverse the CFG: swap predecessor and successor lists, entry ↔ exit.
        let n = cfg.len();
        let rev_succs: Vec<Vec<BBId>> = (0..n).map(|i| cfg.pred[i].clone()).collect();
        let rev_cfg = Cfg::new(n, rev_succs, cfg.exit, cfg.entry);
        lengauer_tarjan(&rev_cfg, cfg.exit)
    }

    /// Walk the dominator tree in pre-order (entry first, then dominated nodes).
    pub fn preorder_walk(&self, entry: BBId, out: &mut Vec<BBId>) {
        out.push(entry);
        for &child in &self.children[entry.0] {
            self.preorder_walk(child, out);
        }
    }

    /// Return the depth of a node in the dominator tree (entry = 0).
    #[must_use]
    pub fn depth(&self, node: BBId) -> usize {
        let mut d = 0usize;
        let mut cur = node;
        // `.get()` rather than indexing: an out-of-range `node` (adversarial
        // input) yields depth 0 instead of panicking.
        while let Some(Some(p)) = self.idom.get(cur.0) {
            d += 1;
            cur = *p;
        }
        d
    }
}

// ── Lengauer-Tarjan ───────────────────────────────────────────────────────────

/// Compute the dominator tree for `cfg` with the given `entry` node.
///
/// Implements the simple ("non-path-compressed") variant of Lengauer-Tarjan for
/// clarity.  Complexity: O(m log n) where m = number of edges, n = number of nodes.
///
/// # Panics
/// Panics if a non-root DFS node lacks a parent (indicates malformed input).
#[must_use]
pub fn lengauer_tarjan(cfg: &Cfg, entry: BBId) -> DomTree {
    let n = cfg.len();
    if n == 0 || entry.0 >= n {
        // Empty CFG, or an out-of-range entry (malformed/adversarial input):
        // there is nothing to compute a dominator tree over: `n` nodes,
        // all with unknown/no dominator.
        return DomTree::new(n);
    }

    // ── Phase 1: depth-first spanning tree ───────────────────────────────────
    // `dfn[v]`  = DFS discovery number of v (0 = first).
    // `vertex[i]` = node with DFS number i.
    // `parent[v]` = DFS-tree parent of v.
    let mut dfn: Vec<Option<usize>> = vec![None; n];
    let mut vertex: Vec<BBId> = Vec::with_capacity(n);
    let mut parent: Vec<Option<BBId>> = vec![None; n];

    // Iterative DFS to avoid stack overflow on large CFGs.
    let mut stack: Vec<(BBId, usize)> = vec![(entry, 0)]; // (node, succ_index)
    dfn[entry.0] = Some(0);
    vertex.push(entry);

    while let Some((u, _si)) = stack.last().copied() {
        let succs = &cfg.succ[u.0];
        // Find the next unvisited successor.
        let next_unvisited = succs.iter().find(|&&v| dfn[v.0].is_none());
        if let Some(&v) = next_unvisited {
            let num = vertex.len();
            dfn[v.0] = Some(num);
            vertex.push(v);
            parent[v.0] = Some(u);
            stack.push((v, 0));
        } else {
            stack.pop();
        }
    }

    let dfs_count = vertex.len();

    // ── Phase 2: compute semi-dominators ─────────────────────────────────────
    // `semi[v]` = DFS number of the semi-dominator of v.
    let mut semi: Vec<usize> = (0..n).map(|i| dfn[i].unwrap_or(i)).collect();
    let mut ancestor: Vec<Option<BBId>> = vec![None; n];
    let mut label: Vec<BBId> = (0..n).map(BBId).collect();
    // `bucket[v]` = nodes whose semi-dominator is v, awaiting idom resolution.
    let mut bucket: Vec<Vec<BBId>> = vec![Vec::new(); n];
    let mut idom_arr: Vec<Option<BBId>> = vec![None; n];

    // Process nodes in reverse DFS order (skip root at index 0).
    for i in (1..dfs_count).rev() {
        let w = vertex[i];

        // Compute semi-dominator of w:
        // semi(w) = min { semi(v) | v ∈ pred(w), DFS(v) < DFS(w) }
        //         ∪ min { semi(u) | v ∈ pred(w), DFS(v) > DFS(w), u = min(semi) on
        //                  path from v to its ancestor with smallest DFS number }
        for &v in &cfg.pred[w.0] {
            if dfn[v.0].is_none() {
                continue; // unreachable predecessor
            }
            let u = eval(
                v,
                &mut ancestor,
                &semi,
                &mut label,
                dfn[entry.0].unwrap_or(0),
            );
            let semi_u = semi[u.0];
            if semi_u < semi[w.0] {
                semi[w.0] = semi_u;
            }
        }

        // Add w to its semi-dominator's bucket and link w under its DFS parent.
        bucket[vertex[semi[w.0]].0].push(w);
        let parent_w = parent[w.0].expect("non-root node has a DFS parent");
        link(parent_w, w, &mut ancestor);

        // Process the bucket of w's parent: for each v with semi(v) = parent(w),
        // set idom(v) = u if semi(u) < semi(v) (u = eval(v)), else parent(w).
        for v in std::mem::take(&mut bucket[parent_w.0]) {
            let u = eval(
                v,
                &mut ancestor,
                &semi,
                &mut label,
                dfn[entry.0].unwrap_or(0),
            );
            idom_arr[v.0] = Some(if semi[u.0] < semi[v.0] { u } else { parent_w });
        }
    }

    // ── Phase 3: compute immediate dominators ─────────────────────────────────
    // Forward pass: where the tentative idom is not the semi-dominator, the true
    // idom is the idom of the tentative idom.
    for i in 1..dfs_count {
        let w = vertex[i];
        if let Some(idom_w) = idom_arr[w.0]
            && idom_w != vertex[semi[w.0]]
        {
            idom_arr[w.0] = idom_arr[idom_w.0];
        }
    }

    // Build the DomTree.
    let mut tree = DomTree::new(n);
    tree.idom = idom_arr;
    // Set entry's idom to None.
    tree.idom[entry.0] = None;
    // Build children list.
    for v in 0..n {
        if let Some(p) = tree.idom[v] {
            tree.children[p.0].push(BBId(v));
        }
    }

    tree
}

// ── Union-Find helpers for Lengauer-Tarjan ─────────────────────────────────────

/// `link(v, w)`: add edge v→w to the forest (used in Lengauer-Tarjan).
fn link(v: BBId, w: BBId, ancestor: &mut [Option<BBId>]) {
    ancestor[w.0] = Some(v);
}

/// `eval(v)`: find the vertex u with minimum `semi` value on the path from v to the
/// root of its tree.  Performs path compression.
fn eval(
    v: BBId,
    ancestor: &mut [Option<BBId>],
    semi: &[usize],
    label: &mut [BBId],
    _entry_dfn: usize,
) -> BBId {
    if ancestor[v.0].is_none() {
        return v;
    }
    compress(v, ancestor, semi, label);
    label[v.0]
}

/// Path-compress and update `label` to the minimum-semi ancestor.
fn compress(
    v: BBId,
    ancestor: &mut [Option<BBId>],
    semi: &[usize],
    label: &mut [BBId],
) {
    // Collect the path of vertices whose ancestor has an ancestor, then
    // compress from the top down (iterative to avoid stack overflow on deep CFGs).
    let mut stack = vec![v];
    while let Some(anc) = ancestor[stack[stack.len() - 1].0]
        && ancestor[anc.0].is_some()
    {
        stack.push(anc);
    }
    // The last pushed vertex's ancestor is already a root child; process the rest.
    stack.pop();
    while let Some(u) = stack.pop() {
        let anc = ancestor[u.0].unwrap();
        if semi[label[anc.0].0] < semi[label[u.0].0] {
            label[u.0] = label[anc.0];
        }
        ancestor[u.0] = ancestor[anc.0];
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a simple linear 4-node CFG: 0→1→2→3.
    fn linear_cfg(n: usize) -> Cfg {
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        Cfg::new(n, succs, BBId(0), BBId(n - 1))
    }

    /// Diamond CFG: 0→1, 0→2, 1→3, 2→3.
    fn diamond_cfg() -> Cfg {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        Cfg::new(4, succs, BBId(0), BBId(3))
    }

    #[test]
    fn test_linear_idoms() {
        let cfg = linear_cfg(4);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.idom[0], None);
        assert_eq!(dom.idom[1], Some(BBId(0)));
        assert_eq!(dom.idom[2], Some(BBId(1)));
        assert_eq!(dom.idom[3], Some(BBId(2)));
    }

    #[test]
    fn test_diamond_idoms() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // Entry has no idom.
        assert_eq!(dom.idom[0], None);
        // 1 and 2 are dominated by entry (0).
        assert_eq!(dom.idom[1], Some(BBId(0)));
        assert_eq!(dom.idom[2], Some(BBId(0)));
        // Join node 3 is dominated by entry (0).
        assert_eq!(dom.idom[3], Some(BBId(0)));
    }

    #[test]
    fn test_dominates_linear() {
        let cfg = linear_cfg(5);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert!(dom.dominates(BBId(0), BBId(4)));
        assert!(dom.dominates(BBId(2), BBId(4)));
        assert!(!dom.dominates(BBId(4), BBId(2)));
        assert!(dom.dominates(BBId(3), BBId(3))); // every node dominates itself
    }

    #[test]
    fn test_dominance_frontier_diamond() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let df = dom.dominance_frontier(&cfg);
        // DF(1) = {3}, DF(2) = {3}.
        assert!(df[1].contains(&BBId(3)));
        assert!(df[2].contains(&BBId(3)));
    }

    #[test]
    fn test_iterated_df() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let seed: HashSet<BBId> = [BBId(1)].into();
        let idf = dom.iterated_dominance_frontier(&cfg, &seed);
        assert!(idf.contains(&BBId(3)));
    }

    #[test]
    fn test_preorder_walk() {
        let cfg = linear_cfg(4);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let mut order = Vec::new();
        dom.preorder_walk(BBId(0), &mut order);
        assert_eq!(order, vec![BBId(0), BBId(1), BBId(2), BBId(3)]);
    }

    #[test]
    fn test_post_dominance_tree() {
        let cfg = linear_cfg(4);
        let pdom = DomTree::post_dominance_tree(&cfg);
        // In a linear CFG the post-dominator of every node is the exit (3).
        // Specifically: idom_post[2] should be Some(BBId(3)).
        assert!(pdom.idom[2].is_some());
    }

    #[test]
    fn test_depth() {
        let cfg = linear_cfg(5);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.depth(BBId(0)), 0);
        assert_eq!(dom.depth(BBId(1)), 1);
        assert_eq!(dom.depth(BBId(4)), 4);
    }

    #[test]
    fn test_empty_cfg() {
        let dom = DomTree::new(0);
        assert!(dom.idom.is_empty());
    }

    #[test]
    fn test_children_populated() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // Entry (0) should dominate 1, 2, and 3.
        assert!(dom.children[0].contains(&BBId(1)));
        assert!(dom.children[0].contains(&BBId(2)));
    }

    // ── link/eval not exported, tested indirectly via lengauer_tarjan ──────────

    #[test]
    fn test_out_of_range_successor_dropped_not_panicking() {
        // Node 0's successor list claims an edge to node 99, which does not
        // exist (n = 2). This must be silently dropped, not panic.
        let succs = vec![vec![BBId(1), BBId(99)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        assert_eq!(cfg.succ[0], vec![BBId(1)]);
        assert_eq!(cfg.pred.len(), 2); // out-of-range target never grew the block count
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.idom[1], Some(BBId(0)));
    }

    #[test]
    fn test_out_of_range_entry_does_not_panic() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        // Entry index 99 is out of range for a 2-node CFG.
        let dom = lengauer_tarjan(&cfg, BBId(99));
        assert_eq!(dom.node_count(), 2);
        assert!(dom.idom.iter().all(Option::is_none));
    }

    #[test]
    fn test_empty_cfg_entry_does_not_panic() {
        let cfg = Cfg::new(0, vec![], BBId(0), BBId(0));
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.node_count(), 0);
    }

    #[test]
    fn test_dominates_out_of_range_b_does_not_panic() {
        let cfg = linear_cfg(3);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert!(!dom.dominates(BBId(0), BBId(999)));
    }

    #[test]
    fn test_depth_out_of_range_node_does_not_panic() {
        let cfg = linear_cfg(3);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.depth(BBId(999)), 0);
    }

    #[test]
    fn test_loop_cfg() {
        // 0 → 1 → 2 → 1 (back edge), 2 → 3
        let succs = vec![vec![BBId(1)], vec![BBId(2)], vec![BBId(1), BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // 1 is dominated by 0.
        assert_eq!(dom.idom[1], Some(BBId(0)));
        // 2 is dominated by 1.
        assert_eq!(dom.idom[2], Some(BBId(1)));
    }
}

// ── DomTree extended API ──────────────────────────────────────────────────────

impl DomTree {
    /// Return all blocks dominated by `bb` (not including `bb` itself).
    #[must_use]
    pub fn dominated_by(&self, bb: BBId) -> Vec<BBId> {
        let mut result = Vec::new();
        let mut stack: Vec<BBId> = self.children.get(bb.0).cloned().unwrap_or_default();
        while let Some(node) = stack.pop() {
            result.push(node);
            if let Some(ch) = self.children.get(node.0) {
                stack.extend_from_slice(ch);
            }
        }
        result
    }

    /// Return `true` if `a` strictly dominates `b` (`a ≠ b` and `a` dominates `b`).
    #[must_use]
    pub fn strictly_dominates(&self, a: BBId, b: BBId) -> bool {
        a != b && self.dominates(a, b)
    }

    /// All ancestors of `bb` in the dominator tree (proper dominators), in order
    /// from immediate dominator to the entry.
    #[must_use]
    pub fn dominators_of(&self, mut bb: BBId) -> Vec<BBId> {
        let mut chain = Vec::new();
        while let Some(Some(parent)) = self.idom.get(bb.0) {
            chain.push(*parent);
            bb = *parent;
        }
        chain
    }

    /// Least common dominator of `a` and `b`.
    #[must_use]
    pub fn common_dominator(&self, a: BBId, b: BBId) -> Option<BBId> {
        let a_chain: std::collections::HashSet<usize> = std::iter::once(a.0)
            .chain(self.dominators_of(a).iter().map(|b| b.0))
            .collect();
        if a_chain.contains(&b.0) {
            return Some(b);
        }
        let mut cur = b;
        loop {
            if a_chain.contains(&cur.0) {
                return Some(cur);
            }
            match self.idom.get(cur.0) {
                Some(Some(parent)) => cur = *parent,
                _ => return None,
            }
        }
    }

    /// Total number of nodes in the dominator tree.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.idom.len()
    }

    /// Whether `bb` is a leaf in the dominator tree (no children).
    #[must_use]
    pub fn is_leaf(&self, bb: BBId) -> bool {
        self.children.get(bb.0).is_none_or(Vec::is_empty)
    }
}

// ── Cfg extended helpers ──────────────────────────────────────────────────────

impl Cfg {
    /// All successors of `bb`.
    #[must_use]
    pub fn successors(&self, bb: BBId) -> &[BBId] {
        self.succ.get(bb.0).map_or(&[], Vec::as_slice)
    }

    /// All predecessors of `bb`.
    #[must_use]
    pub fn predecessors(&self, bb: BBId) -> &[BBId] {
        self.pred.get(bb.0).map_or(&[], Vec::as_slice)
    }

    /// BFS reachable set from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: BBId) -> std::collections::HashSet<BBId> {
        use std::collections::VecDeque;
        let mut visited = std::collections::HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);
        while let Some(node) = queue.pop_front() {
            for &succ in self.successors(node) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Whether `bb` is unreachable from the entry.
    #[must_use]
    pub fn is_unreachable(&self, bb: BBId) -> bool {
        !self.reachable_from(self.entry).contains(&bb)
    }

    /// Reverse the CFG edges (for post-dominator computation).
    #[must_use]
    pub fn reverse(&self) -> Self {
        let n = self.succ.len();
        // In the reversed graph, old succs become preds and vice-versa.
        let rev_succ = self.pred.clone();
        let rev_pred = self.succ.clone();
        debug_assert_eq!(rev_succ.len(), n, "reversed CFG must preserve node count");
        debug_assert_eq!(rev_pred.len(), n, "reversed CFG must preserve node count");
        Self {
            succ: rev_succ,
            pred: rev_pred,
            entry: self.exit,
            exit: self.entry,
        }
    }
}

// ── DominanceFrontier extended ────────────────────────────────────────────────

impl DomTree {
    /// Compute the iterated dominance frontier (IDF / DF+) of a set of seed blocks.
    ///
    /// The IDF is the smallest set S such that `df(S) ⊆ S`.
    /// Used in Cytron's SSA construction algorithm for φ-node placement.
    #[must_use]
    pub fn iterated_dominance_frontier_vec(&self, cfg: &Cfg, seeds: &[BBId]) -> Vec<BBId> {
        let df = self.dominance_frontier(cfg);
        let mut result: std::collections::HashSet<BBId> = std::collections::HashSet::new();
        let mut worklist: std::collections::VecDeque<BBId> = seeds.iter().copied().collect();

        while let Some(b) = worklist.pop_front() {
            for &y in &df[b.0] {
                if result.insert(y) {
                    worklist.push_back(y);
                }
            }
        }

        let mut v: Vec<BBId> = result.into_iter().collect();
        v.sort_unstable_by_key(|b| b.0);
        v
    }
}

// ── Extended dominator-tree tests ─────────────────────────────────────────────

#[cfg(test)]
mod dom_extended_tests {
    use super::*;

    fn linear_cfg(n: usize) -> Cfg {
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        Cfg::new(n, succs, BBId(0), BBId(n - 1))
    }

    fn diamond_cfg() -> Cfg {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        Cfg::new(4, succs, BBId(0), BBId(3))
    }

    #[test]
    fn strictly_dominates_entry_over_all() {
        let cfg = linear_cfg(4);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert!(dom.strictly_dominates(BBId(0), BBId(3)));
        assert!(!dom.strictly_dominates(BBId(0), BBId(0)));
    }

    #[test]
    fn dominated_by_entry_is_all_others() {
        let cfg = linear_cfg(4);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let dominated = dom.dominated_by(BBId(0));
        assert_eq!(dominated.len(), 3); // blocks 1, 2, 3
    }

    #[test]
    fn dominators_of_linear() {
        let cfg = linear_cfg(4);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let chain = dom.dominators_of(BBId(3));
        // Dominator chain for block 3: [2, 1, 0].
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], BBId(2));
        assert_eq!(chain[2], BBId(0));
    }

    #[test]
    fn common_dominator_diamond() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let lcd = dom.common_dominator(BBId(1), BBId(2));
        assert_eq!(lcd, Some(BBId(0)));
    }

    #[test]
    fn common_dominator_same_block() {
        let cfg = linear_cfg(3);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // Common dominator of bb1 with itself is bb1.
        let lcd = dom.common_dominator(BBId(1), BBId(1));
        assert_eq!(lcd, Some(BBId(1)));
    }

    #[test]
    fn node_count_matches_cfg() {
        let cfg = linear_cfg(5);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.node_count(), 5);
    }

    #[test]
    fn is_leaf_for_exit_block() {
        let cfg = linear_cfg(3);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert!(dom.is_leaf(BBId(2)));
        assert!(!dom.is_leaf(BBId(0)));
    }

    #[test]
    fn cfg_reachable_from_entry() {
        let cfg = linear_cfg(4);
        let r = cfg.reachable_from(BBId(0));
        assert_eq!(r.len(), 4);
    }

    #[test]
    fn cfg_is_unreachable_isolated() {
        // Block 3 is disconnected.
        let succs = vec![vec![BBId(1)], vec![BBId(2)], vec![], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(2));
        assert!(cfg.is_unreachable(BBId(3)));
        assert!(!cfg.is_unreachable(BBId(0)));
    }

    #[test]
    fn cfg_reverse_swaps_edges() {
        let cfg = linear_cfg(3);
        let rev = cfg.reverse();
        // In reverse, old succ becomes pred.
        assert!(rev.succ[2].contains(&BBId(1)));
        assert!(rev.succ[1].contains(&BBId(0)));
    }

    #[test]
    fn iterated_dom_frontier_diamond() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // IDF of {bb1, bb2} should be {bb3}.
        let idf = dom.iterated_dominance_frontier_vec(&cfg, &[BBId(1), BBId(2)]);
        assert!(idf.contains(&BBId(3)));
    }

    #[test]
    fn iterated_dom_frontier_empty_seeds() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let idf = dom.iterated_dominance_frontier_vec(&cfg, &[]);
        assert!(idf.is_empty());
    }

    #[test]
    fn depth_is_zero_for_entry() {
        let cfg = linear_cfg(1);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.depth(BBId(0)), 0);
    }

    #[test]
    fn strictly_dominates_is_false_for_non_dom() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        // bb1 does NOT dominate bb2 in a diamond.
        assert!(!dom.strictly_dominates(BBId(1), BBId(2)));
    }

    // ── Coverage-gap tests ─────────────────────────────────────────────────────

    #[test]
    fn cfg_len_and_is_empty() {
        let cfg = linear_cfg(4);
        assert_eq!(cfg.len(), 4);
        assert!(!cfg.is_empty());
        let empty = Cfg::new(0, vec![], BBId(0), BBId(0));
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn cfg_successors_predecessors() {
        let cfg = diamond_cfg();
        assert_eq!(cfg.successors(BBId(0)), &[BBId(1), BBId(2)]);
        assert_eq!(cfg.predecessors(BBId(3)), &[BBId(1), BBId(2)]);
        // Out-of-range block returns empty slice, not a panic.
        assert!(cfg.successors(BBId(99)).is_empty());
        assert!(cfg.predecessors(BBId(99)).is_empty());
    }

    #[test]
    fn iterated_dominance_frontier_hashset_matches_vec_version() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let seed: HashSet<BBId> = [BBId(1), BBId(2)].into();
        let idf_set = dom.iterated_dominance_frontier(&cfg, &seed);
        let idf_vec = dom.iterated_dominance_frontier_vec(&cfg, &[BBId(1), BBId(2)]);
        let idf_vec_set: HashSet<BBId> = idf_vec.into_iter().collect();
        assert_eq!(idf_set, idf_vec_set);
        assert!(idf_set.contains(&BBId(3)));
    }

    #[test]
    fn iterated_dominance_frontier_hashset_loop() {
        // 0 → 1 → 2 → 1 (back edge), 2 → 3. Seed = {2} should pull in bb1
        // (loop header) via the dominance frontier.
        let succs = vec![vec![BBId(1)], vec![BBId(2)], vec![BBId(1), BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let seed: HashSet<BBId> = [BBId(2)].into();
        let idf = dom.iterated_dominance_frontier(&cfg, &seed);
        assert!(idf.contains(&BBId(1)));
    }

    #[test]
    fn iterated_dominance_frontier_hashset_empty_seed() {
        let cfg = diamond_cfg();
        let dom = lengauer_tarjan(&cfg, BBId(0));
        let idf = dom.iterated_dominance_frontier(&cfg, &HashSet::new());
        assert!(idf.is_empty());
    }

    #[test]
    fn common_dominator_disjoint_branches_returns_entry() {
        // A CFG with two independent diamonds hanging off entry: LCA of nodes
        // in unrelated subtrees must fall back to the shared root.
        let succs = vec![
            vec![BBId(1), BBId(2)],
            vec![BBId(3)],
            vec![BBId(4)],
            vec![],
            vec![],
        ];
        let cfg = Cfg::new(5, succs, BBId(0), BBId(0));
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.common_dominator(BBId(3), BBId(4)), Some(BBId(0)));
    }

    #[test]
    fn common_dominator_none_when_unrelated_trees() {
        // Two disconnected components: bb2 unreachable from entry, so it has
        // no idom chain reaching a shared ancestor with bb1.
        let succs = vec![vec![BBId(1)], vec![], vec![]];
        let cfg = Cfg::new(3, succs, BBId(0), BBId(1));
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert_eq!(dom.common_dominator(BBId(1), BBId(2)), None);
    }

    #[test]
    fn reverse_round_trip_preserves_edges() {
        let cfg = diamond_cfg();
        let rev = cfg.reverse();
        let back = rev.reverse();
        assert_eq!(back.succ, cfg.succ);
        assert_eq!(back.pred, cfg.pred);
        assert_eq!(back.entry, cfg.entry);
        assert_eq!(back.exit, cfg.exit);
    }

    #[test]
    fn dominated_by_leaf_is_empty() {
        let cfg = linear_cfg(3);
        let dom = lengauer_tarjan(&cfg, BBId(0));
        assert!(dom.dominated_by(BBId(2)).is_empty());
    }
}
