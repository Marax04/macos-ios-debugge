//! `cfg_dominators.rs` — Efficient dominator tree computation.
//!
//! Implements:
//! - Lengauer-Tarjan O(n α(n)) dominator algorithm
//! - Immediate dominator computation
//! - Dominance frontier and iterated DF (for phi placement)
//! - Post-dominator tree
//! - Extended queries: dominator path, LCA in dominator tree

use crate::{CfgEdge, ControlFlowGraph, DominatorTree, PostDominatorTree};
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Union-Find with path compression and union by rank (for LT α(n) part)
// ─────────────────────────────────────────────────────────────────────────────

/// A union-find data structure with path compression and union by rank.
pub struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
    /// The minimum-label node on the path (for Lengauer-Tarjan's EVAL function).
    label: Vec<usize>,
}

impl UnionFind {
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
            label: (0..n).collect(),
        }
    }

    /// FIND with path compression; returns the root.
    ///
    /// Implemented iteratively: a recursive walk-up-then-compress here would
    /// blow the stack on the long dominator chains produced by large
    /// straight-line functions (e.g. a linear run of thousands of blocks),
    /// which is exactly the adversarial/pathological shape this algorithm
    /// must tolerate.
    pub fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cur = x;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }

    /// EVAL from Lengauer-Tarjan: returns the vertex on the path from x to the
    /// root of its subtree with minimum semi-dominator.
    pub fn eval(&mut self, x: usize, semi: &[usize]) -> usize {
        if self.parent[x] == x {
            return self.label[x];
        }
        self.compress(x, semi);
        self.label[x]
    }

    /// Path-compress the chain from `x` up to (but not including) its root,
    /// updating `label` along the way to the minimum-semi node seen.
    ///
    /// Iterative rather than recursive for the same reason as [`Self::find`]:
    /// a long uncompressed chain (worst case, one per LT `eval` call before
    /// any compression happens) would otherwise recurse once per node and
    /// overflow the stack on large functions.
    fn compress(&mut self, x: usize, semi: &[usize]) {
        // Collect the chain from `x` up to (but not including) the root that
        // still needs compressing.
        let mut chain = Vec::new();
        let mut cur = x;
        while self.parent[self.parent[cur]] != self.parent[cur] {
            chain.push(cur);
            cur = self.parent[cur];
        }
        chain.push(cur);

        // Walk back down from the node nearest the root, propagating the
        // best label and re-parenting each node directly to the true root.
        let root = self.parent[self.parent[cur]];
        for &node in chain.iter().rev() {
            if semi[self.label[self.parent[node]]] < semi[self.label[node]] {
                self.label[node] = self.label[self.parent[node]];
            }
            self.parent[node] = root;
        }
    }

    /// LINK: unite the trees rooted at `v` and `w`.
    pub fn link(&mut self, v: usize, w: usize) {
        self.parent[w] = v;
        if self.rank[v] < self.rank[w] {
            let t = v;
            let _ = t;
        } else if self.rank[v] > self.rank[w] {
            // v stays root
        } else {
            self.rank[v] += 1;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LengauerTarjanDom — full Lengauer-Tarjan dominator computation
// ─────────────────────────────────────────────────────────────────────────────

/// Result of the Lengauer-Tarjan dominator algorithm.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LtDominatorResult {
    /// Immediate dominator for each node (in RPO index space).
    /// `idom[0]` is `None` (entry has no dominator).
    pub idom: Vec<Option<usize>>,
    /// DFS order: `dfs_order[rpo_index] = address`.
    pub dfs_order: Vec<Address>,
    /// Reverse map: address → RPO index.
    pub addr_to_index: HashMap<Address, usize>,
    /// Semi-dominator numbers.
    pub semi: Vec<usize>,
}

impl LtDominatorResult {
    /// Convert to the standard `DominatorTree` format.
    #[must_use]
    pub fn to_dominator_tree(&self) -> DominatorTree {
        let n = self.dfs_order.len();
        let mut idom_map: HashMap<Address, Option<Address>> = HashMap::new();
        let mut children: HashMap<Address, Vec<Address>> = HashMap::new();
        let mut frontiers: HashMap<Address, Vec<Address>> = HashMap::new();

        for i in 0..n {
            let addr = self.dfs_order[i];
            let parent = self.idom[i].map(|p| self.dfs_order[p]);
            idom_map.insert(addr, parent);
            children.entry(addr).or_default();
            frontiers.entry(addr).or_default();
        }

        for (&node, &parent_opt) in &idom_map {
            if let Some(parent) = parent_opt {
                children.entry(parent).or_default().push(node);
            }
        }
        // `idom_map` is a HashMap, so the push order above is nondeterministic
        // hash order; sort so `DominatorTree::dominated_by` gets a
        // reproducible result (same fix as in `lib.rs`).
        for kids in children.values_mut() {
            kids.sort_by_key(|a| a.0);
        }

        DominatorTree { idom: idom_map, children, frontiers }
    }

    /// Get the immediate dominator address of `addr`.
    #[must_use]
    pub fn idom_of(&self, addr: Address) -> Option<Address> {
        let idx = *self.addr_to_index.get(&addr)?;
        let idom_idx = self.idom[idx]?;
        Some(self.dfs_order[idom_idx])
    }

    /// Get the semi-dominator number of `addr`.
    #[must_use]
    pub fn semi_of(&self, addr: Address) -> Option<usize> {
        let idx = *self.addr_to_index.get(&addr)?;
        Some(self.semi[idx])
    }
}

/// Computes dominators using the Lengauer-Tarjan algorithm.
///
/// Time complexity: O(n α(n)) with path compression.
/// Reference: Lengauer & Tarjan, "A Fast Algorithm for Finding Dominators in a
/// Flowgraph", TOPLAS 1979.
pub struct LengauerTarjanDominator;

impl LengauerTarjanDominator {
    /// Compute the dominator tree for the given CFG.
    pub fn compute(cfg: &ControlFlowGraph) -> LtDominatorResult {
        let entry = cfg.entry;
        let n = cfg.blocks.len();
        if n == 0 {
            return LtDominatorResult::default();
        }

        // -- Step 1: DFS to number vertices --
        let mut dfs_order: Vec<Address> = Vec::with_capacity(n);
        let mut addr_to_index: HashMap<Address, usize> = HashMap::new();
        let mut succs_adj: HashMap<Address, Vec<Address>> = HashMap::new();
        let mut preds_adj: HashMap<Address, Vec<Address>> = HashMap::new();

        for b in cfg.blocks.keys() {
            succs_adj.entry(*b).or_default();
            preds_adj.entry(*b).or_default();
        }
        for edge in &cfg.edges {
            succs_adj.entry(edge.from).or_default().push(edge.to);
            preds_adj.entry(edge.to).or_default().push(edge.from);
        }

        // Iterative DFS. Track the DFS-tree parent for each discovered node.
        //
        // Lengauer-Tarjan numbers vertices in DFS *discovery* (preorder) order,
        // NOT reverse-postorder: the semidominator theorem and the EVAL/LINK
        // path-compression forest rely on a node's number being the order in
        // which it was first visited. Using RPO here silently computes wrong
        // immediate dominators on graphs where preorder and RPO diverge (found
        // by soundness_fuzz::dominator_implementations_agree_fuzz). Record the
        // preorder directly at discovery time.
        let mut visited = HashSet::new();
        let mut stack: Vec<(Address, usize)> = vec![(entry, 0)];
        visited.insert(entry);
        let mut preorder: Vec<Address> = vec![entry];
        let mut dfs_parent: HashMap<Address, Address> = HashMap::new();

        while let Some((node, idx)) = stack.last_mut() {
            let node = *node;
            let children = succs_adj.get(&node).map_or(&[][..], Vec::as_slice);
            if *idx < children.len() {
                let child = children[*idx];
                *idx += 1;
                if visited.insert(child) {
                    dfs_parent.insert(child, node);
                    preorder.push(child);
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
            }
        }
        // `dfs_order` was pre-allocated with capacity `n`; populate it now from
        // the DFS preorder so we keep that reservation and surface the DFS
        // discovery numbering via `LtDominatorResult::dfs_order`.
        dfs_order.extend(preorder.iter().copied());
        for (i, &addr) in dfs_order.iter().enumerate() {
            addr_to_index.insert(addr, i);
        }

        let n = dfs_order.len();
        if n == 0 {
            return LtDominatorResult::default();
        }

        // -- Step 2: Initialize --
        let mut semi: Vec<usize> = (0..n).collect(); // semi[v] = v initially
        let mut idom: Vec<Option<usize>> = vec![None; n];
        let mut bucket: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut uf = UnionFind::new(n);

        // Build predecessor list in index space.
        let mut preds_idx: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in &cfg.edges {
            if let (Some(&fi), Some(&ti)) = (addr_to_index.get(&edge.from), addr_to_index.get(&edge.to)) {
                preds_idx[ti].push(fi);
            }
        }

        // -- Steps 2-4: Compute semi-dominators and immediate dominators --
        for w in (1..n).rev() {
            // Step 2: Compute semi(w).
            for &v in &preds_idx[w] {
                let u = uf.eval(v, &semi);
                if semi[u] < semi[w] {
                    semi[w] = semi[u];
                }
            }

            // Add w to bucket of its semi-dominator.
            bucket[semi[w]].push(w);

            // Link w to its parent in the DFS tree (the node that discovered w).
            let parent = dfs_parent
                .get(&dfs_order[w])
                .and_then(|a| addr_to_index.get(a).copied());
            if let Some(p) = parent {
                uf.link(p, w);

                // Step 3: For each v in bucket[parent], compute idom(v).
                let bucket_copy = bucket[p].clone();
                bucket[p].clear();
                for v in bucket_copy {
                    let u = uf.eval(v, &semi);
                    idom[v] = if semi[u] < semi[v] { Some(u) } else { Some(p) };
                }
            }
        }

        // Drain any remaining buckets (nodes whose semi-dominator was an
        // ancestor that has no descendants of its own in the DFS tree): for
        // these, idom is the semi-dominator itself.
        for p in 0..n {
            let bucket_copy = std::mem::take(&mut bucket[p]);
            for v in bucket_copy {
                let u = uf.eval(v, &semi);
                idom[v] = if semi[u] < semi[v] { Some(u) } else { Some(p) };
            }
        }

        // Step 4: Adjust idoms.
        for w in 1..n {
            if let Some(d) = idom[w]
                && Some(d) != Some(semi[w]) {
                    idom[w] = idom[d];
                }
        }

        LtDominatorResult { idom, dfs_order, addr_to_index, semi }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominanceFrontierComputer — standard Cytron et al. algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Computes dominance frontiers from a dominator tree and CFG edges.
pub struct DominanceFrontierComputer;

impl DominanceFrontierComputer {
    /// Compute DF(n) for all n using the standard algorithm:
    ///   For each join point y (>1 predecessor), walk up from each predecessor
    ///   p toward idom(y), adding y to DF of each node on the path.
    #[must_use]
    pub fn compute(
        dom: &DominatorTree,
        edges: &[CfgEdge],
    ) -> HashMap<Address, Vec<Address>> {
        let mut df: HashMap<Address, Vec<Address>> = HashMap::new();
        for addr in dom.idom.keys() {
            df.entry(*addr).or_default();
        }

        for edge in edges {
            let join = edge.to;
            // Only process join points: blocks where idom is defined.
            if dom.idom.get(&join).is_none() {
                continue;
            }

            // Keep the "no immediate dominator" case as `None`. Collapsing it
            // onto `join` itself (`unwrap_or(join)`) made the walk stop one
            // node early whenever the join IS the entry: for a back edge to the
            // entry the ascent broke before entry could be added to its own
            // dominance frontier, and DF(entry) came out empty. By the
            // definition DF(n) = { y : n dominates a predecessor of y and n
            // does not strictly dominate y }, the entry does belong there.
            // The two sibling implementations (`DominatorTree::compute` in
            // lib.rs and `DominanceFrontier::build` in loop_analysis.rs) both
            // carry a comment documenting this same correction; this third
            // copy had been left behind.
            let join_idom: Option<Address> = dom.idom[&join];
            let mut runner = edge.from;
            loop {
                if !dom.strictly_dominates(runner, join) {
                    df.entry(runner).or_default().push(join);
                }
                match dom.idom.get(&runner).copied() {
                    Some(Some(parent)) => {
                        if parent == runner || Some(parent) == join_idom {
                            break;
                        }
                        runner = parent;
                    }
                    _ => break,
                }
            }
        }

        // Deduplicate.
        for set in df.values_mut() {
            set.sort_unstable_by_key(|a| a.0);
            set.dedup();
        }

        df
    }

    /// Compute iterated dominance frontier IDF(S) for a set of nodes S.
    #[must_use]
    pub fn iterated_frontier(
        df: &HashMap<Address, Vec<Address>>,
        seeds: &[Address],
    ) -> Vec<Address> {
        let mut result: HashSet<Address> = HashSet::new();
        let mut worklist: VecDeque<Address> = seeds.iter().copied().collect();
        while let Some(n) = worklist.pop_front() {
            if let Some(frontier) = df.get(&n) {
                for &f in frontier {
                    if result.insert(f) {
                        worklist.push_back(f);
                    }
                }
            }
        }
        let mut v: Vec<Address> = result.into_iter().collect();
        v.sort_unstable_by_key(|a| a.0);
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostDominatorComputer — efficient post-dominator tree
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the post-dominator tree by reversing the CFG.
///
/// A node `a` post-dominates `b` iff every path from `b` to any exit passes
/// through `a`. Computed by running the Lengauer-Tarjan algorithm on the
/// reversed CFG with a virtual exit node.
pub struct PostDominatorComputer;

impl PostDominatorComputer {
    /// Virtual exit address sentinel.
    const VIRTUAL_EXIT: u64 = u64::MAX;

    /// Compute the post-dominator tree.
    pub fn compute(cfg: &ControlFlowGraph) -> PostDominatorTree {
        let virtual_exit = Address::new(Self::VIRTUAL_EXIT);

        // Build reverse adjacency.
        let mut has_successor: HashSet<Address> = HashSet::new();
        for e in &cfg.edges {
            has_successor.insert(e.from);
        }

        // Add edges: real_exit → virtual_exit (in reverse: virtual_exit → real_exit).
        let mut rev_succs: HashMap<Address, Vec<Address>> = HashMap::new();
        rev_succs.entry(virtual_exit).or_default();
        // `cfg.blocks` is a HashMap; sort addresses before appending the
        // synthetic virtual_exit->real_exit edges so the DFS/RPO traversal
        // below (and hence the internal iteration order of the dominator
        // computation) is reproducible across runs.
        let mut block_addrs: Vec<Address> = cfg.blocks.keys().copied().collect();
        block_addrs.sort_by_key(|a| a.0);
        for addr in block_addrs {
            rev_succs.entry(addr).or_default();
            if !has_successor.contains(&addr) {
                // addr is a real exit: add virtual_exit → addr in the reversed graph.
                rev_succs.entry(virtual_exit).or_default().push(addr);
            }
        }
        for edge in &cfg.edges {
            // Reversed: edge.to → edge.from
            rev_succs.entry(edge.to).or_default().push(edge.from);
        }

        // Run Cooper et al. dominator algorithm on the reversed graph from virtual_exit.
        // Build RPO order for the reversed graph.
        let mut rpo: Vec<Address> = Vec::new();
        let mut visited = HashSet::new();
        let mut stack: Vec<(Address, usize)> = vec![(virtual_exit, 0)];
        visited.insert(virtual_exit);

        while let Some((node, idx)) = stack.last_mut() {
            let node = *node;
            let children = rev_succs.get(&node).map_or(&[][..], Vec::as_slice);
            if *idx < children.len() {
                let child = children[*idx];
                *idx += 1;
                if visited.insert(child) {
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
                rpo.push(node);
            }
        }
        rpo.reverse();

        let n = rpo.len();
        let index: HashMap<Address, usize> = rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // Build predecessors in the reversed graph (= original successors).
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (src_addr, succs) in &rev_succs {
            if let Some(&fi) = index.get(src_addr) {
                for succ in succs {
                    if let Some(&ti) = index.get(succ) {
                        preds[ti].push(fi);
                    }
                }
            }
        }

        // Cooper/Harvey/Kennedy iterative.
        let undef = usize::MAX;
        let mut idom = vec![undef; n];
        idom[0] = 0;

        let intersect = |mut a: usize, mut b: usize, idom: &[usize]| -> usize {
            while a != b {
                while a > b { a = idom[a]; }
                while b > a { b = idom[b]; }
            }
            a
        };

        let mut changed = true;
        while changed {
            changed = false;
            for b in 1..n {
                let mut new_idom = undef;
                for &p in &preds[b] {
                    if idom[p] == undef { continue; }
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

        // Convert to address space, stripping virtual exit.
        let idom_map: HashMap<Address, Option<Address>> = idom
            .iter()
            .enumerate()
            .filter_map(|(i, &d)| {
                let addr = rpo[i];
                if addr == virtual_exit { return None; }
                if d == undef { return None; }
                let parent = rpo[d];
                let parent_opt = if parent == virtual_exit { None } else { Some(parent) };
                Some((addr, parent_opt))
            })
            .collect();

        let mut children: HashMap<Address, Vec<Address>> = HashMap::new();
        for addr in idom_map.keys() {
            children.entry(*addr).or_default();
        }
        for (&node, &parent_opt) in &idom_map {
            if let Some(parent) = parent_opt {
                children.entry(parent).or_default().push(node);
            }
        }
        // See the analogous fix above / in `lib.rs`: `idom_map` is a
        // HashMap, so sort each child list for determinism.
        for kids in children.values_mut() {
            kids.sort_by_key(|a| a.0);
        }

        PostDominatorTree { idom: idom_map, children }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominatorTreeQueries — extended query API
// ─────────────────────────────────────────────────────────────────────────────

/// Extended queries over a dominator tree.
pub struct DominatorTreeQueries<'a> {
    tree: &'a DominatorTree,
}

impl<'a> DominatorTreeQueries<'a> {
    #[must_use]
    pub const fn new(tree: &'a DominatorTree) -> Self {
        Self { tree }
    }

    /// Returns the path from `node` to the root in the dominator tree.
    #[must_use]
    pub fn dom_path_to_root(&self, node: Address) -> Vec<Address> {
        let mut path = vec![node];
        let mut cur = node;
        while let Some(Some(parent)) = self.tree.idom.get(&cur).copied() {
            if parent == cur { break; }
            path.push(parent);
            cur = parent;
        }
        path
    }

    /// Lowest Common Ancestor (LCA) of `a` and `b` in the dominator tree.
    ///
    /// This is equivalent to the nearest common dominator.
    #[must_use]
    pub fn lca(&self, a: Address, b: Address) -> Option<Address> {
        let path_a = self.dom_path_to_root(a);
        let path_b = self.dom_path_to_root(b);

        let set_b: HashSet<Address> = path_b.iter().copied().collect();
        path_a.into_iter().find(|n| set_b.contains(n))
    }

    /// All ancestors of `node` in the dominator tree (the path from `node` to root,
    /// excluding `node` itself).
    #[must_use]
    pub fn ancestors(&self, node: Address) -> Vec<Address> {
        let mut path = self.dom_path_to_root(node);
        path.remove(0);
        path
    }

    /// Whether `a` and `b` are on the same dominator tree path (one dominates the other).
    #[must_use]
    pub fn are_comparable(&self, a: Address, b: Address) -> bool {
        self.tree.dominates(a, b) || self.tree.dominates(b, a)
    }

    /// Number of nodes in the subtree rooted at `node` in the dominator tree.
    #[must_use]
    pub fn subtree_size(&self, node: Address) -> usize {
        let dominated = self.tree.dominated_by(node);
        dominated.len() + 1 // include node itself
    }

    /// All siblings of `node` (nodes with the same immediate dominator).
    #[must_use]
    pub fn siblings(&self, node: Address) -> Vec<Address> {
        let parent = match self.tree.idom.get(&node).copied().flatten() {
            Some(p) => p,
            None => return Vec::new(),
        };
        self.tree
            .children
            .get(&parent)
            .map(|ch| ch.iter().filter(|&&c| c != node).copied().collect())
            .unwrap_or_default()
    }

    /// Dominance tree height (longest path from `node` to a leaf).
    ///
    /// Iterative (explicit-stack post-order) to avoid stack overflow on
    /// deep/adversarial dominator trees; same motivation as the union-find
    /// fix applied elsewhere in this file.
    #[must_use]
    pub fn height(&self, node: Address) -> u32 {
        enum Frame {
            Visit(Address),
            Compute(Address),
        }

        let mut heights: HashMap<Address, u32> = HashMap::new();
        let mut stack = vec![Frame::Visit(node)];

        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(n) => {
                    if heights.contains_key(&n) {
                        continue;
                    }
                    stack.push(Frame::Compute(n));
                    if let Some(children) = self.tree.children.get(&n) {
                        for &c in children {
                            stack.push(Frame::Visit(c));
                        }
                    }
                }
                Frame::Compute(n) => {
                    let h = self
                        .tree
                        .children
                        .get(&n)
                        .map(Vec::as_slice)
                        .unwrap_or(&[])
                        .iter()
                        .map(|c| heights.get(c).copied().unwrap_or(0) + 1)
                        .max()
                        .unwrap_or(0);
                    heights.insert(n, h);
                }
            }
        }

        heights.get(&node).copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhiPlacementHelper — IDF-based phi insertion points
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the set of blocks where phi functions must be placed
/// for a given set of definition sites.
///
/// Uses the standard IDF (iterated dominance frontier) criterion:
/// a phi is required for variable `v` at block `y` iff `y` ∈ `IDF(def_sites(v))`.
pub struct PhiPlacementHelper<'a> {
    df: &'a HashMap<Address, Vec<Address>>,
}

impl<'a> PhiPlacementHelper<'a> {
    #[must_use]
    pub const fn new(df: &'a HashMap<Address, Vec<Address>>) -> Self {
        Self { df }
    }

    /// Compute the minimal phi placement for a variable defined at `def_sites`.
    #[must_use]
    pub fn phi_sites(&self, def_sites: &[Address]) -> Vec<Address> {
        DominanceFrontierComputer::iterated_frontier(self.df, def_sites)
    }

    /// Compute phi placement for multiple variables simultaneously.
    /// Returns a map: block → set of variable indices that need a phi there.
    #[must_use]
    pub fn phi_sites_multi(
        &self,
        def_sites_per_var: &[Vec<Address>],
    ) -> HashMap<Address, Vec<usize>> {
        let mut result: HashMap<Address, Vec<usize>> = HashMap::new();
        for (var_idx, defs) in def_sites_per_var.iter().enumerate() {
            for phi_site in self.phi_sites(defs) {
                result.entry(phi_site).or_default().push(var_idx);
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, EdgeKind};
    use std::collections::HashMap;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn make_cfg(
        block_addrs: &[u64],
        edge_list: &[(u64, u64)],
        entry: u64,
    ) -> ControlFlowGraph {
        let mut blocks = HashMap::new();
        for &a in block_addrs {
            blocks.insert(addr(a), BasicBlock {
                start: addr(a), end: addr(a + 4), instructions: vec![],
            });
        }
        let edges: Vec<CfgEdge> = edge_list
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: addr(f), to: addr(t), kind: EdgeKind::Unconditional,
            })
            .collect();
        let dom_tree = DominatorTree::compute(&blocks, &edges, addr(entry));
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        ControlFlowGraph {
            blocks, edges, entry: addr(entry),
            dom_tree, loops: vec![], post_dom_tree,
        }
    }

    #[test]
    fn lt_dominator_linear_chain() {
        // 0 → 1 → 2 → 3
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0,1),(1,2),(2,3)], 0);
        let result = LengauerTarjanDominator::compute(&cfg);
        let dt = result.to_dominator_tree();
        // idom(1) = 0, idom(2) = 1, idom(3) = 2.
        assert_eq!(dt.idom[&addr(1)], Some(addr(0)));
        assert_eq!(dt.idom[&addr(2)], Some(addr(1)));
        assert_eq!(dt.idom[&addr(3)], Some(addr(2)));
    }

    #[test]
    fn lt_dominator_diamond() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let cfg = make_cfg(&[0,1,2,3], &[(0,1),(0,2),(1,3),(2,3)], 0);
        let result = LengauerTarjanDominator::compute(&cfg);
        let dt = result.to_dominator_tree();
        // idom(1) = 0, idom(2) = 0, idom(3) = 0.
        assert_eq!(dt.idom[&addr(1)], Some(addr(0)));
        assert_eq!(dt.idom[&addr(2)], Some(addr(0)));
        assert_eq!(dt.idom[&addr(3)], Some(addr(0)));
    }

    #[test]
    fn dominance_frontier_branch() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let cfg = make_cfg(&[0,1,2,3], &[(0,1),(0,2),(1,3),(2,3)], 0);
        let df = DominanceFrontierComputer::compute(&cfg.dom_tree, &cfg.edges);
        // DF(1) should contain 3 (join point).
        assert!(df[&addr(1)].contains(&addr(3)));
        assert!(df[&addr(2)].contains(&addr(3)));
    }

    #[test]
    fn iterated_frontier() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3, 3 → 4
        let cfg = make_cfg(&[0,1,2,3,4], &[(0,1),(0,2),(1,3),(2,3),(3,4)], 0);
        let df = DominanceFrontierComputer::compute(&cfg.dom_tree, &cfg.edges);
        let idf = DominanceFrontierComputer::iterated_frontier(&df, &[addr(1)]);
        assert!(idf.contains(&addr(3)));
    }

    /// Differential: `DominatorTreeQueries::lca(a, b)` must equal the DEEPEST
    /// node that dominates both `a` and `b` (brute-forced via `dominates`),
    /// over random CFGs. Guards the query layer against the dominator-tree
    /// internals (which the Lengauer-Tarjan preorder-numbering fix just
    /// touched).
    #[test]
    fn lca_matches_deepest_common_dominator_fuzz() {
        use crate::test_prng::xorshift as xs;
        let mut state = 0x5eed_1234_dead_c0deu64;
        for _ in 0..800 {
            let n = 2 + (xs(&mut state) % 7); // 2..=8 nodes
            let blocks: Vec<u64> = (0..n).collect();
            let mut edges: Vec<(u64, u64)> = Vec::new();
            for u in 0..n {
                for v in 0..n {
                    if u != v && xs(&mut state) % 100 < 35 {
                        edges.push((u, v));
                    }
                }
            }
            // Guarantee every node is reachable from entry 0 (chain fallback),
            // so the dominator tree covers all of them.
            for u in 1..n {
                edges.push((u - 1, u));
            }
            let cfg = make_cfg(&blocks, &edges, 0);
            let q = DominatorTreeQueries::new(&cfg.dom_tree);
            let depth = |node: u64| q.dom_path_to_root(addr(node)).len();
            for &a in &blocks {
                for &b in &blocks {
                    // Deepest common dominator by brute force.
                    let mut best: Option<u64> = None;
                    let mut best_depth = 0usize;
                    for &d in &blocks {
                        if cfg.dom_tree.dominates(addr(d), addr(a))
                            && cfg.dom_tree.dominates(addr(d), addr(b))
                        {
                            let dd = depth(d);
                            if best.is_none() || dd > best_depth {
                                best = Some(d);
                                best_depth = dd;
                            }
                        }
                    }
                    let got = q.lca(addr(a), addr(b)).map(|x| x.as_u64());
                    assert_eq!(
                        got, best,
                        "lca({a},{b})={got:?} but deepest common dominator={best:?}; edges={edges:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn dom_tree_queries_lca() {
        // 0 → 1 → 3, 0 → 2 → 3
        let cfg = make_cfg(&[0,1,2,3], &[(0,1),(0,2),(1,3),(2,3)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        // LCA of 1 and 2 should be 0 (both dominated by 0).
        assert_eq!(queries.lca(addr(1), addr(2)), Some(addr(0)));
    }

    #[test]
    fn dom_tree_queries_subtree_size() {
        // 0 → 1 → 2
        let cfg = make_cfg(&[0,1,2], &[(0,1),(1,2)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        // Subtree of 0 includes 0, 1, 2.
        assert_eq!(queries.subtree_size(addr(0)), 3);
        assert_eq!(queries.subtree_size(addr(1)), 2);
        assert_eq!(queries.subtree_size(addr(2)), 1);
    }

    #[test]
    fn dom_tree_queries_ancestors() {
        let cfg = make_cfg(&[0,1,2,3], &[(0,1),(1,2),(2,3)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        let anc = queries.ancestors(addr(3));
        assert!(anc.contains(&addr(0)));
        assert!(anc.contains(&addr(1)));
        assert!(anc.contains(&addr(2)));
    }

    #[test]
    fn dom_tree_queries_height_basic() {
        // 0 → 1 → 2, 0 → 3.  Height(0) = 2 (via 0→1→2), height(1) = 1,
        // height(2) = 0 (leaf), height(3) = 0 (leaf).
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (0, 3)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        assert_eq!(queries.height(addr(2)), 0);
        assert_eq!(queries.height(addr(3)), 0);
        assert_eq!(queries.height(addr(1)), 1);
        assert_eq!(queries.height(addr(0)), 2);
    }

    #[test]
    fn dom_tree_queries_height_deep_chain_no_stack_overflow() {
        // A long linear dominator chain used to blow the native call stack
        // with the recursive `height` implementation; verify the iterative
        // version handles it and returns the exact expected height.
        const N: u64 = 50_000;
        let block_addrs: Vec<u64> = (0..N).collect();
        let edges: Vec<(u64, u64)> = (0..N - 1).map(|i| (i, i + 1)).collect();
        let cfg = make_cfg(&block_addrs, &edges, 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        assert_eq!(queries.height(addr(0)), (N - 1) as u32);
        assert_eq!(queries.height(addr(N - 1)), 0);
    }

    #[test]
    fn phi_placement_helper() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let cfg = make_cfg(&[0,1,2,3], &[(0,1),(0,2),(1,3),(2,3)], 0);
        let df = DominanceFrontierComputer::compute(&cfg.dom_tree, &cfg.edges);
        let helper = PhiPlacementHelper::new(&df);
        // Variable defined in blocks 1 and 2; phi needed at 3.
        let sites = helper.phi_sites(&[addr(1), addr(2)]);
        assert!(sites.contains(&addr(3)));
    }

    #[test]
    fn post_dominator_linear() {
        // 0 → 1 → 2 (exit)
        let cfg = make_cfg(&[0,1,2], &[(0,1),(1,2)], 0);
        // 2 post-dominates everything.
        assert!(cfg.post_dom_tree.post_dominates(addr(2), addr(0)));
        assert!(cfg.post_dom_tree.post_dominates(addr(2), addr(1)));
        assert!(cfg.post_dom_tree.post_dominates(addr(2), addr(2)));
    }

    #[test]
    fn lt_dominator_idom_of_and_semi_of() {
        // 0 → 1 → 2 → 3
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)], 0);
        let result = LengauerTarjanDominator::compute(&cfg);
        assert_eq!(result.idom_of(addr(3)), Some(addr(2)));
        assert_eq!(result.idom_of(addr(1)), Some(addr(0)));
        // Entry has no dominator.
        assert_eq!(result.idom_of(addr(0)), None);
        // Unknown address is not present at all.
        assert_eq!(result.idom_of(addr(999)), None);
        // semi(0) == 0 (root is its own semi-dominator); every other node's
        // semi-dominator index must be a valid RPO index.
        assert_eq!(result.semi_of(addr(0)), Some(0));
        assert!(result.semi_of(addr(3)).is_some());
        assert_eq!(result.semi_of(addr(999)), None);
    }

    #[test]
    fn dom_tree_queries_are_comparable() {
        // 0 → 1 → 3, 0 → 2 → 3: 1 and 2 are incomparable (neither dominates
        // the other), but 0 and 3 are each comparable with everything.
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        assert!(!queries.are_comparable(addr(1), addr(2)));
        assert!(queries.are_comparable(addr(0), addr(1)));
        assert!(queries.are_comparable(addr(0), addr(3)));
        assert!(queries.are_comparable(addr(1), addr(1)));
    }

    #[test]
    fn dom_tree_queries_siblings() {
        // 0 → 1, 0 → 2, 0 → 3: 1, 2, 3 all share idom 0, so each other node
        // is a sibling of each.
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (0, 2), (0, 3)], 0);
        let queries = DominatorTreeQueries::new(&cfg.dom_tree);
        let sibs = queries.siblings(addr(1));
        assert!(sibs.contains(&addr(2)));
        assert!(sibs.contains(&addr(3)));
        assert!(!sibs.contains(&addr(1)));
        // The root has no idom, hence no siblings.
        assert!(queries.siblings(addr(0)).is_empty());
    }

    #[test]
    fn phi_placement_helper_multi_variable() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3: var A defined at 1, var B defined at 2;
        // both need a phi at the join block 3.
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        let df = DominanceFrontierComputer::compute(&cfg.dom_tree, &cfg.edges);
        let helper = PhiPlacementHelper::new(&df);
        let result = helper.phi_sites_multi(&[vec![addr(1)], vec![addr(2)]]);
        let vars_at_3 = result.get(&addr(3)).cloned().unwrap_or_default();
        assert!(vars_at_3.contains(&0));
        assert!(vars_at_3.contains(&1));
    }

    #[test]
    fn post_dominator_diamond() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3: 3 post-dominates everything, but 1 and
        // 2 do not post-dominate 0 (0 can reach the exit via the other arm).
        let cfg = make_cfg(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)], 0);
        assert!(cfg.post_dom_tree.post_dominates(addr(3), addr(0)));
        assert!(cfg.post_dom_tree.post_dominates(addr(3), addr(1)));
        assert!(!cfg.post_dom_tree.post_dominates(addr(1), addr(0)));
        assert!(!cfg.post_dom_tree.post_dominates(addr(2), addr(0)));
    }

    #[test]
    fn union_find_operations() {
        let semi = vec![0, 1, 2, 3];
        let mut uf = UnionFind::new(4);
        uf.link(0, 1);
        let v = uf.eval(1, &semi);
        // After link(0,1), eval(1) should find minimum label.
        let _ = v;
    }

    #[test]
    fn union_find_find_and_compress_do_not_overflow_on_long_chains() {
        // A long chain 0 <- 1 <- 2 <- ... <- (n-1) (each i linked under i-1)
        // exercises the iterative find/compress path; a naive recursive
        // implementation would blow the stack here.
        const N: usize = 200_000;
        let semi: Vec<usize> = (0..N).collect();
        let mut uf = UnionFind::new(N);
        for i in 1..N {
            uf.link(i - 1, i);
        }
        // find() should resolve all the way to the true root without panicking.
        assert_eq!(uf.find(N - 1), 0);
        // eval() drives compress(); must also not panic and must yield a
        // sane (in-range) label.
        let label = uf.eval(N - 1, &semi);
        assert!(label < N);
    }

    #[test]
    fn lt_dominator_long_linear_chain_no_stack_overflow() {
        // A large straight-line function is a pathological shape for a
        // recursive dominator implementation (both the DFS and the
        // union-find find/compress); make sure it completes.
        const N: u64 = 50_000;
        let addrs: Vec<u64> = (0..N).collect();
        let edges: Vec<(u64, u64)> = (0..N - 1).map(|i| (i, i + 1)).collect();
        let cfg = make_cfg(&addrs, &edges, 0);
        let result = LengauerTarjanDominator::compute(&cfg);
        let dt = result.to_dominator_tree();
        for i in 1..N {
            assert_eq!(dt.idom[&addr(i)], Some(addr(i - 1)));
        }
    }
}
