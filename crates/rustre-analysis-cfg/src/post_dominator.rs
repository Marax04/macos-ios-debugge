//! Post-dominator tree for a CFG.
//!
//! The post-dominator tree is computed by reversing all edges and all exit
//! nodes of the CFG (treating the "virtual exit" as entry) and then running
//! the standard dominator algorithm.
//!
//! A node `a` post-dominates `b` if every path from `b` to any exit passes
//! through `a`.

use crate::{BasicBlock, CfgEdge, DominatorTree, EdgeKind};
use rustre_core::address::Address;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// FullPostDomTree
// ─────────────────────────────────────────────────────────────────────────────

/// Post-dominator tree for a CFG.
///
/// The immediate post-dominator of a node `n` is the unique node that
/// immediately post-dominates `n` on every path to an exit.
#[derive(Debug, Clone, Default)]
pub struct FullPostDomTree {
    /// Immediate post-dominator of each node.  `None` = exit (no post-dom).
    pub idom: HashMap<Address, Option<Address>>,
    /// Children in the post-dominator tree.
    pub children: HashMap<Address, Vec<Address>>,
}

impl FullPostDomTree {
    /// Compute the post-dominator tree for the CFG.
    ///
    /// `blocks` is the set of all blocks; `edges` is the set of all CFG edges;
    /// `exits` is the set of blocks that have no successors (the exit nodes).
    /// A virtual exit node is synthesized when there are multiple exits.
    #[must_use]
    pub fn compute(
        blocks: &HashMap<Address, BasicBlock>,
        edges: &[CfgEdge],
        exits: &[Address],
    ) -> Self {
        if blocks.is_empty() || exits.is_empty() {
            return Self::default();
        }

        // Choose or synthesize the entry for post-dom computation.
        // If there is exactly one exit, use it directly; otherwise create a
        // virtual exit whose address is u64::MAX - 1.
        let virtual_exit = Address(u64::MAX - 1);
        let pdom_entry = if exits.len() == 1 {
            exits[0]
        } else {
            virtual_exit
        };

        // Build reversed edges: for each CFG edge a→b, add a reversed edge b→a.
        // Also if exits.len() > 1, add virtual_exit→exit for each exit.
        let mut rev_edges: Vec<CfgEdge> = edges
            .iter()
            .map(|e| CfgEdge {
                from: e.to,
                to: e.from,
                kind: EdgeKind::Unconditional,
            })
            .collect();

        // Build a synthetic "blocks" set for the reversed graph that includes
        // the virtual exit if needed.
        let mut rev_blocks: HashMap<Address, BasicBlock> = blocks.clone();

        if exits.len() > 1 {
            // Connect each exit to the virtual exit.
            for &exit in exits {
                rev_edges.push(CfgEdge {
                    from: virtual_exit,
                    to: exit,
                    kind: EdgeKind::Unconditional,
                });
            }
            // Add virtual exit as a block with no instructions.
            rev_blocks.insert(
                virtual_exit,
                BasicBlock {
                    start: virtual_exit,
                    end: virtual_exit,
                    instructions: vec![],
                },
            );
        }

        // Run forward dominator algorithm on reversed graph.
        let dom = DominatorTree::compute(&rev_blocks, &rev_edges, pdom_entry);

        // Transfer idom and children (renaming virtual_exit back to None if used).
        let idom = dom
            .idom
            .into_iter()
            .filter(|(addr, _)| *addr != virtual_exit)
            .map(|(addr, idom_opt)| {
                let mapped = idom_opt.and_then(|d| if d == virtual_exit { None } else { Some(d) });
                (addr, mapped)
            })
            .collect();

        let children: HashMap<Address, Vec<Address>> = dom
            .children
            .into_iter()
            .filter(|(addr, _)| *addr != virtual_exit)
            .map(|(addr, kids)| {
                let filtered = kids.into_iter().filter(|&k| k != virtual_exit).collect();
                (addr, filtered)
            })
            .collect();

        Self { idom, children }
    }

    /// Return the immediate post-dominator of `node`, or `None` for exit nodes.
    #[must_use]
    pub fn ipost_dom(&self, node: Address) -> Option<Address> {
        self.idom.get(&node).copied().flatten()
    }

    /// Return `true` if `a` post-dominates `b`.
    #[must_use]
    pub fn post_dominates(&self, a: Address, b: Address) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        while let Some(Some(parent)) = self.idom.get(&cur) {
            if *parent == a {
                return true;
            }
            if *parent == cur {
                return false;
            }
            cur = *parent;
        }
        false
    }

    /// Return `true` if `a` strictly post-dominates `b`.
    #[must_use]
    pub fn strictly_post_dominates(&self, a: Address, b: Address) -> bool {
        a != b && self.post_dominates(a, b)
    }

    /// Return all nodes that are post-dominated by `node`.
    #[must_use]
    pub fn post_dominated_by(&self, node: Address) -> Vec<Address> {
        let mut result = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if let Some(kids) = self.children.get(&n) {
                for &k in kids {
                    result.push(k);
                    stack.push(k);
                }
            }
        }
        result
    }

    /// Find the control dependence region: nodes that are control-dependent on `pred`.
    ///
    /// Node `y` is control-dependent on `x` when there is an edge `x → z` such
    /// that `y` post-dominates `z` but `y` does not strictly post-dominate `x`
    /// (Ferrante–Ottenstein–Warren). Equivalently: walk up the post-dominator
    /// tree from each successor of `x`, stopping at `ipdom(x)`.
    ///
    /// `edges` must be the CFG edges. They are genuinely required: the previous
    /// signature took the full node list instead and never looked at `pred`'s
    /// successors at all, so it returned every node that merely failed to
    /// post-dominate `pred` — including nodes executed strictly BEFORE `pred`,
    /// which cannot depend on its branch. `ControlDependenceGraph::build` in
    /// `cfg_algorithms.rs` already did this walk correctly.
    #[must_use]
    pub fn control_dependent_on(&self, pred: Address, edges: &[CfgEdge]) -> Vec<Address> {
        // Stop at the immediate post-dominator of `pred`: it is reached on
        // every path out of `pred`, so nothing from there upwards depends on
        // which way the branch went.
        let stop_at = self.ipost_dom(pred);
        let mut out: Vec<Address> = Vec::new();
        for edge in edges.iter().filter(|e| e.from == pred) {
            let mut y = edge.to;
            loop {
                if Some(y) == stop_at {
                    break;
                }
                if !out.contains(&y) {
                    out.push(y);
                }
                match self.idom.get(&y).copied().flatten() {
                    Some(parent) if parent != y => y = parent,
                    _ => break,
                }
            }
        }
        out.sort_unstable_by_key(|a| a.0);
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BasicBlock;

    fn a(n: u64) -> Address {
        Address(n)
    }

    fn make_block(addr: u64) -> BasicBlock {
        BasicBlock {
            start: a(addr),
            end: a(addr + 1),
            instructions: vec![],
        }
    }

    fn make_blocks(addrs: &[u64]) -> HashMap<Address, BasicBlock> {
        addrs.iter().map(|&n| (a(n), make_block(n))).collect()
    }

    fn make_edges(pairs: &[(u64, u64)]) -> Vec<CfgEdge> {
        pairs
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect()
    }

    fn exits_of(blocks: &[u64], edges: &[(u64, u64)]) -> Vec<Address> {
        let has_succ: std::collections::HashSet<u64> = edges.iter().map(|&(f, _)| f).collect();
        blocks
            .iter()
            .filter(|&&n| !has_succ.contains(&n))
            .map(|&n| a(n))
            .collect()
    }

    #[test]
    fn test_post_dom_chain() {
        // 0→1→2 (exit)
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (1, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);

        // 2 post-dominates everything
        assert!(pdt.post_dominates(a(2), a(0)));
        assert!(pdt.post_dominates(a(2), a(1)));
        assert!(pdt.post_dominates(a(2), a(2)));
    }

    #[test]
    fn test_post_dom_strictly() {
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (1, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        assert!(pdt.strictly_post_dominates(a(2), a(0)));
        assert!(!pdt.strictly_post_dominates(a(2), a(2)));
    }

    #[test]
    fn test_post_dom_diamond() {
        // 0→1, 0→2, 1→3, 2→3 (3 is exit)
        let blocks = [0u64, 1, 2, 3];
        let edge_pairs = [(0u64, 1), (0, 2), (1, 3), (2, 3)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);

        // 3 post-dominates all
        assert!(pdt.post_dominates(a(3), a(0)));
        assert!(pdt.post_dominates(a(3), a(1)));
        assert!(pdt.post_dominates(a(3), a(2)));
    }

    #[test]
    fn test_post_dom_ipost_dom_chain() {
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (1, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        // ipost_dom(0) should be 1, ipost_dom(1) should be 2
        assert_eq!(pdt.ipost_dom(a(0)), Some(a(1)));
        assert_eq!(pdt.ipost_dom(a(1)), Some(a(2)));
        assert_eq!(pdt.ipost_dom(a(2)), None);
    }

    #[test]
    fn test_post_dom_post_dominated_by() {
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (1, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        let pdb = pdt.post_dominated_by(a(2));
        // 2 is the exit; in the post-dom tree it should be the root
        // post_dominated_by returns children, which for root is empty or 0,1
        assert!(pdb.contains(&a(0)) || pdb.is_empty());
    }

    #[test]
    fn test_post_dom_empty_blocks() {
        let pdt = FullPostDomTree::compute(&HashMap::new(), &[], &[]);
        assert!(pdt.idom.is_empty());
    }

    #[test]
    fn test_post_dom_multiple_exits() {
        // 0→1, 0→2  (both 1 and 2 are exits)
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (0, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        // Should not panic with multiple exits
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        assert!(!pdt.idom.is_empty());
        // Neither exit block should reference the synthetic virtual exit.
        let virtual_exit = Address(u64::MAX - 1);
        assert!(!pdt.idom.contains_key(&virtual_exit));
        for kids in pdt.children.values() {
            assert!(!kids.contains(&virtual_exit));
        }
        // 0 is dominated by neither exit alone; its immediate post-dominator
        // is the virtual exit, which surfaces as `None`.
        assert_eq!(pdt.ipost_dom(a(0)), None);
    }

    // ── post_dominated_by ─────────────────────────────────────────────────

    #[test]
    fn test_post_dom_post_dominated_by_diamond() {
        // 0→1, 0→2, 1→3, 2→3 (3 is exit)
        let blocks = [0u64, 1, 2, 3];
        let edge_pairs = [(0u64, 1), (0, 2), (1, 3), (2, 3)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        // 3 immediately post-dominates 0, 1, 2 (each has only one path to
        // exit, all passing straight through 3).
        let pdb = pdt.post_dominated_by(a(3));
        assert!(pdb.contains(&a(0)));
        assert!(pdb.contains(&a(1)));
        assert!(pdb.contains(&a(2)));
        assert_eq!(pdb.len(), 3);
    }

    // ── control_dependent_on ──────────────────────────────────────────────

    #[test]
    fn test_control_dependent_on_diamond() {
        // 0→1, 0→2, 1→3, 2→3 (3 is exit). Both 1 and 2 are control-dependent
        // on the branch at 0; 3 (the merge point) is not.
        let blocks = [0u64, 1, 2, 3];
        let edge_pairs = [(0u64, 1), (0, 2), (1, 3), (2, 3)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        let deps = pdt.control_dependent_on(a(0), &e);
        assert!(deps.contains(&a(1)));
        assert!(deps.contains(&a(2)));
        assert!(!deps.contains(&a(3)));
    }

    #[test]
    fn test_control_dependent_on_chain_is_empty_downstream() {
        // 0→1→2 (2 is exit): a straight chain has no branch, so nothing
        // beyond the immediate post-dominator is control-dependent on 0.
        let blocks = [0u64, 1, 2];
        let edge_pairs = [(0u64, 1), (1, 2)];
        let b = make_blocks(&blocks);
        let e = make_edges(&edge_pairs);
        let exits = exits_of(&blocks, &edge_pairs);
        let pdt = FullPostDomTree::compute(&b, &e, &exits);
        let deps = pdt.control_dependent_on(a(0), &e);
        // 1 is the immediate post-dominator of 0, and 2 is post-dominated by
        // 0's ipdom, so neither should be reported as control-dependent.
        assert!(!deps.contains(&a(1)));
        assert!(!deps.contains(&a(2)));
    }
}
