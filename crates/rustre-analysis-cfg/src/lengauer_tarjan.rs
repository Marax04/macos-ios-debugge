//! Lengauer-Tarjan semi-dominator / immediate-dominator algorithm (1979).
//!
//! This is an efficient O(N α(N)) implementation that is faster than the
//! Cooper et al. iterative bit-vector approach on large CFGs.  It computes
//! the same immediate-dominator mapping and is exported alongside the existing
//! `DominatorTree`.
//!
//! Reference: "A Fast Algorithm for Finding Dominators in a Flowgraph",
//! T. Lengauer and R. E. Tarjan, 1979.

use rustre_core::address::Address;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Internal index-space structures
// ─────────────────────────────────────────────────────────────────────────────

/// Output of the Lengauer-Tarjan algorithm: maps each node to its immediate
/// dominator.  The entry node maps to `None`.
#[derive(Debug, Clone, Default)]
pub struct LtDomTree {
    /// `idom[n] == None` → entry node.
    pub idom: HashMap<Address, Option<Address>>,
}

impl LtDomTree {
    /// Returns `true` if `a` dominates `b` (walks the idom chain).
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
                return false;
            }
            cur = *parent;
        }
        false
    }

    /// Immediate dominator of `node`, or `None` for the entry.
    #[must_use]
    pub fn idom_of(&self, node: Address) -> Option<Address> {
        self.idom.get(&node).copied().flatten()
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

    /// All nodes whose immediate dominator is `node`.
    #[must_use]
    pub fn children_of(&self, node: Address) -> Vec<Address> {
        self.idom
            .iter()
            .filter_map(|(&k, &v)| if v == Some(node) { Some(k) } else { None })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lengauer-Tarjan implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Lengauer-Tarjan dominator tree for a CFG.
///
/// * `nodes`    — complete set of node addresses.
/// * `succs`    — adjacency list (address → successors).
/// * `entry`    — CFG entry address.
///
/// Returns `None` if `entry` is not in `nodes`.
#[must_use]
pub fn compute_lt<S: ::std::hash::BuildHasher>(
    nodes: &[Address],
    succs: &HashMap<Address, Vec<Address>, S>,
    entry: Address,
) -> Option<LtDomTree> {
    if !nodes.contains(&entry) {
        return None;
    }

    let n = nodes.len();
    // Map Address → index.
    let addr_to_idx: HashMap<Address, usize> =
        nodes.iter().enumerate().map(|(i, &a)| (a, i)).collect();

    let entry_idx = *addr_to_idx.get(&entry)?;

    // Arrays indexed by node index (n = total nodes).
    let mut semi = vec![usize::MAX; n]; // semi-dominator (index)
    let mut idom = vec![usize::MAX; n]; // immediate dominator (index)
    let mut parent = vec![usize::MAX; n]; // DFS parent
    let mut vertex = vec![usize::MAX; n]; // DFS order
    let mut label = (0..n).collect::<Vec<_>>(); // for path compression
    let mut ancestor: Vec<usize> = (0..n).collect();
    let mut dfs_num = vec![usize::MAX; n]; // DFS visit order
    let mut bucket: Vec<Vec<usize>> = vec![vec![]; n];

    // Build predecessor lists (needed for the Lengauer-Tarjan algorithm).
    let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
    for (&from, tos) in succs {
        if let Some(&fi) = addr_to_idx.get(&from) {
            for &to in tos {
                if let Some(&ti) = addr_to_idx.get(&to) {
                    preds[ti].push(fi);
                }
            }
        }
    }

    // ── Step 1: DFS ─────────────────────────────────────────────────────────
    let mut counter = 0usize;
    let mut stack = vec![(entry_idx, usize::MAX, false)];

    while let Some((v, par, processed)) = stack.last().copied() {
        if processed {
            stack.pop();
            continue;
        }
        // Mark as being processed
        let last = stack.last_mut().unwrap();
        last.2 = true;

        if dfs_num[v] == usize::MAX {
            dfs_num[v] = counter;
            vertex[counter] = v;
            semi[v] = counter;
            parent[v] = par;
            counter += 1;

            if let Some(ch) = succs.get(&nodes[v]) {
                for &next in ch.iter().rev() {
                    if let Some(&ni) = addr_to_idx.get(&next) && dfs_num[ni] == usize::MAX {
                        stack.push((ni, v, false));
                    }
                }
            }
        }
    }

    let dfs_count = counter;

    // ── Step 2 & 3 (combined): compute semi-dominators and bucket ────────────
    // Process vertices in reverse DFS order (skip entry).
    for i in (1..dfs_count).rev() {
        let w = vertex[i];

        // Step 2: compute semi(w).
        for &v in &preds[w] {
            if dfs_num[v] == usize::MAX {
                continue;
            }
            let u = eval(v, &mut ancestor, &mut semi, &mut label);
            if semi[u] < semi[w] {
                semi[w] = semi[u];
            }
        }

        // Add w to bucket of vertex[semi[w]].
        let sv = vertex[semi[w]];
        bucket[sv].push(w);

        // Link w to its parent in the forest.
        link(parent[w], w, &mut ancestor);

        // Step 3: process bucket of parent[w].
        let par = parent[w];
        if par == usize::MAX {
            continue;
        }
        let bucket_p: Vec<usize> = std::mem::take(&mut bucket[par]);
        for v in bucket_p {
            let u = eval(v, &mut ancestor, &mut semi, &mut label);
            idom[v] = if semi[u] < semi[v] { u } else { par };
        }
    }

    // ── Step 4: adjust immediate dominators ──────────────────────────────────
    for i in 1..dfs_count {
        let w = vertex[i];
        if idom[w] != vertex[semi[w]] {
            let dom_idom = idom[idom[w]];
            if dom_idom != usize::MAX {
                idom[w] = dom_idom;
            }
        }
    }
    idom[entry_idx] = usize::MAX; // entry has no dominator

    // ── Convert back to Address space ─────────────────────────────────────────
    let mut result: HashMap<Address, Option<Address>> = HashMap::new();
    for __item in vertex.iter().take(dfs_count) {
        let v = *__item;
        let addr = nodes[v];
        if v == entry_idx {
            result.insert(addr, None);
        } else if idom[v] == usize::MAX {
            // Unreachable from entry — skip.
        } else {
            result.insert(addr, Some(nodes[idom[v]]));
        }
    }

    Some(LtDomTree { idom: result })
}

// ── Path-compression helpers ─────────────────────────────────────────────────

fn eval(
    v: usize,
    ancestor: &mut [usize],
    semi: &mut [usize],
    label: &mut [usize],
) -> usize {
    if ancestor[v] == v {
        return label[v];
    }
    compress(v, ancestor, semi, label);
    label[v]
}

fn compress(v: usize, ancestor: &mut [usize], semi: &mut [usize], label: &mut [usize]) {
    let mut path = Vec::new();
    let mut cur = v;
    while ancestor[cur] != cur {
        path.push(cur);
        cur = ancestor[cur];
    }
    // Process path in reverse (path compression).
    let root = cur;
    let mut min_semi_label = label[root];
    for &node in path.iter().rev() {
        if semi[label[node]] > semi[min_semi_label] {
            label[node] = min_semi_label;
        } else {
            min_semi_label = label[node];
        }
        ancestor[node] = root;
    }
}

fn link(v: usize, w: usize, ancestor: &mut [usize]) {
    if v == usize::MAX {
        return;
    }
    ancestor[w] = v;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: u64) -> Address {
        Address::new(v)
    }

    fn build(
        block_ids: &[u64],
        edges: &[(u64, u64)],
    ) -> (Vec<Address>, HashMap<Address, Vec<Address>>) {
        let nodes: Vec<Address> = block_ids.iter().map(|&v| a(v)).collect();
        let mut succs: HashMap<Address, Vec<Address>> = HashMap::new();
        for &n in &nodes {
            succs.entry(n).or_default();
        }
        for &(f, t) in edges {
            succs.entry(a(f)).or_default().push(a(t));
        }
        (nodes, succs)
    }

    #[test]
    fn test_lt_linear_chain() {
        // 0 → 1 → 2 → 3
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(0)), None);
        assert_eq!(dt.idom_of(a(1)), Some(a(0)));
        assert_eq!(dt.idom_of(a(2)), Some(a(1)));
        assert_eq!(dt.idom_of(a(3)), Some(a(2)));
    }

    #[test]
    fn test_lt_diamond() {
        // A=0, B=1, C=2, D=3
        // 0 → {1, 2};  1 → 3;  2 → 3
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(3)), Some(a(0)));
        assert_eq!(dt.idom_of(a(1)), Some(a(0)));
        assert_eq!(dt.idom_of(a(2)), Some(a(0)));
        assert!(dt.dominates(a(0), a(3)));
        assert!(!dt.dominates(a(1), a(3)));
    }

    #[test]
    fn test_lt_loop() {
        // 0 → 1 → 2 → 1 (back edge), 2 → 3
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(1)), Some(a(0)));
        assert_eq!(dt.idom_of(a(2)), Some(a(1)));
        assert_eq!(dt.idom_of(a(3)), Some(a(2)));
    }

    #[test]
    fn test_lt_entry_not_in_nodes_returns_none() {
        let (nodes, succs) = build(&[0, 1], &[(0, 1)]);
        assert!(compute_lt(&nodes, &succs, a(99)).is_none());
    }

    #[test]
    fn test_lt_single_node() {
        let (nodes, succs) = build(&[0], &[]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(0)), None);
    }

    #[test]
    fn test_lt_depth() {
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.depth(a(0)), 0);
        assert_eq!(dt.depth(a(1)), 1);
        assert_eq!(dt.depth(a(3)), 3);
    }

    #[test]
    fn test_lt_children_of() {
        // Diamond: 0 → {1, 2}, {1, 2} → 3
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        let mut children = dt.children_of(a(0));
        children.sort_by_key(|x| x.0);
        // 0 dominates 1, 2, and 3 directly (diamond structure)
        assert!(children.contains(&a(1)));
        assert!(children.contains(&a(2)));
        assert!(children.contains(&a(3)));
    }

    #[test]
    fn test_lt_dominates_self() {
        let (nodes, succs) = build(&[0, 1], &[(0, 1)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert!(dt.dominates(a(0), a(0)));
        assert!(dt.dominates(a(1), a(1)));
    }

    #[test]
    fn test_lt_irreducible_graph() {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3, 3 → 1 (back edge to 1)
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3), (3, 1)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        // 0 must dominate everything since it's the only entry
        assert!(dt.dominates(a(0), a(1)));
        assert!(dt.dominates(a(0), a(2)));
        assert!(dt.dominates(a(0), a(3)));
    }

    // ── Additional edge-case coverage ────────────────────────────────────────

    #[test]
    fn test_lt_empty_nodes_returns_none() {
        let nodes: Vec<Address> = vec![];
        let succs: HashMap<Address, Vec<Address>> = HashMap::new();
        assert!(compute_lt(&nodes, &succs, a(0)).is_none());
    }

    #[test]
    fn test_lt_unreachable_nodes_present() {
        // 0 → 1; node 2 is unreachable from entry.
        let (nodes, succs) = build(&[0, 1, 2], &[(0, 1)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(0)), None);
        assert_eq!(dt.idom_of(a(1)), Some(a(0)));
        // Unreachable node should not have a dominator.
        assert_eq!(dt.idom_of(a(2)), None);
    }

    #[test]
    fn test_lt_self_loop_on_entry() {
        let (nodes, succs) = build(&[0, 1], &[(0, 0), (0, 1)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(0)), None);
        assert_eq!(dt.idom_of(a(1)), Some(a(0)));
        assert!(dt.dominates(a(0), a(1)));
    }

    #[test]
    fn test_lt_depth_unreachable_is_zero() {
        let (nodes, succs) = build(&[0, 1, 99], &[(0, 1)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.depth(a(99)), 0);
    }

    #[test]
    fn test_lt_max_address_value() {
        let (nodes, succs) = build(&[0, u64::MAX], &[(0, u64::MAX)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert_eq!(dt.idom_of(a(u64::MAX)), Some(a(0)));
        assert!(dt.dominates(a(0), a(u64::MAX)));
    }

    #[test]
    fn test_lt_dominates_non_dominator() {
        let (nodes, succs) = build(&[0, 1, 2, 3], &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let dt = compute_lt(&nodes, &succs, a(0)).unwrap();
        assert!(!dt.dominates(a(1), a(2)));
        assert!(!dt.dominates(a(2), a(1)));
    }
}
