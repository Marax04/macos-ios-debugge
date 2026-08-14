// ============================================================================
// analysis/call_graph_build.rs — Build the AppData-level call-graph layer
//
// This pass runs after xref resolution in the load pipeline. For every
// discovered function we walk its outgoing xrefs (already filtered for
// CALL-kind by `resolve_xrefs`) and resolve each callee to a known
// `func_id`. The result is two parallel adjacency maps plus a per-function
// metrics table (in/out-degree, leaf/root flags, BFS depth from the nearest
// root, SCC membership via Tarjan's algorithm).
//
// The CFG-level work that already exists in `crate::core::call_graph` is a
// richer report-oriented graph; this module exposes the same information in
// the lighter shape AppData stores so other panels (decompiler, listing
// xref popups, future call-graph view) can consume it without the
// `CallNode` round-trip.
// ============================================================================

use crate::core::types::{Addr, CallGraphMetrics, Function, XrefEntry, XrefKind};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet, VecDeque};

/// Output of [`build_call_graph_metrics`].
pub struct CallGraphBuildResult {
    /// caller_id -> deduplicated list of callee_ids.
    pub adjacency: IndexMap<u32, Vec<u32>>,
    /// callee_id -> deduplicated list of caller_ids.
    pub inverse: IndexMap<u32, Vec<u32>>,
    /// Per-function metrics keyed by `func_id`.
    pub metrics: IndexMap<u32, CallGraphMetrics>,
}

/// Build the call-graph adjacency tables + per-function metrics from
/// already-resolved cross-references and the function table.
///
/// `entry_addr` is used to ensure the binary entry-point participates in the
/// BFS-depth pass as a root even if it has spurious incoming references
/// (e.g. self-tail call promoted by the linear sweep).
pub fn build_call_graph_metrics(
    functions: &IndexMap<u32, Function>,
    xrefs_from: &IndexMap<u64, Vec<XrefEntry>>,
    func_by_addr: &IndexMap<u64, u32>,
    entry_addr: Addr,
) -> CallGraphBuildResult {
    // ── 1) walk xrefs_from grouped by source address; assign each source addr
    //       to the function that contains it (interval lookup).
    //
    //       To make the per-source lookup O(log n) instead of O(n), sort
    //       function entries by address and binary-search.
    let mut sorted_funcs: Vec<(u64, u64, u32)> = functions
        .values()
        .map(|f| (f.addr.0, f.addr.0.saturating_add(f.size), f.id))
        .collect();
    sorted_funcs.sort_by_key(|(start, _, _)| *start);
    let containing_func = |addr: u64| -> Option<u32> {
        let pos = match sorted_funcs.binary_search_by_key(&addr, |(s, _, _)| *s) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let (start, end, id) = sorted_funcs[pos];
        if addr >= start && addr < end {
            Some(id)
        } else {
            None
        }
    };

    let mut adj_sets: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut inv_sets: HashMap<u32, HashSet<u32>> = HashMap::new();
    for fid in functions.keys() {
        adj_sets.insert(*fid, HashSet::new());
        inv_sets.insert(*fid, HashSet::new());
    }
    for (src_raw, entries) in xrefs_from {
        let Some(caller_id) = containing_func(*src_raw) else {
            continue;
        };
        for xref in entries {
            if !matches!(xref.kind, XrefKind::Call) {
                continue;
            }
            let Some(&callee_id) = func_by_addr.get(&xref.to.0) else {
                continue;
            };
            if let Some(set) = adj_sets.get_mut(&caller_id) {
                set.insert(callee_id);
            }
            if let Some(set) = inv_sets.get_mut(&callee_id) {
                set.insert(caller_id);
            }
        }
    }

    // Stable order: by function id.
    let mut adjacency: IndexMap<u32, Vec<u32>> = IndexMap::new();
    let mut inverse: IndexMap<u32, Vec<u32>> = IndexMap::new();
    let mut sorted_ids: Vec<u32> = functions.keys().copied().collect();
    sorted_ids.sort_unstable();
    for fid in &sorted_ids {
        let mut callees: Vec<u32> = adj_sets.get(fid).cloned().unwrap_or_default().into_iter().collect();
        callees.sort_unstable();
        adjacency.insert(*fid, callees);
        let mut callers: Vec<u32> = inv_sets.get(fid).cloned().unwrap_or_default().into_iter().collect();
        callers.sort_unstable();
        inverse.insert(*fid, callers);
    }

    // ── 2) Tarjan SCC (classic iterative-by-loop, recursive interior). The
    //       graph is bounded by the number of *real* functions so a recursive
    //       walk is safe in practice — typical builds top out around a few
    //       hundred thousand nodes total.
    let sccs = tarjan_scc(&sorted_ids, &adjacency);
    let mut scc_of: HashMap<u32, u32> = HashMap::new();
    let mut nontrivial: HashSet<u32> = HashSet::new();
    for (sid, members) in sccs.iter().enumerate() {
        let scc_id = u32::try_from(sid).unwrap_or(u32::MAX);
        let is_nontrivial = members.len() > 1
            || members
                .first()
                .is_some_and(|m| adjacency.get(m).is_some_and(|v| v.contains(m)));
        if is_nontrivial {
            for m in members {
                nontrivial.insert(*m);
            }
        }
        for m in members {
            scc_of.insert(*m, scc_id);
        }
    }

    // ── 3) Root discovery and BFS depths.
    //
    //       A root is any function with no incoming call edges. The binary
    //       entry-point is always treated as a root regardless of inbound
    //       count so a recursive self-call cannot demote it.
    let entry_id = func_by_addr.get(&entry_addr.0).copied();
    let mut roots: Vec<u32> = sorted_ids
        .iter()
        .copied()
        .filter(|fid| inverse.get(fid).is_some_and(Vec::is_empty))
        .collect();
    if let Some(eid) = entry_id {
        if !roots.contains(&eid) {
            roots.push(eid);
        }
    }

    let mut depth: HashMap<u32, u32> = HashMap::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    for r in &roots {
        depth.insert(*r, 0);
        queue.push_back(*r);
    }
    while let Some(id) = queue.pop_front() {
        let cur_depth = *depth.get(&id).unwrap_or(&u32::MAX);
        if cur_depth == u32::MAX {
            continue;
        }
        let next_depth = cur_depth.saturating_add(1);
        if let Some(callees) = adjacency.get(&id) {
            for callee in callees {
                let entry = depth.entry(*callee).or_insert(u32::MAX);
                if next_depth < *entry {
                    *entry = next_depth;
                    queue.push_back(*callee);
                }
            }
        }
    }

    // ── 4) Assemble per-function metrics.
    let mut metrics: IndexMap<u32, CallGraphMetrics> = IndexMap::new();
    for fid in &sorted_ids {
        let callers_n = inverse.get(fid).map_or(0, Vec::len);
        let callees_n = adjacency.get(fid).map_or(0, Vec::len);
        let in_cycle = nontrivial.contains(fid);
        let scc_id = scc_of.get(fid).copied().filter(|_| in_cycle);
        let depth_from_root = depth.get(fid).copied().filter(|d| *d != u32::MAX);
        let is_root = callers_n == 0 || Some(*fid) == entry_id;
        let is_leaf = callees_n == 0;
        let m = CallGraphMetrics {
            xref_in_count: u32::try_from(callers_n).unwrap_or(u32::MAX),
            xref_out_count: u32::try_from(callees_n).unwrap_or(u32::MAX),
            is_leaf,
            is_root,
            depth_from_root,
            in_cycle,
            scc_id,
        };
        metrics.insert(*fid, m);
    }

    CallGraphBuildResult {
        adjacency,
        inverse,
        metrics,
    }
}

// ── Tarjan SCC (iterative driver, recursive `strongconnect` body) ─────────────

fn tarjan_scc(
    sorted_ids: &[u32],
    adjacency: &IndexMap<u32, Vec<u32>>,
) -> Vec<Vec<u32>> {
    struct S {
        index: u32,
        stack: Vec<u32>,
        on_stack: HashSet<u32>,
        indices: HashMap<u32, u32>,
        low: HashMap<u32, u32>,
        sccs: Vec<Vec<u32>>,
    }

    impl S {
        fn strongconnect(&mut self, v: u32, adj: &IndexMap<u32, Vec<u32>>) {
            self.indices.insert(v, self.index);
            self.low.insert(v, self.index);
            self.index = self.index.saturating_add(1);
            self.stack.push(v);
            self.on_stack.insert(v);
            if let Some(succs) = adj.get(&v) {
                for &w in succs {
                    if !self.indices.contains_key(&w) {
                        self.strongconnect(w, adj);
                        let lv = *self.low.get(&v).unwrap_or(&u32::MAX);
                        let lw = *self.low.get(&w).unwrap_or(&u32::MAX);
                        self.low.insert(v, lv.min(lw));
                    } else if self.on_stack.contains(&w) {
                        let lv = *self.low.get(&v).unwrap_or(&u32::MAX);
                        let iw = *self.indices.get(&w).unwrap_or(&u32::MAX);
                        self.low.insert(v, lv.min(iw));
                    }
                }
            }
            if self.low.get(&v) == self.indices.get(&v) {
                let mut scc = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on_stack.remove(&w);
                    scc.push(w);
                    if w == v {
                        break;
                    }
                }
                self.sccs.push(scc);
            }
        }
    }

    let mut state = S {
        index: 0,
        stack: Vec::new(),
        on_stack: HashSet::new(),
        indices: HashMap::new(),
        low: HashMap::new(),
        sccs: Vec::new(),
    };
    for v in sorted_ids {
        if !state.indices.contains_key(v) {
            state.strongconnect(*v, adjacency);
        }
    }
    state.sccs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Function, FunctionTags};

    fn mkf(id: u32, addr: u64, size: u64) -> Function {
        Function {
            id,
            addr: Addr(addr),
            name: format!("f{id}"),
            size,
            tags: FunctionTags::AUTO,
            sym_id: None,
            comment: String::new(),
            color: None,
        }
    }

    #[test]
    fn linear_chain_depths() {
        // 1 -> 2 -> 3
        let mut funcs = IndexMap::new();
        funcs.insert(1u32, mkf(1, 0x1000, 0x100));
        funcs.insert(2u32, mkf(2, 0x2000, 0x100));
        funcs.insert(3u32, mkf(3, 0x3000, 0x100));
        let mut by_addr = IndexMap::new();
        by_addr.insert(0x1000u64, 1u32);
        by_addr.insert(0x2000u64, 2u32);
        by_addr.insert(0x3000u64, 3u32);
        let mut xrefs_from = IndexMap::new();
        xrefs_from.insert(
            0x1010,
            vec![XrefEntry {
                from: Addr(0x1010),
                to: Addr(0x2000),
                kind: XrefKind::Call,
                label: None,
            }],
        );
        xrefs_from.insert(
            0x2010,
            vec![XrefEntry {
                from: Addr(0x2010),
                to: Addr(0x3000),
                kind: XrefKind::Call,
                label: None,
            }],
        );
        let r = build_call_graph_metrics(&funcs, &xrefs_from, &by_addr, Addr(0x1000));
        assert_eq!(r.metrics[&1].depth_from_root, Some(0));
        assert_eq!(r.metrics[&2].depth_from_root, Some(1));
        assert_eq!(r.metrics[&3].depth_from_root, Some(2));
        assert!(r.metrics[&3].is_leaf);
        assert!(r.metrics[&1].is_root);
        assert!(!r.metrics[&1].in_cycle);
    }

    #[test]
    fn self_loop_in_cycle() {
        let mut funcs = IndexMap::new();
        funcs.insert(1u32, mkf(1, 0x1000, 0x100));
        let mut by_addr = IndexMap::new();
        by_addr.insert(0x1000u64, 1u32);
        let mut xrefs_from = IndexMap::new();
        xrefs_from.insert(
            0x1010,
            vec![XrefEntry {
                from: Addr(0x1010),
                to: Addr(0x1000),
                kind: XrefKind::Call,
                label: None,
            }],
        );
        let r = build_call_graph_metrics(&funcs, &xrefs_from, &by_addr, Addr(0x1000));
        assert!(r.metrics[&1].in_cycle);
        assert!(r.metrics[&1].scc_id.is_some());
    }
}

// ── prod ensure-used ──────────────────────────────────────────────────────────

#[doc(hidden)]
pub fn ensure_used_call_graph_build() {
    let mut funcs: IndexMap<u32, Function> = IndexMap::new();
    funcs.insert(
        1u32,
        Function {
            id: 1,
            addr: Addr(0x1000),
            name: "f1".into(),
            size: 0x100,
            tags: crate::core::types::FunctionTags::AUTO,
            sym_id: None,
            comment: String::new(),
            color: None,
        },
    );
    let mut by_addr: IndexMap<u64, u32> = IndexMap::new();
    by_addr.insert(0x1000, 1);
    let xrefs_from: IndexMap<u64, Vec<XrefEntry>> = IndexMap::new();
    let r = build_call_graph_metrics(&funcs, &xrefs_from, &by_addr, Addr(0x1000));
    let _ = (
        r.adjacency.len(),
        r.inverse.len(),
        r.metrics.len(),
    );
}
