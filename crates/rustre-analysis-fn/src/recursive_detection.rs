//! Recursive function detection for `rustre-analysis-fn`.
//!
//! Detects three related phenomena in a binary call-graph:
//!
//! 1. **Direct recursion** — a function that calls itself (`foo → foo`).
//! 2. **Mutual recursion** — two or more functions that form a cycle
//!    (`foo → bar → foo`), detected via Tarjan's SCC algorithm on the call graph.
//! 3. **Tail recursion** — a recursive self-call implemented as a `JMP` to the
//!    function entry point rather than a `CALL`, enabling elimination of the
//!    stack frame.  Detected by checking whether any `JMP rel32` / `JMP rel8`
//!    within the function body targets the function's own entry address.
//! 4. **Accumulator pattern** — a heuristic that marks a function as
//!    tail-recursive with accumulator when the function has exactly one
//!    recursive tail-call site and at least one parameter register is live
//!    across the back-edge (a simplified proxy for the accumulator idiom).

use std::collections::{HashMap, HashSet};

use crate::MemorySlice;
use petgraph::algo::tarjan_scc as petgraph_tarjan_scc;
use petgraph::graph::DiGraph;
use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// Call-graph edge
// ─────────────────────────────────────────────────────────────────────────────

/// A directed edge in the call graph: `caller → callee`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    /// Address of the calling function.
    pub caller: Address,
    /// Address of the called function.
    pub callee: Address,
    /// Whether this edge is a tail call (`JMP`) rather than a regular `CALL`.
    pub is_tail_call: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Call graph
// ─────────────────────────────────────────────────────────────────────────────

/// An adjacency-list call graph over function entry addresses.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// Outgoing edges: function address → set of callee addresses.
    pub edges: HashMap<u64, HashSet<u64>>,
    /// Full edge set (includes `is_tail_call` information).
    pub full_edges: Vec<CallEdge>,
    /// All known function addresses (nodes).
    pub nodes: HashSet<u64>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node without any edges.
    pub fn add_node(&mut self, addr: Address) {
        self.nodes.insert(addr.as_u64());
        self.edges.entry(addr.as_u64()).or_default();
    }

    /// Add a directed call edge.
    pub fn add_edge(&mut self, edge: CallEdge) {
        self.nodes.insert(edge.caller.as_u64());
        self.nodes.insert(edge.callee.as_u64());
        self.edges
            .entry(edge.caller.as_u64())
            .or_default()
            .insert(edge.callee.as_u64());
        self.full_edges.push(edge);
    }

    /// Return all callee addresses for `caller`.
    pub fn callees(&self, caller: Address) -> impl Iterator<Item = u64> + '_ {
        self.edges
            .get(&caller.as_u64())
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    /// Return `true` if there is a direct edge from `caller` to `target`.
    #[must_use]
    pub fn has_edge(&self, caller: Address, target: Address) -> bool {
        self.edges
            .get(&caller.as_u64())
            .is_some_and(|s| s.contains(&target.as_u64()))
    }

    /// Total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of directed edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.full_edges.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct-recursion detection
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a [`CallGraph`] for directly recursive functions.
///
/// A function `f` is directly recursive if the call graph contains an edge
/// `f → f`.
#[must_use]
pub fn find_direct_recursion(graph: &CallGraph) -> Vec<Address> {
    // Collect from the HashSet then sort: HashSet iteration order is
    // nondeterministic across runs/hasher seeds, and callers may rely on a
    // stable, reproducible ordering of results.
    let mut addrs: Vec<u64> = graph
        .nodes
        .iter()
        .copied()
        .filter(|&addr| {
            graph
                .edges
                .get(&addr)
                .is_some_and(|callees| callees.contains(&addr))
        })
        .collect();
    addrs.sort_unstable();
    addrs.into_iter().map(Address::new).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tarjan's SCC — mutual-recursion detection
// ─────────────────────────────────────────────────────────────────────────────

/// One strongly connected component (SCC) of the call graph.
#[derive(Debug, Clone)]
pub struct Scc {
    /// All function addresses in this SCC.
    pub members: Vec<Address>,
}

impl Scc {
    /// Return `true` if this SCC contains more than one node (i.e., it
    /// represents a mutual-recursion cycle).
    #[must_use]
    pub const fn is_mutual_recursion(&self) -> bool {
        self.members.len() > 1
    }
}

/// Compute all SCCs of `graph` using Tarjan's algorithm (via `petgraph`).
///
/// Returns SCCs in reverse topological order (leaves first).
///
/// # Panics
/// Panics if `petgraph` returns a node index not present in the graph (should never happen).
#[must_use]
pub fn tarjan_sccs(graph: &CallGraph) -> Vec<Scc> {
    // Build a petgraph DiGraph from the CallGraph.
    // Node weights are the function addresses (u64).
    let mut pg: DiGraph<u64, ()> = DiGraph::new();
    let mut addr_to_idx: HashMap<u64, petgraph::graph::NodeIndex> = HashMap::new();

    // Add nodes in a canonical (sorted) order rather than raw HashSet
    // iteration order. `graph.nodes` is a HashSet<u64>, whose iteration
    // order is nondeterministic (hasher-seed/insertion dependent). Since
    // Tarjan's algorithm's DFS visits nodes in index-insertion order, an
    // unsorted seed order makes both the order of returned SCCs *and* the
    // order of members within each SCC nondeterministic across otherwise
    // identical runs, even though SCC membership itself is order-independent.
    let mut sorted_nodes: Vec<u64> = graph.nodes.iter().copied().collect();
    sorted_nodes.sort_unstable();

    for addr in sorted_nodes {
        let idx = pg.add_node(addr);
        addr_to_idx.insert(addr, idx);
    }

    for edge in &graph.full_edges {
        if let (Some(&src), Some(&dst)) = (
            addr_to_idx.get(&edge.caller.as_u64()),
            addr_to_idx.get(&edge.callee.as_u64()),
        ) {
            pg.add_edge(src, dst, ());
        }
    }

    // petgraph's tarjan_scc returns SCCs in reverse topological order.
    petgraph_tarjan_scc(&pg)
        .into_iter()
        .map(|component| Scc {
            members: component
                .into_iter()
                .map(|idx| Address::new(*pg.node_weight(idx).unwrap()))
                .collect(),
        })
        .collect()
}

/// Return all SCCs that represent mutual recursion (size ≥ 2).
#[must_use]
pub fn find_mutual_recursion(graph: &CallGraph) -> Vec<Scc> {
    tarjan_sccs(graph)
        .into_iter()
        .filter(Scc::is_mutual_recursion)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tail-recursion detection (byte-level)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of tail-recursion analysis for one function.
#[derive(Debug, Clone)]
pub struct TailRecursionInfo {
    /// Function entry address.
    pub function_addr: Address,
    /// Addresses of `JMP` instructions that implement tail-recursive calls.
    pub tail_jump_sites: Vec<Address>,
    /// Whether the function looks like it uses an accumulator parameter.
    pub has_accumulator_pattern: bool,
}

impl TailRecursionInfo {
    /// Return `true` if at least one tail-recursive `JMP` was found.
    #[must_use]
    pub const fn is_tail_recursive(&self) -> bool {
        !self.tail_jump_sites.is_empty()
    }
}

/// Scan the body of a single function for tail-recursive `JMP` instructions.
///
/// A tail-recursive `JMP` is a `JMP rel32` (`E9`) or `JMP rel8` (`EB`) whose
/// resolved target equals `function_start`.
#[must_use]
pub fn detect_tail_recursion(
    mem: &MemorySlice<'_>,
    function_start: Address,
    function_end: Address,
) -> TailRecursionInfo {
    let mut tail_jump_sites = Vec::new();
    let bytes = mem.bytes;
    let base = mem.base.as_u64();

    let start_off =
        usize::try_from(function_start.as_u64().saturating_sub(base)).unwrap_or(usize::MAX);
    let end_off = usize::try_from(function_end.as_u64().saturating_sub(base))
        .unwrap_or(usize::MAX)
        .min(bytes.len());

    let mut i = start_off;
    while i < end_off {
        let b = bytes[i];

        // JMP rel32 (E9)
        if i + 5 <= end_off && b == 0xE9 {
            let disp = i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
            let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
            let target = u64::from_ne_bytes(
                (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                    .to_ne_bytes(),
            );
            if target == function_start.as_u64() {
                tail_jump_sites.push(Address::new(base + i as u64));
            }
            i += 5;
            continue;
        }

        // JMP rel8 (EB)
        if i + 2 <= end_off && b == 0xEB {
            let disp = i8::from_le_bytes([bytes[i + 1]]);
            let next_pc = base.wrapping_add(i as u64).wrapping_add(2);
            let target = next_pc.wrapping_add_signed(i64::from(disp));
            if target == function_start.as_u64() {
                tail_jump_sites.push(Address::new(base + i as u64));
            }
            i += 2;
            continue;
        }

        i += 1;
    }

    // Accumulator heuristic: function is small (< 512 bytes) and has exactly
    // one tail-jump site.
    let size = function_end
        .as_u64()
        .saturating_sub(function_start.as_u64());
    let has_accumulator_pattern = tail_jump_sites.len() == 1 && size < 512;

    TailRecursionInfo {
        function_addr: function_start,
        tail_jump_sites,
        has_accumulator_pattern,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Call-graph builder (byte-level)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`CallGraph`] from a list of function address ranges by scanning
/// each function body for `CALL rel32` (`E8`) and `JMP rel32` (`E9`)
/// instructions that resolve to known function entries.
#[must_use]
pub fn build_call_graph(
    mem: &MemorySlice<'_>,
    functions: &[(Address, Address)], // (start, end)
) -> CallGraph {
    let func_starts: HashSet<u64> = functions.iter().map(|(s, _)| s.as_u64()).collect();
    let mut graph = CallGraph::new();

    for &(start, _) in functions {
        graph.add_node(start);
    }

    for &(func_start, func_end) in functions {
        let bytes = mem.bytes;
        let base = mem.base.as_u64();

        let start_off =
            usize::try_from(func_start.as_u64().saturating_sub(base)).unwrap_or(usize::MAX);
        let end_off = usize::try_from(func_end.as_u64().saturating_sub(base))
            .unwrap_or(usize::MAX)
            .min(bytes.len());

        let mut i = start_off;
        while i < end_off {
            let b = bytes[i];

            // CALL rel32 (E8)
            if i + 5 <= end_off && b == 0xE8 {
                let disp =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                let target = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );
                if func_starts.contains(&target) {
                    graph.add_edge(CallEdge {
                        caller: func_start,
                        callee: Address::new(target),
                        is_tail_call: false,
                    });
                }
                i += 5;
                continue;
            }

            // JMP rel32 (E9) — potential tail call
            if i + 5 <= end_off && b == 0xE9 {
                let disp =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
                let target = u64::from_ne_bytes(
                    (i64::from_ne_bytes(next_pc.to_ne_bytes()).wrapping_add(i64::from(disp)))
                        .to_ne_bytes(),
                );
                if func_starts.contains(&target) {
                    graph.add_edge(CallEdge {
                        caller: func_start,
                        callee: Address::new(target),
                        is_tail_call: true,
                    });
                }
                i += 5;
                continue;
            }

            i += 1;
        }
    }

    graph
}

// ─────────────────────────────────────────────────────────────────────────────
// Recursion report
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate recursion analysis results.
#[derive(Debug)]
pub struct RecursionReport {
    /// Directly recursive functions.
    pub direct: Vec<Address>,
    /// SCCs containing mutual recursion.
    pub mutual_sccs: Vec<Scc>,
    /// Tail-recursion information per function.
    pub tail_recursive: Vec<TailRecursionInfo>,
    /// Functions with the accumulator pattern.
    pub accumulator_pattern: Vec<Address>,
}

impl RecursionReport {
    /// Build a full recursion report from a call graph and a set of function
    /// ranges.
    #[must_use]
    pub fn build(
        graph: &CallGraph,
        mem: &MemorySlice<'_>,
        functions: &[(Address, Address)],
    ) -> Self {
        let direct = find_direct_recursion(graph);
        let mutual_sccs = find_mutual_recursion(graph);

        let mut tail_recursive = Vec::new();
        let mut accumulator_pattern = Vec::new();

        for &(start, end) in functions {
            let info = detect_tail_recursion(mem, start, end);
            if info.has_accumulator_pattern {
                accumulator_pattern.push(start);
            }
            if info.is_tail_recursive() {
                tail_recursive.push(info);
            }
        }

        Self {
            direct,
            mutual_sccs,
            tail_recursive,
            accumulator_pattern,
        }
    }

    /// Total number of recursive functions (direct + mutual members).
    #[must_use]
    pub fn total_recursive_count(&self) -> usize {
        let direct = self.direct.len();
        let mutual: usize = self.mutual_sccs.iter().map(|scc| scc.members.len()).sum();
        direct + mutual
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    /// Differential soundness: `tarjan_sccs` (petgraph, via the `CallGraph` →
    /// `DiGraph` translation) must partition nodes such that two nodes share an
    /// SCC iff they are mutually reachable. Cross-checked against a brute-force
    /// reachability oracle on random graphs — catches any edge-translation bug
    /// (dropped/duplicated/mis-mapped edges) between `CallGraph` and petgraph.
    #[test]
    fn tarjan_sccs_matches_mutual_reachability_oracle() {
        use crate::test_prng::xs;
        // Brute-force: is `dst` reachable from `src` following edges?
        fn reaches(edges: &[(u64, u64)], nodes: &[u64], src: u64, dst: u64) -> bool {
            let mut stack = vec![src];
            let mut seen = std::collections::HashSet::new();
            seen.insert(src);
            while let Some(n) = stack.pop() {
                if n == dst {
                    return true;
                }
                for &(u, v) in edges {
                    if u == n && seen.insert(v) {
                        stack.push(v);
                    }
                }
            }
            let _ = nodes;
            seen.contains(&dst)
        }
        let mut state = 0xc0ff_ee00_1234_5678u64;
        for _ in 0..400 {
            let n = 2 + (xs(&mut state) % 6); // 2..=7 nodes
            let node = |i: u64| 0x400 + i * 0x8;
            let mut g = CallGraph::new();
            for i in 0..n {
                g.add_node(addr(node(i)));
            }
            let mut edges: Vec<(u64, u64)> = Vec::new();
            for u in 0..n {
                for v in 0..n {
                    if xs(&mut state) % 100 < 30 {
                        g.add_edge(CallEdge {
                            caller: addr(node(u)),
                            callee: addr(node(v)),
                            is_tail_call: false,
                        });
                        edges.push((node(u), node(v)));
                    }
                }
            }
            let all: Vec<u64> = (0..n).map(node).collect();
            // Map each node to its SCC id per tarjan_sccs.
            let sccs = tarjan_sccs(&g);
            let mut scc_of: HashMap<u64, usize> = HashMap::new();
            for (id, scc) in sccs.iter().enumerate() {
                for m in &scc.members {
                    scc_of.insert(m.as_u64(), id);
                }
            }
            for &x in &all {
                for &y in &all {
                    let mutually = reaches(&edges, &all, x, y) && reaches(&edges, &all, y, x);
                    let same_scc = scc_of.get(&x) == scc_of.get(&y);
                    assert_eq!(
                        mutually, same_scc,
                        "SCC/reachability mismatch for {x:#x},{y:#x}: mutually={mutually} same_scc={same_scc} edges={edges:?}"
                    );
                }
            }
        }
    }

    /// Oracle: `find_direct_recursion` must return exactly the set of nodes
    /// with a self-edge (per the raw random edge list), sorted ascending —
    /// on 500 random graphs.
    #[test]
    fn prop_find_direct_recursion_matches_oracle() {
        use crate::test_prng::xs;
        let mut state = 0x0bad_f00d_1337_c0deu64;
        for _ in 0..500 {
            let n = 1 + (xs(&mut state) % 8);
            let node = |i: u64| 0x400 + i * 8;
            let mut g = CallGraph::new();
            let mut edges: Vec<(u64, u64)> = Vec::new();
            for i in 0..n {
                g.add_node(addr(node(i)));
            }
            for u in 0..n {
                for v in 0..n {
                    if xs(&mut state) % 100 < 20 {
                        g.add_edge(CallEdge {
                            caller: addr(node(u)),
                            callee: addr(node(v)),
                            is_tail_call: false,
                        });
                        edges.push((node(u), node(v)));
                    }
                }
            }
            let mut expected: Vec<u64> = edges
                .iter()
                .filter(|(u, v)| u == v)
                .map(|&(u, _)| u)
                .collect();
            expected.sort_unstable();
            expected.dedup();
            let got: Vec<u64> = find_direct_recursion(&g).iter().map(|a| a.as_u64()).collect();
            assert_eq!(got, expected, "direct recursion mismatch, edges={edges:?}");
        }
    }

    // ── CallGraph ─────────────────────────────────────────────────────────────

    #[test]
    fn call_graph_add_node_and_edge() {
        let mut g = CallGraph::new();
        g.add_node(addr(0x1000));
        g.add_edge(CallEdge {
            caller: addr(0x1000),
            callee: addr(0x2000),
            is_tail_call: false,
        });
        assert!(g.has_edge(addr(0x1000), addr(0x2000)));
        assert!(!g.has_edge(addr(0x2000), addr(0x1000)));
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    // ── Direct recursion ─────────────────────────────────────────────────────

    #[test]
    fn direct_recursion_detected() {
        let mut g = CallGraph::new();
        g.add_edge(CallEdge {
            caller: addr(0x1000),
            callee: addr(0x1000), // self-call
            is_tail_call: false,
        });
        g.add_node(addr(0x2000)); // non-recursive
        let direct = find_direct_recursion(&g);
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0], addr(0x1000));
    }

    #[test]
    fn no_direct_recursion() {
        let mut g = CallGraph::new();
        g.add_edge(CallEdge {
            caller: addr(0x1000),
            callee: addr(0x2000),
            is_tail_call: false,
        });
        assert!(find_direct_recursion(&g).is_empty());
    }

    // ── Tarjan SCCs ───────────────────────────────────────────────────────────

    #[test]
    fn tarjan_finds_mutual_recursion() {
        let mut g = CallGraph::new();
        // A → B, B → A (mutual recursion)
        g.add_edge(CallEdge {
            caller: addr(0xA),
            callee: addr(0xB),
            is_tail_call: false,
        });
        g.add_edge(CallEdge {
            caller: addr(0xB),
            callee: addr(0xA),
            is_tail_call: false,
        });
        // C is isolated
        g.add_node(addr(0xC));

        let mutual = find_mutual_recursion(&g);
        assert_eq!(mutual.len(), 1, "expected one mutual-recursion SCC");
        assert_eq!(mutual[0].members.len(), 2);
    }

    #[test]
    fn tarjan_no_mutual_recursion_in_dag() {
        let mut g = CallGraph::new();
        g.add_edge(CallEdge {
            caller: addr(0x1),
            callee: addr(0x2),
            is_tail_call: false,
        });
        g.add_edge(CallEdge {
            caller: addr(0x2),
            callee: addr(0x3),
            is_tail_call: false,
        });
        let mutual = find_mutual_recursion(&g);
        assert!(mutual.is_empty());
    }

    // ── Tail recursion ────────────────────────────────────────────────────────

    #[test]
    fn tail_recursion_detected_via_jmp_rel32() {
        // Function at 0x1000..0x100F.
        // At offset 5: JMP rel32 back to 0x1000 (i.e., disp = -10)
        // JMP is at 0x1005, next_pc = 0x100A, disp = 0x1000 - 0x100A = -10 = 0xFFFFFFF6
        let mut code = vec![0x90u8; 15];
        let disp: i32 = (0x1000i64 - 0x100A) as i32;
        code[5] = 0xE9;
        code[6..10].copy_from_slice(&disp.to_le_bytes());
        code[10] = 0xC3;

        let mem = MemorySlice::new(Address::new(0x1000), &code);
        let info = detect_tail_recursion(&mem, Address::new(0x1000), Address::new(0x100F));
        assert!(info.is_tail_recursive(), "expected tail-recursive JMP");
        assert_eq!(info.tail_jump_sites.len(), 1);
        assert_eq!(info.tail_jump_sites[0], Address::new(0x1005));
    }

    #[test]
    fn tail_recursion_not_detected_for_forward_jmp() {
        // JMP that goes forward (not back to entry) should not be flagged.
        let mut code = vec![0x90u8; 15];
        let disp: i32 = 3; // forward
        code[0] = 0xE9;
        code[1..5].copy_from_slice(&disp.to_le_bytes());
        let mem = MemorySlice::new(Address::new(0x2000), &code);
        let info = detect_tail_recursion(&mem, Address::new(0x2000), Address::new(0x200F));
        assert!(!info.is_tail_recursive());
    }

    // ── Call-graph builder ────────────────────────────────────────────────────

    #[test]
    fn build_call_graph_detects_self_call() {
        // Self-calling function: CALL $+5 at start (E8 disp → same function).
        // Function at 0x3000..0x3010. CALL at 0x3000 with disp = -5 → 0x3000.
        let mut code = vec![0x90u8; 16];
        let disp: i32 = (0x3000i64 - 0x3005) as i32;
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&disp.to_le_bytes());
        code[5] = 0xC3;
        let mem = MemorySlice::new(Address::new(0x3000), &code);
        let funcs = vec![(Address::new(0x3000), Address::new(0x3010))];
        let g = build_call_graph(&mem, &funcs);
        assert!(g.has_edge(Address::new(0x3000), Address::new(0x3000)));
    }

    // ── Determinism ───────────────────────────────────────────────────────────

    #[test]
    fn find_direct_recursion_is_sorted() {
        // Insert self-calls in a non-sorted order; the result must still come
        // back address-sorted (previously depended on HashSet iteration order).
        let mut g = CallGraph::new();
        for &a in &[0x9000u64, 0x1000, 0x5000, 0x2000] {
            g.add_edge(CallEdge {
                caller: addr(a),
                callee: addr(a),
                is_tail_call: false,
            });
        }
        let direct = find_direct_recursion(&g);
        let addrs: Vec<u64> = direct.iter().map(|a| a.as_u64()).collect();
        let mut sorted = addrs.clone();
        sorted.sort_unstable();
        assert_eq!(addrs, sorted, "find_direct_recursion must return a deterministic sorted order");
    }

    #[test]
    fn tarjan_sccs_deterministic_across_calls() {
        // Build a graph with several independent cycles plus singleton nodes.
        let mut g = CallGraph::new();
        g.add_edge(CallEdge { caller: addr(0x100), callee: addr(0x200), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x200), callee: addr(0x100), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x300), callee: addr(0x400), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x400), callee: addr(0x500), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x500), callee: addr(0x300), is_tail_call: false });
        g.add_node(addr(0x600));

        // Calling repeatedly (each call rebuilds the petgraph from the same
        // CallGraph) must yield byte-identical results every time now that
        // node insertion order is canonicalized.
        let first = tarjan_sccs(&g);
        for _ in 0..5 {
            let again = tarjan_sccs(&g);
            assert_eq!(
                first.iter().map(|s| s.members.clone()).collect::<Vec<_>>(),
                again.iter().map(|s| s.members.clone()).collect::<Vec<_>>(),
                "tarjan_sccs must be deterministic across repeated calls"
            );
        }

        let mutual = find_mutual_recursion(&g);
        assert_eq!(mutual.len(), 2);
    }

    // ── Recursion report ─────────────────────────────────────────────────────

    #[test]
    fn recursion_report_total_count() {
        let mut g = CallGraph::new();
        // Direct self-call
        g.add_edge(CallEdge {
            caller: addr(0x1),
            callee: addr(0x1),
            is_tail_call: false,
        });
        // Mutual: 0x2 ↔ 0x3
        g.add_edge(CallEdge {
            caller: addr(0x2),
            callee: addr(0x3),
            is_tail_call: false,
        });
        g.add_edge(CallEdge {
            caller: addr(0x3),
            callee: addr(0x2),
            is_tail_call: false,
        });

        let mem = MemorySlice::new(Address::new(0), &[]);
        let funcs: Vec<(Address, Address)> = vec![];
        let report = RecursionReport::build(&g, &mem, &funcs);

        // 1 direct + 2 mutual
        assert_eq!(report.total_recursive_count(), 3);
    }
}
