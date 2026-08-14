//! BFS-bounded call-graph slice extraction.
//!
//! [`callgraph_from`] walks the call graph starting from a root address,
//! collecting up to `depth` hops (clamped to 10, default 3).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::recursive_detection::CallGraph;
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single node in a [`CallGraphSlice`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeRec {
    /// Virtual address of the function.
    pub addr: u64,
    /// Optional name, if known from symbol information.
    pub name: Option<String>,
}

/// A depth-bounded subgraph of the full call graph, rooted at a single
/// function address.
///
/// JSON shape (example):
/// ```json
/// {
///   "nodes": [
///     { "addr": 4096, "name": "main" },
///     { "addr": 4200, "name": null }
///   ],
///   "edges": [[4096, 4200]]
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct CallGraphSlice {
    /// All reachable nodes within `depth` hops of the root (root included).
    pub nodes: Vec<NodeRec>,
    /// Directed call edges as `(caller_addr, callee_addr)` pairs.
    pub edges: Vec<(u64, u64)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum depth accepted by [`callgraph_from`].
pub const MAX_DEPTH: u32 = 10;
/// Default BFS depth used when `depth` is 0.
pub const DEFAULT_DEPTH: u32 = 3;

/// Extract a BFS-bounded call-graph slice rooted at `addr`.
///
/// - `depth == 0` is treated as `DEFAULT_DEPTH` (3).
/// - `depth > MAX_DEPTH` is clamped to `MAX_DEPTH` (10).
/// - `names` is an optional map of `address → symbol name`; pass
///   `&HashMap::new()` when no symbol information is available.
///
/// The returned [`CallGraphSlice`] includes the root node even if it has no
/// outgoing edges.
#[must_use]
pub fn callgraph_from<S: std::hash::BuildHasher>(
    graph: &CallGraph,
    addr: Address,
    depth: u32,
    names: &HashMap<u64, String, S>,
) -> CallGraphSlice {
    let effective_depth = match depth {
        0 => DEFAULT_DEPTH,
        d if d > MAX_DEPTH => MAX_DEPTH,
        d => d,
    };

    let root = addr.as_u64();

    // Single BFS pass: visit callees in sorted order for deterministic output,
    // collecting both edges and the node insertion order at once.
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, u32)> = VecDeque::new();
    let mut slice_edges: Vec<(u64, u64)> = Vec::new();
    let mut ordered: Vec<u64> = vec![root];

    visited.insert(root);
    queue.push_back((root, 0));

    while let Some((current, cur_depth)) = queue.pop_front() {
        if cur_depth >= effective_depth {
            continue;
        }

        if let Some(callees) = graph.edges.get(&current) {
            let mut sorted_callees: Vec<u64> = callees.iter().copied().collect();
            sorted_callees.sort_unstable();
            for callee in sorted_callees {
                slice_edges.push((current, callee));
                if visited.insert(callee) {
                    ordered.push(callee);
                    queue.push_back((callee, cur_depth + 1));
                }
            }
        }
    }

    let nodes = ordered
        .into_iter()
        .map(|a| NodeRec {
            addr: a,
            name: names.get(&a).cloned(),
        })
        .collect();

    // Deduplicate edges and sort for determinism.
    slice_edges.sort_unstable();
    slice_edges.dedup();

    CallGraphSlice {
        nodes,
        edges: slice_edges,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DOT rendering
// ─────────────────────────────────────────────────────────────────────────────

/// Styling options for [`render_callgraph_dot_styled`].
#[derive(Debug, Clone, Default)]
pub struct DotOpts {
    /// Color nodes whose name looks like a placeholder (`sub_*`) in light gray.
    pub color_external: bool,
    /// If set, the matching node is filled in light yellow.
    pub highlight_root_addr: Option<u64>,
    /// Optional font name applied to nodes (e.g. `"Helvetica"`).
    pub font: Option<String>,
}

/// Render a [`CallGraphSlice`] as a Graphviz DOT digraph using default styling.
#[must_use]
pub fn render_callgraph_dot(slice: &CallGraphSlice) -> String {
    render_callgraph_dot_styled(slice, &DotOpts::default())
}

/// Render a [`CallGraphSlice`] as a Graphviz DOT digraph with the supplied
/// styling options.
#[must_use]
pub fn render_callgraph_dot_styled(slice: &CallGraphSlice, opts: &DotOpts) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(128 + slice.nodes.len() * 48 + slice.edges.len() * 32);

    let _ = writeln!(
        out,
        "// callgraph slice: {} node(s), {} edge(s)",
        slice.nodes.len(),
        slice.edges.len()
    );
    out.push_str("digraph G {\n");
    out.push_str("    rankdir=LR;\n");
    if let Some(font) = opts.font.as_deref() {
        let _ = writeln!(out, "    node [fontname=\"{}\"];", escape_dot(font));
        let _ = writeln!(out, "    edge [fontname=\"{}\"];", escape_dot(font));
    }

    for n in &slice.nodes {
        let id = node_id(n.addr);
        let label = match n.name.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => format!("{:x}", n.addr),
        };

        let mut attrs = format!("label=\"{}\"", escape_dot(&label));

        let is_external = opts.color_external
            && n.name
                .as_deref()
                .is_some_and(|s| s.starts_with("sub_"));
        let is_root = opts.highlight_root_addr == Some(n.addr);

        if is_root {
            attrs.push_str(",fillcolor=lightyellow,style=filled");
        } else if is_external {
            attrs.push_str(",fillcolor=lightgray,style=filled");
        }

        let _ = writeln!(out, "    {id} [{attrs}];");
    }

    for &(from, to) in &slice.edges {
        let _ = writeln!(out, "    {} -> {};", node_id(from), node_id(to));
    }

    out.push_str("}\n");
    out
}

fn node_id(addr: u64) -> String {
    if addr == 0 {
        "n0".to_string()
    } else {
        format!("n{addr:x}")
    }
}

fn escape_dot(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursive_detection::{CallEdge, CallGraph};

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn empty_names() -> HashMap<u64, String> {
        HashMap::new()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_linear_graph() -> CallGraph {
        // 0x1000 → 0x2000 → 0x3000
        let mut g = CallGraph::new();
        g.add_edge(CallEdge { caller: addr(0x1000), callee: addr(0x2000), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x2000), callee: addr(0x3000), is_tail_call: false });
        g
    }

    // ── Randomized oracle property tests ─────────────────────────────────────

    /// Oracle: `callgraph_from` on 500 random digraphs must return exactly the
    /// nodes within `depth` BFS hops of the root and exactly the edges whose
    /// source is within `depth - 1` hops, per an independent plain-BFS oracle.
    /// Also: two runs must be byte-identical (determinism), the root must be
    /// first, and edges must be sorted+deduped.
    #[test]
    fn prop_callgraph_from_matches_bfs_oracle() {
        use crate::test_prng::xs;
        let mut state = 0x5eed_cafe_f00d_0001u64;
        for _ in 0..500 {
            let n = 1 + (xs(&mut state) % 10); // 1..=10 nodes
            let node = |i: u64| 0x1000 + i * 0x10;
            let mut g = CallGraph::new();
            let mut raw_edges: Vec<(u64, u64)> = Vec::new();
            for i in 0..n {
                g.add_node(addr(node(i)));
            }
            for u in 0..n {
                for v in 0..n {
                    if xs(&mut state) % 100 < 25 {
                        g.add_edge(CallEdge {
                            caller: addr(node(u)),
                            callee: addr(node(v)),
                            is_tail_call: xs(&mut state) & 1 == 0,
                        });
                        raw_edges.push((node(u), node(v)));
                    }
                }
            }
            let root = node(xs(&mut state) % n);
            let depth = 1 + (xs(&mut state) % 4) as u32; // 1..=4

            // Plain BFS oracle: dist map from root.
            let mut dist: HashMap<u64, u32> = HashMap::new();
            dist.insert(root, 0);
            let mut q = VecDeque::new();
            q.push_back(root);
            while let Some(cur) = q.pop_front() {
                let d = dist[&cur];
                for &(u, v) in &raw_edges {
                    if u == cur && !dist.contains_key(&v) {
                        dist.insert(v, d + 1);
                        q.push_back(v);
                    }
                }
            }
            let oracle_nodes: HashSet<u64> =
                dist.iter().filter(|&(_, &d)| d <= depth).map(|(&a, _)| a).collect();
            let mut oracle_edges: Vec<(u64, u64)> = raw_edges
                .iter()
                .copied()
                .filter(|&(u, _)| dist.get(&u).is_some_and(|&d| d < depth))
                .collect();
            oracle_edges.sort_unstable();
            oracle_edges.dedup();

            let slice = callgraph_from(&g, addr(root), depth, &empty_names());
            let got_nodes: HashSet<u64> = slice.nodes.iter().map(|nd| nd.addr).collect();
            assert_eq!(
                got_nodes, oracle_nodes,
                "node set mismatch root={root:#x} depth={depth} edges={raw_edges:?}"
            );
            assert_eq!(got_nodes.len(), slice.nodes.len(), "duplicate nodes emitted");
            assert_eq!(slice.nodes[0].addr, root, "root must be first node");
            assert_eq!(
                slice.edges, oracle_edges,
                "edge set mismatch root={root:#x} depth={depth} edges={raw_edges:?}"
            );

            // Determinism: second run byte-identical.
            let again = callgraph_from(&g, addr(root), depth, &empty_names());
            assert_eq!(slice, again, "callgraph_from must be deterministic");
        }
    }

    // ── Basic reachability ────────────────────────────────────────────────────

    #[test]
    fn root_only_when_no_edges() {
        let mut g = CallGraph::new();
        g.add_node(addr(0xDEAD));
        let slice = callgraph_from(&g, addr(0xDEAD), 3, &empty_names());
        assert_eq!(slice.nodes.len(), 1);
        assert_eq!(slice.nodes[0].addr, 0xDEAD);
        assert!(slice.edges.is_empty());
    }

    #[test]
    fn root_included_even_when_not_in_graph() {
        let g = CallGraph::new();
        let slice = callgraph_from(&g, addr(0xBEEF), 3, &empty_names());
        assert_eq!(slice.nodes.len(), 1);
        assert_eq!(slice.nodes[0].addr, 0xBEEF);
    }

    #[test]
    fn linear_chain_depth_1() {
        let g = make_linear_graph();
        let slice = callgraph_from(&g, addr(0x1000), 1, &empty_names());
        // depth=1: root + direct callees only
        let addrs: Vec<u64> = slice.nodes.iter().map(|n| n.addr).collect();
        assert!(addrs.contains(&0x1000), "root missing");
        assert!(addrs.contains(&0x2000), "depth-1 callee missing");
        // 0x3000 is 2 hops away
        assert!(!addrs.contains(&0x3000), "depth-2 node should not appear at depth 1");
        assert_eq!(slice.edges, vec![(0x1000, 0x2000)]);
    }

    #[test]
    fn linear_chain_depth_2() {
        let g = make_linear_graph();
        let slice = callgraph_from(&g, addr(0x1000), 2, &empty_names());
        let addrs: Vec<u64> = slice.nodes.iter().map(|n| n.addr).collect();
        assert!(addrs.contains(&0x3000));
        assert!(slice.edges.contains(&(0x1000, 0x2000)));
        assert!(slice.edges.contains(&(0x2000, 0x3000)));
    }

    // ── Depth clamping ────────────────────────────────────────────────────────

    #[test]
    fn depth_zero_uses_default() {
        let g = make_linear_graph();
        // default depth is 3, which covers both hops of the 2-hop chain
        let slice_zero = callgraph_from(&g, addr(0x1000), 0, &empty_names());
        let slice_default = callgraph_from(&g, addr(0x1000), DEFAULT_DEPTH, &empty_names());
        assert_eq!(slice_zero.nodes.len(), slice_default.nodes.len());
        assert_eq!(slice_zero.edges.len(), slice_default.edges.len());
    }

    #[test]
    fn depth_above_max_clamped() {
        let g = make_linear_graph();
        let slice_over = callgraph_from(&g, addr(0x1000), 999, &empty_names());
        let slice_max = callgraph_from(&g, addr(0x1000), MAX_DEPTH, &empty_names());
        assert_eq!(slice_over.nodes.len(), slice_max.nodes.len());
    }

    // ── Cycle handling ────────────────────────────────────────────────────────

    #[test]
    fn cycle_does_not_loop_forever() {
        let mut g = CallGraph::new();
        // A → B → A  (cycle)
        g.add_edge(CallEdge { caller: addr(0xA), callee: addr(0xB), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0xB), callee: addr(0xA), is_tail_call: false });
        let slice = callgraph_from(&g, addr(0xA), 5, &empty_names());
        // Should terminate and contain exactly A and B
        let addrs: Vec<u64> = slice.nodes.iter().map(|n| n.addr).collect();
        assert!(addrs.contains(&0xA));
        assert!(addrs.contains(&0xB));
        assert_eq!(addrs.len(), 2);
    }

    // ── Name propagation ─────────────────────────────────────────────────────

    #[test]
    fn names_attached_to_nodes() {
        let g = make_linear_graph();
        let mut names = HashMap::new();
        names.insert(0x1000u64, "main".to_string());
        names.insert(0x2000u64, "helper".to_string());

        let slice = callgraph_from(&g, addr(0x1000), 2, &names);
        let main_node = slice.nodes.iter().find(|n| n.addr == 0x1000).unwrap();
        let helper_node = slice.nodes.iter().find(|n| n.addr == 0x2000).unwrap();
        let unknown_node = slice.nodes.iter().find(|n| n.addr == 0x3000).unwrap();

        assert_eq!(main_node.name.as_deref(), Some("main"));
        assert_eq!(helper_node.name.as_deref(), Some("helper"));
        assert!(unknown_node.name.is_none());
    }

    // ── Edge deduplication ────────────────────────────────────────────────────

    #[test]
    fn no_duplicate_edges() {
        // Graph with two paths to the same callee.
        let mut g = CallGraph::new();
        g.add_edge(CallEdge { caller: addr(0x10), callee: addr(0x30), is_tail_call: false });
        g.add_edge(CallEdge { caller: addr(0x10), callee: addr(0x30), is_tail_call: true });
        let slice = callgraph_from(&g, addr(0x10), 3, &empty_names());
        // CallGraph deduplicates by HashSet, so we expect one edge.
        let count = slice.edges.iter().filter(|&&e| e == (0x10, 0x30)).count();
        assert_eq!(count, 1, "expected exactly one edge (0x10→0x30)");
    }

    // ── Root is first node ────────────────────────────────────────────────────

    #[test]
    fn root_is_first_node() {
        let g = make_linear_graph();
        let slice = callgraph_from(&g, addr(0x1000), 3, &empty_names());
        assert_eq!(slice.nodes[0].addr, 0x1000);
    }

    // ── DOT rendering ─────────────────────────────────────────────────────────

    fn try_render_with_graphviz(dot: &str) -> Option<bool> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut child = Command::new("dot")
            .arg("-Tsvg")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(dot.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        Some(out.status.success() && out.stdout.starts_with(b"<?xml"))
    }

    #[test]
    fn dot_basic_structure() {
        let g = make_linear_graph();
        let mut names = HashMap::new();
        names.insert(0x1000u64, "main".to_string());
        let slice = callgraph_from(&g, addr(0x1000), 2, &names);
        let dot = render_callgraph_dot(&slice);

        assert!(dot.starts_with("// callgraph slice:"));
        assert!(dot.contains("digraph G {"));
        assert!(dot.trim_end().ends_with('}'));
        assert!(dot.contains("n1000"));
        assert!(dot.contains("n2000"));
        assert!(dot.contains("n3000"));
        assert!(dot.contains("label=\"main\""));
        assert!(dot.contains("label=\"2000\""));
        assert!(dot.contains("n1000 -> n2000;"));
        assert!(dot.contains("n2000 -> n3000;"));
        assert!(dot.contains("3 node(s)"));
        assert!(dot.contains("2 edge(s)"));
    }

    #[test]
    fn dot_styled_highlight_and_external() {
        let mut g = CallGraph::new();
        g.add_edge(CallEdge { caller: addr(0x1000), callee: addr(0x2000), is_tail_call: false });
        let mut names = HashMap::new();
        names.insert(0x1000u64, "main".to_string());
        names.insert(0x2000u64, "sub_2000".to_string());
        let slice = callgraph_from(&g, addr(0x1000), 1, &names);

        let opts = DotOpts {
            color_external: true,
            highlight_root_addr: Some(0x1000),
            font: Some("Helvetica".to_string()),
        };
        let dot = render_callgraph_dot_styled(&slice, &opts);

        assert!(dot.contains("fontname=\"Helvetica\""));
        assert!(dot.contains("fillcolor=lightyellow"));
        assert!(dot.contains("fillcolor=lightgray"));
    }

    #[test]
    fn dot_roundtrips_through_graphviz_when_available() {
        let g = make_linear_graph();
        let slice = callgraph_from(&g, addr(0x1000), 2, &empty_names());
        let dot = render_callgraph_dot(&slice);

        match try_render_with_graphviz(&dot) {
            Some(ok) => assert!(ok, "graphviz failed to render generated DOT"),
            None => {
                let re_header = regex::Regex::new(r"^// callgraph slice: \d+ node\(s\), \d+ edge\(s\)").unwrap();
                let re_digraph = regex::Regex::new(r"digraph\s+G\s*\{").unwrap();
                let re_edge = regex::Regex::new(r"n[0-9a-f]+\s+->\s+n[0-9a-f]+;").unwrap();
                assert!(re_header.is_match(&dot));
                assert!(re_digraph.is_match(&dot));
                assert!(re_edge.is_match(&dot));
            }
        }
    }
}
