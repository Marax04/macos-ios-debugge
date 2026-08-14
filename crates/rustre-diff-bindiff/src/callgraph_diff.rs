//! `callgraph_diff` — Call-graph level BinDiff for RustRE.
//!
//! Provides [`CallGraphDiff`], [`FunctionNode`], [`CallEdge`],
//! [`NodeSimilarity`], [`HungarianMatcher`], [`BinDiffReport`],
//! and [`VisualDiffOutput`].

use std::collections::HashMap;
use std::fmt;

// ── FunctionNode ─────────────────────────────────────────────────────────────

/// A function node in the call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionNode {
    pub address: u64,
    pub name: String,
    pub size: u64,
    /// CFG-level hash.
    pub cfg_hash: u64,
    /// Instruction-level hash.
    pub insn_hash: u64,
    /// Number of basic blocks.
    pub block_count: u32,
    /// Number of instructions.
    pub insn_count: u32,
    /// Number of callees (out-degree).
    pub call_count: u32,
    /// Whether the function is imported.
    pub is_imported: bool,
}

impl FunctionNode {
    #[must_use]
    pub fn new(address: u64, name: &str) -> Self {
        Self {
            address,
            name: name.to_owned(),
            size: 0,
            cfg_hash: 0,
            insn_hash: 0,
            block_count: 1,
            insn_count: 0,
            call_count: 0,
            is_imported: false,
        }
    }

    /// Compute a combined structural hash.
    #[must_use]
    pub const fn structural_hash(&self) -> u64 {
        self.cfg_hash ^ (self.insn_hash.rotate_left(32))
    }
}

impl fmt::Display for FunctionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{:#x}(blocks={},insns={})",
            self.name, self.address, self.block_count, self.insn_count
        )
    }
}

// ── CallEdge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_site: u64,
    pub is_indirect: bool,
}

// ── CallGraph ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub nodes: HashMap<u64, FunctionNode>,
    pub edges: Vec<CallEdge>,
}

impl CallGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, f: FunctionNode) {
        self.nodes.insert(f.address, f);
    }
    pub fn add_edge(&mut self, e: CallEdge) {
        self.edges.push(e);
    }

    #[must_use]
    pub fn callers_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|e| e.callee == addr)
            .map(|e| e.caller)
            .collect()
    }
    #[must_use]
    pub fn callees_of(&self, addr: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|e| e.caller == addr)
            .map(|e| e.callee)
            .collect()
    }
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.nodes.len()
    }
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ── NodeSimilarity ────────────────────────────────────────────────────────────

/// Similarity between two function nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeSimilarity {
    pub addr_a: u64,
    pub addr_b: u64,
    pub name_match: bool,
    /// Hash-based similarity [0.0, 1.0].
    pub hash_score: f64,
    /// Instruction-level structural similarity [0.0, 1.0].
    pub insn_score: f64,
    /// Call-graph context similarity [0.0, 1.0].
    pub cg_score: f64,
    /// Weighted aggregate score [0.0, 1.0].
    pub total_score: f64,
}

impl NodeSimilarity {
    #[must_use]
    pub fn compute(
        a: &FunctionNode,
        b: &FunctionNode,
        w_name: f64,
        w_hash: f64,
        w_insn: f64,
        w_cg: f64,
    ) -> Self {
        let name_match = a.name == b.name && !a.name.is_empty() && !a.name.starts_with("sub_");
        let hash_score = if a.cfg_hash == b.cfg_hash && a.cfg_hash != 0 {
            1.0
        } else {
            0.0
        };
        let insn_score = if a.insn_hash == b.insn_hash && a.insn_hash != 0 {
            1.0
        } else {
            let diff = (f64::from(a.insn_count) - f64::from(b.insn_count)).abs();
            let max = f64::from(a.insn_count.max(b.insn_count));
            if max == 0.0 {
                1.0
            } else {
                1.0 - (diff / max).min(1.0)
            }
        };
        let cg_score = {
            let call_diff = (f64::from(a.call_count) - f64::from(b.call_count)).abs();
            let call_max = f64::from(a.call_count.max(b.call_count));
            if call_max == 0.0 {
                1.0
            } else {
                1.0 - (call_diff / call_max).min(1.0)
            }
        };
        let name_f = if name_match { 1.0 } else { 0.0 };
        let total = w_cg.mul_add(cg_score, w_insn.mul_add(insn_score, w_name.mul_add(name_f, w_hash * hash_score)))
            / (w_name + w_hash + w_insn + w_cg);
        Self {
            addr_a: a.address,
            addr_b: b.address,
            name_match,
            hash_score,
            insn_score,
            cg_score,
            total_score: total,
        }
    }
}

// ── HungarianMatcher ─────────────────────────────────────────────────────────

/// Simplified optimal assignment (greedy approximation — O(n²)).
///
/// A full Hungarian algorithm would be O(n³); this greedy version picks the
/// best available match for each node, sorted by score.
pub struct HungarianMatcher;

impl HungarianMatcher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Maximum number of nodes per side for which an O(n²) Cartesian product
    /// is acceptable. Beyond this limit the product Vec would consume O(n²)
    /// memory and CPU, enabling a `DoS` from a crafted binary.
    const MAX_GRAPH_NODES: usize = 5_000;

    /// Compute an optimal (greedy) matching between nodes of two call graphs.
    ///
    /// # Panics
    /// Panics if either graph has more than [`Self::MAX_GRAPH_NODES`] nodes, to
    /// prevent a dos-memory-exhaustion attack from an over-sized call graph.
    #[must_use]
    pub fn match_graphs(a: &CallGraph, b: &CallGraph) -> Vec<NodeSimilarity> {
        assert!(
            a.nodes.len() <= Self::MAX_GRAPH_NODES,
            "HungarianMatcher::match_graphs: graph A has {} nodes, exceeds MAX_GRAPH_NODES {}",
            a.nodes.len(),
            Self::MAX_GRAPH_NODES
        );
        assert!(
            b.nodes.len() <= Self::MAX_GRAPH_NODES,
            "HungarianMatcher::match_graphs: graph B has {} nodes, exceeds MAX_GRAPH_NODES {}",
            b.nodes.len(),
            Self::MAX_GRAPH_NODES
        );
        let mut scores: Vec<NodeSimilarity> = Vec::new();
        for fa in a.nodes.values() {
            for fb in b.nodes.values() {
                let sim = NodeSimilarity::compute(fa, fb, 1.5, 2.0, 1.0, 0.5);
                scores.push(sim);
            }
        }
        // Sort by descending total_score.
        scores.sort_by(|x, y| {
            y.total_score
                .partial_cmp(&x.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut matched_a = std::collections::HashSet::new();
        let mut matched_b = std::collections::HashSet::new();
        let mut result = Vec::new();

        for s in scores {
            if !matched_a.contains(&s.addr_a) && !matched_b.contains(&s.addr_b) {
                matched_a.insert(s.addr_a);
                matched_b.insert(s.addr_b);
                result.push(s);
            }
        }
        result
    }
}

impl Default for HungarianMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── BinDiffReport ─────────────────────────────────────────────────────────────

/// Full `BinDiff` comparison report.
#[derive(Debug, Clone)]
pub struct BinDiffReport {
    pub binary_a: String,
    pub binary_b: String,
    pub matches: Vec<NodeSimilarity>,
    pub unmatched_a: Vec<u64>,
    pub unmatched_b: Vec<u64>,
}

impl BinDiffReport {
    #[must_use]
    pub fn similarity_score(&self) -> f64 {
        if self.matches.is_empty() {
            return 0.0;
        }
        self.matches.iter().map(|m| m.total_score).sum::<f64>()
            / f64::from(u32::try_from(self.matches.len()).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub const fn matched_count(&self) -> usize {
        self.matches.len()
    }
    #[must_use]
    pub const fn unmatched_a_count(&self) -> usize {
        self.unmatched_a.len()
    }
    #[must_use]
    pub const fn unmatched_b_count(&self) -> usize {
        self.unmatched_b.len()
    }

    #[must_use]
    pub fn exact_matches(&self) -> Vec<&NodeSimilarity> {
        self.matches
            .iter()
            .filter(|m| m.total_score >= 0.99)
            .collect()
    }

    #[must_use]
    pub fn changed_functions(&self) -> Vec<&NodeSimilarity> {
        self.matches
            .iter()
            .filter(|m| m.total_score < 0.99 && m.total_score >= 0.5)
            .collect()
    }
}

impl fmt::Display for BinDiffReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BinDiffReport: '{}' vs '{}'\n  matched={} unmatched_a={} unmatched_b={}\n  similarity={:.2}%",
            self.binary_a,
            self.binary_b,
            self.matched_count(),
            self.unmatched_a_count(),
            self.unmatched_b_count(),
            self.similarity_score() * 100.0
        )
    }
}

// ── CallGraphDiff ─────────────────────────────────────────────────────────────

/// Main entry point for call-graph level `BinDiff`.
pub struct CallGraphDiff;

impl CallGraphDiff {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compare two call graphs and return a full report.
    #[must_use]
    pub fn compare(
        &self,
        a: &CallGraph,
        b: &CallGraph,
        name_a: &str,
        name_b: &str,
    ) -> BinDiffReport {
        let matches = HungarianMatcher::match_graphs(a, b);
        let matched_a: std::collections::HashSet<u64> = matches.iter().map(|m| m.addr_a).collect();
        let matched_b: std::collections::HashSet<u64> = matches.iter().map(|m| m.addr_b).collect();

        let unmatched_a = a
            .nodes
            .keys()
            .filter(|k| !matched_a.contains(k))
            .copied()
            .collect();
        let unmatched_b = b
            .nodes
            .keys()
            .filter(|k| !matched_b.contains(k))
            .copied()
            .collect();

        BinDiffReport {
            binary_a: name_a.to_owned(),
            binary_b: name_b.to_owned(),
            matches,
            unmatched_a,
            unmatched_b,
        }
    }
}

impl Default for CallGraphDiff {
    fn default() -> Self {
        Self::new()
    }
}

// ── VisualDiffOutput ──────────────────────────────────────────────────────────

/// Renders a [`BinDiffReport`] to text/HTML output.
pub struct VisualDiffOutput;

impl VisualDiffOutput {
    #[must_use]
    pub fn to_text(report: &BinDiffReport) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "=== BinDiff: '{}' vs '{}' ===\n",
            report.binary_a, report.binary_b
        );
        let _ = writeln!(out, "Overall similarity: {:.1}%", report.similarity_score() * 100.0);
        let _ = writeln!(out, "Matched:   {}", report.matched_count());
        let _ = writeln!(out, "Unmatched A: {}", report.unmatched_a_count());
        let _ = write!(out, "Unmatched B: {}\n\n", report.unmatched_b_count());
        out.push_str("--- Matches ---\n");
        for m in &report.matches {
            let tag = if m.total_score >= 0.99 {
                "IDENTICAL"
            } else if m.total_score >= 0.75 {
                "SIMILAR"
            } else {
                "CHANGED"
            };
            let _ = writeln!(out, "  [{tag}] {:#x} <-> {:#x} score={:.2}", m.addr_a, m.addr_b, m.total_score);
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fn(addr: u64, name: &str, blocks: u32, insns: u32) -> FunctionNode {
        let mut f = FunctionNode::new(addr, name);
        f.block_count = blocks;
        f.insn_count = insns;
        f.cfg_hash = addr ^ u64::from(blocks);
        f.insn_hash = addr ^ u64::from(insns);
        f
    }

    fn simple_cg(fns: Vec<FunctionNode>) -> CallGraph {
        let mut cg = CallGraph::new();
        for f in fns {
            cg.add_function(f);
        }
        cg
    }

    #[test]
    fn test_function_node_display() {
        let f = make_fn(0x1000, "main", 5, 50);
        let s = f.to_string();
        assert!(s.contains("main"), "display='{s}'");
        assert!(s.contains("blocks=5"), "display='{s}'");
    }

    #[test]
    fn test_structural_hash() {
        let mut f = FunctionNode::new(0x1000, "foo");
        f.cfg_hash = 0xDEAD;
        f.insn_hash = 0xBEEF;
        let h1 = f.structural_hash();
        let h2 = f.structural_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_callgraph_add_find() {
        let mut cg = CallGraph::new();
        cg.add_function(make_fn(0x1000, "foo", 1, 10));
        assert_eq!(cg.function_count(), 1);
        assert!(cg.nodes.contains_key(&0x1000));
    }

    #[test]
    fn test_callgraph_edges() {
        let mut cg = CallGraph::new();
        cg.add_function(make_fn(0x1000, "main", 1, 5));
        cg.add_function(make_fn(0x2000, "helper", 1, 3));
        cg.add_edge(CallEdge {
            caller: 0x1000,
            callee: 0x2000,
            call_site: 0x1004,
            is_indirect: false,
        });
        assert_eq!(cg.edge_count(), 1);
        assert_eq!(cg.callees_of(0x1000), vec![0x2000]);
        assert_eq!(cg.callers_of(0x2000), vec![0x1000]);
    }

    #[test]
    fn test_node_similarity_identical() {
        let f = make_fn(0x1000, "foo", 5, 50);
        let g = make_fn(0x2000, "foo", 5, 50);
        let sim = NodeSimilarity::compute(&f, &g, 1.0, 1.0, 1.0, 1.0);
        assert!(sim.total_score >= 0.5, "score={}", sim.total_score);
        assert!(sim.name_match);
    }

    #[test]
    fn test_node_similarity_different_names() {
        let a = make_fn(0x1000, "sub_1000", 3, 30);
        let b = make_fn(0x2000, "sub_2000", 4, 35);
        let sim = NodeSimilarity::compute(&a, &b, 1.0, 1.0, 1.0, 0.0);
        assert!(!sim.name_match);
    }

    #[test]
    fn test_hungarian_matcher_empty() {
        let a = CallGraph::new();
        let b = CallGraph::new();
        let matches = HungarianMatcher::match_graphs(&a, &b);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_hungarian_matcher_single() {
        let cg_a = simple_cg(vec![make_fn(0x1000, "main", 3, 30)]);
        let cg_b = simple_cg(vec![make_fn(0x1000, "main", 3, 30)]);
        let matches = HungarianMatcher::match_graphs(&cg_a, &cg_b);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].total_score > 0.5);
    }

    #[test]
    fn test_hungarian_matcher_two_functions() {
        let cg_a = simple_cg(vec![
            make_fn(0x1000, "main", 3, 30),
            make_fn(0x2000, "helper", 1, 10),
        ]);
        let cg_b = simple_cg(vec![
            make_fn(0x1000, "main", 3, 30),
            make_fn(0x2000, "helper", 1, 10),
        ]);
        let matches = HungarianMatcher::match_graphs(&cg_a, &cg_b);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_compare_identical_binaries() {
        let cg = simple_cg(vec![
            make_fn(0x1000, "main", 5, 50),
            make_fn(0x2000, "init", 2, 20),
        ]);
        let diff = CallGraphDiff::new();
        let report = diff.compare(&cg, &cg, "a.exe", "b.exe");
        assert_eq!(report.matched_count(), 2);
        assert_eq!(report.unmatched_a_count(), 0);
        assert!(report.similarity_score() >= 0.0);
    }

    #[test]
    fn test_report_similarity_score() {
        let report = BinDiffReport {
            binary_a: "a".into(),
            binary_b: "b".into(),
            matches: vec![
                NodeSimilarity {
                    addr_a: 0,
                    addr_b: 0,
                    name_match: true,
                    hash_score: 1.0,
                    insn_score: 1.0,
                    cg_score: 1.0,
                    total_score: 1.0,
                },
                NodeSimilarity {
                    addr_a: 1,
                    addr_b: 1,
                    name_match: false,
                    hash_score: 0.5,
                    insn_score: 0.5,
                    cg_score: 0.5,
                    total_score: 0.5,
                },
            ],
            unmatched_a: Vec::new(),
            unmatched_b: Vec::new(),
        };
        let score = report.similarity_score();
        assert!((score - 0.75).abs() < 1e-6, "score={score}");
    }

    #[test]
    fn test_report_exact_vs_changed() {
        let report = BinDiffReport {
            binary_a: "a".into(),
            binary_b: "b".into(),
            matches: vec![
                NodeSimilarity {
                    addr_a: 0,
                    addr_b: 0,
                    name_match: true,
                    hash_score: 1.0,
                    insn_score: 1.0,
                    cg_score: 1.0,
                    total_score: 1.0,
                },
                NodeSimilarity {
                    addr_a: 1,
                    addr_b: 1,
                    name_match: false,
                    hash_score: 0.5,
                    insn_score: 0.6,
                    cg_score: 0.7,
                    total_score: 0.6,
                },
            ],
            unmatched_a: vec![0x3000],
            unmatched_b: Vec::new(),
        };
        assert_eq!(report.exact_matches().len(), 1);
        assert_eq!(report.changed_functions().len(), 1);
        assert_eq!(report.unmatched_a_count(), 1);
    }

    #[test]
    fn test_visual_diff_output() {
        let cg = simple_cg(vec![make_fn(0x1000, "foo", 1, 10)]);
        let report = CallGraphDiff::new().compare(&cg, &cg, "a", "b");
        let text = VisualDiffOutput::to_text(&report);
        assert!(text.contains("BinDiff"), "text='{text}'");
        assert!(text.contains("Matched"), "text='{text}'");
    }

    #[test]
    fn test_report_display() {
        let report = BinDiffReport {
            binary_a: "old.exe".into(),
            binary_b: "new.exe".into(),
            matches: Vec::new(),
            unmatched_a: Vec::new(),
            unmatched_b: Vec::new(),
        };
        let s = report.to_string();
        assert!(s.contains("old.exe"), "display='{s}'");
        assert!(s.contains("new.exe"), "display='{s}'");
    }

    #[test]
    fn test_hungarian_matcher_default() {
        let _ = HungarianMatcher;
    }

    #[test]
    fn test_callgraph_diff_default() {
        let _ = CallGraphDiff;
    }
}
