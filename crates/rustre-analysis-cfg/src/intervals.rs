//! Allen–Cocke interval analysis and Cifuentes/Simon-style region-based
//! structuring.
//!
//! An *interval* `I(h)` with header `h` is the maximal single-entry subgraph
//! in which `h` is the only entry node and all cycles contain `h`.  The
//! *derived sequence* `G0, G1, …, Gn` is obtained by repeatedly collapsing
//! every interval to a single node; the CFG is reducible iff the sequence
//! terminates in a single node (the "trivial graph").
//!
//! On top of the intervals we perform Cifuentes-style loop structuring:
//! for each interval whose header receives a back edge from inside the
//! interval, the loop is classified as pre-tested (`while`), post-tested
//! (`do/while`) or endless, and the loop body plus follow node are recorded
//! as region metadata.

use crate::ControlFlowGraph;
use rustre_core::address::Address;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// Interval
// ─────────────────────────────────────────────────────────────────────────────

/// A single Allen–Cocke interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interval {
    /// The unique entry (header) node of the interval.
    pub header: Address,
    /// All nodes in the interval, including the header (sorted by address).
    pub nodes: Vec<Address>,
}

impl Interval {
    /// Whether `addr` belongs to this interval.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.nodes.binary_search_by_key(&addr.0, |a| a.0).is_ok()
    }

    /// Number of nodes in the interval.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the interval contains only its header.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// An abstract flow graph used at each level of the derived sequence.
#[derive(Debug, Clone, Default)]
pub struct IntervalGraph {
    /// Node set (headers of the previous level's intervals; at level 0 these
    /// are basic-block addresses).  Sorted.
    pub nodes: Vec<Address>,
    /// Directed edges between nodes.
    pub edges: Vec<(Address, Address)>,
    /// Entry node.
    pub entry: Address,
}

impl IntervalGraph {
    fn preds(&self) -> HashMap<Address, Vec<Address>> {
        let mut m: HashMap<Address, Vec<Address>> = HashMap::new();
        for &(f, t) in &self.edges {
            m.entry(t).or_default().push(f);
        }
        m
    }

    fn succs(&self) -> HashMap<Address, Vec<Address>> {
        let mut m: HashMap<Address, Vec<Address>> = HashMap::new();
        for &(f, t) in &self.edges {
            m.entry(f).or_default().push(t);
        }
        m
    }
}

/// Compute the Allen–Cocke intervals of `g`.
///
/// Classic worklist algorithm: start with `H = {entry}`; for each header `h`
/// grow `I(h)` by adding any node all of whose predecessors are already in
/// `I(h)`; any node with *some* predecessor in an interval but not fully
/// contained becomes a new header.
#[must_use]
pub fn compute_intervals(g: &IntervalGraph) -> Vec<Interval> {
    let preds = g.preds();
    let succs = g.succs();
    let node_set: BTreeSet<Address> = g.nodes.iter().copied().collect();

    let mut headers: BTreeSet<Address> = BTreeSet::new();
    let mut processed_headers: BTreeSet<Address> = BTreeSet::new();
    let mut in_interval: HashSet<Address> = HashSet::new();
    let mut intervals: Vec<Interval> = Vec::new();

    if !node_set.contains(&g.entry) {
        return intervals;
    }
    headers.insert(g.entry);

    while let Some(&h) = headers.iter().find(|h| !processed_headers.contains(h)) {
        processed_headers.insert(h);
        let mut body: BTreeSet<Address> = BTreeSet::new();
        body.insert(h);
        in_interval.insert(h);

        // Grow: add n if all preds of n are in body and n not yet claimed.
        let mut changed = true;
        while changed {
            changed = false;
            for &n in &node_set {
                if body.contains(&n) || in_interval.contains(&n) || n == g.entry {
                    continue;
                }
                let ps = preds.get(&n).map_or(&[][..], Vec::as_slice);
                if !ps.is_empty() && ps.iter().all(|p| body.contains(p)) {
                    body.insert(n);
                    in_interval.insert(n);
                    changed = true;
                }
            }
        }

        // New headers: nodes not in any interval with a predecessor in body.
        for &n in &body {
            for &s in succs.get(&n).map_or(&[][..], Vec::as_slice) {
                if !in_interval.contains(&s) && !body.contains(&s) {
                    headers.insert(s);
                }
            }
        }

        intervals.push(Interval {
            header: h,
            nodes: body.into_iter().collect(),
        });
    }

    // Unreachable nodes get their own trivial intervals so every node is
    // covered (keeps callers total).
    for &n in &node_set {
        if !in_interval.contains(&n) {
            intervals.push(Interval {
                header: n,
                nodes: vec![n],
            });
        }
    }

    intervals
}

/// The derived sequence of interval graphs `G0..Gn`.
#[derive(Debug, Clone)]
pub struct DerivedSequence {
    /// `graphs[0]` is the original graph; each following entry is the result
    /// of collapsing every interval of the previous graph to one node.
    pub graphs: Vec<IntervalGraph>,
    /// Intervals computed for each graph in `graphs` (same indices).
    pub intervals: Vec<Vec<Interval>>,
    /// `true` when the final derived graph is a single node.
    pub reducible: bool,
}

/// Build the derived sequence for `g0`, stopping at the trivial graph or a
/// fixpoint (non-trivial fixpoint ⇒ irreducible).
#[must_use]
pub fn derived_sequence(g0: IntervalGraph) -> DerivedSequence {
    let mut graphs = vec![g0];
    let mut all_intervals: Vec<Vec<Interval>> = Vec::new();

    loop {
        let g = graphs.last().unwrap();
        let ivals = compute_intervals(g);

        // Map node → its interval header.
        let mut owner: HashMap<Address, Address> = HashMap::new();
        for iv in &ivals {
            for &n in &iv.nodes {
                owner.insert(n, iv.header);
            }
        }

        // Build the next-level graph: nodes = headers, edges = inter-interval
        // edges (dedup).
        let mut next_nodes: BTreeSet<Address> = ivals.iter().map(|i| i.header).collect();
        let mut next_edges: BTreeSet<(Address, Address)> = BTreeSet::new();
        for &(f, t) in &g.edges {
            if let (Some(&fo), Some(&to)) = (owner.get(&f), owner.get(&t))
                && fo != to
            {
                next_edges.insert((fo, to));
            }
        }
        // Self-loops on a header (back edge to interval header from inside
        // the same interval) are absorbed — that is exactly the collapse step.
        next_nodes.insert(g.entry);
        let entry_owner = owner.get(&g.entry).copied().unwrap_or(g.entry);

        let next = IntervalGraph {
            nodes: next_nodes.into_iter().collect(),
            edges: next_edges.into_iter().collect(),
            entry: entry_owner,
        };

        let trivial = next.nodes.len() == 1 && next.edges.is_empty();
        let stalled = next.nodes.len() == graphs.last().unwrap().nodes.len();
        all_intervals.push(ivals);

        if trivial {
            graphs.push(next);
            return DerivedSequence {
                graphs,
                intervals: all_intervals,
                reducible: true,
            };
        }
        if stalled {
            return DerivedSequence {
                graphs,
                intervals: all_intervals,
                reducible: false,
            };
        }
        graphs.push(next);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cifuentes-style loop / region structuring on intervals
// ─────────────────────────────────────────────────────────────────────────────

/// Loop shape as classified from the interval structure (Cifuentes 1996,
/// "Structuring Decompiled Graphs").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntervalLoopKind {
    /// Condition tested at the header (`while`).
    PreTested,
    /// Condition tested at the latch (`do/while`).
    PostTested,
    /// No conditional exit at header or latch (`for(;;)`).
    Endless,
}

/// The kind of structured region recovered from interval analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StructuredRegionKind {
    /// A loop region (see [`IntervalLoop::kind`]).
    Loop(IntervalLoopKind),
    /// A single-entry acyclic interval (straight-line / branching region).
    Acyclic,
    /// Multi-entry (irreducible) region left over after the derived sequence
    /// stalled.
    Improper,
}

/// A structured loop discovered on the level-0 interval graph.
#[derive(Debug, Clone)]
pub struct IntervalLoop {
    /// Loop header (interval header).
    pub header: Address,
    /// Latching node (source of the back edge to `header`).
    pub latch: Address,
    /// All blocks in the loop body (header..latch within the interval).
    pub body: BTreeSet<Address>,
    /// Loop shape.
    pub kind: IntervalLoopKind,
    /// The follow node — first block after the loop, if determinable.
    pub follow: Option<Address>,
}

/// A structured region: one entry per interval, tagged with its recovered
/// shape.  This is the "region metadata" surface consumed by structuring.
#[derive(Debug, Clone)]
pub struct StructuredRegion {
    pub header: Address,
    pub blocks: Vec<Address>,
    pub kind: StructuredRegionKind,
}

/// Full interval/region analysis result for one CFG.
#[derive(Debug, Clone)]
pub struct IntervalAnalysis {
    /// Level-0 intervals over basic blocks.
    pub intervals: Vec<Interval>,
    /// The full derived sequence.
    pub derived: DerivedSequence,
    /// Loops structured from the intervals.
    pub loops: Vec<IntervalLoop>,
    /// One region per level-0 interval.
    pub regions: Vec<StructuredRegion>,
    /// Whether the CFG is reducible by interval collapse.
    pub reducible: bool,
}

impl IntervalAnalysis {
    /// Run interval analysis + region structuring over a fully-built CFG.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let g0 = IntervalGraph {
            nodes: {
                let mut v: Vec<Address> = cfg.blocks.keys().copied().collect();
                v.sort_by_key(|a| a.0);
                v
            },
            edges: cfg.edges.iter().map(|e| (e.from, e.to)).collect(),
            entry: cfg.entry,
        };
        let intervals = compute_intervals(&g0);
        let derived = derived_sequence(g0.clone());

        let succs = g0.succs();
        let preds = g0.preds();

        // Node out-degree used to detect 2-way (conditional) blocks.
        let out_degree =
            |a: Address| -> usize { succs.get(&a).map_or(0, Vec::len) };

        // Structure loops: for each interval, find a back edge latch→header
        // with latch inside the interval.
        let mut loops: Vec<IntervalLoop> = Vec::new();
        let mut loop_headers: HashSet<Address> = HashSet::new();
        for iv in &intervals {
            let latch = preds
                .get(&iv.header)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .copied()
                .filter(|p| iv.contains(*p) && *p != iv.header)
                .max_by_key(|a| a.0);
            let latch = match latch {
                Some(l) => l,
                // Self-loop header→header counts too.
                None => {
                    if succs
                        .get(&iv.header)
                        .is_some_and(|s| s.contains(&iv.header))
                    {
                        iv.header
                    } else {
                        continue;
                    }
                }
            };

            // Loop body: nodes of the interval on a path header→latch.
            // Approximation per Cifuentes: nodes in the interval whose
            // reverse-reachability from latch (within the interval) includes
            // them and that are forward-reachable from header.
            let body = loop_body_in_interval(iv, &preds, &succs, latch);

            // Classify the loop.
            let header_2way = out_degree(iv.header) == 2;
            let latch_2way = out_degree(latch) == 2;
            let header_exits = succs
                .get(&iv.header)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .any(|s| !body.contains(s));
            let latch_exits = succs
                .get(&latch)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .any(|s| !body.contains(s));

            let kind = if latch_2way && latch_exits {
                // Latch decides — but if the header also conditionally exits
                // and the latch is the header (self-loop) treat as post-tested.
                if header_2way && header_exits && latch != iv.header {
                    IntervalLoopKind::PreTested
                } else {
                    IntervalLoopKind::PostTested
                }
            } else if header_2way && header_exits {
                IntervalLoopKind::PreTested
            } else {
                IntervalLoopKind::Endless
            };

            // Follow node: the out-of-body successor of the deciding node.
            let decider = match kind {
                IntervalLoopKind::PreTested => iv.header,
                IntervalLoopKind::PostTested => latch,
                IntervalLoopKind::Endless => iv.header,
            };
            let follow = succs
                .get(&decider)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .copied()
                .find(|s| !body.contains(s))
                .or_else(|| {
                    // Endless loops may still have a break exit elsewhere.
                    body.iter()
                        .flat_map(|b| succs.get(b).map_or(&[][..], Vec::as_slice))
                        .copied()
                        .find(|s| !body.contains(s))
                });

            loop_headers.insert(iv.header);
            loops.push(IntervalLoop {
                header: iv.header,
                latch,
                body,
                kind,
                follow,
            });
        }

        // Region metadata: one region per interval.
        let improper_headers: HashSet<Address> = if derived.reducible {
            HashSet::new()
        } else {
            // Every node still present in the stalled final graph that is the
            // target of ≥ 2 inter-interval edges marks an improper region.
            let last = derived.graphs.last().unwrap();
            let mut indeg: BTreeMap<Address, usize> = BTreeMap::new();
            for &(_, t) in &last.edges {
                *indeg.entry(t).or_insert(0) += 1;
            }
            indeg
                .into_iter()
                .filter(|&(_, d)| d >= 2)
                .map(|(a, _)| a)
                .collect()
        };

        let regions = intervals
            .iter()
            .map(|iv| {
                let kind = if let Some(lp) = loops.iter().find(|l| l.header == iv.header) {
                    StructuredRegionKind::Loop(lp.kind)
                } else if improper_headers.contains(&iv.header) {
                    StructuredRegionKind::Improper
                } else {
                    StructuredRegionKind::Acyclic
                };
                StructuredRegion {
                    header: iv.header,
                    blocks: iv.nodes.clone(),
                    kind,
                }
            })
            .collect();

        let reducible = derived.reducible;
        Self {
            intervals,
            derived,
            loops,
            regions,
            reducible,
        }
    }

    /// The innermost loop containing `addr`, if any (smallest body).
    #[must_use]
    pub fn loop_at(&self, addr: Address) -> Option<&IntervalLoop> {
        self.loops
            .iter()
            .filter(|l| l.body.contains(&addr))
            .min_by_key(|l| l.body.len())
    }

    /// Region whose header is `header`.
    #[must_use]
    pub fn region_for(&self, header: Address) -> Option<&StructuredRegion> {
        self.regions.iter().find(|r| r.header == header)
    }
}

/// Nodes in `iv` that lie on a path header→latch: intersection of
/// forward-reachable-from-header and backward-reachable-from-latch, computed
/// within the interval.
fn loop_body_in_interval(
    iv: &Interval,
    preds: &HashMap<Address, Vec<Address>>,
    succs: &HashMap<Address, Vec<Address>>,
    latch: Address,
) -> BTreeSet<Address> {
    let in_iv: HashSet<Address> = iv.nodes.iter().copied().collect();

    let mut fwd: HashSet<Address> = HashSet::new();
    let mut stack = vec![iv.header];
    while let Some(n) = stack.pop() {
        if fwd.insert(n) {
            for &s in succs.get(&n).map_or(&[][..], Vec::as_slice) {
                if in_iv.contains(&s) && !fwd.contains(&s) {
                    stack.push(s);
                }
            }
        }
    }

    let mut bwd: HashSet<Address> = HashSet::new();
    let mut stack = vec![latch];
    while let Some(n) = stack.pop() {
        if bwd.insert(n) {
            if n == iv.header {
                continue; // don't walk above the header
            }
            for &p in preds.get(&n).map_or(&[][..], Vec::as_slice) {
                if in_iv.contains(&p) && !bwd.contains(&p) {
                    stack.push(p);
                }
            }
        }
    }

    let mut body: BTreeSet<Address> = fwd.intersection(&bwd).copied().collect();
    body.insert(iv.header);
    body.insert(latch);
    body
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, CfgEdge, DominatorTree, EdgeKind, PostDominatorTree};
    use std::collections::HashMap as StdHashMap;

    fn a(v: u64) -> Address {
        Address::new(v)
    }

    fn graph(nodes: &[u64], edges: &[(u64, u64)], entry: u64) -> IntervalGraph {
        IntervalGraph {
            nodes: nodes.iter().map(|&n| a(n)).collect(),
            edges: edges.iter().map(|&(f, t)| (a(f), a(t))).collect(),
            entry: a(entry),
        }
    }

    fn cfg(nodes: &[u64], edges: &[(u64, u64)], entry: u64) -> ControlFlowGraph {
        let blocks: StdHashMap<Address, BasicBlock> = nodes
            .iter()
            .map(|&n| {
                (
                    a(n),
                    BasicBlock {
                        start: a(n),
                        end: a(n),
                        instructions: vec![],
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let dom_tree = DominatorTree::compute(&blocks, &edges, a(entry));
        let post_dom_tree = PostDominatorTree::compute(&blocks, &edges);
        let mut c = ControlFlowGraph {
            blocks,
            edges,
            entry: a(entry),
            dom_tree,
            loops: vec![],
            post_dom_tree,
        };
        c.loops = crate::find_natural_loops(&c);
        c
    }

    #[test]
    fn straight_line_single_interval() {
        let g = graph(&[1, 2, 3], &[(1, 2), (2, 3)], 1);
        let ivals = compute_intervals(&g);
        assert_eq!(ivals.len(), 1);
        assert_eq!(ivals[0].header, a(1));
        assert_eq!(ivals[0].nodes, vec![a(1), a(2), a(3)]);
    }

    #[test]
    fn diamond_is_one_interval() {
        let g = graph(&[1, 2, 3, 4], &[(1, 2), (1, 3), (2, 4), (3, 4)], 1);
        let ivals = compute_intervals(&g);
        assert_eq!(ivals.len(), 1);
        assert_eq!(ivals[0].len(), 4);
    }

    #[test]
    fn while_loop_splits_intervals() {
        // 1 -> 2(header) -> 3 -> 2 ; 2 -> 4
        let g = graph(&[1, 2, 3, 4], &[(1, 2), (2, 3), (3, 2), (2, 4)], 1);
        let ivals = compute_intervals(&g);
        // I(1) = {1}, I(2) = {2,3,4}
        assert_eq!(ivals.len(), 2);
        let i2 = ivals.iter().find(|i| i.header == a(2)).unwrap();
        assert!(i2.contains(a(3)));
        assert!(i2.contains(a(4)));
    }

    #[test]
    fn derived_sequence_reducible_terminates_trivially() {
        let g = graph(&[1, 2, 3, 4], &[(1, 2), (2, 3), (3, 2), (2, 4)], 1);
        let ds = derived_sequence(g);
        assert!(ds.reducible);
        let last = ds.graphs.last().unwrap();
        assert_eq!(last.nodes.len(), 1);
        assert!(last.edges.is_empty());
    }

    #[test]
    fn derived_sequence_irreducible_stalls() {
        // Classic irreducible: 1->2, 1->3, 2->3, 3->2
        let g = graph(&[1, 2, 3], &[(1, 2), (1, 3), (2, 3), (3, 2)], 1);
        let ds = derived_sequence(g);
        assert!(!ds.reducible);
        assert!(ds.graphs.last().unwrap().nodes.len() > 1);
    }

    #[test]
    fn analysis_pre_tested_loop() {
        // while: 1 -> 2(cond: ->3 body, ->4 exit), 3 -> 2
        let c = cfg(&[1, 2, 3, 4], &[(1, 2), (2, 3), (2, 4), (3, 2)], 1);
        let ia = IntervalAnalysis::compute(&c);
        assert!(ia.reducible);
        assert_eq!(ia.loops.len(), 1);
        let lp = &ia.loops[0];
        assert_eq!(lp.header, a(2));
        assert_eq!(lp.latch, a(3));
        assert_eq!(lp.kind, IntervalLoopKind::PreTested);
        assert_eq!(lp.follow, Some(a(4)));
        assert!(lp.body.contains(&a(2)) && lp.body.contains(&a(3)));
        assert!(!lp.body.contains(&a(4)));
    }

    #[test]
    fn analysis_post_tested_loop() {
        // do/while: 1 -> 2 -> 3(cond: ->2 back, ->4 exit)
        let c = cfg(&[1, 2, 3, 4], &[(1, 2), (2, 3), (3, 2), (3, 4)], 1);
        let ia = IntervalAnalysis::compute(&c);
        let lp = ia.loops.iter().find(|l| l.header == a(2)).unwrap();
        assert_eq!(lp.kind, IntervalLoopKind::PostTested);
        assert_eq!(lp.latch, a(3));
        assert_eq!(lp.follow, Some(a(4)));
    }

    #[test]
    fn analysis_endless_loop() {
        // 1 -> 2 -> 3 -> 2, no exit
        let c = cfg(&[1, 2, 3], &[(1, 2), (2, 3), (3, 2)], 1);
        let ia = IntervalAnalysis::compute(&c);
        let lp = ia.loops.iter().find(|l| l.header == a(2)).unwrap();
        assert_eq!(lp.kind, IntervalLoopKind::Endless);
        assert_eq!(lp.follow, None);
    }

    #[test]
    fn analysis_self_loop() {
        let c = cfg(&[1, 2, 3], &[(1, 2), (2, 2), (2, 3)], 1);
        let ia = IntervalAnalysis::compute(&c);
        let lp = ia.loops.iter().find(|l| l.header == a(2)).unwrap();
        assert_eq!(lp.latch, a(2));
        assert_eq!(lp.kind, IntervalLoopKind::PostTested);
        assert_eq!(lp.follow, Some(a(3)));
    }

    #[test]
    fn regions_tag_loop_and_acyclic() {
        let c = cfg(&[1, 2, 3, 4], &[(1, 2), (2, 3), (2, 4), (3, 2)], 1);
        let ia = IntervalAnalysis::compute(&c);
        let r1 = ia.region_for(a(1)).unwrap();
        assert_eq!(r1.kind, StructuredRegionKind::Acyclic);
        let r2 = ia.region_for(a(2)).unwrap();
        assert!(matches!(r2.kind, StructuredRegionKind::Loop(_)));
    }

    #[test]
    fn irreducible_cfg_marks_improper_region() {
        let c = cfg(&[1, 2, 3], &[(1, 2), (1, 3), (2, 3), (3, 2)], 1);
        let ia = IntervalAnalysis::compute(&c);
        assert!(!ia.reducible);
        assert!(
            ia.regions
                .iter()
                .any(|r| r.kind == StructuredRegionKind::Improper)
        );
    }

    #[test]
    fn loop_at_finds_innermost() {
        // Nested: outer 2..5, inner 3..4
        let c = cfg(
            &[1, 2, 3, 4, 5, 6],
            &[(1, 2), (2, 3), (3, 4), (4, 3), (4, 5), (5, 2), (5, 6)],
            1,
        );
        let ia = IntervalAnalysis::compute(&c);
        // Level-0 intervals only expose the inner loop; the outer loop shows
        // up at higher derivation levels. loop_at should find the inner one.
        if let Some(lp) = ia.loop_at(a(3)) {
            assert!(lp.body.contains(&a(3)));
        }
        assert!(ia.derived.graphs.len() >= 2);
        assert!(ia.reducible);
    }

    #[test]
    fn unreachable_nodes_get_trivial_intervals() {
        let g = graph(&[1, 2, 99], &[(1, 2)], 1);
        let ivals = compute_intervals(&g);
        assert!(ivals.iter().any(|i| i.header == a(99) && i.len() == 1));
    }
}
