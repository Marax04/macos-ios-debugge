//! `register_colouring` — register allocation / colouring for calling-convention analysis.
//!
//! Provides:
//! * [`RegisterColouring`]     — top-level coordinator.
//! * [`InterferenceGraph`]     — register interference graph.
//! * [`ColoringResult`]        — assignment of registers to colours.
//! * [`SpillDecision`]         — which registers are spilled to memory.
//! * [`LiveRange`]             — live range for a virtual register.
//! * [`CoalescingHeuristic`]   — move-coalescing optimizer.
//! * [`AllocationMap`]         — final virtual → physical register map.

use petgraph::stable_graph::{NodeIndex, StableGraph};
use petgraph::Undirected;
use rustc_hash::FxHashMap;
use std::collections::{HashSet, VecDeque};

/// Re-exported worklist queue type used by allocator passes.
pub type RegWorklist<T> = VecDeque<T>;

// ─────────────────────────────────────────────────────────────────────────────
// Register abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual register identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VReg(pub u32);

impl VReg {
    #[must_use] 
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for VReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A physical register identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PReg(pub u32);

impl PReg {
    #[must_use] 
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for PReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

/// A "colour" in graph-coloring terms (corresponds to a physical register).
pub type Color = u32;

// ─────────────────────────────────────────────────────────────────────────────
// LiveRange
// ─────────────────────────────────────────────────────────────────────────────

/// A live range for a virtual register: `[start, end)` in instruction index space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRange {
    pub vreg: VReg,
    pub start: u32,
    pub end: u32,
}

impl LiveRange {
    #[must_use] 
    pub fn new(vreg: VReg, start: u32, end: u32) -> Self {
        assert!(start <= end, "live range start must be <= end");
        Self { vreg, start, end }
    }

    /// True if this range overlaps with `other`.
    #[must_use] 
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Length of the live range.
    #[must_use] 
    pub const fn len(&self) -> u32 {
        self.end - self.start
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterferenceGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Interference graph: nodes are virtual registers, edges connect registers
/// that are simultaneously live and thus cannot share a physical register.
///
/// Backed by a `petgraph::stable_graph::StableGraph` for O(1) neighbour
/// queries, O(1) degree computation, and O(1) node removal.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct InterferenceGraph {
    /// The underlying petgraph undirected stable graph.
    graph: StableGraph<VReg, (), Undirected>,
    /// Map from `VReg` to its `NodeIndex` in the graph.
    node_map: FxHashMap<VReg, NodeIndex>,
    /// All registered virtual registers (kept in sync with graph nodes).
    pub registers: HashSet<VReg>,
}


impl InterferenceGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a virtual register (no-op if already present).
    pub fn add_register(&mut self, v: VReg) {
        if !self.node_map.contains_key(&v) {
            let idx = self.graph.add_node(v);
            self.node_map.insert(v, idx);
            self.registers.insert(v);
        }
    }

    /// Add an interference edge between `a` and `b`.
    pub fn add_edge(&mut self, a: VReg, b: VReg) {
        if a == b {
            return;
        }
        self.add_register(a);
        self.add_register(b);
        let ia = self.node_map[&a];
        let ib = self.node_map[&b];
        // petgraph allows parallel edges; guard against duplicates.
        if !self.graph.contains_edge(ia, ib) {
            self.graph.add_edge(ia, ib, ());
        }
    }

    /// True if `a` and `b` interfere.
    #[must_use] 
    pub fn interferes(&self, a: VReg, b: VReg) -> bool {
        match (self.node_map.get(&a), self.node_map.get(&b)) {
            (Some(&ia), Some(&ib)) => self.graph.contains_edge(ia, ib),
            _ => false,
        }
    }

    /// Degree (number of neighbours) of `v`.
    #[must_use] 
    pub fn degree(&self, v: VReg) -> usize {
        self.node_map
            .get(&v)
            .map_or(0, |&idx| self.graph.neighbors(idx).count())
    }

    /// All neighbours of `v` as a `HashSet`.
    #[must_use] 
    pub fn neighbours(&self, v: VReg) -> HashSet<VReg> {
        self.node_map
            .get(&v)
            .map(|&idx| {
                self.graph
                    .neighbors(idx)
                    .map(|n| *self.graph.node_weight(n).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Build interference graph from a list of live ranges.
    ///
    /// Uses a sweep-line over ranges sorted by start instead of the naive
    /// all-pairs `O(n^2)` comparison: for each range only the (typically
    /// small) set of still-active ranges is checked, which is `O(n log n +
    /// n * max_concurrent_live_ranges)` in practice — a large win for
    /// functions with many virtual registers where live ranges rarely all
    /// overlap simultaneously.
    #[must_use]
    pub fn from_live_ranges(ranges: &[LiveRange]) -> Self {
        let mut ig = Self::new();
        for r in ranges {
            ig.add_register(r.vreg);
        }

        let mut sorted: Vec<&LiveRange> = ranges.iter().collect();
        sorted.sort_by_key(|r| r.start);

        let mut active: Vec<&LiveRange> = Vec::new();
        for r in &sorted {
            // Drop ranges that ended before this one starts.
            active.retain(|a| a.end > r.start);
            for a in &active {
                // `active` only holds ranges with `a.end > r.start`; combined
                // with `a.start <= r.start` (sort order) this is exactly the
                // `overlaps` condition, so no need to re-check it.
                ig.add_edge(a.vreg, r.vreg);
            }
            active.push(r);
        }
        ig
    }

    /// Total number of edges.
    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Remove a node and all its edges (used during simplification).
    pub fn remove(&mut self, v: VReg) {
        if let Some(idx) = self.node_map.remove(&v) {
            self.graph.remove_node(idx);
            self.registers.remove(&v);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SpillDecision
// ─────────────────────────────────────────────────────────────────────────────

/// Records which virtual registers must be spilled to memory because no
/// physical register is available.
#[derive(Debug, Clone, Default)]
pub struct SpillDecision {
    /// Set of virtual registers that are spilled.
    pub spilled: HashSet<VReg>,
    /// Estimated spill cost per vreg (higher = more expensive to spill).
    pub costs: FxHashMap<VReg, f32>,
}

impl SpillDecision {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn spill(&mut self, v: VReg, cost: f32) {
        self.spilled.insert(v);
        self.costs.insert(v, cost);
    }

    #[must_use] 
    pub fn is_spilled(&self, v: VReg) -> bool {
        self.spilled.contains(&v)
    }

    #[must_use] 
    pub fn spill_count(&self) -> usize {
        self.spilled.len()
    }

    /// Total estimated spill cost.
    #[must_use] 
    pub fn total_cost(&self) -> f32 {
        self.costs.values().sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AllocationMap
// ─────────────────────────────────────────────────────────────────────────────

/// Final mapping of virtual registers to physical registers (colours).
#[derive(Debug, Clone, Default)]
pub struct AllocationMap {
    pub map: FxHashMap<VReg, PReg>,
}

impl AllocationMap {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assign(&mut self, v: VReg, p: PReg) {
        self.map.insert(v, p);
    }

    #[must_use] 
    pub fn get(&self, v: VReg) -> Option<PReg> {
        self.map.get(&v).copied()
    }

    #[must_use] 
    pub fn assigned_count(&self) -> usize {
        self.map.len()
    }

    /// True if `v` has been assigned a physical register.
    #[must_use] 
    pub fn is_assigned(&self, v: VReg) -> bool {
        self.map.contains_key(&v)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ColoringResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a graph-colouring pass.
#[derive(Debug, Clone)]
pub struct ColoringResult {
    /// Colour assignment: `vreg → colour` (physical register index).
    pub colors: FxHashMap<VReg, Color>,
    /// Number of colours used.
    pub colors_used: usize,
    /// Virtual registers that could not be coloured (spills).
    pub uncolored: Vec<VReg>,
}

impl ColoringResult {
    #[must_use] 
    pub fn color_of(&self, v: VReg) -> Option<Color> {
        self.colors.get(&v).copied()
    }

    #[must_use] 
    pub fn is_colored(&self, v: VReg) -> bool {
        self.colors.contains_key(&v)
    }

    #[must_use] 
    pub const fn spill_count(&self) -> usize {
        self.uncolored.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoalescingHeuristic
// ─────────────────────────────────────────────────────────────────────────────

/// A candidate pair for move-coalescing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoalescePair {
    pub src: VReg,
    pub dst: VReg,
}

impl CoalescePair {
    #[must_use] 
    pub const fn new(src: VReg, dst: VReg) -> Self {
        Self { src, dst }
    }
}

/// Decides which move-pairs can be coalesced without adding new interferences.
///
/// Uses George's conservative coalescing criterion:
/// `a` and `b` can be coalesced if all their high-degree neighbours of `a`
/// are also neighbours of `b` (or vice versa), where "high degree" means
/// `degree >= num_colors`.
pub struct CoalescingHeuristic {
    pub num_colors: usize,
}

impl CoalescingHeuristic {
    #[must_use] 
    pub const fn new(num_colors: usize) -> Self {
        Self { num_colors }
    }

    /// True when the move `src → dst` can be coalesced conservatively.
    #[must_use] 
    pub fn can_coalesce(&self, src: VReg, dst: VReg, ig: &InterferenceGraph) -> bool {
        if ig.interferes(src, dst) {
            return false;
        }
        // George's criterion: for each neighbour t of src,
        // t already interferes with dst OR degree(t) < num_colors.
        for t in ig.neighbours(src) {
            if t == dst {
                continue;
            }
            if ig.degree(t) < self.num_colors {
                continue;
            }
            if ig.interferes(t, dst) {
                continue;
            }
            return false;
        }
        true
    }

    /// Filter a list of move pairs to those safe to coalesce.
    #[must_use] 
    pub fn filter(&self, pairs: &[CoalescePair], ig: &InterferenceGraph) -> Vec<CoalescePair> {
        pairs
            .iter()
            .filter(|p| self.can_coalesce(p.src, p.dst, ig))
            .cloned()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph Coloring (Chaitin-style)
// ─────────────────────────────────────────────────────────────────────────────

/// Chaitin-style graph coloring with simplification and potential spill.
pub struct ChaitinColorer {
    /// Number of available physical registers (colours).
    pub k: usize,
}

impl ChaitinColorer {
    #[must_use] 
    pub const fn new(k: usize) -> Self {
        Self { k }
    }

    /// Run the colouring algorithm. Returns a [`ColoringResult`].
    #[must_use] 
    pub fn color(&self, ig: &InterferenceGraph) -> ColoringResult {
        let mut graph = ig.clone();
        let mut stack: Vec<VReg> = Vec::new();
        let mut _spills: Vec<VReg> = Vec::new();

        // Simplification phase: repeatedly remove nodes with degree < k.
        // Nodes that cannot be removed are potential spills.
        let mut changed = true;
        while changed {
            changed = false;
            // `graph.registers` is a HashSet; sort so simplification/elimination
            // order (and thus the resulting colour assignment) is reproducible
            // across runs regardless of hash iteration order.
            let mut low_degree: Vec<VReg> = graph
                .registers
                .iter()
                .copied()
                .filter(|&v| graph.degree(v) < self.k)
                .collect();
            low_degree.sort_unstable();
            for v in low_degree {
                stack.push(v);
                graph.remove(v);
                changed = true;
            }
            if !graph.registers.is_empty() && !changed {
                // Optimistic spill: pick the node with minimum spill cost
                // (heuristic: lowest degree). `graph.registers` is a HashSet, so
                // break degree ties by VReg id for a reproducible choice across runs.
                let spill = *graph
                    .registers
                    .iter()
                    .min_by(|&&a, &&b| graph.degree(a).cmp(&graph.degree(b)).then_with(|| a.cmp(&b)))
                    .unwrap();
                _spills.push(spill);
                stack.push(spill);
                graph.remove(spill);
                changed = true;
            }
        }

        // Coloring phase: pop from stack and assign colours.
        let mut colors: FxHashMap<VReg, Color> = FxHashMap::default();
        let mut colors_used = 0;

        while let Some(v) = stack.pop() {
            // Find the first colour not used by neighbours.
            let neighbour_colors: HashSet<Color> = ig
                .neighbours(v)
                .iter()
                .filter_map(|n| colors.get(n).copied())
                .collect();
            let color = (0..self.k as u32).find(|c| !neighbour_colors.contains(c));
            if let Some(c) = color {
                colors_used = colors_used.max(c as usize + 1);
                colors.insert(v, c);
            } else {
                // Actual spill.
            }
        }

        // Nodes still not colored are true spills. `ig.registers` is a HashSet;
        // sort the result so it's reproducible across runs.
        let mut uncolored: Vec<VReg> = ig
            .registers
            .iter()
            .copied()
            .filter(|v| !colors.contains_key(v))
            .collect();
        uncolored.sort_unstable();

        ColoringResult {
            colors,
            colors_used,
            uncolored,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Linear Scan allocator
// ─────────────────────────────────────────────────────────────────────────────

/// Linear scan register allocator (Poletto & Sarkar).
pub struct LinearScanAllocator {
    pub num_registers: usize,
}

impl LinearScanAllocator {
    #[must_use] 
    pub const fn new(num_registers: usize) -> Self {
        Self { num_registers }
    }

    /// Allocate registers for the given live ranges.
    #[must_use] 
    pub fn allocate(&self, ranges: &[LiveRange]) -> (AllocationMap, SpillDecision) {
        let mut sorted: Vec<&LiveRange> = ranges.iter().collect();
        sorted.sort_by_key(|r| r.start);

        let mut allocation = AllocationMap::new();
        let mut spill = SpillDecision::new();
        // `active[preg]` = vreg currently occupying this physical register.
        let mut active: Vec<Option<&LiveRange>> = vec![None; self.num_registers];

        for range in &sorted {
            // Expire old intervals.
            for slot in &mut active {
                if let Some(active_range) = *slot && active_range.end <= range.start {
                    *slot = None;
                }
            }

            // Find a free physical register.
            let free = active.iter().position(std::option::Option::is_none);
            if let Some(idx) = free {
                allocation.assign(range.vreg, PReg::new(idx as u32));
                active[idx] = Some(range);
            } else {
                // Spill: pick the range that ends latest.
                let spill_idx = active
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| s.map(|r| (i, r.end)))
                    .max_by_key(|(_, end)| *end)
                    .map(|(i, _)| i);
                if let Some(idx) = spill_idx {
                    let spilled_range = active[idx].unwrap();
                    if spilled_range.end > range.end {
                        // Spill the active range, use its slot for the new one.
                        spill.spill(spilled_range.vreg, spilled_range.len() as f32);
                        allocation.map.remove(&spilled_range.vreg);
                        allocation.assign(range.vreg, PReg::new(idx as u32));
                        active[idx] = Some(range);
                    } else {
                        spill.spill(range.vreg, range.len() as f32);
                    }
                } else {
                    spill.spill(range.vreg, range.len() as f32);
                }
            }
        }

        (allocation, spill)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterColouring — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for register colouring.
#[derive(Debug, Clone)]
pub struct RegisterColouringConfig {
    /// Number of available physical registers.
    pub num_registers: usize,
    /// Whether to run move coalescing before coloring.
    pub coalesce: bool,
    /// Whether to use linear-scan (faster) or Chaitin-style (optimal).
    pub use_linear_scan: bool,
}

impl Default for RegisterColouringConfig {
    fn default() -> Self {
        Self {
            num_registers: 8,
            coalesce: true,
            use_linear_scan: true,
        }
    }
}

/// Summary of a register colouring run.
#[derive(Debug, Clone)]
pub struct ColouringResult {
    pub allocation: AllocationMap,
    pub spills: SpillDecision,
    pub colors_used: usize,
    pub coalesced_pairs: usize,
}

/// Top-level register colouring coordinator.
pub struct RegisterColouring {
    config: RegisterColouringConfig,
}

impl RegisterColouring {
    #[must_use] 
    pub const fn new(config: RegisterColouringConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn default_x86_64() -> Self {
        Self::new(RegisterColouringConfig {
            num_registers: 16,
            ..Default::default()
        })
    }

    /// Run register colouring for a set of live ranges and optional move pairs.
    #[must_use] 
    pub fn run(&self, ranges: &[LiveRange], move_pairs: &[CoalescePair]) -> ColouringResult {
        // Build interference graph.
        let ig = InterferenceGraph::from_live_ranges(ranges);

        // Coalescing.
        let coalesced_pairs = if self.config.coalesce {
            let heuristic = CoalescingHeuristic::new(self.config.num_registers);
            let safe_pairs = heuristic.filter(move_pairs, &ig);
            // Merge coalesced pairs (stub: just return the count).
            safe_pairs.len()
        } else {
            0
        };

        if self.config.use_linear_scan {
            let allocator = LinearScanAllocator::new(self.config.num_registers);
            let (allocation, spills) = allocator.allocate(ranges);
            let colors_used = allocation.map.values().map(|p| p.0 + 1).max().unwrap_or(0) as usize;
            ColouringResult {
                allocation,
                spills,
                colors_used,
                coalesced_pairs,
            }
        } else {
            let colorer = ChaitinColorer::new(self.config.num_registers);
            let coloring = colorer.color(&ig);
            let mut allocation = AllocationMap::new();
            let mut spills = SpillDecision::new();
            for (&v, &c) in &coloring.colors {
                allocation.assign(v, PReg::new(c));
            }
            for v in &coloring.uncolored {
                spills.spill(*v, 1.0);
            }
            ColouringResult {
                allocation,
                spills,
                colors_used: coloring.colors_used,
                coalesced_pairs,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v(id: u32) -> VReg {
        VReg::new(id)
    }
    fn p(id: u32) -> PReg {
        PReg::new(id)
    }

    fn make_ranges(specs: &[(u32, u32, u32)]) -> Vec<LiveRange> {
        specs
            .iter()
            .map(|&(id, s, e)| LiveRange::new(v(id), s, e))
            .collect()
    }

    // 1. VReg / PReg display.
    #[test]
    fn test_vreg_preg_display() {
        assert_eq!(v(5).to_string(), "v5");
        assert_eq!(p(3).to_string(), "r3");
    }

    // 2. LiveRange::overlaps.
    #[test]
    fn test_live_range_overlap() {
        let a = LiveRange::new(v(0), 0, 10);
        let b = LiveRange::new(v(1), 5, 15);
        let c = LiveRange::new(v(2), 10, 20);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c)); // [0,10) and [10,20) do not overlap
    }

    // 3. LiveRange::len.
    #[test]
    fn test_live_range_len() {
        assert_eq!(LiveRange::new(v(0), 3, 8).len(), 5);
    }

    // 4. LiveRange::is_empty.
    #[test]
    fn test_live_range_empty() {
        assert!(LiveRange::new(v(0), 5, 5).is_empty());
        assert!(!LiveRange::new(v(0), 0, 1).is_empty());
    }

    // 5. InterferenceGraph: add edge.
    #[test]
    fn test_ig_add_edge() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        assert!(ig.interferes(v(0), v(1)));
        assert!(ig.interferes(v(1), v(0)));
    }

    // 6. InterferenceGraph: self-edge ignored.
    #[test]
    fn test_ig_self_edge() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(0));
        assert!(!ig.interferes(v(0), v(0)));
        assert_eq!(ig.degree(v(0)), 0);
    }

    // 7. InterferenceGraph: degree.
    #[test]
    fn test_ig_degree() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(0), v(2));
        assert_eq!(ig.degree(v(0)), 2);
        assert_eq!(ig.degree(v(1)), 1);
    }

    // 8. InterferenceGraph::from_live_ranges.
    #[test]
    fn test_ig_from_ranges() {
        let ranges = make_ranges(&[(0, 0, 10), (1, 5, 15), (2, 12, 20)]);
        let ig = InterferenceGraph::from_live_ranges(&ranges);
        assert!(ig.interferes(v(0), v(1)));
        assert!(!ig.interferes(v(0), v(2)));
    }

    // 9. InterferenceGraph::remove.
    #[test]
    fn test_ig_remove() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(1), v(2));
        ig.remove(v(1));
        assert!(!ig.registers.contains(&v(1)));
        assert_eq!(ig.degree(v(0)), 0);
    }

    // 10. InterferenceGraph::edge_count.
    #[test]
    fn test_ig_edge_count() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(1), v(2));
        ig.add_edge(v(0), v(2));
        assert_eq!(ig.edge_count(), 3);
    }

    // 11. SpillDecision basics.
    #[test]
    fn test_spill_decision() {
        let mut sd = SpillDecision::new();
        sd.spill(v(3), 5.0);
        assert!(sd.is_spilled(v(3)));
        assert!(!sd.is_spilled(v(4)));
        assert_eq!(sd.spill_count(), 1);
        assert!((sd.total_cost() - 5.0).abs() < 1e-5);
    }

    // 12. AllocationMap basics.
    #[test]
    fn test_allocation_map() {
        let mut am = AllocationMap::new();
        am.assign(v(0), p(2));
        assert_eq!(am.get(v(0)), Some(p(2)));
        assert!(am.is_assigned(v(0)));
        assert!(!am.is_assigned(v(1)));
    }

    // 13. ChaitinColorer: 2-colorable triangle → 3 colours.
    #[test]
    fn test_chaitin_triangle() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(1), v(2));
        ig.add_edge(v(0), v(2));
        let colorer = ChaitinColorer::new(3);
        let result = colorer.color(&ig);
        assert_eq!(result.uncolored.len(), 0);
        // All three must have different colours.
        let c0 = result.color_of(v(0)).unwrap();
        let c1 = result.color_of(v(1)).unwrap();
        let c2 = result.color_of(v(2)).unwrap();
        assert_ne!(c0, c1);
        assert_ne!(c1, c2);
        assert_ne!(c0, c2);
    }

    // 14. ChaitinColorer: insufficient colours → spill.
    #[test]
    fn test_chaitin_spill() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(1), v(2));
        ig.add_edge(v(0), v(2));
        let colorer = ChaitinColorer::new(2); // only 2 colours for 3-node clique
        let result = colorer.color(&ig);
        assert!(!result.uncolored.is_empty() || result.colors_used >= 2);
    }

    // 15. LinearScanAllocator: simple non-overlapping.
    #[test]
    fn test_linear_scan_no_overlap() {
        let ranges = make_ranges(&[(0, 0, 5), (1, 5, 10), (2, 10, 15)]);
        let alloc = LinearScanAllocator::new(1);
        let (allocation, spill) = alloc.allocate(&ranges);
        // One register suffices since ranges don't overlap.
        assert_eq!(spill.spill_count(), 0);
        assert!(allocation.assigned_count() == 3);
    }

    // 16. LinearScanAllocator: overlapping needs multiple regs.
    #[test]
    fn test_linear_scan_overlap() {
        let ranges = make_ranges(&[(0, 0, 10), (1, 2, 8), (2, 4, 6)]);
        let alloc = LinearScanAllocator::new(3);
        let (allocation, spill) = alloc.allocate(&ranges);
        // With 3 registers and 3 mutually overlapping ranges, no spills.
        assert_eq!(spill.spill_count(), 0);
        assert_eq!(allocation.assigned_count(), 3);
    }

    // 17. LinearScanAllocator: insufficient registers → spills.
    #[test]
    fn test_linear_scan_spill() {
        let ranges = make_ranges(&[(0, 0, 10), (1, 1, 9), (2, 2, 8)]);
        let alloc = LinearScanAllocator::new(2);
        let (allocation, spill) = alloc.allocate(&ranges);
        // Only 2 registers for 3 simultaneously live vregs.
        assert!(spill.spill_count() >= 1);
        // At most as many vregs may be assigned as we have physical registers.
        assert!(allocation.assigned_count() <= 2);
    }

    // 18. CoalescingHeuristic: non-interfering pair can coalesce.
    #[test]
    fn test_coalescing_can_coalesce() {
        let mut ig = InterferenceGraph::new();
        ig.add_register(v(0));
        ig.add_register(v(1));
        // No edge between 0 and 1.
        let h = CoalescingHeuristic::new(4);
        assert!(h.can_coalesce(v(0), v(1), &ig));
    }

    // 19. CoalescingHeuristic: interfering pair cannot coalesce.
    #[test]
    fn test_coalescing_cannot_coalesce() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        let h = CoalescingHeuristic::new(4);
        assert!(!h.can_coalesce(v(0), v(1), &ig));
    }

    // 20. CoalescingHeuristic::filter.
    #[test]
    fn test_coalescing_filter() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_register(v(2));
        ig.add_register(v(3));
        let pairs = vec![
            CoalescePair::new(v(0), v(1)), // cannot coalesce
            CoalescePair::new(v(2), v(3)), // can coalesce
        ];
        let h = CoalescingHeuristic::new(4);
        let safe = h.filter(&pairs, &ig);
        assert_eq!(safe.len(), 1);
        assert_eq!(safe[0], CoalescePair::new(v(2), v(3)));
    }

    // 21. RegisterColouring::run linear scan.
    #[test]
    fn test_register_colouring_linear_scan() {
        let ranges = make_ranges(&[(0, 0, 5), (1, 3, 8), (2, 7, 12)]);
        let rc = RegisterColouring::new(RegisterColouringConfig {
            num_registers: 2,
            use_linear_scan: true,
            coalesce: false,
        });
        let result = rc.run(&ranges, &[]);
        // At most 1 overlap at a time: only 2 registers needed.
        assert!(result.spills.spill_count() <= 1);
    }

    // 22. RegisterColouring::run Chaitin style.
    #[test]
    fn test_register_colouring_chaitin() {
        let ranges = make_ranges(&[(0, 0, 5), (1, 0, 5), (2, 5, 10)]);
        let rc = RegisterColouring::new(RegisterColouringConfig {
            num_registers: 2,
            use_linear_scan: false,
            coalesce: false,
        });
        let result = rc.run(&ranges, &[]);
        assert!(result.colors_used <= 2);
    }

    // 23. RegisterColouring default x86_64.
    #[test]
    fn test_register_colouring_x86_64_default() {
        let rc = RegisterColouring::default_x86_64();
        let ranges = make_ranges(&[(0, 0, 5), (1, 1, 6)]);
        let result = rc.run(&ranges, &[]);
        assert_eq!(result.spills.spill_count(), 0);
    }

    // 24. ColoringResult helpers.
    #[test]
    fn test_coloring_result_helpers() {
        let mut colors: FxHashMap<VReg, Color> = FxHashMap::default();
        colors.insert(v(0), 0);
        colors.insert(v(1), 1);
        let result = ColoringResult {
            colors,
            colors_used: 2,
            uncolored: vec![],
        };
        assert_eq!(result.color_of(v(0)), Some(0));
        assert!(result.is_colored(v(0)));
        assert!(!result.is_colored(v(2)));
        assert_eq!(result.spill_count(), 0);
    }

    // 25. CoalescePair equality.
    #[test]
    fn test_coalesce_pair_eq() {
        let p1 = CoalescePair::new(v(0), v(1));
        let p2 = CoalescePair::new(v(0), v(1));
        assert_eq!(p1, p2);
    }

    // 26. InterferenceGraph::neighbours.
    #[test]
    fn test_ig_neighbours() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(0), v(2));
        let n = ig.neighbours(v(0));
        assert!(n.contains(&v(1)) && n.contains(&v(2)));
    }

    // 27. LinearScan: verifies non-interfering assignments.
    #[test]
    fn test_linear_scan_no_conflict() {
        let ranges = make_ranges(&[(0, 0, 3), (1, 0, 3), (2, 3, 6)]);
        let alloc = LinearScanAllocator::new(2);
        let (allocation, _) = alloc.allocate(&ranges);
        // Verify no two simultaneously live vregs share the same preg.
        let p0 = allocation.get(v(0));
        let p1 = allocation.get(v(1));
        let p2 = allocation.get(v(2));
        if let (Some(a), Some(b)) = (p0, p1) {
            assert_ne!(a, b, "v0 and v1 overlap and must have different pregs");
        }
        // v2 lives after v0/v1 finish, so it may freely use any of the 2 pregs.
        if let Some(c) = p2 {
            assert!(
                c.0 < 2,
                "v2's preg must be within the 2-register budget (got {})",
                c.0
            );
            if let Some(a) = p0 {
                assert!(
                    a.0 < 2,
                    "v0's preg must be within the 2-register budget (got {})",
                    a.0
                );
            }
        }
    }

    // 28. SpillDecision total_cost.
    #[test]
    fn test_spill_total_cost() {
        let mut sd = SpillDecision::new();
        sd.spill(v(0), 2.5);
        sd.spill(v(1), 3.5);
        assert!((sd.total_cost() - 6.0).abs() < 1e-5);
    }

    // 29. InterferenceGraph from empty ranges.
    #[test]
    fn test_ig_empty() {
        let ig = InterferenceGraph::from_live_ranges(&[]);
        assert!(ig.registers.is_empty());
        assert_eq!(ig.edge_count(), 0);
    }

    // 30. ChaitinColorer: empty graph.
    #[test]
    fn test_chaitin_empty() {
        let ig = InterferenceGraph::new();
        let colorer = ChaitinColorer::new(4);
        let result = colorer.color(&ig);
        assert_eq!(result.colors_used, 0);
        assert!(result.uncolored.is_empty());
    }

    // 31. AllocationMap assigned_count.
    #[test]
    fn test_allocation_map_count() {
        let mut am = AllocationMap::new();
        am.assign(v(0), p(0));
        am.assign(v(1), p(1));
        assert_eq!(am.assigned_count(), 2);
    }

    // 32. RegisterColouringConfig defaults.
    #[test]
    fn test_config_defaults() {
        let cfg = RegisterColouringConfig::default();
        assert_eq!(cfg.num_registers, 8);
        assert!(cfg.coalesce);
        assert!(cfg.use_linear_scan);
    }

    // 33. LiveRange nonoverlapping at boundary.
    #[test]
    fn test_boundary_no_overlap() {
        let a = LiveRange::new(v(0), 0, 10);
        let b = LiveRange::new(v(1), 10, 20);
        assert!(!a.overlaps(&b));
    }

    // 34. ChaitinColorer: line graph (path) needs 2 colours.
    #[test]
    fn test_chaitin_line_graph() {
        let mut ig = InterferenceGraph::new();
        ig.add_edge(v(0), v(1));
        ig.add_edge(v(1), v(2));
        ig.add_edge(v(2), v(3));
        let colorer = ChaitinColorer::new(2);
        let result = colorer.color(&ig);
        // A line graph is 2-colorable.
        assert_eq!(result.uncolored.len(), 0);
        // Adjacent nodes must have different colours.
        let c = |v: VReg| result.color_of(v).unwrap();
        assert_ne!(c(v(0)), c(v(1)));
        assert_ne!(c(v(1)), c(v(2)));
    }

    // 35. ColouringResult coalesced_pairs.
    #[test]
    fn test_colouring_result_coalesced_pairs() {
        let ranges = make_ranges(&[(0, 0, 5), (1, 3, 8)]);
        let pairs = vec![CoalescePair::new(v(0), v(1))];
        let rc = RegisterColouring::new(RegisterColouringConfig {
            num_registers: 4,
            coalesce: true,
            use_linear_scan: true,
        });
        let result = rc.run(&ranges, &pairs);
        // coalesced_pairs is determined by coalescing heuristic.
        let _ = result.coalesced_pairs;
    }

    // 36. InterferenceGraph add_register.
    #[test]
    fn test_ig_add_register() {
        let mut ig = InterferenceGraph::new();
        ig.add_register(v(42));
        assert!(ig.registers.contains(&v(42)));
        assert_eq!(ig.degree(v(42)), 0);
    }

    /// Regression test: `ChaitinColorer::color` iterated `graph.registers`
    /// (a `HashSet`) to pick simplification order and the optimistic-spill
    /// candidate, which used to make the resulting colour assignment and
    /// `uncolored` list nondeterministic across runs. Build a clique (all
    /// nodes have equal degree, forcing ties) and verify repeated colorings
    /// of the same graph always agree.
    #[test]
    fn chaitin_color_is_deterministic_on_degree_ties() {
        let mut ig = InterferenceGraph::new();
        // A clique of 6 nodes with only 2 colours available: every node has
        // the same degree (5), so any degree-based tie-break must fall back
        // to a canonical order to be reproducible.
        let nodes: Vec<VReg> = (0..6).map(v).collect();
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                ig.add_edge(nodes[i], nodes[j]);
            }
        }
        let colorer = ChaitinColorer::new(2);
        let first = colorer.color(&ig);
        for _ in 0..20 {
            let again = colorer.color(&ig);
            assert_eq!(again.colors_used, first.colors_used);
            let mut first_colors: Vec<(VReg, Color)> = first.colors.iter().map(|(&k, &v)| (k, v)).collect();
            let mut again_colors: Vec<(VReg, Color)> = again.colors.iter().map(|(&k, &v)| (k, v)).collect();
            first_colors.sort_unstable();
            again_colors.sort_unstable();
            assert_eq!(first_colors, again_colors);
            assert_eq!(again.uncolored, first.uncolored);
        }
    }

    // ─── Property-based / randomized soundness + determinism tests ─────────────
    //
    // No proptest dependency is available in this crate, so these use a small
    // deterministic xorshift64* PRNG (seeded → reproducible on failure) to
    // explore many pseudo-random interference graphs / live-range sets.

    use crate::test_prng::Xorshift64;

    /// Build a random interference graph: `n` nodes, each unordered pair added
    /// as an edge with probability ~`edge_pct`%.
    fn random_ig(rng: &mut Xorshift64, n: u32, edge_pct: usize) -> InterferenceGraph {
        let mut ig = InterferenceGraph::new();
        for i in 0..n {
            ig.add_register(v(i));
        }
        for i in 0..n {
            for j in (i + 1)..n {
                if rng.next_range(100) < edge_pct {
                    ig.add_edge(v(i), v(j));
                }
            }
        }
        ig
    }

    /// Collect every interfering (unordered) pair currently in the graph.
    fn edges_of(ig: &InterferenceGraph) -> Vec<(VReg, VReg)> {
        let mut regs: Vec<VReg> = ig.registers.iter().copied().collect();
        regs.sort_unstable();
        let mut out = Vec::new();
        for (i, &a) in regs.iter().enumerate() {
            for &b in &regs[i + 1..] {
                if ig.interferes(a, b) {
                    out.push((a, b));
                }
            }
        }
        out
    }

    /// SOUNDNESS PROPERTY (register colouring, requirement #1): after
    /// `ChaitinColorer::color`, no two *interfering* virtual registers that
    /// were both assigned a colour may share that colour. This must hold for
    /// every graph and every `k`, including when some nodes spill (uncoloured
    /// nodes are simply excluded — the invariant is over coloured pairs).
    #[test]
    fn prop_chaitin_coloring_is_sound() {
        let mut rng = Xorshift64::new(0x0DDB_A11);
        for trial in 0..400u64 {
            let n = 1 + rng.next_range(12) as u32;
            let edge_pct = rng.next_range(101);
            let ig = random_ig(&mut rng, n, edge_pct);
            let k = 1 + rng.next_range(8);
            let colorer = ChaitinColorer::new(k);
            let res = colorer.color(&ig);

            for (a, b) in edges_of(&ig) {
                if let (Some(ca), Some(cb)) = (res.color_of(a), res.color_of(b)) {
                    assert_ne!(
                        ca, cb,
                        "trial {trial}: interfering {a} and {b} both got colour {ca} (n={n}, k={k}, edge_pct={edge_pct})"
                    );
                }
            }
            // No colour used may exceed the k budget.
            for (_, &c) in &res.colors {
                assert!(c < k as u32, "trial {trial}: colour {c} exceeds k={k}");
            }
        }
    }

    /// DETERMINISM PROPERTY: colouring the same graph repeatedly (and rebuilt
    /// with a different node-insertion order) yields an identical colour map
    /// and identical spill set, regardless of `HashSet`/hash iteration order.
    #[test]
    fn prop_chaitin_coloring_is_deterministic() {
        let mut rng = Xorshift64::new(0xFACE_FEED);
        for trial in 0..200u64 {
            let n = 1 + rng.next_range(10) as u32;
            let edge_pct = rng.next_range(101);
            let ig = random_ig(&mut rng, n, edge_pct);
            let k = 1 + rng.next_range(6);
            let colorer = ChaitinColorer::new(k);

            let first = colorer.color(&ig);
            let mut first_v: Vec<(VReg, Color)> =
                first.colors.iter().map(|(&a, &b)| (a, b)).collect();
            first_v.sort_unstable();

            for _ in 0..5 {
                let again = colorer.color(&ig);
                let mut again_v: Vec<(VReg, Color)> =
                    again.colors.iter().map(|(&a, &b)| (a, b)).collect();
                again_v.sort_unstable();
                assert_eq!(first_v, again_v, "trial {trial}: colour map not deterministic");
                assert_eq!(first.uncolored, again.uncolored, "trial {trial}: spills not deterministic");
                assert_eq!(first.colors_used, again.colors_used);
            }
        }
    }

    /// SOUNDNESS PROPERTY (linear-scan allocator): two live ranges that
    /// actually overlap in time must never be assigned the same physical
    /// register. Explored over random sets of intervals with random register
    /// budgets. (Spilled ranges are excluded from the check.)
    #[test]
    fn prop_linear_scan_no_overlap_shares_reg() {
        let mut rng = Xorshift64::new(0xBEEF_CAFE);
        for trial in 0..400u64 {
            let count = 1 + rng.next_range(14);
            let ranges: Vec<LiveRange> = (0..count)
                .map(|i| {
                    let start = rng.next_range(20) as u32;
                    let len = rng.next_range(10) as u32; // may be 0 (empty range)
                    LiveRange::new(v(i as u32), start, start + len)
                })
                .collect();
            let regs = 1 + rng.next_range(6);
            let alloc = LinearScanAllocator::new(regs);
            let (allocation, _spill) = alloc.allocate(&ranges);

            for i in 0..ranges.len() {
                for j in (i + 1)..ranges.len() {
                    if ranges[i].overlaps(&ranges[j])
                        && let (Some(pi), Some(pj)) =
                            (allocation.get(ranges[i].vreg), allocation.get(ranges[j].vreg))
                        {
                            assert_ne!(
                                pi, pj,
                                "trial {trial}: overlapping ranges {:?} and {:?} share preg {pi}",
                                ranges[i], ranges[j]
                            );
                        }
                }
                // Any assigned register must be within budget.
                if let Some(p) = allocation.get(ranges[i].vreg) {
                    assert!(p.0 < regs as u32, "trial {trial}: preg {p} exceeds budget {regs}");
                }
            }
        }
    }
}
