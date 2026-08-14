//! Region tree builder for structured control flow.
//!
//! Detects acyclic and cyclic regions in a CFG and builds a [`RegionTree`]
//! that groups basic blocks into structured constructs (sequences, if-then,
//! loops, etc.).  This is the region-identification phase that precedes the
//! DREAM / Phoenix structuring pass.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{BasicBlock, BlockId};

// ── RegionKind ────────────────────────────────────────────────────────────────

/// The structural shape of a [`Region`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionKind {
    /// A single basic block with no branching.
    Block,
    /// A linear chain of blocks with no branching.
    Sequence,
    /// `if (cond) then_body` — one exit falls through.
    IfThen,
    /// `if (cond) then_body else else_body` — two-branch merge.
    IfThenElse,
    /// A natural loop with a single header and latch.
    NaturalLoop,
    /// A self-loop (single block with a back-edge to itself).
    SelfLoop,
    /// A switch with multiple case arms.
    Switch,
    /// An irreducible region (not structurable without gotos).
    Irreducible,
}

// ── AcyclicRegion ─────────────────────────────────────────────────────────────

/// A region containing no back-edges (no loops).
#[derive(Debug, Clone)]
pub struct AcyclicRegion {
    /// Topological order of blocks within this region.
    pub blocks: Vec<BlockId>,
    /// The block that is the single entry point.
    pub entry: BlockId,
    /// The block where control leaves this region (post-dominator).
    pub exit: Option<BlockId>,
    /// Kind of this acyclic region.
    pub kind: RegionKind,
}

impl AcyclicRegion {
    /// Whether this region is a simple conditional.
    #[must_use]
    pub const fn is_conditional(&self) -> bool {
        matches!(self.kind, RegionKind::IfThen | RegionKind::IfThenElse)
    }

    /// Number of blocks in this region.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.blocks.len()
    }
}

// ── CyclicRegion ──────────────────────────────────────────────────────────────

/// A region that contains at least one back-edge (a loop).
#[derive(Debug, Clone)]
pub struct CyclicRegion {
    /// All blocks that belong to the loop body (including header and latch).
    pub body: Vec<BlockId>,
    /// The loop header (target of the back-edge).
    pub header: BlockId,
    /// The latch (source of the back-edge).
    pub latch: BlockId,
    /// Blocks that exit the loop (successors outside the loop body).
    pub exits: Vec<BlockId>,
    /// Kind: `NaturalLoop` or `SelfLoop`.
    pub kind: RegionKind,
}

impl CyclicRegion {
    /// Whether `block` is inside the loop body.
    #[must_use]
    pub fn contains(&self, block: BlockId) -> bool {
        self.body.contains(&block)
    }

    /// Number of blocks in this region.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.body.len()
    }

    /// Whether this is a self-loop (header == latch).
    #[must_use]
    pub fn is_self_loop(&self) -> bool {
        self.header == self.latch
    }
}

// ── Region ────────────────────────────────────────────────────────────────────

/// An identified structural region in the CFG.
#[derive(Debug, Clone)]
pub enum Region {
    Acyclic(AcyclicRegion),
    Cyclic(CyclicRegion),
}

impl Region {
    /// The entry block of this region.
    #[must_use]
    pub const fn entry(&self) -> BlockId {
        match self {
            Self::Acyclic(r) => r.entry,
            Self::Cyclic(r) => r.header,
        }
    }

    /// All blocks that belong to this region.
    #[must_use]
    pub fn blocks(&self) -> &[BlockId] {
        match self {
            Self::Acyclic(r) => &r.blocks,
            Self::Cyclic(r) => &r.body,
        }
    }

    /// The kind of this region.
    #[must_use]
    pub const fn kind(&self) -> &RegionKind {
        match self {
            Self::Acyclic(r) => &r.kind,
            Self::Cyclic(r) => &r.kind,
        }
    }

    /// Whether this region is a loop.
    #[must_use]
    pub const fn is_loop(&self) -> bool {
        matches!(self, Self::Cyclic(_))
    }
}

// ── RegionTreeBuilder ─────────────────────────────────────────────────────────

/// Builds the region tree from a list of basic blocks.
///
/// # Usage
/// ```ignore
/// let builder = RegionTreeBuilder::new(&blocks);
/// let tree = builder.build(entry);
/// ```
pub struct RegionTreeBuilder<'a> {
    blocks: &'a [BasicBlock],
    /// Block adjacency: `block_id` → successors.
    succ: HashMap<BlockId, Vec<BlockId>>,
    /// Block adjacency: `block_id` → predecessors.
    pred: HashMap<BlockId, Vec<BlockId>>,
}

impl<'a> RegionTreeBuilder<'a> {
    /// Create a new builder from a slice of basic blocks.
    #[must_use]
    pub fn new(blocks: &'a [BasicBlock]) -> Self {
        let mut succ: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        let mut pred: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for bb in blocks {
            succ.entry(bb.id).or_default().extend_from_slice(&bb.successors);
            for &s in &bb.successors {
                pred.entry(s).or_default().push(bb.id);
            }
        }
        Self { blocks, succ, pred }
    }

    /// Borrow the underlying basic-block slice this builder was constructed
    /// from. Useful for callers that want to correlate a [`Region`] back to
    /// its source [`BasicBlock`]s without keeping a parallel reference.
    #[must_use]
    pub const fn blocks(&self) -> &'a [BasicBlock] {
        self.blocks
    }

    /// Look up a basic block by id.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&'a BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Build the complete region list for the CFG rooted at `entry`.
    #[must_use]
    pub fn build(&self, entry: BlockId) -> Vec<Region> {
        let back_edges = self.find_back_edges(entry);
        let loop_headers: HashSet<BlockId> = back_edges.iter().map(|(h, _)| *h).collect();

        let mut regions: Vec<Region> = Vec::new();

        // ── Cyclic regions ────────────────────────────────────────────────────
        for (header, latch) in &back_edges {
            let body = self.natural_loop_body(*header, *latch);
            let exits = self.loop_exits(&body);
            let kind = if *header == *latch {
                RegionKind::SelfLoop
            } else {
                RegionKind::NaturalLoop
            };
            regions.push(Region::Cyclic(CyclicRegion {
                body,
                header: *header,
                latch: *latch,
                exits,
                kind,
            }));
        }

        // ── Acyclic regions ───────────────────────────────────────────────────
        let rpo = self.rpo(entry);
        for &bid in &rpo {
            let succs = self.succ.get(&bid).map_or(&[][..], Vec::as_slice);
            // Filter out back-edges.
            let fwd_succs: Vec<BlockId> = succs
                .iter()
                .filter(|&&s| !back_edges.contains(&(bid, s)))
                .copied()
                .collect();

            let kind = match fwd_succs.len() {
                0 => RegionKind::Block,
                1 => {
                    if loop_headers.contains(&bid) {
                        RegionKind::NaturalLoop
                    } else {
                        RegionKind::Sequence
                    }
                }
                2 => {
                    // Two successors → conditional.
                    let join = self.find_join(fwd_succs[0], fwd_succs[1]);
                    if join.is_some_and(|j| j == fwd_succs[0] || j == fwd_succs[1]) {
                        RegionKind::IfThen
                    } else {
                        RegionKind::IfThenElse
                    }
                }
                _ => RegionKind::Switch,
            };

            if kind == RegionKind::Block || kind == RegionKind::Sequence {
                // Only emit non-loop single-block / sequence regions.
                regions.push(Region::Acyclic(AcyclicRegion {
                    blocks: vec![bid],
                    entry: bid,
                    exit: fwd_succs.first().copied(),
                    kind,
                }));
            } else if matches!(kind, RegionKind::IfThen | RegionKind::IfThenElse | RegionKind::Switch) {
                let join = if fwd_succs.len() == 2 {
                    self.find_join(fwd_succs[0], fwd_succs[1])
                } else {
                    self.find_switch_join(&fwd_succs)
                };
                let blocks: Vec<BlockId> = fwd_succs.iter().copied().chain([bid]).collect();
                regions.push(Region::Acyclic(AcyclicRegion {
                    blocks,
                    entry: bid,
                    exit: join,
                    kind,
                }));
            }
        }

        regions
    }

    // ── Back-edge detection ───────────────────────────────────────────────────

    fn find_back_edges(&self, entry: BlockId) -> Vec<(BlockId, BlockId)> {
        let mut colour: HashMap<BlockId, u8> = HashMap::new(); // 0=white,1=grey,2=black
        let mut back = Vec::new();
        self.dfs_back(entry, &mut colour, &mut back);
        back
    }

    fn dfs_back(
        &self,
        node: BlockId,
        colour: &mut HashMap<BlockId, u8>,
        back: &mut Vec<(BlockId, BlockId)>,
    ) {
        colour.insert(node, 1);
        let empty = vec![];
        let succs = self.succ.get(&node).unwrap_or(&empty);
        for &s in succs {
            match colour.get(&s).copied().unwrap_or(0) {
                1 => back.push((s, node)), // s is header, node is latch
                0 => self.dfs_back(s, colour, back),
                _ => {}
            }
        }
        colour.insert(node, 2);
    }

    // ── Natural loop body ─────────────────────────────────────────────────────

    fn natural_loop_body(&self, header: BlockId, latch: BlockId) -> Vec<BlockId> {
        if header == latch {
            return vec![header];
        }
        let mut body: HashSet<BlockId> = HashSet::from([header, latch]);
        let mut worklist = vec![latch];
        while let Some(n) = worklist.pop() {
            let preds = self.pred.get(&n).map_or(&[][..], Vec::as_slice);
            for &p in preds {
                if body.insert(p) {
                    worklist.push(p);
                }
            }
        }
        let mut v: Vec<BlockId> = body.into_iter().collect();
        v.sort_unstable();
        v
    }

    fn loop_exits(&self, body: &[BlockId]) -> Vec<BlockId> {
        let body_set: HashSet<BlockId> = body.iter().copied().collect();
        let mut exits = HashSet::new();
        for &b in body {
            for &s in self.succ.get(&b).map_or(&[][..], Vec::as_slice) {
                if !body_set.contains(&s) {
                    exits.insert(s);
                }
            }
        }
        let mut v: Vec<BlockId> = exits.into_iter().collect();
        v.sort_unstable();
        v
    }

    // ── RPO ──────────────────────────────────────────────────────────────────

    fn rpo(&self, entry: BlockId) -> Vec<BlockId> {
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        self.dfs_post(entry, &mut visited, &mut post);
        post.reverse();
        post
    }

    /// True when `id` names a block that actually exists. Successor lists can
    /// reference ids outside this function (dangling gotos), and an empty
    /// block list means even the entry is absent.
    fn exists(&self, id: BlockId) -> bool {
        self.blocks.iter().any(|b| b.id == id)
    }

    fn dfs_post(
        &self,
        node: BlockId,
        visited: &mut HashSet<BlockId>,
        post: &mut Vec<BlockId>,
    ) {
        if !self.exists(node) || !visited.insert(node) {
            return;
        }
        let empty = vec![];
        for &s in self.succ.get(&node).unwrap_or(&empty) {
            self.dfs_post(s, visited, post);
        }
        post.push(node);
    }

    // ── Join-point search ─────────────────────────────────────────────────────

    fn find_join(&self, a: BlockId, b: BlockId) -> Option<BlockId> {
        let ra = self.bfs_reach(a);
        let rb = self.bfs_reach(b);
        if ra.contains(&b) {
            return Some(b);
        }
        if rb.contains(&a) {
            return Some(a);
        }
        let common: HashSet<BlockId> = ra.intersection(&rb).copied().collect();
        if common.is_empty() {
            return None;
        }
        // Pick lowest by BFS from a.
        let mut queue = VecDeque::from([a]);
        let mut seen = HashSet::new();
        seen.insert(a);
        while let Some(n) = queue.pop_front() {
            if common.contains(&n) && n != a {
                return Some(n);
            }
            for &s in self.succ.get(&n).map_or(&[][..], Vec::as_slice) {
                if seen.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        common.into_iter().next()
    }

    fn find_switch_join(&self, targets: &[BlockId]) -> Option<BlockId> {
        if targets.is_empty() {
            return None;
        }
        let sets: Vec<HashSet<BlockId>> = targets.iter().map(|&t| self.bfs_reach(t)).collect();
        let mut queue = VecDeque::from([targets[0]]);
        let mut seen = HashSet::new();
        while let Some(n) = queue.pop_front() {
            if sets.iter().all(|s| s.contains(&n)) && !targets.contains(&n) {
                return Some(n);
            }
            for &s in self.succ.get(&n).map_or(&[][..], Vec::as_slice) {
                if seen.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        None
    }

    fn bfs_reach(&self, start: BlockId) -> HashSet<BlockId> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(n) = queue.pop_front() {
            if visited.insert(n) {
                for &s in self.succ.get(&n).map_or(&[][..], Vec::as_slice) {
                    queue.push_back(s);
                }
            }
        }
        visited
    }
}

// ── RegionStats ───────────────────────────────────────────────────────────────

/// Statistics about the regions found in a CFG.
#[derive(Debug, Clone, Default)]
pub struct RegionStats {
    pub total: usize,
    pub acyclic: usize,
    pub cyclic: usize,
    pub self_loops: usize,
    pub if_thens: usize,
    pub if_then_elses: usize,
    pub switches: usize,
}

impl RegionStats {
    /// Compute statistics from a region list.
    #[must_use]
    pub fn from_regions(regions: &[Region]) -> Self {
        let mut s = Self {
            total: regions.len(),
            ..Self::default()
        };
        for r in regions {
            match r {
                Region::Acyclic(a) => {
                    s.acyclic += 1;
                    match a.kind {
                        RegionKind::IfThen => s.if_thens += 1,
                        RegionKind::IfThenElse => s.if_then_elses += 1,
                        RegionKind::Switch => s.switches += 1,
                        _ => {}
                    }
                }
                Region::Cyclic(c) => {
                    s.cyclic += 1;
                    if c.is_self_loop() {
                        s.self_loops += 1;
                    }
                }
            }
        }
        s
    }

    /// The ratio of cyclic to total regions (0.0–1.0).
    #[must_use]
    pub fn cyclic_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.cyclic).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bb(id: u32, succs: Vec<u32>) -> BasicBlock {
        BasicBlock {
            id: BlockId::new(id),
            stmts: Vec::new(),
            successors: succs.into_iter().map(BlockId::new).collect(),
        }
    }

    #[test]
    fn single_block() {
        let blocks = vec![bb(0, vec![])];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        assert!(!regions.is_empty());
    }

    #[test]
    fn linear_chain() {
        let blocks = vec![bb(0, vec![1]), bb(1, vec![2]), bb(2, vec![])];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        assert!(!regions.is_empty());
        let stats = RegionStats::from_regions(&regions);
        assert_eq!(stats.cyclic, 0);
    }

    #[test]
    fn self_loop_detected() {
        let blocks = vec![bb(0, vec![0])];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        let cyclic: Vec<_> = regions.iter().filter(|r| r.is_loop()).collect();
        assert!(!cyclic.is_empty());
        if let Region::Cyclic(c) = &cyclic[0] {
            assert!(c.is_self_loop());
        }
    }

    #[test]
    fn natural_loop_while() {
        // 0 → 1 → {2, 3}, 2 → 1 (back), 3 = exit
        let blocks = vec![
            bb(0, vec![1]),
            bb(1, vec![2, 3]),
            bb(2, vec![1]),
            bb(3, vec![]),
        ];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        let cyclic: Vec<_> = regions.iter().filter(|r| r.is_loop()).collect();
        assert!(!cyclic.is_empty());
        if let Region::Cyclic(c) = &cyclic[0] {
            assert_eq!(c.header, BlockId::new(1));
            assert!(c.contains(BlockId::new(2)));
        }
    }

    #[test]
    fn if_then_region_detected() {
        // 0 → {1, 2}, 1 → 2, 2 terminal
        let blocks = vec![bb(0, vec![1, 2]), bb(1, vec![2]), bb(2, vec![])];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        
        assert!(regions
            .iter()
            .any(|r| r.kind() == &RegionKind::IfThen));
    }

    #[test]
    fn if_then_else_region() {
        // 0 → {1, 2}, 1 → 3, 2 → 3, 3 terminal
        let blocks = vec![
            bb(0, vec![1, 2]),
            bb(1, vec![3]),
            bb(2, vec![3]),
            bb(3, vec![]),
        ];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        
        assert!(regions
            .iter()
            .any(|r| r.kind() == &RegionKind::IfThenElse));
    }

    #[test]
    fn loop_exits_computed() {
        let blocks = vec![bb(0, vec![1]), bb(1, vec![2, 3]), bb(2, vec![1]), bb(3, vec![])];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        let cyclic: Vec<_> = regions.iter().filter(|r| r.is_loop()).collect();
        assert!(!cyclic.is_empty());
        if let Region::Cyclic(c) = &cyclic[0] {
            assert!(!c.exits.is_empty());
        }
    }

    #[test]
    fn region_stats_cyclic_ratio() {
        let s = RegionStats {
            total: 10,
            cyclic: 2,
            ..Default::default()
        };
        assert!((s.cyclic_ratio() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn acyclic_region_size() {
        let r = AcyclicRegion {
            blocks: vec![BlockId::new(1), BlockId::new(2), BlockId::new(3)],
            entry: BlockId::new(1),
            exit: None,
            kind: RegionKind::Sequence,
        };
        assert_eq!(r.size(), 3);
    }

    #[test]
    fn cyclic_region_contains() {
        let r = CyclicRegion {
            body: vec![BlockId::new(1), BlockId::new(2)],
            header: BlockId::new(1),
            latch: BlockId::new(2),
            exits: vec![],
            kind: RegionKind::NaturalLoop,
        };
        assert!(r.contains(BlockId::new(1)));
        assert!(!r.contains(BlockId::new(99)));
    }

    #[test]
    fn switch_region_detected() {
        // 0 → {1, 2, 3}, all → 4
        let blocks = vec![
            bb(0, vec![1, 2, 3]),
            bb(1, vec![4]),
            bb(2, vec![4]),
            bb(3, vec![4]),
            bb(4, vec![]),
        ];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        
        assert!(regions
            .iter()
            .any(|r| r.kind() == &RegionKind::Switch));
    }

    #[test]
    fn empty_blocks_list_no_panic() {
        let blocks: Vec<BasicBlock> = vec![];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        assert!(regions.is_empty());
    }

    #[test]
    fn nested_loops() {
        // 0 → 1 (outer hdr), 1 → {2, 5}, 2 → 3 (inner hdr), 3 → {4, 1}, 4 → 3, 5 terminal
        let blocks = vec![
            bb(0, vec![1]),
            bb(1, vec![2, 5]),
            bb(2, vec![3]),
            bb(3, vec![4, 1]),
            bb(4, vec![3]),
            bb(5, vec![]),
        ];
        let builder = RegionTreeBuilder::new(&blocks);
        let regions = builder.build(BlockId::new(0));
        
        assert!(regions.iter().filter(|r| r.is_loop()).count() >= 2);
    }
}
