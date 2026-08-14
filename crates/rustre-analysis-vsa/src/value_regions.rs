//! Abstract region-based alias analysis.
//!
//! Partitions memory into named `Region`s (stack, heap, global, param, return)
//! and computes may/must alias information at the region-descriptor level.
//! The `RegionGraph` tracks inter-region relationships and `ModRefInfo` records
//! which regions each function may modify or read.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

// ─────────────────────────────────────────────────────────────────────────────
// Region / RegionDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A unique region identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegionId(pub u32);

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R{}", self.0)
    }
}

/// The high-level kind of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionKind {
    Stack,
    Heap,
    Global,
    Param,
    ReturnValue,
    Unknown,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::Global => "global",
            Self::Param => "param",
            Self::ReturnValue => "retval",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Describes the properties of a single abstract region.
#[derive(Debug, Clone)]
pub struct RegionDescriptor {
    pub id: RegionId,
    pub kind: RegionKind,
    /// Optional base address (for global regions).
    pub base_address: Option<u64>,
    /// Size in bytes, if known.
    pub size: Option<u64>,
    /// Human-readable label.
    pub label: String,
    /// Whether this region may be shared (aliased by multiple access paths).
    pub may_alias: bool,
}

impl RegionDescriptor {
    #[must_use]
    pub fn new(id: RegionId, kind: RegionKind, label: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            base_address: None,
            size: None,
            label: label.into(),
            may_alias: false,
        }
    }

    #[must_use]
    pub const fn with_address(mut self, addr: u64) -> Self {
        self.base_address = Some(addr);
        self
    }

    #[must_use]
    pub const fn with_size(mut self, sz: u64) -> Self {
        self.size = Some(sz);
        self
    }

    #[must_use]
    pub const fn aliasable(mut self) -> Self {
        self.may_alias = true;
        self
    }

    /// Whether this region is on the stack.
    #[must_use]
    pub fn is_stack(&self) -> bool {
        self.kind == RegionKind::Stack
    }

    /// Whether this region is heap-allocated.
    #[must_use]
    pub fn is_heap(&self) -> bool {
        self.kind == RegionKind::Heap
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Region (symbolic reference)
// ─────────────────────────────────────────────────────────────────────────────

/// A symbolic reference to a region at an optional byte offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Region {
    pub id: RegionId,
    /// Byte offset within the region (signed, to handle negative stack offsets).
    pub offset: i64,
}

impl Region {
    #[must_use]
    pub const fn new(id: RegionId) -> Self {
        Self { id, offset: 0 }
    }

    #[must_use]
    pub const fn with_offset(id: RegionId, offset: i64) -> Self {
        Self { id, offset }
    }

    /// Offsets by `delta`, saturating instead of overflowing.
    ///
    /// # Panics
    ///
    /// Never panics: adversarial/malformed IL (e.g. an already near-`i64::MAX`
    /// offset combined with a large positive `delta`) previously overflowed
    /// this `i64` addition, which panics in debug builds. Saturating keeps
    /// the result well-defined without wrapping around to a spuriously
    /// different (and possibly falsely aliasing/non-aliasing) offset.
    #[must_use]
    pub const fn at_offset(&self, delta: i64) -> Self {
        Self {
            id: self.id,
            offset: self.offset.saturating_add(delta),
        }
    }

    /// Two regions statically alias if they refer to the same `RegionId` and
    /// their offsets overlap within a given element size.
    #[must_use]
    pub fn may_alias_with(&self, other: &Self, elem_size: u64) -> bool {
        if self.id != other.id {
            return false;
        }
        // `abs_diff` computes the unsigned distance directly instead of first
        // subtracting as `i64` (which panics on overflow in debug builds when
        // the two offsets are near opposite ends of the `i64` range).
        let diff = self.offset.abs_diff(other.offset);
        diff < elem_size
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.offset >= 0 {
            write!(f, "{}+{}", self.id, self.offset)
        } else {
            write!(f, "{}{}", self.id, self.offset)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessPath
// ─────────────────────────────────────────────────────────────────────────────

/// An access path: a root region plus a sequence of field/index selectors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessPath {
    pub root: Region,
    pub selectors: Vec<Selector>,
}

/// One step in an access path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Selector {
    /// Struct field at byte offset.
    Field(u32),
    /// Array index.
    Index(u64),
    /// Pointer dereference.
    Deref,
}

impl AccessPath {
    #[must_use]
    pub const fn new(root: Region) -> Self {
        Self {
            root,
            selectors: Vec::new(),
        }
    }

    #[must_use]
    pub fn field(mut self, offset: u32) -> Self {
        self.selectors.push(Selector::Field(offset));
        self
    }

    #[must_use]
    pub fn index(mut self, idx: u64) -> Self {
        self.selectors.push(Selector::Index(idx));
        self
    }

    #[must_use]
    pub fn deref(mut self) -> Self {
        self.selectors.push(Selector::Deref);
        self
    }

    /// Depth of the access path (number of selectors).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.selectors.len()
    }

    /// Whether two access paths definitely alias (same root + same selectors).
    #[must_use]
    pub fn must_alias(&self, other: &Self) -> bool {
        self == other
    }

    /// Whether two access paths may alias (same root region, compatible prefix).
    #[must_use]
    pub fn may_alias(&self, other: &Self) -> bool {
        if self.root.id != other.root.id {
            return false;
        }
        // If one is a prefix of the other they may alias.
        let min_len = self.selectors.len().min(other.selectors.len());
        self.selectors[..min_len] == other.selectors[..min_len]
    }
}

impl fmt::Display for AccessPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.root)?;
        for sel in &self.selectors {
            match sel {
                Selector::Field(o) => write!(f, ".{o}")?,
                Selector::Index(i) => write!(f, "[{i}]")?,
                Selector::Deref => write!(f, "*")?,
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ModRefInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Mod/Ref information for a single function.
#[derive(Debug, Clone, Default)]
pub struct ModRefInfo {
    /// Regions that the function may **write** to (mod).
    pub mod_regions: HashSet<RegionId>,
    /// Regions that the function may **read** from (ref).
    pub ref_regions: HashSet<RegionId>,
}

impl ModRefInfo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a write to a region.
    pub fn add_mod(&mut self, r: RegionId) {
        self.mod_regions.insert(r);
    }

    /// Record a read from a region.
    pub fn add_ref(&mut self, r: RegionId) {
        self.ref_regions.insert(r);
    }

    /// Whether the function may modify region `r`.
    #[must_use]
    pub fn may_mod(&self, r: RegionId) -> bool {
        self.mod_regions.contains(&r)
    }

    /// Whether the function may read region `r`.
    #[must_use]
    pub fn may_ref(&self, r: RegionId) -> bool {
        self.ref_regions.contains(&r)
    }

    /// Pure — neither reads nor writes any known region.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        self.mod_regions.is_empty() && self.ref_regions.is_empty()
    }

    /// Read-only — reads but never writes.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.mod_regions.is_empty() && !self.ref_regions.is_empty()
    }

    /// Merge another `ModRefInfo` into `self` (take union of sets).
    pub fn merge(&mut self, other: &Self) {
        self.mod_regions.extend(&other.mod_regions);
        self.ref_regions.extend(&other.ref_regions);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionSummary
// ─────────────────────────────────────────────────────────────────────────────

/// A per-function region summary produced by the analysis.
#[derive(Debug, Clone, Default)]
pub struct RegionSummary {
    pub function_address: u64,
    pub modref: ModRefInfo,
    /// All access paths observed in the function body.
    pub access_paths: Vec<AccessPath>,
    /// Detected may-alias pairs (paths that may refer to the same location).
    pub may_alias_pairs: Vec<(AccessPath, AccessPath)>,
}

impl RegionSummary {
    #[must_use]
    pub fn new(function_address: u64) -> Self {
        Self {
            function_address,
            ..Default::default()
        }
    }

    /// Record an access path and update modref info.
    pub fn record_write(&mut self, path: AccessPath) {
        self.modref.add_mod(path.root.id);
        self.access_paths.push(path);
    }

    pub fn record_read(&mut self, path: AccessPath) {
        self.modref.add_ref(path.root.id);
        self.access_paths.push(path);
    }

    /// Compute may-alias pairs from the recorded access paths.
    ///
    /// `AccessPath::may_alias` is `false` whenever the two paths have
    /// different roots, so bucket paths by root id first — this keeps the
    /// pairwise comparison confined to same-root groups instead of scanning
    /// every cross-root pair, which matters once a function touches many
    /// distinct regions.
    pub fn compute_may_aliases(&mut self) {
        self.may_alias_pairs.clear();
        // Use a `BTreeMap` (not `HashMap`) keyed on `RegionId` so groups are
        // visited in a canonical order — `HashMap` iteration order is
        // unspecified and would otherwise make `may_alias_pairs` ordering
        // (and thus anything downstream that diffs/hashes it) depend on
        // incidental hash-seed/insertion-order effects across runs.
        let mut by_root: std::collections::BTreeMap<RegionId, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (idx, path) in self.access_paths.iter().enumerate() {
            by_root.entry(path.root.id).or_default().push(idx);
        }
        for indices in by_root.values() {
            for (pos, &i) in indices.iter().enumerate() {
                for &j in &indices[pos + 1..] {
                    let a = &self.access_paths[i];
                    let b = &self.access_paths[j];
                    if a.may_alias(b) && a != b {
                        self.may_alias_pairs.push((a.clone(), b.clone()));
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Directed graph connecting regions by aliasing and containment relationships.
#[derive(Debug, Clone, Default)]
pub struct RegionGraph {
    pub descriptors: HashMap<RegionId, RegionDescriptor>,
    /// Directed graph with `RegionEdgeKind` on edges, backed by petgraph.
    graph: DiGraph<RegionId, RegionEdgeKind>,
    /// Map from `RegionId` to its petgraph `NodeIndex`.
    node_index: HashMap<RegionId, NodeIndex>,
}

/// The kind of relationship between two regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionEdgeKind {
    /// `from` may alias `to`.
    MayAlias,
    /// `from` contains `to` (nested region).
    Contains,
    /// `from` points to `to`.
    PointsTo,
}

impl RegionGraph {
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            graph: DiGraph::new(),
            node_index: HashMap::new(),
        }
    }

    /// Register a region descriptor, adding a node to the petgraph graph.
    pub fn add_region(&mut self, desc: RegionDescriptor) {
        let id = desc.id;
        self.descriptors.insert(id, desc);
        if !self.node_index.contains_key(&id) {
            let ni = self.graph.add_node(id);
            self.node_index.insert(id, ni);
        }
    }

    /// Ensure a node exists for the given `RegionId` (creates a placeholder if absent).
    fn ensure_node(&mut self, id: RegionId) -> NodeIndex {
        if let Some(&ni) = self.node_index.get(&id) {
            return ni;
        }
        let ni = self.graph.add_node(id);
        self.node_index.insert(id, ni);
        ni
    }

    /// Add a directed edge between two regions.
    pub fn add_edge(&mut self, from: RegionId, to: RegionId, kind: RegionEdgeKind) {
        let f = self.ensure_node(from);
        let t = self.ensure_node(to);
        self.graph.add_edge(f, t, kind);
    }

    /// All regions that `r` may alias (undirected: edges in either direction).
    ///
    /// # Panics
    ///
    /// Panics if the graph contains an edge to a node with no associated weight.
    #[must_use]
    pub fn may_aliases(&self, r: RegionId) -> Vec<RegionId> {
        let Some(&ni) = self.node_index.get(&r) else { return Vec::new() };
        let mut result = Vec::new();
        for edge in self.graph.edges(ni) {
            if *edge.weight() == RegionEdgeKind::MayAlias {
                result.push(*self.graph.node_weight(edge.target()).unwrap());
            }
        }
        // Also collect reverse edges (MayAlias is symmetric).
        for edge in self.graph.edges_directed(ni, petgraph::Direction::Incoming) {
            if *edge.weight() == RegionEdgeKind::MayAlias {
                result.push(*self.graph.node_weight(edge.source()).unwrap());
            }
        }
        result
    }

    /// Regions reachable from `r` via `PointsTo` edges (BFS via petgraph).
    ///
    /// # Panics
    ///
    /// Panics if the graph contains a node with no associated weight.
    #[must_use]
    pub fn points_to_closure(&self, r: RegionId) -> HashSet<RegionId> {
        let Some(&start) = self.node_index.get(&r) else { return HashSet::new() };
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(cur) = queue.pop_front() {
            for edge in self.graph.edges(cur) {
                if *edge.weight() == RegionEdgeKind::PointsTo {
                    let tgt = edge.target();
                    let tgt_id = *self.graph.node_weight(tgt).unwrap();
                    if visited.insert(tgt_id) {
                        queue.push_back(tgt);
                    }
                }
            }
        }
        visited.remove(&r);
        visited
    }

    /// Number of regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.descriptors.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionAnalysis — main driver
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract region-based alias analysis driver.
pub struct RegionAnalysis {
    next_id: u32,
    pub graph: RegionGraph,
    /// Summaries keyed by function address.
    pub summaries: HashMap<u64, RegionSummary>,
}

impl Default for RegionAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl RegionAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 0,
            graph: RegionGraph::new(),
            summaries: HashMap::new(),
        }
    }

    /// Allocate a fresh `RegionId`.
    pub fn fresh_region(&mut self, kind: RegionKind, label: impl Into<String>) -> RegionId {
        let id = RegionId(self.next_id);
        self.next_id += 1;
        self.graph
            .add_region(RegionDescriptor::new(id, kind, label));
        id
    }

    /// Allocate a stack region for a function.
    #[must_use]
    pub fn stack_region_for(&mut self, func_addr: u64) -> RegionId {
        self.fresh_region(RegionKind::Stack, format!("stack_{func_addr:#x}"))
    }

    /// Allocate a heap region.
    #[must_use]
    pub fn heap_region(&mut self, label: impl Into<String>) -> RegionId {
        self.fresh_region(RegionKind::Heap, label)
    }

    /// Allocate a global region at a specific address.
    #[must_use]
    pub fn global_region(&mut self, addr: u64) -> RegionId {
        let id = RegionId(self.next_id);
        self.next_id += 1;
        let desc = RegionDescriptor::new(id, RegionKind::Global, format!("global_{addr:#x}"))
            .with_address(addr);
        self.graph.add_region(desc);
        id
    }

    /// Record a write access for a function.
    pub fn record_write(&mut self, func_addr: u64, path: AccessPath) {
        self.summaries
            .entry(func_addr)
            .or_insert_with(|| RegionSummary::new(func_addr))
            .record_write(path);
    }

    /// Record a read access for a function.
    pub fn record_read(&mut self, func_addr: u64, path: AccessPath) {
        self.summaries
            .entry(func_addr)
            .or_insert_with(|| RegionSummary::new(func_addr))
            .record_read(path);
    }

    /// Finalise analysis: compute may-alias pairs for all summaries.
    pub fn finalise(&mut self) {
        for summary in self.summaries.values_mut() {
            summary.compute_may_aliases();
        }
    }

    /// Get the `ModRefInfo` for a function.
    #[must_use]
    pub fn modref_for(&self, func_addr: u64) -> Option<&ModRefInfo> {
        self.summaries.get(&func_addr).map(|s| &s.modref)
    }

    /// All functions that may write to region `r`.
    #[must_use]
    pub fn writers_of(&self, r: RegionId) -> Vec<u64> {
        self.summaries
            .iter()
            .filter(|(_, s)| s.modref.may_mod(r))
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// All functions that may read from region `r`.
    #[must_use]
    pub fn readers_of(&self, r: RegionId) -> Vec<u64> {
        self.summaries
            .iter()
            .filter(|(_, s)| s.modref.may_ref(r))
            .map(|(addr, _)| *addr)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ra() -> RegionAnalysis {
        RegionAnalysis::new()
    }

    // 1. Fresh region IDs are distinct
    #[test]
    fn test_fresh_region_ids_distinct() {
        let mut ra = ra();
        let r1 = ra.fresh_region(RegionKind::Stack, "s1");
        let r2 = ra.fresh_region(RegionKind::Stack, "s2");
        assert_ne!(r1, r2);
    }

    // 2. Stack region is registered in graph
    #[test]
    fn test_stack_region_in_graph() {
        let mut ra = ra();
        let r = ra.stack_region_for(0x1000);
        assert!(ra.graph.descriptors.contains_key(&r));
        assert_eq!(ra.graph.descriptors[&r].kind, RegionKind::Stack);
    }

    // 3. Heap region kind
    #[test]
    fn test_heap_region_kind() {
        let mut ra = ra();
        let r = ra.heap_region("heap0");
        assert!(ra.graph.descriptors[&r].is_heap());
    }

    // 4. Global region has base address
    #[test]
    fn test_global_region_address() {
        let mut ra = ra();
        let r = ra.global_region(0x4000);
        let desc = &ra.graph.descriptors[&r];
        assert_eq!(desc.base_address, Some(0x4000));
        assert_eq!(desc.kind, RegionKind::Global);
    }

    // 5. Record write updates modref
    #[test]
    fn test_record_write_modref() {
        let mut ra = ra();
        let r = ra.heap_region("h0");
        let path = AccessPath::new(Region::new(r));
        ra.record_write(0x1000, path);
        assert!(ra.modref_for(0x1000).expect("exists").may_mod(r));
    }

    // 6. Record read updates modref
    #[test]
    fn test_record_read_modref() {
        let mut ra = ra();
        let r = ra.stack_region_for(0x1000);
        let path = AccessPath::new(Region::new(r));
        ra.record_read(0x1000, path);
        assert!(ra.modref_for(0x1000).expect("exists").may_ref(r));
    }

    // 7. ModRefInfo is_pure for empty
    #[test]
    fn test_modref_is_pure() {
        let mr = ModRefInfo::new();
        assert!(mr.is_pure());
    }

    // 8. ModRefInfo is_read_only
    #[test]
    fn test_modref_is_read_only() {
        let mut mr = ModRefInfo::new();
        mr.add_ref(RegionId(0));
        assert!(mr.is_read_only());
        mr.add_mod(RegionId(0));
        assert!(!mr.is_read_only());
    }

    // 9. ModRefInfo merge
    #[test]
    fn test_modref_merge() {
        let mut mr1 = ModRefInfo::new();
        mr1.add_mod(RegionId(0));
        let mut mr2 = ModRefInfo::new();
        mr2.add_ref(RegionId(1));
        mr1.merge(&mr2);
        assert!(mr1.may_mod(RegionId(0)));
        assert!(mr1.may_ref(RegionId(1)));
    }

    // 10. writers_of correct
    #[test]
    fn test_writers_of() {
        let mut ra = ra();
        let r = ra.global_region(0x5000);
        let path = AccessPath::new(Region::new(r));
        ra.record_write(0x2000, path.clone());
        ra.record_write(0x3000, path);
        let writers = ra.writers_of(r);
        assert_eq!(writers.len(), 2);
    }

    // 11. readers_of correct
    #[test]
    fn test_readers_of() {
        let mut ra = ra();
        let r = ra.global_region(0x6000);
        let path = AccessPath::new(Region::new(r));
        ra.record_read(0x4000, path);
        assert_eq!(ra.readers_of(r).len(), 1);
    }

    // 12. Region with_offset
    #[test]
    fn test_region_with_offset() {
        let r = Region::with_offset(RegionId(0), -8);
        assert_eq!(r.offset, -8);
    }

    // 13. Region at_offset
    #[test]
    fn test_region_at_offset() {
        let r = Region::with_offset(RegionId(0), 4);
        let r2 = r.at_offset(8);
        assert_eq!(r2.offset, 12);
    }

    // 14. Region may_alias_with same id small diff
    #[test]
    fn test_region_may_alias() {
        let a = Region::with_offset(RegionId(0), 0);
        let b = Region::with_offset(RegionId(0), 2);
        assert!(a.may_alias_with(&b, 4)); // within 4 bytes
        assert!(!a.may_alias_with(&b, 2)); // diff >= elem_size
    }

    // 15. Region may_alias_with different ids
    #[test]
    fn test_region_no_alias_different_id() {
        let a = Region::new(RegionId(0));
        let b = Region::new(RegionId(1));
        assert!(!a.may_alias_with(&b, 8));
    }

    // 16. AccessPath must_alias self
    #[test]
    fn test_access_path_must_alias_self() {
        let r = Region::new(RegionId(0));
        let p = AccessPath::new(r).field(0);
        assert!(p.must_alias(&p));
    }

    // 17. AccessPath may_alias prefix
    #[test]
    fn test_access_path_may_alias_prefix() {
        let r = Region::new(RegionId(0));
        let p1 = AccessPath::new(r.clone()).field(0);
        let p2 = AccessPath::new(r).field(0).index(0);
        assert!(p1.may_alias(&p2));
    }

    // 18. AccessPath no alias different roots
    #[test]
    fn test_access_path_no_alias_diff_root() {
        let p1 = AccessPath::new(Region::new(RegionId(0))).field(0);
        let p2 = AccessPath::new(Region::new(RegionId(1))).field(0);
        assert!(!p1.may_alias(&p2));
    }

    // 19. AccessPath depth
    #[test]
    fn test_access_path_depth() {
        let r = Region::new(RegionId(0));
        let p = AccessPath::new(r).field(0).deref().index(3);
        assert_eq!(p.depth(), 3);
    }

    // 20. AccessPath display
    #[test]
    fn test_access_path_display() {
        let r = Region::new(RegionId(0));
        let p = AccessPath::new(r).field(8).index(2);
        let s = p.to_string();
        assert!(s.contains(".8"));
        assert!(s.contains("[2]"));
    }

    // 21. RegionGraph region_count
    #[test]
    fn test_region_graph_region_count() {
        let mut ra = ra();
        ra.fresh_region(RegionKind::Stack, "s0");
        ra.fresh_region(RegionKind::Heap, "h0");
        assert_eq!(ra.graph.region_count(), 2);
    }

    // 22. RegionGraph may_aliases
    #[test]
    fn test_region_graph_may_aliases() {
        let mut rg = RegionGraph::new();
        rg.add_edge(RegionId(0), RegionId(1), RegionEdgeKind::MayAlias);
        let aliases = rg.may_aliases(RegionId(0));
        assert!(aliases.contains(&RegionId(1)));
    }

    // 23. RegionGraph may_aliases symmetric
    #[test]
    fn test_region_graph_may_aliases_symmetric() {
        let mut rg = RegionGraph::new();
        rg.add_edge(RegionId(0), RegionId(1), RegionEdgeKind::MayAlias);
        let aliases = rg.may_aliases(RegionId(1));
        assert!(aliases.contains(&RegionId(0)));
    }

    // 24. RegionGraph points_to_closure
    #[test]
    fn test_points_to_closure() {
        let mut rg = RegionGraph::new();
        rg.add_edge(RegionId(0), RegionId(1), RegionEdgeKind::PointsTo);
        rg.add_edge(RegionId(1), RegionId(2), RegionEdgeKind::PointsTo);
        let closure = rg.points_to_closure(RegionId(0));
        assert!(closure.contains(&RegionId(1)));
        assert!(closure.contains(&RegionId(2)));
        assert!(!closure.contains(&RegionId(0)));
    }

    // 25. RegionSummary compute_may_aliases
    #[test]
    fn test_summary_may_aliases() {
        let mut summary = RegionSummary::new(0x1000);
        let r = RegionId(0);
        let p1 = AccessPath::new(Region::new(r)).field(0);
        let p2 = AccessPath::new(Region::new(r)).field(0).index(0);
        summary.record_read(p1);
        summary.record_read(p2);
        summary.compute_may_aliases();
        assert!(!summary.may_alias_pairs.is_empty());
    }

    // 26. RegionDescriptor is_stack
    #[test]
    fn test_descriptor_is_stack() {
        let desc = RegionDescriptor::new(RegionId(0), RegionKind::Stack, "s");
        assert!(desc.is_stack());
        assert!(!desc.is_heap());
    }

    // 27. RegionDescriptor builder
    #[test]
    fn test_descriptor_builder() {
        let desc = RegionDescriptor::new(RegionId(0), RegionKind::Global, "g")
            .with_address(0x1234)
            .with_size(16)
            .aliasable();
        assert_eq!(desc.base_address, Some(0x1234));
        assert_eq!(desc.size, Some(16));
        assert!(desc.may_alias);
    }

    // 28. RegionKind display
    #[test]
    fn test_region_kind_display() {
        assert_eq!(RegionKind::Stack.to_string(), "stack");
        assert_eq!(RegionKind::Heap.to_string(), "heap");
        assert_eq!(RegionKind::Global.to_string(), "global");
    }

    // 29. Region display positive offset
    #[test]
    fn test_region_display_positive() {
        let r = Region::with_offset(RegionId(0), 4);
        assert_eq!(r.to_string(), "R0+4");
    }

    // 30. Region display negative offset
    #[test]
    fn test_region_display_negative() {
        let r = Region::with_offset(RegionId(0), -8);
        assert_eq!(r.to_string(), "R0-8");
    }

    // 31. RegionId display
    #[test]
    fn test_region_id_display() {
        assert_eq!(RegionId(5).to_string(), "R5");
    }

    // 32. finalise runs on all summaries
    #[test]
    fn test_finalise_runs() {
        let mut ra = ra();
        let r = ra.heap_region("h");
        let p = AccessPath::new(Region::new(r)).field(0);
        ra.record_write(0x1000, p.clone());
        ra.record_read(0x1000, p);
        ra.finalise();
        // No panic = success; may_alias_pairs populated
    }

    // 33. modref_for returns None for unknown function
    #[test]
    fn test_modref_for_unknown() {
        let ra = ra();
        assert!(ra.modref_for(0xdeadbeef).is_none());
    }

    // 34. AccessPath deref selector
    #[test]
    fn test_access_path_deref() {
        let r = Region::new(RegionId(0));
        let p = AccessPath::new(r).deref();
        assert!(matches!(p.selectors[0], Selector::Deref));
    }

    // 35. RegionEdgeKind Contains
    #[test]
    fn test_region_edge_contains() {
        let mut rg = RegionGraph::new();
        rg.add_edge(RegionId(0), RegionId(1), RegionEdgeKind::Contains);
        assert!(
            rg.graph
                .edge_references()
                .any(|edge| *edge.weight() == RegionEdgeKind::Contains)
        );
    }

    // 36. writers_of empty when no writes
    #[test]
    fn test_writers_of_empty() {
        let ra = ra();
        assert!(ra.writers_of(RegionId(0)).is_empty());
    }

    // 37. Multiple functions per region
    #[test]
    fn test_multiple_funcs_per_region() {
        let mut ra = ra();
        let r = ra.global_region(0x8000);
        for addr in [0x1000_u64, 0x2000, 0x3000] {
            ra.record_write(addr, AccessPath::new(Region::new(r)));
        }
        assert_eq!(ra.writers_of(r).len(), 3);
    }

    // 38. RegionSummary new has correct address
    #[test]
    fn test_region_summary_address() {
        let s = RegionSummary::new(0xabcd);
        assert_eq!(s.function_address, 0xabcd);
        assert!(s.modref.is_pure());
    }

    // 39. AccessPath no must_alias when different selectors
    #[test]
    fn test_access_path_no_must_alias_diff_selectors() {
        let r = Region::new(RegionId(0));
        let p1 = AccessPath::new(r.clone()).field(0);
        let p2 = AccessPath::new(r).field(4);
        assert!(!p1.must_alias(&p2));
    }

    // 40. RegionAnalysis default is empty
    #[test]
    fn test_region_analysis_default_empty() {
        let ra = RegionAnalysis::default();
        assert!(ra.summaries.is_empty());
        assert_eq!(ra.graph.region_count(), 0);
    }

    // 41. AccessPath may_alias same selectors
    #[test]
    fn test_access_path_may_alias_same_selectors() {
        let r = Region::new(RegionId(0));
        let p1 = AccessPath::new(r.clone()).field(0).index(1);
        let p2 = AccessPath::new(r).field(0).index(1);
        assert!(p1.may_alias(&p2));
    }

    // 42. RegionGraph points_to_closure empty for isolated node
    #[test]
    fn test_points_to_closure_isolated() {
        let rg = RegionGraph::new();
        let closure = rg.points_to_closure(RegionId(0));
        assert!(closure.is_empty());
    }

    // 43a. Region::at_offset saturates instead of overflow-panicking on
    // malformed/adversarial offsets near the `i64` boundary.
    #[test]
    fn test_region_at_offset_saturates_on_overflow() {
        let r = Region::with_offset(RegionId(0), i64::MAX - 1);
        let r2 = r.at_offset(100);
        assert_eq!(r2.offset, i64::MAX);

        let r = Region::with_offset(RegionId(0), i64::MIN + 1);
        let r2 = r.at_offset(-100);
        assert_eq!(r2.offset, i64::MIN);
    }

    // 43b. Region::may_alias_with must not panic when the two offsets sit at
    // opposite ends of the `i64` range (a naive `a - b` subtraction there
    // overflows in debug builds).
    #[test]
    fn test_region_may_alias_with_extreme_offsets_no_panic() {
        let a = Region::with_offset(RegionId(0), i64::MIN);
        let b = Region::with_offset(RegionId(0), i64::MAX);
        // Should just compute a huge diff and report no alias, not panic.
        assert!(!a.may_alias_with(&b, 8));
    }

    // 43. compute_may_aliases is deterministic across many distinct roots.
    //
    // Regression test: `compute_may_aliases` used to bucket access paths by
    // root region in a `HashMap`, so the order in which same-root groups were
    // processed (and thus the order of `may_alias_pairs`) depended on
    // `HashMap`'s unspecified iteration order. With many distinct
    // `RegionId`s this could vary from run to run (different hash-seed),
    // producing a non-reproducible pair ordering. It's now a `BTreeMap`, so
    // groups are always visited in ascending `RegionId` order.
    #[test]
    fn test_compute_may_aliases_deterministic_order() {
        let mut summary = RegionSummary::new(0x1000);
        // Interleave several distinct roots, each with two aliasing paths,
        // in an order chosen to *not* match ascending RegionId (so a
        // HashMap-iteration-order bug would very likely reorder them).
        let root_ids = [7u32, 3, 9, 1, 5];
        for &rid in &root_ids {
            let r = Region::new(RegionId(rid));
            summary.record_read(AccessPath::new(r.clone()).field(0));
            summary.record_read(AccessPath::new(r).field(0).index(1));
        }

        let mut first = summary.clone();
        first.compute_may_aliases();
        let expected: Vec<RegionId> =
            first.may_alias_pairs.iter().map(|(a, _)| a.root.id).collect();
        assert_eq!(
            expected,
            vec![RegionId(1), RegionId(3), RegionId(5), RegionId(7), RegionId(9)],
            "may_alias_pairs must be ordered by ascending RegionId, not HashMap iteration order"
        );

        // Recomputing repeatedly must always yield the exact same order.
        for _ in 0..10 {
            let mut again = summary.clone();
            again.compute_may_aliases();
            assert_eq!(again.may_alias_pairs, first.may_alias_pairs);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Randomized soundness properties for region / alias summaries.
//
// The core soundness contract of a MAY-alias analysis: must-alias ⟹ may-alias,
// and may-alias must be symmetric and reflexive. An unsound alias analysis that
// reports "no alias" for two paths that actually always refer to the same
// location would let a downstream optimization drop a real dependency.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod prop_soundness {
    use super::*;

    use crate::test_prng::Xs;

    fn rand_path(r: &mut Xs, max_root: u32) -> AccessPath {
        let root = Region::with_offset(RegionId(r.next() as u32 % max_root), (r.next() % 32) as i64);
        let mut p = AccessPath::new(root);
        let depth = r.next() % 4;
        for _ in 0..depth {
            p = match r.next() % 3 {
                0 => p.field((r.next() % 4) as u32),
                1 => p.index(r.next() % 4),
                _ => p.deref(),
            };
        }
        p
    }

    // must_alias ⟹ may_alias (fundamental soundness of a may-analysis).
    #[test]
    fn prop_must_implies_may() {
        let mut r = Xs::new(0xA11A_5000);
        for _ in 0..8000 {
            let a = rand_path(&mut r, 4);
            let b = rand_path(&mut r, 4);
            if a.must_alias(&b) {
                assert!(a.may_alias(&b), "must-alias pair not may-alias: {a} / {b}");
            }
        }
    }

    // may_alias must be reflexive and symmetric.
    #[test]
    fn prop_may_alias_reflexive_symmetric() {
        let mut r = Xs::new(0xB22B_6000);
        for _ in 0..8000 {
            let a = rand_path(&mut r, 4);
            let b = rand_path(&mut r, 4);
            assert!(a.may_alias(&a), "may_alias not reflexive: {a}");
            assert_eq!(
                a.may_alias(&b),
                b.may_alias(&a),
                "may_alias not symmetric: {a} / {b}"
            );
        }
    }

    // Region::may_alias_with must be reflexive (for elem_size>=1) and symmetric.
    #[test]
    fn prop_region_may_alias_with_symmetric() {
        let mut r = Xs::new(0xC33C_7000);
        for _ in 0..8000 {
            let a = Region::with_offset(RegionId((r.next() % 3) as u32), (r.next() % 64) as i64 - 32);
            let b = Region::with_offset(RegionId((r.next() % 3) as u32), (r.next() % 64) as i64 - 32);
            let sz = 1 + r.next() % 16;
            assert_eq!(
                a.may_alias_with(&b, sz),
                b.may_alias_with(&a, sz),
                "region may_alias_with not symmetric: {a} / {b} sz {sz}"
            );
            assert!(a.may_alias_with(&a, sz), "region may_alias_with not reflexive: {a} sz {sz}");
        }
    }

    // compute_may_aliases soundness: EVERY distinct recorded pair that
    // may_alias per the predicate must appear in may_alias_pairs (as an
    // unordered pair). This is the "no dropped dependency" property.
    #[test]
    fn prop_compute_may_aliases_captures_all_pairs() {
        let mut r = Xs::new(0xD44D_8000);
        for _ in 0..1500 {
            let mut summary = RegionSummary::new(0x1000);
            let n = 2 + r.next() % 6;
            for _ in 0..n {
                let p = rand_path(&mut r, 3);
                if r.next() % 2 == 0 {
                    summary.record_read(p);
                } else {
                    summary.record_write(p);
                }
            }
            summary.compute_may_aliases();
            // Brute-force reference over all i<j pairs.
            let paths = summary.access_paths.clone();
            for i in 0..paths.len() {
                for j in (i + 1)..paths.len() {
                    let a = &paths[i];
                    let b = &paths[j];
                    if a.may_alias(b) && a != b {
                        let found = summary.may_alias_pairs.iter().any(|(x, y)| {
                            (x == a && y == b) || (x == b && y == a)
                        });
                        assert!(found, "compute_may_aliases dropped a may-alias pair: {a} / {b}");
                    }
                }
            }
        }
    }

    // points_to_closure must equal brute-force PointsTo-reachability (excluding
    // the start node), i.e. it must not miss any reachable region (soundness).
    #[test]
    fn prop_points_to_closure_matches_bruteforce() {
        let mut r = Xs::new(0xE55E_9000);
        for _ in 0..1000 {
            let nnodes = 2 + (r.next() % 6) as u32;
            let mut rg = RegionGraph::new();
            // Build a random adjacency for PointsTo edges.
            let mut adj: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
            let nedges = r.next() % 10;
            for _ in 0..nedges {
                let a = (r.next() % nnodes as u64) as u32;
                let b = (r.next() % nnodes as u64) as u32;
                rg.add_edge(RegionId(a), RegionId(b), RegionEdgeKind::PointsTo);
                adj.entry(a).or_default().push(b);
            }
            // Occasionally add a decoy non-PointsTo edge.
            if r.next() % 2 == 0 {
                let a = (r.next() % nnodes as u64) as u32;
                let b = (r.next() % nnodes as u64) as u32;
                rg.add_edge(RegionId(a), RegionId(b), RegionEdgeKind::MayAlias);
            }
            let start = (r.next() % nnodes as u64) as u32;
            // Brute-force BFS over PointsTo adjacency.
            let mut expected: HashSet<u32> = HashSet::new();
            let mut stack = vec![start];
            let mut seen: HashSet<u32> = HashSet::new();
            seen.insert(start);
            while let Some(cur) = stack.pop() {
                for &nx in adj.get(&cur).map(|v| v.as_slice()).unwrap_or(&[]) {
                    if seen.insert(nx) {
                        expected.insert(nx);
                        stack.push(nx);
                    }
                }
            }
            expected.remove(&start);
            let got: HashSet<u32> = rg
                .points_to_closure(RegionId(start))
                .into_iter()
                .map(|id| id.0)
                .collect();
            assert_eq!(got, expected, "points_to_closure mismatch from {start}");
        }
    }

    // ModRefInfo::merge is a union (monotone: never loses a mod/ref fact).
    #[test]
    fn prop_modref_merge_is_union() {
        let mut r = Xs::new(0xF66F_A000);
        for _ in 0..4000 {
            let mut a = ModRefInfo::new();
            let mut b = ModRefInfo::new();
            for _ in 0..(r.next() % 5) {
                a.add_mod(RegionId((r.next() % 8) as u32));
                a.add_ref(RegionId((r.next() % 8) as u32));
            }
            let mut expect_mod: HashSet<RegionId> = a.mod_regions.clone();
            let mut expect_ref: HashSet<RegionId> = a.ref_regions.clone();
            for _ in 0..(r.next() % 5) {
                let m = RegionId((r.next() % 8) as u32);
                let rf = RegionId((r.next() % 8) as u32);
                b.add_mod(m);
                b.add_ref(rf);
                expect_mod.insert(m);
                expect_ref.insert(rf);
            }
            a.merge(&b);
            assert_eq!(a.mod_regions, expect_mod);
            assert_eq!(a.ref_regions, expect_ref);
        }
    }
}
