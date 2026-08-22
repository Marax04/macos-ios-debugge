//! C++ inheritance hierarchy recovery.
//!
//! Provides:
//! * `ClassNode` — a class in the recovered hierarchy.
//! * `InheritanceGraph` — directed graph of class relationships.
//! * `VirtualDispatchSite` — a resolved virtual call site.
//! * Analysis functions for building hierarchies from RTTI and vtable data.

use crate::{RttiInfo, VtableDatabase};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// ClassNode
// ─────────────────────────────────────────────────────────────────────────────

/// A class in the recovered C++ inheritance hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassNode {
    /// Demangled class name.
    pub name: String,
    /// Direct base classes (demangled names).
    pub bases: Vec<String>,
    /// Direct derived classes (demangled names).
    pub derived: Vec<String>,
    /// The vtable address(es) associated with this class.
    pub vtable_addresses: Vec<u64>,
    /// RTTI struct address, if recovered.
    pub rtti_address: Option<u64>,
    /// Number of virtual functions (max across all associated vtables).
    pub virtual_function_count: usize,
    /// Whether any base is virtual.
    pub has_virtual_base: bool,
}

impl ClassNode {
    /// Create a new `ClassNode` with just a name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            bases: Vec::new(),
            derived: Vec::new(),
            vtable_addresses: Vec::new(),
            rtti_address: None,
            virtual_function_count: 0,
            has_virtual_base: false,
        }
    }

    /// Whether this class is a root (has no bases).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.bases.is_empty()
    }

    /// Whether this class is a leaf (has no derived classes).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.derived.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InheritanceGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A directed graph of C++ class inheritance relationships.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct InheritanceGraph {
    /// Map from class name to `ClassNode`.
    pub classes: HashMap<String, ClassNode>,
}

impl InheritanceGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an `InheritanceGraph` from a `VtableDatabase`.
    #[must_use]
    pub fn from_database(db: &VtableDatabase) -> Self {
        let mut graph = Self::new();

        // Add all RTTI-derived class information.
        // Iterate in address order: HashMap iteration order is unstable and
        // previously leaked into `derived` edge ordering (and thus BFS order).
        let mut rtti_sorted: Vec<&RttiInfo> = db.rtti.values().collect();
        rtti_sorted.sort_by_key(|r| r.rtti_address);
        for rtti in rtti_sorted {
            graph.add_rtti(rtti);
        }

        // Attach vtable addresses to classes (address order, same reason).
        let mut vt_sorted: Vec<(&u64, &crate::Vtable)> = db.vtables.iter().collect();
        vt_sorted.sort_by_key(|(addr, _)| **addr);
        for (vt_addr, vt) in vt_sorted {
            if let Some(class_name) = &vt.class_name {
                let node = graph
                    .classes
                    .entry(class_name.clone())
                    .or_insert_with(|| ClassNode::new(class_name));
                if !node.vtable_addresses.contains(vt_addr) {
                    node.vtable_addresses.push(*vt_addr);
                }
                node.virtual_function_count = node.virtual_function_count.max(vt.entry_count());
            }
        }

        graph
    }

    /// Add a class from RTTI information.
    pub fn add_rtti(&mut self, rtti: &RttiInfo) {
        // First, update the class node's own fields.
        {
            let node = self
                .classes
                .entry(rtti.type_name.clone())
                .or_insert_with(|| ClassNode::new(&rtti.type_name));
            node.rtti_address = Some(rtti.rtti_address);
            for base in &rtti.base_classes {
                if !node.bases.contains(base) {
                    node.bases.push(base.clone());
                }
            }
        }
        // Then, add reverse edges for each base class.
        for base in &rtti.base_classes {
            let base_node = self
                .classes
                .entry(base.clone())
                .or_insert_with(|| ClassNode::new(base));
            if !base_node.derived.contains(&rtti.type_name) {
                base_node.derived.push(rtti.type_name.clone());
            }
        }
    }

    /// Get a class node by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ClassNode> {
        self.classes.get(name)
    }

    /// All root classes (classes with no base), sorted by name for
    /// deterministic output (`HashMap` iteration order is not stable).
    #[must_use]
    pub fn roots(&self) -> Vec<&ClassNode> {
        let mut out: Vec<&ClassNode> = self.classes.values().filter(|n| n.is_root()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// All leaf classes (classes with no derived classes), sorted by name.
    #[must_use]
    pub fn leaves(&self) -> Vec<&ClassNode> {
        let mut out: Vec<&ClassNode> = self.classes.values().filter(|n| n.is_leaf()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// All classes in BFS order starting from `root_name`.
    #[must_use]
    pub fn bfs_from(&self, root_name: &str) -> Vec<&ClassNode> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        if let Some(root) = self.classes.get(root_name) {
            queue.push_back(root_name.to_owned());
            visited.insert(root_name.to_owned());
            result.push(root);
        }

        while let Some(name) = queue.pop_front() {
            if let Some(node) = self.classes.get(&name) {
                for child in &node.derived {
                    if visited.insert(child.clone())
                        && let Some(child_node) = self.classes.get(child.as_str()) {
                            queue.push_back(child.clone());
                            result.push(child_node);
                        }
                }
            }
        }
        result
    }

    /// All ancestors (transitive base classes) of `class_name`.
    #[must_use]
    pub fn ancestors_of(&self, class_name: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(node) = self.classes.get(class_name) {
            for base in &node.bases {
                if visited.insert(base.clone()) {
                    queue.push_back(base.clone());
                }
            }
        }
        while let Some(name) = queue.pop_front() {
            if let Some(node) = self.classes.get(&name) {
                for base in &node.bases {
                    if visited.insert(base.clone()) {
                        queue.push_back(base.clone());
                    }
                }
            }
        }
        // Sorted for deterministic output: HashSet iteration order is not
        // stable, and this order previously leaked into public results
        // (e.g. `resolve_virtual_dispatch` target ordering).
        let mut out: Vec<String> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// All descendants (transitive derived classes) of `class_name`.
    #[must_use]
    pub fn descendants_of(&self, class_name: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(node) = self.classes.get(class_name) {
            for derived in &node.derived {
                if visited.insert(derived.clone()) {
                    queue.push_back(derived.clone());
                }
            }
        }
        while let Some(name) = queue.pop_front() {
            if let Some(node) = self.classes.get(&name) {
                for derived in &node.derived {
                    if visited.insert(derived.clone()) {
                        queue.push_back(derived.clone());
                    }
                }
            }
        }
        // Sorted for deterministic output (see `ancestors_of`).
        let mut out: Vec<String> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// Whether `a` is-a `b` (a derives from b, directly or transitively).
    #[must_use]
    pub fn is_a(&self, a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        self.ancestors_of(a).iter().any(|s| s == b)
    }

    /// Inheritance depth of `name` (0 for root classes).
    ///
    /// Iterative (explicit-stack) longest-path with memoization: the previous
    /// recursive version could exhaust the native stack on very deep chains and
    /// re-explored shared bases exponentially on diamond-shaped DAGs.
    #[must_use]
    pub fn depth(&self, name: &str) -> usize {
        let mut memo: HashMap<&str, usize> = HashMap::new();
        self.depth_memo(name, &mut memo)
    }

    fn depth_memo<'a>(&'a self, start: &'a str, memo: &mut HashMap<&'a str, usize>) -> usize {
        // Explicit post-order DFS. on_stack guards against cycles.
        enum Frame<'f> { Enter(&'f str), Exit(&'f str) }
        let mut on_stack: HashSet<&str> = HashSet::new();
        let mut stack = vec![Frame::Enter(start)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Enter(name) => {
                    if memo.contains_key(name) || on_stack.contains(name) {
                        continue;
                    }
                    let Some(node) = self.classes.get(name) else {
                        memo.insert(name, 0);
                        continue;
                    };
                    on_stack.insert(node.name.as_str());
                    stack.push(Frame::Exit(node.name.as_str()));
                    for base in &node.bases {
                        stack.push(Frame::Enter(base.as_str()));
                    }
                }
                Frame::Exit(name) => {
                    on_stack.remove(name);
                    let depth = self
                        .classes
                        .get(name)
                        .map_or(0, |node| {
                            node.bases
                                .iter()
                                .map(|b| 1 + memo.get(b.as_str()).copied().unwrap_or(0))
                                .max()
                                .unwrap_or(0)
                        });
                    memo.insert(name, depth);
                }
            }
        }
        memo.get(start).copied().unwrap_or(0)
    }

    /// Total number of classes.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Returns classes that have more than one vtable (occurs with virtual base classes).
    #[must_use]
    pub fn classes_with_multiple_vtables(&self) -> Vec<&ClassNode> {
        let mut out: Vec<&ClassNode> = self
            .classes
            .values()
            .filter(|n| n.vtable_addresses.len() > 1)
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtual dispatch analysis
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved virtual call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDispatchSite {
    /// Address of the call instruction.
    pub call_address: u64,
    /// Vtable slot index (0-based).
    pub slot_index: usize,
    /// All target addresses this call may dispatch to.
    pub possible_targets: Vec<u64>,
    /// Whether this site was fully resolved.
    pub is_resolved: bool,
}

/// Resolve virtual dispatch sites given a type hierarchy and vtable database.
///
/// For each call to vtable slot `slot_index` on a value of dynamic type
/// `static_type` (or any of its descendants), we collect all possible target
/// addresses.
#[must_use]
pub fn resolve_virtual_dispatch(
    call_address: u64,
    static_type: &str,
    slot_index: usize,
    graph: &InheritanceGraph,
    db: &VtableDatabase,
) -> VirtualDispatchSite {
    let mut targets = Vec::new();

    // Collect the type itself and all its descendants.
    let mut type_names: Vec<String> = vec![static_type.to_owned()];
    type_names.extend(graph.descendants_of(static_type));

    for type_name in &type_names {
        if let Some(node) = graph.classes.get(type_name.as_str()) {
            for &vt_addr in &node.vtable_addresses {
                if let Some(vtable) = db.vtables.get(&vt_addr)
                    && let Some(entry) = vtable.entries.get(slot_index)
                        && !targets.contains(&entry.target_address) {
                            targets.push(entry.target_address);
                        }
            }
        }
    }

    let is_resolved = !targets.is_empty();
    VirtualDispatchSite {
        call_address,
        slot_index,
        possible_targets: targets,
        is_resolved,
    }
}

/// Build a mapping from vtable slot index to the set of overriding functions
/// across the whole hierarchy rooted at `root_class`.
#[must_use]
pub fn build_dispatch_table(
    root_class: &str,
    graph: &InheritanceGraph,
    db: &VtableDatabase,
) -> HashMap<usize, Vec<u64>> {
    let mut table: HashMap<usize, Vec<u64>> = HashMap::new();

    let mut classes_to_visit: Vec<String> = vec![root_class.to_owned()];
    classes_to_visit.extend(graph.descendants_of(root_class));

    for class_name in &classes_to_visit {
        if let Some(node) = graph.classes.get(class_name.as_str()) {
            for &vt_addr in &node.vtable_addresses {
                if let Some(vtable) = db.vtables.get(&vt_addr) {
                    // The slot IS the position in the entry list — which is how
                    // `resolve_virtual_dispatch` above reads it back
                    // (`vtable.entries.get(slot_index)`). Deriving it as
                    // `entry.offset / 8` hardcoded a 64-bit pointer, so on a
                    // 32-bit image (4-byte slots) adjacent methods collapsed
                    // onto the same slot and the table silently mixed unrelated
                    // overrides. Using the index is also pointer-size agnostic,
                    // rather than trading one hardcoded width for another.
                    for (slot, entry) in vtable.entries.iter().enumerate() {
                        let targets = table.entry(slot).or_default();
                        if !targets.contains(&entry.target_address) {
                            targets.push(entry.target_address);
                        }
                    }
                }
            }
        }
    }
    table
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a recovered C++ class hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyStats {
    /// Total classes recovered.
    pub total_classes: usize,
    /// Total vtables associated with classes.
    pub total_vtables: usize,
    /// Maximum inheritance depth.
    pub max_depth: usize,
    /// Number of root classes.
    pub root_count: usize,
    /// Number of leaf classes.
    pub leaf_count: usize,
    /// Number of classes with virtual functions.
    pub polymorphic_count: usize,
}

/// Compute statistics for an `InheritanceGraph`.
#[must_use]
pub fn compute_hierarchy_stats(graph: &InheritanceGraph) -> HierarchyStats {
    let total_classes = graph.class_count();
    let root_count = graph.roots().len();
    let leaf_count = graph.leaves().len();
    let total_vtables: usize = graph
        .classes
        .values()
        .map(|n| n.vtable_addresses.len())
        .sum();
    let polymorphic_count = graph
        .classes
        .values()
        .filter(|n| n.virtual_function_count > 0)
        .count();
    let max_depth = graph
        .classes
        .keys()
        .map(|n| graph.depth(n))
        .max()
        .unwrap_or(0);

    HierarchyStats {
        total_classes,
        total_vtables,
        max_depth,
        root_count,
        leaf_count,
        polymorphic_count,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RttiAbi, RttiInfo, Vtable, VtableDatabase, VtableEntry};

    fn make_rtti(name: &str, bases: &[&str]) -> RttiInfo {
        // Use a hash of the name as address to ensure uniqueness.
        let rtti_address = name
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(u64::from(b)));
        RttiInfo {
            type_name: name.to_owned(),
            base_classes: bases.iter().map(|s| (*s).to_owned()).collect(),
            rtti_address,
            abi: RttiAbi::Itanium,
        }
    }

    fn make_vtable(base_addr: u64, class_name: &str, targets: &[u64]) -> Vtable {
        let mut vt = Vtable::new(base_addr);
        vt.class_name = Some(class_name.to_owned());
        for (i, &t) in targets.iter().enumerate() {
            vt.add_entry(VtableEntry::new(i * 8, t));
        }
        vt
    }

    fn make_db() -> VtableDatabase {
        let mut db = VtableDatabase::new();
        db.add_rtti(make_rtti("Base", &[]));
        db.add_rtti(make_rtti("Derived", &["Base"]));
        db.add_rtti(make_rtti("LeafA", &["Derived"]));
        db.add_rtti(make_rtti("LeafB", &["Derived"]));

        let vt_base = make_vtable(0x4000, "Base", &[0x1000, 0x1010]);
        let vt_derived = make_vtable(0x4100, "Derived", &[0x2000, 0x2010]);
        let vt_leaf_a = make_vtable(0x4200, "LeafA", &[0x3000, 0x3010]);
        let vt_leaf_b = make_vtable(0x4300, "LeafB", &[0x4400, 0x4410]);
        db.add_vtable(vt_base);
        db.add_vtable(vt_derived);
        db.add_vtable(vt_leaf_a);
        db.add_vtable(vt_leaf_b);
        db
    }

    #[test]
    fn test_graph_from_database() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        assert!(graph.get("Base").is_some());
        assert!(graph.get("Derived").is_some());
        assert!(graph.get("LeafA").is_some());
    }

    #[test]
    fn test_graph_roots() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let roots = graph.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].name, "Base");
    }

    #[test]
    fn test_graph_leaves() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let mut leaves: Vec<&str> = graph.leaves().iter().map(|n| n.name.as_str()).collect();
        leaves.sort_unstable();
        assert!(leaves.contains(&"LeafA"));
        assert!(leaves.contains(&"LeafB"));
    }

    #[test]
    fn test_ancestors_of_leaf() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let ancestors = graph.ancestors_of("LeafA");
        assert!(ancestors.contains(&"Derived".to_owned()));
        assert!(ancestors.contains(&"Base".to_owned()));
    }

    #[test]
    fn test_ancestors_of_root() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        assert!(graph.ancestors_of("Base").is_empty());
    }

    #[test]
    fn test_descendants_of_root() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let desc = graph.descendants_of("Base");
        assert!(desc.contains(&"Derived".to_owned()));
        assert!(desc.contains(&"LeafA".to_owned()));
        assert!(desc.contains(&"LeafB".to_owned()));
    }

    #[test]
    fn test_is_a() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        assert!(graph.is_a("LeafA", "Base"));
        assert!(graph.is_a("Derived", "Base"));
        assert!(!graph.is_a("Base", "LeafA"));
        assert!(graph.is_a("Base", "Base")); // reflexive
    }

    #[test]
    fn test_depth() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        assert_eq!(graph.depth("Base"), 0);
        assert_eq!(graph.depth("Derived"), 1);
        assert_eq!(graph.depth("LeafA"), 2);
    }

    #[test]
    fn test_bfs_from() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let bfs = graph.bfs_from("Base");
        assert!(!bfs.is_empty());
        assert_eq!(bfs[0].name, "Base");
    }

    #[test]
    fn test_resolve_virtual_dispatch() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let site = resolve_virtual_dispatch(0xABCD, "Base", 0, &graph, &db);
        assert!(site.is_resolved);
        // Targets should include Base::vf[0], Derived::vf[0], LeafA::vf[0], LeafB::vf[0]
        assert!(site.possible_targets.len() >= 2);
    }

    #[test]
    fn test_resolve_virtual_dispatch_leaf() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let site = resolve_virtual_dispatch(0xBEEF, "LeafA", 1, &graph, &db);
        assert!(site.is_resolved);
        assert!(site.possible_targets.contains(&0x3010));
    }

    #[test]
    fn test_build_dispatch_table() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let table = build_dispatch_table("Base", &graph, &db);
        assert!(!table.is_empty());
        assert!(table.contains_key(&0)); // slot 0
        assert!(table.contains_key(&1)); // slot 1
    }

    #[test]
    fn test_hierarchy_stats() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let stats = compute_hierarchy_stats(&graph);
        assert_eq!(stats.total_classes, 4);
        assert_eq!(stats.root_count, 1);
        assert_eq!(stats.leaf_count, 2);
        assert!(stats.max_depth >= 2);
        assert!(stats.polymorphic_count > 0);
    }

    #[test]
    fn test_ancestors_descendants_sorted_deterministic() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let a1 = graph.ancestors_of("LeafA");
        let d1 = graph.descendants_of("Base");
        let mut a_sorted = a1.clone();
        a_sorted.sort_unstable();
        assert_eq!(a1, a_sorted, "ancestors_of must be sorted");
        let mut d_sorted = d1.clone();
        d_sorted.sort_unstable();
        assert_eq!(d1, d_sorted, "descendants_of must be sorted");
        for _ in 0..5 {
            assert_eq!(graph.ancestors_of("LeafA"), a1);
            assert_eq!(graph.descendants_of("Base"), d1);
        }
    }

    #[test]
    fn test_depth_deep_chain_no_stack_overflow() {
        // Regression: recursive longest-path overflowed the stack on deep
        // chains; the iterative version must handle 50k levels.
        let mut db = VtableDatabase::new();
        db.add_rtti(make_rtti("C0", &[]));
        for i in 1..50_000usize {
            let child = format!("C{i}");
            let parent = format!("C{}", i - 1);
            db.add_rtti(RttiInfo {
                type_name: child,
                base_classes: vec![parent],
                rtti_address: 0x1_0000 + i as u64,
                abi: RttiAbi::Itanium,
            });
        }
        let graph = InheritanceGraph::from_database(&db);
        assert_eq!(graph.depth("C49999"), 49_999);
    }

    #[test]
    fn test_depth_cycle_terminates() {
        let mut db = VtableDatabase::new();
        db.add_rtti(RttiInfo {
            type_name: "A".into(),
            base_classes: vec!["B".into()],
            rtti_address: 1,
            abi: RttiAbi::Itanium,
        });
        db.add_rtti(RttiInfo {
            type_name: "B".into(),
            base_classes: vec!["A".into()],
            rtti_address: 2,
            abi: RttiAbi::Itanium,
        });
        let graph = InheritanceGraph::from_database(&db);
        let _ = graph.depth("A"); // must terminate without panic
        let _ = compute_hierarchy_stats(&graph);
    }

    #[test]
    fn test_diamond_depth_efficient() {
        // Layered diamond DAG: memoized depth must finish quickly (the old
        // recursion was exponential in layer count).
        let mut db = VtableDatabase::new();
        db.add_rtti(make_rtti("L0a", &[]));
        db.add_rtti(make_rtti("L0b", &[]));
        for i in 1..40usize {
            let pa = format!("L{}a", i - 1);
            let pb = format!("L{}b", i - 1);
            db.add_rtti(make_rtti(&format!("L{i}a"), &[&pa, &pb]));
            db.add_rtti(make_rtti(&format!("L{i}b"), &[&pa, &pb]));
        }
        let graph = InheritanceGraph::from_database(&db);
        assert_eq!(graph.depth("L39a"), 39);
    }

    #[test]
    fn test_resolve_dispatch_targets_deterministic() {
        let db = make_db();
        let graph = InheritanceGraph::from_database(&db);
        let t1 = resolve_virtual_dispatch(0x1, "Base", 0, &graph, &db).possible_targets;
        for _ in 0..5 {
            let t2 = resolve_virtual_dispatch(0x1, "Base", 0, &graph, &db).possible_targets;
            assert_eq!(t1, t2);
        }
    }

    #[test]
    fn test_class_node_is_root_leaf() {
        let mut node = ClassNode::new("Foo");
        assert!(node.is_root());
        assert!(node.is_leaf());
        node.bases.push("Bar".to_owned());
        assert!(!node.is_root());
    }
}
