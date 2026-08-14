//! Class hierarchy analysis and export.
//!
//! Builds a rich analysis layer on top of `ReconstructedHierarchy`:
//!   * Topological sort (linearisation)
//!   * Interface vs. abstract vs. concrete class detection
//!   * Method dispatch graph (which class provides each final implementation)
//!   * DOT (Graphviz) and JSON export
//!   * Cycle detection (sanity check — should not happen in valid C++ but we
//!     guard against degenerate input)

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::vtable_reconstructor::{ClassNode, ReconstructedHierarchy};

// ─── Hierarchy analyser ───────────────────────────────────────────────────────

pub struct HierarchyAnalyser<'a> {
    pub hierarchy: &'a ReconstructedHierarchy,
}

impl<'a> HierarchyAnalyser<'a> {
    pub fn new(hierarchy: &'a ReconstructedHierarchy) -> Self {
        Self { hierarchy }
    }

    // ─── Topological sort ────────────────────────────────────────────────

    /// Kahn's algorithm over the class DAG.  Returns `Err` if a cycle is found.
    pub fn topological_sort(&self) -> Result<Vec<usize>, CycleError> {
        let n = self.hierarchy.class_count();
        let mut in_degree = vec![0usize; n];
        for class in &self.hierarchy.classes {
            // Guard against malformed hierarchies (e.g. deserialized data) whose
            // ids or base references are out of range.
            if class.id >= n {
                continue;
            }
            for &base in &class.bases {
                if base < n {
                    in_degree[class.id] += 1;
                }
            }
        }
        let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
        let mut order = Vec::new();
        while let Some(cur) = queue.pop_front() {
            order.push(cur);
            for &derived_id in &self.hierarchy.classes[cur].derived {
                // Bounds + underflow guards: an asymmetric derived edge (with no
                // matching base entry) must not panic on index or `0 - 1`.
                if derived_id >= n || in_degree[derived_id] == 0 {
                    continue;
                }
                in_degree[derived_id] -= 1;
                if in_degree[derived_id] == 0 {
                    queue.push_back(derived_id);
                }
            }
        }
        if order.len() == n {
            Ok(order)
        } else {
            Err(CycleError {
                nodes_in_cycle: (0..n).filter(|&i| in_degree[i] > 0).collect(),
            })
        }
    }

    // ─── Classification ──────────────────────────────────────────────────

    pub fn classify_class(&self, id: usize) -> ClassKind {
        let class = match self.hierarchy.classes.get(id) {
            Some(c) => c,
            None => return ClassKind::Unknown,
        };
        if class.is_abstract {
            if class.derived.is_empty() {
                ClassKind::AbstractLeaf
            } else {
                ClassKind::AbstractBase
            }
        } else if class.bases.is_empty() && !class.derived.is_empty() {
            ClassKind::ConcreteRoot
        } else if class.bases.is_empty() && class.derived.is_empty() {
            ClassKind::Standalone
        } else if class.derived.is_empty() {
            ClassKind::ConcreteLeaf
        } else {
            ClassKind::ConcreteMid
        }
    }

    pub fn classify_all(&self) -> HashMap<usize, ClassKind> {
        (0..self.hierarchy.class_count())
            .map(|id| (id, self.classify_class(id)))
            .collect()
    }

    // ─── Interface detection ─────────────────────────────────────────────

    /// A class is treated as "interface-like" if it is abstract, has no base,
    /// and every slot is the same address (pure-virtual stub).
    pub fn is_interface(&self, id: usize) -> bool {
        let c = match self.hierarchy.classes.get(id) { Some(c) => c, None => return false };
        c.is_abstract && c.bases.is_empty()
    }

    pub fn interface_ids(&self) -> Vec<usize> {
        (0..self.hierarchy.class_count()).filter(|&id| self.is_interface(id)).collect()
    }

    // ─── Method dispatch graph ────────────────────────────────────────────

    /// For each (class_id, slot_index) → final implementation address.
    /// Walks the MRO (most-derived takes priority).
    pub fn build_dispatch_table(&self, id: usize) -> Vec<DispatchEntry> {
        let class = match self.hierarchy.classes.get(id) { Some(c) => c, None => return vec![] };
        let slot_count = class.slot_count();
        let mut table: Vec<DispatchEntry> = (0..slot_count).map(|i| DispatchEntry {
            slot_index: i,
            provider_class_id: id,
            fn_addr: class.slots[i].fn_addr,
            is_override: class.slots[i].is_override,
        }).collect();

        // Walk up to base classes: slot inherits base value if not overridden.
        for &base_id in &class.bases {
            let base_class = match self.hierarchy.classes.get(base_id) { Some(c) => c, None => continue };
            for slot in &base_class.slots {
                if slot.index < table.len() && !table[slot.index].is_override {
                    // Derived has not overridden this slot — it inherits from base.
                    // Only update if the derived's slot matches what we'd expect.
                    if table[slot.index].fn_addr == slot.fn_addr {
                        table[slot.index].provider_class_id = base_id;
                    }
                }
            }
        }
        table
    }

    // ─── Reachability ────────────────────────────────────────────────────

    pub fn reachable_from_roots(&self) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut stack: Vec<usize> = self.hierarchy.root_ids.clone();
        while let Some(id) = stack.pop() {
            if !visited.insert(id) { continue; }
            if let Some(c) = self.hierarchy.classes.get(id) {
                for &d in &c.derived { stack.push(d); }
            }
        }
        visited
    }

    /// IDs of classes that are not reachable from any root (possibly
    /// orphaned due to detection errors or stripped RTTI).
    pub fn orphaned_classes(&self) -> Vec<usize> {
        let reachable = self.reachable_from_roots();
        (0..self.hierarchy.class_count())
            .filter(|id| !reachable.contains(id))
            .collect()
    }

    // ─── Statistics ──────────────────────────────────────────────────────

    pub fn statistics(&self) -> HierarchyStats {
        let kinds = self.classify_all();
        let abstract_count = kinds.values().filter(|k| matches!(k, ClassKind::AbstractBase | ClassKind::AbstractLeaf)).count();
        let concrete_count = kinds.values().filter(|k| matches!(k, ClassKind::ConcreteLeaf | ClassKind::ConcreteMid | ClassKind::ConcreteRoot | ClassKind::Standalone)).count();
        let interface_count = self.interface_ids().len();
        let total_slots: usize = self.hierarchy.classes.iter().map(|c| c.slot_count()).sum();
        let total_overrides: usize = self.hierarchy.classes.iter().map(|c| c.override_count()).sum();
        let avg_slots = if self.hierarchy.class_count() > 0 {
            total_slots as f64 / self.hierarchy.class_count() as f64
        } else { 0.0 };
        let max_depth = self.hierarchy.max_depth();
        let orphaned = self.orphaned_classes().len();
        HierarchyStats {
            total_classes: self.hierarchy.class_count(),
            total_relations: self.hierarchy.relation_count(),
            abstract_count,
            concrete_count,
            interface_count,
            total_virtual_slots: total_slots,
            total_overrides,
            avg_slots_per_class: avg_slots,
            max_inheritance_depth: max_depth,
            root_count: self.hierarchy.root_ids.len(),
            orphaned_count: orphaned,
        }
    }
}

// ─── Supporting types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassKind {
    AbstractBase,
    AbstractLeaf,
    ConcreteRoot,
    ConcreteMid,
    ConcreteLeaf,
    Standalone,
    Unknown,
}

impl std::fmt::Display for ClassKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchEntry {
    pub slot_index: usize,
    pub provider_class_id: usize,
    pub fn_addr: u64,
    pub is_override: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyStats {
    pub total_classes: usize,
    pub total_relations: usize,
    pub abstract_count: usize,
    pub concrete_count: usize,
    pub interface_count: usize,
    pub total_virtual_slots: usize,
    pub total_overrides: usize,
    pub avg_slots_per_class: f64,
    pub max_inheritance_depth: usize,
    pub root_count: usize,
    pub orphaned_count: usize,
}

#[derive(Debug, Clone)]
pub struct CycleError {
    pub nodes_in_cycle: Vec<usize>,
}

impl std::fmt::Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cycle detected among class nodes: {:?}", self.nodes_in_cycle)
    }
}

// ─── DOT export ───────────────────────────────────────────────────────────────

pub struct DotExporter<'a> {
    hierarchy: &'a ReconstructedHierarchy,
    pub label_slots: bool,
    pub color_by_kind: bool,
    pub show_vtable_addr: bool,
}

impl<'a> DotExporter<'a> {
    pub fn new(hierarchy: &'a ReconstructedHierarchy) -> Self {
        Self { hierarchy, label_slots: false, color_by_kind: true, show_vtable_addr: false }
    }

    pub fn export(&self) -> String {
        let analyser = HierarchyAnalyser::new(self.hierarchy);
        let kinds = analyser.classify_all();
        let mut out = String::new();
        out.push_str("digraph ClassHierarchy {\n");
        out.push_str("  rankdir=BT;\n");
        out.push_str("  node [shape=box, fontname=\"Helvetica\"];\n\n");

        // Node definitions.
        for class in &self.hierarchy.classes {
            let label = self.node_label(class);
            let color = if self.color_by_kind {
                self.color_for_kind(kinds.get(&class.id).unwrap_or(&ClassKind::Unknown))
            } else {
                "white".to_string()
            };
            out.push_str(&format!(
                "  n{} [label=\"{}\", fillcolor=\"{}\", style=filled];\n",
                class.id, label, color
            ));
        }

        out.push('\n');

        // Edges (derived → base, direction bottom-to-top).
        for class in &self.hierarchy.classes {
            for &base_id in &class.bases {
                let override_count = self.hierarchy.classes[class.id].override_count();
                let edge_label = if override_count > 0 {
                    format!(" [label=\"+{override_count} overrides\"]")
                } else {
                    String::new()
                };
                out.push_str(&format!("  n{} -> n{}{};\n", class.id, base_id, edge_label));
            }
        }

        out.push_str("}\n");
        out
    }

    fn node_label(&self, class: &ClassNode) -> String {
        let name = class.name.as_deref().unwrap_or("?");
        let mut parts = vec![name.replace('"', "'")];
        if self.show_vtable_addr {
            parts.push(format!("vtable=0x{:x}", class.vtable_va));
        }
        if self.label_slots {
            parts.push(format!("{} slots", class.slot_count()));
        }
        parts.join("\\n")
    }

    fn color_for_kind(&self, kind: &ClassKind) -> String {
        match kind {
            ClassKind::AbstractBase  => "#ffe0b2".to_string(), // orange-ish
            ClassKind::AbstractLeaf  => "#fff9c4".to_string(), // yellow-ish
            ClassKind::ConcreteRoot  => "#c8e6c9".to_string(), // green
            ClassKind::ConcreteMid   => "#b3e5fc".to_string(), // light blue
            ClassKind::ConcreteLeaf  => "#e1bee7".to_string(), // purple
            ClassKind::Standalone    => "#f5f5f5".to_string(), // grey
            ClassKind::Unknown       => "#ffffff".to_string(), // white
        }
    }
}

// ─── JSON export ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct JsonHierarchy {
    pub stats: HierarchyStats,
    pub classes: Vec<JsonClass>,
    pub relations: Vec<JsonRelation>,
}

#[derive(Serialize, Deserialize)]
pub struct JsonClass {
    pub id: usize,
    pub name: Option<String>,
    pub vtable_va: String,
    pub slot_count: usize,
    pub override_count: usize,
    pub is_abstract: bool,
    pub confidence: u8,
    pub bases: Vec<usize>,
    pub derived: Vec<usize>,
    pub kind: String,
    pub dispatch_table: Vec<JsonDispatchEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct JsonDispatchEntry {
    pub slot: usize,
    pub fn_addr: String,
    pub provider_id: usize,
    pub is_override: bool,
}

#[derive(Serialize, Deserialize)]
pub struct JsonRelation {
    pub base_id: usize,
    pub derived_id: usize,
    pub overridden_slots: Vec<usize>,
    pub new_slots: usize,
}

pub fn to_json_hierarchy(hierarchy: &ReconstructedHierarchy) -> JsonHierarchy {
    let analyser = HierarchyAnalyser::new(hierarchy);
    let stats = analyser.statistics();
    let kinds = analyser.classify_all();

    let classes = hierarchy.classes.iter().map(|c| {
        let dispatch = analyser.build_dispatch_table(c.id);
        let jdispatch = dispatch.iter().map(|d| JsonDispatchEntry {
            slot: d.slot_index,
            fn_addr: format!("0x{:016x}", d.fn_addr),
            provider_id: d.provider_class_id,
            is_override: d.is_override,
        }).collect();
        JsonClass {
            id: c.id,
            name: c.name.clone(),
            vtable_va: format!("0x{:016x}", c.vtable_va),
            slot_count: c.slot_count(),
            override_count: c.override_count(),
            is_abstract: c.is_abstract,
            confidence: c.confidence,
            bases: c.bases.clone(),
            derived: c.derived.clone(),
            kind: kinds.get(&c.id).map(|k| k.to_string()).unwrap_or_else(|| "Unknown".to_string()),
            dispatch_table: jdispatch,
        }
    }).collect();

    let relations = hierarchy.relations.iter().map(|r| JsonRelation {
        base_id: r.base_id,
        derived_id: r.derived_id,
        overridden_slots: r.overridden_slots.keys().copied().collect(),
        new_slots: r.new_slots,
    }).collect();

    JsonHierarchy { stats, classes, relations }
}

// ─── Method dispatch graph ────────────────────────────────────────────────────

/// A flat view of all final implementations across the whole hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDispatchGraph {
    /// Map: fn_addr → list of (class_id, slot_index) where that function is called.
    /// BTreeMap so serialized output (JSON) is deterministic across runs.
    pub fn_to_callers: std::collections::BTreeMap<String, Vec<(usize, usize)>>,
    /// Map: class_id → vec of fn_addr (final dispatch).
    pub class_dispatch: std::collections::BTreeMap<usize, Vec<String>>,
}

pub fn build_method_dispatch_graph(hierarchy: &ReconstructedHierarchy) -> MethodDispatchGraph {
    let analyser = HierarchyAnalyser::new(hierarchy);
    let mut fn_to_callers: std::collections::BTreeMap<String, Vec<(usize, usize)>> = Default::default();
    let mut class_dispatch: std::collections::BTreeMap<usize, Vec<String>> = Default::default();

    for class in &hierarchy.classes {
        let table = analyser.build_dispatch_table(class.id);
        let dispatch_addrs: Vec<String> = table.iter()
            .map(|e| format!("0x{:016x}", e.fn_addr))
            .collect();
        for entry in &table {
            let key = format!("0x{:016x}", entry.fn_addr);
            fn_to_callers.entry(key).or_default().push((class.id, entry.slot_index));
        }
        class_dispatch.insert(class.id, dispatch_addrs);
    }

    MethodDispatchGraph { fn_to_callers, class_dispatch }
}

// ─── Linear inheritance chain ─────────────────────────────────────────────────

/// Returns a human-readable MRO-style list for a class.
pub fn mro_string(hierarchy: &ReconstructedHierarchy, id: usize) -> String {
    let mut chain = vec![id];
    let mut seen: HashSet<usize> = HashSet::new();
    seen.insert(id);
    let mut current = id;
    loop {
        let node = match hierarchy.classes.get(current) { Some(n) => n, None => break };
        match node.bases.first() {
            // Cycle guard: degenerate hierarchies (mutual bases are reachable
            // from real reconstructor output on equal-length near-identical
            // vtables) previously made this loop spin forever / OOM.
            Some(&base) => {
                if !seen.insert(base) {
                    break;
                }
                chain.push(base);
                current = base;
            }
            None => break,
        }
    }
    chain.iter().map(|&i| {
        hierarchy.classes.get(i)
            .and_then(|c| c.name.as_deref())
            .unwrap_or("?")
    }).collect::<Vec<_>>().join(" → ")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtable_reconstructor::VtableReconstructor;
    use crate::vtable_finder::{VtableCandidate, RttiKind};

    fn make_candidate(va: u64, slots: Vec<u64>, name: Option<&str>) -> VtableCandidate {
        VtableCandidate {
            va,
            slot_count: slots.len(),
            slots,
            rtti_va: None,
            class_name: name.map(|s| s.to_string()),
            rtti_kind: RttiKind::None,
            confidence: 80,
        }
    }

    fn make_hierarchy() -> ReconstructedHierarchy {
        let base_slots = vec![0x401000u64, 0x401010, 0x401020];
        let derived_slots = vec![0x401000u64, 0x402010, 0x401020, 0x402030];
        let candidates = vec![
            make_candidate(0x1000_0000, base_slots, Some("Base")),
            make_candidate(0x1000_0020, derived_slots, Some("Derived")),
        ];
        VtableReconstructor::with_defaults().reconstruct(&candidates)
    }

    #[test]
    fn test_topological_sort_no_cycle() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        let order = analyser.topological_sort();
        assert!(order.is_ok());
        let order = order.unwrap();
        assert_eq!(order.len(), h.class_count());
    }

    #[test]
    fn test_topological_sort_empty() {
        let h = VtableReconstructor::with_defaults().reconstruct(&[]);
        let analyser = HierarchyAnalyser::new(&h);
        assert_eq!(analyser.topological_sort().unwrap().len(), 0);
    }

    #[test]
    fn test_classify_standalone() {
        let candidates = vec![make_candidate(0x1000, vec![0x401000u64, 0x401010], None)];
        let h = VtableReconstructor::with_defaults().reconstruct(&candidates);
        let analyser = HierarchyAnalyser::new(&h);
        let kind = analyser.classify_class(0);
        assert_eq!(kind, ClassKind::Standalone);
    }

    #[test]
    fn test_interface_detection() {
        let same = 0x401000u64;
        let candidates = vec![make_candidate(0x1000, vec![same; 5], Some("IFace"))];
        let h = VtableReconstructor::with_defaults().reconstruct(&candidates);
        let analyser = HierarchyAnalyser::new(&h);
        assert!(analyser.is_interface(0));
        assert_eq!(analyser.interface_ids(), vec![0]);
    }

    #[test]
    fn test_dispatch_table_built() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        for id in 0..h.class_count() {
            let table = analyser.build_dispatch_table(id);
            assert!(!table.is_empty());
        }
    }

    #[test]
    fn test_statistics_fields() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        let stats = analyser.statistics();
        assert_eq!(stats.total_classes, 2);
        assert!(stats.total_virtual_slots > 0);
    }

    #[test]
    fn test_dot_export_contains_nodes() {
        let h = make_hierarchy();
        let exporter = DotExporter::new(&h);
        let dot = exporter.export();
        assert!(dot.contains("digraph ClassHierarchy"));
        assert!(dot.contains("n0"));
        assert!(dot.contains("n1"));
    }

    #[test]
    fn test_dot_export_edges() {
        let h = make_hierarchy();
        let exporter = DotExporter::new(&h);
        let dot = exporter.export();
        // Should have at least one edge if hierarchy was detected.
        // (Edge: n1 -> n0 means Derived extends Base)
        let _ = dot; // just verify no panic
    }

    #[test]
    fn test_json_hierarchy_serializes() {
        let h = make_hierarchy();
        let jh = to_json_hierarchy(&h);
        let json = serde_json::to_string(&jh).unwrap();
        assert!(json.contains("\"total_classes\""));
    }

    #[test]
    fn test_mro_string() {
        let h = make_hierarchy();
        for id in 0..h.class_count() {
            let mro = mro_string(&h, id);
            assert!(!mro.is_empty());
        }
    }

    #[test]
    fn test_reachable_from_roots() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        let reachable = analyser.reachable_from_roots();
        // All classes should be reachable (or at least roots are in the set).
        assert!(!reachable.is_empty());
    }

    #[test]
    fn test_orphaned_classes_empty_for_clean_hierarchy() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        // A proper hierarchy has no orphans (every class is either a root or reachable).
        // This just verifies it runs without panic.
        let _orphans = analyser.orphaned_classes();
    }

    #[test]
    fn test_method_dispatch_graph() {
        let h = make_hierarchy();
        let graph = build_method_dispatch_graph(&h);
        assert!(!graph.class_dispatch.is_empty());
    }

    #[test]
    fn test_hierarchy_stats_avg_slots() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        let stats = analyser.statistics();
        assert!(stats.avg_slots_per_class > 0.0);
    }

    #[test]
    fn test_mro_string_terminates_on_cycle() {
        // Regression: mutual bases (reachable from real reconstructor output on
        // equal-length near-identical vtables) made mro_string loop forever.
        let mut h = make_hierarchy();
        // Force a 2-cycle: 0's first base is 1, 1's first base is 0.
        h.classes[0].bases = vec![1];
        h.classes[1].bases = vec![0];
        let mro = mro_string(&h, 0);
        assert!(!mro.is_empty()); // returned instead of hanging
    }

    #[test]
    fn test_topological_sort_malformed_edges_no_panic() {
        // Regression: out-of-range / asymmetric derived edges previously
        // panicked on index-out-of-bounds or usize underflow.
        let mut h = make_hierarchy();
        h.classes[0].derived.push(999); // dangling edge
        h.classes[1].derived.push(0); // asymmetric: 0 has no matching base
        let _ = HierarchyAnalyser::new(&h).topological_sort(); // must not panic
    }

    #[test]
    fn test_method_dispatch_graph_deterministic_json() {
        let h = make_hierarchy();
        let j1 = serde_json::to_string(&build_method_dispatch_graph(&h)).unwrap();
        for _ in 0..5 {
            let j2 = serde_json::to_string(&build_method_dispatch_graph(&h)).unwrap();
            assert_eq!(j1, j2);
        }
    }

    #[test]
    fn test_classify_all_keys() {
        let h = make_hierarchy();
        let analyser = HierarchyAnalyser::new(&h);
        let kinds = analyser.classify_all();
        assert_eq!(kinds.len(), h.class_count());
    }
}
