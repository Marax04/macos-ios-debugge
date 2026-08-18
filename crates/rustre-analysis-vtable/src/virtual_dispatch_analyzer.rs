//! `virtual_dispatch_analyzer` — Analyze virtual dispatch sites in binary code.
//!
//! Identifies indirect call instructions that load function pointers from vtable
//! offsets, matches dispatch sites to vtable entries recovered by the vtable
//! finder, computes type hierarchy relationships from vtable sharing, and
//! detects potential type-confusion vulnerabilities.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ─── DispatchSite ─────────────────────────────────────────────────────────────

/// The kind of virtual dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchKind {
    /// Standard virtual call via vtable: `call [rcx + offset]`.
    StandardVcall,
    /// Interface dispatch: indirect through an interface vtable sub-object.
    InterfaceDispatch,
    /// Double-dispatch (e.g., visitor pattern two-level vtable).
    DoubleDispatch,
    /// Tail call optimized virtual call.
    TailCallVcall,
    /// Unknown / unclassified indirect call.
    Unknown,
}

impl fmt::Display for DispatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandardVcall => write!(f, "vcall"),
            Self::InterfaceDispatch => write!(f, "interface"),
            Self::DoubleDispatch => write!(f, "double-dispatch"),
            Self::TailCallVcall => write!(f, "tail-vcall"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single virtual dispatch site in the binary.
#[derive(Debug, Clone)]
pub struct DispatchSite {
    /// Address of the indirect call/jump instruction.
    pub call_va: u64,
    /// The object register (e.g., register index 1 = RCX on Windows x64).
    pub object_reg: u8,
    /// Byte offset into the vtable (slot index × `pointer_size`).
    pub vtable_offset: u32,
    /// Inferred vtable virtual address, if resolved.
    pub resolved_vtable_va: Option<u64>,
    /// Resolved function virtual address (the callee), if known.
    pub resolved_callee_va: Option<u64>,
    /// Class name of the receiver, if inferred.
    pub receiver_class: Option<String>,
    /// Slot index (`vtable_offset` / `pointer_size`).
    pub slot_index: u32,
    /// Kind of dispatch.
    pub kind: DispatchKind,
    /// Enclosing function virtual address.
    pub function_va: u64,
    /// Whether the dispatch was fully resolved.
    pub resolved: bool,
}

impl DispatchSite {
    /// Create an unresolved dispatch site.
    #[must_use]
    pub const fn new(call_va: u64, vtable_offset: u32, ptr_size: u32) -> Self {
        Self {
            call_va,
            object_reg: 0,
            vtable_offset,
            resolved_vtable_va: None,
            resolved_callee_va: None,
            receiver_class: None,
            // Guard against a zero pointer size (caller-controlled) — a bare
            // division would panic.
            slot_index: if ptr_size == 0 { 0 } else { vtable_offset / ptr_size },
            kind: DispatchKind::Unknown,
            function_va: 0,
            resolved: false,
        }
    }

    /// Mark the dispatch site as resolved with the given vtable and callee.
    pub const fn resolve(&mut self, vtable_va: u64, callee_va: u64) {
        self.resolved_vtable_va = Some(vtable_va);
        self.resolved_callee_va = Some(callee_va);
        self.resolved = true;
    }
}

impl fmt::Display for DispatchSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DispatchSite {{ va={:#x}, slot={}, kind={}, resolved={} }}",
            self.call_va, self.slot_index, self.kind, self.resolved
        )
    }
}

// ─── VtableLoad ───────────────────────────────────────────────────────────────

/// A vtable load instruction: `mov reg, [object_reg + offset_to_vtable]`.
#[derive(Debug, Clone)]
pub struct VtableLoad {
    /// Address of the load instruction.
    pub load_va: u64,
    /// Register used as the object pointer (source).
    pub object_reg: u8,
    /// Register receiving the vtable pointer (destination).
    pub vtable_reg: u8,
    /// Byte offset of the vtable pointer within the object (usually 0).
    pub object_offset: i32,
    /// Enclosing function virtual address.
    pub function_va: u64,
}

impl VtableLoad {
    /// Create a new vtable load record.
    #[must_use]
    pub const fn new(
        load_va: u64,
        object_reg: u8,
        vtable_reg: u8,
        object_offset: i32,
        function_va: u64,
    ) -> Self {
        Self {
            load_va,
            object_reg,
            vtable_reg,
            object_offset,
            function_va,
        }
    }

    /// Return `true` if this load targets the primary vtable pointer (offset 0).
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.object_offset == 0
    }
}

// ─── TypeHierarchyNode ────────────────────────────────────────────────────────

/// A node in the inferred class hierarchy graph.
#[derive(Debug, Clone)]
pub struct TypeHierarchyNode {
    /// Class name (from RTTI or synthesized from vtable address).
    pub class_name: String,
    /// Vtable virtual address for the primary sub-object.
    pub vtable_va: u64,
    /// Names of direct parent classes.
    pub parents: Vec<String>,
    /// Names of direct child classes (derived from this class).
    pub children: Vec<String>,
    /// Number of virtual methods.
    pub method_count: usize,
    /// Whether this class is believed to be abstract.
    pub is_abstract: bool,
    /// Depth from the root in the hierarchy (root = 0).
    pub depth: usize,
}

impl TypeHierarchyNode {
    /// Create a new node.
    #[must_use]
    pub fn new(class_name: impl Into<String>, vtable_va: u64, method_count: usize) -> Self {
        Self {
            class_name: class_name.into(),
            vtable_va,
            parents: Vec::new(),
            children: Vec::new(),
            method_count,
            is_abstract: false,
            depth: 0,
        }
    }
}

// ─── TypeHierarchy ────────────────────────────────────────────────────────────

/// Inferred C++ type hierarchy from vtable analysis.
#[derive(Debug, Default)]
pub struct TypeHierarchy {
    /// Map from class name to hierarchy node.
    pub nodes: HashMap<String, TypeHierarchyNode>,
    /// Root classes (no known parents).
    pub roots: Vec<String>,
}

impl TypeHierarchy {
    /// Create an empty hierarchy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a class node.
    pub fn add_class(&mut self, node: TypeHierarchyNode) {
        let name = node.class_name.clone();
        self.nodes.insert(name.clone(), node);
    }

    /// Register a parent-child relationship.
    ///
    /// Creates placeholder nodes if either class is not yet registered.
    pub fn add_edge(&mut self, parent: &str, child: &str) {
        self.nodes
            .entry(parent.to_string())
            .or_insert_with(|| TypeHierarchyNode::new(parent, 0, 0))
            .children
            .push(child.to_string());

        self.nodes
            .entry(child.to_string())
            .or_insert_with(|| TypeHierarchyNode::new(child, 0, 0))
            .parents
            .push(parent.to_string());
    }

    /// Recompute depth for all nodes via BFS from roots.
    pub fn compute_depths(&mut self) {
        // Find roots: nodes with no parents (sorted for determinism —
        // HashMap iteration order must not leak into output).
        let mut roots: Vec<String> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.parents.is_empty())
            .map(|(k, _)| k.clone())
            .collect();
        roots.sort_unstable();

        self.roots = roots.clone();

        // BFS with a visited set: guarantees termination on cyclic (corrupt)
        // hierarchies and avoids exponential re-enqueueing on diamonds.
        // Each node gets its minimum depth from any root.
        let mut visited: HashSet<String> = roots.iter().cloned().collect();
        let mut queue: VecDeque<(String, usize)> =
            roots.iter().map(|r| (r.clone(), 0)).collect();
        while let Some((name, depth)) = queue.pop_front() {
            if let Some(node) = self.nodes.get_mut(&name) {
                node.depth = depth;
                let children = node.children.clone();
                for child in children {
                    if visited.insert(child.clone()) {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
        }
    }

    /// Return all class names in BFS order from roots.
    #[must_use]
    pub fn bfs_order(&self) -> Vec<String> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<String> = self.roots.iter().cloned().collect();
        while let Some(name) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            order.push(name.clone());
            if let Some(node) = self.nodes.get(&name) {
                for child in &node.children {
                    queue.push_back(child.clone());
                }
            }
        }
        order
    }

    /// Return the number of classes in the hierarchy.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.nodes.len()
    }

    /// Find all classes that inherit (transitively) from `base_class`.
    #[must_use]
    pub fn all_derived(&self, base_class: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(base_class.to_string());
        while let Some(name) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            if name != base_class {
                result.push(name.clone());
            }
            if let Some(node) = self.nodes.get(&name) {
                for child in &node.children {
                    queue.push_back(child.clone());
                }
            }
        }
        result
    }
}

// ─── TypeConfusionRisk ────────────────────────────────────────────────────────

/// Severity of a detected type-confusion risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational — low risk.
    Info,
    /// Warning — moderate risk.
    Warning,
    /// Critical — high risk, likely exploitable.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A potential type-confusion vulnerability detected via vtable analysis.
#[derive(Debug, Clone)]
pub struct TypeConfusionRisk {
    /// Address of the dispatch site that may be confused.
    pub dispatch_va: u64,
    /// Expected class name at the dispatch site.
    pub expected_class: String,
    /// Conflicting class names that could be substituted.
    pub confused_with: Vec<String>,
    /// Severity assessment.
    pub severity: Severity,
    /// Human-readable description.
    pub description: String,
    /// The slot index that is affected.
    pub affected_slot: u32,
}

impl TypeConfusionRisk {
    /// Create a new type confusion risk record.
    #[must_use]
    pub fn new(
        dispatch_va: u64,
        expected_class: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            dispatch_va,
            expected_class: expected_class.into(),
            confused_with: Vec::new(),
            severity,
            description: description.into(),
            affected_slot: 0,
        }
    }
}

impl fmt::Display for TypeConfusionRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TypeConfusion {{ va={:#x}, class={}, severity={} }}",
            self.dispatch_va, self.expected_class, self.severity
        )
    }
}

// ─── DispatchAnalysis ─────────────────────────────────────────────────────────

/// Complete analysis results for virtual dispatch in a binary.
#[derive(Debug, Default)]
pub struct DispatchAnalysis {
    /// All identified dispatch sites.
    pub sites: Vec<DispatchSite>,
    /// Vtable loads paired with dispatch sites.
    pub loads: Vec<VtableLoad>,
    /// Inferred type hierarchy.
    pub hierarchy: TypeHierarchy,
    /// Detected type-confusion risks.
    pub risks: Vec<TypeConfusionRisk>,
    /// Number of resolved dispatch sites.
    pub resolved_count: usize,
    /// Number of unresolved dispatch sites.
    pub unresolved_count: usize,
}

impl DispatchAnalysis {
    /// Create a new empty analysis result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dispatch site and update counters.
    pub fn add_site(&mut self, site: DispatchSite) {
        if site.resolved {
            self.resolved_count += 1;
        } else {
            self.unresolved_count += 1;
        }
        self.sites.push(site);
    }

    /// Return the resolution rate as a fraction (0.0–1.0).
    #[must_use]
    pub fn resolution_rate(&self) -> f64 {
        let total = self.resolved_count + self.unresolved_count;
        if total == 0 {
            0.0
        } else {
            self.resolved_count as f64 / total as f64
        }
    }

    /// Return all critical risks.
    #[must_use]
    pub fn critical_risks(&self) -> Vec<&TypeConfusionRisk> {
        self.risks
            .iter()
            .filter(|r| r.severity == Severity::Critical)
            .collect()
    }

    /// Return all dispatch sites for a given function.
    #[must_use]
    pub fn sites_in_function(&self, function_va: u64) -> Vec<&DispatchSite> {
        self.sites
            .iter()
            .filter(|s| s.function_va == function_va)
            .collect()
    }

    /// Return all resolved callees (deduplicated).
    #[must_use]
    pub fn resolved_callees(&self) -> Vec<u64> {
        let mut callees: HashSet<u64> = HashSet::new();
        for site in &self.sites {
            if let Some(callee) = site.resolved_callee_va {
                callees.insert(callee);
            }
        }
        let mut v: Vec<u64> = callees.into_iter().collect();
        v.sort_unstable();
        v
    }
}

// ─── VirtualDispatchAnalyzer ──────────────────────────────────────────────────

/// Configuration for `VirtualDispatchAnalyzer`.
#[derive(Debug, Clone)]
pub struct DispatchAnalyzerConfig {
    /// Pointer size in bytes (4 or 8).
    pub ptr_size: u32,
    /// Maximum vtable offset to consider for a single dispatch site.
    pub max_vtable_offset: u32,
    /// Whether to attempt type-confusion detection.
    pub detect_type_confusion: bool,
    /// Whether to infer type hierarchy from vtable prefix sharing.
    pub infer_hierarchy: bool,
}

impl Default for DispatchAnalyzerConfig {
    fn default() -> Self {
        Self {
            ptr_size: 8,
            max_vtable_offset: 4096,
            detect_type_confusion: true,
            infer_hierarchy: true,
        }
    }
}

/// Analyzes virtual dispatch patterns in a binary.
///
/// The analyzer operates on two inputs:
/// 1. A table of known vtables (`vtable_va → [slot_va, ...]`).
/// 2. A list of `DispatchSite`s extracted from disassembly.
///
/// It resolves dispatch sites to vtable entries, infers type hierarchy from
/// vtable prefix relationships, and flags potential type-confusion risks.
#[derive(Debug, Default)]
pub struct VirtualDispatchAnalyzer {
    pub config: DispatchAnalyzerConfig,
    /// Known vtables: `vtable_va` → ordered list of function pointer VAs.
    vtables: HashMap<u64, Vec<u64>>,
    /// Map from class name to vtable VA.
    class_to_vtable: HashMap<String, u64>,
    /// Map from vtable VA to class name.
    vtable_to_class: HashMap<u64, String>,
}

impl VirtualDispatchAnalyzer {
    /// Create a new analyzer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an analyzer with explicit configuration.
    #[must_use]
    pub fn with_config(config: DispatchAnalyzerConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Register a vtable.
    pub fn register_vtable(&mut self, vtable_va: u64, slots: Vec<u64>, class_name: Option<String>) {
        self.vtables.insert(vtable_va, slots);
        if let Some(name) = class_name {
            self.class_to_vtable.insert(name.clone(), vtable_va);
            self.vtable_to_class.insert(vtable_va, name);
        }
    }

    /// Resolve a dispatch site against the known vtables.
    ///
    /// Updates `site.resolved_vtable_va`, `site.resolved_callee_va`, and
    /// `site.receiver_class` in place.
    pub fn resolve_site(&self, site: &mut DispatchSite) {
        let ps = self.config.ptr_size;
        if ps == 0 {
            return; // invalid configuration — a division below would panic
        }
        let offset_checked = site.vtable_offset;
        if offset_checked > self.config.max_vtable_offset {
            return;
        }
        let slot_idx = (offset_checked / ps) as usize;

        // Try each registered vtable in deterministic (vt_va-ascending) order
        // so resolution does not depend on HashMap iteration order.
        let mut entries: Vec<(u64, &Vec<u64>)> =
            self.vtables.iter().map(|(&k, v)| (k, v)).collect();
        entries.sort_by_key(|(va, _)| *va);
        for (vt_va, slots) in entries {
            if let Some(&callee) = slots.get(slot_idx) {
                site.resolve(vt_va, callee);
                if let Some(name) = self.vtable_to_class.get(&vt_va) {
                    site.receiver_class = Some(name.clone());
                }
                site.kind = DispatchKind::StandardVcall;
                return;
            }
        }
    }

    /// Run analysis on a batch of dispatch sites and loads.
    ///
    /// Returns a full `DispatchAnalysis`.
    #[must_use]
    pub fn analyze(
        &self,
        mut sites: Vec<DispatchSite>,
        loads: Vec<VtableLoad>,
    ) -> DispatchAnalysis {
        // Resolve all sites.
        for site in &mut sites {
            self.resolve_site(site);
        }

        // Build type hierarchy from vtable prefix sharing.
        let hierarchy = if self.config.infer_hierarchy {
            self.infer_hierarchy()
        } else {
            TypeHierarchy::new()
        };

        // Detect type confusion.
        let risks = if self.config.detect_type_confusion {
            self.detect_confusion(&sites, &hierarchy)
        } else {
            Vec::new()
        };

        let mut analysis = DispatchAnalysis {
            loads,
            hierarchy,
            risks,
            ..DispatchAnalysis::default()
        };
        for site in sites {
            analysis.add_site(site);
        }
        analysis
    }

    /// Infer class hierarchy from vtable prefix sharing.
    ///
    /// If vtable A is a strict prefix of vtable B (first N slots of B equal all
    /// of A), we infer that B's class derives from A's class.
    fn infer_hierarchy(&self) -> TypeHierarchy {
        let mut hierarchy = TypeHierarchy::new();

        // Add all known classes.
        for (&vt_va, slots) in &self.vtables {
            let name = self
                .vtable_to_class
                .get(&vt_va)
                .cloned()
                .unwrap_or_else(|| format!("class_{vt_va:#x}"));
            let node = TypeHierarchyNode::new(&name, vt_va, slots.len());
            hierarchy.add_class(node);
        }

        // Detect prefix relationships (sorted by vtable VA so that edge
        // insertion order — and thus children/parents ordering — is
        // deterministic across runs).
        let mut vt_list: Vec<(u64, &Vec<u64>)> = self.vtables.iter().map(|(&k, v)| (k, v)).collect();
        vt_list.sort_unstable_by_key(|(va, _)| *va);
        for i in 0..vt_list.len() {
            let (va_a, slots_a) = vt_list[i];
            for j in 0..vt_list.len() {
                if i == j {
                    continue;
                }
                let (va_b, slots_b) = vt_list[j];
                // A is a strict prefix of B?
                let na = slots_a.len();
                let nb = slots_b.len();
                if na > 0 && nb > na && &slots_b[..na] == slots_a.as_slice() {
                    let name_a = self
                        .vtable_to_class
                        .get(&va_a)
                        .cloned()
                        .unwrap_or_else(|| format!("class_{va_a:#x}"));
                    let name_b = self
                        .vtable_to_class
                        .get(&va_b)
                        .cloned()
                        .unwrap_or_else(|| format!("class_{va_b:#x}"));
                    hierarchy.add_edge(&name_a, &name_b);
                }
            }
        }

        hierarchy.compute_depths();
        hierarchy
    }

    /// Detect type-confusion risks in a list of resolved dispatch sites.
    fn detect_confusion(
        &self,
        sites: &[DispatchSite],
        hierarchy: &TypeHierarchy,
    ) -> Vec<TypeConfusionRisk> {
        let mut risks = Vec::new();

        // Group dispatch sites by slot index.
        let mut by_slot: HashMap<u32, Vec<&DispatchSite>> = HashMap::new();
        for site in sites {
            if site.resolved {
                by_slot.entry(site.slot_index).or_default().push(site);
            }
        }

        // For each slot (ascending, for deterministic output order), check if
        // multiple distinct classes are dispatched there.
        let mut slot_keys: Vec<u32> = by_slot.keys().copied().collect();
        slot_keys.sort_unstable();
        for slot in &slot_keys {
            let slot_sites = &by_slot[slot];
            let classes: HashSet<&str> = slot_sites
                .iter()
                .filter_map(|s| s.receiver_class.as_deref())
                .collect();

            if classes.len() > 1 {
                // Multiple classes share a dispatch slot — may indicate confusion.
                // Sort so `primary`/`confused_with` do not depend on HashSet order.
                let mut class_list: Vec<&str> = classes.iter().copied().collect();
                class_list.sort_unstable();
                let primary = class_list[0];
                let confused: Vec<String> = class_list[1..].iter().map(|s| s.to_string()).collect();

                // Check if the classes are in a parent-child relationship.
                // Exclude the primary itself: a class is never its own
                // parent/child, so including it made `related` always false
                // (severity could never be downgraded to Info).
                let related = class_list.iter().filter(|&&c| c != primary).all(|&c| {
                    hierarchy
                        .nodes
                        .get(primary)
                        .map(|n| n.children.iter().any(|ch| ch == c) || n.parents.iter().any(|p| p == c))
                        .unwrap_or(false)
                });

                let severity = if related {
                    Severity::Info
                } else {
                    Severity::Warning
                };

                for site in slot_sites {
                    let mut risk = TypeConfusionRisk::new(
                        site.call_va,
                        site.receiver_class.clone().unwrap_or_default(),
                        severity,
                        format!(
                            "Slot {} dispatched from {} different classes",
                            slot,
                            classes.len()
                        ),
                    );
                    risk.confused_with = confused.clone();
                    risk.affected_slot = *slot;
                    risks.push(risk);
                }
            }
        }

        risks
    }

    /// Return the total number of registered vtables.
    #[must_use]
    pub fn vtable_count(&self) -> usize {
        self.vtables.len()
    }

    /// Lookup which vtable slot resolves a given callee address.
    ///
    /// Returns `(vtable_va, slot_index)` for the first match.
    #[must_use]
    pub fn find_slot_for_callee(&self, callee_va: u64) -> Option<(u64, usize)> {
        // Scan vtables in ascending-VA order so "the first match" is
        // deterministic rather than HashMap-iteration-order dependent.
        let mut keys: Vec<u64> = self.vtables.keys().copied().collect();
        keys.sort_unstable();
        for vt_va in keys {
            if let Some(idx) = self.vtables[&vt_va].iter().position(|&s| s == callee_va) {
                return Some((vt_va, idx));
            }
        }
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_analyzer() -> VirtualDispatchAnalyzer {
        let mut a = VirtualDispatchAnalyzer::new();
        // Register two vtables: Base and Derived (Derived extends Base).
        a.register_vtable(
            0x5000,
            vec![0x1000, 0x1010, 0x1020],
            Some("Base".into()),
        );
        a.register_vtable(
            0x5020,
            // First 3 slots match Base, plus an extra slot so Derived is a
            // strict superset (needed for infer_hierarchy prefix detection).
            vec![0x1000, 0x1010, 0x1020, 0x2000],
            Some("Derived".into()),
        );
        a
    }

    #[test]
    fn test_dispatch_site_new() {
        let site = DispatchSite::new(0xDEAD, 16, 8);
        assert_eq!(site.slot_index, 2);
        assert!(!site.resolved);
    }

    #[test]
    fn test_dispatch_site_resolve() {
        let mut site = DispatchSite::new(0xDEAD, 0, 8);
        site.resolve(0x5000, 0x1000);
        assert!(site.resolved);
        assert_eq!(site.resolved_vtable_va, Some(0x5000));
        assert_eq!(site.resolved_callee_va, Some(0x1000));
    }

    #[test]
    fn test_analyzer_resolve_site() {
        let a = make_analyzer();
        let mut site = DispatchSite::new(0xABCD, 0, 8);
        a.resolve_site(&mut site);
        assert!(site.resolved);
        assert_eq!(site.receiver_class.as_deref(), Some("Base"));
    }

    #[test]
    fn test_analyzer_resolve_slot2() {
        let a = make_analyzer();
        let mut site = DispatchSite::new(0x1234, 16, 8);
        a.resolve_site(&mut site);
        assert!(site.resolved);
        assert_eq!(site.slot_index, 2);
    }

    #[test]
    fn test_hierarchy_bfs_order() {
        let mut h = TypeHierarchy::new();
        h.add_class(TypeHierarchyNode::new("A", 0x1000, 2));
        h.add_class(TypeHierarchyNode::new("B", 0x2000, 3));
        h.add_edge("A", "B");
        h.compute_depths();
        let order = h.bfs_order();
        assert!(order.contains(&"A".to_string()));
        assert!(order.contains(&"B".to_string()));
        assert!(h.nodes["B"].depth == 1);
    }

    #[test]
    fn test_hierarchy_all_derived() {
        let mut h = TypeHierarchy::new();
        h.add_edge("Base", "Mid");
        h.add_edge("Mid", "Leaf");
        h.compute_depths();
        let derived = h.all_derived("Base");
        assert!(derived.contains(&"Mid".to_string()));
        assert!(derived.contains(&"Leaf".to_string()));
    }

    #[test]
    fn test_infer_hierarchy_prefix() {
        let a = make_analyzer();
        let hier = a.infer_hierarchy();
        // Derived's vtable is a superset of Base's, so Derived derives from Base.
        let derived_of_base = hier.all_derived("Base");
        assert!(derived_of_base.contains(&"Derived".to_string()));
    }

    #[test]
    fn test_analyze_resolution_rate() {
        let a = make_analyzer();
        let sites = vec![
            DispatchSite::new(0x1000, 0, 8),
            DispatchSite::new(0x2000, 0, 8),
        ];
        let result = a.analyze(sites, vec![]);
        assert_eq!(result.resolution_rate(), 1.0);
    }

    #[test]
    fn test_find_slot_for_callee() {
        let a = make_analyzer();
        let found = a.find_slot_for_callee(0x1010);
        assert!(found.is_some());
        let (_, idx) = found.unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_dispatch_analysis_sites_in_function() {
        let mut analysis = DispatchAnalysis::new();
        let mut s1 = DispatchSite::new(0x1000, 0, 8);
        s1.function_va = 0x500;
        let mut s2 = DispatchSite::new(0x1010, 0, 8);
        s2.function_va = 0x600;
        analysis.add_site(s1);
        analysis.add_site(s2);
        let in_fn = analysis.sites_in_function(0x500);
        assert_eq!(in_fn.len(), 1);
        assert_eq!(in_fn[0].call_va, 0x1000);
    }

    #[test]
    fn test_type_confusion_risk_display() {
        let r = TypeConfusionRisk::new(0xDEAD, "Foo", Severity::Critical, "test");
        let s = format!("{r}");
        assert!(s.contains("0xdead"));
        assert!(s.contains("Foo"));
        assert!(s.contains("critical"));
    }

    #[test]
    fn test_vtable_load_primary() {
        let load = VtableLoad::new(0x1234, 1, 2, 0, 0x1000);
        assert!(load.is_primary());
        let load2 = VtableLoad::new(0x1234, 1, 2, 8, 0x1000);
        assert!(!load2.is_primary());
    }

    // ── Regressions (graph-algorithm hardening pass) ──────────────────────────

    /// compute_depths had no visited set: a cycle among non-root nodes
    /// reachable from a root looped forever (A→B→C→B…), and diamonds
    /// re-enqueued nodes exponentially.
    #[test]
    fn regress_compute_depths_terminates_on_cycle() {
        let mut h = TypeHierarchy::new();
        h.add_edge("Root", "B");
        h.add_edge("B", "C");
        h.add_edge("C", "B"); // cycle B→C→B, both have parents so neither is a root
        h.compute_depths();
        assert_eq!(h.nodes["Root"].depth, 0);
        assert_eq!(h.nodes["B"].depth, 1);
        assert_eq!(h.nodes["C"].depth, 2);
    }

    /// Wide diamond ladder: without a visited set BFS enqueues 2^N paths.
    #[test]
    fn regress_compute_depths_diamond_ladder_terminates_quickly() {
        let mut h = TypeHierarchy::new();
        for i in 0..40u32 {
            h.add_edge(&format!("L{i}"), &format!("L{}a", i + 1));
            h.add_edge(&format!("L{i}"), &format!("L{}b", i + 1));
            h.add_edge(&format!("L{}a", i + 1), &format!("L{}", i + 1));
            h.add_edge(&format!("L{}b", i + 1), &format!("L{}", i + 1));
        }
        h.compute_depths(); // would take ~2^40 enqueues before the fix
        assert_eq!(h.nodes["L0"].depth, 0);
        assert_eq!(h.nodes["L40"].depth, 80);
    }

    /// BFS assigns minimum depth on multi-path (diamond) reachability.
    #[test]
    fn regress_compute_depths_diamond_min_depth() {
        let mut h = TypeHierarchy::new();
        h.add_edge("A", "B");
        h.add_edge("B", "D");
        h.add_edge("A", "D"); // short path A→D
        h.compute_depths();
        assert_eq!(h.nodes["D"].depth, 1);
    }

    /// roots / bfs_order / infer_hierarchy / detect_confusion previously
    /// leaked HashMap iteration order into their output.
    #[test]
    fn regress_hierarchy_output_deterministic() {
        let build = || {
            let mut a = VirtualDispatchAnalyzer::new();
            a.register_vtable(0x9000, vec![0x1, 0x2], Some("Zeta".into()));
            a.register_vtable(0x5000, vec![0x1, 0x2, 0x3], Some("Alpha".into()));
            a.register_vtable(0x7000, vec![0x1, 0x2, 0x4], Some("Mid".into()));
            a.register_vtable(0x3000, vec![0x9, 0x8], Some("Iso".into()));
            a.infer_hierarchy()
        };
        let h1 = build();
        let h2 = build();
        assert_eq!(h1.roots, h2.roots);
        assert_eq!(h1.bfs_order(), h2.bfs_order());
        // roots are sorted.
        let mut sorted = h1.roots.clone();
        sorted.sort_unstable();
        assert_eq!(h1.roots, sorted);
        // children order deterministic too.
        for (name, node) in &h1.nodes {
            assert_eq!(node.children, h2.nodes[name].children, "children of {name}");
            assert_eq!(node.parents, h2.nodes[name].parents, "parents of {name}");
        }
    }

    #[test]
    fn regress_detect_confusion_deterministic() {
        let run = || {
            let a = VirtualDispatchAnalyzer::new();
            // Pre-resolved sites with offsets above max_vtable_offset so
            // resolve_site leaves receiver_class intact.
            let mut sites = Vec::new();
            for (i, cls) in ["Zeta", "Alpha", "Mid", "Beta"].iter().enumerate() {
                let mut s = DispatchSite::new(0x1000 + i as u64, 0, 8);
                s.vtable_offset = 8192; // > default max_vtable_offset
                s.resolve(0x5000, 0x1000);
                s.receiver_class = Some((*cls).to_string());
                sites.push(s);
            }
            a.analyze(sites, vec![])
                .risks
                .into_iter()
                .map(|r| (r.dispatch_va, r.expected_class, r.confused_with))
                .collect::<Vec<_>>()
        };
        let r1 = run();
        assert!(!r1.is_empty(), "confusion should be detected");
        assert_eq!(r1, run());
        // `confused_with` is sorted (everything except the sorted-first class).
        assert_eq!(r1[0].2, vec!["Beta", "Mid", "Zeta"]);
    }

    /// find_slot_for_callee: "first match" is now lowest vtable VA, not
    /// whichever HashMap bucket iterated first.
    #[test]
    fn regress_find_slot_for_callee_deterministic() {
        let mut a = VirtualDispatchAnalyzer::new();
        a.register_vtable(0x9000, vec![0xAAAA], None);
        a.register_vtable(0x2000, vec![0x1, 0xAAAA], None);
        a.register_vtable(0x5000, vec![0xAAAA], None);
        assert_eq!(a.find_slot_for_callee(0xAAAA), Some((0x2000, 1)));
    }

    /// ptr_size == 0 (caller-controlled config) previously hit a divide-by-zero
    /// panic in DispatchSite::new and resolve_site.
    #[test]
    fn regress_zero_ptr_size_no_panic() {
        let site = DispatchSite::new(0x1000, 16, 0);
        assert_eq!(site.slot_index, 0);
        let mut a = VirtualDispatchAnalyzer::with_config(DispatchAnalyzerConfig {
            ptr_size: 0,
            ..DispatchAnalyzerConfig::default()
        });
        a.register_vtable(0x5000, vec![0x1000], None);
        let mut s = DispatchSite::new(0x1000, 16, 8);
        a.resolve_site(&mut s);
        assert!(!s.resolved);
    }

    /// `related` included the primary class in its own parent/child check, so
    /// it was always false and severity was never Info even for a direct
    /// parent-child pair sharing a slot.
    #[test]
    fn regress_detect_confusion_related_classes_are_info() {
        let mut a = make_analyzer(); // Base is inferred parent of Derived
        a.config.detect_type_confusion = true;
        let mk = |va: u64, cls: &str| {
            let mut s = DispatchSite::new(va, 0, 8);
            s.vtable_offset = 8192; // skip resolve_site rewriting
            s.resolve(0x5000, 0x1000);
            s.receiver_class = Some(cls.to_string());
            s
        };
        let analysis = a.analyze(vec![mk(0x10, "Base"), mk(0x20, "Derived")], vec![]);
        assert!(!analysis.risks.is_empty());
        assert!(
            analysis.risks.iter().all(|r| r.severity == Severity::Info),
            "parent-child slot sharing must be Info, got {:?}",
            analysis.risks.iter().map(|r| r.severity).collect::<Vec<_>>()
        );
        // Unrelated classes must stay Warning.
        let analysis2 = a.analyze(vec![mk(0x10, "Base"), mk(0x20, "Stranger")], vec![]);
        assert!(analysis2.risks.iter().all(|r| r.severity == Severity::Warning));
    }

    #[test]
    fn test_resolved_callees_unique() {
        let mut analysis = DispatchAnalysis::new();
        let mut s1 = DispatchSite::new(0x1000, 0, 8);
        s1.resolve(0x5000, 0x1100);
        let mut s2 = DispatchSite::new(0x2000, 0, 8);
        s2.resolve(0x5000, 0x1100); // same callee
        analysis.add_site(s1);
        analysis.add_site(s2);
        let callees = analysis.resolved_callees();
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0], 0x1100);
    }
}
