//! `cpp_class_hierarchy` — C++ class hierarchy reconstruction.
//!
//! Reconstructs C++ class hierarchies from vtable and RTTI data, handling
//! single/multiple/virtual inheritance and diamond problems.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchyError {
    ClassNotFound(String),
    CyclicHierarchy(Vec<String>),
    VTableParseError(String),
    AmbiguousMethod(String),
}

impl fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassNotFound(name) => write!(f, "class not found: {name}"),
            Self::CyclicHierarchy(cycle) => {
                write!(f, "cyclic hierarchy: {}", cycle.join(" → "))
            }
            Self::VTableParseError(msg) => write!(f, "vtable parse error: {msg}"),
            Self::AmbiguousMethod(msg) => write!(f, "ambiguous method: {msg}"),
        }
    }
}

impl std::error::Error for HierarchyError {}

// ─── VTableEntry ─────────────────────────────────────────────────────────────

/// A single entry in a class's vtable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VTableEntry {
    /// Slot index in the vtable.
    pub slot: usize,
    /// Address of the function implementing this slot.
    pub function_addr: u64,
    /// True if this is a pure virtual function (= 0).
    pub is_pure: bool,
    /// True if this is a virtual destructor.
    pub is_destructor: bool,
    /// Demangled name (if available).
    pub name: Option<String>,
    /// Thunk offset (for virtual base adjustments).
    pub thunk_offset: i64,
}

impl VTableEntry {
    #[must_use] 
    pub const fn new(slot: usize, function_addr: u64) -> Self {
        Self {
            slot,
            function_addr,
            is_pure: function_addr == 0,
            is_destructor: false,
            name: None,
            thunk_offset: 0,
        }
    }

    #[must_use] 
    pub fn pure_virtual(slot: usize) -> Self {
        Self {
            slot,
            function_addr: 0,
            is_pure: true,
            is_destructor: false,
            name: Some("__cxa_pure_virtual".into()),
            thunk_offset: 0,
        }
    }
}

// ─── Inheritance kind ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InheritanceKind {
    /// Standard C++ public single inheritance.
    Single,
    /// C++ virtual inheritance (for diamond resolution).
    Virtual,
    /// Protected inheritance.
    Protected,
    /// Private inheritance.
    Private,
}

// ─── BaseClass ───────────────────────────────────────────────────────────────

/// A base class relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseClass {
    /// Name of the base class.
    pub name: String,
    /// Byte offset of the base subobject within the derived class.
    pub offset: i64,
    /// Kind of inheritance.
    pub kind: InheritanceKind,
    /// True if this is the primary base (first non-virtual base with vtable).
    pub is_primary: bool,
}

impl BaseClass {
    pub fn new(name: impl Into<String>, offset: i64) -> Self {
        Self {
            name: name.into(),
            offset,
            kind: InheritanceKind::Single,
            is_primary: false,
        }
    }
}

// ─── CppClass ────────────────────────────────────────────────────────────────

/// A reconstructed C++ class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CppClass {
    /// Mangled or demangled class name.
    pub name: String,
    /// Virtual address of the vtable.
    pub vtable_addr: Option<u64>,
    /// Vtable entries.
    pub vtable: Vec<VTableEntry>,
    /// Direct base classes.
    pub base_classes: Vec<BaseClass>,
    /// All methods (virtual + non-virtual).
    pub methods: Vec<CppMethod>,
    /// Total object size in bytes.
    pub size_bytes: Option<usize>,
    /// True if this class is abstract (has pure virtual methods).
    pub is_abstract: bool,
    /// Type info address (from RTTI).
    pub typeinfo_addr: Option<u64>,
}

impl CppClass {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            vtable_addr: None,
            vtable: Vec::new(),
            base_classes: Vec::new(),
            methods: Vec::new(),
            size_bytes: None,
            is_abstract: false,
            typeinfo_addr: None,
        }
    }

    /// True if this class has any pure virtual methods.
    #[must_use] 
    pub fn has_pure_virtuals(&self) -> bool {
        self.vtable.iter().any(|e| e.is_pure)
    }

    /// Number of vtable slots.
    #[must_use] 
    pub const fn vtable_size(&self) -> usize {
        self.vtable.len()
    }

    /// Returns base class names.
    #[must_use] 
    pub fn base_names(&self) -> Vec<&str> {
        self.base_classes.iter().map(|b| b.name.as_str()).collect()
    }
}

// ─── CppMethod ───────────────────────────────────────────────────────────────

/// A C++ method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CppMethod {
    pub name: String,
    pub address: u64,
    pub is_virtual: bool,
    pub is_pure: bool,
    pub is_const: bool,
    pub vtable_slot: Option<usize>,
    pub defining_class: String,
}

impl CppMethod {
    pub fn new(name: impl Into<String>, address: u64, defining_class: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            is_virtual: false,
            is_pure: false,
            is_const: false,
            vtable_slot: None,
            defining_class: defining_class.into(),
        }
    }
}

// ─── CppDestructor ───────────────────────────────────────────────────────────

/// Identified C++ destructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CppDestructor {
    pub class_name: String,
    pub address: u64,
    pub is_virtual: bool,
    /// In Itanium ABI: D0 (deleting), D1 (complete), D2 (base).
    pub destructor_kind: DestructorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructorKind {
    /// Deleting destructor (D0).
    Deleting,
    /// Complete object destructor (D1).
    Complete,
    /// Base object destructor (D2).
    Base,
    /// Unknown / MSVC style.
    Unknown,
}

// ─── VirtualBaseOffset ────────────────────────────────────────────────────────

/// Virtual base offset table entry (`vbase_offset`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualBaseOffset {
    pub derived_class: String,
    pub virtual_base: String,
    /// Byte offset from the derived class start to the virtual base subobject.
    pub offset: i64,
}

// ─── SingleInheritanceChain ───────────────────────────────────────────────────

/// A linear inheritance chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleInheritanceChain {
    /// From most-derived to most-base.
    pub chain: Vec<String>,
}

impl SingleInheritanceChain {
    #[must_use] 
    pub const fn new(chain: Vec<String>) -> Self {
        Self { chain }
    }

    #[must_use] 
    pub const fn depth(&self) -> usize {
        self.chain.len()
    }

    #[must_use] 
    pub fn base(&self) -> Option<&str> {
        self.chain.last().map(std::string::String::as_str)
    }

    #[must_use] 
    pub fn most_derived(&self) -> Option<&str> {
        self.chain.first().map(std::string::String::as_str)
    }
}

// ─── MultipleInheritance ─────────────────────────────────────────────────────

/// Represents a multiple-inheritance scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipleInheritance {
    pub derived: String,
    pub bases: Vec<String>,
    pub is_diamond: bool,
    pub virtual_bases: Vec<String>,
}

impl MultipleInheritance {
    pub fn new(derived: impl Into<String>, bases: Vec<String>) -> Self {
        Self {
            derived: derived.into(),
            bases,
            is_diamond: false,
            virtual_bases: Vec::new(),
        }
    }
}

// ─── ClassHierarchyGraph ─────────────────────────────────────────────────────

/// The complete class hierarchy as a directed acyclic graph.
#[derive(Debug, Default)]
pub struct ClassHierarchyGraph {
    pub classes: HashMap<String, CppClass>,
    /// Inheritance edges: derived → list of base names.
    edges: HashMap<String, Vec<String>>,
    /// Reverse edges: base → list of derived names.
    reverse_edges: HashMap<String, Vec<String>>,
    pub virtual_base_offsets: Vec<VirtualBaseOffset>,
    pub destructors: Vec<CppDestructor>,
}

impl ClassHierarchyGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a class.
    pub fn add_class(&mut self, class: CppClass) {
        let name = class.name.clone();
        // Re-registering a class must replace its edges, not accumulate
        // duplicates in `edges` / stale entries in `reverse_edges`.
        if let Some(old_bases) = self.edges.remove(&name) {
            for old_base in old_bases {
                if let Some(rev) = self.reverse_edges.get_mut(&old_base) {
                    rev.retain(|d| d != &name);
                }
            }
        }
        for base in &class.base_classes {
            self.edges
                .entry(name.clone())
                .or_default()
                .push(base.name.clone());
            self.reverse_edges
                .entry(base.name.clone())
                .or_default()
                .push(name.clone());
        }
        self.classes.insert(name, class);
    }

    /// Get a class by name.
    #[must_use] 
    pub fn get_class(&self, name: &str) -> Option<&CppClass> {
        self.classes.get(name)
    }

    /// Get all base class names (direct) of a class.
    #[must_use] 
    pub fn direct_bases(&self, name: &str) -> &[String] {
        self.edges.get(name).map_or(&[], std::vec::Vec::as_slice)
    }

    /// Get all derived classes (direct).
    #[must_use] 
    pub fn direct_derived(&self, name: &str) -> &[String] {
        self.reverse_edges
            .get(name)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// Get all ancestors (transitive closure) via BFS.
    #[must_use] 
    pub fn all_ancestors(&self, name: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(name.to_string());
        while let Some(cur) = queue.pop_front() {
            for base in self.direct_bases(&cur) {
                if visited.insert(base.clone()) {
                    order.push(base.clone());
                    queue.push_back(base.clone());
                }
            }
        }
        order
    }

    /// Get all descendants (transitive closure) via BFS.
    #[must_use] 
    pub fn all_descendants(&self, name: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(name.to_string());
        while let Some(cur) = queue.pop_front() {
            for derived in self.direct_derived(&cur) {
                if visited.insert(derived.clone()) {
                    order.push(derived.clone());
                    queue.push_back(derived.clone());
                }
            }
        }
        order
    }

    /// Check if class `derived` inherits from class `base`.
    #[must_use] 
    pub fn is_subclass_of(&self, derived: &str, base: &str) -> bool {
        let ancestors = self.all_ancestors(derived);
        ancestors.contains(&base.to_string())
    }

    /// Find root classes (those with no base classes).
    #[must_use] 
    pub fn roots(&self) -> Vec<&str> {
        let mut roots: Vec<&str> = self
            .classes
            .keys()
            .filter(|n| self.edges.get(*n).is_none_or(std::vec::Vec::is_empty))
            .map(std::string::String::as_str)
            .collect();
        roots.sort_unstable();
        roots
    }

    /// Detect diamond inheritance patterns.
    #[must_use] 
    pub fn find_diamonds(&self) -> Vec<MultipleInheritance> {
        let mut diamonds = Vec::new();
        let mut names: Vec<&String> = self.classes.keys().collect();
        names.sort_unstable();
        for class in names.into_iter().map(|n| &self.classes[n]) {
            if class.base_classes.len() >= 2 {
                // Gather all ancestors through each path.
                let mut all_anc: HashMap<String, usize> = HashMap::new();
                for base in &class.base_classes {
                    // Count the direct base itself: a diamond can close through
                    // a direct base (D→B→C plus D→C repeats C).
                    *all_anc.entry(base.name.clone()).or_insert(0) += 1;
                    let anc = self.all_ancestors(&base.name);
                    for a in anc {
                        *all_anc.entry(a).or_insert(0) += 1;
                    }
                }
                

                if all_anc
                    .into_iter()
                    .filter(|(_, count)| *count >= 2)
                    .map(|(n, _)| n).next().is_some() {
                    let bases: Vec<String> =
                        class.base_classes.iter().map(|b| b.name.clone()).collect();
                    let vb: Vec<String> = class
                        .base_classes
                        .iter()
                        .filter(|b| b.kind == InheritanceKind::Virtual)
                        .map(|b| b.name.clone())
                        .collect();
                    let mut mi = MultipleInheritance::new(class.name.clone(), bases);
                    mi.is_diamond = true;
                    mi.virtual_bases = vb;
                    diamonds.push(mi);
                }
            }
        }
        diamonds
    }

    /// Resolve virtual method at `slot` for `class_name` (walks hierarchy).
    #[must_use] 
    pub fn resolve_virtual_method(&self, class_name: &str, slot: usize) -> Option<&VTableEntry> {
        self.classes.get(class_name)?;
        // Iterative depth-first walk (bases in declaration order) with a
        // visited set: safe on cyclic (corrupt) hierarchies and on chains
        // deeper than the native call stack.
        let mut visited: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = vec![class_name];
        while let Some(cur) = stack.pop() {
            if !visited.insert(cur) {
                continue;
            }
            if let Some(class) = self.classes.get(cur)
                && let Some(entry) = class.vtable.iter().find(|e| e.slot == slot)
                && !entry.is_pure
            {
                return Some(entry);
            }
            // Push bases reversed so the first base is explored first.
            for base in self.direct_bases(cur).iter().rev() {
                stack.push(base);
            }
        }
        None
    }

    /// Build a single-inheritance chain for a class (only valid for single-inherited classes).
    #[must_use] 
    pub fn single_inheritance_chain(&self, class_name: &str) -> Option<SingleInheritanceChain> {
        let mut chain = Vec::new();
        let mut current = class_name.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return None; // cycle
            }
            chain.push(current.clone());
            let bases = self.direct_bases(&current);
            match bases {
                [] => break,
                [single] => current = single.clone(),
                _ => return None, // multiple inheritance
            }
        }
        Some(SingleInheritanceChain::new(chain))
    }

    /// Count total number of registered classes.
    #[must_use] 
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Count virtual methods in a class's vtable.
    #[must_use] 
    pub fn virtual_method_count(&self, class_name: &str) -> usize {
        self.classes
            .get(class_name)
            .map_or(0, |c| c.vtable.len())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_class(name: &str, bases: &[&str]) -> CppClass {
        let mut c = CppClass::new(name);
        for base in bases {
            c.base_classes.push(BaseClass::new(*base, 0));
        }
        c
    }

    fn make_graph() -> ClassHierarchyGraph {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("Base", &[]));
        g.add_class(make_class("Middle", &["Base"]));
        g.add_class(make_class("Derived", &["Middle"]));
        g
    }

    #[test]
    fn graph_class_count() {
        let g = make_graph();
        assert_eq!(g.class_count(), 3);
    }

    #[test]
    fn graph_get_class() {
        let g = make_graph();
        assert!(g.get_class("Base").is_some());
        assert!(g.get_class("Nonexistent").is_none());
    }

    #[test]
    fn graph_direct_bases() {
        let g = make_graph();
        assert_eq!(g.direct_bases("Derived"), &["Middle"]);
        assert!(g.direct_bases("Base").is_empty());
    }

    #[test]
    fn graph_direct_derived() {
        let g = make_graph();
        assert!(g.direct_derived("Base").contains(&"Middle".to_string()));
    }

    #[test]
    fn graph_all_ancestors() {
        let g = make_graph();
        let anc = g.all_ancestors("Derived");
        assert!(anc.contains(&"Middle".to_string()));
        assert!(anc.contains(&"Base".to_string()));
    }

    #[test]
    fn graph_all_descendants() {
        let g = make_graph();
        let desc = g.all_descendants("Base");
        assert!(desc.contains(&"Middle".to_string()));
        assert!(desc.contains(&"Derived".to_string()));
    }

    #[test]
    fn graph_is_subclass_of() {
        let g = make_graph();
        assert!(g.is_subclass_of("Derived", "Base"));
        assert!(g.is_subclass_of("Middle", "Base"));
        assert!(!g.is_subclass_of("Base", "Derived"));
    }

    #[test]
    fn graph_roots() {
        let g = make_graph();
        let roots = g.roots();
        assert!(roots.contains(&"Base"));
    }

    #[test]
    fn graph_single_inheritance_chain() {
        let g = make_graph();
        let chain = g.single_inheritance_chain("Derived").unwrap();
        assert_eq!(chain.depth(), 3);
        assert_eq!(chain.base(), Some("Base"));
        assert_eq!(chain.most_derived(), Some("Derived"));
    }

    #[test]
    fn graph_single_inheritance_chain_base_class() {
        let g = make_graph();
        let chain = g.single_inheritance_chain("Base").unwrap();
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn graph_find_diamonds() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("A", &[]));
        g.add_class(make_class("B", &["A"]));
        g.add_class(make_class("C", &["A"]));
        let mut diamond = make_class("D", &["B", "C"]);
        // Mark one as virtual.
        diamond.base_classes[0].kind = InheritanceKind::Virtual;
        g.add_class(diamond);
        let diamonds = g.find_diamonds();
        assert!(!diamonds.is_empty());
        let d = &diamonds[0];
        assert_eq!(d.derived, "D");
    }

    #[test]
    fn vtable_entry_pure_virtual() {
        let entry = VTableEntry::pure_virtual(0);
        assert!(entry.is_pure);
        assert_eq!(entry.function_addr, 0);
    }

    #[test]
    fn cpp_class_has_pure_virtuals() {
        let mut c = CppClass::new("Abstract");
        c.vtable.push(VTableEntry::pure_virtual(0));
        assert!(c.has_pure_virtuals());
    }

    #[test]
    fn cpp_class_no_pure_virtuals() {
        let c = CppClass::new("Concrete");
        assert!(!c.has_pure_virtuals());
    }

    #[test]
    fn cpp_class_vtable_size() {
        let mut c = CppClass::new("MyClass");
        c.vtable.push(VTableEntry::new(0, 0x1000));
        c.vtable.push(VTableEntry::new(1, 0x1100));
        assert_eq!(c.vtable_size(), 2);
    }

    #[test]
    fn graph_resolve_virtual_method() {
        let mut g = ClassHierarchyGraph::new();
        let mut base = CppClass::new("Base");
        let mut entry = VTableEntry::new(0, 0x1000);
        entry.name = Some("method0".into());
        base.vtable.push(entry);
        g.add_class(base);

        let derived = make_class("Derived", &["Base"]);
        g.add_class(derived);

        let resolved = g.resolve_virtual_method("Derived", 0);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().function_addr, 0x1000);
    }

    #[test]
    fn graph_virtual_method_count() {
        let mut g = make_graph();
        if let Some(c) = g.classes.get_mut("Base") {
            c.vtable.push(VTableEntry::new(0, 0xABCD));
        }
        assert_eq!(g.virtual_method_count("Base"), 1);
    }

    #[test]
    fn hierarchy_error_display() {
        let e = HierarchyError::ClassNotFound("Foo".into());
        assert!(e.to_string().contains("Foo"));
    }

    #[test]
    fn cpp_class_base_names() {
        let c = make_class("Child", &["Parent1", "Parent2"]);
        let names = c.base_names();
        assert!(names.contains(&"Parent1"));
        assert!(names.contains(&"Parent2"));
    }

    #[test]
    fn destructor_kind_variants() {
        let d = CppDestructor {
            class_name: "Foo".into(),
            address: 0x1000,
            is_virtual: true,
            destructor_kind: DestructorKind::Complete,
        };
        assert_eq!(d.destructor_kind, DestructorKind::Complete);
    }

    #[test]
    fn virtual_base_offset() {
        let vbo = VirtualBaseOffset {
            derived_class: "D".into(),
            virtual_base: "A".into(),
            offset: 16,
        };
        assert_eq!(vbo.offset, 16);
    }

    // ── Regressions (graph-algorithm hardening pass) ──────────────────────────

    /// `resolve_virtual_method` was recursive with no cycle guard: a cyclic
    /// (corrupt-RTTI) hierarchy recursed forever, and a deep chain overflowed
    /// the native stack.
    #[test]
    fn regress_resolve_virtual_method_cyclic_hierarchy_terminates() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("A", &["B"]));
        g.add_class(make_class("B", &["A"]));
        assert!(g.resolve_virtual_method("A", 0).is_none());
    }

    #[test]
    fn regress_resolve_virtual_method_deep_chain_no_stack_overflow() {
        const N: usize = 200_000;
        let mut g = ClassHierarchyGraph::new();
        let mut base = CppClass::new(format!("C{N}"));
        base.vtable.push(VTableEntry::new(0, 0xBEEF));
        g.add_class(base);
        for i in 0..N {
            g.add_class(make_class(&format!("C{i}"), &[&format!("C{}", i + 1)]));
        }
        let resolved = g.resolve_virtual_method("C0", 0).expect("should resolve at root");
        assert_eq!(resolved.function_addr, 0xBEEF);
        // BFS-based transitive queries must also survive the deep chain.
        assert_eq!(g.all_ancestors("C0").len(), N);
        assert!(g.is_subclass_of("C0", &format!("C{N}")));
    }

    /// `resolve_virtual_method` must skip a pure entry and fall through to a base
    /// implementation (previous semantics, preserved by the iterative rewrite).
    #[test]
    fn regress_resolve_virtual_method_pure_falls_through_to_base() {
        let mut g = ClassHierarchyGraph::new();
        let mut base = CppClass::new("Base");
        base.vtable.push(VTableEntry::new(0, 0x1000));
        g.add_class(base);
        let mut derived = make_class("Derived", &["Base"]);
        derived.vtable.push(VTableEntry::pure_virtual(0));
        g.add_class(derived);
        let resolved = g.resolve_virtual_method("Derived", 0).unwrap();
        assert_eq!(resolved.function_addr, 0x1000);
    }

    /// First base must win when two bases implement the same slot
    /// (depth-first, declaration order — matches the old recursive walk).
    #[test]
    fn regress_resolve_virtual_method_first_base_wins() {
        let mut g = ClassHierarchyGraph::new();
        let mut b1 = CppClass::new("B1");
        b1.vtable.push(VTableEntry::new(0, 0x1111));
        g.add_class(b1);
        let mut b2 = CppClass::new("B2");
        b2.vtable.push(VTableEntry::new(0, 0x2222));
        g.add_class(b2);
        g.add_class(make_class("D", &["B1", "B2"]));
        assert_eq!(g.resolve_virtual_method("D", 0).unwrap().function_addr, 0x1111);
    }

    /// `all_ancestors` / `all_descendants` / roots / `find_diamonds` returned
    /// HashMap/HashSet iteration order — nondeterministic across runs.
    /// Now: BFS discovery order (ancestors/descendants) and sorted (roots,
    /// diamonds).
    #[test]
    fn regress_traversal_output_order_deterministic() {
        let build = || {
            let mut g = ClassHierarchyGraph::new();
            for name in ["Z", "M", "A", "Q", "B"] {
                g.add_class(make_class(name, &[]));
            }
            g.add_class(make_class("D", &["Z", "M", "A", "Q", "B"]));
            g
        };
        let g = build();
        // BFS discovery order follows base declaration order.
        assert_eq!(g.all_ancestors("D"), vec!["Z", "M", "A", "Q", "B"]);
        // roots sorted; repeated builds identical.
        assert_eq!(g.roots(), build().roots());
        assert_eq!(g.roots(), {
            let mut r = g.roots();
            r.sort_unstable();
            r
        });
        // Descendants: deterministic across rebuilds.
        assert_eq!(g.all_descendants("Z"), build().all_descendants("Z"));
    }

    #[test]
    fn regress_find_diamonds_deterministic_order() {
        let build = || {
            let mut g = ClassHierarchyGraph::new();
            g.add_class(make_class("A", &[]));
            g.add_class(make_class("B", &["A"]));
            g.add_class(make_class("C", &["A"]));
            g.add_class(make_class("D1", &["B", "C"]));
            g.add_class(make_class("D2", &["B", "C"]));
            g.add_class(make_class("D3", &["B", "C"]));
            g
        };
        let names: Vec<String> = build().find_diamonds().into_iter().map(|d| d.derived).collect();
        assert_eq!(names, vec!["D1", "D2", "D3"]);
        assert_eq!(
            names,
            build().find_diamonds().into_iter().map(|d| d.derived).collect::<Vec<_>>()
        );
    }

    /// `single_inheritance_chain` already had a cycle guard — pin it.
    #[test]
    fn regress_single_inheritance_chain_cycle_returns_none() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("A", &["B"]));
        g.add_class(make_class("B", &["A"]));
        assert!(g.single_inheritance_chain("A").is_none());
    }

    /// Re-registering a class duplicated its edges and left stale reverse
    /// edges; `add_class` now replaces the class's edge set.
    #[test]
    fn regress_add_class_twice_no_duplicate_edges() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("Base", &[]));
        g.add_class(make_class("D", &["Base"]));
        g.add_class(make_class("D", &["Base"])); // re-register identical
        assert_eq!(g.direct_bases("D"), &["Base"]);
        assert_eq!(g.direct_derived("Base"), &["D"]);
        // Re-register with a different base: old edge must be gone.
        g.add_class(make_class("Other", &[]));
        g.add_class(make_class("D", &["Other"]));
        assert_eq!(g.direct_bases("D"), &["Other"]);
        assert!(g.direct_derived("Base").is_empty());
        assert_eq!(g.direct_derived("Other"), &["D"]);
    }

    /// A diamond closing through a direct base (D→B→C plus D→C) was missed
    /// because only ancestor sets — which exclude the direct base itself —
    /// were counted.
    #[test]
    fn regress_find_diamonds_through_direct_base() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("C", &[]));
        g.add_class(make_class("B", &["C"]));
        g.add_class(make_class("D", &["B", "C"]));
        let diamonds = g.find_diamonds();
        assert_eq!(diamonds.len(), 1);
        assert_eq!(diamonds[0].derived, "D");
    }

    /// Two unrelated bases must still not be flagged as a diamond.
    #[test]
    fn regress_find_diamonds_no_false_positive_unrelated_bases() {
        let mut g = ClassHierarchyGraph::new();
        g.add_class(make_class("A", &[]));
        g.add_class(make_class("B", &[]));
        g.add_class(make_class("D", &["A", "B"]));
        assert!(g.find_diamonds().is_empty());
    }

    #[test]
    fn multiple_inheritance_new() {
        let mi = MultipleInheritance::new("D", vec!["B".into(), "C".into()]);
        assert_eq!(mi.bases.len(), 2);
        assert!(!mi.is_diamond);
    }
}
