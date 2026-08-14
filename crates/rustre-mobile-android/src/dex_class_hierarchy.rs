//! DEX class hierarchy builder.
//!
//! Parses `class_def` items from a DEX file byte stream, resolves
//! superclass and interface relationships, and builds a fully connected
//! [`ClassHierarchy`] that supports efficient ancestor/descendant queries.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// InterfaceSet
// ---------------------------------------------------------------------------

/// The set of interface descriptors implemented by a class.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceSet {
    /// Interface descriptors in JVM form, e.g. `Ljava/io/Serializable;`.
    pub interfaces: Vec<String>,
}

impl InterfaceSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interface.
    pub fn add(&mut self, iface: String) {
        if !self.interfaces.contains(&iface) {
            self.interfaces.push(iface);
        }
    }

    /// Returns `true` if the named interface is present.
    #[must_use]
    pub fn contains(&self, iface: &str) -> bool {
        self.interfaces.iter().any(|i| i == iface)
    }

    /// Number of interfaces.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ClassNode
// ---------------------------------------------------------------------------

/// A single class node in the hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassNode {
    /// JVM descriptor, e.g. `Lcom/example/Foo;`.
    pub descriptor: String,
    /// Superclass descriptor, or `None` for `Ljava/lang/Object;` / root nodes.
    pub superclass: Option<String>,
    /// Interfaces implemented directly by this class.
    pub interfaces: InterfaceSet,
    /// DEX access flags.
    pub access_flags: u32,
    /// Source file attribute, if present.
    pub source_file: Option<String>,
    /// Index into the DEX `class_def` table.
    pub class_def_idx: u32,
}

impl ClassNode {
    /// Returns `true` if this class is an interface.
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Returns `true` if this class is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns `true` if this class is public.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns `true` if this class is final.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Simple class name (last component of the descriptor, without `L` and `;`).
    #[must_use]
    pub fn simple_name(&self) -> &str {
        let s = self.descriptor.trim_start_matches('L').trim_end_matches(';');
        s.rsplit('/').next().unwrap_or(s)
    }

    /// Java-style package name (e.g. `com.example`).
    #[must_use]
    pub fn package_name(&self) -> String {
        let s = self.descriptor.trim_start_matches('L').trim_end_matches(';');
        if let Some(pos) = s.rfind('/') {
            s[..pos].replace('/', ".")
        } else {
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// HierarchyBuilder
// ---------------------------------------------------------------------------

/// Incrementally builds a [`ClassHierarchy`] from parsed class definitions.
#[derive(Debug, Default)]
pub struct HierarchyBuilder {
    nodes: Vec<ClassNode>,
}

impl HierarchyBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a class node.
    pub fn add_class(&mut self, node: ClassNode) {
        self.nodes.push(node);
    }

    /// Parse a minimal DEX class-def table from raw bytes and populate the builder.
    ///
    /// This is a lightweight parser that handles the DEX `class_def_item` format:
    ///
    /// ```text
    /// struct class_def_item {
    ///     class_idx:        u32
    ///     access_flags:     u32
    ///     superclass_idx:   u32  (NO_INDEX = 0xFFFFFFFF)
    ///     interfaces_off:   u32
    ///     source_file_idx:  u32  (NO_INDEX = 0xFFFFFFFF)
    ///     annotations_off:  u32
    ///     class_data_off:   u32
    ///     static_values_off:u32
    /// }
    /// ```
    ///
    /// This parser requires a `string_ids` table (offsets into `data`) and a
    /// `type_ids` table (indices into `string_ids`), both encoded as
    /// `Vec<u32>` slices.  For real DEX files these are extracted from the DEX
    /// header; the caller must supply them here.
    pub fn parse_class_defs(
        &mut self,
        data: &[u8],
        class_defs_off: u32,
        class_defs_size: u32,
        type_ids: &[u32],
        string_ids: &[u32],
    ) {
        const ITEM_SIZE: usize = 32; // 8 × u32
        const NO_INDEX: u32 = 0xFFFF_FFFF;

        let base = class_defs_off as usize;
        for i in 0..class_defs_size as usize {
            let off = base + i * ITEM_SIZE;
            if off + ITEM_SIZE > data.len() {
                break;
            }
            let class_idx = read_u32(data, off);
            let access_flags = read_u32(data, off + 4);
            let super_idx = read_u32(data, off + 8);
            let _interfaces_off = read_u32(data, off + 12);
            let src_idx = read_u32(data, off + 16);

            let descriptor = resolve_type_name(data, class_idx, type_ids, string_ids);
            let superclass = if super_idx == NO_INDEX {
                None
            } else {
                Some(resolve_type_name(data, super_idx, type_ids, string_ids))
            };
            let source_file = if src_idx == NO_INDEX {
                None
            } else {
                Some(resolve_string(data, src_idx, string_ids))
            };

            self.nodes.push(ClassNode {
                descriptor,
                superclass,
                interfaces: InterfaceSet::new(),
                access_flags,
                source_file,
                class_def_idx: i as u32,
            });
        }
    }

    /// Consume the builder and produce a [`ClassHierarchy`].
    #[must_use]
    pub fn build(self) -> ClassHierarchy {
        ClassHierarchy::from_nodes(self.nodes)
    }
}

// ---------------------------------------------------------------------------
// DEX byte helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn resolve_string(data: &[u8], idx: u32, string_ids: &[u32]) -> String {
    let idx = idx as usize;
    if idx >= string_ids.len() {
        return format!("<str_{idx}>");
    }
    let off = string_ids[idx] as usize;
    if off >= data.len() {
        return format!("<str_{idx}>");
    }
    // DEX string: ULEB128 length + UTF-8 bytes
    let (str_len, advance) = read_uleb128(data, off);
    let start = off + advance;
    let end = (start + str_len).min(data.len());
    String::from_utf8_lossy(&data[start..end]).to_string()
}

fn resolve_type_name(data: &[u8], type_idx: u32, type_ids: &[u32], string_ids: &[u32]) -> String {
    let tidx = type_idx as usize;
    if tidx >= type_ids.len() {
        return format!("Lunknown/Type{type_idx};");
    }
    resolve_string(data, type_ids[tidx], string_ids)
}

fn read_uleb128(data: &[u8], mut off: usize) -> (usize, usize) {
    let mut result: usize = 0;
    let mut shift = 0usize;
    let start = off;
    loop {
        if off >= data.len() {
            break;
        }
        let b = data[off] as usize;
        off += 1;
        result |= (b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift >= 35 {
            break;
        }
    }
    (result, off - start)
}

// ---------------------------------------------------------------------------
// ClassHierarchy
// ---------------------------------------------------------------------------

/// A fully connected class hierarchy with O(1) lookup by descriptor.
#[derive(Debug, Default)]
pub struct ClassHierarchy {
    /// descriptor → `ClassNode`
    nodes: HashMap<String, ClassNode>,
    /// descriptor → direct subclasses
    subclasses: HashMap<String, Vec<String>>,
    /// descriptor → direct implementors
    implementors: HashMap<String, Vec<String>>,
}

impl ClassHierarchy {
    /// Create an empty hierarchy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a list of nodes.
    #[must_use]
    pub fn from_nodes(nodes: Vec<ClassNode>) -> Self {
        let mut h = Self::new();
        for node in nodes {
            h.add_node(node);
        }
        h
    }

    /// Add a single node to the hierarchy.
    pub fn add_node(&mut self, node: ClassNode) {
        // Register as subclass of superclass.
        if let Some(ref sc) = node.superclass {
            self.subclasses
                .entry(sc.clone())
                .or_default()
                .push(node.descriptor.clone());
        }
        // Register as implementor of each interface.
        for iface in &node.interfaces.interfaces {
            self.implementors
                .entry(iface.clone())
                .or_default()
                .push(node.descriptor.clone());
        }
        self.nodes.insert(node.descriptor.clone(), node);
    }

    /// Look up a class by its JVM descriptor.
    #[must_use]
    pub fn get(&self, descriptor: &str) -> Option<&ClassNode> {
        self.nodes.get(descriptor)
    }

    /// Direct subclasses of `descriptor`.
    #[must_use]
    pub fn direct_subclasses(&self, descriptor: &str) -> &[String] {
        self.subclasses
            .get(descriptor)
            .map_or(&[], Vec::as_slice)
    }

    /// All (transitive) subclasses via BFS.
    #[must_use]
    pub fn all_subclasses(&self, descriptor: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(descriptor.to_string());
        let mut result = Vec::new();
        while let Some(cur) = queue.pop_front() {
            for sub in self.direct_subclasses(&cur) {
                if visited.insert(sub.clone()) {
                    result.push(sub.clone());
                    queue.push_back(sub.clone());
                }
            }
        }
        result
    }

    /// Direct implementors of `interface_descriptor`.
    #[must_use]
    pub fn implementors_of(&self, interface_descriptor: &str) -> &[String] {
        self.implementors
            .get(interface_descriptor)
            .map_or(&[], Vec::as_slice)
    }

    /// All ancestors of `descriptor` in order (closest first).
    #[must_use]
    pub fn ancestors(&self, descriptor: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut cur = descriptor.to_string();
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(cur.clone()) {
                break;
            }
            match self.nodes.get(&cur).and_then(|n| n.superclass.clone()) {
                Some(parent) => {
                    chain.push(parent.clone());
                    cur = parent;
                }
                None => break,
            }
        }
        chain
    }

    /// Returns `true` if `sub` extends or equals `sup`.
    #[must_use]
    pub fn is_subtype_of(&self, sub: &str, sup: &str) -> bool {
        if sub == sup {
            return true;
        }
        let mut cur = sub.to_string();
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(cur.clone()) {
                break;
            }
            if let Some(node) = self.nodes.get(&cur) {
                if node.interfaces.contains(sup) {
                    return true;
                }
                match &node.superclass {
                    Some(sc) if sc == sup => return true,
                    Some(sc) => cur = sc.clone(),
                    None => break,
                }
            } else {
                break;
            }
        }
        false
    }

    /// Total number of classes in the hierarchy.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.nodes.len()
    }

    /// All class descriptors.
    #[must_use]
    pub fn all_descriptors(&self) -> Vec<&str> {
        self.nodes.keys().map(String::as_str).collect()
    }

    /// Find classes whose simple name contains `substr` (case-insensitive).
    #[must_use]
    pub fn search_by_name(&self, substr: &str) -> Vec<&ClassNode> {
        let lower = substr.to_lowercase();
        self.nodes
            .values()
            .filter(|n| n.simple_name().to_lowercase().contains(&lower))
            .collect()
    }

    /// Return all classes that implement the named interface (direct + indirect).
    #[must_use]
    pub fn all_implementors(&self, interface_descriptor: &str) -> Vec<String> {
        let direct: HashSet<String> = self
            .implementors_of(interface_descriptor)
            .iter()
            .cloned()
            .collect();
        let mut result: HashSet<String> = direct.clone();
        // Any subclass of a direct implementor also implements it.
        for d in direct {
            for sub in self.all_subclasses(&d) {
                result.insert(sub);
            }
        }
        result.into_iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(desc: &str, super_desc: Option<&str>, ifaces: &[&str]) -> ClassNode {
        let mut iset = InterfaceSet::new();
        for i in ifaces {
            iset.add(i.to_string());
        }
        ClassNode {
            descriptor: desc.to_string(),
            superclass: super_desc.map(String::from),
            interfaces: iset,
            access_flags: 0x0001,
            source_file: None,
            class_def_idx: 0,
        }
    }

    fn build_simple_hierarchy() -> ClassHierarchy {
        let mut b = HierarchyBuilder::new();
        b.add_class(make_node("Ljava/lang/Object;", None, &[]));
        b.add_class(make_node(
            "Ljava/lang/Number;",
            Some("Ljava/lang/Object;"),
            &[],
        ));
        b.add_class(make_node(
            "Ljava/lang/Integer;",
            Some("Ljava/lang/Number;"),
            &["Ljava/lang/Comparable;"],
        ));
        b.add_class(make_node(
            "Lcom/example/MyInt;",
            Some("Ljava/lang/Integer;"),
            &[],
        ));
        b.build()
    }

    #[test]
    fn test_hierarchy_class_count() {
        let h = build_simple_hierarchy();
        assert_eq!(h.class_count(), 4);
    }

    #[test]
    fn test_hierarchy_get() {
        let h = build_simple_hierarchy();
        assert!(h.get("Ljava/lang/Integer;").is_some());
        assert!(h.get("Lmissing;").is_none());
    }

    #[test]
    fn test_direct_subclasses() {
        let h = build_simple_hierarchy();
        let subs = h.direct_subclasses("Ljava/lang/Number;");
        assert_eq!(subs, ["Ljava/lang/Integer;"]);
    }

    #[test]
    fn test_all_subclasses() {
        let h = build_simple_hierarchy();
        let subs = h.all_subclasses("Ljava/lang/Number;");
        assert!(subs.contains(&"Ljava/lang/Integer;".to_string()));
        assert!(subs.contains(&"Lcom/example/MyInt;".to_string()));
    }

    #[test]
    fn test_ancestors() {
        let h = build_simple_hierarchy();
        let ancs = h.ancestors("Lcom/example/MyInt;");
        assert_eq!(ancs[0], "Ljava/lang/Integer;");
        assert!(ancs.contains(&"Ljava/lang/Object;".to_string()));
    }

    #[test]
    fn test_is_subtype_of_direct() {
        let h = build_simple_hierarchy();
        assert!(h.is_subtype_of(
            "Ljava/lang/Integer;",
            "Ljava/lang/Number;"
        ));
    }

    #[test]
    fn test_is_subtype_of_transitive() {
        let h = build_simple_hierarchy();
        assert!(h.is_subtype_of(
            "Lcom/example/MyInt;",
            "Ljava/lang/Object;"
        ));
    }

    #[test]
    fn test_is_subtype_of_interface() {
        let h = build_simple_hierarchy();
        assert!(h.is_subtype_of(
            "Ljava/lang/Integer;",
            "Ljava/lang/Comparable;"
        ));
    }

    #[test]
    fn test_is_subtype_of_self() {
        let h = build_simple_hierarchy();
        assert!(h.is_subtype_of("Ljava/lang/Integer;", "Ljava/lang/Integer;"));
    }

    #[test]
    fn test_is_not_subtype() {
        let h = build_simple_hierarchy();
        assert!(!h.is_subtype_of("Ljava/lang/Object;", "Ljava/lang/Integer;"));
    }

    #[test]
    fn test_implementors_of() {
        let h = build_simple_hierarchy();
        let impls = h.implementors_of("Ljava/lang/Comparable;");
        assert!(impls.contains(&"Ljava/lang/Integer;".to_string()));
    }

    #[test]
    fn test_all_implementors_includes_subclass() {
        let h = build_simple_hierarchy();
        let all = h.all_implementors("Ljava/lang/Comparable;");
        assert!(all.contains(&"Lcom/example/MyInt;".to_string()));
    }

    #[test]
    fn test_search_by_name() {
        let h = build_simple_hierarchy();
        let found = h.search_by_name("integer");
        assert!(found.iter().any(|n| n.descriptor == "Ljava/lang/Integer;"));
    }

    #[test]
    fn test_class_node_simple_name() {
        let n = make_node("Lcom/example/FooBar;", None, &[]);
        assert_eq!(n.simple_name(), "FooBar");
    }

    #[test]
    fn test_class_node_package_name() {
        let n = make_node("Lcom/example/FooBar;", None, &[]);
        assert_eq!(n.package_name(), "com.example");
    }

    #[test]
    fn test_interface_set_contains() {
        let mut s = InterfaceSet::new();
        s.add("Ljava/io/Serializable;".to_string());
        assert!(s.contains("Ljava/io/Serializable;"));
        assert!(!s.contains("Ljava/lang/Cloneable;"));
    }

    #[test]
    fn test_interface_set_no_duplicates() {
        let mut s = InterfaceSet::new();
        s.add("Ljava/io/Serializable;".to_string());
        s.add("Ljava/io/Serializable;".to_string());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_read_uleb128_single_byte() {
        let data = [0x05u8];
        let (val, adv) = read_uleb128(&data, 0);
        assert_eq!(val, 5);
        assert_eq!(adv, 1);
    }

    #[test]
    fn test_read_uleb128_multi_byte() {
        // 300 in ULEB128: 0xAC 0x02
        let data = [0xACu8, 0x02];
        let (val, adv) = read_uleb128(&data, 0);
        assert_eq!(val, 300);
        assert_eq!(adv, 2);
    }
}
