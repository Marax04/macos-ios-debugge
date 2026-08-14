//! Class-hierarchy type recovery from vtable evidence.
//!
//! `rustre-analysis-vtable` (a sibling crate) detects vtables and decodes
//! RTTI, but is deliberately NOT a dependency of this crate (the workspace
//! wiring goes decompiler → decompiler-type; adding analysis crates here
//! would tangle the graph).  Instead this module defines a small,
//! dependency-free input interface — [`VtableClassInput`] — that the caller
//! (rustre-decompiler) can populate from `rustre_analysis_vtable::Vtable` /
//! `RttiInfo` results, and turns it into:
//!
//! * a class-hierarchy graph (roots, direct bases, derived classes),
//! * a `struct` layout per class with a leading `__vftable` pointer field,
//!   inheriting base-class fields at offset 0 (single inheritance) or at the
//!   recorded base offset (multiple inheritance).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{DecompType, StructField, StructType};

/// Vtable-derived evidence for one class, as supplied by the caller.
///
/// This mirrors what `rustre-analysis-vtable` recovers (class name from RTTI,
/// vtable address, virtual-method slots, base-class names with offsets)
/// without depending on that crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableClassInput {
    /// Demangled class name (from RTTI) or a synthetic `class_<vtable_addr>`.
    pub class_name: String,
    /// Address of the vtable in the binary.
    pub vtable_addr: u64,
    /// Virtual method target addresses, in slot order.
    pub method_addrs: Vec<u64>,
    /// Direct base classes as `(name, offset_in_derived)` pairs.
    /// Single inheritance is `[(base, 0)]`.
    pub bases: Vec<(String, u64)>,
    /// Known instance size in bytes, if any (0 = unknown).
    pub instance_size: u64,
}

impl VtableClassInput {
    /// Convenience constructor for a class with no known bases.
    #[must_use]
    pub fn root(class_name: impl Into<String>, vtable_addr: u64, method_addrs: Vec<u64>) -> Self {
        Self {
            class_name: class_name.into(),
            vtable_addr,
            method_addrs,
            bases: Vec::new(),
            instance_size: 0,
        }
    }

    /// Builder: add a direct base class at the given offset.
    #[must_use]
    pub fn with_base(mut self, base: impl Into<String>, offset: u64) -> Self {
        self.bases.push((base.into(), offset));
        self
    }

    /// Builder: set the known instance size.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.instance_size = size;
        self
    }
}

/// One node in the recovered class hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassNode {
    pub name: String,
    pub vtable_addr: u64,
    /// Number of virtual-method slots in this class's vtable.
    pub method_count: usize,
    /// Direct bases (names).
    pub bases: Vec<String>,
    /// Direct derived classes (names), filled in by the builder.
    pub derived: Vec<String>,
    /// Method slots this class introduces or overrides relative to its
    /// primary base (slots beyond the base's count, plus differing targets).
    pub new_or_overridden_slots: Vec<usize>,
}

/// The recovered hierarchy over all supplied classes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClassHierarchy {
    nodes: BTreeMap<String, ClassNode>,
    inputs: HashMap<String, VtableClassInput>,
}

impl ClassHierarchy {
    /// Build the hierarchy from vtable evidence.
    ///
    /// Bases that were never supplied as inputs are still recorded as edge
    /// targets but get no node (they are external / unrecovered classes).
    #[must_use]
    pub fn build(inputs: Vec<VtableClassInput>) -> Self {
        let mut nodes: BTreeMap<String, ClassNode> = BTreeMap::new();
        let mut input_map: HashMap<String, VtableClassInput> = HashMap::new();

        for inp in &inputs {
            nodes.insert(
                inp.class_name.clone(),
                ClassNode {
                    name: inp.class_name.clone(),
                    vtable_addr: inp.vtable_addr,
                    method_count: inp.method_addrs.len(),
                    bases: inp.bases.iter().map(|(n, _)| n.clone()).collect(),
                    derived: Vec::new(),
                    new_or_overridden_slots: Vec::new(),
                },
            );
            input_map.insert(inp.class_name.clone(), inp.clone());
        }

        // Fill derived edges.
        let edges: Vec<(String, String)> = nodes
            .values()
            .flat_map(|n| n.bases.iter().map(move |b| (b.clone(), n.name.clone())))
            .collect();
        for (base, derived) in edges {
            if let Some(bn) = nodes.get_mut(&base) {
                bn.derived.push(derived);
            }
        }

        // Compute overridden/new slots vs. the primary (first, offset-0) base.
        let slot_info: Vec<(String, Vec<usize>)> = nodes
            .values()
            .map(|n| {
                let inp = &input_map[&n.name];
                let primary_base = inp
                    .bases
                    .iter()
                    .find(|(_, off)| *off == 0)
                    .and_then(|(b, _)| input_map.get(b));
                let slots = match primary_base {
                    None => (0..inp.method_addrs.len()).collect(),
                    Some(base) => inp
                        .method_addrs
                        .iter()
                        .enumerate()
                        .filter(|(i, addr)| {
                            base.method_addrs.get(*i) != Some(*addr)
                        })
                        .map(|(i, _)| i)
                        .collect(),
                };
                (n.name.clone(), slots)
            })
            .collect();
        for (name, slots) in slot_info {
            if let Some(n) = nodes.get_mut(&name) {
                n.new_or_overridden_slots = slots;
            }
        }

        Self {
            nodes,
            inputs: input_map,
        }
    }

    /// Look up a class node by name.
    #[must_use]
    pub fn node(&self, name: &str) -> Option<&ClassNode> {
        self.nodes.get(name)
    }

    /// All class names, sorted.
    #[must_use]
    pub fn class_names(&self) -> Vec<&String> {
        self.nodes.keys().collect()
    }

    /// Classes with no recovered base (hierarchy roots).
    #[must_use]
    pub fn roots(&self) -> Vec<&ClassNode> {
        self.nodes
            .values()
            .filter(|n| n.bases.iter().all(|b| !self.nodes.contains_key(b)))
            .collect()
    }

    /// True if `derived` transitively inherits from `base`.
    #[must_use]
    pub fn is_derived_from(&self, derived: &str, base: &str) -> bool {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = vec![derived];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if let Some(n) = self.nodes.get(cur) {
                for b in &n.bases {
                    if b == base {
                        return true;
                    }
                    stack.push(b.as_str());
                }
            }
        }
        false
    }

    /// Emit a `StructType` layout for one class:
    ///
    /// * `__vftable` function-pointer-table pointer at offset 0 (only for
    ///   classes that own a vtable and whose primary base does not already
    ///   provide the slot),
    /// * one `base_<Name>` embedded field per non-primary base at its offset,
    /// * total size = known `instance_size`, else the minimal cover.
    #[must_use]
    pub fn struct_for(&self, name: &str, ptr_bytes: u64) -> Option<StructType> {
        let inp = self.inputs.get(name)?;
        let mut fields: Vec<StructField> = Vec::new();

        let primary_base = inp.bases.iter().find(|(_, off)| *off == 0);
        if let Some((base_name, _)) = primary_base {
            fields.push(StructField::new(
                0,
                format!("base_{base_name}"),
                self.base_field_type(base_name, ptr_bytes),
            ));
        } else {
            fields.push(StructField::new(
                0,
                "__vftable",
                DecompType::Ptr(Box::new(DecompType::Ptr(Box::new(DecompType::Void)))),
            ));
        }

        for (base_name, off) in &inp.bases {
            if *off == 0 {
                continue; // primary base already emitted
            }
            fields.push(StructField::new(
                *off,
                format!("base_{base_name}"),
                self.base_field_type(base_name, ptr_bytes),
            ));
        }

        let min_size = fields
            .iter()
            .map(|f| f.offset + f.ty.byte_size().unwrap_or(ptr_bytes))
            .max()
            .unwrap_or(ptr_bytes);
        let total_size = if inp.instance_size > 0 {
            inp.instance_size.max(min_size)
        } else {
            min_size
        };

        Some(StructType::new(name, fields, total_size))
    }

    fn base_field_type(&self, base_name: &str, ptr_bytes: u64) -> DecompType {
        self.struct_for(base_name, ptr_bytes).map_or(
            // Unknown external base: opaque pointer-sized blob.
            DecompType::Array(
                Box::new(DecompType::Int(rustre_decompiler_expr::IntWidth::U8)),
                ptr_bytes,
            ),
            |st| DecompType::Struct(Box::new(st)),
        )
    }

    /// Emit `StructType`s for every recovered class.
    #[must_use]
    pub fn all_structs(&self, ptr_bytes: u64) -> Vec<StructType> {
        self.nodes
            .keys()
            .filter_map(|n| self.struct_for(n, ptr_bytes))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diamond_free_inputs() -> Vec<VtableClassInput> {
        vec![
            VtableClassInput::root("Animal", 0x1000, vec![0xA0, 0xA1, 0xA2]).with_size(16),
            VtableClassInput::root("Dog", 0x2000, vec![0xA0, 0xB1, 0xA2, 0xB3])
                .with_base("Animal", 0)
                .with_size(24),
            VtableClassInput::root("Cat", 0x3000, vec![0xA0, 0xC1, 0xA2])
                .with_base("Animal", 0),
        ]
    }

    #[test]
    fn build_links_derived() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let animal = h.node("Animal").unwrap();
        let mut derived = animal.derived.clone();
        derived.sort();
        assert_eq!(derived, vec!["Cat".to_string(), "Dog".to_string()]);
        assert_eq!(h.node("Dog").unwrap().bases, vec!["Animal".to_string()]);
    }

    #[test]
    fn roots_detected() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let roots: Vec<&str> = h.roots().iter().map(|n| n.name.as_str()).collect();
        assert_eq!(roots, vec!["Animal"]);
    }

    #[test]
    fn transitive_inheritance() {
        let mut inputs = diamond_free_inputs();
        inputs.push(
            VtableClassInput::root("Puppy", 0x4000, vec![0xA0, 0xB1, 0xA2, 0xB3])
                .with_base("Dog", 0),
        );
        let h = ClassHierarchy::build(inputs);
        assert!(h.is_derived_from("Puppy", "Dog"));
        assert!(h.is_derived_from("Puppy", "Animal"));
        assert!(h.is_derived_from("Dog", "Animal"));
        assert!(!h.is_derived_from("Animal", "Dog"));
        assert!(!h.is_derived_from("Cat", "Dog"));
    }

    #[test]
    fn overridden_slots_vs_primary_base() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        // Dog overrides slot 1 and adds slot 3; slots 0 and 2 are inherited.
        assert_eq!(h.node("Dog").unwrap().new_or_overridden_slots, vec![1, 3]);
        // Root class: every slot is new.
        assert_eq!(
            h.node("Animal").unwrap().new_or_overridden_slots,
            vec![0, 1, 2]
        );
    }

    #[test]
    fn root_struct_has_vftable_ptr() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let st = h.struct_for("Animal", 8).unwrap();
        assert_eq!(st.fields[0].name, "__vftable");
        assert_eq!(st.fields[0].offset, 0);
        assert!(st.fields[0].ty.is_pointer());
        assert_eq!(st.total_size, 16);
    }

    #[test]
    fn derived_struct_embeds_primary_base() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let st = h.struct_for("Dog", 8).unwrap();
        assert_eq!(st.fields[0].name, "base_Animal");
        assert_eq!(st.fields[0].offset, 0);
        assert!(matches!(&st.fields[0].ty, DecompType::Struct(s) if s.name == "Animal"));
        assert_eq!(st.total_size, 24);
    }

    #[test]
    fn multiple_inheritance_secondary_base_at_offset() {
        let inputs = vec![
            VtableClassInput::root("A", 0x1000, vec![0xA0]).with_size(8),
            VtableClassInput::root("B", 0x2000, vec![0xB0]).with_size(8),
            VtableClassInput::root("C", 0x3000, vec![0xA0, 0xC1])
                .with_base("A", 0)
                .with_base("B", 8)
                .with_size(24),
        ];
        let h = ClassHierarchy::build(inputs);
        let st = h.struct_for("C", 8).unwrap();
        assert_eq!(st.fields.len(), 2);
        assert_eq!(st.fields[0].name, "base_A");
        assert_eq!(st.fields[1].name, "base_B");
        assert_eq!(st.fields[1].offset, 8);
        assert_eq!(st.total_size, 24);
        assert!(h.is_derived_from("C", "A"));
        assert!(h.is_derived_from("C", "B"));
    }

    #[test]
    fn unknown_external_base_is_opaque_blob() {
        let inputs = vec![
            VtableClassInput::root("Widget", 0x1000, vec![0xA0]).with_base("QObject", 0),
        ];
        let h = ClassHierarchy::build(inputs);
        // QObject was never supplied, so Widget is still a root of the
        // *recovered* hierarchy and its base field is an opaque blob.
        assert_eq!(h.roots().len(), 1);
        let st = h.struct_for("Widget", 8).unwrap();
        assert_eq!(st.fields[0].name, "base_QObject");
        assert!(matches!(st.fields[0].ty, DecompType::Array(_, 8)));
    }

    #[test]
    fn all_structs_covers_every_class() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let all = h.all_structs(8);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn serde_round_trip() {
        let h = ClassHierarchy::build(diamond_free_inputs());
        let json = serde_json::to_string(&h.node("Dog").unwrap()).unwrap();
        let back: ClassNode = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, h.node("Dog").unwrap());
    }
}
