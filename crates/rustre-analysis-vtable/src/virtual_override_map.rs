//! Virtual method override map for C++ class hierarchies.
//!
//! Maps base class virtual methods to their derived-class overrides, tracks
//! inheritance chains, and detects override conflicts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── MethodSignature ───────────────────────────────────────────────────────────

/// Simplified C++ method signature for matching virtual overrides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodSignature {
    pub name: String,
    pub return_type: String,
    pub param_types: Vec<String>,
    pub is_const: bool,
}

impl MethodSignature {
    pub fn new(name: impl Into<String>, ret: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            return_type: ret.into(),
            param_types: Vec::new(),
            is_const: false,
        }
    }

    #[must_use] 
    pub fn with_params(mut self, params: Vec<String>) -> Self {
        self.param_types = params;
        self
    }

    #[must_use] 
    pub const fn with_const(mut self) -> Self {
        self.is_const = true;
        self
    }

    /// Two signatures match if they have the same name and param types.
    #[must_use] 
    pub fn matches(&self, other: &Self) -> bool {
        self.name == other.name && self.param_types == other.param_types
    }

    /// Return a mangled-style unique key.
    #[must_use] 
    pub fn key(&self) -> String {
        let params = self.param_types.join(",");
        format!(
            "{}({}){}",
            self.name,
            params,
            if self.is_const { " const" } else { "" }
        )
    }
}

impl std::fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params = self.param_types.join(", ");
        let c = if self.is_const { " const" } else { "" };
        write!(f, "{} {}({}){}", self.return_type, self.name, params, c)
    }
}

// ── OverrideRelation ──────────────────────────────────────────────────────────

/// One override relationship: a derived class method overrides a base class
/// method at the same vtable slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideRelation {
    /// Name of the base class.
    pub base_class: String,
    /// Virtual method offset (slot index × pointer size).
    pub base_method_offset: u32,
    /// Address of the base class implementation.
    pub base_method_addr: u64,
    /// Name of the derived class.
    pub derived_class: String,
    /// Address of the derived class override.
    pub derived_method_addr: u64,
    /// Signature of the overridden method.
    pub signature: Option<MethodSignature>,
    /// Whether the override is pure virtual (addr == 0 or `__cxa_pure_virtual`).
    pub is_pure: bool,
}

impl OverrideRelation {
    pub fn new(
        base_class: impl Into<String>,
        base_offset: u32,
        base_addr: u64,
        derived_class: impl Into<String>,
        derived_addr: u64,
    ) -> Self {
        Self {
            base_class: base_class.into(),
            base_method_offset: base_offset,
            base_method_addr: base_addr,
            derived_class: derived_class.into(),
            derived_method_addr: derived_addr,
            signature: None,
            is_pure: false,
        }
    }

    #[must_use] 
    pub fn with_signature(mut self, sig: MethodSignature) -> Self {
        self.signature = Some(sig);
        self
    }

    #[must_use] 
    pub const fn with_pure(mut self) -> Self {
        self.is_pure = true;
        self
    }

    /// Return `true` if the derived method is the same as the base method
    /// (no override — inherited unchanged).
    #[must_use] 
    pub const fn is_inherited(&self) -> bool {
        self.base_method_addr == self.derived_method_addr
    }
}

impl std::fmt::Display for OverrideRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{} → {}::{:#x} (slot+{:#x})",
            self.base_class,
            self.signature
                .as_ref()
                .map_or("<unknown>", |s| s.name.as_str()),
            self.derived_class,
            self.derived_method_addr,
            self.base_method_offset
        )
    }
}

// ── InheritanceChain ──────────────────────────────────────────────────────────

/// An ordered inheritance chain from a root base class down to a leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritanceChain {
    /// Ordered list of class names, outermost base first.
    pub classes: Vec<String>,
}

impl InheritanceChain {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            classes: vec![root.into()],
        }
    }

    #[must_use]
    pub fn extend(mut self, derived: impl Into<String>) -> Self {
        self.classes.push(derived.into());
        self
    }

    #[must_use] 
    pub const fn depth(&self) -> usize {
        self.classes.len()
    }

    #[must_use] 
    pub fn base(&self) -> Option<&str> {
        self.classes.first().map(std::string::String::as_str)
    }

    #[must_use] 
    pub fn leaf(&self) -> Option<&str> {
        self.classes.last().map(std::string::String::as_str)
    }

    #[must_use] 
    pub fn contains(&self, class: &str) -> bool {
        self.classes.iter().any(|c| c == class)
    }

    /// Return the direct parent of `class` in this chain, or `None`.
    #[must_use] 
    pub fn parent_of(&self, class: &str) -> Option<&str> {
        let idx = self.classes.iter().position(|c| c == class)?;
        if idx == 0 {
            None
        } else {
            Some(self.classes[idx - 1].as_str())
        }
    }
}

impl std::fmt::Display for InheritanceChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.classes.join(" → "))
    }
}

// ── OverrideConflict ──────────────────────────────────────────────────────────

/// Detected override conflict: two derived classes in the same hierarchy
/// override the same slot with different implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideConflict {
    pub base_class: String,
    pub slot_offset: u32,
    pub conflicting_overrides: Vec<(String, u64)>, // (class_name, method_addr)
}

impl OverrideConflict {
    #[must_use] 
    pub const fn severity(&self) -> &'static str {
        if self.conflicting_overrides.len() > 3 {
            "high"
        } else {
            "medium"
        }
    }
}

// ── VirtualOverrideMap ────────────────────────────────────────────────────────

/// Maps base class virtual methods to derived-class overrides.
pub struct VirtualOverrideMap {
    /// `base_class` → [(`slot_offset`, `base_addr`)]
    pub base_methods: HashMap<String, Vec<(u32, u64)>>,
    /// All registered override relations.
    pub overrides: Vec<OverrideRelation>,
    /// Inheritance chains.
    pub chains: Vec<InheritanceChain>,
}

impl VirtualOverrideMap {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            base_methods: HashMap::new(),
            overrides: Vec::new(),
            chains: Vec::new(),
        }
    }

    /// Register the vtable of a base class.
    ///
    /// `vtable` maps `(slot_offset, method_addr)` pairs.
    pub fn register_base(&mut self, class_name: impl Into<String>, vtable: Vec<(u32, u64)>) {
        self.base_methods.insert(class_name.into(), vtable);
    }

    /// Register a derived class's vtable and compute override relations against `base_class`.
    pub fn register_derived(
        &mut self,
        base_class: &str,
        derived_class: impl Into<String>,
        derived_vtable: &[(u32, u64)],
    ) {
        let derived_class = derived_class.into();
        let base_vtable = match self.base_methods.get(base_class) {
            Some(v) => v.clone(),
            None => return,
        };

        for (base_offset, base_addr) in &base_vtable {
            if let Some(&(_, derived_addr)) = derived_vtable.iter().find(|(o, _)| o == base_offset)
                && derived_addr != *base_addr {
                    self.overrides.push(OverrideRelation::new(
                        base_class,
                        *base_offset,
                        *base_addr,
                        &derived_class,
                        derived_addr,
                    ));
                }
        }
    }

    /// Add an inheritance chain.
    pub fn add_chain(&mut self, chain: InheritanceChain) {
        self.chains.push(chain);
    }

    /// Return all overrides for a given base class.
    #[must_use] 
    pub fn overrides_for_base(&self, base_class: &str) -> Vec<&OverrideRelation> {
        self.overrides
            .iter()
            .filter(|o| o.base_class == base_class)
            .collect()
    }

    /// Return all overrides provided by a given derived class.
    #[must_use] 
    pub fn overrides_by(&self, derived_class: &str) -> Vec<&OverrideRelation> {
        self.overrides
            .iter()
            .filter(|o| o.derived_class == derived_class)
            .collect()
    }

    /// Return overrides at a specific vtable slot offset.
    #[must_use] 
    pub fn overrides_at_slot(&self, offset: u32) -> Vec<&OverrideRelation> {
        self.overrides
            .iter()
            .filter(|o| o.base_method_offset == offset)
            .collect()
    }

    /// Detect override conflicts: slots where multiple derived classes provide
    /// different implementations.
    #[must_use] 
    pub fn detect_conflicts(&self) -> Vec<OverrideConflict> {
        // Group by (base_class, slot_offset).
        let mut groups: HashMap<(String, u32), Vec<(String, u64)>> = HashMap::new();
        for ov in &self.overrides {
            groups
                .entry((ov.base_class.clone(), ov.base_method_offset))
                .or_default()
                .push((ov.derived_class.clone(), ov.derived_method_addr));
        }
        let mut out: Vec<OverrideConflict> = groups
            .into_iter()
            .filter(|(_, impls)| {
                // Conflict = more than one unique address.
                let addrs: std::collections::HashSet<u64> = impls.iter().map(|(_, a)| *a).collect();
                addrs.len() > 1
            })
            .map(|((base, slot), impls)| OverrideConflict {
                base_class: base,
                slot_offset: slot,
                conflicting_overrides: impls,
            })
            .collect();
        // Deterministic order: HashMap into_iter order is unstable across runs.
        out.sort_by(|a, b| {
            a.base_class
                .cmp(&b.base_class)
                .then(a.slot_offset.cmp(&b.slot_offset))
        });
        out
    }

    /// Return the number of unique base classes tracked.
    #[must_use] 
    pub fn base_class_count(&self) -> usize {
        self.base_methods.len()
    }

    /// Return the total number of override relations.
    #[must_use] 
    pub const fn override_count(&self) -> usize {
        self.overrides.len()
    }

    /// Find the most overridden method slot across all base classes.
    #[must_use] 
    pub fn most_overridden_slot(&self) -> Option<(String, u32, usize)> {
        let mut counts: HashMap<(String, u32), usize> = HashMap::new();
        for ov in &self.overrides {
            *counts
                .entry((ov.base_class.clone(), ov.base_method_offset))
                .or_insert(0) += 1;
        }
        // Tie-break on the key itself: bare `max_by_key` over HashMap iteration
        // order returned an arbitrary winner among equal counts, making the
        // result nondeterministic across runs.
        counts
            .into_iter()
            .max_by(|((cls_a, slot_a), ca), ((cls_b, slot_b), cb)| {
                ca.cmp(cb)
                    .then_with(|| cls_b.cmp(cls_a)) // prefer lexicographically smaller class
                    .then_with(|| slot_b.cmp(slot_a)) // prefer smaller slot
            })
            .map(|((cls, slot), count)| (cls, slot, count))
    }

    /// Build a summary of override coverage per derived class.
    #[must_use] 
    pub fn coverage_summary(&self) -> HashMap<String, usize> {
        let mut summary: HashMap<String, usize> = HashMap::new();
        for ov in &self.overrides {
            *summary.entry(ov.derived_class.clone()).or_insert(0) += 1;
        }
        summary
    }
}

impl Default for VirtualOverrideMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base_vtable() -> Vec<(u32, u64)> {
        vec![(0, 0x1000), (8, 0x1010), (16, 0x1020)]
    }

    fn derived_vtable_partial() -> Vec<(u32, u64)> {
        // Overrides slot 0, inherits slots 8 and 16.
        vec![(0, 0x2000), (8, 0x1010), (16, 0x1020)]
    }

    fn derived_vtable_full() -> Vec<(u32, u64)> {
        vec![(0, 0x3000), (8, 0x3010), (16, 0x3020)]
    }

    fn make_map() -> VirtualOverrideMap {
        let mut m = VirtualOverrideMap::new();
        m.register_base("Animal", base_vtable());
        m.register_derived("Animal", "Dog", &derived_vtable_partial());
        m.register_derived("Animal", "Cat", &derived_vtable_full());
        m
    }

    // ── MethodSignature ───────────────────────────────────────────────────────

    #[test]
    fn test_sig_new() {
        let s = MethodSignature::new("speak", "void");
        assert_eq!(s.name, "speak");
        assert_eq!(s.return_type, "void");
    }

    #[test]
    fn test_sig_with_params() {
        let s = MethodSignature::new("move", "bool")
            .with_params(vec!["int".to_string(), "int".to_string()]);
        assert_eq!(s.param_types.len(), 2);
    }

    #[test]
    fn test_sig_with_const() {
        let s = MethodSignature::new("name", "string").with_const();
        assert!(s.is_const);
    }

    #[test]
    fn test_sig_matches_same() {
        let a = MethodSignature::new("speak", "void");
        let b = MethodSignature::new("speak", "int"); // different return type but same name/params
        assert!(a.matches(&b));
    }

    #[test]
    fn test_sig_not_matches_different_name() {
        let a = MethodSignature::new("speak", "void");
        let b = MethodSignature::new("run", "void");
        assert!(!a.matches(&b));
    }

    #[test]
    fn test_sig_key() {
        let s = MethodSignature::new("speak", "void");
        let k = s.key();
        assert!(k.starts_with("speak"));
    }

    #[test]
    fn test_sig_display() {
        let s = MethodSignature::new("speak", "void");
        let d = s.to_string();
        assert!(d.contains("speak"));
    }

    // ── OverrideRelation ──────────────────────────────────────────────────────

    #[test]
    fn test_override_relation_new() {
        let r = OverrideRelation::new("Animal", 0, 0x1000, "Dog", 0x2000);
        assert_eq!(r.base_class, "Animal");
        assert_eq!(r.derived_class, "Dog");
        assert_eq!(r.base_method_offset, 0);
    }

    #[test]
    fn test_override_relation_is_inherited() {
        let r = OverrideRelation::new("A", 0, 0x1000, "B", 0x1000);
        assert!(r.is_inherited());
        let r2 = OverrideRelation::new("A", 0, 0x1000, "B", 0x2000);
        assert!(!r2.is_inherited());
    }

    #[test]
    fn test_override_relation_display() {
        let r = OverrideRelation::new("A", 0, 0x1000, "B", 0x2000)
            .with_signature(MethodSignature::new("speak", "void"));
        let s = r.to_string();
        assert!(s.contains("speak"));
        assert!(s.contains('B'));
    }

    #[test]
    fn test_override_relation_with_pure() {
        let r = OverrideRelation::new("A", 0, 0, "B", 0).with_pure();
        assert!(r.is_pure);
    }

    // ── InheritanceChain ──────────────────────────────────────────────────────

    #[test]
    fn test_chain_new() {
        let c = InheritanceChain::new("Animal");
        assert_eq!(c.base(), Some("Animal"));
        assert_eq!(c.depth(), 1);
    }

    #[test]
    fn test_chain_extend() {
        let c = InheritanceChain::new("Animal")
            .extend("Dog")
            .extend("Puppy");
        assert_eq!(c.depth(), 3);
        assert_eq!(c.leaf(), Some("Puppy"));
    }

    #[test]
    fn test_chain_contains() {
        let c = InheritanceChain::new("A").extend("B").extend("C");
        assert!(c.contains("B"));
        assert!(!c.contains("Z"));
    }

    #[test]
    fn test_chain_parent_of() {
        let c = InheritanceChain::new("A").extend("B").extend("C");
        assert_eq!(c.parent_of("B"), Some("A"));
        assert_eq!(c.parent_of("A"), None);
        assert_eq!(c.parent_of("Z"), None);
    }

    #[test]
    fn test_chain_display() {
        let c = InheritanceChain::new("A").extend("B");
        assert_eq!(c.to_string(), "A → B");
    }

    // ── VirtualOverrideMap ────────────────────────────────────────────────────

    #[test]
    fn test_map_base_count() {
        let m = make_map();
        assert_eq!(m.base_class_count(), 1);
    }

    #[test]
    fn test_map_override_count() {
        let m = make_map();
        // Dog overrides slot 0; Cat overrides all 3.
        assert_eq!(m.override_count(), 4);
    }

    #[test]
    fn test_map_overrides_for_base() {
        let m = make_map();
        let ovs = m.overrides_for_base("Animal");
        assert_eq!(ovs.len(), 4);
    }

    #[test]
    fn test_map_overrides_by() {
        let m = make_map();
        let cat_ovs = m.overrides_by("Cat");
        assert_eq!(cat_ovs.len(), 3);
        let dog_ovs = m.overrides_by("Dog");
        assert_eq!(dog_ovs.len(), 1);
    }

    #[test]
    fn test_map_overrides_at_slot_0() {
        let m = make_map();
        let at_0 = m.overrides_at_slot(0);
        // Both Dog and Cat override slot 0.
        assert_eq!(at_0.len(), 2);
    }

    #[test]
    fn test_map_detect_conflicts() {
        let m = make_map();
        let conflicts = m.detect_conflicts();
        // Slot 0 has two different addresses (Dog=0x2000, Cat=0x3000).
        assert!(!conflicts.is_empty());
    }

    #[test]
    fn test_map_no_conflicts_single_derived() {
        let mut m = VirtualOverrideMap::new();
        m.register_base("A", vec![(0, 0x1000)]);
        m.register_derived("A", "B", &[(0, 0x2000)]);
        let conflicts = m.detect_conflicts();
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_map_most_overridden_slot() {
        let m = make_map();
        let (cls, slot, count) = m.most_overridden_slot().unwrap();
        assert_eq!(cls, "Animal");
        assert_eq!(slot, 0); // slot 0 has 2 overrides (Dog + Cat)
        assert_eq!(count, 2);
    }

    #[test]
    fn test_map_coverage_summary() {
        let m = make_map();
        let summary = m.coverage_summary();
        assert_eq!(*summary.get("Cat").unwrap(), 3);
        assert_eq!(*summary.get("Dog").unwrap(), 1);
    }

    #[test]
    fn test_map_add_chain() {
        let mut m = make_map();
        m.add_chain(InheritanceChain::new("Animal").extend("Dog"));
        assert_eq!(m.chains.len(), 1);
    }

    #[test]
    fn test_override_conflict_severity() {
        let c = OverrideConflict {
            base_class: "A".to_string(),
            slot_offset: 0,
            conflicting_overrides: vec![
                ("B".to_string(), 0x1000),
                ("C".to_string(), 0x2000),
                ("D".to_string(), 0x3000),
                ("E".to_string(), 0x4000),
            ],
        };
        assert_eq!(c.severity(), "high");
        let c2 = OverrideConflict {
            base_class: "A".to_string(),
            slot_offset: 0,
            conflicting_overrides: vec![("B".to_string(), 0x1000), ("C".to_string(), 0x2000)],
        };
        assert_eq!(c2.severity(), "medium");
    }

    #[test]
    fn test_most_overridden_slot_deterministic_tie() {
        // Regression: with equal counts, max_by_key over HashMap iteration
        // order returned an arbitrary winner. Ties must break deterministically
        // (lexicographically smallest class, then smallest slot).
        let mut m = VirtualOverrideMap::new();
        m.register_base("A", vec![(0, 0x1000)]);
        m.register_base("B", vec![(8, 0x1010)]);
        m.register_derived("A", "D1", &[(0, 0x2000)]);
        m.register_derived("B", "D2", &[(8, 0x3000)]);
        let first = m.most_overridden_slot().unwrap();
        assert_eq!(first, ("A".to_string(), 0, 1));
        for _ in 0..10 {
            assert_eq!(m.most_overridden_slot().unwrap(), first);
        }
    }

    #[test]
    fn test_detect_conflicts_sorted() {
        let mut m = VirtualOverrideMap::new();
        m.register_base("Z", vec![(0, 0x1)]);
        m.register_base("A", vec![(0, 0x1), (8, 0x2)]);
        m.register_derived("Z", "Z1", &[(0, 0x10)]);
        m.register_derived("Z", "Z2", &[(0, 0x20)]);
        m.register_derived("A", "A1", &[(0, 0x30), (8, 0x40)]);
        m.register_derived("A", "A2", &[(0, 0x50), (8, 0x60)]);
        let conflicts = m.detect_conflicts();
        let keys: Vec<(String, u32)> = conflicts
            .iter()
            .map(|c| (c.base_class.clone(), c.slot_offset))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "conflicts must be sorted");
        for _ in 0..5 {
            let again: Vec<(String, u32)> = m
                .detect_conflicts()
                .iter()
                .map(|c| (c.base_class.clone(), c.slot_offset))
                .collect();
            assert_eq!(again, keys);
        }
    }

    #[test]
    fn test_register_derived_unknown_base() {
        let mut m = VirtualOverrideMap::new();
        // Should not panic even if base is unknown.
        m.register_derived("NonExistentBase", "D", &[(0, 0x1000)]);
        assert_eq!(m.override_count(), 0);
    }
}
