//! Virtual method override tracking across a C++ class hierarchy.
//!
//! Given a set of recovered vtables linked by an inheritance graph, this module
//! determines — for each virtual method slot — which subclass overrides the
//! base-class implementation.
//!
//! The analysis is structured as follows:
//!
//! 1. **`OverrideMap`** — a flat mapping from `(class_name, slot_index)` to
//!    the method address and an optional resolved function name.
//! 2. **`OverrideDiff`** — the difference between a base vtable slot and the
//!    corresponding derived vtable slot (identifies overrides vs. inherited
//!    implementations).
//! 3. **`OverrideAnalyzer`** — orchestrates the comparison of base vs. derived
//!    vtables to build a complete `OverrideMap`.
//! 4. **`MethodSlot`** — a rich record describing one virtual method slot
//!    across the hierarchy: the original definer, the current implementation,
//!    and the override chain.
//! 5. **`OverrideStats`** — aggregate statistics (total slots, overridden slots,
//!    pure-virtual slots, override depth).

use crate::{Vtable, VtableDatabase, VtableEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Core types
// ─────────────────────────────────────────────────────────────────────────────

/// A key uniquely identifying one virtual method slot within a class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotKey {
    /// Name of the class that owns this slot.
    pub class_name: String,
    /// Zero-based slot index within the vtable.
    pub slot_index: usize,
}

impl SlotKey {
    /// Create a new slot key.
    #[must_use]
    pub fn new(class_name: impl Into<String>, slot_index: usize) -> Self {
        Self {
            class_name: class_name.into(),
            slot_index,
        }
    }
}

impl std::fmt::Display for SlotKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}[{}]", self.class_name, self.slot_index)
    }
}

/// The state of a virtual method slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotState {
    /// The slot is overridden by this class (address differs from base).
    Overridden,
    /// The slot is inherited from the base class unchanged (same address).
    Inherited,
    /// The slot is a new virtual method not present in any base (first definer).
    New,
    /// The slot is a pure-virtual placeholder (zero or well-known stub address).
    PureVirtual,
}

impl std::fmt::Display for SlotState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overridden => write!(f, "overridden"),
            Self::Inherited => write!(f, "inherited"),
            Self::New => write!(f, "new"),
            Self::PureVirtual => write!(f, "pure-virtual"),
        }
    }
}

/// Information about one virtual method slot for a given class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSlot {
    /// Zero-based slot index.
    pub slot_index: usize,
    /// The method address in this class's vtable.
    pub address: u64,
    /// Optional demangled or symbol name for this address.
    pub name: Option<String>,
    /// The state of this slot relative to the immediate base class.
    pub state: SlotState,
    /// The class that first defined this virtual method (root definer).
    pub defining_class: String,
    /// The class that provides the current implementation (may be a parent).
    pub implementing_class: String,
    /// Override chain: list of class names that have successively overridden
    /// this slot, from root to the most-derived.
    pub override_chain: Vec<String>,
}

impl MethodSlot {
    /// Whether this slot is overridden in this class.
    #[must_use]
    pub fn is_overridden(&self) -> bool {
        self.state == SlotState::Overridden
    }

    /// Override depth (length of the override chain).
    #[must_use]
    pub const fn override_depth(&self) -> usize {
        self.override_chain.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverrideDiff — base vs. derived comparison for one slot
// ─────────────────────────────────────────────────────────────────────────────

/// The difference between a base and derived class for one virtual slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideDiff {
    /// Zero-based slot index.
    pub slot_index: usize,
    /// Address in the base class vtable.
    pub base_address: u64,
    /// Address in the derived class vtable.
    pub derived_address: u64,
    /// Name of the base class.
    pub base_class: String,
    /// Name of the derived class.
    pub derived_class: String,
    /// Function name in base vtable (if known).
    pub base_name: Option<String>,
    /// Function name in derived vtable (if known).
    pub derived_name: Option<String>,
    /// Whether the slot is truly overridden (addresses differ and derived
    /// address is a valid code address, not a pure-virtual stub).
    pub is_override: bool,
}

impl OverrideDiff {
    /// Return `true` if the derived class provides a new implementation.
    #[must_use]
    pub const fn overrides(&self) -> bool {
        self.is_override && self.base_address != self.derived_address
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverrideMap — flat map of all slot states across a class hierarchy
// ─────────────────────────────────────────────────────────────────────────────

/// A complete mapping of virtual method slot states across all classes.
///
/// Keyed by [`SlotKey`]; each entry is a [`MethodSlot`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideMap {
    /// All slot records, keyed by (class, `slot_index`).
    pub slots: HashMap<SlotKey, MethodSlot>,
    /// For each class, the ordered list of slot indices that are overridden.
    pub overrides_by_class: HashMap<String, Vec<usize>>,
}

impl OverrideMap {
    /// Create an empty `OverrideMap`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a slot record.
    pub fn insert(&mut self, key: SlotKey, slot: MethodSlot) {
        if slot.state == SlotState::Overridden {
            self.overrides_by_class
                .entry(key.class_name.clone())
                .or_default()
                .push(key.slot_index);
        }
        self.slots.insert(key, slot);
    }

    /// Look up a slot record.
    #[must_use]
    pub fn get(&self, key: &SlotKey) -> Option<&MethodSlot> {
        self.slots.get(key)
    }

    /// All slots for a given class, sorted by slot index.
    #[must_use]
    pub fn slots_for_class(&self, class_name: &str) -> Vec<&MethodSlot> {
        let mut result: Vec<&MethodSlot> = self
            .slots
            .iter()
            .filter(|(k, _)| k.class_name == class_name)
            .map(|(_, v)| v)
            .collect();
        result.sort_by_key(|s| s.slot_index);
        result
    }

    /// All slots that are overridden in `class_name`.
    #[must_use]
    pub fn overrides_in_class(&self, class_name: &str) -> Vec<&MethodSlot> {
        self.slots_for_class(class_name)
            .into_iter()
            .filter(|s| s.state == SlotState::Overridden)
            .collect()
    }

    /// All classes that override slot `slot_index`.
    #[must_use]
    pub fn overriders_of_slot(&self, slot_index: usize) -> Vec<&str> {
        self.slots
            .iter()
            .filter(|(k, v)| k.slot_index == slot_index && v.state == SlotState::Overridden)
            .map(|(k, _)| k.class_name.as_str())
            .collect()
    }

    /// Total number of slot records.
    #[must_use]
    pub fn total_slots(&self) -> usize {
        self.slots.len()
    }

    /// Number of slots with `SlotState::Overridden`.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.slots
            .values()
            .filter(|s| s.state == SlotState::Overridden)
            .count()
    }

    /// Number of slots with `SlotState::PureVirtual`.
    #[must_use]
    pub fn pure_virtual_count(&self) -> usize {
        self.slots
            .values()
            .filter(|s| s.state == SlotState::PureVirtual)
            .count()
    }

    /// Number of unique classes represented.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.slots
            .keys()
            .map(|k| k.class_name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Known pure-virtual stub addresses / names
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known pure-virtual stub names used to identify `= 0` slots.
const PURE_VIRTUAL_NAMES: &[&str] = &[
    "__cxa_pure_virtual",
    "_purecall",
    "___cxa_pure_virtual",
    "__pure_virtual",
];

/// Well-known pure-virtual sentinel addresses (architecture-dependent).
/// Callers may extend this via [`OverrideAnalyzer::add_pure_virtual_addr`].
const DEFAULT_PURE_VIRTUAL_ADDRESSES: &[u64] = &[0, u64::MAX];

fn is_pure_virtual_address(addr: u64, extra: &[u64]) -> bool {
    DEFAULT_PURE_VIRTUAL_ADDRESSES.contains(&addr) || extra.contains(&addr)
}

fn is_pure_virtual_entry(entry: &VtableEntry, extra_addrs: &[u64]) -> bool {
    if is_pure_virtual_address(entry.target_address, extra_addrs) {
        return true;
    }
    if let Some(name) = &entry.function_name {
        return PURE_VIRTUAL_NAMES.contains(&name.as_str());
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// OverrideAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for override analysis.
#[derive(Debug, Clone, Default)]
pub struct OverrideAnalyzerConfig {
    /// Additional addresses to treat as pure-virtual stubs.
    pub extra_pure_virtual_addrs: Vec<u64>,
    /// Whether to include inherited (unchanged) slots in the override map.
    pub include_inherited: bool,
    /// Whether to include new-method slots (not in any base).
    pub include_new: bool,
}

/// Analyses vtable relationships to produce an [`OverrideMap`].
pub struct OverrideAnalyzer {
    config: OverrideAnalyzerConfig,
}

impl Default for OverrideAnalyzer {
    fn default() -> Self {
        Self::new(OverrideAnalyzerConfig::default())
    }
}

impl OverrideAnalyzer {
    /// Create a new analyzer with the given configuration.
    #[must_use]
    pub const fn new(config: OverrideAnalyzerConfig) -> Self {
        Self { config }
    }

    /// Add a pure-virtual stub address.
    pub fn add_pure_virtual_addr(&mut self, addr: u64) {
        self.config.extra_pure_virtual_addrs.push(addr);
    }

    /// Compare `base_vt` with `derived_vt` and return the per-slot diffs.
    ///
    /// Only slots present in `base_vt` are compared; derived-only slots are
    /// identified separately.
    #[must_use]
    pub fn diff_vtables(&self, base_vt: &Vtable, derived_vt: &Vtable) -> Vec<OverrideDiff> {
        let base_name = base_vt.class_name.as_deref().unwrap_or("?base?");
        let derived_name = derived_vt.class_name.as_deref().unwrap_or("?derived?");
        let n = base_vt.entries.len().min(derived_vt.entries.len());

        (0..n)
            .map(|i| {
                let be = &base_vt.entries[i];
                let de = &derived_vt.entries[i];
                let is_override = be.target_address != de.target_address
                    && !is_pure_virtual_entry(de, &self.config.extra_pure_virtual_addrs);
                OverrideDiff {
                    slot_index: i,
                    base_address: be.target_address,
                    derived_address: de.target_address,
                    base_class: base_name.to_owned(),
                    derived_class: derived_name.to_owned(),
                    base_name: be.function_name.clone(),
                    derived_name: de.function_name.clone(),
                    is_override,
                }
            })
            .collect()
    }

    /// Build an [`OverrideMap`] for a single `(base, derived)` pair.
    ///
    /// This is the core of the analysis; callers building a full hierarchy
    /// should repeatedly call this function for each parent–child pair and
    /// merge the resulting maps.
    #[must_use]
    pub fn build_override_map_pair(&self, base_vt: &Vtable, derived_vt: &Vtable) -> OverrideMap {
        let mut map = OverrideMap::new();
        let diffs = self.diff_vtables(base_vt, derived_vt);
        let derived_class = derived_vt.class_name.as_deref().unwrap_or("?derived?");
        let base_class = base_vt.class_name.as_deref().unwrap_or("?base?");

        for diff in &diffs {
            let de = &derived_vt.entries[diff.slot_index];
            let is_pv = is_pure_virtual_entry(de, &self.config.extra_pure_virtual_addrs);
            let state = if is_pv {
                SlotState::PureVirtual
            } else if diff.is_override {
                SlotState::Overridden
            } else {
                SlotState::Inherited
            };

            if state == SlotState::Inherited && !self.config.include_inherited {
                continue;
            }

            let chain = if diff.is_override {
                vec![derived_class.to_owned()]
            } else {
                Vec::new()
            };

            let slot = MethodSlot {
                slot_index: diff.slot_index,
                address: de.target_address,
                name: de.function_name.clone(),
                state,
                defining_class: base_class.to_owned(),
                implementing_class: if diff.is_override {
                    derived_class.to_owned()
                } else {
                    base_class.to_owned()
                },
                override_chain: chain,
            };
            map.insert(SlotKey::new(derived_class, diff.slot_index), slot);
        }

        // New slots in derived (beyond the length of base vtable).
        if self.config.include_new {
            let base_len = base_vt.entries.len();
            for (i, de) in derived_vt.entries.iter().enumerate().skip(base_len) {
                let is_pv = is_pure_virtual_entry(de, &self.config.extra_pure_virtual_addrs);
                let state = if is_pv {
                    SlotState::PureVirtual
                } else {
                    SlotState::New
                };
                let slot = MethodSlot {
                    slot_index: i,
                    address: de.target_address,
                    name: de.function_name.clone(),
                    state,
                    defining_class: derived_class.to_owned(),
                    implementing_class: derived_class.to_owned(),
                    override_chain: Vec::new(),
                };
                map.insert(SlotKey::new(derived_class, i), slot);
            }
        }

        map
    }

    /// Build a complete [`OverrideMap`] from a [`VtableDatabase`] using the
    /// stored vtable-to-RTTI links to determine parent–child relationships.
    ///
    /// For each vtable whose RTTI records at least one base class, the analyzer
    /// attempts to find the base's vtable in the database and computes the diff.
    #[must_use]
    pub fn build_from_database(&self, db: &VtableDatabase) -> OverrideMap {
        let mut full_map = OverrideMap::new();

        // Iterate vtables in a deterministic order: HashMap iteration order is
        // not stable across runs, and the merge below is first-write-wins for
        // slots and order-sensitive for `overrides_by_class`.
        let mut ordered: Vec<(&u64, &Vtable)> = db.vtables.iter().collect();
        ordered.sort_by_key(|(addr, _)| **addr);
        for (vtable_addr, vtable) in ordered {
            // Only process vtables linked to RTTI.
            let Some(rtti) = db.rtti_for_vtable(*vtable_addr) else {
                continue;
            };

            for base_name in &rtti.base_classes {
                // Find the base vtable by class name.
                let Some(base_vt) = db.find_by_class(base_name).into_iter().next() else {
                    continue;
                };
                let pair_map = self.build_override_map_pair(base_vt, vtable);
                // Merge into the full map.
                for (key, slot) in pair_map.slots {
                    full_map.slots.entry(key).or_insert(slot);
                }
                for (class, idxs) in pair_map.overrides_by_class {
                    full_map
                        .overrides_by_class
                        .entry(class)
                        .or_default()
                        .extend(idxs);
                }
            }
        }

        full_map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverrideStats — aggregate statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over an [`OverrideMap`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideStats {
    /// Total (class, slot) records.
    pub total_slots: usize,
    /// Number of overridden slots.
    pub overridden: usize,
    /// Number of inherited (unchanged) slots.
    pub inherited: usize,
    /// Number of new-virtual slots (defined in derived, not in any base).
    pub new_virtual: usize,
    /// Number of pure-virtual slots.
    pub pure_virtual: usize,
    /// Number of unique classes represented.
    pub class_count: usize,
    /// Average number of overrides per class.
    pub avg_overrides_per_class: f64,
    /// Maximum override depth seen across all slots.
    pub max_override_depth: usize,
}

impl OverrideStats {
    /// Compute statistics from an [`OverrideMap`].
    #[must_use]
    pub fn compute(map: &OverrideMap) -> Self {
        let total_slots = map.slots.len();
        let mut overridden = 0;
        let mut inherited = 0;
        let mut new_virtual = 0;
        let mut pure_virtual = 0;
        let mut max_depth = 0;

        for slot in map.slots.values() {
            match slot.state {
                SlotState::Overridden => overridden += 1,
                SlotState::Inherited => inherited += 1,
                SlotState::New => new_virtual += 1,
                SlotState::PureVirtual => pure_virtual += 1,
            }
            max_depth = max_depth.max(slot.override_depth());
        }

        let class_count = map.class_count();
        let avg_overrides_per_class = if class_count > 0 {
            f64::from(u32::try_from(overridden).unwrap_or(u32::MAX)) / f64::from(u32::try_from(class_count).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        Self {
            total_slots,
            overridden,
            inherited,
            new_virtual,
            pure_virtual,
            class_count,
            avg_overrides_per_class,
            max_override_depth: max_depth,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Override chain reconstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstruct the full override chain for a specific slot across a hierarchy.
///
/// Given a list of vtables ordered from most-base to most-derived (i.e., the
/// path in the inheritance graph), returns the sequence of `(class_name, address)`
/// pairs where the slot address changes — i.e., each override in order.
#[must_use]
pub fn reconstruct_override_chain(
    vtables: &[&Vtable],
    slot_index: usize,
    extra_pure_virtual_addrs: &[u64],
) -> Vec<(String, u64)> {
    let mut chain: Vec<(String, u64)> = Vec::new();
    let mut last_addr: Option<u64> = None;

    for vt in vtables {
        if slot_index >= vt.entries.len() {
            continue;
        }
        let entry = &vt.entries[slot_index];
        let class = vt.class_name.as_deref().unwrap_or("?");
        let addr = entry.target_address;
        let is_pv = is_pure_virtual_entry(entry, extra_pure_virtual_addrs);

        if is_pv {
            continue;
        }

        if last_addr != Some(addr) {
            chain.push((class.to_owned(), addr));
            last_addr = Some(addr);
        }
    }
    chain
}

/// For each slot index, compute the set of classes that override it, across a
/// flat list of vtables.
///
/// Returns a `HashMap<slot_index, Vec<class_name>>` where the classes are
/// those whose vtable has a different address for that slot than the previous
/// class in `vtables`.
#[must_use]
pub fn all_slot_overriders(
    vtables: &[&Vtable],
    extra_pure_virtual_addrs: &[u64],
) -> HashMap<usize, Vec<String>> {
    let max_slots = vtables.iter().map(|vt| vt.entries.len()).max().unwrap_or(0);
    let mut result: HashMap<usize, Vec<String>> = HashMap::new();

    for slot in 0..max_slots {
        let chain = reconstruct_override_chain(vtables, slot, extra_pure_virtual_addrs);
        // The overriders are all entries after the first (first = definer).
        let overriders: Vec<String> = chain.into_iter().skip(1).map(|(c, _)| c).collect();
        if !overriders.is_empty() {
            result.insert(slot, overriders);
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// OverrideReport — human-readable summary
// ─────────────────────────────────────────────────────────────────────────────

/// A human-readable report of overrides in a class hierarchy.
#[derive(Debug, Clone)]
pub struct OverrideReport {
    /// All override diffs (base vs. derived), sorted by slot index.
    pub diffs: Vec<OverrideDiff>,
    /// Classes sorted by number of overrides (descending).
    pub most_overriding_classes: Vec<(String, usize)>,
    /// Slots that are overridden in the most classes.
    pub most_overridden_slots: Vec<(usize, usize)>,
}

impl OverrideReport {
    /// Build a report from a list of vtables ordered base → derived.
    #[must_use]
    pub fn build(base: &Vtable, derived: &Vtable, extra_pv: &[u64]) -> Self {
        let analyzer = OverrideAnalyzer::default();
        let diffs = analyzer.diff_vtables(base, derived);

        let derived_name = derived.class_name.as_deref().unwrap_or("?").to_owned();
        let override_count = diffs.iter().filter(|d| d.is_override).count();
        let most_overriding_classes = vec![(derived_name, override_count)];

        // Count how many classes override each slot (only one pair here).
        let most_overridden_slots: Vec<(usize, usize)> = diffs
            .iter()
            .filter(|d| d.is_override)
            .map(|d| (d.slot_index, 1usize))
            .collect();

        let _ = extra_pv; // used indirectly via analyzer config

        Self {
            diffs,
            most_overriding_classes,
            most_overridden_slots,
        }
    }

    /// Number of overriding slots in this report.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.diffs.iter().filter(|d| d.is_override).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vtable, VtableEntry};

    fn make_vtable(class: &str, entries: &[(u64, Option<&str>)]) -> Vtable {
        let mut vt = Vtable::new(0x1000);
        vt.class_name = Some(class.to_owned());
        for (i, (addr, name)) in entries.iter().enumerate() {
            let mut e = VtableEntry::new(i * 8, *addr);
            if let Some(n) = name {
                e.function_name = Some(n.to_string());
            }
            vt.add_entry(e);
        }
        vt
    }

    // ── SlotKey ──────────────────────────────────────────────────────────────

    #[test]
    fn test_slot_key_display() {
        let k = SlotKey::new("Foo", 2);
        assert_eq!(k.to_string(), "Foo[2]");
    }

    #[test]
    fn test_slot_key_equality() {
        let k1 = SlotKey::new("Bar", 0);
        let k2 = SlotKey::new("Bar", 0);
        assert_eq!(k1, k2);
        let k3 = SlotKey::new("Baz", 0);
        assert_ne!(k1, k3);
    }

    // ── SlotState display ────────────────────────────────────────────────────

    #[test]
    fn test_slot_state_display() {
        assert_eq!(SlotState::Overridden.to_string(), "overridden");
        assert_eq!(SlotState::Inherited.to_string(), "inherited");
        assert_eq!(SlotState::New.to_string(), "new");
        assert_eq!(SlotState::PureVirtual.to_string(), "pure-virtual");
    }

    // ── OverrideDiff ─────────────────────────────────────────────────────────

    #[test]
    fn test_override_diff_overrides() {
        let diff = OverrideDiff {
            slot_index: 0,
            base_address: 0x1000,
            derived_address: 0x2000,
            base_class: "Base".into(),
            derived_class: "Derived".into(),
            base_name: None,
            derived_name: None,
            is_override: true,
        };
        assert!(diff.overrides());
    }

    #[test]
    fn test_override_diff_not_override_when_same_addr() {
        let diff = OverrideDiff {
            slot_index: 0,
            base_address: 0x1000,
            derived_address: 0x1000,
            base_class: "Base".into(),
            derived_class: "Derived".into(),
            base_name: None,
            derived_name: None,
            is_override: false,
        };
        assert!(!diff.overrides());
    }

    // ── OverrideAnalyzer::diff_vtables ────────────────────────────────────────

    #[test]
    fn test_diff_vtables_no_override() {
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None), (0x1010, None)]);
        let analyzer = OverrideAnalyzer::default();
        let diffs = analyzer.diff_vtables(&base, &derived);
        assert_eq!(diffs.len(), 2);
        assert!(diffs.iter().all(|d| !d.is_override));
    }

    #[test]
    fn test_diff_vtables_one_override() {
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None), (0x2020, None)]);
        let analyzer = OverrideAnalyzer::default();
        let diffs = analyzer.diff_vtables(&base, &derived);
        assert_eq!(diffs.len(), 2);
        assert!(!diffs[0].is_override);
        assert!(diffs[1].is_override);
    }

    #[test]
    fn test_diff_vtables_pure_virtual_not_override() {
        let base = make_vtable("Base", &[(0x1000, None)]);
        // pure virtual address → should not count as override
        let derived = make_vtable("Derived", &[(0, Some("__cxa_pure_virtual"))]);
        let analyzer = OverrideAnalyzer::default();
        let diffs = analyzer.diff_vtables(&base, &derived);
        assert_eq!(diffs.len(), 1);
        assert!(!diffs[0].is_override);
    }

    #[test]
    fn test_diff_vtables_empty_base() {
        let base = make_vtable("Base", &[]);
        let derived = make_vtable("Derived", &[(0x2000, None)]);
        let analyzer = OverrideAnalyzer::default();
        let diffs = analyzer.diff_vtables(&base, &derived);
        assert!(diffs.is_empty()); // min(0, 1) = 0 comparisons
    }

    // ── OverrideAnalyzer::build_override_map_pair ─────────────────────────────

    #[test]
    fn test_build_override_map_pair_override() {
        let config = OverrideAnalyzerConfig {
            include_inherited: false,
            include_new: true,
            ..Default::default()
        };
        let analyzer = OverrideAnalyzer::new(config);
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None), (0x2020, None)]);
        let map = analyzer.build_override_map_pair(&base, &derived);
        // Slot 1 should be overridden.
        let key = SlotKey::new("Derived", 1);
        let slot = map.get(&key).unwrap();
        assert_eq!(slot.state, SlotState::Overridden);
        assert_eq!(slot.implementing_class, "Derived");
    }

    #[test]
    fn test_build_override_map_pair_new_slots() {
        let config = OverrideAnalyzerConfig {
            include_new: true,
            ..Default::default()
        };
        let analyzer = OverrideAnalyzer::new(config);
        let base = make_vtable("Base", &[(0x1000, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None), (0x3000, None)]);
        let map = analyzer.build_override_map_pair(&base, &derived);
        let key = SlotKey::new("Derived", 1);
        let slot = map.get(&key).unwrap();
        assert_eq!(slot.state, SlotState::New);
    }

    // ── OverrideMap methods ──────────────────────────────────────────────────

    #[test]
    fn test_override_map_override_count() {
        let mut map = OverrideMap::new();
        let slot = MethodSlot {
            slot_index: 0,
            address: 0x2000,
            name: None,
            state: SlotState::Overridden,
            defining_class: "Base".into(),
            implementing_class: "Derived".into(),
            override_chain: vec!["Derived".into()],
        };
        map.insert(SlotKey::new("Derived", 0), slot);
        assert_eq!(map.override_count(), 1);
        assert_eq!(map.total_slots(), 1);
    }

    #[test]
    fn test_override_map_overriders_of_slot() {
        let mut map = OverrideMap::new();
        for class in ["A", "B", "C"] {
            let slot = MethodSlot {
                slot_index: 2,
                address: 0x1000,
                name: None,
                state: SlotState::Overridden,
                defining_class: "Base".into(),
                implementing_class: class.into(),
                override_chain: Vec::new(),
            };
            map.insert(SlotKey::new(class, 2), slot);
        }
        let overriders = map.overriders_of_slot(2);
        assert_eq!(overriders.len(), 3);
    }

    #[test]
    fn test_override_map_pure_virtual_count() {
        let mut map = OverrideMap::new();
        let slot = MethodSlot {
            slot_index: 0,
            address: 0,
            name: Some("__cxa_pure_virtual".into()),
            state: SlotState::PureVirtual,
            defining_class: "Abstract".into(),
            implementing_class: "Abstract".into(),
            override_chain: Vec::new(),
        };
        map.insert(SlotKey::new("Concrete", 0), slot);
        assert_eq!(map.pure_virtual_count(), 1);
    }

    // ── OverrideStats ────────────────────────────────────────────────────────

    #[test]
    fn test_override_stats_empty() {
        let map = OverrideMap::new();
        let stats = OverrideStats::compute(&map);
        assert_eq!(stats.total_slots, 0);
        assert_eq!(stats.overridden, 0);
    }

    #[test]
    fn test_override_stats_basic() {
        let config = OverrideAnalyzerConfig {
            include_inherited: true,
            include_new: true,
            ..Default::default()
        };
        let analyzer = OverrideAnalyzer::new(config);
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None), (0x2020, None)]);
        let map = analyzer.build_override_map_pair(&base, &derived);
        let stats = OverrideStats::compute(&map);
        assert_eq!(stats.total_slots, 2);
        assert_eq!(stats.overridden, 1);
        assert_eq!(stats.inherited, 1);
    }

    // ── reconstruct_override_chain ────────────────────────────────────────────

    #[test]
    fn test_reconstruct_override_chain_basic() {
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let child = make_vtable("Child", &[(0x1000, None), (0x2020, None)]);
        let grandchild = make_vtable("GrandChild", &[(0x3030, None), (0x2020, None)]);
        let vts: Vec<&Vtable> = vec![&base, &child, &grandchild];
        // Slot 0: base=0x1000, child=0x1000 (unchanged), grandchild=0x3030 (override)
        let chain0 = reconstruct_override_chain(&vts, 0, &[]);
        assert_eq!(chain0.len(), 2); // Base and GrandChild
        // Slot 1: base=0x1010, child=0x2020 (override), grandchild=0x2020 (unchanged)
        let chain1 = reconstruct_override_chain(&vts, 1, &[]);
        assert_eq!(chain1.len(), 2); // Base and Child
    }

    #[test]
    fn test_reconstruct_override_chain_out_of_range() {
        let vt = make_vtable("Foo", &[(0x1000, None)]);
        let vts = vec![&vt];
        let chain = reconstruct_override_chain(&vts, 99, &[]);
        assert!(chain.is_empty());
    }

    // ── all_slot_overriders ───────────────────────────────────────────────────

    #[test]
    fn test_all_slot_overriders_basic() {
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x2000, None), (0x1010, None)]);
        let vts = vec![&base, &derived];
        let overriders = all_slot_overriders(&vts, &[]);
        // Slot 0 is overridden by Derived.
        assert!(overriders.contains_key(&0));
        assert!(overriders[&0].contains(&"Derived".to_owned()));
        // Slot 1 is not overridden.
        assert!(!overriders.contains_key(&1));
    }

    // ── OverrideReport ───────────────────────────────────────────────────────

    #[test]
    fn test_override_report_count() {
        let base = make_vtable("Base", &[(0x1000, None), (0x1010, None)]);
        let derived = make_vtable("Derived", &[(0x2000, None), (0x1010, None)]);
        let report = OverrideReport::build(&base, &derived, &[]);
        assert_eq!(report.override_count(), 1);
        assert_eq!(report.diffs.len(), 2);
    }

    #[test]
    fn test_override_report_zero_overrides() {
        let base = make_vtable("Base", &[(0x1000, None)]);
        let derived = make_vtable("Derived", &[(0x1000, None)]);
        let report = OverrideReport::build(&base, &derived, &[]);
        assert_eq!(report.override_count(), 0);
    }

    // ── is_pure_virtual helpers ───────────────────────────────────────────────

    #[test]
    fn test_is_pure_virtual_by_name() {
        let mut e = VtableEntry::new(0, 0x1234);
        e.function_name = Some("__cxa_pure_virtual".into());
        assert!(is_pure_virtual_entry(&e, &[]));
    }

    #[test]
    fn test_is_pure_virtual_by_address_zero() {
        let e = VtableEntry::new(0, 0);
        assert!(is_pure_virtual_entry(&e, &[]));
    }

    #[test]
    fn test_is_pure_virtual_extra_addr() {
        let e = VtableEntry::new(0, 0xDEAD_BEEF);
        assert!(!is_pure_virtual_entry(&e, &[]));
        assert!(is_pure_virtual_entry(&e, &[0xDEAD_BEEF]));
    }
}
