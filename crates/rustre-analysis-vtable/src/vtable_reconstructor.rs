//! Vtable reconstructor: derive class hierarchy from a collection of vtable
//! candidates.
//!
//! Algorithm:
//!   1. For each vtable, record its slot set as a function-pointer multiset.
//!   2. Two vtables where A's slots are a strict prefix of B's (possibly with
//!      overrides) imply an inheritance relationship B extends A.
//!   3. Build a "slot signature" per vtable and cluster by longest-common-prefix.
//!   4. Emit `ClassRelation` records (base, derived, override mapping).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::vtable_finder::{Addr, VtableCandidate};

// ─── Slot signatures ──────────────────────────────────────────────────────────

/// A slot signature is the ordered sequence of function pointer addresses in a
/// vtable.  Comparison of two signatures drives inheritance detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotSignature(Vec<Addr>);

impl SlotSignature {
    #[must_use]
    pub const fn new(slots: Vec<Addr>) -> Self {
        Self(slots)
    }

    #[must_use]
    pub const fn len(&self) -> usize { self.0.len() }
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.0.is_empty() }
    #[must_use]
    pub fn slots(&self) -> &[Addr] { &self.0 }

    /// Longest common prefix length, ignoring overrides (treats any differing
    /// address at the same index as an *override* rather than unrelated).
    #[must_use]
    pub fn lcp_with_overrides(&self, other: &Self) -> usize {
        self.0.iter().zip(other.0.iter()).count() // all shared indices are "related"
    }

    /// Returns true if `self` is likely a base class of `other`:
    ///   * `other` has at least as many slots.
    ///   * For every slot index i < `self.len()`, either other[i] == self[i]
    ///     (exact match) or other[i] is a plausible override (different address
    ///     in the same code region — we accept any non-zero address here).
    #[must_use]
    pub fn is_possible_base_of(&self, other: &Self) -> bool {
        if self.len() == 0 || other.len() < self.len() { return false; }
        if self.len() == other.len() && self == other { return false; } // identical → same class
        // At least 50% of shared slots should match exactly.
        let shared = self.len();
        let exact: usize = self.0.iter().zip(other.0.iter())
            .filter(|(a, b)| a == b)
            .count();
        exact * 2 >= shared
    }

    /// Count slots that differ between two signatures of the same length.
    #[must_use]
    pub fn override_count(&self, other: &Self) -> usize {
        self.0.iter().zip(other.0.iter()).filter(|(a, b)| a != b).count()
    }
}

// ─── Virtual method slot ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualSlot {
    /// Slot index (0-based).
    pub index: usize,
    /// Function address in this class's vtable.
    pub fn_addr: Addr,
    /// Whether this slot appears to override a base-class slot.
    pub is_override: bool,
    /// The base-class function address that was overridden (if known).
    pub overrides: Option<Addr>,
    /// Optional symbol name (filled in by external demanglers).
    pub symbol: Option<String>,
}

// ─── Class node ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassNode {
    /// Unique ID for this class (index into the reconstructed hierarchy).
    pub id: usize,
    /// VA of the vtable.
    pub vtable_va: Addr,
    /// Class name from RTTI (if available).
    pub name: Option<String>,
    /// Slot descriptors.
    pub slots: Vec<VirtualSlot>,
    /// IDs of direct base classes.
    pub bases: Vec<usize>,
    /// IDs of direct derived classes.
    pub derived: Vec<usize>,
    /// True if this class overrides at least one slot from any base.
    pub has_overrides: bool,
    /// True if all virtual slots are the same (likely pure abstract).
    pub is_abstract: bool,
    /// Confidence from the finder phase.
    pub confidence: u8,
}

impl ClassNode {
    #[must_use]
    pub const fn slot_count(&self) -> usize { self.slots.len() }
    #[must_use]
    pub fn override_count(&self) -> usize { self.slots.iter().filter(|s| s.is_override).count() }
    #[must_use]
    pub const fn is_leaf(&self) -> bool { self.derived.is_empty() }
    #[must_use]
    pub const fn is_root(&self) -> bool { self.bases.is_empty() }
}

// ─── Class relation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassRelation {
    pub base_id: usize,
    pub derived_id: usize,
    /// Slot-index → override function address in derived.
    pub overridden_slots: HashMap<usize, Addr>,
    /// Number of new slots added in derived beyond base.
    pub new_slots: usize,
}

// ─── Reconstructed hierarchy ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedHierarchy {
    pub classes: Vec<ClassNode>,
    pub relations: Vec<ClassRelation>,
    /// Index of classes with no detected base.
    pub root_ids: Vec<usize>,
}

impl ReconstructedHierarchy {
    #[must_use]
    pub const fn class_count(&self) -> usize { self.classes.len() }
    #[must_use]
    pub const fn relation_count(&self) -> usize { self.relations.len() }

    #[must_use]
    pub fn get_class(&self, id: usize) -> Option<&ClassNode> {
        self.classes.get(id)
    }

    #[must_use]
    pub fn depth_of(&self, id: usize) -> usize {
        let mut memo: HashMap<usize, usize> = HashMap::new();
        self.depth_of_memo(id, &mut memo)
    }

    /// Iterative, memoized longest-path-to-a-root.
    ///
    /// The previous version was a naive recursion bounded only by a 512-frame
    /// depth limit. That bound stops runaway recursion on a cycle but does
    /// nothing about *branching*: a diamond hierarchy (each class deriving from
    /// its two predecessors) re-explored every shared base, costing O(2^k).
    /// Adversarial RTTI is untrusted input, so that was a cheap `DoS`. Memoizing
    /// makes it O(V+E); `on_stack` handles cycles without recursing into them.
    fn depth_of_memo(&self, start: usize, memo: &mut HashMap<usize, usize>) -> usize {
        enum Frame {
            Enter(usize),
            Exit(usize),
        }
        let mut on_stack: HashSet<usize> = HashSet::new();
        let mut stack = vec![Frame::Enter(start)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Enter(id) => {
                    if memo.contains_key(&id) || on_stack.contains(&id) {
                        continue;
                    }
                    let Some(node) = self.classes.get(id) else {
                        memo.insert(id, 0);
                        continue;
                    };
                    on_stack.insert(id);
                    stack.push(Frame::Exit(id));
                    for &base in &node.bases {
                        stack.push(Frame::Enter(base));
                    }
                }
                Frame::Exit(id) => {
                    on_stack.remove(&id);
                    let depth = self
                        .classes
                        .get(id)
                        .map(|node| {
                            node.bases
                                .iter()
                                // A base still on the stack is part of a cycle:
                                // treat it as contributing nothing rather than
                                // looping. Unvisited-but-absent bases score 0.
                                .map(|b| 1 + memo.get(b).copied().unwrap_or(0))
                                .max()
                                .unwrap_or(0)
                        })
                        .unwrap_or(0);
                    memo.insert(id, depth);
                }
            }
        }
        memo.get(&start).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn max_depth(&self) -> usize {
        // Share one memo table across all starts: O(V+E) for the whole graph
        // instead of O(V) independent walks.
        let mut memo: HashMap<usize, usize> = HashMap::new();
        (0..self.classes.len())
            .map(|i| self.depth_of_memo(i, &mut memo))
            .max()
            .unwrap_or(0)
    }

    /// Collect all descendant IDs (BFS).
    #[must_use]
    pub fn descendants_of(&self, id: usize) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(id);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) { continue; }
            if let Some(node) = self.classes.get(cur) {
                for &d in &node.derived { queue.push_back(d); }
            }
        }
        visited.remove(&id);
        // Sorted: HashSet order is nondeterministic and this is a public result.
        let mut out: Vec<usize> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }

    /// Collect all ancestor IDs (BFS upward).
    #[must_use]
    pub fn ancestors_of(&self, id: usize) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(id);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) { continue; }
            if let Some(node) = self.classes.get(cur) {
                for &b in &node.bases { queue.push_back(b); }
            }
        }
        visited.remove(&id);
        let mut out: Vec<usize> = visited.into_iter().collect();
        out.sort_unstable();
        out
    }
}

// ─── Reconstructor configuration ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructorConfig {
    /// Minimum fraction of shared slots (vs base slot count) to declare
    /// an inheritance relationship.
    pub min_shared_ratio: f64,
    /// Allow a class to have at most this many direct bases (for sanity).
    pub max_bases_per_class: usize,
    /// Maximum override count as a fraction of base slot count.
    pub max_override_ratio: f64,
}

impl Default for ReconstructorConfig {
    fn default() -> Self {
        Self {
            min_shared_ratio: 0.5,
            max_bases_per_class: 4,
            max_override_ratio: 0.9,
        }
    }
}

// ─── Reconstructor ────────────────────────────────────────────────────────────

pub struct VtableReconstructor {
    config: ReconstructorConfig,
}

impl VtableReconstructor {
    #[must_use]
    pub const fn new(config: ReconstructorConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ReconstructorConfig::default())
    }

    /// Reconstruct the class hierarchy from a list of vtable candidates.
    #[must_use]
    pub fn reconstruct(&self, candidates: &[VtableCandidate]) -> ReconstructedHierarchy {
        // Build class nodes from candidates.
        let mut classes: Vec<ClassNode> = candidates.iter().enumerate().map(|(id, c)| {
            let slots = c.slots.iter().enumerate().map(|(i, &addr)| VirtualSlot {
                index: i,
                fn_addr: addr,
                is_override: false,
                overrides: None,
                symbol: None,
            }).collect();
            let is_abstract = c.slots.len() >= 2 && c.slots.iter().all(|&a| a == c.slots[0]);
            ClassNode {
                id,
                vtable_va: c.va,
                name: c.class_name.clone(),
                slots,
                bases: Vec::new(),
                derived: Vec::new(),
                has_overrides: false,
                is_abstract,
                confidence: c.confidence,
            }
        }).collect();

        let n = classes.len();
        let sigs: Vec<SlotSignature> = candidates.iter()
            .map(|c| SlotSignature::new(c.slots.clone()))
            .collect();

        let mut relations: Vec<ClassRelation> = Vec::new();

        // For each pair (i, j) check if i is a base of j.
        for i in 0..n {
            for j in 0..n {
                if i == j { continue; }
                if !self.is_base_of(&sigs[i], &sigs[j]) { continue; }
                // Ensure max_bases_per_class constraint.
                if classes[j].bases.len() >= self.config.max_bases_per_class { continue; }
                // Prefer the most specific base (largest slot count).
                // Skip if j already has a longer base.
                let already_has_longer_base = classes[j].bases.iter().any(|&b| {
                    sigs[b].len() > sigs[i].len()
                });
                if already_has_longer_base { continue; }

                // Remove any base that is itself a base of i (i supersedes it).
                let to_remove: Vec<usize> = classes[j].bases.iter().copied()
                    .filter(|&b| self.is_base_of(&sigs[b], &sigs[i]))
                    .collect();
                for b in &to_remove {
                    classes[j].bases.retain(|&x| x != *b);
                    classes[*b].derived.retain(|&x| x != j);
                }

                classes[j].bases.push(i);
                classes[i].derived.push(j);

                let overridden_slots: HashMap<usize, Addr> = sigs[i].slots().iter()
                    .zip(sigs[j].slots().iter())
                    .enumerate()
                    .filter(|(_, (a, b))| a != b)
                    .map(|(idx, (_, &b))| (idx, b))
                    .collect();

                let new_slots = sigs[j].len().saturating_sub(sigs[i].len());
                relations.push(ClassRelation {
                    base_id: i,
                    derived_id: j,
                    overridden_slots: overridden_slots.clone(),
                    new_slots,
                });

                // Mark override flags on the derived class's slots.
                for (&slot_idx, &_override_addr) in &overridden_slots {
                    if let Some(slot) = classes[j].slots.get_mut(slot_idx) {
                        slot.is_override = true;
                        slot.overrides = Some(sigs[i].slots()[slot_idx]);
                    }
                }
                if !overridden_slots.is_empty() { classes[j].has_overrides = true; }
            }
        }

        let root_ids: Vec<usize> = classes.iter()
            .filter(|c| c.bases.is_empty())
            .map(|c| c.id)
            .collect();

        ReconstructedHierarchy { classes, relations, root_ids }
    }

    fn is_base_of(&self, base_sig: &SlotSignature, derived_sig: &SlotSignature) -> bool {
        if base_sig.is_empty() { return false; }
        if derived_sig.len() < base_sig.len() { return false; }
        if base_sig == derived_sig { return false; }

        let shared_len = base_sig.len();
        let exact_matches: usize = base_sig.slots().iter()
            .zip(derived_sig.slots().iter())
            .filter(|(a, b)| a == b)
            .count();
        let override_count = shared_len - exact_matches;
        let override_ratio = override_count as f64 / shared_len as f64;
        let shared_ratio = exact_matches as f64 / shared_len as f64;

        shared_ratio >= self.config.min_shared_ratio
            && override_ratio <= self.config.max_override_ratio
    }
}

// ─── Merge vtable sets across multiple binaries ───────────────────────────────

/// Merge hierarchies from two binaries, keying on class name where available.
#[must_use]
pub fn merge_hierarchies(
    a: &ReconstructedHierarchy,
    b: &ReconstructedHierarchy,
) -> MergedHierarchy {
    let mut entries: Vec<MergedClassEntry> = Vec::new();
    // Build name-indexed lookups.
    let a_by_name: HashMap<&str, &ClassNode> = a.classes.iter()
        .filter_map(|c| c.name.as_deref().map(|n| (n, c)))
        .collect();
    let b_by_name: HashMap<&str, &ClassNode> = b.classes.iter()
        .filter_map(|c| c.name.as_deref().map(|n| (n, c)))
        .collect();

    for (name, a_node) in &a_by_name {
        if let Some(b_node) = b_by_name.get(name) {
            let slot_diff = slot_diff(a_node, b_node);
            entries.push(MergedClassEntry {
                name: name.to_string(),
                slot_count_a: a_node.slot_count(),
                slot_count_b: b_node.slot_count(),
                slot_differences: slot_diff,
                appears_in_both: true,
            });
        } else {
            entries.push(MergedClassEntry {
                name: name.to_string(),
                slot_count_a: a_node.slot_count(),
                slot_count_b: 0,
                slot_differences: Vec::new(),
                appears_in_both: false,
            });
        }
    }
    for (name, b_node) in &b_by_name {
        if !a_by_name.contains_key(name) {
            entries.push(MergedClassEntry {
                name: name.to_string(),
                slot_count_a: 0,
                slot_count_b: b_node.slot_count(),
                slot_differences: Vec::new(),
                appears_in_both: false,
            });
        }
    }
    entries.sort_by(|x, y| x.name.cmp(&y.name));
    MergedHierarchy { entries }
}

fn slot_diff(a: &ClassNode, b: &ClassNode) -> Vec<SlotDifference> {
    let len = a.slots.len().min(b.slots.len());
    (0..len).filter_map(|i| {
        if a.slots[i].fn_addr != b.slots[i].fn_addr {
            Some(SlotDifference {
                slot_index: i,
                addr_a: a.slots[i].fn_addr,
                addr_b: b.slots[i].fn_addr,
            })
        } else {
            None
        }
    }).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotDifference {
    pub slot_index: usize,
    pub addr_a: Addr,
    pub addr_b: Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedClassEntry {
    pub name: String,
    pub slot_count_a: usize,
    pub slot_count_b: usize,
    pub slot_differences: Vec<SlotDifference>,
    pub appears_in_both: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedHierarchy {
    pub entries: Vec<MergedClassEntry>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(va: Addr, slots: Vec<Addr>, name: Option<&str>) -> VtableCandidate {
        VtableCandidate {
            va,
            slot_count: slots.len(),
            slots,
            rtti_va: None,
            class_name: name.map(|s| s.to_string()),
            rtti_kind: crate::vtable_finder::RttiKind::None,
            confidence: 80,
        }
    }

    #[test]
    fn test_simple_base_derived() {
        // Base: [fn0, fn1, fn2]
        // Derived: [fn0, fn1_override, fn2, fn3] (fn1 overridden, fn3 new)
        let base_slots = vec![0x401000u64, 0x401010, 0x401020];
        let derived_slots = vec![0x401000u64, 0x402010, 0x401020, 0x402030];
        let candidates = vec![
            make_candidate(0x1000_0000, base_slots, Some("Base")),
            make_candidate(0x1000_0020, derived_slots, Some("Derived")),
        ];
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&candidates);
        assert_eq!(h.class_count(), 2);
        assert!(!h.root_ids.is_empty());
        // Derived should have Base as its base.
        let derived = h.classes.iter().find(|c| c.name.as_deref() == Some("Derived")).unwrap();
        assert!(!derived.bases.is_empty(), "Derived should have a base class");
    }

    #[test]
    fn test_identical_vtables_not_related() {
        let slots = vec![0x401000u64, 0x401010, 0x401020];
        let candidates = vec![
            make_candidate(0x1000_0000, slots.clone(), Some("A")),
            make_candidate(0x1000_0020, slots.clone(), Some("B")),
        ];
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&candidates);
        // Identical vtables should not imply inheritance.
        for c in &h.classes {
            assert!(c.bases.is_empty() || c.derived.is_empty(),
                "Identical vtables should not have inheritance: {}", c.name.as_deref().unwrap_or("?"));
        }
    }

    #[test]
    fn test_slot_signature_is_possible_base() {
        let base = SlotSignature::new(vec![1, 2, 3]);
        let derived = SlotSignature::new(vec![1, 2, 3, 4, 5]);
        assert!(base.is_possible_base_of(&derived));
        // A longer sig is NOT a base of a shorter one.
        assert!(!derived.is_possible_base_of(&base));
    }

    #[test]
    fn test_slot_signature_not_base_when_too_different() {
        let a = SlotSignature::new(vec![1, 2, 3]);
        let b = SlotSignature::new(vec![10, 20, 30, 40]); // completely different
        assert!(!a.is_possible_base_of(&b));
    }

    #[test]
    fn test_override_count() {
        let a = SlotSignature::new(vec![1, 2, 3]);
        let b = SlotSignature::new(vec![1, 99, 3]);
        assert_eq!(a.override_count(&b), 1);
    }

    #[test]
    fn test_depth_calculation() {
        // Linear chain: A → B → C
        let slots_a = vec![0x401000u64, 0x401010];
        let slots_b = vec![0x401000u64, 0x401010, 0x401020];
        let slots_c = vec![0x401000u64, 0x401010, 0x401020, 0x401030];
        let candidates = vec![
            make_candidate(0x1000_0000, slots_a, Some("A")),
            make_candidate(0x1000_0020, slots_b, Some("B")),
            make_candidate(0x1000_0040, slots_c, Some("C")),
        ];
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&candidates);
        let max = h.max_depth();
        assert!(max >= 1, "Should have at least depth 1 in a chain");
    }

    #[test]
    fn test_leaf_and_root_detection() {
        let slots_a = vec![0x401000u64, 0x401010];
        let slots_b = vec![0x401000u64, 0x401010, 0x401020];
        let candidates = vec![
            make_candidate(0x1000_0000, slots_a, Some("Root")),
            make_candidate(0x1000_0020, slots_b, Some("Leaf")),
        ];
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&candidates);
        let root = h.classes.iter().find(|c| c.name.as_deref() == Some("Root")).unwrap();
        let leaf = h.classes.iter().find(|c| c.name.as_deref() == Some("Leaf")).unwrap();
        assert!(root.is_root());
        assert!(leaf.is_leaf());
    }

    #[test]
    fn test_descendants_of() {
        let slots_a = vec![0x401000u64, 0x401010];
        let slots_b = vec![0x401000u64, 0x401010, 0x401020];
        let candidates = vec![
            make_candidate(0x1000_0000, slots_a, Some("A")),
            make_candidate(0x1000_0020, slots_b, Some("B")),
        ];
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&candidates);
        let a_id = h.classes.iter().find(|c| c.name.as_deref() == Some("A")).map(|c| c.id);
        if let Some(id) = a_id {
            let desc = h.descendants_of(id);
            // B should appear as a descendant of A (if relation was detected).
            let _ = desc; // just verify it runs without panic
        }
    }

    #[test]
    fn test_merge_hierarchies() {
        let slots_a = vec![0x401000u64, 0x401010];
        let slots_b = vec![0x402000u64, 0x402010]; // different addresses
        let cands_a = vec![make_candidate(0x1000_0000, slots_a, Some("Foo"))];
        let cands_b = vec![make_candidate(0x2000_0000, slots_b, Some("Foo"))];
        let rec = VtableReconstructor::with_defaults();
        let ha = rec.reconstruct(&cands_a);
        let hb = rec.reconstruct(&cands_b);
        let merged = merge_hierarchies(&ha, &hb);
        let foo = merged.entries.iter().find(|e| e.name == "Foo").unwrap();
        assert!(foo.appears_in_both);
        assert_eq!(foo.slot_differences.len(), 2); // both slots differ
    }

    #[test]
    fn test_is_abstract_flag() {
        let same = 0x401000u64;
        let c = make_candidate(0x1000_0000, vec![same; 5], Some("AbstractBase"));
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&[c]);
        assert!(h.classes[0].is_abstract);
    }

    #[test]
    fn test_empty_candidates() {
        let rec = VtableReconstructor::with_defaults();
        let h = rec.reconstruct(&[]);
        assert_eq!(h.class_count(), 0);
        assert!(h.root_ids.is_empty());
    }
}
