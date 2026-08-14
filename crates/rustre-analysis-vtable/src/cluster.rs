//! Vtable clustering and virtual-function-slot identification.
//!
//! Once individual vtables have been recovered, two structural questions
//! remain:
//!
//! * **Which vtables belong together?**  A derived class's vtable typically
//!   shares a *prefix* of slots with its base class's vtable (the base's
//!   virtual functions appear at the same slot indices, possibly thunked).
//!   Grouping vtables by shared slot prefixes recovers likely inheritance
//!   clusters even without RTTI.
//! * **Which functions are virtual, and at which slot?**  A function address
//!   that appears in slot *k* of one or more vtables is a virtual function
//!   occupying that slot.  Building the address → slot map identifies the
//!   virtual dispatch surface of the program.

use crate::{Vtable, VtableEntry};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A virtual function slot: a function address together with the slot indices
/// at which it appears across the analysed vtables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualSlot {
    /// The function's address.
    pub function: u64,
    /// Slot indices (0-based) at which this function appears.
    pub slot_indices: BTreeSet<usize>,
    /// Vtables (by base address) that contain this function.
    pub vtables: BTreeSet<u64>,
}

impl VirtualSlot {
    /// Whether the function always occupies the same slot index.
    #[must_use]
    pub fn is_stable_slot(&self) -> bool {
        self.slot_indices.len() == 1
    }

    /// The canonical slot index (lowest), if any.
    #[must_use]
    pub fn primary_slot(&self) -> Option<usize> {
        self.slot_indices.iter().copied().next()
    }
}

/// The result of identifying virtual function slots across vtables.
#[derive(Debug, Clone, Default)]
pub struct SlotMap {
    by_function: BTreeMap<u64, VirtualSlot>,
}

impl SlotMap {
    /// Build a slot map from a set of vtables.
    #[must_use]
    pub fn build(vtables: &[Vtable]) -> Self {
        let mut by_function: BTreeMap<u64, VirtualSlot> = BTreeMap::new();
        for vt in vtables {
            for (idx, entry) in vt.entries.iter().enumerate() {
                let slot = by_function
                    .entry(entry.target_address)
                    .or_insert_with(|| VirtualSlot {
                        function: entry.target_address,
                        slot_indices: BTreeSet::new(),
                        vtables: BTreeSet::new(),
                    });
                slot.slot_indices.insert(idx);
                slot.vtables.insert(vt.base_address);
            }
        }
        Self { by_function }
    }

    /// All identified virtual functions.
    #[must_use]
    pub fn virtual_functions(&self) -> Vec<u64> {
        self.by_function.keys().copied().collect()
    }

    /// The slot record for a function address.
    #[must_use]
    pub fn slot_of(&self, function: u64) -> Option<&VirtualSlot> {
        self.by_function.get(&function)
    }

    /// Whether `function` is virtual (appears in any vtable).
    #[must_use]
    pub fn is_virtual(&self, function: u64) -> bool {
        self.by_function.contains_key(&function)
    }

    /// Functions shared by *more than one* vtable (overridden / inherited).
    #[must_use]
    pub fn shared_functions(&self) -> Vec<u64> {
        self.by_function
            .values()
            .filter(|s| s.vtables.len() > 1)
            .map(|s| s.function)
            .collect()
    }

    /// Number of distinct virtual functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_function.len()
    }

    /// Whether no virtual functions were found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_function.is_empty()
    }
}

/// A cluster of vtables that share a common slot prefix (likely an inheritance
/// hierarchy or a family of related classes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtableCluster {
    /// Base addresses of the vtables in this cluster.
    pub members: Vec<u64>,
    /// The longest common slot prefix shared by all members (function addresses).
    pub shared_prefix: Vec<u64>,
}

impl VtableCluster {
    /// Number of vtables in the cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.members.len()
    }

    /// Length of the shared slot prefix.
    #[must_use]
    pub const fn prefix_len(&self) -> usize {
        self.shared_prefix.len()
    }
}

/// Union-find path-compressed root finder.
fn uf_find(parent: &mut [usize], x: usize) -> usize {
    let mut r = x;
    while parent[r] != r {
        r = parent[r];
    }
    // Path compression.
    let mut cur = x;
    while parent[cur] != r {
        let next = parent[cur];
        parent[cur] = r;
        cur = next;
    }
    r
}

/// Compute the length of the common prefix of two slot sequences.
fn common_prefix_len(a: &[VtableEntry], b: &[VtableEntry]) -> usize {
    a.iter()
        .zip(b.iter())
        .take_while(|(x, y)| x.target_address == y.target_address)
        .count()
}

/// Cluster vtables by shared slot prefixes.
///
/// Two vtables join the same cluster when their common prefix is at least
/// `min_shared` slots long.  This is a single-link agglomerative grouping over
/// the prefix-overlap relation.
#[must_use]
pub fn cluster_vtables(vtables: &[Vtable], min_shared: usize) -> Vec<VtableCluster> {
    let n = vtables.len();
    if n == 0 {
        return Vec::new();
    }
    // Union-find over vtable indices.
    let mut parent: Vec<usize> = (0..n).collect();
    for i in 0..n {
        for j in (i + 1)..n {
            if common_prefix_len(&vtables[i].entries, &vtables[j].entries) >= min_shared {
                let ri = uf_find(&mut parent, i);
                let rj = uf_find(&mut parent, j);
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }

    // Gather members per root.
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let r = uf_find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut clusters: Vec<VtableCluster> = groups
        .into_values()
        .map(|members| {
            // Shared prefix = intersection prefix across all members.
            let prefix = shared_prefix(&members, vtables);
            let mut bases: Vec<u64> = members.iter().map(|&m| vtables[m].base_address).collect();
            bases.sort_unstable();
            VtableCluster {
                members: bases,
                shared_prefix: prefix,
            }
        })
        .collect();
    clusters.sort_by_key(|c| c.members.first().copied().unwrap_or(0));
    clusters
}

/// Longest common slot prefix across a set of vtable indices.
fn shared_prefix(members: &[usize], vtables: &[Vtable]) -> Vec<u64> {
    if members.is_empty() {
        return Vec::new();
    }
    let first = &vtables[members[0]].entries;
    let mut prefix: Vec<u64> = first.iter().map(|e| e.target_address).collect();
    for &m in &members[1..] {
        let len =
            common_prefix_len(&vtables[members[0]].entries, &vtables[m].entries).min(prefix.len());
        prefix.truncate(len);
    }
    prefix
}

/// Heuristically infer (base, derived) candidate pairs: when vtable B's slots
/// are a proper prefix of vtable D's slots, D likely derives from B.
#[must_use]
pub fn infer_derivations(vtables: &[Vtable]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for base in vtables {
        for derived in vtables {
            if base.base_address == derived.base_address {
                continue;
            }
            let bn = base.entries.len();
            let dn = derived.entries.len();
            if bn == 0 || bn >= dn {
                continue;
            }
            let cp = common_prefix_len(&base.entries, &derived.entries);
            if cp == bn {
                out.push((base.base_address, derived.base_address));
            }
        }
    }
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vt(base: u64, fns: &[u64]) -> Vtable {
        let mut v = Vtable::new(base);
        for (i, &f) in fns.iter().enumerate() {
            v.add_entry(VtableEntry::new(i * 8, f));
        }
        v
    }

    #[test]
    fn slot_map_identifies_virtuals() {
        let vts = vec![vt(0x1000, &[0xA, 0xB, 0xC])];
        let sm = SlotMap::build(&vts);
        assert_eq!(sm.len(), 3);
        assert!(sm.is_virtual(0xB));
        assert_eq!(sm.slot_of(0xB).unwrap().primary_slot(), Some(1));
        assert!(!sm.is_virtual(0xFF));
    }

    #[test]
    fn slot_map_shared_functions() {
        // Base [A,B], Derived [A,B,C] -> A and B shared, slot-stable.
        let vts = vec![vt(0x1000, &[0xA, 0xB]), vt(0x2000, &[0xA, 0xB, 0xC])];
        let sm = SlotMap::build(&vts);
        let shared = sm.shared_functions();
        assert!(shared.contains(&0xA));
        assert!(shared.contains(&0xB));
        assert!(!shared.contains(&0xC));
        assert!(sm.slot_of(0xA).unwrap().is_stable_slot());
    }

    #[test]
    fn slot_map_detects_relocated_slot() {
        // 0xA appears in slot 0 in one vtable and slot 1 in another.
        let vts = vec![vt(0x1000, &[0xA, 0xB]), vt(0x2000, &[0xB, 0xA])];
        let sm = SlotMap::build(&vts);
        assert!(!sm.slot_of(0xA).unwrap().is_stable_slot());
        assert_eq!(sm.slot_of(0xA).unwrap().slot_indices.len(), 2);
    }

    #[test]
    fn cluster_groups_shared_prefix() {
        // Two derived vtables sharing the base prefix [A,B].
        let vts = vec![
            vt(0x1000, &[0xA, 0xB, 0xC]),
            vt(0x2000, &[0xA, 0xB, 0xD]),
            vt(0x3000, &[0xE, 0xF]), // unrelated
        ];
        let clusters = cluster_vtables(&vts, 2);
        // One cluster of 2 sharing [A,B], one singleton.
        let big = clusters.iter().find(|c| c.size() == 2).unwrap();
        assert_eq!(big.shared_prefix, vec![0xA, 0xB]);
        assert!(big.members.contains(&0x1000));
        assert!(big.members.contains(&0x2000));
        assert!(
            clusters
                .iter()
                .any(|c| c.size() == 1 && c.members == vec![0x3000])
        );
    }

    #[test]
    fn cluster_transitive_single_link() {
        // A-B share prefix, B-C share prefix -> all one cluster.
        let vts = vec![
            vt(0x1000, &[0xA, 0xB, 0x1]),
            vt(0x2000, &[0xA, 0xB, 0x2]),
            vt(0x3000, &[0xA, 0xB, 0x3]),
        ];
        let clusters = cluster_vtables(&vts, 2);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size(), 3);
    }

    #[test]
    fn cluster_empty_input() {
        assert!(cluster_vtables(&[], 1).is_empty());
    }

    #[test]
    fn infer_derivations_prefix() {
        // Base [A,B] is a proper prefix of Derived [A,B,C].
        let vts = vec![vt(0x1000, &[0xA, 0xB]), vt(0x2000, &[0xA, 0xB, 0xC])];
        let pairs = infer_derivations(&vts);
        assert_eq!(pairs, vec![(0x1000, 0x2000)]);
    }

    #[test]
    fn infer_derivations_none_when_diverge() {
        let vts = vec![vt(0x1000, &[0xA, 0xB]), vt(0x2000, &[0xC, 0xD, 0xE])];
        assert!(infer_derivations(&vts).is_empty());
    }

    // ── Property tests: order-independence and oracle cross-checks ────────

    /// Deterministic pseudo-random permutations without external crates.
    fn permute<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
        let mut v: Vec<T> = items.to_vec();
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        for i in (1..v.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = (state % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
        v
    }

    #[test]
    fn prop_cluster_vtables_order_independent() {
        let vts = vec![
            vt(0x1000, &[0xA, 0xB, 0xC]),
            vt(0x2000, &[0xA, 0xB, 0xD]),
            vt(0x3000, &[0xE, 0xF]),
            vt(0x4000, &[0xA, 0xB]),
            vt(0x5000, &[0xE, 0xF, 0x9]),
        ];
        let baseline = cluster_vtables(&vts, 2);
        for seed in 0..20u64 {
            let shuffled = permute(&vts, seed);
            let got = cluster_vtables(&shuffled, 2);
            assert_eq!(
                got, baseline,
                "clustering must not depend on input order (seed {seed})"
            );
        }
    }

    #[test]
    fn prop_infer_derivations_order_independent() {
        let vts = vec![
            vt(0x1000, &[0xA, 0xB]),
            vt(0x2000, &[0xA, 0xB, 0xC]),
            vt(0x3000, &[0xA, 0xB, 0xC, 0xD]),
            vt(0x4000, &[0x1, 0x2]),
        ];
        let baseline = infer_derivations(&vts);
        for seed in 0..20u64 {
            let got = infer_derivations(&permute(&vts, seed));
            assert_eq!(got, baseline);
        }
    }

    #[test]
    fn prop_slot_map_oracle() {
        // Oracle: brute-force membership check against SlotMap results.
        let vts = vec![
            vt(0x1000, &[0xA, 0xB, 0xC]),
            vt(0x2000, &[0xB, 0xA]),
            vt(0x3000, &[0xC, 0xC, 0xD]),
        ];
        let sm = SlotMap::build(&vts);
        for f in [0xAu64, 0xB, 0xC, 0xD, 0xEE] {
            let expected: bool = vts
                .iter()
                .any(|v| v.entries.iter().any(|e| e.target_address == f));
            assert_eq!(sm.is_virtual(f), expected, "fn {f:#x}");
            if expected {
                let slot = sm.slot_of(f).unwrap();
                // Every recorded (vtable, index) claim must be verifiable.
                for &idx in &slot.slot_indices {
                    assert!(vts.iter().any(|v| {
                        v.entries.get(idx).map(|e| e.target_address) == Some(f)
                    }));
                }
                for &vtb in &slot.vtables {
                    assert!(vts.iter().any(|v| v.base_address == vtb));
                }
            }
        }
        assert_eq!(sm.len(), 4); // A, B, C, D distinct
    }

    #[test]
    fn cluster_prefix_len_helpers() {
        let c = VtableCluster {
            members: vec![1, 2],
            shared_prefix: vec![0xA, 0xB, 0xC],
        };
        assert_eq!(c.size(), 2);
        assert_eq!(c.prefix_len(), 3);
    }
}
