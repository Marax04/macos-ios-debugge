//! Randomized property / oracle tests for hierarchy and parser invariants.
//!
//! Deterministic: every generator is driven by a seeded xorshift64* PRNG, so a
//! failure reported here reproduces exactly from the printed seed.
//!
//! Where a brute-force oracle is cheap (transitive closure, longest path) we
//! compare against it rather than against the implementation's own notion of
//! consistency — self-consistency cannot catch a systematically wrong answer.

#![cfg(test)]

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::hierarchy::InheritanceGraph;
use crate::vtable_reconstructor::{ClassNode, ReconstructedHierarchy, VirtualSlot};
use crate::{RttiAbi, RttiInfo};

// ─── PRNG ────────────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
    fn bool_(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

// ─── Generators ──────────────────────────────────────────────────────────────

/// Random *acyclic* name-based hierarchy: class `i` may only derive from
/// classes with a smaller index, so a brute-force closure is well-defined.
fn gen_dag(rng: &mut Rng, n: usize, max_bases: usize) -> Vec<(String, Vec<String>)> {
    (0..n)
        .map(|i| {
            let name = format!("C{i}");
            let mut bases = Vec::new();
            if i > 0 {
                let k = rng.below(max_bases + 1);
                for _ in 0..k {
                    let b = format!("C{}", rng.below(i));
                    if !bases.contains(&b) {
                        bases.push(b);
                    }
                }
            }
            (name, bases)
        })
        .collect()
}

/// Random hierarchy with NO acyclicity constraint — models adversarial RTTI,
/// including self-edges and mutual bases.
fn gen_cyclic(rng: &mut Rng, n: usize, max_bases: usize) -> Vec<(String, Vec<String>)> {
    (0..n)
        .map(|i| {
            let mut bases = Vec::new();
            let k = rng.below(max_bases + 1);
            for _ in 0..k {
                let b = format!("C{}", rng.below(n));
                if !bases.contains(&b) {
                    bases.push(b);
                }
            }
            (format!("C{i}"), bases)
        })
        .collect()
}

fn build_graph(spec: &[(String, Vec<String>)]) -> InheritanceGraph {
    let mut g = InheritanceGraph::new();
    for (name, bases) in spec {
        g.add_rtti(&RttiInfo {
            type_name: name.clone(),
            base_classes: bases.clone(),
            rtti_address: 0x1000,
            abi: RttiAbi::Itanium,
        });
    }
    g
}

// ─── Oracles ─────────────────────────────────────────────────────────────────

/// Brute-force transitive closure of the base edges, excluding the start node
/// unless it is genuinely reachable from itself via a cycle.
fn oracle_ancestors(spec: &[(String, Vec<String>)], start: &str) -> BTreeSet<String> {
    let edges: HashMap<&str, &Vec<String>> =
        spec.iter().map(|(n, b)| (n.as_str(), b)).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = edges.get(start).map(|b| (*b).clone()).unwrap_or_default();
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.clone()) {
            continue;
        }
        if let Some(bs) = edges.get(cur.as_str()) {
            stack.extend((*bs).iter().cloned());
        }
    }
    seen
}

/// Brute-force longest path to a root over an acyclic spec.
fn oracle_depth(spec: &[(String, Vec<String>)], start: &str) -> usize {
    let edges: HashMap<&str, &Vec<String>> =
        spec.iter().map(|(n, b)| (n.as_str(), b)).collect();
    fn go(edges: &HashMap<&str, &Vec<String>>, name: &str) -> usize {
        edges
            .get(name)
            .map_or(0, |bs| bs.iter().map(|b| 1 + go(edges, b)).max().unwrap_or(0))
    }
    go(&edges, start)
}

// ─── Properties: inheritance graph ───────────────────────────────────────────

/// `ancestors_of` must equal the brute-force transitive closure (oracle).
#[test]
fn prop_ancestors_match_bruteforce_closure() {
    for seed in 1..=800u64 {
        let mut rng = Rng::new(seed);
        let n = 1 + rng.below(12);
        let spec = gen_dag(&mut rng, n, 3);
        let g = build_graph(&spec);
        for (name, _) in &spec {
            let got: BTreeSet<String> = g.ancestors_of(name).into_iter().collect();
            let want = oracle_ancestors(&spec, name);
            assert_eq!(got, want, "seed {seed}, class {name}");
        }
    }
}

/// `ancestors_of` and `descendants_of` must be exact inverses:
/// b ∈ ancestors(a) ⟺ a ∈ descendants(b), for every pair.
#[test]
fn prop_ancestors_descendants_are_exact_inverses() {
    for seed in 1..=800u64 {
        let mut rng = Rng::new(seed);
        let n = 1 + rng.below(10);
        let spec = gen_cyclic(&mut rng, n, 3);
        let g = build_graph(&spec);
        let names: Vec<&str> = spec.iter().map(|(n, _)| n.as_str()).collect();
        for a in &names {
            let anc: HashSet<String> = g.ancestors_of(a).into_iter().collect();
            for b in &names {
                let desc: HashSet<String> = g.descendants_of(b).into_iter().collect();
                assert_eq!(
                    anc.contains(*b),
                    desc.contains(*a),
                    "seed {seed}: ancestors({a}) ∌/∋ {b} disagrees with descendants({b})"
                );
            }
        }
    }
}

/// A class must never be recorded as its own direct base or direct derived,
/// even when the RTTI input claims a self-edge (adversarial input).
#[test]
fn prop_no_self_edge_after_build() {
    let mut rng = Rng::new(0xC0FFEE);
    for _ in 0..500 {
        let n = 1 + rng.below(8);
        let spec = gen_cyclic(&mut rng, n, 3);
        let g = build_graph(&spec);
        for (name, _) in &spec {
            if let Some(node) = g.get(name) {
                // Self-edges are only permitted if the *input* asserted one.
                let input_self = spec
                    .iter()
                    .find(|(n, _)| n == name)
                    .is_some_and(|(_, b)| b.contains(name));
                if !input_self {
                    assert!(!node.bases.contains(name), "self base edge on {name}");
                    assert!(!node.derived.contains(name), "self derived edge on {name}");
                }
            }
        }
    }
}

/// `depth` must equal the brute-force longest path on acyclic input.
#[test]
fn prop_depth_matches_bruteforce_longest_path() {
    for seed in 1..=800u64 {
        let mut rng = Rng::new(seed.wrapping_mul(7919));
        let n = 1 + rng.below(12);
        let spec = gen_dag(&mut rng, n, 3);
        let g = build_graph(&spec);
        for (name, _) in &spec {
            assert_eq!(
                g.depth(name),
                oracle_depth(&spec, name),
                "seed {seed}, class {name}"
            );
        }
    }
}

/// `depth`, `is_a`, `bfs_from` must terminate (not recurse/spin) on cyclic
/// adversarial input. Reaching the end of this test IS the assertion.
#[test]
fn prop_cyclic_input_terminates() {
    for seed in 1..=600u64 {
        let mut rng = Rng::new(seed ^ 0xDEAD_BEEF);
        let n = 1 + rng.below(14);
        let spec = gen_cyclic(&mut rng, n, 4);
        let g = build_graph(&spec);
        for (name, _) in &spec {
            let _ = g.depth(name);
            let _ = g.bfs_from(name);
            let _ = g.is_a(name, "C0");
            let _ = g.ancestors_of(name);
            let _ = g.descendants_of(name);
        }
    }
}

/// Ordered outputs must not depend on insertion order (`HashMap` iteration order
/// must never leak into results).
#[test]
fn prop_ordered_output_is_insertion_order_independent() {
    for seed in 1..=400u64 {
        let mut rng = Rng::new(seed.wrapping_mul(31) | 1);
        let n = 2 + rng.below(10);
        let spec = gen_dag(&mut rng, n, 3);
        let mut shuffled = spec.clone();
        for i in (1..shuffled.len()).rev() {
            shuffled.swap(i, rng.below(i + 1));
        }
        let a = build_graph(&spec);
        let b = build_graph(&shuffled);
        let names_a: Vec<&str> = a.roots().iter().map(|n| n.name.as_str()).collect();
        let names_b: Vec<&str> = b.roots().iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names_a, names_b, "roots() order differs, seed {seed}");
        let la: Vec<&str> = a.leaves().iter().map(|n| n.name.as_str()).collect();
        let lb: Vec<&str> = b.leaves().iter().map(|n| n.name.as_str()).collect();
        assert_eq!(la, lb, "leaves() order differs, seed {seed}");
        for (name, _) in &spec {
            assert_eq!(a.ancestors_of(name), b.ancestors_of(name), "seed {seed}");
            assert_eq!(a.descendants_of(name), b.descendants_of(name), "seed {seed}");
        }
    }
}

// ─── Properties: reconstructed hierarchy (id-based) ──────────────────────────

fn node(id: usize, bases: Vec<usize>) -> ClassNode {
    ClassNode {
        id,
        vtable_va: 0x1000 + id as u64 * 8,
        name: Some(format!("R{id}")),
        slots: vec![VirtualSlot {
            index: 0,
            fn_addr: 0x2000 + id as u64,
            is_override: false,
            overrides: None,
            symbol: None,
        }],
        bases,
        derived: Vec::new(),
        has_overrides: false,
        is_abstract: false,
        confidence: 100,
    }
}

fn link(classes: &mut [ClassNode]) {
    let edges: Vec<(usize, usize)> = classes
        .iter()
        .flat_map(|c| c.bases.iter().map(move |&b| (b, c.id)))
        .collect();
    for (b, d) in edges {
        if let Some(bn) = classes.get_mut(b)
            && !bn.derived.contains(&d)
        {
            bn.derived.push(d);
        }
    }
}

/// A diamond hierarchy (each class derives from its two predecessors) must not
/// cost exponential time in `max_depth`. 60 classes is trivial for a memoized
/// walk and astronomically infeasible for a naive one.
#[test]
fn prop_diamond_hierarchy_does_not_blow_up() {
    let n = 60;
    let mut classes: Vec<ClassNode> = (0..n)
        .map(|i| {
            let bases = match i {
                0 => vec![],
                1 => vec![0],
                _ => vec![i - 1, i - 2],
            };
            node(i, bases)
        })
        .collect();
    link(&mut classes);
    let h = ReconstructedHierarchy {
        classes,
        relations: Vec::new(),
        root_ids: vec![0],
    };
    assert_eq!(h.max_depth(), n - 1);
}

/// Reconstructed-hierarchy walks must terminate on cyclic id graphs.
#[test]
fn prop_reconstructed_cyclic_terminates() {
    for seed in 1..=400u64 {
        let mut rng = Rng::new(seed ^ 0xABCD);
        let n = 1 + rng.below(10);
        let mut classes: Vec<ClassNode> = (0..n)
            .map(|i| {
                let k = rng.below(3);
                let mut bases = Vec::new();
                for _ in 0..k {
                    let b = rng.below(n);
                    if !bases.contains(&b) {
                        bases.push(b);
                    }
                }
                node(i, bases)
            })
            .collect();
        link(&mut classes);
        let h = ReconstructedHierarchy {
            classes,
            relations: Vec::new(),
            root_ids: (0..n).filter(|_| rng.bool_()).collect(),
        };
        let _ = h.max_depth();
        for i in 0..n {
            let _ = h.depth_of(i);
            let _ = h.descendants_of(i);
            let _ = crate::class_hierarchy::mro_string(&h, i);
        }
        let an = crate::class_hierarchy::HierarchyAnalyser::new(&h);
        let _ = an.topological_sort();
        let _ = an.statistics();
    }
}

// ─── Properties: parser / demangler fuzz ─────────────────────────────────────

fn rand_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    (0..len).map(|_| (rng.next_u64() & 0xFF) as u8).collect()
}

/// Every RTTI scanner must survive random and truncated buffers without
/// panicking, at every plausible base/image-base/pointer-size combination.
#[test]
fn prop_rtti_scanners_never_panic_on_random_buffers() {
    let mut rng = Rng::new(0x5EED);
    for _ in 0..600 {
        let len = rng.below(96);
        let data = rand_bytes(&mut rng, len);
        for ptr_size in [4usize, 8] {
            // Adversarial bases, including values that make base+len wrap u64.
            for base in [0u64, 0x1000, u64::MAX - 8, u64::MAX / 2] {
                let _ = crate::msvc_rtti::detect_msvc_rtti(&data, base, 0x1_4000_0000, ptr_size);
            }
        }
        // Truncations of the same buffer must be equally safe.
        for cut in 0..data.len().min(24) {
            let _ = crate::msvc_rtti::detect_msvc_rtti(&data[..cut], 0x1000, 0x1000, 8);
        }
    }
}

/// `MemRegion` / `ImageSection` readers must never panic and must never read
/// outside their buffer, at any address including near `u64::MAX`.
#[test]
fn prop_region_readers_are_bounds_safe() {
    let mut rng = Rng::new(0xB0DE);
    for _ in 0..500 {
        let dlen = rng.below(40);
        let data = rand_bytes(&mut rng, dlen);
        let base = [0u64, 0x1000, u64::MAX - 4][rng.below(3)];
        let region = crate::rtti_parser::MemRegion::new(base, data.clone());
        let sec = crate::msvc_rtti::ImageSection::new(".rdata", base, data.clone());
        for _ in 0..40 {
            let va = match rng.below(4) {
                0 => rng.next_u64(),
                1 => base.wrapping_add(rng.below(64) as u64),
                2 => u64::MAX - rng.below(8) as u64,
                _ => base.wrapping_sub(rng.below(8) as u64),
            };
            let _ = region.read_u32(va);
            let _ = region.read_i32(va);
            let _ = region.read_ptr(va, 8);
            let _ = region.read_ptr(va, 4);
            let _ = region.read_cstr(va);
            let _ = sec.read_u32_le(va);
            let _ = sec.read_i32_le(va);
            let _ = sec.read_u64_le(va);
            let _ = sec.read_cstr(va);
            let _ = sec.read_ptr(va, 8);
        }
    }
}

/// The demanglers must never panic on random / truncated symbol strings, and
/// must always return a non-panicking String for arbitrary UTF-8.
#[test]
fn prop_demanglers_never_panic() {
    let mut rng = Rng::new(0xD3A6);
    let alphabet: &[u8] = b"?@$_0123456789ABZaz.:<>,*&EN13St_ZTV";
    for _ in 0..2000 {
        let len = rng.below(40);
        let s: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())] as char)
            .collect();
        for probe in [s.clone(), format!("_Z{s}"), format!("?{s}"), format!("_ZTV{s}")] {
            let _ = crate::demangler::demangle(&probe);
            let _ = crate::demangler::demangle_itanium(&probe);
            let _ = crate::demangler::demangle_msvc(&probe);
            let _ = crate::demangler::demangle_msvc_function(&probe);
            let _ = crate::rtti_parser::itanium_demangle_basic(&probe);
            let _ = crate::rtti_parser::msvc_demangle_basic(&probe);
            // Truncations: the classic parser-hazard shape.
            for cut in 0..probe.len().min(12) {
                if probe.is_char_boundary(cut) {
                    let _ = crate::demangler::demangle(&probe[..cut]);
                    let _ = crate::demangler::demangle_itanium(&probe[..cut]);
                }
            }
        }
    }
}

// ─── Regression tests for defects found by the properties above ──────────────

/// Regression (found by `prop_diamond_hierarchy_does_not_blow_up`, minimised):
/// `ReconstructedHierarchy::depth_of` was a naive recursion with no
/// memoization, so a diamond hierarchy of k levels cost O(2^k). 40 classes
/// already hangs the un-memoized version; the fixed one is instant.
#[test]
fn regress_depth_of_diamond_is_not_exponential() {
    let n = 40;
    let mut classes: Vec<ClassNode> = (0..n)
        .map(|i| {
            let bases = match i {
                0 => vec![],
                1 => vec![0],
                _ => vec![i - 1, i - 2],
            };
            node(i, bases)
        })
        .collect();
    link(&mut classes);
    let h = ReconstructedHierarchy {
        classes,
        relations: Vec::new(),
        root_ids: vec![0],
    };
    assert_eq!(h.depth_of(n - 1), n - 1);
}

/// Regression: a self-cycle and a 2-cycle must both terminate in `depth_of`
/// without relying on the 512-frame recursion limit.
#[test]
fn regress_depth_of_cycles_terminate() {
    let mut classes = vec![node(0, vec![0]), node(1, vec![2]), node(2, vec![1])];
    link(&mut classes);
    let h = ReconstructedHierarchy {
        classes,
        relations: Vec::new(),
        root_ids: vec![],
    };
    for i in 0..3 {
        let _ = h.depth_of(i);
    }
}

// ─── Properties: vtable_extends (live surface: 7 call sites in decompiler-type)

/// Independent, definition-derived oracle for `vtable_extends`.
///
/// Definition (from the doc comment): `b` extends `a` iff `a`'s virtual-function
/// address sequence is a **strict, non-empty prefix** of `b`'s. Expressed here
/// over plain `Vec<u64>` slices with no reference to the implementation.
fn oracle_extends(a: &[u64], b: &[u64]) -> bool {
    !a.is_empty() && b.len() > a.len() && b[..a.len()] == *a
}

fn vt(addr: u64, targets: &[u64]) -> crate::Vtable {
    let mut v = crate::Vtable::new(addr);
    for (i, &t) in targets.iter().enumerate() {
        v.add_entry(crate::VtableEntry::new(i * 8, t));
    }
    v
}

/// Generator reaching the shapes that break naive prefix code: empty tables,
/// singletons, equal-length pairs, exact prefixes, prefixes that diverge only
/// in the last shared slot, and duplicate/zero target addresses.
fn gen_targets(rng: &mut Rng) -> Vec<u64> {
    let n = rng.below(5);
    (0..n)
        .map(|_| match rng.below(4) {
            0 => 0,
            1 => 0x1000,
            2 => u64::MAX,
            _ => 0x1000 + rng.below(3) as u64,
        })
        .collect()
}

#[test]
fn prop_vtable_extends_matches_definition_oracle() {
    let mut rng = Rng::new(0x5E7E);
    // Coverage counters — the test fails if any interesting category dries up.
    let (mut n_true, mut n_empty_a, mut n_equal_len, mut n_prefix_diverge) = (0, 0, 0, 0);
    for _ in 0..20_000 {
        let mut a = gen_targets(&mut rng);
        let mut b = gen_targets(&mut rng);
        // Half the time, force a genuine prefix relationship (rare by chance).
        if rng.bool_() {
            b = a.clone();
            for _ in 0..=rng.below(3) {
                b.push(rng.next_u64() & 0xFFFF);
            }
            // ...and sometimes corrupt one shared slot, the classic off-by-one trap.
            if !a.is_empty() && rng.below(3) == 0 {
                let i = rng.below(a.len());
                b[i] = b[i].wrapping_add(1);
                n_prefix_diverge += 1;
            }
        }
        if rng.below(9) == 0 {
            a.truncate(0);
        }
        let want = oracle_extends(&a, &b);
        let got = crate::vtable_extends(&vt(0x400, &a), &vt(0x800, &b));
        assert_eq!(got, want, "a={a:x?} b={b:x?}");
        if want {
            n_true += 1;
        }
        if a.is_empty() {
            n_empty_a += 1;
        }
        if a.len() == b.len() {
            n_equal_len += 1;
        }
    }
    assert!(n_true > 500, "generator never produced a true extension: {n_true}");
    assert!(n_empty_a > 500, "generator never produced an empty base: {n_empty_a}");
    assert!(n_equal_len > 200, "generator never produced equal lengths: {n_equal_len}");
    assert!(
        n_prefix_diverge > 200,
        "generator never produced a diverging shared slot: {n_prefix_diverge}"
    );
}

/// Structural laws that follow from the definition and must hold regardless of
/// implementation: irreflexive, antisymmetric, and strictly length-increasing.
#[test]
fn prop_vtable_extends_is_a_strict_order() {
    let mut rng = Rng::new(0xA17E);
    for _ in 0..5_000 {
        let a = gen_targets(&mut rng);
        let mut b = a.clone();
        for _ in 0..=rng.below(3) {
            b.push(rng.next_u64() & 0xFF);
        }
        let (va, vb) = (vt(0x400, &a), vt(0x800, &b));
        assert!(!crate::vtable_extends(&va, &va), "irreflexive violated: {a:x?}");
        if crate::vtable_extends(&va, &vb) {
            assert!(!crate::vtable_extends(&vb, &va), "antisymmetry violated");
            assert!(vb.entry_count() > va.entry_count(), "length law violated");
        }
    }
}
