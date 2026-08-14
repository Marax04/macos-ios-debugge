//! Deep adversarial blitz2 tests for rustre-diff-bindiff (lib.rs surface).
//!
//! Covers: CfgHasher, FunctionFeatures, BinarySnapshot, MatchKind,
//! FunctionMatch, DiffStats, BinDiffer pipeline, DiffReport,
//! FunctionInfo / similarity_score, HungarianSolver, match_functions_hungarian,
//! and the high-level BinDiff facade.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;

use rustre_core::address::Address;
use rustre_diff_bindiff::*;

// ─── Seeded LCG (deterministic, no rand) ─────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Lcg(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        // [lo, hi)
        debug_assert!(hi > lo);
        lo + self.next_u32() % (hi - lo)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn mkfeat(addr: u64) -> FunctionFeatures {
    FunctionFeatures::new(Address::new(addr))
}

fn full_feat(addr: u64, bb: u32, instr: u32, edges: u32) -> FunctionFeatures {
    let mut f = mkfeat(addr);
    f.basic_block_count = bb;
    f.instruction_count = instr;
    f.edge_count = edges;
    f.cfg_hash = (addr ^ 0xC0FFEE).wrapping_mul(0x9E3779B97F4A7C15);
    f.byte_hash = addr.wrapping_mul(0xA5A5_5A5A_DEAD_BEEF);
    f.loop_count = edges.saturating_sub(bb.saturating_sub(1));
    f
}

fn mkinfo(addr: u64) -> FunctionInfo {
    FunctionInfo::new(addr)
}

// ────────────────────────────────────────────────────────────────────────────
// 1. CfgHasher invariants and LCG-fuzz
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t01_cfg_empty_and_basis_constants() {
    assert_eq!(CfgHasher::hash_cfg(&[]), 0);
    assert_eq!(CfgHasher::wl_hash(&[], 0), 0);
    assert_eq!(CfgHasher::wl_hash(&[], 99), 0);
    // hash_linear(0) returns FNV-1a basis.
    assert_eq!(CfgHasher::hash_linear(0), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn t02_cfg_isomorphic_random_renumbering_yields_same_hash() {
    // Build a fixed shape, then renumber nodes deterministically and re-hash.
    let base = vec![
        (10u32, vec![20, 30]),
        (20, vec![40]),
        (30, vec![40]),
        (40, vec![]),
    ];
    let renumbered = vec![
        (1u32, vec![2, 3]),
        (2, vec![9]),
        (3, vec![9]),
        (9, vec![]),
    ];
    assert_eq!(CfgHasher::hash_cfg(&base), CfgHasher::hash_cfg(&renumbered));
}

#[test]
fn t03_cfg_linear_50_distinct_hashes() {
    let mut seen: HashSet<u64> = HashSet::new();
    for i in 1..=50 {
        let h = CfgHasher::hash_linear(i);
        assert!(seen.insert(h), "linear({}) collides", i);
    }
}

#[test]
fn t04_cfg_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let nodes = g.range(0, 20);
        let mut adj: Vec<(u32, Vec<u32>)> = Vec::new();
        for i in 0..nodes {
            let outs = g.range(0, 5);
            let mut s: Vec<u32> = Vec::new();
            for _ in 0..outs {
                if nodes > 0 {
                    s.push(g.range(0, nodes));
                }
            }
            adj.push((i, s));
        }
        // Should never panic on any topology.
        let h1 = CfgHasher::hash_cfg(&adj);
        let h2 = CfgHasher::wl_hash(&adj, g.range(0, 6));
        // h1 deterministic re-hash equals itself.
        assert_eq!(h1, CfgHasher::hash_cfg(&adj));
        let _ = h2;
    }
}

#[test]
fn t05_cfg_iterations_zero_yields_outdegree_hash() {
    // With zero iterations, labels remain initial out-degrees.
    let adj = vec![(0u32, vec![1, 2]), (1, vec![]), (2, vec![])];
    let h_a = CfgHasher::wl_hash(&adj, 0);
    let adj_same_deg = vec![(7u32, vec![8, 9]), (8, vec![]), (9, vec![])];
    let h_b = CfgHasher::wl_hash(&adj_same_deg, 0);
    assert_eq!(h_a, h_b);
}

// ────────────────────────────────────────────────────────────────────────────
// 2. FunctionFeatures
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t06_features_self_similarity_with_cfg_hash() {
    let mut f = full_feat(0x1000, 4, 20, 5);
    f.string_refs = vec!["hi".into(), "world".into()];
    assert!((f.similarity(&f) - 1.0).abs() < 1e-5);
}

#[test]
fn t07_features_similarity_is_in_range() {
    let mut g = Lcg::new();
    for _ in 0..60 {
        let a = full_feat(
            g.next_u64(),
            g.range(0, 200),
            g.range(0, 1000),
            g.range(0, 400),
        );
        let b = full_feat(
            g.next_u64(),
            g.range(0, 200),
            g.range(0, 1000),
            g.range(0, 400),
        );
        let s = a.similarity(&b);
        assert!((0.0..=1.0).contains(&s), "similarity out of range: {}", s);
    }
}

#[test]
fn t08_features_zero_cfg_hash_means_no_bonus() {
    let mut a = mkfeat(1);
    let mut b = mkfeat(2);
    a.basic_block_count = 5;
    b.basic_block_count = 5;
    a.instruction_count = 10;
    b.instruction_count = 10;
    a.edge_count = 6;
    b.edge_count = 6;
    a.loop_count = 0;
    b.loop_count = 0;
    // cfg_hash == 0 on both: should NOT contribute the 0.4 cfg bonus.
    let s = a.similarity(&b);
    // Max possible without cfg_hash bonus = 0.60 (bb+instr+edge+loop+str). Anything
    // ≥ that would mean the 0.40 cfg bonus leaked in.
    assert!(s <= 0.60 + 1e-5, "no cfg bonus expected, got {}", s);
    assert!(s < 1.0);
}

#[test]
fn t09_features_can_match_5x_boundary() {
    let mut a = mkfeat(1);
    let mut b = mkfeat(2);
    a.basic_block_count = 10;
    b.basic_block_count = 50;
    a.instruction_count = 10;
    b.instruction_count = 10;
    // 10 vs 50 = exactly 5x — boundary depends on impl; check it does not panic
    let _ = a.can_match(&b);
    a.basic_block_count = 10;
    b.basic_block_count = 51; // beyond 5x
    a.instruction_count = 10;
    b.instruction_count = 10;
    assert!(!a.can_match(&b));
}

#[test]
fn t10_features_can_match_zero_vs_nonzero() {
    let mut a = mkfeat(1);
    let mut b = mkfeat(2);
    a.basic_block_count = 0;
    b.basic_block_count = 0;
    a.instruction_count = 0;
    b.instruction_count = 0;
    // Identical zeros: should be considered matchable.
    assert!(a.can_match(&b));
}

// ────────────────────────────────────────────────────────────────────────────
// 3. BinarySnapshot
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t11_snapshot_add_function_creates_call_graph_node() {
    let mut s = BinarySnapshot::new("a.bin");
    s.add_function(mkfeat(0x100));
    assert_eq!(s.function_count(), 1);
    assert!(s.function_at(0x100).is_some());
    assert_eq!(s.call_targets(0x100), Vec::<u64>::new());
    assert_eq!(s.callers_of(0x100), Vec::<u64>::new());
}

#[test]
fn t12_snapshot_add_call_auto_creates_nodes() {
    let mut s = BinarySnapshot::new("a.bin");
    s.add_call(0x100, 0x200);
    assert_eq!(s.call_edge_count(), 1);
    assert_eq!(s.call_targets(0x100), vec![0x200]);
    assert_eq!(s.callers_of(0x200), vec![0x100]);
}

#[test]
fn t13_snapshot_call_targets_unknown_returns_empty() {
    let s = BinarySnapshot::new("a.bin");
    assert!(s.call_targets(0xDEAD).is_empty());
    assert!(s.callers_of(0xDEAD).is_empty());
}

#[test]
fn t14_snapshot_fuzz_no_panic() {
    let mut g = Lcg::new();
    let mut s = BinarySnapshot::new("fuzz");
    for _ in 0..200 {
        let a = g.next_u64() & 0xFFFF;
        let b = g.next_u64() & 0xFFFF;
        s.add_function(mkfeat(a));
        s.add_call(a, b);
    }
    assert!(s.function_count() > 0);
    assert!(s.call_edge_count() > 0);
}

// ────────────────────────────────────────────────────────────────────────────
// 4. MatchKind
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t15_matchkind_display_roundtrip_known() {
    let kinds = [
        MatchKind::ExactHash,
        MatchKind::CfgHash,
        MatchKind::CallGraphPropagation,
        MatchKind::NameMatch,
        MatchKind::ManualMatch,
        MatchKind::Heuristic,
    ];
    // No two display strings collide.
    let mut seen: HashSet<String> = HashSet::new();
    for k in kinds {
        assert!(seen.insert(k.to_string()));
    }
}

#[test]
fn t16_matchkind_priority_ordering() {
    assert!(MatchKind::ExactHash.priority() > MatchKind::NameMatch.priority());
    assert!(MatchKind::NameMatch.priority() > MatchKind::CfgHash.priority());
    assert!(MatchKind::CfgHash.priority() > MatchKind::CallGraphPropagation.priority());
    assert!(MatchKind::CallGraphPropagation.priority() > MatchKind::Heuristic.priority());
}

#[test]
fn t17_matchkind_reliable_subset() {
    assert!(MatchKind::ExactHash.is_reliable());
    assert!(MatchKind::NameMatch.is_reliable());
    assert!(!MatchKind::CfgHash.is_reliable());
    assert!(!MatchKind::Heuristic.is_reliable());
    assert!(!MatchKind::CallGraphPropagation.is_reliable());
    assert!(!MatchKind::ManualMatch.is_reliable());
}

#[test]
fn t18_matchkind_eq_display_consistency() {
    // Eq reflexive + display equality for ≥30 pairs.
    let kinds = [
        MatchKind::ExactHash,
        MatchKind::CfgHash,
        MatchKind::CallGraphPropagation,
        MatchKind::NameMatch,
        MatchKind::ManualMatch,
        MatchKind::Heuristic,
    ];
    let mut pairs_checked = 0;
    for a in kinds {
        for b in kinds {
            if a == b {
                assert_eq!(a.to_string(), b.to_string());
                assert_eq!(a.priority(), b.priority());
                assert_eq!(a.is_reliable(), b.is_reliable());
            } else {
                assert_ne!(a, b);
            }
            pairs_checked += 1;
        }
    }
    assert!(pairs_checked >= 30);
}

// ────────────────────────────────────────────────────────────────────────────
// 5. FunctionMatch
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t19_match_with_similarity_clamps() {
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic)
        .with_similarity(2.5);
    assert!((m.similarity - 1.0).abs() < 1e-6);
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic)
        .with_similarity(-0.5);
    assert!((m.similarity - 0.0).abs() < 1e-6);
}

#[test]
fn t20_match_quality_labels_boundaries() {
    let mk = |s: f32, c: f32| {
        let mut m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic)
            .with_similarity(s);
        m.confidence = c;
        m
    };
    assert_eq!(mk(1.0, 1.0).quality_label(), "Identical");
    assert_eq!(mk(0.99, 1.0).quality_label(), "Identical");
    assert_eq!(mk(0.80, 0.80).quality_label(), "Good");
    assert_eq!(mk(0.75, 0.75).quality_label(), "Good");
    assert_eq!(mk(0.70, 0.99).quality_label(), "Partial");
    assert_eq!(mk(0.50, 0.99).quality_label(), "Partial");
    assert_eq!(mk(0.10, 0.10).quality_label(), "Poor");
}

#[test]
fn t21_match_reliable_defaults_one() {
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::ExactHash);
    assert_eq!(m.similarity, 1.0);
    assert_eq!(m.confidence, 1.0);
    let m = FunctionMatch::new(Address::new(1), Address::new(2), MatchKind::Heuristic);
    assert_eq!(m.similarity, 0.0);
    assert_eq!(m.confidence, 0.0);
}

// ────────────────────────────────────────────────────────────────────────────
// 6. BinDiffer phases
// ────────────────────────────────────────────────────────────────────────────

fn snap_with_funcs(name: &str, funcs: Vec<FunctionFeatures>) -> BinarySnapshot {
    let mut s = BinarySnapshot::new(name);
    for f in funcs {
        s.add_function(f);
    }
    s
}

#[test]
fn t22_phase1_unique_exact_hash_matches() {
    let mut fa = mkfeat(0x100);
    fa.byte_hash = 0xAA;
    let mut fb = mkfeat(0x200);
    fb.byte_hash = 0xAA;
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb]);
    let d = BinDiffer::new();
    let m = d.match_by_exact_hash(&a, &b);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, MatchKind::ExactHash);
    assert_eq!(m[0].address_a.as_u64(), 0x100);
    assert_eq!(m[0].address_b.as_u64(), 0x200);
}

#[test]
fn t23_phase1_skips_ambiguous_hash() {
    let mut fa = mkfeat(0x100);
    fa.byte_hash = 0xAA;
    let mut fb1 = mkfeat(0x200);
    fb1.byte_hash = 0xAA;
    let mut fb2 = mkfeat(0x300);
    fb2.byte_hash = 0xAA;
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb1, fb2]);
    let d = BinDiffer::new();
    assert!(d.match_by_exact_hash(&a, &b).is_empty());
}

#[test]
fn t24_phase1_skips_zero_byte_hash() {
    let fa = mkfeat(0x100); // byte_hash = 0
    let fb = mkfeat(0x200);
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb]);
    let d = BinDiffer::new();
    assert!(d.match_by_exact_hash(&a, &b).is_empty());
}

#[test]
fn t25_phase2_cfg_hash_skips_already_matched() {
    let mut fa = mkfeat(0x100);
    fa.cfg_hash = 0xC0;
    let mut fb = mkfeat(0x200);
    fb.cfg_hash = 0xC0;
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb]);
    let d = BinDiffer::new();
    let mut already = HashSet::new();
    already.insert((0x100u64, 0x200u64));
    assert!(d.match_by_cfg_hash(&a, &b, &already).is_empty());
}

#[test]
fn t26_phase2_skips_duplicated_cfg_hash() {
    let mut fa = mkfeat(0x100);
    fa.cfg_hash = 0xC0;
    let mut fb1 = mkfeat(0x200);
    fb1.cfg_hash = 0xC0;
    let mut fb2 = mkfeat(0x300);
    fb2.cfg_hash = 0xC0;
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb1, fb2]);
    let d = BinDiffer::new();
    assert!(d.match_by_cfg_hash(&a, &b, &HashSet::new()).is_empty());
}

#[test]
fn t27_phase3_name_unique_only() {
    let mut fa = mkfeat(0x100);
    fa.name = Some("foo".into());
    let mut fb = mkfeat(0x200);
    fb.name = Some("foo".into());
    let mut fb2 = mkfeat(0x300);
    fb2.name = Some("foo".into());
    let a = snap_with_funcs("a", vec![fa.clone()]);
    let b_dup = snap_with_funcs("b", vec![fb.clone(), fb2.clone()]);
    let b_uniq = snap_with_funcs("b", vec![fb.clone()]);
    let d = BinDiffer::new();
    // Duplicate name → no match
    assert!(d.match_by_name(&a, &b_dup, &HashSet::new()).is_empty());
    // Unique name → match
    let m = d.match_by_name(&a, &b_uniq, &HashSet::new());
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].kind, MatchKind::NameMatch);
}

#[test]
fn t28_phase3_unnamed_skipped() {
    let a = snap_with_funcs("a", vec![mkfeat(0x100)]);
    let b = snap_with_funcs("b", vec![mkfeat(0x200)]);
    let d = BinDiffer::new();
    assert!(d.match_by_name(&a, &b, &HashSet::new()).is_empty());
}

#[test]
fn t29_phase4_propagation_unique_callee() {
    // Seed match: 0x100 ↔ 0x200. 0x100 calls 0x101; 0x200 calls 0x201.
    // Both callees should be matched by propagation.
    let mut fa1 = full_feat(0x100, 3, 10, 3);
    fa1.cfg_hash = 0xAA;
    let mut fa2 = full_feat(0x101, 3, 10, 3);
    fa2.cfg_hash = 0xBB;
    let mut fb1 = full_feat(0x200, 3, 10, 3);
    fb1.cfg_hash = 0xAA;
    let mut fb2 = full_feat(0x201, 3, 10, 3);
    fb2.cfg_hash = 0xBB;
    let mut a = snap_with_funcs("a", vec![fa1, fa2]);
    a.add_call(0x100, 0x101);
    let mut b = snap_with_funcs("b", vec![fb1, fb2]);
    b.add_call(0x200, 0x201);

    let d = BinDiffer::new();
    let mut matches = vec![FunctionMatch::new(
        Address::new(0x100),
        Address::new(0x200),
        MatchKind::CfgHash,
    )
    .with_similarity(1.0)];
    d.propagate_matches(&mut matches, &a, &b);
    assert!(matches
        .iter()
        .any(|m| m.address_a.as_u64() == 0x101 && m.address_b.as_u64() == 0x201));
}

#[test]
fn t30_phase4_skips_ambiguous_multi_callees() {
    // 0x100 calls 0x101 AND 0x102; should NOT propagate.
    let fa1 = full_feat(0x100, 3, 10, 3);
    let fa2 = full_feat(0x101, 3, 10, 3);
    let fa3 = full_feat(0x102, 3, 10, 3);
    let fb1 = full_feat(0x200, 3, 10, 3);
    let fb2 = full_feat(0x201, 3, 10, 3);
    let mut a = snap_with_funcs("a", vec![fa1, fa2, fa3]);
    a.add_call(0x100, 0x101);
    a.add_call(0x100, 0x102);
    let mut b = snap_with_funcs("b", vec![fb1, fb2]);
    b.add_call(0x200, 0x201);

    let d = BinDiffer::new();
    let mut matches = vec![FunctionMatch::new(
        Address::new(0x100),
        Address::new(0x200),
        MatchKind::ExactHash,
    )
    .with_similarity(1.0)];
    let before = matches.len();
    d.propagate_matches(&mut matches, &a, &b);
    assert_eq!(matches.len(), before, "should not propagate ambiguously");
}

#[test]
fn t31_find_candidates_respects_excluded_and_threshold() {
    let mut fa = full_feat(0x100, 5, 20, 5);
    fa.cfg_hash = 0xAA;
    let mut fb_good = full_feat(0x200, 5, 20, 5);
    fb_good.cfg_hash = 0xAA;
    let fb_bad = full_feat(0x300, 100, 1000, 200);
    let b = snap_with_funcs("b", vec![fb_good, fb_bad]);

    let d = BinDiffer::new().with_min_similarity(0.5);
    let cands = d.find_candidates(&fa, &b, &HashSet::new(), 10);
    assert!(!cands.is_empty());
    assert_eq!(cands[0].0, 0x200);
    // Now exclude 0x200.
    let mut excl = HashSet::new();
    excl.insert(0x200u64);
    let cands = d.find_candidates(&fa, &b, &excl, 10);
    // bb_bad is filtered by can_match (instr 20 vs 1000 > 5x), so empty.
    assert!(cands.is_empty());
}

#[test]
fn t32_detailed_similarity_byte_bonus_and_cc_penalty() {
    let mut a = full_feat(0x100, 5, 20, 5);
    let mut b = full_feat(0x200, 5, 20, 5);
    a.cfg_hash = 0xC0;
    b.cfg_hash = 0xC0;
    a.byte_hash = 0xAA;
    b.byte_hash = 0xAA;
    a.cyclomatic_complexity = 5;
    b.cyclomatic_complexity = 5;
    let d = BinDiffer::new();
    let s = d.detailed_similarity(&a, &b);
    assert!(s >= 0.0 && s <= 1.0);

    // High cyclomatic mismatch — penalty applies.
    let mut c = a.clone();
    c.cyclomatic_complexity = 20;
    let s2 = d.detailed_similarity(&a, &c);
    assert!(s2 < s);
}

#[test]
fn t33_full_diff_pipeline_smoke() {
    let mut fa = mkfeat(0x100);
    fa.byte_hash = 0xAA;
    fa.cfg_hash = 0xC0;
    fa.basic_block_count = 4;
    fa.instruction_count = 20;
    fa.name = Some("alpha".into());
    let mut fb = mkfeat(0x200);
    fb.byte_hash = 0xAA;
    fb.cfg_hash = 0xC0;
    fb.basic_block_count = 4;
    fb.instruction_count = 20;
    fb.name = Some("alpha".into());

    let a = snap_with_funcs("a.bin", vec![fa]);
    let b = snap_with_funcs("b.bin", vec![fb]);
    let result = BinDiffer::new().diff(a, b);

    assert_eq!(result.function_matches.len(), 1);
    assert_eq!(result.unmatched_a.len(), 0);
    assert_eq!(result.unmatched_b.len(), 0);
    assert!(result.stats.identical_count >= 1);
    assert_eq!(result.match_for_a(0x100).unwrap().address_b.as_u64(), 0x200);
    assert_eq!(result.match_for_b(0x200).unwrap().address_a.as_u64(), 0x100);
    let _summary = result.print_summary();
}

#[test]
fn t34_diff_unmatched_functions_reported() {
    let mut fa1 = mkfeat(0x100);
    fa1.byte_hash = 0xAA;
    let mut fb1 = mkfeat(0x200);
    fb1.byte_hash = 0xAA;
    // Make 0x101 wildly different from 0x201 (5x+ block count) so can_match=false.
    let mut fa2 = mkfeat(0x101);
    fa2.basic_block_count = 2;
    fa2.instruction_count = 4;
    let mut fb2 = mkfeat(0x201);
    fb2.basic_block_count = 100;
    fb2.instruction_count = 500;

    let a = snap_with_funcs("a", vec![fa1, fa2]);
    let b = snap_with_funcs("b", vec![fb1, fb2]);
    let r = BinDiffer::new().diff(a, b);
    // 0x100/0x200 match by hash; 0x101/0x201 fail can_match() filter.
    assert!(r.unmatched_a.contains(&0x101));
    assert!(r.unmatched_b.contains(&0x201));
}

// ────────────────────────────────────────────────────────────────────────────
// 7. DiffReport outputs
// ────────────────────────────────────────────────────────────────────────────

fn small_diff_result() -> DiffResult {
    let mut fa = mkfeat(0x100);
    fa.byte_hash = 0xAA;
    fa.name = Some("foo".into());
    let mut fb = mkfeat(0x200);
    fb.byte_hash = 0xAA;
    fb.name = Some("foo".into());
    let a = snap_with_funcs("aaa", vec![fa]);
    let b = snap_with_funcs("bbb", vec![fb]);
    BinDiffer::new().diff(a, b)
}

#[test]
fn t35_report_csv_contains_header_and_row() {
    let r = small_diff_result();
    let rep = DiffReport::new(r);
    let csv = rep.csv();
    assert!(csv.starts_with("addr_a,addr_b,similarity,kind,name_a,name_b\n"));
    assert!(csv.contains("0x100"));
    assert!(csv.contains("0x200"));
}

#[test]
fn t36_report_html_well_formed() {
    let r = small_diff_result();
    let rep = DiffReport::new(r);
    let html = rep.html();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("</html>"));
    assert!(html.contains("0x100"));
}

#[test]
fn t37_report_json_is_array_with_keys() {
    let r = small_diff_result();
    let rep = DiffReport::new(r);
    let json = rep.json();
    assert!(json.starts_with('['));
    assert!(json.ends_with(']'));
    assert!(json.contains("\"addr_a\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"quality\""));
}

#[test]
fn t38_report_diff_for_function_missing_returns_none() {
    let r = small_diff_result();
    let rep = DiffReport::new(r);
    assert!(rep.diff_for_function(0xDEAD_BEEF).is_none());
    assert!(rep.diff_for_function(0x100).is_some());
}

// ────────────────────────────────────────────────────────────────────────────
// 8. FunctionInfo / similarity_score
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t39_similarity_score_zero_when_empty() {
    let a = mkinfo(1);
    let b = mkinfo(2);
    let s = similarity_score(&a, &b);
    // No name, no bytes; cfg ratio = 1 (all zeros equal) → 0.20.
    // md_index 0 == 0 short-circuits to 1.0 → 0.10. Total = 0.30.
    assert!((0.0..=1.0).contains(&s));
    assert!((s - 0.30).abs() < 1e-6, "got {}", s);
}

#[test]
fn t40_similarity_score_perfect_match() {
    let mut a = mkinfo(1);
    a.name = Some("foo".into());
    a.bytes_crc32 = 0xDEAD;
    a.in_edges = 2;
    a.out_edges = 3;
    a.bb_count = 5;
    a.md_index = 1234;
    let mut b = a.clone();
    b.address = 2;
    let s = similarity_score(&a, &b);
    assert!((s - 1.0).abs() < 1e-6);
}

#[test]
fn t41_similarity_score_name_only() {
    let mut a = mkinfo(1);
    a.name = Some("x".into());
    let mut b = mkinfo(2);
    b.name = Some("x".into());
    let s = similarity_score(&a, &b);
    // name 0.40 + cfg (all zero → 1.0) * 0.20 + md (0==0 → 1.0) * 0.10 = 0.70
    assert!((s - 0.70).abs() < 1e-6, "got {}", s);
}

#[test]
fn t42_function_info_from_features_roundtrip_metadata() {
    let mut f = full_feat(0xABCD, 7, 30, 9);
    f.name = Some("k".into());
    f.caller_count = 2;
    f.callee_count = 4;
    let info: FunctionInfo = (&f).into();
    assert_eq!(info.address, 0xABCD);
    assert_eq!(info.name.as_deref(), Some("k"));
    assert_eq!(info.bb_count, 7);
    assert_eq!(info.in_edges, 2);
    assert_eq!(info.out_edges, 4);
    // bytes_crc32 = lower 32 bits of byte_hash
    assert_eq!(info.bytes_crc32, (f.byte_hash & 0xFFFF_FFFF) as u32);
}

// ────────────────────────────────────────────────────────────────────────────
// 9. HungarianSolver
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t43_hungarian_identity_costs() {
    // Diagonal-zero matrix → identity assignment.
    let cost = vec![
        vec![0.0, 1.0, 1.0],
        vec![1.0, 0.0, 1.0],
        vec![1.0, 1.0, 0.0],
    ];
    let sol = HungarianSolver::new(cost).solve();
    let mut s: Vec<(usize, usize)> = sol;
    s.sort();
    assert_eq!(s, vec![(0, 0), (1, 1), (2, 2)]);
}

#[test]
fn t44_hungarian_offdiagonal_zero() {
    // Optimal: (0,1) (1,0)
    let cost = vec![vec![5.0, 0.0], vec![0.0, 5.0]];
    let sol = HungarianSolver::new(cost).solve();
    let mut s = sol;
    s.sort();
    assert_eq!(s, vec![(0, 1), (1, 0)]);
}

#[test]
fn t45_hungarian_rectangular_pad() {
    let cost = vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]];
    let solver = HungarianSolver::new(cost);
    assert_eq!(solver.original_cols(), 3);
    let sol = solver.solve();
    // We get one pair per original row at most; padded rows may add ones.
    let originals: Vec<_> = sol.into_iter().filter(|&(r, _)| r < 2).collect();
    assert!(!originals.is_empty());
}

#[test]
#[should_panic]
fn t46_hungarian_empty_panics_should_panic() {
    let _ = HungarianSolver::new(Vec::<Vec<f64>>::new());
}

#[test]
#[should_panic]
fn t47_hungarian_ragged_panics_should_panic() {
    let cost = vec![vec![1.0, 2.0], vec![3.0]];
    let _ = HungarianSolver::new(cost);
}

#[test]
fn t48_hungarian_fuzz_returns_valid_assignment() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let n = (g.range(1, 6)) as usize;
        let cost: Vec<Vec<f64>> = (0..n)
            .map(|_| {
                (0..n)
                    .map(|_| (g.next_u32() % 100) as f64)
                    .collect()
            })
            .collect();
        let sol = HungarianSolver::new(cost).solve();
        // No row or col is used twice.
        let rows: HashSet<usize> = sol.iter().map(|&(r, _)| r).collect();
        let cols: HashSet<usize> = sol.iter().map(|&(_, c)| c).collect();
        assert_eq!(rows.len(), sol.len());
        assert_eq!(cols.len(), sol.len());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 10. match_functions_hungarian & BinDiff facade
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t49_match_hungarian_empty_inputs() {
    let empty: Vec<FunctionInfo> = vec![];
    let one = vec![{
        let mut i = mkinfo(1);
        i.name = Some("x".into());
        i
    }];
    assert!(match_functions_hungarian(&empty, &one, 0.0).is_empty());
    assert!(match_functions_hungarian(&one, &empty, 0.0).is_empty());
}

#[test]
fn t50_match_hungarian_threshold_drops_low_scores() {
    let a = vec![mkinfo(1)];
    let b = vec![mkinfo(2)];
    // Default similarity for empty-info pairs is ~0.20; threshold above must drop.
    let m_low = match_functions_hungarian(&a, &b, 0.0);
    assert_eq!(m_low.len(), 1);
    let m_high = match_functions_hungarian(&a, &b, 0.99);
    assert!(m_high.is_empty());
}

#[test]
fn t51_match_hungarian_sorts_descending() {
    let mk = |addr: u64, name: &str, crc: u32| {
        let mut i = mkinfo(addr);
        i.name = Some(name.into());
        i.bytes_crc32 = crc;
        i
    };
    let a = vec![mk(1, "alpha", 0xAAA), mk(2, "beta", 0xBBB)];
    let b = vec![mk(11, "alpha", 0xAAA), mk(12, "beta", 0xCCC)];
    let r = match_functions_hungarian(&a, &b, 0.0);
    assert!(r.len() >= 2);
    for i in 1..r.len() {
        assert!(r[i - 1].similarity >= r[i].similarity);
    }
}

#[test]
fn t52_bindiff_facade_runs_clean() {
    let mut fa = mkfeat(0x100);
    fa.byte_hash = 0xAA;
    fa.name = Some("f".into());
    let mut fb = mkfeat(0x200);
    fb.byte_hash = 0xAA;
    fb.name = Some("f".into());
    let a = snap_with_funcs("a", vec![fa]);
    let b = snap_with_funcs("b", vec![fb]);
    let r = BinDiff::new().run(a, b);
    assert_eq!(r.function_matches.len(), 1);
    assert!(r.function_matches[0].is_identical());
}

#[test]
fn t53_bindiff_with_differ_overrides() {
    let differ = BinDiffer::new()
        .with_min_similarity(0.99)
        .without_propagation();
    assert_eq!(differ.min_similarity, 0.99);
    assert!(!differ.enable_propagation);
    let bd = BinDiff::with_differ(differ);
    let a = snap_with_funcs("a", vec![mkfeat(1)]);
    let b = snap_with_funcs("b", vec![mkfeat(2)]);
    let r = bd.run(a, b);
    // No real signals → no matches.
    assert!(r.function_matches.is_empty());
}

#[test]
fn t54_hungarian_threshold_const_value() {
    // Lock in the public const for downstream callers.
    assert_eq!(HUNGARIAN_THRESHOLD, 2000);
}

// ────────────────────────────────────────────────────────────────────────────
// 11. Send + Sync threaded stress on documented Send+Sync types
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t55_function_features_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FunctionFeatures>();
    assert_send_sync::<FunctionInfo>();
    assert_send_sync::<FunctionMatch>();
    assert_send_sync::<MatchKind>();

    let shared = Arc::new({
        let mut f = full_feat(0x100, 8, 50, 10);
        f.string_refs = vec!["a".into(), "b".into()];
        f
    });

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = Arc::clone(&shared);
            thread::spawn(move || {
                let mut acc = 0.0_f32;
                for _ in 0..100 {
                    acc += s.similarity(&s);
                }
                acc
            })
        })
        .collect();
    let mut total = 0.0;
    for h in handles {
        total += h.join().unwrap();
    }
    // 4 threads * 100 self-similarities ≈ 400.0
    assert!((total - 400.0).abs() < 1e-3);
}

#[test]
fn t56_diffstats_by_kind_counts_correct() {
    let mut fa1 = mkfeat(0x100);
    fa1.byte_hash = 0xAA;
    let mut fb1 = mkfeat(0x200);
    fb1.byte_hash = 0xAA;

    let mut fa2 = mkfeat(0x101);
    fa2.name = Some("nm".into());
    let mut fb2 = mkfeat(0x201);
    fb2.name = Some("nm".into());

    let a = snap_with_funcs("a", vec![fa1, fa2]);
    let b = snap_with_funcs("b", vec![fb1, fb2]);
    let r = BinDiffer::new().diff(a, b);
    let by = &r.stats.by_kind;
    let total: usize = by.values().sum();
    assert_eq!(total, r.stats.matched_count);
}

// ────────────────────────────────────────────────────────────────────────────
// 12. top_matches / identical / changed iterators
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t57_top_matches_capped() {
    let r = small_diff_result();
    let top = r.top_matches_by_similarity(5);
    assert!(top.len() <= r.function_matches.len());
}

#[test]
fn t58_identical_and_changed_partition() {
    let r = small_diff_result();
    let ident = r.identical_functions().count();
    let changed = r.changed_functions().count();
    assert_eq!(ident + changed, r.function_matches.len());
}

// ────────────────────────────────────────────────────────────────────────────
// 13. Boundary / overflow safety on detailed_similarity & md_index path
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t59_detailed_similarity_handles_zero_cc() {
    let mut a = mkfeat(0x100);
    a.cyclomatic_complexity = 0;
    let mut b = mkfeat(0x200);
    b.cyclomatic_complexity = 10;
    // Should not panic on div by zero.
    let s = BinDiffer::new().detailed_similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn t60_features_max_values_no_overflow() {
    let mut a = mkfeat(u64::MAX);
    a.basic_block_count = u32::MAX;
    a.instruction_count = u32::MAX;
    a.edge_count = u32::MAX;
    a.loop_count = u32::MAX;
    a.cyclomatic_complexity = u32::MAX;
    a.byte_hash = u64::MAX;
    a.cfg_hash = u64::MAX;
    let b = a.clone();
    // similarity should be 1.0 (all features identical, cfg_hash matches).
    assert!((a.similarity(&b) - 1.0).abs() < 1e-5);
    // FunctionInfo conversion shouldn't overflow either.
    let info: FunctionInfo = (&a).into();
    assert_eq!(info.address, u64::MAX);
    let _ = similarity_score(&info, &info);
}

#[test]
fn t61_matchkind_display_matches_priority_set() {
    // All six display strings, deterministic order check.
    let names: Vec<String> = [
        MatchKind::ExactHash,
        MatchKind::CfgHash,
        MatchKind::CallGraphPropagation,
        MatchKind::NameMatch,
        MatchKind::ManualMatch,
        MatchKind::Heuristic,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert!(names.contains(&"ExactHash".to_string()));
    assert!(names.contains(&"Heuristic".to_string()));
    assert!(names.contains(&"CallGraphPropagation".to_string()));
}

// ────────────────────────────────────────────────────────────────────────────
// 14. Pipeline determinism: repeated runs produce same stats
// ────────────────────────────────────────────────────────────────────────────

fn build_pair() -> (BinarySnapshot, BinarySnapshot) {
    let mut g = Lcg::new();
    let mut a_funcs = Vec::new();
    let mut b_funcs = Vec::new();
    for i in 0..30u64 {
        let mut fa = mkfeat(0x1000 + i);
        let mut fb = mkfeat(0x2000 + i);
        let bb = (g.next_u32() % 10) + 1;
        let instr = bb * 3;
        let edges = bb;
        fa.basic_block_count = bb;
        fa.instruction_count = instr;
        fa.edge_count = edges;
        fa.cfg_hash = i.wrapping_add(1);
        fa.byte_hash = i.wrapping_add(0x100);
        fb.basic_block_count = bb;
        fb.instruction_count = instr;
        fb.edge_count = edges;
        fb.cfg_hash = i.wrapping_add(1);
        fb.byte_hash = i.wrapping_add(0x100);
        a_funcs.push(fa);
        b_funcs.push(fb);
    }
    let a = snap_with_funcs("a", a_funcs);
    let b = snap_with_funcs("b", b_funcs);
    (a, b)
}

#[test]
fn t62_pipeline_deterministic_match_count() {
    let (a1, b1) = build_pair();
    let (a2, b2) = build_pair();
    let r1 = BinDiffer::new().diff(a1, b1);
    let r2 = BinDiffer::new().diff(a2, b2);
    assert_eq!(r1.function_matches.len(), r2.function_matches.len());
    assert_eq!(r1.stats.matched_count, r2.stats.matched_count);
}

#[test]
fn t63_pipeline_all_thirty_match() {
    let (a, b) = build_pair();
    let r = BinDiffer::new().diff(a, b);
    // Each pair shares a unique byte_hash and cfg_hash → all should match.
    assert_eq!(r.function_matches.len(), 30);
    assert!(r.unmatched_a.is_empty());
    assert!(r.unmatched_b.is_empty());
}

#[test]
fn t64_matchkind_display_fromstr_substring_roundtrip() {
    // No FromStr defined; test that Display string fits in a HashMap-key flow
    // (used by DiffStats.by_kind).
    let mut m: HashMap<String, MatchKind> = HashMap::new();
    for k in [
        MatchKind::ExactHash,
        MatchKind::CfgHash,
        MatchKind::CallGraphPropagation,
        MatchKind::NameMatch,
        MatchKind::ManualMatch,
        MatchKind::Heuristic,
    ] {
        m.insert(k.to_string(), k);
    }
    assert_eq!(m.len(), 6);
    assert_eq!(m.get("ExactHash"), Some(&MatchKind::ExactHash));
}
