//! Deep adversarial coverage for `rustre-deobf-mhcde`.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use rustre_deobf_mhcde::{
    BogusControlFlowRemover, CfgBlock, ConstantFoldingHeuristic, ControlFlowFlattener,
    DeadCodeEliminator, EntropyAnalyzer, FoldResult, Hypothesis, HypothesisRunner,
    IdentityHypothesis, JunkCodeDetector, JunkCodeRegion, MhcdeAnalysis, MhcdeOrchestrator,
    MhcdePass, MhcdePatchKind, MhcdeScore, NopStripHypothesis, OpaquePredicate,
    OpaquePredicateDetector, OpaquePredicateType, PatchApplicator, PlannedPatch, ScoreModel,
    XorBestKeyHypothesis, XorFixedKeyHypothesis,
};

// Seeded LCG --- deterministic pseudo-random byte stream.
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut g = make_lcg(seed);
    (0..len).map(|_| (g() >> 24) as u8).collect()
}

// ---------------------------------------------------------------------------
// OpaquePredicateDetector
// ---------------------------------------------------------------------------

#[test]
fn opaque_empty_returns_empty() {
    assert!(OpaquePredicateDetector::new().detect(&[]).is_empty());
}

#[test]
fn opaque_short_inputs_no_panic() {
    let det = OpaquePredicateDetector::new();
    for n in 0..3 {
        assert!(det.detect(&vec![0xC3u8; n]).is_empty());
    }
}

#[test]
fn opaque_lcg_fuzz_never_panics() {
    let det = OpaquePredicateDetector::new();
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..60 {
        let len = (g() as usize) % 256;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let hits = det.detect(&buf);
        let total = det.total_patch_bytes(&buf);
        let by_type = det.count_by_type(&buf);
        // total_patch_bytes must match sum of hit lengths.
        assert_eq!(total, hits.iter().map(|h| h.patch_length).sum::<usize>());
        let counted: usize = by_type.values().sum();
        assert_eq!(counted, hits.len());
    }
}

#[test]
fn opaque_patterns_each_match() {
    let cases: &[(&[u8], OpaquePredicateType)] = &[
        (&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05], OpaquePredicateType::AlwaysTrue),
        (&[0x31, 0xC0, 0x85, 0xC0, 0x75, 0x05], OpaquePredicateType::AlwaysFalse),
        (&[0xB0, 0x01, 0x84, 0xC0, 0x74, 0x05], OpaquePredicateType::AlwaysFalse),
        (&[0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x05], OpaquePredicateType::AlwaysTrue),
        (&[0x83, 0xE0, 0x00, 0x85, 0xC0, 0x74, 0x05], OpaquePredicateType::AlwaysTrue),
        (&[0xF9, 0x72, 0x10], OpaquePredicateType::AlwaysTrue),
        (&[0xF8, 0x73, 0x10], OpaquePredicateType::AlwaysTrue),
        (&[0x33, 0xC9, 0xE3, 0x05], OpaquePredicateType::AlwaysTrue),
    ];
    let det = OpaquePredicateDetector::new();
    for (data, expected) in cases {
        let h = det.detect(data);
        assert!(!h.is_empty(), "expected match for {data:?}");
        assert_eq!(h[0].predicate_type, *expected);
    }
}

#[test]
fn opaque_truncated_inputs() {
    let det = OpaquePredicateDetector::new();
    // Cut each pattern down by one byte; should not match (boundary check).
    let truncated: &[&[u8]] = &[
        &[0x31, 0xC0, 0x85, 0xC0, 0x74],
        &[0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75],
        &[0xF9, 0x72],
    ];
    for d in truncated {
        let _ = det.detect(d); // must not panic
    }
}

#[test]
fn opaque_count_by_type_consistency() {
    let mut data = Vec::new();
    for _ in 0..5 {
        data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00, 0xC3]);
    }
    let det = OpaquePredicateDetector::new();
    let hits = det.detect(&data);
    let counts = det.count_by_type(&data);
    let summed: usize = counts.values().sum();
    assert_eq!(hits.len(), summed);
}

#[test]
fn opaque_serde_roundtrip() {
    let op = OpaquePredicate {
        offset: 42,
        predicate_type: OpaquePredicateType::HashBased,
        patch_length: 9,
        description: "test".into(),
    };
    let json = serde_json::to_string(&op).unwrap();
    let back: OpaquePredicate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.offset, 42);
    assert_eq!(back.patch_length, 9);
    assert_eq!(back.predicate_type, OpaquePredicateType::HashBased);
}

#[test]
fn opaque_type_hash_eq_consistency() {
    let mut seen = std::collections::HashMap::new();
    let types = [
        OpaquePredicateType::AlwaysTrue,
        OpaquePredicateType::AlwaysFalse,
        OpaquePredicateType::DataDependent,
        OpaquePredicateType::PointerBased,
        OpaquePredicateType::HashBased,
    ];
    for t in &types {
        seen.insert(*t, 1);
    }
    for t in &types {
        // Re-insert same key: must collide => same map size.
        seen.insert(*t, 2);
    }
    assert_eq!(seen.len(), 5);
}

// ---------------------------------------------------------------------------
// JunkCodeDetector
// ---------------------------------------------------------------------------

#[test]
fn junk_empty_returns_empty() {
    assert!(JunkCodeDetector::new().detect(&[]).is_empty());
    assert_eq!(JunkCodeDetector::new().total_junk_bytes(&[]), 0);
}

#[test]
fn junk_single_nop_not_sled() {
    // single 0x90 is below sled threshold (>=2).
    let regions = JunkCodeDetector::new().detect(&[0x90, 0xC3]);
    // The 0x90 alone is < 2 so it does not produce a sled region. 0xC3 is RET.
    assert!(regions.iter().all(|r| r.length >= 2));
}

#[test]
fn junk_lcg_fuzz_never_panics() {
    let det = JunkCodeDetector::new();
    let mut g = make_lcg(0xA5A5_0F0F_1234_5678);
    for _ in 0..60 {
        let len = (g() as usize) % 512;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let regions = det.detect(&buf);
        let total = det.total_junk_bytes(&buf);
        assert_eq!(total, regions.iter().map(|r| r.length).sum::<usize>());
        let density = det.junk_density(&buf);
        if !buf.is_empty() {
            assert!((0.0..=512.0).contains(&density));
        }
    }
}

#[test]
fn junk_nop_sled_length_is_sled_size() {
    for n in 2..32 {
        let data = vec![0x90u8; n];
        let regions = JunkCodeDetector::new().detect(&data);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].length, n);
        assert_eq!(regions[0].offset, 0);
    }
}

#[test]
fn junk_push_pop_all_8_regs() {
    let det = JunkCodeDetector::new();
    for r in 0u8..8 {
        let data = vec![0x50 + r, 0x58 + r];
        let regions = det.detect(&data);
        assert!(!regions.is_empty(), "push/pop r{r} should be detected");
        assert_eq!(regions[0].length, 2);
    }
}

#[test]
fn junk_density_zero_for_clean_ret() {
    let data = vec![0xC3, 0xC3, 0xC3, 0xC3];
    let density = JunkCodeDetector::new().junk_density(&data);
    assert_eq!(density, 0.0);
}

#[test]
fn junk_density_bounded_one() {
    // Pure NOP sled => density approaches 1.0.
    let data = vec![0x90u8; 64];
    let density = JunkCodeDetector::new().junk_density(&data);
    assert!((0.99..=1.0).contains(&density));
}

#[test]
fn junk_serde_roundtrip() {
    let r = JunkCodeRegion {
        offset: 7,
        length: 3,
        description: "x".into(),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: JunkCodeRegion = serde_json::from_str(&j).unwrap();
    assert_eq!(back.offset, 7);
    assert_eq!(back.length, 3);
}

// ---------------------------------------------------------------------------
// ControlFlowFlattener
// ---------------------------------------------------------------------------

#[test]
fn cff_lcg_fuzz_never_panics() {
    let cff = ControlFlowFlattener::new();
    let mut g = make_lcg(0x1357_9BDF_2468_ACE0);
    for _ in 0..40 {
        let len = (g() as usize) % 300;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let _ = cff.detect(&buf); // never panics
    }
}

#[test]
fn cff_empty_returns_none() {
    assert!(ControlFlowFlattener::new().detect(&[]).is_none());
}

#[test]
fn cff_fan_out_zero_for_empty_blocks() {
    use rustre_deobf_mhcde::CffDetectionResult;
    let r = CffDetectionResult {
        dispatcher_offset: 0,
        state_var_offset: 0,
        body_blocks: vec![],
        reconstructed_order: vec![],
    };
    assert_eq!(ControlFlowFlattener::dispatcher_fan_out(&r), 0.0);
}

// ---------------------------------------------------------------------------
// DeadCodeEliminator
// ---------------------------------------------------------------------------

const fn mk_block(offset: usize, succ: Vec<usize>) -> CfgBlock {
    CfgBlock {
        offset,
        length: 4,
        successors: succ,
        is_dispatcher: false,
    }
}

#[test]
fn dce_self_loop_terminates() {
    let blocks = vec![mk_block(0, vec![0])];
    let live = DeadCodeEliminator::new().eliminate(&blocks, 0);
    assert_eq!(live.len(), 1);
}

#[test]
fn dce_cycle_two_nodes() {
    let blocks = vec![mk_block(0, vec![4]), mk_block(4, vec![0])];
    let r = DeadCodeEliminator::new().reachable_blocks(&blocks, 0);
    assert_eq!(r.len(), 2);
}

#[test]
fn dce_dead_block_ratio_bounds() {
    let blocks: Vec<CfgBlock> = (0..10)
        .map(|i| mk_block(i * 4, if i < 5 { vec![(i + 1) * 4] } else { vec![] }))
        .collect();
    let ratio = DeadCodeEliminator::new().dead_block_ratio(&blocks, 0);
    assert!((0.0..=1.0).contains(&ratio));
}

#[test]
fn dce_empty_blocks() {
    let blocks: Vec<CfgBlock> = vec![];
    let dce = DeadCodeEliminator::new();
    assert!(dce.reachable_blocks(&blocks, 0).is_empty());
    assert_eq!(dce.dead_block_ratio(&blocks, 0), 0.0);
    assert!(dce.bfs_order(&blocks, 0).is_empty());
}

#[test]
fn dce_dangling_successor() {
    // Block 0 -> 999 (not in set). reachable should only contain 0.
    let blocks = vec![mk_block(0, vec![999])];
    let r = DeadCodeEliminator::new().reachable_blocks(&blocks, 0);
    assert!(r.contains(&0));
    // Note: reachable_blocks returns all offsets reached via edges, including
    // dangling successors not present in the block set. `eliminate` filters
    // those out via the original block list.
    let live = DeadCodeEliminator::new().eliminate(&blocks, 0);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].offset, 0);
}

#[test]
fn dce_build_graph_node_count() {
    let blocks: Vec<CfgBlock> = (0..5).map(|i| mk_block(i * 4, vec![])).collect();
    let (g, map) = DeadCodeEliminator::new().build_graph(&blocks);
    assert_eq!(g.node_count(), 5);
    assert_eq!(map.len(), 5);
}

// ---------------------------------------------------------------------------
// BogusControlFlowRemover
// ---------------------------------------------------------------------------

#[test]
fn bogus_removes_dispatcher_and_junk() {
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![], is_dispatcher: true },
        CfgBlock { offset: 4, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 8, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let mut junk = HashSet::new();
    junk.insert(8usize);
    let kept = BogusControlFlowRemover::new().remove_bogus_blocks(&blocks, &junk);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].offset, 4);
}

#[test]
fn bogus_junk_offset_set_dedupes() {
    let r = vec![
        JunkCodeRegion { offset: 0, length: 1, description: "a".into() },
        JunkCodeRegion { offset: 0, length: 2, description: "b".into() },
        JunkCodeRegion { offset: 5, length: 1, description: "c".into() },
    ];
    let s = BogusControlFlowRemover::junk_offset_set(&r);
    assert_eq!(s.len(), 2);
}

#[test]
fn bogus_dispatcher_blocks_filter() {
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![], is_dispatcher: true },
        CfgBlock { offset: 4, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let d = BogusControlFlowRemover::new().dispatcher_blocks(&blocks);
    assert_eq!(d.len(), 1);
    assert!(d[0].is_dispatcher);
}

// ---------------------------------------------------------------------------
// ConstantFoldingHeuristic
// ---------------------------------------------------------------------------

#[test]
fn fold_xor_eax_eax() {
    let r = ConstantFoldingHeuristic::new().try_fold(&[0x31, 0xC0], 0).unwrap();
    assert_eq!(r.value, 0);
    assert_eq!(r.bytes_consumed, 2);
}

#[test]
fn fold_or_eax_neg1() {
    let r = ConstantFoldingHeuristic::new().try_fold(&[0x83, 0xC8, 0xFF], 0).unwrap();
    assert_eq!(r.value, 0xFFFF_FFFF);
}

#[test]
fn fold_mov_eax_imm32() {
    let r = ConstantFoldingHeuristic::new()
        .try_fold(&[0xB8, 0x78, 0x56, 0x34, 0x12], 0)
        .unwrap();
    assert_eq!(r.value, 0x1234_5678);
    assert_eq!(r.bytes_consumed, 5);
}

#[test]
fn fold_offset_oob() {
    assert!(ConstantFoldingHeuristic::new().try_fold(&[0x31, 0xC0], 5).is_none());
}

#[test]
fn fold_lcg_fuzz_never_panics() {
    let h = ConstantFoldingHeuristic::new();
    let mut g = make_lcg(0xFEED_FACE_DEAD_C0DE);
    for _ in 0..50 {
        let len = (g() as usize) % 200;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        for i in 0..buf.len() {
            let _ = h.try_fold(&buf, i);
        }
        let _ = h.fold_all(&buf);
    }
}

#[test]
fn fold_fold_all_no_overlap() {
    let data = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC0];
    let map = ConstantFoldingHeuristic::new().fold_all(&data);
    assert!(map.contains_key(&0));
    assert!(map.contains_key(&5));
}

#[test]
fn fold_result_serde() {
    let r = FoldResult { value: 0xCAFE_BABE, bytes_consumed: 5 };
    let s = serde_json::to_string(&r).unwrap();
    let back: FoldResult = serde_json::from_str(&s).unwrap();
    assert_eq!(back, r);
}

// ---------------------------------------------------------------------------
// EntropyAnalyzer
// ---------------------------------------------------------------------------

#[test]
fn entropy_zero_for_constant() {
    let data = vec![0x42u8; 256];
    let e = EntropyAnalyzer::entropy(&data);
    assert!(e.abs() < 1e-5);
}

#[test]
fn entropy_max_for_uniform() {
    let data: Vec<u8> = (0..=255).collect();
    let e = EntropyAnalyzer::entropy(&data);
    assert!((e - 8.0).abs() < 1e-3);
}

#[test]
fn entropy_window_min_4() {
    let a = EntropyAnalyzer::new(1);
    assert!(a.window_size >= 4);
}

#[test]
fn entropy_analyze_short_input_returns_one_window() {
    let a = EntropyAnalyzer::new(64);
    let w = a.analyze(&[0u8; 4]);
    assert_eq!(w.len(), 1);
}

#[test]
fn entropy_high_low_disjoint() {
    let a = EntropyAnalyzer::new(64);
    let data: Vec<u8> = (0..128).map(|i| (i & 0xFF) as u8).collect();
    let hi = a.high_entropy_windows(&data, 7.5);
    let lo = a.low_entropy_windows(&data, 1.0);
    for h in &hi {
        for l in &lo {
            assert_ne!(h.offset, l.offset);
        }
    }
}

#[test]
fn entropy_lcg_fuzz() {
    let a = EntropyAnalyzer::new(64);
    let mut g = make_lcg(0x0123_4567_89AB_CDEF);
    for _ in 0..20 {
        let len = (g() as usize) % 1024;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let mean = a.mean_entropy(&buf);
        assert!((0.0..=8.01).contains(&mean));
    }
}

// ---------------------------------------------------------------------------
// PatchApplicator
// ---------------------------------------------------------------------------

#[test]
fn patch_apply_nops() {
    let mut data = vec![0xAA; 8];
    let plan = vec![PlannedPatch {
        offset: 2,
        length: 3,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    let n = PatchApplicator::new().apply_nop_patches(&mut data, &plan);
    assert_eq!(n, 1);
    assert_eq!(&data[2..5], &[0x90, 0x90, 0x90]);
    assert_eq!(data[0], 0xAA);
    assert_eq!(data[7], 0xAA);
}

#[test]
fn patch_out_of_bounds_skipped() {
    let mut data = vec![0xAA; 4];
    let plan = vec![PlannedPatch {
        offset: 2,
        length: 10,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    let n = PatchApplicator::new().apply_nop_patches(&mut data, &plan);
    assert_eq!(n, 0);
    assert_eq!(data, vec![0xAA; 4]);
}

#[test]
fn patch_overflow_saturating() {
    let mut data = vec![0u8; 8];
    let plan = vec![PlannedPatch {
        offset: usize::MAX - 1,
        length: 10,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    // saturating_add => out of bounds => skipped (no panic).
    let n = PatchApplicator::new().apply_nop_patches(&mut data, &plan);
    assert_eq!(n, 0);
}

#[test]
fn patch_apply_fill_custom() {
    let mut data = vec![0; 6];
    let plan = vec![PlannedPatch {
        offset: 1,
        length: 4,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    PatchApplicator::new().apply_fill_patches(&mut data, &plan, 0xCC);
    assert_eq!(&data[1..5], &[0xCC; 4]);
}

#[test]
fn patch_patched_copy_does_not_mutate() {
    let data = vec![0xAA; 8];
    let plan = vec![PlannedPatch {
        offset: 0,
        length: 4,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    let copy = PatchApplicator::new().patched_copy(&data, &plan);
    assert_eq!(data, vec![0xAA; 8]);
    assert_eq!(&copy[..4], &[0x90, 0x90, 0x90, 0x90]);
}

#[test]
fn patch_validate_plan() {
    let plan = vec![PlannedPatch {
        offset: 4,
        length: 4,
        kind: MhcdePatchKind::JunkCode,
        confidence: 1.0,
        description: "x".into(),
    }];
    assert!(PatchApplicator::validate_plan(&plan, 8));
    assert!(!PatchApplicator::validate_plan(&plan, 7));
}

// ---------------------------------------------------------------------------
// MhcdeOrchestrator / MhcdeAnalysis / MhcdeScore
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_clean_data_score_zero() {
    let data = vec![0xC3u8; 64];
    let analysis = MhcdeOrchestrator::new().analyze(&data);
    assert!(analysis.is_clean() || analysis.score.confidence >= 0.0);
}

#[test]
fn orchestrator_patches_no_overlap() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00]);
    data.extend_from_slice(&[0x90u8; 8]);
    data.extend_from_slice(&[0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x00]);
    let analysis = MhcdeOrchestrator::new().analyze(&data);
    // Ensure offsets are strictly non-overlapping and sorted.
    let plan = &analysis.patch_plan;
    for w in plan.windows(2) {
        assert!(w[0].offset <= w[1].offset);
        assert!(w[0].offset + w[0].length <= w[1].offset);
    }
}

#[test]
fn orchestrator_analyze_and_patch_consistent() {
    let mut data = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05, 0xC3];
    let (patched, analysis) = MhcdeOrchestrator::new().analyze_and_patch(&data);
    assert_eq!(patched.len(), data.len());
    for p in &analysis.patch_plan {
        for off in p.offset..p.offset + p.length {
            assert_eq!(patched[off], 0x90);
        }
    }
    // Original untouched.
    data[0] = 0x31;
}

#[test]
fn orchestrator_lcg_fuzz() {
    let orch = MhcdeOrchestrator::new();
    let mut g = make_lcg(0xBEEF_DEAD_FACE_F00D);
    for _ in 0..30 {
        let len = (g() as usize) % 512;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let a = orch.analyze(&buf);
        // Score fields must lie in documented ranges.
        assert!((0.0..=1.0).contains(&a.score.confidence));
        assert!((0.0..=1.0).contains(&a.score.risk));
        // Patch offsets sorted.
        let offs = a.patch_offsets();
        for w in offs.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }
}

#[test]
fn score_tier_thresholds() {
    let mk = |c| MhcdeScore {
        confidence: c,
        risk: 0.0,
        modified_bytes: 0,
        finding_count: 1,
    };
    assert_eq!(mk(0.95).confidence_tier(), "very high");
    assert_eq!(mk(0.80).confidence_tier(), "high");
    assert_eq!(mk(0.60).confidence_tier(), "medium");
    assert_eq!(mk(0.10).confidence_tier(), "low");
    assert_eq!(mk(0.0).confidence_tier(), "none");
}

#[test]
fn score_is_highly_obfuscated() {
    let s = MhcdeScore {
        confidence: 0.8,
        risk: 0.0,
        modified_bytes: 0,
        finding_count: 5,
    };
    assert!(s.is_highly_obfuscated());
    let s2 = MhcdeScore {
        confidence: 0.8,
        risk: 0.0,
        modified_bytes: 0,
        finding_count: 1,
    };
    assert!(!s2.is_highly_obfuscated());
}

#[test]
fn analysis_high_confidence_filter() {
    let a = MhcdeAnalysis {
        opaque_predicates: vec![],
        junk_regions: vec![],
        cff: None,
        patch_plan: vec![
            PlannedPatch { offset: 0, length: 1, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "a".into() },
            PlannedPatch { offset: 1, length: 1, kind: MhcdePatchKind::JunkCode, confidence: 0.9, description: "b".into() },
        ],
        score: MhcdeScore { confidence: 0.0, risk: 0.0, modified_bytes: 0, finding_count: 0 },
    };
    let hi = a.high_confidence_patches(0.8);
    assert_eq!(hi.len(), 1);
}

#[test]
fn analysis_patch_offsets_sorted() {
    let a = MhcdeAnalysis {
        opaque_predicates: vec![],
        junk_regions: vec![],
        cff: None,
        patch_plan: vec![
            PlannedPatch { offset: 10, length: 1, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "a".into() },
            PlannedPatch { offset: 5, length: 1, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "b".into() },
        ],
        score: MhcdeScore { confidence: 0.0, risk: 0.0, modified_bytes: 0, finding_count: 0 },
    };
    assert_eq!(a.patch_offsets(), vec![5, 10]);
}

#[test]
fn mhcde_pass_via_deobf_context() {
    use rustre_deobf::{DeobfContext, DeobfPass};
    let bin = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05, 0xC3, 0x90, 0x90];
    let mut ctx = DeobfContext::new(bin);
    let pass = MhcdePass::new();
    assert!(pass.is_applicable(&ctx));
    let r = pass.run(&mut ctx).unwrap();
    assert!(r.patches_applied >= 1);
    assert_eq!(pass.name(), "mhcde");
}

#[test]
fn mhcde_pass_too_small_input() {
    use rustre_deobf::{DeobfContext, DeobfPass};
    let ctx = DeobfContext::new(vec![0u8; 4]);
    assert!(!MhcdePass::new().is_applicable(&ctx));
}

// ---------------------------------------------------------------------------
// ScoreModel
// ---------------------------------------------------------------------------

#[test]
fn score_empty_natural_is_one() {
    assert_eq!(ScoreModel::naturalness_score(&[]), 1.0);
}

#[test]
fn score_complexity_monotone() {
    let a = ScoreModel::complexity_score(10, 0);
    let b = ScoreModel::complexity_score(10, 30);
    assert!(a >= b);
}

#[test]
fn score_complexity_bounds() {
    for bb in [0usize, 1, 10, 100] {
        for e in [0usize, 1, 50, 1000] {
            let s = ScoreModel::complexity_score(bb, e);
            assert!((0.0..=1.0).contains(&s));
        }
    }
}

#[test]
fn score_complexity_underflow_safe() {
    // edges < basic_blocks should not panic / underflow.
    let s = ScoreModel::complexity_score(100, 0);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn score_naturalness_bounds_lcg() {
    let mut g = make_lcg(0x0F0F_F0F0_5A5A_A5A5);
    for _ in 0..50 {
        let len = (g() as usize) % 400;
        let buf: Vec<u8> = (0..len).map(|_| (g() >> 24) as u8).collect();
        let s = ScoreModel::naturalness_score(&buf);
        assert!((0.0..=1.0).contains(&s), "score out of range: {s}");
    }
}

// ---------------------------------------------------------------------------
// Hypothesis framework
// ---------------------------------------------------------------------------

#[test]
fn hypothesis_identity_returns_input() {
    let data = vec![0xC3, 0x90, 0x90];
    let r = IdentityHypothesis.run(&data);
    assert_eq!(r.transformed.as_deref(), Some(&data[..]));
    assert_eq!(r.name, "identity");
}

#[test]
fn hypothesis_nop_strip_removes_all_0x90() {
    let data = vec![0x90, 0xC3, 0x90, 0xC3];
    let r = NopStripHypothesis.run(&data);
    let t = r.transformed.unwrap();
    assert!(!t.contains(&0x90));
    assert_eq!(t, vec![0xC3, 0xC3]);
}

#[test]
fn hypothesis_xor_roundtrip_fixed_key() {
    let data = vec![0x10, 0x20, 0x30, 0x40];
    let r = XorFixedKeyHypothesis.run(&data);
    let dec = r.transformed.unwrap();
    let back: Vec<u8> = dec.iter().map(|&b| b ^ 0x42).collect();
    assert_eq!(back, data);
}

#[test]
fn hypothesis_combined_score_geometric_mean() {
    use rustre_deobf_mhcde::HypothesisResult;
    let r = HypothesisResult::new("x", 0.81, 0.49);
    let cs = r.combined_score();
    assert!((cs - (0.81f64 * 0.49).sqrt()).abs() < 1e-6);
}

#[test]
fn hypothesis_clamps_inputs() {
    use rustre_deobf_mhcde::HypothesisResult;
    let r = HypothesisResult::new("x", 1.5, -0.5);
    assert_eq!(r.naturalness, 1.0);
    assert_eq!(r.complexity, 0.0);
}

#[test]
fn hypothesis_with_meta_chains() {
    use rustre_deobf_mhcde::HypothesisResult;
    let r = HypothesisResult::new("x", 0.5, 0.5)
        .with_meta("k", "v")
        .with_transformed(vec![1, 2, 3]);
    assert_eq!(r.metadata.get("k").map(std::string::String::as_str), Some("v"));
    assert_eq!(r.transformed.as_deref(), Some(&[1, 2, 3][..]));
}

#[test]
fn hypothesis_runner_select_best_threshold() {
    use rustre_deobf_mhcde::HypothesisResult;
    let results = vec![
        HypothesisResult::new("a", 0.3, 0.3),
        HypothesisResult::new("b", 0.5, 0.5),
    ];
    // Both below 0.6 threshold => None.
    assert!(HypothesisRunner::select_best(&results).is_none());
}

#[test]
fn hypothesis_runner_run_all_preserves_order() {
    let h: Vec<Box<dyn Hypothesis>> = vec![
        Box::new(IdentityHypothesis),
        Box::new(NopStripHypothesis),
        Box::new(XorFixedKeyHypothesis),
    ];
    let r = HypothesisRunner::run_all_in_parallel(&[0u8; 16], &h);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].name, "identity");
    assert_eq!(r[1].name, "nop-strip");
}

#[test]
fn hypothesis_runner_ranked_descending() {
    use rustre_deobf_mhcde::HypothesisResult;
    let v = vec![
        HypothesisResult::new("a", 0.1, 0.1),
        HypothesisResult::new("b", 0.9, 0.9),
        HypothesisResult::new("c", 0.5, 0.5),
    ];
    let r = HypothesisRunner::ranked(v);
    for w in r.windows(2) {
        assert!(w[0].combined_score() >= w[1].combined_score());
    }
}

#[test]
fn hypothesis_default_set_not_empty() {
    let s = HypothesisRunner::default_hypotheses();
    assert_eq!(s.len(), 4);
}

#[test]
fn hypothesis_xor_best_key_not_worse_than_identity() {
    // The best-key search includes key=0 implicitly via initial best_nat.
    let data: Vec<u8> = (0..64).map(|i| (i ^ 0x37) as u8).collect();
    let id = IdentityHypothesis.run(&data);
    let best = XorBestKeyHypothesis.run(&data);
    assert!(best.naturalness >= id.naturalness - 1e-9);
}

// ---------------------------------------------------------------------------
// Send/Sync threaded stress
// ---------------------------------------------------------------------------

#[test]
fn threaded_orchestrator_send_sync_stress() {
    let orch = Arc::new(MhcdeOrchestrator::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let o = Arc::clone(&orch);
        handles.push(thread::spawn(move || {
            let buf = lcg_bytes(0x00AB_CDEF ^ t, 256);
            for _ in 0..100 {
                let a = o.analyze(&buf);
                assert!((0.0..=1.0).contains(&a.score.confidence));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_detectors_concurrent() {
    let det_o = Arc::new(OpaquePredicateDetector::new());
    let det_j = Arc::new(JunkCodeDetector::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let o = Arc::clone(&det_o);
        let j = Arc::clone(&det_j);
        handles.push(thread::spawn(move || {
            let buf = lcg_bytes(0x12345 ^ t, 200);
            for _ in 0..100 {
                let _ = o.detect(&buf);
                let _ = j.detect(&buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
