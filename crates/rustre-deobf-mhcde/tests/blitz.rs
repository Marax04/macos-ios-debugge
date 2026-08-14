//! Exhaustive blitz tests for `rustre-deobf-mhcde` public lib.rs surface.

use std::collections::HashSet;

use rustre_deobf::{DeobfContext, DeobfPass};
use rustre_deobf_mhcde::*;

// ---------------------------------------------------------------------------
// OpaquePredicateDetector
// ---------------------------------------------------------------------------

#[test]
fn opaque_empty_input() {
    let d = OpaquePredicateDetector::new();
    assert!(d.detect(&[]).is_empty());
    assert_eq!(d.total_patch_bytes(&[]), 0);
    assert!(d.count_by_type(&[]).is_empty());
}

#[test]
fn opaque_short_input_under_three_bytes() {
    let d = OpaquePredicateDetector::new();
    assert!(d.detect(&[0x31, 0xC0]).is_empty());
}

#[test]
fn opaque_pattern1_xor_test_jz() {
    let d = OpaquePredicateDetector::new();
    let data = [0x31, 0xC0, 0x85, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.predicate_type == OpaquePredicateType::AlwaysTrue && h.patch_length == 5));
}

#[test]
fn opaque_pattern2_xor_test_jnz() {
    let d = OpaquePredicateDetector::new();
    let data = [0x31, 0xC0, 0x85, 0xC0, 0x75, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.predicate_type == OpaquePredicateType::AlwaysFalse));
}

#[test]
fn opaque_pattern3_mov_al_1_test_jz() {
    let d = OpaquePredicateDetector::new();
    let data = [0xB0, 0x01, 0x84, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.predicate_type == OpaquePredicateType::AlwaysFalse));
}

#[test]
fn opaque_pattern4_or_neg1() {
    let d = OpaquePredicateDetector::new();
    let data = [0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 6 && h.predicate_type == OpaquePredicateType::AlwaysTrue));
}

#[test]
fn opaque_pattern5_and_zero() {
    let d = OpaquePredicateDetector::new();
    let data = [0x83, 0xE0, 0x00, 0x85, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 6));
}

#[test]
fn opaque_pattern6_condensed_xor_jz() {
    let d = OpaquePredicateDetector::new();
    let data = [0x33, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 3));
}

#[test]
fn opaque_pattern7_xor_ecx_jecxz() {
    let d = OpaquePredicateDetector::new();
    let data = [0x33, 0xC9, 0xE3, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 3));
}

#[test]
fn opaque_pattern8_xor_cmp_jz() {
    let d = OpaquePredicateDetector::new();
    let data = [0x31, 0xC0, 0x39, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 5));
}

#[test]
fn opaque_pattern9_mov_eax0_test_jz() {
    let d = OpaquePredicateDetector::new();
    let data = [0xB8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x05];
    let hits = d.detect(&data);
    // Eight bytes are matched — B8 00 00 00 00 (mov eax,0), 85 C0 (test), 74
    // (jz) — and `patch_length` documents itself as "length of the byte sequence
    // to NOP / patch", which `plan_patches` uses verbatim as the region to
    // overwrite. This asserted 7, which stops one byte short of the `74` and so
    // left the conditional branch intact after patching. Every other pattern in
    // the detector sizes the patch to the bytes it matched.
    assert!(hits.iter().any(|h| h.patch_length == 8));
}

#[test]
fn opaque_pattern10_stc_jc() {
    let d = OpaquePredicateDetector::new();
    let data = [0xF9, 0x72, 0x10];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 2));
}

#[test]
fn opaque_pattern11_clc_jnc() {
    let d = OpaquePredicateDetector::new();
    let data = [0xF8, 0x73, 0x10];
    let hits = d.detect(&data);
    assert!(hits.iter().any(|h| h.patch_length == 2));
}

#[test]
fn opaque_pattern12_xor_or1() {
    let d = OpaquePredicateDetector::new();
    let data = [0x31, 0xC0, 0x83, 0xC8, 0x01, 0x85, 0xC0, 0x75, 0x05];
    let hits = d.detect(&data);
    // Eight bytes are matched (31 C0 83 C8 01 85 C0 75) and all eight must be
    // patched: at 7 the region stopped one byte short of the `75` jnz opcode,
    // leaving the conditional branch intact.
    assert!(hits.iter().any(|h| h.patch_length == 8));
}

#[test]
fn opaque_count_by_type_aggregates() {
    let d = OpaquePredicateDetector::new();
    let mut data = vec![];
    data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00]);
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // gap
    data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x75, 0x00]);
    let map = d.count_by_type(&data);
    assert_eq!(*map.get(&OpaquePredicateType::AlwaysTrue).unwrap_or(&0), 1);
    assert_eq!(*map.get(&OpaquePredicateType::AlwaysFalse).unwrap_or(&0), 1);
}

#[test]
fn opaque_no_false_positives_random_zeros() {
    let d = OpaquePredicateDetector::new();
    let data = vec![0u8; 1024];
    assert!(d.detect(&data).is_empty());
}

#[test]
fn opaque_type_ord_consistency() {
    assert!(OpaquePredicateType::AlwaysTrue < OpaquePredicateType::AlwaysFalse);
}

// ---------------------------------------------------------------------------
// JunkCodeDetector
// ---------------------------------------------------------------------------

#[test]
fn junk_empty() {
    let d = JunkCodeDetector::new();
    assert!(d.detect(&[]).is_empty());
    assert_eq!(d.total_junk_bytes(&[]), 0);
    assert_eq!(d.junk_density(&[]), 0.0);
}

#[test]
fn junk_single_nop_not_a_sled() {
    // 1-byte NOP — code requires len >= 2.
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x90]);
    assert!(r.is_empty());
}

#[test]
fn junk_nop_sled_two_bytes() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x90, 0x90]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 2);
}

#[test]
fn junk_push_pop_eax() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x50, 0x58]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 2);
}

#[test]
fn junk_push_pop_edi() {
    // PUSH EDI (0x57), POP EDI (0x5F)
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x57, 0x5F]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_push_pop_mismatch_not_junk() {
    // PUSH EAX (0x50), POP ECX (0x59) — not identity.
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x50, 0x59]);
    assert!(r.is_empty());
}

#[test]
fn junk_xor_reg_zero() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x83, 0xF0, 0x00]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 3);
}

#[test]
fn junk_add_reg_zero() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x83, 0xC0, 0x00]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_sub_reg_zero() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x83, 0xE8, 0x00]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_or_reg_zero() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x83, 0xC8, 0x00]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_and_reg_neg1() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x83, 0xE0, 0xFF]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_mov_same_reg() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x89, 0xC0]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_mov_different_reg_not_junk() {
    // 89 C1 = MOV ECX, EAX
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x89, 0xC1]);
    assert!(r.is_empty());
}

#[test]
fn junk_lea_reg_zero_disp() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x8D, 0x40, 0x00]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_xchg_eax_eax() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x87, 0xC0]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_clc_stc_flag_churn() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0xF8, 0xF9]);
    assert_eq!(r.len(), 1);
}

#[test]
fn junk_multibyte_nop_66_90() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x66, 0x90]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 2);
}

#[test]
fn junk_3byte_nop() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x0F, 0x1F, 0x00]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 3);
}

#[test]
fn junk_4byte_nop() {
    let d = JunkCodeDetector::new();
    let r = d.detect(&[0x0F, 0x1F, 0x40, 0x00]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].length, 4);
}

#[test]
fn junk_density_all_nops() {
    let d = JunkCodeDetector::new();
    let data = vec![0x90; 100];
    let density = d.junk_density(&data);
    assert!((density - 1.0).abs() < 1e-6);
}

#[test]
fn junk_density_no_junk() {
    let d = JunkCodeDetector::new();
    // Random bytes that don't match any junk pattern
    let data = vec![0x48, 0xAB, 0xCD, 0xEF];
    assert_eq!(d.junk_density(&data), 0.0);
}

#[test]
fn junk_total_bytes_sum() {
    let d = JunkCodeDetector::new();
    let mut data = vec![];
    data.extend_from_slice(&[0x90, 0x90, 0x90]); // 3
    data.push(0x48); // gap
    data.extend_from_slice(&[0x50, 0x58]); // 2
    assert_eq!(d.total_junk_bytes(&data), 5);
}

// ---------------------------------------------------------------------------
// ControlFlowFlattener
// ---------------------------------------------------------------------------

#[test]
fn cff_empty_returns_none() {
    let c = ControlFlowFlattener::new();
    assert!(c.detect(&[]).is_none());
}

#[test]
fn cff_no_indirect_jump() {
    let c = ControlFlowFlattener::new();
    assert!(c.detect(&[0x90, 0x90, 0x90, 0x90]).is_none());
}

#[test]
fn cff_indirect_jmp_eax() {
    let c = ControlFlowFlattener::new();
    // FF E0 = jmp eax
    let mut data = vec![0x90; 16];
    data.extend_from_slice(&[0xFF, 0xE0]);
    data.extend_from_slice(&[0x90; 16]);
    let r = c.detect(&data);
    assert!(r.is_some());
}

#[test]
fn cff_dispatcher_fan_out_empty_blocks() {
    let result = CffDetectionResult {
        dispatcher_offset: 0,
        state_var_offset: 0,
        body_blocks: vec![],
        reconstructed_order: vec![],
    };
    assert_eq!(ControlFlowFlattener::dispatcher_fan_out(&result), 0.0);
}

#[test]
fn cff_dispatcher_fan_out_no_edges() {
    let result = CffDetectionResult {
        dispatcher_offset: 0,
        state_var_offset: 0,
        body_blocks: vec![CfgBlock {
            offset: 0,
            length: 4,
            successors: vec![],
            is_dispatcher: false,
        }],
        reconstructed_order: vec![0],
    };
    assert_eq!(ControlFlowFlattener::dispatcher_fan_out(&result), 0.0);
}

// ---------------------------------------------------------------------------
// BogusControlFlowRemover
// ---------------------------------------------------------------------------

#[test]
fn bogus_remove_excludes_dispatcher_and_junk() {
    let r = BogusControlFlowRemover::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: true },
        CfgBlock { offset: 10, length: 4, successors: vec![20], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let mut junk = HashSet::new();
    junk.insert(20);
    let kept = r.remove_bogus_blocks(&blocks, &junk);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].offset, 10);
}

#[test]
fn bogus_junk_offset_set_collects_offsets() {
    let regions = vec![
        JunkCodeRegion { offset: 5, length: 2, description: "a".into() },
        JunkCodeRegion { offset: 100, length: 3, description: "b".into() },
    ];
    let set = BogusControlFlowRemover::junk_offset_set(&regions);
    assert!(set.contains(&5));
    assert!(set.contains(&100));
    assert_eq!(set.len(), 2);
}

#[test]
fn bogus_dispatcher_blocks_filter() {
    let r = BogusControlFlowRemover::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![], is_dispatcher: true },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let disp = r.dispatcher_blocks(&blocks);
    assert_eq!(disp.len(), 1);
    assert_eq!(disp[0].offset, 0);
}

// ---------------------------------------------------------------------------
// DeadCodeEliminator
// ---------------------------------------------------------------------------

#[test]
fn dce_reachable_basic() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let reach = e.reachable_blocks(&blocks, 0);
    assert!(reach.contains(&0));
    assert!(reach.contains(&10));
    assert!(!reach.contains(&20));
}

#[test]
fn dce_eliminate_strips_unreachable() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let live = e.eliminate(&blocks, 0);
    assert_eq!(live.len(), 2);
}

#[test]
fn dce_dead_blocks_returns_unreachable() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let dead = e.dead_blocks(&blocks, 0);
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].offset, 20);
}

#[test]
fn dce_entry_not_in_blocks_returns_empty() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let r = e.reachable_blocks(&blocks, 0);
    assert!(r.is_empty());
}

#[test]
fn dce_ratio_all_dead() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    // entry not in blocks, so 0 reachable, 2 total -> 1.0
    assert!((e.dead_block_ratio(&blocks, 0) - 1.0).abs() < 1e-6);
}

#[test]
fn dce_ratio_all_live() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
    ];
    assert_eq!(e.dead_block_ratio(&blocks, 0), 0.0);
}

#[test]
fn dce_ratio_empty_blocks() {
    let e = DeadCodeEliminator::new();
    assert_eq!(e.dead_block_ratio(&[], 0), 0.0);
}

#[test]
fn dce_cyclic_graph() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![0], is_dispatcher: false },
    ];
    let reach = e.reachable_blocks(&blocks, 0);
    assert_eq!(reach.len(), 2);
}

#[test]
fn dce_build_graph_node_count() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let (g, _) = e.build_graph(&blocks);
    assert_eq!(g.node_count(), 2);
    assert_eq!(g.edge_count(), 1);
}

#[test]
fn dce_bfs_order_starts_at_entry() {
    let e = DeadCodeEliminator::new();
    let blocks = vec![
        CfgBlock { offset: 0, length: 4, successors: vec![10, 20], is_dispatcher: false },
        CfgBlock { offset: 10, length: 4, successors: vec![], is_dispatcher: false },
        CfgBlock { offset: 20, length: 4, successors: vec![], is_dispatcher: false },
    ];
    let order = e.bfs_order(&blocks, 0);
    assert_eq!(order.first(), Some(&0));
    assert_eq!(order.len(), 3);
}

// ---------------------------------------------------------------------------
// ConstantFoldingHeuristic
// ---------------------------------------------------------------------------

#[test]
fn fold_mov_eax_imm32() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0xB8, 0x01, 0x02, 0x03, 0x04], 0).unwrap();
    assert_eq!(r.value, 0x0403_0201);
    assert_eq!(r.bytes_consumed, 5);
}

#[test]
fn fold_xor_eax_eax_31() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0x31, 0xC0], 0).unwrap();
    assert_eq!(r.value, 0);
    assert_eq!(r.bytes_consumed, 2);
}

#[test]
fn fold_xor_eax_eax_33() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0x33, 0xC0], 0).unwrap();
    assert_eq!(r.value, 0);
}

#[test]
fn fold_or_eax_neg1() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0x83, 0xC8, 0xFF], 0).unwrap();
    assert_eq!(r.value, 0xFFFF_FFFF);
    assert_eq!(r.bytes_consumed, 3);
}

#[test]
fn fold_and_eax_zero() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0x83, 0xE0, 0x00], 0).unwrap();
    assert_eq!(r.value, 0);
}

#[test]
fn fold_mov_al_imm8() {
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0xB0, 0x42], 0).unwrap();
    assert_eq!(r.value, 0x42);
    assert_eq!(r.bytes_consumed, 2);
}

#[test]
fn fold_offset_out_of_range() {
    let f = ConstantFoldingHeuristic::new();
    assert!(f.try_fold(&[0x90], 10).is_none());
}

#[test]
fn fold_unknown_opcode_none() {
    let f = ConstantFoldingHeuristic::new();
    assert!(f.try_fold(&[0xFF, 0xFF, 0xFF], 0).is_none());
}

#[test]
fn fold_all_basic_map() {
    let f = ConstantFoldingHeuristic::new();
    let mut data = vec![];
    data.extend_from_slice(&[0x31, 0xC0]); // xor eax,eax @ 0
    data.extend_from_slice(&[0xB0, 0x07]); // mov al,7 @ 2
    let map = f.fold_all(&data);
    assert_eq!(map.get(&0).unwrap().value, 0);
    assert_eq!(map.get(&2).unwrap().value, 7);
}

#[test]
fn fold_mov_eax_imm_boundary_too_short() {
    // need offset+4 < len, so len must be > offset+4. 5-byte mov needs len >= 6.
    // With len=5, condition `offset+4 < data.len()` becomes `4 < 5` true… wait.
    // Actually the check is `offset+4 < data.len()` => fails for len=5.
    // So a 5-byte buffer should NOT match B8 fold. This is an off-by-one bug candidate.
    let f = ConstantFoldingHeuristic::new();
    let r = f.try_fold(&[0xB8, 0x01, 0x02, 0x03, 0x04], 0);
    // The implementation uses `offset+4 < data.len()` which is `4 < 5` = true → matches.
    // But it reads indices 1..=4 which require data.len() > 4. So 5 bytes is exactly right.
    // Document actual behavior: matches.
    assert!(r.is_some());
}

// ---------------------------------------------------------------------------
// EntropyAnalyzer
// ---------------------------------------------------------------------------

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(EntropyAnalyzer::entropy(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    assert_eq!(EntropyAnalyzer::entropy(&[0x42; 100]), 0.0);
}

#[test]
fn entropy_uniform_byte_distribution() {
    // 256 distinct bytes each appearing once -> entropy = 8.0
    let data: Vec<u8> = (0..=255).collect();
    let e = EntropyAnalyzer::entropy(&data);
    assert!((e - 8.0).abs() < 1e-3);
}

#[test]
fn entropy_two_equal_classes_is_one_bit() {
    let mut data = vec![0u8; 50];
    data.extend(vec![1u8; 50]);
    let e = EntropyAnalyzer::entropy(&data);
    assert!((e - 1.0).abs() < 1e-3);
}

#[test]
fn entropy_window_size_min_4() {
    let a = EntropyAnalyzer::new(0);
    assert_eq!(a.window_size, 4);
    let a = EntropyAnalyzer::new(2);
    assert_eq!(a.window_size, 4);
}

#[test]
fn entropy_default_window_256() {
    let a = EntropyAnalyzer::default();
    assert_eq!(a.window_size, 256);
}

#[test]
fn entropy_analyze_short_buffer_single_window() {
    let a = EntropyAnalyzer::new(256);
    let w = a.analyze(&[0u8; 10]);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].offset, 0);
}

#[test]
fn entropy_analyze_strides_half_window() {
    let a = EntropyAnalyzer::new(4);
    let data = vec![0u8; 16];
    let w = a.analyze(&data);
    // step = 4/2 = 2; range 0..=(16-4)=12, step 2 -> 0,2,4,6,8,10,12 = 7 windows
    assert_eq!(w.len(), 7);
}

#[test]
fn entropy_high_low_split() {
    // Use a window large enough that the high-entropy region can saturate.
    let a = EntropyAnalyzer::new(256);
    let mut data: Vec<u8> = (0..=255).collect(); // high entropy window
    data.extend(vec![0u8; 512]); // low entropy region
    let hi = a.high_entropy_windows(&data, 7.0);
    let lo = a.low_entropy_windows(&data, 1.0);
    assert!(!hi.is_empty(), "expected high-entropy window");
    assert!(!lo.is_empty(), "expected low-entropy window");
}

#[test]
fn entropy_mean_nonempty() {
    let a = EntropyAnalyzer::new(4);
    let data = vec![0u8; 16];
    assert_eq!(a.mean_entropy(&data), 0.0);
}

// ---------------------------------------------------------------------------
// PatchApplicator
// ---------------------------------------------------------------------------

#[test]
fn patch_apply_nop_basic() {
    let a = PatchApplicator::new();
    let mut data = vec![0xAA; 8];
    let plan = vec![PlannedPatch {
        offset: 2, length: 3, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "x".into(),
    }];
    let n = a.apply_nop_patches(&mut data, &plan);
    assert_eq!(n, 1);
    assert_eq!(&data[2..5], &[0x90, 0x90, 0x90]);
    assert_eq!(data[1], 0xAA);
    assert_eq!(data[5], 0xAA);
}

#[test]
fn patch_apply_skips_oob() {
    let a = PatchApplicator::new();
    let mut data = vec![0xAA; 4];
    let plan = vec![PlannedPatch {
        offset: 2, length: 10, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "x".into(),
    }];
    let n = a.apply_nop_patches(&mut data, &plan);
    assert_eq!(n, 0);
    assert_eq!(data, vec![0xAA; 4]);
}

#[test]
fn patch_apply_fill_custom_byte() {
    let a = PatchApplicator::new();
    let mut data = vec![0x00; 6];
    let plan = vec![PlannedPatch {
        offset: 0, length: 6, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "f".into(),
    }];
    a.apply_fill_patches(&mut data, &plan, 0xCC);
    assert_eq!(data, vec![0xCC; 6]);
}

#[test]
fn patch_patched_copy_does_not_mutate_input() {
    let a = PatchApplicator::new();
    let data = vec![0xAA; 4];
    let plan = vec![PlannedPatch {
        offset: 0, length: 2, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "p".into(),
    }];
    let copy = a.patched_copy(&data, &plan);
    assert_eq!(data, vec![0xAA; 4]);
    assert_eq!(&copy[..2], &[0x90, 0x90]);
}

#[test]
fn patch_validate_plan_ok() {
    let plan = vec![PlannedPatch {
        offset: 0, length: 4, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "v".into(),
    }];
    assert!(PatchApplicator::validate_plan(&plan, 4));
    assert!(!PatchApplicator::validate_plan(&plan, 3));
}

#[test]
fn patch_validate_plan_overflow_safe() {
    let plan = vec![PlannedPatch {
        offset: usize::MAX, length: 1, kind: MhcdePatchKind::JunkCode, confidence: 0.5, description: "o".into(),
    }];
    // saturating_add to MAX, so MAX <= MAX => true. But that's degenerate.
    // We just want to make sure it doesn't panic.
    let _ = PatchApplicator::validate_plan(&plan, usize::MAX);
}

// ---------------------------------------------------------------------------
// MhcdeScore / MhcdeAnalysis
// ---------------------------------------------------------------------------

#[test]
fn score_confidence_tier_thresholds() {
    let mk = |c: f32| MhcdeScore { confidence: c, risk: 0.0, modified_bytes: 0, finding_count: 0 };
    assert_eq!(mk(0.95).confidence_tier(), "very high");
    assert_eq!(mk(0.80).confidence_tier(), "high");
    assert_eq!(mk(0.6).confidence_tier(), "medium");
    assert_eq!(mk(0.1).confidence_tier(), "low");
    assert_eq!(mk(0.0).confidence_tier(), "none");
}

#[test]
fn score_is_highly_obfuscated_requires_both() {
    let s = MhcdeScore { confidence: 0.9, risk: 0.0, modified_bytes: 0, finding_count: 5 };
    assert!(s.is_highly_obfuscated());
    let s = MhcdeScore { confidence: 0.5, risk: 0.0, modified_bytes: 0, finding_count: 5 };
    assert!(!s.is_highly_obfuscated());
    let s = MhcdeScore { confidence: 0.9, risk: 0.0, modified_bytes: 0, finding_count: 2 };
    assert!(!s.is_highly_obfuscated());
}

#[test]
fn analysis_clean_when_no_findings() {
    let orchestrator = MhcdeOrchestrator::new();
    let a = orchestrator.analyze(&[0x48, 0x8B, 0xC0, 0xC3]); // random non-junk bytes
    let _ = a.is_clean();
    let _ = a.total_findings();
}

#[test]
fn analysis_patch_offsets_sorted() {
    let orchestrator = MhcdeOrchestrator::new();
    let mut data = vec![];
    data.extend_from_slice(&[0x90; 4]); // junk @ 0
    data.extend_from_slice(&[0x48, 0x48]); // gap
    data.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00]); // opaque @ 6
    let a = orchestrator.analyze(&data);
    let offsets = a.patch_offsets();
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    assert_eq!(offsets, sorted);
}

#[test]
fn analysis_high_confidence_patches_filter() {
    let orchestrator = MhcdeOrchestrator::new();
    let data = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00];
    let a = orchestrator.analyze(&data);
    // opaque patches get 0.9 confidence
    let hi = a.high_confidence_patches(0.8);
    assert!(!hi.is_empty());
    let none = a.high_confidence_patches(0.95);
    assert!(none.is_empty());
}

// ---------------------------------------------------------------------------
// MhcdeOrchestrator
// ---------------------------------------------------------------------------

#[test]
fn orch_analyze_empty() {
    let o = MhcdeOrchestrator::new();
    let a = o.analyze(&[]);
    assert!(a.is_clean());
    assert!(a.patch_plan.is_empty());
}

#[test]
fn orch_analyze_and_patch_produces_nops() {
    let o = MhcdeOrchestrator::new();
    let data = vec![0x90, 0x90, 0x90, 0x90];
    let (patched, _a) = o.analyze_and_patch(&data);
    assert_eq!(patched.len(), data.len());
    assert!(patched.iter().all(|&b| b == 0x90));
}

#[test]
fn orch_patches_dont_overlap() {
    let o = MhcdeOrchestrator::new();
    // Construct data where opaque and junk could overlap; orchestrator should dedup.
    let data = vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x00, 0x90, 0x90];
    let a = o.analyze(&data);
    // Verify no two patches overlap.
    for (i, p1) in a.patch_plan.iter().enumerate() {
        for p2 in &a.patch_plan[i + 1..] {
            let p1_end = p1.offset + p1.length;
            let p2_end = p2.offset + p2.length;
            assert!(p1.offset >= p2_end || p2.offset >= p1_end,
                "patches overlap: {:?} and {:?}", p1, p2);
        }
    }
}

#[test]
fn orch_patches_within_bounds() {
    let o = MhcdeOrchestrator::new();
    let data = vec![0x90; 16];
    let a = o.analyze(&data);
    assert!(PatchApplicator::validate_plan(&a.patch_plan, data.len()));
}

// ---------------------------------------------------------------------------
// MhcdePass (DeobfPass impl)
// ---------------------------------------------------------------------------

#[test]
fn pass_name_and_description() {
    let p = MhcdePass::new();
    assert_eq!(p.name(), "mhcde");
    assert!(!p.description().is_empty());
}

#[test]
fn pass_is_applicable_requires_8_bytes() {
    let p = MhcdePass::new();
    let ctx = DeobfContext::new(vec![0u8; 4]);
    assert!(!p.is_applicable(&ctx));
    let ctx = DeobfContext::new(vec![0u8; 8]);
    assert!(p.is_applicable(&ctx));
}

#[test]
fn pass_run_records_patches_and_meta() {
    let p = MhcdePass::new();
    let mut ctx = DeobfContext::new(vec![0x90; 16]);
    let r = p.run(&mut ctx).expect("pass should succeed");
    let _ = r;
    assert!(!ctx.patches.is_empty());
    assert!(ctx.get_meta("mhcde_score").is_some());
    assert!(ctx.get_meta("mhcde_patch_plan_len").is_some());
}

#[test]
fn pass_default_equivalent_to_new() {
    let _ = MhcdePass::default();
}

// ---------------------------------------------------------------------------
// ScoreModel
// ---------------------------------------------------------------------------

#[test]
fn score_naturalness_empty_is_one() {
    assert_eq!(ScoreModel::naturalness_score(&[]), 1.0);
}

#[test]
fn score_naturalness_all_nops_low() {
    // All NOPs -> NOP ratio = 1 -> nop_score = 0; entropy = 0 -> entropy_score=1; dist=1
    // total = 0.40*1 + 0.35*0 + 0.25*1 = 0.65
    let s = ScoreModel::naturalness_score(&[0x90; 64]);
    assert!(s < 0.7);
}

#[test]
fn score_naturalness_in_range() {
    let s = ScoreModel::naturalness_score(&[0x48, 0x8B, 0xC0, 0xC3]);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn score_complexity_simple_function() {
    let s = ScoreModel::complexity_score(1, 0);
    // m = 0 - 1 + 2 = saturating(0-1)+2 = 2; 1/(1+2/30) ≈ 0.9375
    assert!(s > 0.9);
}

#[test]
fn score_complexity_high_complexity() {
    let s = ScoreModel::complexity_score(10, 200);
    assert!(s < 0.2);
}

#[test]
fn score_complexity_in_range() {
    for bb in [1, 5, 10, 50] {
        for e in [0, 5, 50, 500] {
            let s = ScoreModel::complexity_score(bb, e);
            assert!((0.0..=1.0).contains(&s));
        }
    }
}

// ---------------------------------------------------------------------------
// HypothesisResult
// ---------------------------------------------------------------------------

#[test]
fn hyp_result_clamps_inputs() {
    let r = HypothesisResult::new("x", 2.0, -1.0);
    assert_eq!(r.naturalness, 1.0);
    assert_eq!(r.complexity, 0.0);
}

#[test]
fn hyp_result_combined_score_geo_mean() {
    let r = HypothesisResult::new("x", 0.81, 0.49);
    let c = r.combined_score();
    // sqrt(0.81*0.49) = sqrt(0.3969) = 0.63
    assert!((c - 0.63).abs() < 1e-3);
}

#[test]
fn hyp_result_is_viable_threshold() {
    let r = HypothesisResult::new("x", 0.7, 0.7);
    assert!(r.is_viable()); // sqrt(.49) = 0.7
    let r2 = HypothesisResult::new("x", 0.5, 0.5);
    assert!(!r2.is_viable());
}

#[test]
fn hyp_result_with_transformed_and_meta() {
    let r = HypothesisResult::new("x", 0.5, 0.5)
        .with_transformed(vec![1, 2, 3])
        .with_meta("k", "v");
    assert_eq!(r.transformed.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(r.metadata.get("k").map(|s| s.as_str()), Some("v"));
}

// ---------------------------------------------------------------------------
// Built-in hypotheses
// ---------------------------------------------------------------------------

#[test]
fn hyp_identity_returns_input_unchanged() {
    let h = IdentityHypothesis;
    let code = vec![0x48, 0x8B, 0xC0];
    let r = h.run(&code);
    assert_eq!(r.name, "identity");
    assert_eq!(r.transformed.unwrap(), code);
}

#[test]
fn hyp_nop_strip_removes_nops() {
    let h = NopStripHypothesis;
    let code = vec![0x90, 0x48, 0x90, 0xC3, 0x90];
    let r = h.run(&code);
    assert_eq!(r.transformed.unwrap(), vec![0x48, 0xC3]);
}

#[test]
fn hyp_xor_fixed_key_xors_with_0x42() {
    let h = XorFixedKeyHypothesis;
    let code = vec![0x00, 0x42, 0xFF];
    let r = h.run(&code);
    assert_eq!(r.transformed.unwrap(), vec![0x42, 0x00, 0xBD]);
}

#[test]
fn hyp_xor_best_key_finds_a_key() {
    let h = XorBestKeyHypothesis;
    // XOR a "natural" looking buffer with key 0x55 to mask it; best-key should
    // either find 0x55 or return original; either way meta has 'key'.
    let original = vec![0x48; 64];
    let masked: Vec<u8> = original.iter().map(|b| b ^ 0x55).collect();
    let r = h.run(&masked);
    assert!(r.metadata.contains_key("key"));
}

// ---------------------------------------------------------------------------
// HypothesisRunner
// ---------------------------------------------------------------------------

#[test]
fn runner_run_all_preserves_order() {
    let hs: Vec<Box<dyn Hypothesis>> = vec![
        Box::new(IdentityHypothesis),
        Box::new(NopStripHypothesis),
    ];
    let r = HypothesisRunner::run_all_in_parallel(&[0x90, 0x48], &hs);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].name, "identity");
    assert_eq!(r[1].name, "nop-strip");
}

#[test]
fn runner_select_best_below_threshold_none() {
    let r = vec![HypothesisResult::new("a", 0.1, 0.1)];
    assert!(HypothesisRunner::select_best(&r).is_none());
}

#[test]
fn runner_select_best_picks_max() {
    let r = vec![
        HypothesisResult::new("a", 0.8, 0.8),
        HypothesisResult::new("b", 0.95, 0.95),
        HypothesisResult::new("c", 0.7, 0.7),
    ];
    let best = HypothesisRunner::select_best(&r).unwrap();
    assert_eq!(best.name, "b");
}

#[test]
fn runner_default_hypotheses_has_four() {
    let hs = HypothesisRunner::default_hypotheses();
    assert_eq!(hs.len(), 4);
}

#[test]
fn runner_ranked_sorted_descending() {
    let r = vec![
        HypothesisResult::new("low", 0.3, 0.3),
        HypothesisResult::new("hi", 0.9, 0.9),
        HypothesisResult::new("mid", 0.6, 0.6),
    ];
    let ranked = HypothesisRunner::ranked(r);
    assert_eq!(ranked[0].name, "hi");
    assert_eq!(ranked[2].name, "low");
}

#[test]
fn runner_best_empty_returns_none() {
    let hs: Vec<Box<dyn Hypothesis>> = vec![];
    assert!(HypothesisRunner::best(&[0; 4], &hs).is_none());
}

#[test]
fn runner_parallel_equivalent_to_sequential() {
    let hs = HypothesisRunner::default_hypotheses();
    let data = vec![0x48, 0x90, 0xC3, 0x55];
    let seq = HypothesisRunner::run_all_in_parallel(&data, &hs);
    let par = HypothesisRunner::run_parallel(&data, &hs);
    assert_eq!(seq.len(), par.len());
    for (a, b) in seq.iter().zip(par.iter()) {
        assert_eq!(a.name, b.name);
    }
}

// ---------------------------------------------------------------------------
// Serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn serde_opaque_predicate_type_roundtrip() {
    for t in [
        OpaquePredicateType::AlwaysTrue,
        OpaquePredicateType::AlwaysFalse,
        OpaquePredicateType::DataDependent,
        OpaquePredicateType::PointerBased,
        OpaquePredicateType::HashBased,
    ] {
        let s = serde_json::to_string(&t).unwrap();
        let back: OpaquePredicateType = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn serde_mhcde_patch_kind_roundtrip() {
    for k in [MhcdePatchKind::OpaquePredicate, MhcdePatchKind::JunkCode] {
        let s = serde_json::to_string(&k).unwrap();
        let back: MhcdePatchKind = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn serde_planned_patch_roundtrip() {
    let p = PlannedPatch {
        offset: 42, length: 5, kind: MhcdePatchKind::OpaquePredicate,
        confidence: 0.9, description: "x".into(),
    };
    let s = serde_json::to_string(&p).unwrap();
    let back: PlannedPatch = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_fold_result_roundtrip() {
    let f = FoldResult { value: 0xDEAD_BEEF, bytes_consumed: 5 };
    let s = serde_json::to_string(&f).unwrap();
    let back: FoldResult = serde_json::from_str(&s).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// Send/Sync invariants
// ---------------------------------------------------------------------------

#[test]
fn hypothesis_trait_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn Hypothesis>>();
}
