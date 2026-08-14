//! blitz2: deep adversarial coverage of rustre-diff-semantic public API.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction, Operand};
use rustre_diff::{BinaryDiff, FuncFingerprint, FuncMatch};
use rustre_diff_semantic::{
    BinarySemanticDiff, CallGraph, DiffReport, FunctionRenameHeuristic, LshIndex, MinHash,
    NormalizedBytes, SemanticDiffEngine, SemanticDiffResult, SemanticDiffer, SemanticFeatures,
    SemanticMatch, SemanticMatcher, SemanticSignature,
};

// -- seeded LCG ------------------------------------------------------------
struct Lcg { s: u64 }
impl Lcg {
    fn new() -> Self { Self { s: 0xDEAD_BEEF_CAFE_BABE } }
    fn next_u64(&mut self) -> u64 {
        self.s = self.s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.s
    }
    fn next_byte(&mut self) -> u8 { (self.next_u64() >> 24) as u8 }
}

fn mk_instr(addr: u64, mn: &str, ops: &str, flags: InstrFlags) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 4, mn, vec![0x90; 4]);
    i.operands = ops.to_string();
    i.flags = flags;
    i
}

fn feat(addr: u64, name: &str) -> SemanticFeatures {
    let v = vec![
        mk_instr(addr, "PUSH", "rbp", InstrFlags::NONE),
        mk_instr(addr + 4, "MOV", "rbp, rsp", InstrFlags::NONE),
        mk_instr(addr + 8, "ADD", "rax, 0x10", InstrFlags::NONE),
        mk_instr(addr + 12, "RET", "", InstrFlags::RET),
    ];
    SemanticFeatures::from_instructions(addr, name.to_string(), &v)
}

// =========================================================================
// SemanticFeatures
// =========================================================================

#[test]
fn t_features_empty_no_panic() {
    let f = SemanticFeatures::from_instructions(0, "e".into(), &[]);
    assert_eq!(f.feature_count(), 0);
    assert_eq!(f.branch_count, 0);
    assert_eq!(f.loop_count, 0);
}

#[test]
fn t_features_self_similarity_one() {
    for i in 0..50u64 {
        let f = feat(0x1000 + i * 0x10, "x");
        let s = f.semantic_similarity(&f);
        assert!((0.99..=1.01).contains(&s), "i={i} s={s}");
    }
}

#[test]
fn t_features_similarity_in_range() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let a = feat(g.next_u64() & 0xFFFFF, "a");
        let b = feat(g.next_u64() & 0xFFFFF, "b");
        let s = a.semantic_similarity(&b);
        assert!((0.0..=1.0).contains(&s), "s={s}");
    }
}

#[test]
fn t_features_backward_branch_is_loop() {
    let mut i = mk_instr(0x2000, "JMP", "", InstrFlags::BRANCH);
    i.operand_list = vec![Operand::UImmediate(0x1000)];
    let f = SemanticFeatures::from_instructions(0x2000, "l".into(), &[i]);
    assert_eq!(f.branch_count, 1);
    assert_eq!(f.loop_count, 1);
}

#[test]
fn t_features_forward_branch_not_loop() {
    let mut i = mk_instr(0x1000, "JMP", "", InstrFlags::BRANCH);
    i.operand_list = vec![Operand::UImmediate(0x2000)];
    let f = SemanticFeatures::from_instructions(0x1000, "f".into(), &[i]);
    assert_eq!(f.loop_count, 0);
}

#[test]
fn t_features_hex_constant_extracted() {
    let i = mk_instr(0x1000, "MOV", "eax, 0xDEADBEEF", InstrFlags::NONE);
    let f = SemanticFeatures::from_instructions(0x1000, "c".into(), &[i]);
    assert!(f.constant_pool.contains(&0xDEADBEEF));
}

#[test]
fn t_features_constants_sorted_deduped() {
    let i1 = mk_instr(0x1000, "MOV", "eax, 0x10", InstrFlags::NONE);
    let i2 = mk_instr(0x1004, "MOV", "ebx, 0x10", InstrFlags::NONE);
    let i3 = mk_instr(0x1008, "MOV", "ecx, 0x5", InstrFlags::NONE);
    let f = SemanticFeatures::from_instructions(0x1000, "c".into(), &[i1, i2, i3]);
    assert_eq!(f.constant_pool, vec![0x5, 0x10]);
}

#[test]
fn t_features_arithmetic_ops_counted() {
    let mn = ["ADD","SUB","MUL","DIV","IMUL","IDIV","AND","OR","XOR","SHL","SHR","SAR","INC","DEC","NEG","NOT","ADDI","SUBI"];
    let v: Vec<Instruction> = mn.iter().enumerate()
        .map(|(i, m)| mk_instr(0x1000 + i as u64 * 4, m, "", InstrFlags::NONE))
        .collect();
    let f = SemanticFeatures::from_instructions(0x1000, "a".into(), &v);
    assert_eq!(f.arithmetic_ops as usize, mn.len());
}

#[test]
fn t_features_mem_ops_both_flags() {
    let v = vec![
        mk_instr(0x1000, "LDR", "", InstrFlags::READ_MEM),
        mk_instr(0x1004, "STR", "", InstrFlags::WRITE_MEM),
        mk_instr(0x1008, "NOP", "", InstrFlags::NONE),
    ];
    let f = SemanticFeatures::from_instructions(0x1000, "m".into(), &v);
    assert_eq!(f.memory_ops, 2);
}

#[test]
fn t_features_display_contains_name_addr() {
    let f = feat(0xABCD, "myfunc");
    let s = f.to_string();
    assert!(s.contains("myfunc"));
    assert!(s.contains("0xabcd"));
}

// =========================================================================
// NormalizedBytes
// =========================================================================

#[test]
fn t_normalized_round_trip_lengths() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next_u64() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| g.next_byte()).collect();
        let fp = FuncFingerprint::new(0x40_0000, "f".into(), bytes.clone());
        let n = NormalizedBytes::from_fingerprint(&fp);
        assert_eq!(n.normalized_bytes.len(), bytes.len());
        assert_eq!(n.original_address, 0x40_0000);
    }
}

#[test]
fn t_normalized_self_similarity_one() {
    let fp = FuncFingerprint::new(0x1000, "f".into(), vec![1,2,3,4,5,6,7,8]);
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert!((n.structural_similarity(&n) - 1.0).abs() < 1e-9);
}

#[test]
fn t_normalized_zeroes_near_address() {
    // 4 bytes encoding base address itself → should be zeroed.
    let base: u64 = 0x40_0000;
    let mut bytes = (base as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFFu8; 4]);
    let fp = FuncFingerprint::new(base, "f".into(), bytes);
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert_eq!(&n.normalized_bytes[..4], &[0,0,0,0]);
}

#[test]
fn t_normalized_display() {
    let fp = FuncFingerprint::new(0x1000, "x".into(), vec![0u8; 16]);
    let n = NormalizedBytes::from_fingerprint(&fp);
    let s = n.to_string();
    assert!(s.contains("Normalized") && s.contains("16 bytes"));
}

// =========================================================================
// SemanticDiffEngine
// =========================================================================

#[test]
fn t_engine_diff_identical_pair() {
    let e = SemanticDiffEngine::new();
    let r = e.diff_with_features(vec![feat(0x1000,"m")], vec![feat(0x1000,"m")], "a".into(), "b".into()).unwrap();
    assert_eq!(r.semantic_matches.len(), 1);
    assert!(r.feature_similarity > 0.5);
}

#[test]
fn t_engine_diff_empty_both_is_err() {
    let e = SemanticDiffEngine::new();
    assert!(e.diff_with_features(vec![], vec![], "a".into(), "b".into()).is_err());
}

#[test]
fn t_engine_diff_only_added() {
    let e = SemanticDiffEngine::new();
    let r = e.diff_with_features(vec![], vec![feat(0x1000,"n")], "a".into(), "b".into()).unwrap();
    assert!(!r.semantic_matches.is_empty());
    // unpaired → feature_similarity 0
    assert_eq!(r.feature_similarity, 0.0);
}

#[test]
fn t_engine_diff_only_removed() {
    let e = SemanticDiffEngine::new();
    let r = e.diff_with_features(vec![feat(0x1000,"o")], vec![], "a".into(), "b".into()).unwrap();
    assert!(!r.semantic_matches.is_empty());
}

#[test]
fn t_engine_default_works() {
    let e = SemanticDiffEngine::default();
    let r = e.diff_with_features(vec![feat(0x1000,"m")], vec![feat(0x1000,"m")], "a".into(), "b".into()).unwrap();
    assert!(r.feature_similarity >= 0.0);
}

#[test]
fn t_engine_debug_label() {
    assert_eq!(format!("{:?}", SemanticDiffEngine::new()), "SemanticDiffEngine");
}

// =========================================================================
// SemanticDiffResult / SemanticMatch display
// =========================================================================

#[test]
fn t_semantic_match_display_has_scores() {
    let fp = FuncFingerprint::new(0, "f".into(), vec![]);
    let sm = SemanticMatch {
        func_match: FuncMatch::added(fp),
        semantic_similarity: 0.42,
        structural_similarity: 0.99,
        changed_features: vec![],
    };
    let s = sm.to_string();
    assert!(s.contains("0.42") && s.contains("0.99"));
}

#[test]
fn t_semantic_diff_result_display() {
    let r = SemanticDiffResult {
        base: BinaryDiff::new("x".into(), "y".into()),
        semantic_matches: vec![],
        feature_similarity: 0.33,
    };
    assert!(r.to_string().contains("0.33"));
}

// =========================================================================
// MinHash
// =========================================================================

#[test]
fn t_minhash_empty_signature_all_max() {
    let mh = MinHash::new(32);
    let sig = mh.signature(&[]);
    assert!(sig.iter().all(|&v| v == u64::MAX));
}

#[test]
fn t_minhash_deterministic_same_seed() {
    let a = MinHash::new(64);
    let b = MinHash::new(64);
    let elems: Vec<u64> = (0..50).collect();
    assert_eq!(a.signature(&elems), b.signature(&elems));
}

#[test]
fn t_minhash_jaccard_self_one() {
    let mh = MinHash::new(64);
    let sig = mh.signature(&[1,2,3,4,5]);
    assert!((MinHash::estimate_jaccard(&sig, &sig) - 1.0).abs() < 1e-9);
}

#[test]
fn t_minhash_jaccard_mismatched_len_zero() {
    assert_eq!(MinHash::estimate_jaccard(&[1u64,2], &[1u64]), 0.0);
    assert_eq!(MinHash::estimate_jaccard(&[], &[1u64]), 0.0);
}

#[test]
fn t_minhash_fuzz_no_panic() {
    let mut g = Lcg::new();
    let mh = MinHash::new(16);
    for _ in 0..50 {
        let n = (g.next_u64() % 30) as usize;
        let elems: Vec<u64> = (0..n).map(|_| g.next_u64()).collect();
        let sig = mh.signature(&elems);
        assert_eq!(sig.len(), 16);
    }
}

#[test]
fn t_minhash_disjoint_low() {
    let mh = MinHash::new(128);
    let a: Vec<u64> = (0..100).collect();
    let b: Vec<u64> = (10_000..10_100).collect();
    let j = MinHash::estimate_jaccard(&mh.signature(&a), &mh.signature(&b));
    assert!(j < 0.15, "j={j}");
}

// =========================================================================
// LshIndex
// =========================================================================

#[test]
fn t_lsh_empty() {
    let i = LshIndex::new(4, 4);
    assert!(i.is_empty());
    assert_eq!(i.len(), 0);
    assert_eq!(i.num_bands(), 4);
    assert_eq!(i.rows_per_band(), 4);
}

#[test]
fn t_lsh_query_finds_self() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 8);
    let sig = mh.signature(&[1,2,3,4,5,6]);
    idx.insert(0xABCD, &sig);
    assert!(idx.query(&sig).contains(&0xABCD));
    assert_eq!(idx.len(), 1);
}

#[test]
fn t_lsh_duplicate_insert_same_id_keeps_len_one() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 8);
    let sig = mh.signature(&[1,2]);
    idx.insert(0x100, &sig);
    idx.insert(0x100, &sig);
    assert_eq!(idx.len(), 1);
}

#[test]
fn t_lsh_query_no_match_empty() {
    let mh = MinHash::new(32);
    let idx = LshIndex::new(4, 8);
    let sig = mh.signature(&[1,2]);
    assert!(idx.query(&sig).is_empty());
}

#[test]
fn t_lsh_short_signature_no_panic() {
    let idx = LshIndex::new(4, 8);
    // signature shorter than num_bands*rows_per_band → must not panic
    let _ = idx.query(&[1u64, 2, 3]);
}

// =========================================================================
// CallGraph
// =========================================================================

#[test]
fn t_callgraph_add_function_idempotent() {
    let mut cg = CallGraph::new();
    let n1 = cg.add_function(0x1000);
    let n2 = cg.add_function(0x1000);
    assert_eq!(n1, n2);
    assert_eq!(cg.function_count(), 1);
}

#[test]
fn t_callgraph_self_loop_counted_once() {
    let mut cg = CallGraph::new();
    cg.add_call(0x1000, 0x1000);
    cg.add_call(0x1000, 0x1000);
    assert_eq!(cg.call_count(), 1);
}

#[test]
fn t_callgraph_unknown_callees_empty() {
    let cg = CallGraph::new();
    assert!(cg.callees(0xDEAD).is_empty());
    assert!(cg.callers(0xBEEF).is_empty());
}

#[test]
fn t_callgraph_isolated_node_is_leaf_and_root() {
    let mut cg = CallGraph::new();
    cg.add_function(0x1000);
    assert!(cg.is_leaf(0x1000));
    assert!(cg.is_root(0x1000));
}

#[test]
fn t_callgraph_fuzz_no_panic() {
    let mut g = Lcg::new();
    let mut cg = CallGraph::new();
    for _ in 0..100 {
        let a = g.next_u64() % 50;
        let b = g.next_u64() % 50;
        cg.add_call(a, b);
    }
    assert!(cg.function_count() <= 50);
    assert!(cg.call_count() <= 50 * 50);
}

// =========================================================================
// FunctionRenameHeuristic
// =========================================================================

#[test]
fn t_rename_default_threshold_080() {
    let h = FunctionRenameHeuristic::default();
    assert!((h.threshold - 0.8).abs() < 1e-9);
}

#[test]
fn t_rename_below_threshold_not_rename() {
    let h = FunctionRenameHeuristic::new(0.9);
    let a = FuncFingerprint::new(0x1000, "a".into(), vec![]);
    let b = FuncFingerprint::new(0x2000, "b".into(), vec![]);
    let sm = SemanticMatch {
        func_match: FuncMatch::similar(a, b, 0.5),
        semantic_similarity: 0.5,
        structural_similarity: 0.5,
        changed_features: vec![],
    };
    assert!(!h.is_rename(&sm));
}

#[test]
fn t_rename_same_name_not_rename() {
    let h = FunctionRenameHeuristic::new(0.5);
    let a = FuncFingerprint::new(0x1000, "x".into(), vec![]);
    let b = FuncFingerprint::new(0x2000, "x".into(), vec![]);
    let sm = SemanticMatch {
        func_match: FuncMatch::similar(a, b, 0.99),
        semantic_similarity: 0.99,
        structural_similarity: 0.99,
        changed_features: vec![],
    };
    assert!(!h.is_rename(&sm));
}

#[test]
fn t_rename_added_func_not_rename() {
    let h = FunctionRenameHeuristic::new(0.5);
    let a = FuncFingerprint::new(0x1000, "a".into(), vec![]);
    let sm = SemanticMatch {
        func_match: FuncMatch::added(a),
        semantic_similarity: 0.99,
        structural_similarity: 0.99,
        changed_features: vec![],
    };
    assert!(!h.is_rename(&sm));
}

#[test]
fn t_rename_find_renames_filter() {
    let h = FunctionRenameHeuristic::new(0.5);
    let mk = |na: &str, nb: &str, sim: f64| {
        let a = FuncFingerprint::new(0, na.into(), vec![]);
        let b = FuncFingerprint::new(0, nb.into(), vec![]);
        SemanticMatch {
            func_match: FuncMatch::similar(a, b, sim),
            semantic_similarity: sim,
            structural_similarity: sim,
            changed_features: vec![],
        }
    };
    let v = vec![mk("a", "b", 0.9), mk("x", "x", 0.9), mk("p", "q", 0.1)];
    let r = h.find_renames(&v);
    assert_eq!(r.len(), 1);
}

// =========================================================================
// DiffReport / BinarySemanticDiff
// =========================================================================

#[test]
fn t_diff_report_is_identical_for_equal_inputs() {
    let e = SemanticDiffEngine::new();
    let r = e.diff_with_features(vec![feat(0x1000,"m")], vec![feat(0x1000,"m")], "a".into(), "b".into()).unwrap();
    let rep = DiffReport::from_result(&r, 0.8);
    assert!(rep.is_identical());
}

#[test]
fn t_diff_report_display_has_diff_label() {
    let e = SemanticDiffEngine::new();
    let r = e.diff_with_features(vec![feat(0x1000,"m")], vec![feat(0x1000,"m")], "abin".into(), "bbin".into()).unwrap();
    let rep = DiffReport::from_result(&r, 0.8);
    let s = rep.to_string();
    assert!(s.contains("DiffReport") && s.contains("abin") && s.contains("bbin"));
}

#[test]
fn t_binary_semantic_diff_with_params() {
    let d = BinarySemanticDiff::with_params(32, 0.6);
    let dbg = format!("{:?}", d);
    assert!(dbg.contains("32") && dbg.contains("0.6"));
}

#[test]
fn t_binary_semantic_diff_lsh_index_sizes() {
    let d = BinarySemanticDiff::new();
    let feats: Vec<SemanticFeatures> = (0..10).map(|i| feat(0x1000 + i * 0x100, "f")).collect();
    let (idx, sigs) = d.build_lsh_index(&feats);
    assert_eq!(sigs.len(), 10);
    assert!(!idx.is_empty());
}

#[test]
fn t_binary_semantic_diff_full() {
    let d = BinarySemanticDiff::new();
    let r = d.diff(vec![feat(0x1000,"m")], vec![feat(0x1000,"m")], "A".into(), "B".into()).unwrap();
    assert_eq!(r.binary_a, "A");
    assert_eq!(r.binary_b, "B");
}

// =========================================================================
// SemanticSignature / SemanticMatcher / SemanticDiffer
// =========================================================================

fn tiny() -> Vec<u8> {
    vec![0x55, 0x89, 0xE5, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3]
}

#[test]
fn t_sig_empty() {
    let s = SemanticSignature::compute(&[], 0);
    assert_eq!(s.instruction_count, 0);
    assert_eq!(s.call_count, 0);
    assert!(s.unique_constants.is_empty());
    assert!(s.string_refs.is_empty());
}

#[test]
fn t_sig_deterministic() {
    let b = tiny();
    let a = SemanticSignature::compute(&b, 0x1000);
    let c = SemanticSignature::compute(&b, 0x1000);
    assert_eq!(a.cfg_hash, c.cfg_hash);
    assert_eq!(a.instruction_count, c.instruction_count);
}

#[test]
fn t_sig_fuzz_no_panic() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = (g.next_u64() % 200) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| g.next_byte()).collect();
        let s = SemanticSignature::compute(&bytes, g.next_u64());
        // sanity: instruction_count ≤ bytes.len() (each instr ≥ 1 byte advance)
        assert!(s.instruction_count as usize <= bytes.len().max(1));
    }
}

#[test]
fn t_sig_truncated_call_no_panic() {
    // 0xE8 with fewer than 5 bytes total
    let s = SemanticSignature::compute(&[0xE8, 0x01], 0);
    assert!(s.instruction_count >= 1);
}

#[test]
fn t_sig_self_similarity_high() {
    let b = tiny();
    let sa = SemanticSignature::compute(&b, 0x1000);
    let sim = SemanticMatcher::similarity(&sa, &sa);
    assert!(sim > 0.99, "{sim}");
    assert!(SemanticMatcher::are_equivalent(&sa, &sa));
}

#[test]
fn t_sig_similarity_range() {
    let mut g = Lcg::new();
    for _ in 0..30 {
        let la = (g.next_u64() % 100) as usize;
        let lb = (g.next_u64() % 100) as usize;
        let ba: Vec<u8> = (0..la).map(|_| g.next_byte()).collect();
        let bb: Vec<u8> = (0..lb).map(|_| g.next_byte()).collect();
        let sa = SemanticSignature::compute(&ba, 0);
        let sb = SemanticSignature::compute(&bb, 0);
        let s = SemanticMatcher::similarity(&sa, &sb);
        assert!((0.0..=1.0001).contains(&s), "s={s}");
    }
}

#[test]
fn t_differ_diff_function_pair_identical() {
    let b = tiny();
    let d = SemanticDiffer::diff_function_pair(&b, 0x1000, &b, 0x1000);
    assert!(d.is_equivalent);
    assert_eq!(d.addr_a, 0x1000);
    assert_eq!(d.addr_b, 0x1000);
}

#[test]
fn t_differ_added_call_detected() {
    let a = vec![0xC3u8];
    let b = vec![0xE8, 0, 0, 0, 0, 0xC3];
    let d = SemanticDiffer::diff_function_pair(&a, 0, &b, 0);
    assert_eq!(d.added_calls.len(), 1);
    assert!(d.removed_calls.is_empty());
}

#[test]
fn t_differ_diff_binaries_empty_is_perfect() {
    let r = SemanticDiffer::diff_binaries(&[], &[]);
    assert_eq!(r.similarity_score, 1.0);
    assert_eq!(r.total_pairs(), 0);
}

#[test]
fn t_differ_added_removed_addrs() {
    let b = tiny();
    let a = vec![(0x1000u64, b.clone())];
    let bv = vec![(0x2000u64, b)];
    let r = SemanticDiffer::diff_binaries(&a, &bv);
    assert_eq!(r.added_funcs, vec![0x2000]);
    assert_eq!(r.removed_funcs, vec![0x1000]);
}

#[test]
fn t_function_diff_display() {
    let b = tiny();
    let d = SemanticDiffer::diff_function_pair(&b, 0xAA, &b, 0xBB);
    let s = d.to_string();
    assert!(s.contains("FunctionDiff"));
    assert!(s.contains("0xaa"));
}

#[test]
fn t_signature_display_contains_addr() {
    let s = SemanticSignature::compute(&tiny(), 0x4242);
    let str_ = s.to_string();
    assert!(str_.contains("0x4242"));
}

// =========================================================================
// Send/Sync threaded stress
// =========================================================================

#[test]
fn t_threaded_signature_compute() {
    let bytes = Arc::new(tiny());
    let handles: Vec<_> = (0..4).map(|t| {
        let b = Arc::clone(&bytes);
        thread::spawn(move || {
            let mut last = 0u32;
            for _ in 0..100 {
                let s = SemanticSignature::compute(&b, t as u64 * 0x1000);
                last = s.instruction_count;
            }
            last
        })
    }).collect();
    for h in handles {
        assert!(h.join().unwrap() > 0);
    }
}

#[test]
fn t_threaded_minhash_signature() {
    let mh = Arc::new(MinHash::new(64));
    let handles: Vec<_> = (0..4).map(|t| {
        let mh = Arc::clone(&mh);
        thread::spawn(move || {
            for i in 0..100u64 {
                let _ = mh.signature(&[t as u64, i, i*2]);
            }
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t_threaded_differ_diff_binaries() {
    let bytes = Arc::new(tiny());
    let handles: Vec<_> = (0..4).map(|t| {
        let b = Arc::clone(&bytes);
        thread::spawn(move || {
            for _ in 0..100 {
                let f = vec![(t as u64 * 0x1000, (*b).clone())];
                let r = SemanticDiffer::diff_binaries(&f, &f);
                assert_eq!(r.added_funcs.len(), 0);
            }
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
}

// =========================================================================
// boundaries / serde round-trip
// =========================================================================

#[test]
fn t_features_serde_round_trip() {
    let f = feat(0x1000, "rt");
    let j = serde_json::to_string(&f).unwrap();
    let back: SemanticFeatures = serde_json::from_str(&j).unwrap();
    assert_eq!(back.address, f.address);
    assert_eq!(back.name, f.name);
}

#[test]
fn t_sig_serde_round_trip() {
    let s = SemanticSignature::compute(&tiny(), 0x1000);
    let j = serde_json::to_string(&s).unwrap();
    let back: SemanticSignature = serde_json::from_str(&j).unwrap();
    assert_eq!(back.cfg_hash, s.cfg_hash);
    assert_eq!(back.instruction_count, s.instruction_count);
}

#[test]
fn t_max_address_no_panic() {
    let f = feat(u64::MAX - 16, "boundary");
    let s = f.semantic_similarity(&f);
    assert!((0.99..=1.01).contains(&s));
}

#[test]
fn t_features_with_huge_histogram() {
    let mut v = Vec::new();
    for i in 0..200u64 {
        v.push(mk_instr(0x1000 + i*4, "NOP", "", InstrFlags::NONE));
    }
    let f = SemanticFeatures::from_instructions(0x1000, "big".into(), &v);
    assert_eq!(f.mnemonic_histogram.get("NOP"), Some(&200));
}

#[test]
fn t_constant_pool_only_hex_prefix() {
    // decimal-looking tokens should NOT be captured (parser requires 0x prefix)
    let i = mk_instr(0x1000, "MOV", "eax, 12345", InstrFlags::NONE);
    let f = SemanticFeatures::from_instructions(0x1000, "d".into(), &[i]);
    assert!(!f.constant_pool.contains(&12345));
}

#[test]
fn t_lsh_threaded_concurrent_query() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 8);
    for i in 0..20u64 {
        idx.insert(i, &mh.signature(&[i, i*2, i*3]));
    }
    let idx = Arc::new(idx);
    let mh = Arc::new(mh);
    let handles: Vec<_> = (0..4).map(|t| {
        let idx = Arc::clone(&idx);
        let mh = Arc::clone(&mh);
        thread::spawn(move || {
            for i in 0..100u64 {
                let _ = idx.query(&mh.signature(&[t as u64 + i]));
            }
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
}

#[test]
fn t_hash_eq_consistency_features_serde() {
    // SemanticFeatures has no Hash/Eq, but we can verify serde round-trip equivalence
    // via re-serialization equality on 30+ inputs.
    let mut g = Lcg::new();
    for _ in 0..30 {
        let f = feat(g.next_u64() & 0xFFFF, "h");
        let j1 = serde_json::to_string(&f).unwrap();
        let back: SemanticFeatures = serde_json::from_str(&j1).unwrap();
        // HashMap serialization order isn't stable; compare semantic fields.
        assert_eq!(back.address, f.address);
        assert_eq!(back.name, f.name);
        assert_eq!(back.mnemonic_histogram, f.mnemonic_histogram);
        assert_eq!(back.constant_pool, f.constant_pool);
    }
}

#[test]
fn t_mnemonic_histogram_map_keys_match_instrs() {
    let mut map: HashMap<String, u32> = HashMap::new();
    map.insert("ADD".into(), 1);
    let v = vec![mk_instr(0x1000, "ADD", "", InstrFlags::NONE)];
    let f = SemanticFeatures::from_instructions(0x1000, "k".into(), &v);
    assert_eq!(f.mnemonic_histogram, map);
}
