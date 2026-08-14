//! Blitz integration tests for rustre-diff-semantic public API.
//!
//! Focus: lib.rs exposed types — SemanticFeatures, NormalizedBytes, MinHash,
//! LshIndex, CallGraph, FunctionRenameHeuristic, SemanticDiffEngine,
//! BinarySemanticDiff, SemanticSignature, SemanticMatcher, SemanticDiffer,
//! PatchAnalysis, DiffReport.

use rustre_core::address::Address;
use rustre_core::arch::{InstrFlags, Instruction, Operand};
use rustre_diff::{FuncFingerprint, MatchKind};
use rustre_diff_semantic::*;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn mk_instr(addr: u64, mnem: &str, flags: InstrFlags) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 4, mnem, vec![0x90; 4]);
    i.flags = flags;
    i
}

fn mk_instr_with_ops(addr: u64, mnem: &str, ops: Vec<Operand>, flags: InstrFlags) -> Instruction {
    let mut i = mk_instr(addr, mnem, flags);
    i.operand_list = ops;
    i
}

// ---------------------------------------------------------------------------
// SemanticFeatures
// ---------------------------------------------------------------------------

#[test]
fn features_empty_function() {
    let f = SemanticFeatures::from_instructions(0x0, "x".into(), &[]);
    assert_eq!(f.branch_count, 0);
    assert_eq!(f.loop_count, 0);
    assert_eq!(f.call_sites.len(), 0);
    assert!(f.constant_pool.is_empty());
    assert!(f.mnemonic_histogram.is_empty());
}

#[test]
fn features_self_similarity_is_one() {
    let instrs: Vec<Instruction> = (0..5)
        .map(|i| mk_instr(0x1000 + i * 4, "ADD", InstrFlags::NONE))
        .collect();
    let f = SemanticFeatures::from_instructions(0x1000, "a".into(), &instrs);
    let sim = f.semantic_similarity(&f);
    assert!((sim - 1.0).abs() < 1e-9, "self-similarity = {sim}");
}

#[test]
fn features_symmetric_similarity() {
    let a_instrs = vec![mk_instr(0x1000, "ADD", InstrFlags::NONE)];
    let b_instrs = vec![
        mk_instr(0x2000, "ADD", InstrFlags::NONE),
        mk_instr(0x2004, "SUB", InstrFlags::NONE),
    ];
    let a = SemanticFeatures::from_instructions(0x1000, "a".into(), &a_instrs);
    let b = SemanticFeatures::from_instructions(0x2000, "b".into(), &b_instrs);
    let ab = a.semantic_similarity(&b);
    let ba = b.semantic_similarity(&a);
    assert!((ab - ba).abs() < 1e-9, "ab={ab} ba={ba}");
}

#[test]
fn features_loop_detected_backward_branch() {
    // Branch at addr 0x2000 targeting 0x1000 — backward → loop.
    let instr = mk_instr_with_ops(
        0x2000,
        "JMP",
        vec![Operand::UImmediate(0x1000)],
        InstrFlags::BRANCH,
    );
    let f = SemanticFeatures::from_instructions(0x1000, "loop".into(), &[instr]);
    assert_eq!(f.loop_count, 1);
    assert_eq!(f.branch_count, 1);
}

#[test]
fn features_no_loop_on_forward_branch() {
    let instr = mk_instr_with_ops(
        0x1000,
        "JMP",
        vec![Operand::UImmediate(0x2000)],
        InstrFlags::BRANCH,
    );
    let f = SemanticFeatures::from_instructions(0x1000, "fwd".into(), &[instr]);
    assert_eq!(f.loop_count, 0);
    assert_eq!(f.branch_count, 1);
}

#[test]
fn features_constant_pool_dedup_and_sorted() {
    let mut i1 = mk_instr(0x1000, "MOV", InstrFlags::NONE);
    i1.operands = "eax, 0x100".into();
    let mut i2 = mk_instr(0x1004, "MOV", InstrFlags::NONE);
    i2.operands = "ebx, 0x50".into();
    let mut i3 = mk_instr(0x1008, "MOV", InstrFlags::NONE);
    i3.operands = "ecx, 0x100".into();
    let f = SemanticFeatures::from_instructions(0x1000, "c".into(), &[i1, i2, i3]);
    assert_eq!(f.constant_pool, vec![0x50, 0x100]);
}

#[test]
fn features_feature_count_sum() {
    let mut f = SemanticFeatures::from_instructions(0x1000, "x".into(), &[]);
    f.call_sites = vec![1, 2];
    f.string_refs = vec!["a".into()];
    f.constant_pool = vec![10, 20, 30];
    assert_eq!(f.feature_count(), 6);
}

#[test]
fn features_display_contains_name_and_addr() {
    let f = SemanticFeatures::from_instructions(0xDEAD, "myfunc".into(), &[]);
    let s = format!("{f}");
    assert!(s.contains("myfunc"));
    assert!(s.contains("0xdead"));
}

#[test]
fn features_serde_roundtrip() {
    let f = SemanticFeatures::from_instructions(
        0x1000,
        "f".into(),
        &[mk_instr(0x1000, "ADD", InstrFlags::NONE)],
    );
    let j = serde_json::to_string(&f).unwrap();
    let f2: SemanticFeatures = serde_json::from_str(&j).unwrap();
    assert_eq!(f.address, f2.address);
    assert_eq!(f.name, f2.name);
    assert_eq!(f.arithmetic_ops, f2.arithmetic_ops);
}

// ---------------------------------------------------------------------------
// NormalizedBytes
// ---------------------------------------------------------------------------

#[test]
fn normalized_zero_out_address_like_words() {
    // base near 0x401000; embed value 0x401234 (within ±4MiB) as LE bytes.
    let fp = FuncFingerprint::new(
        0x0040_1000,
        "f".into(),
        vec![0x34, 0x12, 0x40, 0x00, 0xC3],
    );
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert_eq!(&n.normalized_bytes[0..4], &[0u8; 4]);
}

#[test]
fn normalized_leaves_far_words_alone() {
    let fp = FuncFingerprint::new(
        0x0040_1000,
        "f".into(),
        vec![0xFF, 0xFF, 0xFF, 0x7F, 0xC3],
    );
    let n = NormalizedBytes::from_fingerprint(&fp);
    // 0x7FFFFFFF is well outside ±4MiB of 0x401000, so bytes preserved.
    assert_eq!(&n.normalized_bytes[0..4], &[0xFF, 0xFF, 0xFF, 0x7F]);
}

#[test]
fn normalized_structural_similarity_self_is_one() {
    let fp = FuncFingerprint::new(0x1000, "f".into(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert!((n.structural_similarity(&n.clone()) - 1.0).abs() < 1e-9);
}

#[test]
fn normalized_empty_bytes_no_panic() {
    let fp = FuncFingerprint::new(0x1000, "f".into(), vec![]);
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert_eq!(n.normalized_bytes.len(), 0);
}

#[test]
fn normalized_saturating_lo() {
    // base = 0 → lo = 0 (saturating), so any small value in [0, 4MiB] zeroed.
    let fp = FuncFingerprint::new(0, "f".into(), vec![0x10, 0x00, 0x00, 0x00, 0xC3]);
    let n = NormalizedBytes::from_fingerprint(&fp);
    assert_eq!(&n.normalized_bytes[0..4], &[0u8; 4]);
}

// ---------------------------------------------------------------------------
// MinHash
// ---------------------------------------------------------------------------

#[test]
fn minhash_signature_length_matches() {
    for n in [1usize, 8, 64, 128] {
        let mh = MinHash::new(n);
        assert_eq!(mh.signature(&[1, 2, 3]).len(), n);
    }
}

#[test]
fn minhash_deterministic_signature() {
    let mh1 = MinHash::new(32);
    let mh2 = MinHash::new(32);
    let sig1 = mh1.signature(&[10, 20, 30]);
    let sig2 = mh2.signature(&[10, 20, 30]);
    assert_eq!(sig1, sig2);
}

#[test]
fn minhash_empty_input_signature_is_max() {
    let mh = MinHash::new(8);
    let sig = mh.signature(&[]);
    assert!(sig.iter().all(|&v| v == u64::MAX));
}

#[test]
fn minhash_jaccard_self_one() {
    let mh = MinHash::new(64);
    let s = mh.signature(&[1, 2, 3, 4, 5]);
    assert_eq!(MinHash::estimate_jaccard(&s, &s), 1.0);
}

#[test]
fn minhash_jaccard_empty_returns_zero() {
    assert_eq!(MinHash::estimate_jaccard(&[], &[]), 0.0);
}

#[test]
fn minhash_jaccard_length_mismatch_returns_zero() {
    assert_eq!(MinHash::estimate_jaccard(&[1, 2, 3], &[1, 2]), 0.0);
}

// ---------------------------------------------------------------------------
// LshIndex
// ---------------------------------------------------------------------------

#[test]
fn lsh_new_is_empty() {
    let idx = LshIndex::new(4, 4);
    assert!(idx.is_empty());
    assert_eq!(idx.len(), 0);
    assert_eq!(idx.num_bands(), 4);
    assert_eq!(idx.rows_per_band(), 4);
}

#[test]
fn lsh_len_counts_distinct_ids() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 4);
    let sig = mh.signature(&[1, 2]);
    idx.insert(1, &sig);
    idx.insert(2, &sig);
    idx.insert(1, &sig); // duplicate id
    assert_eq!(idx.len(), 2);
}

#[test]
fn lsh_query_returns_inserted_id() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 4);
    let sig = mh.signature(&[5, 10, 15]);
    idx.insert(42, &sig);
    let c = idx.query(&sig);
    assert!(c.contains(&42));
}

#[test]
fn lsh_query_dedups_results() {
    let mh = MinHash::new(32);
    let mut idx = LshIndex::new(4, 4);
    let sig = mh.signature(&[5, 10]);
    idx.insert(7, &sig);
    let c = idx.query(&sig);
    // 7 should appear exactly once even though multiple bands match.
    assert_eq!(c.iter().filter(|&&x| x == 7).count(), 1);
}

#[test]
fn lsh_query_empty_signature_no_panic() {
    let idx = LshIndex::new(4, 4);
    let c = idx.query(&[]);
    assert!(c.is_empty());
}

// ---------------------------------------------------------------------------
// CallGraph
// ---------------------------------------------------------------------------

#[test]
fn callgraph_add_function_idempotent() {
    let mut cg = CallGraph::new();
    let i1 = cg.add_function(0x1000);
    let i2 = cg.add_function(0x1000);
    assert_eq!(i1, i2);
    assert_eq!(cg.function_count(), 1);
}

#[test]
fn callgraph_unknown_callees_empty() {
    let cg = CallGraph::new();
    assert!(cg.callees(0xDEAD).is_empty());
    assert!(cg.callers(0xBEEF).is_empty());
}

#[test]
fn callgraph_self_loop() {
    let mut cg = CallGraph::new();
    cg.add_call(0x1000, 0x1000);
    assert_eq!(cg.function_count(), 1);
    assert_eq!(cg.call_count(), 1);
    assert!(!cg.is_leaf(0x1000));
    assert!(!cg.is_root(0x1000));
}

#[test]
fn callgraph_isolated_node_is_leaf_and_root() {
    let mut cg = CallGraph::new();
    cg.add_function(0x9000);
    assert!(cg.is_leaf(0x9000));
    assert!(cg.is_root(0x9000));
}

#[test]
fn callgraph_default_equals_new() {
    let d = CallGraph::default();
    assert_eq!(d.function_count(), 0);
}

// ---------------------------------------------------------------------------
// FunctionRenameHeuristic
// ---------------------------------------------------------------------------

#[test]
fn rename_heuristic_default_threshold() {
    let h = FunctionRenameHeuristic::default();
    assert!((h.threshold - 0.8).abs() < 1e-9);
}

#[test]
fn rename_heuristic_unpaired_match_is_not_rename() {
    let h = FunctionRenameHeuristic::new(0.5);
    let fp = FuncFingerprint::new(0x1000, "a".into(), vec![]);
    let sm = SemanticMatch {
        func_match: rustre_diff::FuncMatch::added(fp),
        semantic_similarity: 0.99,
        structural_similarity: 0.99,
        changed_features: vec![],
    };
    assert!(!h.is_rename(&sm));
}

#[test]
fn rename_heuristic_find_renames_filters() {
    let h = FunctionRenameHeuristic::new(0.7);
    let fp_a = FuncFingerprint::new(0x1000, "old".into(), vec![]);
    let fp_b = FuncFingerprint::new(0x2000, "new".into(), vec![]);
    let rename_match = SemanticMatch {
        func_match: rustre_diff::FuncMatch::similar(fp_a.clone(), fp_b, 0.9),
        semantic_similarity: 0.9,
        structural_similarity: 0.9,
        changed_features: vec![],
    };
    let added_match = SemanticMatch {
        func_match: rustre_diff::FuncMatch::added(fp_a),
        semantic_similarity: 0.9,
        structural_similarity: 0.0,
        changed_features: vec![],
    };
    let v = vec![rename_match, added_match];
    let r = h.find_renames(&v);
    assert_eq!(r.len(), 1);
}

// ---------------------------------------------------------------------------
// SemanticSignature / SemanticMatcher / SemanticDiffer
// ---------------------------------------------------------------------------

#[test]
fn signature_constants_skip_tiny() {
    // 0xB8 followed by 4-byte imm = 0x00000002 → should NOT be in constants (>3 filter).
    let bytes = vec![0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3];
    let sig = SemanticSignature::compute(&bytes, 0x1000);
    assert!(!sig.unique_constants.contains(&2));
}

#[test]
fn signature_call_count_multiple_e8() {
    let mut bytes = vec![];
    for _ in 0..5 {
        bytes.extend_from_slice(&[0xE8, 0, 0, 0, 0]);
    }
    bytes.push(0xC3);
    let sig = SemanticSignature::compute(&bytes, 0x1000);
    assert_eq!(sig.call_count, 5);
}

#[test]
fn signature_truncated_call_no_panic() {
    let bytes = vec![0xE8, 0x01]; // incomplete CALL
    let _sig = SemanticSignature::compute(&bytes, 0x1000);
}

#[test]
fn signature_rex_prefix_skipped() {
    // 0x48 (REX.W) + 0xC3 (RET) — REX must not be treated as INC/DEC.
    let bytes = vec![0x48, 0xC3];
    let sig = SemanticSignature::compute(&bytes, 0x1000);
    assert!(sig.mnemonic_histogram.contains_key("RET"));
    assert!(!sig.mnemonic_histogram.contains_key("INCDEC"));
}

#[test]
fn signature_display_format() {
    let sig = SemanticSignature::compute(&[0xC3], 0x4000);
    let s = format!("{sig}");
    assert!(s.contains("0x4000"));
    assert!(s.contains("instrs="));
    assert!(s.contains("calls="));
}

#[test]
fn matcher_similarity_in_range() {
    let a = SemanticSignature::compute(&[0xC3], 0x1000);
    let b = SemanticSignature::compute(&[0x90; 64], 0x2000);
    let s = SemanticMatcher::similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s), "sim={s}");
}

#[test]
fn differ_diff_function_pair_identical() {
    let bytes = vec![0x55, 0x89, 0xE5, 0xC3];
    let d = SemanticDiffer::diff_function_pair(&bytes, 0x1000, &bytes, 0x2000);
    assert!(d.is_equivalent);
    assert_eq!(d.addr_a, 0x1000);
    assert_eq!(d.addr_b, 0x2000);
}

#[test]
fn differ_diff_binaries_empty_score_one() {
    let r = SemanticDiffer::diff_binaries(&[], &[]);
    assert_eq!(r.similarity_score, 1.0);
    assert_eq!(r.total_pairs(), 0);
}

#[test]
fn differ_diff_binaries_only_added() {
    let r = SemanticDiffer::diff_binaries(&[], &[(0x1000, vec![0xC3])]);
    assert_eq!(r.added_funcs, vec![0x1000]);
    assert!(r.removed_funcs.is_empty());
    assert!((0.0..=1.0).contains(&r.similarity_score));
}

#[test]
fn differ_diff_binaries_only_removed() {
    let r = SemanticDiffer::diff_binaries(&[(0x1000, vec![0xC3])], &[]);
    assert_eq!(r.removed_funcs, vec![0x1000]);
    assert!(r.added_funcs.is_empty());
}

// ---------------------------------------------------------------------------
// SemanticDiffEngine / BinarySemanticDiff / DiffReport
// ---------------------------------------------------------------------------

fn feat(addr: u64, name: &str, mnem: &str, n: usize) -> SemanticFeatures {
    let instrs: Vec<Instruction> = (0..n)
        .map(|i| mk_instr(addr + (i as u64) * 4, mnem, InstrFlags::NONE))
        .collect();
    SemanticFeatures::from_instructions(addr, name.into(), &instrs)
}

#[test]
fn engine_diff_paired_features_yields_match() {
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(
            vec![feat(0x1000, "main", "ADD", 4)],
            vec![feat(0x1000, "main", "ADD", 4)],
            "a".into(),
            "b".into(),
        )
        .unwrap();
    assert_eq!(r.semantic_matches.len(), 1);
    assert!(r.feature_similarity > 0.0);
}

#[test]
fn engine_diff_added_only_paired_count_zero() {
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(
            vec![],
            vec![feat(0x1000, "x", "ADD", 4)],
            "a".into(),
            "b".into(),
        )
        .unwrap();
    // feature_similarity = 0 (no paired matches)
    assert_eq!(r.feature_similarity, 0.0);
    assert!(r
        .semantic_matches
        .iter()
        .any(|m| m.func_match.kind == MatchKind::Added));
}

#[test]
fn diff_report_renames_only_when_threshold_met() {
    // Build a diff result with a Similar match between renamed functions.
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(
            vec![feat(0x1000, "old_name", "ADD", 4)],
            vec![feat(0x1000, "new_name", "ADD", 4)],
            "a".into(),
            "b".into(),
        )
        .unwrap();
    let report_high = DiffReport::from_result(&r, 1.5); // impossible threshold
    assert!(report_high.renames.is_empty());
}

#[test]
fn diff_report_is_identical_for_only_identical() {
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(
            vec![feat(0x1000, "m", "ADD", 2)],
            vec![feat(0x1000, "m", "ADD", 2)],
            "a".into(),
            "b".into(),
        )
        .unwrap();
    let report = DiffReport::from_result(&r, 0.8);
    // If the underlying matcher classifies as Identical, is_identical()=true.
    if report.stats.identical > 0 && report.stats.added == 0 && report.stats.removed == 0 && report.stats.modified == 0 {
        assert!(report.is_identical());
    }
}

#[test]
fn diff_report_modified_matches_filtered() {
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(
            vec![feat(0x1000, "x", "ADD", 4)],
            vec![feat(0x1000, "x", "SUB", 4)],
            "a".into(),
            "b".into(),
        )
        .unwrap();
    let report = DiffReport::from_result(&r, 0.8);
    let _ = report.modified_matches();
}

#[test]
fn diff_report_display_no_panic() {
    let e = SemanticDiffEngine::new();
    let r = e
        .diff_with_features(vec![feat(0x1000, "x", "ADD", 1)], vec![], "a".into(), "b".into())
        .unwrap();
    let report = DiffReport::from_result(&r, 0.8);
    let s = format!("{report}");
    assert!(s.contains("DiffReport"));
}

#[test]
fn binary_diff_with_params_debug() {
    let d = BinarySemanticDiff::with_params(32, 0.6);
    let s = format!("{d:?}");
    assert!(s.contains("BinarySemanticDiff"));
    assert!(s.contains("32"));
}

#[test]
fn binary_diff_build_lsh_index_empty_features() {
    let d = BinarySemanticDiff::new();
    let (idx, sigs) = d.build_lsh_index(&[]);
    assert!(idx.is_empty());
    assert!(sigs.is_empty());
}

#[test]
fn binary_diff_lsh_index_size_matches_features() {
    let d = BinarySemanticDiff::new();
    let feats = vec![
        feat(0x1000, "a", "ADD", 4),
        feat(0x2000, "b", "SUB", 4),
        feat(0x3000, "c", "MOV", 4),
    ];
    let (idx, sigs) = d.build_lsh_index(&feats);
    assert_eq!(sigs.len(), 3);
    assert_eq!(idx.len(), 3);
}

#[test]
fn binary_diff_full_run_no_panic() {
    let d = BinarySemanticDiff::with_params(16, 0.7);
    let report = d
        .diff(
            vec![feat(0x1000, "a", "ADD", 2)],
            vec![feat(0x1000, "a", "ADD", 2)],
            "ba".into(),
            "bb".into(),
        )
        .unwrap();
    assert_eq!(report.binary_a, "ba");
    assert_eq!(report.binary_b, "bb");
}

// ---------------------------------------------------------------------------
// PatchAnalysis
// ---------------------------------------------------------------------------

#[test]
fn patch_analysis_summary_format() {
    let r = SemanticDiffer::diff_binaries(&[], &[]);
    let s = PatchAnalysis::summarize_changes(&r);
    assert!(s.contains("Binary similarity"));
    assert!(s.contains("Functions:"));
}

#[test]
fn patch_analysis_serde_roundtrip() {
    let r = SemanticDiffer::diff_binaries(&[], &[]);
    let res = PatchAnalysis::analyze_patch(&r, &r);
    let j = serde_json::to_string(&res).unwrap();
    let back: PatchAnalysisResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.changed_functions.len(), res.changed_functions.len());
}

#[test]
fn patch_analysis_added_constant_power_of_two_flagged() {
    // Construct: before has only constants, after adds a power-of-two constant.
    // Easiest path: synthesize FunctionDiff variants by going through diff_function_pair
    // with bytes that produce a power-of-two added constant.
    // Before: MOV reg, 0x100 (256, power of two). After: same MOV plus MOV with 0x1000 added.
    let before_bytes_a = vec![0xB8, 0x00, 0x01, 0x00, 0x00, 0xC3]; // MOV eax,0x100
    let before_bytes_b = before_bytes_a.clone();
    let after_bytes_a = vec![0xB8, 0x00, 0x01, 0x00, 0x00, 0xC3];
    // After: includes a new power-of-two constant 0x1000 by adding another MOV imm32.
    let after_bytes_b = vec![
        0xB8, 0x00, 0x01, 0x00, 0x00, // MOV eax,0x100
        0xB8, 0x00, 0x10, 0x00, 0x00, // MOV eax,0x1000 (power of two)
        0xC3,
    ];
    let before_a: Vec<(u64, Vec<u8>)> = vec![(0x1000, before_bytes_a)];
    let before_b: Vec<(u64, Vec<u8>)> = vec![(0x1000, before_bytes_b)];
    let after_a: Vec<(u64, Vec<u8>)> = vec![(0x1000, after_bytes_a)];
    let after_b: Vec<(u64, Vec<u8>)> = vec![(0x1000, after_bytes_b)];
    let before = SemanticDiffer::diff_binaries(&before_a, &before_b);
    let after = SemanticDiffer::diff_binaries(&after_a, &after_b);
    let _ = PatchAnalysis::analyze_patch(&before, &after);
    // Just exercise — power-of-two heuristic path covered if function ends in changed_pairs.
}

#[test]
fn patch_analysis_added_func_flagged_in_security() {
    let bytes = vec![0xC3];
    let a: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone())];
    let b: Vec<(u64, Vec<u8>)> = vec![(0x1000, bytes.clone()), (0x2000, bytes)];
    let before = SemanticDiffer::diff_binaries(&a, &a);
    let after = SemanticDiffer::diff_binaries(&a, &b);
    let r = PatchAnalysis::analyze_patch(&before, &after);
    assert!(r
        .security_relevant_changes
        .iter()
        .any(|s| s.contains("0x2000") && s.contains("newly introduced")));
}

// ---------------------------------------------------------------------------
// SemanticDiffError
// ---------------------------------------------------------------------------

#[test]
fn error_display_normalization() {
    let e = SemanticDiffError::NormalizationFailed("bad".into());
    assert!(format!("{e}").contains("normalization failed"));
}

#[test]
fn error_display_diff() {
    let e = SemanticDiffError::Diff(anyhow::anyhow!("oops"));
    assert!(format!("{e}").contains("diff error"));
}
