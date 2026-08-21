//! Exhaustive blitz tests for `rustre-deobf-iadl`.
//!
//! Focus: surface bugs in public APIs around scoring, orchestration, hashing,
//! perturbation, and binary analysis. Production code is OFF-LIMITS.

use rustre_deobf_iadl::*;
use rustre_deobf_iadl::perturbation::{
    apply_perturbation, measure_effect, rank_perturbations, Perturbation, PerturbationType,
};

// ─────────────────────────────────────────────────────────────────────────────
// IadlState / TentativeState / IadlConfig
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn iadl_state_new_defaults() {
    let s = IadlState::new(0.0, 0);
    assert_eq!(s.iteration, 0);
    assert!(s.score_components.is_empty());
    assert_eq!(s.complexity, 0);
}

#[test]
fn iadl_state_clone_eq() {
    let mut a = IadlState::new(0.5, 10);
    a.score_components.insert("k".into(), 1.0);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn tentative_state_into_strings() {
    let t = TentativeState::new(String::from("id"), 0.1, 1, String::from("r"));
    assert_eq!(t.hypothesis_id, "id");
    assert_eq!(t.rationale, "r");
}

#[test]
fn iadl_config_default_values() {
    let c = IadlConfig::default();
    assert_eq!(c.max_iterations, 64);
    assert_eq!(c.max_no_progress, 3);
    assert!(c.complexity_penalty == 0.0);
    assert!(c.min_improvement > 0.0);
}

// ─────────────────────────────────────────────────────────────────────────────
// ConstantHypothesis / IncrementalHypothesis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn constant_hypothesis_default_prior() {
    let h = ConstantHypothesis::new("c", 0.5, 1, "r");
    assert!((h.prior(&IadlState::new(0.0, 0)) - 0.5).abs() < 1e-9);
}

#[test]
fn constant_hypothesis_with_prior_clamps_above_one() {
    let h = ConstantHypothesis::new("c", 0.0, 0, "").with_prior(5.0);
    assert!((h.prior - 1.0).abs() < 1e-9);
}

#[test]
fn constant_hypothesis_with_prior_clamps_below_zero() {
    let h = ConstantHypothesis::new("c", 0.0, 0, "").with_prior(-1.0);
    assert!(h.prior.abs() < 1e-9);
}

#[test]
fn incremental_hypothesis_zero_factor_noop() {
    let h = IncrementalHypothesis::new("i", 0.0);
    let s = IadlState::new(0.5, 100);
    let t = h.apply(&s);
    assert_eq!(t.complexity, 100);
    assert!((t.score - 0.5).abs() < 1e-9);
}

#[test]
fn incremental_hypothesis_caps_score_at_one() {
    let h = IncrementalHypothesis::new("i", 10.0);
    let s = IadlState::new(0.9, 100);
    let t = h.apply(&s);
    assert!(t.score <= 1.0 + 1e-9);
}

#[test]
fn incremental_hypothesis_factor_two_halves_complexity() {
    let h = IncrementalHypothesis::new("i", 2.0);
    let s = IadlState::new(0.4, 100);
    let t = h.apply(&s);
    assert_eq!(t.complexity, 50);
}

// ─────────────────────────────────────────────────────────────────────────────
// ComplexityScorer / ImprovementScorer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn complexity_scorer_weight_clamped() {
    let s = ComplexityScorer::new(2.5);
    assert!((s.weight - 1.0).abs() < 1e-9);
    let s2 = ComplexityScorer::new(-3.0);
    assert!(s2.weight.abs() < 1e-9);
}

#[test]
fn complexity_scorer_zero_baseline_returns_half() {
    let s = ComplexityScorer::new(1.0);
    let baseline = IadlState::new(0.0, 0);
    let t = TentativeState::new("h", 0.0, 999, "");
    assert!((s.score(&t, &baseline) - 0.5).abs() < 1e-9);
}

#[test]
fn complexity_scorer_higher_complexity_zero_score() {
    let s = ComplexityScorer::new(1.0);
    let baseline = IadlState::new(0.0, 100);
    let t = TentativeState::new("h", 0.0, 500, "");
    assert!(s.score(&t, &baseline).abs() < 1e-9);
}

#[test]
fn improvement_scorer_weight_clamped() {
    let s = ImprovementScorer::new(-1.0);
    assert!(s.weight.abs() < 1e-9);
}

#[test]
fn improvement_scorer_clamps_huge_improvement_to_one() {
    let s = ImprovementScorer::new(1.0);
    let baseline = IadlState::new(0.0, 0);
    let t = TentativeState::new("h", 100.0, 0, "");
    assert!((s.score(&t, &baseline) - 1.0).abs() < 1e-9);
}

// ─────────────────────────────────────────────────────────────────────────────
// HashAlgorithm + compute_hash
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hash_algorithm_unknown_returns_zero() {
    assert_eq!(compute_hash(b"anything", HashAlgorithm::Unknown), 0);
}

#[test]
fn hash_algorithm_all_names() {
    for a in [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
        HashAlgorithm::Unknown,
    ] {
        assert!(!a.name().is_empty());
    }
}

#[test]
fn djb2_known_vector() {
    // Standard djb2("") = 5381
    assert_eq!(compute_hash(b"", HashAlgorithm::Djb2), 5381);
}

#[test]
fn crc32_empty_is_zero() {
    assert_eq!(compute_hash(b"", HashAlgorithm::Crc32), 0);
}

#[test]
fn adler32_empty_is_one() {
    // Adler32("") = 1
    assert_eq!(compute_hash(b"", HashAlgorithm::Adler32), 1);
}

#[test]
fn sdbm_empty_is_zero() {
    assert_eq!(compute_hash(b"", HashAlgorithm::Sdbm), 0);
}

#[test]
fn ror_hash_empty_is_zero() {
    assert_eq!(compute_hash(b"", HashAlgorithm::RorHash), 0);
}

#[test]
fn compute_hash_differs_across_algos() {
    let h1 = compute_hash(b"LoadLibraryA", HashAlgorithm::Djb2);
    let h2 = compute_hash(b"LoadLibraryA", HashAlgorithm::Crc32);
    let h3 = compute_hash(b"LoadLibraryA", HashAlgorithm::Fnv1a32);
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);
}

// ─────────────────────────────────────────────────────────────────────────────
// HashTable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hashtable_default_is_unknown_algo() {
    let t = HashTable::default();
    assert_eq!(t.algorithm, HashAlgorithm::Unknown);
    assert!(t.is_empty());
}

#[test]
fn hashtable_resolve_miss_is_none() {
    let t = HashTable::build(&["A"], HashAlgorithm::Djb2);
    assert!(t.resolve(0).is_none());
}

#[test]
fn hashtable_entries_round_trip() {
    let names = ["X", "Y", "Z"];
    let t = HashTable::build(&names, HashAlgorithm::Sdbm);
    let entries = t.entries();
    assert_eq!(entries.len(), 3);
    for (h, n) in entries {
        assert_eq!(compute_hash(n.as_bytes(), HashAlgorithm::Sdbm), h);
    }
}

#[test]
fn hashtable_insert_with_unknown_algo_collides() {
    // Bug-sniff: Unknown algorithm always returns 0, so inserting multiple
    // names collides on hash 0. The table will only keep the LAST name.
    let mut t = HashTable::new(HashAlgorithm::Unknown);
    t.insert("A");
    t.insert("B");
    assert_eq!(t.len(), 1, "all unknown-algo entries collide on hash 0");
    assert_eq!(t.resolve(0), Some("B"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiHash / ApiResolution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn api_hash_default_unresolved() {
    let h = ApiHash::new(1, HashAlgorithm::Djb2, 0);
    assert!(!h.is_resolved());
    assert!(!h.is_fully_resolved());
}

#[test]
fn api_hash_only_name_not_fully_resolved() {
    let h = ApiHash::new(1, HashAlgorithm::Djb2, 0).with_name("X");
    assert!(h.is_resolved());
    assert!(!h.is_fully_resolved());
}

#[test]
fn api_resolution_confidence_capped_at_100() {
    let h = ApiHash::new(0, HashAlgorithm::Djb2, 0);
    let r = ApiResolution::new(h, 0).with_confidence(500);
    assert_eq!(r.confidence, 100);
    assert!(r.is_high_confidence());
}

#[test]
fn api_resolution_with_address() {
    let h = ApiHash::new(0, HashAlgorithm::Djb2, 0);
    let r = ApiResolution::new(h, 0).with_address(0xDEAD_BEEF);
    assert_eq!(r.resolved_address, Some(0xDEAD_BEEF));
}

#[test]
fn api_resolution_default_confidence_50_not_high() {
    let h = ApiHash::new(0, HashAlgorithm::Djb2, 0);
    let r = ApiResolution::new(h, 0);
    assert_eq!(r.confidence, 50);
    assert!(!r.is_high_confidence());
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlDetector
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_scan_short_data_empty() {
    let d = IadlDetector::new();
    assert!(d.scan_hash_constants(&[1, 2, 3]).is_empty());
}

#[test]
fn detector_scan_all_zeros_empty() {
    let d = IadlDetector::new();
    assert!(d.scan_hash_constants(&[0u8; 64]).is_empty());
}

#[test]
fn detector_scan_all_ones_empty() {
    let d = IadlDetector::new();
    assert!(d.scan_hash_constants(&[0xFFu8; 64]).is_empty());
}

#[test]
fn detector_scan_emits_only_one_per_offset() {
    // Pick a value where BOTH LE and BE pass the filter — ensure no dup.
    // 0x0F0F0F0F: popcount 16, BE == LE so only one would emit anyway.
    // Use an asymmetric value: 0xF000_F00F popcount = 4+4+4 = 12.
    let val: u32 = 0xF0_00_F0_0F; // popcount 4+4+4 = 12
    let data = val.to_le_bytes();
    let d = IadlDetector::new();
    let consts = d.scan_hash_constants(&data);
    // Exactly one entry expected at offset 0.
    assert_eq!(consts.len(), 1);
    assert_eq!(consts[0].1, 0);
}

#[test]
fn detector_loadlib_pattern_finds_all_offsets() {
    let d = IadlDetector::new();
    let data: Vec<u8> = vec![0xFF, 0xD0, 0x00, 0xFF, 0xD2, 0x00, 0xFF, 0x15, 0x00];
    let offsets = d.detect_loadlib_pattern(&data);
    assert!(offsets.contains(&0));
    assert!(offsets.contains(&3));
    assert!(offsets.contains(&6));
}

#[test]
fn detector_loadlib_pattern_dedup_and_sorted() {
    let d = IadlDetector::new();
    let data: Vec<u8> = vec![0xFF, 0xD0, 0xFF, 0xD0];
    let offsets = d.detect_loadlib_pattern(&data);
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    assert_eq!(offsets, sorted);
    let mut dedup = offsets.clone();
    dedup.dedup();
    assert_eq!(offsets, dedup);
}

#[test]
fn detector_identify_algorithm_no_match_unknown() {
    let d = IadlDetector::new();
    let (algo, n) = d.identify_algorithm(&[0xDEAD_BEEF, 0xCAFE_BABE]);
    assert_eq!(algo, HashAlgorithm::Unknown);
    assert_eq!(n, 0);
}

#[test]
fn detector_analyze_below_min_refs_empty() {
    let d = IadlDetector { min_hash_refs: 1000, ..IadlDetector::default() };
    let val: u32 = 0xF0F0_F0F0;
    let data = val.to_le_bytes();
    assert!(d.analyze(&data, 0).is_empty());
}

#[test]
fn detector_analyze_scan_disabled_returns_empty() {
    let mut d = IadlDetector::new();
    d.scan_hashes = false;
    let data: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
    assert!(d.analyze(&data, 0).is_empty());
}

#[test]
fn detector_analyze_call_site_base_applied() {
    // Build data with two djb2 hashes of known APIs at offsets 0 and 8.
    let h1 = compute_hash(b"LoadLibraryA", HashAlgorithm::Djb2) as u32;
    let h2 = compute_hash(b"GetProcAddress", HashAlgorithm::Djb2) as u32;
    let mut data = Vec::new();
    data.extend_from_slice(&h1.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]); // padding (zero → skipped)
    data.extend_from_slice(&h2.to_le_bytes());
    let d = IadlDetector::new();
    let res = d.analyze(&data, 0x1000);
    assert!(!res.is_empty());
    for r in &res {
        assert!(r.call_site >= 0x1000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadLibraryChain / ChainStep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn chain_step_new_no_argument() {
    let s = ChainStep::new(0x100, "LoadLibrary");
    assert!(s.argument.is_none());
}

#[test]
fn chain_empty_is_empty() {
    let c = LoadLibraryChain::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
    assert!(!c.is_complete());
}

#[test]
fn chain_only_gpa_not_complete() {
    let mut c = LoadLibraryChain::new();
    c.push(ChainStep::new(0, "GetProcAddress"));
    assert!(!c.is_complete());
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolutionStats
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resolution_stats_all_resolved_100_percent() {
    let resolutions: Vec<_> = (0..4)
        .map(|i| {
            let h = ApiHash::new(i, HashAlgorithm::Djb2, 0).with_name("X");
            ApiResolution::new(h, 0)
        })
        .collect();
    let s = ResolutionStats::from_resolutions(&resolutions);
    assert_eq!(s.resolved, 4);
    assert_eq!(s.unresolved, 0);
    assert!((s.resolution_rate - 100.0).abs() < 1e-9);
    assert!(s.is_good_coverage());
}

#[test]
fn resolution_stats_50_percent_not_good_coverage() {
    let h_ok = ApiHash::new(1, HashAlgorithm::Djb2, 0).with_name("X");
    let h_no = ApiHash::new(2, HashAlgorithm::Djb2, 0);
    let r = vec![ApiResolution::new(h_ok, 0), ApiResolution::new(h_no, 0)];
    let s = ResolutionStats::from_resolutions(&r);
    // 50% is NOT > 50%, so coverage is not "good".
    assert!(!s.is_good_coverage());
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryIadlReport JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn report_json_round_trip() {
    let r = BinaryIadlReport {
        iterations_run: 5,
        layers_identified: vec![ProtectionLayer::Packer("UPX".into())],
        applied_passes: vec!["UPXUnpack".into()],
        final_score: 0.42,
        recommendations: vec!["x".into()],
        time_elapsed_ms: 999,
    };
    let json = r.to_json().expect("serialise");
    let back = BinaryIadlReport::from_json(&json).expect("deserialise");
    assert_eq!(r.iterations_run, back.iterations_run);
    assert_eq!(r.layers_identified, back.layers_identified);
    assert_eq!(r.applied_passes, back.applied_passes);
}

#[test]
fn report_from_json_malformed_errors() {
    assert!(BinaryIadlReport::from_json("not json").is_err());
    assert!(BinaryIadlReport::from_json("{}").is_err());
}

#[test]
fn report_top_recommendation_empty() {
    let r = BinaryIadlReport {
        iterations_run: 0,
        layers_identified: vec![],
        applied_passes: vec![],
        final_score: 0.0,
        recommendations: vec![],
        time_elapsed_ms: 0,
    };
    assert_eq!(r.top_recommendation(), None);
    assert!(!r.has_progress());
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtectionLayer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn protection_layer_all_names_nonempty() {
    let layers = vec![
        ProtectionLayer::Packer("x".into()),
        ProtectionLayer::VmObfuscation("y".into()),
        ProtectionLayer::AntiDebug(0),
        ProtectionLayer::StringEncryption,
        ProtectionLayer::CflFlattening,
        ProtectionLayer::OpaquePredicates,
        ProtectionLayer::MbaObfuscation,
    ];
    for l in &layers {
        assert!(!l.name().is_empty());
        assert!(l.removal_cost() > 0);
    }
}

#[test]
fn protection_layer_eq_serde() {
    let l = ProtectionLayer::AntiDebug(0b1111);
    let json = serde_json::to_string(&l).unwrap();
    let back: ProtectionLayer = serde_json::from_str(&json).unwrap();
    assert_eq!(l, back);
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryIadlState
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn binary_state_default_no_packer_no_entropy() {
    let s = BinaryIadlState::new(0, 0);
    assert!(!s.has_packer());
    assert!(!s.is_high_entropy("anything"));
}

// ─────────────────────────────────────────────────────────────────────────────
// NaturalnessScorer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn naturalness_scorer_clamps_to_one() {
    let ts = BinaryTentativeState {
        hypothesis_name: "UPXUnpack".into(),
        modifications: vec!["x".into()],
        estimated_naturalness: 1.0,
        estimated_complexity_reduction: 1.0,
    };
    let s = NaturalnessScorer::score(&ts);
    assert!(s <= 1.0 + 1e-9);
}

#[test]
fn naturalness_scorer_baseline_floor() {
    // 50 modifications: base would go below 0.5 but clamped to 0.5 by max().
    let ts = BinaryTentativeState {
        hypothesis_name: "X".into(),
        modifications: (0..50).map(|i| i.to_string()).collect(),
        estimated_naturalness: 0.0,
        estimated_complexity_reduction: 0.0,
    };
    let s = NaturalnessScorer::score(&ts);
    assert!(s >= 0.5 - 1e-9);
}

// ─────────────────────────────────────────────────────────────────────────────
// HypothesisRegistry
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_empty() {
    let r = HypothesisRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.ids().is_empty());
    assert!(r.all().is_empty());
}

#[test]
fn registry_all_sorted_by_id() {
    let mut r = HypothesisRegistry::new();
    r.register(Box::new(ConstantHypothesis::new("c", 0.0, 0, "")));
    r.register(Box::new(ConstantHypothesis::new("a", 0.0, 0, "")));
    r.register(Box::new(ConstantHypothesis::new("b", 0.0, 0, "")));
    let ids: Vec<&str> = r.all().iter().map(|h| h.id()).collect();
    assert_eq!(ids, vec!["a", "b", "c"]);
}

// ─────────────────────────────────────────────────────────────────────────────
// analyze_binary_for_protections edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn analyze_binary_upx_bang_marker() {
    let mut data = vec![0u8; 256];
    data[10..14].copy_from_slice(b"UPX!");
    let s = analyze_binary_for_protections(&data);
    assert!(s.high_entropy_sections.iter().any(|x| x == "UPX!"));
}

#[test]
fn analyze_binary_x64_prologue_counted() {
    let prologue: &[u8] = &[0x55, 0x48, 0x89, 0xE5];
    let mut data = vec![0u8; 256];
    data[..4].copy_from_slice(prologue);
    data[40..44].copy_from_slice(prologue);
    let s = analyze_binary_for_protections(&data);
    assert!(s.function_count >= 2);
}

#[test]
fn analyze_binary_high_entropy_window_detected() {
    // Build a 256-byte buffer with maximally diverse bytes (entropy = 8.0 > 7.0).
    let data: Vec<u8> = (0u8..=255).collect();
    let s = analyze_binary_for_protections(&data);
    assert!(
        s.high_entropy_sections.iter().any(|x| x.starts_with("window_")),
        "uniform-distribution window should be flagged"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlDeobfPass
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn iadl_deobf_pass_empty_hypotheses_returns_no_progress() {
    let pass = IadlDeobfPass::new(
        "p",
        IadlConfig {
            max_iterations: 10,
            max_no_progress: 1,
            min_improvement: 0.0,
            complexity_penalty: 0.0,
        },
    );
    let report = pass.run(0.0, 0, &[], &[]);
    assert_eq!(report.stop_reason, StopReason::NoProgress);
}

// ─────────────────────────────────────────────────────────────────────────────
// IadlError display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn iadl_error_display() {
    let e = IadlError::UnsupportedAlgorithm { name: "x".into() };
    assert!(format!("{e}").contains("unsupported"));
    let e = IadlError::NotFound;
    assert!(format!("{e}").contains("no resolution"));
    let e = IadlError::Analysis("oops".into());
    assert!(format!("{e}").contains("oops"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Send + Sync invariants
// ─────────────────────────────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn trait_objects_are_send_sync() {
    assert_send_sync::<Box<dyn Hypothesis>>();
    assert_send_sync::<Box<dyn Scorer>>();
    assert_send_sync::<Box<dyn BinaryHypothesis>>();
    assert_send_sync::<IadlDetector>();
    assert_send_sync::<HashTable>();
}

// ─────────────────────────────────────────────────────────────────────────────
// Perturbation module
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn perturbation_type_names_distinct_nonempty() {
    let kinds = [
        PerturbationType::ConstantSubstitution { constant: 0 },
        PerturbationType::NopElimination,
        PerturbationType::JunkCodeRemoval,
        PerturbationType::PatternMutation { seed: 0 },
        PerturbationType::ByteRotation { amount: 1 },
        PerturbationType::HashDerivedXor,
        PerturbationType::ByteSwap,
        PerturbationType::BitwiseComplement { region_start: 0, region_len: 0 },
    ];
    for k in kinds {
        assert!(!k.name().is_empty());
        assert!(k.aggressiveness() >= 1 && k.aggressiveness() <= 10);
    }
}

#[test]
fn pattern_mutation_not_reversible() {
    assert!(!PerturbationType::PatternMutation { seed: 1 }.is_reversible());
    assert!(!PerturbationType::JunkCodeRemoval.is_reversible());
}

#[test]
fn perturbation_display_matches_name() {
    let t = PerturbationType::HashDerivedXor;
    assert_eq!(format!("{t}"), t.name());
}

#[test]
fn apply_perturbation_empty_returns_empty() {
    let p = Perturbation::new(PerturbationType::HashDerivedXor);
    assert!(apply_perturbation(&[], &p).is_empty());
}

#[test]
fn apply_constant_substitution_xor_is_involution() {
    let p = Perturbation::new(PerturbationType::ConstantSubstitution { constant: 0xAA });
    let data = b"hello world";
    let once = apply_perturbation(data, &p);
    let twice = apply_perturbation(&once, &p);
    assert_eq!(twice, data);
}

#[test]
fn apply_byte_rotation_zero_is_identity() {
    let p = Perturbation::new(PerturbationType::ByteRotation { amount: 0 });
    let data = b"\x01\x02\x03\x04";
    assert_eq!(apply_perturbation(data, &p), data);
}

#[test]
fn perturbation_record_application_sets_fields() {
    let mut p = Perturbation::new(PerturbationType::NopElimination);
    p.record_application(7, 0.5);
    assert_eq!(p.applied_at_iteration, Some(7));
    assert_eq!(p.last_effect, Some(0.5));
}

#[test]
fn measure_effect_quality_delta_is_finite() {
    let data = b"some plain text \x00\xFF abcd";
    let p = Perturbation::new(PerturbationType::ConstantSubstitution { constant: 0x42 });
    let eff = measure_effect(data, &p);
    assert!(eff.quality_delta.is_finite());
}

#[test]
fn rank_perturbations_sorted_descending() {
    let data = b"hello world hello world hello";
    let ps = vec![
        Perturbation::new(PerturbationType::ConstantSubstitution { constant: 0x20 }),
        Perturbation::new(PerturbationType::ByteRotation { amount: 3 }),
        Perturbation::new(PerturbationType::NopElimination),
    ];
    let ranked = rank_perturbations(data, &ps);
    assert_eq!(ranked.len(), 3);
    for w in ranked.windows(2) {
        assert!(w[0].1 >= w[1].1);
    }
}

#[test]
fn perturbation_effect_is_beneficial_threshold() {
    let e = perturbation_effect_helper(0.1);
    assert!(e.is_beneficial());
    let e0 = perturbation_effect_helper(0.0);
    assert!(!e0.is_beneficial());
}

const fn perturbation_effect_helper(q: f64) -> rustre_deobf_iadl::perturbation::PerturbationEffect {
    use rustre_deobf_iadl::perturbation::PerturbationEffect;
    PerturbationEffect {
        kind: PerturbationType::NopElimination,
        bytes_changed: 0,
        entropy_before: 0.0,
        entropy_after: 0.0,
        printability_after: 0.0,
        quality_delta: q,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary orchestrator: registering custom hypothesis
// ─────────────────────────────────────────────────────────────────────────────

struct DummyBinaryHypothesis;
impl BinaryHypothesis for DummyBinaryHypothesis {
    fn id(&self) -> u64 { 0xDEAD }
    fn name(&self) -> &'static str { "Dummy" }
    fn prior(&self, _s: &BinaryIadlState) -> f64 { 0.0 }
    fn apply(&self, _s: &BinaryIadlState) -> BinaryTentativeState {
        BinaryTentativeState {
            hypothesis_name: "Dummy".into(),
            modifications: vec![],
            estimated_naturalness: 0.0,
            estimated_complexity_reduction: 0.0,
        }
    }
    fn cost_estimate(&self) -> std::time::Duration {
        std::time::Duration::from_millis(1)
    }
}

#[test]
fn binary_orchestrator_register_custom_hypothesis() {
    let mut orch = BinaryIadlOrchestrator::new();
    orch.register(Box::new(DummyBinaryHypothesis));
    // Run on tiny data: dummy has prior 0.0 (< 0.05) so it gets filtered out.
    let r = orch.run(&[0u8; 16]);
    assert!(!r.applied_passes.contains(&"Dummy".to_string()));
}
