//! Blitz2 — deep adversarial tests for `rustre-deobf-iadl` public API.
//!
//! Production code in src/ is unchanged. We use a seeded LCG and deterministic
//! adversarial inputs to stress parsers, scoring, hashing, and orchestration.

use rustre_deobf_iadl::*;
use std::collections::HashSet;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Seeded LCG (no rand / no std::time)
// ─────────────────────────────────────────────────────────────────────────────

fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper hypothesis/scorer
// ─────────────────────────────────────────────────────────────────────────────

struct FixedHyp {
    id: String,
    score: f64,
    complexity: u64,
    prior: f64,
}
impl Hypothesis for FixedHyp {
    fn id(&self) -> &str {
        &self.id
    }
    fn prior(&self, _s: &IadlState) -> f64 {
        self.prior
    }
    fn apply(&self, _s: &IadlState) -> TentativeState {
        TentativeState::new(self.id.clone(), self.score, self.complexity, "fx")
    }
}

struct PassScorer;
impl Scorer for PassScorer {
    fn name(&self) -> &str {
        "pass"
    }
    fn weight(&self) -> f64 {
        1.0
    }
    fn score(&self, t: &TentativeState, _b: &IadlState) -> f64 {
        t.score
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. compute_hash determinism & properties
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t01_compute_hash_all_algos_deterministic() {
    let inputs: &[&[u8]] = &[b"", b"a", b"LoadLibraryA", b"GetProcAddress", b"\x00\x01\xff"];
    for algo in [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
        HashAlgorithm::Unknown,
    ] {
        for inp in inputs {
            let a = compute_hash(inp, algo);
            let b = compute_hash(inp, algo);
            assert_eq!(a, b, "non-deterministic {:?}", algo);
        }
    }
}

#[test]
fn t02_compute_hash_unknown_always_zero() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 64) as usize;
        let v: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        assert_eq!(compute_hash(&v, HashAlgorithm::Unknown), 0);
    }
}

#[test]
fn t03_compute_hash_djb2_known_vector() {
    // djb2("") = 5381
    assert_eq!(compute_hash(b"", HashAlgorithm::Djb2), 5381);
}

#[test]
fn t04_compute_hash_empty_inputs_all_algos() {
    // Empty input must not panic on any algorithm.
    for algo in [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
    ] {
        let _ = compute_hash(b"", algo);
    }
}

#[test]
fn t05_compute_hash_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..200 {
        let n = (g() % 257) as usize;
        let v: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        for algo in [
            HashAlgorithm::Djb2,
            HashAlgorithm::Fnv1a32,
            HashAlgorithm::Sdbm,
            HashAlgorithm::Crc32,
            HashAlgorithm::Adler32,
            HashAlgorithm::RorHash,
        ] {
            let _ = compute_hash(&v, algo);
        }
    }
}

#[test]
fn t06_hash_algorithm_is_known_excludes_unknown() {
    for algo in [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
    ] {
        assert!(algo.is_known());
    }
    assert!(!HashAlgorithm::Unknown.is_known());
}

#[test]
fn t07_hash_algorithm_eq_hash_consistency() {
    use std::collections::HashMap;
    let mut m: HashMap<HashAlgorithm, u32> = HashMap::new();
    let algos = [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
        HashAlgorithm::Unknown,
    ];
    for (i, a) in algos.iter().enumerate() {
        m.insert(*a, i as u32);
    }
    assert_eq!(m.len(), algos.len());
    for (i, a) in algos.iter().enumerate() {
        assert_eq!(m[a], i as u32);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HashTable round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t08_hashtable_roundtrip_50_inputs() {
    let mut g = make_lcg();
    let mut names = Vec::new();
    for i in 0..50 {
        names.push(format!("Api_{i}_{:x}", g() & 0xffff));
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let table = HashTable::build(&refs, HashAlgorithm::Djb2);
    // We may have collisions; just ensure at least one entry per insert resolved.
    assert!(table.len() >= 1);
    for n in &names {
        let h = compute_hash(n.as_bytes(), HashAlgorithm::Djb2);
        assert!(table.resolve(h).is_some());
    }
}

#[test]
fn t09_hashtable_entries_complete() {
    let names = ["A", "B", "C"];
    let table = HashTable::build(&names, HashAlgorithm::Fnv1a32);
    let entries = table.entries();
    let names_set: HashSet<&str> = entries.iter().map(|(_, n)| *n).collect();
    assert!(names_set.contains("A"));
    assert!(names_set.contains("B"));
    assert!(names_set.contains("C"));
}

#[test]
fn t10_hashtable_default_unknown_algo() {
    let t = HashTable::default();
    assert!(t.is_empty());
    assert_eq!(t.algorithm, HashAlgorithm::Unknown);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ApiHash / ApiResolution
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t11_apihash_builders() {
    let a = ApiHash::new(0x42, HashAlgorithm::Crc32, 0x100);
    assert!(!a.is_resolved());
    assert!(!a.is_fully_resolved());
    let b = a.clone().with_name("X");
    assert!(b.is_resolved());
    assert!(!b.is_fully_resolved());
    let c = b.with_dll("kernel32.dll");
    assert!(c.is_fully_resolved());
}

#[test]
fn t12_apiresolution_confidence_clamped() {
    let h = ApiHash::new(0, HashAlgorithm::Crc32, 0);
    let r = ApiResolution::new(h, 0).with_confidence(500);
    assert_eq!(r.confidence, 100);
    assert!(r.is_high_confidence());
}

#[test]
fn t13_apiresolution_low_confidence() {
    let h = ApiHash::new(0, HashAlgorithm::Crc32, 0);
    let r = ApiResolution::new(h, 0).with_confidence(74);
    assert!(!r.is_high_confidence());
}

#[test]
fn t14_apiresolution_with_address() {
    let h = ApiHash::new(0, HashAlgorithm::Crc32, 0);
    let r = ApiResolution::new(h, 0x1000).with_address(0x2000);
    assert_eq!(r.resolved_address, Some(0x2000));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. IadlDetector — fuzz / boundaries
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t15_detector_scan_empty_no_panic() {
    let det = IadlDetector::new();
    assert!(det.scan_hash_constants(&[]).is_empty());
    assert!(det.scan_hash_constants(&[1, 2, 3]).is_empty()); // < 4 bytes
}

#[test]
fn t16_detector_loadlib_empty() {
    let det = IadlDetector::new();
    assert!(det.detect_loadlib_pattern(&[]).is_empty());
}

#[test]
fn t17_detector_loadlib_dedups() {
    let det = IadlDetector::new();
    // Three patterns at one offset - none possible, but adjacent matches should dedup.
    let data = vec![0xFF, 0xD0, 0xFF, 0xD0];
    let offs = det.detect_loadlib_pattern(&data);
    // Should find offset 0 and 2; sorted, unique.
    assert_eq!(offs, vec![0, 2]);
}

#[test]
fn t18_detector_fuzz_no_panic() {
    let mut g = make_lcg();
    let det = IadlDetector::new();
    for _ in 0..30 {
        let n = (g() % 1024) as usize;
        let v: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let _ = det.scan_hash_constants(&v);
        let _ = det.detect_loadlib_pattern(&v);
        let _ = det.analyze(&v, 0x400000);
    }
}

#[test]
fn t19_detector_analyze_scan_disabled() {
    let mut det = IadlDetector::new();
    det.scan_hashes = false;
    let data = vec![0xF0u8; 64];
    assert!(det.analyze(&data, 0).is_empty());
}

#[test]
fn t20_detector_identify_unknown_when_no_match() {
    let det = IadlDetector::new();
    let hashes = vec![0xDEAD_BEEFu64, 0xFEED_FACE];
    let (algo, n) = det.identify_algorithm(&hashes);
    assert_eq!(algo, HashAlgorithm::Unknown);
    assert_eq!(n, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ChainStep / LoadLibraryChain
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t21_chain_step_eq_hash() {
    let a = ChainStep::new(0x100, "LoadLibraryA").with_argument("kernel32.dll");
    let b = ChainStep::new(0x100, "LoadLibraryA").with_argument("kernel32.dll");
    assert_eq!(a, b);
}

#[test]
fn t22_chain_incomplete_missing_loadlib() {
    let mut c = LoadLibraryChain::new();
    c.push(ChainStep::new(0x200, "GetProcAddress"));
    assert!(!c.is_complete());
    assert_eq!(c.len(), 1);
    assert!(!c.is_empty());
}

#[test]
fn t23_chain_empty() {
    let c = LoadLibraryChain::new();
    assert!(c.is_empty());
    assert!(!c.is_complete());
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ProtectionLayer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t24_protection_layer_all_names_nonempty() {
    let layers = [
        ProtectionLayer::Packer("X".into()),
        ProtectionLayer::VmObfuscation("V".into()),
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
fn t25_protection_layer_serde_roundtrip() {
    let l = ProtectionLayer::Packer("UPX".into());
    let j = serde_json::to_string(&l).unwrap();
    let back: ProtectionLayer = serde_json::from_str(&j).unwrap();
    assert_eq!(l, back);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. BinaryIadlState / BinaryTentativeState
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t26_binary_tentative_combined_clamped() {
    // Values exceeding 1 should clamp.
    let ts = BinaryTentativeState {
        hypothesis_name: "X".into(),
        modifications: vec![],
        estimated_naturalness: 5.0,
        estimated_complexity_reduction: 5.0,
    };
    assert!(ts.combined_score() <= 1.0);
    assert!(ts.combined_score() >= 0.0);
}

#[test]
fn t27_binary_state_no_packer_initially() {
    let s = BinaryIadlState::new(0, 0);
    assert!(!s.has_packer());
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. analyze_binary_for_protections — boundaries / fuzz
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t28_analyze_zero_one_byte() {
    let s0 = analyze_binary_for_protections(&[]);
    assert_eq!(s0.binary_size, 0);
    let s1 = analyze_binary_for_protections(&[0x90]);
    assert_eq!(s1.binary_size, 1);
}

#[test]
fn t29_analyze_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..20 {
        let n = (g() % 4096) as usize;
        let v: Vec<u8> = (0..n).map(|_| (g() & 0xff) as u8).collect();
        let st = analyze_binary_for_protections(&v);
        assert_eq!(st.binary_size, v.len());
    }
}

#[test]
fn t30_analyze_detects_all_upx_markers() {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"UPX0");
    data[8..12].copy_from_slice(b"UPX1");
    data[16..20].copy_from_slice(b"UPX!");
    let s = analyze_binary_for_protections(&data);
    assert!(s.high_entropy_sections.iter().any(|s| s == "UPX0"));
    assert!(s.high_entropy_sections.iter().any(|s| s == "UPX1"));
    assert!(s.high_entropy_sections.iter().any(|s| s == "UPX!"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. IadlOrchestrator — boundaries
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t31_orchestrator_zero_iterations() {
    let o = IadlOrchestrator::new(IadlConfig {
        max_iterations: 0,
        max_no_progress: 1,
        min_improvement: 0.0,
        complexity_penalty: 0.0,
    });
    let report = o.run(IadlState::new(0.0, 0), &[], &[]);
    assert_eq!(report.iterations.len(), 0);
    assert_eq!(report.stop_reason, StopReason::IterationBudget);
}

#[test]
fn t32_orchestrator_deterministic_50_runs() {
    let cfg = IadlConfig {
        max_iterations: 5,
        max_no_progress: 100,
        min_improvement: 0.0,
        complexity_penalty: 0.0,
    };
    let mut last: Option<f64> = None;
    for _ in 0..50 {
        let o = IadlOrchestrator::new(cfg);
        let hyps: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHyp {
            id: "x".into(),
            score: 0.7,
            complexity: 10,
            prior: 1.0,
        })];
        let scs: Vec<Box<dyn Scorer>> = vec![Box::new(PassScorer)];
        let r = o.run(IadlState::new(0.0, 0), &hyps, &scs);
        if let Some(v) = last {
            assert!((v - r.final_state.global_score).abs() < 1e-12);
        }
        last = Some(r.final_state.global_score);
    }
}

#[test]
fn t33_orchestrator_complexity_penalty_caps_at_zero() {
    let o = IadlOrchestrator::new(IadlConfig {
        max_iterations: 1,
        max_no_progress: 1,
        min_improvement: 0.0,
        complexity_penalty: 1e9, // huge penalty
    });
    let hyps: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHyp {
        id: "h".into(),
        score: 1.0,
        complexity: 1000,
        prior: 1.0,
    })];
    let scs: Vec<Box<dyn Scorer>> = vec![Box::new(PassScorer)];
    let evs = o.evaluate_all(&IadlState::new(0.0, 0), &hyps, &scs);
    // final_score is clamped to >= 0.0
    assert!(evs[0].final_score >= 0.0);
}

#[test]
fn t34_orchestrator_tiebreak_stable_id_order() {
    let o = IadlOrchestrator::new(IadlConfig::default());
    let mut hyps: Vec<Box<dyn Hypothesis>> = Vec::new();
    for i in 0..10 {
        hyps.push(Box::new(FixedHyp {
            id: format!("h{:02}", 9 - i),
            score: 0.5,
            complexity: 10,
            prior: 1.0,
        }));
    }
    let scs: Vec<Box<dyn Scorer>> = vec![Box::new(PassScorer)];
    let evs = o.evaluate_all(&IadlState::new(0.0, 0), &hyps, &scs);
    // Same score+complexity → sorted by id ascending.
    let ids: Vec<String> = evs.iter().map(|e| e.candidate.hypothesis_id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. ConstantHypothesis / IncrementalHypothesis
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t35_constant_hypothesis_prior_clamped() {
    let h = ConstantHypothesis::new("c", 0.5, 10, "r").with_prior(99.0);
    assert!(h.prior(&IadlState::new(0.0, 0)) <= 1.0);
    let h2 = ConstantHypothesis::new("c", 0.5, 10, "r").with_prior(-2.0);
    assert!(h2.prior(&IadlState::new(0.0, 0)) >= 0.0);
}

#[test]
fn t36_incremental_hypothesis_zero_factor_safe() {
    let h = IncrementalHypothesis::new("i", 0.0);
    let s = IadlState::new(0.5, 100);
    let t = h.apply(&s);
    // No-op path: returns baseline values.
    assert_eq!(t.complexity, 100);
    assert!((t.score - 0.5).abs() < 1e-9);
}

#[test]
fn t37_incremental_hypothesis_score_capped_at_one() {
    let h = IncrementalHypothesis::new("i", 1000.0);
    let s = IadlState::new(0.5, 100);
    let t = h.apply(&s);
    assert!(t.score <= 1.0);
}

#[test]
fn t38_incremental_hypothesis_negative_factor_no_panic() {
    // Negative factor: 1/factor is finite, raw < 0 → u64::MAX guard.
    let h = IncrementalHypothesis::new("i", -2.0);
    let s = IadlState::new(0.5, 100);
    let t = h.apply(&s);
    // raw = 100 * -0.5 = -50.0, not >= 0.0 → u64::MAX
    assert_eq!(t.complexity, u64::MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Scorers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t39_complexity_scorer_zero_baseline_returns_half() {
    let sc = ComplexityScorer::new(1.0);
    let b = IadlState::new(0.0, 0);
    let t = TentativeState::new("x", 0.5, 100, "");
    assert!((sc.score(&t, &b) - 0.5).abs() < 1e-9);
}

#[test]
fn t40_complexity_scorer_weight_clamped() {
    let sc = ComplexityScorer::new(99.0);
    assert!(sc.weight() <= 1.0);
    let sc2 = ComplexityScorer::new(-3.0);
    assert!(sc2.weight() >= 0.0);
}

#[test]
fn t41_improvement_scorer_weight_clamped() {
    let sc = ImprovementScorer::new(99.0);
    assert!(sc.weight() <= 1.0);
}

#[test]
fn t42_complexity_scorer_higher_than_baseline_zero() {
    let sc = ComplexityScorer::new(1.0);
    let b = IadlState::new(0.0, 100);
    let t = TentativeState::new("x", 0.0, 500, "");
    let s = sc.score(&t, &b);
    assert!((s).abs() < 1e-9);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. HypothesisRegistry
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t43_registry_empty() {
    let r = HypothesisRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.ids().is_empty());
    assert!(r.all().is_empty());
}

#[test]
fn t44_registry_all_sorted() {
    let mut r = HypothesisRegistry::new();
    for id in ["c", "a", "b"] {
        r.register(Box::new(ConstantHypothesis::new(id, 0.5, 10, "")));
    }
    let all = r.all();
    let ids: Vec<String> = all.iter().map(|h| h.id().to_owned()).collect();
    assert_eq!(ids, vec!["a".to_string(), "b".into(), "c".into()]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. ResolutionStats
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t45_resolution_stats_all_resolved() {
    let h = ApiHash::new(1, HashAlgorithm::Djb2, 0).with_name("X");
    let rs = vec![ApiResolution::new(h, 0)];
    let st = ResolutionStats::from_resolutions(&rs);
    assert!((st.resolution_rate - 100.0).abs() < 1e-6);
    assert!(st.is_good_coverage());
}

#[test]
fn t46_resolution_stats_none_resolved() {
    let h = ApiHash::new(1, HashAlgorithm::Djb2, 0);
    let rs = vec![ApiResolution::new(h, 0)];
    let st = ResolutionStats::from_resolutions(&rs);
    assert!((st.resolution_rate).abs() < 1e-9);
    assert!(!st.is_good_coverage());
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. BinaryIadlReport — JSON round-trip / serde
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t47_binary_report_json_roundtrip() {
    let r = BinaryIadlReport {
        iterations_run: 3,
        layers_identified: vec![ProtectionLayer::Packer("UPX".into())],
        applied_passes: vec!["UPXUnpack".into()],
        final_score: 0.5,
        recommendations: vec!["x".into()],
        time_elapsed_ms: 10,
    };
    let j = r.to_json().unwrap();
    let back = BinaryIadlReport::from_json(&j).unwrap();
    assert_eq!(back.iterations_run, 3);
    assert_eq!(back.applied_passes, vec!["UPXUnpack".to_string()]);
}

#[test]
fn t48_binary_report_from_json_malformed_errors() {
    assert!(BinaryIadlReport::from_json("not json").is_err());
    assert!(BinaryIadlReport::from_json("{}").is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Send+Sync threaded stress on documented Send+Sync impls
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t49_orchestrator_threaded_stress() {
    let cfg = IadlConfig {
        max_iterations: 4,
        max_no_progress: 100,
        min_improvement: 0.0,
        complexity_penalty: 0.0,
    };
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cfg = cfg;
        handles.push(std::thread::spawn(move || {
            let o = IadlOrchestrator::new(cfg);
            for _ in 0..100 {
                let hyps: Vec<Box<dyn Hypothesis>> = vec![Box::new(FixedHyp {
                    id: "h".into(),
                    score: 0.6,
                    complexity: 10,
                    prior: 1.0,
                })];
                let scs: Vec<Box<dyn Scorer>> = vec![Box::new(PassScorer)];
                let r = o.run(IadlState::new(0.0, 0), &hyps, &scs);
                assert!(r.final_state.global_score > 0.0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t50_binary_orchestrator_threaded_stress() {
    // BinaryIadlOrchestrator::new is Send. Each thread builds its own.
    let data: Arc<Vec<u8>> = Arc::new({
        let mut d = vec![0u8; 1024];
        d[..4].copy_from_slice(b"UPX0");
        d
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let data = Arc::clone(&data);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let mut orch = BinaryIadlOrchestrator::new();
                let r = orch.run(&data);
                assert!(r.iterations_run > 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. ScorerContribution / CandidateEvaluation Eq
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t51_scorer_contribution_eq() {
    let a = ScorerContribution {
        name: "x".into(),
        weight: 0.5,
        score: 0.7,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn t52_iadl_error_display() {
    let e = IadlError::UnsupportedAlgorithm { name: "X".into() };
    assert!(format!("{e}").contains("X"));
    let e2 = IadlError::NotFound;
    assert!(!format!("{e2}").is_empty());
    let e3 = IadlError::Analysis("err".into());
    assert!(format!("{e3}").contains("err"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. Hash/Eq consistency on 30+ ApiHash pairs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t53_hashalgo_eq_hash_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let algos = [
        HashAlgorithm::Djb2,
        HashAlgorithm::Fnv1a32,
        HashAlgorithm::Sdbm,
        HashAlgorithm::Crc32,
        HashAlgorithm::Adler32,
        HashAlgorithm::RorHash,
        HashAlgorithm::Unknown,
    ];
    // 7*7=49 ordered pairs > 30.
    let mut count = 0;
    for a in &algos {
        for b in &algos {
            count += 1;
            let mut ha = DefaultHasher::new();
            a.hash(&mut ha);
            let mut hb = DefaultHasher::new();
            b.hash(&mut hb);
            if a == b {
                assert_eq!(ha.finish(), hb.finish());
            }
            // ApiHash equality across-constructed must still hold.
            let x = ApiHash::new(0x100, *a, 0);
            let y = ApiHash::new(0x100, *a, 0);
            assert_eq!(x, y);
        }
    }
    assert!(count >= 30);
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. Full detector pipeline correctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn t54_detector_analyze_returns_resolutions_when_enough_hashes() {
    let det = IadlDetector {
        min_hash_refs: 1,
        scan_hashes: true,
        scan_loadlib: true,
    };
    // Pack a known CRC32 hash for "LoadLibraryA" so we get a name resolution.
    let h = compute_hash(b"LoadLibraryA", HashAlgorithm::Crc32) as u32;
    let mut data = Vec::new();
    data.extend_from_slice(&h.to_le_bytes());
    // Add a few more 4-byte high-popcount words so identify picks CRC32.
    for name in ["GetProcAddress", "VirtualAlloc", "VirtualProtect"] {
        let h = compute_hash(name.as_bytes(), HashAlgorithm::Crc32) as u32;
        data.extend_from_slice(&h.to_le_bytes());
    }
    let res = det.analyze(&data, 0x400000);
    assert!(!res.is_empty());
}
