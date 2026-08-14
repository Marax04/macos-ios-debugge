//! Deep adversarial test suite Y011 for rustre-crypto-id (lib.rs public API).

use rustre_crypto_id::{
    identify_in_binary, shannon_entropy, ActiveProbeKind, AlgorithmAssessment, AlgorithmId,
    AvalancheAnalyzer, BinaryScanner, ChaCha20Identifier, ConfidenceLevel, ConstantScanner,
    CryptoAlgorithm, CryptoConstant, CryptoFinding, CryptoHit, CryptoIdError, CryptoReport,
    CryptoScanner, EvidenceKind, FunctionScanner, IdentificationConfig, IdentificationEvidence,
    KeyCandidate, RsaDetector, SignatureDatabase, AES_INV_SBOX, AES_RCON, AES_SBOX,
    BUILTIN_TEST_VECTORS, MD5_H, SHA1_H, SHA256_H, SHA256_K, SM4_SBOX,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut g = lcg();
    (0..n).map(|_| (g() >> 24) as u8).collect()
}

// ── Constants integrity ─────────────────────────────────────────────────────

#[test]
fn const_aes_sbox_is_permutation() {
    let mut seen = [false; 256];
    for &b in &AES_SBOX {
        assert!(!seen[b as usize], "AES_SBOX duplicate {b}");
        seen[b as usize] = true;
    }
}

#[test]
fn const_aes_inv_sbox_is_inverse() {
    for i in 0u8..=255 {
        assert_eq!(AES_INV_SBOX[AES_SBOX[i as usize] as usize], i);
    }
    // saturate at 255
    let _ = AES_INV_SBOX[AES_SBOX[255] as usize];
}

#[test]
fn const_sm4_sbox_is_permutation() {
    let mut seen = [false; 256];
    for &b in &SM4_SBOX {
        assert!(!seen[b as usize]);
        seen[b as usize] = true;
    }
}

#[test]
fn const_aes_rcon_length() {
    assert_eq!(AES_RCON.len(), 11);
    assert_eq!(AES_RCON[1], 0x01);
    assert_eq!(AES_RCON[10], 0x36);
}

#[test]
fn const_md5_sha1_sha256_lengths() {
    assert_eq!(MD5_H.len(), 4);
    assert_eq!(SHA1_H.len(), 5);
    assert_eq!(SHA256_H.len(), 8);
    assert_eq!(SHA256_K.len(), 16);
}

// ── CryptoAlgorithm Display + Hash/Eq ────────────────────────────────────────

#[test]
fn algorithm_display_round_trip_uniqueness() {
    use CryptoAlgorithm::*;
    let all = [
        Md5, Sha1, Sha256, Sha512, Sha3_256, Blake2b, Aes128, Aes256, Des, TripleDes, Rc4,
        ChaCha20, Salsa20, Rsa, Ecdsa, Ed25519, X25519, Crc32, Adler32, Sm3, Sm4, Whirlpool, Tiger,
        Ripemd160,
    ];
    let names: HashSet<String> = all.iter().map(std::string::ToString::to_string).collect();
    assert_eq!(names.len(), all.len(), "Display must be unique");
    for a in all {
        assert!(!a.to_string().is_empty());
    }
}

#[test]
fn algorithm_hash_eq_consistency_pairs() {
    use std::collections::HashMap;
    use CryptoAlgorithm::*;
    let all = [
        Md5, Sha1, Sha256, Sha512, Sha3_256, Blake2b, Aes128, Aes256, Des, TripleDes, Rc4,
        ChaCha20, Salsa20, Rsa, Ecdsa, Ed25519, X25519, Crc32, Adler32, Sm3, Sm4, Whirlpool, Tiger,
        Ripemd160,
    ];
    let mut m: HashMap<CryptoAlgorithm, usize> = HashMap::new();
    for (i, a) in all.iter().enumerate() {
        m.insert(*a, i);
    }
    assert_eq!(m.len(), all.len());
    // 30+ Hash/Eq pairs
    for i in 0..all.len() {
        for j in 0..all.len() {
            let eq = all[i] == all[j];
            let same_idx = i == j;
            assert_eq!(eq, same_idx);
            if eq {
                assert_eq!(m[&all[i]], m[&all[j]]);
            }
        }
    }
}

// ── AlgorithmId Display ─────────────────────────────────────────────────────

#[test]
fn algorithm_id_display_custom_round_trip() {
    let custom = AlgorithmId::Custom("Foo123".into());
    assert_eq!(custom.to_string(), "Custom(Foo123)");
    let empty = AlgorithmId::Custom(String::new());
    assert_eq!(empty.to_string(), "Custom()");
}

#[test]
fn algorithm_id_eq_clone() {
    let a = AlgorithmId::Sha256;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(AlgorithmId::Sha256, AlgorithmId::Sha512);
}

// ── SignatureDatabase ───────────────────────────────────────────────────────

#[test]
fn database_default_eq_new_lengths() {
    let a = SignatureDatabase::new();
    let b = SignatureDatabase::default();
    assert_eq!(a.constants().len(), b.constants().len());
    assert!(a.constants().len() >= 9);
}

#[test]
fn database_add_grows() {
    let db = SignatureDatabase::new();
    let before = db.constants().len();
    db.add(CryptoConstant {
        name: "X".into(),
        algorithm: CryptoAlgorithm::Tiger,
        value: vec![1, 2, 3],
        size: 3,
    });
    assert_eq!(db.constants().len(), before + 1);
}

// ── BinaryScanner ───────────────────────────────────────────────────────────

#[test]
fn binary_scanner_empty_data_no_hits() {
    let s = BinaryScanner::new();
    assert!(s.scan(&[]).is_empty());
}

#[test]
fn binary_scanner_single_byte_data() {
    let s = BinaryScanner::new();
    assert!(s.scan(&[0u8]).is_empty());
}

#[test]
fn binary_scanner_finds_aes_at_boundary_zero() {
    let s = BinaryScanner::new();
    let mut data = AES_SBOX.to_vec();
    data.extend(vec![0u8; 16]);
    let hits = s.scan(&data);
    assert!(hits.iter().any(|h| h.algorithm == CryptoAlgorithm::Aes128 && h.offset == 0));
}

#[test]
fn binary_scanner_finds_aes_at_end_boundary() {
    let s = BinaryScanner::new();
    let mut data = vec![0u8; 32];
    data.extend_from_slice(&AES_SBOX);
    let hits = s.scan(&data);
    assert!(hits.iter().any(|h| h.algorithm == CryptoAlgorithm::Aes128 && h.offset == 32));
}

#[test]
fn binary_scanner_hits_sorted_by_offset() {
    let s = BinaryScanner::new();
    let mut data = vec![0u8; 2048];
    data[1000..1000 + 256].copy_from_slice(&AES_SBOX);
    data[100..100 + 256].copy_from_slice(&SM4_SBOX);
    let hits = s.scan(&data);
    let offs: Vec<usize> = hits.iter().map(|h| h.offset).collect();
    let mut sorted = offs.clone();
    sorted.sort_unstable();
    assert_eq!(offs, sorted);
}

#[test]
fn binary_scanner_with_database_constructor() {
    let db = SignatureDatabase::new();
    let s = BinaryScanner::with_database(db);
    let mut data = vec![0u8; 512];
    data[0..256].copy_from_slice(&AES_SBOX);
    assert!(!s.scan(&data).is_empty());
}

#[test]
fn binary_scanner_fuzz_never_panics() {
    let s = BinaryScanner::new();
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 4096) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = s.scan(&data);
    }
}

// ── CryptoScanner full_scan ─────────────────────────────────────────────────

#[test]
fn full_scan_too_short_zero() {
    let s = CryptoScanner::new();
    assert!(matches!(s.full_scan(&[]), Err(CryptoIdError::TooShort)));
}

#[test]
fn full_scan_too_short_three() {
    let s = CryptoScanner::new();
    assert!(matches!(s.full_scan(&[0u8; 3]), Err(CryptoIdError::TooShort)));
}

#[test]
fn full_scan_ok_at_four_bytes() {
    let s = CryptoScanner::new();
    assert!(s.full_scan(&[0u8; 4]).is_ok());
}

#[test]
fn full_scan_default_matches_new() {
    let a = CryptoScanner::new();
    let b = CryptoScanner::default();
    let data = vec![0u8; 64];
    let ra = a.full_scan(&data).unwrap();
    let rb = b.full_scan(&data).unwrap();
    assert_eq!(ra.algorithms_found.len(), rb.algorithms_found.len());
}

#[test]
fn full_scan_recommendations_empty_when_no_hits() {
    let s = CryptoScanner::new();
    let r = s.full_scan(&[0u8; 64]).unwrap();
    assert!(r.algorithms_found.is_empty());
    // Recommendation noting "No known crypto constants found" is expected.
    assert!(r.recommendations.iter().any(|s| s.contains("No known crypto")));
}

#[test]
fn full_scan_md5_recommendation() {
    let s = CryptoScanner::new();
    let md5_bytes: Vec<u8> = MD5_H.iter().flat_map(|&h| h.to_le_bytes()).collect();
    let mut data = vec![0u8; 128];
    data[16..16 + md5_bytes.len()].copy_from_slice(&md5_bytes);
    let r = s.full_scan(&data).unwrap();
    assert!(r.recommendations.iter().any(|s| s.contains("MD5")));
}

#[test]
fn full_scan_fuzz_never_panics() {
    let s = CryptoScanner::new();
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 2048) as usize + 4;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = s.full_scan(&data);
    }
}

// ── CryptoReport assessments / plan ─────────────────────────────────────────

#[test]
fn report_assessments_filters_below_min_confidence() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Md5,
            constant: "X".into(),
            confidence: 0.1,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let cfg = IdentificationConfig {
        min_confidence: 0.5,
        max_probes_per_algorithm: 1,
        include_key_candidates: false,
    };
    assert!(report.assessments(cfg).is_empty());
}

#[test]
fn report_assessments_high_band_above_080() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Aes128,
            constant: "AES-SBOX".into(),
            confidence: 0.95,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let a = report.assessments(IdentificationConfig::default());
    assert_eq!(a[0].level, ConfidenceLevel::High);
}

#[test]
fn report_assessments_medium_band() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Sha1,
            constant: "SHA1".into(),
            confidence: 0.60,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let a = report.assessments(IdentificationConfig::default());
    assert_eq!(a[0].level, ConfidenceLevel::Medium);
}

#[test]
fn report_active_plan_probe_kinds_match_algorithm() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Des,
            constant: "DES".into(),
            confidence: 0.9,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let plan = report.active_identification_plan(IdentificationConfig::default());
    assert!(plan.probes.iter().all(|p| p.kind == ActiveProbeKind::BlockSizeSweep));
}

#[test]
fn report_active_plan_chacha_avalanche() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::ChaCha20,
            constant: "Sig".into(),
            confidence: 0.9,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let plan = report.active_identification_plan(IdentificationConfig::default());
    assert!(plan
        .probes
        .iter()
        .any(|p| p.kind == ActiveProbeKind::KnownPlaintextAvalanche));
}

#[test]
fn report_active_plan_max_probes_respected() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Aes128,
            constant: "AES-SBOX".into(),
            confidence: 0.95,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let cfg = IdentificationConfig {
        min_confidence: 0.5,
        max_probes_per_algorithm: 1,
        include_key_candidates: false,
    };
    let plan = report.active_identification_plan(cfg);
    assert_eq!(plan.probes.len(), 1);
}

#[test]
fn report_evidence_includes_keys_when_configured() {
    let report = CryptoReport {
        algorithms_found: vec![],
        possible_keys: vec![KeyCandidate {
            offset: 0,
            length: 16,
            entropy: 0.95,
            description: "k".into(),
        }],
        recommendations: vec![],
    };
    let cfg = IdentificationConfig {
        min_confidence: 0.0,
        max_probes_per_algorithm: 1,
        include_key_candidates: true,
    };
    let e = report.evidence(cfg);
    assert!(e.iter().any(|ev| ev.kind == EvidenceKind::KeyMaterial));
}

#[test]
fn report_evidence_excludes_keys_when_disabled() {
    let report = CryptoReport {
        algorithms_found: vec![],
        possible_keys: vec![KeyCandidate {
            offset: 0,
            length: 16,
            entropy: 0.95,
            description: "k".into(),
        }],
        recommendations: vec![],
    };
    let cfg = IdentificationConfig {
        min_confidence: 0.0,
        max_probes_per_algorithm: 1,
        include_key_candidates: false,
    };
    assert!(report.evidence(cfg).is_empty());
}

#[test]
fn identification_config_default_values() {
    let c = IdentificationConfig::default();
    assert!((c.min_confidence - 0.5).abs() < 1e-6);
    assert_eq!(c.max_probes_per_algorithm, 2);
    assert!(c.include_key_candidates);
}

// ── FunctionScanner ─────────────────────────────────────────────────────────

#[test]
fn function_scanner_empty_returns_no_hits() {
    assert!(FunctionScanner::analyze(&[]).is_empty());
}

#[test]
fn function_scanner_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 1024) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = FunctionScanner::analyze(&data);
    }
}

// ── shannon_entropy ─────────────────────────────────────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn entropy_uniform_close_to_8() {
    let data: Vec<u8> = (0u8..=255).collect();
    let h = shannon_entropy(&data);
    assert!(h > 7.9);
}

#[test]
fn entropy_constant_bytes_zero() {
    assert_eq!(shannon_entropy(&vec![0x42u8; 1024]), 0.0);
}

#[test]
fn entropy_monotone_with_diversity() {
    let two: Vec<u8> = (0..256).map(|i| u8::from(i >= 128)).collect();
    let four: Vec<u8> = (0..256).map(|i| (i % 4) as u8).collect();
    assert!(shannon_entropy(&four) > shannon_entropy(&two));
}

// ── ConstantScanner ─────────────────────────────────────────────────────────

#[test]
fn constant_scanner_empty_data() {
    assert!(ConstantScanner::scan_bytes(&[]).is_empty());
}

#[test]
fn constant_scanner_short_data_no_panic() {
    for n in 0..16 {
        let _ = ConstantScanner::scan_bytes(&vec![0u8; n]);
    }
}

#[test]
fn constant_scanner_scan_for_all_includes_sigma() {
    let mut data = vec![0u8; 200];
    data[64..80].copy_from_slice(b"expand 32-byte k");
    let f = ConstantScanner::scan_for_all_constants(&data);
    assert!(f
        .iter()
        .any(|c| c.algorithm == AlgorithmId::ChaCha20 && c.offset == 64));
}

#[test]
fn constant_scanner_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 2048) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = ConstantScanner::scan_bytes(&data);
        let _ = ConstantScanner::scan_for_all_constants(&data);
    }
}

#[test]
fn constant_scanner_sorted_by_offset_then_conf_desc() {
    let mut data = vec![0u8; 1024];
    data[200..200 + 256].copy_from_slice(&AES_SBOX);
    data[10..14].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
    let f = ConstantScanner::scan_bytes(&data);
    for w in f.windows(2) {
        assert!(w[0].offset <= w[1].offset);
    }
}

// ── identify_in_binary ──────────────────────────────────────────────────────

#[test]
fn identify_empty_data() {
    assert!(identify_in_binary(&[]).is_empty());
}

#[test]
fn identify_sorted_by_confidence_desc() {
    let mut data = vec![0u8; 600];
    data[300..300 + 256].copy_from_slice(&AES_SBOX);
    data[10..14].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
    let f = identify_in_binary(&data);
    for w in f.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

#[test]
fn identify_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() % 2048) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = identify_in_binary(&data);
    }
}

// ── ChaCha20Identifier ──────────────────────────────────────────────────────

#[test]
fn chacha_detect_const_short() {
    assert!(ChaCha20Identifier::detect_chacha20_const(&[0u8; 4]).is_empty());
}

#[test]
fn chacha_detect_words_short() {
    assert!(ChaCha20Identifier::detect_chacha20_words(&[0u8; 3]).is_empty());
}

#[test]
fn chacha_detect_words_sorted() {
    let mut data = vec![0u8; 200];
    data[10..26].copy_from_slice(b"expand 32-byte k");
    data[100..116].copy_from_slice(b"expand 32-byte k");
    let hits = ChaCha20Identifier::detect_chacha20_words(&data);
    for w in hits.windows(2) {
        assert!(w[0] <= w[1]);
    }
}

#[test]
fn chacha_detect_const_multiple_positions() {
    let sigma = b"expand 32-byte k";
    let mut data = vec![0u8; 300];
    data[0..16].copy_from_slice(sigma);
    data[200..216].copy_from_slice(sigma);
    let hits = ChaCha20Identifier::detect_chacha20_const(&data);
    assert_eq!(hits, vec![0, 200]);
}

#[test]
fn chacha_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = (g() % 1024) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = ChaCha20Identifier::detect_chacha20_const(&data);
        let _ = ChaCha20Identifier::detect_chacha20_words(&data);
    }
}

// ── RsaDetector ─────────────────────────────────────────────────────────────

#[test]
fn rsa_detector_empty() {
    assert!(RsaDetector::detect_rsa_keys(&[]).is_empty());
}

#[test]
fn rsa_detector_pem_marker() {
    let mut data = vec![0u8; 100];
    let pem = b"BEGIN RSA";
    data[10..10 + pem.len()].copy_from_slice(pem);
    let hints = RsaDetector::detect_rsa_keys(&data);
    assert!(hints.iter().any(|h| h.kind == "PEM-RSA" && h.offset == 10));
}

#[test]
fn rsa_detector_der_header() {
    // 0x30 0x82 len_hi len_lo with declared_len >= 64
    let mut data = vec![0u8; 100];
    data[0] = 0x30;
    data[1] = 0x82;
    data[2] = 0x01;
    data[3] = 0x00; // 256
    let hints = RsaDetector::detect_rsa_keys(&data);
    assert!(hints.iter().any(|h| h.kind == "DER-RSA"));
}

#[test]
fn rsa_detector_fuzz_never_panics() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = (g() % 1024) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ = RsaDetector::detect_rsa_keys(&data);
    }
}

#[test]
fn rsa_detector_sorted_by_offset() {
    let mut data = vec![0u8; 200];
    let pem = b"BEGIN RSA";
    data[100..100 + pem.len()].copy_from_slice(pem);
    data[10..10 + pem.len()].copy_from_slice(pem);
    let hints = RsaDetector::detect_rsa_keys(&data);
    for w in hints.windows(2) {
        assert!(w[0].offset <= w[1].offset);
    }
}

// ── AvalancheAnalyzer ───────────────────────────────────────────────────────

#[test]
fn avalanche_zero_input_zero_score() {
    assert_eq!(AvalancheAnalyzer::analyze(<[u8]>::to_vec, 0), 0.0);
}

#[test]
fn avalanche_empty_output_zero_score() {
    assert_eq!(AvalancheAnalyzer::analyze(|_| Vec::new(), 4), 0.0);
}

#[test]
fn avalanche_identity_low_score() {
    let s = AvalancheAnalyzer::analyze(<[u8]>::to_vec, 4);
    assert!(s > 0.0 && s < 0.1);
}

// ── BUILTIN_TEST_VECTORS ────────────────────────────────────────────────────

#[test]
fn builtin_vectors_summary_nonempty() {
    assert!(BUILTIN_TEST_VECTORS.len() >= 5);
    for tv in BUILTIN_TEST_VECTORS {
        assert!(!tv.summary().is_empty());
        assert!(!tv.description.is_empty());
    }
}

// ── ConfidenceLevel via assessment ──────────────────────────────────────────

#[test]
fn confidence_level_serialization_via_assessment() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Aes128,
            constant: "x".into(),
            confidence: 0.85,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let a: Vec<AlgorithmAssessment> = report.assessments(IdentificationConfig::default());
    let json = serde_json::to_string(&a[0]).unwrap();
    let back: AlgorithmAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(back.algorithm, CryptoAlgorithm::Aes128);
    assert_eq!(back.level, ConfidenceLevel::High);
}

#[test]
fn identification_evidence_serde() {
    let e = IdentificationEvidence {
        kind: EvidenceKind::Constant,
        algorithm: Some(CryptoAlgorithm::Md5),
        offset: Some(10),
        label: "x".into(),
        confidence: 0.5,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: IdentificationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn crypto_finding_serde() {
    let f = CryptoFinding {
        offset: 7,
        algorithm: AlgorithmId::Sha256,
        evidence: "h0".into(),
        confidence: 0.8,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: CryptoFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.algorithm, f.algorithm);
}

// ── Send/Sync threaded stress ──────────────────────────────────────────────

#[test]
fn database_send_sync_threaded() {
    let db = Arc::new(SignatureDatabase::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let db = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let c = db.constants();
                assert!(!c.is_empty());
                if i % 10 == 0 {
                    db.add(CryptoConstant {
                        name: format!("T{i}"),
                        algorithm: CryptoAlgorithm::Tiger,
                        value: vec![i as u8],
                        size: 1,
                    });
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(db.constants().len() >= 9);
}

#[test]
fn scanner_threaded_scans() {
    let scanner = Arc::new(BinaryScanner::new());
    let data = Arc::new({
        let mut d = vec![0u8; 1024];
        d[100..100 + 256].copy_from_slice(&AES_SBOX);
        d
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = Arc::clone(&scanner);
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let h = s.scan(&d);
                assert!(h.iter().any(|x| x.algorithm == CryptoAlgorithm::Aes128));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── Boundary / large input ─────────────────────────────────────────────────

#[test]
fn binary_scanner_large_random_input() {
    let s = BinaryScanner::new();
    let data = random_bytes(8192);
    let _ = s.scan(&data);
}

#[test]
fn full_scan_off_by_one_at_four_three() {
    let s = CryptoScanner::new();
    assert!(s.full_scan(&[0u8; 3]).is_err());
    assert!(s.full_scan(&[0u8; 4]).is_ok());
}

#[test]
fn crypto_id_error_display_nonempty() {
    let e = CryptoIdError::TooShort;
    assert!(!e.to_string().is_empty());
    let e = CryptoIdError::Database("x".into());
    assert!(!e.to_string().is_empty());
}
