//! Exhaustive blitz tests for `rustre-crypto-id` public surface.
//!
//! Focus: edge-cases, invariants, round-trips, parser adversarial inputs,
//! and validation of public constant tables against canonical values.

use rustre_crypto_id::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Recompute the canonical CRC-32 IEEE/PKZIP table.
fn canonical_crc32_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB8_8320;
    let mut t = [0u32; 256];
    for i in 0u32..256 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
        }
        t[i as usize] = c;
    }
    t
}

// ── Public constant tables: canonical correctness ────────────────────────────

#[test]
fn aes_sbox_is_a_permutation() {
    let mut seen = [false; 256];
    for &b in &AES_SBOX {
        assert!(!seen[b as usize], "AES_SBOX duplicate byte 0x{b:02x}");
        seen[b as usize] = true;
    }
}

#[test]
fn aes_inv_sbox_is_inverse_of_sbox() {
    for i in 0u8..=255 {
        let fwd = AES_SBOX[i as usize];
        let back = AES_INV_SBOX[fwd as usize];
        assert_eq!(back, i, "inverse S-box mismatch at {i}");
    }
}

#[test]
fn aes_sbox_v2_equals_aes_sbox() {
    assert_eq!(AES_SBOX, AES_SBOX_V2);
}

#[test]
fn aes_inv_sbox_v2_equals_aes_inv_sbox() {
    assert_eq!(AES_INV_SBOX, AES_INV_SBOX_V2);
}

#[test]
fn sm4_sbox_is_a_permutation() {
    let mut seen = [false; 256];
    for &b in &SM4_SBOX {
        assert!(!seen[b as usize], "SM4_SBOX duplicate byte 0x{b:02x}");
        seen[b as usize] = true;
    }
}

#[test]
fn aes_rcon_known_values() {
    // AES Rcon table (index 0 is padding 0x8d, then powers of x in GF(2^8)).
    assert_eq!(
        AES_RCON,
        [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    );
}

#[test]
fn crc32_table_matches_canonical_construction() {
    let canon = canonical_crc32_table();
    // CRC32_TABLE is the public const exposed by the crate.
    for i in 0..256 {
        assert_eq!(
            CRC32_TABLE[i], canon[i],
            "CRC32_TABLE entry {i} mismatch: got 0x{:08x}, expected 0x{:08x}",
            CRC32_TABLE[i], canon[i]
        );
    }
}

#[test]
fn crc32_table_first_and_last_entries() {
    // table[0] is always 0, table[1] = 0x77073096 for the IEEE polynomial.
    assert_eq!(CRC32_TABLE[0], 0);
    assert_eq!(CRC32_TABLE[1], 0x7707_3096);
    // Standard last entry.
    assert_eq!(CRC32_TABLE[255], 0x2D02_EF8D);
}

#[test]
fn crc32_table_no_duplicates_beyond_zero() {
    // The canonical CRC32/IEEE table has 256 distinct entries.
    use std::collections::HashSet;
    let canon = canonical_crc32_table();
    let canon_set: HashSet<u32> = canon.iter().copied().collect();
    assert_eq!(canon_set.len(), 256, "canonical sanity check");

    let actual_set: HashSet<u32> = CRC32_TABLE.iter().copied().collect();
    assert_eq!(
        actual_set.len(),
        256,
        "CRC32_TABLE must contain 256 distinct entries"
    );
}

#[test]
fn crc32_poly_constant_matches() {
    // The reversed CRC32 polynomial used everywhere.
    assert_eq!(CRC32_POLY, 0xEDB8_8320);
}

#[test]
fn sha256_h_values() {
    // FIPS 180-4 §5.3.3 — fractional parts of sqrt of first 8 primes.
    assert_eq!(SHA256_H[0], 0x6a09_e667);
    assert_eq!(SHA256_H[7], 0x5be0_cd19);
    assert_eq!(SHA256_H.len(), 8);
}

#[test]
fn sha256_k_first_16_match() {
    // Cross-check the 16-entry slice against the full SHA256_K_V2.
    for i in 0..16 {
        assert_eq!(SHA256_K[i], SHA256_K_V2[i]);
    }
    assert_eq!(SHA256_K_V2.len(), 64);
    assert_eq!(SHA256_K_V2[63], 0xc671_78f2);
}

#[test]
fn md5_h_values() {
    assert_eq!(MD5_H, [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476]);
}

#[test]
fn md5_t_first_and_last() {
    // RFC 1321 — T[i] = floor(2^32 * |sin(i+1)|).
    assert_eq!(MD5_T[0], 0xd76a_a478);
    assert_eq!(MD5_T[63], 0xeb86_d391);
}

#[test]
fn sha1_h_values() {
    assert_eq!(SHA1_H.len(), 5);
    assert_eq!(SHA1_H[4], 0xC3D2_E1F0);
}

#[test]
fn chacha20_magic_constants() {
    assert_eq!(&CHACHA20_MAGIC, b"expand 32-byte k");
    assert_eq!(&CHACHA20_MAGIC_16, b"expand 16-byte k");
}

// ── CryptoAlgorithm: Display / Eq / Hash ─────────────────────────────────────

#[test]
fn crypto_algorithm_display_covers_all_variants() {
    use std::collections::HashSet;
    let all = [
        CryptoAlgorithm::Md5,
        CryptoAlgorithm::Sha1,
        CryptoAlgorithm::Sha256,
        CryptoAlgorithm::Sha512,
        CryptoAlgorithm::Sha3_256,
        CryptoAlgorithm::Blake2b,
        CryptoAlgorithm::Aes128,
        CryptoAlgorithm::Aes256,
        CryptoAlgorithm::Des,
        CryptoAlgorithm::TripleDes,
        CryptoAlgorithm::Rc4,
        CryptoAlgorithm::ChaCha20,
        CryptoAlgorithm::Salsa20,
        CryptoAlgorithm::Rsa,
        CryptoAlgorithm::Ecdsa,
        CryptoAlgorithm::Ed25519,
        CryptoAlgorithm::X25519,
        CryptoAlgorithm::Crc32,
        CryptoAlgorithm::Adler32,
        CryptoAlgorithm::Sm3,
        CryptoAlgorithm::Sm4,
        CryptoAlgorithm::Whirlpool,
        CryptoAlgorithm::Tiger,
        CryptoAlgorithm::Ripemd160,
    ];
    // Display strings must be unique.
    let names: HashSet<String> = all.iter().map(std::string::ToString::to_string).collect();
    assert_eq!(names.len(), all.len(), "Display strings must be unique");
    // No empty.
    for a in &all {
        assert!(!a.to_string().is_empty());
    }
}

#[test]
fn crypto_algorithm_serde_roundtrip() {
    let a = CryptoAlgorithm::ChaCha20;
    let j = serde_json::to_string(&a).unwrap();
    let back: CryptoAlgorithm = serde_json::from_str(&j).unwrap();
    assert_eq!(a, back);
}

#[test]
fn algorithm_id_serde_roundtrip_custom() {
    let a = AlgorithmId::Custom("XXTEA".into());
    let j = serde_json::to_string(&a).unwrap();
    let back: AlgorithmId = serde_json::from_str(&j).unwrap();
    assert_eq!(a, back);
}

// ── SignatureDatabase ────────────────────────────────────────────────────────

#[test]
fn signature_database_default_eq_new() {
    let a = SignatureDatabase::default();
    let b = SignatureDatabase::new();
    assert_eq!(a.constants().len(), b.constants().len());
}

#[test]
fn signature_database_add_grows_count() {
    let db = SignatureDatabase::new();
    let before = db.constants().len();
    db.add(CryptoConstant {
        name: "TEST-CONST".into(),
        algorithm: CryptoAlgorithm::Tiger,
        value: vec![1, 2, 3, 4],
        size: 4,
    });
    let after = db.constants().len();
    assert_eq!(after, before + 1);
}

#[test]
fn signature_database_concurrent_add_reads() {
    use std::sync::Arc;
    use std::thread;
    let db = Arc::new(SignatureDatabase::new());
    let mut handles = vec![];
    for i in 0..8 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            dbc.add(CryptoConstant {
                name: format!("CONC-{i}"),
                algorithm: CryptoAlgorithm::Whirlpool,
                value: vec![i as u8; 8],
                size: 8,
            });
            // Read back.
            let _ = dbc.constants().len();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let names: Vec<String> = db.constants().iter().map(|c| c.name.clone()).collect();
    for i in 0..8 {
        assert!(names.iter().any(|n| n == &format!("CONC-{i}")));
    }
}

// ── BinaryScanner ────────────────────────────────────────────────────────────

#[test]
fn binary_scanner_empty_input() {
    let s = BinaryScanner::new();
    let hits = s.scan(&[]);
    assert!(hits.is_empty());
}

#[test]
fn binary_scanner_one_byte() {
    let s = BinaryScanner::new();
    let hits = s.scan(&[0xff]);
    assert!(hits.is_empty());
}

#[test]
fn binary_scanner_with_database_preserves_constants() {
    let db = SignatureDatabase::new();
    db.add(CryptoConstant {
        name: "CUSTOM".into(),
        algorithm: CryptoAlgorithm::Tiger,
        value: vec![0xCA, 0xFE, 0xBA, 0xBE],
        size: 4,
    });
    let s = BinaryScanner::with_database(db);
    let mut data = vec![0u8; 16];
    data[8..12].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    let hits = s.scan(&data);
    assert!(hits.iter().any(|h| h.constant == "CUSTOM" && h.offset == 8));
}

#[test]
fn binary_scanner_results_sorted_by_offset() {
    let s = BinaryScanner::new();
    let mut data = vec![0u8; 1024];
    data[500..500 + AES_SBOX.len()].copy_from_slice(&AES_SBOX);
    data[10..14].copy_from_slice(&0x6745_2301u32.to_le_bytes());
    let hits = s.scan(&data);
    for w in hits.windows(2) {
        assert!(w[0].offset <= w[1].offset);
    }
}

// ── CryptoScanner ────────────────────────────────────────────────────────────

#[test]
fn crypto_scanner_too_short_error() {
    let s = CryptoScanner::new();
    let err = s.full_scan(&[1, 2, 3]).unwrap_err();
    assert!(matches!(err, CryptoIdError::TooShort));
}

#[test]
fn crypto_scanner_too_short_zero() {
    let s = CryptoScanner::new();
    assert!(matches!(s.full_scan(&[]).unwrap_err(), CryptoIdError::TooShort));
}

#[test]
fn crypto_scanner_boundary_4_bytes_ok() {
    // 4 bytes is the minimum accepted length.
    let s = CryptoScanner::new();
    let r = s.full_scan(&[0u8; 4]);
    assert!(r.is_ok());
}

#[test]
fn crypto_scanner_recommendations_for_md5() {
    let s = CryptoScanner::new();
    let md5_bytes: Vec<u8> = MD5_H.iter().flat_map(|h| h.to_le_bytes()).collect();
    let mut data = vec![0u8; 256];
    data[16..16 + md5_bytes.len()].copy_from_slice(&md5_bytes);
    let report = s.full_scan(&data).unwrap();
    assert!(
        report
            .recommendations
            .iter()
            .any(|r| r.contains("MD5")),
        "MD5 should be flagged in recommendations"
    );
}

#[test]
fn crypto_scanner_recommendation_when_nothing_found() {
    let s = CryptoScanner::new();
    let r = s.full_scan(&[0u8; 64]).unwrap();
    assert!(r.recommendations.iter().any(|x| x.contains("obfuscated")));
}

// ── shannon_entropy ──────────────────────────────────────────────────────────

#[test]
fn shannon_entropy_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn shannon_entropy_single_byte() {
    assert_eq!(shannon_entropy(&[0x55]), 0.0);
}

#[test]
fn shannon_entropy_uniform_full_alphabet() {
    let d: Vec<u8> = (0u8..=255).collect();
    let h = shannon_entropy(&d);
    assert!((h - 8.0).abs() < 1e-4);
}

#[test]
fn shannon_entropy_binary_half_half() {
    let mut d = vec![0u8; 128];
    d.extend(vec![1u8; 128]);
    let h = shannon_entropy(&d);
    assert!((h - 1.0).abs() < 1e-4);
}

// ── identify_in_binary ───────────────────────────────────────────────────────

#[test]
fn identify_in_binary_empty() {
    assert!(identify_in_binary(&[]).is_empty());
}

#[test]
fn identify_in_binary_finds_aes_full_sbox() {
    let mut d = vec![0u8; 512];
    d[100..100 + 256].copy_from_slice(&AES_SBOX);
    let f = identify_in_binary(&d);
    assert!(f.iter().any(|h| h.algorithm == AlgorithmId::Aes128));
}

#[test]
fn identify_in_binary_sorted_descending_confidence() {
    let mut d = vec![0u8; 600];
    d[0..256].copy_from_slice(&AES_SBOX);
    d[300..304].copy_from_slice(&0x6a09_e667u32.to_be_bytes());
    let f = identify_in_binary(&d);
    for w in f.windows(2) {
        assert!(w[0].confidence >= w[1].confidence);
    }
}

// ── ConstantScanner ──────────────────────────────────────────────────────────

#[test]
fn constant_scanner_short_data_safe() {
    // Must not panic with very short inputs.
    let _ = ConstantScanner::scan_bytes(&[]);
    let _ = ConstantScanner::scan_bytes(&[0]);
    let _ = ConstantScanner::scan_bytes(&[0; 3]);
}

#[test]
fn constant_scanner_chacha_sigma_max_confidence() {
    let mut d = vec![0u8; 64];
    d[16..32].copy_from_slice(b"expand 32-byte k");
    let f = ConstantScanner::scan_bytes(&d);
    let hit = f.iter().find(|h| h.constant_name == "CHACHA20-SIGMA").unwrap();
    assert!(hit.confidence >= 0.99);
}

// ── ChaCha20Identifier ───────────────────────────────────────────────────────

#[test]
fn chacha20_identifier_empty_input() {
    assert!(ChaCha20Identifier::detect_chacha20_const(&[]).is_empty());
    assert!(ChaCha20Identifier::detect_chacha20_words(&[]).is_empty());
}

#[test]
fn chacha20_identifier_single_byte_input() {
    assert!(ChaCha20Identifier::detect_chacha20_const(&[0x65]).is_empty());
    assert!(ChaCha20Identifier::detect_chacha20_words(&[0x65]).is_empty());
}

#[test]
fn chacha20_identifier_const_overlapping_search() {
    let sigma = b"expand 32-byte k";
    let mut d = Vec::new();
    d.extend_from_slice(sigma);
    d.extend_from_slice(sigma);
    let offs = ChaCha20Identifier::detect_chacha20_const(&d);
    assert_eq!(offs, vec![0, 16]);
}

#[test]
fn chacha20_identifier_words_all_four_in_full_sigma() {
    let mut d = vec![0u8; 32];
    d[8..24].copy_from_slice(b"expand 32-byte k");
    let hits = ChaCha20Identifier::detect_chacha20_words(&d);
    // Word indices 0..4 each at offsets 8,12,16,20.
    for wi in 0..4usize {
        assert!(hits.iter().any(|&(off, w)| w == wi && off == 8 + wi * 4));
    }
}

// ── RsaDetector ──────────────────────────────────────────────────────────────

#[test]
fn rsa_detector_empty_input() {
    assert!(RsaDetector::detect_rsa_keys(&[]).is_empty());
}

#[test]
fn rsa_detector_short_no_panic() {
    let _ = RsaDetector::detect_rsa_keys(&[0x30]);
    let _ = RsaDetector::detect_rsa_keys(&[0x30, 0x82]);
    let _ = RsaDetector::detect_rsa_keys(&[0x30, 0x82, 0x01]);
}

#[test]
fn rsa_detector_der_below_threshold_ignored() {
    // declared_len = 0x003F = 63 < 64, must be ignored.
    let mut d = vec![0u8; 20];
    d[0..4].copy_from_slice(&[0x30, 0x82, 0x00, 0x3f]);
    let hints = RsaDetector::detect_rsa_keys(&d);
    assert!(hints.iter().all(|h| h.kind != "DER-RSA"));
}

#[test]
fn rsa_detector_der_at_threshold() {
    // declared_len = 64 → 512-bit estimate (0..=400 band).
    let mut d = vec![0u8; 8];
    d[0..4].copy_from_slice(&[0x30, 0x82, 0x00, 0x40]);
    let hints = RsaDetector::detect_rsa_keys(&d);
    let h = hints.iter().find(|h| h.kind == "DER-RSA").unwrap();
    assert_eq!(h.estimated_bits, 512);
}

#[test]
fn rsa_detector_estimate_bits_bands() {
    let cases = [
        (0x00u8, 0x80u8, 512u32),  // 128
        (0x01, 0xC2, 1024),         // 450
        (0x02, 0xC6, 2048),         // 710
        (0x05, 0xDC, 4096),         // 1500
        (0x0F, 0xA0, 8192),         // 4000
    ];
    for (hi, lo, expected) in cases {
        let mut d = vec![0u8; 8];
        d[0..4].copy_from_slice(&[0x30, 0x82, hi, lo]);
        let hints = RsaDetector::detect_rsa_keys(&d);
        let h = hints.iter().find(|h| h.kind == "DER-RSA").unwrap();
        assert_eq!(
            h.estimated_bits, expected,
            "for declared_len={}",
            (u32::from(hi) << 8) | u32::from(lo)
        );
    }
}

// ── AvalancheAnalyzer ────────────────────────────────────────────────────────

#[test]
fn avalanche_empty_input_zero() {
    assert_eq!(AvalancheAnalyzer::analyze(<[u8]>::to_vec, 0), 0.0);
}

#[test]
fn avalanche_empty_output_zero() {
    assert_eq!(AvalancheAnalyzer::analyze(|_| vec![], 4), 0.0);
}

#[test]
fn avalanche_constant_function_zero() {
    let s = AvalancheAnalyzer::analyze(|_| vec![0xAA; 8], 4);
    assert_eq!(s, 0.0);
}

// ── CryptoReport pipelines ───────────────────────────────────────────────────

#[test]
fn crypto_report_evidence_sorted_and_filtered() {
    let report = CryptoReport {
        algorithms_found: vec![
            CryptoHit {
                offset: 100,
                algorithm: CryptoAlgorithm::Aes128,
                constant: "AES-SBOX".into(),
                confidence: 0.95,
            },
            CryptoHit {
                offset: 10,
                algorithm: CryptoAlgorithm::Md5,
                constant: "MD5-H0".into(),
                confidence: 0.70,
            },
        ],
        possible_keys: vec![KeyCandidate {
            offset: 200,
            length: 16,
            entropy: 0.95,
            description: "blob".into(),
        }],
        recommendations: vec![],
    };

    let cfg = IdentificationConfig::default();
    let ev = report.evidence(cfg);
    // Must include both algorithm-evidence items + the key candidate.
    assert_eq!(ev.len(), 3);
    // include_key_candidates = false → omit key material.
    let cfg2 = IdentificationConfig {
        include_key_candidates: false,
        ..cfg
    };
    let ev2 = report.evidence(cfg2);
    assert_eq!(ev2.len(), 2);
    assert!(ev2.iter().all(|e| e.kind != EvidenceKind::KeyMaterial));
}

#[test]
fn crypto_report_assessments_filtered_by_min_confidence() {
    let report = CryptoReport {
        algorithms_found: vec![CryptoHit {
            offset: 0,
            algorithm: CryptoAlgorithm::Md5,
            constant: "MD5-H0".into(),
            confidence: 0.30,
        }],
        possible_keys: vec![],
        recommendations: vec![],
    };
    let cfg = IdentificationConfig {
        min_confidence: 0.80,
        max_probes_per_algorithm: 1,
        include_key_candidates: false,
    };
    let asses = report.assessments(cfg);
    assert!(asses.is_empty());
}

#[test]
fn crypto_report_active_plan_obeys_max_probes() {
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
fn crypto_report_active_plan_zero_probes() {
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
        max_probes_per_algorithm: 0,
        include_key_candidates: false,
    };
    let plan = report.active_identification_plan(cfg);
    assert_eq!(plan.probes.len(), 0);
}

// ── ConfidenceLevel ──────────────────────────────────────────────────────────

#[test]
fn confidence_level_via_alg_confidence() {
    assert_eq!(AlgorithmConfidence::level(0.0), ConfidenceLevel::Low);
    assert_eq!(AlgorithmConfidence::level(0.49), ConfidenceLevel::Low);
    assert_eq!(AlgorithmConfidence::level(0.50), ConfidenceLevel::Medium);
    assert_eq!(AlgorithmConfidence::level(0.79), ConfidenceLevel::Medium);
    assert_eq!(AlgorithmConfidence::level(0.80), ConfidenceLevel::High);
    assert_eq!(AlgorithmConfidence::level(1.0), ConfidenceLevel::High);
}

// ── BinaryCryptoHit ──────────────────────────────────────────────────────────

#[test]
fn binary_crypto_hit_new_fields() {
    let h = BinaryCryptoHit::new("X", "Y", 42, 0.5, 8);
    assert_eq!(h.algorithm, "X");
    assert_eq!(h.constant_name, "Y");
    assert_eq!(h.offset, 42);
    assert_eq!(h.match_length, 8);
}

// ── scan_for_* family ────────────────────────────────────────────────────────

#[test]
fn scan_for_aes_sbox_empty() {
    assert!(scan_for_aes_sbox(&[]).is_empty());
}

#[test]
fn scan_for_aes_sbox_finds_full_table_confidence_1() {
    let mut d = vec![0u8; 32];
    d.extend_from_slice(&AES_SBOX);
    let hits = scan_for_aes_sbox(&d);
    let h = hits
        .iter()
        .find(|h| h.constant_name == "AES_SBOX" && h.offset == 32)
        .unwrap();
    assert!((h.confidence - 1.0).abs() < 1e-4);
    assert_eq!(h.match_length, 256);
}

#[test]
fn scan_for_sha256_constants_empty() {
    assert!(scan_for_sha256_constants(&[]).is_empty());
}

#[test]
fn scan_for_sha256_le_full_match() {
    let mut d = Vec::new();
    for &k in &SHA256_K {
        d.extend_from_slice(&k.to_le_bytes());
    }
    let hits = scan_for_sha256_constants(&d);
    let h = hits
        .iter()
        .find(|h| h.constant_name == "SHA256_K_LE")
        .unwrap();
    assert!((h.confidence - 1.0).abs() < 1e-4);
}

#[test]
fn scan_for_chacha_magic_finds_both_variants() {
    let mut d = b"prefix ".to_vec();
    d.extend_from_slice(&CHACHA20_MAGIC);
    d.extend_from_slice(b" middle ");
    d.extend_from_slice(&CHACHA20_MAGIC_16);
    let hits = scan_for_chacha_magic(&d);
    assert!(hits.iter().any(|h| h.constant_name == "CHACHA20_MAGIC_32"));
    assert!(hits.iter().any(|h| h.constant_name == "CHACHA20_MAGIC_16"));
}

#[test]
fn scan_for_md5_constants_empty() {
    assert!(scan_for_md5_constants(&[]).is_empty());
}

#[test]
fn scan_binary_for_crypto_constants_sorted() {
    let mut d = vec![0u8; 200];
    d.extend_from_slice(&AES_SBOX);
    d.extend_from_slice(&CHACHA20_MAGIC);
    let hits = scan_binary_for_crypto_constants(&d);
    for w in hits.windows(2) {
        assert!(w[0].offset <= w[1].offset);
    }
}

#[test]
fn scan_binary_for_crypto_constants_no_false_positive_random_zeros() {
    let d = vec![0u8; 4096];
    let hits = scan_binary_for_crypto_constants(&d);
    assert!(hits.is_empty());
}

// ── TestVector ───────────────────────────────────────────────────────────────

#[test]
fn builtin_test_vectors_summary_contains_algorithm() {
    for tv in BUILTIN_TEST_VECTORS {
        let s = tv.summary();
        assert!(s.contains(&tv.algorithm.to_string()), "summary missing alg: {s}");
    }
}

#[test]
fn builtin_test_vectors_aes128_key_length() {
    let v = &BUILTIN_TEST_VECTORS[0];
    assert_eq!(v.algorithm, AlgorithmId::Aes128);
    assert_eq!(v.key.unwrap().len(), 16);
}

#[test]
fn builtin_test_vectors_chacha20_lengths() {
    let v = BUILTIN_TEST_VECTORS
        .iter()
        .find(|v| v.algorithm == AlgorithmId::ChaCha20)
        .unwrap();
    assert_eq!(v.key.unwrap().len(), 32);
    assert_eq!(v.nonce.unwrap().len(), 12);
    assert_eq!(v.plaintext.len(), v.ciphertext.len());
}

// ── EvidenceKind / IdentificationEvidence serde ──────────────────────────────

#[test]
fn evidence_kind_roundtrip() {
    for k in [
        EvidenceKind::Constant,
        EvidenceKind::FunctionPattern,
        EvidenceKind::KeyMaterial,
    ] {
        let j = serde_json::to_string(&k).unwrap();
        let back: EvidenceKind = serde_json::from_str(&j).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn identification_config_default_values() {
    let c = IdentificationConfig::default();
    assert!((c.min_confidence - 0.50).abs() < 1e-6);
    assert_eq!(c.max_probes_per_algorithm, 2);
    assert!(c.include_key_candidates);
}

// ── FunctionScanner ──────────────────────────────────────────────────────────

#[test]
fn function_scanner_empty_input() {
    let h = FunctionScanner::analyze(&[]);
    assert!(h.is_empty());
}

#[test]
fn function_scanner_no_pattern_noise() {
    let code = vec![0x90u8; 1024]; // all NOPs
    let h = FunctionScanner::analyze(&code);
    assert!(h.is_empty());
}

// ── CryptoConstantFound serde ────────────────────────────────────────────────

#[test]
fn crypto_constant_found_serde_roundtrip() {
    let f = CryptoConstantFound {
        offset: 100,
        algorithm: AlgorithmId::ChaCha20,
        constant_name: "X".into(),
        confidence: 0.9,
    };
    let j = serde_json::to_string(&f).unwrap();
    let back: CryptoConstantFound = serde_json::from_str(&j).unwrap();
    assert_eq!(back.offset, f.offset);
    assert_eq!(back.algorithm, f.algorithm);
}

// ── SendSync invariants for Send-relevant types ──────────────────────────────

#[test]
fn signature_database_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SignatureDatabase>();
    assert_send_sync::<BinaryScanner>();
    assert_send_sync::<CryptoScanner>();
}
