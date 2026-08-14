//! blitz2.rs — adversarial tests for rustre-crypto-oracle public API.
//! Focus: boundaries, fuzz, properties, threaded Send+Sync.

use rustre_crypto_oracle::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

// ── seeded LCG ──────────────────────────────────────────────────────────────

fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(g: &mut impl FnMut() -> u64, n: usize) -> Vec<u8> {
    (0..n).map(|_| (g() >> 56) as u8).collect()
}

// ── helpers / dummy oracles ─────────────────────────────────────────────────

struct ConstOracle(bool);
impl Oracle for ConstOracle {
    fn query(&self, _: &[u8]) -> bool { self.0 }
}

struct ResOC(OracleResult);
impl OracleCallable for ResOC {
    fn call(&self, _: &[u8]) -> OracleResult { self.0.clone() }
}

// ── PaddingOracleAttack ─────────────────────────────────────────────────────

#[test]
fn padding_oracle_block_size_mismatch_ct() {
    let o = ConstOracle(true);
    let r = PaddingOracleAttack::decrypt_block(&[0u8; 15], &[0u8; 16], &o);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(15, 16))));
}

#[test]
fn padding_oracle_block_size_mismatch_prev() {
    let o = ConstOracle(true);
    let r = PaddingOracleAttack::decrypt_block(&[0u8; 16], &[0u8; 8], &o);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(8, 16))));
}

#[test]
fn padding_oracle_cbc_bad_length_variants() {
    let o = ConstOracle(false);
    for bad in [1usize, 7, 15, 17, 31, 33] {
        let r = PaddingOracleAttack::decrypt_cbc(&vec![0u8; bad], &[0u8; 16], &o);
        assert!(matches!(r, Err(OracleError::BadLength)));
    }
}

#[test]
fn padding_oracle_cbc_iv_mismatch() {
    let o = ConstOracle(false);
    let r = PaddingOracleAttack::decrypt_cbc(&[0u8; 32], &[0u8; 8], &o);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(8, 16))));
}

#[test]
fn padding_oracle_cbc_zero_blocks_ok() {
    // 0-length ct (multiple of 16) -> Ok(empty)
    let o = ConstOracle(true);
    let r = PaddingOracleAttack::decrypt_cbc(&[], &[0u8; 16], &o).unwrap();
    assert!(r.is_empty());
}

#[test]
fn padding_oracle_detect_padding_error() {
    let v = ResOC(OracleResult::Valid);
    let p = ResOC(OracleResult::PaddingError);
    let o = ResOC(OracleResult::OtherError);
    assert!(!PaddingOracleAttack::detect_padding_error(&v, &[1]));
    assert!(PaddingOracleAttack::detect_padding_error(&p, &[1]));
    assert!(!PaddingOracleAttack::detect_padding_error(&o, &[1]));
}

#[test]
fn padding_oracle_callable_block_size_mismatch() {
    let o = ResOC(OracleResult::PaddingError);
    let r = PaddingOracleAttack::decrypt_block_callable(&[0u8; 7], &[0u8; 16], &o);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(7, 16))));
    let r = PaddingOracleAttack::decrypt_block_callable(&[0u8; 16], &[0u8; 1], &o);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(1, 16))));
}

#[test]
fn padding_oracle_callable_attack_failed_when_never_valid() {
    let o = ResOC(OracleResult::PaddingError);
    let r = PaddingOracleAttack::decrypt_block_callable(&[0u8; 16], &[0u8; 16], &o);
    assert!(matches!(r, Err(OracleError::AttackFailed(_))));
}

#[test]
fn padding_oracle_decrypt_block_attack_failed() {
    let o = ConstOracle(false);
    let r = PaddingOracleAttack::decrypt_block(&[0u8; 16], &[0u8; 16], &o);
    assert!(matches!(r, Err(OracleError::AttackFailed(_))));
}

// ── EcbByteAtATime ──────────────────────────────────────────────────────────

#[test]
fn ecb_detect_short_ct_false() {
    let f = |_input: &[u8]| vec![0u8; 16];
    assert!(!EcbByteAtATime::detect_ecb(&f));
}

#[test]
fn ecb_detect_repeating_ct_true() {
    let f = |_input: &[u8]| {
        let mut v = vec![0u8; 16];
        v.extend(std::iter::repeat_n(0u8, 16));
        v.extend((0u8..16).collect::<Vec<_>>());
        v
    };
    assert!(EcbByteAtATime::detect_ecb(&f));
}

#[test]
fn ecb_determine_block_size_default_when_no_jump() {
    // length never grows -> returns default 16
    let f = |_in: &[u8]| vec![0u8; 0];
    let bs = EcbByteAtATime::determine_block_size(&f);
    assert_eq!(bs, 16);
}

#[test]
fn ecb_determine_block_size_jumps() {
    // base len = 16; once input >= 1 byte, length jumps to 32
    let f = |i: &[u8]| if i.is_empty() { vec![0u8; 16] } else { vec![0u8; 32] };
    assert_eq!(EcbByteAtATime::determine_block_size(&f), 16);
}

#[test]
fn ecb_recover_unknown_suffix_empty() {
    let f = |_i: &[u8]| Vec::<u8>::new();
    let out = EcbByteAtATime::recover_unknown_suffix(&f, 16);
    assert!(out.is_empty());
}

// ── EcbCutAndPasteAttack ────────────────────────────────────────────────────

#[test]
fn ecb_cut_paste_detect_zero_block_size() {
    assert!(!EcbCutAndPasteAttack::detect_ecb(&[0u8; 32], 0));
}

#[test]
fn ecb_cut_paste_detect_too_short() {
    assert!(!EcbCutAndPasteAttack::detect_ecb(&[0u8; 8], 16));
}

#[test]
fn ecb_cut_paste_reorder_zero_block_size() {
    let r = EcbCutAndPasteAttack::reorder_blocks(&[0u8; 16], 0, &[]);
    assert!(matches!(r, Err(OracleError::InvalidParam(_))));
}

#[test]
fn ecb_cut_paste_reorder_bad_length() {
    let r = EcbCutAndPasteAttack::reorder_blocks(&[0u8; 17], 16, &[0]);
    assert!(matches!(r, Err(OracleError::BadLength)));
}

#[test]
fn ecb_cut_paste_reorder_roundtrip_identity() {
    let ct: Vec<u8> = (0u8..64).collect();
    let out = EcbCutAndPasteAttack::reorder_blocks(&ct, 16, &[0, 1, 2, 3]).unwrap();
    assert_eq!(out, ct);
}

#[test]
fn ecb_cut_paste_reorder_fuzz_property() {
    let mut g = lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let num = ((g() >> 56) % 8 + 1) as usize;
        let bs = 16;
        let ct = rand_bytes(&mut g, num * bs);
        // pick a permutation: just reverse
        let order: Vec<usize> = (0..num).rev().collect();
        let out = EcbCutAndPasteAttack::reorder_blocks(&ct, bs, &order).unwrap();
        assert_eq!(out.len(), ct.len());
    }
}

// ── NonceReuseDetection ─────────────────────────────────────────────────────

#[test]
fn nonce_reuse_no_pairs_empty() {
    let r = NonceReuseDetection::find_nonce_reuse(&[]);
    assert!(r.is_empty());
}

#[test]
fn nonce_reuse_all_unique() {
    let pairs: Vec<NonceCiphertext> = (0u8..10)
        .map(|i| NonceCiphertext { nonce: vec![i], ciphertext: vec![] })
        .collect();
    assert!(NonceReuseDetection::find_nonce_reuse(&pairs).is_empty());
}

#[test]
fn nonce_reuse_xor_property() {
    let mut g = lcg(0x1234);
    for _ in 0..50 {
        let n = ((g() >> 56) % 32) as usize + 1;
        let a = rand_bytes(&mut g, n);
        let b = rand_bytes(&mut g, n);
        let x = NonceReuseDetection::xor_ciphertexts(&a, &b);
        let xx = NonceReuseDetection::xor_ciphertexts(&x, &a);
        assert_eq!(xx, b);
    }
}

#[test]
fn nonce_reuse_xor_different_lengths() {
    let r = NonceReuseDetection::xor_ciphertexts(&[1, 2, 3], &[4, 5]);
    assert_eq!(r, vec![1 ^ 4, 2 ^ 5]);
}

#[test]
fn nonce_reuse_english_score_bounds() {
    let s = NonceReuseDetection::analyze_xor_for_english(&[]);
    assert!((0.0..=1.0).contains(&s));
    let s = NonceReuseDetection::analyze_xor_for_english(&[b'a', b' ', b'X']);
    assert!((s - 1.0).abs() < 1e-9);
    let s = NonceReuseDetection::analyze_xor_for_english(&[0, 1, 2]);
    assert!(s.abs() < 1e-9);
}

#[test]
fn nonce_collect_ciphertexts_basic() {
    let f: &dyn Fn(&[u8]) -> (Vec<u8>, Vec<u8>) = &|p| (vec![0u8; 8], p.to_vec());
    let pts: Vec<&[u8]> = vec![b"a", b"bb"];
    let out = NonceReuseDetection::collect_ciphertexts(f, &pts);
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].ciphertext, b"bb");
}

// ── IvPredictionAttack ──────────────────────────────────────────────────────

#[test]
fn iv_predict_single_iv_false() {
    assert!(!IvPredictionAttack::detect_counter_iv(&[vec![0u8; 16]]));
}

#[test]
fn iv_predict_roundtrip_predict_undo() {
    let mut g = lcg(0xABCD_1234);
    for _ in 0..30 {
        let len = ((g() >> 56) % 16) as usize + 1;
        let iv = rand_bytes(&mut g, len);
        let next = IvPredictionAttack::predict_next_iv(&iv);
        assert_eq!(next.len(), iv.len());
    }
}

#[test]
fn iv_predict_wrapping_overflow_le() {
    let iv = vec![0xFFu8; 16];
    let next = IvPredictionAttack::predict_next_iv(&iv);
    assert_eq!(next, vec![0u8; 16]);
}

#[test]
fn iv_forge_chosen_plaintext_bounded() {
    let cur = vec![0u8; 16];
    let known = b"AAAAAAAAAAAAAAAA";
    let want = b"BBBBBBBBBBBBBBBB";
    let f = IvPredictionAttack::forge_chosen_plaintext(&cur, known, want);
    assert_eq!(f.len(), 16);
}

// ── OtpKeyReuse ─────────────────────────────────────────────────────────────

#[test]
fn otp_xor_then_recover_property() {
    let mut g = lcg(0xFACE_FEED);
    for _ in 0..50 {
        let n = ((g() >> 56) % 64) as usize + 1;
        let p1 = rand_bytes(&mut g, n);
        let p2 = rand_bytes(&mut g, n);
        let key = rand_bytes(&mut g, n);
        let c1: Vec<u8> = p1.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        let c2: Vec<u8> = p2.iter().zip(&key).map(|(a, b)| a ^ b).collect();
        let x = OtpKeyReuse::xor_ciphertexts(&c1, &c2);
        let r = OtpKeyReuse::recover_p2(&x, &p1);
        assert_eq!(r, p2);
    }
}

#[test]
fn otp_analyze_xor_empty() {
    assert_eq!(OtpKeyReuse::analyze_xor_distribution(&[]), 0.0);
}

#[test]
fn otp_recover_key_byte_runs() {
    let cols: Vec<u8> = (b'a'..=b'z').collect();
    let key = 0x42u8;
    let enc: Vec<u8> = cols.iter().map(|c| c ^ key).collect();
    let _ = OtpKeyReuse::recover_key_byte(&enc); // must not panic
}

// ── ReplayAttack ────────────────────────────────────────────────────────────

#[test]
fn replay_collect_responses_count() {
    let o = ResOC(OracleResult::Valid);
    let r = ReplayAttack::collect_responses(&o, &[1, 2, 3], 5);
    assert_eq!(r.len(), 5);
    assert!(r.iter().all(|x| *x == OracleResult::Valid));
}

#[test]
fn replay_count_zero() {
    let o = ResOC(OracleResult::PaddingError);
    assert!(ReplayAttack::collect_responses(&o, &[], 0).is_empty());
}

#[test]
fn replay_replay_method() {
    let o = ResOC(OracleResult::OtherError);
    assert_eq!(ReplayAttack::replay(&o, &[9]), OracleResult::OtherError);
}

// ── CbcBitFlippingAttack ────────────────────────────────────────────────────

#[test]
fn cbc_bit_flip_offset_out_of_range() {
    let r = CbcBitFlippingAttack::flip(&[0u8; 32], &[0u8; 16], 32, 0, 1);
    assert!(matches!(r, Err(OracleError::InvalidParam(_))));
}

#[test]
fn cbc_bit_flip_bad_length() {
    let r = CbcBitFlippingAttack::flip(&[0u8; 17], &[0u8; 16], 0, 0, 1);
    assert!(matches!(r, Err(OracleError::BadLength)));
}

#[test]
fn cbc_bit_flip_iv_size_mismatch() {
    let r = CbcBitFlippingAttack::flip(&[0u8; 32], &[0u8; 8], 0, 0, 1);
    assert!(matches!(r, Err(OracleError::BlockSizeMismatch(8, 16))));
}

// ── TimingAttack ────────────────────────────────────────────────────────────

#[test]
fn timing_median_even_count() {
    let m: Vec<TimingMeasurement> = [10u64, 20, 30, 40]
        .iter()
        .map(|d| TimingMeasurement { input: vec![], duration_ns: *d })
        .collect();
    assert_eq!(TimingAttack::median_duration(&m), Some(25));
}

#[test]
fn timing_max_empty() {
    assert!(TimingAttack::find_max_duration(&[]).is_none());
}

#[test]
fn timing_byte_attack_returns_zero_on_zero_samples() {
    let r = TimingAttack::byte_timing_attack(|_| 1_000, 0);
    assert_eq!(r, 0);
}

#[test]
fn timing_byte_attack_picks_largest() {
    // Use byte value as duration: candidate 255 should be picked.
    let r = TimingAttack::byte_timing_attack(|b| u64::from(b), 3);
    assert_eq!(r, 255);
}

// ── AesCracker ──────────────────────────────────────────────────────────────

#[test]
fn aes_cracker_weak_keys_have_expected_count() {
    assert_eq!(AesCracker::weak_keys().len(), 5);
}

#[test]
fn aes_cracker_is_weak_seq() {
    // ascending 0..16 is weak
    assert!(AesCracker::is_weak_key(&(0u8..16).collect::<Vec<_>>()));
    // descending from 255 (255-i for i=0..16) is the documented weak pattern
    let desc: Vec<u8> = (0u8..16).map(|i| 255 - i).collect();
    assert!(AesCracker::is_weak_key(&desc));
}

#[test]
fn aes_cracker_brute_force_too_long_returns_none() {
    assert!(AesCracker::brute_force_short(4, |_| true).is_none());
}

#[test]
fn aes_cracker_brute_force_2byte() {
    let target = vec![0x00u8, 0x05];
    let found = AesCracker::brute_force_short(2, |k| k == target.as_slice());
    assert_eq!(found, Some(target));
}

// ── RsaAttacks ──────────────────────────────────────────────────────────────

#[test]
fn rsa_small_exponent_wrong_e() {
    assert!(RsaAttacks::small_exponent_attack(&[1, 2, 3], 65537).is_none());
}

#[test]
fn rsa_small_exponent_too_long() {
    assert!(RsaAttacks::small_exponent_attack(&[0u8; 17], 3).is_none());
}

#[test]
fn rsa_fermat_factor_even() {
    let (p, q) = RsaAttacks::fermat_factor(100).unwrap();
    assert_eq!(p, 2);
    assert_eq!(q, 50);
}

#[test]
fn rsa_small_exponent_perfect_cube() {
    // 5^3 = 125; bytes for 125 in be
    let c = 125u128.to_be_bytes();
    // strip leading zeros to get a compact ciphertext that decodes to 125
    let start = c.iter().position(|&b| b != 0).unwrap();
    let m = RsaAttacks::small_exponent_attack(&c[start..], 3).unwrap();
    assert_eq!(m, vec![5]);
}

// ── OracleDiscovery ─────────────────────────────────────────────────────────

#[test]
fn oracle_discovery_zero_block_size_err() {
    assert!(matches!(
        OracleDiscovery::probe_suite(0),
        Err(OracleError::InvalidParam(_))
    ));
}

#[test]
fn oracle_discovery_probe_suite_varied_sizes() {
    for bs in [1usize, 8, 16, 32, 64] {
        let probes = OracleDiscovery::probe_suite(bs).unwrap();
        assert_eq!(probes.len(), 4);
        assert!(probes[0].id.contains(&bs.to_string()));
    }
}

#[test]
fn oracle_discovery_no_outcomes_no_findings() {
    let r = OracleDiscovery::analyze_outcomes(16, &[]);
    assert!(r.findings.is_empty());
    assert_eq!(r.probes.len(), 4);
}

#[test]
fn oracle_discovery_timing_skew_below_threshold() {
    let outcomes = vec![OracleProbeOutcome {
        probe_id: "timing-skew-16".into(),
        accepted: true,
        control_accepted: Some(true),
        duration_ns: Some(100),
        control_duration_ns: Some(200),
        response_len: None,
        control_response_len: None,
    }];
    let r = OracleDiscovery::analyze_outcomes(16, &outcomes);
    assert!(r.findings.is_empty());
}

#[test]
fn oracle_discovery_serde_roundtrip() {
    let r = OracleDiscovery::analyze_outcomes(16, &[]);
    let s = serde_json::to_string(&r).unwrap();
    let back: OracleDiscoveryReport = serde_json::from_str(&s).unwrap();
    assert_eq!(back.block_size, 16);
}

// ── EmulatorOracle ──────────────────────────────────────────────────────────

#[test]
fn emulator_oracle_empty_ct_errors() {
    let cfg = EmulatorOracleConfig {
        func_addr: 0,
        input_buf_addr: 0,
        output_buf_addr: 0,
        stack_ptr: 0,
        max_insn: 0,
    };
    let o = EmulatorOracle::new(cfg);
    assert!(matches!(o.decrypt(&[], &[]), Err(OracleError::InvalidParam(_))));
}

#[test]
fn emulator_oracle_identity_stub() {
    let cfg = EmulatorOracleConfig {
        func_addr: 0,
        input_buf_addr: 0,
        output_buf_addr: 0,
        stack_ptr: 0,
        max_insn: 0,
    };
    let o = EmulatorOracle::new(cfg);
    assert_eq!(o.decrypt(&[1, 2, 3], &[]).unwrap(), vec![1, 2, 3]);
}

// ── ProtocolSynthesizer / HttpRequestTemplate ───────────────────────────────

#[test]
fn protocol_synth_empty_returns_empty() {
    assert!(ProtocolSynthesizer::infer_fields(&[]).is_empty());
}

#[test]
fn http_template_render_empty_body() {
    let tpl = HttpRequestTemplate {
        method: "GET".to_string(),
        url: "http://x".to_string(),
        headers: vec![("H".to_string(), "V".to_string())],
        body_fields: vec![],
    };
    let req = tpl.render(&HashMap::new());
    assert_eq!(req.method, "GET");
    assert_eq!(req.headers.len(), 1);
    assert!(req.body.is_empty());
}

#[test]
fn http_template_render_supplied_value_overrides() {
    let tpl = HttpRequestTemplate {
        method: "POST".to_string(),
        url: "/p".to_string(),
        headers: vec![],
        body_fields: vec![("name".to_string(), ProtocolField::Random { size: 4 })],
    };
    let mut vals = HashMap::new();
    vals.insert("name".to_string(), vec![0xABu8, 0xCD]);
    let req = tpl.render(&vals);
    let body = String::from_utf8_lossy(&req.body);
    assert!(body.contains("name=abcd"));
}

#[test]
fn protocol_synth_export_python_contains_keywords() {
    let tpl = HttpRequestTemplate {
        method: "POST".to_string(),
        url: "/oracle".to_string(),
        headers: vec![],
        body_fields: vec![("t".to_string(), ProtocolField::Static(vec![1, 2]))],
    };
    let py = ProtocolSynthesizer::export_python_server(&tpl);
    assert!(py.contains("Flask"));
    assert!(py.contains("/oracle"));
    assert!(py.contains("POST"));
}

// ── RequestFieldAnalyzer ────────────────────────────────────────────────────

#[test]
fn field_analyzer_empty_samples() {
    let fc = RequestFieldAnalyzer::analyze_field_across_samples(&[]);
    assert!(fc.is_constant());
    assert!(!fc.is_random());
    assert_eq!(fc.entropy, 0.0);
}

#[test]
fn field_analyzer_incrementing() {
    let samples: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i]).collect();
    let fc = RequestFieldAnalyzer::analyze_field_across_samples(&samples);
    assert!(fc.is_incrementing());
}

// ── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn threaded_oracle_query_stress() {
    struct CounterOracle;
    impl Oracle for CounterOracle {
        fn query(&self, c: &[u8]) -> bool { c.iter().map(|&b| u32::from(b)).sum::<u32>() % 2 == 0 }
    }
    let o: Arc<dyn Oracle> = Arc::new(CounterOracle);
    let mut handles = vec![];
    for t in 0..4u8 {
        let o = o.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let buf = vec![t, (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8];
                let _ = o.query(&buf);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_oracle_callable_stress() {
    let o: Arc<dyn OracleCallable> = Arc::new(ResOC(OracleResult::Valid));
    let mut handles = vec![];
    for _ in 0..4 {
        let o = o.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100u32 {
                let buf = i.to_le_bytes();
                assert_eq!(o.call(&buf), OracleResult::Valid);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── Fuzz on parsers / no-panic invariants ───────────────────────────────────

#[test]
fn fuzz_probe_suite_never_panics() {
    let mut g = lcg(0xC0FFEE);
    for _ in 0..50 {
        let bs = ((g() >> 56) as usize) + 1; // 1..=256
        let _ = OracleDiscovery::probe_suite(bs).unwrap();
    }
}

#[test]
fn fuzz_xor_ciphertexts_len_min() {
    let mut g = lcg(0xBA5E_BA11);
    for _ in 0..50 {
        let a_len = (g() >> 56) as usize % 64;
        let b_len = (g() >> 56) as usize % 64;
        let a = rand_bytes(&mut g, a_len);
        let b = rand_bytes(&mut g, b_len);
        let r = OtpKeyReuse::xor_ciphertexts(&a, &b);
        assert_eq!(r.len(), a_len.min(b_len));
    }
}

#[test]
fn fuzz_predict_iv_property() {
    let mut g = lcg(0x9E37_79B9);
    for _ in 0..50 {
        let n = ((g() >> 56) % 32) as usize + 1;
        let iv = rand_bytes(&mut g, n);
        let next = IvPredictionAttack::predict_next_iv(&iv);
        assert_eq!(next.len(), iv.len());
    }
}

#[test]
fn fuzz_reorder_bad_index_errs() {
    let mut g = lcg(0xDEAD);
    for _ in 0..30 {
        let nblk = ((g() >> 56) % 4) as usize + 1;
        let ct = rand_bytes(&mut g, nblk * 16);
        let bad = vec![nblk]; // out of range
        let r = EcbCutAndPasteAttack::reorder_blocks(&ct, 16, &bad);
        assert!(r.is_err());
    }
}

// ── OracleProbeOutcome serde round-trip ─────────────────────────────────────

#[test]
fn outcome_serde_roundtrip() {
    let o = OracleProbeOutcome {
        probe_id: "x".into(),
        accepted: true,
        control_accepted: Some(false),
        duration_ns: Some(123),
        control_duration_ns: None,
        response_len: Some(7),
        control_response_len: None,
    };
    let s = serde_json::to_string(&o).unwrap();
    let back: OracleProbeOutcome = serde_json::from_str(&s).unwrap();
    assert_eq!(back, o);
}

#[test]
fn oracle_finding_serde_roundtrip() {
    let f = OracleFinding {
        mode: OracleMode::TimingOracle,
        signal: OracleSignal::TimingSkew,
        confidence: 99,
        summary: "x".into(),
    };
    let s = serde_json::to_string(&f).unwrap();
    let back: OracleFinding = serde_json::from_str(&s).unwrap();
    assert_eq!(back, f);
}
