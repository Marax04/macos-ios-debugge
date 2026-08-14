//! Blitz integration tests for `rustre-crypto-oracle` lib.rs public API.

use rustre_crypto_oracle::*;
use std::collections::HashMap;

// ── helpers ──────────────────────────────────────────────────────────────────

struct AlwaysTrue;
impl Oracle for AlwaysTrue {
    fn query(&self, _: &[u8]) -> bool {
        true
    }
}

struct AlwaysFalse;
impl Oracle for AlwaysFalse {
    fn query(&self, _: &[u8]) -> bool {
        false
    }
}

struct ValidOC;
impl OracleCallable for ValidOC {
    fn call(&self, _: &[u8]) -> OracleResult {
        OracleResult::Valid
    }
}
struct PadErrOC;
impl OracleCallable for PadErrOC {
    fn call(&self, _: &[u8]) -> OracleResult {
        OracleResult::PaddingError
    }
}

// ── OracleError ──────────────────────────────────────────────────────────────

#[test]
fn oracle_error_display() {
    let e = OracleError::BlockSizeMismatch(8, 16);
    assert!(format!("{e}").contains("block size mismatch"));
    assert!(format!("{}", OracleError::BadLength).contains("multiple of block size"));
    assert!(format!("{}", OracleError::QueryFailed).contains("oracle query failed"));
    assert!(format!("{}", OracleError::AttackFailed("x".into())).contains("attack failed"));
    assert!(format!("{}", OracleError::InvalidParam("y".into())).contains("invalid parameter"));
}

// ── OracleResult / OracleCallable / Oracle / Adapter ────────────────────────

#[test]
fn oracle_result_equality() {
    assert_eq!(OracleResult::Valid, OracleResult::Valid);
    assert_ne!(OracleResult::Valid, OracleResult::PaddingError);
    assert_ne!(OracleResult::OtherError, OracleResult::Valid);
}

#[test]
fn bool_oracle_adapter_maps_true_to_valid() {
    let o = AlwaysTrue;
    let a = BoolOracleAdapter(&o);
    assert_eq!(a.call(&[1, 2, 3]), OracleResult::Valid);
}

#[test]
fn bool_oracle_adapter_maps_false_to_padding_error() {
    let o = AlwaysFalse;
    let a = BoolOracleAdapter(&o);
    assert_eq!(a.call(&[1, 2, 3]), OracleResult::PaddingError);
}

#[test]
fn oracle_trait_object_is_send_sync() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn Oracle>();
    assert_send_sync::<dyn OracleCallable>();
}

// ── OracleMode / Target / Probe / Finding / Discovery ───────────────────────

#[test]
fn oracle_target_round_trip_json() {
    let t = OracleTarget {
        endpoint: "http://x".into(),
        mode: OracleMode::EcbOracle,
        block_size: 16,
        iv: None,
    };
    let s = serde_json::to_string(&t).unwrap();
    let back: OracleTarget = serde_json::from_str(&s).unwrap();
    assert_eq!(back.mode, OracleMode::EcbOracle);
    assert!(back.iv.is_none());
}

#[test]
fn oracle_mode_all_variants_serialize() {
    for m in [
        OracleMode::PaddingOracle,
        OracleMode::CbcOracle,
        OracleMode::EcbOracle,
        OracleMode::TimingOracle,
    ] {
        let j = serde_json::to_string(&m).unwrap();
        let r: OracleMode = serde_json::from_str(&j).unwrap();
        assert_eq!(r, m);
    }
}

#[test]
fn probe_suite_zero_block_size_errors() {
    let r = OracleDiscovery::probe_suite(0);
    assert!(matches!(r, Err(OracleError::InvalidParam(_))));
}

#[test]
fn probe_suite_yields_four_probes() {
    let p = OracleDiscovery::probe_suite(8).unwrap();
    assert_eq!(p.len(), 4);
    assert!(p.iter().any(|x| x.signal == OracleSignal::RepeatedBlockLeak));
    assert!(p.iter().any(|x| x.signal == OracleSignal::TimingSkew));
}

#[test]
fn analyze_outcomes_empty() {
    let r = OracleDiscovery::analyze_outcomes(16, &[]);
    assert_eq!(r.block_size, 16);
    assert!(r.findings.is_empty());
    assert_eq!(r.probes.len(), 4);
}

#[test]
fn analyze_outcomes_detects_padding_delta() {
    let outcomes = vec![OracleProbeOutcome {
        probe_id: "padding-delta-16".into(),
        accepted: false,
        control_accepted: Some(true),
        duration_ns: None,
        control_duration_ns: None,
        response_len: None,
        control_response_len: None,
    }];
    let r = OracleDiscovery::analyze_outcomes(16, &outcomes);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].mode, OracleMode::PaddingOracle);
    assert_eq!(r.findings[0].confidence, 90);
}

#[test]
fn analyze_outcomes_detects_timing_skew() {
    let outcomes = vec![OracleProbeOutcome {
        probe_id: "timing-skew-16".into(),
        accepted: true,
        control_accepted: Some(true),
        duration_ns: Some(50_000),
        control_duration_ns: Some(1_000),
        response_len: None,
        control_response_len: None,
    }];
    let r = OracleDiscovery::analyze_outcomes(16, &outcomes);
    assert!(r.findings.iter().any(|f| f.mode == OracleMode::TimingOracle));
}

#[test]
fn discover_with_oracle_runs_without_error() {
    let report = OracleDiscovery::discover_with_oracle(16, &AlwaysTrue).unwrap();
    assert_eq!(report.block_size, 16);
}

// ── PaddingOracleAttack ─────────────────────────────────────────────────────

#[test]
fn padding_oracle_detect_padding_error_true() {
    assert!(PaddingOracleAttack::detect_padding_error(&PadErrOC, &[1, 2]));
}

#[test]
fn padding_oracle_detect_padding_error_false() {
    assert!(!PaddingOracleAttack::detect_padding_error(&ValidOC, &[1, 2]));
}

#[test]
fn padding_oracle_decrypt_block_bad_ct_len() {
    assert!(matches!(
        PaddingOracleAttack::decrypt_block(&[0u8; 8], &[0u8; 16], &AlwaysFalse),
        Err(OracleError::BlockSizeMismatch(8, 16))
    ));
}

#[test]
fn padding_oracle_decrypt_block_bad_prev_len() {
    assert!(matches!(
        PaddingOracleAttack::decrypt_block(&[0u8; 16], &[0u8; 4], &AlwaysFalse),
        Err(OracleError::BlockSizeMismatch(4, 16))
    ));
}

#[test]
fn padding_oracle_decrypt_cbc_bad_length() {
    assert!(matches!(
        PaddingOracleAttack::decrypt_cbc(&[0u8; 17], &[0u8; 16], &AlwaysFalse),
        Err(OracleError::BadLength)
    ));
}

#[test]
fn padding_oracle_decrypt_cbc_bad_iv() {
    assert!(matches!(
        PaddingOracleAttack::decrypt_cbc(&[0u8; 16], &[0u8; 8], &AlwaysFalse),
        Err(OracleError::BlockSizeMismatch(8, 16))
    ));
}

#[test]
fn padding_oracle_decrypt_block_callable_bad_lens() {
    assert!(matches!(
        PaddingOracleAttack::decrypt_block_callable(&[0u8; 4], &[0u8; 16], &PadErrOC),
        Err(OracleError::BlockSizeMismatch(4, 16))
    ));
    assert!(matches!(
        PaddingOracleAttack::decrypt_block_callable(&[0u8; 16], &[0u8; 4], &PadErrOC),
        Err(OracleError::BlockSizeMismatch(4, 16))
    ));
}

// ── EcbByteAtATime ──────────────────────────────────────────────────────────

#[test]
fn ecb_detect_negative_on_random_output() {
    let f = |_input: &[u8]| -> Vec<u8> { (0u8..48).collect() };
    assert!(!EcbByteAtATime::detect_ecb(&f));
}

#[test]
fn ecb_detect_positive_on_repeated_blocks() {
    let f = |_input: &[u8]| -> Vec<u8> {
        let mut v = vec![0xAAu8; 16];
        v.extend_from_slice(&[0xAAu8; 16]);
        v.extend_from_slice(&[0x00u8; 16]);
        v
    };
    assert!(EcbByteAtATime::detect_ecb(&f));
}

#[test]
fn ecb_determine_block_size_jumps() {
    // Pretend the cipher always pads to nearest multiple of 16.
    let f = |input: &[u8]| -> Vec<u8> {
        let len = ((input.len() / 16) + 1) * 16;
        vec![0u8; len]
    };
    let sz = EcbByteAtATime::determine_block_size(&f);
    assert_eq!(sz, 16);
}

// ── NonceReuseDetection ─────────────────────────────────────────────────────

#[test]
fn nonce_reuse_collect_uses_query_fn() {
    let q: NonceCiphertextQuery<'_> = &|pt| (vec![1u8; 4], pt.to_vec());
    let pts: Vec<&[u8]> = vec![b"a", b"bb"];
    let out = NonceReuseDetection::collect_ciphertexts(q, &pts);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].nonce, vec![1, 1, 1, 1]);
    assert_eq!(out[1].ciphertext, b"bb".to_vec());
}

#[test]
fn nonce_reuse_find_no_reuse() {
    let pairs = vec![
        NonceCiphertext { nonce: vec![1], ciphertext: vec![] },
        NonceCiphertext { nonce: vec![2], ciphertext: vec![] },
    ];
    assert!(NonceReuseDetection::find_nonce_reuse(&pairs).is_empty());
}

#[test]
fn nonce_reuse_xor_truncates_to_shortest() {
    let r = NonceReuseDetection::xor_ciphertexts(&[1, 2, 3, 4], &[5, 6]);
    assert_eq!(r, vec![1 ^ 5, 2 ^ 6]);
}

#[test]
fn nonce_reuse_attack_recovers_p2() {
    let p1 = b"hello";
    let p2 = b"WORLD";
    let key = b"KEYKK";
    let ct1: Vec<u8> = p1.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
    let ct2: Vec<u8> = p2.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
    let rec = NonceReuseDetection::attack_nonce_reuse(&ct1, &ct2, p1);
    assert_eq!(&rec, p2);
}

#[test]
fn nonce_reuse_analyze_xor_for_english_empty_is_zero() {
    assert_eq!(NonceReuseDetection::analyze_xor_for_english(&[]), 0.0);
}

#[test]
fn nonce_reuse_analyze_xor_for_english_all_printable() {
    let s = b"hello world";
    let r = NonceReuseDetection::analyze_xor_for_english(s);
    assert!((r - 1.0).abs() < 1e-9);
}

// ── IvPredictionAttack ──────────────────────────────────────────────────────

#[test]
fn iv_prediction_too_few_ivs() {
    assert!(!IvPredictionAttack::detect_counter_iv(&[]));
    assert!(!IvPredictionAttack::detect_counter_iv(&[vec![0u8; 16]]));
}

#[test]
fn iv_prediction_predict_next() {
    let iv = vec![0xFFu8, 0x00, 0x00, 0x00];
    let next = IvPredictionAttack::predict_next_iv(&iv);
    assert_eq!(next, vec![0x00u8, 0x01, 0x00, 0x00]);
}

#[test]
fn iv_prediction_forge_chosen_plaintext_len() {
    let iv = vec![0u8; 4];
    let kp = b"AAAA";
    let dp = b"BBBB";
    let r = IvPredictionAttack::forge_chosen_plaintext(&iv, kp, dp);
    assert_eq!(r.len(), 4);
}

// ── OtpKeyReuse ─────────────────────────────────────────────────────────────

#[test]
fn otp_xor_empty() {
    assert!(OtpKeyReuse::xor_ciphertexts(&[], &[]).is_empty());
}

#[test]
fn otp_analyze_distribution_empty_returns_zero() {
    assert_eq!(OtpKeyReuse::analyze_xor_distribution(&[]), 0.0);
}

#[test]
fn otp_analyze_distribution_all_printable() {
    let r = OtpKeyReuse::analyze_xor_distribution(b"abcDEF 123");
    assert!((r - 1.0).abs() < 1e-9);
}

#[test]
fn otp_recover_key_byte_finds_xor_key() {
    // Plain "the quick brown fox" XORed with key 0x5A
    let plain = b"the quick brown fox jumps over the lazy dog";
    let key = 0x5Au8;
    let ct: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
    let found = OtpKeyReuse::recover_key_byte(&ct);
    assert_eq!(found, key);
}

// ── ReplayAttack ────────────────────────────────────────────────────────────

#[test]
fn replay_stateless_detection_true_for_const_oracle() {
    assert!(ReplayAttack::detect_stateless(&ValidOC, &[1, 2]));
}

#[test]
fn replay_returns_oracle_result() {
    assert_eq!(ReplayAttack::replay(&ValidOC, &[]), OracleResult::Valid);
    assert_eq!(ReplayAttack::replay(&PadErrOC, &[]), OracleResult::PaddingError);
}

#[test]
fn replay_collect_responses_count() {
    let r = ReplayAttack::collect_responses(&ValidOC, &[0], 5);
    assert_eq!(r.len(), 5);
    assert!(r.iter().all(|x| *x == OracleResult::Valid));
}

#[test]
fn replay_collect_responses_zero() {
    assert!(ReplayAttack::collect_responses(&ValidOC, &[0], 0).is_empty());
}

// ── EmulatorOracle ──────────────────────────────────────────────────────────

#[test]
fn emulator_oracle_new_stores_config() {
    let cfg = EmulatorOracleConfig {
        func_addr: 0x1000,
        input_buf_addr: 0x2000,
        output_buf_addr: 0x3000,
        stack_ptr: 0x4000,
        max_insn: 1000,
    };
    let eo = EmulatorOracle::new(cfg);
    assert_eq!(eo.config.func_addr, 0x1000);
}

#[test]
fn emulator_decrypt_empty_errors() {
    let eo = EmulatorOracle::new(EmulatorOracleConfig {
        func_addr: 0,
        input_buf_addr: 0,
        output_buf_addr: 0,
        stack_ptr: 0,
        max_insn: 1,
    });
    assert!(matches!(eo.decrypt(&[], &[]), Err(OracleError::InvalidParam(_))));
}

#[test]
fn emulator_decrypt_returns_identity() {
    let eo = EmulatorOracle::new(EmulatorOracleConfig {
        func_addr: 0,
        input_buf_addr: 0,
        output_buf_addr: 0,
        stack_ptr: 0,
        max_insn: 1,
    });
    let out = eo.decrypt(&[1, 2, 3], &[]).unwrap();
    assert_eq!(out, vec![1, 2, 3]);
}

// ── CbcBitFlippingAttack ────────────────────────────────────────────────────

#[test]
fn cbc_bit_flip_bad_length() {
    assert!(matches!(
        CbcBitFlippingAttack::flip(&[0u8; 7], &[0u8; 16], 0, 0, 0),
        Err(OracleError::BadLength)
    ));
}

#[test]
fn cbc_bit_flip_bad_iv() {
    assert!(matches!(
        CbcBitFlippingAttack::flip(&[0u8; 16], &[0u8; 8], 0, 0, 0),
        Err(OracleError::BlockSizeMismatch(8, 16))
    ));
}

#[test]
fn cbc_bit_flip_target_out_of_range() {
    assert!(matches!(
        CbcBitFlippingAttack::flip(&[0u8; 16], &[0u8; 16], 99, 0, 0),
        Err(OracleError::InvalidParam(_))
    ));
}

#[test]
fn cbc_bit_flip_first_block_modifies_iv() {
    let (new_iv, new_ct) =
        CbcBitFlippingAttack::flip(&[0u8; 16], &[0u8; 16], 3, 0x10, 0x20).unwrap();
    assert_eq!(new_iv[3], 0x30);
    assert_eq!(new_ct, vec![0u8; 16]);
}

// ── EcbCutAndPasteAttack ────────────────────────────────────────────────────

#[test]
fn ecb_cut_paste_detect_too_short() {
    assert!(!EcbCutAndPasteAttack::detect_ecb(&[0u8; 8], 16));
}

#[test]
fn ecb_cut_paste_detect_zero_block_size() {
    assert!(!EcbCutAndPasteAttack::detect_ecb(&[0u8; 32], 0));
}

#[test]
fn ecb_cut_paste_reorder_zero_block_errors() {
    assert!(matches!(
        EcbCutAndPasteAttack::reorder_blocks(&[0u8; 16], 0, &[0]),
        Err(OracleError::InvalidParam(_))
    ));
}

#[test]
fn ecb_cut_paste_reorder_bad_length() {
    assert!(matches!(
        EcbCutAndPasteAttack::reorder_blocks(&[0u8; 17], 16, &[0]),
        Err(OracleError::BadLength)
    ));
}

#[test]
fn ecb_cut_paste_reorder_identity() {
    let ct: Vec<u8> = (0u8..32).collect();
    let r = EcbCutAndPasteAttack::reorder_blocks(&ct, 16, &[0, 1]).unwrap();
    assert_eq!(r, ct);
}

// ── TimingAttack ────────────────────────────────────────────────────────────

#[test]
fn timing_median_even_count() {
    let m = vec![
        TimingMeasurement { input: vec![], duration_ns: 100 },
        TimingMeasurement { input: vec![], duration_ns: 200 },
        TimingMeasurement { input: vec![], duration_ns: 300 },
        TimingMeasurement { input: vec![], duration_ns: 400 },
    ];
    assert_eq!(TimingAttack::median_duration(&m), Some(250));
}

#[test]
fn timing_max_empty_is_none() {
    assert!(TimingAttack::find_max_duration(&[]).is_none());
}

#[test]
fn timing_byte_attack_zero_samples_returns_zero() {
    let r = TimingAttack::byte_timing_attack(|_| 1u64, 0);
    assert_eq!(r, 0);
}

#[test]
fn timing_byte_attack_picks_max_avg() {
    let r = TimingAttack::byte_timing_attack(
        |c| if c == 42 { 1_000 } else { 10 },
        3,
    );
    assert_eq!(r, 42);
}

// ── AesCracker ──────────────────────────────────────────────────────────────

#[test]
fn aes_weak_keys_includes_zeros_and_ff() {
    let keys = AesCracker::weak_keys();
    assert!(keys.iter().any(|k| k.iter().all(|b| *b == 0)));
    assert!(keys.iter().any(|k| k.iter().all(|b| *b == 0xFF)));
}

#[test]
fn aes_is_weak_key_sequential() {
    let seq: Vec<u8> = (0u8..16).collect();
    assert!(AesCracker::is_weak_key(&seq));
}

#[test]
fn aes_is_weak_key_not_weak() {
    let k: Vec<u8> = vec![0x13u8, 0x37, 0x42, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22];
    assert!(!AesCracker::is_weak_key(&k));
}

#[test]
fn aes_brute_force_too_long_returns_none() {
    assert!(AesCracker::brute_force_short(4, |_| true).is_none());
}

#[test]
fn aes_brute_force_zero_len() {
    // 256^0 = 1; the single empty-key candidate should be tested.
    let r = AesCracker::brute_force_short(0, |k| k.is_empty());
    assert_eq!(r, Some(vec![]));
}

// ── RsaAttacks ──────────────────────────────────────────────────────────────

#[test]
fn rsa_small_exponent_non_three_returns_none() {
    let c = 27u64.to_be_bytes().to_vec();
    assert!(RsaAttacks::small_exponent_attack(&c, 5).is_none());
}

#[test]
fn rsa_small_exponent_recovers_cube_root() {
    // 7^3 = 343
    let bytes = 343u64.to_be_bytes();
    let m = RsaAttacks::small_exponent_attack(&bytes[5..], 3).unwrap();
    assert_eq!(m, vec![7]);
}

#[test]
fn rsa_fermat_factor_even() {
    let r = RsaAttacks::fermat_factor(50).unwrap();
    assert_eq!(r, (2, 25));
}

#[test]
fn rsa_fermat_factor_classic() {
    let (p, q) = RsaAttacks::fermat_factor(3233).unwrap();
    let (lo, hi) = if p < q { (p, q) } else { (q, p) };
    assert_eq!((lo, hi), (53, 61));
}

// ── HttpRequestTemplate / ProtocolField ─────────────────────────────────────

#[test]
fn http_template_render_static() {
    let tpl = HttpRequestTemplate {
        method: "POST".into(),
        url: "http://x/api".into(),
        headers: vec![("X-Test".into(), "1".into())],
        body_fields: vec![("k".into(), ProtocolField::Static(vec![0xDE, 0xAD]))],
    };
    let req = tpl.render(&HashMap::new());
    assert_eq!(req.method, "POST");
    assert_eq!(req.url, "http://x/api");
    assert_eq!(req.headers.len(), 1);
    assert!(String::from_utf8_lossy(&req.body).contains("k=dead"));
}

#[test]
fn http_template_render_overrides_value() {
    let tpl = HttpRequestTemplate {
        method: "GET".into(),
        url: "/".into(),
        headers: vec![],
        body_fields: vec![("f".into(), ProtocolField::Static(vec![0]))],
    };
    let mut v = HashMap::new();
    v.insert("f".to_string(), vec![0xAB, 0xCD]);
    let req = tpl.render(&v);
    assert!(String::from_utf8_lossy(&req.body).contains("f=abcd"));
}

#[test]
fn randomize_field_static() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::Static(vec![1, 2, 3]));
    assert_eq!(r, vec![1, 2, 3]);
}

#[test]
fn randomize_field_random_size() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::Random { size: 8 });
    assert_eq!(r.len(), 8);
}

#[test]
fn randomize_field_timestamp_default() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::Timestamp {
        format: "%s".into(),
    });
    assert_eq!(r, b"1700000000".to_vec());
}

#[test]
fn randomize_field_timestamp_millis() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::Timestamp {
        format: "%ms".into(),
    });
    assert_eq!(r, b"1700000000000".to_vec());
}

#[test]
fn randomize_field_counter() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::Counter { current: 1 });
    assert_eq!(r.len(), 8);
    assert_eq!(r[7], 1);
}

#[test]
fn randomize_field_hmac_stub_is_32_bytes() {
    let r = HttpRequestTemplate::randomize_field(&ProtocolField::HmacSha256 {
        key: vec![],
        data_field_idx: 0,
    });
    assert_eq!(r.len(), 32);
}

// ── ProtocolSynthesizer ─────────────────────────────────────────────────────

#[test]
fn protocol_synth_infer_empty_input() {
    assert!(ProtocolSynthesizer::infer_fields(&[]).is_empty());
}

#[test]
fn protocol_synth_infer_static_field() {
    let samples = vec![vec![0xAAu8]; 4];
    let f = ProtocolSynthesizer::infer_fields(&samples);
    assert_eq!(f.len(), 1);
    assert!(matches!(f[0], ProtocolField::Static(_)));
}

#[test]
fn protocol_synth_export_python_contains_flask() {
    let tpl = HttpRequestTemplate {
        method: "POST".into(),
        url: "/api/x".into(),
        headers: vec![],
        body_fields: vec![("a".into(), ProtocolField::Static(vec![1]))],
    };
    let code = ProtocolSynthesizer::export_python_server(&tpl);
    assert!(code.contains("from flask import"));
    assert!(code.contains("/api/x"));
    assert!(code.contains("'POST'"));
}

// ── RequestFieldAnalyzer ────────────────────────────────────────────────────

#[test]
fn request_field_analyzer_empty() {
    let fc = RequestFieldAnalyzer::analyze_field_across_samples(&[]);
    assert!(fc.is_constant());
    assert_eq!(fc.entropy, 0.0);
}

#[test]
fn request_field_analyzer_constant_samples() {
    let s = vec![vec![1u8, 2, 3]; 5];
    let fc = RequestFieldAnalyzer::analyze_field_across_samples(&s);
    assert!(fc.is_constant());
    assert!(!fc.is_random());
}

#[test]
fn request_field_analyzer_incrementing_samples() {
    let s: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i]).collect();
    let fc = RequestFieldAnalyzer::analyze_field_across_samples(&s);
    assert!(fc.is_incrementing());
    assert!(!fc.is_constant());
}

// ── NonceCiphertext / TimingMeasurement / EmulatorOracleConfig Debug+Clone ──

#[test]
fn struct_clones_and_eqs() {
    let nc = NonceCiphertext {
        nonce: vec![1],
        ciphertext: vec![2],
    };
    let nc2 = nc.clone();
    assert_eq!(nc, nc2);
    let _ = format!("{nc:?}");

    let tm = TimingMeasurement {
        input: vec![1, 2],
        duration_ns: 99,
    };
    let _ = format!("{:?}", tm.clone());
}
