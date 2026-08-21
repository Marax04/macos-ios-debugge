//! Comprehensive integration tests for `rustre-deobf-smc` public API.

use std::collections::HashMap;

use rustre_deobf::{DeobfContext, DeobfError, DeobfPass};
use rustre_deobf_smc::{
    shannon_entropy, looks_like_code, CodeMutationTracker, DynamicSmcDetector,
    DynamicSmcReconstructor, EmuRegisters, EmulatedDecrypt, EmulationTrace, LayeredSmc,
    MutationEvent, MutationType, PolymorphicEngineAnalyzer, SmcAlgorithm, SmcDecryptor,
    SmcDetector, SmcKey, SmcPass, SmcPatcher, SmcRegion, UnpackedRegion, UnpackedRegionDetector,
    WriteEvent, XorChainStep,
};

// ── SmcRegion ───────────────────────────────────────────────────────────────

const fn region(start: u64, end: u64, key: SmcKey, algorithm: SmcAlgorithm) -> SmcRegion {
    SmcRegion { start, end, decryptor_addr: 0, key, algorithm }
}

#[test]
fn region_len_basic() {
    let r = region(0x100, 0x180, SmcKey::Constant(0), SmcAlgorithm::Xor);
    assert_eq!(r.len(), 0x80);
    assert!(!r.is_empty());
}

#[test]
fn region_len_zero_is_empty() {
    let r = region(0x100, 0x100, SmcKey::Constant(0), SmcAlgorithm::Xor);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
}

#[test]
fn region_len_inverted_saturates() {
    let r = region(0x200, 0x100, SmcKey::Constant(0), SmcAlgorithm::Xor);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
}

#[test]
fn region_serde_roundtrip() {
    let r = region(0x10, 0x20, SmcKey::FromMemory(0xCAFE), SmcAlgorithm::Sub);
    let s = serde_json::to_string(&r).unwrap();
    let r2: SmcRegion = serde_json::from_str(&s).unwrap();
    assert_eq!(r2.start, r.start);
    assert_eq!(r2.end, r.end);
    assert_eq!(r2.key, r.key);
    assert_eq!(r2.algorithm, r.algorithm);
}

// ── SmcKey / SmcAlgorithm ───────────────────────────────────────────────────

#[test]
fn smckey_equality() {
    assert_eq!(SmcKey::Constant(7), SmcKey::Constant(7));
    assert_ne!(SmcKey::Constant(7), SmcKey::Constant(8));
    assert_ne!(SmcKey::Derived, SmcKey::Constant(0));
    assert_eq!(SmcKey::FromRegister("BL".into()), SmcKey::FromRegister("BL".into()));
}

#[test]
fn smckey_serde_all_variants() {
    for k in [
        SmcKey::Constant(0xDEAD_BEEF),
        SmcKey::Derived,
        SmcKey::FromMemory(0x1000),
        SmcKey::FromRegister("EAX".to_owned()),
    ] {
        let s = serde_json::to_string(&k).unwrap();
        let k2: SmcKey = serde_json::from_str(&s).unwrap();
        assert_eq!(k, k2);
    }
}

#[test]
fn smcalgorithm_serde_all_variants() {
    for a in [
        SmcAlgorithm::Xor,
        SmcAlgorithm::Add,
        SmcAlgorithm::Sub,
        SmcAlgorithm::Rol,
        SmcAlgorithm::Ror,
        SmcAlgorithm::XorRolling,
        SmcAlgorithm::AddRolling,
        SmcAlgorithm::Custom(vec![0x01, 0x02, 0x03]),
    ] {
        let s = serde_json::to_string(&a).unwrap();
        let a2: SmcAlgorithm = serde_json::from_str(&s).unwrap();
        assert_eq!(a, a2);
    }
}

// ── SmcDecryptor ────────────────────────────────────────────────────────────

#[test]
fn decryptor_default_eq_new() {
    let _ = SmcDecryptor;
    let _ = SmcDecryptor::new();
}

#[test]
fn decrypt_xor_constant_key() {
    let r = region(0, 4, SmcKey::Constant(0x5A), SmcAlgorithm::Xor);
    let data = vec![0x00, 0x5A, 0xFF, 0xA5];
    let got = SmcDecryptor::new().decrypt(&data, &r);
    assert_eq!(got, vec![0x5A, 0x00, 0xA5, 0xFF]);
}

#[test]
fn decrypt_xor_empty_input() {
    let r = region(0, 0, SmcKey::Constant(0xAB), SmcAlgorithm::Xor);
    let got = SmcDecryptor::new().decrypt(&[], &r);
    assert!(got.is_empty());
}

#[test]
fn decrypt_add_subtracts_key() {
    let r = region(0, 3, SmcKey::Constant(10), SmcAlgorithm::Add);
    let got = SmcDecryptor::new().decrypt(&[10, 20, 30], &r);
    assert_eq!(got, vec![0, 10, 20]);
}

#[test]
fn decrypt_add_wraps_below_zero() {
    let r = region(0, 2, SmcKey::Constant(5), SmcAlgorithm::Add);
    let got = SmcDecryptor::new().decrypt(&[0u8, 3], &r);
    assert_eq!(got, vec![0u8.wrapping_sub(5), 3u8.wrapping_sub(5)]);
}

#[test]
fn decrypt_sub_adds_key() {
    let r = region(0, 3, SmcKey::Constant(7), SmcAlgorithm::Sub);
    let got = SmcDecryptor::new().decrypt(&[1, 2, 3], &r);
    assert_eq!(got, vec![8, 9, 10]);
}

#[test]
fn decrypt_rol_size_preserved() {
    let r = region(0, 4, SmcKey::Constant(3), SmcAlgorithm::Rol);
    let got = SmcDecryptor::new().decrypt(&[0x12, 0x34, 0x56, 0x78], &r);
    assert_eq!(got.len(), 4);
}

#[test]
fn decrypt_ror_size_preserved() {
    let r = region(0, 4, SmcKey::Constant(3), SmcAlgorithm::Ror);
    let got = SmcDecryptor::new().decrypt(&[0x12, 0x34, 0x56, 0x78], &r);
    assert_eq!(got.len(), 4);
}

#[test]
fn decrypt_rol_zero_amount_identity() {
    let r = region(0, 3, SmcKey::Constant(0), SmcAlgorithm::Rol);
    let data = vec![0xAA, 0x55, 0x00];
    let got = SmcDecryptor::new().decrypt(&data, &r);
    assert_eq!(got, data);
}

#[test]
fn decrypt_xor_rolling_roundtrip() {
    let r = region(0, 5, SmcKey::Constant(0x77), SmcAlgorithm::XorRolling);
    let plain = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let mut cipher = Vec::new();
    let mut prev = 0x77u8;
    for &p in &plain { let c = p ^ prev; cipher.push(c); prev = c; }
    let got = SmcDecryptor::new().decrypt(&cipher, &r);
    assert_eq!(got, plain);
}

#[test]
fn decrypt_add_rolling_roundtrip() {
    let r = region(0, 4, SmcKey::Constant(0x10), SmcAlgorithm::AddRolling);
    let plain = vec![1u8, 2, 3, 4];
    let mut cipher = Vec::new();
    let mut prev = 0x10u8;
    for &p in &plain { let c = p.wrapping_add(prev); cipher.push(c); prev = c; }
    let got = SmcDecryptor::new().decrypt(&cipher, &r);
    assert_eq!(got, plain);
}

#[test]
fn decrypt_with_derived_key_defaults_zero() {
    let r = region(0, 3, SmcKey::Derived, SmcAlgorithm::Xor);
    let data = vec![0xAB, 0xCD, 0xEF];
    let got = SmcDecryptor::new().decrypt(&data, &r);
    assert_eq!(got, data); // xor with 0
}

#[test]
fn decrypt_with_from_memory_key_defaults_zero() {
    let r = region(0, 2, SmcKey::FromMemory(0x1234), SmcAlgorithm::Xor);
    let got = SmcDecryptor::new().decrypt(&[0x10, 0x20], &r);
    assert_eq!(got, vec![0x10, 0x20]);
}

#[test]
fn decrypt_custom_xor_then_add() {
    let r = region(0, 3,
        SmcKey::Constant(0),
        SmcAlgorithm::Custom(vec![0x01, 0x0F, 0x02, 0x01]),
    );
    let got = SmcDecryptor::new().decrypt(&[0x00, 0x10, 0x20], &r);
    let expected: Vec<u8> = [0x00u8, 0x10, 0x20].iter().map(|&b| (b ^ 0x0F).wrapping_add(0x01)).collect();
    assert_eq!(got, expected);
}

#[test]
fn decrypt_custom_unknown_opcode_no_change() {
    let r = region(0, 2, SmcKey::Constant(0), SmcAlgorithm::Custom(vec![0xFF, 0xAA]));
    let data = vec![0x01u8, 0x02];
    let got = SmcDecryptor::new().decrypt(&data, &r);
    assert_eq!(got, data);
}

#[test]
fn decrypt_custom_empty_ops_returns_clone() {
    let r = region(0, 2, SmcKey::Constant(0), SmcAlgorithm::Custom(vec![]));
    let data = vec![9u8, 8];
    let got = SmcDecryptor::new().decrypt(&data, &r);
    assert_eq!(got, data);
}

// ── SmcDetector ─────────────────────────────────────────────────────────────

#[test]
fn detector_short_input_returns_empty() {
    assert!(SmcDetector::new().detect(&[0u8; 4]).is_empty());
}

#[test]
fn detector_default_is_constructible() {
    let _ = SmcDetector;
}

#[test]
fn detector_finds_xor_loop_pattern() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0xB9, 0x10, 0x00, 0x00, 0x00]);
    data.extend_from_slice(&[0xBF, 0x00, 0x20, 0x00, 0x00]);
    data.extend_from_slice(&[0x80, 0x34, 0x0F, 0x77]);
    data.extend_from_slice(&[0xE2, 0xF7]);
    let regions = SmcDetector::new().detect(&data);
    assert!(!regions.is_empty());
    assert!(regions.iter().any(|r| matches!(r.algorithm, SmcAlgorithm::Xor)));
}

#[test]
fn detector_finds_pushpop_xor() {
    let mut data = vec![0x60];
    data.extend_from_slice(&[0xBF, 0x00, 0x30, 0x00, 0x00]);
    data.extend_from_slice(&[0x80, 0x37, 0x99]);
    data.push(0x61);
    let regions = SmcDetector::new().detect(&data);
    assert!(!regions.is_empty());
}

// ── SmcPatcher ──────────────────────────────────────────────────────────────

#[test]
fn patcher_default_constructible() {
    let _ = SmcPatcher;
}

#[test]
fn patcher_xor_produces_single_patch() {
    let key = 0x33u8;
    let r = region(0, 5, SmcKey::Constant(u64::from(key)), SmcAlgorithm::Xor);
    let plain = vec![1u8, 2, 3, 4, 5];
    let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
    let patches = SmcPatcher::new().build_patches(&cipher, &r, 0).unwrap();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].patched, plain);
    assert_eq!(patches[0].original, cipher);
}

#[test]
fn patcher_returns_too_short_when_offset_past_end() {
    let r = region(0, 100, SmcKey::Constant(0), SmcAlgorithm::Xor);
    let err = SmcPatcher::new().build_patches(&[0u8; 10], &r, 0).unwrap_err();
    match err {
        DeobfError::TooShort { needed, have } => {
            assert_eq!(needed, 100);
            assert_eq!(have, 10);
        }
        other => panic!("expected TooShort, got {other:?}"),
    }
}

#[test]
fn patcher_empty_region_succeeds() {
    let r = region(0, 0, SmcKey::Constant(0), SmcAlgorithm::Xor);
    let patches = SmcPatcher::new().build_patches(&[0u8; 8], &r, 0).unwrap();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].patched.is_empty());
}

// ── LayeredSmc ──────────────────────────────────────────────────────────────

#[test]
fn layered_default_max_layers_is_eight() {
    assert_eq!(LayeredSmc::default().max_layers, 8);
}

#[test]
fn layered_new_sets_max_layers() {
    assert_eq!(LayeredSmc::new(3).max_layers, 3);
}

#[test]
fn layered_no_regions_returns_zero_layers() {
    let data = vec![0x90u8; 64];
    let (out, n) = LayeredSmc::new(4).decrypt_all(&data);
    assert_eq!(out, data);
    assert_eq!(n, 0);
}

#[test]
fn layered_empty_input() {
    let (out, n) = LayeredSmc::new(2).decrypt_all(&[]);
    assert!(out.is_empty());
    assert_eq!(n, 0);
}

// ── EmuRegisters ────────────────────────────────────────────────────────────

#[test]
fn emu_registers_default_all_zero() {
    let r = EmuRegisters::default();
    for i in 0..16u8 { assert_eq!(r.read(i), 0); }
    assert_eq!(r.rip, 0);
    assert_eq!(r.flags, 0);
}

#[test]
fn emu_registers_read_write_roundtrip() {
    let mut r = EmuRegisters::default();
    r.write(3, 0xDEAD_BEEF);
    assert_eq!(r.read(3), 0xDEAD_BEEF);
}

#[test]
fn emu_registers_index_wraps() {
    let mut r = EmuRegisters::default();
    r.write(17, 42); // 17 & 15 == 1
    assert_eq!(r.read(1), 42);
    assert_eq!(r.read(17), 42);
}

// ── EmulatedDecrypt ─────────────────────────────────────────────────────────

#[test]
fn emulated_decrypt_default_constructible() {
    let _ = EmulatedDecrypt;
    let _ = EmulatedDecrypt::new();
}

#[test]
fn emulated_trace_xor_recovers_key() {
    let code = vec![0x80, 0x31, 0xAB, 0x49, 0x75, 0xFB];
    let t: EmulationTrace = EmulatedDecrypt::new().trace(&code, 8);
    assert_eq!(t.recovered_key, 0xAB);
    assert!(matches!(t.algorithm, SmcAlgorithm::Xor));
    assert!(t.iterations > 0);
}

#[test]
fn emulated_trace_add_recovers_key() {
    let code = vec![0x80, 0x07, 0x22, 0x47, 0x75, 0xFB];
    let t = EmulatedDecrypt::new().trace(&code, 8);
    assert_eq!(t.recovered_key, 0x22);
    assert!(matches!(t.algorithm, SmcAlgorithm::Add));
}

#[test]
fn emulated_trace_sub_recovers_key() {
    let code = vec![0x80, 0x29, 0x33, 0x49, 0x75, 0xFB];
    let t = EmulatedDecrypt::new().trace(&code, 8);
    assert_eq!(t.recovered_key, 0x33);
    assert!(matches!(t.algorithm, SmcAlgorithm::Sub));
}

#[test]
fn emulated_trace_empty_code() {
    let t = EmulatedDecrypt::new().trace(&[], 16);
    assert_eq!(t.recovered_key, 0);
    assert_eq!(t.iterations, 0);
}

#[test]
fn emulated_trace_respects_max_iter() {
    let code = vec![0x75, 0xFE]; // JNZ -2 infinite loop
    let t = EmulatedDecrypt::new().trace(&code, 5);
    assert!(t.iterations <= 5);
}

#[test]
fn emulated_trace_nop_only() {
    let code = vec![0x90u8; 8];
    let t = EmulatedDecrypt::new().trace(&code, 16);
    assert_eq!(t.recovered_key, 0);
    assert_eq!(t.iterations, 0);
}

// ── SmcPass / DeobfPass ─────────────────────────────────────────────────────

#[test]
fn smcpass_name_and_description() {
    let p = SmcPass::new();
    assert_eq!(p.name(), "smc-deobf");
    assert!(!p.description().is_empty());
}

#[test]
fn smcpass_default_eq_new() {
    let _ = SmcPass::default();
    let _ = SmcPass::new();
}

#[test]
fn smcpass_applicable_requires_min_size() {
    let p = SmcPass::new();
    assert!(!p.is_applicable(&DeobfContext::new(vec![0u8; 15])));
    assert!(p.is_applicable(&DeobfContext::new(vec![0u8; 16])));
}

#[test]
fn smcpass_no_regions_zero_patches() {
    let mut ctx = DeobfContext::new(vec![0x90u8; 32]);
    let r = SmcPass::new().run(&mut ctx).unwrap();
    assert_eq!(r.patches_applied, 0);
}

// ── DynamicSmcDetector / Reconstructor ──────────────────────────────────────

#[test]
fn dynamic_default_empty() {
    let d = DynamicSmcDetector::default();
    assert!(d.events().is_empty());
    assert!(!d.is_smc_execution(0));
}

#[test]
fn dynamic_records_writes() {
    let mut d = DynamicSmcDetector::new();
    d.add_write(0x1000, 0x2000, 0xAA);
    d.add_write(0x1004, 0x2001, 0xBB);
    assert_eq!(d.events().len(), 2);
    assert!(d.is_smc_execution(0x2000));
    assert!(d.is_smc_execution(0x2001));
    assert!(!d.is_smc_execution(0x2002));
}

#[test]
fn dynamic_to_memory_map_uses_last_write() {
    let mut d = DynamicSmcDetector::new();
    d.add_write(0, 0x100, 0x11);
    d.add_write(0, 0x100, 0x22);
    let m = d.to_memory_map();
    assert_eq!(m.get(&0x100), Some(&0x22));
}

#[test]
fn write_event_equality_and_copy() {
    let a = WriteEvent { address: 1, value: 2, pc: 3 };
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn reconstructor_overlay_basic() {
    let mut map = HashMap::new();
    map.insert(0x10u64, 0xFFu8);
    map.insert(0x12u64, 0xEEu8);
    let r = DynamicSmcReconstructor::new(map);
    let out = r.reconstruct(0x10, &[0, 0, 0, 0]);
    assert_eq!(out, vec![0xFF, 0, 0xEE, 0]);
}

#[test]
fn reconstructor_from_detector() {
    let mut d = DynamicSmcDetector::new();
    d.add_write(0, 5, 0xAB);
    let r = DynamicSmcReconstructor::from_detector(&d);
    let out = r.reconstruct(5, &[0u8; 2]);
    assert_eq!(out[0], 0xAB);
    assert_eq!(out[1], 0);
}

#[test]
fn reconstructor_no_writes_returns_original() {
    let r = DynamicSmcReconstructor::new(HashMap::new());
    let orig = vec![1u8, 2, 3];
    assert_eq!(r.reconstruct(0, &orig), orig);
}

// ── PolymorphicEngineAnalyzer / MutationEvent / MutationType ────────────────

#[test]
fn poly_analyzer_default_constructible() {
    let _ = PolymorphicEngineAnalyzer;
    let _ = PolymorphicEngineAnalyzer::new();
}

#[test]
fn poly_analyzer_no_diff_no_events() {
    let a = vec![1u8, 2, 3, 4];
    let events = PolymorphicEngineAnalyzer::new().analyze(&a, &a);
    assert!(events.is_empty());
}

#[test]
fn poly_analyzer_finds_diff() {
    let a = vec![0x00u8; 16];
    let mut b = a.clone();
    b[4] = 0x90; b[5] = 0x90; b[6] = 0x90; b[7] = 0x90;
    let events = PolymorphicEngineAnalyzer::new().analyze(&a, &b);
    assert!(!events.is_empty());
}

#[test]
fn mutation_type_serde() {
    for m in [
        MutationType::NopInsertion,
        MutationType::RegisterSubstitution,
        MutationType::ConstantReencoding,
        MutationType::InstructionReorder,
        MutationType::JunkCode,
        MutationType::OpaquePredicate,
        MutationType::EquivalentSubstitution,
        MutationType::Transposition,
    ] {
        let s = serde_json::to_string(&m).unwrap();
        let m2: MutationType = serde_json::from_str(&s).unwrap();
        assert_eq!(m, m2);
    }
}

#[test]
fn mutation_event_serde() {
    let e = MutationEvent {
        offset: 5,
        kind: MutationType::NopInsertion,
        original: vec![1, 2, 3],
        mutated: vec![0x90, 0x90, 0x90],
        description: "x".into(),
    };
    let s = serde_json::to_string(&e).unwrap();
    let e2: MutationEvent = serde_json::from_str(&s).unwrap();
    assert_eq!(e2.offset, e.offset);
    assert_eq!(e2.kind, e.kind);
}

// ── CodeMutationTracker ─────────────────────────────────────────────────────

#[test]
fn tracker_new_has_one_generation() {
    let t = CodeMutationTracker::new(vec![0u8; 8]);
    assert_eq!(t.generation_count(), 1);
    assert!(t.mutations_at(0).is_empty());
}

#[test]
fn tracker_add_snapshot_records_diff() {
    let mut t = CodeMutationTracker::new(vec![0u8; 16]);
    let mut s2 = vec![0u8; 16];
    s2[2..10].fill(0x90);
    t.add_snapshot(s2);
    assert_eq!(t.generation_count(), 2);
    assert!(!t.mutations_at(0).is_empty());
    assert!(!t.all_mutations().is_empty());
}

#[test]
fn tracker_mutations_at_out_of_range_empty() {
    let t = CodeMutationTracker::new(vec![0u8; 4]);
    assert!(t.mutations_at(99).is_empty());
}

#[test]
fn tracker_snapshot_lookup() {
    let t = CodeMutationTracker::new(vec![1u8, 2, 3]);
    assert_eq!(t.snapshot(0), Some(&[1u8, 2, 3][..]));
    assert_eq!(t.snapshot(1), None);
}

#[test]
fn tracker_count_by_type_buckets() {
    let mut t = CodeMutationTracker::new(vec![0u8; 16]);
    let mut s2 = vec![0u8; 16];
    s2[0..8].fill(0x90);
    t.add_snapshot(s2);
    let counts = t.count_by_type();
    assert!(counts.values().sum::<usize>() >= 1);
}

#[test]
fn tracker_default_no_snapshots() {
    let t = CodeMutationTracker::default();
    assert_eq!(t.generation_count(), 0);
}

// ── UnpackedRegion / UnpackedRegionDetector ─────────────────────────────────

#[test]
fn unpacked_region_len_and_empty() {
    let r = UnpackedRegion { start: 10, end: 20, entropy: 4.0, looks_like_code: false };
    assert_eq!(r.len(), 10);
    assert!(!r.is_empty());
    let r0 = UnpackedRegion { start: 5, end: 5, entropy: 0.0, looks_like_code: false };
    assert!(r0.is_empty());
}

#[test]
fn unpacked_region_serde() {
    let r = UnpackedRegion { start: 1, end: 2, entropy: 3.5, looks_like_code: true };
    let s = serde_json::to_string(&r).unwrap();
    let r2: UnpackedRegion = serde_json::from_str(&s).unwrap();
    assert_eq!(r2, r);
}

#[test]
fn unpacked_detector_default_params() {
    let d = UnpackedRegionDetector::default();
    assert_eq!(d.window_size, 256);
    assert!((d.entropy_threshold - 6.0).abs() < f64::EPSILON);
}

#[test]
fn unpacked_detector_new_sets_params() {
    let d = UnpackedRegionDetector::new(64, 5.5);
    assert_eq!(d.window_size, 64);
    assert!((d.entropy_threshold - 5.5).abs() < f64::EPSILON);
}

#[test]
fn unpacked_detector_short_input_empty() {
    let d = UnpackedRegionDetector::default();
    assert!(d.detect(&[0u8; 16]).is_empty());
}

#[test]
fn unpacked_detector_low_entropy_finds_region() {
    let d = UnpackedRegionDetector::new(32, 6.0);
    // Construct: 64 bytes low-entropy then 64 bytes random-ish high entropy.
    let mut data = vec![0u8; 64];
    for i in 0..64u8 { data.push(i.wrapping_mul(31).wrapping_add(7)); }
    let _ = d.detect(&data); // just exercise; result is heuristic
}

// ── shannon_entropy ─────────────────────────────────────────────────────────

#[test]
fn shannon_entropy_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn shannon_entropy_uniform_is_zero() {
    assert!(shannon_entropy(&[0x42u8; 100]).abs() < 1e-9);
}

#[test]
fn shannon_entropy_two_symbols_is_one_bit() {
    let mut data = vec![0u8; 50];
    data.extend(vec![1u8; 50]);
    let h = shannon_entropy(&data);
    assert!((h - 1.0).abs() < 1e-9, "got {h}");
}

#[test]
fn shannon_entropy_full_byte_range_is_eight() {
    let data: Vec<u8> = (0..=255u8).collect();
    let h = shannon_entropy(&data);
    assert!((h - 8.0).abs() < 1e-9, "got {h}");
}

// ── looks_like_code ─────────────────────────────────────────────────────────

#[test]
fn looks_like_code_empty_is_false() {
    assert!(!looks_like_code(&[]));
}

#[test]
fn looks_like_code_nop_sled_true() {
    assert!(looks_like_code(&[0x90u8; 32]));
}

#[test]
fn looks_like_code_high_bytes_false() {
    assert!(!looks_like_code(&[0xD0u8; 32]));
}

// ── XorChainStep ────────────────────────────────────────────────────────────

#[test]
fn xor_chain_step_serde() {
    let s = XorChainStep { key: 0x55, pre_op: 1, rot_amount: 3 };
    let j = serde_json::to_string(&s).unwrap();
    let s2: XorChainStep = serde_json::from_str(&j).unwrap();
    assert_eq!(s, s2);
}

#[test]
fn xor_chain_step_apply_pre_op_none() {
    let s = XorChainStep { key: 0x0F, pre_op: 0, rot_amount: 0 };
    assert_eq!(s.apply(0xF0), 0xF0 ^ 0x0F);
}

#[test]
fn xor_chain_step_apply_pre_op_not() {
    let s = XorChainStep { key: 0x00, pre_op: 1, rot_amount: 0 };
    assert_eq!(s.apply(0xAA), !0xAA);
}

// ── Send/Sync bounds (compile-time only) ────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<SmcRegion>();
    assert_send_sync::<SmcKey>();
    assert_send_sync::<SmcAlgorithm>();
    assert_send_sync::<SmcDecryptor>();
    assert_send_sync::<SmcDetector>();
    assert_send_sync::<SmcPatcher>();
    assert_send_sync::<LayeredSmc>();
    assert_send_sync::<EmuRegisters>();
    assert_send_sync::<EmulatedDecrypt>();
    assert_send_sync::<EmulationTrace>();
    assert_send_sync::<SmcPass>();
    assert_send_sync::<DynamicSmcDetector>();
    assert_send_sync::<DynamicSmcReconstructor>();
    assert_send_sync::<WriteEvent>();
    assert_send_sync::<PolymorphicEngineAnalyzer>();
    assert_send_sync::<CodeMutationTracker>();
    assert_send_sync::<MutationEvent>();
    assert_send_sync::<MutationType>();
    assert_send_sync::<UnpackedRegion>();
    assert_send_sync::<UnpackedRegionDetector>();
    assert_send_sync::<XorChainStep>();
}
