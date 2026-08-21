//! blitz2 — deep adversarial coverage of rustre-deobf public surface.

use rustre_deobf::*;
use std::sync::Arc;

// Seeded LCG (no rand/time).
fn lcg_seed(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut g = lcg_seed(seed);
    (0..len).map(|_| (g() >> 56) as u8).collect()
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Patch round-trips & error paths
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t01_patch_roundtrip_lcg_50() {
    for i in 0..50u64 {
        let data = lcg_bytes(0xDEAD_BEEF_CAFE_BABE ^ i, 64);
        let mut buf = data.clone();
        let p = Patch::new(0, data.clone(), vec![0xAA; data.len()], "swap");
        p.apply(&mut buf).unwrap();
        assert_eq!(buf, vec![0xAA; data.len()]);
    }
}

#[test]
fn t02_patch_offset_at_end_zero_len() {
    let mut data = vec![1u8, 2, 3];
    let p = Patch::new(3, vec![], vec![], "noop tail");
    p.apply(&mut data).unwrap();
    assert_eq!(data, vec![1, 2, 3]);
}

#[test]
fn t03_patch_offset_overflow_returns_err() {
    let mut data = vec![0u8; 8];
    let p = Patch::new(usize::MAX - 1, vec![], vec![0xFF, 0xFF, 0xFF, 0xFF], "ovf");
    assert!(p.apply(&mut data).is_err());
}

#[test]
fn t04_patch_original_mismatch_specific_err() {
    let mut data = vec![0x11, 0x22, 0x33];
    let p = Patch::new(0, vec![0xAA, 0xBB], vec![0xCC, 0xDD], "x");
    match p.apply(&mut data) {
        Err(DeobfError::PatchConflict { offset, .. }) => assert_eq!(offset, 0),
        other => panic!("expected PatchConflict, got {other:?}"),
    }
}

#[test]
fn t05_patch_eq_clone_consistency() {
    let pairs = (0..30u64).map(|i| {
        Patch::new(
            i as usize,
            lcg_bytes(i, 4),
            lcg_bytes(i ^ 0xFF, 4),
            format!("p{i}"),
        )
    });
    for p in pairs {
        let c = p.clone();
        assert_eq!(p, c);
        // Hash/Eq via PartialEq only — but check that Debug doesn't panic.
        let _ = format!("{p:?}");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 2. DeobfContext
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t06_context_apply_patches_oob_err() {
    let mut ctx = DeobfContext::new(vec![0u8; 2]);
    ctx.patches.push(Patch::new(1, vec![], vec![0xFF, 0xFF, 0xFF], "oob"));
    assert!(ctx.apply_patches().is_err());
}

#[test]
fn t07_context_va_unmapped_returns_none() {
    let ctx = DeobfContext::new(vec![]);
    assert_eq!(ctx.va_to_file_offset(0x0040_1000), None);
}

#[test]
fn t08_context_meta_overwrite() {
    let mut ctx = DeobfContext::new(vec![]);
    ctx.set_meta("k", serde_json::json!(1));
    ctx.set_meta("k", serde_json::json!(2));
    assert_eq!(ctx.get_meta("k"), Some(&serde_json::json!(2)));
}

// ────────────────────────────────────────────────────────────────────────────
// 3. DeobfResult merge semantics
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t09_merge_into_empty_preserves_other_confidence() {
    let mut empty = DeobfResult::default();
    let other = DeobfResult::new(3, vec!["x".into()], 9, 0.42);
    empty.merge(&other);
    assert_eq!(empty.patches_applied, 3);
    assert!((empty.confidence - 0.42).abs() < 1e-6);
}

#[test]
fn t10_merge_with_zero_patches_keeps_self_confidence() {
    let mut r1 = DeobfResult::new(0, vec![], 0, 0.5);
    let r2 = DeobfResult::new(0, vec![], 0, 0.9);
    r1.merge(&r2);
    // total==0 → confidence stays as self's confidence (no division done).
    assert!((r1.confidence - 0.5).abs() < 1e-6);
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Pipeline / Registry
// ────────────────────────────────────────────────────────────────────────────

struct CountingPass {
    name: &'static str,
    patches: usize,
}
impl DeobfPass for CountingPass {
    fn name(&self) -> &'static str { self.name }
    fn description(&self) -> &'static str { "counter" }
    fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        Ok(DeobfResult::new(self.patches, vec![], 0, 1.0))
    }
    fn is_applicable(&self, _ctx: &DeobfContext) -> bool { true }
}

#[test]
fn t11_pipeline_empty_runs_cleanly() {
    let pipeline = DeobfPipeline::new();
    let mut ctx = DeobfContext::new(vec![]);
    let r = pipeline.run_all(&mut ctx);
    assert!(r.pass_results.is_empty());
}

#[test]
fn t12_pipeline_run_returns_elapsed() {
    let mut p = DeobfPipeline::new();
    p.add_pass(Box::new(CountingPass { name: "a", patches: 2 }));
    let mut ctx = DeobfContext::new(vec![]);
    let result = p.run(&mut ctx).unwrap();
    assert_eq!(result.total_patches, 2);
    assert_eq!(result.passes_run, 1);
}

#[test]
fn t13_pass_registry_run_selection_unknown_errs() {
    let reg = PassRegistry::new();
    let mut ctx = DeobfContext::new(vec![]);
    match reg.run_selection(&["nope"], &mut ctx) {
        Err(DeobfError::NotApplicable(_)) => {}
        _ => panic!("expected NotApplicable"),
    }
}

#[test]
fn t14_deobf_pass_registry_separator_normalisation() {
    let mut reg = DeobfPassRegistry::new();
    reg.register(Arc::new(NopSledRemover::new()));
    // Registered name is "nop-sled-remover" (kebab); lookup both forms.
    assert!(reg.get("nop-sled-remover").is_some());
    assert!(reg.get("nop_sled_remover").is_some());
    assert!(reg.get("unknown_pass").is_none());
}

#[test]
fn t15_pipeline_arc_pass_forwards_name() {
    let mut p = DeobfPipeline::new();
    p.add_pass_arc(Arc::new(NopSledRemover::new()));
    let mut ctx = DeobfContext::new(vec![0x90u8; 8]);
    let r = p.run_all(&mut ctx);
    assert_eq!(r.pass_results[0].0, "nop-sled-remover");
}

// ────────────────────────────────────────────────────────────────────────────
// 5. PatternMatcher
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t16_pattern_empty_pattern_no_match() {
    let mut m = PatternMatcher::new();
    m.add_pattern("empty", vec![]);
    assert!(m.scan(&[1, 2, 3]).is_empty());
}

#[test]
fn t17_pattern_too_short_data() {
    let mut m = PatternMatcher::new();
    m.add_pattern("p", vec![1, 2, 3, 4]);
    assert!(m.scan(&[1, 2]).is_empty());
}

#[test]
fn t18_pattern_fuzz_no_panic() {
    let mut g = lcg_seed(0xDEAD_BEEF_CAFE_BABE);
    let mut m = PatternMatcher::new();
    m.add_pattern("sig", vec![0xDE, 0xAD]);
    for _ in 0..50 {
        let len = (g() % 256) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() >> 56) as u8).collect();
        let _ = m.scan(&data);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 6. XorDecryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t19_xor_constant_roundtrip_all_keys_lcg_50() {
    let plain = lcg_bytes(0xAA55_AA55_AA55_AA55, 64);
    for key in 0u8..=255 {
        let c = XorDecryptor::decrypt_constant(&plain, key);
        let d = XorDecryptor::decrypt_constant(&c, key);
        assert_eq!(d, plain);
    }
}

#[test]
fn t20_xor_cyclic_empty_key_identity() {
    let data = vec![1u8, 2, 3, 4];
    assert_eq!(XorDecryptor::decrypt_cyclic(&data, &[]), data);
}

#[test]
fn t21_xor_rolling_roundtrip_lcg() {
    for i in 0..50u64 {
        let plain = lcg_bytes(i.wrapping_mul(0x1234_5678), 32);
        let init = (i & 0xFF) as u8;
        // Encrypt
        let mut cipher = Vec::with_capacity(plain.len());
        let mut prev = init;
        for &b in &plain {
            let c = b ^ prev;
            cipher.push(c);
            prev = c;
        }
        let dec = XorDecryptor::decrypt_rolling(&cipher, init);
        assert_eq!(dec, plain);
    }
}

#[test]
fn t22_xor_entropy_empty_is_zero() {
    assert_eq!(XorDecryptor::entropy(&[]), 0.0);
}

#[test]
fn t23_xor_recover_handles_short() {
    let (_k, _d) = XorDecryptor::recover_single_byte_key(&[]);
    let (_k, _d) = XorDecryptor::recover_single_byte_key(&[0u8]);
}

// ────────────────────────────────────────────────────────────────────────────
// 7. RolRorDecryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t24_rol_ror_all_byte_all_rot() {
    for rot in 0u8..16 {
        for b in 0u8..=255 {
            assert_eq!(RolRorDecryptor::ror(RolRorDecryptor::rol(b, rot), rot), b);
        }
    }
}

#[test]
fn t25_rol_ror_recover_no_panic_on_empty() {
    let (_r, _is_rol, _d) = RolRorDecryptor::recover_rotation(&[]);
}

// ────────────────────────────────────────────────────────────────────────────
// 8. Base64 — boundaries / malformed / round-trip
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t26_base64_empty_is_empty() {
    assert_eq!(Base64Decoder::decode(b"").unwrap(), Vec::<u8>::new());
}

#[test]
fn t27_base64_invalid_chars_none() {
    assert!(Base64Decoder::decode(b"!!!!").is_none());
}

#[test]
fn t28_base64_find_skips_short() {
    // Less than 16 chars → not reported.
    assert!(Base64Decoder::find_all(b"TWFu").is_empty());
}

#[test]
fn t29_base64_decode_fuzz_no_panic() {
    let mut g = lcg_seed(0xCAFE_F00D_DEAD_BEEF);
    for _ in 0..50 {
        let len = (g() % 64) as usize;
        let data: Vec<u8> = (0..len).map(|_| (g() >> 56) as u8).collect();
        let _ = Base64Decoder::decode(&data);
        let _ = Base64Decoder::find_all(&data);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 9. RC4 — KSA permutation invariants, round-trip
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t30_rc4_roundtrip_lcg() {
    for i in 0..50u64 {
        let plain = lcg_bytes(i, 48);
        let key = lcg_bytes(i.wrapping_mul(7), 1 + (i % 16) as usize);
        let c = Rc4Decryptor::decrypt(&plain, &key);
        let d = Rc4Decryptor::decrypt(&c, &key);
        assert_eq!(d, plain);
    }
}

#[test]
fn t31_rc4_empty_data_empty_out() {
    assert_eq!(Rc4Decryptor::decrypt(&[], b"k"), Vec::<u8>::new());
}

// ────────────────────────────────────────────────────────────────────────────
// 10. ChaCha20 — round-trip, short-key/nonce errs
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t32_chacha20_short_key_errs() {
    let r = ChaCha20Decryptor::crypt(b"data", &[0u8; 16], &[0u8; 12]);
    assert!(matches!(r, Err(DeobfError::TooShort { .. })));
}

#[test]
fn t33_chacha20_short_nonce_errs() {
    let r = ChaCha20Decryptor::crypt(b"data", &[0u8; 32], &[0u8; 8]);
    assert!(matches!(r, Err(DeobfError::TooShort { .. })));
}

#[test]
fn t34_chacha20_multi_block_roundtrip() {
    let key = [0x55u8; 32];
    let nonce = [0x11u8; 12];
    let plain: Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
    let c = ChaCha20Decryptor::crypt(&plain, &key, &nonce).unwrap();
    let d = ChaCha20Decryptor::crypt(&c, &key, &nonce).unwrap();
    assert_eq!(d, plain);
}

// ────────────────────────────────────────────────────────────────────────────
// 11. Checksums — known vectors
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t35_crc32_table_matches_bitwise_lcg() {
    for i in 0..50u64 {
        let data = lcg_bytes(i, 1 + (i & 0x3F) as usize);
        assert_eq!(Crc32::checksum(&data), Crc32::checksum_table(&data));
    }
}

#[test]
fn t36_adler32_single_byte() {
    // For b: a=1+b, b=1+b → adler = ((1+b)<<16) | (1+b)
    let v = Adler32::checksum(&[0x10]);
    assert_eq!(v, (0x11 << 16) | 0x11);
}

// ────────────────────────────────────────────────────────────────────────────
// 12. EntropyScanner — zero-window guard, sliding boundaries
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t37_entropy_scanner_zero_window_safe() {
    let s = EntropyScanner { window: 0, threshold: 1.0, step: 0 };
    assert!(s.scan(&[1, 2, 3]).is_empty());
}

#[test]
fn t38_entropy_scanner_short_data_high_entropy() {
    let s = EntropyScanner { window: 1024, threshold: 0.5, step: 64 };
    let data: Vec<u8> = (0..32u8).collect();
    let regions = s.scan(&data);
    // Short path: returns single-region if entropy ≥ threshold.
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].offset, 0);
}

// ────────────────────────────────────────────────────────────────────────────
// 13. PatchSet — overlap rejection, sort invariant
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t39_patchset_offset_overflow_rejected() {
    let mut ps = PatchSet::new();
    let p = Patch::new(usize::MAX - 1, vec![], vec![0u8; 4], "ovf");
    assert!(!ps.insert(p));
}

#[test]
fn t40_patchset_apply_oob_errs() {
    let mut ps = PatchSet::new();
    ps.insert(Patch::new(10, vec![], vec![0xFF, 0xFF], "tail"));
    assert!(ps.apply_to(&[0u8; 5]).is_err());
}

#[test]
fn t41_patchset_into_patches_preserves_order() {
    let mut ps = PatchSet::new();
    ps.insert(Patch::new(20, vec![], vec![0x1], "c"));
    ps.insert(Patch::new(5, vec![], vec![0x2], "a"));
    ps.insert(Patch::new(10, vec![], vec![0x3], "b"));
    let v = ps.into_patches();
    assert_eq!(v[0].offset, 5);
    assert_eq!(v[1].offset, 10);
    assert_eq!(v[2].offset, 20);
}

// ────────────────────────────────────────────────────────────────────────────
// 14. HexDumper — width / base
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t42_hexdumper_zero_width_defaults_to_16() {
    let d = HexDumper { width: 0, base_address: 0 };
    let out = d.dump(b"abcdefghijklmnop");
    assert!(out.contains("61")); // 'a'
}

#[test]
fn t43_hexdumper_empty_data_empty_output() {
    assert_eq!(HexDumper::new().dump(&[]), "");
    assert_eq!(HexDumper::new().hex_only(&[]), "");
}

// ────────────────────────────────────────────────────────────────────────────
// 15. BinarySection
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t44_binary_section_empty() {
    let s = BinarySection::new(".empty", 0, vec![]);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert!(!s.looks_packed());
}

// ────────────────────────────────────────────────────────────────────────────
// 16. ConstantFoldingPass — every op
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t45_constant_folding_all_ops() {
    for &(op, a, b, expected) in &[
        (0x01u8, 5u32, 7u32, 12u32),                  // ADD
        (0x02, 10, 3, 7),                              // SUB
        (0x03, 0xF0, 0x0F, 0x00),                      // AND
        (0x04, 0xF0, 0x0F, 0xFF),                      // OR
        (0x05, 0xAA, 0x55, 0xFF),                      // XOR
        (0x06, 3, 4, 12),                              // MUL
    ] {
        let mut data = vec![op];
        data.extend_from_slice(&a.to_le_bytes());
        data.extend_from_slice(&b.to_le_bytes());
        data.push(0x90);
        let mut ctx = DeobfContext::new(data);
        let pass = ConstantFoldingPass::new();
        pass.run(&mut ctx).unwrap();
        let patched = ctx.apply_patches().unwrap();
        let v = u32::from_le_bytes([patched[1], patched[2], patched[3], patched[4]]);
        assert_eq!(v, expected, "op={op:#x}");
    }
}

#[test]
fn t46_constant_folding_too_short_not_applicable() {
    let pass = ConstantFoldingPass::new();
    let ctx = DeobfContext::new(vec![0u8; 8]);
    assert!(!pass.is_applicable(&ctx));
}

#[test]
fn t47_constant_folding_fuzz_no_panic() {
    let pass = ConstantFoldingPass::new();
    for i in 0..50u64 {
        let data = lcg_bytes(i ^ 0xF00D, 64);
        let mut ctx = DeobfContext::new(data);
        let _ = pass.run(&mut ctx);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 17. NopSledRemover boundary
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t48_nop_sled_boundary_exactly_min() {
    let r = NopSledRemover::with_min_sled(4);
    let sleds = r.find_sleds(&[0xCC, 0x90, 0x90, 0x90, 0x90, 0xCC]);
    assert_eq!(sleds.len(), 1);
    assert_eq!(sleds[0].1, 4);
}

#[test]
fn t49_nop_sled_off_by_one_below_min() {
    let r = NopSledRemover::with_min_sled(4);
    let sleds = r.find_sleds(&[0xCC, 0x90, 0x90, 0x90, 0xCC]);
    assert!(sleds.is_empty());
}

#[test]
fn t50_nop_sled_not_applicable_no_nops() {
    let pass = NopSledRemover::new();
    let ctx = DeobfContext::new(vec![0x00; 128]);
    assert!(!pass.is_applicable(&ctx));
}

// ────────────────────────────────────────────────────────────────────────────
// 18. Display / FromStr-ish — ObfuscationType + DeobfReport summary
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t51_obfuscation_type_display_all_variants() {
    let variants = [
        (ObfuscationType::ControlFlowFlattening, "CFF"),
        (ObfuscationType::VirtualMachine, "VM"),
        (ObfuscationType::SelfModifyingCode, "SMC"),
        (ObfuscationType::StringEncryption, "StringEnc"),
        (ObfuscationType::OpaquePredicates, "Opaque"),
        (ObfuscationType::MixedBooleanArithmetic, "MBA"),
        (ObfuscationType::AntiDebug, "AntiDebug"),
        (ObfuscationType::PackedExecutable, "Packed"),
        (ObfuscationType::Unknown, "Unknown"),
    ];
    for (v, s) in variants {
        assert_eq!(v.to_string(), s);
    }
}

#[test]
fn t52_deobf_report_display_matches_summary() {
    let mut r = DeobfReport::new("x");
    r.total_patches = 7;
    r.total_modified_bytes = 14;
    r.techniques_detected.push("t".into());
    assert_eq!(r.to_string(), r.summary());
}

// ────────────────────────────────────────────────────────────────────────────
// 19. Send/Sync threaded stress
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t53_arc_pass_send_sync_4t_100ops() {
    let pass: Arc<dyn DeobfPass> = Arc::new(NopSledRemover::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = pass.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let mut ctx = DeobfContext::new(vec![0x90u8; 8]);
                let r = p.run(&mut ctx).unwrap();
                assert!(r.patches_applied > 0);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t54_constant_folding_pass_threaded() {
    let pass: Arc<dyn DeobfPass> = Arc::new(ConstantFoldingPass::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let p = pass.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                let mut ctx = DeobfContext::new(lcg_bytes(t.wrapping_mul(101) ^ i, 64));
                let _ = p.run(&mut ctx);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 20. IterativeDeobf / HybridDeobf / DeobfSession / Heuristics
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t55_iterative_terminates_when_no_patches() {
    let mut p = DeobfPipeline::new();
    p.add_pass(Box::new(CountingPass { name: "z", patches: 0 }));
    let iter = IterativeDeobf::new(p, 5);
    let (_, iters) = iter.run(vec![0u8; 4]).unwrap();
    assert_eq!(iters, 1);
}

#[test]
fn t56_hybrid_with_no_pipelines_returns_input() {
    let h = HybridDeobf::new();
    let r = h.run(&[1u8, 2, 3]).unwrap();
    assert_eq!(r, vec![1, 2, 3]);
}

#[test]
fn t57_session_metrics_accumulate() {
    let mut p = DeobfPipeline::new();
    p.add_pass(Box::new(CountingPass { name: "y", patches: 3 }));
    let mut s = DeobfSession::new("s", p);
    let mut ctx = DeobfContext::new(vec![]);
    s.run_on(&mut ctx).unwrap();
    s.run_on(&mut ctx).unwrap();
    assert_eq!(s.metrics.total_patches, 6);
    assert_eq!(s.run_count(), 2);
}

#[test]
fn t58_heuristics_empty_data_not_obfuscated() {
    let h = DeobfHeuristics::new();
    assert!(!h.is_likely_obfuscated(&[]));
}

#[test]
fn t59_classifier_most_likely_empty_none() {
    let clf = ObfuscationClassifier::new();
    assert!(clf.most_likely().is_none());
}

#[test]
fn t60_db_round_trip_multiple() {
    let mut db = DeobfDb::new();
    for i in 0..30u64 {
        let id = format!("bin{i}");
        db.save_patches(
            id.clone(),
            vec![Patch::new(i as usize, vec![], vec![(i & 0xFF) as u8], "r")],
        );
        assert_eq!(db.patches_for(&id).len(), 1);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 21. SimpleSubstitution / StringDecryptor empty inputs
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn t61_substitution_empty_most_frequent_zero() {
    assert_eq!(SimpleSubstitution::most_frequent_byte(&[]), 0);
}

#[test]
fn t62_string_decryptor_below_min_empty() {
    let r = StringDecryptor::try_xor_constant(b"ab", 16);
    assert!(r.is_empty());
    let r = StringDecryptor::try_xor_rolling(b"ab", 16);
    assert!(r.is_empty());
}
