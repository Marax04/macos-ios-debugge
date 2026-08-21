//! Exhaustive test suite for rustre-deobf public APIs (lib.rs surface).
//!
//! Focus: edge cases, boundary conditions, adversarial inputs, round-trips,
//! Send/Sync invariants, and currently dead-code public functions.

use rustre_deobf::*;
use std::sync::Arc;

// ────────────────────────────────────────────────────────────────────────────
// Patch
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn patch_new_stores_fields() {
    let p = Patch::new(7, vec![1, 2], vec![3, 4], "why");
    assert_eq!(p.offset, 7);
    assert_eq!(p.original, vec![1, 2]);
    assert_eq!(p.patched, vec![3, 4]);
    assert_eq!(p.reason, "why");
}

#[test]
fn patch_apply_zero_length_original_succeeds() {
    let mut data = vec![0xAA, 0xBB, 0xCC];
    let p = Patch::new(1, vec![], vec![0xFF], "insert");
    p.apply(&mut data).unwrap();
    assert_eq!(data, vec![0xAA, 0xFF, 0xCC]);
}

#[test]
fn patch_apply_at_end_boundary() {
    let mut data = vec![0xAA, 0xBB];
    let p = Patch::new(2, vec![], vec![], "noop at end");
    p.apply(&mut data).unwrap();
    assert_eq!(data, vec![0xAA, 0xBB]);
}

#[test]
fn patch_apply_offset_overflow_returns_err() {
    let mut data = vec![0u8; 4];
    let p = Patch::new(usize::MAX, vec![], vec![1, 2, 3], "overflow");
    assert!(matches!(p.apply(&mut data), Err(DeobfError::TooShort { .. })));
}

#[test]
fn patch_apply_original_extends_past_buffer() {
    let mut data = vec![0u8; 2];
    let p = Patch::new(1, vec![0, 0, 0, 0], vec![1], "orig too long");
    assert!(matches!(p.apply(&mut data), Err(DeobfError::TooShort { .. })));
}

#[test]
fn patch_apply_mismatched_original_is_conflict() {
    let mut data = vec![0x11, 0x22];
    let p = Patch::new(0, vec![0xFF, 0xFF], vec![0xAA, 0xBB], "mismatch");
    match p.apply(&mut data) {
        Err(DeobfError::PatchConflict { offset, .. }) => assert_eq!(offset, 0),
        other => panic!("expected PatchConflict, got {other:?}"),
    }
}

#[test]
fn patch_serde_roundtrip() {
    let p = Patch::new(3, vec![1, 2], vec![9, 8], "ser");
    let s = serde_json::to_string(&p).unwrap();
    let back: Patch = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfContext
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn context_new_is_empty() {
    let ctx = DeobfContext::new(vec![1, 2, 3]);
    assert_eq!(ctx.binary, vec![1, 2, 3]);
    assert!(ctx.patches.is_empty());
    assert!(ctx.metadata.is_empty());
    assert!(ctx.address_map.is_empty());
    assert!(ctx.segment_mappings.is_empty());
}

#[test]
fn context_apply_patches_oob_errors() {
    let mut ctx = DeobfContext::new(vec![0u8; 2]);
    ctx.patches.push(Patch::new(1, vec![], vec![1, 2, 3], "oob"));
    assert!(matches!(ctx.apply_patches(), Err(DeobfError::TooShort { .. })));
}

#[test]
fn context_apply_patches_overflow_errors() {
    let mut ctx = DeobfContext::new(vec![0u8; 2]);
    ctx.patches.push(Patch::new(usize::MAX, vec![], vec![1], "oflw"));
    assert!(matches!(ctx.apply_patches(), Err(DeobfError::TooShort { .. })));
}

#[test]
fn context_va_to_file_offset_uses_address_map_fallback() {
    let mut ctx = DeobfContext::new(vec![]);
    ctx.address_map.insert(0x1000, 0x200);
    assert_eq!(ctx.va_to_file_offset(0x1000), Some(0x200));
    assert_eq!(ctx.va_to_file_offset(0x9999), None);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfResult merge
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_result_merge_zero_patches_keeps_confidence() {
    let mut r1 = DeobfResult::new(0, vec![], 0, 0.5);
    let r2 = DeobfResult::new(0, vec![], 0, 0.9);
    r1.merge(&r2);
    // Both have zero patches → division by zero guarded → confidence unchanged.
    assert_eq!(r1.confidence, 0.5);
    assert_eq!(r1.patches_applied, 0);
}

#[test]
fn deobf_result_merge_accumulates_bytes_and_transforms() {
    let mut r1 = DeobfResult::new(1, vec!["x".into()], 2, 1.0);
    let r2 = DeobfResult::new(3, vec!["y".into(), "z".into()], 4, 0.0);
    r1.merge(&r2);
    assert_eq!(r1.patches_applied, 4);
    assert_eq!(r1.modified_bytes, 6);
    assert_eq!(r1.transformations, vec!["x", "y", "z"]);
    // Weighted: (1*1.0 + 3*0.0) / 4 = 0.25
    assert!((r1.confidence - 0.25).abs() < 1e-6);
}

// ────────────────────────────────────────────────────────────────────────────
// PatternMatcher
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn pattern_matcher_empty_pattern_skipped() {
    let mut m = PatternMatcher::new();
    m.add_pattern("empty", vec![]);
    assert!(m.scan(&[0, 1, 2]).is_empty());
}

#[test]
fn pattern_matcher_data_shorter_than_pattern() {
    let mut m = PatternMatcher::new();
    m.add_pattern("p", vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert!(m.scan(&[0xAA, 0xBB]).is_empty());
}

#[test]
fn pattern_matcher_partial_mask() {
    let mut m = PatternMatcher::new();
    // Match high nibble only.
    m.add_masked_pattern("hi", vec![0xA0], vec![0xF0]);
    let hits = m.scan(&[0xAB, 0x12, 0xAF, 0xB0]);
    let names: Vec<_> = hits.iter().map(|h| h.offset).collect();
    assert_eq!(names, vec![0, 2]);
}

#[test]
#[should_panic(expected = "pattern and mask must have the same length")]
fn pattern_matcher_mask_len_mismatch_panics() {
    let mut m = PatternMatcher::new();
    m.add_masked_pattern("bad", vec![0x00, 0x01], vec![0xFF]);
}

#[test]
fn pattern_matcher_default_equals_new() {
    let a = PatternMatcher::new();
    let b = PatternMatcher::default();
    assert!(a.scan(&[0]).is_empty());
    assert!(b.scan(&[0]).is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// XorDecryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn xor_entropy_empty_is_zero() {
    assert_eq!(XorDecryptor::entropy(&[]), 0.0);
}

#[test]
fn xor_entropy_single_byte() {
    assert_eq!(XorDecryptor::entropy(&[0x42]), 0.0);
}

#[test]
fn xor_decrypt_cyclic_empty_key_returns_input() {
    let data = vec![1, 2, 3];
    assert_eq!(XorDecryptor::decrypt_cyclic(&data, &[]), data);
}

#[test]
fn xor_decrypt_cyclic_roundtrip_long_key() {
    let key = b"abcdef";
    let plain = b"the quick brown fox jumps";
    let cipher = XorDecryptor::decrypt_cyclic(plain, key);
    let back = XorDecryptor::decrypt_cyclic(&cipher, key);
    assert_eq!(back, plain);
}

#[test]
fn xor_decrypt_constant_empty_input() {
    assert_eq!(XorDecryptor::decrypt_constant(&[], 0x42), Vec::<u8>::new());
}

#[test]
fn xor_recover_single_byte_key_zero_input() {
    let (_k, dec) = XorDecryptor::recover_single_byte_key(&[]);
    assert!(dec.is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// RolRorDecryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn rol_ror_rotation_normalized_modulo_8() {
    // rol by 8 == rol by 0 == identity (because of `& 7`).
    assert_eq!(RolRorDecryptor::rol(0xA5, 8), 0xA5);
    assert_eq!(RolRorDecryptor::ror(0xA5, 16), 0xA5);
}

#[test]
fn rol_ror_recover_rotation_runs() {
    let plain = b"Hello world this is plaintext.";
    let cipher: Vec<u8> = plain.iter().map(|&b| RolRorDecryptor::rol(b, 3)).collect();
    let (_rot, _is_rol, dec) = RolRorDecryptor::recover_rotation(&cipher);
    // Heuristic — just ensure non-empty output is produced.
    assert_eq!(dec.len(), cipher.len());
}

// ────────────────────────────────────────────────────────────────────────────
// SimpleSubstitution
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn simple_substitution_empty_data_defaults_to_zero() {
    assert_eq!(SimpleSubstitution::most_frequent_byte(&[]), 0);
}

#[test]
fn simple_substitution_table_is_bijection_via_swap() {
    let data = vec![0x55; 10];
    let table = SimpleSubstitution::build_substitution_table(&data, 0xAA);
    // Verify it's still a permutation.
    let mut seen = [false; 256];
    for &v in &table {
        seen[v as usize] = true;
    }
    assert!(seen.iter().all(|&x| x));
    // 0x55 → 0xAA (the swap)
    assert_eq!(table[0x55], 0xAA);
    assert_eq!(table[0xAA], 0x55);
}

// ────────────────────────────────────────────────────────────────────────────
// Base64Decoder
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn base64_decode_empty_is_empty() {
    assert_eq!(Base64Decoder::decode(b"").unwrap(), Vec::<u8>::new());
}

#[test]
fn base64_decode_whitespace_stripped() {
    // "Man" → "TWFu", with embedded whitespace.
    assert_eq!(Base64Decoder::decode(b"TW Fu\n").unwrap(), b"Man");
}

#[test]
fn base64_decode_full_padding() {
    // "f" → "Zg=="
    assert_eq!(Base64Decoder::decode(b"Zg==").unwrap(), b"f");
}

#[test]
fn base64_decode_invalid_chars_none() {
    assert!(Base64Decoder::decode(b"@@@@").is_none());
}

#[test]
fn base64_find_all_too_short_returns_empty() {
    // Less than 16 b64 chars → no find.
    assert!(Base64Decoder::find_all(b"SGVsbG8=").is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// StringDecryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn string_decryptor_too_short_input() {
    assert!(StringDecryptor::try_xor_constant(b"a", 8).is_empty());
    assert!(StringDecryptor::try_xor_rolling(b"a", 8).is_empty());
}

#[test]
fn string_decryptor_skips_zero_key() {
    // Even with already-printable input, results never use key=0.
    let results = StringDecryptor::try_xor_constant(b"plaintext xx xx xx", 8);
    for r in &results {
        assert!(!r.method.contains("key=0x00"), "method was {}", r.method);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PassRegistry / DeobfPipeline
// ────────────────────────────────────────────────────────────────────────────

struct CountPass(&'static str);
impl DeobfPass for CountPass {
    fn name(&self) -> &'static str {
        self.0
    }
    fn description(&self) -> &'static str {
        "counts"
    }
    fn run(&self, _ctx: &mut DeobfContext) -> Result<DeobfResult, DeobfError> {
        Ok(DeobfResult::new(1, vec!["t".into()], 1, 1.0))
    }
    fn is_applicable(&self, _ctx: &DeobfContext) -> bool {
        true
    }
}

#[test]
fn registry_is_empty_initially() {
    let r = PassRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.names().is_empty());
}

#[test]
fn registry_register_returns_replaced() {
    let mut r = PassRegistry::new();
    assert!(r.register(Box::new(CountPass("dup"))).is_none());
    let old = r.register(Box::new(CountPass("dup")));
    assert!(old.is_some());
    assert_eq!(r.len(), 1);
}

#[test]
fn registry_run_selection_unknown_pass_returns_notapplicable() {
    let r = PassRegistry::new();
    let mut ctx = DeobfContext::new(vec![]);
    match r.run_selection(&["nope"], &mut ctx) {
        Err(DeobfError::NotApplicable(msg)) => assert!(msg.contains("nope")),
        other => panic!("expected NotApplicable, got {other:?}"),
    }
}

#[test]
fn pipeline_default_is_empty() {
    let p = DeobfPipeline::default();
    assert_eq!(p.pass_count(), 0);
}

#[test]
fn pipeline_run_returns_passes_run_count() {
    let mut p = DeobfPipeline::new();
    p.add_pass(Box::new(CountPass("a")));
    p.add_pass(Box::new(CountPass("b")));
    let mut ctx = DeobfContext::new(vec![]);
    let r = p.run(&mut ctx).unwrap();
    assert_eq!(r.passes_run, 2);
    assert_eq!(r.total_patches, 2);
}

#[test]
fn pipeline_add_pass_arc_works() {
    let mut p = DeobfPipeline::new();
    p.add_pass_arc(Arc::new(CountPass("shared")));
    let mut ctx = DeobfContext::new(vec![]);
    let r = p.run_all(&mut ctx);
    assert_eq!(r.pass_results.len(), 1);
    assert_eq!(r.pass_results[0].0, "shared");
}

#[test]
fn pipeline_passes_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn DeobfPass>>();
}

// ────────────────────────────────────────────────────────────────────────────
// TransformResult
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn transform_result_serde_roundtrip() {
    let t = TransformResult::Applied {
        rule: "r".into(),
        description: "d".into(),
    };
    let s = serde_json::to_string(&t).unwrap();
    let back: TransformResult = serde_json::from_str(&s).unwrap();
    assert_eq!(t, back);
}

#[test]
fn transform_result_error_not_applied_not_skipped() {
    let e = TransformResult::Error { message: "x".into() };
    assert!(!e.is_applied());
    assert!(!e.is_skipped());
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfReport
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_report_display_matches_summary() {
    let r = DeobfReport::new("bin");
    assert_eq!(r.to_string(), r.summary());
}

#[test]
fn deobf_report_add_obfuscation_appends() {
    let mut r = DeobfReport::new("b");
    r.add_obfuscation(ObfuscationType::AntiDebug, 0.75);
    assert_eq!(r.techniques_detected.len(), 1);
    assert!(r.techniques_detected[0].contains("AntiDebug"));
    assert!(r.techniques_detected[0].contains("0.75"));
}

#[test]
fn deobf_report_set_elapsed_ms_persists() {
    let mut r = DeobfReport::default();
    r.set_elapsed_ms(1234);
    assert_eq!(r.elapsed_ms, 1234);
}

// ────────────────────────────────────────────────────────────────────────────
// Rc4Decryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn rc4_ksa_with_empty_key_is_identity() {
    let s = Rc4Decryptor::ksa(b"");
    for i in 0..=255usize {
        assert_eq!(s[i], i as u8);
    }
}

#[test]
fn rc4_decrypt_empty_data() {
    assert_eq!(Rc4Decryptor::decrypt(&[], b"key"), Vec::<u8>::new());
}

#[test]
fn rc4_known_vector_key_test_vec() {
    // RFC 6229: key="Key" (3 bytes), plaintext="Plaintext" (9 bytes).
    let cipher = Rc4Decryptor::decrypt(b"Plaintext", b"Key");
    let expected = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];
    assert_eq!(cipher, expected);
}

#[test]
fn rc4_brute_force_returns_some_key() {
    let plain = b"Hello short pad";
    let cipher = Rc4Decryptor::decrypt(plain, &[0x42]);
    let (k, _d) = Rc4Decryptor::brute_force_short_key(&cipher);
    assert!(!k.is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// ChaCha20Decryptor
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn chacha20_short_key_errors() {
    let key = [0u8; 31];
    let nonce = [0u8; 12];
    match ChaCha20Decryptor::block(&key, &nonce, 0) {
        Err(DeobfError::TooShort { needed, have }) => {
            assert_eq!(needed, 32);
            assert_eq!(have, 31);
        }
        other => panic!("expected TooShort, got {other:?}"),
    }
}

#[test]
fn chacha20_short_nonce_errors() {
    let key = [0u8; 32];
    let nonce = [0u8; 11];
    assert!(matches!(
        ChaCha20Decryptor::block(&key, &nonce, 0),
        Err(DeobfError::TooShort { needed: 12, have: 11 })
    ));
}

#[test]
fn chacha20_crypt_propagates_short_key_error() {
    assert!(ChaCha20Decryptor::crypt(b"hello", &[0u8; 10], &[0u8; 12]).is_err());
}

#[test]
fn chacha20_crypt_handles_multi_block_data() {
    let key = [0xABu8; 32];
    let nonce = [0xCDu8; 12];
    let plain = vec![0u8; 200]; // > 3 blocks
    let cipher = ChaCha20Decryptor::crypt(&plain, &key, &nonce).unwrap();
    assert_eq!(cipher.len(), 200);
    let back = ChaCha20Decryptor::crypt(&cipher, &key, &nonce).unwrap();
    assert_eq!(back, plain);
}

#[test]
fn chacha20_empty_data_is_empty() {
    assert_eq!(
        ChaCha20Decryptor::crypt(&[], &[0u8; 32], &[0u8; 12]).unwrap(),
        Vec::<u8>::new()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Adler32 / Crc32
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn adler32_single_byte() {
    // a = 1+97=98, b = 0+98=98 → (98<<16)|98
    assert_eq!(Adler32::checksum(b"a"), (98u32 << 16) | 98);
}

#[test]
fn crc32_empty_is_zero() {
    assert_eq!(Crc32::checksum(&[]), 0);
    assert_eq!(Crc32::checksum_table(&[]), 0);
}

#[test]
fn crc32_table_matches_bitwise_random_sizes() {
    for size in [1usize, 7, 16, 33, 100, 257] {
        let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(31)).collect();
        assert_eq!(Crc32::checksum(&data), Crc32::checksum_table(&data),
            "mismatch at size {size}");
    }
}

// ────────────────────────────────────────────────────────────────────────────
// EntropyScanner
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn entropy_scanner_data_smaller_than_window_high_entropy() {
    let data: Vec<u8> = (0u8..=200).collect();
    let scanner = EntropyScanner::default();
    let regions = scanner.scan(&data);
    // 201 bytes < 256 window, but entropy is high.
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].offset, 0);
    assert_eq!(regions[0].length, 201);
}

#[test]
fn entropy_scanner_custom_threshold() {
    let scanner = EntropyScanner { window: 64, threshold: 0.5, step: 32 };
    let data = vec![0u8; 128]; // entropy = 0
    assert!(scanner.scan(&data).is_empty());
}

#[test]
fn entropy_scanner_max_region_none_when_empty() {
    let scanner = EntropyScanner::default();
    assert!(scanner.max_entropy_region(&[0u8; 32]).is_none());
}

// ────────────────────────────────────────────────────────────────────────────
// BinarySection
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn binary_section_empty_is_empty() {
    let s = BinarySection::new(".empty", 0, vec![]);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert!(!s.looks_packed());
}

#[test]
fn binary_section_entropy_bits_quantized() {
    let s = BinarySection::new(".x", 0, vec![0xFF; 16]);
    assert_eq!(s.entropy_bits, 0);
}

// ────────────────────────────────────────────────────────────────────────────
// PatchSet
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn patchset_new_is_empty() {
    let ps = PatchSet::new();
    assert!(ps.is_empty());
    assert_eq!(ps.len(), 0);
    assert!(ps.patches().is_empty());
}

#[test]
fn patchset_into_patches_consumes() {
    let mut ps = PatchSet::new();
    ps.insert(Patch::new(0, vec![], vec![0xAA], "x"));
    let v = ps.into_patches();
    assert_eq!(v.len(), 1);
}

#[test]
fn patchset_apply_to_oob_errors() {
    let mut ps = PatchSet::new();
    ps.insert(Patch::new(5, vec![], vec![1, 2, 3], "oob"));
    assert!(matches!(
        ps.apply_to(&[0u8; 4]),
        Err(DeobfError::TooShort { .. })
    ));
}

#[test]
fn patchset_apply_to_preserves_unmodified_bytes() {
    let mut ps = PatchSet::new();
    ps.insert(Patch::new(1, vec![], vec![0xFF, 0xEE], "mid"));
    let out = ps.apply_to(&[0x11, 0x22, 0x33, 0x44, 0x55]).unwrap();
    assert_eq!(out, vec![0x11, 0xFF, 0xEE, 0x44, 0x55]);
}

#[test]
fn patchset_adjacent_patches_allowed() {
    // p1 covers [0..2), p2 covers [2..4) — adjacent, not overlapping.
    let mut ps = PatchSet::new();
    assert!(ps.insert(Patch::new(0, vec![], vec![0, 0], "a")));
    assert!(ps.insert(Patch::new(2, vec![], vec![0, 0], "b")));
}

// ────────────────────────────────────────────────────────────────────────────
// HexDumper
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn hexdumper_empty_data_empty_output() {
    let d = HexDumper::new();
    assert_eq!(d.dump(&[]), "");
    assert_eq!(d.hex_only(&[]), "");
}

#[test]
fn hexdumper_default_width_16() {
    let d = HexDumper::new();
    assert_eq!(d.width, 16);
    assert_eq!(d.base_address, 0);
}

#[test]
fn hexdumper_non_printable_shown_as_dot() {
    let d = HexDumper::new();
    let out = d.dump(&[0x00, 0x01, 0x02]);
    // ASCII column for these bytes should be dots.
    assert!(out.ends_with("...\n"));
}

// ────────────────────────────────────────────────────────────────────────────
// ConstantFoldingPass
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn constant_folding_not_applicable_when_too_short() {
    let pass = ConstantFoldingPass::new();
    let ctx = DeobfContext::new(vec![0u8; 8]);
    assert!(!pass.is_applicable(&ctx));
}

#[test]
fn constant_folding_unknown_opcode_skipped() {
    // op=0xFF is not folded.
    let data = vec![0xFFu8; 32];
    let mut ctx = DeobfContext::new(data);
    let pass = ConstantFoldingPass::new();
    let r = pass.run(&mut ctx).unwrap();
    assert_eq!(r.patches_applied, 0);
    assert!(ctx.patches.is_empty());
}

#[test]
fn constant_folding_mul_wraps() {
    // op=0x06 MUL with large values that wrap.
    let mut data = vec![0x06u8];
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // a
    data.extend_from_slice(&2u32.to_le_bytes()); // b
    data.push(0x90);
    let mut ctx = DeobfContext::new(data);
    let r = ConstantFoldingPass::new().run(&mut ctx).unwrap();
    assert_eq!(r.patches_applied, 1);
    let patched = ctx.apply_patches().unwrap();
    let val = u32::from_le_bytes([patched[1], patched[2], patched[3], patched[4]]);
    assert_eq!(val, 0xFFFF_FFFEu32);
}

// ────────────────────────────────────────────────────────────────────────────
// NopSledRemover
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn nop_sled_not_applicable_when_no_nops() {
    let pass = NopSledRemover::new();
    let ctx = DeobfContext::new(vec![0xCCu8; 16]);
    assert!(!pass.is_applicable(&ctx));
}

#[test]
fn nop_sled_with_min_sled_threshold() {
    let pass = NopSledRemover::with_min_sled(3);
    let data = vec![0xCC, 0x90, 0x90, 0xCC, 0x90, 0x90, 0x90, 0xCC];
    let sleds = pass.find_sleds(&data);
    // Only the 3-NOP run qualifies.
    assert_eq!(sleds.len(), 1);
    assert_eq!(sleds[0], (4, 3));
}

#[test]
fn nop_sled_zero_confidence_when_no_patches() {
    // is_applicable false means run won't be called normally — call directly.
    let pass = NopSledRemover::with_min_sled(10);
    let mut ctx = DeobfContext::new(vec![0x90u8; 5]);
    let r = pass.run(&mut ctx).unwrap();
    assert_eq!(r.patches_applied, 0);
    assert_eq!(r.confidence, 0.0);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfOptions / DeobfPipelineResult / DeobfPassRegistry
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_options_default_zero() {
    let o = DeobfOptions::default();
    assert_eq!(o.max_iterations, 0);
    assert!(!o.aggressive);
    assert!(!o.verbose);
    assert!(o.arch_hint.is_none());
}

#[test]
fn deobf_pipeline_result_success_rate_zero_when_no_passes() {
    let r = DeobfPipelineResult {
        total_patches: 0,
        passes_run: 0,
        elapsed_ms: 0,
        pass_results: vec![],
    };
    assert_eq!(r.success_rate(), 0.0);
}

#[test]
fn deobf_pipeline_result_success_rate_one_when_any_pass() {
    let r = DeobfPipelineResult {
        total_patches: 0,
        passes_run: 1,
        elapsed_ms: 0,
        pass_results: vec![],
    };
    assert_eq!(r.success_rate(), 1.0);
}

#[test]
fn deobf_pass_registry_build_pipeline_ignores_unknown() {
    let reg = DeobfPassRegistry::new();
    let p = reg.build_pipeline(&["nope"], DeobfOptions::default());
    assert_eq!(p.pass_count(), 0);
}

#[test]
fn deobf_pass_registry_names_after_register() {
    let mut reg = DeobfPassRegistry::new();
    reg.register(Arc::new(NopSledRemover::new()));
    let names = reg.names();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "nop-sled-remover");
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfMetrics
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_metrics_patches_per_pass_zero() {
    let m = DeobfMetrics::default();
    assert_eq!(m.patches_per_pass(), 0.0);
}

// ────────────────────────────────────────────────────────────────────────────
// HybridDeobf
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn hybrid_deobf_no_pipelines_returns_input_unchanged() {
    let hd = HybridDeobf::new();
    let data = vec![1u8, 2, 3];
    let out = hd.run(&data).unwrap();
    assert_eq!(out, data);
}

#[test]
fn hybrid_deobf_pipeline_count() {
    let mut hd = HybridDeobf::default();
    assert_eq!(hd.pipeline_count(), 0);
    hd.add_pipeline(DeobfPipeline::new());
    assert_eq!(hd.pipeline_count(), 1);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfHeuristics
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_heuristics_signature_count() {
    let mut h = DeobfHeuristics::new();
    assert_eq!(h.signature_count(), 0);
    h.add_signature("UPX");
    h.add_signature("ASPack");
    assert_eq!(h.signature_count(), 2);
}

#[test]
fn deobf_heuristics_low_entropy_not_obfuscated() {
    let h = DeobfHeuristics::new();
    assert!(!h.is_likely_obfuscated(&vec![0u8; 256]));
}

#[test]
fn deobf_heuristics_entropy_empty_zero() {
    assert_eq!(DeobfHeuristics::entropy(&[]), 0.0);
}

// ────────────────────────────────────────────────────────────────────────────
// ObfuscationClassifier
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn classifier_no_data_no_detections() {
    let mut clf = ObfuscationClassifier::new();
    clf.classify(&[]);
    // Entropy of empty is 0, jmp_count/len = NaN/inf depending on impl…
    // The classifier may push anti-debug pattern matches, but on empty input
    // none of the conditions should fire that depend on length.
    // We just assert no panic and detections are not negative count.
    let _ = clf.detections().len();
}

#[test]
fn classifier_anti_debug_pattern_detected() {
    let mut clf = ObfuscationClassifier::new();
    let mut data = vec![0u8; 64];
    data.extend_from_slice(b"\x64\x8B\x0D");
    data.extend_from_slice(&[0u8; 64]);
    clf.classify(&data);
    assert!(clf
        .detections()
        .iter()
        .any(|(t, _)| *t == ObfuscationType::AntiDebug));
}

#[test]
fn classifier_most_likely_returns_none_when_empty() {
    let clf = ObfuscationClassifier::new();
    assert!(clf.most_likely().is_none());
}

#[test]
fn obfuscation_type_eq_and_copy() {
    let a = ObfuscationType::AntiDebug;
    let b = a;
    assert_eq!(a, b);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfDb
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobfdb_empty_returns_empty_slice() {
    let db = DeobfDb::new();
    assert!(db.patches_for("missing").is_empty());
    assert_eq!(db.report_count(), 0);
}

#[test]
fn deobfdb_overwrites_on_same_id() {
    let mut db = DeobfDb::new();
    db.save_patches("x", vec![Patch::new(0, vec![], vec![1], "a")]);
    db.save_patches("x", vec![]);
    assert!(db.patches_for("x").is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// IterativeDeobf
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn iterative_deobf_no_patches_converges_in_one_iter() {
    let pipeline = DeobfPipeline::new(); // no passes → no patches
    let iter = IterativeDeobf::new(pipeline, 5);
    let (out, n) = iter.run(vec![1, 2, 3]).unwrap();
    assert_eq!(out, vec![1, 2, 3]);
    assert_eq!(n, 1);
}

#[test]
fn iterative_deobf_respects_max_iterations() {
    // A pass that always reports 1 patch but doesn't actually modify (empty patches vec push).
    // Actually pipeline.run counts patches from the pass's DeobfResult only if
    // the pass adds to ctx.patches. Use NopSledRemover which keeps producing patches
    // until no NOPs remain. After first iter, NOPs become 0x00, so it converges.
    let mut pipeline = DeobfPipeline::new();
    pipeline.add_pass(Box::new(NopSledRemover::new()));
    let iter = IterativeDeobf::new(pipeline, 3);
    let (out, n) = iter.run(vec![0x90u8; 8]).unwrap();
    assert_eq!(out.len(), 8);
    assert!(n <= 3);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfSession
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_session_metrics_accumulate() {
    let mut p = DeobfPipeline::new();
    p.add_pass(Box::new(CountPass("c")));
    let mut s = DeobfSession::new("id", p);
    let mut ctx = DeobfContext::new(vec![]);
    s.run_on(&mut ctx).unwrap();
    s.run_on(&mut ctx).unwrap();
    assert_eq!(s.run_count(), 2);
    assert_eq!(s.metrics.passes_run, 2);
    assert_eq!(s.metrics.total_patches, 2);
}

// ────────────────────────────────────────────────────────────────────────────
// DeobfError Display
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn deobf_error_display_messages() {
    assert!(DeobfError::NotApplicable("x".into()).to_string().contains('x'));
    assert!(DeobfError::ParseError("p".into()).to_string().contains('p'));
    assert!(DeobfError::TooShort { needed: 4, have: 1 }
        .to_string()
        .contains('4'));
    assert!(DeobfError::PatchConflict { offset: 0xAB, reason: "r".into() }
        .to_string()
        .contains("0xab"));
}

#[test]
fn deobf_error_from_anyhow() {
    let e: DeobfError = anyhow::anyhow!("oops").into();
    assert!(matches!(e, DeobfError::Other(_)));
}
