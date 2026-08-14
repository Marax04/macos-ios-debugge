//! Deep adversarial coverage for rustre-deobf-smc public API.
//!
//! All randomness uses a seeded LCG.  Tests cover round-trip properties,
//! boundaries, fuzz inputs, hash/eq consistency, serialization, threading.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use rustre_deobf::{DeobfContext, DeobfError, DeobfPass, Patch};
use rustre_deobf_smc::*;

fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn lcg_bytes(n: usize) -> Vec<u8> {
    let mut g = make_lcg();
    (0..n).map(|_| (g() >> 24) as u8).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcDecryptor — algorithm round-trips
// ─────────────────────────────────────────────────────────────────────────────

const fn region_with(key: u64, algo: SmcAlgorithm, len: u64) -> SmcRegion {
    SmcRegion {
        start: 0,
        end: len,
        decryptor_addr: 0,
        key: SmcKey::Constant(key),
        algorithm: algo,
    }
}

#[test]
fn xor_decrypt_50_seeded_inputs() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let key = (g() & 0xFF) as u8;
        let len = ((g() % 256) as usize) + 1;
        let plain: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let cipher: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let region = region_with(u64::from(key), SmcAlgorithm::Xor, len as u64);
        let dec = SmcDecryptor::new().decrypt(&cipher, &region);
        assert_eq!(dec, plain);
    }
}

#[test]
fn add_sub_decrypt_inverse_50_inputs() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let key = (g() & 0xFF) as u8;
        let len = ((g() % 64) as usize) + 1;
        let plain: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();

        // Encrypt with "Add": cipher = plain + key.
        let cipher: Vec<u8> = plain.iter().map(|&b| b.wrapping_add(key)).collect();
        let region = region_with(u64::from(key), SmcAlgorithm::Add, len as u64);
        assert_eq!(SmcDecryptor::new().decrypt(&cipher, &region), plain);

        // Encrypt with "Sub": cipher = plain - key.
        let cipher2: Vec<u8> = plain.iter().map(|&b| b.wrapping_sub(key)).collect();
        let region2 = region_with(u64::from(key), SmcAlgorithm::Sub, len as u64);
        assert_eq!(SmcDecryptor::new().decrypt(&cipher2, &region2), plain);
    }
}

#[test]
fn xor_rolling_decrypt_50_inputs() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let key = (g() & 0xFF) as u8;
        let len = ((g() % 64) as usize) + 1;
        let plain: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let mut prev = key;
        let cipher: Vec<u8> = plain
            .iter()
            .map(|&p| {
                let c = p ^ prev;
                prev = c;
                c
            })
            .collect();
        let region = region_with(u64::from(key), SmcAlgorithm::XorRolling, len as u64);
        assert_eq!(SmcDecryptor::new().decrypt(&cipher, &region), plain);
    }
}

#[test]
fn decryptor_empty_input_returns_empty() {
    for algo in [
        SmcAlgorithm::Xor,
        SmcAlgorithm::Add,
        SmcAlgorithm::Sub,
        SmcAlgorithm::Rol,
        SmcAlgorithm::Ror,
        SmcAlgorithm::XorRolling,
        SmcAlgorithm::AddRolling,
        SmcAlgorithm::Custom(vec![0x01, 0x02]),
    ] {
        let region = region_with(0x42, algo, 0);
        let out = SmcDecryptor::new().decrypt(&[], &region);
        assert!(out.is_empty());
    }
}

#[test]
fn decryptor_xor_key_zero_is_identity() {
    let data = lcg_bytes(64);
    let region = region_with(0, SmcAlgorithm::Xor, data.len() as u64);
    assert_eq!(SmcDecryptor::new().decrypt(&data, &region), data);
}

#[test]
fn decryptor_derived_key_uses_zero() {
    let data = vec![0xAAu8, 0xBB, 0xCC];
    let region = SmcRegion {
        start: 0,
        end: 3,
        decryptor_addr: 0,
        key: SmcKey::Derived,
        algorithm: SmcAlgorithm::Xor,
    };
    // Derived key falls back to 0x00 — XOR with 0 is identity.
    assert_eq!(SmcDecryptor::new().decrypt(&data, &region), data);
}

#[test]
fn decryptor_custom_unknown_op_leaves_byte_unchanged() {
    let ops = vec![0xFFu8, 0x10]; // unknown opcode
    let region = SmcRegion {
        start: 0,
        end: 4,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Custom(ops),
    };
    let data = vec![0x11u8, 0x22, 0x33, 0x44];
    assert_eq!(SmcDecryptor::new().decrypt(&data, &region), data);
}

#[test]
fn decryptor_custom_odd_length_ignored() {
    let ops = vec![0x01u8]; // truncated: no arg byte
    let region = SmcRegion {
        start: 0,
        end: 2,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Custom(ops),
    };
    let data = vec![0xAAu8, 0xBB];
    assert_eq!(SmcDecryptor::new().decrypt(&data, &region), data);
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcRegion — boundary
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn region_len_zero_and_max() {
    let r0 = SmcRegion {
        start: 0,
        end: 0,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    assert!(r0.is_empty());
    assert_eq!(r0.len(), 0);

    // start > end uses saturating subtraction → 0
    let r_invert = SmcRegion {
        start: 100,
        end: 50,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    assert_eq!(r_invert.len(), 0);

    let r_max = SmcRegion {
        start: 0,
        end: u64::MAX,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    assert_eq!(r_max.len(), u64::MAX);
    assert!(!r_max.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcDetector — fuzz, truncation, boundary
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 600) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = SmcDetector::new().detect(&data);
    }
}

#[test]
fn detector_empty_returns_empty() {
    assert!(SmcDetector::new().detect(&[]).is_empty());
    assert!(SmcDetector::new().detect(&[0x90]).is_empty());
    assert!(SmcDetector::new().detect(&[0u8; 4]).is_empty());
}

#[test]
fn detector_truncated_just_below_threshold_no_panic() {
    for n in 0..13 {
        let data = vec![0xB9u8; n];
        let _ = SmcDetector::new().detect(&data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcPatcher — bounds and round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn patcher_zero_length_region_succeeds() {
    let region = SmcRegion {
        start: 0,
        end: 0,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    let patches = SmcPatcher::new().build_patches(&[0u8; 4], &region, 0).unwrap();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].patched.is_empty());
}

#[test]
fn patcher_offset_at_end_with_empty_region() {
    let region = SmcRegion {
        start: 0,
        end: 0,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    let data = vec![0u8; 4];
    // Offset at very end with zero size is valid.
    assert!(SmcPatcher::new().build_patches(&data, &region, 4).is_ok());
}

#[test]
fn patcher_offset_past_end_errors() {
    let region = SmcRegion {
        start: 0,
        end: 1,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: SmcAlgorithm::Xor,
    };
    let data = vec![0u8; 4];
    assert!(matches!(
        SmcPatcher::new().build_patches(&data, &region, 4),
        Err(DeobfError::TooShort { .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// LayeredSmc
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn layered_smc_terminates_within_max_layers() {
    let mut g = make_lcg();
    let data: Vec<u8> = (0..1024).map(|_| (g() & 0xFF) as u8).collect();
    let (out, layers) = LayeredSmc::new(3).decrypt_all(&data);
    assert_eq!(out.len(), data.len());
    assert!(layers <= 3);
}

#[test]
fn layered_smc_zero_max_layers() {
    let data = vec![0x90u8; 32];
    let (_, layers) = LayeredSmc::new(0).decrypt_all(&data);
    assert_eq!(layers, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuRegisters
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn emu_registers_wraps_at_16() {
    let mut r = EmuRegisters::default();
    r.write(0, 0xAAAA);
    r.write(16, 0xBBBB); // same as index 0
    assert_eq!(r.read(0), 0xBBBB);
    r.write(255, 0xCCCC); // 255 & 15 == 15
    assert_eq!(r.read(15), 0xCCCC);
}

// ─────────────────────────────────────────────────────────────────────────────
// EmulatedDecrypt
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn emulated_decrypt_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 128) as usize;
        let code: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = EmulatedDecrypt::new().trace(&code, 32);
    }
}

#[test]
fn emulated_decrypt_zero_max_iter() {
    let code = vec![0x80, 0x31, 0x99];
    let tr = EmulatedDecrypt::new().trace(&code, 0);
    // Loops counted only via JNZ; non-loop steps still proceed.
    assert_eq!(tr.iterations, 0);
}

#[test]
fn emulated_decrypt_empty_code() {
    let tr = EmulatedDecrypt::new().trace(&[], 16);
    assert_eq!(tr.iterations, 0);
    assert_eq!(tr.recovered_key, 0);
}

#[test]
fn emulated_decrypt_sub_records_key() {
    // SUB [mem], imm8 form: 80 28 imm8
    let code = vec![0x80, 0x28, 0x77];
    let tr = EmulatedDecrypt::new().trace(&code, 8);
    assert_eq!(tr.recovered_key, 0x77);
    assert!(matches!(tr.algorithm, SmcAlgorithm::Sub));
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcPass
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn smc_pass_name_description() {
    let p = SmcPass::new();
    assert_eq!(p.name(), "smc-deobf");
    assert!(!p.description().is_empty());
}

#[test]
fn smc_pass_applicable_boundary() {
    let p = SmcPass::new();
    // exactly 16 = applicable
    assert!(p.is_applicable(&DeobfContext::new(vec![0u8; 16])));
    assert!(!p.is_applicable(&DeobfContext::new(vec![0u8; 15])));
}

// ─────────────────────────────────────────────────────────────────────────────
// DynamicSmcDetector + Reconstructor
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dynamic_detector_to_memory_map_last_write_wins() {
    let mut d = DynamicSmcDetector::new();
    d.add_write(1, 0x100, 0xAA);
    d.add_write(2, 0x100, 0xBB);
    let m = d.to_memory_map();
    assert_eq!(m.get(&0x100), Some(&0xBB));
    assert_eq!(d.events().len(), 2);
}

#[test]
fn dynamic_reconstructor_overflow_at_u64_max() {
    let mut m = HashMap::new();
    m.insert(u64::MAX, 0xAB);
    let rec = DynamicSmcReconstructor::new(m);
    let out = rec.reconstruct(u64::MAX - 2, &[1, 2, 3, 4, 5]);
    // base+0=MAX-2, base+1=MAX-1, base+2=MAX (→0xAB), base+3 would overflow → stop
    assert_eq!(out[0], 1);
    assert_eq!(out[1], 2);
    assert_eq!(out[2], 0xAB);
}

// ─────────────────────────────────────────────────────────────────────────────
// PolymorphicEngineAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn polymorph_analyze_no_panic_on_unequal_lengths() {
    let a = vec![0x90u8; 32];
    let b = vec![0x40u8; 8];
    let _ = PolymorphicEngineAnalyzer::new().analyze(&a, &b);
    let _ = PolymorphicEngineAnalyzer::new().analyze(&b, &a);
}

#[test]
fn polymorph_analyze_fuzz() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 128) as usize;
        let a: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let b: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = PolymorphicEngineAnalyzer::new().analyze(&a, &b);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeMutationTracker
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mutation_tracker_snapshot_indexing() {
    let t = CodeMutationTracker::new(vec![1u8, 2, 3]);
    assert_eq!(t.snapshot(0), Some(&[1u8, 2, 3][..]));
    assert!(t.snapshot(5).is_none());
    assert_eq!(t.generation_count(), 1);
}

#[test]
fn mutation_tracker_mutations_out_of_range_empty() {
    let t = CodeMutationTracker::new(vec![0u8; 4]);
    assert!(t.mutations_at(99).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// shannon_entropy + looks_like_code
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn shannon_entropy_within_bounds() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() % 512) as usize) + 1;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let h = shannon_entropy(&data);
        assert!((0.0..=8.0 + 1e-9).contains(&h), "h={h}");
    }
}

#[test]
fn looks_like_code_empty_false() {
    assert!(!looks_like_code(&[]));
}

// ─────────────────────────────────────────────────────────────────────────────
// UnpackedRegionDetector
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unpacked_region_detector_input_shorter_than_window() {
    let det = UnpackedRegionDetector::new(256, 6.0);
    let regions = det.detect(&[0x90u8; 128]);
    assert!(regions.is_empty());
}

#[test]
fn unpacked_region_detector_fuzz() {
    let mut g = make_lcg();
    for _ in 0..20 {
        let n = (g() % 1024) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = UnpackedRegionDetector::default().detect(&data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XorChainStep / XorChain — round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xor_chain_step_50_seeded_round_trips() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let step = XorChainStep {
            key: (g() & 0xFF) as u8,
            pre_op: (g() % 4) as u8,
            rot_amount: (g() & 7) as u8,
        };
        let b = (g() & 0xFF) as u8;
        assert_eq!(step.reverse(step.apply(b)), b);
    }
}

#[test]
fn xor_chain_50_round_trips() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let mut chain = XorChain::new();
        let steps = (g() % 5) + 1;
        for _ in 0..steps {
            chain.push(XorChainStep {
                key: (g() & 0xFF) as u8,
                pre_op: (g() % 4) as u8,
                rot_amount: (g() & 7) as u8,
            });
        }
        let n = ((g() % 64) as usize) + 1;
        let plain: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let cipher = chain.encrypt(&plain);
        let back = chain.decrypt(&cipher);
        assert_eq!(back, plain);
    }
}

#[test]
fn xor_chain_detector_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 256) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = XorChainDetector::new().detect(&data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AddRolCipher
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn add_rol_cipher_50_round_trips() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let cipher = AddRolCipher::new(
            (g() & 0xFF) as u8,
            (g() & 7) as u8,
            (g() & 1) == 0,
        );
        let n = ((g() % 64) as usize) + 1;
        let plain: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let enc = cipher.encrypt(&plain);
        let dec = cipher.decrypt(&enc);
        assert_eq!(dec, plain);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcStats
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn smc_stats_counts_each_algo() {
    let mk = |a: SmcAlgorithm| SmcRegion {
        start: 0,
        end: 16,
        decryptor_addr: 0,
        key: SmcKey::Constant(0),
        algorithm: a,
    };
    let regions = vec![
        mk(SmcAlgorithm::Xor),
        mk(SmcAlgorithm::Add),
        mk(SmcAlgorithm::Rol),
        mk(SmcAlgorithm::Ror),
        mk(SmcAlgorithm::XorRolling),
        mk(SmcAlgorithm::AddRolling),
        SmcRegion {
            start: 0,
            end: 16,
            decryptor_addr: 0,
            key: SmcKey::Derived,
            algorithm: SmcAlgorithm::Xor,
        },
    ];
    let s = SmcStats::from_regions(&regions);
    assert_eq!(s.regions_detected, 7);
    assert_eq!(s.regions_decrypted, 7);
    assert_eq!(s.xor_count, 2);
    assert_eq!(s.add_count, 1);
    assert_eq!(s.rol_count, 2);
    assert_eq!(s.rolling_count, 2);
    assert_eq!(s.derived_key_count, 1);
    assert_eq!(s.bytes_decrypted, 16 * 7);
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcBinaryPatcher
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn binary_patcher_ordered_application_last_overlap_wins() {
    let mut p = SmcBinaryPatcher::new();
    p.add_patch(Patch::new(0, vec![0u8; 4], vec![0x11; 4], "a".to_string()));
    p.add_patch(Patch::new(2, vec![0u8; 2], vec![0x22; 2], "b".to_string()));
    let out = p.apply(&[0u8; 4]).unwrap();
    // Second patch is at higher offset so it applies after the first.
    assert_eq!(out, vec![0x11, 0x11, 0x22, 0x22]);
}

#[test]
fn binary_patcher_count() {
    let mut p = SmcBinaryPatcher::new();
    assert_eq!(p.patch_count(), 0);
    p.add_patch(Patch::new(0, vec![0u8; 1], vec![1u8], "x".to_string()));
    assert_eq!(p.patch_count(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteExecuteDetector
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn write_execute_detector_size_zero_treated_as_1() {
    let mut d = WriteExecuteDetector::new();
    d.add_write(0x1000, 0x2000, 0);
    d.add_execution(0x1010, 0x2000);
    let pairs = d.find_write_then_execute();
    assert_eq!(pairs.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcKey / SmcAlgorithm — Hash/Eq consistency (Eq only; verify equality pairs)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn smc_key_eq_consistency_30_pairs() {
    let mut g = make_lcg();
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..30 {
        let v = g();
        let a = SmcKey::Constant(v);
        let b = SmcKey::Constant(v);
        let c = SmcKey::Constant(v.wrapping_add(1));
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Display-ish via Debug: ensure deterministic
        let s = format!("{a:?}");
        seen.insert(s);
    }
    assert!(!seen.is_empty());
}

#[test]
fn smc_algorithm_eq_consistency() {
    let pairs = [
        (SmcAlgorithm::Xor, SmcAlgorithm::Xor, true),
        (SmcAlgorithm::Xor, SmcAlgorithm::Add, false),
        (SmcAlgorithm::Custom(vec![1, 2]), SmcAlgorithm::Custom(vec![1, 2]), true),
        (SmcAlgorithm::Custom(vec![1, 2]), SmcAlgorithm::Custom(vec![1, 3]), false),
        (SmcAlgorithm::Rol, SmcAlgorithm::Ror, false),
        (SmcAlgorithm::AddRolling, SmcAlgorithm::AddRolling, true),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq, "comparing {a:?} == {b:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialization round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn serde_round_trip_region_and_report() {
    let region = SmcRegion {
        start: 0x1000,
        end: 0x2000,
        decryptor_addr: 0x500,
        key: SmcKey::FromRegister("EAX".to_string()),
        algorithm: SmcAlgorithm::Custom(vec![0x01, 0x02]),
    };
    let j = serde_json::to_string(&region).unwrap();
    let r2: SmcRegion = serde_json::from_str(&j).unwrap();
    assert_eq!(r2.start, region.start);
    assert_eq!(r2.end, region.end);
    assert_eq!(r2.key, region.key);
    assert_eq!(r2.algorithm, region.algorithm);

    let stats = SmcStats::from_regions(&[region]);
    let j2 = serde_json::to_string(&stats).unwrap();
    let _: SmcStats = serde_json::from_str(&j2).unwrap();
}

#[test]
fn serde_round_trip_xor_chain() {
    let mut chain = XorChain::new();
    chain.push(XorChainStep { key: 1, pre_op: 2, rot_amount: 3 });
    chain.push(XorChainStep { key: 4, pre_op: 0, rot_amount: 0 });
    let j = serde_json::to_string(&chain).unwrap();
    let c2: XorChain = serde_json::from_str(&j).unwrap();
    assert_eq!(c2.len(), 2);
    assert_eq!(c2.steps[0].key, 1);
}

#[test]
fn serde_round_trip_smc_kind_indicator() {
    for kind in [
        SmcKind::WriteToCodeSection,
        SmcKind::VirtualProtectRwx,
        SmcKind::UnpackLoop,
        SmcKind::DecryptionRoutine,
        SmcKind::SelfPatch,
    ] {
        let ind = SmcIndicator::new(42, kind.clone(), 0.5);
        let j = serde_json::to_string(&ind).unwrap();
        let i2: SmcIndicator = serde_json::from_str(&j).unwrap();
        assert_eq!(i2.kind, kind);
        assert_eq!(i2.offset, 42);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcIndicator confidence clamp
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn indicator_clamp_extremes() {
    // f32::clamp(NaN, lo, hi) returns NaN by definition; only check finite inputs.
    let i = SmcIndicator::new(0, SmcKind::SelfPatch, f32::INFINITY);
    assert!(i.confidence <= 1.0);
    let i2 = SmcIndicator::new(0, SmcKind::SelfPatch, f32::NEG_INFINITY);
    assert!(i2.confidence >= 0.0);
    let i3 = SmcIndicator::new(0, SmcKind::SelfPatch, 2.0);
    assert_eq!(i3.confidence, 1.0);
    let i4 = SmcIndicator::new(0, SmcKind::SelfPatch, -1.0);
    assert_eq!(i4.confidence, 0.0);
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_smc_indicators — fuzz
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detect_smc_indicators_fuzz_no_panic() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = (g() % 512) as usize;
        let data: Vec<u8> = (0..n).map(|_| (g() & 0xFF) as u8).collect();
        let _ = detect_smc_indicators(&data);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceWriteEvent / Timeline
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trace_write_event_target_end_overflow_saturates() {
    let ev = TraceWriteEvent::new(0, 0, u64::MAX - 1, 0, vec![0u8; 4], None);
    // saturating add → u64::MAX
    assert_eq!(ev.target_end(), u64::MAX);
}

#[test]
fn timeline_snapshot_at_or_before_unsorted() {
    let mut tl = CodeGenerationTimeline::new();
    tl.add_snapshot(200, vec![0x22]);
    tl.add_snapshot(100, vec![0x11]);
    tl.sort_by_time();
    let s = tl.snapshot_at_or_before(150).unwrap();
    assert_eq!(s.0, 100);
    let s2 = tl.snapshot_at_or_before(50);
    assert!(s2.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcAnalyzer::identify_stages — boundary at exactly STAGE_GAP_THRESHOLD_MS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn identify_stages_gap_exactly_threshold_stays_single() {
    let mut tl = CodeGenerationTimeline::new();
    tl.add_event(TraceWriteEvent::new(0, 0, 0x1000, 0, vec![1], None));
    // gap == THRESHOLD is NOT a new stage (only gap > THRESHOLD splits).
    tl.add_event(TraceWriteEvent::new(
        STAGE_GAP_THRESHOLD_MS,
        0,
        0x1004,
        0,
        vec![1],
        None,
    ));
    let stages = SmcAnalyzer::identify_stages(&tl);
    assert_eq!(stages.len(), 1);
}

#[test]
fn identify_stages_gap_threshold_plus_one_splits() {
    let mut tl = CodeGenerationTimeline::new();
    tl.add_event(TraceWriteEvent::new(0, 0, 0x1000, 0, vec![1], None));
    tl.add_event(TraceWriteEvent::new(
        STAGE_GAP_THRESHOLD_MS + 1,
        0,
        0x1004,
        0,
        vec![1],
        None,
    ));
    let stages = SmcAnalyzer::identify_stages(&tl);
    assert_eq!(stages.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Send/Sync threaded stress
// ─────────────────────────────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<SmcDecryptor>();
    assert_send_sync::<SmcDetector>();
    assert_send_sync::<SmcPatcher>();
    assert_send_sync::<LayeredSmc>();
    assert_send_sync::<EmulatedDecrypt>();
    assert_send_sync::<XorChainDetector>();
    assert_send_sync::<AddRolCipher>();
    assert_send_sync::<PolymorphicEngineAnalyzer>();
    assert_send_sync::<SmcAnalyzer>();
    assert_send_sync::<MockSmcTracer>();
    assert_send_sync::<SmcKey>();
    assert_send_sync::<SmcAlgorithm>();
}

#[test]
fn threaded_decrypt_4x100_ops() {
    let decryptor = Arc::new(SmcDecryptor::new());
    let region = Arc::new(region_with(0x42, SmcAlgorithm::Xor, 16));
    let mut handles = vec![];
    for tid in 0..4u64 {
        let d = Arc::clone(&decryptor);
        let r = Arc::clone(&region);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let v = (tid.wrapping_mul(31).wrapping_add(i)) as u8;
                let plain = vec![v; 16];
                let cipher: Vec<u8> = plain.iter().map(|&b| b ^ 0x42).collect();
                let dec = d.decrypt(&cipher, &r);
                assert_eq!(dec, plain);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_detector_4x100_ops() {
    let data = Arc::new(lcg_bytes(256));
    let mut handles = vec![];
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let det = SmcDetector::new();
            for _ in 0..100 {
                let _ = det.detect(&d);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_xor_chain_4x100_round_trips() {
    let mut chain = XorChain::new();
    chain.push(XorChainStep { key: 0x33, pre_op: 0, rot_amount: 0 });
    chain.push(XorChainStep { key: 0x77, pre_op: 2, rot_amount: 3 });
    let chain = Arc::new(chain);
    let mut handles = vec![];
    for tid in 0..4u64 {
        let c = Arc::clone(&chain);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let v = (tid.wrapping_mul(91).wrapping_add(i)) as u8;
                let plain = vec![v; 32];
                let enc = c.encrypt(&plain);
                let dec = c.decrypt(&enc);
                assert_eq!(dec, plain);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
