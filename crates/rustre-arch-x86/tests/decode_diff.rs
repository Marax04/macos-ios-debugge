//! Differential + property-based robustness tests for the x86 decoder and
//! length scanner, using iced-x86 as the oracle.
//!
//! Invariants tested:
//!   1. Decoding/lifting/length-scanning arbitrary bytes must NEVER panic.
//!   2. Whenever iced-x86 decodes a valid instruction at the start of a buffer
//!      AND our `instr_length` returns `Ok(n)`, `n == iced.len()`.
//!      (Our scanner is known-incomplete — table gaps yield `UnknownOpcode` —
//!      so we never assert that it must succeed, only that when it does it
//!      must agree.)
//!   3. A curated corpus of tricky encodings has locked-in expected lengths.
//!
//! Exclusions (documented, intentional):
//!   * 16-bit *addressing* forms (bits==16 without 0x67, or bits!=64 with
//!     0x67): the length scanner's ModRM/SIB model is 32/64-bit only; 16-bit
//!     ModRM has a different displacement table (mod=00/rm=6 => disp16, no
//!     SIB). The scanner is not specified for these and the pre-existing
//!     blitz suite excludes them too.
//!
//! TODO(second oracle): yaxpeax-x86 is NOT currently in the workspace
//! Cargo.lock (only yaxpeax-arm is, via the ARM crate). Per policy we do not
//! add a heavy new dev-dependency just for cross-checking; if yaxpeax-x86
//! ever enters the workspace, add a third-way mnemonic/length agreement test
//! here (iced vs yaxpeax vs instr_length).
//
// DECODER DISAGREEMENT allowlist
// ------------------------------
// Genuine `instr_length` vs iced-x86 divergences found by this suite are
// recorded in `known_divergence` below (exact bytes + mode + both lengths)
// so the bugs stay visible while the suite stays green. See that function
// for the current list (empty means no known divergences at HEAD).

use iced_x86::{Decoder, DecoderOptions};
use proptest::prelude::*;
use rustre_arch_x86::length::instr_length;
use rustre_arch_x86::{X86Arch, X86LiftAdapter, lift_to_llil_with_bits};
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Deterministic LCG (same constants as tests/blitz.rs and src/length.rs).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

/// Returns true when the effective *address size* is 16-bit, which the length
/// scanner's ModRM/SIB model intentionally does not cover (see module docs).
fn excluded_16bit_addressing(bytes: &[u8], bits: u32) -> bool {
    let ps = rustre_arch_x86::prefix::PrefixSet::consume(bytes, bits == 64);
    if bytes.get(ps.count).is_none() {
        return true; // prefix-only stream, nothing to compare
    }
    match bits {
        64 => false,
        32 => ps.addr_size,  // 0x67 in 32-bit mode => 16-bit addressing
        _ => !ps.addr_size,  // 16-bit mode default addressing is 16-bit
    }
}

/// Explicit allowlist of known real divergences between `instr_length` and
/// iced-x86. Each entry documents a decoder bug that must not be hidden.
/// Format: (mode bits, instruction bytes exactly as iced consumed them).
fn known_divergence(iced_bytes: &[u8], bits: u32) -> bool {
    const KNOWN: &[(u32, &[u8])] = &[
        // (none currently known)
    ];
    KNOWN
        .iter()
        .any(|&(b, k)| b == bits && iced_bytes.starts_with(k))
}

/// Core differential check for one buffer/mode. Returns a description of a
/// mismatch, if any (caller decides whether to fail or collect).
fn diff_one(bytes: &[u8], bits: u32) -> Result<(), String> {
    if excluded_16bit_addressing(bytes, bits) {
        return Ok(());
    }
    let mut dec = Decoder::with_ip(bits, bytes, 0x1000, DecoderOptions::NONE);
    let iced = dec.decode();
    if iced.is_invalid() {
        return Ok(());
    }
    let iced_len = iced.len();
    if iced_len == 0 || iced_len > bytes.len() {
        return Ok(());
    }
    if let Ok(our_len) = instr_length(bytes, bits)
        && our_len != iced_len && !known_divergence(&bytes[..iced_len], bits) {
            return Err(format!(
                "length mismatch (bits={bits}): bytes={:02x?} ours={our_len} iced={iced_len} ({iced})",
                &bytes[..iced_len.max(our_len).min(bytes.len())]
            ));
        }
    Ok(())
}

/// Exercise every decode/lift/length entry point on arbitrary bytes; the only
/// assertion is "no panic".
fn no_panic_one(bytes: &[u8], bits: u32) {
    let _ = instr_length(bytes, bits);
    // iced decode + full lift pipeline.
    if let Some(iced) = X86LiftAdapter::decode_one_iced(bits, bytes, 0x1000) {
        let _ = lift_to_llil_with_bits(&iced, bits);
    }
    // High-level arch entry points.
    let arch = match bits {
        16 => X86Arch::new_16bit(),
        32 => X86Arch::new_32bit(),
        _ => X86Arch::new_64bit(),
    };
    let _ = arch.lift(Address::new(0x1000), bytes);
    let _ = rustre_arch_x86::disassemble_and_lift(bytes, 0x1000, bits as u8);
}

// ---------------------------------------------------------------------------
// (a) Property: never panic on arbitrary byte buffers, all modes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_no_panic_64bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        no_panic_one(&bytes, 64);
    }

    #[test]
    fn prop_no_panic_32bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        no_panic_one(&bytes, 32);
    }

    #[test]
    fn prop_no_panic_16bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        no_panic_one(&bytes, 16);
    }

    // -----------------------------------------------------------------------
    // (b) Property: differential length agreement vs iced-x86, all modes
    // -----------------------------------------------------------------------

    #[test]
    fn prop_diff_length_64bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        if let Err(msg) = diff_one(&bytes, 64) {
            prop_assert!(false, "{}", msg);
        }
    }

    #[test]
    fn prop_diff_length_32bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        if let Err(msg) = diff_one(&bytes, 32) {
            prop_assert!(false, "{}", msg);
        }
    }

    #[test]
    fn prop_diff_length_16bit(bytes in prop::collection::vec(any::<u8>(), 1..=15)) {
        if let Err(msg) = diff_one(&bytes, 16) {
            prop_assert!(false, "{}", msg);
        }
    }
}

// ---------------------------------------------------------------------------
// (d) Curated corpus of tricky encodings with locked-in expected lengths
// ---------------------------------------------------------------------------

#[test]
fn curated_tricky_encodings_match_iced_and_expected() {
    // (bits, bytes, expected_len) — expected_len is the iced-verified length,
    // hardcoded so a future iced upgrade or scanner regression is caught.
    let cases: &[(u32, &[u8], usize)] = &[
        // -- length-changing 0x66 / 0x67 prefixes ---------------------------
        (64, &[0x66, 0xB8, 0x34, 0x12], 4),                   // mov ax, imm16
        (64, &[0x66, 0x05, 0x34, 0x12], 4),                   // add ax, imm16
        (64, &[0x66, 0x68, 0x34, 0x12], 4),                   // push imm16
        (64, &[0x67, 0x8B, 0x00], 3),                         // mov eax, [eax] (addr32)
        (32, &[0x66, 0xB8, 0x34, 0x12], 4),                   // mov ax, imm16
        (16, &[0x66, 0xB8, 0x78, 0x56, 0x34, 0x12], 6),       // mov eax, imm32 (16-bit mode)
        (16, &[0xB8, 0x34, 0x12], 3),                         // mov ax, imm16
        (16, &[0xE8, 0x00, 0x10], 3),                         // call rel16
        (16, &[0x66, 0xE8, 0x00, 0x10, 0x00, 0x00], 6),       // call rel32 in 16-bit mode
        // -- redundant / stacked prefixes ------------------------------------
        (64, &[0x2E, 0x2E, 0x66, 0x90], 4),                   // css css o16 nop
        (64, &[0x66, 0x66, 0x90], 3),                         // double 0x66
        (64, &[0xF0, 0x48, 0x0F, 0xB1, 0x0B], 5),             // lock cmpxchg [rbx], rcx
        (64, &[0xF3, 0x90], 2),                               // pause
        // -- REX combos -------------------------------------------------------
        (64, &[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8], 10),      // movabs rax, imm64
        (64, &[0x4F, 0x89, 0x04, 0xC8], 4),                   // mov [r8+r9*8], r8
        (64, &[0x48, 0xF7, 0xC0, 0, 0, 0, 0], 7),             // test rax, imm32
        (64, &[0x48, 0xF7, 0xD8], 3),                         // neg rax (no imm)
        (64, &[0x66, 0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8], 11),// 66 then REX.W: imm64 wins
        // -- RIP-relative -----------------------------------------------------
        (64, &[0x48, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12], 7), // mov rax, [rip+disp32]
        (64, &[0xFF, 0x15, 0, 0, 0, 0], 6),                   // call [rip+disp32]
        // -- SIB with no base (mod=00, base=101 => disp32) ---------------------
        (64, &[0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12], 7), // mov eax, [disp32]
        (64, &[0x8B, 0x04, 0xCD, 0, 0, 0, 0], 7),             // mov eax, [rcx*8+disp32]
        (64, &[0x89, 0x04, 0x24], 3),                         // mov [rsp], eax
        (64, &[0x8B, 0x44, 0x24, 0x08], 4),                   // mov eax, [rsp+8]
        // -- VEX with and without imm8 ----------------------------------------
        (64, &[0xC5, 0xF8, 0x58, 0xC1], 4),                   // vaddps xmm0, xmm0, xmm1
        (64, &[0xC5, 0xF9, 0x70, 0xC0, 0x1B], 5),             // vpshufd imm8 (0F map)
        (64, &[0xC5, 0xF8, 0xC2, 0xC1, 0x02], 5),             // vcmpleps imm8
        (64, &[0xC4, 0xE3, 0x75, 0x02, 0xC2, 0xAA], 6),       // vpblendd imm8 (0F3A map)
        (64, &[0xC4, 0xE2, 0x7D, 0x17, 0xC2], 5),             // vptest (0F38, no imm)
        (64, &[0xC4, 0xE2, 0x71, 0x98, 0x04, 0x25, 0, 0, 0, 0], 10), // vfmadd132ps xmm, mem
        // -- EVEX with and without imm8 ----------------------------------------
        (64, &[0x62, 0xF1, 0x74, 0x48, 0x58, 0xC2], 6),       // vaddps zmm0, zmm1, zmm2
        (64, &[0x62, 0xF1, 0x7D, 0x48, 0x70, 0xC0, 0x1B], 7), // vpshufd zmm imm8
        (64, &[0x62, 0xF1, 0x74, 0x48, 0x58, 0x44, 0x24, 0x40], 8), // vaddps zmm, [rsp+disp8*N]
        (64, &[0x62, 0xF3, 0x6D, 0x48, 0x03, 0xC1, 0x07], 7), // valignd zmm imm8 (0F3A map)
        // -- 0F38 / 0F3A legacy -------------------------------------------------
        (64, &[0x0F, 0x38, 0x00, 0xC1], 4),                   // pshufb mm0, mm1
        (64, &[0x66, 0x0F, 0x38, 0x17, 0xC1], 5),             // ptest xmm0, xmm1
        (64, &[0x0F, 0x3A, 0x0F, 0xC1, 0x08], 5),             // palignr mm, mm, imm8
        (64, &[0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x08], 6),       // palignr xmm, xmm, imm8
        // -- x87 escapes ---------------------------------------------------------
        (64, &[0xD9, 0xC0], 2),                               // fld st0
        (64, &[0xD8, 0x04, 0x24], 3),                         // fadd dword [rsp]
        (64, &[0xDD, 0x45, 0x08], 3),                         // fld qword [rbp+8]
        (64, &[0xDF, 0xE0], 2),                               // fnstsw ax
        (64, &[0xDB, 0x2C, 0x25, 0, 0, 0, 0], 7),             // fld tbyte [disp32]
        // -- long NOPs / misc ------------------------------------------------------
        (64, &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00], 6),       // nopw [rax+rax]
        (64, &[0x0F, 0x1F, 0x84, 0x00, 0, 0, 0, 0], 8),       // nopl [rax+rax+disp32]
        (64, &[0x0F, 0xC8], 2),                               // bswap eax
        (64, &[0x0F, 0x20, 0xC0], 3),                         // mov rax, cr0 (mod ignored)
        (64, &[0xA1, 0, 0, 0, 0, 0, 0, 0, 0], 9),             // mov eax, moffs64
        (64, &[0x67, 0xA1, 0, 0, 0, 0], 6),                   // mov eax, moffs32 (0x67)
    ];

    for &(bits, bytes, expected) in cases {
        let mut dec = Decoder::with_ip(bits, bytes, 0x1000, DecoderOptions::NONE);
        let iced = dec.decode();
        assert!(
            !iced.is_invalid(),
            "corpus case must decode via iced (bits={bits}): {bytes:02x?}"
        );
        assert_eq!(
            iced.len(),
            expected,
            "iced length changed?! (bits={bits}) {bytes:02x?} ({iced})"
        );
        assert_eq!(
            instr_length(bytes, bits),
            Ok(expected),
            "instr_length disagrees (bits={bits}): {bytes:02x?} ({iced})"
        );
    }
}

// ---------------------------------------------------------------------------
// (e) Deterministic LCG stress loop: decode + length + lift, ~200k iterations
// ---------------------------------------------------------------------------

#[test]
fn stress_lcg_decode_length_lift_agreement() {
    let mut rng = Lcg(0xDEC0_DE00_D1FF_5EED);
    let mut mismatches: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for i in 0..200_000usize {
        let bits = match i % 4 {
            0 | 1 => 64, // weight 64-bit
            2 => 32,
            _ => 16,
        };
        let len = 1 + (rng.next() % 15) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push((rng.next() >> 32) as u8);
        }

        // Length differential (never panics; collects real mismatches).
        if let Err(msg) = diff_one(&bytes, bits) {
            if mismatches.len() < 20 {
                mismatches.push(msg);
            }
        } else {
            checked += 1;
        }

        // Lift robustness on a subsample (lifting is the slow part).
        if i % 8 == 0
            && let Some(iced) = X86LiftAdapter::decode_one_iced(bits, &bytes, 0x1000)
        {
            let _ = lift_to_llil_with_bits(&iced, bits);
        }
    }

    assert!(checked > 10_000, "stress corpus exercised too few inputs: {checked}");
    assert!(
        mismatches.is_empty(),
        "stress found {} length mismatches:\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
}
