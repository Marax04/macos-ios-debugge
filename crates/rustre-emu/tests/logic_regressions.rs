//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_emu::arm_interpreter::ArmThumbInterpreter;
use rustre_emu::heap_emulator::{HeapEmulator, HeapError};
use rustre_emu::{Emulator, MemPerms};

const CODE: u32 = 0x1000;
const DATA: u32 = 0x2000;

/// Map code at 0x1000 and a scratch data page at 0x2000, then load `code`.
fn emu(code: &[u8]) -> ArmThumbInterpreter {
    let mut e = ArmThumbInterpreter::new();
    e.map_memory(u64::from(CODE), 0x1000, MemPerms::ALL).unwrap();
    e.map_memory(u64::from(DATA), 0x1000, MemPerms::ALL).unwrap();
    e.write_memory(u64::from(CODE), code).unwrap();
    e.regs.set_pc(CODE);
    e
}

/// A 16-bit Thumb instruction followed by BKPT, little-endian.
fn prog(insn: u16) -> Vec<u8> {
    let mut v = insn.to_le_bytes().to_vec();
    v.extend_from_slice(&[0x00, 0xBE]); // BKPT
    v
}

// ── Thumb load/store: a LOAD performed a WRITE ─────────────────────────────

/// `exec_ldr_str_reg_sp` handles bits[15:13] == 0b100, which in Thumb is
/// STRH/LDRH (immediate) and STR/LDR (SP-relative). It demultiplexed them on
/// `(insn >> 9) & 0xF` — a bit field that does not identify those encodings at
/// all — and dispatched to register-offset arms that never legitimately
/// arrive here.
///
/// `LDRH r0, [r1, #0]` therefore executed as `STRB (register)`: instead of
/// loading, it WROTE r0 to r1 + r0. An emulated load silently corrupting
/// emulated memory is as bad as this class gets.
#[test]
fn ldrh_immediate_loads_and_does_not_write() {
    // 0x8808 = LDRH r0, [r1, #0]
    let mut e = emu(&prog(0x8808));
    e.regs.r[0] = 0x41;
    e.regs.r[1] = u32::from(DATA);
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();

    assert_eq!(
        e.regs.r[0], 0,
        "r0 must hold the zero-extended halfword read from 0x2000 (which is 0)"
    );
    let touched = e.read_memory(u64::from(DATA) + 0x41, 1).unwrap();
    assert_eq!(
        touched[0], 0,
        "a LOAD must not write; 0x{:x} was written to r1+r0",
        0x2041
    );
}

/// `STR r4, [sp, #0]` decoded to op 0xA, the SP-relative LOAD arm: the store
/// became a load and r4 was overwritten instead of memory.
#[test]
fn str_sp_relative_stores_and_does_not_load() {
    // 0x9400 = STR r4, [sp, #0]
    let mut e = emu(&prog(0x9400));
    e.regs.r[4] = 0xDEAD_BEEF;
    e.regs.set_sp(DATA);
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();

    assert_eq!(e.regs.r[4], 0xDEAD_BEEF, "a STORE must not clobber rt");
    let stored = e.read_memory(u64::from(DATA), 4).unwrap();
    assert_eq!(
        u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]),
        0xDEAD_BEEF,
        "the value must have reached [sp, #0]"
    );
}

/// `STR r0, [sp, #0]` decoded to op 8, which had no arm at all: a perfectly
/// ordinary instruction was rejected as invalid.
#[test]
fn str_sp_relative_with_r0_is_not_an_invalid_instruction() {
    // 0x9000 = STR r0, [sp, #0]
    let mut e = emu(&prog(0x9000));
    e.regs.r[0] = 0x1234_5678;
    e.regs.set_sp(DATA);
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .expect("STR r0,[sp,#0] is a valid Thumb instruction");

    let stored = e.read_memory(u64::from(DATA), 4).unwrap();
    assert_eq!(
        u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]),
        0x1234_5678
    );
}

/// LDR (SP-relative) must still load.
#[test]
fn ldr_sp_relative_still_loads() {
    // 0x9801 = LDR r0, [sp, #4]
    let mut e = emu(&prog(0x9801));
    e.regs.set_sp(DATA);
    e.write_memory(u64::from(DATA) + 4, &0xCAFE_BABEu32.to_le_bytes())
        .unwrap();
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();
    assert_eq!(e.regs.r[0], 0xCAFE_BABE);
}

/// STRH (immediate) must store a halfword and leave the neighbouring bytes
/// alone.
#[test]
fn strh_immediate_stores_a_halfword() {
    // 0x800A = STRH r2, [r1, #0]
    let mut e = emu(&prog(0x800A));
    e.regs.r[1] = u32::from(DATA);
    e.regs.r[2] = 0xFFFF_1234;
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();
    let m = e.read_memory(u64::from(DATA), 4).unwrap();
    assert_eq!(u16::from_le_bytes([m[0], m[1]]), 0x1234);
    assert_eq!(&m[2..4], &[0, 0], "only two bytes may be written");
}

// ── RSB negated the wrong register ────────────────────────────────────────

/// `RSB r0, r1, #0` computes `0 - r1`. The implementation used the
/// DESTINATION register as the operand (`0 - r0`), so with r0 = 0 it produced
/// 0 and set Z — the exact opposite of the negation that was requested.
#[test]
fn rsb_negates_the_source_register_not_the_destination() {
    // 0x4248 = RSB r0, r1, #0
    let mut e = emu(&prog(0x4248));
    e.regs.r[0] = 0;
    e.regs.r[1] = 5;
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();

    assert_eq!(
        e.regs.r[0], 0xFFFF_FFFB,
        "0 - r1 = -5; the result was computed from r0 instead"
    );
    assert!(e.regs.nf(), "the result is negative, so N must be set");
    assert!(!e.regs.zf(), "the result is non-zero, so Z must be clear");
}

// ── ASR carry-out read the wrong bit ──────────────────────────────────────

/// The carry-out of a right shift is the LAST bit shifted OUT — bit
/// `shift - 1`. `asr_c` read bit `shift`, i.e. the lowest bit that SURVIVES.
/// The sibling `lsr_c`, directly above it, already gets this right.
///
/// A wrong carry makes the following BCS/BCC branch the wrong way, so control
/// flow diverges from the real program.
#[test]
fn asr_carry_out_is_the_last_bit_shifted_out() {
    // 0x104A = ASRS r2, r1, #1
    let mut e = emu(&prog(0x104A));
    e.regs.r[1] = 2; // 0b10 — bit0 is 0, so carry-out must be 0
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();

    assert_eq!(e.regs.r[2], 1);
    assert!(
        !e.regs.cf(),
        "bit0 of 0b10 is 0, so ASR #1 shifts out a 0; reading bit1 instead \
         reports carry set"
    );
}

/// And when a 1 really is shifted out, the carry must be set.
#[test]
fn asr_sets_carry_when_a_one_is_shifted_out() {
    // 0x104A = ASRS r2, r1, #1
    let mut e = emu(&prog(0x104A));
    e.regs.r[1] = 3; // 0b11 — bit0 is 1
    e.start(u64::from(CODE), u64::from(CODE) + 0x100, 0, 100)
        .unwrap();
    assert_eq!(e.regs.r[2], 1);
    assert!(e.regs.cf(), "bit0 of 0b11 is 1");
}

// ── heap: a write past the buffer landed in the canary unnoticed ──────────

/// `check_access` located the block by testing whether the START address falls
/// inside `[user_ptr, user_ptr + size)`. A write that begins exactly AT the end
/// of the buffer is inside no block at all, so it fell through to the
/// "not a heap address — allow" case: the single most common heap overflow,
/// one byte past the end, was reported as fine.
#[test]
fn a_one_byte_write_past_the_buffer_is_an_overflow() {
    let mut h = HeapEmulator::with_defaults();
    let p = h.malloc(16, 0).unwrap();

    let r = h.check_access(p + 16, 1, true, 0);
    assert!(
        matches!(r, Err(HeapError::BufferOverflow(_))),
        "one byte past a 16-byte buffer is an overflow, got {r:?}"
    );
}

/// An access that starts inside and runs past the end must still be caught.
#[test]
fn an_access_spanning_the_end_is_still_an_overflow() {
    let mut h = HeapEmulator::with_defaults();
    let p = h.malloc(16, 0).unwrap();
    assert!(matches!(
        h.check_access(p + 12, 8, true, 0),
        Err(HeapError::BufferOverflow(_))
    ));
}

/// A legitimate in-bounds access must stay legal.
#[test]
fn an_in_bounds_access_is_allowed() {
    let mut h = HeapEmulator::with_defaults();
    let p = h.malloc(16, 0).unwrap();
    assert!(h.check_access(p, 16, true, 0).is_ok());
    assert!(h.check_access(p + 8, 8, false, 0).is_ok());
}

/// An address far from any allocation is not the heap's business.
#[test]
fn a_non_heap_address_is_still_allowed() {
    let mut h = HeapEmulator::with_defaults();
    let _ = h.malloc(16, 0).unwrap();
    assert!(h.check_access(0xDEAD_0000, 4, true, 0).is_ok());
}
