//! Do NOP-like hint instructions terminate a basic block?
//!
//! # Why this matters more than the opcode list suggests
//!
//! `LlilVerifier` counts `Unimplemented`/`Undefined` as flow-ending, which is a
//! conservative and reasonable choice for a genuinely unknown encoding. It is
//! NOT reasonable for instructions that are architecturally no-ops: those fall
//! through, and truncating a block at one silently loses the rest of it for
//! every later analysis.
//!
//! The encodings that matter here are not exotic:
//!
//! * `F3 0F 1E FA` — **ENDBR64**. On any CET-enabled binary this is the FIRST
//!   instruction of every indirect-call target, i.e. of most functions. If it
//!   ended a block, essentially every function would be truncated at its own
//!   entry point.
//! * `0F 1F /0` — multi-byte NOP, the standard alignment padding compilers
//!   insert INSIDE functions.
//! * `0F 18 /1` — PREFETCHNTA and friends, ordinary in optimised copy loops.
//!
//! So this measures the real-world exposure of the "unmodelled ⇒ flow-ending"
//! rule before anyone decides whether to change it — rather than reasoning about
//! it from the opcode table.

use rustre_arch_x86::lift_to_llil_with_bits;

use iced_x86::{Decoder, DecoderOptions};

/// Lift one encoding and report `(mnemonic, any_terminator)`.
fn lift_one(bytes: &[u8]) -> (String, bool, usize) {
    let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
    let insn = dec.decode();
    let llil = lift_to_llil_with_bits(&insn, 64);
    let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();
    let terminates = llil.iter().any(|ai| ai.instr.is_terminator());
    (mnemonic, terminates, llil.len())
}

/// Encodings that are architecturally no-ops or pure hints: control ALWAYS
/// continues to the next instruction, so none of them may terminate a block.
const FALL_THROUGH: &[(&str, &[u8])] = &[
    ("endbr64", &[0xF3, 0x0F, 0x1E, 0xFA]),
    ("endbr32", &[0xF3, 0x0F, 0x1E, 0xFB]),
    ("nop r/m16", &[0x66, 0x0F, 0x1F, 0x00]),
    ("nop r/m32", &[0x0F, 0x1F, 0x00]),
    ("nop r/m32 (long)", &[0x0F, 0x1F, 0x44, 0x00, 0x00]),
    // `0F 18 /digit`: the digit lives in ModRM.reg, so the ModRM byte is
    // `digit << 3` (mod=00, rm=000). Writing these by hand shifted every one by
    // a slot on the first attempt — "prefetcht2" was really `0F 18 /4`, a
    // reserved NOP, and the test then blamed the lifter for it. The decode
    // guard below now catches that class before it can mislead.
    ("prefetchnta (/0)", &[0x0F, 0x18, 0x00]),
    ("prefetcht0 (/1)", &[0x0F, 0x18, 0x08]),
    ("prefetcht1 (/2)", &[0x0F, 0x18, 0x10]),
    ("prefetcht2 (/3)", &[0x0F, 0x18, 0x18]),
    ("prefetchw (/1)", &[0x0F, 0x0D, 0x08]),
    ("pause", &[0xF3, 0x90]),
    ("nop", &[0x90]),
];

/// Guard against the DEFECTIVE-TEST class: every entry must decode to something
/// the decoder itself recognises as a no-op or hint. Without this, a mistyped
/// ModRM silently turns a "prefetch" case into a reserved-NOP case and the test
/// reports a lifter defect that does not exist — which is exactly what the
/// first version of this file did.
#[test]
fn corpus_entries_really_are_hints_or_nops() {
    for (label, bytes) in FALL_THROUGH {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let insn = dec.decode();
        assert!(!insn.is_invalid(), "{label}: does not decode");
        let m = format!("{:?}", insn.mnemonic()).to_lowercase();
        assert!(
            m.contains("nop") || m.contains("prefetch") || m.contains("endbr")
                || m.contains("pause"),
            "{label} ({bytes:02x?}) decodes as `{m}`, which is not a hint or NOP              — the encoding in this list is wrong, not the lifter"
        );
        assert!(
            !m.contains("reserved"),
            "{label} ({bytes:02x?}) decodes as `{m}`: a RESERVED encoding is not a              documented hint, so it does not belong in this list"
        );
    }
}

#[test]
fn hint_and_nop_encodings_never_terminate_a_block() {
    let mut offenders = Vec::new();
    for (label, bytes) in FALL_THROUGH {
        let (mnemonic, terminates, n) = lift_one(bytes);
        if terminates {
            offenders.push(format!(
                "{label} ({bytes:02x?} -> {mnemonic}): lifts to {n} instruction(s) \
                 including a TERMINATOR, so a block ends here"
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "{} fall-through encoding(s) terminate a block:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}
