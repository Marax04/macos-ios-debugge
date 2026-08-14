//! Differential cross-check: `src/branch.rs`'s classifier vs `iced_x86`.
//!
//! # Why this file exists
//!
//! `src/branch.rs` (768 lines) answers "is this instruction a control transfer,
//! and which kind" from opcode patterns alone, without a full decode. The
//! 2026-07-23 wiring audit found its only caller is `lib.rs:2223`, which does
//! `let _ = crate::branch::classify_branch(&bytes);` — **the work runs and the
//! answer is thrown away**. So the module was producing no signal whatsoever:
//! nothing consumed it and nothing checked it.
//!
//! That makes it the same situation as the retained decode tables, and it gets
//! the same treatment: demote it to a differential ORACLE by comparing it with
//! the decoder the lifter actually uses. Two independently-written descriptions
//! of one machine fact — "does control leave this instruction, and how":
//!   * `branch::classify_branch` → [`BranchKind`], from opcode bytes;
//!   * `iced_x86::Instruction::flow_control()`, from a real decode.
//!
//! This is the pairing that found the `REP`-vs-DF defect: where two such
//! descriptions disagree, at least one is wrong, and neither could say so
//! before a check like this existed.
//!
//! # Why the two error directions are not equivalent
//!
//! * Classifier says NOT a branch, decoder says it IS — a MISSED control
//!   transfer. This is the dangerous direction: a CFG built on it runs two
//!   basic blocks together and every later analysis inherits the error.
//! * Classifier says branch, decoder says plain — an INVENTED transfer, which
//!   fragments blocks.
//! Both are asserted; they are reported separately so a regression says which.
//!
//! Encodings are synthesised systematically (every primary opcode and every
//! `0F xx`, each given a register-direct ModRM and immediate padding) rather
//! than hand-written — hand-built encodings were the single largest source of
//! DEFECTIVE TESTS found in this workspace on 2026-07-23.

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use rustre_arch_x86::branch::{BranchKind, classify_branch};

/// Bytes for `opcode` (optionally behind the `0F` escape) with a
/// register-direct ModRM and enough padding that a longer-than-expected
/// instruction still has operand bytes to consume.
fn synth(escape: bool, opcode: u8) -> Vec<u8> {
    let mut v = Vec::new();
    if escape {
        v.push(0x0F);
    }
    v.push(opcode);
    v.push(0xC0); // mod=11, reg=0, rm=0
    v.extend_from_slice(&[0u8; 12]);
    v
}

/// Does `kind` describe the same control-flow behaviour as `fc`?
///
/// The two vocabularies are not identical and the mapping is stated ONCE, in
/// full, so that "they agree" cannot quietly come to mean "we found some excuse".
fn agrees(kind: BranchKind, fc: FlowControl) -> bool {
    match kind {
        BranchKind::DirectJump => fc == FlowControl::UnconditionalBranch,
        // `Loop`/`JrCxz` are conditional branches to iced, as they are to the ISA.
        BranchKind::ConditionalJump | BranchKind::Loop => fc == FlowControl::ConditionalBranch,
        BranchKind::DirectCall => fc == FlowControl::Call,
        BranchKind::IndirectCall => fc == FlowControl::IndirectCall,
        BranchKind::IndirectJump => fc == FlowControl::IndirectBranch,
        BranchKind::Return => fc == FlowControl::Return,
        // INT/INT3/INTO and SYSCALL/SYSENTER both leave the program; iced
        // spells the first Interrupt and the second Call (control does return,
        // to a different privilege level). Accept either for both, because the
        // distinction is a naming choice, not a disagreement about the machine.
        BranchKind::Interrupt | BranchKind::Syscall => {
            matches!(fc, FlowControl::Interrupt | FlowControl::Call)
        }
        // "Not a branch" must mean control simply continues. `Exception` is an
        // instruction that only ever faults (iced's answer for undefined
        // encodings) — not a control transfer the classifier should claim, and
        // not a plain instruction either, so it is excluded at the call site
        // rather than blessed here.
        BranchKind::NotBranch => fc == FlowControl::Next,
    }
}

#[test]
fn branch_classifier_agrees_with_iced_flow_control() {
    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut missed = Vec::new();
    let mut invented = Vec::new();
    let mut miscategorised = Vec::new();

    for escape in [false, true] {
        for opcode in 0u16..=0xFF {
            let opcode = u8::try_from(opcode).unwrap();
            let bytes = synth(escape, opcode);
            let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
            let insn = dec.decode();
            if insn.is_invalid() {
                skipped += 1;
                continue;
            }
            let fc = insn.flow_control();
            // Encodings that only fault carry no control-flow claim to compare.
            if fc == FlowControl::Exception || fc == FlowControl::XbeginXabortXend {
                skipped += 1;
                continue;
            }

            let kind = classify_branch(&bytes);
            compared += 1;
            if agrees(kind, fc) {
                continue;
            }

            let name = format!("{:?}", insn.mnemonic()).to_lowercase();
            let label = if escape {
                format!("0F {opcode:#04x} ({name})")
            } else {
                format!("{opcode:#04x} ({name})")
            };
            let detail = format!("{label}: classifier says {kind:?}, iced says {fc:?}");

            if kind == BranchKind::NotBranch {
                missed.push(detail);
            } else if fc == FlowControl::Next {
                invented.push(detail);
            } else {
                miscategorised.push(detail);
            }
        }
    }

    // Anti-degeneracy: a cross-check that compares almost nothing passes while
    // proving nothing — the failure mode that lets fake oracles survive.
    assert!(
        compared >= 200,
        "cross-check degenerated: only {compared} encodings compared ({skipped} skipped)"
    );

    assert!(
        missed.is_empty() && invented.is_empty() && miscategorised.is_empty(),
        "branch classifier disagrees with iced on {} of {compared} encodings\n\
         \nMISSED control transfers ({}) — classifier says NotBranch, decoder disagrees:\n  {}\n\
         \nINVENTED control transfers ({}):\n  {}\n\
         \nWRONG KIND ({}):\n  {}",
        missed.len() + invented.len() + miscategorised.len(),
        missed.len(),
        missed.join("\n  "),
        invented.len(),
        invented.join("\n  "),
        miscategorised.len(),
        miscategorised.join("\n  ")
    );

    println!("branch classifier vs iced: {compared} encodings agree, {skipped} skipped");
}
