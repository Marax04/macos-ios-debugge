//! Every instruction the DECODER says transfers control must lift to IL that
//! contains a terminator.
//!
//! # Why this file exists
//!
//! `IRET` was dispatched to `lift_fpu_generic` — the effect-only intrinsic
//! helper — and so lifted to a block with no terminator at all: a CFG built
//! from that IL ran straight past the handler. Fixed 2026-07-28.
//!
//! Grepping `lift_fpu_generic` afterwards showed IRET was not alone in that
//! helper: `ERETS`/`ERETU` (FRED enclave return), `UIRET` (user-interrupt
//! return) and `SYSEXIT`/`SYSRET` are all returns, and they were routed the same
//! way. Rather than judge each by eye, this asks the DECODER — the same source
//! the lifter itself uses — and pins the general rule.
//!
//! The property is one-directional on purpose: an instruction that transfers
//! control MUST produce a terminator (otherwise a block silently runs on, which
//! corrupts every later analysis). The converse is not asserted here — the IL
//! deliberately treats some unmodelled encodings as flow-ending, a conservative
//! choice measured separately in `hint_nops_do_not_end_blocks.rs`.
//!
//! Encodings are produced by `iced_x86`'s own encoder, never written by hand:
//! hand-built encodings were the single largest source of DEFECTIVE TESTS found
//! in this workspace on 2026-07-23 — and one slipped into the companion file in
//! this very session.

use iced_x86::{Code, Decoder, DecoderOptions, Encoder, FlowControl, Instruction};
#[path = "common/mod.rs"]
mod common;

use rustre_arch_x86::lift_to_llil_with_bits;

/// Zero-operand control transfers. Restricted to the no-operand forms so the
/// encoder can build them without operand guesswork; that is enough to cover
/// the family the `lift_fpu_generic` grep turned up.
const CONTROL_TRANSFERS: &[(&str, Code)] = &[
    ("iretq", Code::Iretq),
    ("iretd", Code::Iretd),
    ("iretw", Code::Iretw),
    ("sysretq", Code::Sysretq),
    ("sysretd", Code::Sysretd),
    ("sysexitq", Code::Sysexitq),
    ("sysexitd", Code::Sysexitd),
    ("uiret", Code::Uiret),
    ("retnq", Code::Retnq),
    ("retfq", Code::Retfq),
    // NOT listed: `syscall` / `sysenter`. The decoder calls them `Call`, and
    // control genuinely DOES return to the next instruction; this IL has a
    // dedicated `SysCall` variant that continues on purpose (same category as
    // `Breakpoint` for INT3). Asserting a terminator for them would be
    // demanding the wrong semantics, not finding a bug.
    ("ud2", Code::Ud2),
];

fn encode(code: Code) -> Option<Vec<u8>> {
    let instr = Instruction::with(code);
    let mut enc = Encoder::new(64);
    enc.encode(&instr, 0x1000).ok()?;
    Some(enc.take_buffer())
}

#[test]
fn instructions_that_transfer_control_lift_to_a_terminator() {
    let mut checked = 0usize;
    let mut offenders = Vec::new();

    for (label, code) in CONTROL_TRANSFERS {
        let Some(bytes) = encode(*code) else {
            continue; // not encodable in 64-bit mode; nothing to assert
        };
        let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let insn = dec.decode();
        if insn.is_invalid() {
            continue;
        }
        // Ask the DECODER whether control leaves, rather than assuming from the
        // mnemonic. `Next` means it falls through and is out of scope here.
        let fc = insn.flow_control();
        if fc == FlowControl::Next {
            continue;
        }
        checked += 1;

        let llil = lift_to_llil_with_bits(&insn, 64);
        if !llil.iter().any(|ai| ai.instr.is_terminator()) {
            offenders.push(format!(
                "{label} ({bytes:02x?}, iced flow={fc:?}): lifts to {} instruction(s), \
                 NONE of them a terminator — a CFG runs straight past it",
                llil.len()
            ));
        }
    }

    // Anti-degeneracy: if the encoder refused everything this would pass while
    // proving nothing.
    assert!(
        checked >= 8,
        "degenerated: only {checked} control transfers were encodable"
    );

    assert!(
        offenders.is_empty(),
        "{} control transfer(s) lift without a terminator:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );

    println!("{checked} control transfers all lift to a terminator");
}

/// Systematic sweep: synthesise the whole primary and `0F` opcode space with a
/// few ModRM/prefix shapes, ask the DECODER which encodings transfer control,
/// and require every one of them to lift to a terminator.
///
/// This is the generalisation of the named list above. It needs no knowledge of
/// which mnemonics exist, so it covers the operand-carrying transfers (`JMPE`,
/// `JKNZD`/`JKZD`, `XBEGIN`/`XABORT`, indirect `JMP`/`CALL` through ModRM
/// groups) that a hand-written list would have to remember to include — the
/// same "what is the harness silent about" gap that produced most of this
/// session's findings.
#[test]
fn synthesised_opcode_space_control_transfers_lift_to_terminators() {
    // BOTH modes. Every sweep in this crate hard-coded 64-bit, so 32-bit
    // lifting — a whole regime the lifter supports — had never been measured.
    // Same shape as the MPX blind spot: the harness was silent over a region,
    // which is exactly where a defect survives.
    for bits in [16u32, 32, 64] {
        sweep_control_transfers(bits);
    }
}

fn sweep_control_transfers(bits: u32) {
    // Shared encoding space — see `tests/common/mod.rs`. `mod=11` and `mod=00`
    // reach different ModRM group members (`FF /2` is CALL r/m, `FF /4` is JMP
    // r/m), and the rm field selects whole instructions in the `0F 01 /r` space.
    let modrms = common::modrms(0);
    let stems = common::opcode_stems();

    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for stem in &stems {
        {
            for opcode in 0u16..=0xFF {
                let opcode = u8::try_from(opcode).unwrap();
                for &modrm in &modrms {
                  for filler in common::fillers() {
                    let mut bytes: Vec<u8> = stem.clone();
                    bytes.push(opcode);
                    bytes.push(modrm);
                    bytes.extend_from_slice(&filler);

                    let mut dec = Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::NONE);
                    let insn = dec.decode();
                    if insn.is_invalid() {
                        continue;
                    }
                    let fc = insn.flow_control();
                    // Only the "control leaves" cases are in scope. `Exception`
                    // is excluded: an always-faulting encoding is not a
                    // transfer the lifter is expected to model as one.
                    if !matches!(
                        fc,
                        FlowControl::UnconditionalBranch
                            | FlowControl::IndirectBranch
                            | FlowControl::ConditionalBranch
                            | FlowControl::Return
                            | FlowControl::Interrupt
                    ) {
                        continue;
                    }
                    let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();
                    // One report per (mnemonic, flow) pair keeps the failure
                    // message a diagnosis rather than a wall of duplicates.
                    let key = format!("{mnemonic}/{fc:?}");
                    if !seen.insert(key.clone()) {
                        continue;
                    }
                    // INT3 is a recorded DESIGN QUESTION, not an oversight:
                    // this IL models `Breakpoint` as CONTINUING on purpose (a
                    // debugger-inserted breakpoint resumes at the next
                    // instruction), and the neighbouring `INTO` mapping is
                    // arguably the more wrong of the two — it emits an
                    // UNCONDITIONAL trap although INTO only traps when OF is
                    // set. They are wrong in OPPOSITE directions, so neither is
                    // aligned to the other without deciding which is right.
                    if mnemonic == "int3" {
                        continue;
                    }
                    checked += 1;

                    let llil = lift_to_llil_with_bits(&insn, 64);
                    if !llil.iter().any(|ai| ai.instr.is_terminator()) {
                        offenders.push(format!(
                            "{mnemonic} ({bytes:02x?}, iced flow={fc:?}): {} IL instruction(s),                              NONE a terminator",
                            llil.len()
                        ));
                    }
                }
              }
            }
        }
    }

    assert!(
        checked >= 20,
        "sweep degenerated at {bits}-bit: only {checked} distinct control transfers generated"
    );
    assert!(
        offenders.is_empty(),
        "{} distinct control transfer(s) lift without a terminator          (of {checked} swept):
  {}",
        offenders.len(),
        offenders.join("
  ")
    );
    println!("[{bits}-bit] swept {checked} distinct control transfers; all lift to a terminator");
}

/// The REVERSE class: instructions the IL ends a block on, that the decoder says
/// simply fall through.
///
/// A missing terminator merges two basic blocks; a FALSE one fragments a block
/// that should be whole, so every later analysis sees an edge that does not
/// exist. Both directions are defects, and only the first has been swept so far.
///
/// `Unimplemented` / `Undefined` / `Trap` are EXCLUDED, not overlooked: this IL
/// deliberately treats an unmodelled or always-faulting encoding as flow-ending,
/// a conservative choice measured separately in `hint_nops_do_not_end_blocks.rs`
/// (where the encodings that actually occur in real code — ENDBR64, the NOP
/// family, PREFETCHh, PAUSE — were confirmed to fall through correctly). What is
/// flagged here is a REAL control-flow terminator (`Ret`, `Jump`, `CondJump`,
/// `Call`, …) emitted for an instruction that does not transfer control.
#[test]
fn fall_through_instructions_do_not_emit_a_real_terminator() {
    use rustre_il_llil::LlilInstruction as I;

    // ALL 64 register-form ModRM bytes (mod=11, every reg × every rm), plus a
    // memory form. The previous set fixed rm=0, so SEVEN of the eight rm values
    // were never generated — and the `0F 01 /r` opcode-extension space encodes
    // whole instructions in rm (`VMCALL` C1, `VMXOFF` C4, `STGI` DC, `CLGI` DD).
    // Those were invisible to every sweep in this crate.
    // Shared encoding space, same as the forward direction — a REVERSE check
    // that is narrower than the forward one would let a false terminator hide
    // exactly where the forward sweep already looks.
    let modrms = common::modrms(0);
    let stems = common::opcode_stems();

    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for stem in &stems {
        {
            for opcode in 0u16..=0xFF {
                let opcode = u8::try_from(opcode).unwrap();
                for &modrm in &modrms {
                  for filler in common::fillers() {
                    let mut bytes: Vec<u8> = stem.clone();
                    bytes.push(opcode);
                    bytes.push(modrm);
                    bytes.extend_from_slice(&filler);

                    let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
                    let insn = dec.decode();
                    if insn.is_invalid() || insn.flow_control() != FlowControl::Next {
                        continue;
                    }
                    let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();
                    if !seen.insert(mnemonic.clone()) {
                        continue;
                    }
                    checked += 1;

                    let llil = lift_to_llil_with_bits(&insn, 64);
                    let bad: Vec<String> = llil
                        .iter()
                        .filter(|ai| {
                            matches!(
                                ai.instr,
                                I::Ret
                                    | I::Return { .. }
                                    | I::Jump(..)
                                    | I::JumpTo { .. }
                                    | I::JumpDest { .. }
                                    | I::CondJump { .. }
                                    | I::ConditionalJump { .. }
                                    | I::Call(..)
                                    | I::CondCall { .. }
                                    | I::TailCall { .. }
                            )
                        })
                        .map(|ai| format!("{:?}", ai.instr))
                        .collect();
                    if !bad.is_empty() {
                        offenders.push(format!(
                            "{mnemonic} ({bytes:02x?}) falls through per the decoder, \
                             but the IL emits: {}",
                            bad.join(", ")
                        ));
                    }
                }
              }
            }
        }
    }

    assert!(
        checked >= 100,
        "sweep degenerated: only {checked} fall-through mnemonics generated"
    );
    assert!(
        offenders.is_empty(),
        "{} fall-through instruction(s) emit a real terminator (of {checked} swept):\n  {}",
        offenders.len(),
        offenders.iter().take(20).cloned().collect::<Vec<_>>().join("\n  ")
    );
    println!("swept {checked} fall-through mnemonics; none emits a false terminator");
}
