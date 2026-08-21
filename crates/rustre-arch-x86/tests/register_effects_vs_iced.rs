//! Does the lifted IL write the registers the decoder says are written?
//!
//! # Why
//!
//! Register writes are the dependency backbone of every later analysis. A write
//! the IL does NOT model means a decompiler believes the old value survives —
//! it will propagate a stale definition into everything downstream. A write the
//! IL INVENTS creates a false definition that kills a live value.
//!
//! Memory effects got this treatment in iterations 19–23 and it produced four
//! real defects. Registers are the larger half and had never been swept.
//!
//! # The independent oracle
//!
//! `iced_x86::InstructionInfoFactory::info(&insn).used_registers()` reports, per
//! register, whether it is Read, Write, ReadWrite or a conditional variant —
//! from the decoder's own instruction database, not from this crate's lifter.
//!
//! # Normalisation, and why it is not a loophole
//!
//! The decoder may say `EAX` where the IL writes `rax`, or `AL` where the IL
//! writes `al`. Both are the same architectural register, so BOTH sides are
//! normalised through `Register::full_register()` — iced's own table, not a
//! hand-written map. The comparison is therefore "was this architectural
//! register written at all", which is the question dependency analysis asks.
//! Sub-register WIDTH correctness is a different question, already covered by
//! `alias_model_crosscheck.rs` and by the hardware oracle.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register};
#[path = "common/mod.rs"]
mod common;

use rustre_arch_x86::lift_to_llil_with_bits;
use rustre_il_llil::{LlilInstruction, LlilRegister};

/// Architectural registers the IL WRITES, normalised to their full form.
fn il_written_registers(llil: &[rustre_il_llil::LlilAnnotatedInstr]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for ai in llil {
        if let LlilInstruction::SetReg { dest: LlilRegister::Concrete(n), .. } = &ai.instr {
            out.insert(normalise(n));
        }
        if let LlilInstruction::SetRegSplit {
            low: LlilRegister::Concrete(lo),
            high: LlilRegister::Concrete(hi),
            ..
        } = &ai.instr
        {
            out.insert(normalise(lo));
            out.insert(normalise(hi));
        }
        // `Pop` and `Load` write their destination too. The first version of
        // this oracle looked only at `SetReg`/`SetRegSplit` and therefore
        // reported `leave` as never writing `rbp` — when `lift_leave` writes it
        // via `Pop { dest: bp }`, correctly. Read the IL's own vocabulary
        // before believing a mass failure; this is the fifth time that rule
        // has stopped a "fix" to correct code.
        if let LlilInstruction::Pop { dest: LlilRegister::Concrete(n), .. }
        | LlilInstruction::Load { dest: LlilRegister::Concrete(n), .. } = &ai.instr
        {
            out.insert(normalise(n));
        }
    }
    out
}

/// Map an IL register name to its 64-bit parent, via iced's own table where the
/// name is recognisable. Unknown names (temporaries, x87 slots, flags) pass
/// through unchanged so they can never silently match a real register.
fn normalise(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for r in Register::values() {
        if format!("{r:?}").to_ascii_lowercase() == lower {
            return format!("{:?}", r.full_register()).to_ascii_lowercase();
        }
    }
    lower
}

#[test]
fn registers_the_decoder_says_are_written_are_modelled() {
    let stems = common::opcode_stems();
    let modrms = common::modrms(0b011);

    let mut factory = InstructionInfoFactory::new();
    let mut checked = 0usize;
    let mut masked_seen = 0usize;
    let mut broadcast_seen = 0usize;
    let mut by_kind: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for bits in [16u32, 32, 64] {
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

                        let mut dec =
                            Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::MPX);
                        let insn = dec.decode();
                        if insn.is_invalid() {
                            continue;
                        }
                        // COVERAGE WITNESSES. A green result on a widened axis
                        // is worthless unless the axis was actually reached, so
                        // the sweep counts what it claims to cover and asserts
                        // it below. Without this, a malformed EVEX prefix would
                        // simply decode to nothing and the run would still pass,
                        // reporting "clean" for a region it never entered.
                        if insn.op_mask() != Register::None {
                            masked_seen += 1;
                        }
                        if insn.is_broadcast() {
                            broadcast_seen += 1;
                        }
                        let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();
                        if !seen.insert(format!("{bits}:{mnemonic}")) {
                            continue;
                        }

                        let llil = lift_to_llil_with_bits(&insn, bits);
                        // An `Unimplemented`/`Undefined` lift is an honest "this
                        // is not modelled at all" — comparing its register
                        // effects would measure the disclaimer, not a defect.
                        if llil.iter().any(|ai| {
                            matches!(
                                ai.instr,
                                LlilInstruction::Unimplemented { .. }
                                    | LlilInstruction::UnimplementedRaw { .. }
                                    | LlilInstruction::Undefined
                            )
                        }) {
                            continue;
                        }

                        let info = factory.info(&insn);
                        let mut want: BTreeSet<String> = BTreeSet::new();
                        for r in info.used_registers() {
                            if !matches!(
                                r.access(),
                                OpAccess::Write
                                    | OpAccess::ReadWrite
                                    | OpAccess::CondWrite
                                    | OpAccess::ReadCondWrite
                            ) {
                                continue;
                            }
                            let reg = r.register();
                            // Segment, control, debug and the instruction
                            // pointer are architectural state this IL models
                            // through dedicated nodes (Push/Ret/Jump) or not at
                            // all; they are out of scope for "did the lifter
                            // write the GPR/vector destination".
                            if reg.is_segment_register()
                                || format!("{reg:?}").starts_with("CR")
                                || format!("{reg:?}").starts_with("DR")
                                || format!("{reg:?}").starts_with("TR")
                                || matches!(reg, Register::RIP | Register::EIP | Register::RSP | Register::ESP | Register::SP)
                            {
                                continue;
                            }
                            want.insert(
                                format!("{:?}", reg.full_register()).to_ascii_lowercase(),
                            );
                        }
                        if want.is_empty() {
                            continue;
                        }
                        checked += 1;

                        let got = il_written_registers(&llil);
                        let missing: Vec<&String> =
                            want.iter().filter(|w| !got.contains(*w)).collect();
                        // THE OTHER DIRECTION. Until now this oracle only
                        // asked "is a real write missing"; the memory oracle has
                        // checked both directions since iteration 22, and that
                        // asymmetry is what let `RDPKRU` define a register
                        // literally named "none" for as long as it did — an
                        // INVENTED write creates a false definition that kills a
                        // live value, the mirror defect of a missing one.
                        //
                        // Only names iced recognises as architectural registers
                        // are compared: temporaries and flag pseudo-registers
                        // are this IL's own vocabulary, not a claim about the
                        // machine.
                        //
                        // Two classes are excluded, each for a stated reason —
                        // an ITEMISED allow-list, never a silent filter:
                        //
                        //  * `rsp`. The `want` side already drops it (this IL
                        //    models the stack pointer through dedicated
                        //    Push/Pop/Ret nodes), so comparing it in the other
                        //    direction is an asymmetry in the ORACLE: `leave`,
                        //    `enter` and `popad` adjust rsp correctly and were
                        //    flagged for doing so.
                        //  * the x87 trio and `syscall`, itemised below, where
                        //    the IL is deliberately MORE complete than iced's
                        //    table.
                        let deliberate: &[(&str, &str)] = &[
                            // AMD APM vol. 3, SYSCALL: RFLAGS is saved into
                            // R11. Verified against the manual in iteration 29;
                            // iced does not list it, the IL is right.
                            ("syscall", "r11"),
                            // FPATAN/FYL2X/FYL2XP1 compute into ST(1) and pop.
                            // This IL does not model the stack positionally, so
                            // both slots are written (iteration 33). ST(0) is
                            // not invented — its old value really is consumed.
                            ("fpatan", "st0"),
                            ("fyl2x", "st0"),
                            ("fyl2xp1", "st0"),
                        ];
                        let invented: Vec<&String> = got
                            .iter()
                            .filter(|g| {
                                !want.contains(*g)
                                    && g.as_str() != "rsp"
                                    && !deliberate
                                        .iter()
                                        .any(|(m, r)| *m == mnemonic && *r == g.as_str())
                                    && Register::values().any(|r| {
                                        r != Register::None
                                            && format!("{:?}", r.full_register())
                                                .to_ascii_lowercase()
                                                == ***g
                                    })
                            })
                            .collect();
                        if !invented.is_empty() {
                            by_kind.entry("INVENTED register write").or_default().push(format!(
                                "[{bits}] {mnemonic} ({bytes:02x?}): IL writes {invented:?},                                  decoder reports only {want:?}"
                            ));
                        }
                        if !missing.is_empty() {
                            by_kind.entry("MISSING register write").or_default().push(format!(
                                "[{bits}] {mnemonic} ({bytes:02x?}): decoder writes {missing:?}, \
                                 IL writes {got:?}"
                            ));
                        }
                      }
                    }
                }
            }
        }
    }

    assert!(
        checked >= 200,
        "sweep degenerated: only {checked} register-writing mnemonics generated"
    );
    assert!(
        masked_seen > 0 && broadcast_seen > 0,
        "the EVEX mask/broadcast axis was NOT reached: {masked_seen} masked and          {broadcast_seen} broadcast encodings decoded. A clean result over an          axis the generator never entered is not evidence of anything."
    );

    // RATCHET, now an EXACT equality at ZERO: over 889 register-writing
    // mnemonics in both 32- and 64-bit modes, every architectural register the
    // decoder says is written IS written by the IL. The first run of this
    // oracle (iteration 26) found 120 real missing writes; iterations 27-31
    // closed all of them — BCD, leave, popad, ins/outs, rdpmc/xgetbv, xbegin,
    // cpuid, syscall, the x87 ST(0) writers, xlatb, in, bndmk/bndldx, the
    // key-locker forms, the VIA PadLock bulk-crypto family, frstor, cmpxchg8b
    // and enclv.
    //
    // A floor of 0 means any NEW unmodelled register write fails immediately,
    // which is the whole point: a write the IL omits makes a decompiler believe
    // the OLD VALUE SURVIVES and propagate a stale definition downstream.
    const PINNED_MISSING_WRITES: usize = 0;
    // The invented direction is pinned at 0 from its first run: it was added
    // after the missing direction reached 0, so there is no legacy backlog to
    // ratchet down.
    let invented_now = by_kind
        .get("INVENTED register write")
        .map_or(0, std::vec::Vec::len);
    assert!(
        invented_now == 0,
        "IL INVENTS {invented_now} register write(s) the decoder does not report:
  {}",
        by_kind
            .get("INVENTED register write")
            .map(|v| v.iter().take(200).cloned().collect::<Vec<_>>().join("
  "))
            .unwrap_or_default()
    );
    let missing = by_kind
        .get("MISSING register write")
        .map_or(0, std::vec::Vec::len);
    // `PINNED_MISSING_WRITES` may legitimately be 0, so compare through `Ord`
    // instead of `<` / `<=`: with an unsigned pin of 0 those are absurd
    // comparisons and the "lower the pin" branch below could never be reached.
    let detail = || {
        by_kind
            .get("MISSING register write")
            .map(|v| v.iter().take(200).cloned().collect::<Vec<_>>().join("
  "))
            .unwrap_or_default()
    };
    match missing.cmp(&PINNED_MISSING_WRITES) {
        core::cmp::Ordering::Less => println!(
            "NOTE: missing register writes down to {missing} from the pinned {PINNED_MISSING_WRITES} — lower the pin."
        ),
        core::cmp::Ordering::Equal => {}
        core::cmp::Ordering::Greater => panic!(
            "register-effect modelling REGRESSED: {missing} missing writes, {PINNED_MISSING_WRITES} pinned — {} new:
  {}",
            missing - PINNED_MISSING_WRITES,
            detail()
        ),
    }
}
