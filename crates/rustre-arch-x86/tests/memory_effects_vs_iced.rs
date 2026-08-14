//! Does the lifted IL model the memory accesses the decoder says happen?
//!
//! # Why this matters
//!
//! A memory access that the IL does NOT model loses a dependency: dead-code
//! elimination is then free to delete a store that mattered, or to reorder past
//! a load. A memory access the IL INVENTS creates a false dependency, which
//! blocks optimisation and can make an instruction look like it faults.
//!
//! Both directions are defects, so both are swept — the same discipline that
//! closed the control-flow class (`control_transfers_emit_terminators.rs`),
//! where checking only one direction would have missed half of it.
//!
//! # The independent oracle
//!
//! `iced_x86::InstructionInfoFactory::info(&insn).used_memory()` reports, per
//! memory operand, whether it is Read, Write or ReadWrite. That is the decoder's
//! own answer, derived from its instruction database rather than from this
//! crate's lifter, so it is a genuinely second description of the same fact.
//!
//! Verified before use rather than assumed: `8b 03` (`mov eax,[rbx]`) reports
//! `access=Read`, `89 03` (`mov [rbx],eax`) reports `access=Write`, and a
//! register-only form reports nothing.
//!
//! Encodings are synthesised across the opcode maps with a MEMORY-form ModRM
//! (`mod=00`), never written by hand.

use std::collections::BTreeMap;

use iced_x86::{
    Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, OpKind,
};
#[path = "common/mod.rs"]
mod common;

use rustre_arch_x86::lift_to_llil_with_bits;
use rustre_il_llil::{LlilExpr, LlilInstruction};

/// Does this IL sequence contain a memory LOAD anywhere in an expression?
fn has_load(llil: &[rustre_il_llil::LlilAnnotatedInstr]) -> bool {
    fn expr_has_load(e: &LlilExpr) -> bool {
        // `Load` is the only expression that reads memory; everything else is
        // scanned structurally via the debug rendering, which is exact enough
        // for "does a load appear anywhere" and immune to new variants being
        // added without this test noticing.
        format!("{e:?}").contains("Load {")
    }
    llil.iter().any(|ai| {
        // `Pop` and `Ret` carry their stack READ implicitly, same reasoning as
        // `Push`/`Call` in `has_store`.
        if matches!(
            ai.instr,
            LlilInstruction::Pop { .. } | LlilInstruction::Ret | LlilInstruction::Return { .. }
        ) {
            return true;
        }
        let rendered = format!("{:?}", ai.instr);
        rendered.contains("Load {") || {
            match &ai.instr {
                LlilInstruction::SetReg { value, .. } => expr_has_load(value),
                _ => false,
            }
        }
    })
}

fn has_store(llil: &[rustre_il_llil::LlilAnnotatedInstr]) -> bool {
    // `Push` and `Call` carry their stack WRITE implicitly: this IL has
    // dedicated nodes for them rather than lowering to `rsp -= n; [rsp] = v`.
    // Looking only for `Store` reported `push [rbx]` and `call [rbx]` as
    // unmodelled writes — the oracle being too literal, not a defect. Verified
    // by lifting them and reading the IL, not assumed.
    llil.iter().any(|ai| {
        matches!(
            ai.instr,
            LlilInstruction::Store { .. }
                | LlilInstruction::Push { .. }
                | LlilInstruction::Call(..)
                | LlilInstruction::CondCall { .. }
        )
    })
}

#[test]
fn modelled_memory_accesses_match_the_decoder() {
    // BOTH modes: every sweep in this crate hard-coded 64-bit, leaving 32-bit
    // lifting entirely unmeasured even though the lifter supports it.
    // Instructions INVALID in 64-bit (AAM/AAD/BCD, PUSHA/POPA, the segment ops)
    // only appear here.
    for bits in [16u32, 32, 64] {
        sweep_memory_effects(bits);
    }
}

fn sweep_memory_effects(bits: u32) {
    // Shared encoding space — see `tests/common/mod.rs`. This oracle used to
    // carry its own narrower copy (legacy maps only, one ModRM form), which is
    // exactly the asymmetry that lets a defect survive in one oracle's blind
    // spot while its siblings look clean.
    let stems = common::opcode_stems();
    let modrms = common::modrms(0b011);

    let mut factory = InstructionInfoFactory::new();
    let mut checked = 0usize;
    let mut by_kind: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
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

                    // MPX (`BND*`) shares encoding space with reserved NOPs and
                    // only decodes with this option — without it the whole family
                    // was invisible to this sweep.
                    let mut dec =
                        Decoder::with_ip(bits, &bytes, 0x1000, DecoderOptions::MPX);
                    let insn = dec.decode();
                    if insn.is_invalid() {
                        continue;
                    }
                    // Only encodings that really carry a memory operand.
                    if !(0..insn.op_count()).any(|k| insn.op_kind(k) == OpKind::Memory) {
                        continue;
                    }

                    let info = factory.info(&insn);
                    let mut want_read = false;
                    let mut want_write = false;
                    for m in info.used_memory() {
                        match m.access() {
                            OpAccess::Read | OpAccess::CondRead => want_read = true,
                            OpAccess::Write | OpAccess::CondWrite => want_write = true,
                            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                                want_read = true;
                                want_write = true;
                            }
                            _ => {}
                        }
                    }
                    let mnemonic_early =
                        format!("{:?}", insn.mnemonic()).to_lowercase();
                    if !want_read && !want_write {
                        // A memory OPERAND with NO ACCESS: the instruction uses
                        // the ADDRESS, it does not dereference it. `LEA` is the
                        // classic; MPX's `BNDMK`/`BNDLDX`/`BNDSTX` are the same
                        // shape. Modelling a `Load` here INVENTS a read that can
                        // fault and that no analysis should see.
                        //
                        // This direction was missing from the oracle entirely —
                        // it only ever checked missing load, missing store and
                        // invented store. Found by following the `_effect_only`
                        // test-name rule to the MPX family.
                        if seen.insert(format!("noaccess:{mnemonic_early}")) {
                            checked += 1;
                            let llil = lift_to_llil_with_bits(&insn, bits);
                            if has_load(&llil) {
                                by_kind.entry("INVENTED load").or_default().push(format!(
                                    "{mnemonic_early} ({bytes:02x?}): decoder reports NO memory                                      access (address-only operand), IL loads"
                                ));
                            }
                        }
                        continue;
                    }

                    let mnemonic = format!("{:?}", insn.mnemonic()).to_lowercase();
                    if !seen.insert(mnemonic.clone()) {
                        continue;
                    }
                    checked += 1;

                    let llil = lift_to_llil_with_bits(&insn, bits);
                    let got_load = has_load(&llil);
                    let got_store = has_store(&llil);

                    if want_read && !got_load {
                        by_kind.entry("MISSING load").or_default().push(format!(
                            "{mnemonic} ({bytes:02x?}): decoder says the memory operand is READ, \
                             IL models no load"
                        ));
                    }
                    if want_write && !got_store {
                        by_kind.entry("MISSING store").or_default().push(format!(
                            "{mnemonic} ({bytes:02x?}): decoder says the memory operand is \
                             WRITTEN, IL models no store"
                        ));
                    }
                    if !want_write && got_store {
                        by_kind.entry("INVENTED store").or_default().push(format!(
                            "{mnemonic} ({bytes:02x?}): decoder says no memory write, IL stores"
                        ));
                    }
                }
              }
            }
        }
    }

    assert!(
        checked >= 100,
        "sweep degenerated at {bits}-bit: only {checked} memory-touching mnemonics generated"
    );

    // RATCHET, not an allow-list of names.
    //
    // Every current disagreement has ONE root cause: state-heavy x87 and system
    // instructions are lifted through `lift_fpu_generic`, which calls
    // `read_operand` on EVERY operand. For an operand the ISA only WRITES
    // (`fist [rbx]`, `fnstcw [rbx]`, `fnsave [rbx]`) that produces a bogus LOAD
    // and no STORE — so a decompiler sees the location as read and never
    // modified, and dead-store elimination is free to drop the address
    // computation. The mirror case is `fadd [rbx]`, where the IL stores to the
    // x87 stack slot and the decoder rightly reports no memory write.
    //
    // Fixing that means giving the intrinsic helper access-aware operand
    // handling (address instead of load for write-only operands, `Store` of the
    // intrinsic result) — a design change across ~10 instructions, deliberately
    // not improvised. Until then the counts are PINNED: a new instruction with
    // unmodelled memory effects fails here, and the numbers shrink as the
    // families are fixed. Pinning counts rather than names keeps the check
    // sensitive to newcomers without listing 40 mnemonics.
    const PINNED: &[(&str, usize)] = &[
        ("INVENTED store", 0),
        ("MISSING load", 0),
        ("MISSING store", 0),
        ("INVENTED load", 0),
    ];
    let mut regressions: Vec<String> = Vec::new();
    for (kind, entries) in &by_kind {
        let allowed = PINNED
            .iter()
            .find(|(k, _)| k == kind)
            .map_or(0, |(_, n)| *n);
        if entries.len() > allowed {
            regressions.push(format!(
                "{kind}: {} now, {allowed} pinned — {} new:
    {}",
                entries.len(),
                entries.len() - allowed,
                entries.iter().take(8).cloned().collect::<Vec<_>>().join("
    ")
            ));
        }
    }
    for (kind, allowed) in PINNED {
        let now = by_kind.get(kind).map_or(0, std::vec::Vec::len);
        if now < *allowed {
            println!(
                "NOTE: `{kind}` is down to {now} from the pinned {allowed} —                  lower the pin."
            );
        }
    }
    assert!(
        regressions.is_empty(),
        "memory-effect modelling REGRESSED at {bits}-bit over {checked} mnemonics:
  {}",
        regressions.join("
  ")
    );

    let pinned_total: usize = by_kind.values().map(std::vec::Vec::len).sum();
    println!(
        "[{bits}-bit] {checked} memory-touching mnemonics swept; {pinned_total} known          disagreement(s) still pinned (all one root cause — see the comment above),          0 new"
    );
}
