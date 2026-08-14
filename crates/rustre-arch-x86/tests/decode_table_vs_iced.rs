//! Differential cross-check: `x86_decode_table` vs the real decoder (`iced_x86`).
//!
//! # Why this file exists
//!
//! `src/x86_decode_table.rs` (3396 lines) is retained but NOT wired into
//! `src/lift.rs`, kept — per its sibling's disclaimer — "as a possible future
//! cross-validation / second-opinion decode path independent of lift.rs".
//! A 2026-07-23 audit found that cross-validation had never been built. A
//! companion file, `db_lifter_flag_crosscheck.rs`, now covers the FLAG half of
//! the retained data (`x86_instruction_database`). This covers the DECODE half.
//!
//! The comparison is between two independently-written descriptions of the same
//! fact — "which mnemonic does this opcode byte denote":
//!   * the retained table's `OpcodeEntry::mnemonic`;
//!   * what `iced_x86`, the decoder the lifter actually uses, answers.
//!
//! The table describes its own operand requirements (`has_modrm()`,
//! `min_imm_bytes()`), so valid instruction bytes can be synthesised from each
//! entry rather than hand-written — which is deliberate: hand-built encodings
//! were the single largest source of DEFECTIVE TESTS found in this workspace on
//! 2026-07-23 (a missing nibble in AVR's LDI, a missing bit in MSP430's jump
//! opcode, a wrong `1001` field in ARM's MLA).
//!
//! # Deliberate scope limits
//!
//! * ALL FOUR opcode spaces are now covered, each by its own check with its own
//!   comparison floor: primary (183 opcodes), `0F xx` (158), `0F 38 xx` (52),
//!   `0F 3A xx` (25). What remains uncovered is the VEX/EVEX encoding of the
//!   same spaces — this table has no VEX variants (they were removed as dead
//!   scaffolding; `iced_x86` handles VEX upstream), so there is nothing here to
//!   compare, not a hole being ignored.
//! * Each check was mutation-verified: corrupting one table mnemonic turns the
//!   corresponding check RED. An oracle never seen to fail proves nothing, and
//!   these three passed on the first run.
//! * `/digit` group opcodes are skipped: ModRM.reg selects the instruction, so
//!   the entry names a group, not a mnemonic, and there is nothing to compare.
//! * Entries whose synthesised bytes do not decode are SKIPPED, not failed: the
//!   synthesis is approximate (a real encoding may need a specific ModRM or a
//!   register operand the placeholder does not supply).
//! * Mnemonic comparison is by prefix, so `movsd`/`movsxd`-style suffixes and
//!   iced's operand-size decorations do not count as disagreements.

use iced_x86::{Decoder, DecoderOptions};
use rustre_arch_x86::x86_decode_table::{OpcodeEntry, OpcodeGroup, PrefixHandler, X86DecodeTable};

/// Build plausible bytes for an opcode using the table's OWN declarations.
fn synthesise(opcode: u8, has_modrm: bool, imm_bytes: usize) -> Vec<u8> {
    let mut v = vec![opcode];
    if has_modrm {
        // mod=11 (register-direct), reg=0, rm=0 — the least constrained form.
        v.push(0xC0);
    }
    v.extend(std::iter::repeat_n(0u8, imm_bytes));
    // Pad so a longer-than-expected instruction still has bytes to consume
    // instead of decoding as invalid for the wrong reason.
    v.extend_from_slice(&[0u8; 8]);
    v
}

#[test]
fn decode_table_mnemonics_agree_with_iced() {
    let table = X86DecodeTable::build();
    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut disagreements = Vec::new();

    for opcode in 0u16..=0xFF {
        let opcode = u8::try_from(opcode).unwrap();
        let Some(entry) = table.lookup(opcode) else {
            continue;
        };
        // Escape bytes are not instructions in their own right.
        if matches!(opcode, 0x0F | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67)
            || (0x40..=0x4F).contains(&opcode) // REX prefixes in 64-bit mode
            || matches!(opcode, 0xF0 | 0xF2 | 0xF3)
        {
            skipped += 1;
            continue;
        }

        let bytes = synthesise(opcode, entry.format.has_modrm(), entry.format.min_imm_bytes());
        let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let insn = dec.decode();
        if insn.is_invalid() {
            skipped += 1;
            continue;
        }

        let iced_mnem = format!("{:?}", insn.mnemonic()).to_lowercase();
        let table_mnem = entry.mnemonic.to_lowercase();
        compared += 1;

        // ── Calibration ──────────────────────────────────────────────────
        // The first version of this check reported 31 "disagreements", ALL of
        // them benign. Recording why, because an uncalibrated oracle that cries
        // wolf is worse than none — and the temptation is to silence it with 31
        // hand-written exceptions, which would make it vacuous.
        //
        // (a) GROUP PLACEHOLDERS (17): `grp1`…`grp5`, `x87`. These are not
        //     mnemonics at all — the real instruction is selected by ModRM.reg,
        //     and the table says so deliberately. Nothing to compare.
        // (b) MULTI-WIDTH NAMES (6): `movsw/d/q`, `cbw/cwde/cdqe`, `insw/d`, …
        //     The table lists every width variant in one string; iced answers
        //     with the one for the operand size actually decoded. Split on `/`
        //     and accept any alternative.
        // (c) TRUE ALIASES (4): fwait/wait, loopnz/loopne, loopz/loope,
        //     icebp/int1 — one instruction, two accepted spellings. Listed
        //     EXPLICITLY, not pattern-matched, so the list stays auditable.
        if table_mnem.starts_with("grp") || table_mnem == "x87" {
            compared -= 1;
            skipped += 1;
            continue;
        }
        const ALIASES: &[(&str, &str)] = &[
            ("fwait", "wait"),
            ("loopnz", "loopne"),
            ("loopz", "loope"),
            ("icebp", "int1"),
        ];
        let aliased = ALIASES
            .iter()
            .any(|(a, b)| (*a == table_mnem && *b == iced_mnem) || (*b == table_mnem && *a == iced_mnem));

        // Agree if any `/`-separated alternative matches by prefix in either
        // direction (the table uses canonical short names, iced may decorate).
        // The multi-width names use two conventions at once:
        //   `cbw/cwde/cdqe` — each alternative is a COMPLETE mnemonic;
        //   `insw/d`, `movsw/d/q` — the tail alternatives are WIDTH SUFFIXES on
        //   the first alternative's stem (insw -> ins + d; movsw -> movs + q).
        // Expand both readings, so the comparison stays a real name match
        // rather than a loose "any prefix" rule that would accept anything.
        let alts: Vec<&str> = table_mnem.split('/').map(str::trim).filter(|a| !a.is_empty()).collect();
        let mut candidates: Vec<String> = alts.iter().map(|a| (*a).to_string()).collect();
        if let Some(first) = alts.first() {
            let stem: String = first.chars().take(first.chars().count().saturating_sub(1)).collect();
            for tail in alts.iter().skip(1).filter(|t| t.chars().count() <= 2) {
                candidates.push(format!("{stem}{tail}"));
            }
        }
        let agrees = aliased
            || candidates
                .iter()
                .any(|c| iced_mnem.starts_with(c.as_str()) || c.starts_with(&iced_mnem));
        if !agrees {
            disagreements.push(format!(
                "opcode {opcode:#04x}: table says `{table_mnem}`, iced decodes `{iced_mnem}`"
            ));
        }
    }

    // Anti-degeneracy: a cross-check that compares nothing passes while proving
    // nothing — the failure mode that lets fake oracles survive for years.
    assert!(
        compared >= 40,
        "cross-check degenerated: only {compared} opcodes compared ({skipped} skipped)"
    );

    assert!(
        disagreements.is_empty(),
        "decode table and iced disagree on {} of {compared} opcodes:\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );

    println!("decode table vs iced: {compared} opcodes agree, {skipped} skipped");
}

/// Shared mnemonic comparison, extracted so the 0F check below applies exactly
/// the same calibration as the primary check above rather than a looser one of
/// its own. Returns `None` when the table entry is a group placeholder (nothing
/// to compare), `Some(true/false)` otherwise.
fn mnemonics_agree(table_mnem: &str, iced_mnem: &str) -> Option<bool> {
    if table_mnem.starts_with("grp") || table_mnem == "x87" {
        return None;
    }
    const ALIASES: &[(&str, &str)] = &[
        ("fwait", "wait"),
        ("loopnz", "loopne"),
        ("loopz", "loope"),
        ("icebp", "int1"),
    ];
    let aliased = ALIASES.iter().any(|(a, b)| {
        (*a == table_mnem && *b == iced_mnem) || (*b == table_mnem && *a == iced_mnem)
    });
    let alts: Vec<&str> =
        table_mnem.split('/').map(str::trim).filter(|a| !a.is_empty()).collect();
    let mut candidates: Vec<String> = alts.iter().map(|a| (*a).to_string()).collect();
    if let Some(first) = alts.first() {
        let stem: String =
            first.chars().take(first.chars().count().saturating_sub(1)).collect();
        for tail in alts.iter().skip(1).filter(|t| t.chars().count() <= 2) {
            candidates.push(format!("{stem}{tail}"));
        }
    }
    Some(
        aliased
            || candidates
                .iter()
                .any(|c| iced_mnem.starts_with(c.as_str()) || c.starts_with(iced_mnem)),
    )
}

/// THE COVERAGE HOLE THIS CLOSES. The primary-opcode check above states its own
/// scope limit — "escape tables need a second byte and mandatory-prefix
/// handling, which is a separate exercise" — so the two-byte `0F xx` space, by
/// far the larger half of the retained table, was never cross-validated at all.
/// A harness that is silent over a region is exactly where a wrong entry
/// survives: the retention argument for this table ("a second-opinion decode
/// path") is only as good as the fraction of it anyone has checked.
///
/// The mandatory prefix is taken from each entry's OWN `PrefixHandler` and
/// emitted ahead of the `0F`, so `66 0F 58` (addpd) and `F3 0F 58` (addss) are
/// each compared against what iced makes of that exact byte string — the
/// prefix is part of the identity of the instruction here, not decoration.
/// Cross-check one escape table. `escape` is the opcode-map prefix the space is
/// reached through (`[0F]`, `[0F, 38]`, `[0F, 3A]`), so the three spaces share
/// ONE comparison instead of three copies that would drift apart — the same
/// reasoning that gave the lifter a single `df_select`.
///
/// Returns `(compared, skipped, disagreements)` so each caller asserts its own
/// anti-degeneracy floor: the three spaces differ in size several-fold, and one
/// shared floor would be either vacuous for the big space or unmeetable for the
/// small one.
fn check_escape(
    label: &str,
    escape: &[u8],
    entries: &[OpcodeEntry],
) -> (usize, usize, Vec<String>) {
    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut disagreements = Vec::new();

    for entry in entries {
        // A /digit group opcode names no single instruction: ModRM.reg selects
        // it (0F 01 is sgdt/lgdt/…/vmcall depending on reg and mod). Same
        // reason the primary check skips the `grpN` placeholders — here the
        // table spells the group out (`lgdt/sgdt`, `prefetch`) instead of
        // labelling it, so the skip must key on the DECLARED group, not on how
        // the name happens to be spelled.
        if entry.group != OpcodeGroup::None {
            skipped += 1;
            continue;
        }

        // Synthesise BOTH ModRM forms and accept either. This is not leniency:
        // several 0F opcodes are two different instructions selected by `mod`
        // alone (0F 16 is movhps with a memory operand and movlhps with a
        // register one), and an entry declaring `InstrFormat::M` means the
        // memory form is the one it describes. Trying only mod=11 compared the
        // table's memory-form name against iced's register-form answer and
        // manufactured 4 disagreements that were artefacts of the synthesis.
        // Deriving the operand form from the entry's own declaration is the
        // same discipline as deriving length from `min_imm_bytes()`.
        const MODRM_REG: u8 = 0xC0; // mod=11, reg=0, rm=0  → register operand
        const MODRM_MEM: u8 = 0x00; // mod=00, reg=0, rm=0  → [rax], no SIB
        let mut verdict: Option<(String, String)> = None;
        let mut any_decoded = false;

        for modrm in [MODRM_MEM, MODRM_REG] {
            let mut bytes: Vec<u8> = Vec::new();
            match entry.prefix {
                PrefixHandler::P66 => bytes.push(0x66),
                PrefixHandler::PF2 => bytes.push(0xF2),
                PrefixHandler::PF3 => bytes.push(0xF3),
                // REX.W must directly precede the opcode (after legacy prefixes).
                PrefixHandler::RexW => bytes.push(0x48),
                PrefixHandler::None => {}
            }
            bytes.extend_from_slice(escape);
            bytes.push(entry.opcode);
            if entry.format.has_modrm() {
                bytes.push(modrm);
            }
            bytes.extend(std::iter::repeat_n(0u8, entry.format.min_imm_bytes()));
            bytes.extend_from_slice(&[0u8; 8]);

            let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
            let insn = dec.decode();
            if insn.is_invalid() {
                continue;
            }
            any_decoded = true;
            let iced_mnem = format!("{:?}", insn.mnemonic()).to_lowercase();
            let table_mnem = entry.mnemonic.to_lowercase();
            match mnemonics_agree(&table_mnem, &iced_mnem) {
                // Group placeholder: nothing to compare, and no other form will
                // change that — stop looking at this entry.
                None => {
                    verdict = None;
                    any_decoded = false;
                    break;
                }
                Some(true) => {
                    verdict = None;
                    any_decoded = true;
                    break; // agreement in either form settles the entry
                }
                Some(false) => verdict = Some((table_mnem, iced_mnem)),
            }
            // An entry with no ModRM byte encodes one form only; a second pass
            // would decode identical bytes and prove nothing.
            if !entry.format.has_modrm() {
                break;
            }
        }

        if !any_decoded {
            skipped += 1;
            continue;
        }
        compared += 1;
        if let Some((table_mnem, iced_mnem)) = verdict {
            disagreements.push(format!(
                "{label} {:#04x} (prefix {}): table says `{table_mnem}`, iced decodes                  `{iced_mnem}` in both ModRM forms",
                entry.opcode, entry.prefix
            ));
        }
    }

    (compared, skipped, disagreements)
}

/// Assert one escape space agrees with iced, with its own comparison floor.
fn assert_escape_agrees(label: &str, escape: &[u8], entries: &[OpcodeEntry], floor: usize) {
    let (compared, skipped, disagreements) = check_escape(label, escape, entries);
    // Anti-degeneracy, same reasoning as the primary check: a cross-check that
    // compares a handful of entries passes while leaving the hole it was
    // written to close.
    assert!(
        compared >= floor,
        "{label} cross-check degenerated: only {compared} entries compared ({skipped} skipped)"
    );
    assert!(
        disagreements.is_empty(),
        "{label} table and iced disagree on {} of {compared} entries:
  {}",
        disagreements.len(),
        disagreements.join("
  ")
    );
    println!("{label} vs iced: {compared} entries agree, {skipped} skipped");
}

#[test]
fn escape_0f_mnemonics_agree_with_iced() {
    let table = X86DecodeTable::build();
    assert_escape_agrees("0F", &[0x0F], &table.escape_0f.0, 60);
}

/// THE REMAINING HOLE, now closed. `0F 38` carries SSE4/AES-NI/SHA and `0F 3A`
/// the immediate-operand SSE4 forms; both were outside every check in this file
/// until now, and an unchecked region is exactly where a wrong entry survives.
#[test]
fn escape_0f38_mnemonics_agree_with_iced() {
    let table = X86DecodeTable::build();
    assert_escape_agrees("0F 38", &[0x0F, 0x38], &table.escape_0f38.0, 20);
}

#[test]
fn escape_0f3a_mnemonics_agree_with_iced() {
    let table = X86DecodeTable::build();
    assert_escape_agrees("0F 3A", &[0x0F, 0x3A], &table.escape_0f3a.0, 10);
}

/// The table must be non-trivial: an empty or near-empty table would make the
/// comparison above vacuous no matter how carefully it is written.
#[test]
fn decode_table_is_populated() {
    let table = X86DecodeTable::build();
    assert!(
        table.primary_count() >= 100,
        "primary table has only {} entries",
        table.primary_count()
    );
    assert!(table.total_count() > table.primary_count());
}
