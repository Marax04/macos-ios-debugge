//! Differential cross-check: `x86_instruction_database` vs the real lifter.
//!
//! # Why this file exists
//!
//! `src/x86_instruction_database.rs` (1210 lines) and `src/x86_decode_table.rs`
//! (3396 lines) are deliberately retained but NOT wired into `src/lift.rs`.
//! Their own doc comment states the justification:
//!
//! > "It is intentionally retained -- not dead code pending removal -- per
//! >  explicit user instruction, as a possible future cross-validation /
//! >  second-opinion decode path independent of lift.rs."
//!
//! A 2026-07-23 wiring audit found that the cross-validation path the
//! disclaimer promised had **never been built**: nothing compared the database
//! against `lift.rs`, so 4606 retained lines produced no signal at all. This
//! file is that missing check, for the part of the database that is genuinely
//! independent and machine-checkable: **which EFLAGS an instruction writes**.
//!
//! Two descriptions of the same semantics, written separately:
//!   * the database's `FlagEffects { writes, clears, sets, undef, … }`;
//!   * the `SetFlag` instructions the lifter actually emits.
//! Where they disagree, at least one is wrong — and neither could tell you so
//! before this test existed.
//!
//! # Deliberate scope limits
//!
//! * Only flags that are **architecturally defined** are compared. `undef`
//!   flags are excluded: the SDM lets the CPU do anything, so the lifter is
//!   free to model them or not.
//! * BOTH directions are now asserted. Modelling a flag the ISA says is not
//!   written is always a defect. The reverse — failing to model one the ISA
//!   does define — was left informational on the theory that the lifter omits
//!   flags nothing consumes; measured, that allowance turned out to be unused
//!   (the gap set is empty across all 42 mnemonics), so it is now a ratchet.
//!   A future case that genuinely cannot be modelled belongs here as a named
//!   exception, not as a silently widened check.
//! * Only mnemonics present in BOTH sources are examined.

use iced_x86::{Decoder, DecoderOptions};
use rustre_arch_x86::x86_instruction_database::{X86InstructionDatabase, eflags};
use rustre_arch_x86::disassemble_and_lift;
use rustre_il_llil::LlilInstruction;

/// One case: a mnemonic as the database spells it, plus bytes that encode it.
struct Case {
    mnemonic: &'static str,
    bytes: &'static [u8],
}

/// Instructions whose encodings are already exercised elsewhere in this crate,
/// so the bytes are known-good and the test is about the FLAGS, not decoding.
const CASES: &[Case] = &[
    Case { mnemonic: "add", bytes: &[0x48, 0x01, 0xD8] },        // add rax, rbx
    Case { mnemonic: "sub", bytes: &[0x48, 0x29, 0xD8] },        // sub rax, rbx
    Case { mnemonic: "adc", bytes: &[0x48, 0x11, 0xD8] },        // adc rax, rbx
    Case { mnemonic: "sbb", bytes: &[0x48, 0x19, 0xD8] },        // sbb rax, rbx
    Case { mnemonic: "and", bytes: &[0x48, 0x21, 0xD8] },        // and rax, rbx
    Case { mnemonic: "or",  bytes: &[0x48, 0x09, 0xD8] },        // or  rax, rbx
    Case { mnemonic: "xor", bytes: &[0x48, 0x31, 0xD8] },        // xor rax, rbx
    Case { mnemonic: "cmp", bytes: &[0x48, 0x39, 0xD8] },        // cmp rax, rbx
    Case { mnemonic: "test", bytes: &[0x48, 0x85, 0xD8] },       // test rax, rbx
    Case { mnemonic: "inc", bytes: &[0x48, 0xFF, 0xC0] },        // inc rax
    Case { mnemonic: "dec", bytes: &[0x48, 0xFF, 0xC8] },        // dec rax
    Case { mnemonic: "neg", bytes: &[0x48, 0xF7, 0xD8] },        // neg rax
    Case { mnemonic: "not", bytes: &[0x48, 0xF7, 0xD0] },        // not rax  (no flags)
    Case { mnemonic: "mov", bytes: &[0x48, 0x89, 0xD8] },        // mov rax, rbx (no flags)
    Case { mnemonic: "lea", bytes: &[0x48, 0x8D, 0x43, 0x08] },  // lea rax,[rbx+8] (no flags)
    Case { mnemonic: "bt",  bytes: &[0x0F, 0xA3, 0xC8] },        // bt eax, ecx
    Case { mnemonic: "bts", bytes: &[0x0F, 0xAB, 0xC8] },        // bts eax, ecx
    // Shifts and rotates: CF/OF are the subtle ones (OF is architecturally
    // UNDEFINED for counts != 1, which `undef` must absorb).
    Case { mnemonic: "shl", bytes: &[0x48, 0xC1, 0xE0, 0x04] },  // shl rax, 4
    Case { mnemonic: "shr", bytes: &[0x48, 0xC1, 0xE8, 0x04] },  // shr rax, 4
    Case { mnemonic: "sar", bytes: &[0x48, 0xC1, 0xF8, 0x04] },  // sar rax, 4
    Case { mnemonic: "rol", bytes: &[0x48, 0xC1, 0xC0, 0x04] },  // rol rax, 4
    Case { mnemonic: "ror", bytes: &[0x48, 0xC1, 0xC8, 0x04] },  // ror rax, 4
    // Multiply / divide: earlier sessions found real defects in the high half.
    Case { mnemonic: "imul", bytes: &[0x48, 0x0F, 0xAF, 0xC3] }, // imul rax, rbx
    Case { mnemonic: "mul",  bytes: &[0x48, 0xF7, 0xE3] },       // mul rbx
    Case { mnemonic: "div",  bytes: &[0x48, 0xF7, 0xF3] },       // div rbx
    Case { mnemonic: "idiv", bytes: &[0x48, 0xF7, 0xFB] },       // idiv rbx
    // Bit scan / count: ZF is defined, the destination is not (source == 0).
    Case { mnemonic: "bsf", bytes: &[0x48, 0x0F, 0xBC, 0xC3] },  // bsf rax, rbx
    Case { mnemonic: "bsr", bytes: &[0x48, 0x0F, 0xBD, 0xC3] },  // bsr rax, rbx
    Case { mnemonic: "popcnt", bytes: &[0xF3, 0x48, 0x0F, 0xB8, 0xC3] },
    // Flag-only and direction-flag instructions.
    Case { mnemonic: "stc", bytes: &[0xF9] },                    // sets CF
    Case { mnemonic: "clc", bytes: &[0xF8] },                    // clears CF
    Case { mnemonic: "cmc", bytes: &[0xF5] },                    // complements CF
    Case { mnemonic: "std", bytes: &[0xFD] },                    // sets DF
    Case { mnemonic: "cld", bytes: &[0xFC] },                    // clears DF
    // Conditional moves / sets READ flags and must write none.
    Case { mnemonic: "cmove", bytes: &[0x48, 0x0F, 0x44, 0xC3] },
    Case { mnemonic: "sete", bytes: &[0x0F, 0x94, 0xC0] },
    // Stack and control flow: must not invent flag writes.
    Case { mnemonic: "push", bytes: &[0x50] },                   // push rax
    Case { mnemonic: "pop",  bytes: &[0x58] },                   // pop rax
    Case { mnemonic: "xchg", bytes: &[0x48, 0x87, 0xD8] },       // xchg rax, rbx
    Case { mnemonic: "bswap", bytes: &[0x48, 0x0F, 0xC8] },      // bswap rax
    Case { mnemonic: "xadd", bytes: &[0x48, 0x0F, 0xC1, 0xD8] }, // xadd rax, rbx
    Case { mnemonic: "cmpxchg", bytes: &[0x48, 0x0F, 0xB1, 0xD8] },
];

/// Map a lifter flag name onto the database's EFLAGS bit.
fn flag_bit(name: &str) -> Option<u16> {
    match name {
        "cf" => Some(eflags::CF),
        "pf" => Some(eflags::PF),
        "af" => Some(eflags::AF),
        "zf" => Some(eflags::ZF),
        "sf" => Some(eflags::SF),
        "of" => Some(eflags::OF),
        "df" => Some(eflags::DF),
        "if" => Some(eflags::IF),
        "tf" => Some(eflags::TF),
        _ => None,
    }
}

fn pretty(mask: u16) -> String {
    let mut v = Vec::new();
    for (n, b) in [
        ("cf", eflags::CF), ("pf", eflags::PF), ("af", eflags::AF),
        ("zf", eflags::ZF), ("sf", eflags::SF), ("of", eflags::OF),
        ("df", eflags::DF), ("if", eflags::IF), ("tf", eflags::TF),
    ] {
        if mask & b != 0 {
            v.push(n);
        }
    }
    if v.is_empty() { "∅".into() } else { v.join("|") }
}

#[test]
fn lifter_never_writes_a_flag_the_database_says_is_untouched() {
    let db = X86InstructionDatabase::build();
    let mut checked = 0usize;
    let mut coverage = Vec::new();
    let mut violations = Vec::new();

    for case in CASES {
        let Some(fe) = db.flag_effects(case.mnemonic) else {
            continue; // not in the database — nothing to cross-check
        };
        checked += 1;

        // Architecturally touched, per the database. `undef` is excluded in
        // BOTH directions: the SDM permits any value, so neither modelling nor
        // omitting such a flag is a defect.
        let defined_writes = (fe.writes | fe.clears | fe.sets) & !fe.undef;

        let mut lifted_mask = 0u16;
        for (_ip, ops) in disassemble_and_lift(case.bytes, 0x1000, 64) {
            for op in &ops {
                if let LlilInstruction::SetFlag { name, .. } = &op.instr
                    && let Some(b) = flag_bit(name)
                {
                    lifted_mask |= b;
                }
            }
        }

        // The always-a-defect direction: the lifter defines a flag the ISA says
        // this instruction does not touch. That silently invents a fact later
        // passes (branch fusion, flag recovery) will trust.
        let invented = lifted_mask & !defined_writes & !fe.undef;
        if invented != 0 {
            violations.push(format!(
                "{}: lifter writes {} which the database says is untouched \
                 (db defines {}, lifter emits {})",
                case.mnemonic,
                pretty(invented),
                pretty(defined_writes),
                pretty(lifted_mask)
            ));
        }

        // Informational: flags the ISA defines that the lifter does not model.
        // Legitimate (the lifter omits what nothing consumes), but worth
        // printing so the gap is visible rather than assumed.
        let unmodelled = defined_writes & !lifted_mask;
        if unmodelled != 0 {
            coverage.push(format!("{}: not modelled {}", case.mnemonic, pretty(unmodelled)));
        }
    }

    assert!(checked >= 10, "cross-check degenerated: only {checked} mnemonics matched");
    assert!(
        violations.is_empty(),
        "lifter/database flag disagreement:\n  {}\n\ncoverage gaps (informational):\n  {}",
        violations.join("\n  "),
        coverage.join("\n  ")
    );

    // RATCHET. This direction used to be informational-only, on the reasoning
    // that the lifter "may legitimately model fewer flags than the ISA
    // defines". Measured on 2026-07-28, that allowance is unused: across all
    // 42 cross-checked mnemonics the gap set is EMPTY — the lifter models every
    // architecturally-defined flag the database declares.
    //
    // So the allowance was costing coverage and buying nothing. Unbounded, a
    // lifter that STOPPED emitting ZF for `add` would keep this test green and
    // merely print one more line, while flag recovery (branch fusion, the SBB
    // conditional idiom) silently lost its input. Asserting the set is empty
    // makes that regression red, and makes any genuinely-unmodellable flag an
    // explicit, reasoned exception instead of a line nobody reads.
    assert!(
        coverage.is_empty(),
        "the lifter stopped modelling flags the ISA defines — if this is \
         deliberate, add the case here with the reason rather than widening \
         the check:\n  {}",
        coverage.join("\n  ")
    );

    // The retained database only earns its keep if the comparison is visible.
    println!("cross-checked {checked} mnemonics; unmodelled-flag gaps: none");
}

/// The database must actually contain the instructions the lifter handles most:
/// a cross-check over an empty intersection would pass while proving nothing.
#[test]
fn database_covers_the_common_arithmetic_mnemonics() {
    let db = X86InstructionDatabase::build();
    for m in ["add", "sub", "and", "or", "xor", "cmp", "test", "inc", "dec", "neg"] {
        assert!(
            db.flag_effects(m).is_some(),
            "database has no flag effects for `{m}` — the cross-check above \
             would silently skip it"
        );
    }
}

/// Sanity: the decoder agrees the test bytes are what the case claims.
/// A mis-encoded case would compare the wrong instruction's flags and could
/// report a phantom disagreement — the exact defect shape found in several
/// hand-built encodings elsewhere in this workspace on 2026-07-23.
#[test]
fn case_bytes_decode_to_their_claimed_mnemonic() {
    for case in CASES {
        let mut dec = Decoder::with_ip(64, case.bytes, 0x1000, DecoderOptions::NONE);
        let insn = dec.decode();
        assert!(!insn.is_invalid(), "case `{}` does not decode", case.mnemonic);
        let text = format!("{insn:?}").to_lowercase();
        assert!(
            text.contains(case.mnemonic),
            "case `{}` decodes as {:?}, not the claimed mnemonic",
            case.mnemonic,
            insn.mnemonic()
        );
    }
}
