//! Differential cross-check: the TWO hand-written x86 sub-register alias
//! models in this workspace.
//!
//! # Why this file exists
//!
//! x86-64's sub-register rules are stated once in the manual and implemented
//! twice here, independently:
//!
//!   * `rustre_il_llil::llil_interpreter::CpuState::{read,write}_reg_aliased`
//!     — the IL interpreter's model (`x86_alias` table);
//!   * `IState::write_named` inside `tests/semantics_oracle.rs` — the model the
//!     hardware oracle uses.
//!
//! Only the second has ever been checked against real silicon, and thoroughly:
//! ~136 encodings executed on the host CPU agree with it, including the
//! partial-register cases (`mov al, bl`, `mov ah, bh`, `add ah, bh`,
//! `mov eax, ebx`) and the 16-bit family added 2026-07-28. The first has unit
//! tests only.
//!
//! So this compares the unvalidated model against the validated one. Where they
//! disagree, `il-llil` is wrong — transitively against the CPU. This is the same
//! "two independent descriptions of one machine fact" pairing that found the
//! REP/DF, ICEBP, REX-nullification and CMPXCHG defects in this session; it is
//! cheaper than a second JIT harness and no less decisive.
//!
//! # The rules being compared
//!
//! * a 64-bit write replaces the register;
//! * a 32-bit write ZERO-EXTENDS, clearing bits 63:32;
//! * an 8/16-bit write PRESERVES the surrounding bits (read-modify-write);
//! * `ah`/`bh`/`ch`/`dh` address byte 1, not byte 0.
//!
//! The corpus is every alias name crossed with edge-case values, generated
//! rather than hand-listed.

use rustre_il_llil::llil_interpreter::CpuState;

/// Reference model, mirroring `semantics_oracle.rs::IState::write_named` — the
/// silicon-validated one. Kept as a small local copy ON PURPOSE: importing it
/// is impossible across test binaries, and re-deriving it here from the same
/// stated rules is what makes this a differential rather than a tautology.
fn reference_write(old_parent: u64, shift: u32, bits: u32, value: u64) -> u64 {
    match bits {
        64 => value,
        32 => value & 0xFFFF_FFFF,
        b => {
            let m = ((1u64 << b) - 1) << shift;
            (old_parent & !m) | ((value << shift) & m)
        }
    }
}

fn reference_read(parent: u64, shift: u32, bits: u32) -> u64 {
    if bits >= 64 {
        parent
    } else {
        (parent >> shift) & ((1u64 << bits) - 1)
    }
}

/// (alias name, 64-bit parent name, bit offset within the parent, width bits).
/// Written out so the test states the rule it is checking instead of asking the
/// model under test what the rule is.
const ALIASES: &[(&str, &str, u32, u32)] = &[
    ("rax", "rax", 0, 64), ("eax", "rax", 0, 32), ("ax", "rax", 0, 16),
    ("al", "rax", 0, 8), ("ah", "rax", 8, 8),
    ("rbx", "rbx", 0, 64), ("ebx", "rbx", 0, 32), ("bx", "rbx", 0, 16),
    ("bl", "rbx", 0, 8), ("bh", "rbx", 8, 8),
    ("rcx", "rcx", 0, 64), ("ecx", "rcx", 0, 32), ("cx", "rcx", 0, 16),
    ("cl", "rcx", 0, 8), ("ch", "rcx", 8, 8),
    ("rdx", "rdx", 0, 64), ("edx", "rdx", 0, 32), ("dx", "rdx", 0, 16),
    ("dl", "rdx", 0, 8), ("dh", "rdx", 8, 8),
    ("rsi", "rsi", 0, 64), ("esi", "rsi", 0, 32), ("si", "rsi", 0, 16),
    ("rdi", "rdi", 0, 64), ("edi", "rdi", 0, 32), ("di", "rdi", 0, 16),
    ("rbp", "rbp", 0, 64), ("ebp", "rbp", 0, 32),
    ("r8", "r8", 0, 64), ("r8d", "r8", 0, 32), ("r8w", "r8", 0, 16),
    ("r8b", "r8", 0, 8),
    ("r15", "r15", 0, 64), ("r15d", "r15", 0, 32), ("r15w", "r15", 0, 16),
    ("r15b", "r15", 0, 8),
];

const SEEDS: &[u64] = &[
    0,
    u64::MAX,
    0x1234_5678_9ABC_DEF0,
    0xFFFF_FFFF_0000_0000,
    0x0000_0000_FFFF_FFFF,
    0xDEAD_BEEF_CAFE_BABE,
    0x8000_0000_0000_0001,
];

const VALUES: &[u64] = &[
    0,
    1,
    0x7F,
    0x80,
    0xFF,
    0xFFFF,
    0xFFFF_FFFF,
    u64::MAX,
    0x1122_3344_5566_7788,
];

#[test]
fn il_llil_alias_model_agrees_with_the_silicon_validated_one() {
    let mut compared = 0usize;
    let mut by_kind: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut examples: Vec<String> = Vec::new();

    for &(name, parent, shift, bits) in ALIASES {
        for &seed in SEEDS {
            for &value in VALUES {
                // ── WRITE: does the parent end up the same? ──
                let mut cpu = CpuState::new(8);
                cpu.write_reg(parent, seed);
                cpu.write_reg_aliased(name, value);
                let got_parent = cpu.read_reg(parent);
                let want_parent = reference_write(seed, shift, bits, value);
                compared += 1;
                if got_parent != want_parent {
                    *by_kind.entry(format!("write:{bits}-bit")).or_insert(0) += 1;
                    if examples.len() < 12 {
                        examples.push(format!(
                            "write {name} = {value:#x} over {parent}={seed:#x}: \
                             il-llil {got_parent:#x}, reference {want_parent:#x}"
                        ));
                    }
                }

                // ── READ: does the alias observe the right slice? ──
                let mut cpu = CpuState::new(8);
                cpu.write_reg(parent, seed);
                let got = cpu.read_reg_aliased(name);
                let want = reference_read(seed, shift, bits);
                compared += 1;
                if got != want {
                    *by_kind.entry(format!("read:{bits}-bit")).or_insert(0) += 1;
                    if examples.len() < 12 {
                        examples.push(format!(
                            "read {name} from {parent}={seed:#x}: \
                             il-llil {got:#x}, reference {want:#x}"
                        ));
                    }
                }
            }
        }
    }

    // Anti-degeneracy: a comparison over an empty alias list would pass while
    // proving nothing.
    assert!(
        compared >= 2000,
        "cross-check degenerated: only {compared} comparisons"
    );

    assert!(
        by_kind.is_empty(),
        "the two alias models disagree on {} of {compared} comparisons\n\
         \nBY KIND (one rule many times, or many distinct bugs?):\n  {}\n\
         \nEXAMPLES:\n  {}",
        by_kind.values().sum::<usize>(),
        by_kind
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n  "),
        examples.join("\n  ")
    );

    println!("alias models agree over {compared} comparisons");
}
