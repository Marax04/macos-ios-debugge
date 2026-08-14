//! Sub-registers must collapse onto their 64-bit parent's type-var slot.
//!
//! # Why this test exists
//!
//! `typevar_for_register` assigns each x86-64 GPR a fixed slot so that two
//! independent passes over the same function produce identical type-vars. That
//! only holds if `AL`, `AX`, `EAX` and `RAX` all land on the **same** slot: if
//! they did not, writing `al` and reading `rax` would look like two unrelated
//! values and the solver would never merge them.
//!
//! The function used to carry eight explicit arms — `Register::EAX => 1`
//! through `EDI => 8` — after already calling `full_register()`. Measured, they
//! were unreachable: `full_register()` maps `EAX → RAX`, `AL → RAX`,
//! `AX → RAX`, `R8D → R8` and `SPL → RSP`. They were removed.
//!
//! They were worse than redundant. Listing only the 32-bit aliases implied that
//! *only* those were handled, inviting someone to "complete" the list with the
//! byte or `R8D`-style registers — work that would be dead on arrival, and that
//! could easily introduce a wrong slot while looking like a fix.
//!
//! So this test replaces those arms with the property they were trying to
//! express, checked across all four width families.

use iced_x86::Register;
use rustre_analysis_typerecov::mem_access_scanner::typevar_for_register;

/// Every width of the same architectural register must share one slot.
#[test]
fn all_widths_of_a_register_share_one_slot() {
    let families: &[(&str, &[Register])] = &[
        ("rax", &[Register::RAX, Register::EAX, Register::AX, Register::AL]),
        ("rcx", &[Register::RCX, Register::ECX, Register::CX, Register::CL]),
        ("rdx", &[Register::RDX, Register::EDX, Register::DX, Register::DL]),
        ("rbx", &[Register::RBX, Register::EBX, Register::BX, Register::BL]),
        ("rsp", &[Register::RSP, Register::ESP, Register::SP, Register::SPL]),
        ("rbp", &[Register::RBP, Register::EBP, Register::BP, Register::BPL]),
        ("rsi", &[Register::RSI, Register::ESI, Register::SI, Register::SIL]),
        ("rdi", &[Register::RDI, Register::EDI, Register::DI, Register::DIL]),
        ("r8", &[Register::R8, Register::R8D, Register::R8W, Register::R8L]),
        ("r15", &[Register::R15, Register::R15D, Register::R15W, Register::R15L]),
    ];

    for (name, regs) in families {
        let slots: Vec<_> = regs.iter().map(|r| typevar_for_register(*r)).collect();
        let first = slots[0];
        assert!(first.is_some(), "{name}: il registro a 64 bit deve avere uno slot");
        for (r, s) in regs.iter().zip(&slots) {
            assert_eq!(
                *s, first,
                "{name}: {r:?} finisce su uno slot diverso dal suo parent a 64 bit — \
                 scrivere una sotto-parte e leggere il registro pieno apparirebbe \
                 come due valori scorrelati"
            );
        }
    }
}

/// Distinct architectural registers must **not** share a slot.
///
/// The mirror of the property above, and the one that actually catches a typo:
/// two registers mapped to the same id would merge unrelated types silently,
/// which is exactly the failure a duplicated `=> 1` would cause.
#[test]
fn distinct_registers_do_not_collide() {
    let regs = [
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8, Register::R9, Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    ];
    let mut seen = std::collections::HashMap::new();
    for r in regs {
        let slot = typevar_for_register(r).unwrap_or_else(|| panic!("{r:?} senza slot"));
        if let Some(prev) = seen.insert(slot, r) {
            panic!("{r:?} e {prev:?} condividono lo slot {slot:?}: tipi non correlati verrebbero fusi");
        }
    }
    assert_eq!(seen.len(), 16, "attesi 16 slot distinti, trovati {}", seen.len());
}

/// Registers outside the GPR file have no slot.
///
/// Returning `Some` for an XMM or a segment register would let floating-point
/// or segment state be unified with integer state.
#[test]
fn non_gpr_registers_have_no_slot() {
    for r in [
        Register::XMM0,
        Register::XMM15,
        Register::ES,
        Register::FS,
        Register::ST0,
        Register::RIP,
        Register::None,
    ] {
        assert_eq!(
            typevar_for_register(r),
            None,
            "{r:?} non è un GPR e non deve avere uno slot"
        );
    }
}

/// The mapping must be stable across calls — the whole reason it exists.
#[test]
fn the_mapping_is_deterministic() {
    for _ in 0..3 {
        assert_eq!(typevar_for_register(Register::RAX), typevar_for_register(Register::AL));
        assert_eq!(typevar_for_register(Register::R8), typevar_for_register(Register::R8D));
    }
}
