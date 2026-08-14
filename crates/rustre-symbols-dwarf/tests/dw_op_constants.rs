//! The `DW_OP_*` constants, pinned against the DWARF specification.
//!
//! This crate ships three parallel location-expression implementations
//! (`dwarf_expression_evaluator`, `dwarf_location_expr`, `location_expr`) and
//! says so in each of their module docs: "each carries an independent bug set
//! and a fix applied here does not propagate".  `dwarf_location_expr` is the
//! only one that exports its opcode table, so it is the one that can be pinned
//! from outside.
//!
//! Written after `location_expr` was found with the whole `DW_OP_breg*` block
//! shifted up by seven — `0x77..=0x96` instead of `0x70..=0x8F`.  The shift was
//! self-consistent (`0x77 + 31 == 0x96`), so nothing inside that file looked
//! wrong; what gave it away was the spec, the two sibling tables, and the fact
//! that `0x96` is also `DW_OP_nop`.
//!
//! Note on fixtures: the literals below are taken from DWARF 5 §7.7.1, never
//! from the constants under test.  A test written in terms of the symbol it is
//! meant to police cannot fail — that is exactly how the `breg` shift survived
//! its own unit test.

use rustre_symbols_dwarf::dwarf_location_expr as ops;

/// The three 32-entry register blocks, which is where an off-by-N shift does
/// the most damage: the constants bound *ranges*, so a shifted block both drops
/// real opcodes and swallows unrelated ones.
#[test]
fn the_register_blocks_sit_where_the_spec_puts_them() {
    // DWARF 5 §7.7.1, table 7.9.
    assert_eq!(ops::DW_OP_LIT0, 0x30, "DW_OP_lit0");
    assert_eq!(ops::DW_OP_LIT31, 0x4F, "DW_OP_lit31");
    assert_eq!(ops::DW_OP_REG0, 0x50, "DW_OP_reg0");
    assert_eq!(ops::DW_OP_REG31, 0x6F, "DW_OP_reg31");
    assert_eq!(ops::DW_OP_BREG0, 0x70, "DW_OP_breg0");
    assert_eq!(ops::DW_OP_BREG31, 0x8F, "DW_OP_breg31");
}

/// Each block holds exactly 32 entries, and they abut without overlapping.
/// This is the arithmetic form of the same property: it holds regardless of
/// where the blocks start, so it catches a *widened* block that a spot check on
/// the first entry would miss.
#[test]
fn each_register_block_is_exactly_thirty_two_wide() {
    for (name, first, last) in [
        ("lit", ops::DW_OP_LIT0, ops::DW_OP_LIT31),
        ("reg", ops::DW_OP_REG0, ops::DW_OP_REG31),
        ("breg", ops::DW_OP_BREG0, ops::DW_OP_BREG31),
    ] {
        assert_eq!(
            u16::from(last) - u16::from(first),
            31,
            "the DW_OP_{name}0..DW_OP_{name}31 block spans {} entries, not 32",
            u16::from(last) - u16::from(first) + 1
        );
    }

    assert!(
        ops::DW_OP_LIT31 < ops::DW_OP_REG0,
        "the lit and reg blocks overlap"
    );
    assert!(
        ops::DW_OP_REG31 < ops::DW_OP_BREG0,
        "the reg and breg blocks overlap"
    );
}

/// No single-byte opcode may fall inside a register block: the block is matched
/// as a range, so anything inside it is unreachable no matter where its own arm
/// sits.  `DW_OP_bregx`, `DW_OP_piece` and `DW_OP_deref_size` were dead code for
/// exactly this reason while the breg block was shifted.
#[test]
fn no_scalar_opcode_is_swallowed_by_a_register_block() {
    let blocks = [
        ("lit", ops::DW_OP_LIT0, ops::DW_OP_LIT31),
        ("reg", ops::DW_OP_REG0, ops::DW_OP_REG31),
        ("breg", ops::DW_OP_BREG0, ops::DW_OP_BREG31),
    ];

    // Scalar opcodes whose encodings are fixed by DWARF 5 §7.7.1.
    let scalars: &[(&str, u8)] = &[
        ("DW_OP_addr", 0x03),
        ("DW_OP_deref", 0x06),
        ("DW_OP_constu", 0x10),
        ("DW_OP_consts", 0x11),
        ("DW_OP_dup", 0x12),
        ("DW_OP_drop", 0x13),
        ("DW_OP_over", 0x14),
        ("DW_OP_pick", 0x15),
        ("DW_OP_swap", 0x16),
        ("DW_OP_rot", 0x17),
        ("DW_OP_abs", 0x19),
        ("DW_OP_and", 0x1A),
        ("DW_OP_div", 0x1B),
        ("DW_OP_minus", 0x1C),
        ("DW_OP_mod", 0x1D),
        ("DW_OP_mul", 0x1E),
        ("DW_OP_neg", 0x1F),
        ("DW_OP_not", 0x20),
        ("DW_OP_or", 0x21),
        ("DW_OP_plus", 0x22),
        ("DW_OP_plus_uconst", 0x23),
        ("DW_OP_shl", 0x24),
        ("DW_OP_shr", 0x25),
        ("DW_OP_shra", 0x26),
        ("DW_OP_xor", 0x27),
        ("DW_OP_bra", 0x28),
        ("DW_OP_eq", 0x29),
        ("DW_OP_ge", 0x2A),
        ("DW_OP_gt", 0x2B),
        ("DW_OP_le", 0x2C),
        ("DW_OP_lt", 0x2D),
        ("DW_OP_ne", 0x2E),
        ("DW_OP_skip", 0x2F),
        ("DW_OP_regx", 0x90),
        ("DW_OP_fbreg", 0x91),
        ("DW_OP_bregx", 0x92),
        ("DW_OP_piece", 0x93),
        ("DW_OP_deref_size", 0x94),
        ("DW_OP_xderef_size", 0x95),
        ("DW_OP_nop", 0x96),
        ("DW_OP_push_object_address", 0x97),
        ("DW_OP_call2", 0x98),
        ("DW_OP_call4", 0x99),
        ("DW_OP_call_ref", 0x9A),
        ("DW_OP_form_tls_address", 0x9B),
        ("DW_OP_call_frame_cfa", 0x9C),
        ("DW_OP_bit_piece", 0x9D),
        ("DW_OP_implicit_value", 0x9E),
        ("DW_OP_stack_value", 0x9F),
    ];

    for &(name, value) in scalars {
        for (block, first, last) in blocks {
            assert!(
                !(first..=last).contains(&value),
                "{name} ({value:#04x}) falls inside the DW_OP_{block}0..\
                 DW_OP_{block}31 range {first:#04x}..={last:#04x}, so it can \
                 never be reached"
            );
        }
    }

    assert_eq!(scalars.len(), 49, "the scalar table lost entries");
}

/// The scalar opcodes this crate exports must carry their standard encodings.
#[test]
fn exported_scalar_opcodes_match_the_specification() {
    // Literals from DWARF 5 §7.7.1 — deliberately not written in terms of the
    // constants being checked.
    assert_eq!(ops::DW_OP_ADDR, 0x03);
    assert_eq!(ops::DW_OP_DEREF, 0x06);
    assert_eq!(ops::DW_OP_CONSTU, 0x10);
    assert_eq!(ops::DW_OP_CONSTS, 0x11);
    assert_eq!(ops::DW_OP_DUP, 0x12);
    assert_eq!(ops::DW_OP_DROP, 0x13);
    assert_eq!(ops::DW_OP_OVER, 0x14);
    assert_eq!(ops::DW_OP_PICK, 0x15);
    assert_eq!(ops::DW_OP_ROT, 0x17);
    assert_eq!(ops::DW_OP_ABS, 0x19);
    assert_eq!(ops::DW_OP_PLUS_UCONST, 0x23);
    assert_eq!(ops::DW_OP_SKIP, 0x2F);
    assert_eq!(ops::DW_OP_REGX, 0x90);
    assert_eq!(ops::DW_OP_FBREG, 0x91);
    assert_eq!(ops::DW_OP_BREGX, 0x92);
    assert_eq!(ops::DW_OP_PIECE, 0x93);
    assert_eq!(ops::DW_OP_DEREF_SIZE, 0x94);
    assert_eq!(ops::DW_OP_NOP, 0x96);
    assert_eq!(ops::DW_OP_CALL_FRAME_CFA, 0x9C);
    assert_eq!(ops::DW_OP_BIT_PIECE, 0x9D);
    assert_eq!(ops::DW_OP_IMPLICIT_VALUE, 0x9E);
    assert_eq!(ops::DW_OP_STACK_VALUE, 0x9F);
    assert_eq!(ops::DW_OP_IMPLICIT_POINTER, 0xA0);
    assert_eq!(ops::DW_OP_ADDRX, 0xA1);
    assert_eq!(ops::DW_OP_CONSTX, 0xA2);
    assert_eq!(ops::DW_OP_ENTRY_VALUE, 0xA3);
    assert_eq!(ops::DW_OP_CONST_TYPE, 0xA4);
    assert_eq!(ops::DW_OP_CONVERT, 0xA8);
}
