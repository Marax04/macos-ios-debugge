//! Regression tests for the DWARF hardening pass.
//!
//! Every test here fails (panics, or asserts a wrong value) against the
//! pre-fix crate.

use std::collections::HashMap;

use rustre_symbols_dwarf::{
    DwarfReader,
    dwarf_abbrev::{DwForm, FormValue, read_form_value},
    dwarf_call_frame::{CfaRule, CfiSection, RegRule},
    dwarf_line_program::LineProgram,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn sleb(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (v == 0 && !sign_bit) || (v == -1 && sign_bit) {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn reader_with(sections: &[(&str, Vec<u8>)]) -> DwarfReader {
    let mut m: HashMap<String, Vec<u8>> = HashMap::new();
    for (k, v) in sections {
        m.insert((*k).to_string(), v.clone());
    }
    DwarfReader::from_sections(m)
}

// ─── 1. line_range == 0 division-by-zero DoS ──────────────────────────────────

/// A `.debug_line` header may legally contain `line_range = 0`; it was then used
/// as a divisor in the special-opcode path and panicked with
/// "attempt to calculate the remainder with a divisor of zero".
#[test]
fn line_info_survives_zero_line_range() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes()); // version = 4
    body.extend_from_slice(&6u32.to_le_bytes()); // header_length
    body.push(1); // minimum_instruction_length
    body.push(1); // maximum_ops_per_insn (v4+)
    body.push(1); // default_is_stmt
    body.push(0); // line_base
    body.push(0); // line_range == 0  <-- the hazard
    body.push(1); // opcode_base = 1 => every opcode takes the special path
    body.push(0); // include_directories terminator
    body.push(0); // file_names terminator
    body.push(0x05); // an opcode >= opcode_base: special path, divides by 0

    let mut sect = Vec::new();
    sect.extend_from_slice(&(body.len() as u32).to_le_bytes());
    sect.extend_from_slice(&body);

    let reader = reader_with(&[(".debug_line", sect)]);
    // Must not panic. The malformed unit is skipped, so no entries.
    let entries = reader.line_info();
    assert!(entries.is_empty(), "malformed unit should yield no entries");
}

/// Same hazard through the standalone `LineProgram` parser: it divided by
/// `line_range` in `decode_special` and in the `DW_LNS_const_add_pc` path.
#[test]
fn line_program_parse_rejects_zero_line_range() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&6u32.to_le_bytes());
    body.push(1);
    body.push(1);
    body.push(1);
    body.push(0);
    body.push(0); // line_range == 0
    body.push(1); // opcode_base
    body.push(0);
    body.push(0);
    body.push(0x05);

    let mut sect = Vec::new();
    sect.extend_from_slice(&(body.len() as u32).to_le_bytes());
    sect.extend_from_slice(&body);

    // Previously this parsed fine and then `execute()` panicked with
    // "attempt to divide by zero".
    assert!(
        LineProgram::parse(&sect, 0).is_err(),
        "a zero line_range must be rejected at parse time"
    );
}

// ─── 2. strx / addrx forms must consume their bytes ───────────────────────────

/// `DW_FORM_strx1..4` / `DW_FORM_addrx1..4` fell into the catch-all arm, which
/// returned success while advancing the cursor by ZERO bytes — silently
/// desynchronising every subsequent attribute and sibling DIE in the unit.
/// clang emits `DW_FORM_strx1` for nearly every name in DWARF 5 output.
#[test]
fn strx_and_addrx_forms_consume_their_operands() {
    let data = [0xAAu8, 0xBB, 0xCC, 0xDD];

    let cases: &[(DwForm, usize, u64)] = &[
        (DwForm::StrX1, 1, 0xAA),
        (DwForm::StrX2, 2, 0xBB_AA),
        (DwForm::StrX3, 3, 0xCC_BB_AA),
        (DwForm::StrX4, 4, 0xDD_CC_BB_AA),
        (DwForm::AddrX1, 1, 0xAA),
        (DwForm::AddrX2, 2, 0xBB_AA),
        (DwForm::AddrX3, 3, 0xCC_BB_AA),
        (DwForm::AddrX4, 4, 0xDD_CC_BB_AA),
    ];

    for &(form, want_len, want_val) in cases {
        let mut pos = 0usize;
        let v = read_form_value(&data, &mut pos, form, 8, false, 0)
            .unwrap_or_else(|| panic!("{form:?} failed to decode"));
        assert_eq!(pos, want_len, "{form:?} consumed the wrong byte count");
        assert_eq!(v, FormValue::Uint(want_val), "{form:?} decoded wrong value");
    }
}

/// `AddrX1` is a 1-byte index, not an `addr_size`-wide address.
#[test]
fn addrx1_fixed_size_is_one_byte() {
    assert_eq!(DwForm::AddrX1.fixed_size(8), Some(1));
    assert_eq!(DwForm::StrX3.fixed_size(8), Some(3));
}

// ─── 3. DWARF 5 unit header layout ────────────────────────────────────────────

/// Build a minimal DWARF-5 `.debug_info` CU containing one `DW_TAG_subprogram`.
/// DWARF 5 §7.5.1 orders the header `version, unit_type, address_size,
/// abbrev_offset` — the old code read `abbrev_offset` before `address_size`
/// (the v2-v4 layout), producing a nonsense offset into `.debug_abbrev`.
fn dwarf5_cu() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    const DW_TAG_COMPILE_UNIT: u64 = 0x11;
    const DW_TAG_SUBPROGRAM: u64 = 0x2e;
    const DW_AT_NAME: u64 = 0x03;
    const DW_AT_LOW_PC: u64 = 0x11;
    const DW_AT_HIGH_PC: u64 = 0x12;
    const DW_AT_DECL_FILE: u64 = 0x3a;
    const DW_FORM_ADDR: u64 = 0x01;
    const DW_FORM_DATA8: u64 = 0x07;
    const DW_FORM_STRING: u64 = 0x08;
    const DW_FORM_IMPLICIT_CONST: u64 = 0x21;

    // .debug_abbrev
    let mut abbrev = Vec::new();
    // code 1: compile_unit, has children, no attrs
    abbrev.extend(uleb(1));
    abbrev.extend(uleb(DW_TAG_COMPILE_UNIT));
    abbrev.push(1); // has children
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(0));
    // code 2: subprogram, no children, name/low_pc/high_pc + implicit_const
    abbrev.extend(uleb(2));
    abbrev.extend(uleb(DW_TAG_SUBPROGRAM));
    abbrev.push(0);
    abbrev.extend(uleb(DW_AT_NAME));
    abbrev.extend(uleb(DW_FORM_STRING));
    // DW_FORM_implicit_const: the value lives here in the abbrev table and
    // consumes ZERO bytes of .debug_info. The old reader errored on it and
    // then resumed parsing from a mid-DIE offset.
    abbrev.extend(uleb(DW_AT_DECL_FILE));
    abbrev.extend(uleb(DW_FORM_IMPLICIT_CONST));
    abbrev.extend(sleb(7));
    abbrev.extend(uleb(DW_AT_LOW_PC));
    abbrev.extend(uleb(DW_FORM_ADDR));
    abbrev.extend(uleb(DW_AT_HIGH_PC));
    abbrev.extend(uleb(DW_FORM_DATA8));
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(0));
    abbrev.push(0); // end of table

    // DIEs
    let mut dies = Vec::new();
    dies.extend(uleb(1)); // compile_unit
    dies.extend(uleb(2)); // subprogram
    dies.extend_from_slice(b"main\0");
    dies.extend_from_slice(&0x4000u64.to_le_bytes()); // low_pc
    dies.extend_from_slice(&0x40u64.to_le_bytes()); // high_pc (length)
    dies.push(0); // end of children
    dies.push(0); // end of CU

    // v5 header: version, unit_type, address_size, abbrev_offset
    let mut body = Vec::new();
    body.extend_from_slice(&5u16.to_le_bytes()); // version = 5
    body.push(0x01); // DW_UT_compile
    body.push(8); // address_size
    body.extend_from_slice(&0u32.to_le_bytes()); // abbrev_offset
    body.extend_from_slice(&dies);

    let mut info = Vec::new();
    info.extend_from_slice(&(body.len() as u32).to_le_bytes());
    info.extend_from_slice(&body);

    (info, abbrev, Vec::new())
}

#[test]
fn dwarf5_unit_header_and_implicit_const_parse() {
    let (info, abbrev, strs) = dwarf5_cu();
    let reader = reader_with(&[
        (".debug_info", info),
        (".debug_abbrev", abbrev),
        (".debug_str", strs),
    ]);

    let funcs = reader.functions();
    assert_eq!(funcs.len(), 1, "DWARF 5 CU should yield exactly one function");
    assert_eq!(funcs[0].name, "main");
    assert_eq!(funcs[0].low_pc, 0x4000);
    // high_pc is a length here, so the end address is low_pc + 0x40.
    assert_eq!(funcs[0].high_pc, 0x4040);
}

/// A version the reader does not understand must be skipped, not mis-parsed
/// with the v2-v4 header layout.
#[test]
fn unknown_unit_version_is_skipped_not_misparsed() {
    let mut body = Vec::new();
    body.extend_from_slice(&99u16.to_le_bytes()); // bogus version
    body.extend_from_slice(&[0u8; 16]);
    let mut info = Vec::new();
    info.extend_from_slice(&(body.len() as u32).to_le_bytes());
    info.extend_from_slice(&body);

    let reader = reader_with(&[(".debug_info", info), (".debug_abbrev", vec![0u8])]);
    assert!(reader.functions().is_empty());
}

// ─── 4. DW_FORM_line_strp resolves against .debug_line_str ───────────────────

/// `DW_FORM_line_strp` (0x1f) indexes `.debug_line_str`, a section the reader
/// never even loaded; offsets were resolved against `.debug_str`, yielding a
/// plausible-but-wrong string (a suffix of some unrelated entry) with no error.
#[test]
fn line_strp_resolves_against_debug_line_str() {
    const DW_TAG_COMPILE_UNIT: u64 = 0x11;
    const DW_TAG_SUBPROGRAM: u64 = 0x2e;
    const DW_AT_NAME: u64 = 0x03;
    const DW_AT_LOW_PC: u64 = 0x11;
    const DW_FORM_ADDR: u64 = 0x01;
    const DW_FORM_LINE_STRP: u64 = 0x1f;

    // .debug_str deliberately holds a decoy at offset 0.
    let debug_str = b"WRONG_FROM_DEBUG_STR\0".to_vec();
    let debug_line_str = b"right_name\0".to_vec();

    let mut abbrev = Vec::new();
    abbrev.extend(uleb(1));
    abbrev.extend(uleb(DW_TAG_COMPILE_UNIT));
    abbrev.push(1);
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(2));
    abbrev.extend(uleb(DW_TAG_SUBPROGRAM));
    abbrev.push(0);
    abbrev.extend(uleb(DW_AT_NAME));
    abbrev.extend(uleb(DW_FORM_LINE_STRP));
    abbrev.extend(uleb(DW_AT_LOW_PC));
    abbrev.extend(uleb(DW_FORM_ADDR));
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(0));
    abbrev.push(0);

    let mut dies = Vec::new();
    dies.extend(uleb(1));
    dies.extend(uleb(2));
    dies.extend_from_slice(&0u32.to_le_bytes()); // line_strp offset 0
    dies.extend_from_slice(&0x1000u64.to_le_bytes());
    dies.push(0);
    dies.push(0);

    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes()); // version 4 layout
    body.extend_from_slice(&0u32.to_le_bytes()); // abbrev_offset
    body.push(8); // address_size
    body.extend_from_slice(&dies);

    let mut info = Vec::new();
    info.extend_from_slice(&(body.len() as u32).to_le_bytes());
    info.extend_from_slice(&body);

    let reader = reader_with(&[
        (".debug_info", info),
        (".debug_abbrev", abbrev),
        (".debug_str", debug_str),
        (".debug_line_str", debug_line_str),
    ]);

    let funcs = reader.functions();
    assert_eq!(funcs.len(), 1);
    assert_eq!(
        funcs[0].name, "right_name",
        "line_strp must resolve in .debug_line_str, not .debug_str"
    );
}

// ─── 5. .eh_frame pointer encodings ───────────────────────────────────────────

/// Assemble one CIE (augmentation "zR", FDE encoding `pcrel|sdata4`) plus one
/// FDE, the overwhelmingly common shape emitted by gcc/clang.
fn eh_frame_pcrel_sdata4() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // ── CIE at offset 0 ──
    let mut cie = Vec::new();
    cie.extend_from_slice(&0u32.to_le_bytes()); // CIE id
    cie.push(1); // version
    cie.extend_from_slice(b"zR\0"); // augmentation
    cie.extend(uleb(1)); // code_alignment_factor
    cie.extend(sleb(-8)); // data_alignment_factor
    cie.extend(uleb(16)); // return_address_register
    // augmentation data: 'R' => one encoding byte
    cie.extend(uleb(1));
    cie.push(0x1B); // DW_EH_PE_pcrel | DW_EH_PE_sdata4
    // initial instructions: DW_CFA_def_cfa(reg=7, off=8), DW_CFA_offset(16, 1)
    cie.push(0x0C);
    cie.extend(uleb(7));
    cie.extend(uleb(8));
    cie.push(0x80 | 16);
    cie.extend(uleb(1));
    while cie.len() % 4 != 0 {
        cie.push(0); // DW_CFA_nop padding
    }
    out.extend_from_slice(&(cie.len() as u32).to_le_bytes());
    out.extend_from_slice(&cie);

    // ── FDE ──
    let fde_start = out.len();
    let mut fde = Vec::new();
    // CIE pointer: distance back from this field to the CIE.
    let cie_ptr_field_off = fde_start + 4;
    fde.extend_from_slice(&(cie_ptr_field_off as u32).to_le_bytes());
    // pc_begin, pcrel-relative to the field's own offset in the section.
    let pc_begin_field_off = fde_start + 8;
    let target: i64 = 0x1000;
    let disp = target - pc_begin_field_off as i64;
    fde.extend_from_slice(&(disp as i32).to_le_bytes()); // sdata4 (4 bytes!)
    fde.extend_from_slice(&0x40i32.to_le_bytes()); // pc_range, sdata4
    fde.extend(uleb(0)); // augmentation length ('z')
    // DW_CFA_advance_loc(1); DW_CFA_def_cfa_offset(16); DW_CFA_restore(16)
    fde.push(0x40 | 1);
    fde.push(0x0E);
    fde.extend(uleb(16));
    fde.push(0xC0 | 16);
    while fde.len() % 4 != 0 {
        fde.push(0);
    }
    out.extend_from_slice(&(fde.len() as u32).to_le_bytes());
    out.extend_from_slice(&fde);

    out
}

/// With `pcrel|sdata4` (low nibble 0x0B) the old decoder consumed 8 bytes for a
/// 4-byte field and ignored the pc-relative base, so `pc_range` was read from
/// the wrong offset and `fde_for_pc` never matched a real PC.
#[test]
fn eh_frame_pcrel_sdata4_fde_is_decoded() {
    let data = eh_frame_pcrel_sdata4();
    let cfi = CfiSection::parse(&data, true);

    assert_eq!(cfi.cies.len(), 1, "expected exactly one CIE");
    assert_eq!(cfi.fdes.len(), 1, "expected exactly one FDE");

    let fde = &cfi.fdes[0];
    assert_eq!(fde.pc_begin, 0x1000, "pcrel base was not applied");
    assert_eq!(fde.pc_range, 0x40, "pc_range read from the wrong offset");
    assert!(fde.covers(0x1000));
    assert!(fde.covers(0x103F));
    assert!(!fde.covers(0x1040));
    assert!(
        cfi.fde_for_pc(0x1010).is_some(),
        "fde_for_pc must find the FDE covering a real PC"
    );
}

/// `Fde::parse` recorded its own section offset as `cie_offset`, so
/// `unwind_table_for_pc`'s CIE lookup never matched and silently fell back to
/// `cies.first()` — wrong `data_align`/`return_addr_reg` whenever a binary has
/// more than one CIE.
#[test]
fn fde_records_the_cie_it_points_at() {
    let data = eh_frame_pcrel_sdata4();
    let cfi = CfiSection::parse(&data, true);
    let fde = &cfi.fdes[0];

    assert_ne!(
        fde.cie_offset, fde.section_offset,
        "cie_offset must be the referenced CIE, not the FDE's own offset"
    );
    assert!(
        cfi.cies.iter().any(|c| c.section_offset == fde.cie_offset),
        "cie_offset must resolve to a real CIE by direct lookup"
    );
}

/// `DW_CFA_restore` must restore the rule the CIE's initial instructions set,
/// not delete the rule outright. The CIE above establishes `ra` via
/// `DW_CFA_offset(16, 1)`; deleting it terminates a backtrace one frame early.
#[test]
fn cfa_restore_restores_the_cie_initial_rule() {
    let data = eh_frame_pcrel_sdata4();
    let cfi = CfiSection::parse(&data, true);
    let table = cfi
        .unwind_table_for_pc(0x1010)
        .expect("unwind table for a covered pc");
    let row = table.row_for_pc(0x1010).expect("row for pc");

    match row.registers.get(&16) {
        Some(RegRule::Offset(off)) => assert_eq!(*off, -8, "ra rule scaled by data_align"),
        other => panic!("DW_CFA_restore dropped the CIE's ra rule: {other:?}"),
    }
    assert_eq!(
        row.cfa,
        CfaRule::RegisterAndOffset { reg: 7, offset: 16 }
    );
}

// ─── 6. Unwinder uses the real CFI program ────────────────────────────────────

/// `unwind_with_eh_frame` used to return a hardcoded x86-64 step
/// (`CFA = rsp+8`, `ra = CFA-8`) for every covered PC regardless of the CFI
/// program. Here the real rule at 0x1010 is `rsp+16`.
#[test]
fn unwinder_honours_the_cfi_program() {
    use rustre_symbols_dwarf::DwarfUnwinder;

    let data = eh_frame_pcrel_sdata4();
    let unwinder = DwarfUnwinder::from_sections(&data, &[]);

    let step = unwinder
        .unwind_at(0x1010)
        .expect("a covered pc should produce an unwind step");
    assert_eq!(step.cfa_register, 7);
    assert_eq!(
        step.cfa_offset, 16,
        "hardcoded cfa_offset=8 instead of the CFI program's 16"
    );
    assert_eq!(step.ra_register, 16);
    assert_eq!(step.ra_cfa_offset, -8);

    // Outside any FDE the unwinder must report failure so the caller can fall
    // back to the frame-pointer chain, not fabricate a step.
    assert!(unwinder.unwind_at(0x9_0000).is_none());
}

// ─── 7. Recursion depth caps ──────────────────────────────────────────────────

/// A `.debug_info` made of repeated has-children abbrevs with no null
/// terminators drove `parse_die_tree` to recurse once per byte, overflowing the
/// stack — an uncatchable abort.
#[test]
fn deeply_nested_dies_do_not_overflow_the_stack() {
    const DW_TAG_LEXICAL_BLOCK: u64 = 0x0b;

    // abbrev code 1: has children, no attributes.
    let mut abbrev = Vec::new();
    abbrev.extend(uleb(1));
    abbrev.extend(uleb(DW_TAG_LEXICAL_BLOCK));
    abbrev.push(1); // has children
    abbrev.extend(uleb(0));
    abbrev.extend(uleb(0));
    abbrev.push(0);

    // 64 KiB of "open another child" and never close one.
    let dies = vec![0x01u8; 64 * 1024];

    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(8);
    body.extend_from_slice(&dies);

    let mut info = Vec::new();
    info.extend_from_slice(&(body.len() as u32).to_le_bytes());
    info.extend_from_slice(&body);

    let reader = reader_with(&[(".debug_info", info), (".debug_abbrev", abbrev)]);
    // Must return rather than abort the process.
    let _ = reader.functions();
}

/// A `DW_FORM_indirect` chain (0x16 0x16 0x16 …) recursed once per byte.
#[test]
fn indirect_form_chain_is_capped() {
    let data = vec![0x16u8; 4096];
    let mut pos = 0usize;
    // Must terminate and report failure rather than blow the stack.
    let v = read_form_value(&data, &mut pos, DwForm::Indirect, 8, false, 0);
    assert!(v.is_none() || pos <= data.len());
}

// ─── 8. Extended line opcodes snap to their declared length ───────────────────

/// DWARF requires an extended opcode to occupy exactly `length` bytes. The
/// handlers advanced by whatever they happened to consume, so a
/// `DW_LNE_set_address` declaring more bytes than it used desynchronised every
/// subsequent row.
#[test]
fn oversized_extended_opcode_does_not_desync() {
    let mut prog: Vec<u8> = Vec::new();
    // DW_LNE_set_address with length 9 (1 subcode + 8 address) then padding.
    prog.push(0x00);
    prog.extend(uleb(12)); // over-declared length: 3 bytes of padding
    prog.push(0x02); // DW_LNE_set_address
    prog.extend_from_slice(&0x2000u64.to_le_bytes());
    prog.extend_from_slice(&[0, 0, 0]); // padding inside the opcode
    prog.push(0x01); // DW_LNS_copy -> emits a row
    prog.push(0x00); // DW_LNE_end_sequence
    prog.extend(uleb(1));
    prog.push(0x01);

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&4u16.to_le_bytes()); // version
    let header_after_len: Vec<u8> = {
        let mut h = Vec::new();
        h.push(1); // minimum_instruction_length
        h.push(1); // maximum_ops_per_insn
        h.push(1); // default_is_stmt
        h.push(0xFB); // line_base = -5
        h.push(14); // line_range
        h.push(13); // opcode_base
        h.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0]); // std opcode lens
        h.push(0); // include_directories terminator
        h.extend_from_slice(b"a.c\0");
        h.extend(uleb(0));
        h.extend(uleb(0));
        h.extend(uleb(0));
        h.push(0); // file_names terminator
        h
    };
    body.extend_from_slice(&(header_after_len.len() as u32).to_le_bytes());
    body.extend_from_slice(&header_after_len);
    body.extend_from_slice(&prog);

    let mut sect = Vec::new();
    sect.extend_from_slice(&(body.len() as u32).to_le_bytes());
    sect.extend_from_slice(&body);

    let reader = reader_with(&[(".debug_line", sect)]);
    let entries = reader.line_info();
    assert!(
        entries.iter().any(|e| e.address == 0x2000),
        "expected a row at the address set by the over-declared opcode, got {entries:?}"
    );
}

// ─── 9. DW_OP_deref must not report the address as the value ─────────────────

/// `DW_OP_deref` was a silent no-op that left the ADDRESS on the stack, so a
/// spilled pointer at `DW_OP_fbreg -24; DW_OP_deref` evaluated to
/// `Address(frame_base-24)` — the address of the slot, not the pointer it
/// holds — indistinguishable from success at the call site.
#[test]
fn deref_reports_that_it_needs_memory() {
    use rustre_symbols_dwarf::dwarf_expression_evaluator::{
        DwarfExprEvaluator, EvalError, OpResult, SimpleRegisterFile, location_expression,
    };

    const DW_OP_LIT0: u8 = 0x30;
    const DW_OP_DEREF: u8 = 0x06;

    let evaluator = DwarfExprEvaluator::new_64bit();
    let regs = SimpleRegisterFile::default();

    // Sanity: without the deref the address is a legitimate result.
    assert_eq!(
        location_expression(&[DW_OP_LIT0 + 8], &evaluator, &regs).unwrap(),
        OpResult::Address(8)
    );

    // With the deref it must NOT silently return Address(8).
    let r = location_expression(&[DW_OP_LIT0 + 8, DW_OP_DEREF], &evaluator, &regs);
    assert_eq!(r, Err(EvalError::RequiresMemory));
}

/// An unrecognised form has no known size, and DWARF attributes are packed with
/// no separators — it cannot be skipped. Reporting success while consuming zero
/// bytes desynchronised the whole DIE stream, so it must be a hard failure.
#[test]
fn unknown_form_is_a_hard_error_not_a_zero_byte_success() {
    let data = [0x11u8, 0x22, 0x33, 0x44];
    let mut pos = 0usize;
    assert!(
        read_form_value(&data, &mut pos, DwForm::Unknown, 8, false, 0).is_none(),
        "an unknown form must fail rather than silently consume nothing"
    );
    assert_eq!(pos, 0);
}

// ─── 17. DwarfReader::line_info must use the DWARF 5-correct line parser ─────

/// Build a spec-correct DWARF 5 line-number program plus its `.debug_line_str`.
///
/// DWARF 5 (§6.2.4) orders the header `version`, `address_size`,
/// `segment_selector_size`, `header_length`, and replaces the NUL-terminated
/// directory / file lists with entry-format tables. The inline reader in
/// `lib.rs` implements neither, so it misparses this unit entirely.
fn dwarf5_line_unit() -> (Vec<u8>, Vec<u8>) {
    let line_str: Vec<u8> = b"/src\0main.c\0".to_vec();

    let mut header: Vec<u8> = Vec::new();
    header.extend_from_slice(&5u16.to_le_bytes()); // version = 5
    header.push(8); // address_size
    header.push(0); // segment_selector_size
    header.extend_from_slice(&0u32.to_le_bytes()); // header_length (patched below)
    let header_length_at = header.len() - 4;

    header.push(1); // minimum_instruction_length
    header.push(1); // maximum_ops_per_insn
    header.push(1); // default_is_stmt
    header.push(0xfb); // line_base = -5
    header.push(14); // line_range
    header.push(13); // opcode_base
    header.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);

    // directory table: 1 format (DW_LNCT_path, DW_FORM_line_strp), 1 entry
    header.push(1);
    header.push(0x01); // DW_LNCT_path
    header.push(0x1f); // DW_FORM_line_strp
    header.push(1); // directories_count
    header.extend_from_slice(&0u32.to_le_bytes()); // -> "/src"

    // file table: 2 formats (path=line_strp, directory_index=udata), 1 entry
    header.push(2);
    header.push(0x01); // DW_LNCT_path
    header.push(0x1f); // DW_FORM_line_strp
    header.push(0x02); // DW_LNCT_directory_index
    header.push(0x0f); // DW_FORM_udata
    header.push(1); // file_names_count
    header.extend_from_slice(&5u32.to_le_bytes()); // -> "main.c"
    header.push(0); // directory_index = 0

    let hl = (header.len() - (header_length_at + 4)) as u32;
    header[header_length_at..header_length_at + 4].copy_from_slice(&hl.to_le_bytes());

    // set_address(0x2000), set_file(0), advance_line(+41), copy, end_sequence.
    let mut ops: Vec<u8> = Vec::new();
    ops.extend_from_slice(&[0x00, 0x09, 0x02]);
    ops.extend_from_slice(&0x2000u64.to_le_bytes());
    ops.extend_from_slice(&[0x04, 0x00]); // DW_LNS_set_file, ULEB 0
    ops.extend_from_slice(&[0x03, 41]); // DW_LNS_advance_line, SLEB +41
    ops.push(0x01); // DW_LNS_copy
    ops.extend_from_slice(&[0x00, 0x01, 0x01]); // DW_LNE_end_sequence

    let mut unit: Vec<u8> = Vec::new();
    let body_len = (header.len() + ops.len()) as u32;
    unit.extend_from_slice(&body_len.to_le_bytes());
    unit.extend_from_slice(&header);
    unit.extend_from_slice(&ops);
    (unit, line_str)
}

/// `DwarfReader::line_info()` read through an inline copy of the line program
/// in `lib.rs` that predates the DWARF 5 header fix landed in
/// `dwarf_line_program.rs` — so the fix was dead code on the path the reader
/// actually uses. This asserts the corrected parser is the one executing:
/// a v5 unit must yield its real address, file and line.
#[test]
fn line_info_uses_the_dwarf5_correct_line_parser() {
    let (unit, line_str) = dwarf5_line_unit();
    let reader = reader_with(&[
        (".debug_line", unit),
        (".debug_line_str", line_str),
    ]);

    let entries = reader.line_info();
    let row = entries
        .iter()
        .find(|e| e.address == 0x2000)
        .unwrap_or_else(|| panic!("no row at 0x2000; the v5 unit was misparsed: {entries:?}"));

    // The inline reader resolved names from a NUL-terminated file list it
    // never built for v5, so `file` came back empty (or garbage).
    assert_eq!(row.file, "/src/main.c", "v5 entry-format file table not used");
    assert_eq!(row.line, 42, "line register not advanced against the v5 header");
}

/// The same unit through the standalone parser, to pin down that any failure
/// above is in the wiring rather than in `LineProgram` itself.
#[test]
fn dwarf5_line_unit_parses_standalone() {
    let (unit, line_str) = dwarf5_line_unit();
    let (prog, _) =
        LineProgram::parse_with_str_sections(&unit, 0, &line_str, &[]).expect("v5 parse");
    assert_eq!(prog.version, 5);
    assert_eq!(prog.resolve_file(0).as_deref(), Some("/src/main.c"));
}
