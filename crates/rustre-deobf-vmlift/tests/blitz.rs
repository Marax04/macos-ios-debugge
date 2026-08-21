//! Exhaustive blitz tests for `rustre-deobf-vmlift` public API in lib.rs.
//!
//! Goal: surface bugs. Tests do not call into private modules' internals
//! beyond what the crate root re-exports / uses.

use rustre_deobf_vmlift::{
    BinOpKind, DecodeError, GuestInstruction, GuestOpcode, HandlerSemantic, PopDst, PushSrc,
    RawDispatcherKind, RawDispatcherSite, VmBytecodeDisassembler, VmDispatcherDetector,
    VmInstruction, VmInstructionDef, VmIsa, VmLifter, VmLifterPipeline, run_pass,
    suggest_mnemonic,
};

// ────────────────────────────────────────────────────────────────────────────
// VmLifter::lift_to_instructions — happy paths
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn lift_empty_returns_empty_vec() {
    assert_eq!(VmLifter::lift_to_instructions(&[]).unwrap(), vec![]);
}

#[test]
fn lift_halt_only() {
    let v = VmLifter::lift_to_instructions(&[0x07]).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, GuestOpcode::Halt);
    assert!(v[0].reg_dst.is_none() && v[0].reg_src.is_none() && v[0].imm.is_none());
}

#[test]
fn lift_add_max_regs() {
    let v = VmLifter::lift_to_instructions(&[0x01, 0xFF, 0xFF]).unwrap();
    assert_eq!(v[0].reg_dst, Some(255));
    assert_eq!(v[0].reg_src, Some(255));
}

#[test]
fn lift_sub_zero_regs() {
    let v = VmLifter::lift_to_instructions(&[0x02, 0x00, 0x00]).unwrap();
    assert_eq!(v[0].opcode, GuestOpcode::Sub);
    assert_eq!(v[0].reg_dst, Some(0));
    assert_eq!(v[0].reg_src, Some(0));
}

#[test]
fn lift_push_reg_then_pop_reg() {
    let v = VmLifter::lift_to_instructions(&[0x03, 0x05, 0x04, 0x06]).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].opcode, GuestOpcode::Push);
    assert_eq!(v[0].reg_src, Some(5));
    assert_eq!(v[1].opcode, GuestOpcode::Pop);
    assert_eq!(v[1].reg_dst, Some(6));
}

#[test]
fn lift_load_mem_le_immediate() {
    // 0x05 rd rs imm32-le
    let v = VmLifter::lift_to_instructions(&[0x05, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    assert_eq!(v[0].imm, Some(0xEFBE_ADDE));
}

#[test]
fn lift_store_mem_le_immediate() {
    let v = VmLifter::lift_to_instructions(&[0x06, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(v[0].opcode, GuestOpcode::Store);
    assert_eq!(v[0].imm, Some(1));
}

#[test]
fn lift_loadimm_zero() {
    let v = VmLifter::lift_to_instructions(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(v[0].opcode, GuestOpcode::Load);
    assert_eq!(v[0].reg_dst, Some(0));
    assert_eq!(v[0].reg_src, None);
    assert_eq!(v[0].imm, Some(0));
}

#[test]
fn lift_loadimm_max() {
    let v = VmLifter::lift_to_instructions(&[0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    assert_eq!(v[0].imm, Some(u32::MAX));
}

#[test]
fn lift_pushimm_max() {
    let v = VmLifter::lift_to_instructions(&[0x09, 0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    assert_eq!(v[0].opcode, GuestOpcode::Push);
    assert_eq!(v[0].imm, Some(u32::MAX));
}

#[test]
fn lift_long_program() {
    let mut bc = Vec::new();
    for _ in 0..100 {
        bc.extend_from_slice(&[0x01, 0x00, 0x01]);
    }
    bc.push(0x07);
    let v = VmLifter::lift_to_instructions(&bc).unwrap();
    assert_eq!(v.len(), 101);
}

// ────────────────────────────────────────────────────────────────────────────
// VmLifter::lift_to_instructions — error paths (Err variant specificity)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn err_unknown_opcode_first() {
    assert_eq!(
        VmLifter::lift_to_instructions(&[0xFF]).unwrap_err(),
        "Unknown opcode in bytecode"
    );
}

#[test]
fn err_unknown_opcode_after_valid() {
    // valid halt then unknown
    assert_eq!(
        VmLifter::lift_to_instructions(&[0x07, 0xAA]).unwrap_err(),
        "Unknown opcode in bytecode"
    );
}

#[test]
fn err_add_truncated_no_operands() {
    assert_eq!(
        VmLifter::lift_to_instructions(&[0x01]).unwrap_err(),
        "Unexpected end of bytecode for Add instruction"
    );
}

#[test]
fn err_add_truncated_one_operand() {
    assert_eq!(
        VmLifter::lift_to_instructions(&[0x01, 0x00]).unwrap_err(),
        "Unexpected end of bytecode for Add instruction"
    );
}

#[test]
fn err_sub_truncated() {
    assert!(VmLifter::lift_to_instructions(&[0x02]).is_err());
    assert!(VmLifter::lift_to_instructions(&[0x02, 0x01]).is_err());
}

#[test]
fn err_push_reg_truncated() {
    assert_eq!(
        VmLifter::lift_to_instructions(&[0x03]).unwrap_err(),
        "Unexpected end of bytecode for Push reg instruction"
    );
}

#[test]
fn err_pop_truncated() {
    assert_eq!(
        VmLifter::lift_to_instructions(&[0x04]).unwrap_err(),
        "Unexpected end of bytecode for Pop reg instruction"
    );
}

#[test]
fn err_load_truncated_each_step() {
    for n in 1..=6 {
        let mut bc = vec![0x05];
        bc.extend(std::iter::repeat_n(0u8, n - 1));
        assert!(VmLifter::lift_to_instructions(&bc).is_err(), "n={n}");
    }
    // n=7 = success
    assert!(VmLifter::lift_to_instructions(&[0x05, 0, 0, 0, 0, 0, 0]).is_ok());
}

#[test]
fn err_store_truncated_each_step() {
    for n in 1..=6 {
        let mut bc = vec![0x06];
        bc.extend(std::iter::repeat_n(0u8, n - 1));
        assert!(VmLifter::lift_to_instructions(&bc).is_err(), "n={n}");
    }
    assert!(VmLifter::lift_to_instructions(&[0x06, 0, 0, 0, 0, 0, 0]).is_ok());
}

#[test]
fn err_loadimm_truncated_each_step() {
    for n in 1..=5 {
        let mut bc = vec![0x08];
        bc.extend(std::iter::repeat_n(0u8, n - 1));
        assert!(VmLifter::lift_to_instructions(&bc).is_err(), "n={n}");
    }
    assert!(VmLifter::lift_to_instructions(&[0x08, 0, 0, 0, 0, 0]).is_ok());
}

#[test]
fn err_pushimm_truncated_each_step() {
    for n in 1..=4 {
        let mut bc = vec![0x09];
        bc.extend(std::iter::repeat_n(0u8, n - 1));
        assert!(VmLifter::lift_to_instructions(&bc).is_err(), "n={n}");
    }
    assert!(VmLifter::lift_to_instructions(&[0x09, 0, 0, 0, 0]).is_ok());
}

// ────────────────────────────────────────────────────────────────────────────
// to_pseudo_il and Display
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn pseudo_il_matches_display() {
    let bc = vec![0x01, 0x00, 0x01, 0x07];
    let instrs = VmLifter::lift_to_instructions(&bc).unwrap();
    let p = VmLifter::to_pseudo_il(&instrs);
    assert_eq!(p, vec!["ADD r0, r1", "HALT"]);
}

#[test]
fn display_load_all_branches() {
    let none_none = GuestInstruction {
        opcode: GuestOpcode::Load,
        reg_dst: Some(0),
        reg_src: None,
        imm: None,
    };
    assert_eq!(none_none.to_string(), "LOAD r0, ?");
}

#[test]
fn display_store_imm_only() {
    let i = GuestInstruction {
        opcode: GuestOpcode::Store,
        reg_dst: None,
        reg_src: Some(1),
        imm: Some(0x40),
    };
    assert_eq!(i.to_string(), "STORE [0x40], r1");
}

#[test]
fn display_store_src_only() {
    let i = GuestInstruction {
        opcode: GuestOpcode::Store,
        reg_dst: Some(2),
        reg_src: Some(3),
        imm: None,
    };
    assert_eq!(i.to_string(), "STORE [r2], r3");
}

// ────────────────────────────────────────────────────────────────────────────
// GuestInstruction equality/clone/hash-ish
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn guest_instruction_eq_and_clone() {
    let a = GuestInstruction {
        opcode: GuestOpcode::Add,
        reg_dst: Some(1),
        reg_src: Some(2),
        imm: None,
    };
    let b = a.clone();
    assert_eq!(a, b);
    let c = GuestInstruction { reg_dst: Some(2), ..a };
    assert_ne!(a, c);
}

#[test]
fn guest_opcode_copy() {
    let o = GuestOpcode::Add;
    let o2 = o; // Copy
    assert_eq!(o, o2);
}

// ────────────────────────────────────────────────────────────────────────────
// suggest_mnemonic / HandlerSemantic helpers
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn semantic_is_control_flow() {
    assert!(HandlerSemantic::Branch.is_control_flow());
    assert!(HandlerSemantic::Call.is_control_flow());
    assert!(HandlerSemantic::Ret.is_control_flow());
    assert!(HandlerSemantic::Halt.is_control_flow());
    assert!(!HandlerSemantic::Push(PushSrc::Memory).is_control_flow());
    assert!(!HandlerSemantic::BinOp(BinOpKind::Add).is_control_flow());
    assert!(!HandlerSemantic::Load(4).is_control_flow());
    assert!(!HandlerSemantic::Cmp.is_control_flow());
}

#[test]
fn semantic_accesses_memory() {
    assert!(HandlerSemantic::Load(1).accesses_memory());
    assert!(HandlerSemantic::Store(2).accesses_memory());
    assert!(HandlerSemantic::Push(PushSrc::Memory).accesses_memory());
    assert!(HandlerSemantic::Pop(PopDst::Memory).accesses_memory());
    assert!(!HandlerSemantic::Push(PushSrc::Constant(5)).accesses_memory());
    assert!(!HandlerSemantic::Push(PushSrc::VirtualReg(0)).accesses_memory());
    assert!(!HandlerSemantic::Pop(PopDst::VirtualReg(0)).accesses_memory());
    assert!(!HandlerSemantic::BinOp(BinOpKind::Xor).accesses_memory());
}

#[test]
fn suggest_mnemonic_all_binops() {
    use BinOpKind::*;
    let pairs = [
        (Add, "VADD"),
        (Sub, "VSUB"),
        (Mul, "VMUL"),
        (Div, "VDIV"),
        (And, "VAND"),
        (Or, "VOR"),
        (Xor, "VXOR"),
        (Shl, "VSHL"),
        (Shr, "VSHR"),
        (Sar, "VSAR"),
        (Rol, "VROL"),
        (Ror, "VROR"),
    ];
    for (op, expected) in pairs {
        assert_eq!(
            suggest_mnemonic(&HandlerSemantic::BinOp(op.clone())),
            expected,
            "for {op:?}"
        );
        // Also via the method on HandlerSemantic
        assert_eq!(HandlerSemantic::BinOp(op).suggest_mnemonic(), expected);
    }
}

#[test]
fn suggest_mnemonic_misc() {
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Halt), "VHALT");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Unknown), "VUNK");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Cmp), "VCMP");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Ret), "VRET");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Call), "VCALL");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Branch), "VBRANCH");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::IpAdvance(3)), "VIPADVANCE");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Load(8)), "VLOAD");
    assert_eq!(suggest_mnemonic(&HandlerSemantic::Store(2)), "VSTORE");
}

#[test]
fn handler_semantic_display() {
    assert_eq!(HandlerSemantic::Push(PushSrc::Constant(0x10)).to_string(), "VPUSH #0x10");
    assert_eq!(HandlerSemantic::Push(PushSrc::VirtualReg(3)).to_string(), "VPUSH vr3");
    assert_eq!(HandlerSemantic::Push(PushSrc::Memory).to_string(), "VPUSH [mem]");
    assert_eq!(HandlerSemantic::Pop(PopDst::VirtualReg(2)).to_string(), "VPOP  vr2");
    assert_eq!(HandlerSemantic::Pop(PopDst::Memory).to_string(), "VPOP  [mem]");
    assert_eq!(HandlerSemantic::BinOp(BinOpKind::Add).to_string(), "VAdd");
    assert_eq!(HandlerSemantic::Load(4).to_string(), "VLOAD32  [addr]");
    assert_eq!(HandlerSemantic::Store(2).to_string(), "VSTORE16 [addr]");
    assert_eq!(HandlerSemantic::Halt.to_string(), "VHALT");
    assert_eq!(HandlerSemantic::IpAdvance(5).to_string(), "VIP+=5");
    assert_eq!(HandlerSemantic::Unknown.to_string(), "VUNK");
}

#[test]
fn handler_semantic_eq() {
    assert_eq!(
        HandlerSemantic::Push(PushSrc::Constant(7)),
        HandlerSemantic::Push(PushSrc::Constant(7))
    );
    assert_ne!(
        HandlerSemantic::Push(PushSrc::Constant(7)),
        HandlerSemantic::Push(PushSrc::Constant(8))
    );
}

// ────────────────────────────────────────────────────────────────────────────
// VmIsa
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn isa_new_is_empty() {
    let isa = VmIsa::new();
    assert!(isa.is_empty());
    assert_eq!(isa.len(), 0);
    assert!(isa.lookup(0x01).is_none());
    assert_eq!(isa.listing(), "");
    assert!(isa.sorted_handlers().is_empty());
}

#[test]
fn isa_default_is_default_empty() {
    let isa = VmIsa::default();
    assert!(isa.is_empty());
}

#[test]
fn isa_register_and_lookup() {
    let mut isa = VmIsa::new();
    let def = VmInstructionDef::new(0x42, HandlerSemantic::Halt);
    isa.register(def);
    assert!(!isa.is_empty());
    assert_eq!(isa.len(), 1);
    let got = isa.lookup(0x42).unwrap();
    assert_eq!(got.opcode, 0x42);
    assert_eq!(got.mnemonic, "VHALT");
    assert_eq!(got.operand_bytes, 0);
}

#[test]
fn isa_register_replaces_existing() {
    let mut isa = VmIsa::new();
    isa.register(VmInstructionDef::new(0x10, HandlerSemantic::Halt));
    isa.register(VmInstructionDef::new(0x10, HandlerSemantic::Ret));
    assert_eq!(isa.len(), 1);
    assert_eq!(isa.lookup(0x10).unwrap().mnemonic, "VRET");
}

#[test]
fn isa_sorted_handlers_ordered() {
    let mut isa = VmIsa::new();
    for op in [0x05u8, 0x01, 0x09, 0x03, 0x07] {
        isa.register(VmInstructionDef::new(op, HandlerSemantic::Halt));
    }
    let s = isa.sorted_handlers();
    let ops: Vec<u8> = s.iter().map(|d| d.opcode).collect();
    assert_eq!(ops, vec![0x01, 0x03, 0x05, 0x07, 0x09]);
}

#[test]
fn isa_listing_nonempty() {
    let mut isa = VmIsa::new();
    isa.register(VmInstructionDef::new(0x07, HandlerSemantic::Halt));
    let l = isa.listing();
    assert!(l.contains("VHALT"));
    assert!(l.contains("0x07"));
}

#[test]
fn isa_default_lifter_isa_covers_01_to_09() {
    let isa = VmIsa::default_lifter_isa();
    for op in 0x01u8..=0x09 {
        assert!(isa.lookup(op).is_some(), "op {op:#x} missing");
    }
    assert_eq!(isa.len(), 9);
    assert!(isa.lookup(0x00).is_none());
    assert!(isa.lookup(0x0A).is_none());
}

#[test]
fn vm_instruction_def_default_operand_bytes_branches() {
    // Push const → 8 (default), then default_lifter_isa overrides to 4
    let d = VmInstructionDef::new(0x09, HandlerSemantic::Push(PushSrc::Constant(0)));
    assert_eq!(d.operand_bytes, 8);

    let d = VmInstructionDef::new(0x03, HandlerSemantic::Push(PushSrc::VirtualReg(0)));
    assert_eq!(d.operand_bytes, 1);

    let d = VmInstructionDef::new(0x04, HandlerSemantic::Pop(PopDst::VirtualReg(0)));
    assert_eq!(d.operand_bytes, 1);

    let d = VmInstructionDef::new(0x05, HandlerSemantic::Load(6));
    assert_eq!(d.operand_bytes, 6);

    let d = VmInstructionDef::new(0x06, HandlerSemantic::Store(3));
    assert_eq!(d.operand_bytes, 3);

    let d = VmInstructionDef::new(0x10, HandlerSemantic::IpAdvance(0));
    assert_eq!(d.operand_bytes, 4);

    let d = VmInstructionDef::new(0x11, HandlerSemantic::Branch);
    assert_eq!(d.operand_bytes, 4);

    let d = VmInstructionDef::new(0x07, HandlerSemantic::Halt);
    assert_eq!(d.operand_bytes, 0);

    let d = VmInstructionDef::new(0x12, HandlerSemantic::Cmp);
    assert_eq!(d.operand_bytes, 0);

    let d = VmInstructionDef::new(0x13, HandlerSemantic::Push(PushSrc::Memory));
    assert_eq!(d.operand_bytes, 0);

    let d = VmInstructionDef::new(0x14, HandlerSemantic::Pop(PopDst::Memory));
    assert_eq!(d.operand_bytes, 0);
}

#[test]
fn vm_instruction_def_display_contains_opcode_and_mnemonic() {
    let d = VmInstructionDef::new(0x07, HandlerSemantic::Halt);
    let s = d.to_string();
    assert!(s.contains("0x07"));
    assert!(s.contains("VHALT"));
    assert!(s.contains("operand_bytes=0"));
}

#[test]
fn isa_static_suggest_mnemonic() {
    assert_eq!(VmIsa::suggest_mnemonic(&HandlerSemantic::Halt), "VHALT");
}

// ────────────────────────────────────────────────────────────────────────────
// VmBytecodeDisassembler
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn disasm_empty_buffer_returns_empty() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[], &isa).unwrap();
    assert!(r.is_empty());
}

#[test]
fn disasm_halt() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0x07], &isa).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].opcode, 0x07);
    assert_eq!(r[0].mnemonic, "VHALT");
    assert!(r[0].operands.is_empty());
}

#[test]
fn disasm_unknown_opcode_emits_vunk_and_continues() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0xAA, 0x07], &isa).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].mnemonic, "VUNK_AA");
    assert!(r[0].operands.is_empty());
    assert_eq!(r[1].mnemonic, "VHALT");
}

#[test]
fn disasm_add_emits_two_operands() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0x01, 0x05, 0x09], &isa).unwrap();
    assert_eq!(r[0].operands, vec![5, 9]);
}

#[test]
fn disasm_pushreg_emits_one_operand() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0x03, 0x07], &isa).unwrap();
    assert_eq!(r[0].operands, vec![7]);
}

#[test]
fn disasm_load_six_byte_form() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(
        &[0x05, 0x01, 0x02, 0x78, 0x56, 0x34, 0x12],
        &isa,
    )
    .unwrap();
    assert_eq!(r[0].operands, vec![1, 2, 0x1234_5678]);
}

#[test]
fn disasm_loadimm_five_byte_form() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(
        &[0x08, 0x03, 0x78, 0x56, 0x34, 0x12],
        &isa,
    )
    .unwrap();
    assert_eq!(r[0].operands, vec![3, 0x1234_5678]);
}

#[test]
fn disasm_pushimm_four_byte_form() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0x09, 0x78, 0x56, 0x34, 0x12], &isa).unwrap();
    assert_eq!(r[0].operands, vec![0x1234_5678]);
}

#[test]
fn disasm_truncated_returns_specific_error() {
    let isa = VmIsa::default_lifter_isa();
    // Add expects 2 operand bytes, supply only 1
    let err = VmBytecodeDisassembler::disassemble(&[0x01, 0x00], &isa).unwrap_err();
    match err {
        DecodeError::TruncatedInstruction {
            offset,
            opcode,
            expected_operand_bytes,
            available_bytes,
        } => {
            assert_eq!(offset, 0);
            assert_eq!(opcode, 0x01);
            assert_eq!(expected_operand_bytes, 2);
            assert_eq!(available_bytes, 1);
        }
    }
}

#[test]
fn disasm_truncated_offset_nonzero() {
    let isa = VmIsa::default_lifter_isa();
    // halt then add with no operands
    let err = VmBytecodeDisassembler::disassemble(&[0x07, 0x01], &isa).unwrap_err();
    match err {
        DecodeError::TruncatedInstruction { offset, opcode, expected_operand_bytes, available_bytes } => {
            assert_eq!(offset, 1);
            assert_eq!(opcode, 0x01);
            assert_eq!(expected_operand_bytes, 2);
            assert_eq!(available_bytes, 0);
        }
    }
}

#[test]
fn disasm_decode_error_display_mentions_offset() {
    let isa = VmIsa::default_lifter_isa();
    let err = VmBytecodeDisassembler::disassemble(&[0x01], &isa).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("truncated"));
    assert!(msg.contains("0x0"));
}

#[test]
fn disasm_to_text_empty() {
    assert_eq!(VmBytecodeDisassembler::to_text(&[]), "");
}

#[test]
fn disasm_to_text_nonempty() {
    let isa = VmIsa::default_lifter_isa();
    let v = VmBytecodeDisassembler::disassemble(&[0x07], &isa).unwrap();
    let t = VmBytecodeDisassembler::to_text(&v);
    assert!(t.contains("VHALT"));
}

#[test]
fn vm_instruction_display_no_ops() {
    let i = VmInstruction {
        offset: 0x10,
        opcode: 0x07,
        operands: vec![],
        mnemonic: "VHALT".into(),
    };
    let s = i.to_string();
    assert!(s.contains("VHALT"));
    // formatted as {:#06x} → "0x0010"
    assert!(s.contains("0x0010"), "got: {s}");
}

#[test]
fn vm_instruction_display_with_ops() {
    let i = VmInstruction {
        offset: 0,
        opcode: 0x09,
        operands: vec![0x42, 0x100],
        mnemonic: "VPUSH".into(),
    };
    let s = i.to_string();
    assert!(s.contains("VPUSH"));
    assert!(s.contains("0x42"));
    assert!(s.contains("0x100"));
}

// ────────────────────────────────────────────────────────────────────────────
// VmDispatcherDetector
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn detector_empty_input_no_panic() {
    let v = VmDispatcherDetector::detect_in_bytes(&[], 0);
    assert!(v.is_empty());
}

#[test]
fn detector_short_input_no_panic() {
    for n in 0..7 {
        let buf = vec![0u8; n];
        let _ = VmDispatcherDetector::detect_in_bytes(&buf, 0x1000);
    }
}

#[test]
fn detector_pattern_a_indirect_indexed_jmp() {
    // FF 24 CD disp32-le
    let code = [0xFFu8, 0x24, 0xCD, 0x00, 0x00, 0x00, 0x00];
    let v = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(!v.is_empty(), "expected at least one dispatcher");
    assert!(v[0].description.contains("FF 24 CD"));
}

#[test]
fn detector_pattern_b_computed_jmp_ff_e0() {
    // 48 8B 00  (table load) then FF E0
    let code = [0x48u8, 0x8B, 0x00, 0xFF, 0xE0];
    let v = VmDispatcherDetector::detect_in_bytes(&code, 0x0040_0000);
    assert!(v.iter().any(|d| d.description.contains("computed-jmp FF E0")));
}

#[test]
fn detector_pattern_b_computed_jmp_ff_e1() {
    let code = [0xFFu8, 0xE1];
    let v = VmDispatcherDetector::detect_in_bytes(&code, 0);
    // Should still detect with lower confidence (no table-load hint)
    assert!(v.iter().any(|d| d.description.contains("computed-jmp FF E1")));
}

#[test]
fn detector_pattern_c_call_pop_add() {
    // E8 00 00 00 00 | 58 (pop rax) | 48 81 C0 04 00 00 00
    let code = [
        0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x81, 0xC0, 0x04, 0x00, 0x00, 0x00, 0x90,
    ];
    let v = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(v.iter().any(|d| d.description.contains("call+pop+add")));
}

#[test]
fn detector_no_false_positives_on_zeros() {
    let code = vec![0u8; 256];
    let v = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(v.is_empty());
}

#[test]
fn extract_jump_table_entries_empty_data() {
    // BUG SURFACE: with table_offset=0 and empty data, current code computes
    // limit = 0.saturating_sub(8) = 0, off = 0, off > limit is false, then
    // tries to index data[0..8] — likely panics.
    let v = VmDispatcherDetector::extract_jump_table_entries(&[], 0, 4, 8);
    assert!(v.is_empty());
}

#[test]
fn extract_jump_table_entries_zero_count() {
    let data = vec![1u8; 32];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 0, 8);
    assert!(v.is_empty());
}

#[test]
fn extract_jump_table_entries_basic_8byte() {
    // Build a small table of three 8-byte LE pointers within plausible range.
    let mut data = Vec::new();
    for v in [0x1000u64, 0x2000, 0x3000] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let entries = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 3, 8);
    assert_eq!(entries, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn extract_jump_table_entries_stops_on_zero() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x100u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0x200u64.to_le_bytes());
    let entries = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 3, 8);
    // 0 is implausible → stops at second.
    assert_eq!(entries, vec![0x100]);
}

#[test]
fn extract_jump_table_entries_4byte() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x10u32.to_le_bytes());
    data.extend_from_slice(&0x20u32.to_le_bytes());
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 2, 4);
    assert_eq!(v, vec![0x10, 0x20]);
}

#[test]
fn extract_jump_table_entries_2byte() {
    let data: Vec<u8> = vec![0x10, 0x00, 0x20, 0x00];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 2, 2);
    assert_eq!(v, vec![0x10, 0x20]);
}

#[test]
fn extract_jump_table_entries_invalid_addr_size_returns_empty() {
    let data = vec![1u8; 16];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 4, 3);
    assert!(v.is_empty());
}

#[test]
fn extract_jump_table_entries_offset_past_end() {
    let data = vec![1u8; 8];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 100, 4, 8);
    assert!(v.is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// RawDispatcherKind / RawDispatcherSite
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn raw_dispatcher_kind_display() {
    assert!(RawDispatcherKind::IndirectIndexedJmp.to_string().contains("indirect"));
    assert!(RawDispatcherKind::ComputedJmp.to_string().contains("computed"));
    assert!(RawDispatcherKind::CallPopAddChain.to_string().contains("call+pop+add"));
}

#[test]
fn raw_dispatcher_kind_eq_and_clone() {
    let a = RawDispatcherKind::ComputedJmp;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(RawDispatcherKind::ComputedJmp, RawDispatcherKind::CallPopAddChain);
}

#[test]
fn raw_dispatcher_site_constructible_and_clone() {
    let s = RawDispatcherSite {
        address: 0x1000,
        offset: 4,
        kind: RawDispatcherKind::ComputedJmp,
        table_entries: vec![0x10, 0x20],
    };
    let c = s;
    assert_eq!(c.address, 0x1000);
    assert_eq!(c.table_entries.len(), 2);
}

// ────────────────────────────────────────────────────────────────────────────
// VmLifterPipeline
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn pipeline_detect_and_report_empty() {
    let r = VmLifterPipeline::detect_and_report(&[], 0x0040_0000);
    assert_eq!(r.dispatchers_found, 0);
    assert_eq!(r.isa.len(), 9);
    assert!(!r.analysis_notes.is_empty());
    assert!(r.analysis_notes.iter().any(|n| n.contains("WARNING")));
}

#[test]
fn pipeline_detect_and_report_with_dispatcher() {
    let code = [0xFFu8, 0xE1];
    let r = VmLifterPipeline::detect_and_report(&code, 0);
    assert!(r.dispatchers_found >= 1);
}

#[test]
fn pipeline_full_empty_bytecode_errors() {
    let err = VmLifterPipeline::full_pipeline(&[], 0, &[]).unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[test]
fn pipeline_full_lifts_a_halt_program() {
    let lines = VmLifterPipeline::full_pipeline(&[], 0x1000, &[0x07]).unwrap();
    let all = lines.join("\n");
    assert!(all.contains("VM Lift Report"));
    assert!(all.contains("VHALT"));
    assert!(all.contains("Disassembly"));
}

#[test]
fn pipeline_full_disassembles_complex_program() {
    let bc = [
        0x09, 0x10, 0x00, 0x00, 0x00, // pushimm 0x10
        0x03, 0x01, // push r1
        0x04, 0x02, // pop r2
        0x07, // halt
    ];
    let lines = VmLifterPipeline::full_pipeline(&[], 0, &bc).unwrap();
    let all = lines.join("\n");
    assert!(all.contains("VPUSH"));
    assert!(all.contains("VPOP"));
    assert!(all.contains("VHALT"));
}

#[test]
fn pipeline_full_propagates_decode_error_in_bytecode() {
    // Add opcode missing operands → disassembler errors → pipeline returns Err
    let err = VmLifterPipeline::full_pipeline(&[], 0, &[0x01]).unwrap_err();
    assert!(err.to_string().contains("decode"));
}

// ────────────────────────────────────────────────────────────────────────────
// run_pass smoke
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn run_pass_lifts_the_bytes_it_is_given() {
    // The old form called `run_pass()` with no argument and discarded the
    // result, so it asserted only "did not panic" about a hardcoded byte.
    // It now lifts real input and the output is checked.
    let lifted = run_pass(&[0x07]);
    let empty = run_pass(&[]);
    assert!(empty.is_empty(), "no bytes means no pseudo-IL, got {empty:?}");
    // Whatever 0x07 lifts to, it must be deterministic.
    assert_eq!(lifted, run_pass(&[0x07]), "lifting must be deterministic");
}

// ────────────────────────────────────────────────────────────────────────────
// Send/Sync sanity for shared types
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VmIsa>();
    assert_send_sync::<VmInstructionDef>();
    assert_send_sync::<VmInstruction>();
    assert_send_sync::<HandlerSemantic>();
    assert_send_sync::<GuestInstruction>();
    assert_send_sync::<DecodeError>();
    assert_send_sync::<RawDispatcherSite>();
    assert_send_sync::<RawDispatcherKind>();
}
