//! Exhaustive blitz tests for `rustre-il-llil`.

use rustre_core::address::Address;
use rustre_il_llil::*;

// ─── Size ────────────────────────────────────────────────────────────────────

#[test]
fn size_bytes_values() {
    assert_eq!(Size::Byte.bytes(), 1);
    assert_eq!(Size::Word.bytes(), 2);
    assert_eq!(Size::DWord.bytes(), 4);
    assert_eq!(Size::QWord.bytes(), 8);
    assert_eq!(Size::OWord.bytes(), 16);
}

#[test]
fn size_bits_values() {
    assert_eq!(Size::Byte.bits(), 8);
    assert_eq!(Size::Word.bits(), 16);
    assert_eq!(Size::DWord.bits(), 32);
    assert_eq!(Size::QWord.bits(), 64);
    assert_eq!(Size::OWord.bits(), 128);
}

#[test]
fn size_aliases() {
    assert_eq!(Size::B1, Size::Byte);
    assert_eq!(Size::B2, Size::Word);
    assert_eq!(Size::B4, Size::DWord);
    assert_eq!(Size::B8, Size::QWord);
}

#[test]
fn size_try_from_valid() {
    assert_eq!(Size::try_from(1usize).unwrap(), Size::Byte);
    assert_eq!(Size::try_from(2usize).unwrap(), Size::Word);
    assert_eq!(Size::try_from(4usize).unwrap(), Size::DWord);
    assert_eq!(Size::try_from(8usize).unwrap(), Size::QWord);
    assert_eq!(Size::try_from(16usize).unwrap(), Size::OWord);
}

#[test]
fn size_try_from_invalid() {
    assert!(Size::try_from(0usize).is_err());
    assert!(Size::try_from(3usize).is_err());
    assert!(Size::try_from(7usize).is_err());
    // 32 bytes is now `Size::YWord` (256-bit AVX/AVX2 YMM) and 64 bytes is
    // `Size::ZWord` (512-bit AVX-512 ZMM); use values still invalid under
    // the extended enum.
    assert!(Size::try_from(9usize).is_err());
    assert!(Size::try_from(128usize).is_err());
}

#[test]
fn size_display_is_byte_count() {
    assert_eq!(format!("{}", Size::Byte), "1");
    assert_eq!(format!("{}", Size::OWord), "16");
}

// ─── LlilRegister ────────────────────────────────────────────────────────────

#[test]
fn register_name_concrete_and_temp() {
    assert_eq!(LlilRegister::Concrete("rax".into()).name(), "rax");
    assert_eq!(LlilRegister::Temporary(7).name(), "tmp7");
}

#[test]
fn register_from_string_and_str() {
    let r1: LlilRegister = "rbx".into();
    let r2: LlilRegister = String::from("rbx").into();
    assert_eq!(r1, r2);
    assert!(matches!(r1, LlilRegister::Concrete(_)));
}

#[test]
fn register_display_matches_name() {
    let r = LlilRegister::Temporary(99);
    assert_eq!(format!("{r}"), "tmp99");
}

#[test]
fn register_eq_and_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(LlilRegister::Concrete("rax".into()));
    set.insert(LlilRegister::Concrete("rax".into()));
    set.insert(LlilRegister::Temporary(0));
    assert_eq!(set.len(), 2);
}

// ─── LlilExpr basics ────────────────────────────────────────────────────────

#[test]
fn expr_const_is_const() {
    let e = llil_const(42, Size::QWord);
    assert_eq!(e.is_const(), Some(42));
    assert!(!e.is_const_zero());
}

#[test]
fn expr_const_zero() {
    let e = llil_const(0, Size::DWord);
    assert!(e.is_const_zero());
    assert_eq!(e.is_const(), Some(0));
}

#[test]
fn expr_non_const_is_none() {
    let e = llil_reg("rax", Size::QWord);
    assert_eq!(e.is_const(), None);
    assert!(!e.is_const_zero());
}

#[test]
fn expr_result_size_const_and_reg() {
    assert_eq!(llil_const(0, Size::Word).result_size(), Size::Word);
    assert_eq!(llil_reg("rax", Size::QWord).result_size(), Size::QWord);
}

#[test]
fn expr_result_size_arith() {
    let a = llil_add(llil_const(1, Size::DWord), llil_const(2, Size::DWord), Size::DWord);
    assert_eq!(a.result_size(), Size::DWord);
}

#[test]
fn expr_result_size_cmp_is_byte() {
    let cmp = llil_cmp_eq(llil_const(1, Size::QWord), llil_const(2, Size::QWord));
    assert_eq!(cmp.result_size(), Size::Byte);
    let cmp2 = llil_cmp_slt(llil_const(0, Size::QWord), llil_const(1, Size::QWord));
    assert_eq!(cmp2.result_size(), Size::Byte);
}

#[test]
fn expr_result_size_flag_is_byte() {
    assert_eq!(llil_flag("zero").result_size(), Size::Byte);
}

#[test]
fn expr_result_size_extension() {
    let zx = llil_zx(llil_const(0xff, Size::Byte), Size::Byte, Size::QWord);
    assert_eq!(zx.result_size(), Size::QWord);
    let sx = llil_sx(llil_const(0xff, Size::Byte), Size::Byte, Size::DWord);
    assert_eq!(sx.result_size(), Size::DWord);
}

#[test]
fn expr_display_const() {
    let e = llil_const(0x10, Size::DWord);
    assert_eq!(format!("{e}"), "0x10.4");
}

#[test]
fn expr_display_arith() {
    let e = llil_add(llil_const(1, Size::QWord), llil_const(2, Size::QWord), Size::QWord);
    let s = format!("{e}");
    assert!(s.contains("+"));
    assert!(s.contains("0x1"));
    assert!(s.contains("0x2"));
}

// ─── LlilInstruction ────────────────────────────────────────────────────────

#[test]
fn instr_is_terminator() {
    assert!(LlilInstruction::Ret.is_terminator());
    assert!(LlilInstruction::Return { value: None }.is_terminator());
    assert!(LlilInstruction::Undefined.is_terminator());
    assert!(!LlilInstruction::Nop.is_terminator());
    assert!(!LlilInstruction::SysCall.is_terminator());
    assert!(!LlilInstruction::Breakpoint.is_terminator());
}

#[test]
fn instr_cond_jump_successors() {
    let cj = LlilInstruction::CondJump {
        cond: llil_const(1, Size::Byte),
        true_dest: Address::new(0x100),
        false_dest: Address::new(0x200),
    };
    let succ = cj.successors();
    assert_eq!(succ.len(), 2);
    assert!(succ.contains(&Address::new(0x100)));
    assert!(succ.contains(&Address::new(0x200)));
}

#[test]
fn instr_jump_to_successors() {
    let j = LlilInstruction::JumpTo {
        dest: llil_const(0, Size::QWord),
        targets: vec![Address::new(1), Address::new(2), Address::new(3)],
    };
    assert_eq!(j.successors().len(), 3);
}

#[test]
fn instr_nop_successors_empty() {
    // Non-terminator returns empty per docstring (caller adds fall-through).
    assert!(LlilInstruction::Nop.successors().is_empty());
    assert!(LlilInstruction::Ret.successors().is_empty());
}

#[test]
fn instr_writes_reg_setreg() {
    let i = LlilInstruction::SetReg {
        dest: LlilRegister::Concrete("rax".into()),
        size: Size::QWord,
        value: llil_const(0, Size::QWord),
    };
    assert!(i.writes_reg(&LlilRegister::Concrete("rax".into())));
    assert!(!i.writes_reg(&LlilRegister::Concrete("rbx".into())));
}

#[test]
fn instr_writes_reg_split_high_or_low() {
    let i = LlilInstruction::SetRegSplit {
        high: LlilRegister::Concrete("rdx".into()),
        low: LlilRegister::Concrete("rax".into()),
        src: llil_const(0, Size::QWord),
    };
    assert!(i.writes_reg(&LlilRegister::Concrete("rdx".into())));
    assert!(i.writes_reg(&LlilRegister::Concrete("rax".into())));
}

#[test]
fn instr_reads_reg_through_expression() {
    let i = LlilInstruction::SetReg {
        dest: LlilRegister::Concrete("rax".into()),
        size: Size::QWord,
        value: llil_add(llil_reg("rbx", Size::QWord), llil_const(1, Size::QWord), Size::QWord),
    };
    assert!(i.reads_reg(&LlilRegister::Concrete("rbx".into())));
    assert!(!i.reads_reg(&LlilRegister::Concrete("rcx".into())));
}

#[test]
fn instr_reads_flag() {
    let i = LlilInstruction::SetReg {
        dest: LlilRegister::Concrete("rax".into()),
        size: Size::QWord,
        value: llil_flag("zero"),
    };
    assert!(i.reads_flag("zero"));
    assert!(!i.reads_flag("carry"));
}

#[test]
fn instr_writes_flag() {
    let i = LlilInstruction::SetFlag {
        name: "carry".into(),
        src: llil_const(1, Size::Byte),
    };
    assert!(i.writes_flag("carry"));
    assert!(!i.writes_flag("zero"));
}

// ─── LlilBuilder ────────────────────────────────────────────────────────────

#[test]
fn builder_empty() {
    let b = LlilBuilder::new();
    let v = b.build();
    assert!(v.is_empty());
}

#[test]
fn builder_default_eq_new() {
    let b = LlilBuilder::default();
    assert!(b.build().is_empty());
}

#[test]
fn builder_emits_in_order() {
    let mut b = LlilBuilder::at(Address::new(0x1000), 3);
    b.set_reg("rax", Size::QWord, llil_const(42, Size::QWord));
    b.advance_to(Address::new(0x1003), 1).ret();
    let v = b.build();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].address, Address::new(0x1000));
    assert_eq!(v[0].size, 3);
    assert_eq!(v[1].address, Address::new(0x1003));
    assert!(matches!(v[1].instr, LlilInstruction::Ret));
}

#[test]
fn builder_all_helpers_emit() {
    let mut b = LlilBuilder::at(Address::new(0), 1);
    b.nop();
    b.set_reg("r", Size::QWord, llil_const(0, Size::QWord));
    b.load("r", Size::QWord, llil_const(0, Size::QWord));
    b.store(llil_const(0, Size::QWord), Size::QWord, llil_const(0, Size::QWord));
    b.jump(llil_const(0, Size::QWord));
    b.call(llil_const(0, Size::QWord));
    b.cond_jump(llil_const(1, Size::Byte), Address::new(0), Address::new(0));
    b.trap(0xdead);
    b.syscall();
    b.push_stack(Size::QWord, llil_const(0, Size::QWord));
    b.pop("r", Size::QWord);
    b.push_instr(Size::QWord, llil_const(0, Size::QWord));
    b.ret();
    let v = b.build();
    assert_eq!(v.len(), 13);
}

// ─── LlilBasicBlock / LlilFunction ──────────────────────────────────────────

#[test]
fn block_empty_and_terminator() {
    let block = LlilBasicBlock::default();
    assert!(block.is_empty());
    assert!(block.last_instr().is_none());
    assert!(block.terminator().is_none());
}

#[test]
fn block_terminator_detected() {
    let mut block = LlilBasicBlock::default();
    block.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Nop));
    block.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    assert!(!block.is_empty());
    assert!(block.terminator().is_some());
}

#[test]
fn block_non_terminator_last() {
    let mut block = LlilBasicBlock::default();
    block.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Nop));
    assert!(block.last_instr().is_some());
    assert!(block.terminator().is_none(), "Nop is not a terminator");
}

#[test]
fn function_new_temporary_assigns_sequential_ids() {
    let mut f = LlilFunction::new(Address::new(0));
    let t0 = f.new_temporary(Size::QWord);
    let t1 = f.new_temporary(Size::QWord);
    assert_eq!(t0, LlilRegister::Temporary(0));
    assert_eq!(t1, LlilRegister::Temporary(1));
    assert_eq!(f.temp_count, 2);
}

#[test]
fn function_block_at_and_instr_at() {
    let mut f = LlilFunction::new(Address::new(0x1000));
    let mut block = LlilBasicBlock::default();
    block.id = 0;
    block.start = Address::new(0x1000);
    block.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x1000),
        size: 1,
        instr: LlilInstruction::Nop,
        length: 1,
    });
    f.add_block(block);
    assert!(f.block_at(Address::new(0x1000)).is_some());
    assert!(f.block_at(Address::new(0x2000)).is_none());
    assert!(f.instr_at(Address::new(0x1000)).is_some());
    assert!(f.instr_at(Address::new(0x9999)).is_none());
}

#[test]
fn function_all_instrs_iterates_in_order() {
    let mut f = LlilFunction::new(Address::new(0));
    for i in 0..3 {
        let mut b = LlilBasicBlock::default();
        b.id = i;
        b.start = Address::new(u64::from(i) * 0x10);
        b.instrs.push(LlilAnnotatedInstr {
            address: Address::new(u64::from(i) * 0x10),
            size: 1,
            instr: LlilInstruction::Nop,
            length: 1,
        });
        f.add_block(b);
    }
    let all: Vec<_> = f.all_instrs().collect();
    assert_eq!(all.len(), 3);
}

// ─── AnnotatedInstr ─────────────────────────────────────────────────────────

#[test]
fn annotated_default_is_nop() {
    let a = LlilAnnotatedInstr::default();
    assert!(matches!(a.instr, LlilInstruction::Nop));
}

#[test]
fn annotated_from_instr_sets_default_addr() {
    let a: LlilAnnotatedInstr = LlilInstruction::Ret.into();
    assert_eq!(a.address, Address::default());
    assert!(matches!(a.instr, LlilInstruction::Ret));
}

#[test]
fn annotated_display_contains_addr_and_instr() {
    let a = LlilAnnotatedInstr {
        address: Address::new(0x1234),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    };
    let s = format!("{a}");
    assert!(s.contains("ret"));
}

// ─── Interpreter ────────────────────────────────────────────────────────────

#[test]
fn interp_new_state() {
    let i = LlilInterpreter::new(64, 0x40);
    assert_eq!(i.memory.len(), 64);
    assert_eq!(i.sp, 0x40);
    assert!(i.regs.is_empty());
}

#[test]
fn interp_set_and_read_reg() {
    let mut i = LlilInterpreter::new(0, 0);
    i.set_reg("rax", 42);
    assert_eq!(i.read_reg("rax").unwrap(), 42);
}

#[test]
fn interp_read_undefined_reg_errors() {
    let i = LlilInterpreter::new(0, 0);
    let err = i.read_reg("nope").unwrap_err();
    assert!(matches!(err, InterpError::UndefinedRegister(_)));
}

#[test]
fn interp_mem_round_trip_le() {
    let mut i = LlilInterpreter::new(16, 0);
    i.mem_write(0, 0x1122334455667788, 8).unwrap();
    assert_eq!(i.mem_read(0, 8).unwrap(), 0x1122334455667788);
    // Low byte first (little-endian)
    assert_eq!(i.memory[0], 0x88);
    assert_eq!(i.memory[7], 0x11);
}

#[test]
fn interp_mem_partial_widths() {
    let mut i = LlilInterpreter::new(16, 0);
    i.mem_write(0, 0xAABBCCDD, 4).unwrap();
    assert_eq!(i.mem_read(0, 1).unwrap(), 0xDD);
    assert_eq!(i.mem_read(0, 2).unwrap(), 0xCCDD);
    assert_eq!(i.mem_read(0, 4).unwrap(), 0xAABBCCDD);
}

#[test]
fn interp_mem_oob_read() {
    let i = LlilInterpreter::new(4, 0);
    assert!(matches!(i.mem_read(2, 8).unwrap_err(), InterpError::MemOutOfBounds(_)));
    assert!(matches!(i.mem_read(100, 1).unwrap_err(), InterpError::MemOutOfBounds(_)));
}

#[test]
fn interp_mem_oob_write() {
    let mut i = LlilInterpreter::new(4, 0);
    assert!(matches!(i.mem_write(3, 0, 8).unwrap_err(), InterpError::MemOutOfBounds(_)));
}

#[test]
fn interp_mem_overflow_addr_size() {
    let i = LlilInterpreter::new(16, 0);
    // start+size overflows usize
    let r = i.mem_read(u64::MAX, 8);
    assert!(r.is_err());
}

#[test]
fn interp_eval_const() {
    let i = LlilInterpreter::new(0, 0);
    assert_eq!(i.eval_expr(&llil_const(7, Size::QWord)).unwrap(), 7);
}

#[test]
fn interp_eval_add_with_mask() {
    let i = LlilInterpreter::new(0, 0);
    let e = llil_add(llil_const(0xFF, Size::Byte), llil_const(0x02, Size::Byte), Size::Byte);
    // (0xFF + 2) & 0xFF == 0x01
    assert_eq!(i.eval_expr(&e).unwrap(), 0x01);
}

#[test]
fn interp_eval_sub_wraps() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::SubT(
        Box::new(llil_const(1, Size::QWord)),
        Box::new(llil_const(2, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(i.eval_expr(&e).unwrap(), u64::MAX);
}

#[test]
fn interp_eval_div_by_zero() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::DivU(
        Box::new(llil_const(10, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    assert!(matches!(i.eval_expr(&e).unwrap_err(), InterpError::DivisionByZero(_)));
}

#[test]
fn interp_eval_div_signed_by_zero() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::DivS(
        Box::new(llil_const(10, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    assert!(matches!(i.eval_expr(&e).unwrap_err(), InterpError::DivisionByZero(_)));
}

#[test]
fn interp_eval_mod_by_zero() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::ModU(
        Box::new(llil_const(10, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    assert!(matches!(i.eval_expr(&e).unwrap_err(), InterpError::DivisionByZero(_)));
}

#[test]
fn interp_eval_cmp_eq_true_false() {
    let i = LlilInterpreter::new(0, 0);
    let t = llil_cmp_eq(llil_const(5, Size::QWord), llil_const(5, Size::QWord));
    assert_eq!(i.eval_expr(&t).unwrap(), 1);
    let f = llil_cmp_eq(llil_const(5, Size::QWord), llil_const(6, Size::QWord));
    assert_eq!(i.eval_expr(&f).unwrap(), 0);
}

#[test]
fn interp_eval_cmp_signed_lt() {
    let i = LlilInterpreter::new(0, 0);
    // -1 (as u64::MAX) <s 0 should be true (1)
    let e = llil_cmp_slt(llil_const(u64::MAX, Size::QWord), llil_const(0, Size::QWord));
    assert_eq!(i.eval_expr(&e).unwrap(), 1);
}

#[test]
fn interp_eval_sign_extend_negative_byte() {
    let i = LlilInterpreter::new(0, 0);
    let e = llil_sx(llil_const(0xFF, Size::Byte), Size::Byte, Size::QWord);
    // 0xFF as signed byte == -1 -> 0xFFFFFFFFFFFFFFFF
    assert_eq!(i.eval_expr(&e).unwrap(), u64::MAX);
}

#[test]
fn interp_eval_zero_extend_byte_to_qword() {
    let i = LlilInterpreter::new(0, 0);
    let e = llil_zx(llil_const(0x80, Size::Byte), Size::Byte, Size::QWord);
    assert_eq!(i.eval_expr(&e).unwrap(), 0x80);
}

#[test]
fn interp_eval_register_ref_propagates_error() {
    let i = LlilInterpreter::new(0, 0);
    let e = llil_reg("nonexistent", Size::QWord);
    assert!(matches!(i.eval_expr(&e).unwrap_err(), InterpError::UndefinedRegister(_)));
}

#[test]
fn interp_eval_flag_defaults_zero() {
    let i = LlilInterpreter::new(0, 0);
    assert_eq!(i.eval_expr(&llil_flag("zero")).unwrap(), 0);
}

#[test]
fn interp_eval_cond_expr_picks_branch() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::CondExpr {
        cond: Box::new(llil_const(1, Size::Byte)),
        true_val: Box::new(llil_const(42, Size::QWord)),
        false_val: Box::new(llil_const(99, Size::QWord)),
        size: Size::QWord,
    };
    assert_eq!(i.eval_expr(&e).unwrap(), 42);
    let f = LlilExpr::CondExpr {
        cond: Box::new(llil_const(0, Size::Byte)),
        true_val: Box::new(llil_const(42, Size::QWord)),
        false_val: Box::new(llil_const(99, Size::QWord)),
        size: Size::QWord,
    };
    assert_eq!(i.eval_expr(&f).unwrap(), 99);
}

#[test]
fn interp_step_setreg() {
    let mut i = LlilInterpreter::new(0, 0);
    let ai = LlilAnnotatedInstr {
        address: Address::new(0x10),
        size: 2,
        instr: LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(99, Size::QWord),
        },
        length: 2,
    };
    let next = i.step(&ai).unwrap();
    assert_eq!(next, Some(Address::new(0x12)));
    assert_eq!(i.read_reg("rax").unwrap(), 99);
}

#[test]
fn interp_step_ret_returns_none() {
    let mut i = LlilInterpreter::new(0, 0);
    let ai = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    };
    assert_eq!(i.step(&ai).unwrap(), None);
}

#[test]
fn interp_step_call_errors() {
    let mut i = LlilInterpreter::new(0, 0);
    let ai = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 5,
        instr: LlilInstruction::CallDest { dest: llil_const(0x2000, Size::QWord) },
        length: 5,
    };
    let err = i.step(&ai).unwrap_err();
    assert!(matches!(err, InterpError::Call(0x2000)));
}

#[test]
fn interp_step_push_pop_round_trip() {
    let mut i = LlilInterpreter::new(64, 32);
    let push_ai = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Push { size: Size::QWord, src: llil_const(0xCAFEBABE, Size::QWord) },
        length: 1,
    };
    i.step(&push_ai).unwrap();
    assert_eq!(i.sp, 24);
    let pop_ai = LlilAnnotatedInstr {
        address: Address::new(1),
        size: 1,
        instr: LlilInstruction::Pop { dest: LlilRegister::Concrete("rbx".into()), size: Size::QWord },
        length: 1,
    };
    i.step(&pop_ai).unwrap();
    assert_eq!(i.sp, 32);
    assert_eq!(i.read_reg("rbx").unwrap(), 0xCAFEBABE);
}

#[test]
fn interp_step_cond_jump_picks_branch() {
    let mut i = LlilInterpreter::new(0, 0);
    let ai = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: Address::new(0xAA),
            false_dest: Address::new(0xBB),
        },
        length: 1,
    };
    assert_eq!(i.step(&ai).unwrap(), Some(Address::new(0xAA)));

    let ai_false = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::CondJump {
            cond: llil_const(0, Size::Byte),
            true_dest: Address::new(0xAA),
            false_dest: Address::new(0xBB),
        },
        length: 1,
    };
    assert_eq!(i.step(&ai_false).unwrap(), Some(Address::new(0xBB)));
}

#[test]
fn interp_run_simple_function() {
    // Build a function: set rax = 42; ret
    let mut f = LlilFunction::new(Address::new(0x1000));
    let mut block = LlilBasicBlock::default();
    block.start = Address::new(0x1000);
    block.id = 0;
    block.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x1000),
        size: 5,
        instr: LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(42, Size::QWord),
        },
        length: 5,
    });
    block.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x1005),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    });
    f.add_block(block);

    let mut i = LlilInterpreter::new(0, 0);
    i.run(&f).unwrap();
    assert_eq!(i.read_reg("rax").unwrap(), 42);
}

#[test]
fn interp_run_step_limit() {
    // Infinite loop via jump-to-self
    let mut f = LlilFunction::new(Address::new(0x1000));
    let mut block = LlilBasicBlock::default();
    block.start = Address::new(0x1000);
    block.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x1000),
        size: 0,
        instr: LlilInstruction::JumpDest { dest: llil_const(0x1000, Size::QWord) },
        length: 0,
    });
    f.add_block(block);

    let mut i = LlilInterpreter::new(0, 0);
    i.step_limit = 50;
    let err = i.run(&f).unwrap_err();
    assert!(matches!(err, InterpError::StepLimitExceeded(_)));
}

// ─── CFG ────────────────────────────────────────────────────────────────────

#[test]
fn cfg_build_single_block() {
    let mut f = LlilFunction::new(Address::new(0));
    let mut b = LlilBasicBlock::default();
    b.id = 0;
    b.start = Address::new(0);
    b.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    f.add_block(b);
    let cfg = LlilCfg::build(&f);
    assert_eq!(cfg.graph.node_count(), 1);
    assert_eq!(cfg.graph.edge_count(), 0);
}

#[test]
fn cfg_build_cond_jump_two_edges() {
    let mut f = LlilFunction::new(Address::new(0));
    let mut entry = LlilBasicBlock::default();
    entry.id = 0;
    entry.start = Address::new(0);
    entry.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::CondJump {
            cond: llil_const(1, Size::Byte),
            true_dest: Address::new(0x10),
            false_dest: Address::new(0x20),
        },
        length: 1,
    });
    let mut t = LlilBasicBlock::default();
    t.id = 1;
    t.start = Address::new(0x10);
    t.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    let mut fblk = LlilBasicBlock::default();
    fblk.id = 2;
    fblk.start = Address::new(0x20);
    fblk.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    f.add_block(entry);
    f.add_block(t);
    f.add_block(fblk);
    let cfg = LlilCfg::build(&f);
    assert_eq!(cfg.graph.node_count(), 3);
    assert_eq!(cfg.graph.edge_count(), 2);
}

#[test]
fn cfg_edge_display() {
    assert_eq!(format!("{}", CfgEdge::Unconditional), "unconditional");
    assert_eq!(format!("{}", CfgEdge::True), "true");
    assert_eq!(format!("{}", CfgEdge::False), "false");
    assert_eq!(format!("{}", CfgEdge::Call), "call");
}

// ─── Serialisation ──────────────────────────────────────────────────────────

#[test]
fn function_to_json_valid_json() {
    let mut f = LlilFunction::new(Address::new(0x1234));
    let mut b = LlilBasicBlock::default();
    b.id = 0;
    b.start = Address::new(0x1234);
    b.end = Address::new(0x1235);
    b.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    f.add_block(b);

    let json = function_to_json(&f).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["entry"], 0x1234);
}

#[test]
fn function_to_dot_contains_graph() {
    let f = LlilFunction::new(Address::new(0));
    let dot = function_to_dot(&f);
    assert!(dot.starts_with("digraph"));
    assert!(dot.trim_end().ends_with("}"));
}

#[test]
fn function_to_text_works_on_empty() {
    let f = LlilFunction::new(Address::new(0));
    let _t = function_to_text(&f);
}

#[test]
fn llil_function_to_json_and_pretty() {
    let f = LlilFunction::new(Address::new(0x10));
    let s = llil_function_to_json(&f).unwrap();
    let p = llil_function_to_json_pretty(&f).unwrap();
    assert!(p.len() >= s.len());
}

#[test]
fn snapshot_round_trip() {
    let mut f = LlilFunction::new(Address::new(0x40));
    let mut b = LlilBasicBlock::default();
    b.id = 0;
    b.start = Address::new(0x40);
    b.instrs.push(LlilAnnotatedInstr::from(LlilInstruction::Ret));
    f.add_block(b);
    let snap = snapshot_function(&f);
    let json = serde_json::to_string(&snap).unwrap();
    let back = llil_snapshot_from_json(&json).unwrap();
    assert_eq!(back.blocks.len(), snap.blocks.len());
}

// ─── Convenience constructors ──────────────────────────────────────────────

#[test]
fn llil_load_wraps_addr() {
    let e = llil_load(llil_const(0x1000, Size::QWord), Size::DWord);
    match e {
        LlilExpr::Load { size, .. } => assert_eq!(size, Size::DWord),
        _ => panic!("expected Load"),
    }
}

#[test]
fn llil_shl_shr_kinds() {
    let s = llil_shl(llil_const(1, Size::QWord), llil_const(3, Size::QWord), Size::QWord);
    assert!(matches!(s, LlilExpr::ShlT(..)));
    let r = llil_shr(llil_const(8, Size::QWord), llil_const(1, Size::QWord), Size::QWord);
    assert!(matches!(r, LlilExpr::Shr(..)));
}

#[test]
fn llil_sp_and_flag() {
    let sp = llil_sp(Size::QWord);
    assert_eq!(sp.result_size(), Size::QWord);
    let fl = llil_flag("zero");
    assert!(matches!(fl, LlilExpr::Flag(_)));
}

#[test]
fn llil_tmp_creates_temporary_ref() {
    let t = llil_tmp(5, Size::DWord);
    match t {
        LlilExpr::RegisterRef { reg: LlilRegister::Temporary(5), size } => {
            assert_eq!(size, Size::DWord);
        }
        _ => panic!("expected tmp5"),
    }
}

// ─── Rotate / Shift interpreter coverage ───────────────────────────────────

#[test]
fn interp_rol_basic() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::Rol(
        Box::new(llil_const(0x8000_0000_0000_0001, Size::QWord)),
        Box::new(llil_const(1, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(i.eval_expr(&e).unwrap(), 0x3);
}

#[test]
fn interp_ror_basic() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::Ror(
        Box::new(llil_const(0x3, Size::QWord)),
        Box::new(llil_const(1, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(i.eval_expr(&e).unwrap(), 0x8000_0000_0000_0001);
}

#[test]
fn interp_sar_negative() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::Sar(
        Box::new(llil_const(u64::MAX, Size::QWord)),
        Box::new(llil_const(1, Size::QWord)),
        Size::QWord,
    );
    // arithmetic shift of all-ones stays all-ones
    assert_eq!(i.eval_expr(&e).unwrap(), u64::MAX);
}

#[test]
fn interp_lowpart() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::LowPart {
        expr: Box::new(llil_const(0xAABBCCDD, Size::QWord)),
        to: Size::Word,
    };
    assert_eq!(i.eval_expr(&e).unwrap(), 0xCCDD);
}

#[test]
fn interp_not_inverts_bits() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::Not(Box::new(llil_const(0, Size::QWord)), Size::QWord);
    assert_eq!(i.eval_expr(&e).unwrap(), u64::MAX);
}

#[test]
fn interp_neg() {
    let i = LlilInterpreter::new(0, 0);
    let e = LlilExpr::Neg(Box::new(llil_const(1, Size::QWord)), Size::QWord);
    assert_eq!(i.eval_expr(&e).unwrap(), u64::MAX);
}

// ─── lift bridge ──────────────────────────────────────────────────────────

#[test]
fn lift_const_expr() {
    use rustre_il_lift::IrExpr;
    let e = lift_ir_expr_to_llil(&IrExpr::Const(7));
    match e {
        LlilExpr::Const { value, size } => {
            assert_eq!(value, 7);
            assert_eq!(size, Size::QWord);
        }
        _ => panic!(),
    }
}

#[test]
fn lift_add_expr() {
    use rustre_il_lift::IrExpr;
    let e = lift_ir_expr_to_llil(&IrExpr::Add(
        Box::new(IrExpr::Const(1)),
        Box::new(IrExpr::Const(2)),
    ));
    assert!(matches!(e, LlilExpr::AddT(..)));
}

#[test]
fn lifted_instr_empty_effects_is_nop() {
    let li = rustre_il_lift::LiftedInstr {
        address: 0x100,
        original_mnemonic: String::new(),
        ir_text: String::new(),
        il_level: rustre_il_lift::LiftLevel::Llil,
        effects: vec![],
    };
    let out = lifted_instr_to_llil(&li);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].instr, LlilInstruction::Nop));
    assert_eq!(out[0].address, Address::new(0x100));
}
