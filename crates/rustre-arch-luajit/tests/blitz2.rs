//! Deep adversarial tests for rustre-arch-luajit public API.

use rustre_core::arch::{Architecture, InstrFlags};
use rustre_arch_luajit::{
    BasicBlock, DumpFlags, InstrCategory, LjConst, LjFmt, LjOp, LjUpvalue, LuaJitArch,
    LuaJitBytecode, LuaJitProto, ParseError, RegAccess, collect_reg_accesses, disassemble_listing,
    find_basic_blocks, format_instruction, instr_a, instr_b, instr_c, instr_d, instr_d_signed,
    instr_op, make_lj_abc, make_lj_ad, make_lj_ad_signed,
};
use rustre_core::address::Address;

// Seeded LCG
fn mk_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// --- LjOp / mnemonic / category coverage ---

#[test]
fn t01_ljop_roundtrip_all_valid() {
    for v in 0u8..=96 {
        let op = LjOp::from_u8(v).expect("valid opcode");
        assert_eq!(op as u8, v);
        assert!(!op.mnemonic().is_empty());
    }
}

#[test]
fn t02_ljop_invalid_returns_none() {
    for v in 97u16..=255 {
        assert!(LjOp::from_u8(v as u8).is_none(), "v={v}");
    }
}

#[test]
fn t03_mnemonic_uppercase_and_unique() {
    let mut seen = std::collections::HashSet::new();
    for v in 0u8..=96 {
        let m = LjOp::from_u8(v).unwrap().mnemonic();
        assert_eq!(m, m.to_uppercase());
        assert!(seen.insert(m), "dup {m}");
    }
}

#[test]
fn t04_category_each_op_classified() {
    for v in 0u8..=96 {
        let cat = LjOp::from_u8(v).unwrap().category();
        // Just verify it doesn't panic and returns *some* category
        let _ = format!("{cat:?}");
    }
}

#[test]
fn t05_category_specific_ranges() {
    assert_eq!(LjOp::Islt.category(), InstrCategory::Comparison);
    assert_eq!(LjOp::Mov.category(), InstrCategory::Arithmetic);
    assert_eq!(LjOp::Kstr.category(), InstrCategory::LoadConst);
    assert_eq!(LjOp::Uget.category(), InstrCategory::Upvalue);
    assert_eq!(LjOp::Tgetv.category(), InstrCategory::TableGet);
    assert_eq!(LjOp::Tsetv.category(), InstrCategory::TableSet);
    assert_eq!(LjOp::Call.category(), InstrCategory::Call);
    assert_eq!(LjOp::Ret.category(), InstrCategory::Return);
    assert_eq!(LjOp::Jmp.category(), InstrCategory::Branch);
    assert_eq!(LjOp::Funcf.category(), InstrCategory::FuncHeader);
}

// --- Encode/decode helpers round-trip ---

#[test]
fn t06_make_lj_abc_roundtrip() {
    let mut lcg = mk_lcg();
    for _ in 0..60 {
        let r = lcg();
        let op = (r & 0x7f) as u8 % 97;
        let a = ((r >> 8) & 0xff) as u8;
        let b = ((r >> 16) & 0xff) as u8;
        let c = ((r >> 24) & 0xff) as u8;
        let w = make_lj_abc(op, a, b, c);
        assert_eq!(instr_op(w), op);
        assert_eq!(instr_a(w), a);
        assert_eq!(instr_b(w), b);
        assert_eq!(instr_c(w), c);
    }
}

#[test]
fn t07_make_lj_ad_roundtrip() {
    let mut lcg = mk_lcg();
    for _ in 0..60 {
        let r = lcg();
        let op = (r & 0xff) as u8;
        let a = ((r >> 8) & 0xff) as u8;
        let d = (r >> 16) as u16;
        let w = make_lj_ad(op, a, d);
        assert_eq!(instr_op(w), op);
        assert_eq!(instr_a(w), a);
        assert_eq!(instr_d(w), d);
    }
}

#[test]
fn t08_make_lj_ad_signed_roundtrip() {
    for d_s in [-32768i16, -1, 0, 1, 32767] {
        let w = make_lj_ad_signed(88, 0, d_s);
        assert_eq!(instr_d_signed(w), d_s);
    }
}

#[test]
fn t09_instr_d_combines_b_c() {
    let w = make_lj_ad(0, 0, 0x1234);
    assert_eq!(instr_b(w), 0x12);
    assert_eq!(instr_c(w), 0x34);
    assert_eq!(instr_d(w), 0x1234);
}

#[test]
fn t10_instr_extractor_boundaries() {
    assert_eq!(instr_op(0xFFFF_FFFF), 0xFF);
    assert_eq!(instr_a(0xFFFF_FFFF), 0xFF);
    assert_eq!(instr_b(0xFFFF_FFFF), 0xFF);
    assert_eq!(instr_c(0xFFFF_FFFF), 0xFF);
    assert_eq!(instr_d(0xFFFF_FFFF), 0xFFFF);
    assert_eq!(instr_op(0), 0);
    assert_eq!(instr_d(0), 0);
}

// --- Architecture trait ---

#[test]
fn t11_arch_metadata() {
    let a = LuaJitArch::new();
    assert_eq!(a.name(), "luajit");
    assert_eq!(a.pointer_size(), 8);
    assert_eq!(a.instruction_alignment(), 4);
    assert_eq!(a.max_instruction_length(), 4);
    assert_eq!(a.registers().len(), 16);
}

#[test]
fn t12_arch_disassemble_short_buffer() {
    let a = LuaJitArch::new();
    assert!(a.disassemble(Address::new(0), &[1, 2, 3]).is_err());
    assert!(a.disassemble(Address::new(0), &[]).is_err());
}

#[test]
fn t13_arch_disassemble_invalid_opcode() {
    let a = LuaJitArch::new();
    let w = make_lj_abc(200, 0, 0, 0);
    let r = a.disassemble(Address::new(0), &w.to_le_bytes());
    assert!(r.is_err());
}

#[test]
fn t14_arch_disassemble_mov() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Mov as u8, 3, 7);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert_eq!(i.mnemonic, "mov");
    assert!(i.operands.contains("R3"));
}

#[test]
fn t15_arch_disassemble_ret_flags() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
}

#[test]
fn t16_arch_disassemble_call_flags() {
    let a = LuaJitArch::new();
    let w = make_lj_abc(LjOp::Call as u8, 0, 1, 1);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.flags.contains(InstrFlags::CALL));
}

#[test]
fn t17_arch_disassemble_branch_flags() {
    let a = LuaJitArch::new();
    let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 10);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.flags.contains(InstrFlags::BRANCH));
}

#[test]
fn t18_arch_disassemble_conditional_flags() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Islt as u8, 0, 0);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(i.flags.contains(InstrFlags::CONDITIONAL));
}

#[test]
fn t19_arch_disassemble_fuzz_never_panics() {
    let a = LuaJitArch::new();
    let mut lcg = mk_lcg();
    for _ in 0..200 {
        let w = lcg() as u32;
        let _ = a.disassemble(Address::new(0), &w.to_le_bytes());
    }
}

#[test]
fn t20_arch_disassemble_block_length_matches() {
    let a = LuaJitArch::new();
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ];
    let res = a.disassemble_block(Address::new(0x1000), &words);
    assert_eq!(res.len(), 2);
    for r in &res {
        assert!(r.is_ok());
    }
}

// --- Detail ---

#[test]
fn t21_detail_out_of_bounds_none() {
    let a = LuaJitArch::new();
    assert!(a.detail(5, &[]).is_none());
}

#[test]
fn t22_detail_branch_target_set_for_jmp() {
    let a = LuaJitArch::new();
    let words = vec![make_lj_ad_signed(LjOp::Jmp as u8, 0, 3)];
    let d = a.detail(0, &words).unwrap();
    assert_eq!(d.branch_target, Some(4));
    assert_eq!(d.fmt, LjFmt::AdSigned);
}

#[test]
fn t23_detail_no_branch_target_for_mov() {
    let a = LuaJitArch::new();
    let words = vec![make_lj_ad(LjOp::Mov as u8, 0, 0)];
    let d = a.detail(0, &words).unwrap();
    assert_eq!(d.branch_target, None);
}

#[test]
fn t24_detail_writes_reg_for_mov() {
    let a = LuaJitArch::new();
    let words = vec![make_lj_ad(LjOp::Mov as u8, 5, 0)];
    let d = a.detail(0, &words).unwrap();
    assert!(d.writes_reg(5));
    assert!(!d.writes_reg(6));
}

#[test]
fn t25_detail_writes_reg_false_for_stores() {
    let a = LuaJitArch::new();
    // GSET (55) = store, writes_reg should be false
    let words = vec![make_lj_ad(55, 5, 0)];
    let d = a.detail(0, &words).unwrap();
    assert!(!d.writes_reg(5));
}

#[test]
fn t26_detail_mnemonic_matches_op() {
    let a = LuaJitArch::new();
    let words = vec![make_lj_ad(LjOp::Mov as u8, 0, 0)];
    let d = a.detail(0, &words).unwrap();
    assert_eq!(d.mnemonic(), "mov");
}

// --- format_instruction / disassemble_listing ---

#[test]
fn t27_format_known_opcode() {
    let w = make_lj_abc(LjOp::Addvv as u8, 1, 2, 3);
    let s = format_instruction(4, w);
    assert!(s.contains("ADDVV"));
    assert!(s.contains("R1"));
    assert!(s.contains("0004"));
}

#[test]
fn t28_format_unknown_opcode() {
    let w = make_lj_abc(200, 0, 0, 0);
    let s = format_instruction(0, w);
    assert!(s.contains("???"));
}

#[test]
fn t29_disassemble_listing_multi() {
    let words = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 1),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ];
    let s = disassemble_listing(&words);
    assert!(s.contains("MOV"));
    assert!(s.contains("RET0"));
    assert_eq!(s.lines().count(), 2);
}

#[test]
fn t30_disassemble_listing_empty() {
    assert_eq!(disassemble_listing(&[]), "");
}

// --- basic blocks ---

#[test]
fn t31_basic_blocks_empty() {
    assert!(find_basic_blocks(&[]).is_empty());
}

#[test]
fn t32_basic_blocks_single_no_branch() {
    let words = vec![make_lj_ad(LjOp::Mov as u8, 0, 0)];
    let bbs = find_basic_blocks(&words);
    assert_eq!(bbs.len(), 1);
    assert_eq!(bbs[0], BasicBlock { start: 0, end: 1 });
    assert_eq!(bbs[0].len(), 1);
    assert!(!bbs[0].is_empty());
}

#[test]
fn t33_basic_blocks_split_at_jmp() {
    // jmp +1 (target = 2), mov, mov
    let words = vec![
        make_lj_ad_signed(LjOp::Jmp as u8, 0, 1),
        make_lj_ad(LjOp::Mov as u8, 0, 0),
        make_lj_ad(LjOp::Mov as u8, 1, 0),
    ];
    let bbs = find_basic_blocks(&words);
    assert!(bbs.len() >= 2);
}

#[test]
fn t34_basic_blocks_return_splits() {
    let words = vec![
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
        make_lj_ad(LjOp::Mov as u8, 0, 0),
    ];
    let bbs = find_basic_blocks(&words);
    assert_eq!(bbs.len(), 2);
}

#[test]
fn t35_basic_block_empty_predicate() {
    let bb = BasicBlock { start: 5, end: 5 };
    assert!(bb.is_empty());
    assert_eq!(bb.len(), 0);
}

#[test]
fn t36_basic_blocks_fuzz_never_panics() {
    let mut lcg = mk_lcg();
    for _ in 0..30 {
        let n = (lcg() % 20) as usize;
        let words: Vec<u32> = (0..n).map(|_| lcg() as u32).collect();
        let _ = find_basic_blocks(&words);
    }
}

// --- collect_reg_accesses ---

#[test]
fn t37_reg_accesses_mov_writes_a() {
    let words = vec![make_lj_ad(LjOp::Mov as u8, 3, 0)];
    let accs = collect_reg_accesses(&words);
    assert!(accs.iter().any(|a| a.reg == 3 && a.is_def));
}

#[test]
fn t38_reg_accesses_abc_uses_b_and_c() {
    let words = vec![make_lj_abc(LjOp::Addvv as u8, 0, 5, 7)];
    let accs = collect_reg_accesses(&words);
    assert!(accs.iter().any(|a| a.reg == 5 && !a.is_def));
    assert!(accs.iter().any(|a| a.reg == 7 && !a.is_def));
}

#[test]
fn t39_reg_access_eq_and_hash() {
    let a = RegAccess { instr_idx: 0, reg: 3, is_def: true };
    let b = RegAccess { instr_idx: 0, reg: 3, is_def: true };
    let c = RegAccess { instr_idx: 0, reg: 3, is_def: false };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// --- DumpFlags ---

#[test]
fn t40_dumpflags_decode_all_bits() {
    let f = DumpFlags::from_byte(0x0F);
    assert!(f.be() && f.strip() && f.ffi() && f.fr2());
    let z = DumpFlags::from_byte(0);
    assert!(!z.be() && !z.strip() && !z.ffi() && !z.fr2());
}

#[test]
fn t41_dumpflags_individual_bits() {
    assert!(DumpFlags::from_byte(0x01).be());
    assert!(DumpFlags::from_byte(0x02).strip());
    assert!(DumpFlags::from_byte(0x04).ffi());
    assert!(DumpFlags::from_byte(0x08).fr2());
}

// --- LuaJitProto ---

#[test]
fn t42_proto_defaults_and_helpers() {
    let p = LuaJitProto::default();
    assert_eq!(p.instr_count(), 0);
    assert!(!p.has_children());
    assert!(p.string_constants().is_empty());
    assert!(p.used_opcodes().is_empty());
    assert!(p.branches().is_empty());
}

#[test]
fn t43_proto_is_vararg_flag() {
    let mut p = LuaJitProto::default();
    p.flags = 0x02;
    assert!(p.is_vararg());
    p.flags = 0;
    assert!(!p.is_vararg());
}

#[test]
fn t44_proto_iter_instructions() {
    let mut p = LuaJitProto::default();
    p.instructions = vec![1, 2, 3];
    let v: Vec<_> = p.iter_instructions().collect();
    assert_eq!(v, vec![(0, 1u32), (1, 2), (2, 3)]);
}

#[test]
fn t45_proto_string_constants() {
    let mut p = LuaJitProto::default();
    p.constants = vec![
        LjConst::String(b"hi".to_vec()),
        LjConst::Integer(7),
        LjConst::String(b"bye".to_vec()),
    ];
    let s = p.string_constants();
    assert_eq!(s.len(), 2);
}

#[test]
fn t46_proto_category_histogram() {
    let mut p = LuaJitProto::default();
    p.instructions = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 0),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ];
    let h = p.category_histogram();
    assert_eq!(h.len(), 11);
    assert_eq!(h[InstrCategory::Arithmetic as usize], 1);
    assert_eq!(h[InstrCategory::Return as usize], 1);
}

#[test]
fn t47_proto_used_opcodes_unique() {
    let mut p = LuaJitProto::default();
    p.instructions = vec![
        make_lj_ad(LjOp::Mov as u8, 0, 0),
        make_lj_ad(LjOp::Mov as u8, 1, 0),
        make_lj_ad(LjOp::Ret0 as u8, 0, 0),
    ];
    let ops = p.used_opcodes();
    assert_eq!(ops.len(), 2);
}

#[test]
fn t48_ljupvalue_eq_hash() {
    let u1 = LjUpvalue { on_stack: true, idx: 3 };
    let u2 = LjUpvalue { on_stack: true, idx: 3 };
    let u3 = LjUpvalue { on_stack: false, idx: 3 };
    assert_eq!(u1, u2);
    assert_ne!(u1, u3);
}

#[test]
fn t49_ljconst_eq() {
    assert_eq!(LjConst::Integer(5), LjConst::Integer(5));
    assert_ne!(LjConst::Integer(5), LjConst::Integer(6));
    assert_eq!(LjConst::Nil, LjConst::Nil);
    assert_eq!(LjConst::Bool(true), LjConst::Bool(true));
    assert_ne!(LjConst::Bool(true), LjConst::Bool(false));
}

// --- ParseError + LuaJitBytecode ---

#[test]
fn t50_parse_too_short() {
    assert_eq!(LuaJitBytecode::parse(&[]), Err(ParseError::UnexpectedEof));
    assert_eq!(LuaJitBytecode::parse(&[0x1b, 0x4c]), Err(ParseError::UnexpectedEof));
}

#[test]
fn t51_parse_bad_magic() {
    let data = [0x00, 0x00, 0x00, 0x01, 0x00];
    assert_eq!(LuaJitBytecode::parse(&data), Err(ParseError::BadMagic));
}

#[test]
fn t52_parse_bad_version() {
    let data = [0x1b, 0x4c, 0x4a, 99, 0x02];
    assert_eq!(LuaJitBytecode::parse(&data), Err(ParseError::BadMagic));
}

#[test]
fn t53_parse_error_display() {
    assert!(!format!("{}", ParseError::UnexpectedEof).is_empty());
    assert!(!format!("{}", ParseError::BadMagic).is_empty());
    assert!(!format!("{}", ParseError::Overflow).is_empty());
    assert!(!format!("{}", ParseError::BadUleb).is_empty());
}

#[test]
fn t54_parse_fuzz_never_panics() {
    let mut lcg = mk_lcg();
    for _ in 0..200 {
        let n = (lcg() % 64) as usize;
        let data: Vec<u8> = (0..n).map(|_| lcg() as u8).collect();
        let _ = LuaJitBytecode::parse(&data);
    }
}

#[test]
fn t55_parse_minimal_stripped_no_protos_errors() {
    // magic + version + flags (strip=1) + sentinel(0)
    let data = [0x1b, 0x4c, 0x4a, 1, 0x02, 0x00];
    // Empty proto stack -> UnexpectedEof
    assert_eq!(LuaJitBytecode::parse(&data), Err(ParseError::UnexpectedEof));
}

// --- Send/Sync ---

#[test]
fn t56_arch_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LuaJitArch>();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                let a = LuaJitArch::new();
                for i in 0..100 {
                    let w = make_lj_ad(LjOp::Mov as u8, i as u8, 0);
                    let _ = a.disassemble(Address::new(0), &w.to_le_bytes());
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t57_proto_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<LuaJitProto>();
    assert_send_sync::<LuaJitBytecode>();
}

// --- branch_kind ---

#[test]
fn t58_branch_kind_jmp() {
    use rustre_core::arch::BranchKind;
    let a = LuaJitArch::new();
    let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 5);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert_eq!(a.branch_kind(&i), Some(BranchKind::UnconditionalJump));
}

#[test]
fn t59_branch_kind_ret() {
    use rustre_core::arch::BranchKind;
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert_eq!(a.branch_kind(&i), Some(BranchKind::Return));
}

#[test]
fn t60_branch_kind_none_for_mov() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Mov as u8, 0, 0);
    let i = a.disassemble(Address::new(0), &w.to_le_bytes()).unwrap();
    assert!(a.branch_kind(&i).is_none());
}

#[test]
fn t61_get_branches_jmp_target() {
    let a = LuaJitArch::new();
    let w = make_lj_ad_signed(LjOp::Jmp as u8, 0, 2);
    let i = a.disassemble(Address::new(0x100), &w.to_le_bytes()).unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
}

#[test]
fn t62_get_branches_ret() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Ret0 as u8, 0, 0);
    let i = a.disassemble(Address::new(0x100), &w.to_le_bytes()).unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
}

#[test]
fn t63_get_branches_mov_empty() {
    let a = LuaJitArch::new();
    let w = make_lj_ad(LjOp::Mov as u8, 0, 0);
    let i = a.disassemble(Address::new(0x100), &w.to_le_bytes()).unwrap();
    assert!(a.get_branches(&i).is_empty());
}

// --- Boundary make_lj_ad_signed extremes ---

#[test]
fn t64_make_ad_signed_extremes() {
    let w = make_lj_ad_signed(88, 0, i16::MIN);
    assert_eq!(instr_d_signed(w), i16::MIN);
    let w2 = make_lj_ad_signed(88, 0, i16::MAX);
    assert_eq!(instr_d_signed(w2), i16::MAX);
}
