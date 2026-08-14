//! Deep adversarial test suite for `rustre-il-llil` (blitz2).

use rustre_core::address::Address;
use rustre_il_llil::*;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

// ── seeded LCG ────────────────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn hash_of<T: Hash>(x: &T) -> u64 {
    let mut h = DefaultHasher::new();
    x.hash(&mut h);
    h.finish()
}

// ── Size ──────────────────────────────────────────────────────────────────
#[test]
fn size_bytes_and_bits_match() {
    let cases = [
        (Size::Byte, 1usize, 8usize),
        (Size::Word, 2, 16),
        (Size::DWord, 4, 32),
        (Size::QWord, 8, 64),
        (Size::OWord, 16, 128),
    ];
    for (s, b, bits) in cases {
        assert_eq!(s.bytes(), b);
        assert_eq!(s.bits(), bits);
    }
}

#[test]
fn size_aliases_match_canonical() {
    assert_eq!(Size::B1, Size::Byte);
    assert_eq!(Size::B2, Size::Word);
    assert_eq!(Size::B4, Size::DWord);
    assert_eq!(Size::B8, Size::QWord);
}

#[test]
fn size_try_from_roundtrip() {
    for s in [Size::Byte, Size::Word, Size::DWord, Size::QWord, Size::OWord] {
        let n = s.bytes();
        assert_eq!(Size::try_from(n).unwrap(), s);
    }
}

#[test]
fn size_try_from_errors_on_invalid_bytes() {
    // 32 bytes (`Size::YWord`, AVX/AVX2 YMM) and 64 bytes (`Size::ZWord`,
    // AVX-512 ZMM) are now valid sizes, so they were removed from this list.
    for n in [0usize, 3, 5, 6, 7, 9, 15, 17, 63, 65, 1024, usize::MAX] {
        assert!(Size::try_from(n).is_err(), "n={n}");
    }
}

#[test]
fn size_display_is_byte_count() {
    assert_eq!(format!("{}", Size::Byte), "1");
    assert_eq!(format!("{}", Size::Word), "2");
    assert_eq!(format!("{}", Size::DWord), "4");
    assert_eq!(format!("{}", Size::QWord), "8");
    assert_eq!(format!("{}", Size::OWord), "16");
}

// ── LlilRegister ──────────────────────────────────────────────────────────
#[test]
fn register_name_and_display() {
    let r = LlilRegister::Concrete("rax".into());
    assert_eq!(r.name(), "rax");
    assert_eq!(format!("{r}"), "rax");
    let t = LlilRegister::Temporary(7);
    assert_eq!(t.name(), "tmp7");
    assert_eq!(format!("{t}"), "tmp7");
}

#[test]
fn register_from_string_and_str() {
    let a: LlilRegister = "rbx".into();
    let b: LlilRegister = String::from("rbx").into();
    assert_eq!(a, b);
    assert_eq!(a, LlilRegister::Concrete("rbx".into()));
}

#[test]
fn register_hash_eq_consistency() {
    let pairs: Vec<(LlilRegister, LlilRegister)> = (0..30u32)
        .map(|i| {
            if i % 2 == 0 {
                (
                    LlilRegister::Concrete(format!("r{i}")),
                    LlilRegister::Concrete(format!("r{i}")),
                )
            } else {
                (LlilRegister::Temporary(i), LlilRegister::Temporary(i))
            }
        })
        .collect();
    for (a, b) in &pairs {
        assert_eq!(a, b);
        assert_eq!(hash_of(a), hash_of(b));
    }
}

// ── LlilExpr basics ──────────────────────────────────────────────────────
#[test]
fn const_is_const_zero_helpers() {
    let z = llil_const(0, Size::QWord);
    assert!(z.is_const_zero());
    assert_eq!(z.is_const(), Some(0));
    let nz = llil_const(7, Size::DWord);
    assert!(!nz.is_const_zero());
    assert_eq!(nz.is_const(), Some(7));
    let r = llil_reg("rax", Size::QWord);
    assert!(!r.is_const_zero());
    assert_eq!(r.is_const(), None);
}

#[test]
fn expr_result_size_matches_construction() {
    for s in [Size::Byte, Size::Word, Size::DWord, Size::QWord, Size::OWord] {
        assert_eq!(llil_const(0, s).result_size(), s);
        assert_eq!(llil_reg("r", s).result_size(), s);
        assert_eq!(
            llil_add(llil_const(1, s), llil_const(2, s), s).result_size(),
            s
        );
    }
    let cmp = llil_cmp_eq(llil_const(1, Size::QWord), llil_const(2, Size::QWord));
    assert_eq!(cmp.result_size(), Size::Byte);
    let zx = llil_zx(llil_const(1, Size::Byte), Size::Byte, Size::QWord);
    assert_eq!(zx.result_size(), Size::QWord);
}

#[test]
fn expr_display_smoketest() {
    let e = llil_add(
        llil_reg("rax", Size::QWord),
        llil_const(0x10, Size::QWord),
        Size::QWord,
    );
    let s = format!("{e}");
    assert!(s.contains("rax"));
    assert!(s.contains("0x10"));
    assert!(s.contains('+'));
}

// ── Interpreter eval correctness ─────────────────────────────────────────
fn interp() -> LlilInterpreter {
    LlilInterpreter::new(4096, 0x1000)
}

#[test]
fn eval_arith_50_deterministic() {
    let mut g = lcg();
    let interp = interp();
    for _ in 0..50 {
        let a = g();
        let b = g();
        let mask = u64::MAX;
        let add = llil_add(
            llil_const(a, Size::QWord),
            llil_const(b, Size::QWord),
            Size::QWord,
        );
        let sub = llil_sub(
            llil_const(a, Size::QWord),
            llil_const(b, Size::QWord),
            Size::QWord,
        );
        let xor = llil_xor(
            llil_const(a, Size::QWord),
            llil_const(b, Size::QWord),
            Size::QWord,
        );
        assert_eq!(interp.eval_expr(&add).unwrap(), a.wrapping_add(b) & mask);
        assert_eq!(interp.eval_expr(&sub).unwrap(), a.wrapping_sub(b) & mask);
        assert_eq!(interp.eval_expr(&xor).unwrap(), a ^ b);
    }
}

#[test]
fn eval_masking_byte_word() {
    let interp = interp();
    let big = 0x1122_3344_5566_7788u64;
    let add_byte = llil_add(
        llil_const(big, Size::Byte),
        llil_const(1, Size::Byte),
        Size::Byte,
    );
    let v = interp.eval_expr(&add_byte).unwrap();
    assert_eq!(v, big.wrapping_add(1) & 0xFF);
    let add_word = llil_add(
        llil_const(big, Size::Word),
        llil_const(1, Size::Word),
        Size::Word,
    );
    let v = interp.eval_expr(&add_word).unwrap();
    assert_eq!(v, big.wrapping_add(1) & 0xFFFF);
}

#[test]
fn eval_div_by_zero_signals_err() {
    let interp = interp();
    let d = LlilExpr::DivU(
        Box::new(llil_const(5, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    matches!(interp.eval_expr(&d).unwrap_err(), InterpError::DivisionByZero(_));
    let dm = LlilExpr::ModU(
        Box::new(llil_const(5, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    matches!(interp.eval_expr(&dm).unwrap_err(), InterpError::DivisionByZero(_));
    let ds = LlilExpr::DivS(
        Box::new(llil_const(5, Size::QWord)),
        Box::new(llil_const(0, Size::QWord)),
        Size::QWord,
    );
    matches!(interp.eval_expr(&ds).unwrap_err(), InterpError::DivisionByZero(_));
}

#[test]
fn eval_unsigned_compares_50_deterministic() {
    let mut g = lcg();
    let interp = interp();
    for _ in 0..50 {
        let a = g();
        let b = g();
        let lt = llil_cmp_eq(llil_const(a, Size::QWord), llil_const(b, Size::QWord));
        assert_eq!(interp.eval_expr(&lt).unwrap(), u64::from(a == b));
        let ne = llil_cmp_ne(llil_const(a, Size::QWord), llil_const(b, Size::QWord));
        assert_eq!(interp.eval_expr(&ne).unwrap(), u64::from(a != b));
        let slt = llil_cmp_slt(llil_const(a, Size::QWord), llil_const(b, Size::QWord));
        assert_eq!(
            interp.eval_expr(&slt).unwrap(),
            u64::from((a as i64) < b as i64)
        );
    }
}

#[test]
fn eval_zx_sx_roundtrips() {
    let interp = interp();
    // ZeroExtend masks to source width.
    let val = 0xFFu64;
    let z = llil_zx(llil_const(val, Size::Byte), Size::Byte, Size::QWord);
    assert_eq!(interp.eval_expr(&z).unwrap(), 0xFF);
    // SignExtend of negative byte fills high bits.
    let s = llil_sx(llil_const(0x80, Size::Byte), Size::Byte, Size::QWord);
    let r = interp.eval_expr(&s).unwrap();
    assert_eq!(r, 0xFFFF_FFFF_FFFF_FF80);
    // SignExtend of positive byte leaves high bits clear.
    let s2 = llil_sx(llil_const(0x7F, Size::Byte), Size::Byte, Size::QWord);
    assert_eq!(interp.eval_expr(&s2).unwrap(), 0x7F);
}

#[test]
fn eval_lowpart() {
    let interp = interp();
    let e = LlilExpr::LowPart {
        expr: Box::new(llil_const(0xAABB_CCDDu64, Size::DWord)),
        to: Size::Byte,
    };
    assert_eq!(interp.eval_expr(&e).unwrap(), 0xDD);
    let e2 = LlilExpr::LowPart {
        expr: Box::new(llil_const(0xAABB_CCDDu64, Size::DWord)),
        to: Size::Word,
    };
    assert_eq!(interp.eval_expr(&e2).unwrap(), 0xCCDD);
}

#[test]
fn eval_rol_ror_boundaries() {
    let interp = interp();
    // shift 0 = identity
    let r0 = LlilExpr::Rol(
        Box::new(llil_const(0x12345678, Size::DWord)),
        Box::new(llil_const(0, Size::DWord)),
        Size::DWord,
    );
    assert_eq!(interp.eval_expr(&r0).unwrap(), 0x12345678);
    // QWord rotate
    let r1 = LlilExpr::Rol(
        Box::new(llil_const(0x1, Size::QWord)),
        Box::new(llil_const(4, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(interp.eval_expr(&r1).unwrap(), 0x10);
    let r2 = LlilExpr::Ror(
        Box::new(llil_const(0x10, Size::QWord)),
        Box::new(llil_const(4, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(interp.eval_expr(&r2).unwrap(), 0x1);
}

#[test]
fn eval_neg_and_not() {
    let interp = interp();
    let n = LlilExpr::Neg(Box::new(llil_const(1, Size::QWord)), Size::QWord);
    assert_eq!(interp.eval_expr(&n).unwrap(), 1u64.wrapping_neg());
    let nt = LlilExpr::Not(Box::new(llil_const(0, Size::QWord)), Size::QWord);
    assert_eq!(interp.eval_expr(&nt).unwrap(), u64::MAX);
}

#[test]
fn eval_cond_expr_selects_branch() {
    let interp = interp();
    let e = LlilExpr::CondExpr {
        cond: Box::new(llil_const(1, Size::Byte)),
        true_val: Box::new(llil_const(0xAA, Size::QWord)),
        false_val: Box::new(llil_const(0xBB, Size::QWord)),
        size: Size::QWord,
    };
    assert_eq!(interp.eval_expr(&e).unwrap(), 0xAA);
    let e2 = LlilExpr::CondExpr {
        cond: Box::new(llil_const(0, Size::Byte)),
        true_val: Box::new(llil_const(0xAA, Size::QWord)),
        false_val: Box::new(llil_const(0xBB, Size::QWord)),
        size: Size::QWord,
    };
    assert_eq!(interp.eval_expr(&e2).unwrap(), 0xBB);
}

// ── Memory ───────────────────────────────────────────────────────────────
#[test]
fn mem_read_write_roundtrip_50() {
    let mut g = lcg();
    let mut it = interp();
    for _ in 0..50 {
        let addr = (g() as usize % (it.memory.len() - 8)) as u64;
        let val = g();
        it.mem_write(addr, val, 8).unwrap();
        assert_eq!(it.mem_read(addr, 8).unwrap(), val);
    }
}

#[test]
fn mem_read_oob_errors() {
    let it = interp();
    let n = it.memory.len();
    matches!(
        it.mem_read(n as u64, 1).unwrap_err(),
        InterpError::MemOutOfBounds(_)
    );
    matches!(
        it.mem_read((n - 4) as u64, 8).unwrap_err(),
        InterpError::MemOutOfBounds(_)
    );
    // address overflow
    matches!(
        it.mem_read(u64::MAX, 16).unwrap_err(),
        InterpError::MemOutOfBounds(_)
    );
}

#[test]
fn mem_read_zero_size_succeeds_in_bounds() {
    let it = interp();
    // 0-size read at any in-bounds address shouldn't error.
    assert_eq!(it.mem_read(0, 0).unwrap(), 0);
    assert_eq!(it.mem_read(it.memory.len() as u64, 0).unwrap(), 0);
}

#[test]
fn mem_write_oob_errors() {
    let mut it = interp();
    let n = it.memory.len();
    matches!(
        it.mem_write(n as u64, 0, 1).unwrap_err(),
        InterpError::MemOutOfBounds(_)
    );
}

#[test]
fn read_reg_undefined_is_error() {
    let it = interp();
    matches!(
        it.read_reg("never_set").unwrap_err(),
        InterpError::UndefinedRegister(_)
    );
}

#[test]
fn set_then_read_reg_ok() {
    let mut it = interp();
    it.set_reg("rax", 42);
    assert_eq!(it.read_reg("rax").unwrap(), 42);
}

// ── Builder & Function ───────────────────────────────────────────────────
#[test]
fn builder_default_and_new_equiv() {
    let a = LlilBuilder::new().build();
    let b = LlilBuilder::default().build();
    assert_eq!(a.len(), 0);
    assert_eq!(b.len(), 0);
}

#[test]
fn builder_emits_instrs_in_order() {
    let mut b = LlilBuilder::at(Address::new(0x1000), 3);
    b.set_reg("rax", Size::QWord, llil_const(1, Size::QWord));
    b.advance_to(Address::new(0x1003), 1).ret();
    let out = b.build();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].address, Address::new(0x1000));
    assert_eq!(out[1].address, Address::new(0x1003));
    assert!(matches!(out[1].instr, LlilInstruction::Ret));
}

#[test]
fn builder_all_emit_methods() {
    let mut b = LlilBuilder::at(Address::new(0), 1);
    b.nop();
    b.set_reg("r", Size::QWord, llil_const(0, Size::QWord));
    b.store(llil_const(0, Size::QWord), Size::Byte, llil_const(0, Size::Byte));
    b.load("r2", Size::QWord, llil_const(0, Size::QWord));
    b.jump(llil_const(8, Size::QWord));
    b.call(llil_const(16, Size::QWord));
    b.trap(0xCC);
    b.syscall();
    b.push_stack(Size::QWord, llil_const(0, Size::QWord));
    b.pop("r3", Size::QWord);
    b.push_instr(Size::QWord, llil_const(0, Size::QWord));
    b.cond_jump(llil_const(1, Size::Byte), Address::new(8), Address::new(16));
    b.ret();
    let v = b.build();
    assert_eq!(v.len(), 13);
}

// ── Terminator / successors ──────────────────────────────────────────────
#[test]
fn terminators_classification() {
    assert!(LlilInstruction::Ret.is_terminator());
    assert!(LlilInstruction::Undefined.is_terminator());
    assert!(!LlilInstruction::Nop.is_terminator());
    let cj = LlilInstruction::CondJump {
        cond: llil_const(1, Size::Byte),
        true_dest: Address::new(8),
        false_dest: Address::new(16),
    };
    assert!(cj.is_terminator());
    assert_eq!(cj.successors(), vec![Address::new(8), Address::new(16)]);
    let nop = LlilInstruction::Nop;
    assert!(nop.successors().is_empty());
}

#[test]
fn jumpto_successors_match_targets() {
    let targets = vec![Address::new(0x10), Address::new(0x20), Address::new(0x30)];
    let jt = LlilInstruction::JumpTo {
        dest: llil_const(0, Size::QWord),
        targets: targets.clone(),
    };
    assert_eq!(jt.successors(), targets);
    assert!(jt.is_terminator());
}

// ── reads/writes reg/flag ────────────────────────────────────────────────
#[test]
fn writes_reg_correct() {
    let r = LlilRegister::Concrete("rax".into());
    let inst = LlilInstruction::SetReg {
        dest: r.clone(),
        size: Size::QWord,
        value: llil_const(0, Size::QWord),
    };
    assert!(inst.writes_reg(&r));
    assert!(!inst.writes_reg(&LlilRegister::Concrete("rbx".into())));
}

#[test]
fn reads_reg_traverses_subexprs() {
    let r = LlilRegister::Concrete("rcx".into());
    let inst = LlilInstruction::SetReg {
        dest: LlilRegister::Concrete("rax".into()),
        size: Size::QWord,
        value: llil_add(
            llil_reg("rcx", Size::QWord),
            llil_const(1, Size::QWord),
            Size::QWord,
        ),
    };
    assert!(inst.reads_reg(&r));
    assert!(!inst.reads_reg(&LlilRegister::Concrete("rbx".into())));
}

#[test]
fn reads_writes_flag() {
    let inst = LlilInstruction::SetFlag {
        name: "cf".into(),
        src: llil_flag("zf"),
    };
    assert!(inst.writes_flag("cf"));
    assert!(!inst.writes_flag("zf"));
    assert!(inst.reads_flag("zf"));
    assert!(!inst.reads_flag("cf"));
}

// ── Function helpers ─────────────────────────────────────────────────────
#[test]
fn function_new_temporary_allocates_unique() {
    let mut f = LlilFunction::new(Address::new(0x1000));
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
    block.start = Address::new(0x1000);
    block.end = Address::new(0x1004);
    block.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x1000),
        size: 4,
        instr: LlilInstruction::Nop,
        length: 4,
    });
    f.add_block(block);
    assert!(f.block_at(Address::new(0x1000)).is_some());
    assert!(f.block_at(Address::new(0x9999)).is_none());
    assert!(f.instr_at(Address::new(0x1000)).is_some());
    assert!(f.instr_at(Address::new(0x2000)).is_none());
}

// ── End-to-end interpreter ──────────────────────────────────────────────
#[test]
fn interp_run_simple_function() {
    // function: set rax = 5; ret.
    let mut f = LlilFunction::new(Address::new(0x100));
    let mut blk = LlilBasicBlock {
        start: Address::new(0x100),
        end: Address::new(0x101),
        instrs: vec![],
        id: 0,
        successors: vec![],
    };
    blk.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x100),
        size: 1,
        instr: LlilInstruction::SetReg {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
            value: llil_const(5, Size::QWord),
        },
        length: 1,
    });
    blk.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x101),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    });
    f.add_block(blk);
    let mut it = interp();
    it.run(&f).unwrap();
    assert_eq!(it.read_reg("rax").unwrap(), 5);
}

#[test]
fn interp_step_terminators() {
    let mut it = interp();
    let nop = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Nop,
        length: 1,
    };
    assert_eq!(it.step(&nop).unwrap(), Some(Address::new(1)));
    let ret = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    };
    assert_eq!(it.step(&ret).unwrap(), None);
    let call = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::CallDest {
            dest: llil_const(0x500, Size::QWord),
        },
        length: 1,
    };
    matches!(it.step(&call).unwrap_err(), InterpError::Call(_));
}

#[test]
fn interp_undefined_errs() {
    let mut it = interp();
    let u = LlilAnnotatedInstr {
        address: Address::new(0x12),
        size: 1,
        instr: LlilInstruction::Undefined,
        length: 1,
    };
    matches!(it.step(&u).unwrap_err(), InterpError::Unimplemented(_));
}

// ── Lifting helpers smoketest ───────────────────────────────────────────
#[test]
fn llil_reg_and_tmp_constructors() {
    let r = llil_reg("rdx", Size::QWord);
    matches!(r, LlilExpr::RegisterRef { .. });
    let t = llil_tmp(3, Size::DWord);
    matches!(t, LlilExpr::RegisterRef { reg: LlilRegister::Temporary(3), .. });
    let sp = llil_sp(Size::QWord);
    matches!(sp, LlilExpr::StackPointer(_));
}

// ── Send/Sync stress ────────────────────────────────────────────────────
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<Size>();
    assert_send_sync::<LlilRegister>();
    assert_send_sync::<LlilExpr>();
    assert_send_sync::<LlilInstruction>();
    assert_send_sync::<LlilAnnotatedInstr>();
    assert_send_sync::<LlilBasicBlock>();
    assert_send_sync::<LlilFunction>();
}

#[test]
fn threaded_eval_stress_4x100() {
    use std::sync::Arc;
    use std::thread;
    let interp = Arc::new(interp());
    let mut handles = vec![];
    for _ in 0..4 {
        let it = Arc::clone(&interp);
        handles.push(thread::spawn(move || {
            let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
            let mut g = move || {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s
            };
            for _ in 0..100 {
                let a = g();
                let b = g();
                let e = llil_add(
                    llil_const(a, Size::QWord),
                    llil_const(b, Size::QWord),
                    Size::QWord,
                );
                let v = it.eval_expr(&e).unwrap();
                assert_eq!(v, a.wrapping_add(b));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── HashMap/Eq pairs ────────────────────────────────────────────────────
#[test]
fn register_hashset_dedup() {
    let mut set: HashSet<LlilRegister> = HashSet::new();
    set.insert("rax".into());
    set.insert(LlilRegister::Concrete("rax".into()));
    set.insert("rbx".into());
    set.insert(LlilRegister::Temporary(0));
    set.insert(LlilRegister::Temporary(0));
    assert_eq!(set.len(), 3);
}

#[test]
fn size_hashset_dedup() {
    let mut set: HashSet<Size> = HashSet::new();
    set.insert(Size::Byte);
    set.insert(Size::B1);
    set.insert(Size::Word);
    set.insert(Size::B2);
    assert_eq!(set.len(), 2);
}

// ── Fuzz: 64 random expressions never panic ─────────────────────────────
#[test]
fn fuzz_eval_never_panics() {
    let it = interp();
    let mut g = lcg();
    for _ in 0..64 {
        let a = g();
        let b = g();
        let exprs = [
            llil_add(llil_const(a, Size::QWord), llil_const(b, Size::QWord), Size::QWord),
            llil_sub(llil_const(a, Size::QWord), llil_const(b, Size::QWord), Size::QWord),
            llil_xor(llil_const(a, Size::QWord), llil_const(b, Size::QWord), Size::QWord),
            llil_or(llil_const(a, Size::QWord), llil_const(b, Size::QWord), Size::QWord),
            llil_and(llil_const(a, Size::QWord), llil_const(b, Size::QWord), Size::QWord),
            llil_shl(
                llil_const(a, Size::QWord),
                llil_const(b & 0x3f, Size::QWord),
                Size::QWord,
            ),
            llil_shr(
                llil_const(a, Size::QWord),
                llil_const(b & 0x3f, Size::QWord),
                Size::QWord,
            ),
        ];
        for e in exprs {
            // each must produce Ok or specific error; never panic.
            let _ = it.eval_expr(&e);
        }
    }
}

// ── boundary constants ──────────────────────────────────────────────────
#[test]
fn boundary_const_evaluations() {
    let it = interp();
    for v in [0u64, 1, u8::MAX as u64, u16::MAX as u64, u32::MAX as u64, u64::MAX] {
        let e = llil_const(v, Size::QWord);
        assert_eq!(it.eval_expr(&e).unwrap(), v);
    }
}

// ── Step limit ──────────────────────────────────────────────────────────
#[test]
fn step_limit_triggers_error() {
    // Infinite loop: jump to self.
    let mut f = LlilFunction::new(Address::new(0x100));
    let mut blk = LlilBasicBlock {
        start: Address::new(0x100),
        end: Address::new(0x100),
        instrs: vec![],
        id: 0,
        successors: vec![],
    };
    blk.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x100),
        size: 1,
        instr: LlilInstruction::JumpDest {
            dest: llil_const(0x100, Size::QWord),
        },
        length: 1,
    });
    f.add_block(blk);
    let mut it = interp();
    it.step_limit = 50;
    matches!(it.run(&f).unwrap_err(), InterpError::StepLimitExceeded(_));
}

// ── basic_block helpers ─────────────────────────────────────────────────
#[test]
fn basic_block_empty_helpers() {
    let b = LlilBasicBlock::default();
    assert!(b.is_empty());
    assert!(b.last_instr().is_none());
    assert!(b.terminator().is_none());
}

#[test]
fn basic_block_terminator_detected() {
    let mut b = LlilBasicBlock::default();
    b.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Nop,
        length: 1,
    });
    b.instrs.push(LlilAnnotatedInstr {
        address: Address::new(1),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    });
    assert!(!b.is_empty());
    assert!(b.terminator().is_some());
}

#[test]
fn annotated_from_instruction_default_addr() {
    let a: LlilAnnotatedInstr = LlilInstruction::Nop.into();
    assert_eq!(a.address, Address::default());
    assert_eq!(a.size, 0);
}

// ── Push/Pop interpreter behavior ───────────────────────────────────────
#[test]
fn push_pop_roundtrip() {
    let mut it = LlilInterpreter::new(4096, 0x800);
    let push = LlilAnnotatedInstr {
        address: Address::new(0),
        size: 1,
        instr: LlilInstruction::Push {
            size: Size::QWord,
            src: llil_const(0xDEAD_BEEF, Size::QWord),
        },
        length: 1,
    };
    it.step(&push).unwrap();
    let pop = LlilAnnotatedInstr {
        address: Address::new(1),
        size: 1,
        instr: LlilInstruction::Pop {
            dest: LlilRegister::Concrete("rax".into()),
            size: Size::QWord,
        },
        length: 1,
    };
    it.step(&pop).unwrap();
    assert_eq!(it.read_reg("rax").unwrap(), 0xDEAD_BEEF);
    assert_eq!(it.sp, 0x800);
}

// ── JSON serialise smoketest ────────────────────────────────────────────
#[test]
fn function_to_json_runs() {
    let mut f = LlilFunction::new(Address::new(0x100));
    let mut blk = LlilBasicBlock::default();
    blk.start = Address::new(0x100);
    blk.instrs.push(LlilAnnotatedInstr {
        address: Address::new(0x100),
        size: 1,
        instr: LlilInstruction::Ret,
        length: 1,
    });
    f.add_block(blk);
    let s = function_to_json(&f).unwrap();
    assert!(s.contains("entry"));
    assert!(s.contains("blocks"));
}
