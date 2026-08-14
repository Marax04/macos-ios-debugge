//! Blitz test suite for rustre-il-mlil core APIs.
//!
//! Exhaustive coverage of: SsaVar, MlilExpr, MlilInstruction, MlilBasicBlock,
//! MlilFunction, fold_mlil_expr, eliminate_dead_stores, propagate_copies,
//! eliminate_trivial_phis, infer_types, MlilPassManager, text/dot/json output.

use rustre_core::address::Address;
use rustre_il_mlil::*;

fn v(name: &str, ver: u32) -> SsaVar {
    SsaVar::new(name, ver)
}
fn cst(val: u64, sz: Size) -> MlilExpr {
    MlilExpr::Const { value: val, size: sz }
}
fn var(name: &str, ver: u32, sz: Size) -> MlilExpr {
    MlilExpr::Var { var: v(name, ver), size: sz }
}

// ─── SsaVar ─────────────────────────────────────────────────────────────────

#[test]
fn ssavar_new_and_initial() {
    let a = SsaVar::new("rax", 0);
    let b = SsaVar::initial("rax");
    assert_eq!(a, b);
    assert_eq!(a.version, 0);
    assert_eq!(a.name, "rax");
}

#[test]
fn ssavar_next_version() {
    let a = SsaVar::new("x", 3);
    let b = a.next_version();
    assert_eq!(b.version, 4);
    assert_eq!(b.name, "x");
    // original unchanged
    assert_eq!(a.version, 3);
}

#[test]
fn ssavar_display() {
    assert_eq!(format!("{}", v("rbx", 2)), "rbx#2");
    assert_eq!(format!("{}", v("", 0)), "#0");
}

#[test]
fn ssavar_eq_and_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(v("a", 1));
    s.insert(v("a", 1));
    s.insert(v("a", 2));
    assert_eq!(s.len(), 2);
}

#[test]
fn ssavar_ord() {
    let mut xs = vec![v("b", 0), v("a", 5), v("a", 1)];
    xs.sort();
    assert_eq!(xs, vec![v("a", 1), v("a", 5), v("b", 0)]);
}

// ─── MlilExpr.result_size ───────────────────────────────────────────────────

#[test]
fn expr_result_size_const_var_load() {
    assert_eq!(cst(0, Size::Byte).result_size(), Size::Byte);
    assert_eq!(var("x", 0, Size::QWord).result_size(), Size::QWord);
    assert_eq!(
        MlilExpr::Load {
            addr: Box::new(cst(0, Size::QWord)),
            size: Size::DWord,
        }
        .result_size(),
        Size::DWord
    );
}

#[test]
fn expr_result_size_arith() {
    let e = MlilExpr::Add(
        Box::new(cst(1, Size::DWord)),
        Box::new(cst(2, Size::DWord)),
        Size::DWord,
    );
    assert_eq!(e.result_size(), Size::DWord);
}

#[test]
fn expr_result_size_cmp_is_byte() {
    let e = MlilExpr::CmpEq(Box::new(cst(1, Size::QWord)), Box::new(cst(2, Size::QWord)));
    assert_eq!(e.result_size(), Size::Byte);
}

#[test]
fn expr_result_size_extends() {
    let e = MlilExpr::ZeroExtend {
        expr: Box::new(cst(0, Size::Byte)),
        from: Size::Byte,
        to: Size::QWord,
    };
    assert_eq!(e.result_size(), Size::QWord);
    let e2 = MlilExpr::SignExtend {
        expr: Box::new(cst(0, Size::Byte)),
        from: Size::Byte,
        to: Size::DWord,
    };
    assert_eq!(e2.result_size(), Size::DWord);
}

#[test]
fn expr_result_size_select() {
    let e = MlilExpr::Select {
        cond: Box::new(cst(1, Size::Byte)),
        true_val: Box::new(cst(0, Size::DWord)),
        false_val: Box::new(cst(0, Size::DWord)),
        size: Size::DWord,
    };
    assert_eq!(e.result_size(), Size::DWord);
}

#[test]
fn expr_result_size_call() {
    let e = MlilExpr::Call {
        dest: Box::new(cst(0x1000, Size::QWord)),
        args: vec![],
        return_size: Size::DWord,
    };
    assert_eq!(e.result_size(), Size::DWord);
}

// ─── MlilExpr.is_const and uses_var ─────────────────────────────────────────

#[test]
fn is_const_basic() {
    assert_eq!(cst(42, Size::QWord).is_const(), Some(42));
    assert_eq!(var("x", 0, Size::QWord).is_const(), None);
}

#[test]
fn uses_var_finds_in_load_addr() {
    let e = MlilExpr::Load {
        addr: Box::new(var("rax", 1, Size::QWord)),
        size: Size::DWord,
    };
    assert!(e.uses_var(&v("rax", 1)));
    assert!(!e.uses_var(&v("rax", 2)));
    assert!(!e.uses_var(&v("rbx", 1)));
}

#[test]
fn uses_var_finds_in_binop() {
    let e = MlilExpr::Add(
        Box::new(cst(1, Size::QWord)),
        Box::new(var("y", 3, Size::QWord)),
        Size::QWord,
    );
    assert!(e.uses_var(&v("y", 3)));
    assert!(!e.uses_var(&v("y", 4)));
}

#[test]
fn uses_var_const_and_flag_never_match() {
    assert!(!cst(0, Size::Byte).uses_var(&v("x", 0)));
    assert!(!MlilExpr::Flag { name: "z".into() }.uses_var(&v("z", 0)));
    assert!(!MlilExpr::Undefined(Size::Byte).uses_var(&v("anything", 0)));
    assert!(!MlilExpr::StackPointer(Size::QWord).uses_var(&v("sp", 0)));
}

#[test]
fn uses_var_in_select_branches() {
    let e = MlilExpr::Select {
        cond: Box::new(cst(0, Size::Byte)),
        true_val: Box::new(var("t", 1, Size::DWord)),
        false_val: Box::new(var("f", 1, Size::DWord)),
        size: Size::DWord,
    };
    assert!(e.uses_var(&v("t", 1)));
    assert!(e.uses_var(&v("f", 1)));
    assert!(!e.uses_var(&v("c", 1)));
}

#[test]
fn uses_var_in_call_args() {
    let e = MlilExpr::Call {
        dest: Box::new(var("fn", 0, Size::QWord)),
        args: vec![var("arg", 1, Size::QWord)],
        return_size: Size::QWord,
    };
    assert!(e.uses_var(&v("fn", 0)));
    assert!(e.uses_var(&v("arg", 1)));
}

// ─── MlilInstruction terminator / phi / defined_var / uses_var ──────────────

#[test]
fn instr_is_terminator() {
    assert!(MlilInstruction::Ret { values: vec![] }.is_terminator());
    assert!(MlilInstruction::Jump { dest: cst(0, Size::QWord) }.is_terminator());
    assert!(MlilInstruction::CondJump {
        cond: cst(1, Size::Byte),
        true_dest: Address::new(0x10),
        false_dest: Address::new(0x20),
    }
    .is_terminator());
    assert!(MlilInstruction::TailCall { dest: cst(0, Size::QWord), args: vec![] }.is_terminator());
    assert!(MlilInstruction::Trap { code: 3 }.is_terminator());
    assert!(!MlilInstruction::Nop.is_terminator());
    assert!(!MlilInstruction::Undefined.is_terminator());
}

#[test]
fn instr_is_phi() {
    assert!(MlilInstruction::Phi { dest: v("x", 1), sources: vec![] }.is_phi());
    assert!(!MlilInstruction::Nop.is_phi());
}

#[test]
fn instr_defined_var_assign_phi_call_syscall() {
    let assign = MlilInstruction::Assign {
        dest: v("a", 1),
        size: Size::QWord,
        src: cst(0, Size::QWord),
    };
    assert_eq!(assign.defined_var(), Some(&v("a", 1)));

    let phi = MlilInstruction::Phi { dest: v("p", 2), sources: vec![v("p", 0), v("p", 1)] };
    assert_eq!(phi.defined_var(), Some(&v("p", 2)));

    let call = MlilInstruction::Call {
        dest: cst(0, Size::QWord),
        args: vec![],
        ret_vars: vec![v("ret", 0), v("ret2", 0)],
    };
    assert_eq!(call.defined_var(), Some(&v("ret", 0)));

    let call_empty = MlilInstruction::Call {
        dest: cst(0, Size::QWord),
        args: vec![],
        ret_vars: vec![],
    };
    assert_eq!(call_empty.defined_var(), None);

    assert_eq!(MlilInstruction::Nop.defined_var(), None);
}

#[test]
fn instr_uses_var_in_phi() {
    let phi = MlilInstruction::Phi { dest: v("d", 3), sources: vec![v("a", 1), v("b", 2)] };
    assert!(phi.uses_var(&v("a", 1)));
    assert!(phi.uses_var(&v("b", 2)));
    assert!(!phi.uses_var(&v("c", 1)));
}

#[test]
fn instr_uses_var_in_store_addr_and_src() {
    let st = MlilInstruction::Store {
        addr: var("p", 0, Size::QWord),
        size: Size::DWord,
        src: var("val", 1, Size::DWord),
    };
    assert!(st.uses_var(&v("p", 0)));
    assert!(st.uses_var(&v("val", 1)));
    assert!(!st.uses_var(&v("p", 1)));
}

#[test]
fn instr_display_smoke() {
    let s = format!("{}", MlilInstruction::Nop);
    assert_eq!(s, "nop");
    let s = format!(
        "{}",
        MlilInstruction::Assign { dest: v("x", 1), size: Size::QWord, src: cst(7, Size::QWord) }
    );
    assert!(s.contains("x#1"));
    assert!(s.contains("0x7"));
}

// ─── MlilBasicBlock ─────────────────────────────────────────────────────────

fn ann(addr: u64, instr: MlilInstruction) -> MlilAnnotatedInstr {
    MlilAnnotatedInstr { address: Address::new(addr), instr }
}

fn make_block(id: u32) -> MlilBasicBlock {
    MlilBasicBlock {
        id,
        start: Address::new(0x1000),
        end: Address::new(0x1010),
        instrs: vec![
            ann(
                0x1000,
                MlilInstruction::Phi { dest: v("p", 1), sources: vec![v("p", 0)] },
            ),
            ann(
                0x1004,
                MlilInstruction::Assign {
                    dest: v("x", 1),
                    size: Size::QWord,
                    src: var("p", 1, Size::QWord),
                },
            ),
            ann(0x1008, MlilInstruction::Ret { values: vec![var("x", 1, Size::QWord)] }),
        ],
        predecessors: vec![],
        successors: vec![],
    }
}

#[test]
fn block_phis_and_non_phi_split() {
    let b = make_block(0);
    assert_eq!(b.phis().count(), 1);
    assert_eq!(b.non_phi_instrs().count(), 2);
}

#[test]
fn block_terminator_is_ret() {
    let b = make_block(0);
    let t = b.terminator().expect("has terminator");
    assert!(matches!(t.instr, MlilInstruction::Ret { .. }));
}

#[test]
fn block_terminator_none_if_not_terminator_last() {
    let mut b = make_block(0);
    b.instrs.pop(); // remove Ret
    assert!(b.terminator().is_none());
}

#[test]
fn block_defined_vars_and_used_vars() {
    let b = make_block(0);
    let defs = b.defined_vars();
    assert!(defs.contains(&&v("p", 1)));
    assert!(defs.contains(&&v("x", 1)));
    let uses = b.used_vars();
    assert!(uses.contains(&v("p", 1)));
    assert!(uses.contains(&v("x", 1)));
    assert!(uses.contains(&v("p", 0)));
}

// ─── MlilFunction ───────────────────────────────────────────────────────────

fn make_func() -> MlilFunction {
    let mut f = MlilFunction::new(Address::new(0x1000));
    let b0 = MlilBasicBlock {
        id: 0,
        start: Address::new(0x1000),
        end: Address::new(0x1010),
        instrs: vec![ann(
            0x1000,
            MlilInstruction::Assign {
                dest: v("a", 1),
                size: Size::QWord,
                src: cst(5, Size::QWord),
            },
        )],
        predecessors: vec![],
        successors: vec![1],
    };
    let b1 = MlilBasicBlock {
        id: 1,
        start: Address::new(0x1010),
        end: Address::new(0x1020),
        instrs: vec![
            ann(
                0x1010,
                MlilInstruction::Assign {
                    dest: v("b", 1),
                    size: Size::QWord,
                    src: var("a", 1, Size::QWord),
                },
            ),
            ann(0x1014, MlilInstruction::Ret { values: vec![var("b", 1, Size::QWord)] }),
        ],
        predecessors: vec![0],
        successors: vec![],
    };
    f.blocks.push(b0);
    f.blocks.push(b1);
    f
}

#[test]
fn function_block_by_id_and_at() {
    let f = make_func();
    assert!(f.block_by_id(0).is_some());
    assert!(f.block_by_id(99).is_none());
    assert_eq!(f.block_at(Address::new(0x1000)).map(|b| b.id), Some(0));
    assert_eq!(f.block_at(Address::new(0x100F)).map(|b| b.id), Some(0));
    // boundary: end is exclusive
    assert_eq!(f.block_at(Address::new(0x1010)).map(|b| b.id), Some(1));
    assert!(f.block_at(Address::new(0x9999)).is_none());
}

#[test]
fn function_all_instrs_in_order() {
    let f = make_func();
    let addrs: Vec<u64> = f.all_instrs().map(|ai| ai.address.as_u64()).collect();
    assert_eq!(addrs, vec![0x1000, 0x1010, 0x1014]);
}

#[test]
fn function_find_def_and_uses() {
    let f = make_func();
    let def = f.find_def(&v("a", 1)).expect("def exists");
    assert_eq!(def.address.as_u64(), 0x1000);
    assert!(f.find_def(&v("nope", 0)).is_none());

    let uses = f.find_uses(&v("a", 1));
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].address.as_u64(), 0x1010);
}

#[test]
fn function_all_vars() {
    let f = make_func();
    let vars = f.all_vars();
    assert!(vars.contains(&v("a", 1)));
    assert!(vars.contains(&v("b", 1)));
}

// ─── fold_mlil_expr ─────────────────────────────────────────────────────────

#[test]
fn fold_add_const() {
    let e = MlilExpr::Add(
        Box::new(cst(3, Size::QWord)),
        Box::new(cst(4, Size::QWord)),
        Size::QWord,
    );
    let (out, n) = fold_mlil_expr(e);
    assert_eq!(out, cst(7, Size::QWord));
    assert!(n >= 1);
}

#[test]
fn fold_add_zero_identity_left() {
    let e = MlilExpr::Add(
        Box::new(cst(0, Size::QWord)),
        Box::new(var("x", 1, Size::QWord)),
        Size::QWord,
    );
    let (out, n) = fold_mlil_expr(e);
    assert_eq!(out, var("x", 1, Size::QWord));
    assert!(n >= 1);
}

#[test]
fn fold_add_zero_identity_right() {
    let e = MlilExpr::Add(
        Box::new(var("x", 1, Size::QWord)),
        Box::new(cst(0, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, var("x", 1, Size::QWord));
}

#[test]
fn fold_add_truncates_to_size() {
    // 0xFF + 1 in u8 = 0
    let e = MlilExpr::Add(
        Box::new(cst(0xFF, Size::Byte)),
        Box::new(cst(1, Size::Byte)),
        Size::Byte,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::Byte));
}

#[test]
fn fold_sub_const_underflow_wraps() {
    let e = MlilExpr::Sub(
        Box::new(cst(0, Size::DWord)),
        Box::new(cst(1, Size::DWord)),
        Size::DWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0xFFFF_FFFF, Size::DWord));
}

#[test]
fn fold_sub_x_minus_x_zero() {
    let e = MlilExpr::Sub(
        Box::new(var("x", 1, Size::QWord)),
        Box::new(var("x", 1, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::QWord));
}

#[test]
fn fold_sub_x_minus_x_with_load_preserves() {
    // load is side-effectful — must NOT fold x - x = 0 when x is a Load.
    let load = MlilExpr::Load {
        addr: Box::new(cst(0x1000, Size::QWord)),
        size: Size::QWord,
    };
    let e = MlilExpr::Sub(Box::new(load.clone()), Box::new(load), Size::QWord);
    let (out, _) = fold_mlil_expr(e);
    assert!(!matches!(out, MlilExpr::Const { value: 0, .. }));
}

#[test]
fn fold_mul_zero_pure() {
    let e = MlilExpr::Mul(
        Box::new(var("x", 1, Size::QWord)),
        Box::new(cst(0, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::QWord));
}

#[test]
fn fold_mul_one_identity() {
    let e = MlilExpr::Mul(
        Box::new(cst(1, Size::QWord)),
        Box::new(var("x", 1, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, var("x", 1, Size::QWord));
}

#[test]
fn fold_and_zero() {
    let e = MlilExpr::And(
        Box::new(cst(0, Size::QWord)),
        Box::new(var("x", 1, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::QWord));
}

#[test]
fn fold_and_all_ones_identity() {
    let e = MlilExpr::And(
        Box::new(var("x", 1, Size::Byte)),
        Box::new(cst(0xFF, Size::Byte)),
        Size::Byte,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, var("x", 1, Size::Byte));
}

#[test]
fn fold_xor_x_x_zero() {
    let e = MlilExpr::Xor(
        Box::new(var("x", 1, Size::DWord)),
        Box::new(var("x", 1, Size::DWord)),
        Size::DWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::DWord));
}

#[test]
fn fold_or_idem() {
    let e = MlilExpr::Or(
        Box::new(var("x", 1, Size::DWord)),
        Box::new(var("x", 1, Size::DWord)),
        Size::DWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, var("x", 1, Size::DWord));
}

#[test]
fn fold_shl_overshift_zero() {
    // 1 << 64 saturates to 0 per spec
    let e = MlilExpr::Shl(
        Box::new(cst(1, Size::QWord)),
        Box::new(cst(64, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::QWord));
}

#[test]
fn fold_shr_overshift_zero() {
    let e = MlilExpr::Shr(
        Box::new(cst(0xFFFF_FFFF_FFFF_FFFF, Size::QWord)),
        Box::new(cst(64, Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::QWord));
}

#[test]
fn fold_sar_sign_extend() {
    // sar of -1 (all bits set in u8) by 7 = still -1
    let e = MlilExpr::Sar(
        Box::new(cst(0xFF, Size::Byte)),
        Box::new(cst(7, Size::Byte)),
        Size::Byte,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0xFF, Size::Byte));
}

#[test]
fn fold_neg_double_neg() {
    let inner = var("x", 1, Size::QWord);
    let e = MlilExpr::Neg(
        Box::new(MlilExpr::Neg(Box::new(inner.clone()), Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, inner);
}

#[test]
fn fold_not_double_not() {
    let inner = var("x", 1, Size::QWord);
    let e = MlilExpr::Not(
        Box::new(MlilExpr::Not(Box::new(inner.clone()), Size::QWord)),
        Size::QWord,
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, inner);
}

#[test]
fn fold_cmpeq_const_true() {
    let e = MlilExpr::CmpEq(Box::new(cst(5, Size::QWord)), Box::new(cst(5, Size::QWord)));
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(1, Size::Byte));
}

#[test]
fn fold_cmpeq_x_x_true() {
    let e = MlilExpr::CmpEq(
        Box::new(var("x", 1, Size::QWord)),
        Box::new(var("x", 1, Size::QWord)),
    );
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(1, Size::Byte));
}

#[test]
fn fold_cmpne_const_false() {
    let e = MlilExpr::CmpNe(Box::new(cst(5, Size::QWord)), Box::new(cst(5, Size::QWord)));
    let (out, _) = fold_mlil_expr(e);
    assert_eq!(out, cst(0, Size::Byte));
}

#[test]
fn fold_passthrough_other_variants() {
    let e = MlilExpr::StackPointer(Size::QWord);
    let (out, n) = fold_mlil_expr(e.clone());
    assert_eq!(out, e);
    assert_eq!(n, 0);
}

// ─── eliminate_dead_stores ──────────────────────────────────────────────────

#[test]
fn dead_store_removes_unused_assign() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![
            ann(
                0x0,
                MlilInstruction::Assign {
                    dest: v("dead", 1),
                    size: Size::QWord,
                    src: cst(7, Size::QWord),
                },
            ),
            ann(0x4, MlilInstruction::Ret { values: vec![] }),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let removed = eliminate_dead_stores(&mut f);
    assert_eq!(removed, 1);
    assert_eq!(f.blocks[0].instrs.len(), 1);
}

#[test]
fn dead_store_keeps_load_side_effect() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![ann(
            0x0,
            MlilInstruction::Assign {
                dest: v("dead", 1),
                size: Size::QWord,
                src: MlilExpr::Load {
                    addr: Box::new(cst(0x1000, Size::QWord)),
                    size: Size::QWord,
                },
            },
        )],
        predecessors: vec![],
        successors: vec![],
    });
    let removed = eliminate_dead_stores(&mut f);
    assert_eq!(removed, 0);
    assert_eq!(f.blocks[0].instrs.len(), 1);
}

#[test]
fn dead_store_keeps_used_var() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![
            ann(
                0x0,
                MlilInstruction::Assign {
                    dest: v("x", 1),
                    size: Size::QWord,
                    src: cst(7, Size::QWord),
                },
            ),
            ann(
                0x4,
                MlilInstruction::Ret { values: vec![var("x", 1, Size::QWord)] },
            ),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let removed = eliminate_dead_stores(&mut f);
    assert_eq!(removed, 0);
}

// ─── propagate_copies ───────────────────────────────────────────────────────

#[test]
fn copy_prop_simple() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x20),
        instrs: vec![
            ann(
                0x0,
                MlilInstruction::Assign {
                    dest: v("b", 1),
                    size: Size::QWord,
                    src: var("a", 1, Size::QWord),
                },
            ),
            ann(
                0x4,
                MlilInstruction::Ret { values: vec![var("b", 1, Size::QWord)] },
            ),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let n = propagate_copies(&mut f);
    assert!(n >= 1);
    // The Ret should now use a#1, not b#1.
    if let MlilInstruction::Ret { values } = &f.blocks[0].instrs[1].instr {
        if let MlilExpr::Var { var, .. } = &values[0] {
            assert_eq!(var, &v("a", 1));
        } else {
            panic!("expected Var");
        }
    } else {
        panic!("expected Ret");
    }
}

#[test]
fn copy_prop_transitive_chain() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x30),
        instrs: vec![
            // b = a
            ann(
                0x0,
                MlilInstruction::Assign {
                    dest: v("b", 1),
                    size: Size::QWord,
                    src: var("a", 1, Size::QWord),
                },
            ),
            // c = b
            ann(
                0x4,
                MlilInstruction::Assign {
                    dest: v("c", 1),
                    size: Size::QWord,
                    src: var("b", 1, Size::QWord),
                },
            ),
            // d = c
            ann(
                0x8,
                MlilInstruction::Assign {
                    dest: v("d", 1),
                    size: Size::QWord,
                    src: var("c", 1, Size::QWord),
                },
            ),
            ann(
                0xC,
                MlilInstruction::Ret { values: vec![var("d", 1, Size::QWord)] },
            ),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let _ = propagate_copies(&mut f);
    if let MlilInstruction::Ret { values } = &f.blocks[0].instrs[3].instr {
        if let MlilExpr::Var { var, .. } = &values[0] {
            assert_eq!(var, &v("a", 1), "transitive copy chain should resolve to root");
        } else {
            panic!("expected Var");
        }
    }
}

#[test]
fn copy_prop_returns_zero_when_no_copies() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![ann(0, MlilInstruction::Nop)],
        predecessors: vec![],
        successors: vec![],
    });
    assert_eq!(propagate_copies(&mut f), 0);
}

// ─── eliminate_trivial_phis ─────────────────────────────────────────────────

#[test]
fn trivial_phi_eliminated() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![
            ann(
                0x0,
                MlilInstruction::Phi { dest: v("x", 2), sources: vec![v("x", 1)] },
            ),
            ann(
                0x4,
                MlilInstruction::Ret { values: vec![var("x", 2, Size::QWord)] },
            ),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let n = eliminate_trivial_phis(&mut f);
    assert_eq!(n, 1);
    assert_eq!(f.blocks[0].instrs.len(), 1);
    if let MlilInstruction::Ret { values } = &f.blocks[0].instrs[0].instr {
        if let MlilExpr::Var { var, .. } = &values[0] {
            assert_eq!(var, &v("x", 1));
        }
    }
}

#[test]
fn nontrivial_phi_kept() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![ann(
            0x0,
            MlilInstruction::Phi { dest: v("x", 2), sources: vec![v("x", 0), v("x", 1)] },
        )],
        predecessors: vec![],
        successors: vec![],
    });
    let n = eliminate_trivial_phis(&mut f);
    assert_eq!(n, 0);
    assert_eq!(f.blocks[0].instrs.len(), 1);
}

// ─── infer_types ─────────────────────────────────────────────────────────────

#[test]
fn infer_types_const_assign() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x10),
        instrs: vec![ann(
            0x0,
            MlilInstruction::Assign {
                dest: v("x", 1),
                size: Size::DWord,
                src: cst(5, Size::DWord),
            },
        )],
        predecessors: vec![],
        successors: vec![],
    });
    let types = infer_types(&f);
    assert_eq!(types.get(&v("x", 1)), Some(&InferredType::Int(Size::DWord)));
}

#[test]
fn infer_types_phi_picks_known() {
    let mut f = MlilFunction::new(Address::new(0));
    f.blocks.push(MlilBasicBlock {
        id: 0,
        start: Address::new(0),
        end: Address::new(0x20),
        instrs: vec![
            ann(
                0x0,
                MlilInstruction::Assign {
                    dest: v("a", 1),
                    size: Size::QWord,
                    src: cst(0, Size::QWord),
                },
            ),
            ann(
                0x4,
                MlilInstruction::Phi { dest: v("p", 1), sources: vec![v("a", 1), v("unknown", 0)] },
            ),
        ],
        predecessors: vec![],
        successors: vec![],
    });
    let types = infer_types(&f);
    assert_eq!(types.get(&v("p", 1)), Some(&InferredType::Int(Size::QWord)));
}

#[test]
fn inferred_type_display() {
    assert_eq!(format!("{}", InferredType::Int(Size::DWord)), "int32");
    assert_eq!(format!("{}", InferredType::Pointer), "ptr");
    assert_eq!(format!("{}", InferredType::Bool), "bool");
    assert_eq!(format!("{}", InferredType::Unknown), "?");
}

// ─── MlilPassManager ─────────────────────────────────────────────────────────

#[test]
fn pass_manager_standard_names() {
    let pm = MlilPassManager::standard();
    let names = pm.pass_names();
    assert!(names.contains(&"mlil-constant-fold"));
    assert!(names.contains(&"mlil-dead-store-elim"));
    assert!(names.contains(&"mlil-phi-elim"));
    assert!(names.contains(&"mlil-copy-propagation"));
}

#[test]
fn pass_manager_runs_on_simple_func() {
    let mut f = make_func();
    let mut pm = MlilPassManager::standard();
    let total = pm.run_all(&mut f).expect("pipeline runs");
    // doesn't matter exactly how many, just that it doesn't panic and counts a u32
    let _ = total;
}

#[test]
fn pass_manager_empty_returns_zero() {
    let mut pm = MlilPassManager::new();
    let mut f = make_func();
    assert_eq!(pm.run_all(&mut f).unwrap(), 0);
}

// ─── Pretty-print / DOT / JSON ─────────────────────────────────────────────

#[test]
fn function_to_text_contains_entry_and_blocks() {
    let f = make_func();
    let t = mlil_function_to_text(&f);
    assert!(t.contains("MLIL Function @ 0x1000"));
    assert!(t.contains("Block 0"));
    assert!(t.contains("Block 1"));
}

#[test]
fn function_to_dot_is_digraph() {
    let f = make_func();
    let d = mlil_function_to_dot(&f);
    assert!(d.starts_with("digraph"));
    assert!(d.contains("bb0 -> bb1"));
    assert!(d.ends_with("}\n"));
}

#[test]
fn function_to_json_round_trip_parses() {
    let f = make_func();
    let j = mlil_function_to_json(&f).expect("json ok");
    let parsed: serde_json::Value = serde_json::from_str(&j).expect("valid json");
    assert_eq!(parsed["entry"], 0x1000);
    assert!(parsed["blocks"].is_array());
    assert_eq!(parsed["blocks"].as_array().unwrap().len(), 2);
}

// ─── effects_to_mlil ────────────────────────────────────────────────────────

#[test]
fn effects_to_mlil_empty() {
    let v = effects_to_mlil(&[]);
    assert!(v.is_empty());
}

#[test]
fn effects_to_mlil_regwrite() {
    use rustre_il_lift::{Effect, IrExpr};
    let effects = vec![Effect::RegWrite {
        reg: "rax".into(),
        value: IrExpr::Const(42),
    }];
    let out = effects_to_mlil(&effects);
    assert_eq!(out.len(), 1);
    match &out[0] {
        MlilInstruction::Assign { dest, src, .. } => {
            assert_eq!(dest.name, "rax");
            assert_eq!(src.is_const(), Some(42));
        }
        _ => panic!("expected Assign"),
    }
}

#[test]
fn effects_to_mlil_return_no_value() {
    use rustre_il_lift::Effect;
    let effects = vec![Effect::Return { value: None }];
    let out = effects_to_mlil(&effects);
    assert!(matches!(out[0], MlilInstruction::Ret { ref values } if values.is_empty()));
}

#[test]
fn effects_to_mlil_trap() {
    use rustre_il_lift::Effect;
    let effects = vec![Effect::Trap { vector: 3 }];
    let out = effects_to_mlil(&effects);
    assert!(matches!(out[0], MlilInstruction::Trap { code: 3 }));
}
