//! blitz2 — deep adversarial tests for rustre-il-mlil.
//!
//! No `std::time` / rand: seeded LCG for fuzz determinism.

use rustre_core::address::Address;
use rustre_il_mlil::{
    algebraic_simplify, build_use_def_chains, collect_constants, collect_var_info,
    compute_dominators, compute_liveness, eliminate_dead_stores, eliminate_redundant_loads,
    eliminate_trivial_phis, fold_mlil_expr, infer_types, mlil_expr_to_c, mlil_function_to_dot,
    mlil_function_to_json, mlil_function_to_text, propagate_copies, strength_reduce, InferredType,
    MlilAnnotatedInstr, MlilBasicBlock, MlilConstantFoldingPass, MlilCopyPropagationPass,
    MlilDeadStorePass, MlilExpr, MlilExprBuilder, MlilFunction, MlilFunctionBuilder,
    MlilInstrBuilder, MlilInstruction, MlilPass, MlilPassManager, MlilPhiEliminationPass, Size,
    SsaMlilFunction, SsaVar,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

const fn lcg_step(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s
}

const fn cst(v: u64, sz: Size) -> MlilExpr {
    MlilExpr::Const { value: v, size: sz }
}

fn var(name: &str, ver: u32, sz: Size) -> MlilExpr {
    MlilExpr::Var {
        var: SsaVar::new(name, ver),
        size: sz,
    }
}

fn block(id: u32, start: u64, end: u64, instrs: Vec<MlilInstruction>) -> MlilBasicBlock {
    MlilBasicBlock {
        id,
        start: Address(start),
        end: Address(end),
        instrs: instrs
            .into_iter()
            .enumerate()
            .map(|(i, instr)| MlilAnnotatedInstr {
                address: Address(start + i as u64),
                instr,
            })
            .collect(),
        predecessors: Vec::new(),
        successors: Vec::new(),
    }
}

// ─── SsaVar tests ────────────────────────────────────────────────────────────

#[test]
fn ssavar_new_and_display() {
    let v = SsaVar::new("rax", 3);
    assert_eq!(v.name, "rax");
    assert_eq!(v.version, 3);
    assert_eq!(format!("{v}"), "rax#3");
}

#[test]
fn ssavar_initial_is_v0() {
    let v = SsaVar::initial("rbx");
    assert_eq!(v.version, 0);
    assert_eq!(format!("{v}"), "rbx#0");
}

#[test]
fn ssavar_next_version_increments() {
    let v = SsaVar::new("r1", 5);
    let n = v.next_version();
    assert_eq!(n.version, 6);
    assert_eq!(n.name, "r1");
}

#[test]
fn ssavar_next_version_saturates() {
    let v = SsaVar::new("r1", u32::MAX);
    let n = v.next_version();
    assert_eq!(n.version, u32::MAX);
}

#[test]
fn ssavar_hash_eq_consistency_30() {
    use std::collections::HashSet;
    let mut set: HashSet<SsaVar> = HashSet::new();
    for i in 0..30u32 {
        let v = SsaVar::new(format!("v{}", i % 10), i % 5);
        set.insert(v.clone());
        // Equal values hash to the same bucket — re-insert is a no-op.
        assert!(set.contains(&v));
    }
    // 10 names × 5 versions = 50 possible but only 30 inserts; ensure dedupe works.
    assert!(set.len() <= 30);
}

#[test]
fn ssavar_ord_lexicographic() {
    let a = SsaVar::new("a", 5);
    let b = SsaVar::new("a", 6);
    let c = SsaVar::new("b", 0);
    assert!(a < b);
    assert!(b < c);
    assert!(a < c);
}

// ─── MlilExpr basic ─────────────────────────────────────────────────────────

#[test]
fn expr_result_size_const() {
    assert_eq!(cst(7, Size::DWord).result_size(), Size::DWord);
}

#[test]
fn expr_result_size_cmp_is_byte() {
    let e = MlilExpr::CmpEq(Box::new(cst(1, Size::QWord)), Box::new(cst(2, Size::QWord)));
    assert_eq!(e.result_size(), Size::Byte);
}

#[test]
fn expr_is_const() {
    assert_eq!(cst(42, Size::QWord).is_const(), Some(42));
    assert_eq!(var("x", 0, Size::QWord).is_const(), None);
}

#[test]
fn expr_uses_var() {
    let v = SsaVar::new("x", 0);
    let e = MlilExpr::Add(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(cst(3, Size::QWord)),
        Size::QWord,
    );
    assert!(e.uses_var(&v));
    assert!(!e.uses_var(&SsaVar::new("y", 0)));
}

#[test]
fn expr_node_count() {
    let e = MlilExpr::Add(
        Box::new(cst(1, Size::QWord)),
        Box::new(cst(2, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(e.node_count(), 3);
}

#[test]
fn expr_vars_used_dedups() {
    let e = MlilExpr::Add(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(var("x", 0, Size::QWord)),
        Size::QWord,
    );
    let vs = e.vars_used();
    assert_eq!(vs.len(), 1);
    assert_eq!(vs[0], SsaVar::new("x", 0));
}

#[test]
fn expr_is_pure_const() {
    assert!(cst(1, Size::QWord).is_pure());
}

#[test]
fn expr_is_pure_load_false() {
    let e = MlilExpr::Load {
        addr: Box::new(cst(0x1000, Size::QWord)),
        size: Size::QWord,
    };
    assert!(!e.is_pure());
}

// ─── Display round-tripping properties ──────────────────────────────────────

#[test]
fn expr_display_const_hex() {
    assert_eq!(format!("{}", cst(255, Size::Byte)), "0xff");
}

#[test]
fn expr_display_add() {
    let e = MlilExpr::Add(
        Box::new(var("a", 0, Size::QWord)),
        Box::new(var("b", 1, Size::QWord)),
        Size::QWord,
    );
    assert_eq!(format!("{e}"), "(a#0 + b#1)");
}

// ─── MlilInstruction ────────────────────────────────────────────────────────

#[test]
fn instr_is_terminator() {
    let j = MlilInstrBuilder::jump(cst(0x1000, Size::QWord));
    assert!(j.is_terminator());
    let n = MlilInstruction::Nop;
    assert!(!n.is_terminator());
    assert!(MlilInstruction::Ret { values: vec![] }.is_terminator());
}

#[test]
fn instr_is_phi() {
    let p = MlilInstrBuilder::phi(SsaVar::new("x", 2), vec![SsaVar::new("x", 0)]);
    assert!(p.is_phi());
}

#[test]
fn instr_defined_var_assign() {
    let i = MlilInstrBuilder::assign(SsaVar::new("r", 3), Size::QWord, cst(0, Size::QWord));
    assert_eq!(i.defined_var(), Some(&SsaVar::new("r", 3)));
}

#[test]
fn instr_defined_var_nop() {
    assert_eq!(MlilInstruction::Nop.defined_var(), None);
}

#[test]
fn instr_uses_var_phi() {
    let v = SsaVar::new("x", 0);
    let p = MlilInstrBuilder::phi(SsaVar::new("x", 2), vec![v.clone(), SsaVar::new("x", 1)]);
    assert!(p.uses_var(&v));
}

// ─── Constant folding ───────────────────────────────────────────────────────

#[test]
fn fold_add_constants() {
    let e = MlilExpr::Add(
        Box::new(cst(10, Size::QWord)),
        Box::new(cst(32, Size::QWord)),
        Size::QWord,
    );
    let (f, n) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(42));
    assert!(n >= 1);
}

#[test]
fn fold_add_identity_zero_right() {
    let e = MlilExpr::Add(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(cst(0, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert!(matches!(f, MlilExpr::Var { .. }));
}

#[test]
fn fold_sub_self_zero() {
    let e = MlilExpr::Sub(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(var("x", 0, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_xor_self_zero() {
    let e = MlilExpr::Xor(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(var("x", 0, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_mul_by_one() {
    let e = MlilExpr::Mul(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(cst(1, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert!(matches!(f, MlilExpr::Var { .. }));
}

#[test]
fn fold_mul_by_zero() {
    let e = MlilExpr::Mul(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(cst(0, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_truncates_to_size_byte() {
    // 0xFF + 1 in u8 must truncate to 0.
    let e = MlilExpr::Add(
        Box::new(cst(0xFF, Size::Byte)),
        Box::new(cst(1, Size::Byte)),
        Size::Byte,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_neg_const() {
    let e = MlilExpr::Neg(Box::new(cst(5, Size::QWord)), Size::QWord);
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0u64.wrapping_sub(5)));
}

#[test]
fn fold_not_const() {
    let e = MlilExpr::Not(Box::new(cst(0, Size::Byte)), Size::Byte);
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0xFF));
}

#[test]
fn fold_shl_overflow_yields_zero() {
    // shift >= width → 0 (per documented safe_shl)
    let e = MlilExpr::Shl(
        Box::new(cst(1, Size::Byte)),
        Box::new(cst(8, Size::Byte)),
        Size::Byte,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_shr_overflow_yields_zero() {
    let e = MlilExpr::Shr(
        Box::new(cst(0xFF, Size::Byte)),
        Box::new(cst(8, Size::Byte)),
        Size::Byte,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_cmpeq_true() {
    let e = MlilExpr::CmpEq(Box::new(cst(7, Size::QWord)), Box::new(cst(7, Size::QWord)));
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(1));
    assert_eq!(f.result_size(), Size::Byte);
}

#[test]
fn fold_cmpne_false() {
    let e = MlilExpr::CmpNe(Box::new(cst(7, Size::QWord)), Box::new(cst(7, Size::QWord)));
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_double_neg_cancels() {
    let inner = MlilExpr::Neg(Box::new(var("x", 0, Size::QWord)), Size::QWord);
    let outer = MlilExpr::Neg(Box::new(inner), Size::QWord);
    let (f, _) = fold_mlil_expr(outer);
    assert!(matches!(f, MlilExpr::Var { .. }));
}

#[test]
fn fold_seeded_lcg_never_panics() {
    let mut s = lcg_seed();
    for _ in 0..200 {
        let a = lcg_step(&mut s);
        let b = lcg_step(&mut s);
        let sz = match (lcg_step(&mut s)) % 4 {
            0 => Size::Byte,
            1 => Size::Word,
            2 => Size::DWord,
            _ => Size::QWord,
        };
        // Try several ops; each must terminate.
        let e1 = MlilExpr::Add(Box::new(cst(a, sz)), Box::new(cst(b, sz)), sz);
        let (f, _) = fold_mlil_expr(e1);
        // result must fit size
        if let Some(v) = f.is_const() {
            let bits = sz.bits();
            if bits < 64 {
                assert!(v < (1u64 << bits), "fold did not truncate value {v} to {bits} bits");
            }
        }
        let e2 = MlilExpr::Shl(Box::new(cst(a, sz)), Box::new(cst(b & 0xFF, sz)), sz);
        let _ = fold_mlil_expr(e2);
    }
}

// ─── Builders ────────────────────────────────────────────────────────────────

#[test]
fn expr_builder_const_val() {
    let e = MlilExprBuilder::const_val(0xABCD, Size::DWord).build();
    assert_eq!(e.is_const(), Some(0xABCD));
    assert_eq!(e.result_size(), Size::DWord);
}

#[test]
fn expr_builder_chained_add() {
    let e = MlilExprBuilder::const_val(1, Size::QWord)
        .add(cst(2, Size::QWord), Size::QWord)
        .add(cst(3, Size::QWord), Size::QWord)
        .build();
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(6));
}

#[test]
fn function_builder_versions() {
    let mut b = MlilFunctionBuilder::new(Address(0x1000));
    let v0 = b.define("x");
    assert_eq!(v0.version, 0);
    let v1 = b.define("x");
    assert_eq!(v1.version, 1);
    let v2 = b.define("y");
    assert_eq!(v2.version, 0);
    let r = b.read("x");
    assert_eq!(r.version, 1);
}

// ─── Function-level passes & analyses ───────────────────────────────────────

fn build_simple_func() -> MlilFunction {
    let mut f = MlilFunction::new(Address(0x1000));
    let mut b = block(
        0,
        0x1000,
        0x1010,
        vec![
            MlilInstrBuilder::assign(SsaVar::new("a", 0), Size::QWord, cst(10, Size::QWord)),
            MlilInstrBuilder::assign(
                SsaVar::new("b", 0),
                Size::QWord,
                MlilExpr::Add(
                    Box::new(var("a", 0, Size::QWord)),
                    Box::new(cst(5, Size::QWord)),
                    Size::QWord,
                ),
            ),
            MlilInstrBuilder::ret(vec![var("b", 0, Size::QWord)]),
        ],
    );
    b.successors = vec![];
    f.blocks.push(b);
    f
}

#[test]
fn func_total_instr_count() {
    let f = build_simple_func();
    assert_eq!(f.total_instr_count(), 3);
}

#[test]
fn func_is_empty() {
    let f = MlilFunction::new(Address(0));
    assert!(f.is_empty());
    let g = build_simple_func();
    assert!(!g.is_empty());
}

#[test]
fn func_block_by_id() {
    let f = build_simple_func();
    assert!(f.block_by_id(0).is_some());
    assert!(f.block_by_id(99).is_none());
}

#[test]
fn func_find_def_and_uses() {
    let f = build_simple_func();
    let a = SsaVar::new("a", 0);
    assert!(f.find_def(&a).is_some());
    assert_eq!(f.find_uses(&a).len(), 1);
}

#[test]
fn eliminate_dead_stores_kills_unused() {
    let mut f = MlilFunction::new(Address(0x1000));
    // dead = 1; live = 2; ret(live)
    let b = block(
        0,
        0x1000,
        0x1010,
        vec![
            MlilInstrBuilder::assign(SsaVar::new("dead", 0), Size::QWord, cst(1, Size::QWord)),
            MlilInstrBuilder::assign(SsaVar::new("live", 0), Size::QWord, cst(2, Size::QWord)),
            MlilInstrBuilder::ret(vec![var("live", 0, Size::QWord)]),
        ],
    );
    f.blocks.push(b);
    let n = eliminate_dead_stores(&mut f);
    assert_eq!(n, 1);
    assert_eq!(f.total_instr_count(), 2);
}

#[test]
fn dead_stores_preserve_load() {
    // x = [addr]; y = 1; ret y  — load has side effect, must not be removed.
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![
            MlilInstrBuilder::assign(
                SsaVar::new("x", 0),
                Size::QWord,
                MlilExpr::Load {
                    addr: Box::new(cst(0x1000, Size::QWord)),
                    size: Size::QWord,
                },
            ),
            MlilInstrBuilder::assign(SsaVar::new("y", 0), Size::QWord, cst(1, Size::QWord)),
            MlilInstrBuilder::ret(vec![var("y", 0, Size::QWord)]),
        ],
    );
    f.blocks.push(b);
    let _ = eliminate_dead_stores(&mut f);
    // load must remain (preserves observable behaviour)
    assert!(f.all_instrs().any(|ai| matches!(&ai.instr,
        MlilInstruction::Assign { src: MlilExpr::Load { .. }, .. })));
}

#[test]
fn propagate_copies_chain() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![
            MlilInstrBuilder::assign(SsaVar::new("a", 0), Size::QWord, cst(7, Size::QWord)),
            MlilInstrBuilder::assign(
                SsaVar::new("b", 0),
                Size::QWord,
                var("a", 0, Size::QWord),
            ),
            MlilInstrBuilder::assign(
                SsaVar::new("c", 0),
                Size::QWord,
                var("b", 0, Size::QWord),
            ),
            MlilInstrBuilder::ret(vec![var("c", 0, Size::QWord)]),
        ],
    );
    f.blocks.push(b);
    let n = propagate_copies(&mut f);
    // Return should now reference a (transitive).
    assert!(n >= 1);
    let last = f.blocks[0].instrs.last().unwrap();
    if let MlilInstruction::Ret { values } = &last.instr {
        if let MlilExpr::Var { var: v, .. } = &values[0] {
            assert_eq!(v.name, "a");
        } else {
            panic!("expected var");
        }
    }
}

#[test]
fn eliminate_trivial_phis_single_source() {
    let mut f = MlilFunction::new(Address(0));
    let mut b = block(
        0,
        0,
        16,
        vec![
            MlilInstrBuilder::phi(SsaVar::new("x", 1), vec![SsaVar::new("x", 0)]),
            MlilInstrBuilder::ret(vec![var("x", 1, Size::QWord)]),
        ],
    );
    b.successors = vec![];
    f.blocks.push(b);
    let n = eliminate_trivial_phis(&mut f);
    assert_eq!(n, 1);
    // No phi remains.
    assert!(!f.all_instrs().any(|ai| ai.instr.is_phi()));
}

#[test]
fn eliminate_trivial_phis_multi_source_kept() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![MlilInstrBuilder::phi(
            SsaVar::new("x", 2),
            vec![SsaVar::new("x", 0), SsaVar::new("x", 1)],
        )],
    );
    f.blocks.push(b);
    let n = eliminate_trivial_phis(&mut f);
    assert_eq!(n, 0);
}

#[test]
fn redundant_load_elim_const_addr() {
    let mut f = MlilFunction::new(Address(0));
    let addr = cst(0x4000, Size::QWord);
    let b = block(
        0,
        0,
        16,
        vec![
            MlilInstrBuilder::assign(
                SsaVar::new("a", 0),
                Size::QWord,
                MlilExpr::Load {
                    addr: Box::new(addr.clone()),
                    size: Size::QWord,
                },
            ),
            MlilInstrBuilder::assign(
                SsaVar::new("b", 0),
                Size::QWord,
                MlilExpr::Load {
                    addr: Box::new(addr),
                    size: Size::QWord,
                },
            ),
        ],
    );
    f.blocks.push(b);
    let n = eliminate_redundant_loads(&mut f);
    assert_eq!(n, 1);
}

#[test]
fn strength_reduce_mul_pow2() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![MlilInstrBuilder::assign(
            SsaVar::new("y", 0),
            Size::QWord,
            MlilExpr::Mul(
                Box::new(var("x", 0, Size::QWord)),
                Box::new(cst(8, Size::QWord)),
                Size::QWord,
            ),
        )],
    );
    f.blocks.push(b);
    let n = strength_reduce(&mut f);
    assert_eq!(n, 1);
    let ai = &f.blocks[0].instrs[0];
    if let MlilInstruction::Assign { src, .. } = &ai.instr {
        assert!(matches!(src, MlilExpr::Shl(..)));
    }
}

#[test]
fn algebraic_simplify_add_zero() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![MlilInstrBuilder::assign(
            SsaVar::new("y", 0),
            Size::QWord,
            MlilExpr::Add(
                Box::new(var("x", 0, Size::QWord)),
                Box::new(cst(0, Size::QWord)),
                Size::QWord,
            ),
        )],
    );
    f.blocks.push(b);
    let n = algebraic_simplify(&mut f);
    assert!(n >= 1);
}

// ─── Type inference ─────────────────────────────────────────────────────────

#[test]
fn infer_types_const_is_int() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![MlilInstrBuilder::assign(
            SsaVar::new("v", 0),
            Size::DWord,
            cst(5, Size::DWord),
        )],
    );
    f.blocks.push(b);
    let types = infer_types(&f);
    assert_eq!(types.get(&SsaVar::new("v", 0)), Some(&InferredType::Int(Size::DWord)));
}

#[test]
fn infer_types_cmp_is_bool() {
    let mut f = MlilFunction::new(Address(0));
    let b = block(
        0,
        0,
        16,
        vec![MlilInstrBuilder::assign(
            SsaVar::new("b", 0),
            Size::Byte,
            MlilExpr::CmpEq(Box::new(cst(1, Size::QWord)), Box::new(cst(2, Size::QWord))),
        )],
    );
    f.blocks.push(b);
    let types = infer_types(&f);
    assert_eq!(types.get(&SsaVar::new("b", 0)), Some(&InferredType::Bool));
}

// ─── CFG/liveness/dominators ────────────────────────────────────────────────

#[test]
fn dominators_single_block() {
    let f = build_simple_func();
    let dom = compute_dominators(&f);
    assert_eq!(dom.get(&0), Some(&0));
}

#[test]
fn dominators_empty_func() {
    let f = MlilFunction::new(Address(0));
    let dom = compute_dominators(&f);
    assert!(dom.is_empty());
}

#[test]
fn liveness_single_block() {
    let f = build_simple_func();
    let live = compute_liveness(&f);
    assert!(live.contains_key(&0));
}

#[test]
fn use_def_chains_record_def_and_use() {
    let f = build_simple_func();
    let chains = build_use_def_chains(&f);
    let a = SsaVar::new("a", 0);
    let entries = chains.get(&a).expect("var a missing");
    assert!(entries.iter().any(|e| e.is_def));
    assert!(entries.iter().any(|e| !e.is_def));
}

// ─── Pretty-printers / JSON ─────────────────────────────────────────────────

#[test]
fn pretty_text_contains_entry() {
    let f = build_simple_func();
    let t = mlil_function_to_text(&f);
    assert!(t.contains("0x1000"));
}

#[test]
fn pretty_dot_contains_digraph() {
    let f = build_simple_func();
    let d = mlil_function_to_dot(&f);
    assert!(d.starts_with("digraph"));
}

#[test]
fn json_round_trip_parses() {
    let f = build_simple_func();
    let j = mlil_function_to_json(&f).expect("json ok");
    let parsed: serde_json::Value = serde_json::from_str(&j).expect("parse");
    assert_eq!(parsed["entry"], 0x1000);
}

#[test]
fn c_pretty_prints_expr() {
    let e = MlilExpr::Add(
        Box::new(var("x", 0, Size::QWord)),
        Box::new(cst(3, Size::QWord)),
        Size::QWord,
    );
    let s = mlil_expr_to_c(&e);
    assert!(s.contains("x#0"));
    assert!(s.contains("3"));
}

// ─── Pass manager ───────────────────────────────────────────────────────────

#[test]
fn pass_manager_standard_has_passes() {
    let pm = MlilPassManager::standard();
    let names = pm.pass_names();
    assert!(names.contains(&"mlil-constant-fold"));
    assert!(names.contains(&"mlil-dead-store-elim"));
}

#[test]
fn pass_manager_runs_idempotent_on_empty() {
    let mut pm = MlilPassManager::standard();
    let mut f = MlilFunction::new(Address(0));
    let n = pm.run_all(&mut f).expect("run");
    assert_eq!(n, 0);
}

#[test]
fn pass_names_of_pass_structs() {
    assert_eq!(MlilConstantFoldingPass.name(), "mlil-constant-fold");
    assert_eq!(MlilDeadStorePass.name(), "mlil-dead-store-elim");
    assert_eq!(MlilPhiEliminationPass.name(), "mlil-phi-elim");
    assert_eq!(MlilCopyPropagationPass.name(), "mlil-copy-propagation");
}

// ─── Collectors ─────────────────────────────────────────────────────────────

#[test]
fn collect_constants_finds_all() {
    let f = build_simple_func();
    let cs = collect_constants(&f);
    assert!(cs.contains(&10));
    assert!(cs.contains(&5));
}

#[test]
fn var_info_use_count() {
    let f = build_simple_func();
    let info = collect_var_info(&f);
    let a_info = info.iter().find(|i| i.var.name == "a").unwrap();
    assert_eq!(a_info.use_count, 1);
}

// ─── SsaMlilFunction wrapper ────────────────────────────────────────────────

#[test]
fn ssa_wrapper_deref() {
    let f = build_simple_func();
    let s = SsaMlilFunction(f);
    assert_eq!(s.total_instr_count(), 3);
    let inner = s.into_inner();
    assert_eq!(inner.total_instr_count(), 3);
}

// ─── Send + Sync threaded stress ────────────────────────────────────────────

#[test]
fn ssavar_send_sync_threaded() {
    use std::sync::Arc;
    use std::thread;
    let v = Arc::new(SsaVar::new("shared", 7));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let v = Arc::clone(&v);
        handles.push(thread::spawn(move || {
            let mut count = 0u64;
            for _ in 0..100 {
                if v.version == 7 && v.name == "shared" {
                    count += 1;
                }
            }
            count
        }));
    }
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 400);
}

#[test]
fn mlil_function_send_threaded_clone() {
    use std::sync::Arc;
    use std::thread;
    let f = Arc::new(build_simple_func());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let f = Arc::clone(&f);
        handles.push(thread::spawn(move || {
            let mut count = 0u64;
            for _ in 0..100 {
                count += f.total_instr_count() as u64;
            }
            count
        }));
    }
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 4 * 100 * 3);
}

// ─── Boundary integer values ────────────────────────────────────────────────

#[test]
fn fold_add_u64_wrapping() {
    let e = MlilExpr::Add(
        Box::new(cst(u64::MAX, Size::QWord)),
        Box::new(cst(1, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(0));
}

#[test]
fn fold_sub_underflow_wraps() {
    let e = MlilExpr::Sub(
        Box::new(cst(0, Size::QWord)),
        Box::new(cst(1, Size::QWord)),
        Size::QWord,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(u64::MAX));
}

#[test]
fn fold_size_word_truncation() {
    let e = MlilExpr::Add(
        Box::new(cst(0xFFFF, Size::Word)),
        Box::new(cst(2, Size::Word)),
        Size::Word,
    );
    let (f, _) = fold_mlil_expr(e);
    assert_eq!(f.is_const(), Some(1));
}

// ─── State machine: builder versions ────────────────────────────────────────

#[test]
fn builder_block_id_allocates_distinct() {
    let mut b = MlilFunctionBuilder::new(Address(0));
    let i0 = b.alloc_block_id();
    let i1 = b.alloc_block_id();
    let i2 = b.alloc_block_id();
    assert_eq!(i0, 0);
    assert_eq!(i1, 1);
    assert_eq!(i2, 2);
}

#[test]
fn fuzz_propagate_copies_terminates() {
    // Build a long copy chain via LCG of length up to 64; propagate_copies must
    // produce a valid result and not loop.
    let mut s = lcg_seed();
    for _ in 0..10 {
        let mut f = MlilFunction::new(Address(0));
        let len = ((lcg_step(&mut s) % 32) + 2) as usize;
        let mut instrs = Vec::new();
        // x0 = 1
        instrs.push(MlilInstrBuilder::assign(
            SsaVar::new("v0", 0),
            Size::QWord,
            cst(1, Size::QWord),
        ));
        for i in 1..len {
            instrs.push(MlilInstrBuilder::assign(
                SsaVar::new(format!("v{i}"), 0),
                Size::QWord,
                var(&format!("v{}", i - 1), 0, Size::QWord),
            ));
        }
        instrs.push(MlilInstrBuilder::ret(vec![var(
            &format!("v{}", len - 1),
            0,
            Size::QWord,
        )]));
        let b = block(0, 0, 0x1000, instrs);
        f.blocks.push(b);
        let _ = propagate_copies(&mut f);
        // After transitive prop, return should point at v0.
        let last = f.blocks[0].instrs.last().unwrap();
        if let MlilInstruction::Ret { values } = &last.instr
            && let MlilExpr::Var { var: v, .. } = &values[0] {
                assert_eq!(v.name, "v0");
            }
    }
}
