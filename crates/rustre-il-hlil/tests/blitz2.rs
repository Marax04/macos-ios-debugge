//! Deep adversarial blitz2 test suite for `rustre-il-hlil` public API.

use rustre_core::address::Address;
use rustre_il_hlil::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── Helpers ──────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
}

fn cst32(v: i64) -> HlilExpr {
    HlilExpr::Const { value: v, ty: HlilType::i32() }
}

fn var32(name: &str) -> HlilVar {
    HlilVar::new(name, HlilType::i32())
}

fn vexpr(name: &str) -> HlilExpr {
    HlilExpr::Var { var: var32(name) }
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

// ── HlilType ─────────────────────────────────────────────────────────────────

#[test]
fn type_int_constructors_all() {
    assert!(HlilType::i8().is_integer());
    assert!(HlilType::i16().is_integer());
    assert!(HlilType::i32().is_integer());
    assert!(HlilType::i64().is_integer());
    assert!(HlilType::u8().is_integer());
    assert!(HlilType::u16().is_integer());
    assert!(HlilType::u32().is_integer());
    assert!(HlilType::u64().is_integer());
    assert!(!HlilType::Bool.is_integer());
    assert!(!HlilType::Void.is_integer());
}

#[test]
fn type_is_pointer_negatives() {
    assert!(HlilType::ptr(HlilType::Void, 64).is_pointer());
    assert!(HlilType::ptr(HlilType::i32(), 32).is_pointer());
    assert!(!HlilType::i32().is_pointer());
    assert!(!HlilType::Bool.is_pointer());
    assert!(!HlilType::Unknown.is_pointer());
}

#[test]
fn type_byte_size_pointer_widths() {
    assert_eq!(HlilType::ptr(HlilType::Void, 32).byte_size(), Some(4));
    assert_eq!(HlilType::ptr(HlilType::Void, 64).byte_size(), Some(8));
    assert_eq!(HlilType::ptr(HlilType::i64(), 16).byte_size(), Some(2));
}

#[test]
fn type_byte_size_float() {
    assert_eq!(HlilType::Float { bits: 16 }.byte_size(), Some(2));
    assert_eq!(HlilType::Float { bits: 32 }.byte_size(), Some(4));
    assert_eq!(HlilType::Float { bits: 64 }.byte_size(), Some(8));
    // bits not multiple of 8 → None
    assert_eq!(HlilType::Float { bits: 7 }.byte_size(), None);
    assert_eq!(HlilType::Int { signed: true, bits: 3 }.byte_size(), None);
}

#[test]
fn type_byte_size_zero_count_array() {
    let a = HlilType::Array { elem: Box::new(HlilType::i32()), count: Some(0) };
    assert_eq!(a.byte_size(), Some(0));
}

#[test]
fn type_byte_size_overflow_array() {
    // count too big → overflow → None
    let a = HlilType::Array { elem: Box::new(HlilType::i64()), count: Some(u64::MAX) };
    assert_eq!(a.byte_size(), None);
    // very large product overflow u32
    let b = HlilType::Array { elem: Box::new(HlilType::i32()), count: Some(u64::from(u32::MAX)) };
    assert_eq!(b.byte_size(), None);
}

#[test]
fn type_byte_size_nested_array() {
    let inner = HlilType::Array { elem: Box::new(HlilType::u8()), count: Some(4) };
    let outer = HlilType::Array { elem: Box::new(inner), count: Some(3) };
    assert_eq!(outer.byte_size(), Some(12));
}

#[test]
fn type_byte_size_function_unknown() {
    let f = HlilType::Function { ret: Box::new(HlilType::Void), params: vec![] };
    assert_eq!(f.byte_size(), None);
}

#[test]
fn type_display_signed_unsigned() {
    assert_eq!(HlilType::i8().to_string(), "int8_t");
    assert_eq!(HlilType::i16().to_string(), "int16_t");
    assert_eq!(HlilType::i32().to_string(), "int32_t");
    assert_eq!(HlilType::i64().to_string(), "int64_t");
    assert_eq!(HlilType::u8().to_string(), "uint8_t");
    assert_eq!(HlilType::u16().to_string(), "uint16_t");
    assert_eq!(HlilType::u32().to_string(), "uint32_t");
    assert_eq!(HlilType::u64().to_string(), "uint64_t");
}

#[test]
fn type_display_special() {
    assert_eq!(HlilType::Void.to_string(), "void");
    assert_eq!(HlilType::Bool.to_string(), "bool");
    assert_eq!(HlilType::Unknown.to_string(), "unknown");
    assert_eq!(HlilType::Float { bits: 32 }.to_string(), "float");
    assert_eq!(HlilType::Float { bits: 64 }.to_string(), "double");
    assert_eq!(HlilType::Float { bits: 128 }.to_string(), "float128");
    // ⚠ `RUSTRE_INT128` e' default-ON dal 2026-08-14 e rende `__int128` /
    // `unsigned __int128`, che sono i tipi VERI di gcc; `int128_t` non esiste
    // in C ed era un segnaposto. Si accettano entrambe le forme perche' il
    // gate resta spegnibile (`RUSTRE_INT128=0`): un test che asserisse una
    // sola forma codificherebbe lo stato del gate invece della proprieta'.
    let i128 = HlilType::Int { signed: true, bits: 128 }.to_string();
    assert!(i128 == "__int128" || i128 == "int128_t", "inatteso: {i128}");
    let u128 = HlilType::Int { signed: false, bits: 128 }.to_string();
    assert!(
        u128 == "unsigned __int128" || u128 == "uint128_t",
        "inatteso: {u128}"
    );
}

#[test]
fn type_display_pointer_array_struct() {
    assert_eq!(HlilType::ptr(HlilType::i32(), 64).to_string(), "int32_t *");
    let a = HlilType::Array { elem: Box::new(HlilType::u8()), count: Some(16) };
    assert_eq!(a.to_string(), "uint8_t[16]");
    let au = HlilType::Array { elem: Box::new(HlilType::u8()), count: None };
    assert_eq!(au.to_string(), "uint8_t[]");
    assert_eq!(HlilType::Struct { name: "S".into() }.to_string(), "struct S");
    assert_eq!(HlilType::Enum { name: "E".into() }.to_string(), "enum E");
}

#[test]
fn type_display_function_ptr() {
    let f = HlilType::Function {
        ret: Box::new(HlilType::i32()),
        params: vec![HlilType::i32(), HlilType::ptr(HlilType::Void, 64)],
    };
    let s = f.to_string();
    assert!(s.contains("int32_t (*)("));
    assert!(s.contains("int32_t, void *"));
}

#[test]
fn type_hash_eq_consistency() {
    let pairs = [
        (HlilType::i32(), HlilType::i32()),
        (HlilType::u64(), HlilType::u64()),
        (HlilType::Void, HlilType::Void),
        (HlilType::Bool, HlilType::Bool),
        (HlilType::Unknown, HlilType::Unknown),
        (HlilType::ptr(HlilType::i32(), 64), HlilType::ptr(HlilType::i32(), 64)),
        (HlilType::Struct { name: "X".into() }, HlilType::Struct { name: "X".into() }),
        (HlilType::Enum { name: "E".into() }, HlilType::Enum { name: "E".into() }),
        (HlilType::Float { bits: 32 }, HlilType::Float { bits: 32 }),
        (HlilType::Array { elem: Box::new(HlilType::i8()), count: Some(4) },
         HlilType::Array { elem: Box::new(HlilType::i8()), count: Some(4) }),
    ];
    for (a, b) in &pairs {
        assert_eq!(a, b);
        assert_eq!(hash_of(a), hash_of(b));
    }
    // Add 20 fuzzy pairs from different bit widths.
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..30 {
        let bits = (lcg.next() % 64 + 1) as u32;
        let signed = lcg.next() & 1 == 0;
        let a = HlilType::Int { signed, bits };
        let b = HlilType::Int { signed, bits };
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

#[test]
fn type_inequality() {
    assert_ne!(HlilType::i32(), HlilType::u32());
    assert_ne!(HlilType::i32(), HlilType::i64());
    assert_ne!(HlilType::Void, HlilType::Bool);
    assert_ne!(
        HlilType::Struct { name: "A".into() },
        HlilType::Struct { name: "B".into() }
    );
}

// ── HlilVar ──────────────────────────────────────────────────────────────────

#[test]
fn var_new_and_param() {
    let v = HlilVar::new("x", HlilType::i32());
    assert_eq!(v.name, "x");
    assert!(!v.is_param);
    assert!(!v.is_ssa);
    assert_eq!(v.version, 0);
    assert_eq!(v.stack_offset, None);
    let p = HlilVar::param("p", HlilType::u8());
    assert!(p.is_param);
    assert_eq!(p.name, "p");
}

#[test]
fn var_display_format() {
    let v = HlilVar::new("count", HlilType::i32());
    assert_eq!(v.to_string(), "int32_t count");
    let p = HlilVar::param("arg0", HlilType::ptr(HlilType::Void, 64));
    assert_eq!(p.to_string(), "void * arg0");
}

#[test]
fn var_hash_eq_pairs() {
    for i in 0..30 {
        let a = HlilVar::new(format!("v{i}"), HlilType::i32());
        let b = HlilVar::new(format!("v{i}"), HlilType::i32());
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }
}

// ── HlilExpr type tagging ────────────────────────────────────────────────────

#[test]
fn expr_type_basic_carriers() {
    assert_eq!(cst32(5).expr_type(), &HlilType::i32());
    let cmp = HlilExpr::CmpEq(Box::new(cst32(1)), Box::new(cst32(2)));
    assert_eq!(cmp.expr_type(), &HlilType::Bool);
    let und = HlilExpr::Undefined(HlilType::u64());
    assert_eq!(und.expr_type(), &HlilType::u64());
}

#[test]
fn expr_type_sizeof_is_u64() {
    let s = HlilExpr::SizeOf { ty: HlilType::i8() };
    assert!(matches!(s.expr_type(), HlilType::Int { signed: false, bits: 64 }));
}

#[test]
fn expr_type_var_addressof_cast_call() {
    let v = vexpr("a");
    assert_eq!(v.expr_type(), &HlilType::i32());

    let ao = HlilExpr::AddressOf { var: var32("a") };
    assert_eq!(ao.expr_type(), &HlilType::i32());

    let c = HlilExpr::Cast { expr: Box::new(cst32(1)), to: HlilType::u8() };
    assert_eq!(c.expr_type(), &HlilType::u8());

    let call = HlilExpr::Call {
        func: Box::new(vexpr("f")),
        args: vec![],
        ret_ty: HlilType::Void,
    };
    assert_eq!(call.expr_type(), &HlilType::Void);
}

#[test]
fn expr_type_alternate_forms_unknown() {
    let alt = HlilExpr::BitOr(Box::new(cst32(1)), Box::new(cst32(2)));
    assert_eq!(alt.expr_type(), &HlilType::Unknown);
    let cf = HlilExpr::ConstFloat(1.5);
    assert_eq!(cf.expr_type(), &HlilType::Unknown);
}

#[test]
fn expr_is_const_and_zero() {
    assert_eq!(cst32(7).is_const(), Some(7));
    assert!(cst32(0).is_const_zero());
    assert!(!cst32(1).is_const_zero());
    assert_eq!(vexpr("x").is_const(), None);
}

#[test]
fn expr_uses_var_traversals() {
    let target = var32("t");
    let other = var32("o");
    // simple Var
    assert!(HlilExpr::Var { var: target.clone() }.uses_var(&target));
    assert!(!HlilExpr::Var { var: other.clone() }.uses_var(&target));
    // nested Add
    let e = HlilExpr::Add(
        Box::new(HlilExpr::Var { var: target.clone() }),
        Box::new(cst32(3)),
        HlilType::i32(),
    );
    assert!(e.uses_var(&target));
    assert!(!e.uses_var(&other));
    // ternary
    let t = HlilExpr::Ternary {
        cond: Box::new(cst32(1)),
        then: Box::new(HlilExpr::Var { var: target.clone() }),
        else_: Box::new(cst32(2)),
        ty: HlilType::i32(),
    };
    assert!(t.uses_var(&target));
    // call
    let c = HlilExpr::Call {
        func: Box::new(vexpr("f")),
        args: vec![HlilExpr::Var { var: target.clone() }],
        ret_ty: HlilType::Void,
    };
    assert!(c.uses_var(&target));
    // alt form
    let alt = HlilExpr::BitAnd(Box::new(HlilExpr::Var { var: target.clone() }), Box::new(cst32(0xFF)));
    assert!(alt.uses_var(&target));
    // const never uses
    assert!(!cst32(42).uses_var(&target));
}

#[test]
fn expr_uses_var_address_of_distinct() {
    let v1 = var32("v1");
    let v2 = var32("v2");
    let e = HlilExpr::AddressOf { var: v1.clone() };
    assert!(e.uses_var(&v1));
    assert!(!e.uses_var(&v2));
}

#[test]
fn expr_complexity_terminals_one() {
    assert_eq!(cst32(0).complexity(), 1);
    assert_eq!(vexpr("x").complexity(), 1);
    assert_eq!(HlilExpr::AddressOf { var: var32("a") }.complexity(), 1);
    assert_eq!(HlilExpr::SizeOf { ty: HlilType::i32() }.complexity(), 1);
    assert_eq!(HlilExpr::Undefined(HlilType::Bool).complexity(), 1);
    assert_eq!(HlilExpr::Float { value: 1.0, ty: HlilType::Float { bits: 32 } }.complexity(), 1);
}

#[test]
fn expr_complexity_recursive() {
    let e = HlilExpr::Add(Box::new(cst32(1)), Box::new(cst32(2)), HlilType::i32());
    assert_eq!(e.complexity(), 3);
    let nested = HlilExpr::Add(
        Box::new(e),
        Box::new(HlilExpr::Neg(Box::new(cst32(5)), HlilType::i32())),
        HlilType::i32(),
    );
    // 1 + (1+1+1) + (1+1) = 6
    assert_eq!(nested.complexity(), 6);
}

// ── Display for HlilExpr ─────────────────────────────────────────────────────

#[test]
fn display_arith_ops() {
    let a = cst32(1);
    let b = cst32(2);
    assert_eq!(HlilExpr::Add(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 + 2)");
    assert_eq!(HlilExpr::Sub(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 - 2)");
    assert_eq!(HlilExpr::Mul(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 * 2)");
    assert_eq!(HlilExpr::Div(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 / 2)");
    assert_eq!(HlilExpr::Mod(Box::new(a.clone()), Box::new(b), HlilType::i32()).to_string(), "(1 % 2)");
    assert_eq!(HlilExpr::Neg(Box::new(a), HlilType::i32()).to_string(), "-1");
}

#[test]
fn display_bitwise_and_shift() {
    let a = cst32(1);
    let b = cst32(2);
    assert_eq!(HlilExpr::And(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 & 2)");
    assert_eq!(HlilExpr::Or(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 | 2)");
    assert_eq!(HlilExpr::Xor(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 ^ 2)");
    assert_eq!(HlilExpr::Not(Box::new(a.clone()), HlilType::i32()).to_string(), "~1");
    assert_eq!(HlilExpr::Shl(Box::new(a.clone()), Box::new(b.clone()), HlilType::i32()).to_string(), "(1 << 2)");
    assert_eq!(HlilExpr::Shr(Box::new(a), Box::new(b), HlilType::i32()).to_string(), "(1 >> 2)");
}

#[test]
fn display_comparisons_logical() {
    let a = cst32(1);
    let b = cst32(2);
    assert_eq!(HlilExpr::CmpEq(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 == 2)");
    assert_eq!(HlilExpr::CmpNe(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 != 2)");
    assert_eq!(HlilExpr::CmpLt(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 < 2)");
    assert_eq!(HlilExpr::CmpGt(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 > 2)");
    assert_eq!(HlilExpr::CmpLe(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 <= 2)");
    assert_eq!(HlilExpr::CmpGe(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 >= 2)");
    assert_eq!(HlilExpr::LogicalAnd(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 && 2)");
    assert_eq!(HlilExpr::LogicalOr(Box::new(a.clone()), Box::new(b)).to_string(), "(1 || 2)");
    assert_eq!(HlilExpr::LogicalNot(Box::new(a)).to_string(), "!1");
}

#[test]
fn display_special_exprs() {
    assert_eq!(cst32(42).to_string(), "42");
    assert_eq!(vexpr("foo").to_string(), "foo");
    assert_eq!(HlilExpr::AddressOf { var: var32("a") }.to_string(), "&a");
    assert_eq!(
        HlilExpr::Deref { addr: Box::new(vexpr("p")), ty: HlilType::i32() }.to_string(),
        "*p"
    );
    assert_eq!(
        HlilExpr::FieldAccess { base: Box::new(vexpr("s")), field: "f".into(), ty: HlilType::i32() }.to_string(),
        "s.f"
    );
    assert_eq!(
        HlilExpr::Index { base: Box::new(vexpr("a")), idx: Box::new(cst32(3)), ty: HlilType::i32() }.to_string(),
        "a[3]"
    );
    assert_eq!(
        HlilExpr::Cast { expr: Box::new(cst32(1)), to: HlilType::u8() }.to_string(),
        "(uint8_t)1"
    );
    assert_eq!(HlilExpr::SizeOf { ty: HlilType::i32() }.to_string(), "sizeof(int32_t)");
    assert_eq!(HlilExpr::Undefined(HlilType::i32()).to_string(), "undefined");
}

#[test]
fn display_call_and_ternary() {
    let c = HlilExpr::Call {
        func: Box::new(vexpr("foo")),
        args: vec![cst32(1), cst32(2), cst32(3)],
        ret_ty: HlilType::i32(),
    };
    assert_eq!(c.to_string(), "foo(1, 2, 3)");
    let c0 = HlilExpr::Call {
        func: Box::new(vexpr("noop")),
        args: vec![],
        ret_ty: HlilType::Void,
    };
    assert_eq!(c0.to_string(), "noop()");

    let t = HlilExpr::Ternary {
        cond: Box::new(cst32(1)),
        then: Box::new(cst32(2)),
        else_: Box::new(cst32(3)),
        ty: HlilType::i32(),
    };
    assert_eq!(t.to_string(), "(1 ? 2 : 3)");
}

#[test]
fn display_alternate_forms() {
    let a = cst32(1);
    let b = cst32(2);
    assert_eq!(HlilExpr::BitAnd(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 & 2)");
    assert_eq!(HlilExpr::BitOr(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 | 2)");
    assert_eq!(HlilExpr::BitXor(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 ^ 2)");
    assert_eq!(HlilExpr::BoolAnd(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 && 2)");
    assert_eq!(HlilExpr::BoolOr(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 || 2)");
    assert_eq!(HlilExpr::BoolNot(Box::new(a.clone())).to_string(), "!1");
    assert_eq!(HlilExpr::DivU(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 / 2)");
    assert_eq!(HlilExpr::DivS(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 / 2)");
    assert_eq!(HlilExpr::ModU(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 % 2)");
    assert_eq!(HlilExpr::ModS(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 % 2)");
    assert_eq!(HlilExpr::Sar(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 >> 2)");
    assert_eq!(HlilExpr::CmpSlt(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 < 2)");
    assert_eq!(HlilExpr::CmpUlt(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 < 2)");
    assert_eq!(HlilExpr::CmpSle(Box::new(a.clone()), Box::new(b.clone())).to_string(), "(1 <= 2)");
    assert_eq!(HlilExpr::CmpUge(Box::new(a), Box::new(b)).to_string(), "(1 >= 2)");
    assert_eq!(
        HlilExpr::ArrayIndex { array: Box::new(vexpr("a")), index: Box::new(cst32(0)) }.to_string(),
        "a[0]"
    );
    assert_eq!(
        HlilExpr::AddrOf(Box::new(vexpr("x"))).to_string(),
        "&x"
    );
    assert_eq!(
        HlilExpr::If {
            cond: Box::new(cst32(1)),
            then_branch: Box::new(cst32(2)),
            else_branch: Box::new(cst32(3)),
        }.to_string(),
        "(1 ? 2 : 3)"
    );
}

#[test]
fn display_extreme_const_values() {
    assert_eq!(cst32(i64::MAX).to_string(), i64::MAX.to_string());
    assert_eq!(cst32(i64::MIN).to_string(), i64::MIN.to_string());
    assert_eq!(cst32(0).to_string(), "0");
    assert_eq!(cst32(-1).to_string(), "-1");
}

// ── HlilStatement ────────────────────────────────────────────────────────────

#[test]
fn stmt_is_terminator() {
    assert!(HlilStatement::Return(vec![]).is_terminator());
    assert!(HlilStatement::Break.is_terminator());
    assert!(HlilStatement::Continue.is_terminator());
    assert!(HlilStatement::Goto(Address::from(0u64)).is_terminator());
    assert!(!HlilStatement::Nop.is_terminator());
    assert!(!HlilStatement::Expression(cst32(0)).is_terminator());
    assert!(!HlilStatement::Label("L".into()).is_terminator());
}

#[test]
fn stmt_contains_return_nested() {
    let ret = HlilStatement::Return(vec![cst32(0)]);
    assert!(ret.contains_return());

    let if_stmt = HlilStatement::If {
        cond: cst32(1),
        then_body: vec![ret.clone()],
        else_body: vec![],
    };
    assert!(if_stmt.contains_return());

    let while_stmt = HlilStatement::While {
        cond: cst32(1),
        body: vec![ret.clone()],
    };
    assert!(while_stmt.contains_return());

    let do_while = HlilStatement::DoWhile {
        body: vec![ret.clone()],
        cond: cst32(1),
    };
    assert!(do_while.contains_return());

    let for_stmt = HlilStatement::For {
        init: None, cond: None, step: None,
        body: vec![ret.clone()],
    };
    assert!(for_stmt.contains_return());

    let switch = HlilStatement::Switch {
        value: cst32(0),
        cases: vec![SwitchCase { values: vec![1], body: vec![ret.clone()] }],
        default: vec![],
    };
    assert!(switch.contains_return());

    let block = HlilStatement::Block(vec![ret]);
    assert!(block.contains_return());

    let no_ret = HlilStatement::Block(vec![HlilStatement::Nop, HlilStatement::Break]);
    assert!(!no_ret.contains_return());
}

#[test]
fn stmt_walk_counts_all_nested() {
    // build: if (1) { ret; nop; } else { nop; }
    let s = HlilStatement::If {
        cond: cst32(1),
        then_body: vec![HlilStatement::Return(vec![]), HlilStatement::Nop],
        else_body: vec![HlilStatement::Nop],
    };
    let mut count = 0;
    s.walk(&mut |_| count += 1);
    // outer + 3 children = 4
    assert_eq!(count, 4);

    let block = HlilStatement::Block(vec![
        HlilStatement::Nop,
        HlilStatement::Block(vec![HlilStatement::Break, HlilStatement::Continue]),
    ]);
    let mut count = 0;
    block.walk(&mut |_| count += 1);
    // outer + nop + inner block + break + continue = 5
    assert_eq!(count, 5);
}

#[test]
fn stmt_walk_switch_and_for() {
    let switch = HlilStatement::Switch {
        value: cst32(0),
        cases: vec![
            SwitchCase { values: vec![1], body: vec![HlilStatement::Break] },
            SwitchCase { values: vec![2], body: vec![HlilStatement::Continue] },
        ],
        default: vec![HlilStatement::Nop],
    };
    let mut count = 0;
    switch.walk(&mut |_| count += 1);
    // outer + 2 case bodies + 1 default = 4
    assert_eq!(count, 4);

    let for_stmt = HlilStatement::For {
        init: Some(Box::new(HlilStatement::Nop)),
        cond: None, step: None,
        body: vec![HlilStatement::Nop, HlilStatement::Nop],
    };
    let mut count = 0;
    for_stmt.walk(&mut |_| count += 1);
    // outer + init + 2 body = 4
    assert_eq!(count, 4);
}

#[test]
fn stmt_display_assign_and_return() {
    let assign = HlilStatement::Assign {
        dest: vexpr("x"),
        src: cst32(5),
    };
    assert_eq!(assign.to_string(), "x = 5;");

    let ret_empty = HlilStatement::Return(vec![]);
    assert_eq!(ret_empty.to_string(), "return;");
    let ret_one = HlilStatement::Return(vec![cst32(1)]);
    assert_eq!(ret_one.to_string(), "return 1;");
    let ret_two = HlilStatement::Return(vec![cst32(1), cst32(2)]);
    assert_eq!(ret_two.to_string(), "return 1, 2;");

    assert_eq!(HlilStatement::Break.to_string(), "break;");
    assert_eq!(HlilStatement::Continue.to_string(), "continue;");
    assert_eq!(HlilStatement::Label("L1".into()).to_string(), "L1:");
    assert_eq!(HlilStatement::Nop.to_string(), ";");
}

#[test]
fn stmt_display_var_decl_forms() {
    let v = HlilVar::new("x", HlilType::i32());
    let d1 = HlilStatement::VarDeclare { var: v.clone(), init: Some(cst32(7)) };
    assert_eq!(d1.to_string(), "int32_t x = 7;");
    let d2 = HlilStatement::VarDeclare { var: v.clone(), init: None };
    assert_eq!(d2.to_string(), "int32_t x;");

    let d3 = HlilStatement::VarDecl {
        var: v.clone(),
        ty: HlilType::u8(),
        init: Some(cst32(9)),
    };
    assert_eq!(d3.to_string(), "uint8_t x = 9;");
    let d4 = HlilStatement::VarDecl {
        var: v,
        ty: HlilType::u8(),
        init: None,
    };
    assert_eq!(d4.to_string(), "uint8_t x;");
}

#[test]
fn stmt_display_if_and_while() {
    let s = HlilStatement::If {
        cond: cst32(1),
        then_body: vec![HlilStatement::Nop],
        else_body: vec![],
    };
    let out = s.to_string();
    assert!(out.starts_with("if (1) {"));
    assert!(out.ends_with('}'));
    assert!(!out.contains("else"));

    let s2 = HlilStatement::If {
        cond: cst32(1),
        then_body: vec![HlilStatement::Break],
        else_body: vec![HlilStatement::Continue],
    };
    let out2 = s2.to_string();
    assert!(out2.contains("else {"));

    let w = HlilStatement::While {
        cond: cst32(1),
        body: vec![HlilStatement::Break],
    };
    let outw = w.to_string();
    assert!(outw.starts_with("while (1) {"));
}

#[test]
fn stmt_display_assign_unpack_and_expr() {
    let s = HlilStatement::AssignUnpack {
        dests: vec![var32("a"), var32("b")],
        src: vexpr("pair"),
    };
    assert_eq!(s.to_string(), "(a, b) = pair;");

    let e = HlilStatement::Expr(cst32(42));
    assert_eq!(e.to_string(), "42;");
    let e2 = HlilStatement::Expression(cst32(43));
    assert_eq!(e2.to_string(), "43;");
}

#[test]
fn stmt_display_dowhile_and_switch() {
    let s = HlilStatement::DoWhile {
        body: vec![HlilStatement::Break],
        cond: cst32(0),
    };
    let out = s.to_string();
    assert!(out.starts_with("do {"));
    assert!(out.contains("} while (0);"));

    let sw = HlilStatement::Switch {
        value: vexpr("x"),
        cases: vec![SwitchCase { values: vec![1, 2], body: vec![HlilStatement::Break] }],
        default: vec![HlilStatement::Nop],
    };
    let out = sw.to_string();
    assert!(out.contains("switch (x) {"));
    assert!(out.contains("case 1:"));
    assert!(out.contains("case 2:"));
    assert!(out.contains("default:"));
}

// ── HlilPrototype ────────────────────────────────────────────────────────────

#[test]
fn proto_display_basic() {
    let p = HlilPrototype {
        name: "fn".into(),
        return_type: HlilType::i32(),
        params: vec![HlilVar::param("a", HlilType::i32()), HlilVar::param("b", HlilType::i32())],
        is_variadic: false,
        calling_convention: None,
    };
    assert_eq!(p.to_string(), "int32_t fn(int32_t a, int32_t b)");

    let p2 = HlilPrototype {
        name: "g".into(),
        return_type: HlilType::Void,
        params: vec![],
        is_variadic: true,
        calling_convention: None,
    };
    assert_eq!(p2.to_string(), "void g(...)");

    let p3 = HlilPrototype {
        name: "h".into(),
        return_type: HlilType::Void,
        params: vec![HlilVar::param("x", HlilType::i32())],
        is_variadic: true,
        calling_convention: None,
    };
    assert_eq!(p3.to_string(), "void h(int32_t x, ...)");
}

// ── HlilFunction ─────────────────────────────────────────────────────────────

#[test]
fn function_new_defaults() {
    let f = HlilFunction::new(Address::from(0x1000u64), "main");
    assert_eq!(f.prototype.name, "main");
    assert_eq!(f.prototype.return_type, HlilType::Void);
    assert!(f.prototype.params.is_empty());
    assert!(!f.prototype.is_variadic);
    assert!(f.locals.is_empty());
    assert!(f.body.is_empty());
    assert!(f.lifted_from.is_none());
}

#[test]
fn function_add_local_and_iter() {
    let mut f = HlilFunction::new(Address::from(0u64), "f");
    f.add_local(var32("a"));
    f.add_local(var32("b"));
    assert_eq!(f.locals.len(), 2);
    f.body.push(HlilStatement::Nop);
    f.body.push(HlilStatement::Return(vec![]));
    assert_eq!(f.all_statements().count(), 2);
}

#[test]
fn function_calls_made_collects_deeply() {
    let mut f = HlilFunction::new(Address::from(0u64), "f");
    let call_a = HlilExpr::Call {
        func: Box::new(vexpr("a")), args: vec![], ret_ty: HlilType::Void,
    };
    let call_b = HlilExpr::Call {
        func: Box::new(vexpr("b")), args: vec![], ret_ty: HlilType::Void,
    };
    // Nested: call_a as arg to another call
    let nested = HlilExpr::Call {
        func: Box::new(vexpr("outer")),
        args: vec![call_a],
        ret_ty: HlilType::Void,
    };
    f.body.push(HlilStatement::Expression(nested));
    f.body.push(HlilStatement::Expression(call_b));
    let calls = f.calls_made();
    // outer call + inner call_a + call_b = 3
    assert_eq!(calls.len(), 3);
}

#[test]
fn function_vars_used_collects() {
    let mut f = HlilFunction::new(Address::from(0u64), "f");
    f.body.push(HlilStatement::Assign {
        dest: vexpr("x"),
        src: HlilExpr::Add(Box::new(vexpr("y")), Box::new(vexpr("z")), HlilType::i32()),
    });
    let vars = f.vars_used();
    assert_eq!(vars.len(), 3);
    let names: Vec<&str> = vars.iter().map(|v| v.name.as_str()).collect();
    assert!(names.contains(&"x"));
    assert!(names.contains(&"y"));
    assert!(names.contains(&"z"));
}

#[test]
fn function_print_contains_signature() {
    let mut f = HlilFunction::new(Address::from(0u64), "myfunc");
    f.prototype.return_type = HlilType::i32();
    f.prototype.params = vec![HlilVar::param("a", HlilType::i32())];
    f.body.push(HlilStatement::Return(vec![vexpr("a")]));
    let printed = f.print();
    assert!(printed.contains("myfunc"));
    assert!(printed.contains("int32_t"));
    assert!(printed.contains("return"));
}

// ── CCodePrinter ─────────────────────────────────────────────────────────────

#[test]
fn printer_default_uses_4_spaces() {
    let p = CCodePrinter::new();
    assert_eq!(p.indent_width, 4);
    assert!(!p.use_tabs);
}

#[test]
fn printer_print_type_and_expr_match_display() {
    let p = CCodePrinter::new();
    assert_eq!(p.print_type(&HlilType::i32()), "int32_t");
    assert_eq!(p.print_expr(&cst32(5)), "5");
    assert_eq!(p.print_expr(&vexpr("hello")), "hello");
}

#[test]
fn printer_print_statement_basic() {
    let p = CCodePrinter::new();
    let s = HlilStatement::Return(vec![cst32(0)]);
    let out = p.print_statement(&s, 0);
    assert!(out.contains("return 0;"));
}

// ── Deterministic many-input fuzz ────────────────────────────────────────────

#[test]
fn fuzz_const_display_round_trip_50() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let v = lcg.next() as i64;
        let e = cst32(v);
        // Display must produce parseable i64.
        let s = e.to_string();
        let parsed: i64 = s.parse().expect("display should parse back");
        assert_eq!(parsed, v);
    }
}

#[test]
fn fuzz_expr_uses_var_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let target = var32("target");
    for _ in 0..50 {
        let r = lcg.next() % 6;
        let e = match r {
            0 => cst32(lcg.next() as i64),
            1 => vexpr("target"),
            2 => vexpr("other"),
            3 => HlilExpr::Add(Box::new(cst32(1)), Box::new(vexpr("target")), HlilType::i32()),
            4 => HlilExpr::Call {
                func: Box::new(vexpr("f")),
                args: vec![cst32(lcg.next() as i64), vexpr("target")],
                ret_ty: HlilType::Void,
            },
            _ => HlilExpr::Cast { expr: Box::new(vexpr("target")), to: HlilType::u8() },
        };
        // does not panic
        let _ = e.uses_var(&target);
        let _ = e.complexity();
        let _ = e.expr_type();
        let _ = e.to_string();
    }
}

#[test]
fn fuzz_byte_size_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let bits = (lcg.next() % 256) as u32;
        let signed = lcg.next() & 1 == 0;
        let t = HlilType::Int { signed, bits };
        let _ = t.byte_size();
        let _ = t.to_string();

        let count = lcg.next();
        let a = HlilType::Array {
            elem: Box::new(HlilType::Int { signed, bits: bits.max(1) }),
            count: Some(count),
        };
        let _ = a.byte_size();
    }
}

#[test]
fn fuzz_stmt_walk_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let r = lcg.next() % 5;
        let s = match r {
            0 => HlilStatement::Nop,
            1 => HlilStatement::Return(vec![cst32(lcg.next() as i64)]),
            2 => HlilStatement::If {
                cond: cst32(1),
                then_body: vec![HlilStatement::Break],
                else_body: vec![HlilStatement::Continue],
            },
            3 => HlilStatement::Block(vec![HlilStatement::Nop, HlilStatement::Nop]),
            _ => HlilStatement::While {
                cond: cst32(1),
                body: vec![HlilStatement::Break],
            },
        };
        let mut count = 0;
        s.walk(&mut |_| count += 1);
        assert!(count >= 1);
        let _ = s.to_string();
        let _ = s.is_terminator();
        let _ = s.contains_return();
    }
}

#[test]
fn fuzz_function_print_never_panics() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for i in 0..50 {
        let mut f = HlilFunction::new(Address::from(lcg.next()), format!("fn{i}"));
        f.prototype.return_type = if lcg.next() & 1 == 0 { HlilType::Void } else { HlilType::i32() };
        if lcg.next() & 1 == 0 {
            f.prototype.params.push(HlilVar::param("a", HlilType::i32()));
        }
        f.body.push(HlilStatement::Return(vec![]));
        let s = f.print();
        assert!(!s.is_empty());
        let d = f.to_string();
        assert_eq!(s, d);
    }
}

// ── Send/Sync threaded ───────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HlilType>();
    assert_send_sync::<HlilVar>();
    assert_send_sync::<HlilExpr>();
    assert_send_sync::<HlilStatement>();
    assert_send_sync::<HlilFunction>();
    assert_send_sync::<HlilPrototype>();
    assert_send_sync::<CCodePrinter>();
}

#[test]
fn threaded_stress_display() {
    use std::sync::Arc;
    use std::thread;

    let e = Arc::new(HlilExpr::Add(
        Box::new(HlilExpr::Mul(Box::new(cst32(2)), Box::new(vexpr("x")), HlilType::i32())),
        Box::new(cst32(5)),
        HlilType::i32(),
    ));
    let mut handles = vec![];
    for _ in 0..4 {
        let e = Arc::clone(&e);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let s = e.to_string();
                assert_eq!(s, "((2 * x) + 5)");
                let _ = e.complexity();
                let _ = e.expr_type();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn threaded_stress_function_print() {
    use std::sync::Arc;
    use std::thread;

    let mut f = HlilFunction::new(Address::from(0x100u64), "tfn");
    f.prototype.return_type = HlilType::i32();
    f.body.push(HlilStatement::Return(vec![cst32(0)]));
    let f = Arc::new(f);
    let mut handles = vec![];
    for _ in 0..4 {
        let f = Arc::clone(&f);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let s = f.print();
                assert!(s.contains("tfn"));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── Boundary integer behaviour ───────────────────────────────────────────────

#[test]
fn const_extreme_values_round_trip() {
    for &v in &[0i64, 1, -1, i64::MAX, i64::MIN, i64::MAX - 1, i64::MIN + 1] {
        let e = cst32(v);
        assert_eq!(e.is_const(), Some(v));
        assert_eq!(e.is_const_zero(), v == 0);
    }
}

#[test]
fn type_array_count_boundary_one() {
    let a = HlilType::Array { elem: Box::new(HlilType::u8()), count: Some(1) };
    assert_eq!(a.byte_size(), Some(1));
}
