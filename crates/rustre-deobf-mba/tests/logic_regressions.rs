//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.
//!
//! The two defects here are the worst kind an obfuscation pass can have: they
//! do not produce a wrong answer themselves, they DISABLE the check that is
//! supposed to stop everything else from producing one.

use rustre_deobf_mba::deobf_mba_pass::{DeobfMbaPass, IrExpr};
use rustre_deobf_mba::{MbaExpr, TruthTableVerifier};

fn v(name: &str) -> Box<IrExpr> {
    Box::new(IrExpr::Var(name.to_string()))
}

/// `verify_with_z3` is the gate on every accepted rewrite. It samples 64
/// assignments, but the variable index is ADDED to the per-sample seed rather
/// than mixed into it, so the k-th variable is always `first_var + k (mod
/// 256)`: every sample lies on the diagonal `y = x+1, z = x+2, …`.
///
/// Two expressions that merely agree on that one line are declared
/// equivalent — so the "SMT verification" proves nothing at all.
#[test]
fn equivalence_sampling_does_not_lie_on_a_diagonal() {
    let pass = DeobfMbaPass::new();

    // x + y  vs  2x + 1 — equal only when y == x + 1, which is exactly the
    // diagonal the sampler used to walk.
    let original = IrExpr::Add(v("x"), v("y"));
    let simplified = IrExpr::Add(
        Box::new(IrExpr::Add(v("x"), v("x"))),
        Box::new(IrExpr::Const(1)),
    );

    assert!(
        !pass.verify_with_z3(&original, &simplified),
        "x + y is not 2x + 1 (x=0, y=0 gives 0 vs 1); accepting it means the \
         verification gate is inert"
    );
}

/// Genuinely equivalent expressions must still verify — the fix must not turn
/// the gate from always-true into always-false.
#[test]
fn genuinely_equivalent_expressions_still_verify() {
    let pass = DeobfMbaPass::new();

    // x + y == y + x
    assert!(pass.verify_with_z3(
        &IrExpr::Add(v("x"), v("y")),
        &IrExpr::Add(v("y"), v("x"))
    ));

    // x + x == 2 * x
    assert!(pass.verify_with_z3(
        &IrExpr::Add(v("x"), v("x")),
        &IrExpr::Mul(Box::new(IrExpr::Const(2)), v("x"))
    ));

    // (x ^ y) + 2*(x & y) == x + y  — the classic MBA identity.
    let mba = IrExpr::Add(
        Box::new(IrExpr::Xor(v("x"), v("y"))),
        Box::new(IrExpr::Mul(
            Box::new(IrExpr::Const(2)),
            Box::new(IrExpr::And(v("x"), v("y"))),
        )),
    );
    assert!(pass.verify_with_z3(&mba, &IrExpr::Add(v("x"), v("y"))));
}

/// Several pairs that differ only off the diagonal must all be rejected.
#[test]
fn non_equivalent_pairs_are_all_rejected() {
    let pass = DeobfMbaPass::new();
    let cases: Vec<(IrExpr, IrExpr)> = vec![
        (IrExpr::Add(v("x"), v("y")), IrExpr::Add(v("x"), v("x"))),
        (IrExpr::Xor(v("x"), v("y")), IrExpr::Const(1)),
        (IrExpr::Sub(v("y"), v("x")), IrExpr::Const(1)),
        (IrExpr::And(v("x"), v("y")), v("x").as_ref().clone()),
    ];
    for (a, b) in cases {
        assert!(
            !pass.verify_with_z3(&a, &b),
            "{a:?} and {b:?} are not equivalent but were accepted"
        );
    }
}

/// `TruthTableVerifier::verify_equivalent` binds only the first `max_vars`
/// variables; `eval` then fails for the rest, and the failure was mapped to
/// "no counterexample". Any pair with 5+ distinct variables was therefore
/// reported equivalent, whatever it was.
///
/// The sibling `is_always_const` treats the same eval failure AS a
/// counterexample — the sound direction.
#[test]
fn too_many_variables_is_not_a_proof_of_equivalence() {
    let verifier = TruthTableVerifier::new().with_bits(2);

    let sum = ["v0", "v1", "v2", "v3", "v4"]
        .iter()
        .map(|n| MbaExpr::Var((*n).to_string()))
        .reduce(|a, b| MbaExpr::Add(Box::new(a), Box::new(b)))
        .unwrap();

    let result = verifier.verify_equivalent(&sum, &MbaExpr::Const(0));
    assert!(
        !result.equivalent,
        "five distinct variables exceed max_vars, so nothing was proven — \
         reporting `equivalent` is unsound"
    );
}

/// Within the variable budget the verifier must keep working in both
/// directions.
#[test]
fn small_expressions_are_still_verified_normally() {
    let verifier = TruthTableVerifier::new().with_bits(2);

    let x = MbaExpr::Var("x".to_string());
    let y = MbaExpr::Var("y".to_string());

    // x + y == y + x
    let r = verifier.verify_equivalent(
        &MbaExpr::Add(Box::new(x.clone()), Box::new(y.clone())),
        &MbaExpr::Add(Box::new(y.clone()), Box::new(x.clone())),
    );
    assert!(r.equivalent, "commutativity must still verify");

    // x + y != x
    let r = verifier.verify_equivalent(&MbaExpr::Add(Box::new(x.clone()), Box::new(y)), &x);
    assert!(!r.equivalent, "x + y is not x");
    assert!(r.counterexample.is_some(), "a real difference has a witness");
}

// ── translate_mba_to_ir: arithmetic vs logical shift ───────────────────────

use rustre_deobf_mba::deobf_mba_pass::{translate_ir_to_mba, translate_mba_to_ir};

/// `Sar` is an ARITHMETIC (sign-extending) right shift and `Shr` a logical
/// one — `MbaExpr::eval` keeps them distinct (`logical_shr` vs signed `>>`).
/// Translating both to `IrExpr::Shr` silently drops the sign extension, so
/// simplified IR handed back to the caller means something different for
/// negative operands: `-8 >> 1` becomes `0x7FFF_FFFF_FFFF_FFFC` instead of -4.
#[test]
fn arithmetic_and_logical_shifts_do_not_collapse() {
    let x = MbaExpr::Var("x".to_string());
    let sar = MbaExpr::Sar(Box::new(x.clone()), 1);
    let shr = MbaExpr::Shr(Box::new(x), 1);

    assert_ne!(
        translate_mba_to_ir(&sar),
        translate_mba_to_ir(&shr),
        "an arithmetic and a logical right shift are different operations \
         and must not translate to the same IR"
    );
}

/// The round trip must preserve the distinction in both directions.
#[test]
fn the_shift_kind_survives_a_round_trip() {
    let x = MbaExpr::Var("x".to_string());
    for original in [
        MbaExpr::Sar(Box::new(x.clone()), 3),
        MbaExpr::Shr(Box::new(x), 3),
    ] {
        let back = translate_ir_to_mba(&translate_mba_to_ir(&original));
        let same_kind = matches!(
            (&original, &back),
            (MbaExpr::Sar(..), MbaExpr::Sar(..)) | (MbaExpr::Shr(..), MbaExpr::Shr(..))
        );
        assert!(
            same_kind,
            "{original:?} came back as {back:?} — the shift kind was lost"
        );
    }
}

// ── translate_ir_to_mba: opaque nodes must stay distinct ───────────────────

/// `Store`, `Call` and `Phi` were mapped to variable names that ignore their
/// operands — every store became `store_result`, every phi `phi_result`, and a
/// call became `call_{name}` regardless of its arguments. Two DIFFERENT opaque
/// values therefore became the SAME symbolic variable, and the simplifier's
/// `x ^ x -> 0`, `x - x -> 0`, `x & x -> x` rules then "proved" unrelated
/// values equal.
///
/// The neighbouring arms (Div/Mod/Eq/Ne/Lt/Le/Load) all hash their operands
/// via `ir_var_hash` — the mechanism that keeps distinct opaque nodes distinct.
#[test]
fn calls_with_different_arguments_are_different_values() {
    let fx = IrExpr::Call("f".to_string(), vec![IrExpr::Var("x".to_string())]);
    let fy = IrExpr::Call("f".to_string(), vec![IrExpr::Var("y".to_string())]);

    assert_ne!(
        translate_ir_to_mba(&fx),
        translate_ir_to_mba(&fy),
        "f(x) and f(y) are different values and must not share a variable"
    );
}

#[test]
fn distinct_stores_and_phis_are_different_values() {
    let s1 = IrExpr::Store(v("a"), Box::new(IrExpr::Const(1)));
    let s2 = IrExpr::Store(v("b"), Box::new(IrExpr::Const(2)));
    assert_ne!(translate_ir_to_mba(&s1), translate_ir_to_mba(&s2));

    let p1 = IrExpr::Phi(vec![IrExpr::Var("x".to_string())]);
    let p2 = IrExpr::Phi(vec![IrExpr::Var("y".to_string())]);
    assert_ne!(translate_ir_to_mba(&p1), translate_ir_to_mba(&p2));
}

/// The identical opaque node must still map to the identical variable —
/// otherwise a genuine `f(x) ^ f(x)` would stop simplifying to 0.
#[test]
fn identical_opaque_nodes_still_share_a_variable() {
    let a = IrExpr::Call("f".to_string(), vec![IrExpr::Var("x".to_string())]);
    let b = IrExpr::Call("f".to_string(), vec![IrExpr::Var("x".to_string())]);
    assert_eq!(translate_ir_to_mba(&a), translate_ir_to_mba(&b));

    let s = IrExpr::Store(v("a"), Box::new(IrExpr::Const(1)));
    assert_eq!(translate_ir_to_mba(&s), translate_ir_to_mba(&s.clone()));
}

/// End to end: `f(x) ^ f(y)` must NOT be simplified away to zero.
#[test]
fn xor_of_two_different_calls_is_not_zero() {
    let expr = IrExpr::Xor(
        Box::new(IrExpr::Call(
            "f".to_string(),
            vec![IrExpr::Var("x".to_string())],
        )),
        Box::new(IrExpr::Call(
            "f".to_string(),
            vec![IrExpr::Var("y".to_string())],
        )),
    );
    let mba = translate_ir_to_mba(&expr);
    let simplified = rustre_deobf_mba::MbaSimplifier::new().simplify(mba).simplified;
    assert_ne!(
        simplified,
        MbaExpr::Const(0),
        "f(x) ^ f(y) is not zero; simplifying it away means two unrelated \
         values were identified"
    );
}
