//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Each test here was written BEFORE its fix and confirmed to fail against the
//! then-current code. That ordering matters: an audit finding is only worth
//! acting on once a test reproduces it, and a test written after the fix
//! proves nothing about what the fix changed.

use rustre_analysis_dataflow::available_expressions::{
    compute_available, find_cse_opportunities, AvailBlock, AvailStmt, AvailableExpressions,
    BinOpKind, ExpressionUniverse, VarId,
};

fn make_blocks(
    layout: Vec<(usize, Vec<AvailStmt>, Vec<usize>)>,
) -> (Vec<AvailBlock>, Vec<Vec<usize>>) {
    let n = layout.len();
    let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
    let blocks: Vec<AvailBlock> = layout
        .into_iter()
        .map(|(id, stmts, succs)| {
            for &s in &succs {
                if s < n {
                    preds[s].push(id);
                }
            }
            AvailBlock { id, stmts, succs }
        })
        .collect();
    (blocks, preds)
}

/// A recomputation is only redundant if the expression is still available AT
/// THAT STATEMENT. Testing every statement against the block's ENTRY set
/// ignores kills performed earlier in the same block, so a recomputation whose
/// operands were just redefined is reported as redundant — and eliminating it
/// would substitute the pre-redefinition value.
#[test]
fn in_block_redefinition_kills_the_cse_candidate() {
    let mut u = ExpressionUniverse::new();
    let v0 = VarId::new(0);
    let v1 = VarId::new(1);
    let e0 = u.bin_op(BinOpKind::Add, v0, v1);
    let analysis = AvailableExpressions::new(u.into_exprs());

    let (blocks, preds) = make_blocks(vec![
        // block 0: v2 = v0 + v1   → e0 available on exit
        (
            0,
            vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])],
            vec![1],
        ),
        // block 1: v0 = <opaque>  → kills e0
        //          v3 = v0 + v1   → NOT redundant, v0 changed
        (
            1,
            vec![
                AvailStmt::define(v0),
                AvailStmt::assign(VarId::new(3), e0, vec![v0, v1]),
            ],
            vec![],
        ),
    ]);

    let result = compute_available(&blocks, 0, &preds, &analysis);
    // e0 really is available on ENTRY to block 1 — that part is correct.
    assert!(result.avail_in(1).unwrap().contains(e0));

    let opps = find_cse_opportunities(&analysis, &blocks, &result);
    assert!(
        !opps.iter().any(|o| o.block_id == 1),
        "v0 was redefined earlier in block 1, so `v0 + v1` is not available \
         there; reporting it as redundant would substitute a stale value. \
         Got: {opps:?}"
    );
}

/// The genuine case must keep working: no intervening kill, so the second
/// computation really is redundant.
#[test]
fn a_real_redundant_recomputation_is_still_reported() {
    let mut u = ExpressionUniverse::new();
    let v0 = VarId::new(0);
    let v1 = VarId::new(1);
    let e0 = u.bin_op(BinOpKind::Add, v0, v1);
    let analysis = AvailableExpressions::new(u.into_exprs());

    let (blocks, preds) = make_blocks(vec![
        (
            0,
            vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])],
            vec![1],
        ),
        (
            1,
            vec![AvailStmt::assign(VarId::new(3), e0, vec![v0, v1])],
            vec![],
        ),
    ]);

    let result = compute_available(&blocks, 0, &preds, &analysis);
    let opps = find_cse_opportunities(&analysis, &blocks, &result);
    assert!(
        opps.iter().any(|o| o.block_id == 1 && o.expr_id == e0),
        "expected the redundant recomputation in block 1 to be reported"
    );
}

/// Two computations of the same expression in one block, with a redefinition
/// between them: the first is redundant, the second is not.
#[test]
fn kills_apply_at_the_right_statement_index() {
    let mut u = ExpressionUniverse::new();
    let v0 = VarId::new(0);
    let v1 = VarId::new(1);
    let e0 = u.bin_op(BinOpKind::Add, v0, v1);
    let analysis = AvailableExpressions::new(u.into_exprs());

    let (blocks, preds) = make_blocks(vec![
        (
            0,
            vec![AvailStmt::assign(VarId::new(2), e0, vec![v0, v1])],
            vec![1],
        ),
        (
            1,
            vec![
                // stmt 0: still available → redundant
                AvailStmt::assign(VarId::new(3), e0, vec![v0, v1]),
                // stmt 1: kills e0
                AvailStmt::define(v1),
                // stmt 2: recomputed after the kill → NOT redundant
                AvailStmt::assign(VarId::new(4), e0, vec![v0, v1]),
            ],
            vec![],
        ),
    ]);

    let result = compute_available(&blocks, 0, &preds, &analysis);
    let opps = find_cse_opportunities(&analysis, &blocks, &result);
    let idx: Vec<usize> = opps
        .iter()
        .filter(|o| o.block_id == 1)
        .map(|o| o.stmt_index)
        .collect();
    assert_eq!(
        idx,
        vec![0],
        "only statement 0 is redundant; statement 2 follows a kill of v1"
    );
}

// ── ValueRange lattice ─────────────────────────────────────────────────────

use rustre_analysis_dataflow::value_range::ValueRange;

/// Bottom is the identity of join. The sentinel encoding of bottom is the
/// empty interval [1, 0]; taking componentwise min/max against it fabricates
/// a range of values that were never possible.
#[test]
fn joining_with_bottom_is_the_identity() {
    let bot = ValueRange::bottom();
    assert!(bot.is_bottom());

    for other in [
        ValueRange::constant(5),
        ValueRange::interval(-3, 9),
        ValueRange::constant(0),
    ] {
        let j = bot.join(&other);
        assert_eq!(
            (j.min, j.max),
            (other.min, other.max),
            "⊥ ∨ {:?}..{:?} must be the other operand, got {:?}..{:?}",
            other.min,
            other.max,
            j.min,
            j.max
        );

        let j2 = other.join(&bot);
        assert_eq!(
            (j2.min, j2.max),
            (other.min, other.max),
            "join must be commutative with respect to ⊥"
        );
    }
}

/// A range narrowed to nothing is bottom, and joining it back must not
/// resurrect values.
#[test]
fn an_empty_narrowing_stays_empty_under_join() {
    let empty = ValueRange::interval(0, 10).restrict_lower(20);
    assert!(empty.is_bottom(), "restricting [0,10] to >= 20 yields ⊥");

    let j = empty.join(&ValueRange::constant(5));
    assert!(
        !j.is_bottom(),
        "⊥ ∨ {{5}} is {{5}}, which is not bottom"
    );
    assert_eq!(j.constant_value(), Some(5), "⊥ ∨ {{5}} must be exactly {{5}}");
}

#[test]
fn joining_bottom_with_bottom_is_bottom() {
    let j = ValueRange::bottom().join(&ValueRange::bottom());
    assert!(j.is_bottom());
}

/// The dual property: bottom ABSORBS under meet. This one already held — the
/// sentinel `[1, 0]` happens to survive max-of-lowers / min-of-uppers — but it
/// held by accident, so pin it down before someone changes the encoding.
#[test]
fn meeting_with_bottom_stays_bottom() {
    let bot = ValueRange::bottom();
    for other in [
        ValueRange::constant(5),
        ValueRange::interval(-3, 9),
        ValueRange::interval(-9, -4),
        ValueRange::top(),
    ] {
        assert!(bot.meet(&other).is_bottom(), "⊥ ∧ x must be ⊥");
        assert!(other.meet(&bot).is_bottom(), "x ∧ ⊥ must be ⊥");
    }
}

// ── compute_live_intervals: time numbering ─────────────────────────────────

use rustre_analysis_dataflow::live_ranges::{compute_live_intervals, compute_live_ranges};
use rustre_analysis_dataflow::cfg_dom::{BBId, Cfg};
use rustre_analysis_dataflow::ssa::{Instruction, SsaFunction, SsaVar, Var};

fn v(n: &str) -> Var {
    Var::new(n)
}
fn sv(n: &str, ver: u32) -> SsaVar {
    SsaVar {
        base: Var::new(n),
        version: ver,
    }
}

/// Block 0 defines t, x, u; block 1 uses t. `t` is therefore live across the
/// whole of block 0 and genuinely interferes with `u`.
///
/// With two slots reserved per block but instruction slots numbered
/// `bb*2 + 1 + ii`, block 0's own exit slot lands BEFORE its later
/// instructions and its instruction slots spill into block 1's slots. The
/// numbering stops being injective and the interference is missed — the
/// unsound direction: a register allocator would let `u` clobber `t`.
#[test]
fn a_value_live_across_a_block_interferes_with_later_defs_in_it() {
    let cfg = Cfg::new(2, vec![vec![BBId(1)], vec![]], BBId(0), BBId(1));

    let mut i0 = Instruction::new(0, Some(v("t")), vec![]);
    i0.ssa_def = Some(sv("t", 0));
    let mut i1 = Instruction::new(1, Some(v("x")), vec![]);
    i1.ssa_def = Some(sv("x", 0));
    let mut i2 = Instruction::new(2, Some(v("u")), vec![]);
    i2.ssa_def = Some(sv("u", 0));

    let mut i3 = Instruction::new(3, None, vec![v("t")]);
    i3.ssa_uses = vec![sv("t", 0)];

    let func = SsaFunction::new(cfg, &vec![vec![i0, i1, i2], vec![i3]]);
    let lr = compute_live_ranges(&func);
    let intervals = compute_live_intervals(&func, &lr);

    let get = |name: &str| {
        intervals
            .iter()
            .find(|i| i.var.0 == name)
            .unwrap_or_else(|| panic!("no interval for {name}"))
    };
    let t = get("t");
    let u = get("u");

    assert!(
        t.overlaps(u),
        "t is defined before u and is still live at the end of the block \
         (it is used in block 1), so the two interfere and must not share a \
         register. t = [{}, {}], u = [{}, {}]",
        t.start,
        t.end,
        u.start,
        u.end
    );
}

/// The time numbering must be injective: no two distinct program points may
/// receive the same slot, or unrelated variables collide.
#[test]
fn block_slot_ranges_do_not_collide() {
    // Three blocks, each with several instructions — enough that a two-slots-
    // per-block scheme must overrun into its neighbours.
    let cfg = Cfg::new(
        3,
        vec![vec![BBId(1)], vec![BBId(2)], vec![]],
        BBId(0),
        BBId(2),
    );

    let mut id = 0usize;
    let mut mk = |name: &str| {
        let mut i = Instruction::new(id, Some(v(name)), vec![]);
        i.ssa_def = Some(sv(name, 0));
        id += 1;
        i
    };
    let b0 = vec![mk("a"), mk("b"), mk("c")];
    let b1 = vec![mk("d"), mk("e"), mk("f")];
    let b2 = vec![mk("g")];

    let func = SsaFunction::new(cfg, &vec![b0, b1, b2]);
    let lr = compute_live_ranges(&func);
    let intervals = compute_live_intervals(&func, &lr);

    // Every one of these variables is defined and dead immediately (nothing
    // uses them), so no two may be reported as overlapping.
    for a in &intervals {
        for b in &intervals {
            if a.var == b.var {
                continue;
            }
            assert!(
                !a.overlaps(b),
                "{:?} [{}, {}] and {:?} [{}, {}] are dead-on-definition in \
                 different places and must not overlap",
                a.var,
                a.start,
                a.end,
                b.var,
                b.start,
                b.end
            );
        }
    }
}
