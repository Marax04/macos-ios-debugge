//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_diff_semantic::behavior_diff::{ApiCall, BehaviorSignature, ExternalInteraction};
use rustre_diff_semantic::control_flow_diff::{
    AlignmentStrategy, BasicBlock, ControlFlowGraph, Terminator,
};
use rustre_diff_semantic::similarity::FeatureExtractor;
use rustre_diff_semantic::variable_diff::{VarChange, VarDescriptor, VarType, VariableDiffer};

// ── variable_diff: rename detection could never fire ───────────────────────

/// `find_rename_candidate`'s third parameter is named `map_a` and is used to
/// skip candidates that were ALREADY matched by name. The caller passes
/// `&map_b` — which contains *every* variable of B — so the loop `continue`s
/// on every candidate and returns `None` for any input at all.
///
/// Every renamed variable was therefore reported as a Removed + Added pair,
/// which is exactly the signal an analyst uses to tell a refactor from a
/// behavioural change.
#[test]
fn a_renamed_variable_is_detected_as_a_rename() {
    let a = [VarDescriptor::new("counter", VarType::Int32)];
    let b = [VarDescriptor::new("counter_x", VarType::Int32)];

    let d = VariableDiffer::new().diff(0x1000, 0x2000, &a, &b);

    let renames: Vec<&VarChange> = d
        .changes
        .iter()
        .filter(|c| matches!(c, VarChange::Renamed { .. }))
        .collect();
    assert_eq!(
        renames.len(),
        1,
        "name_similarity(\"counter\", \"counter_x\") is 0.75 > 0.5, so this is a \
         rename; got {:?}",
        d.changes
    );
}

/// A variable that really disappeared must still be Removed — the fix must not
/// turn every removal into a spurious rename.
#[test]
fn an_unrelated_removal_is_still_a_removal() {
    let a = [VarDescriptor::new("counter", VarType::Int32)];
    let b = [VarDescriptor::new("zzz_unrelated_name", VarType::Int32)];

    let d = VariableDiffer::new().diff(0x1000, 0x2000, &a, &b);
    assert!(
        d.changes
            .iter()
            .any(|c| matches!(c, VarChange::Removed(_))),
        "dissimilar names are not a rename: {:?}",
        d.changes
    );
}

/// A variable present under the same name in both sides must never be consumed
/// as a rename target for some other variable.
#[test]
fn a_surviving_variable_is_not_stolen_as_a_rename_target() {
    let a = [
        VarDescriptor::new("counter", VarType::Int32),
        VarDescriptor::new("counter_x", VarType::Int32),
    ];
    let b = [VarDescriptor::new("counter_x", VarType::Int32)];

    let d = VariableDiffer::new().diff(0x1000, 0x2000, &a, &b);
    assert!(
        !d.changes
            .iter()
            .any(|c| matches!(c, VarChange::Renamed { new_name, .. } if new_name == "counter_x")),
        "counter_x exists in BOTH sides; it cannot also be the target of a \
         rename from counter: {:?}",
        d.changes
    );
}

// ── control_flow_diff: compute_dominators hung forever ─────────────────────

/// `intersect` implements Cooper's algorithm, which walks up the dominator
/// tree comparing REVERSE-POSTORDER numbers. This one compares raw addresses,
/// and `idom[entry] == entry` makes the entry a fixed point: as soon as a join
/// block has a predecessor at a LOWER address than the entry — a cold block
/// placed before the function start, entirely ordinary in real binaries — the
/// `while b1 > b2` loop can never terminate.
///
/// A hang is the one failure mode a caller cannot recover from.
#[test]
fn dominators_terminate_when_a_block_lies_below_the_entry() {
    let cfg = ControlFlowGraph::from_blocks(
        0x2000,
        vec![
            BasicBlock::new(
                0x2000,
                8,
                2,
                Terminator::Branch {
                    true_target: 0x1000,
                    false_target: 0x3000,
                },
            ),
            BasicBlock::new(0x1000, 8, 2, Terminator::Jump(0x3000)),
            BasicBlock::new(0x3000, 4, 1, Terminator::Return),
        ],
    );

    let idom = cfg.compute_dominators();
    assert_eq!(idom.get(&0x2000), Some(&0x2000));
    assert_eq!(idom.get(&0x1000), Some(&0x2000));
    assert_eq!(
        idom.get(&0x3000),
        Some(&0x2000),
        "0x3000 is reached from both 0x2000 and 0x1000, so its immediate \
         dominator is the entry"
    );
}

/// The ordinary diamond must still be dominated correctly.
#[test]
fn dominators_are_correct_for_a_plain_diamond() {
    let cfg = ControlFlowGraph::from_blocks(
        0x1000,
        vec![
            BasicBlock::new(
                0x1000,
                8,
                2,
                Terminator::Branch {
                    true_target: 0x1010,
                    false_target: 0x1020,
                },
            ),
            BasicBlock::new(0x1010, 8, 2, Terminator::Jump(0x1030)),
            BasicBlock::new(0x1020, 8, 2, Terminator::Jump(0x1030)),
            BasicBlock::new(0x1030, 4, 1, Terminator::Return),
        ],
    );

    let idom = cfg.compute_dominators();
    assert_eq!(idom.get(&0x1010), Some(&0x1000));
    assert_eq!(idom.get(&0x1020), Some(&0x1000));
    assert_eq!(idom.get(&0x1030), Some(&0x1000));
}

/// A loop must not hang either, and the back edge must be found.
#[test]
fn dominators_terminate_on_a_loop() {
    let cfg = ControlFlowGraph::from_blocks(
        0x1000,
        vec![
            BasicBlock::new(0x1000, 8, 2, Terminator::Jump(0x1010)),
            BasicBlock::new(
                0x1010,
                8,
                2,
                Terminator::Branch {
                    true_target: 0x1010,
                    false_target: 0x1020,
                },
            ),
            BasicBlock::new(0x1020, 4, 1, Terminator::Return),
        ],
    );

    let idom = cfg.compute_dominators();
    assert_eq!(idom.get(&0x1010), Some(&0x1000));
    assert!(cfg.back_edges().contains(&(0x1010, 0x1010)));
}

// ── AlignmentStrategy::RelativeOffset: unsigned underflow ──────────────────────

/// The offset is computed with `saturating_sub`, so every block placed BELOW
/// the function entry — cold/outlined code, which compilers emit routinely —
/// clamps to offset 0 and translates to the new entry block. The block is then
/// reported as an unchanged match against unrelated code, and no Removed
/// record is emitted for it.
#[test]
fn a_block_below_the_entry_does_not_alias_the_entry() {
    let s = AlignmentStrategy::RelativeOffset;
    let below = s.translate(0x1F00, 0x2000, 0x3000);
    let entry = s.translate(0x2000, 0x2000, 0x3000);

    assert_ne!(
        below, entry,
        "0x1F00 is 0x100 BELOW the entry; clamping it onto the new entry makes \
         two distinct blocks indistinguishable"
    );
    assert_eq!(below, 0x2F00, "the offset is signed: 0x3000 - 0x100");
}

/// Ordinary forward offsets must be unaffected.
#[test]
fn offsets_above_the_entry_translate_as_before() {
    let s = AlignmentStrategy::RelativeOffset;
    assert_eq!(s.translate(0x2010, 0x2000, 0x3000), 0x3010);
    assert_eq!(s.translate(0x2000, 0x2000, 0x3000), 0x3000);
}

// ── behavior_diff: two different behaviours scored identical ───────────────

/// `similarity` computes Jaccard over `api_calls` ONLY, ignoring
/// `interaction_classes` — even though the hash covers both. Two functions
/// that call the same API but one talks to the NETWORK while the other touches
/// the FILE system score a flat 1.0: identical, by a metric whose whole job is
/// telling behaviours apart.
#[test]
fn differing_interaction_classes_are_not_perfectly_similar() {
    let a = BehaviorSignature::compute(
        "f",
        &[ApiCall::new("send")],
        &[ExternalInteraction::Hardware("gpu".to_string())],
    );
    let b = BehaviorSignature::compute(
        "g",
        &[ApiCall::new("send")],
        &[ExternalInteraction::Ui("log".to_string())],
    );

    assert_ne!(a.hash, b.hash, "the hashes already distinguish these two");
    assert!(
        a.similarity(&b) < 1.0,
        "same API but different external interaction is not identical behaviour \
         (got {})",
        a.similarity(&b)
    );
}

/// Genuinely identical behaviour must still score 1.0.
#[test]
fn identical_behaviour_is_still_perfectly_similar() {
    let a = BehaviorSignature::compute(
        "f",
        &[ApiCall::new("send")],
        &[ExternalInteraction::Hardware("gpu".to_string())],
    );
    let b = BehaviorSignature::compute(
        "g",
        &[ApiCall::new("send")],
        &[ExternalInteraction::Hardware("gpu".to_string())],
    );
    assert!((a.similarity(&b) - 1.0).abs() < 1e-9);
}

// ── similarity: approx_loops depended on instruction ORDER ─────────────────

/// The branch count is taken from `windows(3)` looking only at `w[2]`, so a
/// branch in the first two positions is invisible: `["jne","ret"]` scores 0 and
/// `["jne","mov","mov"]` scores 0, while the same instructions reordered to
/// `["mov","mov","jne"]` score 1. A feature used for similarity matching must
/// depend on the code, not on where in the buffer it happens to sit.
#[test]
fn the_branch_feature_does_not_depend_on_position() {
    let front = FeatureExtractor::extract("f", 0, &["jne", "mov", "mov"], &[], &[]);
    let back = FeatureExtractor::extract("f", 0, &["mov", "mov", "jne"], &[], &[]);

    assert_eq!(
        front.get_int("approx_loops"),
        back.get_int("approx_loops"),
        "the same instruction multiset scored differently depending on order"
    );
    assert_eq!(front.get_int("approx_loops"), 1);
}

/// A function too short for a 3-wide window still has its branch counted.
#[test]
fn a_short_function_still_reports_its_branch() {
    let fv = FeatureExtractor::extract("f", 0, &["jne", "ret"], &[], &[]);
    assert_eq!(
        fv.get_int("approx_loops"),
        1,
        "a two-instruction function with a branch reported none"
    );
}

/// Branch-free code must still score zero.
#[test]
fn branch_free_code_reports_no_branches() {
    let fv = FeatureExtractor::extract("f", 0, &["mov", "add", "ret"], &[], &[]);
    assert_eq!(fv.get_int("approx_loops"), 0);
}
