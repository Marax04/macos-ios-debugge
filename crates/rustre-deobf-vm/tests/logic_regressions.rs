//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_deobf_vm::{BytecodeCandidate, VmSemanticOp};

// ── Shannon entropy above its own ceiling ─────────────────────────────────

/// `compute_entropy_f32` normalises with
/// `u16::try_from(data.len()).unwrap_or(u16::MAX)`. For any input longer than
/// 65535 bytes the conversion fails and `n` silently becomes 65535, while the
/// per-symbol counts are clamped the same way — so the probabilities no longer
/// sum to 1 and the result leaves the range entirely.
///
/// Shannon entropy over a byte alphabet cannot exceed 8 bits per byte. A
/// function that returns 19.5 is not mismeasuring, it is reporting something
/// that cannot exist.
///
/// Two CORRECT copies of this same computation already live in this crate
/// (`lib.rs` `compute_entropy` and `isa_reconstruction.rs` `compute_entropy`),
/// both normalising with `u32`.
#[test]
fn entropy_never_exceeds_eight_bits_per_byte() {
    // 200 000 bytes, every value appearing ~781 times: maximal real entropy.
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    let c = BytecodeCandidate::new(&data, 0);

    assert!(
        c.entropy <= 8.0,
        "entropy of a byte stream cannot exceed 8 bits/byte, got {}",
        c.entropy
    );
    assert!(
        (c.entropy - 8.0).abs() < 0.01,
        "a uniform byte distribution has entropy 8.0, got {}",
        c.entropy
    );
}

/// Short inputs were already handled correctly and must stay that way.
#[test]
fn entropy_of_a_short_uniform_block_is_still_right() {
    let data: Vec<u8> = (0..=255u8).collect();
    let c = BytecodeCandidate::new(&data, 0);
    assert!(
        (c.entropy - 8.0).abs() < 0.01,
        "256 distinct bytes is exactly 8 bits/byte, got {}",
        c.entropy
    );
}

/// A single repeated byte carries no information at all.
#[test]
fn entropy_of_a_constant_block_is_zero() {
    let data = vec![0x41u8; 100_000];
    let c = BytecodeCandidate::new(&data, 0);
    assert!(
        c.entropy.abs() < 1e-6,
        "one repeated symbol has zero entropy, got {}",
        c.entropy
    );
}

// ── a load does not shrink the stack ──────────────────────────────────────

/// `Load32` pops an ADDRESS and pushes the VALUE it read: net stack effect 0.
/// It was grouped with the binary operators, which pop two and push one, so it
/// was credited with -1.
///
/// `VmLifter::simulate` — the twin that actually runs the ops — leaves exactly
/// one value on the stack for `[PushImm, Load32]`, so the two disagree about
/// the same program. Any stack-depth reconstruction under-counts by one per
/// load.
#[test]
fn a_load_leaves_the_stack_depth_unchanged() {
    assert_eq!(
        VmSemanticOp::Load32.stack_delta(),
        0,
        "Load32 consumes the address and leaves the loaded word"
    );
}

/// The sequence the audit names must net out to one value on the stack.
#[test]
fn push_then_load_leaves_one_value() {
    let ops = [VmSemanticOp::PushImm(0x1000), VmSemanticOp::Load32];
    let net: i32 = ops.iter().map(VmSemanticOp::stack_delta).sum();
    assert_eq!(net, 1, "one value remains: the word that was loaded");
}

/// The genuinely binary operators must keep their -1, and a store its -2.
#[test]
fn binary_operators_keep_their_delta() {
    assert_eq!(VmSemanticOp::Add.stack_delta(), -1);
    assert_eq!(VmSemanticOp::Xor.stack_delta(), -1);
    assert_eq!(VmSemanticOp::Store32.stack_delta(), -2);
    assert_eq!(VmSemanticOp::PushImm(0).stack_delta(), 1);
    assert_eq!(VmSemanticOp::Nop.stack_delta(), 0);
}
