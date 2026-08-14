//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.
//!
//! Two of the three produce numbers that are impossible on their face — 125%
//! coverage, "100%" for one block out of three. A metric that can exceed its
//! own ceiling is not measuring what it claims to.

use rustre_trace_coverage::coverage_bitmap_ext::CoverageBitmap;
use rustre_trace_coverage::function_coverage::{CoverageRun, FunctionStats};

// ── covered_bbs counted EXECUTIONS, not distinct blocks ───────────────────

/// `record_bb_execution` throws the block address away (`let _ = bb_addr;`) and
/// increments `covered_bbs` on every call. A loop header entered four times
/// therefore reports four covered blocks out of four — full coverage of a
/// function whose other three blocks were never reached.
#[test]
fn revisiting_one_block_does_not_cover_the_function() {
    let mut run = CoverageRun::new("r");
    run.register_function(FunctionStats::new("f", 0x1000, "m").with_total_bbs(4));

    for _ in 0..4 {
        run.record_bb_execution(0x1000, 0x1000);
    }

    let f = run.functions.get(&0x1000).expect("registered");
    assert_eq!(
        f.covered_bbs, 1,
        "one distinct block was reached, not four"
    );
    assert!(
        (f.bb_coverage_pct() - 25.0).abs() < 1e-9,
        "1 of 4 blocks is 25%, got {}",
        f.bb_coverage_pct()
    );
    assert!(!f.is_fully_covered());
}

/// With more hits than blocks the number leaves the range entirely.
#[test]
fn coverage_can_never_exceed_one_hundred_percent() {
    let mut run = CoverageRun::new("r");
    run.register_function(FunctionStats::new("f", 0x1000, "m").with_total_bbs(4));
    for _ in 0..5 {
        run.record_bb_execution(0x1000, 0x1000);
    }
    let pct = run.functions.get(&0x1000).unwrap().bb_coverage_pct();
    assert!(
        pct <= 100.0,
        "reported {pct}% coverage — a percentage above 100 is not a measurement"
    );
}

/// Distinct blocks must still accumulate.
#[test]
fn distinct_blocks_are_counted_once_each() {
    let mut run = CoverageRun::new("r");
    run.register_function(FunctionStats::new("f", 0x1000, "m").with_total_bbs(4));
    run.record_bb_execution(0x1000, 0x1000);
    run.record_bb_execution(0x1000, 0x1010);
    run.record_bb_execution(0x1000, 0x1010); // revisit
    run.record_bb_execution(0x1000, 0x1020);

    let f = run.functions.get(&0x1000).unwrap();
    assert_eq!(f.covered_bbs, 3);
    assert!(f.was_executed);
}

// ── the edge hash was symmetric ───────────────────────────────────────────

/// `EdgeId::from_pcs` indexes with `prev_pc ^ cur_pc`. XOR is symmetric, so a
/// call `A -> B` and its return `B -> A` — two different edges, and precisely
/// the pair a coverage map exists to tell apart — land in the same slot.
///
/// AFL's formula is `(prev >> 1) ^ cur` for exactly this reason.
///
/// The map is sized 65536 (AFL's default): with only 1024 slots these two
/// hashes would still collide by modulo, which is an ordinary property of a
/// small hash table and not the defect under test.
#[test]
fn a_call_and_its_return_are_two_distinct_edges() {
    let mut bm = CoverageBitmap::new(65536);
    bm.record_edge(0x1000, 0x2000);
    bm.record_edge(0x2000, 0x1000);

    assert_eq!(
        bm.popcount(),
        2,
        "A->B and B->A collided into a single bitmap slot"
    );
}

/// Every self-edge hashed to 0, so all of them were indistinguishable from one
/// another — and from any other pair with equal PCs.
#[test]
fn distinct_self_edges_do_not_share_a_slot() {
    let mut bm = CoverageBitmap::new(65536);
    bm.record_edge(0x1000, 0x1000);
    bm.record_edge(0x9999, 0x9999);

    assert_eq!(
        bm.popcount(),
        2,
        "every self-edge hashed to index 0, so a tight loop anywhere in the \
         program looked like the same edge"
    );
}

/// The same edge recorded twice must still occupy one slot.
#[test]
fn the_same_edge_twice_is_one_slot() {
    let mut bm = CoverageBitmap::new(65536);
    bm.record_edge(0x1000, 0x2000);
    bm.record_edge(0x1000, 0x2000);
    assert_eq!(bm.popcount(), 1);
}
