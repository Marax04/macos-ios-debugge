//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_fn::heuristics::{
    ClangPgoHeuristic, CompilerHeuristic, GccStackCanaryHeuristic,
};
use rustre_analysis_fn::MemorySlice;
use rustre_core::address::Address;

// ── ClangPgoHeuristic::promote_cluster ─────────────────────────────────────

/// The comment says "Skip past the cluster", but the statement is a `break`,
/// which leaves the whole scan. Every dense cluster after the first was
/// silently dropped.
#[test]
fn every_dense_cluster_is_reported_not_just_the_first() {
    let h = ClangPgoHeuristic {
        cluster_threshold: 5,
        window_bytes: 4096,
    };
    // Two clusters of five, far apart enough not to share a window.
    let candidates: Vec<Address> = [
        0x1000u64, 0x1010, 0x1020, 0x1030, 0x1040, // cluster A
        0x40000, 0x40010, 0x40020, 0x40030, 0x40040, // cluster B
    ]
    .iter()
    .map(|&a| Address::new(a))
    .collect();

    let out = h.promote_cluster(&candidates);
    assert_eq!(
        out.len(),
        10,
        "both clusters must be promoted, got {} results",
        out.len()
    );

    let addrs: Vec<u64> = out.iter().map(|r| r.address.as_u64()).collect();
    assert!(addrs.contains(&0x40000), "second cluster was dropped: {addrs:#x?}");
}

/// A candidate list with no dense cluster must yield nothing — the fix must
/// not simply stop breaking and start promoting everything.
#[test]
fn sparse_candidates_are_not_promoted() {
    let h = ClangPgoHeuristic {
        cluster_threshold: 5,
        window_bytes: 0x100,
    };
    let candidates: Vec<Address> = [0x1000u64, 0x2000, 0x3000, 0x4000, 0x5000]
        .iter()
        .map(|&a| Address::new(a))
        .collect();
    assert!(h.promote_cluster(&candidates).is_empty());
}

/// No address may be promoted twice: skipping past a cluster means exactly
/// that, not re-scanning its tail.
#[test]
fn cluster_members_are_reported_once_each() {
    let h = ClangPgoHeuristic {
        cluster_threshold: 3,
        window_bytes: 0x100,
    };
    let candidates: Vec<Address> = [0x1000u64, 0x1010, 0x1020, 0x1030, 0x1040]
        .iter()
        .map(|&a| Address::new(a))
        .collect();

    let out = h.promote_cluster(&candidates);
    let addrs: Vec<u64> = out.iter().map(|r| r.address.as_u64()).collect();
    let unique: std::collections::HashSet<u64> = addrs.iter().copied().collect();
    assert_eq!(
        addrs.len(),
        unique.len(),
        "duplicate promotions: {addrs:#x?}"
    );
}

// ── GccStackCanaryHeuristic::run ───────────────────────────────────────────

/// The doc says it "walks backwards up to 32 bytes to find the function
/// entry", but the body blindly subtracts 32, so the reported entry is wrong
/// by (32 − real prologue distance) and usually lands inside the PREVIOUS
/// function. The MSVC sibling anchors on the prologue byte instead.
#[test]
fn canary_heuristic_anchors_on_the_prologue_not_a_fixed_offset() {
    let mut code = vec![0x90u8; 0x60]; // nop filler
    code[0x24] = 0x55; // push rbp — the real function entry
    // mov rax, fs:[N] at 0x28
    code[0x28..0x2D].copy_from_slice(&[0x64, 0x48, 0x8B, 0x04, 0x25]);

    let mem = MemorySlice::new(Address::new(0x1000), &code);
    let out = GccStackCanaryHeuristic.run(&mem);

    assert_eq!(out.len(), 1, "one canary load, one candidate");
    assert_eq!(
        out[0].address.as_u64(),
        0x1024,
        "the entry is the `push rbp` at 0x1024, not 0x28 − 32 = 0x1008"
    );
}

/// With the prologue immediately before the canary load, the blind −32 would
/// be even further off; the anchored version must land exactly on it.
#[test]
fn canary_heuristic_finds_an_adjacent_prologue() {
    let mut code = vec![0x90u8; 0x60];
    code[0x30] = 0x55;
    code[0x31..0x36].copy_from_slice(&[0x64, 0x48, 0x8B, 0x04, 0x25]);

    let mem = MemorySlice::new(Address::new(0x2000), &code);
    let out = GccStackCanaryHeuristic.run(&mem);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].address.as_u64(), 0x2030);
}

// ── StackFrame array detection ─────────────────────────────────────────────

use rustre_analysis_fn::stack_frame_analyzer::{CallingConvention, StackFrame};

/// `detect_arrays` walks forward expecting DESCENDING offsets, but the only
/// production caller (`StackFrame::into_analysis`) sorts ASCENDING. The two
/// never agree, so no stack array is ever promoted: `array_count()` is
/// structurally always zero and every slot stays `Scalar`.
#[test]
fn adjacent_equal_sized_slots_become_an_array() {
    // `long buf[3]` at rbp-24: three 8-byte slots at -24, -16, -8.
    let mut f = StackFrame::new(0x1000);
    f.record_access(-24, 8, true);
    f.record_access(-16, 8, true);
    f.record_access(-8, 8, true);

    let analysis = f.into_analysis(10, CallingConvention::SysV64);
    assert_eq!(
        analysis.array_count(),
        3,
        "three adjacent 8-byte slots are one array of 3; locals = {:?}",
        analysis.locals
    );
}

/// Slots of different sizes, or with a gap between them, are NOT an array —
/// the fix must not start promoting everything.
#[test]
fn non_adjacent_or_mixed_slots_stay_scalar() {
    let mut f = StackFrame::new(0x1000);
    f.record_access(-8, 8, true);
    f.record_access(-32, 4, true); // different size, and a gap
    let analysis = f.into_analysis(10, CallingConvention::SysV64);
    assert_eq!(analysis.array_count(), 0);
}

/// A larger array must be recognised whole.
#[test]
fn a_longer_array_is_detected_in_full() {
    let mut f = StackFrame::new(0x1000);
    for k in 1..=6i64 {
        f.record_access(-4 * k, 4, true);
    }
    let analysis = f.into_analysis(10, CallingConvention::SysV64);
    assert_eq!(
        analysis.array_count(),
        6,
        "six adjacent 4-byte slots form one array; locals = {:?}",
        analysis.locals
    );
}

// ── FunctionSplitter::split ────────────────────────────────────────────────

use rustre_analysis_fn::function_splitting::{FunctionSplitter, SplitterConfig};
use rustre_analysis_fn::{Confidence, DetectionSource, FunctionBoundary};

fn fb(start: u64, end: u64) -> FunctionBoundary {
    let mut b = FunctionBoundary::new(
        Address::new(start),
        Confidence::High,
        DetectionSource::CallTarget,
    );
    b.end = Some(Address::new(end));
    b
}

/// The splitter's whole purpose is to return a NON-OVERLAPPING list. When one
/// outer function contains several inner entries, the outer's end was
/// overwritten once per overlap, so the LAST (farthest) inner start won
/// instead of the FIRST (nearest) — and the outer still swallowed the inner
/// functions between them.
#[test]
fn the_outer_function_is_cut_at_the_nearest_inner_entry() {
    // 0x1000..0x1200 with inner entries at 0x1080 and 0x1100.
    let mut code = vec![0x90u8; 0x200];
    code[0x80] = 0xC3; // ret
    code[0x100] = 0xC3; // ret
    code[0x1FF] = 0xC3;
    let mem = MemorySlice::new(Address::new(0x1000), &code);

    let splitter = FunctionSplitter::new(SplitterConfig::default());
    let out = splitter.split(
        vec![fb(0x1000, 0x1200), fb(0x1080, 0x1200), fb(0x1100, 0x1200)],
        &mem,
    );

    let outer = out
        .iter()
        .find(|b| b.start.as_u64() == 0x1000)
        .expect("outer kept");
    assert_eq!(
        outer.end.map(|e| e.as_u64()),
        Some(0x1080),
        "the outer must stop at the NEAREST inner entry (0x1080), not the \
         farthest; got {:?}",
        outer.end.map(|e| e.as_u64())
    );
}

/// The stated contract: the returned list must not overlap.
#[test]
fn the_returned_boundaries_do_not_overlap() {
    let mut code = vec![0x90u8; 0x200];
    code[0x80] = 0xC3;
    code[0x100] = 0xC3;
    code[0x1FF] = 0xC3;
    let mem = MemorySlice::new(Address::new(0x1000), &code);

    let splitter = FunctionSplitter::new(SplitterConfig::default());
    let out = splitter.split(
        vec![fb(0x1000, 0x1200), fb(0x1080, 0x1200), fb(0x1100, 0x1200)],
        &mem,
    );

    for w in out.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        if let Some(end) = a.end {
            assert!(
                end.as_u64() <= b.start.as_u64(),
                "{:#x}..{:#x} overlaps the function starting at {:#x}",
                a.start.as_u64(),
                end.as_u64(),
                b.start.as_u64()
            );
        }
    }
}
