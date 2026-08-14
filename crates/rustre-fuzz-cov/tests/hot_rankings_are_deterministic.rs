//! "Hot" rankings are read by a human deciding where to look next, so they have
//! to be reproducible.
//!
//! Both `FunctionCoverage::hot_functions` and `QemuCovCollector::hot_tbs` rank
//! entries held in a `HashMap` — whose iteration order Rust randomises per
//! process — and both used a sort keyed on the hit count alone. `sort_by` is
//! stable, so equally-hot entries came out in hash order.
//!
//! For `hot_tbs` it is worse than presentation: it ends in `take(n)`, so ties
//! straddling the cutoff changed *which* translation blocks were reported at
//! all. Two runs over the same trace disagreed about the hottest code, and
//! neither could be reproduced.

use rustre_fuzz_cov::coverage_statistics::FunctionCoverage;
use rustre_fuzz_cov::qemu_tcg_cov::QemuCovCollector;

/// Addresses deliberately inserted out of order, all with the *same* count, so
/// the tie-break is the only thing deciding the answer.
const TIED: [u64; 8] = [0x5000, 0x1000, 0x8000, 0x3000, 0x7000, 0x2000, 0x6000, 0x4000];

fn coverage_from(order: &[u64]) -> FunctionCoverage {
    let mut fc = FunctionCoverage::new();
    for &addr in order {
        fc.record_calls(addr, 10);
    }
    fc
}

#[test]
fn hot_functions_does_not_depend_on_insertion_order() {
    let forward = coverage_from(&TIED);
    let mut rev = TIED;
    rev.reverse();
    let backward = coverage_from(&rev);

    let a = forward.hot_functions(1);
    let b = backward.hot_functions(1);

    assert_eq!(a.len(), 8, "premise: every tied function clears the threshold");
    assert_eq!(
        a, b,
        "reversing the insertion order changed the hot-function ranking"
    );

    // Equal counts, so the order is decided by the address: ascending.
    let addrs: Vec<u64> = a.iter().map(|&(addr, _)| addr).collect();
    let mut sorted = addrs.clone();
    sorted.sort_unstable();
    assert_eq!(addrs, sorted, "ties must resolve to ascending address");
}

#[test]
fn hot_functions_still_ranks_by_count_first() {
    // Premise: the tie-break has not replaced the ranking. The hotter function
    // sits at the highest address, so an address-only order would rank it last.
    let mut fc = coverage_from(&TIED);
    fc.record_calls(0x9000, 500);

    let top = fc.hot_functions(1);
    assert_eq!(
        top[0],
        (0x9000, 500),
        "the hottest function must rank first regardless of its address"
    );
}

fn collector_from(order: &[u64]) -> QemuCovCollector {
    let mut c = QemuCovCollector::new();
    for &pc in order {
        // One execution each: every record ties with every other.
        c.record_tb(pc, 16);
    }
    c
}

#[test]
fn hot_tbs_membership_does_not_depend_on_insertion_order() {
    // The decisive consequence: with a cutoff, ties decide *membership*, not
    // just order. The same trace must always report the same hottest blocks.
    let mut rev = TIED;
    rev.reverse();
    let mut shuffled = TIED;
    shuffled.swap(0, 7);
    shuffled.swap(2, 5);

    let a: Vec<u64> = collector_from(&TIED).hot_tbs(4).iter().map(|r| r.pc).collect();
    let b: Vec<u64> = collector_from(&rev).hot_tbs(4).iter().map(|r| r.pc).collect();
    let c: Vec<u64> = collector_from(&shuffled).hot_tbs(4).iter().map(|r| r.pc).collect();

    assert_eq!(a.len(), 4, "premise: there are more blocks than the cutoff");
    assert_eq!(a, b, "reversing the insertion order changed the top-N blocks");
    assert_eq!(a, c, "shuffling the insertion order changed the top-N blocks");

    // All counts equal, so the four lowest PCs win.
    assert_eq!(a, vec![0x1000, 0x2000, 0x3000, 0x4000]);
}

#[test]
fn hot_tbs_still_ranks_by_count_first() {
    // Premise: a genuinely hotter block wins even though its PC is the highest.
    let mut c = collector_from(&TIED);
    for _ in 0..50 {
        c.record_tb(0x9000, 16);
    }

    let top = c.hot_tbs(2);
    assert_eq!(
        top[0].pc, 0x9000,
        "the most-executed block must rank first regardless of its address"
    );
    assert!(top[0].count > top[1].count);
}
