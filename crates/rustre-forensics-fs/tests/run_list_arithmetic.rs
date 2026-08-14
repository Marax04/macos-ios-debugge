//! Run-list sizes must survive a hostile image.
//!
//! `parse_data_runs` reads each run's length from the bytes named by the low
//! nibble of the run header — up to fifteen of them — so a length is any `u64`
//! the image cares to state. Multiplying it by a cluster size therefore
//! overflows on crafted input: in release the product wrapped, so a colossal run
//! reported a handful of bytes, and in debug the same multiply panicked. A
//! forensic tool reads exactly this kind of input, so neither is acceptable.

use rustre_forensics_fs::inode::{DataRun, Inode};

const CLUSTER: u64 = 4096;

/// `Inode` has no constructor and every field is public, so build one directly.
fn inode_with(runs: Vec<DataRun>) -> Inode {
    Inode {
        inode_num: 42,
        name: "hostile".into(),
        size: 0,
        alloc_size: 0,
        flags: 0,
        link_count: 1,
        uid: 0,
        gid: 0,
        mode: 0x81A4,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        data_runs: runs,
    }
}

/// A single run whose length cannot be represented in bytes saturates.
#[test]
fn an_absurd_run_length_saturates_instead_of_wrapping() {
    for length in [u64::MAX, u64::MAX / 2, u64::MAX / CLUSTER + 1] {
        let run = DataRun::new(0, length);
        let size = run.byte_size(CLUSTER);
        assert!(
            size >= length,
            "length {length} reported {size} bytes — fewer than the number of \
             clusters, so the multiply wrapped"
        );
    }
    assert_eq!(
        DataRun::new(0, u64::MAX).byte_size(CLUSTER),
        u64::MAX,
        "the largest possible run must report the largest possible size"
    );
}

/// Ordinary runs are unaffected: the fix must not change any real answer.
#[test]
fn ordinary_run_sizes_are_exact() {
    assert_eq!(DataRun::new(0, 0).byte_size(CLUSTER), 0);
    assert_eq!(DataRun::new(0, 1).byte_size(CLUSTER), 4096);
    assert_eq!(DataRun::new(0, 10).byte_size(CLUSTER), 40_960);
    assert_eq!(DataRun::new(0, 1_000_000).byte_size(512), 512_000_000);
    // A cluster size of zero is degenerate but must still be arithmetic, not a
    // special case.
    assert_eq!(DataRun::new(0, 12_345).byte_size(0), 0);
}

/// `byte_size` never decreases as the run grows.
///
/// Monotonicity is the property wrapping violates: it is what makes "bigger run,
/// smaller reported size" impossible, and it holds right across the saturation
/// point where an equality check would have to guess the cut-off.
#[test]
fn reported_size_is_monotonic_in_run_length() {
    let mut previous = 0u64;
    let mut lengths: Vec<u64> = (0..40).map(|i| 1u64 << i).collect();
    lengths.extend([u64::MAX / CLUSTER, u64::MAX / CLUSTER + 1, u64::MAX]);
    lengths.sort_unstable();

    for length in lengths {
        let size = DataRun::new(0, length).byte_size(CLUSTER);
        assert!(
            size >= previous,
            "run of {length} clusters reported {size} bytes, less than the {previous} \
             reported by a shorter run"
        );
        previous = size;
    }
}

/// Summing many runs must not wrap either.
#[test]
fn totalling_many_huge_runs_saturates() {
    let runs = (0..8).map(|_| DataRun::new(0, u64::MAX / 4)).collect();
    let total = inode_with(runs).total_run_bytes(CLUSTER);
    assert_eq!(
        total,
        u64::MAX,
        "eight enormous runs must total the maximum, not wrap around to {total}"
    );
}

/// A realistic inode still totals exactly.
#[test]
fn a_realistic_total_is_exact() {
    let inode = inode_with(vec![
        DataRun::new(100, 3),
        DataRun::new(200, 5),
        DataRun::sparse(2),
    ]);

    assert_eq!(
        inode.total_run_bytes(CLUSTER),
        10 * CLUSTER,
        "3 + 5 + 2 clusters at {CLUSTER} bytes each"
    );
}

/// Guards the tests above: the fixtures must really cross the overflow point.
///
/// If `u64::MAX / CLUSTER` were representable after multiplying, every assertion
/// here would hold without the saturation ever being exercised.
#[test]
fn the_fixtures_actually_reach_the_overflow_point() {
    let just_over = u64::MAX / CLUSTER + 1;
    assert!(
        just_over.checked_mul(CLUSTER).is_none(),
        "{just_over} * {CLUSTER} does not overflow, so these tests prove nothing"
    );
    assert!(
        (u64::MAX / 4).checked_mul(CLUSTER).is_none(),
        "the run used by the totalling test does not overflow on its own"
    );
}
