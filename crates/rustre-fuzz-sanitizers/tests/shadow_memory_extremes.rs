//! Shadow-memory bookkeeping must survive the arithmetic, not just the compare.
//!
//! `poison`, `unpoison`, `is_access_valid` and `first_poison` all compute the
//! end of the range as `addr + size`. Near the top of the address space that
//! addition overflows: with overflow checks on it panics, and without them it
//! wraps to a small value, which turns `first..last` into an EMPTY range. The
//! failure is silent and inverted — a sanitizer that reports a bad access as
//! valid — so it is worth pinning explicitly.
//!
//! The other properties here are derived from the meaning of the operations
//! (round-trip, agreement between two views of the same fact) rather than
//! copied from the implementation.

use rustre_fuzz_sanitizers::shadow_memory::{ShadowByte, ShadowMemory};

/// Addresses that stress the arithmetic, including the very top of the space.
fn extreme_addrs() -> Vec<u64> {
    vec![
        0,
        1,
        7,
        8,
        u64::from(u32::MAX),
        u64::MAX / 2,
        u64::MAX - 64,
        u64::MAX - 8,
        u64::MAX - 1,
        u64::MAX,
    ]
}

#[test]
fn no_address_makes_the_bookkeeping_panic() {
    let mut probed = 0usize;
    for addr in extreme_addrs() {
        // Sizes stay realistic on purpose: `poison` walks the range one granule
        // at a time with no upper bound, so a huge `size` does not fail — it
        // simply runs until the map exhausts memory. That is a separate,
        // pre-existing issue (recorded as an open question), not something this
        // test can assert on without hanging.
        for size in [0u64, 1, 8, 64] {
            let mut sm = ShadowMemory::new();
            sm.poison(addr, size, ShadowByte::HeapFreed);
            let _ = sm.is_access_valid(addr, size);
            let _ = sm.first_poison(addr, size);
            sm.unpoison(addr, size);
            probed += 1;
        }
    }
    assert_eq!(probed, 40, "anti-vacuity: every address/size pair must be probed");
}

#[test]
fn poisoning_the_top_of_the_address_space_is_not_silently_dropped() {
    // The regression this file exists for: if `addr + size` wraps, the granule
    // loop runs zero times, nothing is poisoned, and the access is approved.
    let addr = u64::MAX - 15;
    let mut sm = ShadowMemory::new();

    assert!(
        sm.is_access_valid(addr, 8),
        "premise: the range is clean before poisoning"
    );

    sm.poison(addr, 8, ShadowByte::HeapFreed);

    assert!(
        !sm.is_access_valid(addr, 8),
        "a poisoned range at the top of the address space must not read as valid"
    );
    assert!(
        sm.first_poison(addr, 8).is_some(),
        "first_poison must find the poison it was just given"
    );
    assert!(
        sm.poisoned_count() > 0,
        "anti-vacuity: poisoning must actually have recorded something"
    );
}

#[test]
fn is_access_valid_and_first_poison_always_agree() {
    // Two views of the same fact: an access is invalid exactly when a poisoned
    // granule exists in its range.
    let mut checked = 0usize;
    for addr in extreme_addrs() {
        for size in [1u64, 8, 64] {
            for state in [
                ShadowByte::Addressable,
                ShadowByte::HeapFreed,
                ShadowByte::UserPoisoned,
                ShadowByte::PartiallyAddressable(3),
            ] {
                let mut sm = ShadowMemory::new();
                sm.poison(addr, size, state);
                assert_eq!(
                    sm.is_access_valid(addr, size),
                    sm.first_poison(addr, size).is_none(),
                    "disagreement at addr={addr:#x} size={size} state={state:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 120, "anti-vacuity: every combination must be checked");
}

#[test]
fn unpoison_undoes_poison() {
    let mut restored = 0usize;
    for addr in extreme_addrs() {
        for size in [1u64, 8, 64] {
            let mut sm = ShadowMemory::new();
            sm.poison(addr, size, ShadowByte::HeapFreed);
            sm.unpoison(addr, size);
            assert!(
                sm.is_access_valid(addr, size),
                "unpoison must restore the range at addr={addr:#x} size={size}"
            );
            restored += 1;
        }
    }
    assert_eq!(restored, 30, "anti-vacuity: every pair must be restored");
}

#[test]
fn the_raw_encoding_round_trips_for_every_documented_state() {
    // `PartiallyAddressable` is documented as carrying 1..=7.
    let mut states = vec![
        ShadowByte::Addressable,
        ShadowByte::HeapLeftRedzone,
        ShadowByte::HeapRightRedzone,
        ShadowByte::HeapFreed,
        ShadowByte::StackLeftRedzone,
        ShadowByte::StackRightRedzone,
        ShadowByte::Global,
        ShadowByte::UseAfterReturn,
        ShadowByte::UseAfterScope,
        ShadowByte::UserPoisoned,
        ShadowByte::ArrayCookie,
        ShadowByte::IntraObjectPadding,
        ShadowByte::Internal,
    ];
    states.extend((1..=7).map(ShadowByte::PartiallyAddressable));

    assert_eq!(states.len(), 20, "anti-vacuity: expected every documented state");

    let mut seen_raw = Vec::new();
    for s in &states {
        let raw = s.to_raw();
        assert_eq!(
            ShadowByte::from_raw(raw),
            *s,
            "{s:?} did not survive the raw round-trip (raw = {raw})"
        );
        assert!(
            !seen_raw.contains(&raw),
            "{s:?} collides with another state on raw value {raw}"
        );
        seen_raw.push(raw);
    }
}

#[test]
fn only_addressable_states_are_unpoisoned() {
    // Derived from the meaning of the enum, not from `is_poisoned`'s body.
    for n in 1..=7u8 {
        assert!(!ShadowByte::PartiallyAddressable(n).is_poisoned());
    }
    assert!(!ShadowByte::Addressable.is_poisoned());
    for s in [
        ShadowByte::HeapFreed,
        ShadowByte::HeapLeftRedzone,
        ShadowByte::UseAfterReturn,
        ShadowByte::UserPoisoned,
    ] {
        assert!(s.is_poisoned(), "{s:?} must count as poisoned");
    }
}
