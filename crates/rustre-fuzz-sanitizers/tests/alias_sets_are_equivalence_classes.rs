//! `AliasAnalysis` must behave like the equivalence relation it models.
//!
//! `alias_set_for` is documented as returning *the* alias set containing a
//! pointer. That definite article only holds if the sets are disjoint, which in
//! turn requires `record_alias` to merge transitively: recording `(a, b)` and
//! then `(b, c)` has to leave one class `{a, b, c}`, not two overlapping ones.
//!
//! The properties below are derived from the definition of an equivalence
//! relation — reflexive, symmetric, transitive — rather than copied from the
//! implementation.

use rustre_fuzz_sanitizers::sanitizer_runtime::AliasAnalysis;

fn members(a: &AliasAnalysis, ptr: u64) -> Vec<u64> {
    let mut v = a
        .alias_set_for(ptr)
        .map(|s| s.pointers.clone())
        .unwrap_or_default();
    v.sort_unstable();
    v
}

#[test]
fn recorded_pairs_are_symmetric() {
    let mut a = AliasAnalysis::new();
    a.record_alias(0x20, 0x10);

    assert!(a.has_aliases(0x10), "premise: 0x10 was recorded");
    assert!(a.has_aliases(0x20), "premise: 0x20 was recorded");
    assert_eq!(
        members(&a, 0x10),
        members(&a, 0x20),
        "both members of a recorded pair must see the same class"
    );
}

#[test]
fn aliasing_is_transitive() {
    let mut a = AliasAnalysis::new();
    a.record_alias(0x10, 0x20);
    a.record_alias(0x20, 0x30);

    let expected = vec![0x10, 0x20, 0x30];
    for probe in [0x10u64, 0x20, 0x30] {
        assert_eq!(
            members(&a, probe),
            expected,
            "0x{probe:x} must see the whole class: 0x10~0x20 and 0x20~0x30 imply 0x10~0x30"
        );
    }
}

#[test]
fn a_pointer_belongs_to_exactly_one_class() {
    // Build two separate classes, then bridge them and check they fused rather
    // than leaving the bridging pointer in both.
    let mut a = AliasAnalysis::new();
    a.record_alias(1, 2);
    a.record_alias(3, 4);

    assert_eq!(members(&a, 1), vec![1, 2], "premise: first class is {{1,2}}");
    assert_eq!(members(&a, 3), vec![3, 4], "premise: second class is {{3,4}}");

    a.record_alias(2, 3); // bridge

    let fused = vec![1, 2, 3, 4];
    for probe in [1u64, 2, 3, 4] {
        assert_eq!(
            members(&a, probe),
            fused,
            "after bridging, {probe} must see the single fused class"
        );
    }
}

#[test]
fn unrelated_classes_stay_separate() {
    // Guards against a merge that is too eager and collapses everything.
    let mut a = AliasAnalysis::new();
    a.record_alias(1, 2);
    a.record_alias(100, 200);

    assert_eq!(members(&a, 1), vec![1, 2]);
    assert_eq!(members(&a, 100), vec![100, 200]);
    assert!(
        !a.alias_set_for(1).unwrap().may_alias(100),
        "anti-vacuity: distinct classes must not be merged"
    );
}

#[test]
fn lookups_are_reproducible_and_order_independent() {
    // The same facts recorded in a different order must give the same classes.
    let build = |pairs: &[(u64, u64)]| {
        let mut a = AliasAnalysis::new();
        for &(x, y) in pairs {
            a.record_alias(x, y);
        }
        a
    };

    let forward = build(&[(10, 20), (20, 30), (40, 50)]);
    let shuffled = build(&[(40, 50), (30, 20), (20, 10)]);

    let mut probes = 0usize;
    for probe in [10u64, 20, 30, 40, 50] {
        assert_eq!(
            members(&forward, probe),
            members(&shuffled, probe),
            "class of {probe} changed with the order the aliases were recorded"
        );
        probes += 1;
    }
    assert_eq!(probes, 5, "anti-vacuity: every pointer must be probed");
    assert_eq!(members(&forward, 10), vec![10, 20, 30]);
    assert_eq!(members(&forward, 40), vec![40, 50]);
}

#[test]
fn an_unknown_pointer_has_no_class() {
    let mut a = AliasAnalysis::new();
    a.record_alias(1, 2);
    assert!(!a.has_aliases(999));
    assert!(a.alias_set_for(999).is_none());
}
