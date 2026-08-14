//! Relations that `AddressRange`'s predicates must satisfy jointly.
//!
//! `rustre-core` had no property tests. Each predicate here is individually
//! plausible; what matters is whether they agree with each other and with
//! `contains`, which is the ground truth for "is this address in the range".
//! Ranges are enumerated, including empty and inverted ones, because those are
//! what callers accidentally build (see `page_containing`, which produced an
//! inverted range on the last page of the space).

use rustre_core::address::{Address, AddressRange};

fn r(start: u64, end: u64) -> AddressRange {
    AddressRange::new(Address::new(start), Address::new(end))
}

/// Small ranges: normal, empty, inverted, touching, nested.
fn ranges() -> Vec<AddressRange> {
    let mut v = Vec::new();
    for start in 0..6u64 {
        for end in 0..6u64 {
            v.push(r(start, end));
        }
    }
    v
}

/// Addresses to probe with, one past the range span.
fn probes() -> Vec<Address> {
    (0..8u64).map(Address::new).collect()
}

/// `contains` is the ground truth; every value in the intersection must be in
/// both operands, and nothing else may be dropped.
#[test]
fn intersection_is_exactly_the_shared_addresses() {
    for a in ranges() {
        for b in ranges() {
            let i = a.intersection(&b);
            for p in probes() {
                let in_both = a.contains(p) && b.contains(p);
                let in_i = i.is_some_and(|x| x.contains(p));
                assert_eq!(
                    in_i, in_both,
                    "intersection disagrees at {:#x}: a=[{:#x},{:#x}) b=[{:#x},{:#x}) i={:?}",
                    p.as_u64(),
                    a.start.as_u64(), a.end.as_u64(),
                    b.start.as_u64(), b.end.as_u64(),
                    i.map(|x| (x.start.as_u64(), x.end.as_u64())),
                );
            }
        }
    }
}

/// `overlaps` must mean "the intersection is non-empty" — no more, no less.
#[test]
fn overlaps_agrees_with_intersection() {
    for a in ranges() {
        for b in ranges() {
            let by_predicate = a.overlaps(&b);
            let by_construction = a.intersection(&b).is_some();
            assert_eq!(
                by_predicate, by_construction,
                "overlaps={by_predicate} but intersection={:?} for \
                 a=[{:#x},{:#x}) b=[{:#x},{:#x})",
                by_construction,
                a.start.as_u64(), a.end.as_u64(),
                b.start.as_u64(), b.end.as_u64(),
            );
        }
    }
}

/// If `a` contains the range `b`, it must contain every address of `b`.
#[test]
fn contains_range_implies_contains_each_address() {
    for a in ranges() {
        for b in ranges() {
            if !a.contains_range(&b) {
                continue;
            }
            for p in probes() {
                if b.contains(p) {
                    assert!(
                        a.contains(p),
                        "a=[{:#x},{:#x}) claims to contain b=[{:#x},{:#x}) \
                         but not address {:#x}",
                        a.start.as_u64(), a.end.as_u64(),
                        b.start.as_u64(), b.end.as_u64(),
                        p.as_u64(),
                    );
                }
            }
        }
    }
}

/// Splitting partitions the range: every address lands in exactly one half.
#[test]
fn split_at_partitions_the_range() {
    for a in ranges() {
        for p in probes() {
            let Some((left, right)) = a.split_at(p) else {
                continue;
            };
            for q in probes() {
                let in_a = a.contains(q);
                let in_halves = left.contains(q) ^ right.contains(q);
                assert_eq!(
                    in_a, in_halves,
                    "split of [{:#x},{:#x}) at {:#x} misplaces {:#x}",
                    a.start.as_u64(), a.end.as_u64(), p.as_u64(), q.as_u64(),
                );
            }
        }
    }
}

/// The hull must cover both operands.
#[test]
fn merge_covers_both_operands() {
    for a in ranges() {
        for b in ranges() {
            let m = a.merge(&b);
            for p in probes() {
                if a.contains(p) || b.contains(p) {
                    assert!(
                        m.contains(p),
                        "merge of [{:#x},{:#x}) and [{:#x},{:#x}) lost {:#x}",
                        a.start.as_u64(), a.end.as_u64(),
                        b.start.as_u64(), b.end.as_u64(),
                        p.as_u64(),
                    );
                }
            }
        }
    }
}
