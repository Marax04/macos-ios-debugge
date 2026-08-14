//! Invariants the page helpers must satisfy for every address.
//!
//! `rustre-mem` had no property tests. These check the defining properties by
//! enumeration rather than by fixture, with deliberate attention to the top of
//! the address space — the region fixtures never visit and where `wrapping_add`
//! quietly turns "round up" into "round down".

use rustre_core::address::{Address, AddressRange};
use rustre_mem::region::{page_align_down, page_align_up, page_containing, page_range_indices};

const PAGE: u64 = 0x1000;

/// Addresses spanning the whole space, including the final page.
fn addresses() -> Vec<u64> {
    vec![
        0,
        1,
        0xFFF,
        0x1000,
        0x1001,
        0x7FFF_FFFF,
        0x8000_0000,
        u64::MAX - 0x1000,
        u64::MAX - 0xFFF,
        u64::MAX - 1,
        u64::MAX,
    ]
}

/// The page containing `a` must contain `a`. This is the whole meaning of the
/// function's name, and it holds for every address or the helper is unusable at
/// the boundary.
#[test]
fn page_containing_contains_the_address() {
    for v in addresses() {
        // `AddressRange` is half-open, so no non-inverted range can contain the
        // very last byte of the space. That is a limit of the representation,
        // not of this function, so it is excluded here rather than papered over.
        if v == u64::MAX {
            continue;
        }
        let a = Address::new(v);
        let page = page_containing(a, PAGE);
        assert!(
            page.contains(a),
            "page_containing({v:#x}) = [{:#x}, {:#x}) which does not contain {v:#x}",
            page.start.as_u64(),
            page.end.as_u64(),
        );
    }
}

/// Rounding down never increases an address, and lands on a page boundary.
#[test]
fn align_down_is_a_floor() {
    for v in addresses() {
        let a = Address::new(v);
        let d = page_align_down(a, PAGE).as_u64();
        assert!(d <= v, "align_down({v:#x}) = {d:#x}, which is larger");
        assert_eq!(d % PAGE, 0, "align_down({v:#x}) = {d:#x} is not aligned");
        assert!(
            v - d < PAGE,
            "align_down({v:#x}) = {d:#x} skipped past a whole page"
        );
    }
}

/// Rounding up never decreases an address.
///
/// At the top of the space there is no aligned value above the input, so any
/// answer is a compromise — but returning something *smaller* is the one answer
/// that silently corrupts callers, who use the result as an exclusive end.
/// UNDECIDED — left failing-but-ignored on purpose, not fixed by this pass.
///
/// `Address::align_up` uses `wrapping_add`, and `rustre-core/tests/blitz.rs`
/// pins that with a green test whose comment reads "align_up should wrap, not
/// panic". Wrapping is therefore a deliberate choice, and the function has ~189
/// call sites — many of which use the result as an exclusive end bound, where a
/// value below the input silently inverts a range.
///
/// Worth noting: that green test only asserts the call does not panic; it never
/// asserts the wrapped value, so a saturating implementation would satisfy it
/// too. Which behaviour is wanted is a design decision for the crate owner.
#[test]
#[ignore = "undecided: align_up wrapping is pinned by a green test in rustre-core"]
fn align_up_never_goes_backwards() {
    for v in addresses() {
        let a = Address::new(v);
        let u = page_align_up(a, PAGE).as_u64();
        assert!(
            u >= v,
            "align_up({v:#x}) = {u:#x}, which is BELOW the input — a range built \
             from this end bound is inverted"
        );
    }
}

/// Every address in a range must fall inside the reported page span.
#[test]
fn page_range_indices_cover_the_range() {
    let cases = [
        (0u64, 0x1000u64),
        (0xFFF, 0x1001),
        (0x1000, 0x3000),
        (u64::MAX - 0x2000, u64::MAX),
    ];
    for (start, end) in cases {
        let r = AddressRange::new(Address::new(start), Address::new(end));
        let (first, last) = page_range_indices(&r, PAGE);
        assert!(first <= last, "inverted page span for [{start:#x}, {end:#x})");
        assert_eq!(
            first,
            start / PAGE,
            "first page index wrong for [{start:#x}, {end:#x})"
        );
        assert_eq!(
            last,
            (end - 1) / PAGE,
            "last page index wrong for [{start:#x}, {end:#x})"
        );
    }
}
