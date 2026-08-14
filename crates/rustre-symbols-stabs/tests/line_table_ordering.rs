//! `StabsLineTable` keeps the order its own field documents.
//!
//! `entries` is a public field whose doc reads "Line entries, sorted by
//! address", and `lookup_address` leans on that: it uses `partition_point`,
//! which on an unsorted slice returns a wrong answer *silently* rather than
//! failing.  `add` used to `push`, leaving the invariant to the caller, so the
//! obvious sequence — `new()`, `add()`, `lookup_address()` — was wrong whenever
//! the entries did not happen to arrive in ascending order.
//!
//! The fixtures below deliberately feed addresses out of order.  A test that
//! added them in order would pass against the old `push` too, and so could not
//! police the invariant it is here to protect.

use rustre_symbols_stabs::stabs_line_info::{StabsLineEntry, StabsLineTable};

fn table_added_out_of_order() -> StabsLineTable {
    let mut t = StabsLineTable::new("main", 0x1000);
    // Descending, then interleaved — the worst case for `partition_point`.
    t.add(StabsLineEntry::new(0x1030, "main.c", 12));
    t.add(StabsLineEntry::new(0x1000, "main.c", 10));
    t.add(StabsLineEntry::new(0x1020, "main.c", 11));
    t.add(StabsLineEntry::new(0x1010, "main.c", 10));
    t
}

#[test]
fn entries_stay_sorted_when_added_out_of_order() {
    let t = table_added_out_of_order();
    let addrs: Vec<u64> = t.entries.iter().map(|e| e.address).collect();
    assert_eq!(
        addrs,
        vec![0x1000, 0x1010, 0x1020, 0x1030],
        "the `entries` field documents itself as sorted by address"
    );
}

#[test]
fn lookup_finds_the_last_entry_at_or_below_the_address() {
    let t = table_added_out_of_order();

    // Exactly on an entry.
    assert_eq!(t.lookup_address(0x1020).map(|e| e.address), Some(0x1020));
    // Between two entries — must round *down*.
    assert_eq!(t.lookup_address(0x1028).map(|e| e.address), Some(0x1020));
    // Past the last entry.
    assert_eq!(t.lookup_address(0xFFFF).map(|e| e.address), Some(0x1030));
    // Below the first entry: nothing covers it.
    assert!(t.lookup_address(0x0FFF).is_none());
}

/// Adding in ascending order must behave exactly as before — the fix is an
/// append in the common case, not a reordering.
#[test]
fn ascending_insertion_is_unchanged() {
    let mut t = StabsLineTable::new("main", 0x1000);
    for (i, addr) in [0x1000u64, 0x1010, 0x1020, 0x1030].iter().enumerate() {
        t.add(StabsLineEntry::new(*addr, "main.c", 10 + i as u32));
    }
    let addrs: Vec<u64> = t.entries.iter().map(|e| e.address).collect();
    assert_eq!(addrs, vec![0x1000, 0x1010, 0x1020, 0x1030]);
    assert_eq!(t.lookup_address(0x1015).map(|e| e.line), Some(11));
}
