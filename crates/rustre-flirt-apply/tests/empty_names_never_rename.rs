//! A match with no name must never rename anything.
//!
//! # Why this is a correctness rule, not a tidiness one
//!
//! Renaming `sub_140002620` to `""` is strictly worse than leaving it: the
//! address loses even the identity it had, and every downstream consumer —
//! emitted C, the Level 7 bridge, the symbol table — sees a function with no
//! name at all.
//!
//! This was not hypothetical. The rust-stdlib database carries **25 965 of its
//! 67 168 patterns (38.7%) with no primary name**, and before the guard in
//! `resolve_renames` they produced **188 of 240 renames** on
//! `sample3_rust.exe` — 78% of the output was empty strings.
//!
//! The defect was invisible to every count: "240 matches" reads as success. It
//! only showed up when the *content* of each rename was checked, not the
//! number of them.

use rustre_flirt_apply::{resolve_renames, FlirtMatch};

fn m(addr: u64, name: &str, confidence: u8) -> FlirtMatch {
    FlirtMatch {
        address: addr,
        function_name: name.to_string(),
        lib_name: "testlib".into(),
        confidence,
        pattern_length: 16,
    }
}

#[test]
fn an_empty_name_produces_no_rename() {
    let (renames, stats) = resolve_renames(&[m(0x1000, "", 100)], 0);
    assert!(renames.is_empty(), "un nome vuoto non deve rinominare nulla");
    assert_eq!(stats.matched, 0, "non va contato come match utile");
    assert_eq!(stats.skipped, 1, "va contato come scartato, non sparire in silenzio");
}

#[test]
fn whitespace_only_names_count_as_empty() {
    // A name of spaces is no more usable than an empty one, and would slip past
    // a naive `is_empty()` check.
    for blank in ["", " ", "\t", "   \n "] {
        let (renames, _) = resolve_renames(&[m(0x2000, blank, 100)], 0);
        assert!(renames.is_empty(), "nome {blank:?} non deve rinominare");
    }
}

#[test]
fn named_matches_still_survive_alongside_empty_ones() {
    // The guard must drop only the nameless ones — not act as a blanket filter
    // that quietly loses good matches too.
    let matches = vec![
        m(0x1000, "", 100),
        m(0x2000, "memcpy", 100),
        m(0x3000, "   ", 100),
        m(0x4000, "strlen", 100),
    ];
    let (renames, stats) = resolve_renames(&matches, 0);
    let mut names: Vec<&str> = renames.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["memcpy", "strlen"]);
    assert_eq!(stats.skipped, 2, "esattamente i due senza nome");
}

#[test]
fn no_rename_ever_carries_an_empty_name() {
    // The invariant stated directly: whatever the input, the output never
    // contains a nameless rename.
    let matches: Vec<FlirtMatch> = (0..50)
        .map(|i| {
            let name = if i % 3 == 0 { String::new() } else { format!("fn_{i}") };
            m(0x1000 + i * 0x10, &name, 100)
        })
        .collect();
    let (renames, _) = resolve_renames(&matches, 0);
    assert!(!renames.is_empty(), "i nomi validi devono passare");
    for r in &renames {
        assert!(
            !r.name.trim().is_empty(),
            "rename senza nome a {:#x}",
            r.address
        );
    }
}

#[test]
fn the_confidence_filter_and_the_name_filter_are_both_applied() {
    // A named match below the threshold is still skipped, and a nameless one
    // above it is too — the two guards must not shadow each other.
    let matches = vec![m(0x1000, "low_conf", 10), m(0x2000, "", 100)];
    let (renames, stats) = resolve_renames(&matches, 50);
    assert!(renames.is_empty());
    assert_eq!(stats.skipped, 2);
}
