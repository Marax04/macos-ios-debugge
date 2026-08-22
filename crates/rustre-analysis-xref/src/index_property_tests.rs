//! Randomized property / oracle tests for the xref **index** and the byte
//! **scanners**.
//!
//! The graph algorithms already have a differential matrix in
//! `soundness_fuzz.rs`; this module covers the parts that had never had
//! randomized treatment:
//!
//! * [`XrefIndex`] invariants — every inserted entry retrievable by
//!   `from` / `to` / `kind`, duplicates never silently dropped, `callers_of`
//!   and `callees_of` exact inverses, removal leaves an index observationally
//!   identical to a rebuild-from-survivors oracle, `merge` == concatenation.
//! * Determinism of every ordered output.
//! * Panic-freedom of the byte scanners on random / truncated / adversarial
//!   buffers, including buffers cut mid-UTF8 and mid-UTF16.
//!
//! Every property is checked against a brute-force oracle over a `Vec` of the
//! inserted entries wherever one is cheap to write.

#![cfg(test)]

use crate::extract::{RegionMap, extract_all, extract_code_to_code, extract_code_to_data_riprel};
use crate::import_xref::{extract_first_arg_imm, scan_iat_calls_x86_64};
use crate::string_xref_finder::StringXrefFinder;
use crate::xref_index::{XrefEntry, XrefEntryKind, XrefIndex};
use rustre_core::address::Address;
use std::collections::{BTreeMap, HashSet};

// ── deterministic PRNG (xorshift64*) — no dev-dependencies ────────────────────

use crate::test_prng::Rng;

// ── random entry generation ───────────────────────────────────────────────────

/// Addresses are drawn from a small pool so collisions (and therefore
/// duplicate `(from, to, kind)` triples) happen often — that is exactly the
/// case where a "silently dropped duplicate" bug would hide.
const ADDR_POOL: usize = 8;

fn addr(i: usize) -> u64 {
    0x1000 + (i as u64) * 0x10
}

const TAGS: [&str; 4] = ["alpha", "beta", "", "z\u{00e9}ro"];

fn random_entry(rng: &mut Rng) -> XrefEntry {
    let from = addr(rng.below(ADDR_POOL));
    let to = addr(rng.below(ADDR_POOL));
    let kinds = XrefEntryKind::all();
    let kind = kinds[rng.below(kinds.len())];
    let size = (rng.below(8)) as u8;
    // Tagged kinds get a tag most of the time, but sometimes not — the index
    // has `if kind == X && let Some(tag)` guards that must tolerate both.
    let tagged = matches!(
        kind,
        XrefEntryKind::StringRef | XrefEntryKind::Import | XrefEntryKind::TypeRef
    );
    if tagged && rng.below(4) != 0 {
        XrefEntry::with_tag(from, to, kind, size, TAGS[rng.below(TAGS.len())])
    } else {
        XrefEntry::new(from, to, kind, size)
    }
}

fn build(entries: &[XrefEntry]) -> XrefIndex {
    let mut idx = XrefIndex::new();
    for e in entries {
        idx.add(e.clone());
    }
    idx
}

// ── oracle helpers (brute force over the flat Vec of inserted entries) ────────

fn oracle_from(entries: &[XrefEntry], from: u64) -> Vec<XrefEntry> {
    entries.iter().filter(|e| e.from == from).cloned().collect()
}

fn oracle_to(entries: &[XrefEntry], to: u64) -> Vec<XrefEntry> {
    entries.iter().filter(|e| e.to == to).cloned().collect()
}

fn oracle_callers(entries: &[XrefEntry], to: u64) -> Vec<u64> {
    entries
        .iter()
        .filter(|e| e.to == to && e.kind == XrefEntryKind::Call)
        .map(|e| e.from)
        .collect()
}

fn oracle_callees(entries: &[XrefEntry], from: u64) -> Vec<u64> {
    entries
        .iter()
        .filter(|e| e.from == from && e.kind == XrefEntryKind::Call)
        .map(|e| e.to)
        .collect()
}

fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v
}

/// Observational signature of an index: everything a caller can see, in a
/// canonical order. Two indices with equal signatures are indistinguishable.
fn signature(idx: &XrefIndex) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("total={}", idx.total()));
    parts.push(format!("src={} tgt={}", idx.unique_sources(), idx.unique_targets()));
    let mut all: Vec<String> = idx.iter_all().map(ToString::to_string).collect();
    all.sort();
    parts.push(all.join("|"));
    for &k in XrefEntryKind::all() {
        let mut v: Vec<String> =
            idx.xrefs_of_kind(k).into_iter().map(ToString::to_string).collect();
        v.sort();
        parts.push(format!("{k}:{}", v.join(",")));
    }
    parts.push(format!("strings={:?}", idx.all_strings()));
    parts.push(format!("imports={:?}", idx.all_imports()));
    for t in TAGS {
        parts.push(format!("s[{t}]={:?} i[{t}]={:?}", idx.string_refs(t), idx.import_refs(t)));
    }
    parts.push(format!("hot={:?}", idx.hot_targets(usize::MAX)));
    parts.join(";")
}

// ── Property 1: insert/retrieve completeness, no dropped duplicates ───────────

#[test]
fn prop_index_insert_retrieve_and_duplicates() {
    let mut rng = Rng::new(0xA5A5_1234_DEAD_BEEF);
    for trial in 0..1200u64 {
        let n = rng.below(20);
        let entries: Vec<XrefEntry> = (0..n).map(|_| random_entry(&mut rng)).collect();
        let idx = build(&entries);

        // total() counts every insertion, including exact duplicates.
        assert_eq!(idx.total(), entries.len(), "trial {trial}: total() lost entries");
        assert_eq!(
            idx.iter_all().count(),
            entries.len(),
            "trial {trial}: iter_all() lost entries"
        );

        // Retrievable by `from` and by `to`, with multiplicity.
        for i in 0..ADDR_POOL {
            let a = addr(i);
            assert_eq!(
                sorted(idx.xrefs_from(a).iter().map(ToString::to_string).collect()),
                sorted(oracle_from(&entries, a).iter().map(ToString::to_string).collect()),
                "trial {trial}: xrefs_from({a:#x}) != oracle"
            );
            assert_eq!(
                sorted(idx.xrefs_to(a).iter().map(ToString::to_string).collect()),
                sorted(oracle_to(&entries, a).iter().map(ToString::to_string).collect()),
                "trial {trial}: xrefs_to({a:#x}) != oracle"
            );
        }

        // Retrievable by kind, with multiplicity (duplicates not deduped away).
        for &k in XrefEntryKind::all() {
            let got = sorted(
                idx.xrefs_of_kind(k).into_iter().map(ToString::to_string).collect::<Vec<_>>(),
            );
            let want = sorted(
                entries
                    .iter()
                    .filter(|e| e.kind == k)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(got, want, "trial {trial}: xrefs_of_kind({k}) != oracle");
        }

        // Statistics agree with the oracle.
        let st = idx.stats();
        assert_eq!(st.total_entries, entries.len(), "trial {trial}: stats.total_entries");
        assert_eq!(
            st.unique_sources,
            entries.iter().map(|e| e.from).collect::<HashSet<_>>().len(),
            "trial {trial}: stats.unique_sources"
        );
        assert_eq!(
            st.unique_targets,
            entries.iter().map(|e| e.to).collect::<HashSet<_>>().len(),
            "trial {trial}: stats.unique_targets"
        );
        assert_eq!(
            st.by_kind.values().sum::<usize>(),
            entries.len(),
            "trial {trial}: stats.by_kind must partition all entries"
        );
    }
}

// ── Property 2: callers_of / callees_of are exact inverses ───────────────────

#[test]
fn prop_callers_callees_exact_inverses() {
    let mut rng = Rng::new(0x0BAD_F00D_C0DE_0001);
    for trial in 0..1200u64 {
        let n = rng.below(20);
        let entries: Vec<XrefEntry> = (0..n).map(|_| random_entry(&mut rng)).collect();
        let idx = build(&entries);

        for i in 0..ADDR_POOL {
            let a = addr(i);
            assert_eq!(
                sorted(idx.callers_of(a)),
                sorted(oracle_callers(&entries, a)),
                "trial {trial}: callers_of({a:#x}) != oracle"
            );
            assert_eq!(
                sorted(idx.callees_of(a)),
                sorted(oracle_callees(&entries, a)),
                "trial {trial}: callees_of({a:#x}) != oracle"
            );
        }

        // Inverse relation: b in callees_of(a)  <=>  a in callers_of(b),
        // counted with multiplicity.
        for i in 0..ADDR_POOL {
            for j in 0..ADDR_POOL {
                let (a, b) = (addr(i), addr(j));
                let fwd = idx.callees_of(a).into_iter().filter(|&x| x == b).count();
                let rev = idx.callers_of(b).into_iter().filter(|&x| x == a).count();
                assert_eq!(
                    fwd, rev,
                    "trial {trial}: callees_of({a:#x})∋{b:#x} count {fwd} != callers_of({b:#x})∋{a:#x} count {rev}"
                );
            }
        }

        // hot_targets is exactly the call in-degree histogram.
        let mut oracle_hot: BTreeMap<u64, usize> = BTreeMap::new();
        for e in entries.iter().filter(|e| e.kind == XrefEntryKind::Call) {
            *oracle_hot.entry(e.to).or_insert(0) += 1;
        }
        let mut want: Vec<(u64, usize)> = oracle_hot.into_iter().collect();
        want.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        assert_eq!(idx.hot_targets(usize::MAX), want, "trial {trial}: hot_targets != oracle");
    }
}

// ── Property 3: removal leaves an index identical to a rebuild ───────────────

#[test]
fn prop_removal_matches_rebuild_oracle() {
    let mut rng = Rng::new(0xFEED_FACE_2468_1357);
    for trial in 0..1200u64 {
        let n = rng.below(18);
        let entries: Vec<XrefEntry> = (0..n).map(|_| random_entry(&mut rng)).collect();
        let victim = addr(rng.below(ADDR_POOL));
        let by_from = rng.below(2) == 0;

        let mut idx = build(&entries);
        let removed = if by_from { idx.remove_from(victim) } else { idx.remove_to(victim) };

        let survivors: Vec<XrefEntry> = entries
            .iter()
            .filter(|e| if by_from { e.from != victim } else { e.to != victim })
            .cloned()
            .collect();
        let expect_removed = entries.len() - survivors.len();
        assert_eq!(
            removed, expect_removed,
            "trial {trial}: remove_{} returned {removed}, oracle {expect_removed}",
            if by_from { "from" } else { "to" }
        );

        let rebuilt = build(&survivors);
        assert_eq!(
            signature(&idx),
            signature(&rebuilt),
            "trial {trial}: index after remove_{} differs from rebuild-from-survivors",
            if by_from { "from" } else { "to" }
        );
    }
}

// ── Property 4: merge == concatenation ───────────────────────────────────────

#[test]
fn prop_merge_equals_concatenation() {
    let mut rng = Rng::new(0x1357_9BDF_0246_8ACE);
    for trial in 0..800u64 {
        let a: Vec<XrefEntry> = (0..rng.below(12)).map(|_| random_entry(&mut rng)).collect();
        let b: Vec<XrefEntry> = (0..rng.below(12)).map(|_| random_entry(&mut rng)).collect();

        let mut merged = build(&a);
        merged.merge(build(&b));

        let mut both = a.clone();
        both.extend(b.iter().cloned());
        let direct = build(&both);

        assert_eq!(
            signature(&merged),
            signature(&direct),
            "trial {trial}: merge() != building from the concatenation"
        );
    }
}

// ── Property 5: every ordered output is deterministic ────────────────────────

#[test]
fn prop_ordered_outputs_deterministic() {
    let mut rng = Rng::new(0x2718_2818_2845_9045);
    for trial in 0..600u64 {
        let entries: Vec<XrefEntry> = (0..rng.below(24)).map(|_| random_entry(&mut rng)).collect();
        // Two independently constructed indices over the same entries must
        // produce byte-identical ordered output (no HashMap order leakage).
        let a = build(&entries);
        let b = build(&entries);
        for &k in XrefEntryKind::all() {
            let va: Vec<String> = a.xrefs_of_kind(k).into_iter().map(ToString::to_string).collect();
            let vb: Vec<String> = b.xrefs_of_kind(k).into_iter().map(ToString::to_string).collect();
            assert_eq!(va, vb, "trial {trial}: xrefs_of_kind({k}) order not deterministic");
        }
        assert_eq!(a.all_strings(), b.all_strings(), "trial {trial}: all_strings order");
        assert_eq!(a.all_imports(), b.all_imports(), "trial {trial}: all_imports order");
        assert_eq!(a.hot_targets(5), b.hot_targets(5), "trial {trial}: hot_targets order");
        for t in TAGS {
            assert_eq!(a.string_refs(t), b.string_refs(t), "trial {trial}: string_refs order");
            assert_eq!(a.import_refs(t), b.import_refs(t), "trial {trial}: import_refs order");
        }
        // Repeated calls on the same index are also stable.
        assert_eq!(a.hot_targets(3), a.hot_targets(3));
    }
}

// ── Property 6: XrefIndex::build output is consistent with the index ─────────

#[test]
fn prop_scanner_build_is_self_consistent() {
    let mut rng = Rng::new(0x5EED_0BEE_F00D_9999);
    for trial in 0..600u64 {
        let len = rng.below(96);
        let mut code: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Salt with real E8/E9 opcodes so the scanner actually fires.
        for _ in 0..rng.below(4) {
            if !code.is_empty() {
                let p = rng.below(code.len());
                code[p] = if rng.below(2) == 0 { 0xE8 } else { 0xE9 };
            }
        }
        let base = if rng.below(4) == 0 { u64::MAX - 8 } else { 0x40_0000 };
        let idx = XrefIndex::build(base, &code);

        // Everything the scanner produced is retrievable both ways.
        let all: Vec<XrefEntry> = idx.iter_all().cloned().collect();
        assert_eq!(all.len(), idx.total(), "trial {trial}: build() total mismatch");
        for e in &all {
            assert!(
                idx.xrefs_from(e.from).contains(e),
                "trial {trial}: entry missing from xrefs_from"
            );
            assert!(idx.xrefs_to(e.to).contains(e), "trial {trial}: entry missing from xrefs_to");
        }
        // Deterministic across rebuilds.
        assert_eq!(
            signature(&idx),
            signature(&XrefIndex::build(base, &code)),
            "trial {trial}: XrefIndex::build not deterministic"
        );
    }
}

// ── Property 7: scanners never panic on adversarial buffers ─────────────────

/// Buffers designed to hit truncation edges: cut mid-instruction, mid-UTF8 and
/// mid-UTF16 sequences, all-zero, all-0xFF, and lone surrogates.
fn adversarial_buffers(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    out.push(Vec::new());
    out.push(vec![0u8; rng.below(9)]);
    out.push(vec![0xFFu8; rng.below(9)]);
    // Random noise.
    out.push((0..rng.below(70)).map(|_| rng.byte()).collect());
    // Truncated CALL/JMP rel32 / CALL [RIP+disp32] (1..5 of the needed bytes).
    for op in [vec![0xE8u8], vec![0xE9u8], vec![0xFFu8, 0x15]] {
        for keep in 0..5usize {
            let mut b = op.clone();
            b.extend(std::iter::repeat_n(0xAAu8, keep));
            out.push(b);
        }
    }
    // Valid UTF-8 truncated mid-sequence (2-, 3- and 4-byte code points).
    for s in ["é", "€", "𝄞", "aé€𝄞z"] {
        let bytes = s.as_bytes();
        for cut in 0..=bytes.len() {
            out.push(bytes[..cut].to_vec());
        }
    }
    // UTF-16LE truncated mid-unit and mid-surrogate-pair, plus a lone surrogate.
    let utf16: Vec<u8> = "aé𝄞z".encode_utf16().flat_map(u16::to_le_bytes).collect();
    for cut in 0..=utf16.len() {
        out.push(utf16[..cut].to_vec());
    }
    out.push(vec![0x00, 0xD8]); // lone high surrogate, LE
    out.push(vec![0x00, 0xDC]); // lone low surrogate, LE
    out
}

#[test]
fn prop_scanners_never_panic_on_adversarial_input() {
    let mut rng = Rng::new(0xDEAD_C0DE_FEED_5AFE);
    let bases: [u64; 5] = [0, 1, 0x40_0000, u64::MAX - 3, u64::MAX];
    let mut map = RegionMap::new();
    map.add_code(0x1000, 0x2000);
    map.add_data(0x2000, 0x3000);

    for round in 0..40u64 {
        for buf in adversarial_buffers(&mut rng) {
            for &base in &bases {
                // Byte scanners.
                let _ = XrefIndex::build(base, &buf);
                let _ = extract_code_to_code(Address::new(base), &buf);
                let _ = extract_code_to_data_riprel(Address::new(base), &buf);
                let _ = scan_iat_calls_x86_64(&buf, base);
                for ptr in [0u8, 1, 2, 4, 8, 16, 255] {
                    let _ = extract_all(
                        Address::new(base),
                        &buf,
                        Address::new(base),
                        &buf,
                        ptr,
                        &map,
                    );
                }
                // Argument look-back with out-of-range offsets.
                for off in [0usize, 1, buf.len(), buf.len() + 1, usize::MAX] {
                    let _ = extract_first_arg_imm(&buf, off, rng.below(40));
                }
                // String-xref pattern scanner.
                let finder = StringXrefFinder::new()
                    .with_x86_64()
                    .with_x86_32()
                    .with_min_string_addr(rng.below(0x2000) as u64);
                let _ = finder.scan(&buf, base, base);
                for ptr in [0usize, 3, 4, 8, 9] {
                    let _ = finder.scan_data_pointers(&buf, base, ptr);
                }
            }
        }
        let _ = round;
    }
}

// ── Regression cases (minimised from the properties above) ──────────────────

/// Regression for the duplicate-drop hazard: the same `(from, to, kind)`
/// triple inserted twice must be retrievable twice from every accessor.
/// Minimised from `prop_index_insert_retrieve_and_duplicates`
/// (seed `0xA5A5_1234_DEAD_BEEF`).
#[test]
fn regression_duplicate_triple_not_dropped() {
    let mut idx = XrefIndex::new();
    idx.add_call(0x1000, 0x2000, 5);
    idx.add_call(0x1000, 0x2000, 5);
    assert_eq!(idx.total(), 2);
    assert_eq!(idx.xrefs_from(0x1000).len(), 2);
    assert_eq!(idx.xrefs_to(0x2000).len(), 2);
    assert_eq!(idx.xrefs_of_kind(XrefEntryKind::Call).len(), 2);
    assert_eq!(idx.callers_of(0x2000), vec![0x1000, 0x1000]);
    assert_eq!(idx.callees_of(0x1000), vec![0x2000, 0x2000]);
    assert_eq!(idx.hot_targets(1), vec![(0x2000, 2)]);
}

/// Regression for self-loop removal accounting: `remove_from` on a node whose
/// only xref is a self-loop must clear both directions and leave `total` at 0.
/// Minimised from `prop_removal_matches_rebuild_oracle`
/// (seed `0xFEED_FACE_2468_1357`).
#[test]
fn regression_self_loop_removal_accounting() {
    let mut idx = XrefIndex::new();
    idx.add_call(0x1000, 0x1000, 5);
    assert_eq!(idx.remove_from(0x1000), 1);
    assert_eq!(idx.total(), 0);
    assert!(idx.is_empty());
    assert_eq!(idx.unique_sources(), 0);
    assert_eq!(idx.unique_targets(), 0);
    assert!(idx.xrefs_to(0x1000).is_empty());
    assert!(idx.xrefs_of_kind(XrefEntryKind::Call).is_empty());
}
