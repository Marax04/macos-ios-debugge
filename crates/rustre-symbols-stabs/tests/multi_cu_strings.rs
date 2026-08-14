//! Multi-CU `.stabstr` resolution (audit finding 5: N_UNDF / CU-relative n_strx).
//!
//! In a linker-merged `.stab` section each compilation unit is introduced by an
//! `N_UNDF` header whose `n_value` is the byte size of that CU's `.stabstr`
//! slice; every following `n_strx` is relative to the running total. Before the
//! fix all string resolvers treated `n_strx` as an absolute offset, so CU 1
//! decoded correctly and every later CU silently produced wrong names.
//!
//! Each scenario below is checked through *every* resolver, because the failure
//! mode the audit warned about is one parser being fixed while another is not.

use rustre_symbols_stabs::cu_strings::{CuStringBase, N_UNDF};
use rustre_symbols_stabs::stabs_complete::{RawStab, StabsComplete};
use rustre_symbols_stabs::stabs_full_parser::{FullStabsParser, ParsedStab, StabsRecord};
use rustre_symbols_stabs::stabs_parser::{StabStringTable, StabsParser};
use rustre_symbols_stabs::{StabRecord, StabsLowParser};

const N_FUN: u8 = 0x24;
const N_SO: u8 = 0x64;

// ── fixture builders ─────────────────────────────────────────────────────────

/// One 12-byte STABS record, little- or big-endian.
fn rec(n_strx: u32, n_type: u8, n_desc: u16, n_value: u32, be: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    if be {
        v.extend_from_slice(&n_strx.to_be_bytes());
        v.push(n_type);
        v.push(0);
        v.extend_from_slice(&n_desc.to_be_bytes());
        v.extend_from_slice(&n_value.to_be_bytes());
    } else {
        v.extend_from_slice(&n_strx.to_le_bytes());
        v.push(n_type);
        v.push(0);
        v.extend_from_slice(&n_desc.to_le_bytes());
        v.extend_from_slice(&n_value.to_le_bytes());
    }
    v
}

/// Two CUs, each with its own `.stabstr` slice.
///
/// * CU 1 slice = `"\0a.c\0alpha:F(0,1)\0"` — names at rel. 1 and 5.
/// * CU 2 slice = `"\0b.c\0beta:F(0,1)\0"`  — names at rel. 1 and 5.
///
/// CU 2's `n_strx` values are identical to CU 1's; only the running base tells
/// them apart. Under the old absolute-offset code CU 2's `N_FUN` at `n_strx=5`
/// resolved to `"alpha:F(0,1)"` — CU 1's function name.
fn two_cu_fixture(be: bool) -> (Vec<u8>, Vec<u8>) {
    let mut stabstr = Vec::new();
    stabstr.extend_from_slice(b"\0a.c\0alpha:F(0,1)\0");
    let cu1_len = u32::try_from(stabstr.len()).unwrap();
    stabstr.extend_from_slice(b"\0b.c\0beta:F(0,1)\0");
    let cu2_len = u32::try_from(stabstr.len()).unwrap() - cu1_len;

    let mut stab = Vec::new();
    stab.extend(rec(1, N_UNDF, 2, cu1_len, be));
    stab.extend(rec(1, N_SO, 0, 0x1000, be));
    stab.extend(rec(5, N_FUN, 0, 0x1000, be));
    stab.extend(rec(1, N_UNDF, 2, cu2_len, be));
    stab.extend(rec(1, N_SO, 0, 0x2000, be));
    stab.extend(rec(5, N_FUN, 0, 0x2000, be));
    (stab, stabstr)
}

/// A single non-merged CU with no leading `N_UNDF` — must behave as base 0.
fn single_cu_fixture() -> (Vec<u8>, Vec<u8>) {
    let stabstr = b"\0solo.c\0only_fn:F(0,1)\0".to_vec();
    let mut stab = Vec::new();
    stab.extend(rec(1, N_SO, 0, 0x1000, false));
    stab.extend(rec(8, N_FUN, 0, 0x1000, false));
    (stab, stabstr)
}

fn to_full_records(stab: &[u8]) -> Vec<StabsRecord> {
    rustre_symbols_stabs::stabs_full_parser::parse_stab_section(stab)
}

fn to_raw_stabs(stab: &[u8]) -> Vec<RawStab> {
    stab.chunks_exact(12)
        .map(|c| RawStab {
            str_index: u32::from_le_bytes(c[0..4].try_into().unwrap()),
            n_type: c[4],
            n_other: c[5],
            n_desc: u16::from_le_bytes([c[6], c[7]]),
            n_value: u32::from_le_bytes(c[8..12].try_into().unwrap()),
        })
        .collect()
}

// ── scenario 1: single CU, no N_UNDF header ──────────────────────────────────

#[test]
fn single_cu_without_undf_resolves_absolutely() {
    let (stab, stabstr) = single_cu_fixture();

    let recs = StabRecord::parse_all(&stab, &stabstr);
    assert_eq!(recs[0].string, "solo.c");
    assert_eq!(recs[1].symbol_name(), "only_fn");

    let entries = StabsLowParser::parse(&stab, &stabstr).unwrap();
    assert_eq!(entries[0].string_value, "solo.c");
    assert_eq!(entries[1].string_value, "only_fn:F(0,1)");

    let parsed = FullStabsParser::new(stabstr.clone()).parse_all(&to_full_records(&stab));
    assert!(matches!(&parsed[1], ParsedStab::Function { name, .. } if name == "only_fn"));

    let report = StabsComplete::new()
        .parse(&to_raw_stabs(&stab), &stabstr)
        .unwrap();
    assert_eq!(report.unknown_count, 0);
}

// ── scenario 2: two CUs with distinct string slices ──────────────────────────

#[test]
fn second_cu_names_are_correct_record_level() {
    let (stab, stabstr) = two_cu_fixture(false);
    let recs = StabRecord::parse_all(&stab, &stabstr);

    assert_eq!(recs[0].string, "a.c", "CU1 header");
    assert_eq!(recs[1].string, "a.c", "CU1 N_SO");
    assert_eq!(recs[2].symbol_name(), "alpha", "CU1 N_FUN");
    assert_eq!(recs[3].string, "b.c", "CU2 header");
    assert_eq!(recs[4].string, "b.c", "CU2 N_SO");
    // This is the assertion that failed before the fix: it read "alpha".
    assert_eq!(recs[5].symbol_name(), "beta", "CU2 N_FUN");
}

#[test]
fn second_cu_names_are_correct_low_parser() {
    let (stab, stabstr) = two_cu_fixture(false);
    let entries = StabsLowParser::parse(&stab, &stabstr).unwrap();
    assert_eq!(entries[4].string_value, "b.c");
    assert_eq!(entries[5].string_value, "beta:F(0,1)");
}

#[test]
fn second_cu_names_are_correct_full_parser() {
    let (stab, stabstr) = two_cu_fixture(false);
    let parsed = FullStabsParser::new(stabstr).parse_all(&to_full_records(&stab));
    assert!(matches!(&parsed[2], ParsedStab::Function { name, .. } if name == "alpha"));
    assert!(
        matches!(&parsed[5], ParsedStab::Function { name, .. } if name == "beta"),
        "CU2 function name, got {:?}",
        parsed[5]
    );
}

#[test]
fn second_cu_names_are_correct_stabs_parser() {
    let (stab, stabstr) = two_cu_fixture(false);
    let table = StabStringTable::new(stabstr);
    let mut p = StabsParser::new();
    p.parse_stab_section(&stab, &table, false);

    let files: Vec<&str> = p.units.iter().map(|u| u.filename.as_str()).collect();
    assert_eq!(files, vec!["a.c", "b.c"]);
    let fns: Vec<&str> = p
        .units
        .iter()
        .flat_map(|u| u.functions.iter().map(|f| f.name.as_str()))
        .collect();
    assert_eq!(fns, vec!["alpha", "beta"]);
}

#[test]
fn second_cu_names_are_correct_stabs_complete() {
    let (stab, stabstr) = two_cu_fixture(false);
    let report = StabsComplete::new()
        .parse(&to_raw_stabs(&stab), &stabstr)
        .unwrap();
    assert!(
        report.source_files.iter().any(|f| f.contains("b.c")),
        "CU2 filename missing from {:?}",
        report.source_files
    );
}

/// The `StabStringTable::get` / `FullStabsParser::lookup_str` absolute-offset
/// entry points stay absolute; only the base-aware variants shift.
#[test]
fn absolute_lookup_entry_points_are_unchanged() {
    let (_, stabstr) = two_cu_fixture(false);
    let table = StabStringTable::new(stabstr.clone());
    assert_eq!(table.get(1), "a.c");
    assert_eq!(table.get(5), "alpha:F(0,1)");
    // CU2's slice starts at 18; its file name is at absolute 19.
    assert_eq!(table.get(19), "b.c");
    let fp = FullStabsParser::new(stabstr);
    assert_eq!(fp.lookup_str(23), "beta:F(0,1)");
    assert_eq!(fp.lookup_str(9_999), "");
}

/// Pins the pre-fix answer next to the post-fix one.
///
/// The old code resolved every `n_strx` as an absolute `.stabstr` offset. For
/// CU 2's `N_FUN` (`n_strx = 5`) that is `stabstr[5..]` — which is CU 1's
/// function name. This test asserts both readings explicitly, so the
/// difference the fix makes is visible without reverting it: the absolute
/// reading (still reachable via `lookup_str`) and the CU-relative reading
/// (what `parse_all` now produces) must NOT be the same string.
#[test]
fn absolute_reading_of_cu2_strx_is_cu1_name() {
    let (stab, stabstr) = two_cu_fixture(false);
    let fp = FullStabsParser::new(stabstr.clone());

    // What the six resolvers used to return for CU2's N_FUN record.
    let old = fp.lookup_str(5);
    assert_eq!(old, "alpha:F(0,1)", "pre-fix absolute reading");

    // What they return now.
    let recs = StabRecord::parse_all(&stab, &stabstr);
    let new = recs[5].string.as_str();
    assert_eq!(new, "beta:F(0,1)", "post-fix CU-relative reading");

    assert_ne!(old, new, "the fix must change CU2's decoded name");
}

// ── scenario 3: malformed N_UNDF with an out-of-range size ───────────────────

#[test]
fn malformed_undf_size_does_not_panic_or_desync() {
    let stabstr = b"\0a.c\0alpha\0".to_vec();
    let mut stab = Vec::new();
    // n_value claims a slice far larger than the whole string table.
    stab.extend(rec(1, N_UNDF, 2, u32::MAX, false));
    stab.extend(rec(1, N_SO, 0, 0x1000, false));
    stab.extend(rec(5, N_FUN, 0, 0x1000, false));

    let recs = StabRecord::parse_all(&stab, &stabstr);
    // The bogus size is rejected, so the base stays 0 and CU1 still decodes.
    assert_eq!(recs[0].string, "a.c");
    assert_eq!(recs[1].string, "a.c");
    assert_eq!(recs[2].string, "alpha");

    let entries = StabsLowParser::parse(&stab, &stabstr).unwrap();
    assert_eq!(entries[2].string_value, "alpha");

    let parsed = FullStabsParser::new(stabstr.clone()).parse_all(&to_full_records(&stab));
    assert!(matches!(&parsed[2], ParsedStab::Function { name, .. } if name == "alpha"));

    let table = StabStringTable::new(stabstr.clone());
    let mut p = StabsParser::new();
    p.parse_stab_section(&stab, &table, false);
    assert_eq!(p.units.len(), 1);

    // And the shared tracker records why.
    let mut base = CuStringBase::new();
    base.observe(N_UNDF, u32::MAX, stabstr.len());
    assert_eq!(base.malformed_headers(), 1);
    assert_eq!(base.base(), 0);

    // stabs_complete must return a result, not an error or a panic.
    assert!(
        StabsComplete::new()
            .parse(&to_raw_stabs(&stab), &stabstr)
            .is_ok()
    );
}

#[test]
fn empty_string_table_with_undf_header_is_survivable() {
    let mut stab = Vec::new();
    stab.extend(rec(1, N_UNDF, 1, 40, false));
    stab.extend(rec(5, N_FUN, 0, 0x1000, false));
    let recs = StabRecord::parse_all(&stab, &[]);
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r.string.is_empty()));
}

// ── scenario 4: big-endian ───────────────────────────────────────────────────

#[test]
fn big_endian_multi_cu_matches_little_endian() {
    let (be_stab, stabstr) = two_cu_fixture(true);
    let (le_stab, _) = two_cu_fixture(false);

    let be = StabRecord::parse_all_be(&be_stab, &stabstr);
    let le = StabRecord::parse_all(&le_stab, &stabstr);
    let be_names: Vec<&str> = be.iter().map(|r| r.string.as_str()).collect();
    let le_names: Vec<&str> = le.iter().map(|r| r.string.as_str()).collect();
    assert_eq!(be_names, le_names);
    assert_eq!(
        be_names,
        vec![
            "a.c",
            "a.c",
            "alpha:F(0,1)",
            "b.c",
            "b.c",
            "beta:F(0,1)"
        ]
    );

    // StabsLowParser's explicit-endian path must agree too.
    let entries = StabsLowParser::parse_with_endian(&be_stab, &stabstr, true).unwrap();
    assert_eq!(entries[5].string_value, "beta:F(0,1)");

    // As must the stabs_parser state machine in BE mode.
    let table = StabStringTable::new(stabstr);
    let mut p = StabsParser::new();
    p.parse_stab_section(&be_stab, &table, true);
    let fns: Vec<&str> = p
        .units
        .iter()
        .flat_map(|u| u.functions.iter().map(|f| f.name.as_str()))
        .collect();
    assert_eq!(fns, vec!["alpha", "beta"]);
}

// ── three CUs, to catch an accumulator that only works for the second ────────

#[test]
fn three_cus_accumulate_correctly() {
    let slices: [&[u8]; 3] = [b"\0one\0", b"\0two\0", b"\0three\0"];
    let mut stabstr = Vec::new();
    let mut stab = Vec::new();
    for s in slices {
        stab.extend(rec(1, N_UNDF, 1, u32::try_from(s.len()).unwrap(), false));
        stab.extend(rec(1, N_FUN, 0, 0x1000, false));
        stabstr.extend_from_slice(s);
    }
    let recs = StabRecord::parse_all(&stab, &stabstr);
    let names: Vec<&str> = recs.iter().map(|r| r.string.as_str()).collect();
    assert_eq!(
        names,
        vec!["one", "one", "two", "two", "three", "three"],
        "third CU must not fall back to CU1's slice"
    );
}
