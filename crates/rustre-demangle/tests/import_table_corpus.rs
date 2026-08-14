//! A third corpus: the PE import tables, invisible to `nm`.
//!
//! `nm` lists a binary's defined and undefined symbols but not its import
//! directory, so the names the corpus programs call into KERNEL32 and msvcrt
//! reached neither `real_symbols.txt` nor `pdb_symbols.txt`. `objdump -p` has
//! them, and they were free.
//!
//! They are worth having for one specific reason: **58 of the 240 begin with an
//! underscore** — `_amsg_exit`, `__C_specific_handler`, `___lc_codepage_func`,
//! `__acrt_iob_func` — which is exactly the shape that made the old `_R`, `_T`
//! and `_D` prefix rules invent phantom defects (`_RTC_Initialize` filed as
//! Rust, `_TIFFOpen` as Swift, `_DllMainCRTStartup` as D). `src/sigil.rs` exists
//! to prevent that, and until now it had no REAL data of that shape to be
//! measured against — every underscore-prefixed C name in the test suite was
//! one somebody thought to write down.
//!
//! **Measured 2026-07-30: all 240 classify as `UndecoratedC`, none is claimed
//! by any ABI. No defect.** The value is a negative result over ground truth
//! that did not exist, and a corpus that regenerates with the others.

/// No import name may be claimed by a mangling ABI.
///
/// The phantom-defect property, over real data: a C name filed as an unhandled
/// or mis-decoded ABI is worse than one that declines, because it hides the
/// symbols that genuinely need attention.
#[test]
fn no_import_name_is_claimed_by_an_abi() {
    let mut checked = 0;
    let mut claimed = Vec::new();
    for line in include_str!("data/import_symbols.txt").lines() {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        checked += 1;
        if let Some(r) = rustre_demangle::demangle(sym) {
            claimed.push(format!("{sym} => {} (abi {:?})", r.demangled, r.abi));
        }
    }
    assert!(checked >= 200, "vacuous: only {checked} import names");
    assert!(
        claimed.is_empty(),
        "{} plain C import names were claimed by an ABI:\n{}",
        claimed.len(),
        claimed.join("\n")
    );
}

/// Every one classifies as undecorated C — not as a defect, not as unknown.
///
/// `UnsupportedAbi` and `Unknown` are the two variants this crate locks at zero;
/// a C name landing in either would be a phantom defect hiding a real one.
#[test]
fn every_import_name_classifies_as_undecorated_c() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for line in include_str!("data/import_symbols.txt").lines() {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        checked += 1;
        let reason = format!("{:?}", rustre_demangle::decline::decline_reason(sym));
        if reason != "UndecoratedC" {
            wrong.push(format!("{sym}: {reason}"));
        }
    }
    assert!(checked >= 200, "vacuous: only {checked}");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The corpus really does contain the risky shape.
///
/// A vacuity guard with teeth: if a future regeneration lost the
/// underscore-prefixed names, the two tests above would still pass while
/// testing nothing of interest.
#[test]
fn the_corpus_contains_underscore_prefixed_c_names() {
    let underscored = include_str!("data/import_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('_'))
        .count();
    assert!(
        underscored >= 40,
        "only {underscored} underscore-prefixed names — the corpus lost the \
         shape it exists to cover"
    );
    // And the specific historical offenders' relatives are present.
    let text = include_str!("data/import_symbols.txt");
    for needle in ["__C_specific_handler", "_amsg_exit", "__acrt_iob_func"] {
        assert!(text.contains(needle), "{needle} is missing from the corpus");
    }
}
