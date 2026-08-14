//! A benign decline bucket must not be hiding a mangled symbol.
//!
//! `UnsupportedAbi` is the only `DeclineReason` that counts as a defect, and
//! the crate locks it at 0. That lock is only worth something if the *other*
//! buckets are honest: a symbol that carries a real mangling sigil but gets
//! filed as `UndecoratedC` or `LinkerArtifact` is exactly as undecoded as one
//! filed as `UnsupportedAbi`, and it disappears from the defect count instead
//! of showing up in it.
//!
//! That failure mode is the mirror image of the one `src/decline.rs` already
//! documents. A classifier that is too *loose* invents defects — `_R` claiming
//! `_RTC_Initialize` filed a plain C name as an unhandled mangled symbol. A
//! classifier that is too *tight* does the reverse and is strictly harder to
//! notice, because the number it moves is the one everybody watches, and it
//! moves in the reassuring direction. Nothing in the suite could distinguish
//! "zero unsupported ABIs because every mangled symbol decodes" from "zero
//! unsupported ABIs because the mangled ones were sorted elsewhere".
//!
//! The check is deliberately defined against `src/sigil.rs` rather than
//! against a fresh list of prefixes written here. A second copy of the rule is
//! how `_R` came to exist in five places and take forty iterations to clear;
//! if `sigil` is ever wrong, this test must be wrong the same way rather than
//! silently disagreeing, because a disagreement between two prefix rules is
//! the bug, not the detector.

use rustre_demangle::decline::{decline_reason, DeclineReason};

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Does this string carry a sigil that claims a mangling ABI?
///
/// Delegates to `sigil` for the four prefix-based ABIs and adds the two whose
/// sigils are not expressible there: Itanium's `_Z`/`__Z` and MSVC's leading
/// `?`. Those two are matched here rather than in `sigil` because the module
/// covers the prefixes that were historically duplicated and got a single
/// owner; widening its API is a change to shared code, and this test does not
/// need it.
fn carries_a_mangling_sigil(s: &str) -> bool {
    use rustre_demangle::sigil;
    sigil::is_rust_v0(s)
        || sigil::is_rust_legacy(s)
        || sigil::is_d(s)
        || sigil::is_swift(s)
        || s.starts_with("_Z")
        || s.starts_with("__Z")
        || s.starts_with('?')
}

/// No symbol filed as plain C or as a toolchain artifact may carry a sigil.
///
/// `LinkerSection` is excluded on purpose: `-ffunction-sections` names such as
/// `.pdata.unlikely._ZSt9terminatev` legitimately *embed* a mangled name
/// inside a section name, and the section is still not a symbol. Those are
/// caught by the leading-dot check instead, so a sigil appearing inside one is
/// expected rather than suspicious.
#[test]
fn benign_buckets_contain_no_mangled_symbols() {
    let mut offenders: Vec<(&str, DeclineReason)> = Vec::new();
    let mut checked = 0usize;

    for s in corpora() {
        if rustre_demangle::demangle(s).is_some() {
            continue;
        }
        let reason = decline_reason(s);
        if !matches!(
            reason,
            DeclineReason::UndecoratedC | DeclineReason::LinkerArtifact
        ) {
            continue;
        }
        checked += 1;
        if carries_a_mangling_sigil(s) {
            offenders.push((s, reason));
        }
    }

    // Vacuity guard. If the two benign buckets ever stopped being populated —
    // a classifier change routing everything to `LinkerSection`, say — this
    // test would pass while checking nothing, which is the precise shape of
    // green-but-empty that this crate has been bitten by before.
    println!("checked {checked} symbols in benign decline buckets");
    assert!(
        checked > 500,
        "only {checked} symbols landed in UndecoratedC/LinkerArtifact — the \
         classifier changed shape and this test is no longer measuring it"
    );
    assert!(
        offenders.is_empty(),
        "{} declined symbols carry a mangling sigil but were filed as benign, \
         so they are missing from the UnsupportedAbi defect count; first 10: \
         {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// The converse: nothing filed as `UnsupportedAbi` may be sigil-free.
///
/// Keeps the two directions symmetric. A sigil-free string in the defect
/// bucket is a phantom defect — the thing that made `_RTC_Initialize` look
/// like an unhandled Rust symbol — and it inflates the one number the crate
/// treats as authoritative.
#[test]
fn the_defect_bucket_contains_only_sigil_bearing_symbols() {
    let offenders: Vec<&str> = corpora()
        .into_iter()
        .filter(|s| rustre_demangle::demangle(s).is_none())
        .filter(|s| decline_reason(s) == DeclineReason::UnsupportedAbi)
        .filter(|s| !carries_a_mangling_sigil(s))
        .collect();

    assert!(
        offenders.is_empty(),
        "{} symbols are counted as unsupported ABIs but carry no mangling \
         sigil — phantom defects; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}
