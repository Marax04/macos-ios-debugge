//! Huge length prefixes must not overflow the arithmetic that bounds them.
//!
//! Every backend reads `<len><chars>` and then computes `pos + len` to bound the
//! slice. `len` comes from the symbol, so a prefix near `usize::MAX` overflows the
//! **bounds test itself** — the check meant to prevent an out-of-range slice is
//! the thing that panics.
//!
//! Three instances were found and fixed this way:
//!
//! | site | found |
//! |---|---|
//! | `backends::dropped_swift_local_name` | iter 82 |
//! | `d_demangler::parse_identifier` | iter 83 |
//! | `swift_demangler` length prefix | iter 83 |
//!
//! **None of the four ordinary gates can see this class**: a release build compiles
//! overflow checks out, so the arithmetic wraps silently and the parser merely
//! returns a wrong answer instead of panicking. This test therefore earns its keep
//! only under `tests/debug_assertions_hold.sh`, which runs the suite as a release
//! build with `-C debug-assertions=on`. Under the ordinary gates it still runs, and
//! still guards against a *panic* from indexing, just not against the overflow.
//!
//! Two construction rules, both learned the hard way:
//!
//! * **The huge prefix must sit after a well-formed one.** A parser only reaches
//!   its later arithmetic if the earlier part parsed, so `$s18446744073709551615a`
//!   declines immediately and proves nothing. Inserting into a symbol that decodes
//!   is what reaches the code.
//! * **Magnitude matters, not just shape.** Nineteen nines is 9.99e18; `usize::MAX`
//!   is 1.84e19, so `pos + 9999999999999999999` does not overflow. The first probe
//!   attempt missed for exactly this reason.

/// Symbols that decode, one per ABI, used as carriers.
const BASES: &[&str] = &[
    "_ZN4main5outerEv",
    "_ZN3std6string6String3newEv",
    "_D4main3fooFiZv",
    "_D4main5outerFAyaZv",
    "$s4main5outeryyF",
    "$s10Foundation4DataV5countSivg",
    "?foo@bar@@QEAAHXZ",
    "??_R1A@?0A@EA@type_info@@8",
    "_RNvNtCs1234_3std2io6stdout",
    "runtime.main",
    "type:.eq.[2]runtime.Frame",
];

/// Chosen for magnitude: `usize::MAX`, just below it, one that cannot be
/// represented at all, and one that is large but safe.
const NUMBERS: &[&str] = &[
    "18446744073709551615",
    "18446744073709551614",
    "99999999999999999999",
    "9999999999999999999",
];

#[test]
fn a_huge_length_prefix_at_any_position_does_not_overflow() {
    let mut tried = 0;
    for base in BASES {
        for n in NUMBERS {
            for pos in 0..=base.len() {
                if !base.is_char_boundary(pos) {
                    continue;
                }
                let sym = format!("{}{n}{}", &base[..pos], &base[pos..]);
                // The assertion is that this returns at all. The value is not the
                // point: these are malformed symbols and any answer is acceptable
                // so long as the parser does not panic or wrap.
                let _ = rustre_demangle::demangle(&sym);
                tried += 1;
            }
        }
    }
    assert!(
        tried > 900,
        "vacuous: only {tried} adversarial inputs generated"
    );
}

/// The carriers must still decode, or the sweep above would be testing nothing.
///
/// Without this, deleting a backend would make the sweep pass trivially — every
/// input would decline before reaching any arithmetic.
#[test]
fn the_carrier_symbols_still_decode() {
    let mut decoded = 0;
    for base in BASES {
        if rustre_demangle::demangle(base).is_some() {
            decoded += 1;
        }
    }
    assert!(
        decoded >= 10,
        "only {decoded} of {} carriers decode — the sweep is no longer reaching \
         the parsers it is meant to exercise",
        BASES.len()
    );
}
