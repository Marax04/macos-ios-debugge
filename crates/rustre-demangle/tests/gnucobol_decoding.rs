//! `GnuCOBOL`: an underscore may never survive into a `PROGRAM-ID`.
//!
//! `GnuCOBOL` encodes the hyphen of a `PROGRAM-ID` as `__`, and a COBOL
//! program-name is drawn from letters, digits and hyphens — it cannot contain
//! an underscore at all. So the mangled form's underscores come *only* from
//! hyphens, every run of them is even, and none may reach the output.
//!
//! The detector already rejected a lone `_` (`A_B`), so the rule was known. It
//! was applied to single underscores and not to runs, and `replace("__", "-")`
//! is non-overlapping, so a three-underscore run split into one replacement
//! plus one survivor:
//!
//! ```text
//! A___B  =>  PROGRAM-ID A-_B
//! ```
//!
//! Same shape as the Ada `a___b` → `a._b` and gfortran `___a_MOD_x` → `_a::x`
//! defects: a component check that stopped one rule short, undone by a third
//! underscore.
//!
//! `GnuCOBOL`, Zig, Nim, Clojure, Kotlin/Native, Watcom, Borland and cfront had
//! no presence in either `convention_decoding.rs` or `detector_conventions.rs`
//! — neither of the two independent properties a detector has was checked for
//! any of them.

use rustre_demangle::lang_more::legacy_native::{demangle_gnucobol, detect_gnucobol};

/// The invariant, defined over the OUTPUT: no underscore survives.
///
/// Stated against the character rather than against a list of known-bad
/// symbols, so a shape nobody thought of still fails it.
#[test]
fn no_underscore_reaches_a_program_id() {
    let inputs = [
        "HELLO__WORLD",
        "A__B",
        "A____B",
        "A______B",
        "A__B__C",
        "A1__B2",
        "A___B",
        "A_____B",
        "PROGRAM__NAME__WITH__MANY__PARTS",
    ];
    let mut decoded = 0;
    let mut offenders = Vec::new();
    for s in inputs {
        let Some(out) = demangle_gnucobol(s) else {
            continue;
        };
        decoded += 1;
        let name = out.strip_prefix("PROGRAM-ID ").unwrap_or(&out);
        if name.contains('_') {
            offenders.push(format!("{s} => {out}"));
        }
    }
    assert!(decoded >= 6, "vacuous: only {decoded} decoded");
    assert!(
        offenders.is_empty(),
        "an underscore survived into a PROGRAM-ID, which cannot hold one:\n{}",
        offenders.join("\n")
    );
}

/// An odd underscore run is not `GnuCOBOL` output and must decline.
///
/// Discriminating: `A_B` passes whether or not runs are handled — it is the
/// case anyone writes first, and it was already right. `A___B` and `A_____B`
/// are what separate a correct rule from a plausible one.
#[test]
fn odd_underscore_runs_decline() {
    for sym in ["A_B", "A___B", "A_____B", "A__B___C", "A___B__C"] {
        assert_eq!(
            demangle_gnucobol(sym),
            None,
            "{sym} carries an odd underscore run, so it is not a mangled PROGRAM-ID"
        );
        assert!(!detect_gnucobol(sym), "the detector must not claim {sym}");
    }
}

/// Even runs decode, and each `__` becomes exactly one hyphen.
#[test]
fn even_runs_decode_one_hyphen_per_pair() {
    for (sym, want) in [
        ("HELLO__WORLD", "PROGRAM-ID HELLO-WORLD"),
        ("A__B__C", "PROGRAM-ID A-B-C"),
        ("A1__B2", "PROGRAM-ID A1-B2"),
        ("A____B", "PROGRAM-ID A--B"),
        ("A______B", "PROGRAM-ID A---B"),
    ] {
        assert_eq!(demangle_gnucobol(sym).as_deref(), Some(want), "{sym}");
        assert!(detect_gnucobol(sym), "detector must claim {sym}");
    }
}

/// The shapes outside the convention: a leading or trailing underscore, no
/// underscore at all, lowercase, and a non-uppercase first character.
#[test]
fn names_outside_the_convention_decline() {
    for sym in ["_A__B", "A__B_", "__AB", "AB__", "PROG", "hello__world", "1A__B"] {
        assert_eq!(demangle_gnucobol(sym), None, "{sym}");
        assert!(!detect_gnucobol(sym), "the detector must not claim {sym}");
    }
}
