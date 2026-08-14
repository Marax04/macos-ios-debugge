//! `SymbolConfidence::new` is documented as producing "a value in [0.0, 1.0],
//! clamped", but it was written with `f64::clamp`, which **propagates NaN**
//! instead of bounding it.
//!
//! A NaN confidence is not simply an odd number. Every comparison with NaN is
//! false, so the entry:
//!   * fails `meets_threshold` at *every* threshold, including `0.0`;
//!   * is never replaced during merging (`other > self` is false), so it is
//!     sticky — a better symbol cannot displace it;
//!   * is not reported by `low_confidence` either, since `<` is false too.
//!
//! It becomes unusable *and* invisible, which is the failure mode this codebase
//! keeps producing: silent, not loud.

use rustre_symbols::symbol_table_builder::SymbolConfidence;

/// The special values an `f64` argument can carry.
fn specials() -> Vec<(&'static str, f64)> {
    vec![
        ("zero", 0.0),
        ("neg zero", -0.0),
        ("half", 0.5),
        ("one", 1.0),
        ("above one", 1.5),
        ("large", 1e300),
        ("negative", -1.0),
        ("pos infinity", f64::INFINITY),
        ("neg infinity", f64::NEG_INFINITY),
        ("NaN", f64::NAN),
    ]
}

#[test]
fn the_constructor_always_produces_a_value_in_range() {
    let cases = specials();
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for (label, v) in &cases {
        let c = SymbolConfidence::new(*v).value();
        if !c.is_finite() {
            divergences.push(format!("new({label}) = {c}, not finite"));
        } else if !(0.0..=1.0).contains(&c) {
            divergences.push(format!("new({label}) = {c}, outside [0,1]"));
        }
        checked += 1;
    }

    assert_eq!(checked, 10, "anti-vacuity: every special value exercised");
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn a_nan_confidence_cannot_make_a_symbol_invisible() {
    // The decisive consequence rather than "the value is finite": a confidence
    // that fails `meets_threshold(0.0)` can never be selected by any filter, at
    // any setting. No value in [0,1] can do that.
    let c = SymbolConfidence::new(f64::NAN);

    assert!(
        c.meets_threshold(0.0),
        "a NaN-derived confidence ({c}) meets no threshold at all, so the symbol \
         disappears from every filtered view"
    );
}

#[test]
fn a_nan_confidence_cannot_become_unmergeable() {
    // Merging keeps the higher confidence (`other > self`). With NaN on either
    // side that comparison is false, so a NaN entry is sticky: a better symbol
    // cannot displace it, and it cannot displace anything.
    let nan = SymbolConfidence::new(f64::NAN);
    let good = SymbolConfidence::new(0.9);

    assert!(
        good.value() > nan.value(),
        "a real confidence ({good}) must be able to displace a NaN-derived one ({nan})"
    );
}

#[test]
fn ordinary_values_are_untouched_and_the_bounds_still_saturate() {
    // Premise: the assertions above are not passing because everything now
    // collapses onto a single value.
    assert!((SymbolConfidence::new(0.5).value() - 0.5).abs() < f64::EPSILON);
    assert!((SymbolConfidence::new(1.5).value() - 1.0).abs() < f64::EPSILON);
    assert!((SymbolConfidence::new(-1.0).value() - 0.0).abs() < f64::EPSILON);
    assert!(SymbolConfidence::new(0.9).value() > SymbolConfidence::new(0.1).value());
}
