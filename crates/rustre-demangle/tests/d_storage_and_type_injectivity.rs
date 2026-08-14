//! D parameter *storage classes* and *type constructors* must not collide.
//!
//! `tests/d_type_injectivity.rs` proves no two type-constructor sequences
//! collapse, and `d_decoding.rs::distinct_type_codes_decode_distinctly` proves
//! no two type codes do. Both compare one dimension against itself. A D
//! parameter is written `<storage><type>`, so there is a second axis, and a
//! collision *across* the two satisfies every existing check:
//!
//! ```text
//!   _D4main3fooFKiZv  =>  void main.foo(ref int)     K = the `ref` storage class
//!   _D4main3fooFRiZv  =>  void main.foo(ref int)     R = a `ref` type constructor
//! ```
//!
//! Two distinct linker symbols, one rendering. Injectivity needs no oracle —
//! it asks whether two inputs collapse, not what the right answer is — which is
//! the same reason the neighbouring D checks can exist at all.
//!
//! Measured over storage × constructor × base: **3 collisions, all this one
//! pair.** Nothing else on either axis collides.
//!
//! The final test widens this to D's whole function grammar — linkage ×
//! attributes × storage × constructor × base × terminator × return, 15120
//! symbols — because a two-axis check is only one step better than a one-axis
//! check. Over the full product exactly **two** collision families exist, and
//! both are named exclusions: this `K`/`R` pair, and the variadic terminators
//! `X` and `Y`, which share a rendering *deliberately* (see
//! `d_decoding.rs::all_three_parameter_terminators_end_the_list` — D spells
//! both `...` in source, so one rendering is faithful rather than lossy).
//!
//! Which side is wrong is *not* decidable here, and the open decision is
//! recorded as an ignored test below rather than guessed at. The evidence to
//! hand points at `R`: `parse_param_storage` implements exactly D's documented
//! storage set `J K L M`, with `ref` as `K`; `R` is the `extern(C++)` linkage
//! sigil in three other places in the same file; and the `R => ref <type>` arm
//! carries a bare comment, no citation and no test of its own. But "remove a
//! decode" is a claim about D's grammar, and this crate has no D ground truth —
//! the same gate that blocks the `__T…` template names and the `Q<n>`
//! back-references.

use std::collections::BTreeMap;

/// `void main.foo(<code>)`.
fn symbol(code: &str) -> String {
    format!("_D4main3fooF{code}Zv")
}

fn demangle(code: &str) -> Option<String> {
    rustre_demangle::demangle(&symbol(code)).map(|r| r.demangled)
}

/// D's documented parameter storage classes, plus the empty case.
const STORAGE: [&str; 5] = ["", "J", "K", "L", "M"];

/// Type constructors, plus the empty case.
const CTORS: [&str; 13] = ["", "P", "A", "R", "O", "x", "y", "G3", "D", "C", "S", "E", "T"];

const BASES: [&str; 3] = ["i", "a", "d"];

/// The known collision, kept as a named exclusion so it cannot quietly become
/// the general case — the discipline used for Swift's unrendered nominal-kind
/// marker.
fn is_known_collision(codes: &[String]) -> bool {
    let mut sorted: Vec<&str> = codes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.len() == 2
        && sorted[0].strip_prefix('K') == sorted[1].strip_prefix('R')
        && sorted[0].starts_with('K')
        && sorted[1].starts_with('R')
}

/// The invariant across both axes.
#[test]
fn storage_and_type_constructors_do_not_collide() {
    let mut by_output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut decoded = 0;

    for s in STORAGE {
        for c in CTORS {
            for b in BASES {
                let code = format!("{s}{c}{b}");
                if let Some(rendered) = demangle(&code) {
                    decoded += 1;
                    by_output.entry(rendered).or_default().push(code);
                }
            }
        }
    }

    assert!(decoded > 100, "vacuous: only {decoded} decoded");

    let unexpected: Vec<_> = by_output
        .iter()
        .filter(|(_, codes)| codes.len() > 1 && !is_known_collision(codes))
        .map(|(out, codes)| format!("{codes:?} -> {out}"))
        .collect();
    assert!(unexpected.is_empty(), "new cross-axis collisions: {unexpected:#?}");
}

/// Vacuity guard for the exclusion: the known collision must still be there.
///
/// Without this the test above passes just as well if `K` or `R` stops decoding
/// for an unrelated reason, and the exclusion would silently become dead.
#[test]
fn the_known_collision_is_still_the_only_one() {
    let collisions = BASES
        .iter()
        .filter(|b| demangle(&format!("K{b}")).is_some())
        .filter(|b| demangle(&format!("K{b}")) == demangle(&format!("R{b}")))
        .count();
    assert_eq!(collisions, BASES.len(), "K/R no longer collide — remove the exclusion");
}

/// The open decision, asserted as the behaviour that is *not* implemented.
///
/// `K` is D's `ref` parameter storage class; whatever `R` is in this position,
/// it cannot also be `ref`, because then no consumer could tell the two symbols
/// apart. Settling it needs a real D binary or a D oracle — see the module note
/// for why the evidence points at `R` without being enough to act on.
#[test]
#[ignore = "needs a D oracle: which of K/R is the real `ref` is not decidable here"]
fn a_storage_class_and_a_type_constructor_render_differently() {
    for b in BASES {
        assert_ne!(
            demangle(&format!("K{b}")),
            demangle(&format!("R{b}")),
            "K{b} and R{b} are different symbols and must not render alike"
        );
    }
}


/// The same invariant over D's entire function grammar.
///
/// Six axes crossed at once, 15120 symbols. A per-axis test cannot see a
/// collision that needs two axes to express, and this crate had three per-axis
/// D tests and no cross-axis one — which is how the `K`/`R` pair survived.
///
/// Exactly two collision families exist over the full product, both excluded by
/// name below. Anything else is a new finding.
#[test]
fn the_whole_function_grammar_is_injective() {
    const LINKAGE: [&str; 6] = ["F", "U", "W", "V", "R", "Y"];
    const ATTRS: [&str; 7] = ["", "Na", "Nb", "NaNb", "Ni", "Nk", "Nm"];
    const TERM: [&str; 3] = ["Z", "X", "Y"];
    const RET: [&str; 2] = ["v", "i"];

    let mut by_output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut decoded = 0;

    for l in LINKAGE {
        for a in ATTRS {
            for s in STORAGE {
                for c in CTORS {
                    for b in BASES {
                        for t in TERM {
                            for r in RET {
                                let tail = format!("{l}{a}{s}{c}{b}{t}{r}");
                                let sym = format!("_D4main3foo{tail}");
                                if let Some(res) = rustre_demangle::demangle(&sym) {
                                    decoded += 1;
                                    by_output.entry(res.demangled).or_default().push(tail);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(decoded > 10_000, "vacuous: only {decoded} decoded");

    let unexpected: Vec<_> = by_output
        .iter()
        .filter(|(_, codes)| codes.len() > 1)
        .filter(|(_, codes)| !is_known_family(codes))
        .map(|(out, codes)| format!("{codes:?} -> {out}"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "{} new collision families: {:#?}",
        unexpected.len(),
        &unexpected[..unexpected.len().min(10)]
    );
}

/// Whether a collision group is explained by the two known alternations.
///
/// Both must be folded **together**: over the full product a group can combine
/// them, giving four codes that differ in `K`/`R` *and* in `X`/`Y` at once. A
/// predicate that folds one family at a time reports those as new findings —
/// which is what the first version of this test did.
/// The folding is **positional**, which matters: `R` is also the `extern(C++)`
/// linkage sigil and `Y` the `extern(Objective-C)` one, both at index 0, and the
/// terminator is the second-to-last byte. Folding them everywhere happens to be
/// safe only because no group can mix a linkage with a storage class — an
/// accident of the alphabets, not a property worth relying on.
fn is_known_family(codes: &[String]) -> bool {
    let normalise = |s: &str| -> String {
        let n = s.len();
        s.char_indices()
            .map(|(i, c)| match c {
                // `R` as a type constructor: anywhere but the linkage slot.
                'R' if i > 0 => 'K',
                // `Y` as a variadic terminator: the byte before the return type.
                'Y' if i + 2 == n => 'X',
                other => other,
            })
            .collect()
    };
    let first = normalise(&codes[0]);
    codes.iter().all(|c| normalise(c) == first)
}
