//! Public enum variants that nothing constructs must stay documented as such.
//!
//! An unreachable variant is not harmless: a consumer matching on it writes a
//! branch that can never fire, and gets silence instead of an error. This crate
//! has already paid for that once — `MangleLanguage::Java` was unreachable from
//! `classify`, so `filter_by_language(…, Java)` returned nothing on JNI input.
//!
//! Four such variants remain, each marking a construct the corresponding parser
//! does not implement:
//!
//! * `GoSymbolKind::TypeAssertionThunk`
//! * `SwiftNode::Substitution`, `::Label`, `::Variadic`
//!
//! They are **not** wired up here. Deciding which Go symbols are genuinely
//! type-assertion thunks, or how Swift spells argument labels and variadics,
//! needs semantics neither ABI can supply — both are oracle-less. Guessing
//! would trade a documented gap for fabricated output, which this crate treats
//! as the worse of the two.
//!
//! What this file enforces is the *documentation*: the doc comment on each must
//! keep saying it is never produced, so the next reader is not misled into
//! writing a dead filter.

/// The doc comments must keep their "never produced" warning.
///
/// Checked against the source text rather than behaviour, because behaviour
/// cannot distinguish "unreachable" from "not exercised by these inputs" — the
/// vacuity problem. If someone implements one of these constructs, this test
/// fails and the annotation must be removed along with it, which is exactly the
/// review moment worth forcing.
#[test]
fn unreachable_variants_are_still_marked_unreachable() {
    let go = include_str!("../src/go_demangler.rs");
    let swift = include_str!("../src/swift_demangler.rs");

    for (src, marker, variant) in [
        (go, "**Never produced by this crate.**", "GoSymbolKind::TypeAssertionThunk"),
        (swift, "**Never produced.** Back-references", "SwiftNode::Substitution"),
        (swift, "**Never produced** — argument labels", "SwiftNode::Label"),
        (swift, "**Never produced** — variadic", "SwiftNode::Variadic"),
    ] {
        assert!(
            src.contains(marker),
            "{variant} lost its unreachability note — if it is now produced, \
             delete the note deliberately; if not, restore it"
        );
    }
}

/// Vacuity guard: the variants must still exist under those names.
///
/// Without this the test above would pass forever if the enums were renamed or
/// the variants deleted, since it only greps for prose.
#[test]
fn the_annotated_variants_still_exist() {
    let go = include_str!("../src/go_demangler.rs");
    let swift = include_str!("../src/swift_demangler.rs");

    assert!(go.contains("TypeAssertionThunk,"), "GoSymbolKind variant gone");
    for v in ["Substitution(usize),", "Label(String, Box<Self>),", "Variadic(Box<Self>),"] {
        assert!(swift.contains(v), "SwiftNode variant gone: {v}");
    }
}

/// D template arguments are decoded by code the live path cannot reach.
///
/// `d_demangler` has a `__T` branch in `parse_identifier`, a template-argument
/// loop, and a `parse_template_value`. None of it runs. In the D ABI a template
/// instance is a *length-prefixed* identifier whose body begins with `__T`
/// (`_D4main10__T3fooTiZ3fooFZv`), so at that position the parser sees a digit,
/// never `_` — the `__T` branch fires only for a form the grammar never emits.
/// The raw byte-copy path handles it instead, which is why the block is echoed
/// verbatim into the output.
///
/// This is pinned rather than fixed because the fix is the deferred one: the
/// crate has no D oracle and no D binary, so how a template instance *should*
/// render is not established here. What the test protects against is subtler
/// than the gap itself — someone repairing `parse_template_value` (whose `b'0'`
/// and `b'1'` arms are dead behind an `is_ascii_digit` branch above them, and
/// which never consumes the Type that the grammar puts before the Value) and
/// concluding from green tests that D templates now decode. They would not: the
/// function is never called.
///
/// The assertions are deliberately weak on *rendering* and strong on
/// *reachability*. They say the mangled block survives into the output, which
/// is exactly the observation that proves the argument parser was bypassed.
#[test]
fn d_template_arguments_are_echoed_because_their_parser_is_unreachable() {
    // Build the length prefix from the block; hand-counted prefixes have
    // produced fake defects in this crate repeatedly.
    let sym = |args: &str| {
        let block = format!("__T3foo{args}Z");
        format!("_D4main{}{block}3fooFZv", block.len())
    };

    let mut checked = 0;
    for args in ["Ti", "TiTAk", "Vii42", "ViN42", "Vin"] {
        let s = sym(args);
        let out = rustre_demangle::demangle(&s)
            .unwrap_or_else(|| panic!("{s} must still decode"))
            .demangled;

        // The signature is recovered correctly — the defect is confined to the
        // name, which is why this reads as an echo and not as fabrication.
        assert!(out.starts_with("void main."), "{s} => {out}");
        assert!(out.ends_with(".foo()"), "{s} => {out}");

        // The tell: raw mangling reaches the output verbatim. Had the template
        // argument parser run, `Ti` would have become `int` and the `__T`/`Z`
        // delimiters would be gone.
        assert!(
            out.contains(&format!("__T3foo{args}Z")),
            "template block was decoded, not echoed — the argument parser is \
             now reachable and this test's premise is stale: {s} => {out}"
        );
        checked += 1;
    }
    assert!(checked >= 5, "vacuous: only {checked} template shapes checked");

    // Control: the same `__T` WITHOUT a length prefix is the only shape that
    // reaches the template branch — and the grammar never emits it, so it is
    // rejected outright. This is what makes the branch dead rather than rare.
    assert!(
        rustre_demangle::demangle("_D4main__T3fooTiZ3fooFZv").is_none(),
        "the unprefixed form is not valid D and must not decode"
    );
}
