//! Nothing may appear in a Swift rendering that is not in the symbol, and the
//! same tail must decode the same way wherever it appears.
//!
//! `tests/swift_completeness.rs` is defined over the *input*: every named
//! component must survive. That catches **loss of a name** and is structurally
//! blind to two other failures — invention, and loss of everything that is not
//! a name. This file is the counterpart, and the second blind spot is where it
//! found a real defect.
//!
//! Swift has no oracle among this crate's dependencies, so neither check can
//! ask what the right answer is. Both work by comparing output against input
//! alone.
//!
//! Every symbol here is built by a generator that computes its own length
//! prefixes. A hand-miscounted prefix yields a truncated but *correct*
//! decoding, which reads exactly like a demangler bug — the trap
//! `swift_completeness` documents at length.

use std::collections::{BTreeMap, BTreeSet};

/// `$s` + length-prefixed components + a raw tail.
fn sym(parts: &[&str], tail: &str) -> String {
    let mut s = String::from("$s");
    for p in parts {
        s.push_str(&p.len().to_string());
        s.push_str(p);
    }
    s.push_str(tail);
    s
}

fn render(s: &str) -> String {
    rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode")).demangled
}

/// Length-prefixed identifiers, extracted lexically. Conservative: a digit run
/// must be followed by exactly that many identifier characters.
fn identifiers(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && b[i] != b'0' {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if let Ok(n) = s[i..j].parse::<usize>()
                && n >= 1
                && j + n <= b.len()
            {
                let cand = &s[j..j + n];
                if cand.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    out.push(cand.to_owned());
                    i = j + n;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Maximal identifier runs of a rendered string.
fn idents(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Words the renderer contributes itself: the entity kinds it names, and the
/// standard-library types the one-letter substitutions expand to (`Si`, `SS`,
/// `Sb`, `Sd`). Anything outside this set has to come from the symbol.
const VOCABULARY: [&str; 9] =
    ["Swift", "Int", "String", "Bool", "Double", "getter", "setter", "unparsed", "modify"];

/// The generated population, plus settled real-world shapes.
fn population() -> Vec<String> {
    let mut out: Vec<String> = [
        "$s10Foundation3URLV6stringACSgSS_tcfc",
        "$s10Foundation4DataV5countSivg",
        "$s4test3FooC3baryyF",
        "$s7SwiftUI4TextV6stringACSS_tcfc",
        "$s4main3FooCACycfc",
        "$s4main3FooV3bazyySi_SStF",
        "$s4main1AC1BCfd",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();

    for module in ["main", "app", "MyModule"] {
        for name in ["bar", "value", "someMember"] {
            for tail in ["Sivp", "Sivg", "Sivs", "SSvp", "Sbvg", "Sdvg", "yyF"] {
                out.push(sym(&[module, name], tail));
                for ty in ["Foo", "LongTypeName"] {
                    out.push(sym(&[module, ty], &format!("V{}{name}{tail}", name.len())));
                    out.push(sym(&[module, ty], &format!("C{}{name}{tail}", name.len())));
                }
            }
        }
    }
    out
}

/// Splits a rendering into the decoded head and the raw `[unparsed …]` echo.
fn split_unparsed(rendered: &str) -> (&str, Option<&str>) {
    match rendered.split_once(" [unparsed ") {
        Some((head, rest)) => (head, Some(rest.trim_end_matches(']'))),
        None => (rendered, None),
    }
}

/// **The defect.** A variable's `<type>v[<accessor>]` tail means the same thing
/// at every nesting depth, so it must render the same way.
///
/// It did not. The tail was implemented only for members of a nominal type; on
/// a module-level global the identical suffix fell through to the function
/// loop, which discards the types it collected unless an `F` arrives:
///
/// ```text
///   $s4main8MyStructV5valueSivp  =>  main.MyStruct.value : Swift.Int
///   $s4main6globalSivp           =>  main.global [unparsed Sivp]
/// ```
///
/// Discriminating by construction: the expected decoration is not written down
/// here, it is *taken from the member form* and then required of the module
/// form. A change that alters both consistently still passes; one that fixes
/// only one of them, or neither, fails.
#[test]
fn a_variable_tail_renders_the_same_at_every_nesting_depth() {
    let mut checked = 0;
    for tail in ["Sivp", "Sivg", "Sivs", "SSvp", "Sbvg", "Sdvg", "Sivr", "SivM"] {
        let member = render(&sym(&["main", "Foo"], &format!("V5value{tail}")));
        let decoration = member
            .strip_prefix("main.Foo.value")
            .unwrap_or_else(|| panic!("member form did not decode as expected: {member}"));

        let module = render(&sym(&["main", "value"], tail));
        assert_eq!(
            module,
            format!("main.value{decoration}"),
            "tail {tail} decodes differently at module level"
        );
        assert!(!module.contains("[unparsed"), "{tail} left unparsed at module level: {module}");
        checked += 1;
    }
    assert!(checked >= 8, "vacuous: {checked} tails");
}

/// Soundness: every identifier in the decoded head comes from the symbol or
/// from the renderer's own vocabulary.
#[test]
fn no_swift_rendering_invents_an_identifier() {
    let pop = population();
    assert!(pop.len() > 200, "vacuous: {} symbols", pop.len());

    let mut invented = Vec::new();
    for s in &pop {
        let rendered = render(s);
        let (head, _) = split_unparsed(&rendered);
        let src: BTreeSet<String> = identifiers(s).into_iter().collect();
        for id in idents(head) {
            if !src.contains(&id) && !VOCABULARY.contains(&id.as_str()) {
                invented.push(format!("{id:?} in {s}  ->  {rendered}"));
            }
        }
    }
    assert!(invented.is_empty(), "{} invented: {invented:#?}", invented.len());
}

/// The `[unparsed …]` marker exists to be honest about a tail the parser did
/// not consume, which is only true if it echoes the symbol verbatim. A mutated
/// echo would read exactly like a faithful one.
#[test]
fn an_unparsed_marker_echoes_the_symbol_verbatim() {
    let mut seen = 0;
    for s in population() {
        let rendered = render(&s);
        if let (_, Some(tail)) = split_unparsed(&rendered) {
            assert!(s.contains(tail), "{s} echoes {tail:?}, which is not in it");
            seen += 1;
        }
    }
    assert!(seen > 0, "vacuous: no unparsed markers in the population");
}

/// Rendering changes are where collisions get introduced in this crate — four
/// times so far — so any change to the Swift renderer has to face this.
///
/// One collision is deliberate and excluded here: the nominal-kind marker is
/// not rendered, so `…3FooV3barSivp` and `…3FooC3barSivp` both give
/// `main.Foo.bar : Swift.Int`. That matches Swift's own simplified form, and
/// the two cannot denote different entities in the first place — a module may
/// not declare both a `struct Foo` and a `class Foo`, so the pair is
/// unreachable in real code rather than ambiguous. Changing it would mean
/// inventing a presentation with no oracle to justify it, which this crate
/// refuses for Swift. The population below therefore varies the *path*, not the
/// kind marker.
#[test]
fn distinct_entities_render_distinctly() {
    let mut pop: Vec<String> = Vec::new();
    for module in ["main", "app", "MyModule"] {
        for name in ["bar", "value", "someMember"] {
            for tail in ["Sivp", "Sivg", "Sivs", "SSvp", "Sbvg", "Sdvg", "yyF"] {
                pop.push(sym(&[module, name], tail));
                // Distinct type names per kind, so no two symbols name the same
                // path with a different marker.
                pop.push(sym(&[module, "StructTy"], &format!("V{}{name}{tail}", name.len())));
                pop.push(sym(&[module, "ClassTy"], &format!("C{}{name}{tail}", name.len())));
            }
        }
    }

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for s in &pop {
        let r = render(s);
        if let Some(prev) = seen.insert(r.clone(), s.clone()) {
            assert_eq!(&prev, s, "{prev} and {s} both render {r}");
        }
    }
    assert_eq!(seen.len(), pop.len(), "collisions among {} symbols", pop.len());
    assert!(seen.len() > 150, "vacuous: {} distinct renderings", seen.len());
}

/// Pins the exclusion above, so it stays a *known* collision rather than
/// quietly becoming the general case. If the renderer ever learns to name the
/// nominal kind, this fails and the exclusion can be removed.
#[test]
fn the_nominal_kind_marker_is_deliberately_not_rendered() {
    let as_struct = render(&sym(&["main", "Foo"], "V3barSivp"));
    let as_class = render(&sym(&["main", "Foo"], "C3barSivp"));
    assert_eq!(as_struct, as_class, "kind marker is now rendered; update the exclusion");
    assert_eq!(as_struct, "main.Foo.bar : Swift.Int");
}
