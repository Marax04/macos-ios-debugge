//! A truncated symbol may degrade, but it may not invent.
//!
//! Truncation is where a decoder is most tempted to fabricate: it has partial
//! structure and must decide what to do with it. Nothing in this suite had ever
//! fed a decoder a prefix — every other invariant compares one whole input
//! against one output.
//!
//! Two properties, both established by probing before they were written down.
//!
//! **No fabrication.** Every identifier in the rendering of a truncated symbol
//! must be traceable to that truncated input. Verified over 31078 truncated Go
//! decodes and the generated D and Swift populations: zero invented tokens.
//!
//! **No structurally corrupt fields.** `namespace`, `class`, `function`,
//! `return_type` and each `args` entry must have balanced brackets. A field
//! split with a naive `rsplit("::")` cuts through `::<&str>` and through
//! `std::vector<int, std::allocator<int>>`, and the result is a field that
//! cannot be reassembled — the bracket-unaware-split defect that
//! `go_completeness` itself shipped in its first three revisions.
//!
//! A note on the probe, because the first version of it lied. Tokenising a
//! mangled symbol with a generic identifier scanner glues the length prefix to
//! the name — `$s4main` scans as one token `s4main`, so `main` looks invented
//! in every Swift rendering. The input side must be read with a
//! length-prefix-aware extractor, and the `[unparsed …]` echo must be excluded,
//! since it is a literal copy of the input by construction. Before those two
//! corrections the probe reported 34 "fabrications", all of them artefacts.

use rustre_demangle::ManglingAbi;
use std::collections::BTreeSet;

/// Maximal identifier runs — how a fabricated name would have to appear.
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

/// Length-prefixed identifiers, as D and Swift actually encode them.
fn prefixed(s: &str) -> BTreeSet<String> {
    let b = s.as_bytes();
    let mut out = BTreeSet::new();
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
                    out.insert(cand.to_owned());
                    i = j + n;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Words each renderer contributes itself.
///
/// Kept **per ABI** rather than pooled. A single shared list is weaker than it
/// looks: D's `int` would excuse a fabricated `[int]` in a *Go* rendering, and
/// the negative control below caught exactly that.
const fn vocabulary(abi: ManglingAbi) -> &'static [&'static str] {
    match abi {
        ManglingAbi::Go => &["closure", "descriptor", "for"],
        ManglingAbi::Swift => &[
            "Swift", "Int", "String", "Bool", "Double", "getter", "setter", "unparsed", "modify",
        ],
        ManglingAbi::D => &[
            "void", "int", "char", "bool", "double", "immutable", "const", "shared", "inout",
            "pure", "nothrow", "ref", "property", "trusted", "safe", "nogc", "live", "scope",
            "return", "function", "delegate", "noreturn", "__vector",
        ],
        _ => &[],
    }
}

/// Everything after the honest `[unparsed …]` marker is a literal copy of the
/// input, so it cannot be fabrication and is checked separately.
fn decoded_head(rendered: &str) -> &str {
    rendered.split_once(" [unparsed ").map_or(rendered, |(head, _)| head)
}

fn invented(input: &str, rendered: &str, abi: ManglingAbi) -> Vec<String> {
    let mut src: BTreeSet<String> = idents(input).into_iter().collect();
    src.extend(prefixed(input));
    let vocab = vocabulary(abi);
    idents(decoded_head(rendered))
        .into_iter()
        .filter(|id| !src.contains(id) && !vocab.contains(&id.as_str()))
        .filter(|id| !id.chars().all(|c| c.is_ascii_digit()))
        .collect()
}

/// D and Swift, which have no corpus. Length prefixes computed.
fn generated() -> Vec<String> {
    let mut out = Vec::new();
    for tail in ["FiZv", "FZv", "FiiZi", "MxFNaZv", "FAyaZv", "FDFiZvZv", "FNiZv", "i"] {
        for parts in [vec!["main", "foo"], vec!["pkg", "mod", "Type", "meth"]] {
            let mut s = String::from("_D");
            for p in &parts {
                s.push_str(&p.len().to_string());
                s.push_str(p);
            }
            s.push_str(tail);
            out.push(s);
        }
    }
    for tail in ["Sivp", "Sivg", "yyF", "SSvp", "V5valueSivg", "C3barSivs"] {
        for parts in [vec!["main", "value"], vec!["Foundation", "Data"]] {
            let mut s = String::from("$s");
            for p in &parts {
                s.push_str(&p.len().to_string());
                s.push_str(p);
            }
            s.push_str(tail);
            out.push(s);
        }
    }
    out
}

/// The invariant, over every prefix of every Go symbol in the real corpus.
#[test]
fn a_truncated_go_symbol_invents_nothing() {
    let mut checked = 0usize;
    let mut bad = Vec::new();

    for s in include_str!("data/real_symbols.txt").lines().map(str::trim) {
        if s.is_empty() || s.starts_with(['.', '_', '?']) {
            continue;
        }
        if !rustre_demangle::demangle(s).is_some_and(|r| r.abi == ManglingAbi::Go) {
            continue;
        }
        for cut in 1..s.len() {
            if !s.is_char_boundary(cut) {
                continue;
            }
            let part = &s[..cut];
            let Some(r) = rustre_demangle::demangle(part) else { continue };
            checked += 1;
            for id in invented(part, &r.demangled, r.abi) {
                bad.push(format!("{id:?} in {part:?} -> {}", r.demangled));
            }
        }
    }
    assert!(checked > 25_000, "vacuous: only {checked} truncated decodes");
    assert!(bad.is_empty(), "{} invented under truncation: {:#?}", bad.len(), &bad[..bad.len().min(20)]);
}

/// Same invariant for the two ABIs with no oracle, where fabrication has
/// nothing to contradict it.
#[test]
fn a_truncated_d_or_swift_symbol_invents_nothing() {
    let mut checked = 0usize;
    let mut bad = Vec::new();

    for full in generated() {
        for cut in 1..full.len() {
            if !full.is_char_boundary(cut) {
                continue;
            }
            let part = &full[..cut];
            let Some(r) = rustre_demangle::demangle(part) else { continue };
            checked += 1;
            for id in invented(part, &r.demangled, r.abi) {
                bad.push(format!("{id:?} in {part:?} -> {}", r.demangled));
            }
        }
    }
    assert!(checked > 100, "vacuous: only {checked} truncated decodes");
    assert!(bad.is_empty(), "{} invented under truncation: {bad:#?}", bad.len());
}

/// The probe must be able to fail — the corrections described in the module
/// note each made it weaker, and this is what stops it being weakened to
/// nothing.
#[test]
fn the_check_catches_a_fabrication() {
    let input = "internal/godebug.update.func2";
    let go = ManglingAbi::Go;
    assert!(invented(input, "internal/godebug.update {closure-1 #2}", go).is_empty());
    for fake in [
        "internal/godebug.update.mysteryHelper",
        "runtime.update {closure-1 #2}",
        // `int` is D vocabulary, not Go's. A pooled list would excuse this.
        "internal/godebug.update[int]",
    ] {
        assert!(!invented(input, fake, go).is_empty(), "{fake} slipped through");
    }
}

/// Structured fields must be reassemblable: brackets balanced in every one.
///
/// This is what a bracket-unaware split shows as — cutting `::<&str>` or
/// `std::vector<int, std::allocator<int>>` leaves a field with a dangling
/// bracket. Itanium is the load-bearing case with 847 real symbols and deep
/// template nesting.
#[test]
fn structured_fields_have_balanced_brackets() {
    fn unbalanced(t: &str) -> bool {
        let (mut angle, mut square, mut round) = (0i32, 0i32, 0i32);
        for ch in t.chars() {
            match ch {
                '<' => angle += 1,
                '>' => angle -= 1,
                '[' => square += 1,
                ']' => square -= 1,
                '(' => round += 1,
                ')' => round -= 1,
                _ => {}
            }
            if angle < 0 || square < 0 || round < 0 {
                return true;
            }
        }
        angle != 0 || square != 0 || round != 0
    }

    let corpora = [
        include_str!("data/real_symbols.txt"),
        include_str!("data/pdb_symbols.txt"),
        include_str!("data/pdb_proc_symbols.txt"),
    ];
    let mut checked = 0usize;
    let mut bad = Vec::new();
    let mut abis = BTreeSet::new();

    for body in corpora {
        for s in body.lines().map(str::trim) {
            let Some(r) = rustre_demangle::demangle(s) else { continue };
            checked += 1;
            abis.insert(format!("{:?}", r.abi));
            let fields = [
                ("namespace", r.namespace.clone().unwrap_or_default()),
                ("class", r.class.clone().unwrap_or_default()),
                ("function", r.function.clone()),
                ("return_type", r.return_type.clone().unwrap_or_default()),
            ];
            for (label, value) in fields {
                if unbalanced(&value) {
                    bad.push(format!("{s}: {label} = {value:?}"));
                }
            }
            for (i, a) in r.args.iter().enumerate() {
                if unbalanced(a) {
                    bad.push(format!("{s}: args[{i}] = {a:?}"));
                }
            }
        }
    }
    assert!(checked > 3000, "vacuous: {checked} symbols");
    assert!(abis.len() >= 4, "vacuous: only {abis:?} exercised");
    assert!(bad.is_empty(), "{} unbalanced fields: {:#?}", bad.len(), &bad[..bad.len().min(15)]);
}
