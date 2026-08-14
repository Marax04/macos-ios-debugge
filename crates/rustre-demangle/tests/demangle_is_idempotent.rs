//! Demangling a demangled name must not change it again.
//!
//! Consumers do double-demangle — a symbol passes through a pipeline that
//! cannot know whether an earlier stage already decoded it. A backend that
//! re-processes its own output into something *different* corrupts the name
//! silently, and no existing check looked at this: every invariant in this
//! suite compares one output against one input.
//!
//! The property holds. Over the 3161 decodable symbols in all four real corpora,
//! and over generated D, Swift and convention populations, the rendered string
//! is a fixed point in every case — the second pass either declines or returns
//! the identical string.
//!
//! **The `abi` field is not.** Three convention decoders render a dotted name
//! that the Go detector then claims, so a second pass reports `Go`:
//!
//! ```text
//!   camlStdlib__Printf__printf  =>  Stdlib.Printf.printf   [OCaml, then Go]
//!   pkg__child__proc            =>  pkg.child.proc         [Ada,   then Go]
//!   Java_com_example_Foo_bar    =>  com.example.Foo.bar    [Java,  then Go]
//! ```
//!
//! That matters because consumers route on `abi` — the argument that justified
//! fixing the Mach-O legacy-Rust label, where the rendered string was already
//! right and only the label was wrong.
//!
//! It is nonetheless **not fixable here**, and the numbers are why. Identity
//! echo cannot be the discriminator: 1809 of the 2163 real Go symbols render
//! identically to their input, so echoing is normal for this ABI. Capitalisation
//! cannot be either: 0 of those 2163 begin with an uppercase component, which
//! would separate `Stdlib.Printf.printf` — but `pkg.child.proc` and
//! `com.example.Foo.bar` are lowercase and would still be claimed, so the rule
//! buys one case out of three while adding a heuristic with no Go oracle behind
//! it. A bare lowercase dotted name genuinely *is* ambiguous; `pkg.child.proc`
//! is a plausible Go symbol.
//!
//! So the transitions are pinned below as known, not asserted away. If Go ever
//! gains ground truth, that test fails and the exclusion can go.

use rustre_demangle::ManglingAbi;

const CORPORA: [&str; 4] = [
    include_str!("data/real_symbols.txt"),
    include_str!("data/pdb_symbols.txt"),
    include_str!("data/import_symbols.txt"),
    include_str!("data/pdb_proc_symbols.txt"),
];

/// Symbols with no corpus: D, Swift, and the convention decoders. Length
/// prefixes computed, never hand-counted.
fn uncorpused() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tail in ["FiZv", "FZv", "FiiZi", "MxFNaZv", "FAyaZv", "FPiZv", "i"] {
        for parts in [vec!["main", "foo"], vec!["main", "Klass", "foo"]] {
            let mut s = String::from("_D");
            for p in &parts {
                s.push_str(&p.len().to_string());
                s.push_str(p);
            }
            s.push_str(tail);
            out.push(s);
        }
    }
    for tail in ["Sivp", "Sivg", "Sivs", "yyF", "SSvp"] {
        for parts in [vec!["main", "value"], vec!["main", "Foo"]] {
            let mut s = String::from("$s");
            for p in &parts {
                s.push_str(&p.len().to_string());
                s.push_str(p);
            }
            s.push_str(tail);
            out.push(s);
        }
    }
    out.extend(
        [
            "camlStdlib__Printf__printf",
            "camlList__map",
            "pkg__child__proc",
            "_ada_pkg__proc",
            "__mymod_MOD_solve",
            "Java_com_example_Foo_bar",
            "Java_pkg_Cls_m_1n",
            "luaopen_socket_core",
            "Init_my_ext_core",
        ]
        .iter()
        .map(|s| (*s).to_string()),
    );
    out
}

/// The invariant: the rendered string is a fixed point.
#[test]
fn the_rendered_string_is_a_fixed_point() {
    let mut checked = 0;
    let mut unstable = Vec::new();

    let corpus = CORPORA.iter().flat_map(|b| b.lines()).map(str::trim).map(str::to_owned);
    for s in corpus.chain(uncorpused()) {
        if s.is_empty() {
            continue;
        }
        let Some(first) = rustre_demangle::demangle(&s) else { continue };
        checked += 1;
        if let Some(second) = rustre_demangle::demangle(&first.demangled)
            && second.demangled != first.demangled
        {
            unstable.push(format!(
                "{s}\n     1st: {}\n     2nd: {}",
                first.demangled, second.demangled
            ));
        }
    }
    assert!(checked > 3000, "vacuous: only {checked} symbols");
    assert!(unstable.is_empty(), "{} not idempotent:\n{unstable:#?}", unstable.len());
}

/// Stability must survive repetition, not just one extra pass — a decoder that
/// converges after two rounds would satisfy the test above.
#[test]
fn repeated_passes_do_not_drift() {
    for s in uncorpused() {
        let Some(first) = rustre_demangle::demangle(&s) else { continue };
        let mut cur = first.demangled.clone();
        for round in 1..=4 {
            let Some(next) = rustre_demangle::demangle(&cur) else { break };
            assert_eq!(next.demangled, cur, "{s} drifted on round {round}");
            cur = next.demangled;
        }
    }
}

/// The known `abi`-label transitions, pinned rather than asserted away. See the
/// module note for the measurements that rule out a fix.
#[test]
fn the_known_abi_relabellings_are_exactly_these() {
    let expected = [
        ("camlStdlib__Printf__printf", ManglingAbi::OCaml),
        ("pkg__child__proc", ManglingAbi::Ada),
        ("Java_com_example_Foo_bar", ManglingAbi::Java),
    ];
    for (sym, first_abi) in expected {
        let first = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(first.abi, first_abi, "{sym}");

        let second = rustre_demangle::demangle(&first.demangled)
            .unwrap_or_else(|| panic!("{sym}: output no longer re-decodes; update this note"));
        assert_eq!(second.demangled, first.demangled, "{sym}: string must still be stable");
        assert_eq!(
            second.abi,
            ManglingAbi::Go,
            "{sym}: relabelling changed; if Go was tightened, remove this exclusion"
        );
    }
}

/// Bounds the exclusion by *class*, not by example.
///
/// The reclaim is a property of the three conventions that render a dotted
/// name, so it applies to every symbol they decode — not just the three quoted
/// above. What must not happen is a *fourth* decoder joining them: an ABI whose
/// output is re-claimed is a decoder emitting something that reads as another
/// language's input, and only these three are known to.
#[test]
fn only_the_dotted_conventions_have_their_output_reclaimed() {
    let dotted = [ManglingAbi::OCaml, ManglingAbi::Ada, ManglingAbi::Java];
    let mut surprises = Vec::new();
    let mut reclaimed = 0;

    for s in uncorpused() {
        let Some(first) = rustre_demangle::demangle(&s) else { continue };
        let Some(second) = rustre_demangle::demangle(&first.demangled) else { continue };
        if second.abi == first.abi {
            continue;
        }
        reclaimed += 1;
        if !(dotted.contains(&first.abi) && second.abi == ManglingAbi::Go) {
            surprises.push(format!(
                "{s} -> {} : {:?} then {:?}",
                first.demangled, first.abi, second.abi
            ));
        }
    }
    assert!(surprises.is_empty(), "new output-reclaim cases: {surprises:#?}");
    assert!(reclaimed > 0, "vacuous: the reclaim stopped happening — update the note");
}
