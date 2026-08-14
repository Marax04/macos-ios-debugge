//! Feeding a rendering back in must not corrupt it.
//!
//! Double-demangling is not a supported operation, but it happens: a pipeline
//! that demangles a symbol table twice, a tool that stores rendered names and
//! later re-processes them. The failure that matters is not "it decodes again"
//! — it is **decoding to something different**, because that silently rewrites
//! a name that was already correct.
//!
//! Sweeping the real corpora this way found a detector claiming plain prose:
//!
//! ```text
//! "typeinfo for __cxxabiv1::__class_type_info"      (already demangled C++)
//!   -> "typeinfo for :_cxxabiv1::__class.type (info)"
//! ```
//!
//! `detect_ghc` matches any name ending in a GHC suffix (`_info`, `_closure`,
//! `_entry`, …) with enough underscores, and had no rule about the characters
//! in between. A GHC symbol is **z-encoded** — every character outside
//! `[A-Za-z0-9_]` is escaped, `zc` for `:` and `ZL` for `(` — so one can never
//! contain whitespace or punctuation. That is the anchor for the fix: it comes
//! from the encoding, not from a heuristic about what looks like prose.
//!
//! Same shape as `_R` claiming `_RTC_Initialize` and `_T` claiming
//! `_TIFFOpen`, with the extra sting that the output was actively corrupted
//! rather than merely declined.

/// Renderings that must not be re-claimed and rewritten.
const ALREADY_DEMANGLED: &[&str] = &[
    "typeinfo for __cxxabiv1::__class_type_info",
    "typeinfo name for __cxxabiv1::__class_type_info",
    "typeinfo for __cxxabiv1::__si_class_type_info",
    "typeinfo name for __cxxabiv1::__si_class_type_info",
];

#[test]
fn a_demangled_cxx_name_is_not_claimed_by_the_ghc_detector() {
    for text in ALREADY_DEMANGLED {
        let got = rustre_demangle::demangle(text).map(|r| r.demangled);
        assert!(
            got.as_deref().is_none_or(|d| d == *text),
            "already-demangled text was rewritten: {text:?} -> {got:?}"
        );
    }
}

/// The narrow rule, stated directly: a GHC symbol contains only
/// `[A-Za-z0-9_]`.
///
/// Both directions matter. Rejecting punctuation must not cost a real GHC
/// symbol, so the positive cases are pinned beside the negative ones — a fix
/// that simply tightened the detector into uselessness would pass the sweep
/// above while losing every Haskell symbol.
#[test]
fn the_ghc_detector_takes_only_z_encodable_names() {
    use rustre_demangle::lang_extra::detect_ghc;

    // Real z-encoded shapes must still be claimed.
    for sym in [
        "base_GHCziBase_map_closure",
        "base_GHCziBase_zdfEqInt_info",
        "main_Main_main_entry",
    ] {
        assert!(detect_ghc(sym), "{sym} is a GHC symbol and must be claimed");
    }

    // Anything a z-encoding cannot produce must not be.
    for text in [
        "typeinfo for __cxxabiv1::__class_type_info",
        "std::vector<int>::push_back_info",
        "some name with spaces_info",
    ] {
        assert!(
            !detect_ghc(text),
            "{text:?} cannot be a z-encoded symbol but was claimed"
        );
    }
}

/// No corpus rendering may re-decode into a *different* string.
///
/// Stable re-decoding is fine — many Go names are already readable and decode
/// to themselves. What this forbids is a rewrite.
///
/// **Go is excluded, and the reason is a property of Go rather than a
/// convenience.** Its renderings are deliberately *not* in the input language:
/// the backend strips the synthetic `go.shape.` qualifier, rewrites the
/// `type:`/`go:` namespaces, spells closures `{closure-1 #5}`, and inserts a
/// space after commas in generic argument lists. Re-feeding such a string is
/// not "demangling the same symbol again", it is parsing a different language,
/// and 38 Go symbols round-trip into a reshuffled — not corrupted — form
/// because of it.
///
/// Every other ABI renders something that is still recognisably its own input
/// shape, which is why the cross-ABI corruption this file fixes showed up
/// there. Excluding Go by ABI rather than by output shape keeps the check
/// strict where it is meaningful instead of growing an exclusion per symbol
/// family; the first version of this test excluded `{closure-` and promptly
/// missed a second Go family (generic type descriptors).
#[test]
fn no_corpus_rendering_re_decodes_into_a_different_string() {
    let corpus = include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty());

    let mut offenders: Vec<(&str, String, String)> = Vec::new();
    let mut checked = 0usize;
    for sym in corpus {
        let Some(first) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        let Some(second) = rustre_demangle::demangle(&first.demangled) else {
            continue;
        };
        if format!("{:?}", first.abi) == "Go" {
            continue;
        }
        if second.demangled != first.demangled {
            offenders.push((sym, first.demangled, second.demangled));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} renderings were rewritten when fed back in; first 5: {:?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
    assert!(
        checked > 3000,
        "vacuity guard: only {checked} renderings round-tripped"
    );
}

/// A plain C name must never be claimed — and above all never *rewritten*.
///
/// The whitespace rule added alongside this file stopped `detect_ghc` claiming
/// prose, but not an all-lowercase C function that happens to end in a GHC
/// suffix with enough underscores:
///
/// ```text
/// "some_random_c_function_info" -> "some:random_c.function (info)"
/// ```
///
/// The discriminating property was already written in `detect_ghc`'s own doc
/// comment, which argues OCaml and Ada are safely excluded because *"GHC's own
/// names carry an uppercase module (`base_GHCziBase_…`)"* — true, and never
/// enforced. Requiring an uppercase letter is that stated rule, applied.
///
/// This is the `_RTC_Initialize` / `_TIFFOpen` shape: a detector looser than
/// what it detects files ordinary C names as unhandled manglings, and the
/// phantoms hide real defects. Here it went further and corrupted the name.
#[test]
fn an_all_lowercase_c_name_is_not_claimed_as_haskell() {
    use rustre_demangle::decline::{DeclineReason, decline_reason};

    for name in [
        "some_random_c_function_info",
        "my_module_closure",
        "deregister_tm_clones",
        "a_b_c_entry",
    ] {
        let got = rustre_demangle::demangle(name).map(|r| r.demangled);
        assert!(
            got.is_none(),
            "plain C name {name:?} was claimed and rendered {got:?}"
        );
        assert_eq!(
            decline_reason(name),
            DeclineReason::UndecoratedC,
            "{name} is a C identifier and must be classified as one"
        );
    }

    // Control: a real GHC symbol, which carries an uppercase z-encoded module,
    // must still decode. Without this the fix could pass by rejecting
    // everything.
    for sym in [
        "base_GHCziBase_map_closure",
        "base_GHCziBase_zdfEqInt_info",
        "main_Main_main_entry",
    ] {
        assert!(
            rustre_demangle::demangle(sym).is_some(),
            "{sym} is a GHC symbol and must still decode"
        );
    }
}

/// ARM ELF mapping symbols are linker artifacts, not names.
///
/// `$a` (ARM code), `$t` (Thumb), `$d` (data) and `$x` (A64 code), optionally
/// suffixed with `.<anything>`, mark instruction-set transitions inside a
/// section. Every ARM toolchain emits them and they name no entity, so
/// `LinkerArtifact` is the honest bucket. They were falling through to
/// `DeclineReason::Unknown` — the variant this crate keeps locked at zero,
/// which only stayed green because neither corpus is an ARM binary.
#[test]
fn arm_mapping_symbols_are_linker_artifacts() {
    use rustre_demangle::decline::{DeclineReason, decline_reason};

    for sym in ["$a", "$t", "$d", "$x", "$d.realdata", "$t.0"] {
        assert_eq!(
            decline_reason(sym),
            DeclineReason::LinkerArtifact,
            "{sym} is an ARM mapping symbol"
        );
        assert!(
            !decline_reason(sym).is_defect(),
            "{sym} must not count as a defect"
        );
    }

    // Control: `$` followed by anything else is not a mapping symbol, and the
    // LLVM constant-pool form must keep its own classification.
    assert_eq!(
        decline_reason("$f32.deadbeef"),
        DeclineReason::LinkerArtifact
    );
    assert_ne!(decline_reason("$zzz"), DeclineReason::LinkerArtifact);
}

/// Go's detector must not claim build strings that share a symbol table with
/// real symbols.
///
/// `GCC: (GNU) 12.2.0` is a `.comment` string, not a symbol, and it was echoed
/// back as a Go decode because it contains dots and the detector claimed
/// anything dotted.
///
/// The discriminating rule had to be found by measurement, not assumption:
/// whitespace alone cannot disqualify a Go symbol, because generic
/// instantiations genuinely contain it — `…Pointer[go.shape.struct {
/// internal/sync.isEntry bool }]`. Counting over the corpus, **31 of 2163** Go
/// symbols contain whitespace and **none** has any at bracket depth zero. That
/// is the property this pins: spaces are legal inside type arguments and
/// nowhere else.
///
/// The 31 generic symbols are asserted to survive, because a rule that simply
/// rejected whitespace would pass the negative cases while silently dropping
/// them — the trade this crate has been burned by before, when declining all
/// `go:`/`type:` names satisfied an invariant and destroyed 83 real decodes.
#[test]
fn go_does_not_claim_build_strings() {
    for text in [
        "GCC: (GNU) 12.2.0",
        "GCC: (GNU) 9.4.0",
        "clang version 15.0.7",
        "rustc version 1.75.0",
    ] {
        assert!(
            rustre_demangle::demangle(text).is_none(),
            "{text:?} is a build string, not a symbol, but was claimed"
        );
    }
}

/// Go generic instantiations, whose type arguments contain spaces, must keep
/// decoding.
#[test]
fn go_generic_instantiations_with_spaces_still_decode() {
    let mut checked = 0;
    for sym in include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.contains(char::is_whitespace))
    {
        // Every whitespace-carrying corpus symbol that Go owns must still be
        // claimed; the whitespace all sits inside brackets.
        if sym.starts_with("type:") || sym.starts_with("go:") || sym.contains('[') {
            assert!(
                rustre_demangle::demangle(sym).is_some(),
                "generic Go symbol lost: {sym}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 25,
        "vacuity guard: only {checked} whitespace-carrying Go symbols exercised"
    );
}

/// The whitespace rule must stay a *two-stage* check.
///
/// `GoDemangler::detect` runs for every symbol on the dispatch path, and the
/// first version of this rule ran a per-character match with bracket-depth
/// tracking on all of them. An interleaved A/B — alternating two prebuilt
/// binaries under the same machine load, since absolute figures on this host
/// are bimodal and useless — showed the depth scan losing 4 rounds out of 5.
/// Gating it behind a plain byte predicate, which short-circuits the ~98.6% of
/// symbols containing no whitespace at all, removed the difference.
///
/// This test cannot measure speed, so it pins the *behaviour that must survive
/// the optimisation*: both stages agree, for symbols with no whitespace, with
/// whitespace inside brackets, and with whitespace outside them. A future
/// rewrite that keeps only the fast path would break the third case here
/// rather than in a consumer.
#[test]
fn the_whitespace_rule_is_unchanged_by_the_fast_path() {
    use rustre_demangle::go_demangler::GoDemangler;

    // No whitespace: the fast path returns early and the symbol is claimed.
    for sym in ["main.main", "runtime.gcBgMarkWorker", "errors..inittask"] {
        assert!(GoDemangler::detect(sym), "{sym} must still be detected");
    }

    // Whitespace inside brackets: legal Go generics, must survive the gate.
    for sym in [
        "type:.eq.[16]sync/atomic.Pointer[go.shape.struct { internal/sync.isEntry bool }]",
        "internal/sync.entry[go.shape.interface {},go.shape.interface {}]",
    ] {
        assert!(
            GoDemangler::detect(sym),
            "generic instantiation must still be detected: {sym}"
        );
    }

    // Whitespace outside brackets: not a Go symbol.
    for text in ["GCC: (GNU) 12.2.0", "clang version 15.0.7", "foo bar.baz"] {
        assert!(
            !GoDemangler::detect(text),
            "{text:?} has whitespace at depth 0 and must not be claimed"
        );
    }
}

/// `detect_ghc`'s conditions are order-independent, and reordering them must
/// not change what it claims.
///
/// The function is a conjunction of pure predicates — suffix, uppercase,
/// z-encodable characters, underscore count, and deferral to OCaml/Ada — so
/// they may be evaluated in any order. That freedom was used to put the
/// selective, bounded test first; this pins the *behaviour* that must be
/// identical either way, since a reordering is exactly the kind of change that
/// looks safe and can silently drop a condition.
///
/// Each negative case below fails a different one of the five conditions, so a
/// dropped condition surfaces here rather than as a phantom claim in a corpus.
#[test]
fn detect_ghc_conditions_are_all_still_enforced() {
    use rustre_demangle::lang_extra::detect_ghc;

    // Claimed: satisfies every condition.
    for sym in [
        "base_GHCziBase_map_closure",
        "base_GHCziBase_zdfEqInt_info",
        "main_Main_main_entry",
    ] {
        assert!(detect_ghc(sym), "{sym} must be claimed");
    }

    // Fails the suffix condition.
    assert!(!detect_ghc("base_GHCziBase_map_nothing"));
    // Fails the leading-underscore condition.
    assert!(!detect_ghc("_base_GHCziBase_map_closure"));
    // Fails the uppercase (z-encoded module) condition.
    assert!(!detect_ghc("some_random_c_function_info"));
    // Fails the z-encodable-characters condition.
    assert!(!detect_ghc("typeinfo for __cxxabiv1::__class_type_info"));
    // Fails the underscore-count condition.
    assert!(!detect_ghc("A_info"));
    // Fails the OCaml/Ada deferral.
    assert!(!detect_ghc("camlDune__exe__Main__entry"));
}

/// Go's character set is closed, and arbitrary punctuation is not in it.
///
/// The detector claimed any name containing a dot, so 8.5% of random
/// printable-ASCII strings "decoded" — echoed back verbatim and counted as
/// `Decoded` in the classification metric, which is this crate's authoritative
/// one. A detector looser than what it detects invents symbols; that is the
/// `_RTC_Initialize` / `_TIFFOpen` lesson, here at scale.
///
/// The permitted set was **measured**, not assumed: across all 2163 Go symbols
/// in the corpora the only non-alphanumeric characters that occur are
/// `space ( ) * , - . / : [ ] _ { }` and `·`, the interface-thunk marker. The
/// positive cases below are drawn from that measurement, so a rule tightened
/// past it fails here rather than in a consumer.
#[test]
fn go_does_not_claim_arbitrary_punctuation() {
    use rustre_demangle::go_demangler::GoDemangler;

    // Characters no Go symbol can contain.
    for text in [
        "~TTz3.3J-,.l",
        "a.b`c",
        "a.b\"c",
        r"a.b\c",
        "a.b?c",
        "a.b$c",
        "a.b@c",
        "a.b<c>",
        "a.b|c",
        "a.b#c",
        "a.b;c",
        "a.b=c",
        "a.b+c",
        "a.b'c",
        "a.b!c",
        "a.b^c",
        "a.b%c",
    ] {
        assert!(
            !GoDemangler::detect(text),
            "{text:?} contains a character no Go symbol can hold, but was claimed"
        );
    }

    // Every character that *does* occur in the real corpus must stay claimable.
    for sym in [
        "main.main",
        "runtime.gcBgMarkWorker",
        "main.(*T).Method",
        "internal/sync.entry[go.shape.interface {},go.shape.interface {}]",
        "type:.eq.[2]runtime.Frame",
        "errors..inittask",
        "main.foo.func1",
        "pkg.Type.method·ftab",
        "a-b.c",
    ] {
        assert!(
            GoDemangler::detect(sym),
            "{sym} uses only characters measured in the real corpus and must be claimed"
        );
    }
}
