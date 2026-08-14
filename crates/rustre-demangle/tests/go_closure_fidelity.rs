//! Go closure annotations must be backed by a closure in the symbol.
//!
//! Go names a closure by suffixing its enclosing function — `f.func1`,
//! `f.func2.1`, `f.deferwrap1`. A bare numeric segment is something else
//! entirely: `runtime.init.0` is the package's first init function, and
//! `errors..typeAssert.2` is a compiler-internal entry. Reporting those as
//! `{closure-1 #?}` invents structure that is not in the symbol, and drops
//! the index the real name does carry.

/// Package init functions keep their number and gain no closure annotation.
#[test]
fn package_init_functions_are_not_closures() {
    for s in [
        "runtime.init.0",
        "runtime.init.7",
        "os.init.1",
        "sync.init.0",
        "internal/bytealg.init.0",
    ] {
        let r = rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode"));
        assert!(
            !r.demangled.contains("{closure"),
            "{s} is an init function, not a closure: {}",
            r.demangled
        );
        assert!(
            r.demangled.contains(s.rsplit('.').next().unwrap()),
            "{s} must keep its index: {}",
            r.demangled
        );
    }
}

/// Compiler-internal entries are not closures either.
#[test]
fn compiler_internal_entries_are_not_closures() {
    for s in ["errors..typeAssert.2", "runtime..interfaceSwitch.0"] {
        let r = rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode"));
        assert!(
            !r.demangled.contains("{closure"),
            "{s} is a compiler-internal entry, not a closure: {}",
            r.demangled
        );
    }
}

/// Real closures keep their annotation — this fix must not silence them.
#[test]
fn real_closures_keep_their_annotation() {
    for s in [
        "internal/godebug.update.func1",
        "internal/godebug.(*Setting).Value.func1",
    ] {
        let r = rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode"));
        assert!(
            r.demangled.contains("{closure"),
            "{s} is a real closure and must stay annotated: {}",
            r.demangled
        );
    }
}

/// Nested closures still nest: the numeric segment counts once a `funcN` has
/// established that we are inside a closure.
#[test]
fn nested_closures_still_nest() {
    let r = rustre_demangle::demangle("os.init.OnceValue[go.shape.bool].func5.1")
        .expect("nested closure must decode");
    assert!(
        r.demangled.contains("{closure-2"),
        "expected depth 2: {}",
        r.demangled
    );
}

/// Corpus-wide invariant: every closure annotation the crate emits is backed
/// by a Go closure suffix in the symbol.
#[test]
fn no_fabricated_closure_annotations_in_corpus() {
    let raw = include_str!("data/real_symbols.txt");
    let mut fabricated: Vec<(&str, String)> = Vec::new();
    let mut decoded = 0usize;
    for s in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        decoded += 1;
        if r.demangled.contains("{closure") && !has_go_closure_suffix(s) {
            fabricated.push((s, r.demangled));
        }
    }
    assert!(
        fabricated.is_empty(),
        "{} symbols got a closure annotation with no closure suffix: {:#?}",
        fabricated.len(),
        &fabricated[..fabricated.len().min(10)]
    );
    // Vacuity guard: the loop also skips every symbol that declines, so both an
    // empty corpus and a decoding regression would leave `fabricated` empty and
    // pass. "No offenders because it is right" and "no offenders because
    // nothing was examined" must not look the same.
    assert!(
        decoded > 2000,
        "only {decoded} symbols decoded — nothing meaningful was examined"
    );
}

/// Whether `s` carries a Go closure marker: `.funcN`, `.deferwrapN`,
/// `.gowrapN`.
fn has_go_closure_suffix(s: &str) -> bool {
    s.split('.').any(|seg| {
        let stem = seg.trim_end_matches(|c: char| c.is_ascii_digit());
        stem.len() < seg.len() && matches!(stem, "func" | "deferwrap" | "gowrap")
    })
}

/// A closure's enclosing name is everything before the `funcN`, not just the
/// first dotted component.
///
/// `init.OnceValue[go.shape.bool].func5` is the fifth closure inside the
/// generic `OnceValue`, called from `init`. Keeping only the first component
/// dropped `OnceValue` and left the type arguments attached to `init` —
/// `os.init[bool] {closure-1 #5}` — which loses the function's identity. It
/// affected 12 of the 28 generic Go symbols in the real corpus.
#[test]
fn closure_keeps_its_full_enclosing_name() {
    for (sym, needle) in [
        ("os.init.OnceValue[go.shape.bool].func5", "init.OnceValue"),
        (
            "internal/syscall/windows.init.OnceValue[go.shape.bool].func5.1",
            "init.OnceValue",
        ),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.demangled.contains(needle),
            "{sym} -> {}, expected to keep {needle:?}",
            r.demangled
        );
    }
}

/// Corpus-wide: no generic Go symbol may lose the name preceding its type
/// arguments.
#[test]
fn no_generic_go_symbol_loses_its_function_name() {
    let mut checked = 0usize;
    let mut lost: Vec<(&str, String)> = Vec::new();

    for s in include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("[go.shape."))
    {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        checked += 1;
        let Some(idx) = s.find("[go.shape.") else {
            continue;
        };
        let name = s[..idx].rsplit('.').next().unwrap_or("");
        if !name.is_empty() && !r.demangled.contains(name) {
            lost.push((s, r.demangled.clone()));
        }
    }

    println!("{checked} generic Go symbols checked");
    assert!(
        checked > 20,
        "only {checked} generic symbols — suite gone vacuous"
    );
    assert!(
        lost.is_empty(),
        "{} generic symbols lost the name before their type arguments; \
         first 5: {:#?}",
        lost.len(),
        &lost[..lost.len().min(5)]
    );
}

/// Generic receivers keep both the receiver and its type arguments.
///
/// The corpus carries these — `internal/sync.(*HashTrieMap[go.shape.interface
/// {},go.shape.interface {}]).Load` — and they exercise three things at once:
/// the pointer/value distinction, the synthetic `go.shape.` qualifier that
/// must be stripped, and a comma-separated argument list inside a receiver.
#[test]
fn generic_receivers_survive_intact() {
    for (sym, class, func, in_output) in [
        (
            "internal/sync.(*HashTrieMap[go.shape.interface {},go.shape.interface {}]).Load",
            "*HashTrieMap",
            "Load",
            "(*HashTrieMap[interface {}, interface {}]).Load",
        ),
        (
            "main.Map[go.shape.string,go.shape.int].Get",
            "Map",
            "Get",
            "Map[string, int].Get",
        ),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(r.class.as_deref(), Some(class), "{sym}: receiver");
        assert_eq!(r.function, func, "{sym}: method");
        assert!(
            r.demangled.contains(in_output),
            "{sym} -> {}, expected to contain {in_output:?}",
            r.demangled
        );
        assert!(
            !r.demangled.contains("go.shape."),
            "{sym}: the synthetic shape qualifier must be stripped: {}",
            r.demangled
        );
    }
}

/// The pointer/value receiver distinction must be preserved — they are
/// different methods in Go, and collapsing them would merge two symbols.
#[test]
fn pointer_and_value_receivers_stay_distinct() {
    let ptr = rustre_demangle::demangle("net/http.(*Server).ListenAndServe")
        .expect("must decode");
    let val = rustre_demangle::demangle("net/http.Header.Get").expect("must decode");

    assert_eq!(ptr.class.as_deref(), Some("*Server"));
    assert_eq!(val.class.as_deref(), Some("Header"));
    assert!(
        ptr.demangled.contains("(*Server)"),
        "pointer receiver must keep its parentheses and star: {}",
        ptr.demangled
    );
}
