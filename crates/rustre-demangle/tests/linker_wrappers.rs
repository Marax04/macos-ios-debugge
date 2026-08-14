//! Linker-generated indirection symbols (`.refptr.`, `__imp_`).
//!
//! mingw-w64's ld emits `.refptr.<sym>` for references that must go through a
//! pointer, and the PE import table uses `__imp_<sym>`. Both wrap an
//! otherwise-ordinary mangled name that the crate already decodes; before this
//! was handled, 187 such symbols in the real corpus were declined outright.
//!
//! The two properties that matter and are asserted here:
//!   * the payload is decoded, and
//!   * the prefix survives into the output, so `.refptr.f` never reads as `f`.

/// A wrapped Itanium symbol decodes, with the prefix preserved.
#[test]
fn refptr_wrapping_itanium_symbol_decodes() {
    let r = rustre_demangle::demangle(".refptr._ZNSt10bad_typeidD1Ev")
        .expect(".refptr. around a decodable Itanium symbol must decode");
    assert!(
        r.demangled.starts_with(".refptr."),
        "prefix must survive: {}",
        r.demangled
    );
    let inner = rustre_demangle::demangle("_ZNSt10bad_typeidD1Ev").unwrap();
    assert_eq!(r.demangled, format!(".refptr.{}", inner.demangled));
    assert_eq!(r.original, ".refptr._ZNSt10bad_typeidD1Ev");
}

/// The wrapper must not launder an undecodable payload into a "decoded"
/// result. `_CRT_MT` is a plain C variable; the whole symbol stays declined.
#[test]
fn refptr_wrapping_plain_c_name_is_declined() {
    assert!(
        rustre_demangle::demangle(".refptr._CRT_MT").is_none(),
        "a wrapper around a non-mangled payload must not be reported as decoded"
    );
}

/// PE import thunks decode the same way.
#[test]
fn imp_thunk_decodes_payload() {
    let Some(r) = rustre_demangle::demangle("__imp__ZNSt10bad_typeidD1Ev") else {
        panic!("__imp_ around a decodable Itanium symbol must decode");
    };
    assert!(r.demangled.starts_with("__imp_"), "{}", r.demangled);
}

/// Nesting resolves through both layers.
#[test]
fn nested_wrappers_resolve() {
    let Some(r) = rustre_demangle::demangle(".refptr.__imp__ZNSt10bad_typeidD1Ev") else {
        panic!("nested wrappers must resolve");
    };
    assert!(
        r.demangled.starts_with(".refptr.__imp_"),
        "both prefixes must survive: {}",
        r.demangled
    );
}

/// The prefix alone carries no payload and must be declined, not treated as an
/// empty-named symbol.
#[test]
fn bare_prefix_is_declined() {
    assert!(rustre_demangle::demangle(".refptr.").is_none());
    assert!(rustre_demangle::demangle("__imp_").is_none());
}

/// Section names that merely resemble the prefix must be untouched.
#[test]
fn section_names_stay_declined() {
    for s in [".bss", ".ctors", ".debug_abbrev", ".CRT$XCA", ".refptrx"] {
        assert!(
            rustre_demangle::demangle(s).is_none(),
            "{s} is not a symbol and must be declined"
        );
    }
}
