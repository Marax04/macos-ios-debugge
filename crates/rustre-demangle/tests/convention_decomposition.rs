//! The convention decoders must fill the structured fields, and fill them with
//! names rather than prose.
//!
//! `DemanglingResult` carries a rendered string *and* a decomposition. The
//! convention decoders render descriptive text — `lua module open:
//! socket.core`, `php method: ArrayObject::count`, `mexFunction (MATLAB MEX
//! gateway)` — and two different builders derived the fields from it in two
//! opposite wrong ways:
//!
//! * `lang_extra::result` left `function` **empty**, so OCaml, Ada, gfortran,
//!   JNI and the Windows C decorations decoded correctly and reported no
//!   function name at all;
//! * the `lang_more` arm in `backends.rs` set `function` to the **whole
//!   sentence**, so a consumer asking for the function of `luaopen_socket_core`
//!   got the string `"lua module open: socket.core"`.
//!
//! Both passed `tests/structured_consistency.rs`, whose invariant is that each
//! field must appear *inside* the rendering: an empty field is vacuously
//! contained and the full string is contained literally. That invariant is
//! necessary and not sufficient — the same blind spot recorded for the Go
//! backend's fabricated metadata, and for the Swift decomposition fixed in
//! `tests/swift_decomposition.rs`.
//!
//! This matters because the fields are what consumers use: the decompiler names
//! variables from them.

fn parts(sym: &str) -> (Option<String>, String, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.function, r.demangled)
}

/// `function` must be an identifier, never the descriptive rendering.
#[test]
fn function_is_a_name_not_a_sentence() {
    let mut checked = 0;
    for (sym, want_fn) in [
        ("luaopen_socket_core", "core"),
        ("Init_my_ext_core", "my_ext_core"),
        ("PyInit_my_ext_core", "my_ext_core"),
        ("R_init_mypkg", "mypkg"),
        ("Sqlite3_Init", "Sqlite3"),
        ("zif_myfunc", "myfunc"),
        ("zim_ArrayObject_count", "count"),
        ("boot_Foo__Bar", "Bar"),
        ("mexFunction", "mexFunction"),
    ] {
        let (_, function, rendered) = parts(sym);
        assert_eq!(function, want_fn, "{sym} -> {rendered}");

        // The two failure modes, named so neither can return in disguise.
        assert!(
            !function.contains(": "),
            "the descriptive prefix leaked into `function` for {sym}: {function}"
        );
        assert!(
            !function.contains(' '),
            "`function` must be an identifier, got prose for {sym}: {function}"
        );
        checked += 1;
    }
    assert!(checked > 7, "vacuous: only {checked} conventions checked");
}

/// `function` must not be empty for a symbol that decoded.
///
/// These are the decoders that reported nothing at all. Each has a perfectly
/// extractable entity name in its own rendering.
#[test]
fn a_decoded_symbol_always_names_its_function() {
    let mut checked = 0;
    for (sym, want_ns, want_fn) in [
        (
            "camlStdlib__Printf__printf_42",
            Some("Stdlib.Printf"),
            "printf",
        ),
        ("ada__text_io__put_line", Some("ada.text_io"), "put_line"),
        ("__physics_MOD_get_value", Some("physics"), "get_value"),
        // JNI names a package, a CLASS and a method by construction, so the
        // class is reported in `class` and the namespace is the package alone.
        // This test's purpose — that `function` is non-empty and correct — is
        // unaffected; the namespace value was an incidental product of the
        // generic splitter, which folded the class into it.
        ("Java_com_example_Foo_bar", Some("com.example"), "bar"),
        ("_MessageBoxA@16", None, "MessageBoxA"),
    ] {
        let (namespace, function, rendered) = parts(sym);
        assert!(
            !function.is_empty(),
            "{sym} decoded to {rendered} but reported no function"
        );
        assert_eq!(function, want_fn, "function of {sym}");
        assert_eq!(namespace.as_deref(), want_ns, "namespace of {sym}");
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} checked");
}

/// The path separator is whatever the rendering used, and the *last* component
/// is the entity.
///
/// Discriminating on purpose: a single-component name is split correctly by any
/// implementation, so only nested paths separate a real split from `function =
/// everything`. Both separators the conventions emit are covered, because
/// handling one and not the other would leave half the decoders wrong.
#[test]
fn nested_paths_split_on_the_separator_the_rendering_uses() {
    for (sym, ns, function) in [
        // `::` paths
        ("zim_ArrayObject_count", Some("ArrayObject"), "count"),
        ("boot_Foo__Bar", Some("Foo"), "Bar"),
        ("*Foo::Bar::baz<Int32>:Nil", Some("Foo::Bar"), "baz"),
        ("__physics_MOD_get_value", Some("physics"), "get_value"),
        // `.` paths
        ("luaopen_socket_core", Some("socket"), "core"),
        ("camlStdlib__Printf__printf_42", Some("Stdlib.Printf"), "printf"),
        // See the note above: the class is its own field now, so the package
        // is the namespace. The split this test checks for still happens.
        ("Java_com_example_Foo_bar", Some("com.example"), "bar"),
    ] {
        let (got_ns, got_fn, rendered) = parts(sym);
        assert_eq!(got_ns.as_deref(), ns, "namespace of {sym} ({rendered})");
        assert_eq!(got_fn, function, "function of {sym} ({rendered})");
    }
}

/// Control: a name with no path must not gain a namespace.
///
/// A split that over-reached would invent one, which is the mirror of the
/// defect fixed here.
#[test]
fn flat_names_gain_no_namespace() {
    for sym in [
        "zif_myfunc",
        "Sqlite3_Init",
        "R_init_mypkg",
        "mexFunction",
        "_MessageBoxA@16",
        "julia_My_Mod_func_1234",
    ] {
        let (namespace, function, rendered) = parts(sym);
        assert!(
            namespace.is_none(),
            "{sym} ({rendered}) has no path but reported namespace {namespace:?}"
        );
        assert!(!function.is_empty(), "{sym} reported no function");
    }
}

/// The rendered strings themselves are untouched by this change.
///
/// Without this, a "fix" that rewrote the renderings to make the split easier
/// would pass everything above while breaking the decoding tests' contract.
#[test]
fn renderings_are_unchanged() {
    for (sym, rendering) in [
        ("luaopen_socket_core", "lua module open: socket.core"),
        ("zim_ArrayObject_count", "php method: ArrayObject::count"),
        ("camlStdlib__Printf__printf_42", "Stdlib.Printf.printf"),
        ("Java_com_example_Foo_bar", "com.example.Foo.bar"),
        ("mexFunction", "mexFunction (MATLAB MEX gateway)"),
    ] {
        let (_, _, rendered) = parts(sym);
        assert_eq!(rendered, rendering, "rendering of {sym} changed");
    }
}
