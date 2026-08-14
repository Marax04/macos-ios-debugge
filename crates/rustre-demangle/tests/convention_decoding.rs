//! The convention-based detectors must decode to their language's real shape.
//!
//! `tests/detector_conventions.rs` checks the *other* direction — that these
//! detectors do not claim ordinary C names. This one checks that what they do
//! claim, they render correctly, which is a separate property: a detector can
//! be perfectly restrained and still produce the wrong string.
//!
//! Neither corpus contains a gfortran, Ada, OCaml or GHC symbol, so these are
//! written against each language's documented convention.

fn demangled(s: &str) -> Option<String> {
    rustre_demangle::demangle(s).map(|r| r.demangled)
}

/// gfortran module procedures: `__<module>_MOD_<proc>`.
#[test]
fn gfortran_module_procedures() {
    assert_eq!(demangled("__mymod_MOD_compute").as_deref(), Some("mymod::compute"));
    assert_eq!(demangled("__geometry_MOD_area").as_deref(), Some("geometry::area"));
}

/// A Fortran procedure name may itself contain `_MOD_` (identifiers allow
/// underscores), so the separator is ambiguous. gfortran's convention — and the
/// only stable choice — is that the FIRST `_MOD_` divides module from
/// procedure: `__physics_MOD_get_MOD_value` is `physics::get_MOD_value`, not
/// `physics_MOD_get::value`. The two scalar test cases above cannot exercise
/// this; splitting on the last `_MOD_` would pass them and fail here.
#[test]
fn gfortran_splits_on_the_first_mod_separator() {
    assert_eq!(
        demangled("__physics_MOD_get_MOD_value").as_deref(),
        Some("physics::get_MOD_value")
    );
}

/// GNAT Ada: `pkg__subprogram`, nesting included.
#[test]
fn gnat_ada_packages() {
    assert_eq!(
        demangled("ada__text_io__put_line").as_deref(),
        Some("ada.text_io.put_line")
    );
    assert_eq!(
        demangled("mypkg__inner__proc").as_deref(),
        Some("mypkg.inner.proc")
    );
}

/// OCaml joins **every** module-path component with `__`, so a nested path
/// needs every separator converted.
///
/// This used to split once, leaving `camlStdlib__Printf__printf_42` as
/// `Stdlib.Printf__printf` — the inner module rendered as part of the function
/// name. The single-module case looked right, which is why it went unnoticed.
#[test]
fn ocaml_nested_modules_convert_every_separator() {
    assert_eq!(demangled("camlList__map_1234").as_deref(), Some("List.map"));
    assert_eq!(
        demangled("camlStdlib__Printf__printf_42").as_deref(),
        Some("Stdlib.Printf.printf")
    );
    assert_eq!(
        demangled("camlA__B__C__f_7").as_deref(),
        Some("A.B.C.f"),
        "three levels of nesting"
    );
}

/// An OCaml symbol whose entity is `entry` (or another word that is also a GHC
/// suffix) must still decode as OCaml. `camlDune__exe__Main__entry` is a real
/// Dune executable entry point; the GHC detector claimed it because it ends in
/// `_entry` and the dispatcher tries GHC first, so it declined a valid symbol
/// until GHC learned to defer to OCaml's own detector.
#[test]
fn ocaml_entity_colliding_with_a_ghc_suffix_still_decodes() {
    assert_eq!(
        demangled("camlDune__exe__Main__entry").as_deref(),
        Some("Dune.exe.Main.entry")
    );
    // `bytes` and `closure` are GHC suffixes too; an OCaml value named that
    // must not be stolen either.
    assert_eq!(
        demangled("camlStdlib__Bytes__bytes_3").as_deref(),
        Some("Stdlib.Bytes.bytes")
    );
}

/// An Ada symbol whose final component is a GHC suffix word must still decode
/// as Ada. GHC's detector claims `ada__text__info` (ends in `_info`, enough
/// underscores) but cannot decode it; the dispatcher tries GHC first and
/// short-circuits on its failure, so the symbol declined before the Ada
/// detector ran until `detect_ghc` learned to defer to Ada's own detector. The
/// control case has no GHC suffix and always worked — it guards against the fix
/// over-reaching.
#[test]
fn ada_component_colliding_with_a_ghc_suffix_still_decodes() {
    for (sym, want) in [
        ("ada__text__info", "ada.text.info"),
        ("ada__foo__bytes", "ada.foo.bytes"),
        ("ada__io__entry", "ada.io.entry"),
        ("ada__x__srt", "ada.x.srt"),
        ("ada__text_io__put_line", "ada.text_io.put_line"),
    ] {
        assert_eq!(demangled(sym).as_deref(), Some(want), "{sym}");
    }
}

/// The deferral must cover EVERY GHC suffix, not just the few that motivated it.
/// `detect_ghc` claims any lowercase-with-enough-underscores name ending in one
/// of its seven suffixes, so an Ada or OCaml entity named after any of them is
/// at risk of being stolen. This walks the full list for both ABIs, so adding a
/// GHC suffix without extending the deferral fails here rather than silently
/// declining a class of real symbols.
#[test]
fn every_ghc_suffix_defers_to_ada_and_ocaml() {
    let suffixes = [
        "info",
        "closure",
        "entry",
        "con_entry",
        "static_info",
        "srt",
        "bytes",
    ];
    for suf in suffixes {
        assert_eq!(
            demangled(&format!("ada__pkg__{suf}")).as_deref(),
            Some(format!("ada.pkg.{suf}").as_str()),
            "Ada entity named after GHC suffix {suf} was stolen"
        );
        assert_eq!(
            demangled(&format!("camlMod__{suf}")).as_deref(),
            Some(format!("Mod.{suf}").as_str()),
            "OCaml entity named after GHC suffix {suf} was stolen"
        );
    }
}

/// GHC Z-encoding: `zi` is `.`, `zd` is `$`, and the suffix names the entity.
#[test]
fn ghc_z_encoding() {
    let r = demangled("base_GHCziBase_zdfEqInt_info").expect("must decode");
    assert!(r.contains("GHC.Base"), "zi must decode to `.`: {r}");
    assert!(r.contains('$'), "zd must decode to `$`: {r}");
}

/// The lowercase `zu` escape is `_`, distinct from the separator underscores
/// GHC uses between package / module / name. A decoder that treated every `_`
/// alike, or dropped `zu`, would merge or lose the character; here the decoded
/// `_` must sit *inside* the entity name (`Show_Maybe`), not split it.
#[test]
fn ghc_zu_escape_is_an_underscore_within_the_name() {
    let r = demangled("base_DataziMaybe_zdfShowzuMaybe_info").expect("must decode");
    assert!(
        r.contains("$fShow_Maybe"),
        "zu must decode to `_` inside the name: {r}"
    );
    assert!(r.contains("Data.Maybe"), "zi must still decode to `.`: {r}");
}

/// The uppercase bracket escapes `ZM`/`ZN` are `[`/`]`. The empty-list type
/// constructor `[]` is the discriminating case: a decoder missing either escape
/// would leave `ZM`/`ZN` in the output rather than the brackets.
#[test]
fn ghc_bracket_escapes_form_the_empty_list() {
    let r = demangled("ghczmprim_GHCziTypes_ZMZN_closure").expect("must decode");
    assert!(
        r.contains("GHC.Types.[]"),
        "ZM/ZN must decode to `[`/`]`: {r}"
    );
    assert!(
        !r.contains("ZM") && !r.contains("ZN"),
        "no bracket escape may survive undecoded: {r}"
    );
}

/// The package key is Z-encoded like every other component and must be decoded
/// too. `ghc-prim` mangles to `ghczmprim` (`zm` = `-`); emitting the raw
/// `ghczmprim` while the module decoded to `GHC.Types` applied the same escape
/// inconsistently across one symbol. The discriminating check is that no `zm`
/// survives in the package.
#[test]
fn ghc_package_key_is_z_decoded() {
    let r = demangled("ghczmprim_GHCziTypes_ZMZN_closure").expect("must decode");
    assert!(
        r.starts_with("ghc-prim:"),
        "the package `ghczmprim` must decode to `ghc-prim`: {r}"
    );
    // A package with no escapes is unaffected — the fix must not mangle `base`.
    let b = demangled("base_GHCziBase_map_info").expect("must decode");
    assert!(b.starts_with("base:"), "escape-free package unchanged: {b}");
}

/// The unicode character escape `z<hex>U` carries a code point in lowercase
/// hex. `~` is 0x7e (`z7eU`), `!` is 0x21 (`z21U`), and a code point whose hex
/// begins with a letter is zero-prefixed (`é` = 0xe9 -> `z0e9U`) — which is
/// exactly why a `z` before a *digit* is this escape and not a letter escape.
/// A decoder that only knew the single-letter table leaves `z7eU` verbatim.
#[test]
fn ghc_unicode_character_escape_decodes() {
    for (sym, ch) in [
        ("base_GHCziBase_z7eU_info", '~'),
        ("base_GHCziBase_z21U_info", '!'),
        ("base_GHCziBase_z0e9U_info", 'é'),
    ] {
        let r = demangled(sym).expect("must decode");
        assert!(
            r.contains(ch),
            "{sym} must render the character {ch:?}: {r}"
        );
        assert!(!r.contains("U_"), "no unicode escape may survive undecoded: {r}");
    }
}

/// Tuple constructors `Z<n>T` (boxed) and `Z<n>H` (unboxed) encode their arity
/// as decimal digits, which the single-letter escape table cannot handle. The
/// arities discriminate: `Z2T` is `(,)`, `Z3T` is `(,,)`, `Z0T` is unit `()`,
/// and the unboxed `Z2H` is `(#,#)`. A decoder that stopped at the letter table
/// leaves `Z2T` verbatim in the output.
#[test]
fn ghc_tuple_constructors_decode_by_arity() {
    for (sym, want) in [
        ("ghczmprim_GHCziTuple_Z2T_closure", "GHC.Tuple.(,)"),
        ("ghczmprim_GHCziTuple_Z3T_closure", "GHC.Tuple.(,,)"),
        ("ghczmprim_GHCziTuple_Z0T_closure", "GHC.Tuple.()"),
        ("ghczmprim_GHCziPrim_Z2H_closure", "GHC.Prim.(#,#)"),
    ] {
        let r = demangled(sym).expect("must decode");
        assert!(r.contains(want), "{sym} must render {want}: {r}");
        assert!(
            !r.contains("Z2T") && !r.contains("Z3T") && !r.contains("Z0T") && !r.contains("Z2H"),
            "no tuple escape may survive undecoded: {r}"
        );
    }
}

/// A bare `caml` prefix with no module path is not an OCaml symbol.
///
/// `caml__foo` is deliberately absent: OCaml rejects it (the module path is
/// empty) but it matches GNAT Ada's `pkg__subprogram` shape exactly, so the
/// Ada detector claims it and renders `caml.foo`. That is the documented
/// ambiguity of convention-based detection, not a defect — the same shape as
/// Perl XS `boot_<module>` colliding with a C `boot_strap`. Asserting a
/// decline here would be asserting that Ada should lose, which nothing
/// justifies.
#[test]
fn degenerate_ocaml_names_are_declined() {
    for s in ["caml", "caml__", "camlfoo"] {
        assert!(demangled(s).is_none(), "{s} must be declined");
    }
}

/// The OCaml/Ada overlap, pinned so the resolution is deliberate rather than
/// an accident of dispatch order.
#[test]
fn caml_double_underscore_is_claimed_by_ada() {
    use rustre_demangle::lang_extra::demangle_ocaml;
    assert!(
        demangle_ocaml("caml__foo").is_none(),
        "OCaml must reject an empty module path"
    );
    assert_eq!(
        demangled("caml__foo").as_deref(),
        Some("caml.foo"),
        "the Ada convention matches this shape and claims it"
    );
}

/// Scripting-runtime conventions, on *discriminating* inputs.
///
/// Each of these was previously exercised with one trivial case, which cannot
/// tell a correct implementation from a naive one — `camlList__map` decoded
/// fine while nested OCaml modules were broken. A compound name is what
/// separates them.
///
/// Note two conventions that look alike and are deliberately different: Lua
/// treats `_` in a `luaopen_` name as a submodule separator, while Ruby keeps
/// it, because a Ruby extension name may legitimately contain underscores.
#[test]
fn scripting_conventions_handle_compound_names() {
    for (sym, needle) in [
        // Lua: `_` separates submodules.
        ("luaopen_socket", "socket"),
        ("luaopen_socket_core", "socket.core"),
        // Ruby: `_` is part of the extension name, not a separator.
        ("Init_mymodule", "mymodule"),
        ("Init_my_ext_core", "my_ext_core"),
        // PHP: `zif_` is a function, `zim_` a class method.
        ("zif_count", "count"),
        ("zim_ArrayObject_count", "ArrayObject::count"),
        // Perl XS: `__` encodes `::`.
        ("boot_Foo", "Foo"),
        ("boot_Foo__Bar", "Foo::Bar"),
    ] {
        let got = demangled(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            got.contains(needle),
            "{sym} -> {got}, expected to contain {needle:?}"
        );
    }
}

/// A Perl XS sub name may itself contain underscores, so after `__` is restored
/// to `::` the *first* remaining `_` separates the final package component from
/// the sub. `XS_List__Util_dl_load_file` is `List::Util::dl_load_file`, not
/// `List::Util_dl_load::file`. Only a sub name with an internal underscore
/// exercises this — the `XS_Foo_bar` shape the gate suite uses cannot, since
/// splitting on the first or last `_` gives the same answer there.
#[test]
fn perl_xs_sub_name_may_contain_underscores() {
    assert_eq!(
        demangled("XS_List__Util_dl_load_file").as_deref(),
        Some("perl xsub: List::Util::dl_load_file")
    );
    assert_eq!(
        demangled("XS_Foo_get_value").as_deref(),
        Some("perl xsub: Foo::get_value")
    );
}

/// Windows calling-convention decorations, all three spellings.
#[test]
fn windows_decorations_are_undecorated() {
    for (sym, want) in [
        ("_helper@8", "helper"),   // stdcall
        ("@fast@12", "fast"),      // fastcall
        ("helper@8", "helper"),    // bare
    ] {
        assert_eq!(demangled(sym).as_deref(), Some(want), "{sym}");
    }
}

/// The compound-name rule for the scripting conventions the test above does
/// not reach: Python 3, R, Julia and Crystal.
///
/// Same principle as `scripting_conventions_handle_compound_names`, applied to
/// the detectors it leaves out. A single-component name passes whether or not
/// the implementation knows where the boundary is; the discriminating input is
/// one whose *name itself* contains the separator character.
///
/// The expectations differ per convention, and that is the point:
///   * Python 3 and R treat `_` as part of the module name, so
///     `PyInit_my_ext_core` is the module `my_ext_core`, not `my.ext.core`.
///     Lua, tested above, splits on it — the two must not converge.
///   * Julia appends a numeric id which must come off, while the name may
///     itself contain underscores.
///   * Crystal carries a leading `*`, a `::`-separated path and a
///     `<args>:Return` suffix; the nested case proves the path is not
///     truncated at the first `::`.
#[test]
fn remaining_scripting_conventions_handle_compound_names() {
    let mut checked = 0;
    for (sym, needle, forbidden) in [
        // Python 3: `_` belongs to the module name.
        ("PyInit_mymodule", "mymodule", "my.module"),
        ("PyInit_my_ext_core", "my_ext_core", "my.ext.core"),
        // R: same rule.
        ("R_init_mypkg", "mypkg", "my.pkg"),
        ("R_init_my_pkg_core", "my_pkg_core", "my.pkg.core"),
        // Julia: strip the trailing numeric id, keep underscores in the name.
        ("julia_myfunc_1234", "myfunc", "1234"),
        ("julia_My_Mod_func_1234", "My_Mod_func", "1234"),
        // Crystal: full `::` path, no truncation at the first separator.
        ("*Foo::bar<Int32>:Nil", "Foo::bar", "<Int32>"),
        ("*Foo::Bar::baz<Int32>:Nil", "Foo::Bar::baz", "<Int32>"),
    ] {
        let got = demangled(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            got.contains(needle),
            "{sym} -> {got}, expected to contain {needle:?}"
        );
        assert!(
            !got.contains(forbidden),
            "{sym} -> {got}, must not contain {forbidden:?}"
        );
        checked += 1;
    }
    assert!(checked > 6, "vacuous: only {checked} conventions exercised");
}

/// Tcl's detector is deliberately narrow, and that narrowness is a decision
/// worth pinning rather than a limitation to be "fixed".
///
/// The convention is a bare suffix (`<Pkg>_Init`) with no reserved prefix, so
/// it claims on shape alone. Allowing underscores inside the package name would
/// make `My_Ext_Init` ambiguous — package `My_Ext`, or package `My` with an
/// entry point named `Ext_Init`? — and, worse, would let the detector claim
/// ordinary C functions that merely end in `_Init`. That is the phantom-defect
/// mistake `_R` made with `_RTC_Initialize` and `_T` with `_TIFFOpen`: a
/// claimed-but-undecodable symbol is filed as an unhandled ABI and hides real
/// ones.
///
/// Today the rule lives only in a code comment. This makes it fail loudly if
/// someone loosens it.
#[test]
fn the_tcl_detector_stays_narrow_on_purpose() {
    // Claimed: uppercase-initial, alphanumeric package.
    for (sym, want) in [
        ("Sqlite3_Init", "Sqlite3"),
        ("Tk_Init", "Tk"),
        ("Expect_SafeInit", "Expect"),
    ] {
        let got = demangled(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(got.contains(want), "{sym} -> {got}");
    }

    // Not claimed: an underscore in the package makes the split ambiguous, and
    // a lowercase initial is not a Tcl package name.
    for sym in ["My_Ext_Init", "my_Init", "foo_Init", "_Init"] {
        assert!(
            demangled(sym).is_none(),
            "{sym} must not be claimed — the split is ambiguous"
        );
    }
}

/// GHC `Z<n>T`: the arity must be one a Haskell tuple can have.
///
/// The z-encoding writes an n-tuple constructor as `Z<n>T` (`Z2T` is `(,)`) and
/// its unboxed form as `Z<n>H`. `Z0T` is unit `()`. Haskell has **no 1-tuple**,
/// so `Z1T` is malformed input.
///
/// The arity was read with `digits.parse().unwrap_or(0)` and rendered with
/// `n.saturating_sub(1)` commas, so two malformed inputs collapsed onto unit:
///
/// ```text
/// Z1T                        => ()      same as Z0T
/// Z99999999999999999999T     => ()      same as Z0T
/// ```
///
/// Distinct inputs producing one output assert a fact the input never gave —
/// the shape fixed for D's `G` and `B` numbers. The fix reuses the verbatim path
/// this decoder already applies to a `Z<digits>` run not closed by `T`/`H`,
/// rather than inventing a new behaviour for malformed arity.
///
/// The pairs are what discriminate: `Z0T` must still be `()` and `Z2T` must
/// still be `(,)`, or a fix that simply stopped decoding tuples would pass.
#[test]
fn a_ghc_tuple_arity_must_be_valid_and_representable() {
    let ghc = |s: &str| {
        rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must decode"))
            .demangled
    };

    // Valid arities, boxed and unboxed.
    assert!(ghc("base_GHCziBase_Z2T_closure").contains("(,)"));
    assert!(ghc("base_GHCziBase_Z3T_closure").contains("(,,)"));
    assert!(ghc("base_GHCziBase_Z4T_closure").contains("(,,,)"));
    assert!(ghc("base_GHCziBase_Z2H_closure").contains("(#,#)"));
    assert!(ghc("base_GHCziBase_Z3H_closure").contains("(#,,#)"));

    // Unit: arity zero is legal and distinct from the malformed cases below.
    let unit = ghc("base_GHCziBase_Z0T_closure");
    assert!(unit.contains("()"), "Z0T is unit: {unit}");

    // Malformed arities must NOT render as unit, and must not silently vanish.
    for (sym, run) in [
        ("base_GHCziBase_Z1T_closure", "Z1T"),
        ("base_GHCziBase_Z1H_closure", "Z1H"),
        ("base_GHCziBase_Z99999999999999999999T_closure", "Z99999999999999999999T"),
    ] {
        let got = ghc(sym);
        assert!(
            got.contains(run),
            "{sym} must re-emit the malformed run verbatim, got {got}"
        );
        assert!(
            !got.contains("()") && !got.contains("(#"),
            "{sym} rendered a tuple for an invalid arity: {got}"
        );
    }

    // Control: the existing verbatim case for a run not closed by T/H.
    assert!(ghc("base_GHCziBase_Z2X_closure").contains("Z2X"));

    // Control: the rest of the z-encoding is untouched — `zi` is `.`, and the
    // module path must still decode, so the fix cannot have disabled the
    // decoder wholesale.
    assert!(ghc("base_GHCziBase_Z2T_closure").contains("GHC.Base"));
}

/// Every convention decoder must keep the name, and no two may agree.
///
/// The crate has 33 convention detectors across `lang_more/*` and `lang_extra`.
/// Neither of the two properties the house rules demand of them was asserted
/// *across* the set — `tests/detector_conventions.rs` checks individual
/// exclusions and the cases above check individual renderings, but nothing held
/// the whole family to a shared invariant.
///
/// Two are checkable with no oracle and no corpus (there is none for most of
/// these languages):
///
/// * **name preservation** — a decoder that claims a symbol must carry its name
///   into the rendering. Dropping it is the loss fixed for Swift locals and D
///   named types.
/// * **injectivity** — two different symbols must not render identically, the
///   property that caught D's `G`/`B` numbers and GHC's tuple arity.
///
/// Found nothing when added: of 20 documented prefixes, 11 decode, **0 lose the
/// name and 0 collide**. Recorded so it stays that way, since a shared
/// invariant over 33 decoders is cheaper to keep than to rediscover.
///
/// The nine that decline are not failures: their full rules need more structure
/// than a bare prefix plus a name (`XS_` wants a package separator, `VMT_$` a
/// Pascal class shape). Declining an input that does not satisfy the rule is the
/// correct answer, so this test asserts a floor on how many decode rather than
/// demanding all of them.
#[test]
fn convention_decoders_keep_the_name_and_do_not_collide() {
    use std::collections::BTreeMap;

    /// Documented prefixes, read from the detectors' own `strip_prefix` calls.
    const PREFIXES: &[&str] = &[
        "luaopen_", "PyInit_", "Init_", "XS_", "R_init_", "R_unload_", "boot_",
        "napi_register_module_", "zim_", "zif_", "julia_", "japi1_", "j_",
        "kfun:", "kclass:", "ktype:", "VMT_$", "INIT$_$", "FINALIZE$_$",
        "__device_stub__Z",
    ];
    /// Distinctive so its presence in the output cannot be a coincidence, and
    /// free of `_` so no decoder can legitimately split it.
    const NAME: &str = "distinctivename";

    let mut by_output: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut lost: Vec<String> = Vec::new();
    let mut decoded = 0;

    for p in PREFIXES {
        let sym = format!("{p}{NAME}");
        let Some(r) = rustre_demangle::demangle(&sym) else {
            continue;
        };
        decoded += 1;
        if !r.demangled.contains(NAME) {
            lost.push(format!("{sym} -> {}", r.demangled));
        }
        by_output.entry(r.demangled).or_default().push(sym);
    }

    assert!(
        decoded >= 11,
        "vacuous: only {decoded} of {} prefixes decoded",
        PREFIXES.len()
    );
    assert!(lost.is_empty(), "decoders dropped the name: {lost:#?}");

    let collisions: Vec<_> = by_output.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        collisions.is_empty(),
        "distinct convention symbols render identically: {collisions:#?}"
    );
}

/// **Open decision — asserts the correct behaviour, which is not implemented.**
///
/// Julia's code generator emits three prefixes, and `modern_native`'s own doc
/// names them as distinct forms: `julia_<name>_<id>`, `japi1_<name>_<id>`,
/// `j_<name>_<id>`. `demangle_julia` drops the prefix, so all three collapse:
///
/// ```text
/// julia_myfunc_1234  =>  myfunc
/// japi1_myfunc_1234  =>  myfunc
/// j_myfunc_1234      =>  myfunc
/// ```
///
/// Measured: **every** decoded field agrees — `abi`, `namespace`, `class`,
/// `function` and `demangled` are identical across the three. Every other
/// convention decoder in this crate labels the kind it found (`perl xsub:` vs
/// `perl bootstrap:`, `vmt for`, `$init`), so Julia is the outlier.
///
/// Two things keep this a recorded decision rather than a fix:
///
/// * **`result.original` retains the input verbatim**, so the distinction is not
///   destroyed — only absent from the decoded view. That is materially less
///   severe than a lost name.
/// * Rendering it requires deciding what the prefixes *mean*, and there is no
///   Julia oracle. This crate's precedent for exactly that situation is the Go
///   `_main` namespace, deliberately left alone because the output is a faithful
///   echo rather than fabrication and the fix would be an unverifiable
///   heuristic.
///
/// The cheapest honest fix, if taken, is to echo the prefix — a token that is
/// already in the input, so not an invention. It would change
/// `julia_compiled_functions` and the `julia_myfunc_1234` expectations above,
/// which is why it needs a decision rather than a commit.
#[test]
#[ignore = "the three Julia codegen prefixes collapse; rendering them needs a decision, not a guess"]
fn julia_codegen_prefixes_are_distinguishable() {
    let of = |s: &str| rustre_demangle::demangle(s).map(|r| r.demangled);

    let julia = of("julia_myfunc_1234");
    let japi1 = of("japi1_myfunc_1234");
    let short = of("j_myfunc_1234");

    assert!(julia.is_some() && japi1.is_some() && short.is_some());
    assert_ne!(julia, japi1, "julia_ and japi1_ are different entry points");
    assert_ne!(julia, short, "julia_ and j_ are different entry points");
    assert_ne!(japi1, short, "japi1_ and j_ are different entry points");
}

/// The specialization id may be dropped — that part is settled, not open.
///
/// Guards the *other* half of the collision above, so a future fix aimed at the
/// prefixes cannot drift into keeping the numeric id. Two specializations of one
/// function are the same function, and the id is a disambiguator of the kind
/// this crate already strips for Rust legacy hashes.
#[test]
fn julia_specialization_ids_are_deliberately_dropped() {
    let of = |s: &str| {
        rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must decode"))
            .demangled
    };
    assert_eq!(of("julia_myfunc_1234"), of("julia_myfunc_5678"));
    assert_eq!(of("julia_myfunc_1234"), "myfunc");
    // And the id must not leak into the rendering.
    assert!(!of("julia_typeinf_ext_1067").contains("1067"));
}

/// The GHC z-encoding must be injective, and every escape reachable.
///
/// Fourth table swept under iter 95's rule — *a table with N inputs needs N vectors*.
/// The previous three (MSVC vtable cv, access/storage, operators) each had defects in
/// the unsampled part. **This one does not**: 52 escapes, 52 distinct decodings, no
/// collisions, nothing declined.
///
/// ### What this establishes, and what it does not
///
/// GHC has no oracle among this crate's dependencies, so a sweep comparing the
/// decoder to **its own table** would be tautological — the trap identified at iter
/// 88, where `cpp_demangler`'s "813/813" turned out to compare two wrappers over the
/// same engine.
///
/// What is decidable without a reference is **injectivity**: the z-encoding exists to
/// be reversible, so two escapes decoding to the same character would be a certain
/// defect regardless of which mapping is right. Reachability is the second half — an
/// escape that declines is one the decoder cannot handle at all.
///
/// This does **not** verify that any individual mapping matches GHC's `Encoding.hs`.
/// That needs a source this crate does not have, and asserting the table against
/// itself would just restate the code. `tests/convention_decoding.rs`'s other GHC
/// tests cover the specific mappings that were derived from documentation.
#[test]
fn the_ghc_z_encoding_is_injective_and_fully_reachable() {
    use std::collections::BTreeMap;

    let mut by_decoding: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut declined: Vec<String> = Vec::new();

    for (prefix, letters) in [
        ('z', "abcdefghijklmnopqrstuvwxyz"),
        ('Z', "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ] {
        for c in letters.chars() {
            let escape = format!("{prefix}{c}");
            // Embedded between two ordinary letters so the decoded character cannot
            // be confused with a delimiter the renderer adds.
            let sym = format!("base_GHCziBase_a{escape}b_closure");
            match rustre_demangle::demangle(&sym) {
                Some(r) => {
                    let tail = r
                        .demangled
                        .split('.')
                        .next_back()
                        .unwrap_or(&r.demangled)
                        .replace(" (closure)", "");
                    by_decoding.entry(tail).or_default().push(escape);
                }
                None => declined.push(escape),
            }
        }
    }

    assert!(
        declined.is_empty(),
        "these escapes are unreachable: {declined:?}"
    );
    assert_eq!(
        by_decoding.len(),
        52,
        "expected 52 distinct decodings for 52 escapes, got {}",
        by_decoding.len()
    );

    let collisions: Vec<_> = by_decoding.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        collisions.is_empty(),
        "the z-encoding must be reversible, but these escapes decode alike: {collisions:#?}"
    );
}
