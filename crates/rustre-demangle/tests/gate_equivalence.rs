//! The feature-gated dispatchers (`lang_extra::demangle_extra`,
//! `lang_more::demangle_more`) must behave EXACTLY like the plain,
//! ungated detector chains they replaced. Every gate is a claimed
//! *necessary* condition of its detector; this suite is the proof
//! obligation. If a gate is wrong, a family silently stops matching —
//! recompilability-style metrics would never notice, so this test is the
//! only guard. Extend it whenever a gate or a detector changes.

use proptest::prelude::*;
use rustre_demangle::lang_extra::{
    self, demangle_c_decorated, demangle_gfortran, demangle_ghc, demangle_gnat_ada,
    demangle_jni, demangle_ocaml, detect_c_decorated, detect_gfortran, detect_ghc,
    detect_gnat_ada, detect_jni, detect_ocaml,
};
use rustre_demangle::lang_more::{
    self, fortran_hpc, jvm, legacy_native, modern_native, pascal_family, scripting,
};
use rustre_demangle::{ManglingAbi, ObjCDemangler};

/// The pre-gate `lang_extra` chain, reconstructed verbatim from the public
/// per-family detectors, reduced to `(demangled, abi)` for comparison.
fn ungated_extra(mangled: &str) -> Option<(String, ManglingAbi)> {
    if detect_jni(mangled) {
        return demangle_jni(mangled).map(|d| (d, ManglingAbi::Java));
    }
    if ObjCDemangler::detect(mangled) {
        return ObjCDemangler::demangle(mangled).map(|d| (d, ManglingAbi::ObjC));
    }
    if detect_gfortran(mangled) {
        return demangle_gfortran(mangled).map(|d| (d, ManglingAbi::Fortran));
    }
    if detect_ghc(mangled) {
        return demangle_ghc(mangled).map(|d| (d, ManglingAbi::Haskell));
    }
    if detect_ocaml(mangled) {
        return demangle_ocaml(mangled).map(|d| (d, ManglingAbi::OCaml));
    }
    if detect_c_decorated(mangled) {
        return demangle_c_decorated(mangled).map(|d| (d, ManglingAbi::C));
    }
    if detect_gnat_ada(mangled) {
        return demangle_gnat_ada(mangled).map(|d| (d, ManglingAbi::Ada));
    }
    None
}

/// The pre-gate `lang_more` chain, reconstructed verbatim from the public
/// per-module dispatchers, in the original order.
fn ungated_more(mangled: &str) -> Option<(String, &'static str)> {
    jvm::demangle(mangled)
        .or_else(|| pascal_family::demangle(mangled))
        .or_else(|| fortran_hpc::demangle(mangled))
        .or_else(|| scripting::demangle(mangled))
        .or_else(|| modern_native::demangle(mangled))
        .or_else(|| legacy_native::demangle(mangled))
}

fn assert_agree(sym: &str) {
    let gated_extra =
        lang_extra::demangle_extra(sym).map(|r| (r.demangled, r.abi));
    assert_eq!(
        gated_extra,
        ungated_extra(sym),
        "lang_extra gate diverges on {sym:?}"
    );
    assert_eq!(
        lang_more::demangle_more(sym),
        ungated_more(sym),
        "lang_more gate diverges on {sym:?}"
    );
}

/// One positive seed per detector family, so every gate is exercised on the
/// accepting side (a gate that wrongly rejects would fail here immediately).
const FAMILY_SEEDS: &[&str] = &[
    // lang_extra
    "Java_com_example_Widget_render",
    "JNICALL_Java_a_b",
    "-[NSString stringWithFormat:]",
    "  +[Foo bar]",
    "_OBJC_CLASS_$_NSObject",
    "__mymod_MOD_solve",
    "ghczmprim_GHCziTypes_True_closure",
    "camlFoo__bar_271",
    "_memcpy@12",
    "@fastfn@8",
    "ada__text_io__put_line",
    // lang_more: jvm
    "kfun:kotlin.collections.List#get(kotlin.Int){}kotlin.Any?",
    "kclass:kotlin.String",
    "my.ns$handler__1234",
    "scala.collection.Map$anonfun$get$1",
    "Predef$",
    // pascal
    "@Forms@TApplication@Run$qqrv",
    "SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING",
    "INIT$_$UNIT1",
    // fortran/hpc
    "__device_stub__Z3addPi",
    "main._omp_fn.0",
    "_Z4workv.omp_outlined.",
    "mymod_mp_solve_",
    // scripting
    "PyInit_spam",
    "initspam",
    "Init_nokogiri",
    "zif_strlen",
    "zim_Foo_bar",
    "luaopen_socket_core",
    "XS_Foo_bar",
    "boot_DynaLoader",
    "napi_register_module_v1",
    "R_init_stats",
    "Sqlite3_Init",
    "Foo_SafeInit",
    "Pkg_Unload",
    // modern native
    "*MyClass#method<Foo, Int32>:Bar",
    "julia_typeinf_ext_1067",
    "j_f_123",
    "outer__anon_1234",
    "main__test_u4",
    // legacy native
    "foo__4Testi",
    "__ct__4Testv",
    "W?foo$n(ii)v",
    "mexFunction",
    "_mexFunction",
    "HELLO__WORLD",
    // near-misses / plain C runtime names that must keep missing
    "memcpy",
    "_start",
    "__libc_start_main",
    "main",
    "printf",
    "",
    "_",
    "__",
    "$",
    "kfun",
    "initG",
    "Java_",
];

#[test]
fn family_seeds_agree() {
    for sym in FAMILY_SEEDS {
        assert_agree(sym);
    }
}

/// Anti-vacuity guard: the seed list must actually exercise the accepting
/// side of both gated dispatchers, otherwise the equivalence above proves
/// nothing about the gates letting matches through.
#[test]
fn family_seeds_are_not_vacuous() {
    let extra_hits = FAMILY_SEEDS
        .iter()
        .filter(|s| lang_extra::demangle_extra(s).is_some())
        .count();
    let more_hits = FAMILY_SEEDS
        .iter()
        .filter(|s| lang_more::demangle_more(s).is_some())
        .count();
    assert!(extra_hits >= 8, "only {extra_hits} lang_extra seeds match");
    assert!(more_hits >= 15, "only {more_hits} lang_more seeds match");
}

/// The full real-binary corpus (6055 symbols from the 12 corpus
/// executables) must agree symbol-by-symbol.
#[test]
fn real_corpus_agrees() {
    let data = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/real_symbols.txt"),
    )
    .expect("real_symbols.txt");
    let mut checked = 0usize;
    for sym in data.lines().map(str::trim).filter(|l| !l.is_empty()) {
        assert_agree(sym);
        checked += 1;
    }
    // Vacuity guard, in the spirit of `family_seeds_are_not_vacuous` below:
    // `.expect` above catches a *missing* corpus, but an empty or truncated one
    // would run this loop zero times and pass. These files are regenerated by a
    // script that has silently truncated them before.
    assert!(
        checked > 5000,
        "only {checked} corpus symbols compared — real_symbols.txt is truncated"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2048,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    /// Arbitrary printable strings: gated and ungated chains agree.
    #[test]
    fn arbitrary_strings_agree(s in "\\PC*") {
        assert_agree(&s);
    }

    /// Identifier-shaped strings (the realistic miss population) agree.
    #[test]
    fn identifier_strings_agree(s in "[A-Za-z_$@.:*#\\[\\]][A-Za-z0-9_$@.:#]{0,40}") {
        assert_agree(&s);
    }

    /// Family-prefixed strings stress each gate's accepting boundary.
    #[test]
    fn prefixed_strings_agree(
        prefix in prop::sample::select(vec![
            "Java_", "JNICALL_Java_", "-[", "+[", "_OBJC_", "__", "caml",
            "kfun:", "kclass:", "@", "PyInit_", "init", "Init_", "zif_",
            "zim_", "XS_", "boot_", "luaopen_", "R_init_", "napi_", "julia_",
            "j_", "*", "W?", "mex", "__device_stub_",
        ]),
        body in "[A-Za-z0-9_$@.:#]{0,32}",
    ) {
        let sym = format!("{prefix}{body}");
        assert_agree(&sym);
    }

    /// Suffix-driven detectors (Tcl `_Init`/`_Unload`, GHC `_closure`/`_info`,
    /// ifort trailing `_`, OpenMP `.omp` forms) get dedicated coverage.
    #[test]
    fn suffixed_strings_agree(
        body in "[A-Za-z0-9_]{1,24}",
        suffix in prop::sample::select(vec![
            "_Init", "_SafeInit", "_Unload", "_closure", "_info", "_",
            "._omp_fn.0", ".omp_outlined.", "_mp_x_", "__anon_12", "__m_u4",
        ]),
    ) {
        let sym = format!("{body}{suffix}");
        assert_agree(&sym);
    }
}
