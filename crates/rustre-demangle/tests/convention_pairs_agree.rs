//! Every convention `detect_X` must agree with its `demangle_X`.
//!
//! The crate already guards this for the four `Demangler` trait backends
//! (`detect_demangle_agreement.rs`), and that suite is where the recurring
//! defect shape was first named: *one rule, two copies, only one updated*.
//! But the 33 convention pairs in `lang_extra`/`lang_more` are free functions,
//! not trait impls, so they were outside it — and drifted in BOTH directions:
//!
//! * `detect_jni` claimed `Java_a_B_c_4b` after iter 109 taught only
//!   `demangle_jni` that `_4` is not a JNI escape. A detector looser than its
//!   backend files a real symbol as an unhandled ABI.
//! * `demangle_ocaml` decoded `caml_a__b` to `_a.b` while `detect_ocaml`
//!   correctly refused: OCaml module names are capitalised, and lowercase
//!   `caml_` is the C-stub convention.
//! * `demangle_ghc` rewrote the COFF section name
//!   `.pdata$_ZL17parse_lsda_header…` into
//!   `.pdata$:(17parse_lsda_header… (info)` while `detect_ghc` refused.
//!
//! A backend looser than its detector is worse than the reverse: it is
//! fabrication that `detect`-gated callers never see, so it hides until
//! something calls `demangle` directly — which `AutoDemangler` does.

use rustre_demangle::{lang_extra, lang_more};

type Pair = (&'static str, fn(&str) -> bool, fn(&str) -> Option<String>);

fn pairs() -> Vec<Pair> {
    vec![
        ("lang_extra::jni", lang_extra::detect_jni, lang_extra::demangle_jni),
        ("lang_extra::gfortran", lang_extra::detect_gfortran, lang_extra::demangle_gfortran),
        ("lang_extra::gnat_ada", lang_extra::detect_gnat_ada, lang_extra::demangle_gnat_ada),
        ("lang_extra::ocaml", lang_extra::detect_ocaml, lang_extra::demangle_ocaml),
        ("lang_extra::ghc", lang_extra::detect_ghc, lang_extra::demangle_ghc),
        ("lang_extra::c_decorated", lang_extra::detect_c_decorated, lang_extra::demangle_c_decorated),
        ("lang_more::fortran_hpc::cuda_stub", lang_more::fortran_hpc::detect_cuda_stub, lang_more::fortran_hpc::demangle_cuda_stub),
        ("lang_more::fortran_hpc::gcc_omp", lang_more::fortran_hpc::detect_gcc_omp, lang_more::fortran_hpc::demangle_gcc_omp),
        ("lang_more::fortran_hpc::clang_omp", lang_more::fortran_hpc::detect_clang_omp, lang_more::fortran_hpc::demangle_clang_omp),
        ("lang_more::fortran_hpc::intel_fortran", lang_more::fortran_hpc::detect_intel_fortran, lang_more::fortran_hpc::demangle_intel_fortran),
        ("lang_more::fortran_hpc::f77_underscore", lang_more::fortran_hpc::detect_f77_underscore, lang_more::fortran_hpc::demangle_f77_underscore),
        ("lang_more::jvm::kotlin_native", lang_more::jvm::detect_kotlin_native, lang_more::jvm::demangle_kotlin_native),
        ("lang_more::jvm::clojure", lang_more::jvm::detect_clojure, lang_more::jvm::demangle_clojure),
        ("lang_more::jvm::scala", lang_more::jvm::detect_scala, lang_more::jvm::demangle_scala),
        ("lang_more::legacy_native::cfront", lang_more::legacy_native::detect_cfront, lang_more::legacy_native::demangle_cfront),
        ("lang_more::legacy_native::watcom", lang_more::legacy_native::detect_watcom, lang_more::legacy_native::demangle_watcom),
        ("lang_more::legacy_native::mex", lang_more::legacy_native::detect_mex, lang_more::legacy_native::demangle_mex),
        ("lang_more::legacy_native::gnucobol", lang_more::legacy_native::detect_gnucobol, lang_more::legacy_native::demangle_gnucobol),
        ("lang_more::modern_native::julia", lang_more::modern_native::detect_julia, lang_more::modern_native::demangle_julia),
        ("lang_more::modern_native::nim", lang_more::modern_native::detect_nim, lang_more::modern_native::demangle_nim),
        ("lang_more::modern_native::crystal", lang_more::modern_native::detect_crystal, lang_more::modern_native::demangle_crystal),
        ("lang_more::modern_native::zig", lang_more::modern_native::detect_zig, lang_more::modern_native::demangle_zig),
        ("lang_more::pascal_family::borland", lang_more::pascal_family::detect_borland, lang_more::pascal_family::demangle_borland),
        ("lang_more::pascal_family::fpc", lang_more::pascal_family::detect_fpc, lang_more::pascal_family::demangle_fpc),
        ("lang_more::scripting::python3_init", lang_more::scripting::detect_python3_init, lang_more::scripting::demangle_python3_init),
        ("lang_more::scripting::python2_init", lang_more::scripting::detect_python2_init, lang_more::scripting::demangle_python2_init),
        ("lang_more::scripting::ruby_init", lang_more::scripting::detect_ruby_init, lang_more::scripting::demangle_ruby_init),
        ("lang_more::scripting::php", lang_more::scripting::detect_php, lang_more::scripting::demangle_php),
        ("lang_more::scripting::lua", lang_more::scripting::detect_lua, lang_more::scripting::demangle_lua),
        ("lang_more::scripting::perl_xs", lang_more::scripting::detect_perl_xs, lang_more::scripting::demangle_perl_xs),
        ("lang_more::scripting::napi", lang_more::scripting::detect_napi, lang_more::scripting::demangle_napi),
        ("lang_more::scripting::r_init", lang_more::scripting::detect_r_init, lang_more::scripting::demangle_r_init),
        ("lang_more::scripting::tcl", lang_more::scripting::detect_tcl, lang_more::scripting::demangle_tcl),
    ]
}

/// Inputs chosen from the shapes that actually broke these decoders — boundary
/// underscores, empty and digit-initial components, truncation, sigils
/// belonging to other ABIs — plus both real corpora.
fn inputs() -> Vec<String> {
    let mut v: Vec<String> = [
        "a__b", "a___b", "a____b", "_a__b", "a__b_", "a__2b", "__a_MOD_x",
        "___a_MOD_x", "__a_MOD_", "Java_a_B_c", "Java_a_B_c_0b", "Java_a_B_c_4b",
        "caml_a__b", "camlA__b__c", "_ada_x", "x", "_", "__", "___", "_Z1fv",
        "_RNvC1a1b", "_D3fooZ", "$s1a1bC", "Init_x", "luaopen_a_b", "Z1TZ2H",
        "mymod_MP_x", "a.b.c", "go.func.1", "main.main", "_main.main",
        "__imp_x", "?f@@YAXXZ", ".pdata$_ZL1fv_info", "some_c_function_info",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    v.extend(
        include_str!("data/real_symbols.txt")
            .lines()
            .chain(include_str!("data/pdb_symbols.txt").lines())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned),
    );
    v
}

#[test]
fn every_convention_detector_agrees_with_its_backend() {
    let pairs = pairs();
    let inputs = inputs();
    let mut offenders: Vec<String> = Vec::new();
    let mut claims = 0usize;

    for (name, detect, demangle) in &pairs {
        for i in &inputs {
            let (d, m) = (detect(i), demangle(i).is_some());
            if d {
                claims += 1;
            }
            match (d, m) {
                (true, false) => offenders.push(format!("{name}: CLAIMS but cannot decode {i:?}")),
                (false, true) => offenders.push(format!("{name}: decodes UNCLAIMED {i:?}")),
                _ => {}
            }
        }
    }

    // Vacuity guards: "no offenders because it is right" and "no offenders
    // because nothing was checked" look identical from a green test.
    assert!(pairs.len() >= 33, "only {} pairs in the table", pairs.len());
    assert!(inputs.len() > 6000, "only {} inputs", inputs.len());
    // Only ~8, and that number is the point rather than a weak threshold: the
    // real corpora are Itanium and Go ONLY, so none of the 33 conventions
    // matches them and they contribute almost nothing here. Every claim comes
    // from the hand-picked list above. That is exactly why the defects in this
    // area were only ever found by grammar-derived inputs, and why raising
    // this number would mean adding a corpus, not loosening a detector.
    assert!(claims >= 8, "vacuous: only {claims} claims, expected >= 8");
    assert!(
        offenders.is_empty(),
        "{} detector/backend divergences:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

/// The table above must not fall behind the source.
///
/// Measuring coverage by grepping names is a trap this session has already
/// fallen into — but the failure mode here is the opposite one: a NEW
/// `detect_X`/`demangle_X` pair added later would silently go unguarded. So
/// the check is defined over the sources, and it only has to answer "is every
/// pair present in the table", which a name scan can answer exactly.
#[test]
fn the_pair_table_covers_every_convention_detector() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.join("lang_extra.rs")];
    for e in std::fs::read_dir(src.join("lang_more")).expect("lang_more must exist") {
        let p = e.expect("dir entry").path();
        if p.extension().is_some_and(|x| x == "rs") {
            files.push(p);
        }
    }
    assert!(files.len() > 5, "vacuous: only {} sources", files.len());

    let table = pairs();
    let mut missing: Vec<String> = Vec::new();
    let mut found = 0usize;
    for f in &files {
        let text = std::fs::read_to_string(f).expect("source must be readable");
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("pub fn detect_") else {
                continue;
            };
            let Some(stem) = rest.split('(').next() else {
                continue;
            };
            // Only pairs: a detector with no `demangle_` twin is out of scope.
            if !text.contains(&format!("pub fn demangle_{stem}(")) {
                continue;
            }
            found += 1;
            if !table.iter().any(|(n, _, _)| n.ends_with(&format!("::{stem}"))) {
                missing.push(format!("{}: detect_{stem}", f.display()));
            }
        }
    }
    assert!(found >= 33, "vacuous: only {found} pairs found in the source");
    assert!(
        missing.is_empty(),
        "these detector/backend pairs are not guarded by \
         `every_convention_detector_agrees_with_its_backend`:\n{}",
        missing.join("\n")
    );
}
