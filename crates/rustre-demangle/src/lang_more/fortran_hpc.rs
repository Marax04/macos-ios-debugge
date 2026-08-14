//! Demanglers for Fortran and HPC-runtime symbol conventions.
//!
//! Covered schemes (strictest first, as tried by [`demangle`]):
//!
//! 1. **CUDA kernel host stubs** (`__device_stub__Z...`): nvcc emits a host-side
//!    stub for every `__global__` kernel by prefixing the Itanium-mangled kernel
//!    name with `__device_stub_`. We strip the prefix, label the symbol as a
//!    stub, and return the inner `_Z...` name *intact* so the caller can feed it
//!    back through an Itanium demangler. Runtime registration plumbing such as
//!    `__cudaRegisterFunction` / `__cudaRegisterFatBinary` are plain C symbols,
//!    not mangled names, and are intentionally not handled here.
//! 2. **GCC OpenMP outlined regions** (`<base>._omp_fn.<N>`): GCC's OpenMP
//!    lowering outlines each `#pragma omp parallel`/`task` body into a function
//!    named after its host function with an `._omp_fn.<N>` suffix. `<base>` may
//!    itself be Itanium-mangled (C++ host function); it is returned intact
//!    inside the label so the caller can re-demangle it.
//! 3. **Clang/LLVM OpenMP outlined regions** (`<base>.omp_outlined.` or
//!    `<base>.omp_outlined..<N>`): same idea, Clang spelling.
//! 4. **Intel ifort/ifx module procedures** (`<module>_mp_<proc>_`): all
//!    lowercase, module and procedure joined by `_mp_`, one trailing
//!    underscore. Example: `mymod_mp_solve_` → `mymod::solve`.
//!
//! ## Intentionally NOT handled in [`demangle`]
//!
//! - **Bare f77 trailing-underscore names** (`dgemm_`, `my_sub__`): the classic
//!   Fortran-77 convention appends one underscore (two with `g77 -fsecond-underscore`
//!   style when the name itself contains an underscore). This pattern matches an
//!   enormous number of ordinary C symbols (`pthread_create_`-alikes, any
//!   `snake_case` name someone suffixed), so a detector permissive enough to catch
//!   real f77 symbols would steal names from every other ABI in the
//!   auto-dispatcher. It is therefore **gated out of [`demangle`]** and exposed
//!   only as a classification *hint* via [`detect_f77_underscore`] /
//!   [`demangle_f77_underscore`], which callers may use when they already know
//!   the object file came from a Fortran compiler.
//! - **gfortran module procedures** (`__mod_MOD_proc`): implemented elsewhere in
//!   this crate; not duplicated here.
//! - **Cray CCE / classic-flang / LLVM flang module mangling**: reliable public
//!   documentation of the exact schemes (e.g. `proc_$module_`-style names or
//!   flang's `_QM<module>P<proc>` forms) could not be verified from this
//!   environment, so rather than guess and risk mis-demangling, these are left
//!   as documented future work.

/// Returns `true` if `mangled` looks like an nvcc CUDA kernel host stub,
/// i.e. `__device_stub_` immediately followed by an Itanium `_Z` name.
#[must_use]
pub fn detect_cuda_stub(mangled: &str) -> bool {
    mangled
        .strip_prefix("__device_stub__Z")
        .is_some_and(|rest| rest.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric()))
}

/// Demangles an nvcc CUDA kernel host stub.
///
/// Strips the `__device_stub_` prefix and returns a label containing the inner
/// Itanium-mangled kernel name **unmodified**, so the caller can re-demangle it:
/// `__device_stub__Z3addPi` → `[CUDA kernel stub] _Z3addPi`.
#[must_use]
pub fn demangle_cuda_stub(mangled: &str) -> Option<String> {
    if !detect_cuda_stub(mangled) {
        return None;
    }
    // Keep the leading `_Z` of the inner name: the stub prefix is `__device_stub_`.
    let inner = &mangled["__device_stub_".len()..];
    Some(format!("[CUDA kernel stub] {inner}"))
}

/// Returns `true` if `mangled` is a GCC OpenMP outlined function
/// (`<base>._omp_fn.<N>` with a non-empty base and a decimal region number).
#[must_use]
pub fn detect_gcc_omp(mangled: &str) -> bool {
    mangled.rfind("._omp_fn.").is_some_and(|pos| {
        let digits = &mangled[pos + "._omp_fn.".len()..];
        pos > 0 && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Demangles a GCC OpenMP outlined function.
///
/// `main._omp_fn.0` → `main [OpenMP outlined region 0]`. The base is returned
/// intact (it may itself be an Itanium-mangled C++ name for the caller to
/// re-demangle).
#[must_use]
pub fn demangle_gcc_omp(mangled: &str) -> Option<String> {
    if !detect_gcc_omp(mangled) {
        return None;
    }
    let pos = mangled.rfind("._omp_fn.")?;
    let base = &mangled[..pos];
    let n = &mangled[pos + "._omp_fn.".len()..];
    Some(format!("{base} [OpenMP outlined region {n}]"))
}

/// Returns `true` if `mangled` is a Clang/LLVM OpenMP outlined function
/// (`<base>.omp_outlined.` optionally followed by `.<N>` digits).
#[must_use]
pub fn detect_clang_omp(mangled: &str) -> bool {
    mangled.rfind(".omp_outlined.").is_some_and(|pos| {
        let rest = &mangled[pos + ".omp_outlined.".len()..];
        pos > 0
            && (rest.is_empty()
                || rest
                    .strip_prefix('.')
                    .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())))
    })
}

/// Demangles a Clang/LLVM OpenMP outlined function.
///
/// `_Z4workv.omp_outlined.` → `_Z4workv [OpenMP outlined region]`;
/// `main.omp_outlined..3` → `main [OpenMP outlined region 3]`.
/// The base is returned intact for possible re-demangling.
#[must_use]
pub fn demangle_clang_omp(mangled: &str) -> Option<String> {
    if !detect_clang_omp(mangled) {
        return None;
    }
    let pos = mangled.rfind(".omp_outlined.")?;
    let base = &mangled[..pos];
    let rest = &mangled[pos + ".omp_outlined.".len()..];
    Some(rest.strip_prefix('.').map_or_else(
        || format!("{base} [OpenMP outlined region]"),
        |n| format!("{base} [OpenMP outlined region {n}]"),
    ))
}

/// Returns `true` for a lowercase identifier chunk valid in an ifort name:
/// starts with a lowercase letter, then lowercase letters, digits or `_`.
fn is_ifort_ident(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Returns `true` if `mangled` is an Intel ifort/ifx module procedure:
/// `<module>_mp_<proc>_`, all lowercase, exactly one `_mp_` separator,
/// one trailing underscore.
#[must_use]
pub fn detect_intel_fortran(mangled: &str) -> bool {
    let Some(body) = mangled.strip_suffix('_') else {
        return false;
    };
    let Some(pos) = body.find("_mp_") else {
        return false;
    };
    // Exactly one `_mp_` separator keeps the detector strict.
    if body[pos + 4..].contains("_mp_") {
        return false;
    }
    let (module, proc) = (&body[..pos], &body[pos + 4..]);
    is_ifort_ident(module) && is_ifort_ident(proc) && !proc.ends_with('_')
}

/// Demangles an Intel ifort/ifx module procedure:
/// `mymod_mp_solve_` → `mymod::solve`.
#[must_use]
pub fn demangle_intel_fortran(mangled: &str) -> Option<String> {
    if !detect_intel_fortran(mangled) {
        return None;
    }
    let body = mangled.strip_suffix('_')?;
    let pos = body.find("_mp_")?;
    Some(format!("{}::{}", &body[..pos], &body[pos + 4..]))
}

/// Classification **hint** (deliberately excluded from [`demangle`]): `true`
/// if `mangled` could be a bare f77 trailing-underscore external
/// (`dgemm_`, `my_sub__`).
///
/// Requirements: all lowercase letters/digits/underscores, starts with a
/// letter, at least 3 characters before the suffix, and either one trailing
/// `_` (name without inner underscores) or two trailing `__` (name with inner
/// underscores, g77/gfortran `-fsecond-underscore`-style). Even so, this
/// matches countless ordinary C symbols — use only when the source object is
/// already known to be Fortran.
#[must_use]
pub fn detect_f77_underscore(mangled: &str) -> bool {
    let name = if let Some(n) = mangled.strip_suffix("__") {
        if !n.contains('_') {
            return false;
        }
        n
    } else if let Some(n) = mangled.strip_suffix('_') {
        if n.contains('_') {
            return false;
        }
        n
    } else {
        return false;
    };
    name.len() >= 3
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Demangles a bare f77 trailing-underscore external (hint-only; see
/// [`detect_f77_underscore`]): `dgemm_` → `dgemm`, `my_sub__` → `my_sub`.
#[must_use]
pub fn demangle_f77_underscore(mangled: &str) -> Option<String> {
    if !detect_f77_underscore(mangled) {
        return None;
    }
    Some(
        mangled
            .trim_end_matches('_')
            .to_owned(),
    )
}

/// Tries each Fortran/HPC scheme strictest-first and returns the demangled
/// text plus a language label. Bare f77 trailing-underscore names are
/// intentionally **not** tried here (see module docs).
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    if let Some(s) = demangle_cuda_stub(mangled) {
        return Some((s, "CUDA"));
    }
    if let Some(s) = demangle_gcc_omp(mangled) {
        return Some((s, "OpenMP (GCC)"));
    }
    if let Some(s) = demangle_clang_omp(mangled) {
        return Some((s, "OpenMP (Clang)"));
    }
    if let Some(s) = demangle_intel_fortran(mangled) {
        return Some((s, "Fortran (Intel)"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuda_stub() {
        assert_eq!(
            demangle_cuda_stub("__device_stub__Z3addPi").as_deref(),
            Some("[CUDA kernel stub] _Z3addPi")
        );
        assert_eq!(
            demangle("__device_stub__Z9vectorAddPKfS0_Pfi"),
            Some(("[CUDA kernel stub] _Z9vectorAddPKfS0_Pfi".to_owned(), "CUDA"))
        );
        assert!(!detect_cuda_stub("__device_stub__Z")); // empty inner name
        assert!(!detect_cuda_stub("__cudaRegisterFunction")); // plain C runtime symbol
    }

    #[test]
    fn gcc_omp() {
        assert_eq!(
            demangle("main._omp_fn.0"),
            Some(("main [OpenMP outlined region 0]".to_owned(), "OpenMP (GCC)"))
        );
        assert_eq!(
            demangle("_Z5solvev._omp_fn.2"),
            Some((
                "_Z5solvev [OpenMP outlined region 2]".to_owned(),
                "OpenMP (GCC)"
            ))
        );
        assert!(!detect_gcc_omp("main._omp_fn.")); // no region number
        assert!(!detect_gcc_omp("._omp_fn.0")); // empty base
    }

    #[test]
    fn clang_omp() {
        assert_eq!(
            demangle("_Z4workv.omp_outlined."),
            Some((
                "_Z4workv [OpenMP outlined region]".to_owned(),
                "OpenMP (Clang)"
            ))
        );
        assert_eq!(
            demangle("main.omp_outlined..3"),
            Some(("main [OpenMP outlined region 3]".to_owned(), "OpenMP (Clang)"))
        );
        assert!(!detect_clang_omp("main.omp_outlined..x"));
    }

    #[test]
    fn intel_fortran() {
        assert_eq!(
            demangle("mymod_mp_solve_"),
            Some(("mymod::solve".to_owned(), "Fortran (Intel)"))
        );
        assert_eq!(
            demangle_intel_fortran("linear_algebra_mp_lu_decomp_").as_deref(),
            Some("linear_algebra::lu_decomp")
        );
        assert!(!detect_intel_fortran("MyMod_mp_Solve_")); // uppercase
        assert!(!detect_intel_fortran("mymod_mp_solve")); // no trailing underscore
        assert!(!detect_intel_fortran("_mp_x_")); // empty module
        assert!(!detect_intel_fortran("a_mp_b_mp_c_")); // ambiguous double separator
    }

    #[test]
    fn f77_hint_only() {
        // Valid as a hint...
        assert!(detect_f77_underscore("dgemm_"));
        assert_eq!(demangle_f77_underscore("my_sub__").as_deref(), Some("my_sub"));
        // ...but never claimed by the dispatcher entry point.
        assert_eq!(demangle("dgemm_"), None);
        assert_eq!(demangle("my_sub__"), None);
        // Strictness of the hint itself.
        assert!(!detect_f77_underscore("ab_")); // too short
        assert!(!detect_f77_underscore("my_sub_")); // inner underscore needs double suffix
        assert!(!detect_f77_underscore("dgemm__")); // double suffix needs inner underscore
        assert!(!detect_f77_underscore("Foo_")); // uppercase
    }

    #[test]
    fn rejects_other_abis() {
        for sym in [
            "_Z3fooi",
            "?f@@YAHH@Z",
            "_RNvC3foo3bar",
            "$s4main3fooyyF",
            "_D4core4stdcQf",
            "main.main",
            "runtime.morestack",
            "__mymod_MOD_myproc", // gfortran, handled elsewhere
            "__cudaRegisterFunction",
        ] {
            assert_eq!(demangle(sym), None, "must not claim {sym}");
        }
    }
}
