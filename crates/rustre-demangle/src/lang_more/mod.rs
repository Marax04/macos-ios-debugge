//! Demanglers for the long tail of language runtimes: scripting-extension
//! entry points, JVM-family encodings, the Pascal family, Fortran/HPC,
//! modern natives and legacy C++ schemes.
//!
//! Every submodule exposes `demangle(mangled) -> Option<(String, &'static str)>`
//! returning the readable form plus the language name; [`demangle_more`]
//! tries them strictest-first. These run in the auto-dispatcher after the
//! core ABIs and [`crate::lang_extra`], and before Go (whose permissive
//! detector must stay last).

pub mod fortran_hpc;
pub mod jvm;
pub mod legacy_native;
pub mod modern_native;
pub mod pascal_family;
pub mod scripting;

use crate::lang_extra::SymFeatures;

/// Try every language group in this module, strictest first.
///
/// Returns the demangled text and the language name.
#[must_use]
pub fn demangle_more(mangled: &str) -> Option<(String, &'static str)> {
    let features = SymFeatures::scan(mangled);
    demangle_more_with(mangled, &features)
}

/// [`demangle_more`] with pre-computed [`SymFeatures`], sharing the byte scan
/// with [`crate::lang_extra::demangle_extra_with`] on the hot path.
///
/// Each family is guarded by a *necessary* condition of its detectors
/// (equivalence enforced by `tests/gate_equivalence.rs`):
/// - jvm: Kotlin/Native starts with `k` and needs `:`; every Clojure/Scala
///   accepting branch needs a `$`.
/// - pascal: Borland/Delphi starts with `@`; FPC starts with an uppercase
///   letter and every accepted shape contains `$`.
/// - `fortran_hpc`: CUDA stubs start with `_`; OpenMP outlining needs `.`;
///   ifort `_mp_` symbols end with `_`.
/// - scripting: fixed prefixes (`napi…`, `PyInit_`, `R_…`, `luaopen_`,
///   `zif_`/`zim_`, `XS_`/`boot_`, `Init_`); Tcl entry points end in
///   `…Init`/`…Unload` (last byte `t`/`d`) and contain `_`. Python 2's bare
///   `init` prefix is deliberately absent — it is not dispatched generically.
/// - `modern_native`: Crystal starts with `*`, Julia with `j`; Zig (`__anon_`)
///   and Nim (`…__<alias>_u<n>`) both contain `__`.
/// - `legacy_native`: cfront and `GnuCOBOL` contain `__`; Watcom starts with
///   `W`; MEX is `mexFunction`/`mexfilerequiredapiversion` with optional `_`.
pub(crate) fn demangle_more_with(
    mangled: &str,
    f: &SymFeatures,
) -> Option<(String, &'static str)> {
    if ((f.first == b'k' && f.has_colon) || f.has_dollar)
        && let Some(r) = jvm::demangle(mangled)
    {
        return Some(r);
    }
    if (f.first == b'@' || (f.has_dollar && f.first.is_ascii_uppercase()))
        && let Some(r) = pascal_family::demangle(mangled)
    {
        return Some(r);
    }
    if (f.first == b'_' || f.has_dot || f.last == b'_')
        && let Some(r) = fortran_hpc::demangle(mangled)
    {
        return Some(r);
    }
    // `b'i'` was here only for the Python 2 `init<module>` rule, which no
    // longer runs generically (see `scripting::demangle`); dropping it keeps
    // every lowercase-`i` C name off this path entirely.
    if (matches!(f.first, b'n' | b'P' | b'R' | b'l' | b'z' | b'X' | b'b' | b'I')
        || (f.has_underscore && matches!(f.last, b't' | b'd')))
        && let Some(r) = scripting::demangle(mangled)
    {
        return Some(r);
    }
    if (matches!(f.first, b'*' | b'j') || f.has_dunder)
        && let Some(r) = modern_native::demangle(mangled)
    {
        return Some(r);
    }
    if (f.has_dunder || matches!(f.first, b'W' | b'm' | b'_'))
        && let Some(r) = legacy_native::demangle(mangled)
    {
        return Some(r);
    }
    None
}
