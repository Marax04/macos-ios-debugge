//! Demanglers for modern native-compiled languages: Julia, Nim, Crystal and
//! Zig, plus documentation for schemes that are intentionally *not* claimed.
//!
//! Every detector here is strict: this module runs inside the auto-dispatcher
//! after the prefix-based ABIs (Rust `_R`, Itanium `_Z`, MSVC `?…@@`, Swift
//! `$s`, D `_D`) and before Go, whose permissive any-name-with-a-dot detector
//! must stay last. A permissive detector here would steal symbols from those
//! ABIs, so each scheme requires its own unambiguous marker.
//!
//! # Schemes intentionally not claimed
//!
//! - **Julia runtime** (`jl_*`, e.g. `jl_apply_generic`, `jl_gc_alloc`):
//!   these are plain, unmangled C names of the libjulia runtime; there is
//!   nothing to demangle and claiming the whole `jl_` prefix would be
//!   needlessly greedy. Only *compiled Julia functions* (`julia_`, `japi1_`,
//!   `j_` + trailing numeric specialization id) are claimed.
//! - **Zig plain names**: ordinary Zig symbols are fully qualified dotted
//!   names (`std.mem.copy`, `main.main`) with no mangling at all — they are
//!   byte-for-byte indistinguishable from Go symbols, so they are left to the
//!   Go demangler. Only Zig's anonymous/generic instantiation marker
//!   `__anon_<id>` is distinctive enough to claim.
//! - **V**: the V compiler emits plain C names of the form `module__fn`
//!   (e.g. `main__main`) — a bare double underscore also used by GNAT Ada and
//!   many C runtimes, so it is too weak to detect.
//! - **Odin**: Odin emits dotted `package.procedure` names (plus `..` for
//!   polymorphic instantiations in some versions) — again indistinguishable
//!   from Go's scheme; left to the Go demangler.
//! - **Carbon**: the language has no stable toolchain or documented symbol
//!   mangling yet; nothing to implement.
//! - **Erlang/Elixir NIFs**: NIF libraries are ordinary C/C++ shared objects;
//!   the only convention is an informal `_nif` suffix on plain C names, far
//!   too weak to detect.

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// ── Julia ────────────────────────────────────────────────────────────────────

/// Compiled Julia function symbols.
///
/// They appear in native code as `julia_<name>_<id>`, `japi1_<name>_<id>` or
/// `j_<name>_<id>`, where `<id>` is a decimal specialization id appended by
/// the Julia code generator (e.g. `julia_typeinf_ext_1067`,
/// `japi1_print_1234`).
///
/// `<name>` may contain
/// Julia's `!` mutation suffix. Runtime `jl_*` names are plain C and are not
/// claimed (see module docs).
#[must_use]
pub fn detect_julia(mangled: &str) -> bool {
    julia_parts(mangled).is_some()
}

fn julia_parts(mangled: &str) -> Option<(&str, &str)> {
    let rest = mangled
        .strip_prefix("julia_")
        .or_else(|| mangled.strip_prefix("japi1_"))
        .or_else(|| mangled.strip_prefix("j_"))?;
    let (name, id) = rest.rsplit_once('_')?;
    if name.is_empty() || id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Julia identifiers: ASCII identifier chars plus `!` (and `.` for
    // qualified names in some dumps). Reject anything wilder.
    if !name.chars().all(|c| is_ident_char(c) || c == '!' || c == '.') {
        return None;
    }
    Some((name, id))
}

/// Demangle a compiled Julia function symbol: strip the code-generator prefix
/// and the trailing numeric specialization id
/// (`julia_typeinf_ext_1067` → `typeinf_ext`).
#[must_use]
pub fn demangle_julia(mangled: &str) -> Option<String> {
    let (name, _id) = julia_parts(mangled)?;
    Some(name.to_owned())
}

// ── Nim ──────────────────────────────────────────────────────────────────────

/// Modern Nim (1.x/2.x C backend) mangles `proc name` in module `m` as
/// `<name>__<moduleAlias>_u<int>` (e.g. `main__test_u4`,
/// `newSeq__systemZassertions_u56`).
///
/// The module alias encodes path
/// separators as `Z`. The detector requires the exact `__…_u<digits>` shape,
/// no leading underscore (which keeps out gfortran `__mod_MOD_…` and C
/// runtime names), and identifier characters only.
///
/// **The `_u<int>` suffix does NOT keep GNAT Ada out.** This detector does not
/// decide the routing: Ada is tried first on the live path, its detector knows
/// nothing about `_u<int>`, and an all-lowercase Nim symbol satisfies it — so
/// `main__test_u4` decodes as Ada `main.test_u4` and never arrives here. Only a
/// module alias carrying an uppercase letter (`systemZassertions`) fails Ada's
/// charset test and reaches this decoder.
///
/// That is not obviously wrong: `Main.Test_U4` is a real GNAT name mangling to
/// the same bytes, so the input is genuinely ambiguous and Ada-first is a
/// choice rather than a defect. It is spelled out because the previous wording
/// asserted the opposite and was measured false
/// (`tests/disambiguator_collisions.rs::lowercase_nim_symbols_are_routed_to_ada`).
#[must_use]
pub fn detect_nim(mangled: &str) -> bool {
    nim_parts(mangled).is_some()
}

fn nim_parts(mangled: &str) -> Option<(&str, &str, &str)> {
    if mangled.starts_with('_') || !mangled.chars().all(is_ident_char) {
        return None;
    }
    // Last `__` separates the proc name from `<moduleAlias>_u<digits>`.
    let sep = mangled.rfind("__")?;
    let name = &mangled[..sep];
    let rest = &mangled[sep + 2..];
    let (module, id) = rest.rsplit_once("_u")?;
    if name.is_empty()
        || module.is_empty()
        || module.contains('_')
        || id.is_empty()
        || !id.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((name, module, id))
}

/// Demangle a Nim symbol to `module.name`
/// (`main__test_u4` → `test.main`). The module alias is kept verbatim
/// (its `Z` path-separator escapes are not expanded).
#[must_use]
pub fn demangle_nim(mangled: &str) -> Option<String> {
    let (name, module, _id) = nim_parts(mangled)?;
    Some(format!("{module}.{name}"))
}

// ── Crystal ──────────────────────────────────────────────────────────────────

/// Crystal symbol detection (leading `*`).
///
/// Crystal symbols read `*Class#method<GenericArgs>:ReturnType` (instance
/// methods), `*Class::method:ReturnType` (class methods / top-level
/// functions in a namespace) or `*fn:ReturnType` (e.g.
/// `*CallStack::unwind:Array(Pointer(Void))`).
///
/// No other ABI uses a leading
/// `*`, so the detector requires it plus a `:` or `#` and printable content.
#[must_use]
pub fn detect_crystal(mangled: &str) -> bool {
    mangled.strip_prefix('*').is_some_and(|rest| {
        !rest.is_empty()
            && (rest.contains(':') || rest.contains('#'))
            && !rest.starts_with(':')
            && !rest.starts_with('#')
            // Whitespace only occurs inside a generic argument list
            // (`<Foo, Int32>`); a space before any `<` is not Crystal.
            && !rest.split('<').next().unwrap_or(rest).contains(char::is_whitespace)
    })
}

/// Demangle a Crystal symbol to its short form.
///
/// Strips the leading `*`, and
/// cut at the generic argument list (`<…>`) or the return-type `:` —
/// while keeping `::` namespace separators intact
/// (`*CallStack::unwind:Array(Pointer(Void))` → `CallStack::unwind`,
/// `*Foo#bar<Foo, Int32>:Int32` → `Foo#bar`).
#[must_use]
pub fn demangle_crystal(mangled: &str) -> Option<String> {
    if !detect_crystal(mangled) {
        return None;
    }
    let rest = &mangled[1..];
    let bytes = rest.as_bytes();
    let mut end = rest.len();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => {
                end = i;
                break;
            }
            b':' => {
                if bytes.get(i + 1) == Some(&b':') {
                    i += 2;
                    continue;
                }
                end = i;
                break;
            }
            _ => i += 1,
        }
    }
    let short = &rest[..end];
    if short.is_empty() {
        return None;
    }
    Some(short.to_owned())
}

// ── Zig ──────────────────────────────────────────────────────────────────────

/// Zig anonymous/generic instantiations carry the distinctive marker
/// `__anon_<id>` on an otherwise plain dotted qualified name
/// (e.g. `std.fmt.format__anon_1234`).
///
/// Only such names are claimed: plain
/// dotted Zig names are indistinguishable from Go (see module docs). The
/// detector requires a dot before the marker and a decimal id after it.
#[must_use]
pub fn detect_zig(mangled: &str) -> bool {
    zig_parts(mangled).is_some()
}

fn zig_parts(mangled: &str) -> Option<(&str, &str)> {
    let pos = mangled.find("__anon_")?;
    let base = &mangled[..pos];
    let id = &mangled[pos + "__anon_".len()..];
    if base.is_empty()
        || id.is_empty()
        || !id.bytes().all(|b| b.is_ascii_digit())
        || !base.contains('.')
        || base.starts_with('_')
        || !base.chars().all(|c| is_ident_char(c) || c == '.')
    {
        return None;
    }
    Some((base, id))
}

/// Demangle a Zig anonymous-instantiation symbol by dropping the `__anon_<id>`
/// suffix (`std.fmt.format__anon_1234` → `std.fmt.format`).
#[must_use]
pub fn demangle_zig(mangled: &str) -> Option<String> {
    let (base, _id) = zig_parts(mangled)?;
    Some(base.to_owned())
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Try every scheme in this module, strictest first, returning the demangled
/// text and the language name on the first match.
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    if let Some(s) = demangle_crystal(mangled) {
        return Some((s, "Crystal"));
    }
    if let Some(s) = demangle_julia(mangled) {
        return Some((s, "Julia"));
    }
    if let Some(s) = demangle_zig(mangled) {
        return Some((s, "Zig"));
    }
    if let Some(s) = demangle_nim(mangled) {
        return Some((s, "Nim"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn julia_compiled_functions() {
        assert_eq!(
            demangle_julia("julia_typeinf_ext_1067").as_deref(),
            Some("typeinf_ext")
        );
        assert_eq!(
            demangle_julia("julia_generic_matmatmul!_4276").as_deref(),
            Some("generic_matmatmul!")
        );
        assert_eq!(
            demangle_julia("japi1_print_1234").as_deref(),
            Some("print")
        );
        assert_eq!(demangle_julia("j_getindex_2001").as_deref(), Some("getindex"));
        assert_eq!(
            demangle("julia_typeinf_ext_1067"),
            Some(("typeinf_ext".to_owned(), "Julia"))
        );
    }

    #[test]
    fn julia_rejects() {
        // Runtime names are plain C: intentionally not claimed.
        assert!(!detect_julia("jl_apply_generic"));
        // No trailing numeric id.
        assert!(!detect_julia("julia_main"));
        assert!(!detect_julia("julia__42")); // empty name
        assert!(!detect_julia("j_1234")); // id only
    }

    #[test]
    fn nim_symbols() {
        assert_eq!(
            demangle_nim("main__test_u4").as_deref(),
            Some("test.main")
        );
        assert_eq!(
            demangle_nim("newSeq__systemZassertions_u56").as_deref(),
            Some("systemZassertions.newSeq")
        );
        assert_eq!(
            demangle("main__test_u4"),
            Some(("test.main".to_owned(), "Nim"))
        );
    }

    #[test]
    fn nim_rejects() {
        // GNAT Ada: no `_u<int>` suffix.
        assert!(!detect_nim("pkg__child__subprogram"));
        // gfortran module procedure: leading underscores.
        assert!(!detect_nim("__mymod_MOD_solve"));
        // C runtime doubled-underscore names.
        assert!(!detect_nim("__libc_start_main"));
        // `_u` must be followed by digits only.
        assert!(!detect_nim("main__test_util"));
    }

    #[test]
    fn crystal_symbols() {
        assert_eq!(
            demangle_crystal("*CallStack::unwind:Array(Pointer(Void))").as_deref(),
            Some("CallStack::unwind")
        );
        assert_eq!(
            demangle_crystal("*Foo#bar<Foo, Int32>:Int32").as_deref(),
            Some("Foo#bar")
        );
        assert_eq!(
            demangle_crystal("*raise<Exception+>:NoReturn").as_deref(),
            Some("raise")
        );
        assert_eq!(
            demangle("*CallStack::unwind:Array(Pointer(Void))"),
            Some(("CallStack::unwind".to_owned(), "Crystal"))
        );
    }

    #[test]
    fn crystal_rejects() {
        assert!(!detect_crystal("CallStack::unwind")); // no leading `*`
        assert!(!detect_crystal("*")); // empty
        assert!(!detect_crystal("*plainname")); // no `:` or `#`
        assert!(demangle_crystal("*:Int32").is_none()); // empty short form
    }

    #[test]
    fn zig_anon_instantiations() {
        assert_eq!(
            demangle_zig("std.fmt.format__anon_1234").as_deref(),
            Some("std.fmt.format")
        );
        assert_eq!(
            demangle("std.fmt.format__anon_1234"),
            Some(("std.fmt.format".to_owned(), "Zig"))
        );
    }

    #[test]
    fn zig_rejects() {
        // Plain dotted Zig names are left to Go.
        assert!(!detect_zig("std.mem.copy"));
        assert!(!detect_zig("main.main"));
        // Marker without a dotted base or without a numeric id.
        assert!(!detect_zig("format__anon_1234"));
        assert!(!detect_zig("std.fmt.format__anon_x"));
    }

    #[test]
    fn other_abis_rejected_everywhere() {
        for sym in [
            "_Z3fooi",              // Itanium
            "?f@@YAHH@Z",           // MSVC
            "_RNvC3foo3bar",        // Rust v0
            "$s4main3fooyyF",       // Swift
            "_D4core4main1fFZv",    // D
            "main.main",            // Go
            "Java_com_x_Y_m",       // JNI
            "__mymod_MOD_solve",    // gfortran
            "pkg__child__sub",      // GNAT Ada
        ] {
            assert!(demangle(sym).is_none(), "wrongly claimed: {sym}");
        }
    }
}
