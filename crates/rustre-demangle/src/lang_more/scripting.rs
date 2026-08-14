//! Native-extension entry-point conventions of scripting languages.
//!
//! Scripting languages (Python, Ruby, PHP, Lua, Perl, JavaScript/Node.js, R,
//! Tcl) do **not** mangle their own user-level names — they are interpreted or
//! byte-compiled and keep names in interpreter data structures. What *does*
//! show up in native binaries is the C entry point each runtime looks up when
//! loading a compiled extension module. This module decodes those
//! conventions:
//!
//! - **Python**: `PyInit_<module>` (Python 3) and `init<module>` (Python 2).
//!   Runtime-internal symbols (`PyEval_*`, `_Py*`, `PyObject_*`, …) are C API
//!   functions of the interpreter itself, not user code, and are intentionally
//!   not claimed here.
//! - **Ruby**: `Init_<ext>`.
//! - **PHP**: `zif_<function>` (Zend internal function), `zim_<Class>_<method>`
//!   (Zend internal method). Other `zend_*` symbols belong to the Zend engine
//!   runtime and are not claimed.
//! - **Lua**: `luaopen_<module>`, where dots in the module path become
//!   underscores (`luaopen_socket_core` → `require "socket.core"`).
//! - **Perl XS**: `XS_<Package>_<name>` and `boot_<Package>`, where the
//!   package separator `::` becomes `__`.
//! - **Node.js N-API / node-gyp**: the fixed registration exports
//!   `napi_register_module_v1` and `node_api_module_get_api_version_v1` are
//!   recognized and labeled. NAN/V8 C++ addon wrappers are Itanium-mangled
//!   (`_Z…`) and handled by the C++ demangler, not here.
//! - **R**: `R_init_<pkg>` (and its unload twin `R_unload_<pkg>`).
//! - **Tcl**: `<Pkg>_Init` / `<Pkg>_SafeInit` / `<Pkg>_Unload`. This suffix
//!   convention is inherently permissive, so it is matched only when the
//!   package part starts with an uppercase letter and is purely alphanumeric,
//!   and it is tried last.
//!
//! Not applicable (documented, deliberately absent): pure-Python/Ruby/PHP/
//! Lua/Perl/JS user symbols, Python `cpdef`/Cython internals (Itanium or plain
//! C), PHP userland functions, shell languages.
//!
//! Every detector is strict: these run in the auto-dispatcher after the
//! prefix-based ABIs (Rust `_R`, Itanium `_Z`, MSVC `?`, Swift `$s`, D `_D`)
//! and before Go's permissive any-name-with-a-dot detector, so nothing here
//! may claim `_Z3fooi`, `?f@@YAHH@Z`, `_RNvC3foo3bar`, `$s4main…`, `_Dmain`,
//! or `main.main`.

/// Returns `true` if every char is `[A-Za-z0-9_]` and the string is a valid C
/// identifier (non-empty, does not start with a digit).
fn is_c_ident(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ── Python ───────────────────────────────────────────────────────────────────

/// Detect a Python 3 C-extension init symbol `PyInit_<module>`.
#[must_use]
pub fn detect_python3_init(mangled: &str) -> bool {
    mangled
        .strip_prefix("PyInit_")
        .is_some_and(is_c_ident)
}

/// Demangle `PyInit_<module>` to a readable description.
///
/// `PyInit_spam` → `python module init: spam`. Dotted submodule paths keep
/// their underscores (`CPython` uses the last path component only).
#[must_use]
pub fn demangle_python3_init(mangled: &str) -> Option<String> {
    let module = mangled.strip_prefix("PyInit_").filter(|m| is_c_ident(m))?;
    Some(format!("python module init: {module}"))
}

/// Detect a Python 2 C-extension init symbol `init<module>`.
///
/// This prefix is short and could collide with unrelated C functions
/// (`initgraph`, …), so it is only consulted after every other scheme in this
/// module and requires a lowercase-starting identifier module name, matching
/// Python 2 module naming practice.
#[must_use]
pub fn detect_python2_init(mangled: &str) -> bool {
    mangled.strip_prefix("init").is_some_and(|m| {
        is_c_ident(m) && m.chars().next().is_some_and(|c| c.is_ascii_lowercase())
    })
}

/// Demangle `init<module>` (Python 2) to a readable description.
///
/// **Not used by the generic dispatcher**, and unsafe to apply blindly: the
/// `init` prefix has no distinguishing mark, so any C identifier starting with
/// `init` plus a lowercase letter matches — `initialized` yields the module
/// `ialized`. Call this only when the binary is known to be a Python 2
/// extension.
#[must_use]
pub fn demangle_python2_init(mangled: &str) -> Option<String> {
    if !detect_python2_init(mangled) {
        return None;
    }
    let module = mangled.strip_prefix("init")?;
    Some(format!("python2 module init: {module}"))
}

// ── Ruby ─────────────────────────────────────────────────────────────────────

/// Detect a Ruby C-extension init symbol `Init_<ext>`.
#[must_use]
pub fn detect_ruby_init(mangled: &str) -> bool {
    mangled.strip_prefix("Init_").is_some_and(is_c_ident)
}

/// Demangle `Init_<ext>` to a readable description.
///
/// `Init_nokogiri` → `ruby extension init: nokogiri`.
#[must_use]
pub fn demangle_ruby_init(mangled: &str) -> Option<String> {
    let ext = mangled.strip_prefix("Init_").filter(|m| is_c_ident(m))?;
    Some(format!("ruby extension init: {ext}"))
}

// ── PHP / Zend ───────────────────────────────────────────────────────────────

/// Detect a PHP Zend internal-function symbol `zif_<function>` or
/// internal-method symbol `zim_<Class>_<method>`.
#[must_use]
pub fn detect_php(mangled: &str) -> bool {
    mangled
        .strip_prefix("zif_")
        .is_some_and(is_c_ident)
        || mangled
            .strip_prefix("zim_")
            .is_some_and(|r| is_c_ident(r) && r.contains('_'))
}

/// Demangle a PHP `zif_`/`zim_` symbol.
///
/// `zif_strlen` → `php function: strlen`;
/// `zim_DateTime_format` → `php method: DateTime::format`.
#[must_use]
pub fn demangle_php(mangled: &str) -> Option<String> {
    if let Some(func) = mangled.strip_prefix("zif_").filter(|m| is_c_ident(m)) {
        return Some(format!("php function: {func}"));
    }
    let rest = mangled
        .strip_prefix("zim_")
        .filter(|m| is_c_ident(m) && m.contains('_'))?;
    // Class names cannot contain `_`-ambiguity-free separators; the Zend
    // convention is `zim_<Class>_<method>` with the FIRST underscore after the
    // class name. Split at the first `_` (classes with underscores are rare;
    // this matches how tooling like gdb pretty-printers splits it).
    let (class, method) = rest.split_once('_')?;
    if method.is_empty() {
        return None;
    }
    Some(format!("php method: {class}::{method}"))
}

// ── Lua ──────────────────────────────────────────────────────────────────────

/// Detect a Lua C-module open symbol `luaopen_<module>`.
#[must_use]
pub fn detect_lua(mangled: &str) -> bool {
    mangled.strip_prefix("luaopen_").is_some_and(is_c_ident)
}

/// Demangle `luaopen_<module>`; underscores map back to dots
/// (`luaopen_socket_core` → `lua module open: socket.core`).
#[must_use]
pub fn demangle_lua(mangled: &str) -> Option<String> {
    let module = mangled
        .strip_prefix("luaopen_")
        .filter(|m| is_c_ident(m))?;
    Some(format!("lua module open: {}", module.replace('_', ".")))
}

// ── Perl XS ──────────────────────────────────────────────────────────────────

/// Detect a Perl XS symbol `XS_<Package>_<name>` or `boot_<Package>`
/// (`::` mangled as `__`).
#[must_use]
pub fn detect_perl_xs(mangled: &str) -> bool {
    mangled
        .strip_prefix("XS_")
        .is_some_and(|r| is_c_ident(r) && r.contains('_'))
        || mangled.strip_prefix("boot_").is_some_and(is_c_ident)
}

/// Demangle a Perl XS symbol.
///
/// `XS_List__Util_sum` → `perl xsub: List::Util::sum`;
/// `boot_List__Util` → `perl bootstrap: List::Util`.
#[must_use]
pub fn demangle_perl_xs(mangled: &str) -> Option<String> {
    if let Some(pkg) = mangled.strip_prefix("boot_").filter(|m| is_c_ident(m)) {
        return Some(format!("perl bootstrap: {}", pkg.replace("__", "::")));
    }
    let rest = mangled
        .strip_prefix("XS_")
        .filter(|m| is_c_ident(m) && m.contains('_'))?;
    // `__` is the package separator; after restoring it, the first remaining
    // `_` separates the final package component from the sub name (sub names
    // may themselves contain underscores, e.g. `dl_load_file`).
    let restored = rest.replace("__", "::");
    let (pkg, name) = restored.split_once('_')?;
    if pkg.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("perl xsub: {pkg}::{name}"))
}

// ── Node.js N-API ────────────────────────────────────────────────────────────

/// Detect a Node.js N-API addon registration export.
///
/// Only the two fixed entry points are claimed; NAN/V8 C++ wrappers are
/// Itanium-mangled and handled elsewhere.
#[must_use]
pub fn detect_napi(mangled: &str) -> bool {
    matches!(
        mangled,
        "napi_register_module_v1" | "node_api_module_get_api_version_v1"
    )
}

/// Demangle a Node.js N-API registration export to its description.
#[must_use]
pub fn demangle_napi(mangled: &str) -> Option<String> {
    match mangled {
        "napi_register_module_v1" => Some("node.js N-API addon entry point".to_owned()),
        "node_api_module_get_api_version_v1" => {
            Some("node.js N-API addon api-version query".to_owned())
        }
        _ => None,
    }
}

// ── R ────────────────────────────────────────────────────────────────────────

/// Detect an R package native-init symbol `R_init_<pkg>` or `R_unload_<pkg>`.
#[must_use]
pub fn detect_r_init(mangled: &str) -> bool {
    mangled
        .strip_prefix("R_init_")
        .or_else(|| mangled.strip_prefix("R_unload_"))
        .is_some_and(is_c_ident)
}

/// Demangle `R_init_<pkg>` / `R_unload_<pkg>`.
///
/// `R_init_stats` → `R package init: stats`.
#[must_use]
pub fn demangle_r_init(mangled: &str) -> Option<String> {
    if let Some(pkg) = mangled.strip_prefix("R_init_").filter(|m| is_c_ident(m)) {
        return Some(format!("R package init: {pkg}"));
    }
    let pkg = mangled
        .strip_prefix("R_unload_")
        .filter(|m| is_c_ident(m))?;
    Some(format!("R package unload: {pkg}"))
}

// ── Tcl ──────────────────────────────────────────────────────────────────────

/// Detect a Tcl package entry point `<Pkg>_Init`, `<Pkg>_SafeInit`, or
/// `<Pkg>_Unload`.
///
/// This is a suffix convention with no reserved prefix, so it is deliberately
/// narrow: the package part must start with an uppercase ASCII letter and be
/// purely alphanumeric (no underscores, which would make the split ambiguous).
#[must_use]
pub fn detect_tcl(mangled: &str) -> bool {
    tcl_split(mangled).is_some()
}

/// Split a Tcl entry point into `(package, kind)` if it matches the strict
/// convention described on [`detect_tcl`].
fn tcl_split(mangled: &str) -> Option<(&str, &str)> {
    let (pkg, kind) = ["_SafeInit", "_Init", "_Unload"]
        .iter()
        .find_map(|suf| mangled.strip_suffix(suf).map(|p| (p, &suf[1..])))?;
    let mut chars = pkg.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    if !pkg.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some((pkg, kind))
}

/// Demangle a Tcl package entry point.
///
/// `Sqlite3_Init` → `tcl package init: Sqlite3`;
/// `Expect_SafeInit` → `tcl package safe-init: Expect`.
#[must_use]
pub fn demangle_tcl(mangled: &str) -> Option<String> {
    let (pkg, kind) = tcl_split(mangled)?;
    let what = match kind {
        "SafeInit" => "safe-init",
        "Unload" => "unload",
        _ => "init",
    };
    Some(format!("tcl package {what}: {pkg}"))
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Try every scripting-extension scheme, strictest first, returning the
/// demangled text and the language name on the first match.
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    // Fixed-string and long-prefix schemes first; the short/ambiguous
    // `init<module>` (Python 2) and Tcl suffix convention last.
    if detect_napi(mangled) {
        return demangle_napi(mangled).map(|d| (d, "Node.js"));
    }
    if detect_python3_init(mangled) {
        return demangle_python3_init(mangled).map(|d| (d, "Python"));
    }
    if detect_r_init(mangled) {
        return demangle_r_init(mangled).map(|d| (d, "R"));
    }
    if detect_lua(mangled) {
        return demangle_lua(mangled).map(|d| (d, "Lua"));
    }
    if detect_php(mangled) {
        return demangle_php(mangled).map(|d| (d, "PHP"));
    }
    if detect_perl_xs(mangled) {
        return demangle_perl_xs(mangled).map(|d| (d, "Perl"));
    }
    if detect_ruby_init(mangled) {
        return demangle_ruby_init(mangled).map(|d| (d, "Ruby"));
    }
    // NOT dispatched here: `init<module>` (Python 2). Unlike every other
    // scheme above, its prefix carries no distinguishing mark — no underscore,
    // no capital — so it matches ordinary English C identifiers. The real
    // corpus has `initialized`, which it decoded as
    // `python2 module init: ialized`, chopping a word in half and reporting it
    // with full confidence. There is no signal that separates `initspam` (the
    // module `spam`) from a C function of that name, so the generic dispatcher
    // cannot use this rule soundly. [`demangle_python2_init`] stays public for
    // callers who know they are looking at a Python 2 extension.
    if detect_tcl(mangled) {
        return demangle_tcl(mangled).map(|d| (d, "Tcl"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python3() {
        assert_eq!(
            demangle("PyInit_spam"),
            Some(("python module init: spam".to_owned(), "Python"))
        );
        assert_eq!(
            demangle_python3_init("PyInit__ssl").as_deref(),
            Some("python module init: _ssl")
        );
        assert!(!detect_python3_init("PyInit_"));
        assert!(!detect_python3_init("PyEval_EvalFrameEx"));
    }

    #[test]
    fn python2() {
        // Still available to a caller who knows the binary is a Python 2
        // extension…
        assert_eq!(
            demangle_python2_init("initspam").as_deref(),
            Some("python2 module init: spam")
        );
        assert!(!detect_python2_init("init")); // empty module
        assert!(!detect_python2_init("initTk")); // uppercase start rejected
        assert!(!detect_python2_init("init.ctor")); // not an identifier
    }

    /// …but the generic dispatcher must not apply it. The `init` prefix has no
    /// distinguishing mark, so ordinary C names match: the real corpus symbol
    /// `initialized` was decoded as `python2 module init: ialized`.
    #[test]
    fn python2_is_not_dispatched_generically() {
        assert_eq!(demangle("initspam"), None);
        assert_eq!(demangle("initialized"), None);
        assert_eq!(demangle("initdb"), None);
    }

    #[test]
    fn ruby() {
        assert_eq!(
            demangle("Init_nokogiri"),
            Some(("ruby extension init: nokogiri".to_owned(), "Ruby"))
        );
        assert!(!detect_ruby_init("Init_"));
    }

    #[test]
    fn php() {
        assert_eq!(
            demangle("zif_strlen"),
            Some(("php function: strlen".to_owned(), "PHP"))
        );
        assert_eq!(
            demangle("zim_DateTime_format"),
            Some(("php method: DateTime::format".to_owned(), "PHP"))
        );
        assert!(!detect_php("zend_hash_find")); // runtime, not user
        assert!(!detect_php("zim_Foo")); // no method part
    }

    #[test]
    fn lua() {
        assert_eq!(
            demangle("luaopen_socket_core"),
            Some(("lua module open: socket.core".to_owned(), "Lua"))
        );
        assert_eq!(
            demangle_lua("luaopen_cjson").as_deref(),
            Some("lua module open: cjson")
        );
        assert!(!detect_lua("luaopen_"));
    }

    #[test]
    fn perl() {
        assert_eq!(
            demangle("XS_List__Util_sum"),
            Some(("perl xsub: List::Util::sum".to_owned(), "Perl"))
        );
        assert_eq!(
            demangle("boot_List__Util"),
            Some(("perl bootstrap: List::Util".to_owned(), "Perl"))
        );
        assert_eq!(
            demangle_perl_xs("XS_DynaLoader_dl_load_file").as_deref(),
            Some("perl xsub: DynaLoader::dl_load_file")
        );
        assert!(!detect_perl_xs("XS_nounderscore"));
    }

    #[test]
    fn napi() {
        assert_eq!(
            demangle("napi_register_module_v1"),
            Some(("node.js N-API addon entry point".to_owned(), "Node.js"))
        );
        assert!(detect_napi("node_api_module_get_api_version_v1"));
        assert!(!detect_napi("napi_create_string_utf8")); // runtime API, not entry
    }

    #[test]
    fn r_lang() {
        assert_eq!(
            demangle("R_init_stats"),
            Some(("R package init: stats".to_owned(), "R"))
        );
        assert_eq!(
            demangle_r_init("R_unload_stats").as_deref(),
            Some("R package unload: stats")
        );
        assert!(!detect_r_init("R_init_"));
        assert!(!detect_r_init("Rf_allocVector"));
    }

    #[test]
    fn tcl() {
        assert_eq!(
            demangle("Sqlite3_Init"),
            Some(("tcl package init: Sqlite3".to_owned(), "Tcl"))
        );
        assert_eq!(
            demangle_tcl("Expect_SafeInit").as_deref(),
            Some("tcl package safe-init: Expect")
        );
        assert_eq!(
            demangle_tcl("Tk_Unload").as_deref(),
            Some("tcl package unload: Tk")
        );
        assert!(!detect_tcl("my_pkg_Init")); // lowercase start
        assert!(!detect_tcl("Foo_Bar_Init")); // underscore in package part
        assert!(!detect_tcl("_Init"));
    }

    #[test]
    fn rejects_other_abis() {
        for sym in [
            "_Z3fooi",
            "?f@@YAHH@Z",
            "_RNvC3foo3bar",
            "$s4main3fooyyF",
            "_D4test3fooFZv",
            "main.main",
            "runtime.morestack",
            "Java_com_example_Foo_bar",
            "_ZN4core3fmt5writeE",
            "__imp_CreateFileW",
        ] {
            assert_eq!(demangle(sym), None, "must not claim {sym}");
        }
    }
}
