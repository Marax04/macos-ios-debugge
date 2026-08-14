//! GCC function-local statics are not Go symbols.
//!
//! GCC promotes a local `static` variable to a linker symbol named
//! `<var>.<counter>` — `msg.0`, `table.0`, `state_mbrtowc.0` — and nests the
//! suffix when the counter itself is scoped, giving `C.9.0`. All of these
//! appear in the real corpus (they come out of `nm` over the mingw CRT).
//!
//! They are dotted, and Go is the permissive detector that runs last, so
//! before this fix they were claimed as Go and echoed back unchanged with
//! `abi: Go`. That is the same fabrication shape as the `__emutls_v.` and
//! trailing-dot defects: the one ABI with no oracle claiming what is not its
//! own, and an identity echo counted as a decode.
//!
//! A local static has no demangling — it is undecorated C data — so the
//! correct outcome is to decline it.

use rustre_demangle::go_demangler::GoDemangler;

/// The real corpus symbols, plus the nested `C.9.0` form.
#[test]
fn gcc_local_statics_are_not_claimed_by_go() {
    for sym in [
        "msg.0",
        "table.0",
        "state_mbrtowc.0",
        "state_mbsrtowcs.0",
        "was_init.0",
        "p05.0",
        "once.0",
        "fpi.0",
        "C.9.0",
    ] {
        assert!(
            !GoDemangler::detect(sym),
            "{sym} is a GCC local static, not a Go symbol"
        );
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} has no demangling and must be declined, not echoed"
        );
    }
}

/// DISCRIMINATING CASE: Go symbols with a numeric *tail* must still decode.
///
/// This is the case that makes the rule grammar-based rather than a blunt
/// "reject a numeric last component". `errors..interfaceSwitch.0` and
/// `errors..typeAssert.2` end in a bare integer exactly like a local static,
/// but they carry a non-numeric identifier earlier (`interfaceSwitch`,
/// `typeAssert`) that a local static never has. A fix that keyed on the last
/// component alone would pass the test above and silently drop these real Go
/// symbols; only an input that separates the two implementations catches it.
#[test]
fn go_symbols_with_numeric_tails_still_decode() {
    for sym in [
        "errors..interfaceSwitch.0",
        "errors..typeAssert.2",
        "sync.(*Once).Do.func1",
    ] {
        assert!(
            GoDemangler::detect(sym),
            "{sym} is a real Go symbol and must still be detected"
        );
        assert!(
            rustre_demangle::demangle(sym).is_some(),
            "{sym} must still decode"
        );
    }
}

/// Ordinary Go names are unaffected.
#[test]
fn ordinary_go_names_still_detect() {
    for sym in ["main.main", "fmt.Println", "github.com/user/repo.Func"] {
        assert!(GoDemangler::detect(sym), "{sym} must still be detected");
        assert!(rustre_demangle::demangle(sym).is_some(), "{sym} must decode");
    }
}
