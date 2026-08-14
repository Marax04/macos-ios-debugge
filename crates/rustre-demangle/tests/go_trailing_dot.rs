//! A Go symbol never ends in a dot.
//!
//! `GoDemangler::detect` accepted any name containing a dot at a position
//! greater than zero, with no requirement that a component follow it. Since Go
//! is the permissive backend — it runs last, after every strict backend has
//! declined — that made it the catch-all for any dotted leftover, and it
//! echoed those back as successful decodes.
//!
//! Found while fixing the `__emutls_v.` wrapper: the wrapper split correctly
//! refuses an empty payload, so the bare prefix fell through to Go, which
//! claimed it. Same defect family as the Go fabrications already on record —
//! the ABI with no oracle claiming what is not its own.
//!
//! The fix is deliberately narrow, and this file exists mainly to pin *why*.

use rustre_demangle::go_demangler::GoDemangler;

/// Names ending in a dot have an empty final component and are not Go.
#[test]
fn trailing_dot_names_are_rejected() {
    for sym in [
        "__emutls_v.",
        "__emutls_t.",
        "main.",
        "errors..inittask.",
        ".",
    ] {
        assert!(
            !GoDemangler::detect(sym),
            "{sym} ends in a dot and has no final component — not a Go symbol"
        );
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} must not be echoed back as a decode"
        );
    }
}

/// DISCRIMINATING CASE: empty *middle* components are legitimate Go.
///
/// This is the case that makes the fix narrow rather than convenient. The
/// obvious implementation — reject any empty component — passes the test above
/// and silently loses real symbols: the compiler emits `errors..inittask`,
/// `errors..interfaceSwitch.0` and `errors..typeAssert.2`, all present in the
/// real corpus. A test written only against trailing dots would not tell the
/// two implementations apart.
#[test]
fn empty_middle_components_are_still_accepted() {
    for sym in [
        "errors..inittask",
        "errors..interfaceSwitch.0",
        "errors..typeAssert.2",
    ] {
        assert!(
            GoDemangler::detect(sym),
            "{sym} is a real corpus symbol with an empty middle component and \
             must still be detected as Go"
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
    }
}
