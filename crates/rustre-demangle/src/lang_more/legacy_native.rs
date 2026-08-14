//! Demanglers for legacy native toolchains.
//!
//! Covered schemes, tried strictest-first by [`demangle`]:
//!
//! 1. **cfront / GCC 2.x C++** — the pre-Itanium `name__<len><Class><sig>`
//!    scheme used by AT&T cfront (and, with small variations, by g++ 2.x and
//!    Symbian/EPOC toolchains): `foo__4Testi` → `Test::foo(int)`,
//!    `__ct__4Testv` → `Test::Test()`, free functions `h__Fic` → `h(int, char)`,
//!    const members `bar__C4Testv` → `Test::bar() const`, operator names
//!    `__pl`, `__mi`, `__ml`, `__dv`, ….
//! 2. **Watcom C++** — `W?name$n(args)ret`, e.g. `W?h$n(ia)v` for
//!    `void h(int, char)` (format per the Watcom 10.6 column of the classic
//!    name-mangling comparison tables). Detection is exact on the `W?` prefix;
//!    argument decoding is best-effort.
//! 3. **MATLAB MEX** — MEX files are ordinary shared libraries whose only
//!    well-known exports are `mexFunction` (the gateway) and
//!    `mexfilerequiredapiversion`; these are recognized and labeled, nothing
//!    is mangled.
//! 4. **`GnuCOBOL`** — `cobc` compiles each `PROGRAM-ID` to a C function whose
//!    name is the program-id with `-` mapped to `__` (COBOL allows dashes in
//!    identifiers, C does not): `HELLO__WORLD` → COBOL program `HELLO-WORLD`.
//!    Only accepted for all-uppercase names containing a `__` pair, to avoid
//!    stealing ordinary C identifiers.
//!
//! Intentionally **not** handled because the languages have no native symbol
//! mangling of their own:
//!
//! - **VB6** — native VB6 DLLs export plain (unmangled) names or ordinals;
//!   runtime calls go through `DllFunctionCall` in `msvbvm60.dll`. There is
//!   nothing to demangle.
//! - Symbian/EPOC and g++ 2.x symbols are folded into the cfront path above
//!   rather than treated as separate schemes.

/// cfront / g++ 2.x operator-name table (`__pl` → `operator+`, …).
const CFRONT_OPERATORS: &[(&str, &str)] = &[
    ("apl", "operator+="),
    ("ami", "operator-="),
    ("amu", "operator*="),
    ("adv", "operator/="),
    ("amd", "operator%="),
    ("aer", "operator^="),
    ("aad", "operator&="),
    ("aor", "operator|="),
    ("als", "operator<<="),
    ("ars", "operator>>="),
    ("pl", "operator+"),
    ("mi", "operator-"),
    ("ml", "operator*"),
    ("dv", "operator/"),
    ("md", "operator%"),
    ("er", "operator^"),
    ("ad", "operator&"),
    ("or", "operator|"),
    ("co", "operator~"),
    ("nt", "operator!"),
    ("as", "operator="),
    ("ls", "operator<<"),
    ("rs", "operator>>"),
    ("eq", "operator=="),
    ("ne", "operator!="),
    ("lt", "operator<"),
    ("gt", "operator>"),
    ("le", "operator<="),
    ("ge", "operator>="),
    ("aa", "operator&&"),
    ("oo", "operator||"),
    ("pp", "operator++"),
    ("mm", "operator--"),
    ("cm", "operator,"),
    ("rm", "operator->*"),
    ("rf", "operator->"),
    ("cl", "operator()"),
    ("vc", "operator[]"),
    ("nw", "operator new"),
    ("dl", "operator delete"),
    ("vn", "operator new[]"),
    ("vd", "operator delete[]"),
];

/// Parse one cfront/g++2 type code from `chars`, returning its C++ spelling.
///
/// Handles the modifier prefixes `P`/`R`/`C`/`U`/`S` and the classic base
/// codes plus `<len>Name` class references. Returns `None` on anything
/// unrecognized (keeping the detector strict).
fn parse_cfront_type(chars: &mut std::str::Chars<'_>) -> Option<String> {
    // ARM/cfront modifiers apply to what FOLLOWS them, so the type must be
    // built from the base OUTWARD. Collecting `P`/`R` into a suffix and
    // `C`/`U`/`S` into a prefix — as this did — destroys that ordering and
    // collapses distinct types onto one rendering:
    //
    //   PCc  = P(Cc)  = pointer to const char  = `const char*`
    //   CPc  = C(Pc)  = const pointer to char  = `char* const`
    //
    // Both rendered `const char*`, and `CPCc` (`const char* const`) rendered it
    // too — three inputs, one output. It also dropped `const` outright when a
    // sign qualifier came first (`UCi` -> `unsigned int`) and stacked
    // qualifiers into types C++ cannot express (`UUi` -> `unsigned unsigned
    // int`).
    let mut mods = Vec::new();
    let mut c = chars.next()?;
    while matches!(c, 'P' | 'R' | 'C' | 'U' | 'S') {
        mods.push(c);
        c = chars.next()?;
    }

    // A sign qualifier belongs to the base type: at most one, and nothing may
    // sit between it and the base.
    let sign = match mods.last() {
        Some(&s @ ('U' | 'S')) => {
            mods.pop();
            Some(s)
        }
        _ => None,
    };
    if mods.iter().any(|m| matches!(m, 'U' | 'S')) {
        return None; // stacked or misplaced sign qualifier
    }

    let base = match c {
        'v' => "void",
        'c' => "char",
        's' => "short",
        'i' => "int",
        'l' => "long",
        'x' => "long long",
        'f' => "float",
        'd' => "double",
        'r' => "long double",
        'b' => "bool",
        'w' => "wchar_t",
        'e' => "...",
        '0'..='9' => {
            let mut len = c.to_digit(10)? as usize;
            let rest = chars.as_str();
            let mut consumed = 0;
            for d in rest.chars() {
                if let Some(v) = d.to_digit(10) {
                    len = len * 10 + v as usize;
                    consumed += 1;
                } else {
                    break;
                }
            }
            for _ in 0..consumed {
                chars.next();
            }
            let name: String = chars.by_ref().take(len).collect();
            if name.len() != len || !name.chars().all(|n| n.is_ascii_alphanumeric() || n == '_') {
                return None;
            }
            return build_cfront_type(&mods, &name);
        }
        _ => return None,
    };

    let base = match sign {
        Some('U') => format!("unsigned {base}"),
        Some('S') => format!("signed {base}"),
        _ => base.to_owned(),
    };
    build_cfront_type(&mods, &base)
}

/// Wrap `base` in `mods`, innermost (rightmost) first.
///
/// `const` renders west of a plain type (`const char`) and east of a pointer or
/// reference (`char* const`), which is what makes the two orderings visibly
/// different rather than silently equal.
fn build_cfront_type(mods: &[char], base: &str) -> Option<String> {
    let mut out = base.to_owned();
    // `const` already applied at this indirection level. Applying it twice is
    // not a type C++ can express — the old code silently collapsed the pair,
    // which merely lost information; building outward would instead FABRICATE
    // `const const int`.
    let mut qualified = false;
    let mut indirect = false; // outermost is currently `*` or `&`
    let mut is_ref = false;
    for &m in mods.iter().rev() {
        match m {
            'P' => {
                // C++ has no pointer to a reference.
                if is_ref {
                    return None;
                }
                out.push('*');
                indirect = true;
                qualified = false;
            }
            'R' => {
                // Nor a reference to a reference.
                if is_ref {
                    return None;
                }
                out.push('&');
                indirect = true;
                is_ref = true;
                qualified = false;
            }
            'C' => {
                if qualified {
                    return None;
                }
                qualified = true;
                if indirect {
                    out.push_str(" const");
                } else {
                    out.insert_str(0, "const ");
                }
                // A qualifier does not change what the type is a pointer to.
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Parse a `<len>Name` class token, e.g. `4Test` → `Test`.
fn parse_cfront_class(chars: &mut std::str::Chars<'_>) -> Option<String> {
    let first = chars.clone().next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    parse_cfront_type(chars)
}

/// Parse a cfront signature tail: optional `C` (const member), optional
/// `<len>Class`, then argument types. Returns `(class, args, is_const)`.
fn parse_cfront_signature(sig: &str) -> Option<(Option<String>, Vec<String>, bool)> {
    let mut chars = sig.chars();
    let mut is_const = false;
    let mut peek = chars.clone().next()?;
    if peek == 'C' {
        // `C` before a class digit marks a const member function.
        let mut ahead = chars.clone();
        ahead.next();
        if ahead.next().is_some_and(|d| d.is_ascii_digit()) {
            is_const = true;
            chars.next();
            peek = chars.clone().next()?;
        }
    }
    let class = if peek.is_ascii_digit() {
        Some(parse_cfront_class(&mut chars)?)
    } else if peek == 'F' {
        chars.next();
        None
    } else {
        return None;
    };
    let mut args = Vec::new();
    while chars.clone().next().is_some() {
        args.push(parse_cfront_type(&mut chars)?);
    }
    // A lone `void` means an empty parameter list.
    if args == ["void"] {
        args.clear();
    }
    Some((class, args, is_const))
}

/// Detect a cfront / g++ 2.x mangled C++ symbol (`foo__4Testi`, `h__Fi`,
/// `__ct__4Testv`, …).
#[must_use]
pub fn detect_cfront(mangled: &str) -> bool {
    demangle_cfront(mangled).is_some()
}

/// Demangle a cfront / g++ 2.x C++ symbol.
///
/// Returns e.g. `Test::foo(int)` for `foo__4Testi`, `Test::Test()` for
/// `__ct__4Testv`, `h(int, char)` for `h__Fic`.
#[must_use]
pub fn demangle_cfront(mangled: &str) -> Option<String> {
    if mangled.len() < 5 || !mangled.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // Reject other ABIs outright.
    if mangled.starts_with("_Z") || mangled.starts_with("_R") || mangled.starts_with("_D") {
        return None;
    }
    let (name_part, sig) = if let Some(rest) = mangled.strip_prefix("__") {
        // Special member / operator: `__<code>__<sig>`.
        let (code, sig) = rest.split_once("__")?;
        let name = match code {
            "ct" => "{ctor}".to_string(),
            "dt" => "{dtor}".to_string(),
            _ => CFRONT_OPERATORS
                .iter()
                .find(|(k, _)| *k == code)
                .map(|(_, v)| (*v).to_string())?,
        };
        (name, sig)
    } else {
        // Plain function: split at the first `__` followed by a valid
        // signature start (digit, `F`, or `C<digit>`).
        let bytes = mangled.as_bytes();
        let mut split = None;
        let mut i = 1; // name must be non-empty
        while i + 2 < bytes.len() {
            if bytes[i] == b'_' && bytes[i + 1] == b'_' {
                let c = bytes[i + 2];
                let ok = c.is_ascii_digit()
                    || c == b'F'
                    || (c == b'C'
                        && bytes.get(i + 3).is_some_and(u8::is_ascii_digit));
                if ok {
                    split = Some(i);
                    break;
                }
            }
            i += 1;
        }
        let pos = split?;
        (mangled[..pos].to_string(), &mangled[pos + 2..])
    };
    let (class, args, is_const) = parse_cfront_signature(sig)?;
    let name = match (&class, name_part.as_str()) {
        (Some(c), "{ctor}") => format!("{c}::{c}"),
        (Some(c), "{dtor}") => format!("{c}::~{c}"),
        (None, "{ctor}" | "{dtor}") => return None,
        (Some(c), n) => format!("{c}::{n}"),
        (None, n) => n.to_string(),
    };
    let args = args.join(", ");
    let cv = if is_const { " const" } else { "" };
    Some(format!("{name}({args}){cv}"))
}

/// Decode one Watcom C++ argument-type code (best-effort, from observed
/// examples: `i` int, `a` char, `v` void, …).
/// Decode a Watcom argument-code run into one rendered type per PARAMETER.
///
/// `u` is a qualifier, not a standalone type: `ui` is `unsigned int`, a single
/// parameter. Mapping each character independently rendered it as
/// `unsigned, int` — two parameters where the source has one, and `uui` gave
/// three. Phantom parameters are the defect class this repo singles out as the
/// worst kind, because they are invisible to every check but arity itself.
fn parse_watcom_args(codes: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut chars = codes.chars();
    while let Some(c) = chars.next() {
        if c == 'u' {
            // Exactly one `u`, and it must qualify a following base type.
            let base = chars.next()?;
            if base == 'u' {
                return None;
            }
            out.push(format!("unsigned {}", watcom_type(base)?));
        } else {
            out.push(watcom_type(c)?.to_owned());
        }
    }
    Some(out.join(", "))
}

const fn watcom_type(c: char) -> Option<&'static str> {
    match c {
        'a' => Some("char"),
        'i' => Some("int"),
        's' => Some("short"),
        'l' => Some("long"),
        'f' => Some("float"),
        'd' => Some("double"),
        'u' => Some("unsigned"),
        'v' => Some("void"),
        _ => None,
    }
}

/// Detect a Watcom C++ mangled symbol (`W?name$…`).
#[must_use]
pub fn detect_watcom(mangled: &str) -> bool {
    mangled
        .strip_prefix("W?")
        .and_then(|rest| rest.split_once('$'))
        .is_some_and(|(name, tail)| {
            !name.is_empty()
                && !tail.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Demangle a Watcom C++ symbol, best-effort.
///
/// `W?h$n(ia)v` (`void h(int, char)`) → `h(int, char)`. When the argument
/// codes are not understood the name alone is recovered as `name(...)`.
#[must_use]
pub fn demangle_watcom(mangled: &str) -> Option<String> {
    if !detect_watcom(mangled) {
        return None;
    }
    let (name, tail) = mangled.strip_prefix("W?")?.split_once('$')?;
    let args = tail.find('(').and_then(|open| {
        let close = tail[open..].find(')')? + open;
        parse_watcom_args(&tail[open + 1..close])
    });
    // When the arguments cannot be read, emit the NAME ALONE.
    //
    // This used to fall back to `name(...)`, which is not a placeholder: `(...)`
    // is a real C++ signature meaning varargs, so "I could not read the
    // arguments" was rendered as a positive claim about the function's type —
    // and seven distinct inputs, including a well-formed symbol carrying no
    // argument group at all, collapsed onto that one output. A bare name claims
    // nothing and loses nothing, and `f` stays distinguishable from `f()`.
    Some(args.map_or_else(|| name.to_owned(), |a| format!("{name}({a})")))
}

/// Detect a MATLAB MEX gateway export.
#[must_use]
pub fn detect_mex(mangled: &str) -> bool {
    let bare = mangled.strip_prefix('_').unwrap_or(mangled);
    bare == "mexFunction" || bare == "mexfilerequiredapiversion"
}

/// Label a MATLAB MEX gateway export (`mexFunction`,
/// `mexfilerequiredapiversion`). These are plain C exports, not mangled;
/// they are recognized so binaries can be identified as MEX files.
#[must_use]
pub fn demangle_mex(mangled: &str) -> Option<String> {
    if !detect_mex(mangled) {
        return None;
    }
    let bare = mangled.strip_prefix('_').unwrap_or(mangled);
    if bare == "mexFunction" {
        Some("mexFunction (MATLAB MEX gateway)".to_string())
    } else {
        Some("mexfilerequiredapiversion (MATLAB MEX API version stub)".to_string())
    }
}

/// Detect a `GnuCOBOL` program symbol: an all-uppercase C identifier containing
/// `__` (the `cobc` encoding of `-` in a `PROGRAM-ID`).
#[must_use]
pub fn detect_gnucobol(mangled: &str) -> bool {
    mangled.contains("__")
        && !mangled.starts_with('_')
        && !mangled.ends_with('_')
        && mangled.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && mangled
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        // EVERY underscore run must be even. GnuCOBOL encodes the hyphen of a
        // PROGRAM-ID as `__`, and a COBOL program-name cannot contain an
        // underscore at all, so an odd run cannot be its output. Rejecting a
        // lone `_` was already here; runs were not, and `replace("__", "-")`
        // is non-overlapping, so `A___B` rendered `PROGRAM-ID A-_B` — an
        // underscore surviving into a name that cannot hold one.
        && mangled
            .split(|c: char| c != '_')
            .all(|run| run.len() % 2 == 0)
}

/// Demangle a `GnuCOBOL` program symbol back to its `PROGRAM-ID`:
/// `HELLO__WORLD` → `PROGRAM-ID HELLO-WORLD`.
#[must_use]
pub fn demangle_gnucobol(mangled: &str) -> Option<String> {
    if !detect_gnucobol(mangled) {
        return None;
    }
    Some(format!("PROGRAM-ID {}", mangled.replace("__", "-")))
}

/// Try every legacy-native scheme, strictest first: cfront/g++2, Watcom C++,
/// MATLAB MEX, `GnuCOBOL`. Returns the demangled text and the language label.
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    if let Some(s) = demangle_cfront(mangled) {
        return Some((s, "C++ (cfront/g++2)"));
    }
    if let Some(s) = demangle_watcom(mangled) {
        return Some((s, "C++ (Watcom)"));
    }
    if let Some(s) = demangle_mex(mangled) {
        return Some((s, "MATLAB MEX"));
    }
    if let Some(s) = demangle_gnucobol(mangled) {
        return Some((s, "COBOL"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfront_member() {
        assert_eq!(demangle_cfront("foo__4Testi").as_deref(), Some("Test::foo(int)"));
    }

    #[test]
    fn cfront_ctor_dtor() {
        assert_eq!(demangle_cfront("__ct__4Testv").as_deref(), Some("Test::Test()"));
        assert_eq!(demangle_cfront("__dt__4Testv").as_deref(), Some("Test::~Test()"));
    }

    #[test]
    fn cfront_operator() {
        assert_eq!(
            demangle_cfront("__pl__7Complexd").as_deref(),
            Some("Complex::operator+(double)")
        );
    }

    #[test]
    fn gcc2_free_functions() {
        // Real g++ 2.9.x manglings of void h(int) / h(int, char) / h(void).
        assert_eq!(demangle_cfront("h__Fi").as_deref(), Some("h(int)"));
        assert_eq!(demangle_cfront("h__Fic").as_deref(), Some("h(int, char)"));
        assert_eq!(demangle_cfront("h__Fv").as_deref(), Some("h()"));
    }

    #[test]
    fn cfront_const_member_and_pointers() {
        assert_eq!(
            demangle_cfront("bar__C4Testv").as_deref(),
            Some("Test::bar() const")
        );
        assert_eq!(
            demangle_cfront("set__4TestPCc").as_deref(),
            Some("Test::set(const char*)")
        );
    }

    #[test]
    fn cfront_rejects_plain_c_symbols() {
        assert!(demangle_cfront("__libc_start_main").is_none());
        assert!(demangle_cfront("foo__bar").is_none());
        assert!(demangle_cfront("printf").is_none());
        assert!(demangle_cfront("_GLOBAL__sub_I_x").is_none());
    }

    #[test]
    fn watcom() {
        // Watcom C++ 10.6 mangling of void h(int, char).
        assert_eq!(demangle_watcom("W?h$n(ia)v").as_deref(), Some("h(int, char)"));
        assert_eq!(demangle_watcom("W?h$n()v").as_deref(), Some("h()"));
        assert_eq!(demangle_watcom("W?h$n(i)v").as_deref(), Some("h(int)"));
    }

    #[test]
    fn mex() {
        assert_eq!(
            demangle_mex("mexFunction").as_deref(),
            Some("mexFunction (MATLAB MEX gateway)")
        );
        assert!(demangle_mex("mexSomethingElse").is_none());
    }

    #[test]
    fn gnucobol() {
        assert_eq!(
            demangle_gnucobol("HELLO__WORLD").as_deref(),
            Some("PROGRAM-ID HELLO-WORLD")
        );
        assert!(demangle_gnucobol("hello__world").is_none());
        assert!(demangle_gnucobol("HELLOWORLD").is_none());
        assert!(demangle_gnucobol("_FOO__BAR").is_none());
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
            "_ZN4Test3fooEi",
        ] {
            assert!(demangle(sym).is_none(), "wrongly accepted {sym}");
        }
    }

    #[test]
    fn dispatcher_order() {
        assert_eq!(
            demangle("foo__4Testi"),
            Some(("Test::foo(int)".to_string(), "C++ (cfront/g++2)"))
        );
        assert_eq!(
            demangle("W?h$n(i)v"),
            Some(("h(int)".to_string(), "C++ (Watcom)"))
        );
        assert_eq!(
            demangle("HELLO__WORLD"),
            Some(("PROGRAM-ID HELLO-WORLD".to_string(), "COBOL"))
        );
    }
}
