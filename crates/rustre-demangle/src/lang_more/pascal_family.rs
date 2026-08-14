//! Demanglers for the Pascal language family.
//!
//! Covered schemes:
//!
//! * **Borland/Embarcadero Delphi and C++Builder** — symbols such as
//!   `@Forms@TApplication@Run$qqrv`: an `@`-separated unit/class/method path
//!   followed by an optional `$q…` signature (`qqr` = `__fastcall` register
//!   convention, `qqs` = `__stdcall`, then Borland one-letter type codes,
//!   e.g. `v` = `void`, `i` = `int`). Rendered as `Unit.Class.Method(args)`.
//! * **Free Pascal (FPC)** — uppercase-dominated symbols with `$$`
//!   separators: plain routines `UNIT_$$_PROC$ARG$$RET`, class methods
//!   `UNIT$_$CLASS_$__$$_METHOD$ARG$$RET`, virtual method tables
//!   `VMT_$UNIT_$$_CLASS`, and unit init/finalization sections
//!   `INIT$_$UNIT` / `FINALIZE$_$UNIT`. Rendered lowercased as
//!   `unit.class.method(args):ret`.
//!
//! **Turbo Pascal** is intentionally not covered: classic Turbo Pascal
//! produced no exported name mangling of note (symbols were plain,
//! case-folded identifiers), so there is nothing to demangle.

/// Returns `true` if `sym` looks like a Borland/Embarcadero Delphi or
/// C++Builder mangled name (`@Unit@Class@Method$qqrv` style).
///
/// The check is strict: the symbol must start with `@`, contain only
/// identifier characters plus `@` and `$`, and any `$` must introduce a
/// `q`-style signature. This keeps Itanium (`_Z…`), MSVC (`?…@@…`),
/// Rust (`_R…`), Swift (`$s…`), D (`_D…`) and Go (`pkg.Func`) names out.
#[must_use]
pub fn detect_borland(sym: &str) -> bool {
    let Some(rest) = sym.strip_prefix('@') else {
        return false;
    };
    let (path, sig) = match rest.split_once('$') {
        Some((p, s)) => (p, Some(s)),
        None => (rest, None),
    };
    if path.is_empty() {
        return false;
    }
    let mut components = 0usize;
    for comp in path.split('@') {
        if comp.is_empty()
            || !comp.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || !comp.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return false;
        }
        components += 1;
    }
    if components < 2 {
        // A bare `@name` is too ambiguous (could be a plain assembler-level
        // symbol); require at least Unit@Proc.
        return false;
    }
    // The signature, when present, must be a Borland `q…` argument list.
    sig.is_none_or(|s| {
        s.starts_with('q') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '@' || c == '$')
    })
}

/// Parses one Borland type code from `s`, returning the rendered type and
/// the remaining input, or `None` if the code is not recognized.
fn borland_type(s: &str) -> Option<(String, &str)> {
    // Borland modifiers qualify what FOLLOWS them, so the type must be built
    // from the base OUTWARD. Accumulating `x` into a flag and `p`/`r` into a
    // pushed suffix destroyed that ordering twice over:
    //
    //   pxi = p(x(i)) = pointer to const int  = `const int*`
    //   xpi = x(p(i)) = const pointer to int  = `int* const`
    //
    // both rendered `const int*` (as did `xpxi`), and because the suffix was
    // PUSHED rather than prepended the indirections came out reversed —
    // `rpi` (reference to pointer, `int*&`) rendered `int&*` while the illegal
    // `pri` rendered `int*&`, i.e. exactly swapped.
    let mut rest = s;
    let mut mods = Vec::new();
    while let Some(c @ ('x' | 'p' | 'r')) = rest.chars().next() {
        mods.push(c);
        rest = &rest[1..];
    }
    let mut chars = rest.chars();
    let c = chars.next()?;
    let base: String;
    if c.is_ascii_digit() {
        // Length-prefixed class/record name, e.g. `17System@TObject`.
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let len: usize = digits.parse().ok()?;
        let after = &rest[digits.len()..];
        if after.len() < len {
            return None;
        }
        base = after[..len].replace('@', ".");
        rest = &after[len..];
    } else {
        rest = &rest[c.len_utf8()..];
        base = match c {
            'v' => "void".to_owned(),
            'c' => "char".to_owned(),
            's' => "short".to_owned(),
            'i' => "int".to_owned(),
            'l' => "long".to_owned(),
            'f' => "float".to_owned(),
            'd' => "double".to_owned(),
            'g' => "long double".to_owned(),
            'o' => "bool".to_owned(),
            'b' => "wchar_t".to_owned(),
            'u' => {
                let u = rest.chars().next()?;
                rest = &rest[u.len_utf8()..];
                match u {
                    'c' => "unsigned char".to_owned(),
                    's' => "unsigned short".to_owned(),
                    'i' => "unsigned int".to_owned(),
                    'l' => "unsigned long".to_owned(),
                    _ => return None,
                }
            }
            'z' => {
                let z = rest.chars().next()?;
                rest = &rest[z.len_utf8()..];
                match z {
                    'c' => "signed char".to_owned(),
                    _ => return None,
                }
            }
            _ => return None,
        };
    }
    Some((build_borland_type(&mods, &base)?, rest))
}

/// Wrap `base` in `mods`, innermost (rightmost) first.
///
/// `const` renders west of a plain type and east of an indirection, so the two
/// orderings stay visibly different instead of silently equal. C++ has neither
/// a pointer to a reference nor a reference to a reference, so both decline.
fn build_borland_type(mods: &[char], base: &str) -> Option<String> {
    let mut out = base.to_owned();
    // `const` already applied at this indirection level. Applying it twice is
    // not a type C++ can express — the old code silently collapsed the pair,
    // which merely lost information; building outward would instead FABRICATE
    // `const const int`.
    let mut qualified = false;
    let mut indirect = false;
    let mut is_ref = false;
    for &m in mods.iter().rev() {
        match m {
            'p' => {
                if is_ref {
                    return None;
                }
                out.push('*');
                indirect = true;
                qualified = false;
            }
            'r' => {
                if is_ref {
                    return None;
                }
                out.push('&');
                indirect = true;
                is_ref = true;
                qualified = false;
            }
            'x' => {
                if qualified {
                    return None;
                }
                qualified = true;
                if indirect {
                    out.push_str(" const");
                } else {
                    out.insert_str(0, "const ");
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Renders the Borland `q…` signature (after the calling-convention codes)
/// as a parenthesized argument list, or `None` if a type code is unknown.
fn borland_args(mut s: &str) -> Option<String> {
    let mut args: Vec<String> = Vec::new();
    while !s.is_empty() {
        let (ty, rest) = borland_type(s)?;
        args.push(ty);
        s = rest;
    }
    if args.len() == 1 && args[0] == "void" {
        return Some("()".to_owned());
    }
    Some(format!("({})", args.join(", ")))
}

/// Demangles a Borland/Embarcadero Delphi or C++Builder symbol such as
/// `@Forms@TApplication@Run$qqrv` into `Forms.TApplication.Run()`.
///
/// Returns `None` if the symbol does not pass [`detect_borland`].
#[must_use]
pub fn demangle_borland(sym: &str) -> Option<String> {
    if !detect_borland(sym) {
        return None;
    }
    let rest = &sym[1..];
    let (path, sig) = match rest.split_once('$') {
        Some((p, s)) => (p, Some(s)),
        None => (rest, None),
    };
    let dotted = path.replace('@', ".");
    let Some(sig) = sig else {
        return Some(dotted);
    };
    // Strip the calling-convention marker: `qqr` (fastcall/register),
    // `qqs` (stdcall), or a bare `q`.
    let body = sig
        .strip_prefix("qqr")
        .or_else(|| sig.strip_prefix("qqs"))
        .or_else(|| sig.strip_prefix('q'))
        .unwrap_or(sig);
    // An unreadable argument list yields the NAME ALONE. `(...)` is not a
    // placeholder — it is a real C++ signature meaning varargs — so emitting it
    // on failure turned "I could not read the arguments" into a positive claim
    // about the function's type. Same defect as Watcom's, fixed at iter 116.
    Some(borland_args(body).map_or_else(|| dotted.clone(), |args| format!("{dotted}{args}")))
}

/// Returns `true` if every character of `s` is allowed in a Free Pascal
/// mangled name: uppercase ASCII letters, digits, `_` and `$`.
fn fpc_charset(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || c == '$')
}

/// Returns `true` if `sym` looks like a Free Pascal (FPC) mangled name.
///
/// Strict by construction: FPC names are uppercase-only (plus digits, `_`,
/// `$`) and must contain one of the characteristic markers `_$$_`, `$_$`,
/// or start with `VMT_$`, `INIT$_$`, or `FINALIZE$_$`. Lowercase letters,
/// dots, or other ABIs' prefixes all fail the charset test.
#[must_use]
pub fn detect_fpc(sym: &str) -> bool {
    if !fpc_charset(sym) || !sym.starts_with(|c: char| c.is_ascii_uppercase()) {
        return false;
    }
    sym.starts_with("VMT_$")
        || sym.starts_with("INIT$_$")
        || sym.starts_with("FINALIZE$_$")
        || sym.contains("_$$_")
}

/// Renders an FPC `$`-separated argument/result tail (`$ARG$ARG$$RET`)
/// appended to `out`, lowercased: `(arg,arg):ret`.
fn fpc_render_tail(out: &mut String, tail: &str) {
    let (args_part, ret) = match tail.split_once("$$") {
        Some((a, r)) => (a, Some(r)),
        None => (tail, None),
    };
    let args: Vec<String> = args_part
        .split('$')
        .filter(|a| !a.is_empty())
        .map(str::to_lowercase)
        .collect();
    out.push('(');
    out.push_str(&args.join(","));
    out.push(')');
    if let Some(r) = ret
        && !r.is_empty()
    {
        out.push(':');
        out.push_str(&r.to_lowercase());
    }
}

/// Demangles a Free Pascal symbol.
///
/// `SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING` becomes
/// `sysutils.inttostr(longint):ansistring`, and
/// `CLASSES$_$TSTRINGLIST_$__$$_ADD$ANSISTRING$$LONGINT` into
/// `classes.tstringlist.add(ansistring):longint`.
///
/// Also handles
/// `VMT_$UNIT_$$_CLASS`, `INIT$_$UNIT`, and `FINALIZE$_$UNIT`.
///
/// Returns `None` if the symbol does not pass [`detect_fpc`].
#[must_use]
pub fn demangle_fpc(sym: &str) -> Option<String> {
    if !detect_fpc(sym) {
        return None;
    }
    if let Some(unit) = sym.strip_prefix("INIT$_$") {
        return Some(format!("{}.$init", unit.to_lowercase()));
    }
    if let Some(unit) = sym.strip_prefix("FINALIZE$_$") {
        return Some(format!("{}.$finalize", unit.to_lowercase()));
    }
    if let Some(rest) = sym.strip_prefix("VMT_$") {
        let (unit, class) = rest.split_once("_$$_")?;
        return Some(format!(
            "vmt for {}.{}",
            unit.to_lowercase(),
            class.to_lowercase()
        ));
    }
    // Class method: UNIT$_$CLASS_$__$$_METHOD…
    if let Some((unit, rest)) = sym.split_once("$_$")
        && let Some((class, method_part)) = rest.split_once("_$__$$_")
    {
        {
            let mut out = format!(
                "{}.{}.",
                unit.to_lowercase(),
                class.to_lowercase()
            );
            let (method, tail) = match method_part.split_once('$') {
                Some((m, t)) => (m, Some(t)),
                None => (method_part, None),
            };
            out.push_str(&method.to_lowercase());
            match tail {
                Some(t) => fpc_render_tail(&mut out, t),
                None => out.push_str("()"),
            }
            return Some(out);
        }
    }
    // Plain routine: UNIT_$$_PROC…
    let (unit, rest) = sym.split_once("_$$_")?;
    if unit.is_empty() || rest.is_empty() {
        return None;
    }
    let mut out = format!("{}.", unit.to_lowercase());
    let (proc, tail) = match rest.split_once('$') {
        Some((p, t)) => (p, Some(t)),
        None => (rest, None),
    };
    out.push_str(&proc.to_lowercase());
    match tail {
        Some(t) => fpc_render_tail(&mut out, t),
        None => out.push_str("()"),
    }
    Some(out)
}

/// Tries each Pascal-family scheme, strictest first (Free Pascal, then
/// Borland/Delphi), returning the demangled text and language name.
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    if let Some(text) = demangle_fpc(mangled) {
        return Some((text, "Free Pascal"));
    }
    if let Some(text) = demangle_borland(mangled) {
        return Some((text, "Delphi"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borland_method() {
        assert_eq!(
            demangle_borland("@Forms@TApplication@Run$qqrv").as_deref(),
            Some("Forms.TApplication.Run()")
        );
    }

    #[test]
    fn borland_args_rendered() {
        assert_eq!(
            demangle_borland("@Sysutils@IntToStr$qqri").as_deref(),
            Some("Sysutils.IntToStr(int)")
        );
        assert_eq!(
            demangle_borland("@Unit1@Proc$qqrpxci").as_deref(),
            Some("Unit1.Proc(const char*, int)")
        );
    }

    #[test]
    fn borland_class_arg() {
        assert_eq!(
            demangle_borland("@Unit1@Handler$qqrp14System@TObject").as_deref(),
            Some("Unit1.Handler(System.TObject*)")
        );
    }

    #[test]
    fn borland_no_signature() {
        assert_eq!(
            demangle_borland("@System@Randomize").as_deref(),
            Some("System.Randomize")
        );
    }

    /// An unreadable argument list yields the NAME ALONE, not `(...)`.
    ///
    /// This test previously pinned `Unit1.Proc(...)`. That was not a
    /// placeholder: `(...)` is a real C++ signature meaning varargs, so the
    /// fallback turned "I could not read the arguments" into a positive claim
    /// about the function's type. The same defect was fixed in Watcom one
    /// iteration earlier. A bare name claims nothing and loses nothing.
    #[test]
    fn borland_unknown_types_fall_back() {
        assert_eq!(
            demangle_borland("@Unit1@Proc$qqrQ99").as_deref(),
            Some("Unit1.Proc")
        );
    }

    #[test]
    fn fpc_plain_routine() {
        assert_eq!(
            demangle_fpc("SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING").as_deref(),
            Some("sysutils.inttostr(longint):ansistring")
        );
    }

    #[test]
    fn fpc_class_method() {
        assert_eq!(
            demangle_fpc("CLASSES$_$TSTRINGLIST_$__$$_ADD$ANSISTRING$$LONGINT").as_deref(),
            Some("classes.tstringlist.add(ansistring):longint")
        );
    }

    #[test]
    fn fpc_procedure_no_args() {
        assert_eq!(
            demangle_fpc("UNIT1_$$_DOSTUFF").as_deref(),
            Some("unit1.dostuff()")
        );
    }

    #[test]
    fn fpc_vmt_init_finalize() {
        assert_eq!(
            demangle_fpc("VMT_$SYSTEM_$$_TOBJECT").as_deref(),
            Some("vmt for system.tobject")
        );
        assert_eq!(demangle_fpc("INIT$_$SYSUTILS").as_deref(), Some("sysutils.$init"));
        assert_eq!(
            demangle_fpc("FINALIZE$_$CLASSES").as_deref(),
            Some("classes.$finalize")
        );
    }

    #[test]
    fn dispatcher_labels() {
        assert_eq!(
            demangle("SYSUTILS_$$_INTTOSTR$LONGINT$$ANSISTRING"),
            Some(("sysutils.inttostr(longint):ansistring".to_owned(), "Free Pascal"))
        );
        assert_eq!(
            demangle("@Forms@TApplication@Run$qqrv"),
            Some(("Forms.TApplication.Run()".to_owned(), "Delphi"))
        );
    }

    #[test]
    fn rejects_other_abis() {
        for sym in [
            "_Z3fooi",
            "?f@@YAHH@Z",
            "_RNvC3foo3bar",
            "$s4main3fooyyF",
            "_D4core4stdc5stdio6printfFPxaZi",
            "main.main",
            "github.com/user/pkg.Func",
            "_main",
            "printf",
            "@plt",
            "@GLIBC_2.2.5",
        ] {
            assert!(demangle(sym).is_none(), "should reject {sym}");
            assert!(!detect_borland(sym), "borland detect should reject {sym}");
            assert!(!detect_fpc(sym), "fpc detect should reject {sym}");
        }
    }
}
