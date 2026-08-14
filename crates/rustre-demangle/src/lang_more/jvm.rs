//! Demanglers for JVM-family native/compiled symbol schemes beyond plain JNI
//! (`Java_...` JNI symbols are handled elsewhere in this crate and are
//! intentionally **not** reimplemented here).
//!
//! Covered schemes, strictest-first:
//!
//! * **Kotlin/Native** — symbols produced by the Kotlin/Native compiler:
//!   `kfun:<package.Class>#<name>(<params>){<type-params>}<return>`, plus
//!   `kclass:` (class metadata) and `ktype:` (type metadata) symbols.
//! * **Clojure** — compiled function class names `ns$fn_name__1234` with the
//!   Clojure munging (`_PLUS_` = `+`, `_BANG_` = `!`, `_QMARK_` = `?`,
//!   `_STAR_` = `*`, `_SLASH_` = `/`, remaining `_` = `-`), decoded back to
//!   `ns/fn-name`.
//! * **Scala** — the `$`-encodings Scala uses for JVM class/method names:
//!   operator encodings (`$plus` = `+`, `$colon` = `:`, ...), `$anonfun$`
//!   lambda classes, `$adapted` bridge methods, specialization suffixes such
//!   as `$mcII$sp`, and the trailing `$` of module (object) classes.
//!
//! **Groovy** has *no* native symbol mangling of its own: Groovy compiles to
//! ordinary JVM class files with plain Java identifiers (dynamic dispatch
//! goes through invokedynamic / `MetaClass`, not through name encoding), so
//! it is intentionally not applicable here and no Groovy decoder is provided.
//!
//! All detectors are strict: they run inside the auto-dispatcher after the
//! prefix-based ABIs (Rust, Itanium, MSVC, Swift, D) and before Go, whose
//! permissive any-name-with-a-dot detector must stay last. Symbols such as
//! `_Z3fooi`, `?f@@YAHH@Z`, `_RNvC3foo3bar`, `$s4main3fooyyF`, `_D4main...`
//! and bare `pkg.Func` names must never match here.

// ── Kotlin/Native ────────────────────────────────────────────────────────────

/// Returns `true` for Kotlin/Native runtime symbols: `kfun:` (function),
/// `kclass:` (class metadata) or `ktype:` (type metadata), with a non-empty
/// payload after the prefix.
#[must_use]
pub fn detect_kotlin_native(mangled: &str) -> bool {
    ["kfun:", "kclass:", "ktype:"]
        .iter()
        .any(|p| mangled.strip_prefix(p).is_some_and(|r| !r.is_empty()))
}

/// Demangle a Kotlin/Native symbol.
///
/// `kfun:kotlin.collections.List#get(kotlin.Int){}kotlin.Any?` becomes
/// `kotlin.collections.List.get(kotlin.Int): kotlin.Any?`; `kclass:`/`ktype:`
/// payloads are rendered as `class <name>` / `type <name>`.
#[must_use]
pub fn demangle_kotlin_native(mangled: &str) -> Option<String> {
    if let Some(rest) = mangled.strip_prefix("kclass:") {
        return (!rest.is_empty()).then(|| format!("class {rest}"));
    }
    if let Some(rest) = mangled.strip_prefix("ktype:") {
        return (!rest.is_empty()).then(|| format!("type {rest}"));
    }
    let rest = mangled.strip_prefix("kfun:")?;
    if rest.is_empty() {
        return None;
    }
    // Split off the `{type-params}` block and the trailing return type.
    let (head, return_part) = match rest.find('{') {
        Some(open) => {
            let after = &rest[open..];
            let close = after.find('}')?;
            (&rest[..open], &after[close + 1..])
        }
        None => (rest, ""),
    };
    // `<receiver>#<name>(args)` — a missing receiver (`kfun:#main(){}`)
    // yields just `name(args)`.
    let mut out = match head.split_once('#') {
        Some(("", name)) => name.to_owned(),
        Some((recv, name)) => format!("{recv}.{name}"),
        None => head.to_owned(),
    };
    if out.is_empty() {
        return None;
    }
    if !return_part.is_empty() {
        out.push_str(": ");
        out.push_str(return_part);
    }
    Some(out)
}

// ── Clojure ──────────────────────────────────────────────────────────────────

/// Clojure munge table: `_TOKEN_` encodings for characters that are legal in
/// Clojure symbols but not in JVM identifiers.
const CLOJURE_MUNGE: &[(&str, char)] = &[
    ("_PLUS_", '+'),
    ("_BANG_", '!'),
    ("_QMARK_", '?'),
    ("_STAR_", '*'),
    ("_SLASH_", '/'),
    ("_GT_", '>'),
    ("_LT_", '<'),
    ("_EQ_", '='),
    ("_TILDE_", '~'),
    ("_AMPERSAND_", '&'),
    ("_BAR_", '|'),
    ("_PERCENT_", '%'),
    ("_CARET_", '^'),
    ("_APOS_", '\''),
    ("_SHARP_", '#'),
    ("_COLON_", ':'),
];

fn is_clojure_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// Returns `true` for compiled Clojure function class names of the shape
/// `ns$fn_name__1234` (or `ns$fn_name` containing a `_MUNGE_` token).
///
/// Strictness: exactly one `$`, an identifier-shaped namespace and name, and
/// either a trailing `__<digits>` compilation counter or at least one known
/// munge token — a bare `a$b` with neither is rejected.
#[must_use]
pub fn detect_clojure(mangled: &str) -> bool {
    let Some((ns, name)) = mangled.split_once('$') else {
        return false;
    };
    if name.contains('$') || !is_clojure_ident(ns) || !is_clojure_ident(name) {
        return false;
    }
    let has_counter = name
        .rsplit_once("__")
        .is_some_and(|(stem, digits)| {
            !stem.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        });
    has_counter || CLOJURE_MUNGE.iter().any(|(tok, _)| name.contains(tok))
}

/// Demangle a compiled Clojure function class name:
/// `clojure.core$assoc_BANG___5416` becomes `clojure.core/assoc!`.
#[must_use]
pub fn demangle_clojure(mangled: &str) -> Option<String> {
    if !detect_clojure(mangled) {
        return None;
    }
    let (ns, name) = mangled.split_once('$')?;
    // Drop the trailing `__<digits>` compilation counter, if present.
    let stem = match name.rsplit_once("__") {
        Some((stem, digits))
            if !stem.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            stem
        }
        _ => name,
    };
    let mut decoded = stem.to_owned();
    for (tok, ch) in CLOJURE_MUNGE {
        decoded = decoded.replace(tok, &ch.to_string());
    }
    // Remaining underscores encode `-`.
    decoded = decoded.replace('_', "-");
    Some(format!("{ns}/{decoded}"))
}

// ── Scala ────────────────────────────────────────────────────────────────────

/// Scala operator name encodings (`NameTransformer` in the Scala compiler).
const SCALA_OPS: &[(&str, &str)] = &[
    ("$plus", "+"),
    ("$minus", "-"),
    ("$times", "*"),
    ("$div", "/"),
    ("$colon", ":"),
    ("$less", "<"),
    ("$greater", ">"),
    ("$eq", "="),
    ("$bang", "!"),
    ("$percent", "%"),
    ("$amp", "&"),
    ("$bar", "|"),
    ("$up", "^"),
    ("$tilde", "~"),
    ("$qmark", "?"),
    ("$at", "@"),
    ("$hash", "#"),
    ("$bslash", "\\"),
];

const fn scala_spec_type(c: char) -> Option<&'static str> {
    Some(match c {
        'I' => "Int",
        'J' => "Long",
        'D' => "Double",
        'F' => "Float",
        'Z' => "Boolean",
        'C' => "Char",
        'B' => "Byte",
        'S' => "Short",
        'V' => "Unit",
        _ => return None,
    })
}

/// Splits a trailing `$mcXX$sp` specialization suffix off `name`, returning
/// `(stem, decoded type list)` when present.
fn split_specialization(name: &str) -> Option<(&str, String)> {
    let stem = name.strip_suffix("$sp")?;
    let idx = stem.rfind("$mc")?;
    let codes = &stem[idx + 3..];
    if codes.is_empty() {
        return None;
    }
    let mut types = Vec::with_capacity(codes.len());
    for c in codes.chars() {
        types.push(scala_spec_type(c)?);
    }
    Some((&stem[..idx], types.join(",")))
}

/// Returns `true` for Scala JVM name encodings: names built from Java
/// identifier characters, `.` and `$`, containing at least one distinctly
/// Scala marker.
///
/// Markers are `$anonfun$`, `$adapted`, a `$mcXX$sp` specialization
/// suffix, an operator encoding such as `$plus`, or a module-class trailing
/// `$` on a dotted name.
///
/// Plain dotted names without any `$` marker (e.g. Go's `main.main`) and
/// symbols starting with `$` (Swift's `$s...`) are rejected.
#[must_use]
pub fn detect_scala(mangled: &str) -> bool {
    if mangled.is_empty()
        || mangled.starts_with('$')
        || mangled.starts_with(|c: char| c.is_ascii_digit())
        || !mangled
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$'))
    {
        return false;
    }
    mangled.contains("$anonfun$")
        || mangled.ends_with("$adapted")
        || split_specialization(mangled).is_some()
        || SCALA_OPS.iter().any(|(tok, _)| mangled.contains(tok))
        || (mangled.ends_with('$') && mangled.contains('.') && !mangled.ends_with(".$"))
}

/// Decode a Scala JVM-encoded name.
///
/// Operator encodings become their symbolic
/// form, `$anonfun$f$1` becomes `f.<anonfun-1>`, `$adapted` and `$mcXX$sp`
/// become bracketed annotations, and a module class `Foo$` becomes
/// `object Foo`.
///
/// `scala.collection.immutable.List.$plus$plus` decodes to
/// `scala.collection.immutable.List.++`.
#[must_use]
pub fn demangle_scala(mangled: &str) -> Option<String> {
    if !detect_scala(mangled) {
        return None;
    }
    let mut suffixes: Vec<String> = Vec::new();
    let mut name = mangled;
    if let Some(stripped) = name.strip_suffix("$adapted") {
        suffixes.push("[adapted]".to_owned());
        name = stripped;
    }
    if let Some((stem, types)) = split_specialization(name) {
        suffixes.push(format!("[specialized {types}]"));
        // `split_specialization` borrows from `name`; re-slice from `mangled`.
        name = &name[..stem.len()];
    }
    let is_module = name.ends_with('$') && !name.ends_with("$anonfun$");
    let core = if is_module { &name[..name.len() - 1] } else { name };
    if core.is_empty() {
        return None;
    }
    // Decode operator encodings first (they may be adjacent: `$plus$plus`).
    let mut decoded = core.to_owned();
    for (tok, sym) in SCALA_OPS {
        decoded = decoded.replace(tok, sym);
    }
    // Lambda classes: `Outer$$anonfun$map$1` → `Outer.map.<anonfun-1>`.
    while let Some(idx) = decoded.find("$anonfun$") {
        let before = decoded[..idx].trim_end_matches('$').to_owned();
        let after = &decoded[idx + "$anonfun$".len()..];
        let (fn_name, ordinal) = match after.split_once('$') {
            Some((f, n)) if n.bytes().all(|b| b.is_ascii_digit()) && !n.is_empty() => {
                (f, Some(n.to_owned()))
            }
            _ => (after, None),
        };
        let mut rebuilt = before;
        if !rebuilt.is_empty() {
            rebuilt.push('.');
        }
        rebuilt.push_str(fn_name);
        match ordinal {
            Some(n) => {
                rebuilt.push_str(".<anonfun-");
                rebuilt.push_str(&n);
                rebuilt.push('>');
            }
            None => rebuilt.push_str(".<anonfun>"),
        }
        decoded = rebuilt;
    }
    // Any leftover `$` separators (nested/inner classes) read as `.`.
    let mut result: String = decoded
        .split('$')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if is_module {
        result = format!("object {result}");
    }
    for s in &suffixes {
        result.push(' ');
        result.push_str(s);
    }
    Some(result)
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Try every JVM-family scheme in this module, strictest-first
/// (Kotlin/Native, then Clojure, then Scala), returning the demangled text
/// and the language name on the first match.
#[must_use]
pub fn demangle(mangled: &str) -> Option<(String, &'static str)> {
    if detect_kotlin_native(mangled) {
        return demangle_kotlin_native(mangled).map(|s| (s, "Kotlin/Native"));
    }
    if detect_clojure(mangled) {
        return demangle_clojure(mangled).map(|s| (s, "Clojure"));
    }
    if detect_scala(mangled) {
        return demangle_scala(mangled).map(|s| (s, "Scala"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kotlin_native_kfun() {
        assert_eq!(
            demangle("kfun:kotlin.collections.List#get(kotlin.Int){}kotlin.Any?"),
            Some((
                "kotlin.collections.List.get(kotlin.Int): kotlin.Any?".to_owned(),
                "Kotlin/Native"
            ))
        );
        assert_eq!(
            demangle_kotlin_native("kfun:#main(){}").as_deref(),
            Some("main()")
        );
        assert_eq!(
            demangle_kotlin_native("kfun:kotlin.Throwable#<init>(kotlin.String?){}").as_deref(),
            Some("kotlin.Throwable.<init>(kotlin.String?)")
        );
    }

    #[test]
    fn kotlin_native_kclass_ktype() {
        assert_eq!(
            demangle("kclass:kotlin.String"),
            Some(("class kotlin.String".to_owned(), "Kotlin/Native"))
        );
        assert_eq!(
            demangle_kotlin_native("ktype:kotlin.Int").as_deref(),
            Some("type kotlin.Int")
        );
        assert!(demangle_kotlin_native("kfun:").is_none());
    }

    #[test]
    fn clojure_munging() {
        assert_eq!(
            demangle("clojure.core$assoc_BANG___5416"),
            Some(("clojure.core/assoc!".to_owned(), "Clojure"))
        );
        assert_eq!(
            demangle_clojure("my.ns$fn_name__1234").as_deref(),
            Some("my.ns/fn-name")
        );
        assert_eq!(
            demangle_clojure("clojure.core$nil_QMARK___4611").as_deref(),
            Some("clojure.core/nil?")
        );
        assert_eq!(
            demangle_clojure("clojure.core$_PLUS_").as_deref(),
            Some("clojure.core/+")
        );
    }

    #[test]
    fn clojure_strictness() {
        // No counter and no munge token: not confidently Clojure.
        assert!(!detect_clojure("a$b"));
        assert!(!detect_clojure("scala.Predef$"));
        assert!(!detect_clojure("kfun:foo#bar(){}"));
    }

    #[test]
    fn scala_operators() {
        assert_eq!(
            demangle("scala.collection.immutable.List.$plus$plus"),
            Some(("scala.collection.immutable.List.++".to_owned(), "Scala"))
        );
        assert_eq!(
            demangle_scala("scala.Predef.$qmark$qmark$qmark").as_deref(),
            Some("scala.Predef.???")
        );
        assert_eq!(
            demangle_scala("$colon$colon").as_deref(),
            None,
            "leading `$` must be rejected (Swift `$s` territory)"
        );
    }

    #[test]
    fn scala_module_anonfun_specialized() {
        assert_eq!(
            demangle_scala("scala.Predef$").as_deref(),
            Some("object scala.Predef")
        );
        assert_eq!(
            demangle_scala("com.example.Main$$anonfun$run$1").as_deref(),
            Some("com.example.Main.run.<anonfun-1>")
        );
        assert_eq!(
            demangle_scala("apply$mcII$sp").as_deref(),
            Some("apply [specialized Int,Int]")
        );
        assert_eq!(
            demangle_scala("foldLeft$mcJD$sp$adapted").as_deref(),
            Some("foldLeft [adapted] [specialized Long,Double]")
        );
    }

    #[test]
    fn rejects_other_abis() {
        for sym in [
            "_Z3fooi",
            "?f@@YAHH@Z",
            "_RNvC3foo3bar",
            "$s4main3fooyyF",
            "_D4main4funcFZv",
            "main.main",
            "Java_com_example_Foo_bar",
            "fmt.Println",
            "runtime.morestack_noctxt",
            "__gnat_raise_exception",
        ] {
            assert!(demangle(sym).is_none(), "must not claim {sym}");
        }
    }

    #[test]
    fn plain_dotted_names_left_for_go() {
        assert!(!detect_scala("main.main"));
        assert!(!detect_scala("some.pkg.Func"));
        assert!(!detect_clojure("main.main"));
    }
}
