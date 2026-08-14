//! Demanglers for additional language runtimes beyond the core six ABIs:
//! Java (JNI), Objective-C, gfortran, GNAT Ada, OCaml, GHC Haskell, and
//! Windows C calling-convention decorations.
//!
//! Each scheme here has a deliberately *strict* detector: these run inside
//! [`crate::AutoDemangler`] after the prefix-based ABIs (Rust, Itanium, MSVC,
//! Swift, D) and before Go, whose permissive any-name-with-a-dot detector
//! must stay last.

use crate::core_types::{DemanglingResult, ManglingAbi};

/// Cheap single-pass byte-level features of a symbol, used to gate whole
/// detector families before running them.
///
/// Every gate built on these features is a *necessary* condition distilled
/// from the corresponding detector — never a sufficient one. Equivalence of
/// the gated dispatchers with the plain detector chains is enforced by
/// `tests/gate_equivalence.rs`; extend that test when adding a gate.
#[expect(
    clippy::struct_excessive_bools,
    reason = "deliberately a flat bag of independent byte-presence flags \
              filled by one scan; a state machine would obscure the gates"
)]
pub(crate) struct SymFeatures {
    /// First byte, or 0 for the empty string.
    pub(crate) first: u8,
    /// Last byte, or 0 for the empty string.
    pub(crate) last: u8,
    /// Contains `_`.
    pub(crate) has_underscore: bool,
    /// Contains `__`.
    pub(crate) has_dunder: bool,
    /// Contains `$`.
    pub(crate) has_dollar: bool,
    /// Contains `@`.
    pub(crate) has_at: bool,
    /// Contains `.`.
    pub(crate) has_dot: bool,
    /// Contains `:`.
    pub(crate) has_colon: bool,
    /// Contains `[`.
    pub(crate) has_bracket: bool,
    /// Contains an ASCII uppercase letter.
    pub(crate) has_upper: bool,
}

impl SymFeatures {
    /// Scan `s` once and collect the features.
    pub(crate) fn scan(s: &str) -> Self {
        let bytes = s.as_bytes();
        let mut f = Self {
            first: bytes.first().copied().unwrap_or(0),
            last: bytes.last().copied().unwrap_or(0),
            has_underscore: false,
            has_dunder: false,
            has_dollar: false,
            has_at: false,
            has_dot: false,
            has_colon: false,
            has_bracket: false,
            has_upper: false,
        };
        let mut prev_underscore = false;
        for &b in bytes {
            match b {
                b'_' => {
                    f.has_underscore = true;
                    if prev_underscore {
                        f.has_dunder = true;
                    }
                }
                b'$' => f.has_dollar = true,
                b'@' => f.has_at = true,
                b'.' => f.has_dot = true,
                b':' => f.has_colon = true,
                b'[' => f.has_bracket = true,
                b'A'..=b'Z' => f.has_upper = true,
                _ => {}
            }
            prev_underscore = b == b'_';
        }
        f
    }
}

/// The return type of a convention rendering, when it has one.
///
/// Only Kotlin/Native spells one, after the parameter list:
/// `a.B.c(kotlin.Int): kotlin.Any?`. The `: ` must FOLLOW the closing paren —
/// the descriptive renderings this module also produces (`lua module open:
/// socket.core`, `php method: ArrayObject::count`) put a path after their
/// colon, not a type, and reporting that as a return type would be the
/// "whole sentence in a field" defect all over again.
#[must_use]
pub fn split_convention_return(demangled: &str) -> Option<String> {
    let close = demangled.rfind(')')?;
    let after = demangled.get(close + 1..)?.trim_start();
    let ty = after.strip_prefix(':')?.trim();
    (!ty.is_empty()).then(|| ty.to_owned())
}

/// The parameter list of a convention rendering, as one entry per parameter.
///
/// The C++-family decoders in `lang_more` (cfront, Watcom, Borland) render a
/// full signature — `f(int, char)` — but their results reported `args: []`, so
/// a consumer reading the structured field saw a function with NO parameters
/// while the string showed two. That is the arity defect class inverted: iter
/// 116 found Watcom inventing phantom parameters in the rendering, and the
/// field was silently dropping real ones.
///
/// Depth-aware, so a function-pointer or template parameter counts once.
/// Returns an empty list for `()` and for the C spelling `(void)`, matching the
/// Itanium path.
#[must_use]
pub fn split_convention_args(demangled: &str) -> Vec<String> {
    let Some(open) = demangled.find('(') else {
        return Vec::new();
    };
    let mut depth = 0i32;
    let mut close = None;
    for (i, c) in demangled.char_indices().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return Vec::new();
    };
    let inner = demangled[open + 1..close].trim();
    if inner.is_empty() || inner == "void" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(inner[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(inner[start..].trim().to_owned());
    out
}

/// Split a convention rendering into `(namespace, function)`.
///
/// The convention decoders render descriptive prose — `lua module open:
/// socket.core`, `php method: ArrayObject::count`, `mexFunction (MATLAB MEX
/// gateway)` — and the structured fields were derived from it in two different
/// wrong ways: [`result`] below left `function` **empty**, while the
/// `lang_more` path in `backends.rs` set it to the **whole sentence**. Both
/// satisfied `tests/structured_consistency.rs`, which only requires a field to
/// appear inside the rendering: an empty field is vacuously contained, and the
/// full string is contained literally.
///
/// Consumers use these fields — the decompiler names variables from them — so
/// `function: "lua module open: socket.core"` is not a cosmetic problem.
///
/// The rule is mechanical and reads only what the crate itself emitted:
/// drop a `"<description>: "` prefix and a trailing parenthetical, then split
/// the remaining path on `::` or `.`.
#[must_use]
pub fn split_convention_rendering(demangled: &str) -> (Option<String>, String) {
    // `lua module open: socket.core` -> `socket.core`
    let path = demangled.rsplit_once(": ").map_or(demangled, |(_, r)| r);
    // `mexFunction (MATLAB MEX gateway)` -> `mexFunction`
    let path = path.split(" (").next().unwrap_or(path).trim();
    // `pkg.proc [ada entry]` -> `pkg.proc`. A bracketed tag is an annotation
    // this crate SYNTHESISES, never part of a name, and every other annotated
    // rendering already keeps its marker out of the fields — the clone suffix
    // (`void main.foo() [clone .cold]`) reports `foo`, and the Swift operator
    // suffix (`main.foo() -> () [TA]`) reports `foo`. The GNAT tags added at
    // iter 136 were the outlier, reporting `function: "proc [ada entry]"`.
    let path = path.split(" [").next().unwrap_or(path).trim();

    let (sep, parts): (&str, Vec<&str>) = if path.contains("::") {
        ("::", path.split("::").collect())
    } else {
        (".", path.split('.').collect())
    };
    let parts: Vec<&str> = parts.into_iter().filter(|p| !p.is_empty()).collect();

    match parts.as_slice() {
        [] => (None, path.to_owned()),
        [only] => (None, (*only).to_owned()),
        [rest @ .., last] => (Some(rest.join(sep)), (*last).to_owned()),
    }
}

/// Structured fields for an Objective-C rendering.
///
/// [`split_convention_rendering`] is built for the convention decoders' prose
/// (`lua module open: socket.core`) and finds no separator in `-[Foo bar]`, so
/// the WHOLE rendering became the `function` field — the exact failure its own
/// doc comment describes, still present for Obj-C.
///
/// The method syntax carries the two parts directly: `-[Foo bar]` is class
/// `Foo`, selector `bar`. The metadata forms (`class Foo`, `protocol Foo`,
/// `instance methods of Foo`) name a single entity, which is the last
/// whitespace-separated token; `ivar Foo::count` additionally carries a scope.
fn objc_result(mangled: &str, demangled: String) -> DemanglingResult {
    let (class, function) = objc_fields(&demangled);
    DemanglingResult {
        original: mangled.to_owned(),
        demangled,
        abi: ManglingAbi::ObjC,
        namespace: None,
        class,
        function,
        args: Vec::new(),
        return_type: None,
    }
}

fn objc_fields(demangled: &str) -> (Option<String>, String) {
    // `±[Class sel]`, possibly with a `(Category)` on the class.
    if let Some(inner) = demangled
        .strip_prefix("-[")
        .or_else(|| demangled.strip_prefix("+["))
        .and_then(|r| r.strip_suffix(']'))
    {
        let mut it = inner.splitn(2, char::is_whitespace);
        let class = it.next().unwrap_or("").trim();
        let sel = it.next().unwrap_or("").trim();
        if sel.is_empty() {
            return (None, class.to_owned());
        }
        return (Some(class.to_owned()), sel.to_owned());
    }
    // `ivar Foo::count` — the last token carries a scope.
    let last = demangled
        .rsplit(char::is_whitespace)
        .next()
        .unwrap_or(demangled);
    last.rsplit_once("::").map_or_else(
        || (None, last.to_owned()),
        |(scope, name)| (Some(scope.to_owned()), name.to_owned()),
    )
}

/// Structured fields for a JNI rendering.
///
/// A JNI symbol names package, CLASS and method by construction —
/// `Java_com_foo_Bar_baz` is `com.foo` / `Bar` / `baz` — but the generic
/// splitter put everything before the method into `namespace`
/// (`"com.foo.Bar"`, class `None`), losing the one distinction the convention
/// makes explicit.
///
/// Unlike Rust and MSVC, which guess that the last scope component is a class,
/// this is not a guess: the JNI encoding places the class there.
fn jni_result(mangled: &str, demangled: String) -> DemanglingResult {
    let mut parts: Vec<&str> = demangled.split('.').collect();
    let function = parts.pop().unwrap_or_default().to_owned();
    let class = parts.pop().map(str::to_owned);
    let namespace = (!parts.is_empty()).then(|| parts.join("."));
    DemanglingResult {
        original: mangled.to_owned(),
        demangled,
        abi: ManglingAbi::Java,
        namespace,
        class,
        function,
        args: Vec::new(),
        return_type: None,
    }
}

fn result(mangled: &str, demangled: String, abi: ManglingAbi) -> DemanglingResult {
    let (namespace, function) = split_convention_rendering(&demangled);
    DemanglingResult {
        original: mangled.to_owned(),
        demangled,
        abi,
        namespace,
        class: None,
        function,
        args: Vec::new(),
        return_type: None,
    }
}

// ── Java JNI ─────────────────────────────────────────────────────────────────

/// `Java_<pkg>_<Class>_<method>` with escapes `_1` = `_`, `_2` = `;`,
/// `_3` = `[`, `_0XXXX` = UTF-16 code unit; `__` starts the overload
/// signature, which is dropped from the readable form.
#[must_use]
pub fn detect_jni(mangled: &str) -> bool {
    // Delegate: iter 109 taught `demangle_jni` the escape table (`_4`-`_9` are
    // undefined, `_0` needs exactly four hex digits) but left this shape rule
    // behind, so the detector kept claiming what the backend now declines.
    demangle_jni(mangled).is_some()
}

/// Demangle a JNI native-method symbol to `pkg.Class.method`.
#[must_use]
pub fn demangle_jni(mangled: &str) -> Option<String> {
    let rest = mangled
        .strip_prefix("Java_")
        .or_else(|| mangled.strip_prefix("JNICALL_Java_"))?;
    // A JNI native method encodes package, class AND method, so at least one
    // further separator must follow `Java_`. Without this, `Java_helper` — a
    // plain C name — decoded to `helper`. The rule lived only in the detector;
    // delegating without moving it here traded one divergence for another.

    // `__` separates the name from the (optional) argument signature.
    let name_part = rest.split("__").next()?;
    if name_part.is_empty() {
        return None;
    }
    // No component of the NAME may be empty. `Java__` decoded to a lone `.`,
    // `Java_a_` to `a.` and `Java__b` to `.b` — a package, class or method with
    // no name at all. Same shape as the Ada and gfortran component rules
    // (iter 110): the check existed for the symbol as a whole, not for its
    // parts.
    //
    // It must run on `name_part` and not on `rest`: `__` is the overload-
    // signature separator, so checking before the split rejected the perfectly
    // ordinary `Java_pkg_Cls_meth__Ljava_lang_String_2`.
    if name_part.split('_').any(str::is_empty) {
        return None;
    }
    // A JNI native method encodes package, class AND method, so the NAME must
    // carry at least one separator. This was checked on everything after
    // `Java_`, which includes the overload signature — so `Java_a__b_` passed
    // (the `__` satisfied it) and decoded to the single component `a`, a symbol
    // with no class and no method.
    if !name_part.contains('_') {
        return None;
    }
    let mut out = String::with_capacity(name_part.len());
    let mut chars = name_part.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' {
            match chars.peek() {
                Some('1') => {
                    chars.next();
                    out.push('_');
                }
                Some('2') => {
                    chars.next();
                    out.push(';');
                }
                Some('3') => {
                    chars.next();
                    out.push('[');
                }
                Some('0') => {
                    chars.next();
                    // EXACTLY four hex digits. `take(4)` yields fewer when the input
                    // runs short, and `from_str_radix` accepts a 1-3 digit string, so a
                    // truncated escape silently swallowed the rest of the name:
                    // `Java_com_foo_Bar_a_0b` rendered `com.foo.Bar.a`, losing the `b`.
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return None;
                    }
                    let cu = u32::from_str_radix(&hex, 16).ok()?;
                    // A supplementary-plane character is spelled as a UTF-16
                    // surrogate pair — two `_0XXXX` escapes. A high surrogate
                    // (0xD800..=0xDBFF) is not a scalar value on its own, so
                    // combine it with the following low surrogate (which must
                    // itself be a `_0XXXX` escape) before emitting.
                    let ch = if (0xD800..=0xDBFF).contains(&cu) {
                        if chars.next() != Some('_') || chars.next() != Some('0') {
                            return None;
                        }
                        let lo_hex: String = chars.by_ref().take(4).collect();
                        if lo_hex.len() != 4 {
                            return None;
                        }
                        let lo = u32::from_str_radix(&lo_hex, 16).ok()?;
                        if !(0xDC00..=0xDFFF).contains(&lo) {
                            return None;
                        }
                        let scalar = 0x1_0000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
                        char::from_u32(scalar)?
                    } else {
                        char::from_u32(cu)?
                    };
                    out.push(ch);
                }
                // `_` before a digit is an ESCAPE marker, and only `_0`-`_3` are
                // defined. `_4`-`_9` do not exist, so treating the `_` as a package
                // separator invented a component: `Java_com_foo_Bar_a_4b` rendered
                // `com.foo.Bar.a.4b`, and `4b` cannot be a Java identifier — it starts
                // with a digit. Declining is the honest answer for an undefined escape.
                Some(d) if d.is_ascii_digit() => return None,
                // Otherwise `_` is the package/class separator.
                _ => out.push('.'),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

// ── Objective-C ────────────────────────────────────────────────────────────────

// Objective-C detection and rendering live in [`crate::classify::ObjCDemangler`];
// this module only routes to it so there is exactly one implementation.

// ── gfortran ─────────────────────────────────────────────────────────────────

/// Whether `s` begins with an ASCII letter.
///
/// Ada and Fortran identifiers must both start with a letter, so a component
/// that does not is not an identifier the compiler could have mangled.
fn starts_with_ascii_letter(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// gfortran module procedures: `__<module>_MOD_<procedure>`.
#[must_use]
pub fn detect_gfortran(mangled: &str) -> bool {
    // Delegate rather than restate the rule: a detector looser than its
    // backend claims symbols nothing can decode, and `___a_MOD_x` was exactly
    // that once the leading-letter rule landed below.
    demangle_gfortran(mangled).is_some()
}

/// Demangle `__mymod_MOD_solve` to `mymod::solve`.
#[must_use]
pub fn demangle_gfortran(mangled: &str) -> Option<String> {
    let rest = mangled.strip_prefix("__")?;
    let (module, proc) = rest.split_once("_MOD_")?;
    // A Fortran identifier must begin with a LETTER. Testing only for
    // non-empty let a third leading underscore through: `___a_MOD_x` rendered
    // `_a::x`, naming a module that cannot exist in the language.
    if !starts_with_ascii_letter(module) || !starts_with_ascii_letter(proc) {
        return None;
    }
    Some(format!("{module}::{proc}"))
}

// ── GNAT Ada ─────────────────────────────────────────────────────────────────

/// GNAT encodes `Pkg.Child.Subprogram` as `pkg__child__subprogram`, all
/// lowercase.
///
/// The detector requires a double underscore *between*
/// identifiers, no leading underscore (which C runtime symbols use), and the
/// GNAT character set, so `__libc_start_main` and plain C names stay out.
#[must_use]
pub fn detect_gnat_ada(mangled: &str) -> bool {
    !mangled.starts_with('_')
        && mangled.contains("__")
        && !mangled.ends_with('_')
        && mangled
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        // Every component must be an Ada identifier, which begins with a
        // LETTER. Rejecting only empty and digit-initial components let a
        // third underscore through: `a___b` rendered `a._b`, and an Ada
        // identifier can never start with an underscore (they are only legal
        // *between* alphanumerics).
        && mangled.split("__").all(starts_with_ascii_letter)
}

/// Demangle `ada__text_io__put_line` to `ada.text_io.put_line`.
#[must_use]
pub fn demangle_gnat_ada(mangled: &str) -> Option<String> {
    if !detect_gnat_ada(mangled) {
        return None;
    }
    Some(mangled.split("__").collect::<Vec<_>>().join("."))
}

/// GNAT's compiler-generated entry points.
///
/// * `_ada_<unit>` is the Ada-callable entry every library-level main carries.
/// * `<unit>___elabb` / `___elabs` elaborate a unit's body / spec, and every
///   Ada unit has them.
///
/// All three declined as `UndecoratedC` — real Ada symbols filed as plain C
/// names, so a consumer grouping by language lost them. They are excluded by
/// the ordinary rules for good reasons (a leading underscore, and a component
/// starting with `_`), which is why they need their own handling rather than a
/// loosening.
///
/// The kind is reported as a bracketed tag rather than folded into the name:
/// `_ada_pkg__proc` and `pkg__proc` are DIFFERENT symbols — the Ada-callable
/// wrapper and the procedure itself — and rendering both as `pkg.proc` would
/// merge them.
fn demangle_gnat_special(mangled: &str) -> Option<String> {
    let dotted = |unit: &str| -> Option<String> {
        if !detect_gnat_ada(unit) && !is_simple_ada_name(unit) {
            return None;
        }
        Some(unit.split("__").collect::<Vec<_>>().join("."))
    };
    if let Some(unit) = mangled.strip_prefix("_ada_") {
        return dotted(unit).map(|d| format!("{d} [ada entry]"));
    }
    for (suffix, tag) in [("___elabb", "elaborate body"), ("___elabs", "elaborate spec")] {
        if let Some(unit) = mangled.strip_suffix(suffix) {
            return dotted(unit).map(|d| format!("{d} [{tag}]"));
        }
    }
    None
}

/// A single Ada identifier: letter-initial, lowercase/digit/underscore, and no
/// `__` (which would make it a qualified name for [`detect_gnat_ada`]).
fn is_simple_ada_name(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("__")
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

// ── OCaml ────────────────────────────────────────────────────────────────────

/// OCaml native symbols: `caml<Module>__<name>_<uid>`, module capitalised.
#[must_use]
pub fn detect_ocaml(mangled: &str) -> bool {
    mangled
        .strip_prefix("caml")
        .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_uppercase()) && r.contains("__"))
}

/// Demangle `camlFoo__bar_271` to `Foo.bar`.
#[must_use]
pub fn demangle_ocaml(mangled: &str) -> Option<String> {
    // An OCaml module name is CAPITALISED, and `caml_` (lowercase) is the C-stub
    // convention, not a module path — `caml_ml_open_descriptor_in` is a runtime
    // primitive. Only `detect_ocaml` knew that, so `caml_a__b` decoded to
    // `_a.b`, naming a module OCaml cannot express.
    if !detect_ocaml(mangled) {
        return None;
    }
    let rest = mangled.strip_prefix("caml")?;
    // OCaml joins every module-path component with `__`, so
    // `Stdlib.Printf.printf` mangles as `camlStdlib__Printf__printf_42`.
    // Splitting once left the inner separators intact and produced
    // `Stdlib.Printf__printf` — a module path rendered as part of the
    // function name.
    let mut parts: Vec<&str> = rest.split("__").collect();
    let name = parts.pop()?;
    if name.is_empty() || parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    // Drop the trailing numeric uid, if any.
    let base = match name.rsplit_once('_') {
        Some((head, tail)) if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => name,
    };
    Some(format!("{}.{base}", parts.join(".")))
}

// ── GHC Haskell ──────────────────────────────────────────────────────────────

/// GHC symbol suffixes that mark a z-encoded Haskell symbol.
const GHC_SUFFIXES: &[&str] = &["info", "closure", "entry", "con_entry", "static_info", "srt", "bytes"];

/// GHC symbols look like `<pkg>_<Module>_<name>_<suffix>` with module and
/// name z-encoded (`zi` = `.`, `zu` = `_`, `zd` = `$`, …).
#[must_use]
pub fn detect_ghc(mangled: &str) -> bool {
    // Ordered cheapest-and-most-selective first. Every condition below is a
    // pure predicate ANDed with the others, so the order is free to choose:
    // the suffix test rejects almost every symbol for a bounded `strip_suffix`
    // over seven short strings, while the whole-string scans and the two full
    // detector calls used to run *before* it.
    //
    // **Measured neutral, not an optimisation.** An interleaved A/B over the
    // benchmark corpus put the two orderings within noise of each other
    // (medians 1.035M vs 1.053M calls/s, six rounds). `detect_ghc` is simply
    // not hot for that corpus — most symbols never reach it. The ordering is
    // kept because it is the sensible one, not because it was shown to be
    // faster; do not cite it as a speedup.

    // 1. The GHC suffix, and enough underscore-separated parts to be a
    //    module-qualified name. Bounded work, and false for nearly everything.
    if !GHC_SUFFIXES
        .iter()
        .any(|s| mangled.strip_suffix(s).is_some_and(|r| r.ends_with('_')))
        || mangled.starts_with('_')
    {
        return false;
    }

    // 2. A GHC symbol names its module in z-encoded form, which always carries
    //    an uppercase letter: `base_GHCziBase_…`, `main_Main_…`. The doc for
    //    the OCaml/Ada deferral below already relied on that property, but
    //    nothing enforced it, so an all-lowercase C function ending in a GHC
    //    suffix was claimed *and rewritten*:
    //
    //      "some_random_c_function_info" -> "some:random_c.function (info)"
    if !mangled.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    // 3. z-encoding escapes every character outside `[A-Za-z0-9_]` (`zc` for
    //    `:`, `ZL` for `(`), so a GHC symbol can never contain whitespace or
    //    punctuation. Without this the suffix rule claimed ordinary prose —
    //    including *already demangled* C++ names, which it then rewrote:
    //
    //      "typeinfo for __cxxabiv1::__class_type_info"
    //        -> "typeinfo for :_cxxabiv1::__class.type (info)"
    if !mangled
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return false;
    }

    if mangled.split('_').count() < 3 {
        return false;
    }

    // 4. Last, because each is a full detector: GHC is the loosest convention
    //    detector and also matches OCaml and Ada names it cannot decode
    //    (`camlDune__exe__Main__entry`, a real Dune entry point, and
    //    `ada__text__info`). The dispatcher tries GHC first and short-circuits
    //    on its failure, so without deferring here those valid symbols declined
    //    before their own detector ran. Deferring to each backend's own
    //    detector keeps GHC from claiming what is not its own — the contract
    //    the dispatch chain and its `gate_equivalence` proof rely on.
    !(detect_ocaml(mangled) || detect_gnat_ada(mangled))
}

/// Decode GHC z-encoding: lowercase `z` and uppercase `Z` escape sequences.
#[must_use]
pub fn zdecode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        // Tuple constructors: `Z<n>T` is the boxed n-tuple `(,,)` (with n-1
        // commas; `Z0T` is unit `()`), `Z<n>H` the unboxed `(#,#)`. The digits
        // are decimal and variable-length, so they need lookahead the
        // single-`next()` escape table below cannot do. A `Z<digits>` run not
        // closed by `T`/`H` is malformed; it is re-emitted verbatim.
        if c == 'Z' && chars.peek().is_some_and(char::is_ascii_digit) {
            let mut digits = String::new();
            while let Some(&d) = chars.peek() {
                if !d.is_ascii_digit() {
                    break;
                }
                digits.push(d);
                chars.next();
            }
            // The arity must be representable, and it must be an arity a
            // Haskell tuple can have: 0 (unit) or 2 and above. There is no
            // 1-tuple, so `Z1T` is malformed input.
            //
            // `unwrap_or(0)` plus `saturating_sub(1)` collapsed both cases onto
            // unit: `Z1T` and an arity too large to parse each rendered `()`,
            // which is what `Z0T` means. Distinct inputs producing one output
            // assert a fact the input never gave — the shape fixed for D's `G`
            // and `B` numbers. Malformed runs take the verbatim path this
            // decoder already uses for a run not closed by `T`/`H`.
            let arity = digits.parse::<usize>().ok().filter(|n| *n == 0 || *n >= 2);
            let next = chars.next();
            match (next, arity) {
                (Some('T'), Some(n)) => {
                    out.push('(');
                    out.extend(std::iter::repeat_n(',', n.saturating_sub(1)));
                    out.push(')');
                }
                (Some('H'), Some(n)) => {
                    out.push_str("(#");
                    out.extend(std::iter::repeat_n(',', n.saturating_sub(1)));
                    out.push_str("#)");
                }
                (other, _) => {
                    out.push('Z');
                    out.push_str(&digits);
                    if let Some(o) = other {
                        out.push(o);
                    }
                }
            }
            continue;
        }
        // Unicode character escape: `z<hex>U`, the code point in lowercase hex
        // terminated by `U`. The encoder zero-prefixes a hex run beginning with
        // a letter (`é` = 0xe9 -> `z0e9U`), so a lowercase `z` followed by a
        // *digit* is always this escape and never one of the single-letter
        // escapes below — the disambiguation is unambiguous. A run not closed by
        // `U`, or one whose value is not a scalar, is malformed and re-emitted.
        if c == 'z' && chars.peek().is_some_and(char::is_ascii_digit) {
            let mut hex = String::new();
            while chars.peek().is_some_and(char::is_ascii_hexdigit) {
                hex.push(chars.next().unwrap_or_default());
            }
            if chars.peek() == Some(&'U') {
                chars.next();
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                    continue;
                }
                // Value parsed but is not a scalar value: keep the `U` we ate.
                out.push('z');
                out.push_str(&hex);
                out.push('U');
                continue;
            }
            out.push('z');
            out.push_str(&hex);
            continue;
        }
        match c {
            'z' | 'Z' => {
                let next = chars.next();
                let table = if c == 'z' { z_letter_escape } else { cap_z_letter_escape };
                if let Some(d) = next.and_then(table) {
                    out.push(d);
                } else {
                    // Not a known escape: re-emit the sigil and whatever
                    // followed, verbatim.
                    out.push(c);
                    if let Some(o) = next {
                        out.push(o);
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The lowercase `z<letter>` single-character escapes of GHC z-encoding.
const fn z_letter_escape(c: char) -> Option<char> {
    Some(match c {
        'i' => '.',
        'u' => '_',
        'a' => '&',
        'b' => '|',
        'c' => '^',
        'd' => '$',
        'e' => '=',
        'g' => '>',
        'h' => '#',
        'l' => '<',
        'm' => '-',
        'n' => '!',
        'p' => '+',
        'q' => '\'',
        'r' => '\\',
        's' => '/',
        't' => '*',
        'v' => '%',
        'z' => 'z',
        _ => return None,
    })
}

/// The uppercase `Z<letter>` single-character escapes of GHC z-encoding.
/// (The `Z<digits>T`/`H` tuple forms are handled separately in `zdecode`.)
const fn cap_z_letter_escape(c: char) -> Option<char> {
    Some(match c {
        'C' => ':',
        'L' => '(',
        'R' => ')',
        'M' => '[',
        'N' => ']',
        'Z' => 'Z',
        _ => return None,
    })
}

/// Demangle `base_GHCziBase_map_info` to `base:GHC.Base.map (info)`.
#[must_use]
pub fn demangle_ghc(mangled: &str) -> Option<String> {
    // The detector carries rules this function never had — no leading `_`, an
    // uppercase letter in the module — and without them a COFF section name
    // that merely ends in a GHC suffix was rewritten wholesale:
    // `.pdata$_ZL17parse_lsda_header…` became
    // `.pdata$:(17parse_lsda_header… (info)`.
    if !detect_ghc(mangled) {
        return None;
    }
    let (body, suffix) = GHC_SUFFIXES.iter().find_map(|s| {
        mangled
            .strip_suffix(s)
            .and_then(|r| r.strip_suffix('_'))
            .map(|body| (body, *s))
    })?;
    let (pkg, rest) = body.split_once('_')?;
    let (module, name) = rest.rsplit_once('_')?;
    if pkg.is_empty() || module.is_empty() || name.is_empty() {
        return None;
    }
    // The package key is Z-encoded like every other component: `ghc-prim`
    // mangles to `ghczmprim` (`zm` = `-`), and a modern key carries a
    // Z-encoded version (`ghczmprimzm0zi5…`). It was previously emitted raw
    // while the module and name were decoded, so the same `zm`/`zi` escape
    // rendered as `-`/`.` in one component and survived undecoded in another.
    // Escape-free names (`base`, `main`) are unchanged by `zdecode`.
    Some(format!(
        "{}:{}.{} ({suffix})",
        zdecode(pkg),
        zdecode(module),
        zdecode(name)
    ))
}

// ── Windows C calling-convention decorations ─────────────────────────────────

/// `_name@12` (stdcall) and `@name@8` (fastcall): a C identifier with the
/// argument-bytes count appended.
#[must_use]
pub fn detect_c_decorated(mangled: &str) -> bool {
    let rest = mangled
        .strip_prefix('@')
        .or_else(|| mangled.strip_prefix('_'))
        .unwrap_or(mangled);
    let Some((name, digits)) = rest.rsplit_once('@') else {
        return false;
    };
    // The digits are a count of argument *bytes*, so they are a plain decimal
    // number: MSVC emits `@0`, `@4`, `@16` and never zero-pads. Accepting any
    // run of digits made this claim MSVC constant-pool symbols, whose payload
    // happens to be numeric — `__xmm@00000000000000010000000000000001` was
    // read as a stdcall decoration and rendered `_xmm`, discarding the very
    // bytes that identify the constant. Two different constants then decoded
    // to the same string.
    //
    // Same shape as the `_R`/`_T`/`_D` prefix rules this crate removed: a
    // detector looser than the thing it detects invents symbols.
    let plausible_byte_count =
        digits.len() == 1 || !digits.starts_with('0');

    !name.is_empty()
        && !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit())
        && plausible_byte_count
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// Strip the decoration: `_MessageBoxA@16` becomes `MessageBoxA`.
#[must_use]
pub fn demangle_c_decorated(mangled: &str) -> Option<String> {
    if !detect_c_decorated(mangled) {
        return None;
    }
    let rest = mangled
        .strip_prefix('@')
        .or_else(|| mangled.strip_prefix('_'))
        .unwrap_or(mangled);
    rest.rsplit_once('@').map(|(name, _)| name.to_owned())
}

// ── Dispatcher glue ──────────────────────────────────────────────────────────

/// Try every scheme in this module, strictest first.
#[must_use]
pub fn demangle_extra(mangled: &str) -> Option<DemanglingResult> {
    let features = SymFeatures::scan(mangled);
    demangle_extra_with(mangled, &features)
}

/// [`demangle_extra`] with pre-computed [`SymFeatures`], so the byte scan can
/// be shared with [`crate::lang_more::demangle_more_with`] on the hot path.
///
/// Each `if` is guarded by a *necessary* condition of its detector:
/// - JNI: `Java_` / `JNICALL_Java_` both start with `J`.
/// - `ObjC`: `±[Class sel]` contains `[` (even with leading whitespace, which
///   the detector trims); `_OBJC_` starts with `_`.
/// - gfortran: `__<mod>_MOD_<proc>` starts with `__`.
/// - GHC: needs a `_<suffix>` and must not start with `_`.
/// - OCaml: `caml<Module>__…` starts with `c`.
/// - Decorated C: `_f@8` / `@f@8` needs an `@`.
/// - Ada: all-lowercase charset with `__`, no leading `_`.
pub(crate) fn demangle_extra_with(
    mangled: &str,
    f: &SymFeatures,
) -> Option<DemanglingResult> {
    if f.first == b'J' && detect_jni(mangled) {
        return demangle_jni(mangled).map(|d| jni_result(mangled, d));
    }
    if (f.has_bracket || f.first == b'_') && crate::classify::ObjCDemangler::detect(mangled) {
        return crate::classify::ObjCDemangler::demangle(mangled)
            .map(|d| objc_result(mangled, d));
    }
    if f.first == b'_' && f.has_dunder && detect_gfortran(mangled) {
        return demangle_gfortran(mangled).map(|d| result(mangled, d, ManglingAbi::Fortran));
    }
    if f.first != b'_' && f.has_underscore && detect_ghc(mangled) {
        return demangle_ghc(mangled).map(|d| result(mangled, d, ManglingAbi::Haskell));
    }
    if f.first == b'c' && detect_ocaml(mangled) {
        return demangle_ocaml(mangled).map(|d| result(mangled, d, ManglingAbi::OCaml));
    }
    if f.has_at && detect_c_decorated(mangled) {
        return demangle_c_decorated(mangled).map(|d| result(mangled, d, ManglingAbi::C));
    }
    if f.first != b'_' && f.has_dunder && !f.has_upper && detect_gnat_ada(mangled) {
        return demangle_gnat_ada(mangled).map(|d| result(mangled, d, ManglingAbi::Ada));
    }
    // GNAT's compiler-generated entry points need their own line: the gate
    // above excludes a leading `_`, and `detect_gnat_ada` rejects a component
    // starting with `_`, so `_ada_hello` and `pkg___elabb` never reached the
    // Ada backend at all and were filed as undecorated C.
    //
    // `detect_gnat_ada` is deliberately NOT widened to cover them: it is used
    // as an *exclusion* elsewhere in this module, where a looser rule rejects
    // more rather than claiming more, and loosening it there would change the
    // sign of the test.
    // `_ada_<unit>` carries no `__` when the unit is a single identifier, so the
    // gate needs the prefix as well as the dunder used by the elaboration forms.
    if !f.has_upper
        && (f.has_dunder || mangled.starts_with("_ada_"))
        && let Some(d) = demangle_gnat_special(mangled)
    {
        return Some(result(mangled, d, ManglingAbi::Ada));
    }
    None
}
