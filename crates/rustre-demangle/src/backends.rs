//! Backend demanglers: Itanium (via `cpp_demangle`), MSVC (manual parser),
//! Rust (via `rustc-demangle`), Swift (heuristic), and the [`AutoDemangler`].

use crate::core_types::{Demangler, DemanglingResult, ManglingAbi};
use crate::msvc_extras::{demangle_msvc_rtti, msvc_calling_convention};

// ── Itanium demangler (via cpp_demangle) ──────────────────────────────────────

/// Demangler for the Itanium C++ ABI (GCC, Clang, on Linux/macOS/BSD).
pub struct ItaniumDemangler;

impl Demangler for ItaniumDemangler {
    fn detect(&self, mangled: &str) -> bool {
        mangled.starts_with("_Z") || mangled.starts_with("__Z")
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if !self.detect(mangled) {
            return None;
        }
        let sym = cpp_demangle::BorrowedSymbol::new(mangled.as_bytes()).ok()?;
        // `Symbol`'s `Display` can itself fail on pathological inputs, and
        // `ToString::to_string` turns that failure into a panic — go through
        // the fallible `demangle` API instead.
        let raw = sym
            .demangle(&cpp_demangle::DemangleOptions::default())
            .ok()?;
        // Normalize vendor-specific `{vtable(T)}` / `{vtt(T)}` / `{typeinfo(T)}`
        // forms produced by `cpp_demangle` to the canonical Itanium-ABI
        // wording used by `c++filt` ("vtable for T", "VTT for T",
        // "typeinfo for T", "typeinfo name for T").
        let normalized =
            repair_ss_ctor_dropped_param(mangled, &normalize_itanium_special(&raw));
        // If this is actually a legacy Rust symbol (Itanium-style with the
        // `::h<16 hex>` trailing hash component), strip the hash so the output
        // matches `c++filt`/`rustc-demangle` alternate-form conventions and the
        // validator's expected wording.
        let demangled = crate::rust_demangler::strip_rust_hash(&normalized);

        let (namespace, class, function, args, return_type) = split_itanium_components(&demangled);

        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled,
            abi: ManglingAbi::Itanium,
            namespace,
            class,
            function,
            args,
            return_type,
        })
    }
}

/// Repair a qualifier `cpp_demangle` misplaces when a substitution is
/// followed by a nested component: `A&::B` must read `A::B&` (observed on
/// `_ZNK10__cxxabiv120__si_class_type_info11__do_upcastE…`, where the third
/// parameter rendered as `__class_type_info&::__upcast_result`). The token
/// `&::` / `*::` never occurs in a correctly rendered C++ name, so the
/// rewrite cannot misfire on valid output.
#[must_use]
pub fn repair_misplaced_qualifier(text: &str) -> String {
    if !text.contains("&::") && !text.contains("*::") {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let qual = chars[i];
        let qualifier_before_nested = (qual == '&' || qual == '*')
            && chars.get(i + 1) == Some(&':')
            && chars.get(i + 2) == Some(&':');
        if qualifier_before_nested {
            // Consume the following `::ident` chain, then re-emit the
            // qualifier after it.
            let mut chain_end = i + 1;
            while chars.get(chain_end) == Some(&':') && chars.get(chain_end + 1) == Some(&':') {
                let mut ident_end = chain_end + 2;
                let start = ident_end;
                while ident_end < chars.len()
                    && (chars[ident_end].is_alphanumeric()
                        || chars[ident_end] == '_'
                        || chars[ident_end] == '~')
                {
                    ident_end += 1;
                }
                if ident_end == start {
                    break;
                }
                chain_end = ident_end;
            }
            out.extend(&chars[i + 1..chain_end]);
            out.push(qual);
            i = chain_end;
        } else {
            out.push(qual);
            i += 1;
        }
    }
    out
}

/// Repair a parameter dropped by `cpp_demangle` (≤ 0.4.5, still unfixed) in
/// `std::string` (`Ss`) template constructors.
///
/// For `_ZNSsC1IPKcEET_S2_RKSaIcE` the reference renders
/// `…(char const*, std::allocator<char> const&)`, losing the second
/// `char const*`; `c++filt` (the ABI ground truth, see
/// `examples/cxxfilt_compare.rs`) keeps both. Free-function shapes with the
/// same `T_S2_` sequence (`_Z3fooIPKcEvT_S2_`) are rendered correctly, so
/// the repair is gated on the exact defective shape: an `Ss` constructor
/// whose parameters start `T_S2_`. In that context `S2_` resolves to the
/// same type as `T_`, so the fix duplicates the first rendered parameter.
/// Idempotent: once upstream renders the duplicate, the repair no-ops.
#[must_use]
pub fn repair_ss_ctor_dropped_param(mangled: &str, rendered: &str) -> String {
    if !(mangled.starts_with("_ZNSsC") && mangled.contains("EET_S2_")) {
        return rendered.to_owned();
    }
    // The parameter list is the parenthesised group closing at the end of
    // the rendered string; find its `(` by depth-counting backwards, so a
    // first parameter that itself contains parentheses cannot mislead us.
    let bytes = rendered.as_bytes();
    if bytes.last() != Some(&b')') {
        return rendered.to_owned();
    }
    let mut depth = 0i32;
    let mut open = None;
    for (i, &b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(open) = open else {
        return rendered.to_owned();
    };
    let inner = &rendered[open + 1..rendered.len() - 1];
    // First top-level parameter (depth-aware comma split).
    let mut d = 0i32;
    let mut first_end = inner.len();
    for (i, c) in inner.char_indices() {
        match c {
            '(' | '<' | '[' => d += 1,
            ')' | '>' | ']' => d -= 1,
            ',' if d == 0 => {
                first_end = i;
                break;
            }
            _ => {}
        }
    }
    let first = inner[..first_end].trim();
    if first.is_empty() {
        return rendered.to_owned();
    }
    // Already repaired (or fixed upstream): the duplicate is present.
    let rest = inner[first_end..].trim_start_matches(',').trim_start();
    if rest.starts_with(first)
        && rest[first.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == ',')
    {
        return rendered.to_owned();
    }
    format!(
        "{}({first}, {inner})",
        &rendered[..open]
    )
}

/// Convert `cpp_demangle`'s `{vtable(T)}` / `{vtt(T)}` / `{typeinfo(T)}` /
/// `{typeinfo name(T)}` rendering into the canonical Itanium-ABI wording
/// (`vtable for T`, `VTT for T`, `typeinfo for T`, `typeinfo name for T`)
/// that downstream tools and the validator suite expect.
///
/// Also applies [`repair_misplaced_qualifier`] on every path, so all public
/// Itanium entry points share the fix.
pub fn normalize_itanium_special(raw: &str) -> String {
    let s = raw.trim();
    // Match `{<kind>(<inner>)}` with balanced parens for `<inner>`.
    if let Some(body) = s.strip_prefix('{').and_then(|t| t.strip_suffix('}'))
        && let Some(open) = body.find('(')
        && body.ends_with(')')
    {
        let kind = body[..open].trim();
        let inner = &body[open + 1..body.len() - 1];
        let label = match kind {
            "vtable" => Some("vtable for"),
            "vtt" | "VTT" => Some("VTT for"),
            "typeinfo" => Some("typeinfo for"),
            "typeinfo name" => Some("typeinfo name for"),
            "construction vtable" => Some("construction vtable for"),
            _ => None,
        };
        if let Some(lbl) = label {
            return repair_misplaced_qualifier(&format!("{lbl} {inner}"));
        }
    }
    repair_misplaced_qualifier(raw)
}

/// Best-effort decomposition of a demangled Itanium symbol string.
/// Returns `(namespace, class, function, args, return_type)`.
/// Split a qualified name on `::` occurring outside brackets.
///
/// Shared by the Itanium and Rust decompositions, which both need this rule and
/// previously each had their own copy — the Rust one bracket-aware, the Itanium
/// one a naive `split("::")`. Only the *split* is shared: the callers differ in
/// what they do afterwards (Rust trims each part and drops a trailing turbofish
/// group; Itanium does neither), so consolidating the post-processing too would
/// change behaviour rather than dedupe it.
///
/// Two subtleties, both of which were live defects:
///
/// * `->` is a token, not a closing bracket. Decrementing on its `>` drove the
///   depth negative on any rendering containing a function type.
/// * depth is clamped at zero, so one unbalanced closer — `operator>`, a stray
///   `>` — degrades locally instead of disabling every later split.
///
/// `sep` is the scope separator: `::` for Itanium and Rust, `.` for Swift.
fn split_scope_at_depth_zero<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    let bytes = s.as_bytes();
    let sep = sep.as_bytes();
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0usize);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' if i > 0 && bytes[i - 1] == b'-' => {}
            b'>' | b')' | b']' => depth = (depth - 1).max(0),
            _ if depth == 0 && bytes[i..].starts_with(sep) => {
                out.push(&s[start..i]);
                i += sep.len();
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start..]);
    out
}

/// Split an argument list on commas occurring outside brackets.
///
/// The MSVC decomposition used a plain `split(',')`, so a single templated
/// parameter became several: `f(std::pair<int,int>)` reported two arguments,
/// `std::pair<int` and `int>`. That is a **phantom parameter** — an arity error
/// that the rendered string does not show and that no type check can catch. The
/// Itanium decomposition had always split at depth zero; this is the shared
/// rule, so the two cannot drift apart again.
pub fn split_args_at_depth_zero(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let (mut out, mut depth, mut start) = (Vec::new(), 0i32, 0usize);
    let mut push = |from: usize, to: usize| {
        let t = s[from..to].trim();
        if !t.is_empty() {
            out.push(t.to_owned());
        }
    };
    for i in 0..bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' if i > 0 && bytes[i - 1] == b'-' => {}
            b'>' | b')' | b']' => depth = (depth - 1).max(0),
            b',' if depth == 0 => {
                push(start, i);
                start = i + 1;
            }
            _ => {}
        }
    }
    push(start, bytes.len());
    out
}

/// Does `haystack` contain `needle` as a **whole identifier**?
///
/// `haystack.contains(needle)` is the wrong test, and was the original one. A
/// short local name occurs incidentally inside the enclosing rendering, so the
/// guard passed vacuously and the collision it exists to catch survived:
///
/// ```text
/// $s4main5outeryyF1aL_yyF  =>  main.outer() -> ()   (same as the enclosing fn)
/// ```
///
/// `"main.outer() -> ()"` contains `a`, `n`, `u`, `t`, `e`, `r`, `ou` and `ute`
/// as substrings, so every local name spelled from those letters escaped the
/// check while `inside` and `helper` were caught — the guard worked only for
/// names long enough to be unlucky. Matching on identifier boundaries fixes it
/// and invents nothing: a rendered component is delimited by characters that
/// cannot occur in a Swift identifier.
fn contains_identifier(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| tok == needle)
}

/// The name of a Swift identifier that did not reach the rendering.
///
/// A local declaration is mangled as a length-prefixed identifier immediately
/// followed by `L`. The length prefix fixes where the identifier ends, so an `L`
/// in that position is an operator and never part of the name.
///
/// Defined over the **input**, like `tests/go_completeness.rs`, rather than over
/// parser state: what matters is that a name present in the symbol is absent from
/// the output, wherever the parser happened to stop. Returns `None` when the name
/// did reach the output, so a future implementation of local entities silently
/// turns this check off instead of having to be removed.
///
/// # Why the `L` cannot be dropped
///
/// Widening this to *any* dropped length-prefixed identifier looks right — it
/// also rejects `$s4main4Beta5gammayyF` (three bare identifiers, malformed: a
/// nested entity's parent carries a kind marker) and `$s4main2añ3baryyF` (a cut
/// prefix, which then swallows `bar` too). Both were tried, twice.
///
/// It breaks `$sSS7countedSiSo7NSArrayCF` => `Swift.String.counted`. `NSArray`
/// is a length-prefixed identifier in **signature** position, and the renderer
/// drops signatures — that is the loss the measured Swift trailing-input
/// exemption exists to permit (`tests/trailing_input.rs`: full consumption would
/// decline 7 of 16 realistic symbols).
///
/// So a bare identifier is ambiguous: in path position its absence is lost
/// **identity**, in type position merely lost **detail**. Only the first is a
/// defect, and an input-only rule cannot tell them apart. `L` can, because it
/// marks a path component. Distinguishing the rest needs parser state, not a
/// wider string scan.
///
/// An earlier attempt blamed the non-ASCII character in the control instead;
/// that was wrong. Non-ASCII identifiers decode in every valid position —
/// `$s3añ3fooyyF`, `$s4main3añyyF`, `$s4main3añC3baryyF`, `$s4main3FooC3añyyF`.
fn dropped_swift_local_name(mangled: &str, demangled: &str) -> Option<String> {
    let bytes = mangled.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let Ok(len) = mangled[start..i].parse::<usize>() else {
            continue;
        };
        // A zero-length identifier is not a name; `?module`-style declines
        // already cover those.
        //
        // `i + len` must be CHECKED, not plain: `len` comes from the symbol, so a
        // prefix at `usize::MAX` makes the sum overflow.
        // `$s4main5outeryyF18446744073709551615aL_yyF` decodes far enough to reach
        // here and then panicked with "attempt to add with overflow" — reachable
        // on attacker-controlled input, and invisible to the release gates because
        // overflow checks are compiled out there.
        let Some(end) = i.checked_add(len) else {
            continue;
        };
        if len == 0 || end >= bytes.len() {
            continue;
        }
        // `len` is a BYTE length, so the slice can land inside a multibyte
        // character — `$s2añ…` panicked here until `get` replaced indexing.
        // A prefix that does not fall on a char boundary is malformed anyway.
        let Some(name) = mangled.get(i..end) else {
            continue;
        };
        if bytes[end] == b'L' && !contains_identifier(demangled, name) {
            return Some(name.to_owned());
        }
        i += len;
    }
    None
}

/// Index of the first `(` that starts a Swift signature — i.e. one not nested
/// inside generic arguments. `MyApp.Foo<(Swift.Int) -> ()>.bar` has its first
/// `(` inside `<…>`, so truncating at that byte lost the whole path after it.
fn swift_signature_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            // The `>` of `->` is part of a token, not a closing bracket.
            b'>' if i > 0 && bytes[i - 1] == b'-' => {}
            b'>' => depth = (depth - 1).max(0),
            b'(' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

pub fn split_itanium_components(
    demangled: &str,
) -> (
    Option<String>,
    Option<String>,
    String,
    Vec<String>,
    Option<String>,
) {
    // Locate the argument list – the last balanced `(...)` pair.
    let args_str;
    let qualified_name;
    let return_type;

    // Find the outermost top-level `(...)` pair by scanning from the end
    // with balanced-paren tracking, so nested parens (e.g. function-pointer
    // arguments like `f(int (*)(int))`) are handled correctly.
    let outer_parens = {
        let bytes = demangled.as_bytes();
        let mut depth: i32 = 0;
        let mut close_idx: Option<usize> = None;
        let mut open_idx: Option<usize> = None;
        for (i, &b) in bytes.iter().enumerate().rev() {
            match b {
                b')' => {
                    if depth == 0 {
                        close_idx = Some(i);
                    }
                    depth += 1;
                }
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        open_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        // An argument list sits at the *end* of the rendering, optionally
        // followed by cv/ref qualifiers. A balanced `(...)` anywhere else
        // belongs to the name, and treating it as arguments erased the name:
        // `(anonymous namespace)::__new_handler` — a variable with no argument
        // list at all — reported `function: ""` on 4 real corpus symbols,
        // because everything before the parens was taken as the return type and
        // everything after was discarded.
        let trailing_ok = close_idx.is_some_and(|c| {
            let tail = demangled[c + 1..].trim();
            tail.is_empty()
                || ["const", "volatile", "&", "&&", "noexcept", "const&", "const&&"]
                    .iter()
                    .any(|q| tail == *q || tail.starts_with(&format!("{q} ")))
        });
        if trailing_ok {
            open_idx.zip(close_idx)
        } else {
            None
        }
    };

    if let Some((paren_open, paren_close)) = outer_parens {
        let before_paren = &demangled[..paren_open];
        let args_part = &demangled[paren_open + 1..paren_close];
        // Shared with the MSVC decomposition, which used a naive `split(',')`.
        args_str = split_args_at_depth_zero(args_part);

        // Strip leading return type (present for free functions in some styles).
        let (ret, qname) = split_return_type(before_paren);
        return_type = ret;
        qualified_name = qname;
    } else {
        args_str = Vec::new();
        qualified_name = demangled.to_owned();
        return_type = None;
    }

    // Split `qualified_name` by `::` **at bracket depth zero**.
    //
    // A naive `split("::")` cut inside template arguments, so every templated
    // name was shredded:
    //   bool __gnu_cxx::operator==<char const*, std::string>(…)
    //     => class "operator==<char const*, std", function "string>"
    // A component holding a stray `>` and half a qualified type is wrong on
    // inspection, no oracle required. Measured over `real_symbols.txt`: 435
    // unbalanced components across 297 templated renderings.
    //
    // `split_rust_components` already split this way; this is the crate's
    // recurring shape — one rule, two copies, only one of them updated.
    let parts: Vec<&str> = split_scope_at_depth_zero(&qualified_name, "::");
    let function = parts.last().copied().unwrap_or("").to_owned();
    let (namespace, class) = match parts.len() {
        0 | 1 => (None, None),
        2 => (None, Some(parts[0].to_owned())),
        n => {
            let ns = parts[..n - 2].join("::");
            let cls = parts[n - 2].to_owned();
            (Some(ns), Some(cls))
        }
    };

    (namespace, class, function, args_str, return_type)
}

/// Attempt to split a leading return type from the qualified name portion.
fn split_return_type(s: &str) -> (Option<String>, String) {
    // Common C++ type keywords that indicate a return type prefix.
    let type_prefixes = [
        "void", "int", "bool", "char", "long", "short", "float", "double", "unsigned", "signed",
        "const", "static", "inline", "virtual", "explicit", "auto", "decltype", "noexcept",
        "size_t", "uint", "int8_t", "uint8_t", "int16_t", "int32_t", "int64_t",
    ];
    for prefix in &type_prefixes {
        if let Some(stripped) = s.strip_prefix(prefix) {
            let rest = stripped.trim_start();
            // Make sure the rest looks like a qualified name (starts with a letter or `_`).
            if rest.starts_with(|c: char| c.is_alphabetic() || c == '_' || c == ':') {
                return (
                    Some((*prefix).to_owned()),
                    strip_calling_convention(rest).to_owned(),
                );
            }
        }
    }
    (None, strip_calling_convention(s).to_owned())
}

/// Strip a leading MSVC calling-convention keyword (`__cdecl`, `__stdcall`, …)
/// from a demangled name fragment, returning the remainder.
fn strip_calling_convention(s: &str) -> &str {
    const CONVENTIONS: [&str; 7] = [
        "__cdecl",
        "__pascal",
        "__thiscall",
        "__stdcall",
        "__fastcall",
        "__vectorcall",
        "__clrcall",
    ];
    for cc in CONVENTIONS {
        if let Some(rest) = s.strip_prefix(cc) {
            return rest.trim_start();
        }
    }
    s
}

// ── MSVC demangler (manual parser) ───────────────────────────────────────────

/// Demangler for MSVC-mangled names (`?` prefix).
pub struct MsvcDemangler;

impl Demangler for MsvcDemangler {
    fn detect(&self, mangled: &str) -> bool {
        mangled.starts_with('?')
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if !self.detect(mangled) {
            return None;
        }
        let demangled = demangle_msvc_internal(mangled)?;
        let (namespace, class, function, args, return_type) = split_msvc_components(&demangled);
        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled,
            abi: ManglingAbi::Msvc,
            namespace,
            class,
            function,
            args,
            return_type,
        })
    }
}

fn split_msvc_components(
    demangled: &str,
) -> (
    Option<String>,
    Option<String>,
    String,
    Vec<String>,
    Option<String>,
) {
    // Strip any trailing "const" / "volatile" qualifiers after `)`.
    let base = demangled.rfind(')').map_or(demangled, |p| &demangled[..=p]);

    let args_str;
    let rest;

    // Find the outermost argument list using a balanced-paren scan (right-to-left).
    // rfind('(') would incorrectly match inner parens in types like `void(*)(int)`.
    let outer_paren_open = {
        let bytes = base.as_bytes();
        let mut depth = 0i32;
        let mut found = None;
        for i in (0..bytes.len()).rev() {
            match bytes[i] {
                b')' => depth += 1,
                b'(' => {
                    depth -= 1;
                    if depth == 0 {
                        found = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        found
    };
    if let Some(paren_open) = outer_paren_open {
        let paren_close = base.rfind(')').unwrap_or(base.len());
        let args_part = if paren_close > paren_open { &base[paren_open + 1..paren_close] } else { "" };
        // Depth-aware: a plain `split(',')` turned one templated parameter into
        // several. See `split_args_at_depth_zero`.
        let split: Vec<String> = split_args_at_depth_zero(args_part);
        // `f(void)` takes no parameters — the C spelling for an empty list,
        // which MSVC mangles as `X`. Leaving `["void"]` in `args` handed a
        // caller a one-parameter signature for a function that has none: a
        // phantom parameter, the shape that compiles cleanly and is silently
        // wrong. The rendered string already prints `(void)`; only the
        // structured field needs to say zero. The Itanium path (`v`) has
        // always reported an empty list here.
        args_str = if split.len() == 1 && split[0] == "void" {
            Vec::new()
        } else {
            split
        };
        rest = base[..paren_open].to_owned();
    } else {
        args_str = Vec::new();
        rest = base.to_owned();
    }

    let (return_type, qualified) = split_return_type(rest.trim());
    // Depth-aware, like the Itanium, Rust and Swift decompositions: a naive
    // `split("::")` cut inside template arguments, so `std::vector<std::pair<
    // int, int> >::push_back` reported the class as a fragment of the type
    // arguments. This was the fourth and last copy of that rule.
    let parts: Vec<&str> = split_scope_at_depth_zero(&qualified, "::");
    // In an MSVC rendering the entity name is the last whitespace-separated
    // token: `int* g` is the variable `g`, not a variable called `int* g`.
    // `split_return_type` separates the simple cases (`int x`) but not ones
    // whose type ends in punctuation or is itself a qualified name, so
    // `?g@@3PAHA` reported `function: "int* g"` and
    // `?__type_info_root_node@@3U__type_info_node@@A` reported the whole
    // rendering.
    //
    // MSVC's special names are backtick-quoted and *contain* spaces
    // (`` `vector deleting destructor' ``), so for those the entity starts at
    // the backtick and runs to the end. Taking the last token there would
    // leave `destructor'`.
    let last = parts.last().copied().unwrap_or("");
    let function = last.find('`').map_or_else(
        || {
            last.rsplit(char::is_whitespace)
                .next()
                .unwrap_or("")
                .to_owned()
        },
        |i| last[i..].to_owned(),
    );
    // The SAME rule the entity name uses, applied to the first scope component.
    // Only `function` was normalised, so the access specifier, return type and
    // calling convention stayed glued to the leading scope:
    //
    //   ?bar@Foo@@QAEXXZ    class     = "public: void __thiscall Foo"
    //   ?bar@Foo@Ns@@QAEXXZ namespace = "public: void __thiscall Ns"
    //
    // Every MSVC member function had a garbage `class`, and consumers route on
    // these fields — the decompiler names variables from them.
    let entity = |part: &str| -> String {
        part.find('`').map_or_else(
            || {
                part.rsplit(char::is_whitespace)
                    .next()
                    .unwrap_or("")
                    .to_owned()
            },
            |i| part[i..].to_owned(),
        )
    };
    let (namespace, class) = match parts.len() {
        0 | 1 => (None, None),
        2 => (None, Some(entity(parts[0]))),
        n => {
            let mut scopes: Vec<String> = parts[..n - 1].iter().map(|p| (*p).to_owned()).collect();
            if let Some(first) = scopes.first_mut() {
                *first = entity(first);
            }
            let cls = scopes.pop().unwrap_or_default();
            (Some(scopes.join("::")), Some(cls))
        }
    };

    (namespace, class, function, args_str, return_type)
}

// ── Internal MSVC parser ──────────────────────────────────────────────────────

struct MsvcParser<'a> {
    input: &'a [u8],
    pos: usize,
    type_backrefs: Vec<String>,
    name_backrefs: Vec<String>,
    /// Recursion depth through `parse_msvc_type`.
    ///
    /// This parser was the only one in the crate with **no** recursion limit —
    /// `cpp_demangler` has `MAX_DEPTH`, `d_demangler` has `enter()`/`leave()`,
    /// `swift_demangler` tracks `depth`. So `?foo@@YAX` + `PEA` x 4096 + `H@Z`
    /// recursed until the thread **overflowed its stack**, which `catch_unwind`
    /// cannot rescue: a crafted symbol crashed the process outright.
    depth: usize,
}

impl<'a> MsvcParser<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
            type_backrefs: Vec::new(),
            name_backrefs: Vec::new(),
            depth: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).map(|&b| b as char)
    }

    /// Peek `n` bytes past the cursor without consuming.
    fn peek_at(&self, n: usize) -> Option<char> {
        self.input.get(self.pos + n).map(|&b| b as char)
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn consume(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn consume_str(&mut self, s: &str) -> bool {
        let b = s.as_bytes();
        if self.pos + b.len() <= self.input.len() && &self.input[self.pos..self.pos + b.len()] == b
        {
            self.pos += b.len();
            true
        } else {
            false
        }
    }
}

/// Parse a function-local scope component, `<N>?<enclosing symbol>@`.
///
/// The caller has consumed the `?` that introduces it, so the cursor sits on
/// the scope index. Renders as `` `enclosing'::`N+1' ``, matching `undname`,
/// which reports the index one higher than encoded.
///
/// Appears in symbols for `static`s declared inside a function, e.g.
/// `?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA`.
fn parse_msvc_local_scope(p: &mut MsvcParser) -> Option<String> {
    let idx = p.next()?.to_digit(10)?;
    if !p.consume('?') {
        return None;
    }
    // The enclosing symbol is itself fully mangled and carries its own leading
    // `?`. Consume it: `parse_msvc_qualified_name` starts after that byte and
    // would otherwise read it as an operator code, turning
    // `__local_stdio_printf_options` into `operator_unknown__`.
    p.consume('?');
    let inner = parse_msvc_qualified_name(p)?;
    if inner.is_empty() {
        return None;
    }
    // What follows is the enclosing symbol's own encoding (function class,
    // calling convention, return type, parameters), which is not part of the
    // scope name; skip it and the `@` that closes the scope.
    //
    // This skipped to the first `@`, which is only correct when the enclosing
    // function takes NO parameters. A parameter list is terminated by `@Z`, and
    // a class-typed parameter carries `@`s of its own, so the first `@` lands
    // in the middle of the encoding and everything after is misread:
    //
    //   ?x@?1??f@@YAXXZ@4HA    decoded    (`YAXXZ` happens to contain no `@`)
    //   ?x@?1??f@@YAXH@Z@4HA   DECLINED   (stopped inside `H@Z`)
    //
    // The boundary is the `@` that closes the scope, recognisable by what
    // precedes it. A function's encoding ends in `Z` (`@Z` after a parameter
    // list, `XZ` for `void`); the corpus's own symbols end in the no-signature
    // marker `9` (`?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA`).
    // Every `@` *inside* a parameter list is preceded by a type character.
    //
    // Both terminators matter: keying only on `Z@` fixes the parameterised case
    // and breaks the two real corpus symbols, which contain no `Z` at all —
    // caught immediately by the tests a concurrent agent had already written
    // for them.
    //
    // Not watertight — a class fragment literally named `Z` or `9` immediately
    // before an `@` would still cut early — but that is far rarer than "the
    // enclosing function has parameters", and it declines rather than decoding
    // wrongly.
    // Parse the enclosing signature rather than skipping it, so the enclosing
    // OVERLOAD is named: `f(void)::x` and `f(int)::x` are different symbols and
    // `msvc-demangler` renders them differently.
    //
    // `_partial` because a standalone symbol must be consumed entirely but this
    // one is followed by the variable's own storage class.
    let bare = inner.join("::");
    let save = p.pos;
    let enclosing = if let Some(sig) = parse_msvc_function_or_data_tail_partial(p, &bare) {
        // The signature parsed; the cursor now sits on the `@` that closes the
        // scope, so consume exactly that and nothing else.
        p.consume('@');
        sig
    } else {
        // Not a function tail — the corpus's own symbols carry the no-signature
        // marker `9`. Rewind and skip to the boundary, which is the `@` preceded
        // by `Z` (a parameter list, or `void`) or by `9`. Every `@` *inside* a
        // parameter list is preceded by a type character instead.
        p.pos = save;
        let mut prev = '\0';
        while let Some(c) = p.next() {
            if (prev == 'Z' || prev == '9') && c == '@' {
                break;
            }
            prev = c;
        }
        bare
    };
    // Historical note, kept because the shape recurs: the enclosing signature
    // used to be skipped entirely, so every overload of `f` was the same scope —
    //
    //   ?x@?1??f@@YAXXZ@4HA           `f'::`2'::x
    //   ?x@?1??f@@YAXH@Z@4HA          `f'::`2'::x
    //   ?x@?1??f@@YAXPAVFoo@@@Z@4HA   `f'::`2'::x
    //
    // where `msvc-demangler` names `void __cdecl f(int)` and so on. Before the
    // boundary fix above, two of those three declined outright, so the
    // collision is newly *visible*, not newly introduced.
    //
    // and the remedy needed `parse_msvc_function_or_data_tail` to stop requiring
    // full input consumption — which it does for a standalone symbol, correctly,
    // since the trailing-input fix. Hence the `_partial` split.
    Some(format!("`{enclosing}'::`{}'", idx + 1))
}

/// Anonymous namespace: `?A@` (older) or `?A0x<hex>@` (what MSVC emits today).
///
/// `undname` renders it `` `anonymous namespace' ``; the `0x<hex>` discriminator
/// identifies *which* anonymous namespace and is not printed, so it is consumed and
/// dropped.
///
/// Without this the `A` fell through to operator decoding and
/// `?f@?A0x12345678@@YAXXZ` came out as `x12345678::f::operator[]::f(void)` — an
/// `operator[]` invented from nothing, the hex tag turned into a namespace, and the
/// function name emitted twice. Confidently wrong structure, which this crate treats
/// as worse than declining.
///
/// Returns `None` without consuming anything when the input is not this form, so the
/// caller can fall through to the other `?`-prefixed cases.
fn parse_msvc_anonymous_namespace(p: &mut MsvcParser) -> Option<String> {
    if p.peek() != Some('A')
        || !(p.peek_at(1) == Some('@') || (p.peek_at(1) == Some('0') && p.peek_at(2) == Some('x')))
    {
        return None;
    }
    p.next(); // 'A'
    if p.consume('0') && p.consume('x') {
        while p.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            p.next();
        }
    }
    if !p.consume('@') {
        return None;
    }
    let name = "`anonymous namespace'".to_owned();
    // Registers a name back-reference like every other component, so a later
    // digit can refer to it.
    if p.name_backrefs.len() < 10 {
        p.name_backrefs.push(name.clone());
    }
    Some(name)
}

fn parse_msvc_qualified_name(p: &mut MsvcParser) -> Option<Vec<String>> {
    let mut components = Vec::new();
    loop {
        match p.peek() {
            None => break,
            Some('@') => {
                p.next();
                break;
            }
            Some(c) if c.is_ascii_digit() => {
                p.next();
                let idx = c as usize - '0' as usize;
                if idx < p.name_backrefs.len() {
                    components.push(p.name_backrefs[idx].clone());
                } else {
                    return None;
                }
                // A backref digit replaces an entire `name@` fragment, so no
                // `@` follows it: the next `@` (if any) is the list
                // terminator and must be left for the loop to see, or the
                // bytes after it (e.g. the parameter list in `…PEAV1@XZ`)
                // get swallowed into the qualified name.
            }
            Some('?') => {
                p.next();
                // Function-local scope: `?<N>?<enclosing symbol>@`, as in
                // `?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA`
                // — a `static` declared inside a function. `undname` renders
                // the scope as `` `enclosing'::`N+1' ``, so the whole symbol
                // reads
                // ``unsigned __int64 `__local_stdio_printf_options'::`2'::_OptionsStorage``.
                //
                // Must be tested before the operator decoding below, which
                // would otherwise read the `1` of `?1?` as a destructor.
                if p.peek().is_some_and(|c| c.is_ascii_digit()) && p.peek_at(1) == Some('?') {
                    components.push(parse_msvc_local_scope(p)?);
                    // A local scope is necessarily the outermost one, and the
                    // `@` closing it also terminates the name list. Continuing
                    // the loop would read the storage-class byte that follows
                    // (`4`) as a name-backreference index.
                    break;
                }
                if let Some(name) = parse_msvc_anonymous_namespace(p) {
                    components.push(name);
                    continue;
                }
                // Template name: `?$<name>@<type-args>@`, e.g. the
                // `?$vector@H@` inside `V?$vector@H@std@@` or the whole name
                // of `??$max@H@@YAHHH@Z`. Rendered as `name<args>`.
                if p.consume('$') {
                    let mut name = String::new();
                    while let Some(c) = p.peek() {
                        if c == '@' {
                            break;
                        }
                        name.push(p.next()?);
                    }
                    if name.is_empty() || !p.consume('@') {
                        return None;
                    }
                    let mut args = Vec::new();
                    loop {
                        if p.consume('@') {
                            break;
                        }
                        p.peek()?;
                        // Non-type argument: `$0<encoded-number>` (integer).
                        //
                        // A `$$`-prefixed *type* also starts with `$`, so peek at the
                        // second byte instead of committing. `??$h@$$CBH@@YAXXZ`
                        // (`h<int const>`) declined because this branch consumed the
                        // first `$`, demanded a `0`, and found the second `$`.
                        if p.peek() == Some('$') && p.peek_at(1) == Some('0') {
                            p.next();
                            p.next();
                            args.push(parse_msvc_number(p)?.to_string());
                            continue;
                        }
                        args.push(parse_msvc_type(p)?);
                    }
                    let full = format!("{name}<{}>", args.join(", "));
                    if p.name_backrefs.len() < 10 {
                        p.name_backrefs.push(full.clone());
                    }
                    components.push(full);
                    continue;
                }
                let op = p.next()?;
                let op_name = msvc_operator_name(p, op)?;
                components.push(op_name);
                // If a `@` follows immediately, the operator had no enclosing
                // class (e.g. `??3@YA...`). One `@` terminates the qualified
                // name list and the storage class / function type follows.
                if p.consume('@') {
                    break;
                }
            }
            _ => {
                let mut name = String::new();
                while let Some(c) = p.peek() {
                    if c == '@' {
                        break;
                    }
                    name.push(p.next()?);
                }
                if name.is_empty() {
                    break;
                }
                if p.name_backrefs.len() < 10 {
                    p.name_backrefs.push(name.clone());
                }
                components.push(name);
                p.consume('@');
            }
        }
    }

    components.reverse();

    // Fix up ctor/dtor names.
    let len = components.len();
    if len >= 2 {
        if components[len - 1] == "ctor" {
            let src = components[len - 2].clone();
            components[len - 1] = src;
        } else if components[len - 1] == "dtor" {
            let base = components[len - 2].clone();
            components[len - 1] = format!("~{base}");
        }
    }

    Some(components)
}

/// `??_<code>` special names, shared by the operator path and the special-data path.
///
/// Both mapped these codes, and only the operator path had the full table: the data
/// path hardcoded four (`_7`, `_8`, `_E`, `_G`). So the fifteen entries added at iter
/// 97 worked in *function* shape (`??_HA@@QEAAXXZ`) and **declined** in data shape
/// (`??_HA@@8`, `??_HA@@6B@`) — measured at iter 100: of 120 shapes with ground truth,
/// 38 differed, every one a data-shaped special name.
///
/// One rule, two copies, only one complete — this crate's recurring shape, and the
/// reason this is now a single function rather than a table plus a hardcoded subset.
///
/// Strings taken verbatim from `msvc-demangler`.
const fn msvc_underscore_special_name(code: char) -> Option<&'static str> {
    Some(match code {
        '0' => "operator/=",
        '1' => "operator%=",
        '2' => "operator>>=",
        '3' => "operator<<=",
        '4' => "operator&=",
        '5' => "operator|=",
        '6' => "operator^=",
        // Table names, with no `operator` prefix.
        '7' => "`vftable'",
        '8' => "`vbtable'",
        '9' => "`vcall'",
        'A' => "`typeof'",
        'C' => "`string'",
        'D' => "`vbase destructor'",
        'E' => "`vector deleting destructor'",
        'F' => "`default constructor closure'",
        'G' => "`scalar deleting destructor'",
        'H' => "`vector constructor iterator'",
        'I' => "`vector destructor iterator'",
        'J' => "`vector vbase constructor iterator'",
        'K' => "`virtual displacement map'",
        'L' => "`eh vector constructor iterator'",
        'M' => "`eh vector destructor iterator'",
        'N' => "`eh vector vbase constructor iterator'",
        'O' => "`copy constructor closure'",
        'S' => "`local vftable'",
        'T' => "`local vftable constructor closure'",
        'U' => "operator new[]",
        'V' => "operator delete[]",
        'X' => "`placement delete closure'",
        'Y' => "`placement delete[] closure'",
        _ => return None,
    })
}

fn msvc_operator_name(p: &mut MsvcParser, first: char) -> Option<String> {
    match first {
        '0' => Some("ctor".to_owned()),
        '1' => Some("dtor".to_owned()),
        '2' => Some("operator new".to_owned()),
        '3' => Some("operator delete".to_owned()),
        '4' => Some("operator=".to_owned()),
        '5' => Some("operator>>".to_owned()),
        '6' => Some("operator<<".to_owned()),
        '7' => Some("operator!".to_owned()),
        '8' => Some("operator==".to_owned()),
        '9' => Some("operator!=".to_owned()),
        'A' => Some("operator[]".to_owned()),
        'B' => Some("operator conversion".to_owned()),
        'C' => Some("operator->".to_owned()),
        'D' => Some("operator*".to_owned()),
        'E' => Some("operator++".to_owned()),
        'F' => Some("operator--".to_owned()),
        'G' => Some("operator-".to_owned()),
        'H' => Some("operator+".to_owned()),
        'I' => Some("operator&".to_owned()),
        'J' => Some("operator->*".to_owned()),
        'K' => Some("operator/".to_owned()),
        'L' => Some("operator%".to_owned()),
        'M' => Some("operator<".to_owned()),
        'N' => Some("operator<=".to_owned()),
        'O' => Some("operator>".to_owned()),
        'P' => Some("operator>=".to_owned()),
        'Q' => Some("operator,".to_owned()),
        'R' => Some("operator()".to_owned()),
        'S' => Some("operator~".to_owned()),
        'T' => Some("operator^".to_owned()),
        'U' => Some("operator|".to_owned()),
        'V' => Some("operator&&".to_owned()),
        'W' => Some("operator||".to_owned()),
        'X' => Some("operator*=".to_owned()),
        'Y' => Some("operator+=".to_owned()),
        'Z' => Some("operator-=".to_owned()),
        '_' => {
            let c = p.next()?;
            // `??__E<name>` / `??__F<name>`: the compiler-generated initialiser and
            // atexit destructor for a namespace-scope object. The `<name>` that
            // follows is the OBJECT, not a class.
            if c == '_' {
                return match p.next()? {
                    'E' => Some("`dynamic initializer'".to_owned()),
                    'F' => Some("`dynamic atexit destructor'".to_owned()),
                    _ => None,
                };
            }
            // No fallback marker. `??_B`, `??_P`, `??_Q`, `??_W` and `??_Z` have no
            // entry and no ground truth — `msvc-demangler` rejects every spelling
            // tried at iter 97 — but they were still rendering
            // `operator_unknown_<code>`, which names nothing and reaches callers as if
            // it were the function's name.
            //
            // An oracle with no opinion does not license emitting a marker: declining
            // is this crate's standing answer for a construct it cannot read. Found by
            // applying the Go anti-invention guard (iter 64) to MSVC, which is where
            // 23 fabrications had already been fixed — these five survived because
            // they are not reachable from the corpus and the oracle could not
            // contradict them.
            msvc_underscore_special_name(c).map(str::to_owned)
        }
        // Same rule for a bare `??<code>` with no table entry.
        _ => None,
    }
}

/// Decode an MSVC-encoded number: `?` prefixes a negative value; a single
/// digit `0`-`9` encodes 1-10; otherwise hex digits written as `A`-`P`
/// (= 0-15) terminated by `@`, so `$0L@` is 11 and `$0BAA@` is 256.
fn parse_msvc_number(p: &mut MsvcParser) -> Option<i64> {
    let negative = p.consume('?');
    let c = p.next()?;
    let value = if c.is_ascii_digit() {
        i64::from(c as u8 - b'0') + 1
    } else {
        let mut v: i64 = 0;
        let mut d = c;
        loop {
            if !d.is_ascii_uppercase() || d > 'P' {
                return None;
            }
            v = v.checked_mul(16)?.checked_add(i64::from(d as u8 - b'A'))?;
            d = p.next()?;
            if d == '@' {
                break;
            }
        }
        v
    };
    Some(if negative { -value } else { value })
}

/// Parse the referent of an MSVC rvalue reference, the `$$Q` prefix already
/// consumed, and render `<type>&&`.
///
/// Like a pointer, the referent carries an optional `__ptr64`/`__ptr32` marker
/// (`E`/`F`) before its cv byte: `$$QEAH` is `E` (ptr64) + `A` (no cv) + `H`
/// (int) = `int&&`. Consuming only one byte after `$$Q` mis-read `EAH` as `E`
/// then a stray `A` reference and declined the whole symbol.
fn parse_msvc_rvalue_ref(p: &mut MsvcParser) -> Option<String> {
    if matches!(p.peek(), Some('E' | 'F')) {
        p.next();
    }
    let _cv = p.next()?;
    let inner = parse_msvc_type(p)?;
    Some(format!("{inner}&&"))
}

/// Parse an MSVC function-pointer type (`<ptr>6<cc><return><params>@Z`), the
/// pointer sigil already consumed, rendering `<ret> (<cc> *)(<params>)`.
///
/// The `6` marks a function type; the byte after it is the calling convention,
/// then the return type, then the parameter list terminated by `@Z`/`Z`
/// (`X`/void when empty). `?f@@YAXP6AHH@Z@Z` is
/// `void __cdecl f(int (__cdecl *)(int))`.
fn parse_msvc_function_pointer(p: &mut MsvcParser, ptr_sigil: char) -> Option<String> {
    p.next()?; // the `6`
    let cc = crate::msvc_extras::msvc_calling_convention(p.next()? as u8);
    let ret = parse_msvc_type(p)?;
    let mut params = Vec::new();
    loop {
        if p.consume_str("@Z") || p.consume('Z') {
            break;
        }
        if p.peek().is_none() {
            break;
        }
        match parse_msvc_type(p) {
            Some(t) => params.push(t),
            None => return None,
        }
    }
    let params_str = if params.is_empty() || (params.len() == 1 && params[0] == "void") {
        "void".to_owned()
    } else {
        params.join(", ")
    };
    let star = match ptr_sigil {
        'Q' => "* const",
        'R' => "* volatile",
        'S' => "* const volatile",
        _ => "*",
    };
    let result = format!("{ret} ({} {star})({params_str})", cc.as_str());
    if p.type_backrefs.len() < 10 {
        p.type_backrefs.push(result.clone());
    }
    Some(result)
}

/// The `$$` type family, the prefix not yet consumed.
///
/// `$$Q` (rvalue reference) is handled by its own parser before this is reached; the
/// rest declined until iter 94, honestly but uselessly — they are ordinary in
/// templated code and the oracle has ground truth for all of them.
///
/// | encoding | means |
/// |---|---|
/// | `$$T` | `std::nullptr_t` |
/// | `$$A<cc>…@Z` | a function **type**, not a pointer to one |
/// | `$$B<array>` | an array type |
/// | `$$C<cv><type>` | a type carrying cv qualifiers |
fn parse_msvc_dollar_dollar_type(p: &mut MsvcParser) -> Option<String> {
    if !p.consume_str("$$") {
        return None;
    }
    match p.next()? {
        'T' => Some("std::nullptr_t".to_owned()),
        'A' => parse_msvc_bare_function_type(p),
        // The payload is the same `Y<ndims><dims><elem>` an array pointer uses,
        // rendered without the `(*)`.
        'B' => parse_msvc_pointer_to_array(p, 'P').map(|arr| arr.replace(" (*)", "")),
        'C' => {
            let cv = p.next()?;
            let inner = parse_msvc_type(p)?;
            Some(match cv {
                'A' => inner,
                'B' => format!("{inner} const"),
                'C' => format!("{inner} volatile"),
                'D' => format!("{inner} const volatile"),
                // An unrecognised cv byte is not a qualifier; declining beats
                // guessing which one was meant.
                _ => return None,
            })
        }
        _ => None,
    }
}

/// Parse the signature after `$$A`: a bare function *type*.
///
/// `$$A6AXXZ` is `void __cdecl (void)`. The payload is the same `6<cc><ret><params>`
/// a `P6` pointer wraps, but the rendering is not the pointer's with the `*` removed
/// — `undname` puts the calling convention *before* the parenthesised parameter list
/// here (`void __cdecl (void)`), where the pointer form puts it inside
/// (`void (__cdecl *)(void)`). Building it directly rather than by string surgery on
/// the pointer form; my first attempt did the latter and produced
/// `void (__cdecl)(void)`.
fn parse_msvc_bare_function_type(p: &mut MsvcParser) -> Option<String> {
    p.next()?; // the `6`
    let cc = crate::msvc_extras::msvc_calling_convention(p.next()? as u8);
    let ret = parse_msvc_type(p)?;
    let mut params = Vec::new();
    loop {
        if p.consume_str("@Z") || p.consume('Z') {
            break;
        }
        p.peek()?;
        params.push(parse_msvc_type(p)?);
    }
    let params_str = if params.is_empty() || (params.len() == 1 && params[0] == "void") {
        "void".to_owned()
    } else {
        params.join(", ")
    };
    Some(format!("{ret} {} ({params_str})", cc.as_str()))
}

/// Parse an MSVC **member** function pointer, the `8` not yet consumed.
///
/// Encoding: `P8<class>@<this-modifiers><cv><cc><return><params>@Z`. So
/// `P8A@@EAAXXZ` is a pointer to a `void (void)` member of `A`, which `undname`
/// renders `void (__cdecl A::*)(void)`.
///
/// Previously declined: `parse_msvc_pointer` handled `P6` (a plain function
/// pointer) but not `P8`, so the `8` was read as a cv byte and the whole symbol was
/// rejected. Member function pointers are ordinary in real C++, so this was the
/// largest remaining capability gap in the MSVC path — and a decline is honest, so
/// this is added capability rather than a fabrication fix.
///
/// The `this`-pointer modifiers are consumed and not rendered, matching what
/// `msvc-demangler` prints for this position; the `const` of a const member
/// function *is* rendered, after the parameter list.
fn parse_msvc_member_function_pointer(p: &mut MsvcParser, ptr_sigil: char) -> Option<String> {
    p.next()?; // the `8`
    let class = parse_msvc_qualified_name(p)?.join("::");
    if class.is_empty() {
        return None;
    }
    // `this`-pointer modifiers, then the cv byte. Same shape as
    // `parse_msvc_qualifiers`, and the same reason to consume all of them: leaving
    // one decodes the calling convention a byte out of alignment.
    while matches!(p.peek(), Some('E' | 'F' | 'I')) {
        p.next();
    }
    let cv = p.next()?;
    let cc = crate::msvc_extras::msvc_calling_convention(p.next()? as u8);
    let ret = parse_msvc_type(p)?;
    let mut params = Vec::new();
    loop {
        if p.consume_str("@Z") || p.consume('Z') {
            break;
        }
        p.peek()?;
        params.push(parse_msvc_type(p)?);
    }
    let params_str = if params.is_empty() || (params.len() == 1 && params[0] == "void") {
        "void".to_owned()
    } else {
        params.join(", ")
    };
    let star = match ptr_sigil {
        'Q' => "* const",
        'R' => "* volatile",
        'S' => "* const volatile",
        _ => "*",
    };
    let konst = if cv == 'B' || cv == 'D' { " const" } else { "" };
    let result = format!(
        "{ret} ({} {class}::{star})({params_str}){konst}",
        cc.as_str()
    );
    if p.type_backrefs.len() < 10 {
        p.type_backrefs.push(result.clone());
    }
    Some(result)
}

/// Whether a rendered type is one of MSVC's built-in primitives.
///
/// A primitive parameter occupies no back-reference slot. The encoding makes
/// this test exact rather than a heuristic: class, struct, union and enum names
/// arrive through `V`/`U`/`T`/`W` and are rendered qualified, so no user type
/// can collide with these spellings.
fn is_msvc_primitive(t: &str) -> bool {
    matches!(
        t,
        "void"
            | "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "unsigned short"
            | "int"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "float"
            | "double"
            | "long double"
            | "__int64"
            | "unsigned __int64"
            | "__int128"
            | "unsigned __int128"
            | "wchar_t"
            | "char8_t"
            | "char16_t"
            | "char32_t"
    )
}

/// Parse an MSVC enum type, the `W` sigil already consumed, rendering
/// `enum <qualified-name>`.
///
/// The encoding is `W<underlying-type-digit><qualified-name>`. The digit (0..=7)
/// selects the underlying integer type (int, unsigned, char, …) and is not
/// rendered; `undname`/`msvc-demangler` prefix the name with `enum`. Without
/// consuming the digit, the name parser started at `4Color@1@` and declined the
/// whole symbol.
fn parse_msvc_enum(p: &mut MsvcParser) -> Option<String> {
    p.next()?;
    let name_parts = parse_msvc_qualified_name(p)?;
    let t = format!("enum {}", name_parts.join("::"));
    if p.type_backrefs.len() < 10 {
        p.type_backrefs.push(t.clone());
    }
    Some(t)
}

/// Parse an MSVC pointer-to-array type, the pointer sigil and pointee cv byte
/// already consumed and `Y` next, rendering the declarator `<elem> (*)[d…]`.
///
/// The array grammar is `Y<ndims><dim…>`, each a standard MSVC number
/// (`9` → 10, `BE@` → 20). An array behind a pointer renders as a declarator,
/// `int (*)[10]`, not a suffix, so the standalone `(*)` slot is where a
/// variable name is later woven for data symbols (`?arr@@3PAY09HA` →
/// `int (*arr)[10]`). Verified against `msvc-demangler`.
fn parse_msvc_pointer_to_array(p: &mut MsvcParser, sigil: char) -> Option<String> {
    p.next()?; // the `Y`
    let ndims = parse_msvc_number(p)?;
    if !(1..=64).contains(&ndims) {
        return None;
    }
    let mut dims = String::new();
    for _ in 0..ndims {
        let d = parse_msvc_number(p)?;
        dims.push('[');
        dims.push_str(&d.to_string());
        dims.push(']');
    }
    let elem = parse_msvc_type(p)?;
    let star = match sigil {
        'P' => "*",
        'Q' => "* const",
        'R' => "* volatile",
        'S' => "* const volatile",
        _ => unreachable!(),
    };
    let result = format!("{elem} ({star}){dims}");
    if p.type_backrefs.len() < 10 {
        p.type_backrefs.push(result.clone());
    }
    Some(result)
}

/// Parse an MSVC pointer/reference type (`P`/`Q`/`R`/`S`), the sigil already
/// consumed, rendering `<pointee><suffix>`. Delegates `P6…` to the
/// function-pointer parser, since there the inner is a signature, not a type.
fn parse_msvc_pointer(p: &mut MsvcParser, sigil: char) -> Option<String> {
    // Function pointer: `P6<cc><return><params>@Z` — the `6` marks a function
    // type; without this branch the `6` was read as a cv byte and declined.
    if p.peek() == Some('6') {
        return parse_msvc_function_pointer(p, sigil);
    }
    // Member function pointer: `P8<class>@<cv><cc><signature>`.
    if p.peek() == Some('8') {
        return parse_msvc_member_function_pointer(p, sigil);
    }
    // Optional __ptr64 / __ptr32 marker.
    if matches!(p.peek(), Some('E' | 'F')) {
        p.next();
    }
    let cv = p.next()?; // CV qualifier on pointee
    // Pointer to array (`Y<ndims><dims…><elem>`): renders as a declarator
    // (`elem (*)[d]`), not a plain suffix, so it cannot compose as a string.
    if p.peek() == Some('Y') {
        return parse_msvc_pointer_to_array(p, sigil);
    }
    let mut t = parse_msvc_type(p)?;
    if cv == 'B' || cv == 'D' {
        t = format!("const {t}");
    }
    let suffix = match sigil {
        'P' => "*",
        'Q' => "* const",
        'R' => "* volatile",
        'S' => "* const volatile",
        _ => unreachable!(),
    };
    // A function-pointer pointee is a **declarator**, not a type that a suffix can be
    // appended to. `undname` weaves the outer `*` in beside the inner one:
    //
    //   P8A@@EAAXXZ      ->  void (__cdecl A::*)(void)
    //   PEAP8A@@EAAXXZ   ->  void (__cdecl A::* *)(void)     <- outer * goes INSIDE
    //
    // Appending gave `void (__cdecl A::*)(void)*`, which is not valid C++ and reads
    // as a pointer to the whole function type. The array case already weaves for the
    // same reason (`parse_msvc_pointer_to_array`); this is the function-pointer half
    // of that rule, found by testing the iter-93 member-pointer fix in *nested*
    // position rather than at the top level of a parameter list.
    // Space BEFORE the woven star, matching `undname`: `A::* *)` and not `A::** )`.
    // Both normalise equal, so the differential could not tell them apart; the literal
    // assertion in `a_pointer_to_a_function_pointer_weaves_the_star` is what caught it.
    let result = t.rfind("*)").map_or_else(
        || format!("{t}{suffix}"),
        |i| format!("{} {suffix}{}", &t[..=i], &t[i + 1..]),
    );
    if p.type_backrefs.len() < 10 {
        p.type_backrefs.push(result.clone());
    }
    Some(result)
}

/// Every recursive path in the MSVC parser passes through here, so this is where
/// the depth limit belongs. 64 matches `cpp_demangler::MAX_DEPTH`; real symbols
/// nest a handful deep, and the deepest in either corpus is far below it.
const MSVC_MAX_DEPTH: usize = 64;

fn parse_msvc_type(p: &mut MsvcParser) -> Option<String> {
    p.depth += 1;
    if p.depth > MSVC_MAX_DEPTH {
        p.depth -= 1;
        return None;
    }
    let out = parse_msvc_type_inner(p);
    p.depth -= 1;
    out
}

fn parse_msvc_type_inner(p: &mut MsvcParser) -> Option<String> {
    // RValue ref shorthand (`$$Q<marker><cv><type>`).
    if p.consume_str("$$Q") {
        return parse_msvc_rvalue_ref(p);
    }

    if p.peek() == Some('$') && p.peek_at(1) == Some('$') {
        return parse_msvc_dollar_dollar_type(p);
    }

    // Type backref.
    if let Some(c) = p.peek()
        && c.is_ascii_digit() {
            p.next();
            let idx = c as usize - '0' as usize;
            if idx < p.type_backrefs.len() {
                return Some(p.type_backrefs[idx].clone());
            }
            return None;
        }

    let c = p.next()?;
    match c {
        // Return-type cv prefix (`?A` = none, `?B` = const, …), used when a
        // function returns a class by value or a cv-qualified type, e.g. the
        // `?AV0@` in `??HFoo@@QEAA?AV0@AEBV0@@Z`.
        '?' => {
            let cv = p.next()?;
            let inner = parse_msvc_type(p)?;
            if cv == 'B' || cv == 'D' {
                Some(format!("const {inner}"))
            } else {
                Some(inner)
            }
        }
        // Pointer / reference qualifiers.
        'P' | 'Q' | 'R' | 'S' => parse_msvc_pointer(p, c),
        'A' | 'B' => {
            if matches!(p.peek(), Some('E' | 'F')) {
                p.next();
            }
            let cv = p.next()?;
            let inner = parse_msvc_type(p)?;
            let mut t = inner;
            if cv == 'B' || cv == 'D' {
                t = format!("const {t}");
            }
            let result = if c == 'A' {
                format!("{t}&")
            } else {
                format!("{t}&& ")
            };
            Some(result)
        }
        'X' => Some("void".to_owned()),
        'D' => Some("char".to_owned()),
        'C' => Some("signed char".to_owned()),
        'E' => Some("unsigned char".to_owned()),
        'F' => Some("short".to_owned()),
        'G' => Some("unsigned short".to_owned()),
        'H' => Some("int".to_owned()),
        'I' => Some("unsigned int".to_owned()),
        'J' => Some("long".to_owned()),
        'K' => Some("unsigned long".to_owned()),
        'M' => Some("float".to_owned()),
        'N' => Some("double".to_owned()),
        'O' => Some("long double".to_owned()),
        '_' => {
            let next_c = p.next()?;
            match next_c {
                'N' => Some("bool".to_owned()),
                'J' => Some("long long".to_owned()),
                'K' => Some("unsigned long long".to_owned()),
                'W' => Some("wchar_t".to_owned()),
                'S' => Some("char16_t".to_owned()),
                'U' => Some("char32_t".to_owned()),
                // MSVC's 128-bit integers. Without these they rendered
                // `_unknown_L` / `_unknown_M` — this module's "I could not read
                // this" marker, emitted as if it were a type name.
                'L' => Some("__int128".to_owned()),
                'M' => Some("unsigned __int128".to_owned()),
                // An unrecognised `_`-prefixed code is not a type. Declining is
                // what the rest of the crate does with an unreadable construct;
                // rendering the marker reports a fabrication as a decode.
                _ => None,
            }
        }
        'U' | 'V' => {
            let name_parts = parse_msvc_qualified_name(p)?;
            let t = name_parts.join("::");
            if p.type_backrefs.len() < 10 {
                p.type_backrefs.push(t.clone());
            }
            Some(t)
        }
        'W' => parse_msvc_enum(p),
        _ => None,
    }
}

/// Access, cv and calling-convention information decoded from the bytes that
/// follow an MSVC qualified name.
struct MsvcQualifiers {
    /// Access specifier, e.g. `"public: "`; empty for free functions.
    /// Kept as `&'static str` so decoding a member function allocates nothing
    /// for its prefix — this path is hot and the set of prefixes is fixed.
    access: &'static str,
    /// Storage specifier, e.g. `"virtual "`; empty when neither static nor
    /// virtual.
    storage: &'static str,
    /// The `this`-pointer cv qualifier, already rendered with its leading
    /// space: `""`, `" const"`, `" volatile"` or `" const volatile"`.
    ///
    /// This was a `bool` set from `cv == 'B' || cv == 'D'`, so two of the four
    /// states the byte encodes were unrepresentable: `volatile` was dropped
    /// entirely and `const volatile` rendered as plain `const`. Distinct
    /// symbols therefore collapsed onto one name — `?foo@Cls@@QAAXXZ` with
    /// `?foo@Cls@@QCAXXZ`, and `QBA…` with `QDA…` — which `msvc-demangler`
    /// separates:
    ///
    /// ```text
    ///   ?foo@Cls@@QCAXXZ
    ///     was  public: void __cdecl Cls::foo(void)
    ///     want public: void __cdecl Cls::foo(void) volatile
    /// ```
    this_cv: &'static str,
    /// Whether this is a vtable **thunk** (`G`/`H`, `O`/`P`, `W`/`X`).
    ///
    /// A thunk carries a vtable displacement immediately after the access char, and
    /// not consuming it shifted every following field: `?f@A@@GA@AEXXZ` rendered
    /// `private: virtual void& __cdecl A::f(void)` — a **fabricated reference return
    /// type** and the wrong calling convention — against the oracle's
    /// `[thunk]: private: virtual void __thiscall A::f(void)`. All six thunk letters
    /// were wrong the same way; the other eighteen were correct.
    is_thunk: bool,
    /// Whether the `this` pointer is `__restrict` (`I`).
    ///
    /// It was consumed and **discarded**. Skipping the `this`-pointer modifiers is
    /// necessary for alignment — the comment where they are read says so — but this
    /// one is not noise: `?f@A@@QEIAAXXZ` is `A::f(void) __restrict` and rendered as
    /// `A::f(void)`, so two different functions became indistinguishable.
    ///
    /// Only `I` is surfaced. `E` (`__ptr64`) is not printed by `undname` on x64, and
    /// `F` (`__unaligned`) is not printed by `msvc-demangler` either — measured:
    /// `?f@A@@QEFAAXXZ` gives `A::f(void)`. With no ground truth saying it should
    /// appear, rendering it would be inventing output, so `F` is still consumed and
    /// dropped.
    this_restrict: bool,
    /// The decoded calling convention.
    calling_convention: crate::msvc_extras::CallingConvention,
}

/// Decode the access / cv / calling-convention run that follows a qualified
/// name, given the already-consumed `access_char`.
fn parse_msvc_qualifiers(p: &mut MsvcParser, access_char: char) -> Option<MsvcQualifiers> {
    match access_char {
        'Y' | 'Z' => {
            // Non-member (free) function; the next byte is the calling convention.
            let cc = p.next()? as u8;
            Some(MsvcQualifiers {
                access: "",
                storage: "",
                this_cv: "",
                is_thunk: false,
                this_restrict: false,
                calling_convention: msvc_calling_convention(cc),
            })
        }
        'A'..='X' => {
            // Member function. The access char also encodes storage: each
            // group of eight letters maps to private/protected/public, and
            // within a group the pairs mean normal/static/virtual/thunk.
            let idx = access_char as u8 - b'A';
            let access = match idx / 8 {
                0 => "private: ",
                1 => "protected: ",
                _ => "public: ",
            };
            let storage = match (idx % 8) / 2 {
                1 => "static ",
                2 | 3 => "virtual ",
                _ => "",
            };
            // A thunk (`(idx % 8) / 2 == 3`) carries the vtable displacement here,
            // before the `this` modifiers. It must be consumed or every following
            // field decodes from the wrong byte.
            let is_thunk = (idx % 8) / 2 == 3;
            if is_thunk {
                parse_msvc_number(p)?;
            }
            // Static member functions have no `this` pointer, so the encoding
            // carries neither `this` modifiers nor a cv byte: the calling
            // convention follows the access char directly. Reading a cv byte
            // here would shift every following field by one byte.
            let mut this_restrict = false;
            let cv = if storage == "static " {
                'A'
            } else {
                // `this`-pointer modifiers precede the cv byte and must all be
                // consumed, or every following field is decoded one byte out of
                // alignment. Two of the three mean something: `I` is `__restrict`
                // and `F` is `__unaligned`. `E` is `__ptr64`, which `undname` does
                // not print on x64.
                while let Some(m) = p.peek() {
                    match m {
                        'I' => this_restrict = true,
                        // Consumed for alignment, not rendered: see the field doc.
                        'E' | 'F' => {}
                        _ => break,
                    }
                    p.next();
                }
                p.next()?
            };
            let cc = p.next()? as u8; // calling convention
            Some(MsvcQualifiers {
                access,
                storage,
                // All four states of the cv byte, per `undname` and
                // `msvc-demangler`: `A` none, `B` const, `C` volatile,
                // `D` const volatile.
                this_cv: match cv {
                    'B' => " const",
                    'C' => " volatile",
                    'D' => " const volatile",
                    _ => "",
                },
                is_thunk,
                this_restrict,
                calling_convention: msvc_calling_convention(cc),
            })
        }
        _ => None,
    }
}

pub fn demangle_msvc_internal(mangled: &str) -> Option<String> {
    // RTTI symbols (`??_R<n>…`) are decoded separately.
    if mangled.starts_with("??_R") {
        return demangle_msvc_rtti(mangled);
    }

    // vftable / vbtable / scalar-deleting-dtor / vector-deleting-dtor /
    // special data symbols: `??_7Foo@@6B@`, `??_8Foo@@7B@`, `??_E…`, `??_G…`.
    if let Some(s) = demangle_msvc_special_data(mangled) {
        return Some(s);
    }

    let mut p = MsvcParser::new(mangled);
    if !p.consume('?') {
        return None;
    }

    let name_components = parse_msvc_qualified_name(&mut p)?;
    let name = name_components.join("::");

    parse_msvc_function_or_data_tail(&mut p, &name)
}

///
/// Parse an MSVC parameter list, maintaining the argument back-reference table.
///
/// A numeric back-reference (`0`-`9`) names a previously-seen TOP-LEVEL
/// parameter type, and every parameter except a bare primitive takes one
/// slot. Verified against `msvc-demangler`, which is the only way to settle
/// it: `?f@@YAXHVFoo@@0@Z` is `int, Foo, Foo` — the `int` occupies no slot —
/// while `?f@@YAXABHVFoo@@0@Z` is `int const&, Foo, int const&`, so a
/// *reference to* a primitive does.
///
/// The individual type parsers each registered whatever they built,
/// including NESTED types, so a parameter containing a class registered the
/// class as well and the back-reference resolved to it:
///
///   ?f@@YAXPAVFoo@@0@Z    was `Foo*, Foo`      (want `Foo*, Foo*`)
///   ?f@@YAXABVFoo@@0@Z    was `const Foo&, Foo` (want two `const Foo&`)
///   ?f@@YAXPAPAVFoo@@0@Z  was `Foo**, Foo`     (want two `Foo**`)
///
/// — wrong silently, in a way no string comparison against our own output
/// could reveal. Truncating to the pre-parameter length discards those
/// nested registrations; the reference branch never registered at all, which
/// is why `?f@@YAXABH0@Z` declined outright.
fn parse_msvc_param_list(p: &mut MsvcParser) -> (Vec<String>, bool) {
    let mut params = Vec::new();
    let mut terminated = false;
    loop {
        if p.consume('Z') {
            terminated = true;
            break;
        }
        if p.consume_str("@Z") {
            terminated = true;
            break;
        }
        if p.peek().is_none() {
            // Running out of input is NOT a valid termination: the grammar
            // requires `Z`. Treating it as one reported a TRUNCATED symbol as a
            // complete one — `?bar@Foo@@QAEX` and `?bar@Foo@@QAEXX` both
            // rendered `public: void __thiscall Foo::bar(void)`, identical to
            // the intact `?bar@Foo@@QAEXXZ`, and `msvc-demangler` rejects both.
            // Same class as the trailing-input rule in
            // `tests/trailing_input.rs`, seen from the other side.
            break;
        }
        let slots = p.type_backrefs.len();
        if let Some(t) = parse_msvc_type(p) {
            p.type_backrefs.truncate(slots);
            if !is_msvc_primitive(&t) && p.type_backrefs.len() < 10 {
                p.type_backrefs.push(t.clone());
            }
            params.push(t);
        } else {
            break;
        }
    }

    (params, terminated)
}


/// Parse the tail of an MSVC symbol after its qualified name: the access/
/// storage byte, then either a data type (`3`/`0`-`2`) or a function signature
/// (return type + parameters), formatting the whole against `name`.
///
/// Split out so the deleting-destructor path can reuse it. A `??_E…`/`??_G…`
/// symbol is an ordinary member function whose *name* is the special label —
/// `type_info@@UEAAPEAXI@Z` is `public: virtual void * __cdecl
/// …(unsigned int)` — so once the label is supplied as `name`, the remaining
/// bytes parse exactly like any member function. Rendering only the label, as
/// the code did before, dropped that entire signature.
fn parse_msvc_function_or_data_tail(p: &mut MsvcParser, name: &str) -> Option<String> {
    parse_msvc_tail_inner(p, name, true)
}

/// As [`parse_msvc_function_or_data_tail`], but the parser need not have
/// consumed the whole input.
///
/// A function-local scope embeds a complete enclosing symbol and is *followed*
/// by the variable's own storage class, so the full-consumption rule — correct
/// for a standalone symbol, and deliberate since the trailing-input fix — makes
/// the shared parser unusable there. This is the same parse, reporting what it
/// built and leaving the cursor where it stopped.
fn parse_msvc_function_or_data_tail_partial(p: &mut MsvcParser, name: &str) -> Option<String> {
    parse_msvc_tail_inner(p, name, false)
}

fn parse_msvc_tail_inner(p: &mut MsvcParser, name: &str, require_end: bool) -> Option<String> {
    // Access / storage class.
    let access_char = p.next()?;

    // Data symbols: `?<name>@@3<type><cv>` (`3` = global/static data).
    if matches!(access_char, '0'..='5') {
        // `0`/`1`/`2` are static *member* data with an access level;
        // `3` (global) and `4`/`5` carry no prefix.
        let prefix = match access_char {
            '0' => "private: static ",
            '1' => "protected: static ",
            '2' => "public: static ",
            _ => "",
        };
        let ty = parse_msvc_type(p)?;
        // `__ptr64` / `__unaligned` / `__restrict` markers may precede the
        // variable's own cv byte (e.g. the `E` in `?g_name@@3PEBDEB`).
        let mut had_markers = false;
        while matches!(p.peek(), Some('E' | 'F' | 'I')) {
            had_markers = true;
            p.next();
        }
        // Trailing cv byte for the variable itself. Mirror `undname`: on a
        // non-pointer type it prefixes `const`; on a plain pointer it renders
        // a const *pointer* (`char * const`); when `__ptr64`-style markers
        // preceded it, the constness is already carried by the pointer
        // encoding and rendering it again would double the `const`.
        let cv = p.next().unwrap_or('A');
        let qualified = if cv == 'B' || cv == 'D' {
            if !ty.contains('*') {
                format!("const {ty}")
            } else if had_markers {
                ty
            } else {
                format!("{ty} const")
            }
        } else {
            ty
        };
        if p.pos < p.input.len() {
            return None;
        }
        // Pointer-to-array declarators weave the variable name inside the
        // `(*)` slot — `int (*)[10]` + `arr` → `int (*arr)[10]` — rather than
        // appending it, which would misrender as `int (*)[10] arr`.
        if qualified.contains("(*)") {
            let woven = qualified.replacen("(*)", &format!("(*{name})"), 1);
            return Some(format!("{prefix}{woven}"));
        }
        return Some(format!("{prefix}{qualified} {name}"));
    }

    let MsvcQualifiers {
        access,
        storage,
        this_cv,
        is_thunk,
        this_restrict,
        calling_convention,
    } = parse_msvc_qualifiers(p, access_char)?;

    // Return type (absent for ctors/dtors: '@').
    let return_type = if p.consume('@') {
        None
    } else {
        Some(parse_msvc_type(p)?)
    };

    let (params, terminated) = parse_msvc_param_list(p);
    if !terminated {
        return None;
    }

    // MSVC renders an empty parameter list as `(void)`.
    let params_str = if params.is_empty() || (params.len() == 1 && params[0] == "void") {
        "void".to_owned()
    } else {
        params.join(", ")
    };

    let mut result = String::with_capacity(name.len() + params_str.len() + 32);
    // `undname` puts `[thunk]: ` before the access specifier.
    if is_thunk {
        result.push_str("[thunk]: ");
    }
    result.push_str(access);
    result.push_str(storage);
    if let Some(ret) = return_type {
        result.push_str(&ret);
        result.push(' ');
    }
    // Render the calling convention between the return type and the name,
    // mirroring MSVC's `undname` output (e.g. `int __cdecl foo(void)`).
    result.push_str(calling_convention.as_str());
    result.push(' ');
    result.push_str(name);
    result.push('(');
    result.push_str(&params_str);
    result.push(')');
    result.push_str(this_cv);
    // Same position as `const`.
    if this_restrict {
        result.push_str(" __restrict");
    }

    // A standalone symbol must have been consumed entirely for the result to be
    // valid; an embedded one is followed by its container's own encoding.
    if require_end && p.pos < p.input.len() {
        return None;
    }

    Some(result)
}

/// Decode MSVC special data symbols: `??_7…@@<cv>B@` (vftable),
/// `??_8…@@<cv>B@` (vbtable), `??_E…` (vector deleting dtor),
/// `??_G…` (scalar deleting dtor).
///
/// Returns `None` if the input does not match one of these patterns.
/// String literals: `??_C@_<0|1><length><checksum>@<encoded-bytes>@`.
///
/// `_0` is narrow, `_1` wide; the length is an MSVC number, the checksum an
/// alphanumeric run, and the payload the encoded bytes. `undname` and
/// `msvc-demangler` both render the whole thing as `` `string' `` — they do **not**
/// decode the content — so that is the answer here too, and no part of the payload is
/// interpreted.
///
/// The structure is validated rather than prefix-matched, so a malformed symbol
/// declines instead of being claimed: without the `@`-delimited checksum and payload
/// this would accept `??_C@` followed by anything.
fn demangle_msvc_string_literal(mangled: &str) -> Option<String> {
    let rest = mangled.strip_prefix("??_C@")?;
    let rest = rest.strip_prefix('_')?;
    // Width marker.
    let rest = rest.strip_prefix('0').or_else(|| rest.strip_prefix('1'))?;
    // Length, as an MSVC number: decimal digits, or `A`-`P` hex terminated by `@`.
    let mut p = MsvcParser::new(rest);
    parse_msvc_number(&mut p)?;
    let after_len = &rest[p.pos..];
    // Checksum: a non-empty alphanumeric run, then `@`.
    let (checksum, payload) = after_len.split_once('@')?;
    if checksum.is_empty() || !checksum.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    // Payload, then the closing `@`. The bytes themselves are not interpreted.
    if !payload.ends_with('@') {
        return None;
    }
    Some("`string'".to_owned())
}

pub fn demangle_msvc_special_data(mangled: &str) -> Option<String> {
    // String literals have their own shape — a width marker, length, checksum and
    // encoded payload rather than a class name — so they are handled before the
    // table-and-name forms below.
    if let Some(s) = demangle_msvc_string_literal(mangled) {
        return Some(s);
    }

    // Any `??_<code>` special name, via the shared table — not the four this path
    // used to hardcode. `is_data` is decided by what FOLLOWS the class name (a
    // `6`/`7`/`8` table marker means data), so the same label works in both shapes.
    let code = mangled.strip_prefix("??_").and_then(|r| r.chars().next())?;
    // `??__E`/`??__F` are handled on the operator path, not here.
    if code == '_' {
        return None;
    }
    let label = msvc_underscore_special_name(code)?;
    let rest = &mangled[4..];
    // Data forms end with a table marker and cv byte (`@@8`, `@@6B@`); function forms
    // carry an access char and signature. Deciding from the tail rather than from the
    // code is what lets one table serve both.
    let is_data = {
        let mut probe = MsvcParser::new(rest);
        parse_msvc_qualified_name(&mut probe)
            .is_some_and(|_| matches!(probe.peek(), Some('6' | '7' | '8')) || probe.peek().is_none())
    };

    // The class name follows as an @-terminated qualified name list ending
    // with `@@`. Use a sub-parser to extract it.
    let mut p = MsvcParser::new(rest);
    let components = parse_msvc_qualified_name(&mut p)?;
    if components.is_empty() {
        return None;
    }
    let qname = components.join("::");

    if is_data {
        // After `@@` comes the table-KIND marker (`6` for a vftable, `7` for a
        // vbtable), and the cv qualifier is the byte AFTER it, using the same
        // encoding as everywhere else in this file: `A` none, `B` const,
        // `C` volatile, `D` const volatile.
        //
        // This read the marker itself as the cv, mapping `6`->const and
        // `7`->volatile, so it produced a *constant* answer per table kind and was
        // right for exactly one of four cases in each family. Measured against the
        // oracle:
        //
        // ```text
        // ??_7A@@6A@  ours: const A::`vftable'   oracle: A::`vftable'
        // ??_7A@@6B@  ours: const A::`vftable'   oracle: const A::`vftable'   <- agreed by luck
        // ??_7A@@6C@  ours: const A::`vftable'   oracle: volatile A::`vftable'
        // ??_8A@@7B@  ours: volatile A::`vbtable'  oracle: const A::`vbtable'
        // ```
        //
        // `??_7A@@6B@` was the only shape under test, and it passed because
        // `6`->const and `B`->const happen to agree. Seven of the eight
        // marker/cv combinations were wrong.
        // `8` is the plain-data marker and ends the symbol; `6`/`7` introduce a
        // table form that continues with a cv byte and a closing `@`. `8` was
        // not consumed here before, which was invisible while nothing checked
        // for leftovers and became a decline the moment something did.
        if matches!(p.peek(), Some('6' | '7' | '8')) {
            p.next();
        }
        // The cv byte is CONSUMED, including `A` (no qualifier). Peeking without
        // consuming left the parser mid-symbol, which is why the end-of-input
        // check below could not have been written before.
        let cv_str = match p.peek() {
            Some('A') => {
                p.next();
                ""
            }
            Some('B') => {
                p.next();
                "const "
            }
            Some('C') => {
                p.next();
                "volatile "
            }
            Some('D') => {
                p.next();
                "const volatile "
            }
            _ => "",
        };
        // The form ends `<marker><cv>@`, and nothing may follow. Without this the
        // parser stopped as soon as it had enough and ignored the rest, so
        // `??_7type_info@@6B@GARBAGE` rendered exactly like `??_7type_info@@6B@` —
        // two different linker symbols collapsing to one name, which is the defect
        // `tests/trailing_input.rs` already forbids for D and Itanium.
        // Two legal endings, and nothing after either: exhausted already (the
        // bare `??_7Foo@@`, which `msvc-demangler` accepts, and the plain-data
        // `??_AA@@8`), or a single closing `@` after the cv byte.
        if p.peek().is_some() && (!p.consume('@') || p.peek().is_some()) {
            return None;
        }
        Some(format!("{cv_str}{qname}::{label}"))
    } else {
        // Deleting destructor: the label is the method name, and the bytes
        // after the qualified name are an ordinary member-function signature
        // (`UEAAPEAXI@Z` = `public: virtual void * __cdecl …(unsigned int)`).
        // Parse them through the shared tail so the full signature is rendered,
        // matching `undname`/`msvc-demangler`. If the tail is absent or does
        // not parse (a bare `??_EFoo@@`), fall back to the label alone.
        let method = format!("{qname}::{label}");
        if p.peek().is_none() {
            return Some(method);
        }
        parse_msvc_function_or_data_tail(&mut p, &method).or(Some(method))
    }
}

// ── Rust demangler (via rustc-demangle) ───────────────────────────────────────

/// Demangler for Rust mangled symbols (both legacy `_ZN` and v0 `_R` prefix).
pub struct RustDemangler;

/// Whether `s` uses Rust mangling: v0 (`_R` + an RFC 2603 path tag) or legacy
/// (`_ZN…17h<16 hex digits>E`).
///
/// Delegates to [`crate::sigil`], the single definition of these prefixes.
fn is_rust_mangling(s: &str) -> bool {
    crate::sigil::is_rust(s)
}

impl Demangler for RustDemangler {
    fn detect(&self, mangled: &str) -> bool {
        // Shares `is_rust_mangling` with `demangle` below, deliberately: this
        // used to accept any `_ZN…E`, which is every Itanium nested name. That
        // was harmless while `demangle` was equally loose, but once `demangle`
        // was tightened the two disagreed on 89 corpus symbols — `detect`
        // promising a decode that `demangle` then declined, so a caller
        // writing `if d.detect(s) { d.demangle(s).unwrap() }` would panic.
        is_rust_mangling(mangled)
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        // `rustc_demangle` accepts more than Rust: legacy Rust mangling is
        // Itanium-shaped, so a plain C++ data symbol like
        // `_ZN10__cxxabiv119__terminate_handlerE` parses and would be returned
        // under `ManglingAbi::Rust`. The rendered string happens to be right,
        // but the ABI label is not, and consumers route on it. Gate on the
        // symbol actually being Rust; anything else falls through to the
        // Itanium backend, which owns it.
        if !is_rust_mangling(mangled) {
            return None;
        }
        let demangled_sym = rustc_demangle::try_demangle(mangled).ok()?;
        // Use the alternate `{:#}` formatter to omit the trailing legacy
        // hash suffix (e.g. `::hb6e4a2c0bcfaa0ad`) and v0 disambiguators —
        // callers that need the raw form can use `rustc_demangle` directly.
        let demangled = format!("{demangled_sym:#}");
        // Rustc-demangle returns the original on failure – treat that as None.
        if demangled == mangled {
            return None;
        }

        let (namespace, class, function, args) = split_rust_components(&demangled);
        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled,
            abi: ManglingAbi::Rust,
            namespace,
            class,
            function,
            args,
            return_type: None,
        })
    }
}

pub fn split_rust_components(demangled: &str) -> (Option<String>, Option<String>, String, Vec<String>) {
    // Split on `::` at bracket depth zero, then drop trailing turbofish
    // groups. Truncating at the first `<` — which is what this did — empties
    // the whole name when the rendering *starts* with a qualified type:
    // `<str>::trim_start_matches::<&str>` and
    // `core::panicking::assert_failed::<usize, usize>` both reported
    // `function: ""`, 71 such symbols across the real corpora.
    // Shared with the Itanium decomposition; the post-processing below is not.
    let mut parts: Vec<&str> = split_scope_at_depth_zero(demangled, "::")
        .into_iter()
        .map(str::trim)
        .collect();
    // A trailing `<…>` is the instantiation's type arguments, not the entity.
    while parts.len() > 1 && parts.last().is_some_and(|p| p.starts_with('<')) {
        parts.pop();
    }
    parts.retain(|p| !p.is_empty());
    // An INHERENT impl renders as `<Type>::method`, and the angle brackets are
    // syntax, not part of any name. Keeping them cost both fields on half the
    // real Rust corpus:
    //
    //   <std::path::Path>::is_absolute
    //     was  namespace None, class "<std::path::Path>"
    //     now  namespace "std::path", class "Path"
    //
    // 25 of 137 real Rust decodes are this shape. The inner path is spliced
    // back into the scope list so it decomposes exactly as the equivalent
    // non-impl rendering does — nothing is invented, only un-bracketed.
    //
    // A TRAIT impl (`<main::Foo as core::fmt::Debug>::fmt`, 43 more) is
    // deliberately left alone: its bracketed part is an impl header rather
    // than a path, and choosing between the self type and the trait for
    // `class` is a judgement the rendering does not make for us.
    let spliced: Vec<&str> = parts.first().map_or_else(Vec::new, |first| {
        first
            .strip_prefix('<')
            .and_then(|t| t.strip_suffix('>'))
            .filter(|inner| !inner.contains(" as ") && !inner.is_empty())
            .map_or_else(Vec::new, |inner| split_scope_at_depth_zero(inner, "::"))
    });
    if !spliced.is_empty() {
        parts.splice(0..1, spliced);
    }
    let function = parts.last().copied().unwrap_or("").to_owned();
    // Strip trailing hash component (16-hex-digit closures etc.).
    let (namespace, class) = match parts.len() {
        0 | 1 => (None, None),
        2 => (None, Some(parts[0].to_owned())),
        n => {
            let ns = parts[..n - 2].join("::");
            let cls = parts[n - 2].to_owned();
            (Some(ns), Some(cls))
        }
    };
    (namespace, class, function, Vec::new())
}

// ── Swift demangler (heuristic) ───────────────────────────────────────────────

/// Heuristic demangler for Swift mangled names.
///
/// Swift uses `_T0` (Swift 4+) or `$s` / `$S` prefixes.  We perform best-effort
/// parsing of the module, type, and member names.
pub struct SwiftDemangler;

/// The Swift 5 operator suffix at the end of `mangled`, if any.
///
/// These are `T` followed by one lowercase or uppercase letter, optionally with
/// further payload for `Tw` (value witness). Only the trailing `T<letter>` is
/// returned; the caller decides whether it was ignored by the parser.
fn swift_operator_suffix(mangled: &str) -> Option<&str> {
    let b = mangled.as_bytes();
    // Peel the WHOLE trailing run of `T<letter>` groups, not just the last one.
    // Swift chains these (`TATm`), and reporting only the final group made
    // `…FTA` and `…FTATA` collide again — the very defect the marker exists to
    // remove.
    let mut start = b.len();
    while start >= 2 && b[start - 2] == b'T' && b[start - 1].is_ascii_alphabetic() {
        start -= 2;
    }
    if start == b.len() {
        // `Tw` (value witness) carries a payload, so the run may end in bytes
        // that are not part of a pair: `…FTwxx`.
        let window = b.len().min(6);
        for back in 3..=window {
            let s2 = b.len() - back;
            if b[s2] == b'T'
                && b[s2 + 1].is_ascii_alphabetic()
                && b[s2..].iter().all(u8::is_ascii_alphanumeric)
            {
                return Some(&mangled[s2..]);
            }
        }
        return None;
    }
    // Something must remain for the stem to be a symbol at all.
    if start < 3 {
        return None;
    }
    Some(&mangled[start..])
}

impl Demangler for SwiftDemangler {
    fn detect(&self, mangled: &str) -> bool {
        // The sigil test stays in `sigil.rs` — writing a second copy here is the
        // mistake this crate spent forty iterations undoing. What is added is a
        // condition local to *claiming*: a bare sigil with nothing after it is
        // not a symbol, so `$s` alone must not be claimed.
        //
        // This has to move in step with `demangle` below, which declines when
        // the parse yields only a placeholder. `detect` promising more than
        // `demangle` delivers is the divergence that once panicked 89 corpus
        // symbols through `if d.detect(s) { d.demangle(s).unwrap() }`, and is
        // guarded by `tests/detect_demangle_agreement.rs`.
        // Cheap structural check, deliberately not a parse: `detect` sits on the
        // dispatch hot path. When the body opens with a length prefix, that
        // length must fit in what follows — which rejects `$s10ab` and `$s0foo`
        // without decoding anything. Anything past the first component is left
        // to `demangle`.
        let body_is_plausible = |rest: &str| {
            if rest.is_empty() {
                return false;
            }
            // Swift manglings are ASCII — a non-ASCII name is punycoded — so a
            // body opening with anything else cannot start an entity.
            if !rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return false;
            }
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                return true; // not length-prefixed: a substitution, sigil letter, …
            }
            // A zero-length identifier is not a name, and an absurdly long run
            // of digits cannot be a length — both are rejected, as is a length
            // that does not fit in the remaining text.
            digits.parse::<usize>().is_ok_and(|n| {
                // The length is in *bytes*. It must fit, and it must land on a
                // character boundary — a prefix ending between the bytes of a
                // multi-byte character names nothing, and `demangle` declines
                // it, so claiming it here would put the two out of step.
                n > 0
                    && rest.len() - digits.len() >= n
                    && rest.is_char_boundary(digits.len() + n)
            })
        };
        let has_body =
            |prefix: &str| mangled.strip_prefix(prefix).is_some_and(body_is_plausible);

        (crate::sigil::is_swift(mangled)
            && (has_body("$s") || has_body("$S") || has_body("_$s") || has_body("_$S")))
            || has_body("_T0")
            || has_body("__T0")
            || crate::swift_demangler::detect_old_swift(mangled)
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if !self.detect(mangled) {
            return None;
        }
        // Prefer the full grammar parser; fall back to the length-prefix
        // heuristic when it cannot make sense of the symbol.
        let parsed = crate::swift_demangler::swift_demangle(mangled);
        let demangled = if parsed == mangled || parsed.is_empty() {
            demangle_swift_heuristic(mangled)?
        } else {
            parsed
        };
        // A rendering that still carries one of this module's own "could not
        // parse it" placeholders is not a decode: reporting it as one counts a
        // fabrication as a success, both in `DeclineReason::Decoded` and in the
        // corpus decode total.
        //
        // `$s` alone, `$s10ab` (a length prefix longer than what follows) and
        // `$s{}` all reached here as `?module`, and `$s0foo` — a zero-length
        // identifier — as `.() -> ()` with an empty leading component. Declining
        // them applies to Swift the rule this crate already enforces elsewhere:
        // a bare sigil is not a symbol, which is why `Java_` alone declines and
        // why the loose `_R`/`_T`/`_D` prefix rules were removed.
        //
        // These markers never occur in a legitimate rendering — they are
        // produced only by the `unwrap_or_else` fallbacks in `swift_demangler`.
        if demangled.contains("?module")
            || demangled.contains("?(")
            || demangled.starts_with('.')
            || demangled.is_empty()
        {
            return None;
        }

        // A Swift 5 *operator suffix* — `TA` partial-apply forwarder, `To`
        // Obj-C thunk, `TD` dynamic-dispatch thunk, `Tj`, `Tq`, `Tm`, … — names
        // a DIFFERENT symbol at a different address, and the parser stopped at
        // the entity terminator and ignored it. Eleven distinct symbols
        // (`…yyF`, `…yyFTA`, `…yyFTo`, …) all rendered `main.foo() -> ()`.
        //
        // The test is self-verifying rather than a guess about the grammar: the
        // suffix is reported only when removing it yields the SAME rendering,
        // which is precisely the case where the parser ignored it. A suffix the
        // parser does consume changes the output and is left alone, so this
        // cannot misfire on a symbol that merely ends in those letters.
        //
        // The marker is echoed verbatim instead of being spelled out
        // ("partial apply forwarder for …"): those spellings are Swift's, and
        // with no Swift oracle here an unverified label is the fabrication this
        // crate punishes hardest. A faithful echo loses nothing and restores
        // injectivity, which is the defect at hand.
        let demangled = match swift_operator_suffix(mangled) {
            Some(sfx) => {
                let stem = &mangled[..mangled.len() - sfx.len()];
                // Re-parse the stem with the SAME local parser, never through
                // `crate::demangle`. Going back through the public entry point
                // re-entered this very check, so a symbol ending in repeated
                // `T<letter>` recursed once per suffix and
                // `$s4main3fooyyF` + `TA` x1024 **overflowed the stack** — an
                // uncatchable process kill, the failure mode
                // `tests/recursion_is_bounded.rs` exists for. Introduced by the
                // first version of this check at iter 131 and missed by three
                // rounds of gates, because that suite had no repeated-suffix
                // shape.
                let stem_parsed = crate::swift_demangler::swift_demangle(stem);
                let stem_renders_alike = stem_parsed != stem
                    && !stem_parsed.is_empty()
                    && stem_parsed == demangled;
                if stem_renders_alike {
                    format!("{demangled} [{sfx}]")
                } else {
                    demangled
                }
            }
            None => demangled,
        };

        // A local entity whose name never reached the output is lost identity,
        // not merely lost detail.
        //
        // Swift is deliberately exempt from the crate's trailing-input rule,
        // and for a measured reason (see `tests/trailing_input.rs`): its parser
        // consumes the whole symbol for only 9 of 16 realistic inputs, so
        // demanding full consumption would decline 7 legitimate symbols. But
        // that exemption was too broad. It also covered the case where the
        // unconsumed tail contains a *name*:
        //
        //   $s4main5outeryyF6insideL_yyF  =>  main.outer() -> ()
        //   $s4main5outeryyF              =>  main.outer() -> ()
        //
        // Two different entities, one output. The tails the exemption exists to
        // protect are type and constructor grammar — there the signature detail
        // is lost but the name is fully recovered. Here the name `inside` is
        // dropped, so the symbol is indistinguishable from its own enclosing
        // function. That collision is decidable without a Swift oracle: it says
        // nothing about how a local entity *should* render, only that it must
        // not silently become something else.
        if let Some(name) = dropped_swift_local_name(mangled, &demangled) {
            // Must use the SAME predicate the helper decides with. Asserting
            // `!demangled.contains(&name)` here was a substring test guarding an
            // identifier-boundary decision, so it fired on every short local
            // name — `$s4main5outeryyF1aL_yyF` panicked in any build with debug
            // assertions on. Release builds hid it, which is what this project
            // always uses.
            debug_assert!(!contains_identifier(&demangled, &name));
            return None;
        }

        let (namespace, class, function) = split_swift_components(&demangled);
        // The rendering names the return type after `->`, and the field said
        // `None`: `$s4main3fooySiF` rendered `main.foo() -> Swift.Int` while
        // reporting no return type at all. Pure extraction — the information is
        // already in the string, so no grammar and no oracle are involved.
        //
        // The LAST `->` at depth zero: a parameter that is itself a function
        // type (`(Int) -> Bool`) carries one of its own, and taking the first
        // would report the parameter's result as the function's.
        let return_type = split_trailing_arrow_type(&demangled);
        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled,
            abi: ManglingAbi::Swift,
            namespace,
            class,
            function,
            args: Vec::new(),
            return_type,
        })
    }
}

/// The type after the last top-level `->` in a Swift rendering.
///
/// Depth-aware over `(`/`<`/`[`, so a function-typed parameter's own arrow does
/// not win: in `main.f((Int) -> Bool) -> Swift.Int` the result is
/// `Swift.Int`, not `Bool`.
fn split_trailing_arrow_type(demangled: &str) -> Option<String> {
    let b = demangled.as_bytes();
    let mut depth = 0i32;
    let mut last = None;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'(' | b'<' | b'[' => depth += 1,
            b')' | b'>' if i > 0 && b[i - 1] == b'-' => {}
            b')' | b'>' | b']' => depth -= 1,
            b'-' if depth == 0 && b.get(i + 1) == Some(&b'>') => {
                last = Some(i);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let at = last?;
    let ty = demangled.get(at + 2..)?.trim();
    (!ty.is_empty()).then(|| ty.to_owned())
}

/// Heuristic Swift demangler.  Decodes length-prefixed identifiers.
pub fn demangle_swift_heuristic(mangled: &str) -> Option<String> {
    swift_heuristic_parts(mangled).map(|(name, _tail)| name)
}

/// The heuristic's rendering together with the mangling it could not read.
///
/// The heuristic stops at the first non-digit and joins the length-prefixed
/// identifiers, silently discarding the rest. That rest is the SIGNATURE, and
/// dropping it collapsed distinct functions onto one name:
///
/// ```text
/// $s4main3fooySaySiGF    (Array<Int>)      main.foo
/// $s4main3fooySDySSSiGF  (Dictionary)      main.foo
/// $s4main3fooySi_SitF    (tuple)           main.foo
/// ```
///
/// `swift_completeness.rs` cannot see this: its invariant is defined over
/// `<len><chars>` identifiers, and a standard-library substitution (`Si`, `SS`,
/// `Say…G`) carries no length prefix — the same blind spot that let Go drop a
/// numeric closure index past `go_completeness.rs` (iter 120).
///
/// Rendering these types properly needs the Swift grammar and an oracle to
/// validate it, neither of which is available. Reporting the tail verbatim
/// needs neither, and restores the distinction — the same remedy as the
/// operator suffixes at iter 131.
fn swift_heuristic_parts(mangled: &str) -> Option<(String, &str)> {
    // Determine where the actual encoded name starts.
    let rest = if let Some(s) = mangled.strip_prefix("__T0") {
        s
    } else if let Some(s) = mangled.strip_prefix("_T0") {
        s
    } else if let Some(s) = mangled.strip_prefix("_$s").or_else(|| mangled.strip_prefix("_$S")) {
        // Mach-O underscore form; the encoded name follows the sigil.
        s
    } else if mangled.starts_with("$s") || mangled.starts_with("$S") {
        &mangled[2..]
    } else {
        return None;
    };

    let mut components = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Try to read a decimal length prefix.
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let len: usize = std::str::from_utf8(&bytes[start..i]).ok()?.parse().ok()?;
            let end = i.checked_add(len)?;
            if len == 0 || end > bytes.len() {
                break;
            }
            let ident = std::str::from_utf8(&bytes[i..end]).ok()?;
            components.push(ident.to_owned());
            i = end;
        } else {
            // Non-digit suffix (function kind marker etc.) – stop.
            break;
        }
    }

    if components.is_empty() {
        return None;
    }
    Some((components.join("."), &rest[i..]))
}

pub fn split_swift_components(demangled: &str) -> (Option<String>, Option<String>, String) {
    // Drop the synthesized `[unparsed …]` annotation before splitting. It is
    // added by `swift_demangle` when the parser produced a path but no
    // signature (iter 142), and a marker in a FIELD is the defect iter 140
    // fixed for the GNAT tags and D's nested-scope parens — reintroduced here
    // by the very next rendering feature, which is why that iteration's note
    // says a new annotation must be run past the field probe.
    let demangled = demangled.split(" [unparsed ").next().unwrap_or(demangled);
    // Only the *path* portion of the rendering may be split on `.`. A Swift
    // rendering also carries a type annotation, a signature and an accessor
    // suffix, none of which are path components, and splitting the whole string
    // put them in the wrong fields:
    //
    //   "Foundation.Data.count.getter : Swift.Int"
    //     was  ns=Foundation  class="getter : Swift"  function="Int"
    //     now  ns=Foundation  class=Data             function=count
    //
    // `class` was an accessor kind glued to half a type name, `function` was
    // the *return type*, and `Data` — the actual type — was lost. It passed the
    // consistency check in `tests/structured_consistency.rs` because each of
    // those substrings does occur in the rendered string; that invariant is
    // necessary but not sufficient, the same blind spot recorded for the Go
    // backend's fabricated metadata.
    let path = {
        // ` : T` is a type annotation on a property or accessor.
        let p = demangled.split(" : ").next().unwrap_or(demangled);
        // `(…)` onwards is the signature — but only a `(` that is not nested
        // inside generic arguments. A naive `split('(')` cut inside
        // `Foo<(Swift.Int) -> ()>` and discarded the rest of the path.
        let p = swift_signature_start(p).map_or(p, |i| &p[..i]);
        // A trailing accessor marker names the operation, not an enclosing
        // type: the entity is `count`, not `count.getter`.
        ["getter", "setter", "modify", "read", "willset", "didset"]
            .iter()
            .find_map(|k| p.strip_suffix(k).and_then(|r| r.strip_suffix('.')))
            .unwrap_or(p)
            .trim()
    };

    // Depth-aware, because Swift generic arguments contain dots:
    // `MyApp.Container<Swift.Int>.insert` split naively gave class `Int>` — a
    // fragment of the type arguments with a stray closing bracket, where the
    // class is `Container<Swift.Int>`. Same defect as the Itanium and Rust
    // decompositions; this was the third copy of the rule.
    let parts: Vec<&str> = split_scope_at_depth_zero(path, ".")
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let function = parts.last().copied().unwrap_or("").to_owned();
    match parts.len() {
        0 | 1 => (None, None, function),
        2 => (Some(parts[0].to_owned()), None, function),
        n => (
            Some(parts[0].to_owned()),
            Some(parts[n - 2].to_owned()),
            function,
        ),
    }
}

// ── D demangler (via the full `d_demangler` parser) ───────────────────────────

/// Demangler for D language symbols (`_D` prefix).
pub struct DLangDemangler;

impl Demangler for DLangDemangler {
    fn detect(&self, mangled: &str) -> bool {
        crate::d_demangler::DDemangler::detect(mangled)
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if !self.detect(mangled) {
            return None;
        }
        let sym = crate::d_demangler::DDemangler::new(mangled).demangle().ok()?;

        // Same rule as the Swift backend: a rendering that still carries this
        // crate's own "could not read it" placeholder is not a decode.
        // `d_demangler` writes `?(<code>)` for a type code it does not
        // implement and a bare `?` for a component that ran out of input, so
        // `_D3fooQeFiZv` (a `Q` back-reference, unimplemented) reported
        // `Some("?(Q) foo")` with `DeclineReason::Decoded` — a fabrication
        // counted as a success in the classification metric.
        //
        // A legitimate D rendering never contains `?`: every type code the
        // parser understands has a spelling.
        if sym.demangled.contains('?') {
            return None;
        }

        // `class` was hard-coded `None`, so the aggregate a method belongs to
        // was folded into the namespace: `_D4main3Foo3barMFZv` reported
        // `namespace: "main.Foo"` and no class, losing the distinction a
        // consumer routes on.
        //
        // D can be exact where the other ABIs guess. Rust and MSVC assume the
        // last scope component is the class, which is wrong for a nested module
        // (`core::fmt::write` reports `fmt` as a class); D's mangling carries
        // `M` precisely when the symbol belongs to an aggregate, so the split
        // is made on that evidence and only then.
        let (namespace, class) = match (sym.is_member, sym.module_path.as_slice()) {
            (_, []) => (None, None),
            (true, [only]) => (None, Some((*only).clone())),
            (true, path) => path.split_last().map_or((None, None), |(cls, ns)| {
                (Some(scrub_d_scope(ns)), Some(cls.clone()))
            }),
            (false, path) => (Some(scrub_d_scope(path)), None),
        };
        let (args, return_type) = sym.func_type.as_ref().map_or_else(
            || (Vec::new(), None),
            |ft| {
                let args = ft
                    .params
                    .iter()
                    .map(|p| format!("{}{}", p.storage.as_str(), p.type_name))
                    .collect();
                (args, Some(ft.return_type.clone()))
            },
        );
        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled: sym.demangled,
            abi: ManglingAbi::D,
            namespace,
            class,
            function: sym.name,
            args,
            return_type,
        })
    }
}

/// Join D scope components, dropping the function-scope marker.
///
/// A function nested in another function's scope renders as
/// `main.foo().bar()`, and the `()` marks that `foo` is a function rather than
/// a module (iter 130). That marker belongs in the rendering, not in the
/// `namespace` field, which reported `"main.foo(int)"` — a scope no consumer
/// can look up. A D module name cannot contain parentheses, so removing them is
/// unambiguous.
fn scrub_d_scope(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| p.split('(').next().unwrap_or(p))
        .collect::<Vec<_>>()
        .join(".")
}

// ── Go demangler ──────────────────────────────────────────────────────────────

/// Demangler for Go symbol names (`pkg/path.Func`, `pkg.(*T).Method`).
///
/// Go names are not mangled in the C++ sense, but they encode package paths,
/// receivers and closure nesting that benefit from structured decoding.
pub struct GoLangDemangler;

impl Demangler for GoLangDemangler {
    fn detect(&self, mangled: &str) -> bool {
        crate::go_demangler::GoDemangler::detect(mangled)
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if !self.detect(mangled) {
            return None;
        }
        let sym = crate::go_demangler::decode_go_symbol(mangled, true)?;
        let namespace = if sym.package.import_path.is_empty() {
            None
        } else {
            Some(sym.package.import_path.clone())
        };
        let class = sym.receiver.as_ref().map(|r| {
            if sym.receiver_is_pointer {
                format!("*{r}")
            } else {
                r.clone()
            }
        });
        Some(DemanglingResult {
            original: mangled.to_owned(),
            demangled: sym.demangled,
            abi: ManglingAbi::Go,
            namespace,
            class,
            function: sym.function_name,
            args: Vec::new(),
            return_type: None,
        })
    }
}

/// Additional language runtimes (JNI, Objective-C, gfortran, GNAT Ada,
/// OCaml, GHC Haskell, decorated C). Strict detectors; see
/// [`crate::lang_extra`].
pub struct LangExtraDemangler;

impl Demangler for LangExtraDemangler {
    fn detect(&self, mangled: &str) -> bool {
        self.demangle(mangled).is_some()
    }

    fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        // One shared byte scan gates all detector families in both modules.
        let features = crate::lang_extra::SymFeatures::scan(mangled);
        if let Some(r) = crate::lang_extra::demangle_extra_with(mangled, &features) {
            return Some(r);
        }
        // Long-tail language groups (JVM, Pascal, HPC, scripting, …).
        let (demangled, language) = crate::lang_more::demangle_more_with(mangled, &features)?;
        let abi = match language {
            l if l.contains("Fortran") => ManglingAbi::Fortran,
            l if l.contains("Haskell") => ManglingAbi::Haskell,
            _ => ManglingAbi::Unknown,
        };
        // Same decomposition as the `lang_extra` path, from the one shared
        // helper. These two builders previously disagreed in opposite
        // directions — this one put the whole descriptive rendering in
        // `function`, the other left it empty — which is the duplicated-dispatch
        // shape this crate has paid for repeatedly.
        let (namespace, function) = crate::lang_extra::split_convention_rendering(&demangled);
        // The C++-family decoders here (cfront, Watcom, Borland) render a full
        // signature, and `args` was hard-coded empty: `f__Fic` rendered
        // `f(int, char)` while reporting ZERO parameters. Reading the field
        // gave a different arity from reading the string.
        let args = crate::lang_extra::split_convention_args(&demangled);
        // Kotlin/Native renders its return type after the parameter list
        // (`a.B.c(kotlin.Int): kotlin.Any?`), and the field said `None`. Taken
        // from the rendering only when it follows the signature, so a
        // descriptive prose rendering (`lua module open: socket.core`) — whose
        // `: ` precedes a PATH, not a type — is untouched.
        let return_type = crate::lang_extra::split_convention_return(&demangled);
        Some(DemanglingResult {
            original: mangled.to_owned(),
            function,
            demangled,
            abi,
            namespace,
            class: None,
            args,
            return_type,
        })
    }
}

// ── Linker-generated wrapper symbols ─────────────────────────────────────────

/// Prefixes the linker/compiler attaches to an otherwise-normal mangled name
/// to denote an indirection rather than the entity itself.
///
/// `.refptr.` is emitted by mingw-w64's ld for references that must go through
/// a pointer; `__imp_` is the PE import-table thunk. Both can nest
/// (`.refptr.__imp_foo`), which the caller handles by recursing.
///
/// `__emutls_v.` and `__emutls_t.` are GCC's emulated-TLS symbols for a
/// thread-local variable: respectively its control object and its initialiser
/// template. They belong here for the same reason as `.refptr.` — the payload
/// is an ordinary mangled name and the prefix denotes an indirection to it,
/// not the entity itself.
///
/// Without them the permissive Go backend claimed
/// `__emutls_v._ZZN12_GLOBAL__N_1L10get_globalEvE6global` (it contains dots)
/// and echoed it back unchanged, reporting `abi: Go` for a C++ thread-local
/// and counting an identity echo as a decode. The payload alone already
/// decoded correctly as Itanium, so the capability was present all along and
/// only the prefix stood in the way.
const LINKER_WRAPPERS: [&str; 4] = [".refptr.", "__imp_", "__emutls_v.", "__emutls_t."];

/// Split a linker wrapper prefix off `s`, returning `(prefix, payload)`.
///
/// Returns `None` when `s` carries no such prefix, or when the payload would
/// be empty. The payload is NOT validated here: the caller decides whether it
/// decodes, so a wrapper around a plain C name (`.refptr._CRT_MT`) is still
/// correctly declined rather than reported as a decoded symbol.
///
/// Public so that tests reasoning about wrapped symbols can strip the prefix
/// through this function instead of keeping their own list. `abi_labelling.rs`
/// hardcoded `.refptr.`/`__imp_` and broke the moment `__emutls_v.` was added
/// — a second copy of a rule that drifted from the first, which is the defect
/// shape this crate has paid for repeatedly.
#[must_use]
pub fn split_linker_wrapper(s: &str) -> Option<(&str, &str)> {
    // Runs on every symbol, so gate on the first byte before comparing whole
    // prefixes: `.refptr.` and `__imp_` start with `.` and `_` respectively,
    // and the overwhelming majority of symbols match neither shape.
    if !matches!(s.as_bytes().first(), Some(b'.' | b'_')) {
        return None;
    }
    LINKER_WRAPPERS.iter().find_map(|p| {
        let rest = s.strip_prefix(p)?;
        (!rest.is_empty()).then_some((*p, rest))
    })
}

// ── GCC IPA clone suffixes ───────────────────────────────────────────────────

/// Tags GCC uses when interprocedural optimisation creates a clone of a
/// function, always followed by the clone's index: `foo.isra.0`, `foo.part.0`,
/// `foo.constprop.0.isra.0`.
const CLONE_TAGS_WITH_INDEX: [&str; 4] = ["isra", "part", "constprop", "lto_priv"];

/// Clone tags that stand alone, with no index segment: `foo.part.0.cold`.
const CLONE_TAGS_BARE: [&str; 2] = ["cold", "localalias"];

/// Tags whose index must be NUMERIC: LLVM's `ThinLTO` suffix `.llvm.<number>`.
///
/// Kept apart from [`CLONE_TAGS_WITH_INDEX`] because `llvm` is a plausible Go
/// package or type name, while `.llvm.` followed by a decimal number is not.
/// Without the digit test, `main.llvm.Foo` would be read as a clone of `main`.
const CLONE_TAGS_WITH_NUMERIC_INDEX: [&str; 1] = ["llvm"];

/// Split a GCC clone suffix off `s`, returning `(base, suffix)`.
///
/// A clone suffix is decisive evidence that the name is a C/C++ symbol: Go
/// never emits one. The caller therefore handles such names exclusively and
/// must not fall through to the permissive Go detector, which would otherwise
/// claim them (they contain dots) and invent closure structure that is not
/// there — `__pformat_int.isra.0` became `__pformat_int.isra {closure-1 #?}`.
pub fn split_clone_suffix(s: &str) -> Option<(&str, &str)> {
    // One pass over dot-separated segments, not one substring search per
    // marker. This runs on every symbol the strict backends decline, which
    // includes every Go name — and Go names are dotted by construction, so
    // searching for `.isra.` and friends individually cost the Go path 2.2×
    // (758ns → 1.69µs) before this was rewritten.
    let mut offset = 0usize;
    let mut segments = s.split('.').peekable();
    // The first segment is the base name and can never be a tag: a leading
    // marker would leave an empty base.
    if let Some(first) = segments.next() {
        offset += first.len();
    }
    while let Some(seg) = segments.next() {
        let is_clone = if CLONE_TAGS_WITH_INDEX.contains(&seg) {
            // The index segment must be present, mirroring the `.isra.` form:
            // a trailing bare `.isra` is not something GCC emits, and a Go
            // package could legitimately end in such a word.
            segments.peek().is_some()
        } else if CLONE_TAGS_WITH_NUMERIC_INDEX.contains(&seg) {
            // `.llvm.<number>` was missing entirely, so a `ThinLTO`-suffixed
            // symbol was not recognised as a C-family name and fell through to
            // the permissive Go detector: `_D4main3fooFZv.llvm.1234567890` was
            // reported as **Go**, with the raw mangling echoed as its own
            // "demangling". `.cold` and `.part.0` worked, which is what made
            // the gap invisible — the table was right for every tag in it.
            segments
                .peek()
                .is_some_and(|idx| !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit()))
        } else {
            CLONE_TAGS_BARE.contains(&seg)
        };
        if is_clone {
            return Some((&s[..offset], &s[offset..]));
        }
        offset += seg.len() + 1; // segment plus its leading `.`
    }
    None
}

/// Whether `s` names a linker constant pool entry: `$f64.3ff0000000000000`.
///
/// The Go linker parks literal constants under `$<type>.<hex bits>`. These are
/// storage, not code, and there is nothing to demangle — the Go detector used
/// to claim them (they contain a dot) and echo them back unchanged, which
/// counted as a decode while conveying nothing.
fn is_linker_constant_pool(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('$') else {
        return false;
    };
    let Some((tag, bits)) = rest.split_once('.') else {
        return false;
    };
    matches!(tag, "f32" | "f64" | "i32" | "i64")
        && !bits.is_empty()
        && bits.chars().all(|c| c.is_ascii_hexdigit())
}

// ── AutoDemangler ─────────────────────────────────────────────────────────────

/// Tries all known demanglers in order and returns the first successful result.
///
/// Order matters: schemes with strict prefixes (Rust, Itanium, MSVC, Swift, D)
/// are tried before Go, whose detection is deliberately permissive (any name
/// containing a `.`) and would otherwise shadow them.
pub struct AutoDemangler {
    /// Backends whose detection is a strict prefix or grammar check.
    strict: Vec<Box<dyn Demangler>>,
    /// Backends that may claim a name on weak evidence. Tried only after
    /// every strict backend has declined, and after clone-suffix handling.
    permissive: Vec<Box<dyn Demangler>>,
}

impl Default for AutoDemangler {
    fn default() -> Self {
        Self {
            strict: vec![
                Box::new(RustDemangler),
                Box::new(ItaniumDemangler),
                Box::new(MsvcDemangler),
                Box::new(SwiftDemangler),
                Box::new(DLangDemangler),
                Box::new(LangExtraDemangler),
            ],
            // Go detection accepts any name containing a `.`, so it must see
            // a symbol only once nothing else can explain it.
            permissive: vec![Box::new(GoLangDemangler)],
        }
    }
}

impl AutoDemangler {
    /// Create a new `AutoDemangler` with the default ordered set of demanglers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to demangle `mangled` with each registered demangler in order.
    #[must_use]
    pub fn demangle(&self, mangled: &str) -> Option<DemanglingResult> {
        if let Some((prefix, inner)) = split_linker_wrapper(mangled) {
            // Linker-generated indirection symbol wrapping a real mangled
            // name. Decode the payload and re-attach the prefix verbatim, so
            // the result stays distinguishable from the function itself —
            // `.refptr.f` is a pointer to `f`, not `f`.
            let mut r = self.demangle(inner)?;
            mangled.clone_into(&mut r.original);
            r.demangled = format!("{prefix}{}", r.demangled);
            // `function` names the final component and is deliberately left
            // alone: the prefix qualifies the whole symbol, so prefixing both
            // made them disagree — `.refptr.~bad_typeid` is nowhere inside
            // `.refptr.std::bad_typeid::~bad_typeid()`. The indirection is
            // recorded in `demangled` and `original`.
            return Some(r);
        }
        // A leading `.` marks a PE/COFF section name, not a symbol —
        // `.text`, `.pdata$_ZL17parse_lsda_header…`, `.debug_info`. Go, the
        // one scheme whose names contain dots, never starts with one, and
        // `.refptr.` was already handled above.
        //
        // Without this the GHC detector claimed
        // `.pdata$_ZL17parse_lsda_headerP15_Unwind_ContextPKhP16lsda_header_info`
        // — it carries `ZL`, which is a Z-encoded `(`, and ends in `_info`
        // like a real GHC closure — and emitted
        // `.pdata$:(17parse_lsda_header…lsda.header (info)`. This also makes
        // the decoder agree with `decline_reason`, which already files every
        // leading-dot name as `LinkerSection`.
        if mangled.starts_with('.') {
            return None;
        }
        // A single `demangle` call per backend: every implementation re-checks
        // its own detection internally, and a separate `detect` pass would run
        // the full decode twice for backends whose detection *is* the decode
        // (e.g. `LangExtraDemangler`).
        let clone = split_clone_suffix(mangled);
        for d in &self.strict {
            if let Some(r) = d.demangle(mangled) {
                // A backend that claimed a clone-suffixed name must have
                // ACCOUNTED for the suffix. Several swallowed it into the name
                // instead, because a dot is ordinary inside their grammar:
                //
                //   Java_com_foo_Bar_baz.cold  ->  com.foo.Bar.baz.cold
                //                                  function == "cold"
                //   $s4main3fooyyFTA.cold      ->  main.foo() -> ()
                //
                // The JNI method was RENAMED to the clone tag, and Swift lost
                // both the tag and the `[TA]` operator suffix, collapsing five
                // distinct symbols onto one rendering.
                //
                // The test is `[clone `, this crate's own formatting (and
                // `cpp_demangle`'s), not the suffix text: a rendering that
                // merely ends in `.cold` may have absorbed it rather than
                // reported it. Backends that format their own clones — Itanium
                // through the oracle — keep doing so; the rest fall through to
                // the shared wrapper below.
                // Itanium and Rust are ORACLE-BACKED and handle suffixes
                // themselves, each in its own way: `cpp_demangle` writes
                // `[clone .cold]`, while `rustc-demangle` appends `.cold`
                // inline and DROPS `.llvm.<hash>` entirely. Second-guessing
                // either would undo iter 127, whose whole point was that the
                // oracle decides. The rule applies to the rest.
                let oracle_backed = matches!(
                    r.abi,
                    ManglingAbi::Itanium | ManglingAbi::Rust
                );
                if clone.is_none() || oracle_backed || r.demangled.contains("[clone ") {
                    return Some(r);
                }
                break;
            }
        }
        if let Some((base, suffix)) = clone {
            // A GCC clone suffix proves the name is C/C++, so this is
            // exclusive: decode the base or decline. Falling through would let
            // the Go detector claim it on the strength of a dot and invent
            // closure structure that is not in the symbol. When the base is a
            // plain C name there is nothing to decode, and declining is what
            // `c++filt` does too.
            //
            // Reached only after the strict backends declined the whole name,
            // so Itanium symbols keep `cpp_demangle`'s own clone formatting.
            // `split_clone_suffix` cuts at the leftmost marker, so `base`
            // never carries one itself and no recursion is needed.
            let mut r = self.demangle_strict(base)?;
            mangled.clone_into(&mut r.original);
            r.demangled = format!("{} [clone {suffix}]", r.demangled);
            return Some(r);
        }
        if is_linker_constant_pool(mangled) {
            return None;
        }
        for d in &self.permissive {
            if let Some(r) = d.demangle(mangled) {
                return Some(r);
            }
        }
        None
    }

    /// Run only the strict backends against `mangled`.
    fn demangle_strict(&self, mangled: &str) -> Option<DemanglingResult> {
        self.strict.iter().find_map(|d| d.demangle(mangled))
    }
}

// ── Convenience function ──────────────────────────────────────────────────────

/// Attempt to demangle `s` using the shared `AutoDemangler`.
///
/// The demangler set is built once per process and reused, so repeated calls
/// do not re-allocate the backend list.
///
/// Returns `None` if no demangler recognised the symbol.
#[must_use]
pub fn demangle(s: &str) -> Option<DemanglingResult> {
    static SHARED: std::sync::OnceLock<AutoDemangler> = std::sync::OnceLock::new();
    let r = SHARED.get_or_init(AutoDemangler::default).demangle(s)?;
    // A decode must carry a NAME. `Some("")` hands the caller a success with no
    // symbol in it — the exact failure the Obj-C backend's own comment warns
    // about — and the crate already enforces this per-ABI (Obj-C's empty
    // payloads, Swift's `?module`, D's `?`). Stating it once here covers the
    // ones that were missed: `_RNvC0_0_` (zero-length crate AND value name)
    // rendered the empty string, and `Java__` rendered a lone `.`.
    //
    // Deliberately narrow: it rejects only renderings with no alphanumeric
    // character at all, so an operator name (`clojure.core/+`, MSVC
    // `operator+`) is untouched. It also does NOT contradict an oracle on any
    // real symbol — `rustc-demangle` renders `_RNvC0_0_` as the empty string
    // too, but rustc never emits such a name, so declining a degenerate input
    // costs nothing while keeping `DeclineReason::Decoded` meaningful.
    if !r.demangled.chars().any(char::is_alphanumeric) {
        return None;
    }
    Some(r)
}
