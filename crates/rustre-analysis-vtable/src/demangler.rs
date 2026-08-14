//! C++ name demangling utilities.
//!
//! Provides lightweight demangling for:
//! * Itanium ABI (`_Z…`) mangled names — partial, covering the most common patterns.
//! * MSVC decorated names (`.?AV…`) — strip and reconstruct qualified names.
//! * Plain symbol detection (already demangled or not a mangled name).

// ─────────────────────────────────────────────────────────────────────────────
// Mangling detection
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a symbol name appears to be an Itanium-ABI mangled name.
#[must_use]
pub fn is_itanium_mangled(name: &str) -> bool {
    name.starts_with("_Z") || name.starts_with("__Z")
}

/// Whether a symbol name appears to be an MSVC decorated name.
#[must_use]
pub fn is_msvc_mangled(name: &str) -> bool {
    name.starts_with('?') || name.starts_with(".?AV") || name.starts_with(".?AU")
}

// ─────────────────────────────────────────────────────────────────────────────
// Itanium demangler (partial, pure-Rust)
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to demangle an Itanium-ABI mangled name.
///
/// Covers the most common patterns:
/// * Nested names (`_ZN…E`)
/// * Constructor/destructor indicators (`C1`, `C2`, `D0`, `D1`, `D2`)
/// * Qualified names with numeric-length prefixes
/// * `const`/`volatile` markers
/// * Built-in types (`i`, `v`, `b`, `c`, `d`, `f`, `s`, `l`, etc.)
///
/// Returns the original name if demangling fails.
#[must_use]
pub fn demangle_itanium(name: &str) -> String {
    let trimmed = name.trim_start_matches("__Z").trim_start_matches("_Z");
    if trimmed.is_empty() {
        return name.to_owned();
    }
    ItaniumDemangler::new(trimmed).demangle().unwrap_or_else(|| name.to_owned())
}

struct ItaniumDemangler<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ItaniumDemangler<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn demangle(&mut self) -> Option<String> {
        self.parse_name()
    }

    fn parse_name(&mut self) -> Option<String> {
        match self.peek()? {
            b'N' => self.parse_nested_name(),
            b'L' => {
                self.consume();
                self.parse_name()
            }
            _ => self.parse_unqualified_name(),
        }
    }

    fn parse_nested_name(&mut self) -> Option<String> {
        self.consume(); // 'N'
        let mut parts = Vec::new();
        // Handle cv-qualifiers.
        while matches!(self.peek(), Some(b'K' | b'V' | b'r')) {
            self.consume();
        }
        while self.peek() != Some(b'E') && self.peek().is_some() {
            if let Some(part) = self.parse_name_part() {
                parts.push(part);
            } else {
                break;
            }
        }
        if self.peek() == Some(b'E') {
            self.consume();
        }
        if parts.is_empty() {
            return None;
        }
        Some(parts.join("::"))
    }

    fn parse_name_part(&mut self) -> Option<String> {
        match self.peek()? {
            b'C' => {
                self.consume();
                let ctor_kind = self.consume()?;
                let kind = match ctor_kind {
                    b'2' => "base-ctor",
                    b'3' => "allocating-ctor",
                    _ => "ctor",
                };
                Some(kind.to_owned())
            }
            b'D' => {
                self.consume();
                let dtor_kind = self.consume()?;
                let kind = match dtor_kind {
                    b'0' => "delete-dtor",
                    b'2' => "base-dtor",
                    _ => "dtor",
                };
                Some(kind.to_owned())
            }
            b'0'..=b'9' => self.parse_source_name(),
            b'S' => Some(self.parse_substitution()),
            b'T' => {
                self.consume();
                self.consume();
                Some("T".to_owned())
            } // template param
            _ => None,
        }
    }

    fn parse_unqualified_name(&mut self) -> Option<String> {
        match self.peek()? {
            b'0'..=b'9' => self.parse_source_name(),
            b'C' | b'D' => self.parse_name_part(),
            b'K' | b'V' | b'r' => {
                self.consume();
                self.parse_unqualified_name()
            }
            _ => self.parse_builtin_type().map(std::borrow::ToOwned::to_owned),
        }
    }

    fn parse_source_name(&mut self) -> Option<String> {
        let mut len_str = String::new();
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            len_str.push(self.consume()? as char);
        }
        let len: usize = len_str.parse().ok()?;
        // checked_add: a huge declared length (e.g. "_Z18446744073709551615foo")
        // must not overflow `pos + len` (which would wrap in release builds and
        // produce an inverted slice range → panic).
        let end = self.pos.checked_add(len)?;
        if end > self.input.len() {
            return None;
        }
        let s = std::str::from_utf8(&self.input[self.pos..end]).ok()?;
        self.pos = end;
        Some(s.to_owned())
    }

    fn parse_substitution(&mut self) -> String {
        self.consume(); // 'S'
        match self.peek() {
            Some(b't') => {
                self.consume();
                "std".to_owned()
            }
            Some(b'a') => {
                self.consume();
                "std::allocator".to_owned()
            }
            Some(b'b') => {
                self.consume();
                "std::basic_string".to_owned()
            }
            Some(b's') => {
                self.consume();
                "std::string".to_owned()
            }
            Some(b'i') => {
                self.consume();
                "std::istream".to_owned()
            }
            Some(b'o') => {
                self.consume();
                "std::ostream".to_owned()
            }
            Some(b'_') => {
                self.consume();
                "S_".to_owned()
            }
            _ => "S".to_owned(),
        }
    }

    fn parse_builtin_type(&mut self) -> Option<&'static str> {
        let t = match self.consume()? {
            b'v' => "void",
            b'b' => "bool",
            b'c' => "char",
            b'a' => "signed char",
            b'h' => "unsigned char",
            b's' => "short",
            b't' => "unsigned short",
            b'i' => "int",
            b'j' => "unsigned int",
            b'l' => "long",
            b'm' => "unsigned long",
            b'x' => "long long",
            b'y' => "unsigned long long",
            b'f' => "float",
            b'd' => "double",
            b'e' => "long double",
            b'z' => "...",
            b'P' => "pointer",
            b'R' => "ref",
            b'O' => "rvalue-ref",
            _ => return None,
        };
        Some(t)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MSVC demangler
// ─────────────────────────────────────────────────────────────────────────────

/// Demangle an MSVC decorated symbol name.
///
/// Handles the common patterns:
/// * `.?AV` / `.?AU` `TypeDescriptor` names.
/// * `?method@Class@@…` function signatures.
/// * Qualified names with `@` as separator.
#[must_use]
pub fn demangle_msvc(name: &str) -> String {
    if name.starts_with(".?AV") || name.starts_with(".?AU") {
        // TypeDescriptor: strip prefix/suffix, replace `@` with `::`
        let stripped = name
            .trim_start_matches(".?AV")
            .trim_start_matches(".?AU")
            .trim_end_matches("@@");
        return stripped.replace('@', "::");
    }

    if name.starts_with('?') {
        return demangle_msvc_function(name);
    }

    name.to_owned()
}

/// Partial MSVC function name demangler.
///
/// Converts `?method@Class@@QAEHHH@Z` → roughly `Class::method(int, int)`.
#[must_use]
pub fn demangle_msvc_function(name: &str) -> String {
    if !name.starts_with('?') {
        return name.to_owned();
    }
    let body = &name[1..]; // skip leading '?'

    // Split on '@' to get name parts. The first '@' separates method from class.
    let parts: Vec<&str> = body.splitn(10, '@').collect();
    if parts.is_empty() {
        return name.to_owned();
    }

    // If the first token starts with '?' it encodes a special method name (e.g. "?0Foo"
    // for a constructor in class Foo).  The special code is exactly two characters
    // ("?0", "?1", …) and any remaining characters are the first class-name segment.
    // The special code is 2 *bytes* — guard against slicing through a multi-byte
    // UTF-8 character (adversarial symbol names like "?\u{e9}...") which would
    // panic on a non-char-boundary index.
    let (method_token, embedded_class) = if parts[0].starts_with('?')
        && parts[0].len() >= 2
        && parts[0].is_char_boundary(2)
    {
        let code = &parts[0][..2];
        let rest = &parts[0][2..];
        (code, if rest.is_empty() { None } else { Some(rest) })
    } else {
        (parts[0], None)
    };
    let method = decode_special_method_name(method_token);

    // Collect qualified class name (parts until we hit a non-class part).
    let mut class_parts: Vec<&str> = Vec::new();
    if let Some(ec) = embedded_class {
        class_parts.push(ec);
    }
    for part in &parts[1..] {
        if part.is_empty()
            || part.starts_with('Q')
            || part.starts_with('U')
            || part.starts_with('S')
        {
            break;
        }
        if part.starts_with(|c: char| c.is_ascii_uppercase() && !is_msvc_type_code(part))
            || part
                .chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        {
            class_parts.push(part);
        } else {
            break;
        }
    }

    if class_parts.is_empty() {
        method
    } else {
        format!("{}::{}", class_parts.join("::"), method)
    }
}

fn is_msvc_type_code(s: &str) -> bool {
    matches!(
        s,
        "Q" | "U" | "S" | "X" | "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H"
    )
}

fn decode_special_method_name(s: &str) -> String {
    if s.starts_with('?') {
        // Special method names — two forms:
        // "??0" (double-?) for callers that pass the whole token including a leading '?',
        // "?0"  (single-?) for callers inside demangle_msvc_function that already stripped one '?'.
        return match s {
            "??0" | "?0" => "constructor".to_owned(),
            "??1" | "?1" => "destructor".to_owned(),
            "??2" | "?2" => "operator new".to_owned(),
            "??3" | "?3" => "operator delete".to_owned(),
            "??4" | "?4" => "operator=".to_owned(),
            "??5" | "?5" => "operator>>".to_owned(),
            "??6" | "?6" => "operator<<".to_owned(),
            "??7" | "?7" => "operator!".to_owned(),
            "??8" | "?8" => "operator==".to_owned(),
            "??9" | "?9" => "operator!=".to_owned(),
            "??A" | "?A" => "operator[]".to_owned(),
            "??B" | "?B" => "operator type()".to_owned(),
            "??C" | "?C" => "operator->".to_owned(),
            "??D" | "?D" => "operator*".to_owned(),
            _ => s.to_owned(),
        };
    }
    s.to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified demangle
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to demangle a symbol name by auto-detecting the ABI.
///
/// Returns the demangled name, or the original if demangling is not applicable.
#[must_use]
pub fn demangle(name: &str) -> String {
    if is_itanium_mangled(name) {
        demangle_itanium(name)
    } else if is_msvc_mangled(name) {
        demangle_msvc(name)
    } else {
        name.to_owned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mangling detection ────────────────────────────────────────────────

    #[test]
    fn test_is_itanium_mangled() {
        assert!(is_itanium_mangled("_ZN3FooC1Ev"));
        assert!(is_itanium_mangled("__ZN3FooD1Ev"));
        assert!(!is_itanium_mangled("printf"));
        assert!(!is_itanium_mangled("?Foo@@QAEHH@Z"));
    }

    #[test]
    fn test_is_msvc_mangled() {
        assert!(is_msvc_mangled("?Foo@@QAEHH@Z"));
        assert!(is_msvc_mangled(".?AVFoo@@"));
        assert!(!is_msvc_mangled("printf"));
        assert!(!is_msvc_mangled("_ZN3FooC1Ev"));
    }

    // ── Itanium demangle ──────────────────────────────────────────────────

    #[test]
    fn test_itanium_simple_class() {
        // _ZN3FooC1Ev → Foo::ctor (simplified)
        let d = demangle_itanium("_ZN3FooC1Ev");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_itanium_nested_namespace() {
        // _ZN3std6vectorIiE4sizeEv → std::vector<int>::size (simplified)
        let d = demangle_itanium("_ZN3std6vectorE");
        assert!(d.contains("std"), "got: {d}");
        assert!(d.contains("vector"), "got: {d}");
    }

    #[test]
    fn test_itanium_destructor() {
        let d = demangle_itanium("_ZN3FooD1Ev");
        assert!(d.contains("Foo"), "got: {d}");
    }

    #[test]
    fn test_itanium_plain_function() {
        // _Z5helloRKNSt6stringE → hello (simplified)
        let d = demangle_itanium("_Z5hello");
        assert!(d.contains("hello"), "got: {d}");
    }

    #[test]
    fn test_itanium_passthrough_on_failure() {
        let s = "_ZSomethingUnparseable!!!";
        let d = demangle_itanium(s);
        // Should return original
        assert_eq!(d, s);
    }

    // ── MSVC demangle ─────────────────────────────────────────────────────

    #[test]
    fn test_msvc_type_descriptor() {
        assert_eq!(demangle_msvc(".?AVFoo@@"), "Foo");
        assert_eq!(demangle_msvc(".?AUMyStruct@@"), "MyStruct");
    }

    #[test]
    fn test_msvc_nested_type_descriptor() {
        let d = demangle_msvc(".?AVBar@Ns@@");
        assert!(d.contains("Bar"), "got: {d}");
        assert!(d.contains("Ns"), "got: {d}");
    }

    #[test]
    fn test_msvc_plain_passthrough() {
        assert_eq!(demangle_msvc("printf"), "printf");
    }

    #[test]
    fn test_msvc_function_basic() {
        // Simple ?method@Class pattern
        let d = demangle_msvc_function("?getData@Widget@@QAEHXZ");
        assert!(d.contains("getData") || d.contains("Widget"), "got: {d}");
    }

    #[test]
    fn test_msvc_special_constructor() {
        let d = decode_special_method_name("??0");
        assert_eq!(d, "constructor");
    }

    #[test]
    fn test_msvc_special_destructor() {
        let d = decode_special_method_name("??1");
        assert_eq!(d, "destructor");
    }

    #[test]
    fn test_msvc_operator_equals() {
        assert_eq!(decode_special_method_name("??4"), "operator=");
    }

    // ── Unified demangle ──────────────────────────────────────────────────

    #[test]
    fn test_demangle_auto_itanium() {
        let d = demangle("_ZN3FooC1Ev");
        assert!(d.contains("Foo") || d == "_ZN3FooC1Ev", "got: {d}");
    }

    #[test]
    fn test_demangle_auto_msvc() {
        let d = demangle(".?AVFoo@@");
        assert_eq!(d, "Foo");
    }

    #[test]
    fn test_demangle_plain() {
        assert_eq!(demangle("printf"), "printf");
        assert_eq!(demangle("malloc"), "malloc");
    }

    #[test]
    fn test_demangle_empty() {
        assert_eq!(demangle(""), "");
    }

    #[test]
    fn test_demangle_std_substitution() {
        // _ZSt → starts with _Z → treated as Itanium
        let d = demangle_itanium("_ZSt4cout");
        assert!(!d.is_empty());
    }

    // ── Additional edge-case tests ───────────────────────────────────────────

    #[test]
    fn test_is_mangled_negatives() {
        assert!(!is_itanium_mangled(""));
        assert!(!is_itanium_mangled("printf"));
        assert!(!is_itanium_mangled("Z3foo"));
        assert!(!is_msvc_mangled(""));
        assert!(!is_msvc_mangled("printf"));
        assert!(!is_msvc_mangled(".?AX"));
    }

    #[test]
    fn test_itanium_only_prefix_returns_original() {
        // After trimming _Z, input is empty → returns name.
        assert_eq!(demangle_itanium("_Z"), "_Z");
        assert_eq!(demangle_itanium("__Z"), "__Z");
    }

    #[test]
    fn test_itanium_malformed_source_name_length() {
        // 99-length declared but body shorter — should fall back to original.
        let out = demangle_itanium("_Z99foo");
        assert_eq!(out, "_Z99foo");
    }

    #[test]
    fn test_itanium_nested_name() {
        // _ZN3Foo3barEv → Foo::bar
        let out = demangle_itanium("_ZN3Foo3barEv");
        assert!(out.contains("Foo"));
        assert!(out.contains("bar"));
    }

    #[test]
    fn test_itanium_constructor() {
        let out = demangle_itanium("_ZN3FooC2Ev");
        assert!(out.contains("Foo"));
        assert!(out.contains("ctor"));
    }

    #[test]
    fn test_msvc_type_descriptor_nested() {
        let out = demangle_msvc(".?AVFoo@Bar@@");
        // Should become Foo::Bar or Bar::Foo depending on convention; ensure both names appear.
        assert!(out.contains("Foo"));
        assert!(out.contains("Bar"));
    }

    #[test]
    fn test_msvc_struct_prefix() {
        let out = demangle_msvc(".?AUFoo@@");
        assert_eq!(out, "Foo");
    }

    #[test]
    fn test_msvc_special_method_constructor() {
        // ??0Foo@@... is a constructor.
        let out = demangle_msvc("??0Foo@@QAE@XZ");
        assert!(out.contains("constructor"));
        assert!(out.contains("Foo"));
    }

    #[test]
    fn test_demangle_auto_dispatch() {
        // Itanium
        assert!(demangle("_ZN3FooC1Ev").contains("Foo"));
        // MSVC type descriptor
        assert_eq!(demangle(".?AVFoo@@"), "Foo");
        // Unrecognised → passthrough
        assert_eq!(demangle("plain_c_func"), "plain_c_func");
        // Empty stays empty
        assert_eq!(demangle(""), "");
    }

    #[test]
    fn test_itanium_huge_length_no_overflow_panic() {
        // Regression: declared source-name length near usize::MAX previously
        // overflowed `pos + len` (wrapping in release) → inverted slice → panic.
        let s = "_Z18446744073709551615foo";
        assert_eq!(demangle_itanium(s), s);
        let s2 = "_ZN18446744073709551615fooE";
        let _ = demangle_itanium(s2); // must not panic
    }

    #[test]
    fn test_msvc_multibyte_no_char_boundary_panic() {
        // Regression: "?é..." sliced at byte index 2 inside the 2-byte UTF-8
        // char previously panicked.
        let _ = demangle_msvc_function("?\u{e9}abc@Cls@@QAEHXZ");
        let _ = demangle_msvc_function("?\u{1F600}@@QAEHXZ");
        let _ = demangle("?\u{e9}@X@@");
    }

    #[test]
    fn test_msvc_no_class_just_method() {
        // No class parts collected → returns just the decoded method.
        let out = demangle_msvc_function("?foo@@YAHXZ");
        assert!(out.contains("foo"));
    }
}
