//! Language wrappers: the D language demangler and the Rust v0 demangler.

use std::fmt::Write as _;

// ── D language demangler ──────────────────────────────────────────────────────

/// Demangler for D language mangled names (`_D` prefix).
pub struct DDemangler;

impl DDemangler {
    /// Detect D-mangled name.
    #[must_use] 
    pub fn detect(mangled: &str) -> bool {
        // `_D` alone is not enough. The D ABI follows it with a
        // `QualifiedName`, which begins with a length-prefixed identifier —
        // `_D4main3fooFZv`, `_D3std5stdio7writelnFiZv` — so the next byte is a
        // digit.
        //
        // Without that, every C name starting with `_D` was classified as D
        // and, since no backend could decode it, reported as an unhandled
        // mangled symbol: `_DllMainCRTStartup` — the entry point of every
        // Windows DLL — was filed as a D defect. Phantom defects are what hide
        // real ones, and this is the same mistake `_R` made for Rust
        // (`_RTC_Initialize`) and `_T` for Swift (`_TIFFOpen`).
        //
        // Delegates to the grammar parser's own `detect` rather than calling
        // `sigil::is_d` directly, so there is one D detection rule instead of
        // two. The sigil check alone accepted a truncated `_D4` — a length
        // prefix with nothing after it — which this `demangle` then declined.
        // The sigil rule is necessary but not sufficient: it accepts symbols
        // the grammar parser then rejects — a length prefix cutting a
        // multi-byte character, trailing bytes after a complete symbol — and a
        // `detect` that promises more than `demangle` delivers is worse than
        // one that is merely loose, because `if detect(s) { demangle(s).unwrap() }`
        // panics on the difference. That idiom once broke 89 corpus symbols here.
        //
        // This wrapper is standalone public API, not part of `AutoDemangler`'s
        // dispatch (which uses `d_demangler::DDemangler::detect` directly), so
        // confirming with a real parse costs nothing on the hot path.
        crate::d_demangler::DDemangler::detect(mangled) && Self::demangle_inner(mangled).is_some()
    }

    /// The parse itself, shared by `detect` and `demangle` so the two cannot
    /// answer differently.
    fn demangle_inner(mangled: &str) -> Option<String> {
        if let Ok(sym) = crate::d_demangler::DDemangler::new(mangled).demangle() {
            return Some(sym.demangled);
        }
        let rest = &mangled
            .strip_prefix('_')
            .filter(|s| s.starts_with("_D"))
            .unwrap_or(mangled)[2..];
        DParser::new(rest).parse_symbol()
    }

    /// Demangle a D-language symbol.
    ///
    /// Delegates to the full [`crate::d_demangler`] grammar parser; the small
    /// local [`DParser`] is only a fallback. The two disagreed badly before
    /// this delegation: the local parser rendered `_D4main3fooFZv` as
    /// `main.foo -> ?(F)` where the full parser yields `void main.foo()`.
    #[must_use]
    pub fn demangle(mangled: &str) -> Option<String> {
        // The sigil gate first, then the shared parse — `detect` applies the
        // same two steps, so they cannot disagree.
        //
        // The Mach-O `__D…` form is normalised inside
        // `d_demangler::DDemangler::new`, which both D wrappers delegate to.
        if !crate::d_demangler::DDemangler::detect(mangled) {
            return None;
        }
        Self::demangle_inner(mangled)
    }
}

struct DParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> DParser<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn parse_number(&mut self) -> Option<usize> {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        std::str::from_utf8(&self.input[start..self.pos])
            .ok()?
            .parse()
            .ok()
    }

    fn parse_identifier(&mut self) -> Option<String> {
        let len = self.parse_number()?;
        if self.pos + len > self.input.len() {
            return None;
        }
        let s = std::str::from_utf8(&self.input[self.pos..self.pos + len])
            .ok()?
            .to_owned();
        self.pos += len;
        Some(s)
    }

    fn parse_qualified_name(&mut self) -> Vec<String> {
        let mut parts = Vec::new();
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            if let Some(p) = self.parse_identifier() {
                parts.push(p);
            } else {
                break;
            }
        }
        parts
    }

    fn parse_type_suffix(&mut self) -> String {
        match self.next() {
            Some(b'v') => "void".to_owned(),
            Some(b'b') => "bool".to_owned(),
            Some(b'g') => "byte".to_owned(),
            Some(b'h') => "ubyte".to_owned(),
            Some(b's') => "short".to_owned(),
            Some(b't') => "ushort".to_owned(),
            Some(b'i') => "int".to_owned(),
            Some(b'k') => "uint".to_owned(),
            Some(b'l') => "long".to_owned(),
            Some(b'm') => "ulong".to_owned(),
            Some(b'f') => "float".to_owned(),
            Some(b'd') => "double".to_owned(),
            Some(b'e') => "real".to_owned(),
            Some(b'c') => "char".to_owned(),
            Some(b'u') => "wchar".to_owned(),
            Some(b'w') => "dchar".to_owned(),
            Some(b) => format!("?({})", b as char),
            None => "?".to_owned(),
        }
    }

    fn parse_symbol(&mut self) -> Option<String> {
        let parts = self.parse_qualified_name();
        if parts.is_empty() {
            return None;
        }
        let ret_type = if self.pos < self.input.len() {
            Some(self.parse_type_suffix())
        } else {
            None
        };
        let mut result = parts.join(".");
        if let Some(ret) = ret_type {
            write!(result, " -> {ret}").ok();
        }
        Some(result)
    }
}

// ── Rust V0 demangler ────────────────────────────────────────────────────────

/// Full Rust v0 demangler (RFC 2603) that parses `_R`-prefixed symbols.
pub struct RustV0Demangler;

impl RustV0Demangler {
    /// Detect Rust v0 mangled symbol.
    ///
    /// `_R` alone is not enough: RFC 2603 follows it with a path tag, and the
    /// MSVC CRT ships `_RTC_Initialize`/`_RTC_Terminate`, which are ordinary C
    /// functions. Under a bare prefix test `detect` claimed them while
    /// [`Self::demangle`] declined, so `if detect(s) { demangle(s).unwrap() }`
    /// panicked.
    ///
    /// The rule lived in five places before being centralised; every claiming
    /// site now goes through [`crate::sigil`].
    #[must_use]
    pub fn detect(mangled: &str) -> bool {
        crate::sigil::is_rust_v0(mangled)
    }

    /// Demangle a Rust v0 symbol, falling back to rustc-demangle.
    #[must_use] 
    pub fn demangle(mangled: &str) -> Option<String> {
        if !Self::detect(mangled) {
            return None;
        }
        // Prefer rustc-demangle for correctness. Use the alternate form
        // (`{:#}`), which omits the crate disambiguator — the convention the
        // rest of the crate follows. The plain form would render
        // `_RNvCs1234_7mycrate3foo` as `mycrate[3c1c0]::foo` while
        // [`crate::demangle`] returns `mycrate::foo`.
        if let Ok(sym) = rustc_demangle::try_demangle(mangled) {
            let s = format!("{sym:#}");
            if s != mangled {
                return Some(s);
            }
        }
        // Fallback: strip the _R prefix and decode manually.
        let rest = &mangled[2..];
        let mut p = RustV0Parser::new(rest);
        p.parse_path().map(|path| {
            // Strip trailing hash like ::h1234abcd
            strip_rust_hash(&path)
        })
    }
}

pub fn strip_rust_hash(s: &str) -> String {
    // Remove trailing ::h[0-9a-f]{16} suffix
    if let Some(idx) = s.rfind("::h") {
        let suffix = &s[idx + 3..];
        if suffix.len() == 16 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return s[..idx].to_owned();
        }
    }
    s.to_owned()
}

struct RustV0Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> RustV0Parser<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn consume(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_base62(&mut self) -> Option<u64> {
        let mut n: u64 = 0;
        loop {
            let b = self.peek()?;
            let digit = if b.is_ascii_digit() {
                u64::from(b - b'0')
            } else if b.is_ascii_lowercase() {
                u64::from(b - b'a') + 10
            } else if b.is_ascii_uppercase() {
                u64::from(b - b'A') + 36
            } else {
                break;
            };
            self.pos += 1;
            // Use checked arithmetic so maliciously long digit sequences return
            // None rather than silently saturating and misidentifying the symbol.
            n = n.checked_mul(62)?.checked_add(digit)?;
        }
        self.consume(b'_');
        Some(n)
    }

    fn parse_identifier(&mut self) -> Option<String> {
        let _punycode = self.consume(b'u');
        let len = {
            let start = self.pos;
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == start {
                return None;
            }
            std::str::from_utf8(&self.input[start..self.pos])
                .ok()?
                .parse::<usize>()
                .ok()?
        };
        // Optional underscore disambiguator
        self.consume(b'_');
        if self.pos + len > self.input.len() {
            return None;
        }
        let s = std::str::from_utf8(&self.input[self.pos..self.pos + len])
            .ok()?
            .to_owned();
        self.pos += len;
        Some(s)
    }

    fn parse_path(&mut self) -> Option<String> {
        self.depth += 1;
        if self.depth > 64 {
            self.depth -= 1;
            return None;
        }
        let result = self.parse_path_inner();
        self.depth -= 1;
        result
    }

    fn parse_path_inner(&mut self) -> Option<String> {
        match self.peek()? {
            b'C' => {
                // crate-root: C <identifier> <disambiguator>
                self.pos += 1;
                let name = self.parse_identifier()?;
                // optional disambiguator: s followed by base62 number
                if self.peek() == Some(b's') {
                    self.pos += 1;
                    let _ = self.parse_base62();
                }
                Some(name)
            }
            b'M' => {
                // impl: M <type> <path>
                self.pos += 1;
                let _disambig = if self.peek() == Some(b's') {
                    self.pos += 1;
                    self.parse_base62()
                } else {
                    None
                };
                let t = self.parse_type().unwrap_or_else(|| "?".to_owned());
                Some(format!("<{t}>"))
            }
            b'X' => {
                // trait impl: X <type> <path> <path>
                self.pos += 1;
                let _disambig = if self.peek() == Some(b's') {
                    self.pos += 1;
                    self.parse_base62()
                } else {
                    None
                };
                let t = self.parse_type().unwrap_or_else(|| "?".to_owned());
                let tr = self.parse_path().unwrap_or_else(|| "?".to_owned());
                Some(format!("<{t} as {tr}>"))
            }
            b'Y' => {
                // dyn-trait
                self.pos += 1;
                let tr = self.parse_path().unwrap_or_else(|| "?".to_owned());
                Some(format!("dyn {tr}"))
            }
            b'N' => {
                // nested: N <ns> <path> <identifier>
                self.pos += 1;
                let ns = self.next()? as char;
                let parent = self.parse_path().unwrap_or_default();
                let name = self.parse_identifier().unwrap_or_default();
                match ns {
                    'v' => Some(format!("{parent}::{{{name}}}{{closure}}")),
                    _ => Some(format!("{parent}::{name}")),
                }
            }
            b'I' => {
                // generic: I <path> <type>* E
                self.pos += 1;
                let path = self.parse_path().unwrap_or_default();
                let mut args = Vec::new();
                while self.peek().is_some_and(|b| b != b'E') {
                    if let Some(t) = self.parse_type() {
                        args.push(t);
                    } else {
                        break;
                    }
                }
                self.consume(b'E');
                if args.is_empty() {
                    Some(path)
                } else {
                    Some(format!("{path}<{}>", args.join(", ")))
                }
            }
            b'B' => {
                // backref
                self.pos += 1;
                let _ = self.parse_base62();
                Some("_".to_owned()) // simplified backref
            }
            _ => None,
        }
    }

    /// Decode a single-letter Rust v0 primitive-type code.
    const fn parse_primitive_type(b: u8) -> Option<&'static str> {
        match b {
            b'a' => Some("i8"),
            b'b' => Some("bool"),
            b'c' => Some("char"),
            b'd' => Some("f64"),
            b'e' => Some("str"),
            b'f' => Some("f32"),
            b'h' => Some("u8"),
            b'i' => Some("isize"),
            b'j' => Some("u16"),
            b'l' => Some("i32"),
            b'm' => Some("u32"),
            b'n' => Some("i128"),
            b'o' | b'y' => Some("u128"),
            b'p' => Some("_"),
            b's' => Some("i16"),
            b't' => Some("u64"),
            b'u' => Some("usize"),
            b'v' => Some("()"),
            b'x' => Some("i64"),
            b'z' => Some("!"),
            _ => None,
        }
    }

    fn parse_type(&mut self) -> Option<String> {
        let b = self.peek()?;
        if let Some(prim) = Self::parse_primitive_type(b) {
            self.pos += 1;
            return Some(prim.to_owned());
        }
        match b {
            b'A' => {
                // Array: A <type> <const>
                self.pos += 1;
                let elem = self.parse_type().unwrap_or_else(|| "?".to_owned());
                let _len = self.parse_const();
                Some(format!("[{elem}]"))
            }
            b'S' => {
                // Slice: S <type>
                self.pos += 1;
                let elem = self.parse_type().unwrap_or_else(|| "?".to_owned());
                Some(format!("[{elem}]"))
            }
            b'T' => Some(self.parse_type_tuple()),
            b'R' => { self.pos += 1; Some(format!("&{}", self.parse_lt_type())) }
            b'Q' => { self.pos += 1; Some(format!("&mut {}", self.parse_lt_type())) }
            b'P' => { self.pos += 1; Some(format!("*const {}", self.parse_type().unwrap_or_else(|| "?".to_owned()))) }
            b'O' => { self.pos += 1; Some(format!("*mut {}", self.parse_type().unwrap_or_else(|| "?".to_owned()))) }
            b'F' => Some(self.parse_type_fn()),
            b'D' => {
                // Dyn trait
                self.pos += 1;
                let tr = self.parse_path().unwrap_or_else(|| "?".to_owned());
                let _lt = if self.peek() == Some(b'L') {
                    self.pos += 1;
                    self.parse_base62()
                } else {
                    None
                };
                Some(format!("dyn {tr}"))
            }
            b'B' => {
                // Backref
                self.pos += 1;
                let _ = self.parse_base62();
                Some("_".to_owned())
            }
            _ => self.parse_path(),
        }
    }

    fn parse_lt_type(&mut self) -> String {
        if self.peek() == Some(b'L') {
            self.pos += 1;
            let _ = self.parse_base62();
        }
        self.parse_type().unwrap_or_else(|| "?".to_owned())
    }

    fn parse_type_tuple(&mut self) -> String {
        self.pos += 1; // consume b'T'
        let mut elems = Vec::new();
        while self.peek().is_some_and(|b| b != b'E') {
            if let Some(t) = self.parse_type() { elems.push(t); } else { break; }
        }
        self.consume(b'E');
        format!("({})", elems.join(", "))
    }

    fn parse_type_fn(&mut self) -> String {
        self.pos += 1; // consume b'F'
        if self.peek() == Some(b'G') { self.pos += 1; let _ = self.parse_base62(); }
        let _ = self.consume(b'U');
        if self.peek() == Some(b'K') { self.pos += 1; let _ = self.parse_identifier(); }
        let mut params = Vec::new();
        while self.peek().is_some_and(|b| b != b'E') {
            if let Some(t) = self.parse_type() { params.push(t); } else { break; }
        }
        self.consume(b'E');
        let ret = self.parse_type().unwrap_or_else(|| "()".to_owned());
        format!("fn({}) -> {ret}", params.join(", "))
    }

    fn parse_const(&mut self) -> Option<String> {
        match self.peek()? {
            b'p' => {
                self.pos += 1;
                Some("_".to_owned())
            }
            b'B' => {
                self.pos += 1;
                let _ = self.parse_base62();
                Some("_".to_owned())
            }
            _ => {
                // const type + value
                let _t = self.parse_type();
                Some("?".to_owned())
            }
        }
    }
}
