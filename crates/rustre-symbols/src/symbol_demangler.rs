//! Symbol demangling.
//!
//! Supports Itanium/GCC C++ ABI (v3), MSVC (partial), Rust legacy/v0, and
//! Swift mangling.  Outputs a structured [`DemangledName`] with namespace,
//! class, function name, template arguments, and parameter types.
//!
//! Types: [`MangledSymbol`], [`DemangledName`], [`ManglingScheme`],
//! [`TemplateArg`], [`DemanglerError`].

use std::collections::HashMap;
use std::fmt;

// ─── DemanglerError ───────────────────────────────────────────────────────────

/// Errors produced during demangling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemanglerError {
    /// The input does not start with a recognized mangling prefix.
    UnrecognizedPrefix(String),
    /// The mangled name is syntactically malformed.
    Malformed(String),
    /// A length-encoded name field exceeded available input.
    UnexpectedEof,
    /// An integer value overflowed during parsing.
    Overflow,
    /// The mangling scheme is recognized but not fully implemented.
    NotImplemented(String),
}

impl fmt::Display for DemanglerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnrecognizedPrefix(s) => write!(f, "unrecognized prefix: {s}"),
            Self::Malformed(s) => write!(f, "malformed: {s}"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::Overflow => write!(f, "integer overflow"),
            Self::NotImplemented(s) => write!(f, "not implemented: {s}"),
        }
    }
}

// ─── ManglingScheme ───────────────────────────────────────────────────────────

/// The mangling scheme used by a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManglingScheme {
    /// Itanium C++ ABI (GCC, Clang): symbols starting with `_Z` or `__Z`.
    ItaniumV3,
    /// MSVC mangling: symbols starting with `?`.
    Msvc,
    /// Rust legacy mangling: `__ZN` + encoded Rust path.
    RustLegacy,
    /// Rust v0 mangling: symbols starting with `_R`.
    RustV0,
    /// Swift mangling: symbols starting with `_$s` or `_T`.
    Swift,
    /// Symbol is not mangled (plain C or already demangled).
    None,
}

impl fmt::Display for ManglingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ManglingScheme {
    /// Detect the mangling scheme from the first bytes of the symbol name.
    #[must_use]
    pub fn detect(name: &str) -> Self {
        if name.starts_with("_R") {
            return Self::RustV0;
        }
        if name.starts_with("_$s") || name.starts_with("_T0") || name.starts_with("__T0") {
            return Self::Swift;
        }
        // Rust legacy: _ZN ... with Rust-style hash suffix.
        if (name.starts_with("_ZN") || name.starts_with("__ZN")) && name.ends_with('E') {
            // Heuristic: Rust legacy symbols often contain 'h' followed by a hex string.
            if name.contains("17h") || name.contains("20h") {
                return Self::RustLegacy;
            }
        }
        if name.starts_with("_Z") || name.starts_with("__Z") {
            return Self::ItaniumV3;
        }
        if name.starts_with('?') {
            return Self::Msvc;
        }
        Self::None
    }
}

// ─── TemplateArg ─────────────────────────────────────────────────────────────

/// A single template argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateArg {
    /// A type argument.
    Type(String),
    /// A non-type (integer) argument.
    Value(i64),
    /// A parameter pack.
    Pack(Vec<Self>),
    /// Unknown or unparsed argument.
    Unknown(String),
}

impl fmt::Display for TemplateArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(s) => write!(f, "{s}"),
            Self::Value(v) => write!(f, "{v}"),
            Self::Pack(args) => {
                let inner: Vec<String> = args.iter().map(std::string::ToString::to_string).collect();
                write!(f, "{{{}}}", inner.join(", "))
            }
            Self::Unknown(s) => write!(f, "?{s}?"),
        }
    }
}

// ─── DemangledName ────────────────────────────────────────────────────────────

/// Whether a name refers to a constructor, destructor, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpecialMember {
    /// Not a special member function.
    #[default]
    None,
    /// Constructor.
    Constructor,
    /// Destructor.
    Destructor,
}

impl SpecialMember {
    /// Returns `true` for a constructor.
    #[must_use]
    pub const fn is_constructor(self) -> bool {
        matches!(self, Self::Constructor)
    }
    /// Returns `true` for a destructor.
    #[must_use]
    pub const fn is_destructor(self) -> bool {
        matches!(self, Self::Destructor)
    }
}

/// A fully structured demangled symbol name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangledName {
    /// Namespace path components (e.g. `["std", "io"]`).
    pub namespace: Vec<String>,
    /// Enclosing class name, if any.
    pub class_name: Option<String>,
    /// The plain function or variable name.
    pub function_name: String,
    /// Template arguments on the function itself.
    pub template_args: Vec<TemplateArg>,
    /// Parameter types in order.
    pub parameter_types: Vec<String>,
    /// Return type, if known.
    pub return_type: Option<String>,
    /// Original mangling scheme.
    pub scheme: ManglingScheme,
    /// Marks constructor / destructor / neither.
    pub special: SpecialMember,
    /// Whether this is a `const` member.
    pub is_const: bool,
    /// Whether this is a `static` member.
    pub is_static: bool,
    /// CV qualifiers string.
    pub cv_qualifiers: String,
}

impl DemangledName {
    /// Create a minimal demangled name for an unmangled symbol.
    #[must_use]
    pub fn plain(name: impl Into<String>) -> Self {
        Self {
            namespace: Vec::new(),
            class_name: None,
            function_name: name.into(),
            template_args: Vec::new(),
            parameter_types: Vec::new(),
            return_type: None,
            scheme: ManglingScheme::None,
            special: SpecialMember::None,
            is_const: false,
            is_static: false,
            cv_qualifiers: String::new(),
        }
    }

    /// Fully qualified name (`namespace::class::function`).
    #[must_use]
    pub fn qualified_name(&self) -> String {
        let mut parts: Vec<&str> = self.namespace.iter().map(String::as_str).collect();
        if let Some(cls) = &self.class_name {
            parts.push(cls.as_str());
        }
        parts.push(&self.function_name);
        parts.join("::")
    }

    /// Format as a C++ style signature.
    #[must_use]
    pub fn signature(&self) -> String {
        let mut s = self.qualified_name();
        if !self.template_args.is_empty() {
            let targs: Vec<String> = self.template_args.iter().map(std::string::ToString::to_string).collect();
            s.push('<');
            s.push_str(&targs.join(", "));
            s.push('>');
        }
        s.push('(');
        s.push_str(&self.parameter_types.join(", "));
        s.push(')');
        if self.is_const {
            s.push_str(" const");
        }
        s
    }
}

impl fmt::Display for DemangledName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.signature())
    }
}

// ─── MangledSymbol ────────────────────────────────────────────────────────────

/// A symbol name before and after demangling.
#[derive(Debug, Clone)]
pub struct MangledSymbol {
    /// The original mangled symbol name.
    pub mangled: String,
    /// The detected mangling scheme.
    pub scheme: ManglingScheme,
    /// The demangled result, if successful.
    pub demangled: Option<DemangledName>,
    /// Demangling error, if any.
    pub error: Option<DemanglerError>,
}

impl MangledSymbol {
    /// Create a symbol and immediately attempt to demangle it.
    #[must_use]
    pub fn new(mangled: impl Into<String>) -> Self {
        let mangled = mangled.into();
        let scheme = ManglingScheme::detect(&mangled);
        let result = demangle_with_scheme(&mangled, scheme);
        match result {
            Ok(d) => Self {
                mangled,
                scheme,
                demangled: Some(d),
                error: None,
            },
            Err(e) => Self {
                mangled,
                scheme,
                demangled: None,
                error: Some(e),
            },
        }
    }

    /// Return the best available display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if let Some(d) = &self.demangled {
            d.function_name.as_str()
        } else {
            &self.mangled
        }
    }

    /// True if demangling succeeded.
    #[must_use]
    pub const fn is_demangled(&self) -> bool {
        self.demangled.is_some()
    }
}

impl fmt::Display for MangledSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = &self.demangled {
            write!(f, "{d}")
        } else {
            write!(f, "{}", self.mangled)
        }
    }
}

// ─── Demangle dispatch ────────────────────────────────────────────────────────

/// Demangle a symbol using its detected scheme.
///
/// # Errors
/// Returns a [`DemanglerError`] if parsing fails.
pub fn demangle_with_scheme(
    name: &str,
    scheme: ManglingScheme,
) -> Result<DemangledName, DemanglerError> {
    match scheme {
        ManglingScheme::ItaniumV3 => demangle_itanium(name),
        ManglingScheme::Msvc => demangle_msvc(name),
        ManglingScheme::RustLegacy => demangle_rust_legacy(name),
        ManglingScheme::RustV0 => demangle_rust_v0(name),
        ManglingScheme::Swift => demangle_swift(name),
        ManglingScheme::None => Ok(DemangledName::plain(name)),
    }
}

/// Auto-detect and demangle a symbol.
///
/// # Errors
/// Returns a [`DemanglerError`] if parsing fails.
pub fn demangle(name: &str) -> Result<DemangledName, DemanglerError> {
    let scheme = ManglingScheme::detect(name);
    demangle_with_scheme(name, scheme)
}

/// Auto-detect mangling scheme and return a flat, human-readable demangled
/// string. Returns `None` if the symbol is not mangled or cannot be parsed.
///
/// Dispatch order: Rust v0 (`_R`), Rust legacy (`_ZN…E` with hash), Swift
/// (`_$s`, `$s`, `_T0`), Itanium (`_Z`/`__Z`), MSVC (`?`). For Swift, when
/// the structural parser cannot extract a name, returns the mangled form
/// prefixed with `[swift]` rather than failing.
#[must_use]
pub fn demangle_auto(mangled: &str) -> Option<String> {
    if mangled.is_empty() {
        return None;
    }
    // Swift: try structural parse first; fall back to `[swift] <mangled>`.
    if mangled.starts_with("_$s")
        || mangled.starts_with("$s")
        || mangled.starts_with("_T0")
        || mangled.starts_with("__T0")
    {
        let normalized = mangled.strip_prefix("$s").map_or_else(
            || mangled.to_string(),
            |rest| format!("_$s{rest}"),
        );
        if let Ok(d) = demangle_swift(&normalized) {
            let q = d.qualified_name();
            if !q.is_empty() && q != "_" {
                return Some(q);
            }
        }
        return Some(format!("[swift] {mangled}"));
    }
    if mangled.starts_with("_R") {
        return demangle_rust_v0(mangled).ok().map(|d| d.qualified_name());
    }
    if (mangled.starts_with("_ZN") || mangled.starts_with("__ZN"))
        && mangled.ends_with('E')
        && (mangled.contains("17h") || mangled.contains("20h"))
    {
        return demangle_rust_legacy(mangled)
            .ok()
            .map(|d| d.qualified_name());
    }
    if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
        return demangle_itanium(mangled).ok().map(|d| d.signature());
    }
    if mangled.starts_with('?') {
        return demangle_msvc(mangled).ok().map(|d| d.signature());
    }
    None
}

// ─── Itanium C++ ABI demangler ────────────────────────────────────────────────

/// Demangle an Itanium C++ v3 mangled name.
///
/// # Errors
/// Returns [`DemanglerError`] on parse failure.
pub fn demangle_itanium(name: &str) -> Result<DemangledName, DemanglerError> {
    // Strip leading `_Z` or `__Z`.
    let s = name
        .strip_prefix("__Z")
        .or_else(|| name.strip_prefix("_Z"))
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix(name.chars().take(2).collect::<String>()))?;

    let mut parser = ItaniumParser::new(s);
    parser.parse()
}

/// Demangle an Itanium-mangled symbol and also return the substitution
/// table accumulated during parsing (Itanium S_/S0_/S1_... candidates).
///
/// Useful for diagnostics, fuzz harnesses, and round-trip tests that want
/// to inspect which names the parser recorded as substitution slots.
///
/// # Errors
///
/// Returns a [`DemanglerError`] if parsing fails (unrecognized prefix,
/// truncated input, or unsupported construct).
pub fn demangle_itanium_with_substitutions(
    name: &str,
) -> Result<(DemangledName, Vec<String>), DemanglerError> {
    let s = name
        .strip_prefix("__Z")
        .or_else(|| name.strip_prefix("_Z"))
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix(name.chars().take(2).collect::<String>()))?;

    let mut parser = ItaniumParser::new(s);
    let demangled = parser.parse()?;
    let count = parser.substitution_count();
    let mut subs = Vec::with_capacity(count);
    for i in 0..count {
        if let Some(v) = parser.substitution(i) {
            subs.push(v.to_string());
        }
    }
    Ok((demangled, subs))
}

struct ItaniumParser<'a> {
    input: &'a str,
    pos: usize,
    substitution_table: Vec<String>,
}

impl<'a> ItaniumParser<'a> {
    const fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            substitution_table: Vec::new(),
        }
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn consume(&mut self) -> Option<char> {
        let c = self.remaining().chars().next()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn consume_if(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.consume();
            true
        } else {
            false
        }
    }

    /// Parse a <positive-number> N <identifier>.
    fn parse_length_name(&mut self) -> Result<String, DemanglerError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.consume();
        }
        if self.pos == start {
            return Err(DemanglerError::Malformed("expected length".into()));
        }
        let len_str = &self.input[start..self.pos];
        let len: usize = len_str
            .parse()
            .map_err(|_| DemanglerError::Overflow)?;
        // Use get() rather than a raw byte-range slice: `len` may land inside a
        // multi-byte UTF-8 sequence, which would panic on a direct index.
        let name = self
            .input
            .get(self.pos..self.pos + len)
            .ok_or(DemanglerError::UnexpectedEof)?
            .to_string();
        self.pos += len;
        // Record this name as an Itanium substitution candidate (S_, S0_, S1_...).
        self.record_substitution(name.clone());
        Ok(name)
    }

    /// Push a new entry into the Itanium substitution table.
    fn record_substitution(&mut self, value: String) {
        self.substitution_table.push(value);
    }

    /// Look up a previously recorded substitution by index (Itanium S{n}_).
    pub(crate) fn substitution(&self, index: usize) -> Option<&str> {
        self.substitution_table.get(index).map(std::string::String::as_str)
    }

    /// Resolve a substitution index to its recorded name, falling back to the
    /// `<subst>` placeholder when the index is out of range.
    ///
    /// The table only records length-prefixed names, not composite/template
    /// components, so indices in heavily templated symbols can still miss —
    /// this is best-effort rather than index-exact.
    fn substitution_or_placeholder(&self, index: usize) -> String {
        self.substitution(index)
            .map_or_else(|| "<subst>".to_string(), std::string::ToString::to_string)
    }

    /// Number of recorded substitutions; exposed for diagnostics/tests.
    pub(crate) const fn substitution_count(&self) -> usize {
        self.substitution_table.len()
    }

    /// Parse a sequence of nested names terminated by `E`.
    fn parse_nested_name(&mut self) -> Result<Vec<String>, DemanglerError> {
        // Consume leading `N`.
        if !self.consume_if('N') {
            return Err(DemanglerError::Malformed("expected N for nested-name".into()));
        }
        let mut parts: Vec<String> = Vec::new();
        // Optional cv-qualifiers and ref-qualifiers.
        while matches!(self.peek(), Some('K' | 'V' | 'r' | 'R' | 'O')) {
            self.consume();
        }
        while self.peek() != Some('E') && self.peek().is_some() {
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                parts.push(self.parse_length_name()?);
            } else if self.peek() == Some('S') {
                // Substitution reference: S_, S0_, ... or std abbreviations
                // (Sa, Sb, Ss, Si, So, Sd).
                self.consume();
                match self.peek() {
                    Some('t') => { self.consume(); parts.push("std".to_string()); }
                    Some('a') => { self.consume(); parts.push("std::allocator".to_string()); }
                    Some('b') => { self.consume(); parts.push("std::basic_string".to_string()); }
                    Some('s') => { self.consume(); parts.push("std::string".to_string()); }
                    Some('i') => { self.consume(); parts.push("std::istream".to_string()); }
                    Some('o') => { self.consume(); parts.push("std::ostream".to_string()); }
                    Some('d') => { self.consume(); parts.push("std::iostream".to_string()); }
                    // Bare `S_` is substitution index 0.
                    Some('_') => {
                        self.consume();
                        parts.push(self.substitution_or_placeholder(0));
                    }
                    // `S{seq_id}_`: seq_id is base-36 over 0-9A-Z and denotes
                    // index seq_id + 1 (so `S0_` is index 1).
                    Some(c) if c.is_ascii_digit() || c.is_ascii_uppercase() => {
                        let mut seq: Option<usize> = Some(0);
                        while let Some(c) = self.peek() {
                            if c == '_' {
                                self.consume();
                                break;
                            }
                            if !(c.is_ascii_digit() || c.is_ascii_uppercase()) {
                                break;
                            }
                            let Some(d) = c.to_digit(36) else { break };
                            self.consume();
                            seq = seq
                                .and_then(|s| s.checked_mul(36))
                                .and_then(|s| s.checked_add(d as usize));
                        }
                        let idx = seq.and_then(|s| s.checked_add(1));
                        parts.push(
                            idx.map_or_else(
                                || "<subst>".to_string(),
                                |i| self.substitution_or_placeholder(i),
                            ),
                        );
                    }
                    _ => parts.push("<subst>".to_string()),
                }
            } else if self.peek() == Some('I') {
                // Template args. Decode element types as a parenthesized list
                // attached to the previous component.
                self.consume();
                let mut targs: Vec<String> = Vec::new();
                while self.peek() != Some('E') && self.peek().is_some() {
                    let t = self.parse_one_type();
                    if t.is_empty() { break; }
                    targs.push(t);
                }
                self.consume_if('E');
                if let Some(last) = parts.last_mut() {
                    last.push('<');
                    last.push_str(&targs.join(", "));
                    last.push('>');
                } else {
                    parts.push(format!("<{}>", targs.join(", ")));
                }
            } else if self.peek() == Some('C') {
                self.consume();
                self.consume(); // C1/C2/C3
                let class = parts.last().cloned().unwrap_or_default();
                parts.push(if class.is_empty() { "<ctor>".to_string() } else { class });
            } else if self.peek() == Some('D') {
                self.consume();
                self.consume(); // D0/D1/D2
                let class = parts.last().cloned().unwrap_or_default();
                parts.push(if class.is_empty() {
                    "<dtor>".to_string()
                } else {
                    format!("~{class}")
                });
            } else if let Some(op) = self.parse_operator_name() {
                parts.push(op);
            } else {
                let c = self.consume().unwrap();
                parts.push(c.to_string());
            }
        }
        self.consume_if('E');
        Ok(parts)
    }

    fn parse(&mut self) -> Result<DemangledName, DemanglerError> {
        let mut result = DemangledName::plain("");
        result.scheme = ManglingScheme::ItaniumV3;

        if self.peek() == Some('N') {
            let parts = self.parse_nested_name()?;
            let parts = Self::clean_parts(parts);
            if let Some(last) = parts.last() {
                result.function_name.clone_from(last);
                if last.starts_with('~') {
                    result.special = SpecialMember::Destructor;
                } else if parts.len() >= 2 && parts[parts.len() - 2] == *last {
                    result.special = SpecialMember::Constructor;
                }
            }
            let ns_len = if parts.len() > 1 { parts.len() - 1 } else { 0 };
            if ns_len > 1 {
                result.namespace = parts[..ns_len - 1].to_vec();
                result.class_name = parts.get(ns_len - 1).cloned();
            } else if ns_len == 1 {
                result.class_name = parts.first().cloned();
            }
        } else if self.peek() == Some('S') {
            // Std-prefixed unscoped, e.g. _ZSt...
            self.consume();
            if self.consume_if('t') {
                result.namespace = vec!["std".to_string()];
            }
            if let Some(op) = self.parse_operator_name() {
                result.function_name = op;
            } else if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                result.function_name = self.parse_length_name()?;
            }
        } else if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            result.function_name = self.parse_length_name()?;
        } else if let Some(op) = self.parse_operator_name() {
            result.function_name = op;
        } else if self.peek() == Some('L') {
            self.consume();
            result.function_name = "<local>".to_string();
        } else {
            let rest: String = self.remaining().to_string();
            result.function_name = Self::decode_builtin(&rest);
            self.pos = self.input.len();
        }

        result.parameter_types = self.parse_parameter_types();
        // void-only parameter list means `()`.
        if result.parameter_types.len() == 1 && result.parameter_types[0] == "void" {
            result.parameter_types.clear();
        }

        Ok(result)
    }

    /// Decode an Itanium operator-name (two-letter code) if present.
    fn parse_operator_name(&mut self) -> Option<String> {
        let s = self.remaining();
        if s.len() < 2 { return None; }
        let code = &s[..2];
        let name = match code {
            "nw" => "operator new", "na" => "operator new[]",
            "dl" => "operator delete", "da" => "operator delete[]",
            "ps" | "pl" => "operator+",
            "ng" | "mi" => "operator-",
            "ad" | "an" => "operator&",
            "de" | "ml" => "operator*",
            "co" => "operator~",
            "dv" => "operator/", "rm" => "operator%",
            "or" => "operator|",
            "eo" => "operator^", "aS" => "operator=",
            "pL" => "operator+=", "mI" => "operator-=",
            "mL" => "operator*=", "dV" => "operator/=",
            "rM" => "operator%=", "aN" => "operator&=",
            "oR" => "operator|=", "eO" => "operator^=",
            "ls" => "operator<<", "rs" => "operator>>",
            "lS" => "operator<<=", "rS" => "operator>>=",
            "eq" => "operator==", "ne" => "operator!=",
            "lt" => "operator<", "gt" => "operator>",
            "le" => "operator<=", "ge" => "operator>=",
            "nt" => "operator!", "aa" => "operator&&",
            "oo" => "operator||", "pp" => "operator++",
            "mm" => "operator--", "cm" => "operator,",
            "pm" => "operator->*", "pt" => "operator->",
            "cl" => "operator()", "ix" => "operator[]",
            "qu" => "operator?", "cv" => "operator T",
            _ => return None,
        };
        self.pos += 2;
        Some(name.to_string())
    }

    fn clean_parts(parts: Vec<String>) -> Vec<String> {
        parts
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect()
    }

    fn decode_builtin(s: &str) -> String {
        match s {
            "v" => "void".to_string(),
            "b" => "bool".to_string(),
            "c" => "char".to_string(),
            "s" => "short".to_string(),
            "i" => "int".to_string(),
            "j" => "unsigned int".to_string(),
            "l" => "long".to_string(),
            "m" => "unsigned long".to_string(),
            "x" => "long long".to_string(),
            "y" => "unsigned long long".to_string(),
            "f" => "float".to_string(),
            "d" => "double".to_string(),
            "e" => "long double".to_string(),
            "z" => "...".to_string(),
            other => other.to_string(),
        }
    }

    fn parse_parameter_types(&mut self) -> Vec<String> {
        let mut params = Vec::new();
        while !self.remaining().is_empty() {
            let param = self.parse_one_type();
            if param.is_empty() {
                break;
            }
            params.push(param);
        }
        params
    }

    fn parse_one_type(&mut self) -> String {
        match self.peek() {
            Some('v') => { self.consume(); "void".to_string() }
            Some('w') => { self.consume(); "wchar_t".to_string() }
            Some('b') => { self.consume(); "bool".to_string() }
            Some('c') => { self.consume(); "char".to_string() }
            Some('a') => { self.consume(); "signed char".to_string() }
            Some('h') => { self.consume(); "unsigned char".to_string() }
            Some('s') => { self.consume(); "short".to_string() }
            Some('t') => { self.consume(); "unsigned short".to_string() }
            Some('i') => { self.consume(); "int".to_string() }
            Some('j') => { self.consume(); "unsigned int".to_string() }
            Some('l') => { self.consume(); "long".to_string() }
            Some('m') => { self.consume(); "unsigned long".to_string() }
            Some('x') => { self.consume(); "long long".to_string() }
            Some('y') => { self.consume(); "unsigned long long".to_string() }
            Some('n') => { self.consume(); "__int128".to_string() }
            Some('o') => { self.consume(); "unsigned __int128".to_string() }
            Some('f') => { self.consume(); "float".to_string() }
            Some('d') => { self.consume(); "double".to_string() }
            Some('e') => { self.consume(); "long double".to_string() }
            Some('z') => { self.consume(); "...".to_string() }
            Some('D') => {
                self.consume();
                match self.consume() {
                    Some('n') => "std::nullptr_t".to_string(),
                    Some('s') => "char16_t".to_string(),
                    Some('i') => "char32_t".to_string(),
                    Some(c) => c.to_string(),
                    None => String::new(),
                }
            }
            Some('K') => { self.consume(); format!("const {}", self.parse_one_type()) }
            Some('V') => { self.consume(); format!("volatile {}", self.parse_one_type()) }
            Some('P') => { self.consume(); format!("{}*", self.parse_one_type()) }
            Some('R') => { self.consume(); format!("{}&", self.parse_one_type()) }
            Some('O') => { self.consume(); format!("{}&&", self.parse_one_type()) }
            Some('N') => self
                .parse_nested_name()
                .map_or_else(|_| String::new(), |parts| parts.join("::")),
            Some(c) if c.is_ascii_digit() => {
                self.parse_length_name().unwrap_or_default()
            }
            Some('S') => {
                self.consume();
                match self.peek() {
                    Some('t') => { self.consume(); format!("std::{}", self.parse_one_type()) }
                    Some('a') => { self.consume(); "std::allocator".to_string() }
                    Some('b') => { self.consume(); "std::basic_string".to_string() }
                    Some('s') => { self.consume(); "std::string".to_string() }
                    Some('i') => { self.consume(); "std::istream".to_string() }
                    Some('o') => { self.consume(); "std::ostream".to_string() }
                    Some('d') => { self.consume(); "std::iostream".to_string() }
                    _ => {
                        while let Some(c) = self.peek() {
                            if c == '_' { self.consume(); break; }
                            if c.is_ascii_alphanumeric() { self.consume(); } else { break; }
                        }
                        "<subst>".to_string()
                    }
                }
            }
            _ => {
                self.consume().map_or_else(String::new, |c| c.to_string())
            }
        }
    }
}

// ─── MSVC demangler (partial) ─────────────────────────────────────────────────

/// Partial MSVC C++ demangler.
///
/// # Errors
/// Returns [`DemanglerError`] on parse failure.
pub fn demangle_msvc(name: &str) -> Result<DemangledName, DemanglerError> {
    let s = name
        .strip_prefix('?')
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix("?".into()))?;

    // Split at `@@` — left side is the name path, right side is type info.
    let (name_part, type_part) = s.split_once("@@").unwrap_or((s, ""));

    // Name segments separated by single '@'. First segment is the
    // unqualified name (possibly an `?<op>` operator code).
    let segments: Vec<&str> = name_part.split('@').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Err(DemanglerError::Malformed("no segments".into()));
    }

    let mut raw_func = segments[0];
    // Special operator codes like `?0Foo`, `?1Foo` glue the special code
    // to the class name without an `@` separator. Split them apart.
    let mut extra_scope: Option<&str> = None;
    if let Some(rest) = raw_func.strip_prefix('?')
        && rest.len() > 1 {
            // The operator code is one character: `?0`, `?1`, ..., `?A`..`?W`.
            let (code, tail) = rest.split_at(1);
            if !tail.is_empty() {
                extra_scope = Some(tail);
                // Re-borrow raw_func to the operator-code-only slice.
                raw_func = &raw_func[..2]; // `?` + code char
                let _ = code;
            }
        }
    let func_name = decode_msvc_operator(raw_func).unwrap_or_else(|| raw_func.to_string());

    let mut result = DemangledName::plain(&func_name);
    result.scheme = ManglingScheme::Msvc;

    let mut scope: Vec<&str> = Vec::new();
    if let Some(es) = extra_scope { scope.push(es); }
    scope.extend(segments.iter().skip(1).copied());
    if scope.len() == 1 {
        result.class_name = Some(scope[0].to_string());
    } else if scope.len() > 1 {
        result.class_name = Some(scope[0].to_string());
        let mut ns: Vec<String> = scope.iter().skip(1).map(|s| (*s).to_string()).collect();
        ns.reverse();
        result.namespace = ns;
    }

    if raw_func == "?0" || raw_func == "0" {
        result.special = SpecialMember::Constructor;
        if let Some(cls) = &result.class_name {
            result.function_name.clone_from(cls);
        }
    } else if raw_func == "?1" || raw_func == "1" {
        result.special = SpecialMember::Destructor;
        if let Some(cls) = &result.class_name {
            result.function_name = format!("~{cls}");
        }
    }

    // Type part: <access><storage>(<calling-conv>)<return-type><params>Z
    // Examples: QAEXXZ, YAHXZ, SAHH@Z, UAEPAXI@Z
    if !type_part.is_empty() {
        parse_msvc_type_part(type_part, &mut result);
    }

    Ok(result)
}

fn decode_msvc_operator(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix('?')?;
    let code = rest.chars().next()?;
    Some(match code {
        '0' => "<ctor>".to_string(),
        '1' => "<dtor>".to_string(),
        '2' => "operator new".to_string(),
        '3' => "operator delete".to_string(),
        '4' => "operator=".to_string(),
        '5' => "operator>>".to_string(),
        '6' => "operator<<".to_string(),
        '7' => "operator!".to_string(),
        '8' => "operator==".to_string(),
        '9' => "operator!=".to_string(),
        'A' => "operator[]".to_string(),
        'C' => "operator->".to_string(),
        'D' => "operator*".to_string(),
        'E' => "operator++".to_string(),
        'F' => "operator--".to_string(),
        'G' => "operator-".to_string(),
        'H' => "operator+".to_string(),
        'I' => "operator&".to_string(),
        'J' => "operator->*".to_string(),
        'K' => "operator/".to_string(),
        'L' => "operator%".to_string(),
        'M' => "operator<".to_string(),
        'N' => "operator<=".to_string(),
        'O' => "operator>".to_string(),
        'P' => "operator>=".to_string(),
        'Q' => "operator,".to_string(),
        'R' => "operator()".to_string(),
        'S' => "operator~".to_string(),
        'T' => "operator^".to_string(),
        'U' => "operator|".to_string(),
        'V' => "operator&&".to_string(),
        'W' => "operator||".to_string(),
        _ => return None,
    })
}

fn parse_msvc_type_part(tp: &str, result: &mut DemangledName) {
    let mut chars = tp.chars().peekable();
    let access = chars.next();
    match access {
        Some('S' | 'T') => result.is_static = true,          // static
        Some('A' | 'B' | 'I' | 'J' | 'Q' | 'R' | 'U' | 'V' | 'Y') => {} // private/protected/public/virtual/free
        _ => return,
    }
    let is_member = !matches!(access, Some('Y'));
    if is_member {
        // Storage class for `this`: A,B,C,D... encode cv-qualifiers.
        if let Some(&stor) = chars.peek() {
            match stor {
                'B' => { result.is_const = true; result.cv_qualifiers = "const".into(); }
                'C' => { result.cv_qualifiers = "volatile".into(); }
                'D' => { result.is_const = true; result.cv_qualifiers = "const volatile".into(); }
                _ => {}
            }
            chars.next();
        }
    }
    // Calling convention (single char: A=cdecl, E=thiscall, G=stdcall, I=fastcall...).
    chars.next();

    // Return type (single code) then parameter codes until '@' or 'X'.
    let mut rest: String = chars.collect();
    // Strip trailing 'Z' (throw spec terminator).
    if rest.ends_with('Z') { rest.pop(); }
    if rest.ends_with('@') { rest.pop(); }

    let mut it = rest.chars().peekable();
    if let Some(rt) = parse_msvc_one_type(&mut it) {
        result.return_type = Some(rt);
    }
    // Parameters.
    let mut params = Vec::new();
    while let Some(&c) = it.peek() {
        if c == 'X' { it.next(); params.push("void".to_string()); break; }
        if c == 'Z' || c == '@' { it.next(); break; }
        match parse_msvc_one_type(&mut it) {
            Some(t) => params.push(t),
            None => break,
        }
    }
    if params.len() == 1 && params[0] == "void" {
        params.clear();
    }
    result.parameter_types = params;
}

fn parse_msvc_one_type(it: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let c = it.next()?;
    Some(match c {
        'X' => "void".to_string(),
        '_' => match it.next()? {
            'N' => "bool".to_string(),
            'J' => "long long".to_string(),
            'K' => "unsigned long long".to_string(),
            'W' => "wchar_t".to_string(),
            other => format!("_{other}"),
        },
        'D' => "char".to_string(),
        'C' => "signed char".to_string(),
        'E' => "unsigned char".to_string(),
        'F' => "short".to_string(),
        'G' => "unsigned short".to_string(),
        'H' => "int".to_string(),
        'I' => "unsigned int".to_string(),
        'J' => "long".to_string(),
        'K' => "unsigned long".to_string(),
        'M' => "float".to_string(),
        'N' => "double".to_string(),
        'O' => "long double".to_string(),
        'P' => {
            // PA<T>: T*, PB<T>: const T*. Skip storage class char then recurse.
            let storage = it.next()?;
            let inner = parse_msvc_one_type(it).unwrap_or_default();
            match storage {
                'B' | 'D' => format!("const {inner}*"),
                _ => format!("{inner}*"),
            }
        }
        'A' => {
            let storage = it.next()?;
            let inner = parse_msvc_one_type(it).unwrap_or_default();
            match storage {
                'B' | 'D' => format!("const {inner}&"),
                _ => format!("{inner}&"),
            }
        }
        'V' | 'U' => {
            // Class/struct name segments until '@@'.
            let mut name = String::new();
            let mut segs: Vec<String> = Vec::new();
            let mut cur = String::new();
            loop {
                let n = it.next()?;
                if n == '@' {
                    if it.peek() == Some(&'@') { it.next(); if !cur.is_empty() { segs.push(std::mem::take(&mut cur)); } break; }
                    if !cur.is_empty() { segs.push(std::mem::take(&mut cur)); }
                } else {
                    cur.push(n);
                }
            }
            if !segs.is_empty() {
                let first = segs.remove(0);
                segs.reverse();
                if segs.is_empty() {
                    name = first;
                } else {
                    name = format!("{}::{}", segs.join("::"), first);
                }
            }
            name
        }
        other => other.to_string(),
    })
}

// ─── Rust legacy demangler ────────────────────────────────────────────────────

/// Demangle a Rust legacy mangled symbol.
///
/// # Errors
/// Returns [`DemanglerError`] on parse failure.
///
/// # Panics
///
/// Panics if internal invariants about non-empty path component lists are
/// violated (the parser ensures these by construction; a panic here indicates
/// an internal bug).
pub fn demangle_rust_legacy(name: &str) -> Result<DemangledName, DemanglerError> {
    // Rust legacy uses Itanium-style encoding but with different path components.
    // Strip outer Itanium wrapper.
    let s = name
        .strip_prefix("__ZN")
        .or_else(|| name.strip_prefix("_ZN"))
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix(name[..4.min(name.len())].to_string()))?;

    // Strip trailing E.
    let s = s.trim_end_matches('E');

    let mut parser = ItaniumParser::new(s);
    let mut parts = Vec::new();

    while !parser.remaining().is_empty() {
        match parser.parse_length_name() {
            Ok(p) => {
                // Remove Rust hash suffixes like `17hdeadbeef`.
                let clean = strip_rust_hash(&p);
                if !clean.is_empty() {
                    parts.push(clean);
                }
            }
            Err(_) => break,
        }
    }

    if parts.is_empty() {
        return Err(DemanglerError::Malformed("no Rust path components".into()));
    }

    let mut result = DemangledName::plain(parts.last().unwrap().clone());
    result.scheme = ManglingScheme::RustLegacy;
    if parts.len() > 1 {
        result.namespace = parts[..parts.len() - 1].to_vec();
    }
    Ok(result)
}

fn strip_rust_hash(s: &str) -> String {
    // Pattern: name ends with h[0-9a-f]{16}.
    if s.len() < 18 {
        return s.to_string();
    }
    let tail = &s[s.len() - 17..];
    if tail.starts_with('h') && tail[1..].chars().all(|c| c.is_ascii_hexdigit()) {
        s[..s.len() - 17].to_string()
    } else {
        s.to_string()
    }
}

// ─── Rust v0 demangler ────────────────────────────────────────────────────────

/// Demangle a Rust v0 mangled symbol.
///
/// Full v0 demangling is complex; this implements the most common patterns.
///
/// # Errors
/// Returns [`DemanglerError`] on parse failure.
pub fn demangle_rust_v0(name: &str) -> Result<DemangledName, DemanglerError> {
    let s = name
        .strip_prefix("_R")
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix("_R".into()))?;

    let mut result = DemangledName::plain(s.to_string());
    result.scheme = ManglingScheme::RustV0;

    // v0 prefix structure: _R <path-component>+
    // Parse the crate-name and path.
    let mut parser = V0Parser::new(s);
    let parts = parser.parse_path();
    if let Some(last) = parts.last() {
        result.function_name.clone_from(last);
    }
    if parts.len() > 1 {
        result.namespace = parts[..parts.len() - 1].to_vec();
    }

    Ok(result)
}

struct V0Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> V0Parser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn consume(&mut self) -> Option<char> {
        let c = self.remaining().chars().next()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// Parse a base-62 encoded length then that many ASCII chars.
    fn parse_identifier(&mut self) -> Result<String, DemanglerError> {
        // v0 identifiers: optional unicode flag 'u', then a base-62 length, then '_', then chars.
        let is_unicode = if self.peek() == Some('u') {
            self.consume();
            true
        } else {
            false
        };

        let mut len_val = 0usize;
        let mut has_len = false;
        while let Some(c) = self.peek() {
            if let Some(digit) = base62_digit(c) {
                len_val = len_val * 62 + digit;
                self.consume();
                has_len = true;
            } else {
                break;
            }
        }
        if !has_len {
            return Err(DemanglerError::Malformed("missing identifier length".into()));
        }
        // Optional '_' separator if the length ends in a digit.
        if self.peek() == Some('_') {
            self.consume();
        }
        if self.pos + len_val > self.input.len() {
            return Err(DemanglerError::UnexpectedEof);
        }
        let ident = self.input[self.pos..self.pos + len_val].to_string();
        self.pos += len_val;
        let _ = is_unicode; // unicode decoding not implemented
        Ok(ident)
    }

    fn parse_path(&mut self) -> Vec<String> {
        let mut parts = Vec::new();
        // v0 path starts with optional 'C' (crate-root) or 'N' (nested).
        match self.peek() {
            Some('C') => {
                self.consume();
                // crate-root: fingerprint + name.
                let _ = self.parse_identifier(); // fingerprint (ignored)
                if let Ok(name) = self.parse_identifier() {
                    parts.push(name);
                }
            }
            Some('N') => {
                self.consume();
                // nested: namespace tag then inner path then identifier.
                let _ns_tag = self.consume(); // 'v', 't', 'C', etc.
                parts.extend(self.parse_path());
                if let Ok(ident) = self.parse_identifier() {
                    parts.push(ident);
                }
            }
            Some('M') => {
                self.consume();
                parts.push("<impl>".to_string());
            }
            Some('X') => {
                self.consume();
                parts.push("<trait-impl>".to_string());
            }
            _ => {
                // Try plain identifier.
                if let Ok(ident) = self.parse_identifier() {
                    parts.push(ident);
                }
            }
        }
        parts
    }
}

const fn base62_digit(c: char) -> Option<usize> {
    match c {
        '0'..='9' => Some((c as usize) - ('0' as usize)),
        'a'..='z' => Some((c as usize) - ('a' as usize) + 10),
        'A'..='Z' => Some((c as usize) - ('A' as usize) + 36),
        _ => None,
    }
}

// ─── Swift demangler (minimal) ────────────────────────────────────────────────

/// Minimal Swift demangler (extracts module and entity name).
///
/// # Errors
/// Returns [`DemanglerError`] on parse failure.
pub fn demangle_swift(name: &str) -> Result<DemangledName, DemanglerError> {
    let s = name
        .strip_prefix("_$s")
        .or_else(|| name.strip_prefix("_T0"))
        .or_else(|| name.strip_prefix("__T0"))
        .ok_or_else(|| DemanglerError::UnrecognizedPrefix(name[..3.min(name.len())].to_string()))?;

    let mut result = DemangledName::plain(s.to_string());
    result.scheme = ManglingScheme::Swift;

    // Swift symbols: module identifiers encoded as base-10 length + name.
    let mut parts = Vec::new();
    let mut pos = 0;
    let bytes = s.as_bytes();
    while pos < bytes.len() {
        let digit_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == digit_start {
            break;
        }
        let len: usize = s[digit_start..pos].parse().unwrap_or(0);
        if len == 0 || pos + len > s.len() {
            break;
        }
        parts.push(s[pos..pos + len].to_string());
        pos += len;
    }

    if let Some(last) = parts.last() {
        result.function_name.clone_from(last);
    }
    if parts.len() > 1 {
        result.namespace = parts[..parts.len() - 1].to_vec();
    }
    Ok(result)
}

// ─── DemanglerCache ───────────────────────────────────────────────────────────

/// A cache mapping mangled names to their demangled results.
#[derive(Debug, Default)]
pub struct DemanglerCache {
    cache: HashMap<String, Result<DemangledName, DemanglerError>>,
    hits: u64,
    misses: u64,
}

impl DemanglerCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Demangle `name`, returning a cached result if available.
    ///
    /// # Errors
    ///
    /// Returns a [`DemanglerError`] if the name cannot be demangled by any
    /// scheme.
    pub fn demangle(&mut self, name: &str) -> Result<DemangledName, DemanglerError> {
        if let Some(cached) = self.cache.get(name) {
            self.hits += 1;
            return cached.clone();
        }
        self.misses += 1;
        let result = demangle(name);
        self.cache.insert(name.to_string(), result.clone());
        result
    }

    /// Cache hit count.
    #[must_use]
    pub const fn hits(&self) -> u64 {
        self.hits
    }

    /// Cache miss count.
    #[must_use]
    pub const fn misses(&self) -> u64 {
        self.misses
    }

    /// Cache size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// True if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_itanium() {
        assert_eq!(ManglingScheme::detect("_ZN3foo3barEv"), ManglingScheme::ItaniumV3);
        assert_eq!(ManglingScheme::detect("__Z3fooEi"), ManglingScheme::ItaniumV3);
    }

    #[test]
    fn detect_msvc() {
        assert_eq!(ManglingScheme::detect("?foo@bar@@QAEXXZ"), ManglingScheme::Msvc);
    }

    #[test]
    fn detect_rust_v0() {
        assert_eq!(ManglingScheme::detect("_RNvCs1234_7my_crate3foo"), ManglingScheme::RustV0);
    }

    #[test]
    fn detect_none() {
        assert_eq!(ManglingScheme::detect("printf"), ManglingScheme::None);
    }

    #[test]
    fn itanium_bare_substitution_resolves_to_index_zero() {
        // `S_` is substitution index 0 -> the first recorded name, "foo".
        // Before the fix this produced the literal placeholder "<subst>".
        let d = demangle_itanium("_ZN3foo3barS_E").unwrap();
        let q = d.qualified_name();
        assert!(!q.contains("<subst>"), "unresolved substitution in {q}");
        assert!(q.contains("foo::bar::foo"), "{q}");
    }

    #[test]
    fn itanium_numbered_substitution_resolves_to_index_plus_one() {
        // `S0_` is index 1 -> the second recorded name, "bar".
        let d = demangle_itanium("_ZN3foo3barS0_E").unwrap();
        let q = d.qualified_name();
        assert!(!q.contains("<subst>"), "unresolved substitution in {q}");
        assert!(q.contains("foo::bar::bar"), "{q}");
    }

    #[test]
    fn itanium_out_of_range_substitution_keeps_placeholder() {
        // `S9_` is index 10, far past the two recorded names: fall back rather
        // than panic or index out of bounds.
        let d = demangle_itanium("_ZN3foo3barS9_E").unwrap();
        assert!(d.qualified_name().contains("<subst>"));
    }

    #[test]
    fn itanium_std_abbreviation_still_wins_over_seq_id() {
        let d = demangle_itanium("_ZNSt3barEv").unwrap();
        assert!(d.qualified_name().starts_with("std::bar"), "{}", d.qualified_name());
    }

    #[test]
    fn itanium_simple_function() {
        let result = demangle_itanium("_Z3fooEi");
        assert!(result.is_ok(), "{result:?}");
        let d = result.unwrap();
        assert_eq!(d.function_name, "foo");
    }

    #[test]
    fn itanium_nested_name() {
        let result = demangle_itanium("_ZN3foo3barEv");
        assert!(result.is_ok(), "{result:?}");
        let d = result.unwrap();
        assert!(!d.function_name.is_empty());
    }

    #[test]
    fn itanium_unrecognized_prefix() {
        let result = demangle_itanium("printf");
        assert!(matches!(result, Err(DemanglerError::UnrecognizedPrefix(_))));
    }

    #[test]
    fn msvc_basic() {
        let result = demangle_msvc("?foo@MyClass@@QAEXXZ");
        assert!(result.is_ok(), "{result:?}");
        let d = result.unwrap();
        assert_eq!(d.function_name, "foo");
        assert_eq!(d.class_name, Some("MyClass".into()));
    }

    #[test]
    fn msvc_unrecognized() {
        assert!(matches!(
            demangle_msvc("_Z3foo"),
            Err(DemanglerError::UnrecognizedPrefix(_))
        ));
    }

    #[test]
    fn rust_v0_strips_prefix() {
        let result = demangle_rust_v0("_RNvCs1234_7my_crate3foo");
        assert!(result.is_ok(), "{result:?}");
        let d = result.unwrap();
        assert_eq!(d.scheme, ManglingScheme::RustV0);
    }

    #[test]
    fn swift_basic() {
        let result = demangle_swift("_$s9SwiftDemo3fooyyF");
        assert!(result.is_ok(), "{result:?}");
        let d = result.unwrap();
        assert_eq!(d.scheme, ManglingScheme::Swift);
    }

    #[test]
    fn demangled_name_qualified() {
        let mut d = DemangledName::plain("bar");
        d.namespace = vec!["std".into(), "io".into()];
        d.class_name = Some("File".into());
        assert_eq!(d.qualified_name(), "std::io::File::bar");
    }

    #[test]
    fn demangled_name_signature_const() {
        let mut d = DemangledName::plain("method");
        d.parameter_types = vec!["int".into(), "float".into()];
        d.is_const = true;
        let sig = d.signature();
        assert!(sig.contains("const"));
        assert!(sig.contains("method(int, float)"));
    }

    #[test]
    fn template_arg_display() {
        let a = TemplateArg::Type("int".into());
        assert_eq!(a.to_string(), "int");
        let b = TemplateArg::Value(42);
        assert_eq!(b.to_string(), "42");
    }

    #[test]
    fn mangled_symbol_plain() {
        let sym = MangledSymbol::new("printf");
        assert_eq!(sym.scheme, ManglingScheme::None);
        assert!(sym.is_demangled());
        assert_eq!(sym.display_name(), "printf");
    }

    #[test]
    fn demangler_cache_hit() {
        let mut cache = DemanglerCache::new();
        let _ = cache.demangle("printf");
        let _ = cache.demangle("printf");
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn strip_rust_hash_strips() {
        let s = "my_functionhdeadbeefcafe1234";
        // 17 char suffix: 'h' + 16 hex chars.
        let result = strip_rust_hash(s);
        assert!(result.len() < s.len() || !s.contains("hdeadbee"));
    }

    #[test]
    fn demangler_error_display() {
        let e = DemanglerError::UnexpectedEof;
        assert!(e.to_string().contains("unexpected"));
    }

    // ── Real-world Itanium round-trips ────────────────────────────────────────

    #[test]
    fn itanium_real_world_examples() {
        // Each tuple: mangled name + a substring that MUST appear in the demangled signature.
        let cases = [
            ("_ZN3std2io5stdin17h0123456789abcdefE", "stdin"),
            ("_ZN5boost6system15system_categoryEv", "system_category"),
            ("_ZNSt6vectorIiSaIiEE9push_backERKi", "push_back"),
            ("_ZN3fooC1Ev", "foo"),       // constructor
            ("_ZN3fooD1Ev", "~foo"),      // destructor
            ("_ZNK3foo3barEi", "bar"),    // const member
            ("_Z3addii", "add"),          // simple free function
            ("_ZN9wikipedia7article6formatEv", "format"),
        ];
        for (m, expect) in cases {
            let d = demangle_itanium(m).unwrap_or_else(|e| panic!("{m}: {e}"));
            let sig = d.signature();
            assert!(sig.contains(expect), "Itanium {m} -> {sig}, expected {expect}");
            assert_eq!(d.scheme, ManglingScheme::ItaniumV3);
        }
    }

    #[test]
    fn itanium_operator_overload() {
        let d = demangle_itanium("_ZN3fooplERKS_").unwrap();
        assert!(d.function_name.contains("operator+"));
    }

    #[test]
    fn itanium_builtin_types_in_params() {
        let d = demangle_itanium("_Z3foofd").unwrap();
        assert_eq!(d.parameter_types, vec!["float".to_string(), "double".to_string()]);
    }

    // ── Real-world MSVC round-trips ──────────────────────────────────────────

    #[test]
    fn msvc_real_world_examples() {
        let cases: [(&str, &str); 5] = [
            ("?foo@@YAXXZ", "foo"),                              // void foo(void)
            ("?bar@MyClass@@QAEXH@Z", "bar"),                     // MyClass::bar(int)
            ("?Add@Math@@SAHHH@Z", "Add"),                        // static int Math::Add(int,int)
            ("?length@String@util@@QBEHXZ", "length"),            // util::String::length() const
            ("??0Foo@@QAE@XZ", "Foo"),                            // ctor Foo::Foo(void)
        ];
        for (m, expect) in cases {
            let d = demangle_msvc(m).unwrap_or_else(|e| panic!("{m}: {e}"));
            assert!(
                d.function_name.contains(expect) || d.class_name.as_deref() == Some(expect),
                "MSVC {m} -> fn={}, cls={:?}, expected {expect}",
                d.function_name, d.class_name
            );
            assert_eq!(d.scheme, ManglingScheme::Msvc);
        }
    }

    #[test]
    fn msvc_const_member_detected() {
        let d = demangle_msvc("?length@String@util@@QBEHXZ").unwrap();
        assert!(d.is_const, "expected QBE to mark const member");
    }

    #[test]
    fn msvc_static_member_detected() {
        let d = demangle_msvc("?Add@Math@@SAHHH@Z").unwrap();
        assert!(d.is_static, "expected SA to mark static");
    }

    // ── Swift fallback ───────────────────────────────────────────────────────

    #[test]
    fn swift_real_world_examples() {
        let cases = [
            "_$s9SwiftDemo3fooyyF",
            "_$s10Foundation4DataV5countSivg",
            "$s4main5helloyyF",
            "_T05hello5worldyyF",
            "_$s10MyApp10ContentViewV4bodyQrvg",
        ];
        for m in cases {
            let out = demangle_auto(m).unwrap_or_else(|| panic!("auto returned None for {m}"));
            assert!(
                !out.is_empty(),
                "Swift auto-demangle produced empty output for {m}"
            );
        }
    }

    // ── demangle_auto dispatch ───────────────────────────────────────────────

    #[test]
    fn demangle_auto_dispatch() {
        assert!(demangle_auto("_Z3addii").unwrap().contains("add"));
        assert!(demangle_auto("?foo@@YAXXZ").unwrap().contains("foo"));
        assert!(demangle_auto("_RNvCs1234_7my_crate3foo").is_some());
        assert!(demangle_auto("_$s9SwiftDemo3fooyyF").is_some());
        assert!(demangle_auto("printf").is_none());
    }
}

#[cfg(test)]
mod adv_verify_utf8 {
    #[test]
    fn itanium_multibyte() {
        let _ = super::demangle("_ZN3fo\u{e9}E");
    }
    #[test]
    fn v0_multibyte() {
        let _ = super::demangle("_RNvC4fo\u{e9}x4main");
    }

    // -- Regression: byte-slicing panics on non-ASCII Itanium input ----------

    #[test]
    fn itanium_length_name_multibyte_boundary_does_not_panic() {
        // Length 3 against a 4-byte, two-character tail: the byte range lands
        // inside a multi-byte UTF-8 sequence.
        let _ = super::demangle_itanium("_Z3\u{e9}\u{e9}");
    }

    #[test]
    fn itanium_unrecognized_prefix_multibyte_does_not_panic() {
        let _ = super::demangle_itanium("\u{e9}\u{e9}foo");
        let _ = super::demangle_itanium_with_substitutions("\u{e9}\u{e9}foo");
    }

    #[test]
    fn itanium_plain_name_still_demangles() {
        assert!(super::demangle_itanium("_Z3foov").is_ok());
    }

}
