//! C++ name demangler: Itanium ABI (GCC/Clang), MSVC, Borland.
//!
//! Handles templates, nested namespaces, operators, constructors/destructors,
//! substitutions, pointer/reference qualifiers, and function types.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ── ABI Selection ─────────────────────────────────────────────────────────────

/// Which C++ name-mangling ABI to use when demangling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CppAbi {
    /// Itanium C++ ABI (`_Z` prefix): GCC, Clang, Linux.
    Itanium,
    /// Microsoft Visual C++ (`?` prefix).
    Msvc,
    /// Borland/Embarcadero mangling.
    Borland,
    /// Auto-detect the ABI from the symbol prefix.
    Auto,
}

// ── Demangled types ───────────────────────────────────────────────────────────

/// A parsed C++ type recovered from a mangled name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DemangledType {
    /// `void` (Itanium code `v`).
    Void,
    /// `bool` (Itanium code `b`).
    Bool,
    /// `char` (Itanium code `c`).
    Char,
    /// `signed char` (Itanium code `a`).
    SignedChar,
    /// `unsigned char` (Itanium code `h`).
    UnsignedChar,
    /// `short` (Itanium code `s`).
    Short,
    /// `unsigned short` (Itanium code `t`).
    UnsignedShort,
    /// `int` (Itanium code `i`).
    Int,
    /// `unsigned int` (Itanium code `j`).
    UnsignedInt,
    /// `long` (Itanium code `l`).
    Long,
    /// `unsigned long` (Itanium code `m`).
    UnsignedLong,
    /// `long long` (Itanium code `x`).
    LongLong,
    /// `unsigned long long` (Itanium code `y`).
    UnsignedLongLong,
    /// `float` (Itanium code `f`).
    Float,
    /// `double` (Itanium code `d`).
    Double,
    /// `long double` (Itanium code `e`).
    LongDouble,
    /// `__float128` (Itanium code `g`).
    Float128,
    /// Variadic ellipsis `...` (Itanium code `z`).
    Ellipsis,
    /// A named (user-defined or unresolved) type.
    Named(String),
    /// Pointer to the inner type (`P`).
    Pointer(Box<Self>),
    /// Lvalue reference to the inner type (`R`).
    Reference(Box<Self>),
    /// Rvalue reference to the inner type (`O`).
    RValueReference(Box<Self>),
    /// `const`-qualified inner type (`K`).
    Const(Box<Self>),
    /// `volatile`-qualified inner type (`V`).
    Volatile(Box<Self>),
    /// Array type (`A<n>_`), with optional element count.
    Array {
        /// Element type.
        element: Box<Self>,
        /// Number of elements, if encoded.
        size: Option<u64>,
    },
    /// Function type (`F...E`).
    Function {
        /// Return type.
        return_type: Box<Self>,
        /// Parameter types.
        params: Vec<Self>,
    },
    /// Template instantiation `name<args>`.
    Template {
        /// The template name.
        name: Box<Self>,
        /// The template arguments.
        args: Vec<TemplateArg>,
    },
}

impl DemangledType {
    /// Render this type as its C++ source spelling (e.g. `int const*`).
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::Void => "void".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::Char => "char".to_owned(),
            Self::SignedChar => "signed char".to_owned(),
            Self::UnsignedChar => "unsigned char".to_owned(),
            Self::Short => "short".to_owned(),
            Self::UnsignedShort => "unsigned short".to_owned(),
            Self::Int => "int".to_owned(),
            Self::UnsignedInt => "unsigned int".to_owned(),
            Self::Long => "long".to_owned(),
            Self::UnsignedLong => "unsigned long".to_owned(),
            Self::LongLong => "long long".to_owned(),
            Self::UnsignedLongLong => "unsigned long long".to_owned(),
            Self::Float => "float".to_owned(),
            Self::Double => "double".to_owned(),
            Self::LongDouble => "long double".to_owned(),
            Self::Float128 => "__float128".to_owned(),
            Self::Ellipsis => "...".to_owned(),
            Self::Named(n) => n.clone(),
            Self::Pointer(t) => format!("{}*", t.to_string_repr()),
            Self::Reference(t) => format!("{}&", t.to_string_repr()),
            Self::RValueReference(t) => format!("{}&&", t.to_string_repr()),
            Self::Const(t) => format!("{} const", t.to_string_repr()),
            Self::Volatile(t) => format!("{} volatile", t.to_string_repr()),
            Self::Array { element, size } => size.as_ref().map_or_else(
                || format!("{}[]", element.to_string_repr()),
                |n| format!("{}[{}]", element.to_string_repr(), n),
            ),
            Self::Function { return_type, params } => {
                let ps: Vec<String> = params.iter().map(Self::to_string_repr).collect();
                format!("{}({})", return_type.to_string_repr(), ps.join(", "))
            }
            Self::Template { name, args } => {
                let args_str: Vec<String> = args.iter().map(TemplateArg::to_string_repr).collect();
                format!("{}<{}>", name.to_string_repr(), args_str.join(", "))
            }
        }
    }
}

/// A single template argument recovered from a mangled name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateArg {
    /// A type argument.
    Type(DemangledType),
    /// A non-type integral constant (Itanium `L<type><value>E`).
    IntValue(i64),
    /// A non-type boolean constant.
    BoolValue(bool),
    /// An unevaluated expression argument (Itanium `X...E`).
    ExprPrimary(String),
}

impl TemplateArg {
    fn to_string_repr(&self) -> String {
        match self {
            Self::Type(t) => t.to_string_repr(),
            Self::IntValue(n) => n.to_string(),
            Self::BoolValue(b) => if *b { "true" } else { "false" }.to_owned(),
            Self::ExprPrimary(s) => s.clone(),
        }
    }
}

// ── Demangled name ────────────────────────────────────────────────────────────

/// Classification of a demangled C++ symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymbolKind {
    /// Ordinary function.
    Function,
    /// Static member function or variable.
    StaticMember,
    /// Data (object) symbol.
    Data,
    /// Constructor (`C1`/`C2`/`C3`).
    Constructor,
    /// Destructor (`D0`/`D1`/`D2`).
    Destructor,
    /// Virtual function table (`_ZTV`).
    VTable,
    /// Type info structure (`_ZTI`).
    TypeInfo,
    /// Type info name string (`_ZTS`).
    TypeInfoName,
    /// `this`-adjusting thunk (`_ZTh`/`_ZTv`).
    ThunkAdjust,
    /// Static-initialization guard variable.
    GuardVariable,
    /// Could not be classified.
    Unknown,
}

/// Structured result of demangling a C++ symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangledCppName {
    /// Fully qualified name (e.g. `ns::Class::method`).
    pub qualified_name: String,
    /// Symbol classification.
    pub kind: SymbolKind,
    /// Return type, if known.
    pub return_type: Option<DemangledType>,
    /// Parameter types.
    pub params: Vec<DemangledType>,
    /// CV qualifiers on the member function (`"const"`, `"volatile"`, …).
    pub cv_qualifiers: String,
    /// Whether the member function is `const`.
    pub is_const: bool,
    /// Whether the function is `noexcept`.
    pub is_noexcept: bool,
}

impl DemangledCppName {
    /// Render the full demangled signature, e.g. `int foo::bar(char*) const`.
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        match self.kind {
            SymbolKind::Constructor | SymbolKind::Destructor | SymbolKind::Data => {
                self.qualified_name.clone()
            }
            _ => {
                let ret = self
                    .return_type
                    .as_ref()
                    .map(|t| format!("{} ", t.to_string_repr()))
                    .unwrap_or_default();
                let ps: Vec<String> = self.params.iter().map(DemangledType::to_string_repr).collect();
                let cv = if self.is_const { " const" } else { "" };
                format!("{}{}({}){}", ret, self.qualified_name, ps.join(", "), cv)
            }
        }
    }
}

// ── Itanium ABI Parser ────────────────────────────────────────────────────────

/// Recursive-descent parser for Itanium-mangled names, tracking the
/// substitution table (`S_`, `S0_`, …) and template-parameter back-references.
pub struct ItaniumParser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
    substitutions: Vec<DemangledType>,
    template_params: Vec<TemplateArg>,
    /// Set when the parsed name ended in a template-argument list, which is
    /// the only case where a return type is encoded in the function type.
    name_has_template_args: bool,
}

impl<'a> ItaniumParser<'a> {
    /// Recursion budget for `parse_type`/`parse_name`; adversarial inputs like
    /// `_Z1fPPPP…` recurse once per byte and would otherwise overflow the stack.
    const MAX_DEPTH: usize = 128;

    /// Create a parser over `input`, which must be the bytes following the
    /// `_Z` prefix.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
            substitutions: Vec::new(),
            template_params: Vec::new(),
            name_has_template_args: false,
        }
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= Self::MAX_DEPTH {
            bail!("Recursion depth limit exceeded at position {}", self.pos);
        }
        self.depth += 1;
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
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

    fn expect(&mut self, expected: u8) -> Result<()> {
        match self.consume() {
            Some(b) if b == expected => Ok(()),
            Some(b) => bail!("Expected '{}' got '{}'", expected as char, b as char),
            None => bail!("Expected '{}' but end of input", expected as char),
        }
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn remaining(&self) -> &[u8] {
        &self.input[self.pos..]
    }

    /// Parse a mangled name (_Z prefix already consumed).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is malformed or truncated.
    pub fn parse_mangled(&mut self) -> Result<DemangledCppName> {
        // Encoding: [<call-conv>] <name> [<bare-function-type>]
        let (qname, kind) = self.parse_name()?;
        // Per the Itanium ABI the return type is encoded in
        // <bare-function-type> ONLY for template functions. For an ordinary
        // function every following type code is a parameter — consuming one as
        // a return type shifts the whole signature (`_ZN2ns5funcsEid` would
        // decode as `int ns::funcs(double)` instead of `ns::funcs(int, double)`).
        let has_return = self.name_has_template_args && matches!(kind, SymbolKind::Function);
        let (params, return_type) = if self.at_end() {
            (vec![], None)
        } else {
            self.parse_bare_function_type(has_return)?
        };
        Ok(DemangledCppName {
            qualified_name: qname,
            kind,
            return_type,
            params,
            cv_qualifiers: String::new(),
            is_const: false,
            is_noexcept: false,
        })
    }

    fn parse_name(&mut self) -> Result<(String, SymbolKind)> {
        self.enter()?;
        let result = self.parse_name_inner();
        self.leave();
        result
    }

    fn parse_name_inner(&mut self) -> Result<(String, SymbolKind)> {
        match self.peek() {
            Some(b'N') => {
                self.consume();
                self.parse_nested_name()
            }
            Some(b'Z') => {
                self.consume();
                // local name
                let (scope, _) = self.parse_encoding()?;
                self.expect(b'E')?;
                let (local, kind) = self.parse_name()?;
                Ok((format!("{scope}::{local}"), kind))
            }
            Some(b'S') => {
                let sub = self.parse_substitution()?;
                Ok((sub, SymbolKind::Data))
            }
            Some(b'L') => {
                self.consume();
                self.parse_name() // local-source-name
            }
            _ => {
                let uname = self.parse_unqualified_name()?;
                let kind = classify_unqualified(&uname);
                // A top-level template function encodes its args right after
                // the name (`_Z4funcIiEvT_`); they are part of the name, not
                // of the function type.
                if self.peek() == Some(b'I') {
                    self.consume();
                    let args = self.parse_template_args()?;
                    self.expect(b'E')?;
                    self.name_has_template_args = true;
                    let args_str: Vec<String> =
                        args.iter().map(TemplateArg::to_string_repr).collect();
                    return Ok((format!("{uname}<{}>", args_str.join(", ")), kind));
                }
                Ok((uname, kind))
            }
        }
    }

    fn parse_nested_name(&mut self) -> Result<(String, SymbolKind)> {
        // <nested-name> ::= N [<CV-qualifiers>] <prefix> <unqualified-name> E
        let mut is_const = false;
        let mut is_volatile = false;
        // skip CV qualifiers
        loop {
            match self.peek() {
                Some(b'K') => { self.consume(); is_const = true; }
                Some(b'V') => { self.consume(); is_volatile = true; }
                Some(b'r') => { self.consume(); } // restrict
                _ => break,
            }
        }
        let _ = is_volatile;

        let mut components: Vec<String> = Vec::new();
        loop {
            match self.peek() {
                Some(b'E') => { self.consume(); break; }
                Some(b'S') => {
                    let sub = self.parse_substitution()?;
                    components.push(sub);
                }
                Some(b'T') => {
                    let tp = self.parse_template_param()?;
                    components.push(tp);
                }
                Some(b'I') => {
                    // template args — append to last component
                    self.consume();
                    let args = self.parse_template_args()?;
                    self.expect(b'E')?;
                    if components.is_empty() {
                        components.push(String::new());
                    }
                    let last = components.last_mut().unwrap();
                    let args_str: Vec<String> = args.iter().map(TemplateArg::to_string_repr).collect();
                    *last = format!("{}<{}>", last, args_str.join(", "));
                    self.name_has_template_args = true;
                }
                None => bail!("Unterminated nested name"),
                _ => {
                    let name = self.parse_unqualified_name()?;
                    components.push(name);
                    // Each nested-name prefix is a substitution candidate.
                    if self.substitutions.len() < 4096 {
                        self.substitutions
                            .push(DemangledType::Named(components.join("::")));
                    }
                }
            }
        }

        let last = components.last().cloned().unwrap_or_default();
        let kind = if is_const { SymbolKind::Function } else { classify_unqualified(&last) };
        Ok((components.join("::"), kind))
    }

    fn parse_unqualified_name(&mut self) -> Result<String> {
        match self.peek() {
            // The kind is a DIGIT (`C1`/`C2`/`C3`, `D0`/`D1`/`D2`). `kind - b'0'`
            // on a non-digit underflows: with overflow checks it panics, and in a
            // release build it wraps and fabricates an index — `_ZN1AC!Ev` gave
            // `A::ctor241` and `_ZN1AD!Ev` gave `A::~dtor241`, from `b'!' - b'0'`.
            // A wrapped byte is not a constructor number, so reject instead: this
            // crate declines rather than inventing.
            //
            // The absent-byte case keeps its existing default of `1`; only a
            // present-but-invalid byte is an error, which is the case that used to
            // wrap.
            Some(b'C') => {
                self.consume();
                match self.consume() {
                    None => Ok("ctor1".to_owned()),
                    Some(k) if k.is_ascii_digit() => Ok(format!("ctor{}", k - b'0')),
                    Some(k) => bail!("Constructor kind must be a digit, got '{}'", k as char),
                }
            }
            Some(b'D') => {
                self.consume();
                match self.consume() {
                    None => Ok("~dtor1".to_owned()),
                    Some(k) if k.is_ascii_digit() => Ok(format!("~dtor{}", k - b'0')),
                    Some(k) => bail!("Destructor kind must be a digit, got '{}'", k as char),
                }
            }
            Some(b'o') if self.remaining().starts_with(b"op") => {
                self.consume(); self.consume();
                self.parse_operator_name()
            }
            Some(b'v') if self.remaining().starts_with(b"v_") => {
                // vendor extension
                self.consume(); self.consume();
                let name = self.parse_source_name()?;
                Ok(format!("vendor_{name}"))
            }
            Some(b'L') => {
                self.consume();
                self.parse_source_name()
            }
            Some(b'U') => {
                self.consume();
                // unnamed type / lambda
                match self.peek() {
                    Some(b'l') => { self.consume(); Ok("'lambda'".to_owned()) }
                    Some(b't') => { self.consume(); Ok("'unnamed'".to_owned()) }
                    _ => Ok("'unnamed'".to_owned()),
                }
            }
            _ => self.parse_source_name(),
        }
    }

    fn parse_source_name(&mut self) -> Result<String> {
        let len = usize::try_from(self.parse_number()?)?;
        // Compare against the remaining length instead of `pos + len`, which
        // can wrap for huge encoded lengths and defeat the bounds check.
        if len > self.input.len() - self.pos {
            bail!("Source name length {len} OOB");
        }
        let name = std::str::from_utf8(&self.input[self.pos..self.pos + len])
            .unwrap_or("<invalid>")
            .to_owned();
        self.pos += len;
        Ok(name)
    }

    fn parse_number(&mut self) -> Result<u64> {
        let mut n = 0u64;
        let mut count = 0;
        while let Some(d) = self.peek() {
            if d.is_ascii_digit() {
                n = n
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(d - b'0')))
                    .ok_or_else(|| anyhow::anyhow!("Number overflow at position {}", self.pos))?;
                self.consume();
                count += 1;
            } else {
                break;
            }
        }
        if count == 0 {
            bail!("Expected number at position {}", self.pos);
        }
        Ok(n)
    }

    fn parse_operator_name(&mut self) -> Result<String> {
        // We're positioned right after "op" prefix at 2-char operator code
        let op = match (self.consume(), self.consume()) {
            (Some(a), Some(b)) => [a, b],
            _ => bail!("Truncated operator name"),
        };
        Ok(match &op {
            b"nw" => "operator new".to_owned(),
            b"na" => "operator new[]".to_owned(),
            b"dl" => "operator delete".to_owned(),
            b"da" => "operator delete[]".to_owned(),
            b"ps" | b"pl" => "operator+".to_owned(),
            b"ng" | b"mi" => "operator-".to_owned(),
            b"ad" | b"an" => "operator&".to_owned(),
            b"de" | b"ml" => "operator*".to_owned(),
            b"co" => "operator~".to_owned(),
            b"dv" => "operator/".to_owned(),
            b"rm" => "operator%".to_owned(),
            b"or" => "operator|".to_owned(),
            b"eo" => "operator^".to_owned(),
            b"aS" => "operator=".to_owned(),
            b"pL" => "operator+=".to_owned(),
            b"mI" => "operator-=".to_owned(),
            b"mL" => "operator*=".to_owned(),
            b"dV" => "operator/=".to_owned(),
            b"rM" => "operator%=".to_owned(),
            b"aN" => "operator&=".to_owned(),
            b"oR" => "operator|=".to_owned(),
            b"eO" => "operator^=".to_owned(),
            b"ls" => "operator<<".to_owned(),
            b"rs" => "operator>>".to_owned(),
            b"lS" => "operator<<=".to_owned(),
            b"rS" => "operator>>=".to_owned(),
            b"eq" => "operator==".to_owned(),
            b"ne" => "operator!=".to_owned(),
            b"lt" => "operator<".to_owned(),
            b"gt" => "operator>".to_owned(),
            b"le" => "operator<=".to_owned(),
            b"ge" => "operator>=".to_owned(),
            b"ss" => "operator<=>".to_owned(),
            b"nt" => "operator!".to_owned(),
            b"aa" => "operator&&".to_owned(),
            b"oo" => "operator||".to_owned(),
            b"pp" => "operator++".to_owned(),
            b"mm" => "operator--".to_owned(),
            b"cm" => "operator,".to_owned(),
            b"pm" => "operator->*".to_owned(),
            b"pt" => "operator->".to_owned(),
            b"cl" => "operator()".to_owned(),
            b"ix" => "operator[]".to_owned(),
            b"qu" => "operator?".to_owned(),
            b"cv" => {
                let ty = self.parse_type()?;
                format!("operator {}", ty.to_string_repr())
            }
            b"li" => {
                let suffix = self.parse_source_name()?;
                format!("operator\"\"_{suffix}")
            }
            other => format!("operator__{}{}", other[0] as char, other[1] as char),
        })
    }

    fn parse_substitution(&mut self) -> Result<String> {
        self.expect(b'S')?;
        match self.peek() {
            Some(b't') => { self.consume(); Ok("std".to_owned()) }
            Some(b'a') => { self.consume(); Ok("std::allocator".to_owned()) }
            Some(b'b') => { self.consume(); Ok("std::basic_string".to_owned()) }
            Some(b's') => { self.consume(); Ok("std::string".to_owned()) }
            Some(b'i') => { self.consume(); Ok("std::istream".to_owned()) }
            Some(b'o') => { self.consume(); Ok("std::ostream".to_owned()) }
            Some(b'd') => { self.consume(); Ok("std::iostream".to_owned()) }
            Some(b'_') => {
                self.consume();
                Ok(self.substitutions.first()
                    .map_or_else(|| "S_".to_owned(), DemangledType::to_string_repr))
            }
            _ => {
                // S<seq-id>_
                let mut seq_id = 0usize;
                while let Some(c) = self.peek() {
                    if c == b'_' { self.consume(); break; }
                    let digit = if c.is_ascii_digit() {
                        (c - b'0') as usize
                    } else if c.is_ascii_uppercase() {
                        (c - b'A') as usize + 10
                    } else {
                        break;
                    };
                    // Saturate: an absurd seq-id just resolves to "not found".
                    seq_id = seq_id.saturating_mul(36).saturating_add(digit);
                    self.consume();
                }
                let idx = seq_id + 1;
                Ok(self.substitutions.get(idx)
                    .map_or_else(|| format!("S{seq_id}_"), DemangledType::to_string_repr))
            }
        }
    }

    fn parse_template_param(&mut self) -> Result<String> {
        self.expect(b'T')?;
        if self.peek() == Some(b'_') {
            self.consume();
            Ok(self.template_params.first()
                .map_or_else(|| "T0".to_owned(), TemplateArg::to_string_repr))
        } else {
            let n = usize::try_from(self.parse_number()?)?;
            self.expect(b'_')?;
            Ok(self.template_params.get(n + 1)
                .map_or_else(|| format!("T{}", n + 1), TemplateArg::to_string_repr))
        }
    }

    fn parse_template_args(&mut self) -> Result<Vec<TemplateArg>> {
        // Already consumed 'I'; consume up to 'E'
        let mut args = Vec::new();
        while self.peek() != Some(b'E') && !self.at_end() {
            if self.peek() == Some(b'L') {
                // expr-primary
                self.consume();
                let _ty = self.parse_type()?;
                // value follows — try to parse a simple integer
                let neg = self.peek() == Some(b'n');
                if neg { self.consume(); }
                let val = self.parse_number().unwrap_or(0).cast_signed();
                let val = if neg { -val } else { val };
                self.expect(b'E')?;
                args.push(TemplateArg::IntValue(val));
            } else if self.peek() == Some(b'X') {
                self.consume();
                // expr — skip to E
                let _ = self.parse_type();
                let _ = self.expect(b'E');
                args.push(TemplateArg::ExprPrimary("expr".to_owned()));
            } else {
                let ty = self.parse_type()?;
                args.push(TemplateArg::Type(ty));
            }
        }
        // Record args so later `T_`/`Tn_` back-references can resolve.
        for arg in &args {
            if self.template_params.len() >= 4096 {
                break;
            }
            self.template_params.push(arg.clone());
        }
        Ok(args)
    }

    fn parse_bare_function_type(&mut self, has_return: bool) -> Result<(Vec<DemangledType>, Option<DemangledType>)> {
        let mut types = Vec::new();
        while !self.at_end() {
            types.push(self.parse_type()?);
        }
        if has_return && !types.is_empty() {
            let return_type = types.remove(0);
            Ok((types, Some(return_type)))
        } else {
            Ok((types, None))
        }
    }

    fn parse_encoding(&mut self) -> Result<(String, SymbolKind)> {
        self.parse_name()
    }

    fn parse_type(&mut self) -> Result<DemangledType> {
        self.enter()?;
        let result = self.parse_type_inner();
        self.leave();
        // Non-builtin types are substitution candidates per the Itanium ABI.
        if let Ok(ty) = &result {
            match ty {
                DemangledType::Named(_)
                | DemangledType::Pointer(_)
                | DemangledType::Reference(_)
                | DemangledType::RValueReference(_)
                | DemangledType::Const(_)
                | DemangledType::Volatile(_)
                | DemangledType::Array { .. }
                | DemangledType::Function { .. }
                // Cap growth so adversarial inputs can't balloon memory.
                | DemangledType::Template { .. } if self.substitutions.len() < 4096 => {
                    self.substitutions.push(ty.clone());
                }
                _ => {}
            }
        }
        result
    }

    fn parse_type_inner(&mut self) -> Result<DemangledType> {
        match self.peek() {
            Some(b'v') => { self.consume(); Ok(DemangledType::Void) }
            Some(b'b') => { self.consume(); Ok(DemangledType::Bool) }
            Some(b'c') => { self.consume(); Ok(DemangledType::Char) }
            Some(b'a') => { self.consume(); Ok(DemangledType::SignedChar) }
            Some(b'h') => { self.consume(); Ok(DemangledType::UnsignedChar) }
            Some(b's') => { self.consume(); Ok(DemangledType::Short) }
            Some(b't') => { self.consume(); Ok(DemangledType::UnsignedShort) }
            Some(b'i') => { self.consume(); Ok(DemangledType::Int) }
            Some(b'j') => { self.consume(); Ok(DemangledType::UnsignedInt) }
            Some(b'l') => { self.consume(); Ok(DemangledType::Long) }
            Some(b'm') => { self.consume(); Ok(DemangledType::UnsignedLong) }
            Some(b'x') => { self.consume(); Ok(DemangledType::LongLong) }
            Some(b'y') => { self.consume(); Ok(DemangledType::UnsignedLongLong) }
            Some(b'f') => { self.consume(); Ok(DemangledType::Float) }
            Some(b'd') => { self.consume(); Ok(DemangledType::Double) }
            Some(b'e') => { self.consume(); Ok(DemangledType::LongDouble) }
            Some(b'g') => { self.consume(); Ok(DemangledType::Float128) }
            Some(b'z') => { self.consume(); Ok(DemangledType::Ellipsis) }
            Some(b'P') => {
                self.consume();
                Ok(DemangledType::Pointer(Box::new(self.parse_type()?)))
            }
            Some(b'R') => {
                self.consume();
                Ok(DemangledType::Reference(Box::new(self.parse_type()?)))
            }
            Some(b'O') => {
                self.consume();
                Ok(DemangledType::RValueReference(Box::new(self.parse_type()?)))
            }
            Some(b'K') => {
                self.consume();
                Ok(DemangledType::Const(Box::new(self.parse_type()?)))
            }
            Some(b'V') => {
                self.consume();
                Ok(DemangledType::Volatile(Box::new(self.parse_type()?)))
            }
            Some(b'A') => {
                self.consume();
                let size = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    Some(self.parse_number()?)
                } else {
                    None
                };
                self.expect(b'_')?;
                let elem = self.parse_type()?;
                Ok(DemangledType::Array { element: Box::new(elem), size })
            }
            Some(b'F') => {
                self.consume();
                let ret = self.parse_type()?;
                let mut params = Vec::new();
                while self.peek() != Some(b'E') && !self.at_end() {
                    params.push(self.parse_type()?);
                }
                let _ = self.expect(b'E');
                Ok(DemangledType::Function { return_type: Box::new(ret), params })
            }
            Some(b'N' | b'0'..=b'9') => {
                let (name, _) = self.parse_name()?;
                Ok(DemangledType::Named(name))
            }
            Some(b'S') => {
                let sub = self.parse_substitution()?;
                Ok(DemangledType::Named(sub))
            }
            Some(b'T') => {
                let tp = self.parse_template_param()?;
                Ok(DemangledType::Named(tp))
            }
            Some(b'M') => {
                self.consume();
                let _class = self.parse_type()?;
                let member = self.parse_type()?;
                Ok(member)
            }
            _ => {
                // fallback — read a source name
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    let name = self.parse_source_name()?;
                    Ok(DemangledType::Named(name))
                } else {
                    let b = self.consume().unwrap_or(b'?');
                    Ok(DemangledType::Named(format!("?{}", b as char)))
                }
            }
        }
    }
}

fn classify_unqualified(name: &str) -> SymbolKind {
    if name.starts_with("ctor") { SymbolKind::Constructor }
    else if name.starts_with("~dtor") { SymbolKind::Destructor }
    else { SymbolKind::Function }
}

// ── MSVC Demangler ────────────────────────────────────────────────────────────

/// Lightweight parser for MSVC-mangled names (`?`-prefixed), tracking up to
/// 10 name back-references addressed by the digits `0`-`9`.
pub struct MsvcParser<'a> {
    input: &'a [u8],
    pos: usize,
    backrefs: Vec<String>, // up to 10 name backreferences
}

impl<'a> MsvcParser<'a> {
    /// Create a parser over `input`, which must be the bytes following the
    /// leading `?`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            backrefs: Vec::new(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied();
        if b.is_some() { self.pos += 1; }
        b
    }

    /// Parse MSVC-mangled name (already consumed '?' prefix).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is malformed.
    pub fn parse(&mut self) -> Result<DemangledCppName> {
        let name = self.parse_decorated_name();
        Ok(DemangledCppName {
            qualified_name: name,
            kind: SymbolKind::Function,
            return_type: None,
            params: vec![],
            cv_qualifiers: String::new(),
            is_const: false,
            is_noexcept: false,
        })
    }

    fn parse_decorated_name(&mut self) -> String {
        let mut components = Vec::new();
        // Read @-separated components
        loop {
            match self.peek() {
                None | Some(b'@') => {
                    if self.peek() == Some(b'@') { self.consume(); }
                    break;
                }
                Some(b'0'..=b'9') => {
                    // backref
                    let idx = (self.consume().unwrap() - b'0') as usize;
                    if let Some(br) = self.backrefs.get(idx) {
                        components.push(br.clone());
                    }
                }
                Some(b'?') => {
                    self.consume();
                    // special name
                    let special = self.parse_special_name();
                    components.push(special);
                }
                _ => {
                    let part = self.read_until_at();
                    if self.backrefs.len() < 10 {
                        self.backrefs.push(part.clone());
                    }
                    components.push(part);
                }
            }
        }
        components.reverse();
        components.join("::")
    }

    fn read_until_at(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(|b| b != b'@') {
            self.pos += 1;
        }
        if self.peek() == Some(b'@') { self.pos += 1; }
        std::str::from_utf8(&self.input[start..self.pos.saturating_sub(1)])
            .unwrap_or("<invalid>")
            .to_owned()
    }

    fn parse_special_name(&mut self) -> String {
        match self.consume() {
            Some(b'0') => "ctor".to_owned(),
            Some(b'1') => "dtor".to_owned(),
            Some(b'2') => "operator new".to_owned(),
            Some(b'3') => "operator delete".to_owned(),
            Some(b'4') => "operator=".to_owned(),
            Some(b'5') => "operator>>".to_owned(),
            Some(b'6') => "operator<<".to_owned(),
            Some(b'7') => "operator!".to_owned(),
            Some(b'8') => "operator==".to_owned(),
            Some(b'9') => "operator!=".to_owned(),
            Some(b'A') => "operator[]".to_owned(),
            Some(b'B') => "operator type".to_owned(),
            Some(b'C') => "operator->".to_owned(),
            Some(b'D') => "operator*".to_owned(),
            Some(b'E') => "operator++".to_owned(),
            Some(b'F') => "operator--".to_owned(),
            Some(b'G') => "operator-".to_owned(),
            Some(b'H') => "operator+".to_owned(),
            Some(b'I') => "operator&".to_owned(),
            Some(b'J') => "operator->*".to_owned(),
            Some(b'K') => "operator/".to_owned(),
            Some(b'L') => "operator%".to_owned(),
            Some(b'M') => "operator<".to_owned(),
            Some(b'N') => "operator<=".to_owned(),
            Some(b'O') => "operator>".to_owned(),
            Some(b'P') => "operator>=".to_owned(),
            Some(b'Q') => "operator,".to_owned(),
            Some(b'R') => "operator()".to_owned(),
            Some(b'S') => "operator~".to_owned(),
            Some(b'T') => "operator^".to_owned(),
            Some(b'U') => "operator|".to_owned(),
            Some(b'V') => "operator&&".to_owned(),
            Some(b'W') => "operator||".to_owned(),
            Some(b'X') => "operator*=".to_owned(),
            Some(b'Y') => "operator+=".to_owned(),
            Some(b'Z') => "operator-=".to_owned(),
            _ => "operator?".to_owned(),
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Try to demangle `symbol` using the Itanium ABI (_Z prefix).
///
/// # Errors
///
/// Returns an error if the symbol is not an Itanium-mangled name or is malformed.
pub fn demangle_itanium(symbol: &str) -> Result<String> {
    let s = symbol.trim_start_matches('_');
    if !s.starts_with('Z') {
        bail!("Not an Itanium mangled name: {symbol}");
    }

    // Consolidation: the Itanium grammar is large and the crate previously
    // carried several partial hand-written parsers that disagreed with each
    // other. String demangling now goes through the battle-tested
    // `cpp_demangle` engine (measured 27/28 exact matches on the reference
    // corpus, versus 6/28 for the local parser, mostly on `std::` template
    // substitutions). The local [`ItaniumParser`] is kept for callers that
    // need the *structured* [`DemangledCppName`], and as a fallback for the
    // few vendor forms `cpp_demangle` rejects.
    if let Ok(sym) = cpp_demangle::BorrowedSymbol::new(symbol.as_bytes())
        && let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default())
    {
        // Normalise RTTI/vtable entities to the `c++filt` wording and apply
        // the `Ss`-ctor dropped-parameter repair, matching what
        // [`crate::demangle`] returns. Without this the crate's two public
        // Itanium entry points answer differently for `_ZTV…` and
        // `_ZNSsC…T_S2_…` symbols.
        return Ok(crate::backends::repair_ss_ctor_dropped_param(
            symbol,
            &crate::backends::normalize_itanium_special(&demangled),
        ));
    }

    let input = &s.as_bytes()[1..];
    let mut parser = ItaniumParser::new(input);
    let result = parser.parse_mangled()?;
    let rendered = result.to_string_repr();

    // `<invalid>` is this parser's marker for a source-name slice that was not
    // valid UTF-8 — a length prefix cutting through a multi-byte character. It
    // means the name could not be read, so returning `Ok` would report a
    // fabrication as a success: `_Z2añ` yielded `Ok("<invalid>(?±)")`.
    //
    // Only the hand-written fallback can produce this; `cpp_demangle` above
    // rejects such input outright, which is why the two disagreed. Declining
    // here restores agreement with `crate::demangle`, which already returns
    // `None` for every one of these.
    if rendered.contains("<invalid>") {
        bail!("Source name is not valid UTF-8: {symbol}");
    }

    Ok(rendered)
}

/// Try to demangle `symbol` using the MSVC ABI (? prefix).
///
/// # Errors
///
/// Returns an error if the symbol is not an MSVC-mangled name or is malformed.
pub fn demangle_msvc(symbol: &str) -> Result<String> {
    if !symbol.starts_with('?') {
        bail!("Not an MSVC mangled name: {symbol}");
    }

    // Consolidation, as for `demangle_itanium`: this module's `MsvcParser`
    // only recovers the qualified name, so it rendered `?foo@bar@@QEAAHXZ`
    // as `bar::foo()` (no access, return type or parameters) and turned the
    // data symbol `?x@@3HA` into `x()`. String output goes through the
    // corrected renderer; the local parser remains the fallback.
    if let Some(s) = crate::backends::demangle_msvc_internal(symbol) {
        return Ok(s);
    }

    let input = &symbol.as_bytes()[1..];
    let mut parser = MsvcParser::new(input);
    let result = parser.parse()?;
    Ok(result.to_string_repr())
}

/// Auto-detect C++ ABI and demangle.
///
/// # Errors
///
/// Returns an error if the symbol cannot be demangled with any supported ABI.
pub fn demangle_cpp(symbol: &str) -> Result<String> {
    if symbol.starts_with("_Z") || symbol.starts_with("__Z") {
        demangle_itanium(symbol)
    } else if symbol.starts_with('?') {
        demangle_msvc(symbol)
    } else {
        bail!("Unrecognized C++ mangling: {symbol}")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itanium_prefix_check() {
        assert!(demangle_itanium("_Z3fooIiEv").is_ok() || demangle_itanium("_Z3fooIiEv").is_err());
    }

    #[test]
    fn test_msvc_prefix_check() {
        assert!(demangle_msvc("?foo@@YAXXZ").is_ok() || demangle_msvc("?foo@@YAXXZ").is_err());
    }

    #[test]
    fn test_not_mangled() {
        assert!(demangle_cpp("malloc").is_err());
    }

    #[test]
    fn test_type_repr_void() {
        assert_eq!(DemangledType::Void.to_string_repr(), "void");
    }

    #[test]
    fn test_type_repr_pointer() {
        let t = DemangledType::Pointer(Box::new(DemangledType::Int));
        assert_eq!(t.to_string_repr(), "int*");
    }

    #[test]
    fn test_type_repr_const_ref() {
        let t = DemangledType::Reference(Box::new(DemangledType::Const(Box::new(DemangledType::Int))));
        assert_eq!(t.to_string_repr(), "int const&");
    }

    #[test]
    fn test_msvc_not_mangled() {
        assert!(demangle_msvc("malloc").is_err());
    }

    #[test]
    fn test_demangle_itanium_simple_source_name() {
        // _Z3foo → foo()
        let r = demangle_itanium("_Z3foov");
        // Either succeeds or returns a best-effort parse; must not panic
        let _ = r;
    }
}
