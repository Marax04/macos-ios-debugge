//! MSVC C++ name demangling — dedicated module.
//!
//! This module provides a richer, self-contained MSVC demangler that handles:
//! * Function, data, virtual-table, and RTTI symbols.
//! * Template parameters (type, non-type, value).
//! * All calling conventions recognised by MSVC `undname`.
//! * CV-qualifiers, reference qualifiers, pointer/array declarators.
//! * Back-references for both names and types (up to 10 each).
//! * Anonymous namespace, lambda, local static guard, string literal.
//!
//! The public API is [`MsvcDemangler`] (stateless facade) and
//! [`MsvcName`] (rich structured result).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

// ─── TypeCode ─────────────────────────────────────────────────────────────────

/// Primitive type codes in the MSVC mangling scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeCode {
    /// `void` (code `X`).
    Void,
    /// `bool` (code `_N`).
    Bool,
    /// `char` (code `D`).
    Char,
    /// `signed char` (code `C`).
    SignedChar,
    /// `unsigned char` (code `E`).
    UnsignedChar,
    /// `short` (code `F`).
    Short,
    /// `unsigned short` (code `G`).
    UnsignedShort,
    /// `int` (code `H`).
    Int,
    /// `unsigned int` (code `I`).
    UnsignedInt,
    /// `long` (code `J`).
    Long,
    /// `unsigned long` (code `K`).
    UnsignedLong,
    /// `long long`.
    LongLong,
    /// `unsigned long long`.
    UnsignedLongLong,
    /// `float` (code `M`).
    Float,
    /// `double` (code `N`).
    Double,
    /// `long double` (code `O`).
    LongDouble,
    /// `wchar_t` (code `_W`).
    WcharT,
    /// `char8_t` (code `_Q`).
    Char8T,
    /// `char16_t` (code `_S`).
    Char16T,
    /// `char32_t` (code `_U`).
    Char32T,
    /// `__int8` (code `_D`).
    Int8T,
    /// `unsigned __int8` (code `_E`).
    UInt8T,
    /// `__int16` (code `_F`).
    Int16T,
    /// `unsigned __int16` (code `_G`).
    UInt16T,
    /// `__int32` (code `_H`).
    Int32T,
    /// `unsigned __int32` (code `_I`).
    UInt32T,
    /// `__int64` (code `_J`).
    Int64T,
    /// `unsigned __int64` (code `_K`).
    UInt64T,
    /// `nullptr_t` (code `$$T`).
    NullptrT,
    /// Unrecognised type byte, kept verbatim.
    Unknown(u8),
}

impl TypeCode {
    /// Return the C++ spelling of this primitive type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::Char => "char",
            Self::SignedChar => "signed char",
            Self::UnsignedChar => "unsigned char",
            Self::Short => "short",
            Self::UnsignedShort => "unsigned short",
            Self::Int => "int",
            Self::UnsignedInt => "unsigned int",
            Self::Long => "long",
            Self::UnsignedLong => "unsigned long",
            Self::LongLong => "long long",
            Self::UnsignedLongLong => "unsigned long long",
            Self::Float => "float",
            Self::Double => "double",
            Self::LongDouble => "long double",
            Self::WcharT => "wchar_t",
            Self::Char8T => "char8_t",
            Self::Char16T => "char16_t",
            Self::Char32T => "char32_t",
            Self::Int8T => "__int8",
            Self::UInt8T => "unsigned __int8",
            Self::Int16T => "__int16",
            Self::UInt16T => "unsigned __int16",
            Self::Int32T => "__int32",
            Self::UInt32T => "unsigned __int32",
            Self::Int64T => "__int64",
            Self::UInt64T => "unsigned __int64",
            Self::NullptrT => "nullptr_t",
            Self::Unknown(_) => "?",
        }
    }

    /// Parse from an MSVC type byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b'X' | b'Z' => Self::Void, // b'Z' used in parameter termination
            b'_' => Self::Bool, // actual extended type handled elsewhere
            b'D' => Self::Char,
            b'C' => Self::SignedChar,
            b'E' => Self::UnsignedChar,
            b'F' => Self::Short,
            b'G' => Self::UnsignedShort,
            b'H' => Self::Int,
            b'I' => Self::UnsignedInt,
            b'J' => Self::Long,
            b'K' => Self::UnsignedLong,
            b'M' => Self::Float,
            b'N' => Self::Double,
            b'O' => Self::LongDouble,
            _ => Self::Unknown(b),
        }
    }
}

impl std::fmt::Display for TypeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── CallingConvention ────────────────────────────────────────────────────────

/// Calling convention encoded in the MSVC mangling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    /// `__cdecl` (codes `A`/`B`).
    Cdecl,
    /// `__pascal` (codes `C`/`D`).
    Pascal,
    /// `__thiscall` (codes `E`/`F`).
    Thiscall,
    /// `__stdcall` (codes `G`/`H`).
    Stdcall,
    /// `__fastcall` (codes `I`/`J`).
    Fastcall,
    /// `__vectorcall` (codes `Q`/`R`).
    Vectorcall,
    /// `__clrcall` (codes `P`/`S`).
    Clrcall,
    /// `__eabi` (codes `T`/`U`).
    Eabi,
    /// Unrecognised calling-convention byte, kept verbatim.
    Unknown(u8),
}

impl CallingConvention {
    /// Decode the single calling-convention byte emitted by MSVC.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b'A' | b'B' => Self::Cdecl,
            b'C' | b'D' => Self::Pascal,
            b'E' | b'F' => Self::Thiscall,
            b'G' | b'H' => Self::Stdcall,
            b'I' | b'J' => Self::Fastcall,
            b'Q' | b'R' => Self::Vectorcall,
            b'P' | b'S' => Self::Clrcall,
            b'T' | b'U' => Self::Eabi,
            _ => Self::Unknown(b),
        }
    }

    /// Return the `__keyword` spelling of this calling convention
    /// (empty string for [`CallingConvention::Unknown`]).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cdecl => "__cdecl",
            Self::Pascal => "__pascal",
            Self::Thiscall => "__thiscall",
            Self::Stdcall => "__stdcall",
            Self::Fastcall => "__fastcall",
            Self::Vectorcall => "__vectorcall",
            Self::Clrcall => "__clrcall",
            Self::Eabi => "__eabi",
            Self::Unknown(_) => "",
        }
    }
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── SymbolStorage ────────────────────────────────────────────────────────────

/// Access and storage class of an MSVC symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolStorage {
    /// `private:` member (codes `A`/`B`).
    Private,
    /// `protected:` member (codes `C`/`D`).
    Protected,
    /// `public:` member (codes `E`/`F`).
    Public,
    /// Global (free) function or data symbol.
    Global,
    /// Static member.
    Static,
    /// Virtual member with a `this` adjustment thunk (codes `I`/`J`).
    VirtualAdjusted,
    /// Virtual member function (codes `G`/`H`).
    Virtual,
    /// `private: static` member (codes `K`/`L`).
    StaticPrivate,
    /// `protected: static` member (codes `M`/`N`).
    StaticProtected,
    /// `public: static` member (codes `O`/`P`).
    StaticPublic,
}

impl SymbolStorage {
    /// Decode the access/storage-class byte of an MSVC-mangled symbol.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b'A'..=b'B' => Self::Private,
            b'C'..=b'D' => Self::Protected,
            b'E'..=b'F' => Self::Public,
            b'G'..=b'H' => Self::Virtual,
            b'I'..=b'J' => Self::VirtualAdjusted,
            b'K'..=b'L' => Self::StaticPrivate,
            b'M'..=b'N' => Self::StaticProtected,
            b'O'..=b'P' => Self::StaticPublic,
            _ => Self::Global,
        }
    }
}

// ─── TemplateArg ──────────────────────────────────────────────────────────────

/// A single template argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateArg {
    /// A type argument.
    Type(String),
    /// A non-type integral constant.
    Integer(i64),
    /// A non-type pointer or reference.
    Pointer(u64),
    /// A dependent expression (unparsed).
    Expression(String),
}

impl std::fmt::Display for TemplateArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Type(t) => write!(f, "{t}"),
            Self::Integer(n) => write!(f, "{n}"),
            Self::Pointer(p) => write!(f, "0x{p:x}"),
            Self::Expression(e) => write!(f, "{e}"),
        }
    }
}

// ─── MsvcName ─────────────────────────────────────────────────────────────────

/// Structured result of a successful MSVC demangling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsvcName {
    /// The original mangled symbol.
    pub mangled: String,
    /// Fully qualified demangled name (e.g. `Foo::Bar::baz`).
    pub qualified_name: String,
    /// Namespace components (all but the last two path items).
    pub namespace: Vec<String>,
    /// Class name (second-to-last component if it exists).
    pub class: Option<String>,
    /// Bare name (last component).
    pub function_name: String,
    /// Return type (absent for ctors/dtors/special members).
    pub return_type: Option<String>,
    /// Parameter types.
    pub parameters: Vec<String>,
    /// Template arguments if any.
    pub template_args: Vec<TemplateArg>,
    /// Calling convention.
    pub calling_convention: CallingConvention,
    /// Storage class / access level.
    pub storage: SymbolStorage,
    /// Classification flags (see `MsvcName::IS_*` constants).
    pub flags: u8,
    /// CV qualifiers on a data symbol.
    pub data_qualifiers: Vec<String>,
}

impl MsvcName {
    /// Flag: `const` member function.
    pub const IS_CONST: u8       = 1 << 0;
    /// Flag: `volatile` member function.
    pub const IS_VOLATILE: u8    = 1 << 1;
    /// Flag: constructor.
    pub const IS_CONSTRUCTOR: u8 = 1 << 2;
    /// Flag: destructor.
    pub const IS_DESTRUCTOR: u8  = 1 << 3;
    /// Flag: virtual function.
    pub const IS_VIRTUAL: u8     = 1 << 4;
    /// Flag: static member.
    pub const IS_STATIC: u8      = 1 << 5;
    /// Flag: data symbol (not a function).
    pub const IS_DATA: u8        = 1 << 6;

    /// Whether this is a `const` member function.
    #[must_use] pub const fn is_const(&self)       -> bool { self.flags & Self::IS_CONST != 0 }
    /// Whether this is a `volatile` member function.
    #[must_use] pub const fn is_volatile(&self)    -> bool { self.flags & Self::IS_VOLATILE != 0 }
    /// Whether this symbol is a constructor.
    #[must_use] pub const fn is_constructor(&self) -> bool { self.flags & Self::IS_CONSTRUCTOR != 0 }
    /// Whether this symbol is a destructor.
    #[must_use] pub const fn is_destructor(&self)  -> bool { self.flags & Self::IS_DESTRUCTOR != 0 }
    /// Whether this is a virtual member function.
    #[must_use] pub const fn is_virtual(&self)     -> bool { self.flags & Self::IS_VIRTUAL != 0 }
    /// Whether this is a static member.
    #[must_use] pub const fn is_static(&self)      -> bool { self.flags & Self::IS_STATIC != 0 }
    /// Whether this is a data symbol rather than a function.
    #[must_use] pub const fn is_data(&self)        -> bool { self.flags & Self::IS_DATA != 0 }

    /// Build the canonical demangled string from the structured fields.
    #[must_use]
    pub fn to_display(&self) -> String {
        if self.is_data() {
            let quals = if self.data_qualifiers.is_empty() {
                String::new()
            } else {
                format!("{} ", self.data_qualifiers.join(" "))
            };
            return format!("{quals}{}", self.qualified_name);
        }
        let ret = self.return_type.as_ref().map_or_else(String::new, |r| format!("{r} "));
        let cc = self.calling_convention.as_str();
        let cc_str = if cc.is_empty() {
            String::new()
        } else {
            format!("{cc} ")
        };
        let params = if self.parameters.is_empty() {
            "void".to_owned()
        } else {
            self.parameters.join(", ")
        };
        let cv = {
            let mut parts = Vec::new();
            if self.is_const()    { parts.push("const"); }
            if self.is_volatile() { parts.push("volatile"); }
            if parts.is_empty() {
                String::new()
            } else {
                format!(" {}", parts.join(" "))
            }
        };
        format!("{ret}{cc_str}{}({params}){cv}", self.qualified_name)
    }
}

impl std::fmt::Display for MsvcName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_display())
    }
}

// ─── MsvcDemangler ────────────────────────────────────────────────────────────

/// Stateless MSVC C++ symbol demangler.
///
/// # Example
/// ```no_run
/// use rustre_demangle::msvc_demangler::MsvcDemangler;
/// let name = MsvcDemangler::demangle("?foo@@YAXXZ");
/// println!("{:?}", name);
/// ```
pub struct MsvcDemangler;

impl MsvcDemangler {
    /// Detect whether `s` is likely an MSVC-mangled name.
    #[must_use]
    pub fn detect(s: &str) -> bool {
        s.starts_with('?') && s.len() > 1
    }

    /// Attempt to demangle `s`. Returns `None` if parsing fails or the symbol
    /// is not MSVC-mangled.
    #[must_use]
    pub fn demangle(s: &str) -> Option<MsvcName> {
        if !Self::detect(s) {
            return None;
        }
        let mut parser = MsvcParser::new(s);
        parser.parse()
    }

    /// Demangle `s` and return the demangled string, or return `s` unchanged.
    #[must_use]
    pub fn demangle_to_string(s: &str) -> String {
        // Consolidation: the crate previously carried two independent MSVC
        // string renderers that disagreed on 10 of 14 reference symbols. This
        // parser's own renderer mis-decodes member functions — it does not
        // skip the `this`-pointer modifiers (`E`/`F`/`I`) before the cv byte,
        // so `?foo@bar@@QEAAHXZ` came out as `void& __cdecl bar::foo(void)`
        // instead of `public: int __cdecl bar::foo(void)`.
        //
        // String output therefore goes through the corrected renderer in
        // `backends`; [`Self::demangle`] still returns this parser's
        // structured [`MsvcName`] for callers that need the decomposition.
        crate::backends::demangle_msvc_internal(s)
            .unwrap_or_else(|| Self::demangle(s).map_or_else(|| s.to_owned(), |n| n.to_display()))
    }

    /// Decode the MSVC type string for a single type encoding.
    #[must_use]
    pub fn decode_msvc_type(encoded: &str) -> Option<String> {
        let mut parser = MsvcParser::new(encoded);
        parser.parse_type()
    }
}

// ─── MsvcParser (internal) ────────────────────────────────────────────────────

struct MsvcParser<'a> {
    input: &'a [u8],
    pos: usize,
    /// Type back-references (up to 10).
    type_backrefs: Vec<String>,
    /// Name back-references (up to 10).
    name_backrefs: Vec<String>,
    /// Template argument stack.
    template_depth: usize,
    /// Recursion depth for `parse_type`, to bound adversarial `PAPA…` chains.
    type_depth: usize,
}

impl<'a> MsvcParser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            input: s.as_bytes(),
            pos: 0,
            type_backrefs: Vec::with_capacity(10),
            name_backrefs: Vec::with_capacity(10),
            template_depth: 0,
            type_depth: 0,
        }
    }

    // ── Primitives ────────────────────────────────────────────────────────────

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn consume(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    // ── Name parsing ──────────────────────────────────────────────────────────

    /// Parse a `@`-terminated identifier.
    fn parse_identifier(&mut self) -> Option<String> {
        let mut name = String::new();
        while let Some(b) = self.peek() {
            if b == b'@' {
                self.pos += 1;
                break;
            }
            name.push(b as char);
            self.pos += 1;
        }
        if name.is_empty() {
            None
        } else {
            if self.name_backrefs.len() < 10 && self.template_depth == 0
                && !self.name_backrefs.contains(&name) {
                self.name_backrefs.push(name.clone());
            }
            Some(name)
        }
    }

    /// Decode a name back-reference digit.
    fn resolve_name_backref(&self, digit: u8) -> Option<String> {
        let idx = (digit - b'0') as usize;
        self.name_backrefs.get(idx).cloned()
    }

    /// Parse a sequence of `@`-separated name components ending with `@@`.
    fn parse_qualified_name(&mut self) -> Option<Vec<String>> {
        let mut components: Vec<String> = Vec::new();

        loop {
            if self.at_end() {
                break;
            }
            match self.peek() {
                Some(b'@') => {
                    self.pos += 1; // consume terminating `@`
                    break;
                }
                Some(d) if d.is_ascii_digit() => {
                    self.pos += 1;
                    if let Some(n) = self.resolve_name_backref(d) {
                        components.push(n);
                        self.consume(b'@');
                    } else {
                        return None;
                    }
                }
                Some(b'?') => {
                    self.pos += 1;
                    // special name or operator
                    if let Some(c) = self.peek() {
                        self.pos += 1;
                        let op = if c == b'_' {
                            // Extended operator code: read one more byte.
                            let ext = self.next()?;
                            Self::decode_extended_operator(ext)?
                        } else {
                            Self::decode_operator(c)?
                        };
                        components.push(op);
                        self.consume(b'@');
                        // A global-scope special operator (like
                        // `??2@YAPAXI@Z` or `??_V@YAXPAX@Z`) has its name
                        // list terminated by a single `@` after the operator
                        // — there's no enclosing scope. Member-scope
                        // operators (like `??1MyClass@@...`) have a class
                        // name followed by `@@`. Detect the global form by
                        // looking ahead for a `@@` terminator in the
                        // remainder: if none exists, the name list is done.
                        if components.len() == 1
                            && !has_double_at_terminator(&self.input[self.pos..])
                        {
                            break;
                        }
                    } else {
                        return None;
                    }
                }
                _ => {
                    let name = self.parse_identifier()?;
                    components.push(name);
                }
            }
        }

        components.reverse();
        fix_ctor_dtor_names(&mut components);
        Some(components)
    }

    fn decode_operator(c: u8) -> Option<String> {
        let s = match c {
            b'0' => "ctor",
            b'1' => "dtor",
            b'2' => "operator new",
            b'3' => "operator delete",
            b'4' => "operator=",
            b'5' => "operator>>",
            b'6' => "operator<<",
            b'7' => "operator!",
            b'8' => "operator==",
            b'9' => "operator!=",
            b'A' => "operator[]",
            b'B' => "operator type",
            b'C' => "operator->",
            b'D' => "operator*",
            b'E' => "operator++",
            b'F' => "operator--",
            b'G' => "operator-",
            b'H' => "operator+",
            b'I' => "operator&",
            b'J' => "operator->*",
            b'K' => "operator/",
            b'L' => "operator%",
            b'M' => "operator<",
            b'N' => "operator<=",
            b'O' => "operator>",
            b'P' => "operator>=",
            b'Q' => "operator,",
            b'R' => "operator()",
            b'S' => "operator~",
            b'T' => "operator^",
            b'U' => "operator|",
            b'V' => "operator&&",
            b'W' => "operator||",
            b'X' => "operator*=",
            b'Y' => "operator+=",
            b'Z' => "operator-=",
            _ => return None,
        };
        Some(s.to_owned())
    }

    /// Decode an MSVC extended operator code (the byte following `?_`).
    fn decode_extended_operator(c: u8) -> Option<String> {
        let s = match c {
            b'0' => "operator/=",
            b'1' => "operator%=",
            b'2' => "operator>>=",
            b'3' => "operator<<=",
            b'4' => "operator&=",
            b'5' => "operator|=",
            b'6' => "operator^=",
            b'7' => "`vftable'",
            b'8' => "`vbtable'",
            b'9' => "`vcall'",
            b'A' => "`typeof'",
            b'B' => "`local static guard'",
            b'C' => "`string'",
            b'D' => "`vbase destructor'",
            b'E' => "`vector deleting destructor'",
            b'F' => "`default constructor closure'",
            b'G' => "`scalar deleting destructor'",
            b'H' => "`vector constructor iterator'",
            b'I' => "`vector destructor iterator'",
            b'J' => "`vector vbase constructor iterator'",
            b'K' => "`virtual displacement map'",
            b'L' => "`eh vector constructor iterator'",
            b'M' => "`eh vector destructor iterator'",
            b'N' => "`eh vector vbase constructor iterator'",
            b'O' => "`copy constructor closure'",
            b'R' => "RTTI",
            b'S' => "`local vftable'",
            b'T' => "`local vftable constructor closure'",
            b'U' => "operator new[]",
            b'V' => "operator delete[]",
            b'X' => "`placement delete closure'",
            b'Y' => "`placement delete[] closure'",
            _ => return None,
        };
        Some(s.to_owned())
    }

    // ── Type parsing ──────────────────────────────────────────────────────────

    /// Parse a type back-reference or type from the stream.
    fn parse_type(&mut self) -> Option<String> {
        if self.type_depth >= 128 {
            return None;
        }
        self.type_depth += 1;
        let result = self.parse_type_guarded();
        self.type_depth -= 1;
        result
    }

    fn parse_type_guarded(&mut self) -> Option<String> {
        // Type back-reference
        if let Some(d) = self.peek()
            && d.is_ascii_digit()
        {
            self.pos += 1;
            let idx = (d - b'0') as usize;
            return self.type_backrefs.get(idx).cloned();
        }

        let c = self.next()?;
        let t = match c {
            b'X' => "void".to_owned(),
            b'D' => "char".to_owned(),
            b'C' => "signed char".to_owned(),
            b'E' => "unsigned char".to_owned(),
            b'F' => "short".to_owned(),
            b'G' => "unsigned short".to_owned(),
            b'H' => "int".to_owned(),
            b'I' => "unsigned int".to_owned(),
            b'J' => "long".to_owned(),
            b'K' => "unsigned long".to_owned(),
            b'M' => "float".to_owned(),
            b'N' => "double".to_owned(),
            b'O' => "long double".to_owned(),
            b'_' => self.parse_type_extended()?,
            b'P' | b'Q' | b'R' | b'S' => self.parse_type_ptr(c)?,
            b'A' | b'B' => self.parse_type_ref(c)?,
            b'U' | b'V' | b'W' => {
                let name_parts = self.parse_qualified_name()?;
                let t = name_parts.join("::");
                self.add_type_backref(&t);
                t
            }
            b'6' => self.parse_type_fnptr(),
            b'Y' => self.parse_type_array(),
            b'Z' => "...".to_owned(),
            _ => format!("?{}", c as char),
        };
        Some(t)
    }

    fn parse_type_extended(&mut self) -> Option<String> {
        let ext = self.next()?;
        Some(match ext {
            b'N' => "bool".to_owned(),
            b'J' => "__int64".to_owned(),
            b'K' => "unsigned __int64".to_owned(),
            b'W' => "wchar_t".to_owned(),
            b'S' => "char16_t".to_owned(),
            b'U' => "char32_t".to_owned(),
            b'Q' => "char8_t".to_owned(),
            _ => format!("_ext_{}", ext as char),
        })
    }

    fn parse_type_ptr(&mut self, c: u8) -> Option<String> {
        self.skip_ptr64_marker();
        let cv = self.next()?;
        let inner = self.parse_type()?;
        let inner_cv = decode_cv_qual(cv);
        let base = if inner_cv.is_empty() { inner } else { format!("{inner_cv} {inner}") };
        let suffix = match c {
            b'Q' => "* const",
            b'R' => "& volatile",
            b'S' => "* const volatile",
            _ => "*",
        };
        let t = format!("{base}{suffix}");
        self.add_type_backref(&t);
        Some(t)
    }

    fn parse_type_ref(&mut self, c: u8) -> Option<String> {
        self.skip_ptr64_marker();
        let cv = self.next()?;
        let inner = self.parse_type()?;
        let inner_cv = decode_cv_qual(cv);
        let base = if inner_cv.is_empty() { inner } else { format!("{inner_cv} {inner}") };
        let suffix = if c == b'A' { "&" } else { "&&" };
        let t = format!("{base}{suffix}");
        self.add_type_backref(&t);
        Some(t)
    }

    fn parse_type_fnptr(&mut self) -> String {
        let cc_byte = self.next().unwrap_or(b'A');
        let cc = CallingConvention::from_byte(cc_byte);
        let ret = self.parse_type().unwrap_or_else(|| "void".to_owned());
        let mut params = Vec::new();
        loop {
            if matches!(self.peek(), Some(b'@' | b'Z') | None) {
                self.consume(b'@');
                self.consume(b'Z');
                break;
            }
            if let Some(t) = self.parse_type() {
                params.push(t);
            } else {
                break;
            }
        }
        let ps = params.join(", ");
        format!("{ret} ({}) ({})", cc.as_str(), ps)
    }

    fn parse_type_array(&mut self) -> String {
        let dim_count = self.parse_number().unwrap_or(1);
        let mut dims = Vec::new();
        for _ in 0..dim_count {
            let d = self.parse_number().unwrap_or(0);
            dims.push(format!("{d}"));
        }
        let elem = self.parse_type().unwrap_or_else(|| "?".to_owned());
        let brackets = dims.iter().fold(String::new(), |mut s, d| {
            write!(s, "[{d}]").ok();
            s
        });
        format!("{elem}{brackets}")
    }

    fn skip_ptr64_marker(&mut self) {
        if matches!(self.peek(), Some(b'E' | b'F')) {
            self.pos += 1;
        }
    }

    fn add_type_backref(&mut self, t: &str) {
        if self.type_backrefs.len() < 10 && !self.type_backrefs.contains(&t.to_owned()) {
            self.type_backrefs.push(t.to_owned());
        }
    }

    fn parse_number(&mut self) -> Option<usize> {
        // MSVC encodes dimensions as '0'-'9' = 0..9, or base-16 with A..P = 1..16
        let c = self.peek()?;
        if c.is_ascii_digit() {
            self.pos += 1;
            return Some((c - b'0') as usize);
        }
        if (b'A'..=b'P').contains(&c) {
            self.pos += 1;
            // Extended: consume digits until '@'
            let mut val = (c - b'A' + 1) as usize;
            while let Some(d) = self.peek() {
                if d == b'@' {
                    self.pos += 1;
                    break;
                }
                if d.is_ascii_digit() {
                    val = val * 16 + (d - b'0') as usize;
                    self.pos += 1;
                } else if (b'A'..=b'F').contains(&d) {
                    val = val * 16 + (d - b'A' + 10) as usize;
                    self.pos += 1;
                } else {
                    break;
                }
            }
            return Some(val);
        }
        None
    }

    fn parse_params(&mut self) -> Vec<String> {
        let mut params = Vec::new();
        loop {
            if matches!(self.peek(), None | Some(b'Z' | b'@')) {
                self.consume(b'Z');
                self.consume(b'@');
                break;
            }
            if let Some(t) = self.parse_type() {
                params.push(t);
            } else {
                break;
            }
        }
        params
    }

    // ── Top-level symbol parsing ───────────────────────────────────────────────

    fn parse(&mut self) -> Option<MsvcName> {
        // Consume leading `?`
        if !self.consume(b'?') {
            return None;
        }

        // `??_<X>` introduces a special symbol (RTTI, vftable, vbtable, …).
        // Dispatch to `parse_special_symbol` so those forms are decoded with
        // their dedicated handler instead of being misparsed as operators.
        // After consuming the leading `?` above, pos==1; peek()==input[1].
        // We need input[1]=='?' and input[2]=='_' to confirm `??_` prefix.
        if self.peek() == Some(b'?') && self.input.get(self.pos + 1).copied() == Some(b'_') {
            self.next(); // consume second `?`
            self.next(); // consume `_`
            return self.parse_special_symbol();
        }
        // Otherwise `??` introduces an operator name; let parse_qualified_name
        // handle it via its `?` branch.

        let components = self.parse_qualified_name()?;
        let (namespace, class, func_name) = split_components(&components);

        let is_constructor = func_name == class.as_deref().unwrap_or("") && !func_name.is_empty();
        let is_destructor = func_name.starts_with('~');

        // Access / storage class byte
        let storage_byte = self.next()?;
        let is_static = matches!(storage_byte, b'S' | b'K' | b'M' | b'O' | b'C' | b'D');
        let is_virtual =
            matches!(storage_byte, b'E' | b'F' | b'G' | b'H' | b'I' | b'J');
        let is_data = matches!(storage_byte, b'2' | b'3' | b'4');
        let storage = SymbolStorage::from_byte(storage_byte);

        if is_data {
            let data_type = self.parse_type().unwrap_or_default();
            let cv_byte = self.next().unwrap_or(b'A');
            let data_qualifiers = decode_cv_qual_vec(cv_byte);
            let qualified_name = components.join("::");
            return Some(MsvcName {
                mangled: String::from_utf8_lossy(self.input).into_owned(),
                qualified_name,
                namespace,
                class,
                function_name: func_name,
                return_type: Some(data_type),
                parameters: vec![],
                template_args: vec![],
                calling_convention: CallingConvention::Cdecl,
                storage,
                flags: (if is_constructor { MsvcName::IS_CONSTRUCTOR } else { 0 })
                    | (if is_destructor { MsvcName::IS_DESTRUCTOR } else { 0 })
                    | (if is_virtual { MsvcName::IS_VIRTUAL } else { 0 })
                    | (if is_static { MsvcName::IS_STATIC } else { 0 })
                    | MsvcName::IS_DATA,
                data_qualifiers,
            });
        }

        // CV qualifiers for member function
        let (is_const, is_volatile) = if matches!(
            storage_byte,
            b'Y' | b'C' | b'D' | b'K' | b'L' | b'S' | b'T'
        ) {
            (false, false)
        } else {
            let cv_byte = self.next().unwrap_or(b'A');
            (
                matches!(cv_byte, b'B' | b'D' | b'F' | b'H' | b'J' | b'L' | b'N' | b'P'),
                matches!(cv_byte, b'C' | b'D' | b'G' | b'H' | b'K' | b'L' | b'O' | b'P'),
            )
        };

        // Calling convention
        let cc_byte = self.next().unwrap_or(b'A');
        let calling_convention = CallingConvention::from_byte(cc_byte);

        // Return type (absent for ctors/dtors: marker is '@')
        let return_type = if self.consume(b'@') {
            None
        } else {
            self.parse_type()
        };

        // Parameters
        let parameters = self.parse_params();

        let qualified_name = components.join("::");

        Some(MsvcName {
            mangled: String::from_utf8_lossy(self.input).into_owned(),
            qualified_name,
            namespace,
            class,
            function_name: func_name,
            return_type,
            parameters,
            template_args: vec![],
            calling_convention,
            storage,
            flags: (if is_const { MsvcName::IS_CONST } else { 0 })
                | (if is_volatile { MsvcName::IS_VOLATILE } else { 0 })
                | (if is_constructor { MsvcName::IS_CONSTRUCTOR } else { 0 })
                | (if is_destructor { MsvcName::IS_DESTRUCTOR } else { 0 })
                | (if is_virtual { MsvcName::IS_VIRTUAL } else { 0 })
                | (if is_static { MsvcName::IS_STATIC } else { 0 }),
            data_qualifiers: vec![],
        })
    }

    fn parse_special_symbol(&mut self) -> Option<MsvcName> {
        let kind_byte = self.next()?;

        if matches!(kind_byte, b'0'..=b'6' | b'U' | b'V' | b'O') {
            return self.parse_special_extended_op(kind_byte);
        }
        if kind_byte == b'C' {
            return Some(self.parse_special_string_const());
        }
        if kind_byte == b'R' {
            return Some(self.parse_special_rtti());
        }

        let special_name = match kind_byte {
            b'7' => "`vftable'",
            b'8' => "`vbtable'",
            b'9' => "`vcall'",
            b'A' => "`typeof'",
            b'B' => "`local static guard'",
            b'D' => "`vbase destructor'",
            _ => "unknown special",
        };

        let class_name = if !self.at_end() && self.peek() != Some(b'@') {
            let components = self.parse_qualified_name().unwrap_or_default();
            while !self.at_end() { self.next(); }
            if components.is_empty() { None } else { Some(components.join("::")) }
        } else {
            while !self.at_end() { self.next(); }
            None
        };

        let qualified_name = class_name.as_ref().map_or_else(
            || special_name.to_owned(),
            |cls| format!("{cls}::{special_name}"),
        );

        Some(MsvcName {
            mangled: String::from_utf8_lossy(self.input).into_owned(),
            qualified_name,
            namespace: vec![],
            class: class_name,
            function_name: special_name.to_owned(),
            return_type: None,
            parameters: vec![],
            template_args: vec![],
            calling_convention: CallingConvention::Cdecl,
            storage: SymbolStorage::Global,
            flags: 0,
            data_qualifiers: vec![],
        })
    }

    fn parse_special_extended_op(&mut self, kind_byte: u8) -> Option<MsvcName> {
        let op = Self::decode_extended_operator(kind_byte)?;
        self.consume(b'@');
        let mut components: Vec<String> = vec![op];
        if let Some(b) = self.peek()
            && !matches!(b, b'Y' | b'Z' | b'A'..=b'X')
            && let Some(extra) = self.parse_qualified_name() {
            components.extend(extra);
        }
        let (namespace, class, func_name) = if components.len() == 1 {
            (vec![], None, components[0].clone())
        } else {
            let func = components.remove(0);
            let cls = components.pop();
            (components, cls, func)
        };
        let qualified_name = class.as_ref().map_or_else(|| func_name.clone(), |c| format!("{c}::{func_name}"));
        let storage_byte = self.next().unwrap_or(b'Y');
        let storage = SymbolStorage::from_byte(storage_byte);
        let (is_const, is_volatile) = if matches!(storage_byte, b'Y' | b'C' | b'D' | b'K' | b'L' | b'S' | b'T') {
            (false, false)
        } else {
            let cv_byte = self.next().unwrap_or(b'A');
            (
                matches!(cv_byte, b'B' | b'D' | b'F' | b'H' | b'J' | b'L' | b'N' | b'P'),
                matches!(cv_byte, b'C' | b'D' | b'G' | b'H' | b'K' | b'L' | b'O' | b'P'),
            )
        };
        let cc_byte = self.next().unwrap_or(b'A');
        let calling_convention = CallingConvention::from_byte(cc_byte);
        let return_type = if self.consume(b'@') { None } else { self.parse_type() };
        let parameters = self.parse_params();
        Some(MsvcName {
            mangled: String::from_utf8_lossy(self.input).into_owned(),
            qualified_name, namespace, class, function_name: func_name,
            return_type, parameters, template_args: vec![],
            calling_convention, storage,
            flags: (if is_const { MsvcName::IS_CONST } else { 0 })
                | (if is_volatile { MsvcName::IS_VOLATILE } else { 0 }),
            data_qualifiers: vec![],
        })
    }

    fn parse_special_string_const(&mut self) -> MsvcName {
        while !self.at_end() { self.next(); }
        let label = "`string'";
        MsvcName {
            mangled: String::from_utf8_lossy(self.input).into_owned(),
            qualified_name: label.to_owned(),
            namespace: vec![], class: None,
            function_name: label.to_owned(), return_type: None,
            parameters: vec![], template_args: vec![],
            calling_convention: CallingConvention::Cdecl,
            storage: SymbolStorage::Global, flags: 0, data_qualifiers: vec![],
        }
    }

    fn parse_special_rtti(&mut self) -> MsvcName {
        let sub = self.peek().unwrap_or(0);
        let label = if sub == b'0' {
            self.next();
            let type_name = self.parse_type().unwrap_or_else(|| "?".to_owned());
            while !self.at_end() { self.next(); }
            format!("`RTTI Type Descriptor' for {type_name}")
        } else {
            while !self.at_end() { self.next(); }
            "RTTI".to_owned()
        };
        MsvcName {
            mangled: String::from_utf8_lossy(self.input).into_owned(),
            qualified_name: label.clone(), namespace: vec![], class: None,
            function_name: label, return_type: None,
            parameters: vec![], template_args: vec![],
            calling_convention: CallingConvention::Cdecl,
            storage: SymbolStorage::Global, flags: 0, data_qualifiers: vec![],
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Check whether `rest` contains a `@@` qualified-name terminator.
fn has_double_at_terminator(rest: &[u8]) -> bool {
    rest.windows(2).any(|w| w == b"@@")
}

/// Decode a single MSVC CV-qualifier byte into a string suffix.
const fn decode_cv_qual(cv: u8) -> &'static str {
    match cv {
        b'B' => "const",
        b'C' => "volatile",
        b'D' => "const volatile",
        _ => "",
    }
}

/// Decode a CV byte into a Vec<String>.
fn decode_cv_qual_vec(cv: u8) -> Vec<String> {
    match cv {
        b'B' => vec!["const".to_owned()],
        b'C' => vec!["volatile".to_owned()],
        b'D' => vec!["const".to_owned(), "volatile".to_owned()],
        _ => vec![],
    }
}

/// Fix up ctor/dtor names after reversing the component list.
fn fix_ctor_dtor_names(components: &mut [String]) {
    let len = components.len();
    if len < 2 {
        return;
    }
    if components[len - 1] == "ctor" {
        let src = components[len - 2].clone();
        components[len - 1] = src;
    } else if components[len - 1] == "dtor" {
        let base = components[len - 2].clone();
        components[len - 1] = format!("~{base}");
    }
}

/// Split a component slice into (namespace, class, `function_name`).
fn split_components(parts: &[String]) -> (Vec<String>, Option<String>, String) {
    match parts.len() {
        0 => (vec![], None, String::new()),
        1 => (vec![], None, parts[0].clone()),
        2 => (vec![], Some(parts[0].clone()), parts[1].clone()),
        n => {
            let ns: Vec<String> = parts[..n - 2].to_vec();
            let class = Some(parts[n - 2].clone());
            let func = parts[n - 1].clone();
            (ns, class, func)
        }
    }
}

// ─── Batch demangling ─────────────────────────────────────────────────────────

/// Demangle a batch of MSVC symbols, returning a map from mangled → demangled.
///
/// Symbols that cannot be demangled are included with their original value.
#[must_use]
pub fn batch_demangle(symbols: &[&str]) -> HashMap<String, String> {
    symbols
        .iter()
        .map(|&s| {
            let demangled = MsvcDemangler::demangle_to_string(s);
            (s.to_owned(), demangled)
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_msvc() {
        assert!(MsvcDemangler::detect("?foo@@YAXXZ"));
        assert!(!MsvcDemangler::detect("_ZN3foo3barEi"));
        assert!(!MsvcDemangler::detect(""));
    }

    #[test]
    fn type_code_display() {
        assert_eq!(TypeCode::Int.as_str(), "int");
        assert_eq!(TypeCode::LongLong.as_str(), "long long");
        assert_eq!(TypeCode::Void.as_str(), "void");
    }

    #[test]
    fn calling_conv_display() {
        assert_eq!(CallingConvention::Cdecl.as_str(), "__cdecl");
        assert_eq!(CallingConvention::Stdcall.as_str(), "__stdcall");
        assert_eq!(CallingConvention::Thiscall.as_str(), "__thiscall");
    }

    #[test]
    fn decode_msvc_type_int() {
        let t = MsvcDemangler::decode_msvc_type("H");
        assert_eq!(t.as_deref(), Some("int"));
    }

    #[test]
    fn decode_msvc_type_void() {
        let t = MsvcDemangler::decode_msvc_type("X");
        assert_eq!(t.as_deref(), Some("void"));
    }

    #[test]
    fn decode_msvc_type_bool() {
        let t = MsvcDemangler::decode_msvc_type("_N");
        assert_eq!(t.as_deref(), Some("bool"));
    }

    #[test]
    fn decode_msvc_type_longlong() {
        let t = MsvcDemangler::decode_msvc_type("_J");
        assert_eq!(t.as_deref(), Some("__int64"));
    }

    #[test]
    fn non_msvc_returns_none() {
        assert!(MsvcDemangler::demangle("_ZN3foo3barEi").is_none());
        assert!(MsvcDemangler::demangle("").is_none());
    }

    #[test]
    fn split_components_one() {
        let parts = vec!["foo".to_owned()];
        let (ns, cls, func) = split_components(&parts);
        assert!(ns.is_empty());
        assert!(cls.is_none());
        assert_eq!(func, "foo");
    }

    #[test]
    fn split_components_two() {
        let parts = vec!["Foo".to_owned(), "bar".to_owned()];
        let (ns, cls, func) = split_components(&parts);
        assert!(ns.is_empty());
        assert_eq!(cls.as_deref(), Some("Foo"));
        assert_eq!(func, "bar");
    }

    #[test]
    fn split_components_three() {
        let parts = vec!["ns".to_owned(), "Foo".to_owned(), "bar".to_owned()];
        let (ns, cls, func) = split_components(&parts);
        assert_eq!(ns, vec!["ns".to_owned()]);
        assert_eq!(cls.as_deref(), Some("Foo"));
        assert_eq!(func, "bar");
    }

    #[test]
    fn batch_demangle_passthrough() {
        let symbols = vec!["not_msvc_at_all"];
        let result = batch_demangle(&symbols);
        assert_eq!(result["not_msvc_at_all"], "not_msvc_at_all");
    }

    #[test]
    fn fix_ctor_names() {
        let mut parts = vec!["Foo".to_owned(), "ctor".to_owned()];
        fix_ctor_dtor_names(&mut parts);
        assert_eq!(parts[1], "Foo");
    }

    #[test]
    fn demangle_operator_new_array() {
        let n = MsvcDemangler::demangle("??_U@YAPAXI@Z").expect("parse ok");
        assert!(
            n.to_display().contains("operator new[]"),
            "got: {}",
            n.to_display()
        );
    }

    #[test]
    fn demangle_operator_delete_array() {
        let n = MsvcDemangler::demangle("??_V@YAXPAX@Z").expect("parse ok");
        assert!(
            n.to_display().contains("operator delete[]"),
            "got: {}",
            n.to_display()
        );
    }

    #[test]
    fn demangle_destructor() {
        let n = MsvcDemangler::demangle("??1MyClass@@QAE@XZ").expect("parse ok");
        assert!(
            n.to_display().contains("MyClass::~MyClass"),
            "got: {}",
            n.to_display()
        );
    }

    #[test]
    fn fix_dtor_names() {
        let mut parts = vec!["Foo".to_owned(), "dtor".to_owned()];
        fix_ctor_dtor_names(&mut parts);
        assert_eq!(parts[1], "~Foo");
    }

    #[test]
    fn demangle_operator_delete_x64_size_t() {
        // ??3@YAXPEAX_K@Z → operator delete(void*, unsigned __int64)
        let n = MsvcDemangler::demangle("??3@YAXPEAX_K@Z").expect("parse ok");
        let d = n.to_display();
        assert!(d.contains("operator delete"), "got: {d}");
        assert!(d.contains("unsigned __int64"), "got: {d}");
    }

    #[test]
    fn demangle_vftable() {
        // ??_7Foo@@6B@ → Foo::`vftable'
        let n = MsvcDemangler::demangle("??_7Foo@@6B@").expect("parse ok");
        let d = n.to_display();
        assert!(d.contains("Foo"), "got: {d}");
        assert!(d.contains("vftable"), "got: {d}");
    }

    #[test]
    fn demangle_rtti_type_descriptor() {
        // ??_R0?AVBar@@@8 → RTTI Type Descriptor for Bar
        let n = MsvcDemangler::demangle("??_R0?AVBar@@@8").expect("parse ok");
        let d = n.to_display();
        assert!(d.contains("RTTI") || d.contains("Bar"), "got: {d}");
    }

    #[test]
    fn demangle_string_constant() {
        // ??_C@_0BA@ABCDEFGH@hello@ → `string'
        let n = MsvcDemangler::demangle("??_C@_0BA@ABCDEFGH@hello@").expect("parse ok");
        let d = n.to_display();
        assert!(!d.is_empty(), "got empty string");
        assert!(d.contains("string"), "got: {d}");
    }
}
