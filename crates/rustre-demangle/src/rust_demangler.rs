// rust_demangler.rs — hand-written Rust symbol demangler: v0 mangling scheme
// (RFC 2603), legacy hash-based mangling, generic args, closures, impl blocks,
// and const generics.
//
// ─── DO NOT USE FOR v0 — PREFER `crate::demangle` ────────────────────────────
//
// Measured 2026-07-23 against the 135 real rustc-1.96 v0 symbols in
// `tests/data/pdb_symbols.txt`:
//
//     crate::demangle()          135 decoded, all matching `rustc-demangle`
//     demangle_rust()             83 error, 52 decoded-but-wrong, 0 correct
//
// **Zero correct results**, while `crate::demangle` (which delegates to the
// `rustc-demangle` crate) is exact on every one. The parser's own errors say
// why: `Path backref 5 OOB (have 4)` — the back-reference table is
// mis-sized — and `Unknown path tag 'c'`, the crate-root disambiguator form it
// cannot parse. Where it does return `Ok`, the output is wrong in a way that
// loses identity: `…14rustc_demangle12try_demangle` and
// `…14rustc_demangle8demangle` both render as
// `rustc_demangle[a20b64e359616fff]::{{vtable}}` — two different functions,
// one string.
//
// This is public API with ~12 call sites in other workspace crates. Legacy
// (`_ZN…17h…E`) handling is not covered by the figures above; only v0 was
// measured. `tests/rust_demangler_accuracy.rs` pins them so the gap cannot
// widen or be forgotten.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ── Symbol prefix constants ────────────────────────────────────────────────────

const RUST_V0_PREFIX: &str = "_R";
const RUST_LEGACY_PREFIX: &str = "_ZN"; // Rust legacy used Itanium encoding

// ── Rust v0 path kinds ────────────────────────────────────────────────────────

/// A path component of a Rust v0 mangled symbol (RFC 2603 `<path>` production).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RustPath {
    /// Crate root (`C` tag): the crate a symbol originates from.
    CrateRoot {
        /// Crate name.
        name: String,
        /// Crate disambiguator (0 when absent), distinguishing same-named crates.
        disambiguator: u64,
    },
    /// Inherent `impl` block (`M` tag), rendered as `<Type>`.
    InherentImpl {
        /// The `Self` type of the impl block.
        self_type: Box<RustType>,
        /// Impl-block disambiguator (0 when absent).
        disambiguator: u64,
    },
    /// Trait `impl` block (`X` tag), rendered as `<Type as Trait>`.
    TraitImpl {
        /// The implementing `Self` type.
        self_type: Box<RustType>,
        /// Path of the implemented trait.
        trait_path: Box<Self>,
        /// Impl-block disambiguator (0 when absent).
        disambiguator: u64,
    },
    /// Trait definition item (`Y` tag), rendered as `<Type as Trait>`.
    TraitDef {
        /// The `Self` type within the trait definition.
        self_type: Box<RustType>,
        /// Path of the trait itself.
        trait_path: Box<Self>,
    },
    /// Nested path segment (`N` tag): an item inside a parent path.
    Nested {
        /// Namespace tag character (`v` = value, `t` = type, `C` = closure, ...).
        namespace: char,
        /// Enclosing path.
        parent: Box<Self>,
        /// Item name (may be empty for anonymous items).
        name: String,
        /// Item disambiguator (0 when absent), rendered as `{#N}`.
        disambiguator: u64,
    },
    /// Generic instantiation (`I` tag), rendered as `parent<args...>`.
    Generic {
        /// The generic item being instantiated.
        parent: Box<Self>,
        /// Concrete generic arguments (lifetimes, types, consts).
        args: Vec<GenericArg>,
    },
}

impl RustPath {
    /// Render this path as a human-readable `::`-separated Rust path.
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::CrateRoot { name, disambiguator } => {
                if *disambiguator != 0 {
                    format!("{name}[{disambiguator:x}]")
                } else {
                    name.clone()
                }
            }
            Self::InherentImpl { self_type, .. } => {
                format!("<{}>", self_type.to_string_repr())
            }
            Self::TraitImpl { self_type, trait_path, .. }
            | Self::TraitDef { self_type, trait_path } => {
                format!("<{} as {}>", self_type.to_string_repr(), trait_path.to_string_repr())
            }
            Self::Nested { namespace, parent, name, disambiguator } => {
                let parent_str = parent.to_string_repr();
                let suffix = match namespace {
                    'v' => "{{vtable}}".to_owned(),
                    _ => {
                        if *disambiguator != 0 {
                            format!("{name}{{#{disambiguator}}}")
                        } else {
                            name.clone()
                        }
                    }
                };
                if parent_str.is_empty() {
                    suffix
                } else {
                    format!("{parent_str}::{suffix}")
                }
            }
            Self::Generic { parent, args } => {
                let arg_strs: Vec<String> = args.iter().map(GenericArg::to_string_repr).collect();
                format!("{}<{}>", parent.to_string_repr(), arg_strs.join(", "))
            }
        }
    }
}

/// A type in a Rust v0 mangled symbol (RFC 2603 `<type>` production).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RustType {
    /// A primitive type encoded as a single-letter tag (e.g. `i` = `i32`).
    Basic(BasicType),
    /// A path-named (user-defined) type.
    Named(RustPath),
    /// Shared reference `&T` (`R` tag).
    Ref {
        /// Optional lifetime index (base-62 encoded in the symbol).
        lifetime: Option<u64>,
        /// Referent type.
        inner: Box<Self>,
    },
    /// Mutable reference `&mut T` (`W` tag).
    RefMut {
        /// Optional lifetime index (base-62 encoded in the symbol).
        lifetime: Option<u64>,
        /// Referent type.
        inner: Box<Self>,
    },
    /// Raw pointer `*const T` (`P` tag) or `*mut T` (`Q` tag).
    RawPtr {
        /// Pointer mutability (`*const` vs `*mut`).
        mutability: Mutability,
        /// Pointee type.
        inner: Box<Self>,
    },
    /// Fixed-size array `[T; N]` (`A` tag).
    Array {
        /// Element type.
        element: Box<Self>,
        /// Array length const.
        size: Box<RustConst>,
    },
    /// Slice `[T]` (`S` tag).
    Slice(Box<Self>),
    /// Tuple `(T, U, ...)` (`T` tag, `E`-terminated).
    Tuple(Vec<Self>),
    /// Function pointer type (`F` tag).
    FnPtr {
        /// Whether the fn pointer is `unsafe`.
        is_unsafe: bool,
        /// ABI string (`"Rust"` when unspecified, e.g. `"C"` for `extern "C"`).
        abi: String,
        /// Parameter types.
        params: Vec<Self>,
        /// Return type.
        ret: Box<Self>,
    },
    /// Trait object `dyn Trait + ...` (`D` tag).
    DynTrait {
        /// The trait bounds of the object type.
        traits: Vec<RustPath>,
        /// Optional lifetime bound index.
        lifetime: Option<u64>,
    },
    /// The never type `!` (`z` tag).
    Never,
    /// Placeholder / inferred type `_` (`_` tag or unresolved back-reference).
    Placeholder, // _
}

impl RustType {
    /// Render this type in Rust surface syntax (e.g. `&mut [u8; 4]`).
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::Basic(b) => b.to_string_repr().to_owned(),
            Self::Named(p) => p.to_string_repr(),
            Self::Ref { lifetime, inner } => {
                let lt = lifetime.map(|l| format!("'_{l} ")).unwrap_or_default();
                format!("&{}{}", lt, inner.to_string_repr())
            }
            Self::RefMut { lifetime, inner } => {
                let lt = lifetime.map(|l| format!("'_{l} ")).unwrap_or_default();
                format!("&{}mut {}", lt, inner.to_string_repr())
            }
            Self::RawPtr { mutability, inner } => {
                let m = match mutability { Mutability::Const => "const", Mutability::Mut => "mut" };
                format!("*{} {}", m, inner.to_string_repr())
            }
            Self::Array { element, size } => {
                format!("[{}; {}]", element.to_string_repr(), size.to_string_repr())
            }
            Self::Slice(e) => format!("[{}]", e.to_string_repr()),
            Self::Tuple(ts) => {
                let ss: Vec<String> = ts.iter().map(Self::to_string_repr).collect();
                if ts.len() == 1 {
                    format!("({},)", ss[0])
                } else {
                    format!("({})", ss.join(", "))
                }
            }
            Self::FnPtr { is_unsafe, abi, params, ret } => {
                let unsafe_kw = if *is_unsafe { "unsafe " } else { "" };
                let abi_kw = if abi == "Rust" { String::new() } else { format!("extern \"{abi}\" ") };
                let ps: Vec<String> = params.iter().map(Self::to_string_repr).collect();
                format!("{}{}fn({}) -> {}", unsafe_kw, abi_kw, ps.join(", "), ret.to_string_repr())
            }
            Self::DynTrait { traits, lifetime } => {
                let ts: Vec<String> = traits.iter().map(RustPath::to_string_repr).collect();
                let lt = lifetime.map(|l| format!(" + '_{l}")).unwrap_or_default();
                format!("dyn {}{}", ts.join(" + "), lt)
            }
            Self::Never => "!".to_owned(),
            Self::Placeholder => "_".to_owned(),
        }
    }
}

/// Mutability of a raw pointer (`*const` vs `*mut`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mutability {
    /// `*const` pointer.
    Const,
    /// `*mut` pointer.
    Mut,
}

/// A Rust primitive type, encoded in v0 mangling as a single lowercase letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BasicType {
    /// `bool` (`b` tag).
    Bool,
    /// `char` (`c` tag).
    Char,
    /// `str` (`e` tag).
    Str,
    /// `i8` (`a` tag).
    I8,
    /// `i16` (`s` tag).
    I16,
    /// `i32` (`i` tag).
    I32,
    /// `i64` (`l` tag).
    I64,
    /// `i128` (`n` tag).
    I128,
    /// `isize` (`x` tag).
    ISize,
    /// `u8` (`h` tag).
    U8,
    /// `u16` (`t` tag).
    U16,
    /// `u32` (`j` tag).
    U32,
    /// `u64` (`m` tag).
    U64,
    /// `u128` (`o` tag).
    U128,
    /// `usize` (`u`/`y` tags).
    USize,
    /// `f32` (`f` tag).
    F32,
    /// `f64` (`d` tag).
    F64,
    /// Unit type `()` (`v` tag).
    Unit,
    /// C-variadic `...` marker (`p` tag).
    Ellipsis,
    /// Never type `!` (`z` tag).
    Never,
}

impl BasicType {
    /// Render this primitive type as its Rust source spelling (e.g. `"i32"`).
    #[must_use]
    pub const fn to_string_repr(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Char => "char",
            Self::Str => "str",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::I128 => "i128",
            Self::ISize => "isize",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::USize => "usize",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Unit => "()",
            Self::Ellipsis => "...",
            Self::Never => "!",
        }
    }
}

/// A const-generic value in a Rust v0 mangled symbol (RFC 2603 `<const>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RustConst {
    /// An inferred const value, rendered as `_`.
    Inferred,
    /// An unsigned integer const (hex-encoded, `_`-terminated in the symbol).
    Usize(u64),
    /// A `bool` const (`b0`/`b1` encoding).
    Bool(bool),
    /// A `char` const (`c` tag followed by hex code point).
    Char(char),
    /// Placeholder const (`p` tag), rendered as `_`.
    Placeholder,
}

impl RustConst {
    fn to_string_repr(&self) -> String {
        match self {
            Self::Inferred | Self::Placeholder => "_".to_owned(),
            Self::Usize(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Char(c) => format!("'{c}'"),
        }
    }
}

/// A single generic argument inside an `I...E` generic instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenericArg {
    /// A lifetime argument (`L` tag), by base-62 index.
    Lifetime(u64),
    /// A type argument.
    Type(RustType),
    /// A const argument (`K` tag), rendered in braces (e.g. `{4}`).
    Const(RustConst),
}

impl GenericArg {
    fn to_string_repr(&self) -> String {
        match self {
            Self::Lifetime(n) => format!("'_{n}"),
            Self::Type(t) => t.to_string_repr(),
            Self::Const(c) => format!("{{{}}}", c.to_string_repr()),
        }
    }
}

// ── Demangled output ──────────────────────────────────────────────────────────

/// The structured result of demangling a Rust symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangledRustSymbol {
    /// The demangled item path.
    pub path: RustPath,
    /// Optional path of the crate that instantiated this (generic) symbol.
    pub instantiating_crate: Option<RustPath>,
    /// `true` if the symbol used the v0 (`_R`) scheme rather than legacy `_ZN`.
    pub is_v0: bool,
    /// The original mangled symbol text (may be empty when unset).
    pub original: String,
}

impl DemangledRustSymbol {
    /// Render the demangled symbol path as a human-readable string.
    #[must_use]
    pub fn to_string_repr(&self) -> String {
        self.path.to_string_repr()
    }
}

// ── v0 Parser ─────────────────────────────────────────────────────────────────

/// Recursive-descent parser for Rust v0 (`_R`) mangled symbols, with
/// back-reference tables for paths and types and a recursion limit.
pub struct RustV0Parser<'a> {
    input: &'a [u8],
    pos: usize,
    recursion: usize,
    max_recursion: usize,
    /// Back-references: paths and types encountered during parsing.
    path_backref: Vec<RustPath>,
    type_backref: Vec<RustType>,
}

impl<'a> RustV0Parser<'a> {
    /// Create a parser over the symbol bytes *after* the `_R` prefix.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            recursion: 0,
            max_recursion: 128,
            path_backref: Vec::new(),
            type_backref: Vec::new(),
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

    fn expect(&mut self, expected: u8) -> Result<()> {
        match self.consume() {
            Some(b) if b == expected => Ok(()),
            Some(b) => bail!("Expected '{}' got '{}' at pos {}", expected as char, b as char, self.pos),
            None => bail!("Expected '{}' but EOF", expected as char),
        }
    }

    const fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn push_recursion(&mut self) -> Result<()> {
        self.recursion += 1;
        if self.recursion > self.max_recursion {
            bail!("Recursion limit exceeded");
        }
        Ok(())
    }

    const fn pop_recursion(&mut self) {
        self.recursion = self.recursion.saturating_sub(1);
    }

    /// # Errors
    /// Returns an error if the symbol is malformed or not a valid Rust v0 symbol.
    pub fn parse_symbol(&mut self) -> Result<DemangledRustSymbol> {
        // _R[<decimal-number>] <path> [<path>]
        // Already past "_R"
        // Optional version number
        if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.parse_decimal_number()?;
        }
        let path = self.parse_path()?;
        let instantiating_crate = if !self.at_end() && self.peek() != Some(b'.') {
            Some(self.parse_path()?)
        } else {
            None
        };
        Ok(DemangledRustSymbol {
            path,
            instantiating_crate,
            is_v0: true,
            original: String::new(),
        })
    }

    fn parse_path(&mut self) -> Result<RustPath> {
        self.push_recursion()?;
        let tag = self.consume().ok_or_else(|| anyhow::anyhow!("EOF in path"))?;
        let path = match tag {
            b'C' => self.parse_crate_root()?,
            b'M' => self.parse_inherent_impl()?,
            b'X' => self.parse_trait_impl()?,
            b'Y' => self.parse_trait_def()?,
            b'N' => self.parse_nested_path()?,
            b'I' => self.parse_generic_path()?,
            b'B' => self.parse_path_backref()?,
            other => bail!("Unknown path tag '{}' at pos {}", other as char, self.pos),
        };
        self.pop_recursion();
        Ok(path)
    }

    fn parse_crate_root(&mut self) -> Result<RustPath> {
        let disambiguator = self.parse_disambiguator()?;
        let name = self.parse_identifier()?;
        let p = RustPath::CrateRoot { name, disambiguator };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_inherent_impl(&mut self) -> Result<RustPath> {
        let disambiguator = self.parse_disambiguator()?;
        let self_type = self.parse_type()?;
        let p = RustPath::InherentImpl { self_type: Box::new(self_type), disambiguator };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_trait_impl(&mut self) -> Result<RustPath> {
        let disambiguator = self.parse_disambiguator()?;
        let self_type = self.parse_type()?;
        let trait_path = self.parse_path()?;
        let p = RustPath::TraitImpl {
            self_type: Box::new(self_type),
            trait_path: Box::new(trait_path),
            disambiguator,
        };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_trait_def(&mut self) -> Result<RustPath> {
        let self_type = self.parse_type()?;
        let trait_path = self.parse_path()?;
        let p = RustPath::TraitDef {
            self_type: Box::new(self_type),
            trait_path: Box::new(trait_path),
        };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_nested_path(&mut self) -> Result<RustPath> {
        let ns = self.consume().ok_or_else(|| anyhow::anyhow!("EOF in nested ns"))?;
        let namespace = ns as char;
        let parent = self.parse_path()?;
        let disambiguator = self.parse_disambiguator()?;
        let name = self.parse_identifier()?;
        let p = RustPath::Nested {
            namespace,
            parent: Box::new(parent),
            name,
            disambiguator,
        };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_generic_path(&mut self) -> Result<RustPath> {
        let parent = self.parse_path()?;
        let mut args = Vec::new();
        while self.peek() != Some(b'E') && !self.at_end() {
            args.push(self.parse_generic_arg()?);
        }
        self.expect(b'E')?;
        let p = RustPath::Generic { parent: Box::new(parent), args };
        self.path_backref.push(p.clone());
        Ok(p)
    }

    fn parse_path_backref(&mut self) -> Result<RustPath> {
        let idx = usize::try_from(self.parse_base62_number()?)?;
        self.path_backref
            .get(idx)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Path backref {} OOB (have {})", idx, self.path_backref.len()))
    }

    fn parse_generic_arg(&mut self) -> Result<GenericArg> {
        match self.peek() {
            Some(b'L') => {
                self.consume();
                let lt = self.parse_base62_number()?;
                Ok(GenericArg::Lifetime(lt))
            }
            Some(b'K') => {
                self.consume();
                let c = self.parse_const()?;
                Ok(GenericArg::Const(c))
            }
            _ => {
                let ty = self.parse_type()?;
                Ok(GenericArg::Type(ty))
            }
        }
    }

    fn parse_type(&mut self) -> Result<RustType> {
        self.push_recursion()?;
        let result = self.parse_type_inner();
        self.pop_recursion();
        result
    }

    const fn basic_type_from_tag(tag: u8) -> Option<BasicType> {
        Some(match tag {
            b'a' => BasicType::I8,      b'b' => BasicType::Bool,
            b'c' => BasicType::Char,    b'd' => BasicType::F64,
            b'e' => BasicType::Str,     b'f' => BasicType::F32,
            b'h' => BasicType::U8,      b'i' => BasicType::I32,
            b'j' => BasicType::U32,     b'l' => BasicType::I64,
            b'm' => BasicType::U64,     b'n' => BasicType::I128,
            b'o' => BasicType::U128,    b'p' => BasicType::Ellipsis,
            b's' => BasicType::I16,     b't' => BasicType::U16,
            b'u' | b'y' => BasicType::USize,
            b'v' => BasicType::Unit,    b'x' => BasicType::ISize,
            b'z' => BasicType::Never,
            _ => return None,
        })
    }

    fn parse_type_inner(&mut self) -> Result<RustType> {
        let tag = self.peek().ok_or_else(|| anyhow::anyhow!("EOF in type"))?;
        if let Some(basic) = Self::basic_type_from_tag(tag) {
            self.consume();
            let ty = RustType::Basic(basic);
            self.type_backref.push(ty.clone());
            return Ok(ty);
        }
        let ty = match tag {
            b'A' => {
                self.consume();
                let elem = self.parse_type()?;
                let size = self.parse_const()?;
                RustType::Array { element: Box::new(elem), size: Box::new(size) }
            }
            b'D' => {
                self.consume();
                // dyn trait
                let mut traits = Vec::new();
                while self.peek() != Some(b'E') && !self.at_end() {
                    traits.push(self.parse_path()?);
                }
                self.expect(b'E')?;
                let lifetime = if self.peek() == Some(b'L') {
                    self.consume();
                    Some(self.parse_base62_number()?)
                } else {
                    None
                };
                RustType::DynTrait { traits, lifetime }
            }
            b'F' => {
                self.consume();
                self.parse_fn_ptr()?
            }
            b'G' => {
                self.consume();
                // generator — treat as named type
                let p = self.parse_path()?;
                RustType::Named(p)
            }
            b'P' => {
                self.consume();
                let inner = self.parse_type()?;
                RustType::RawPtr { mutability: Mutability::Const, inner: Box::new(inner) }
            }
            b'Q' => {
                self.consume();
                let inner = self.parse_type()?;
                RustType::RawPtr { mutability: Mutability::Mut, inner: Box::new(inner) }
            }
            b'R' => {
                self.consume();
                let lt = self.parse_opt_lifetime()?;
                let inner = self.parse_type()?;
                RustType::Ref { lifetime: lt, inner: Box::new(inner) }
            }
            b'W' => {
                self.consume();
                let lt = self.parse_opt_lifetime()?;
                let inner = self.parse_type()?;
                RustType::RefMut { lifetime: lt, inner: Box::new(inner) }
            }
            b'S' => {
                self.consume();
                let elem = self.parse_type()?;
                RustType::Slice(Box::new(elem))
            }
            b'T' => {
                self.consume();
                let mut elems = Vec::new();
                while self.peek() != Some(b'E') && !self.at_end() {
                    elems.push(self.parse_type()?);
                }
                self.expect(b'E')?;
                RustType::Tuple(elems)
            }
            b'B' => {
                self.consume();
                let idx = usize::try_from(self.parse_base62_number()?)?;
                self.type_backref
                    .get(idx)
                    .cloned()
                    .unwrap_or(RustType::Placeholder)
            }
            b'_' => {
                self.consume();
                RustType::Placeholder
            }
            // Named type (path-based)
            _ => {
                let p = self.parse_path()?;
                RustType::Named(p)
            }
        };
        self.type_backref.push(ty.clone());
        Ok(ty)
    }

    fn parse_fn_ptr(&mut self) -> Result<RustType> {
        let mut is_unsafe = false;
        let mut abi = "Rust".to_owned();
        // Optional 'U' for unsafe
        if self.peek() == Some(b'U') {
            self.consume();
            is_unsafe = true;
        }
        // Optional 'K' for ABI
        if self.peek() == Some(b'K') {
            self.consume();
            abi = self.parse_abi()?;
        }
        // Parameters followed by E and return type
        let mut params = Vec::new();
        while self.peek() != Some(b'E') && !self.at_end() {
            params.push(self.parse_type()?);
        }
        self.expect(b'E')?;
        let ret = self.parse_type()?;
        Ok(RustType::FnPtr { is_unsafe, abi, params, ret: Box::new(ret) })
    }

    fn parse_abi(&mut self) -> Result<String> {
        if self.peek() == Some(b'C') {
            self.consume();
            Ok("C".to_owned())
        } else {
            let id = self.parse_identifier()?;
            Ok(id)
        }
    }

    fn parse_opt_lifetime(&mut self) -> Result<Option<u64>> {
        if self.peek() == Some(b'L') {
            self.consume();
            Ok(Some(self.parse_base62_number()?))
        } else {
            Ok(None)
        }
    }

    fn parse_const(&mut self) -> Result<RustConst> {
        let tag = self.consume().ok_or_else(|| anyhow::anyhow!("EOF in const"))?;
        match tag {
            b'p' => Ok(RustConst::Placeholder),
            b'b' => {
                // bool
                match self.consume() {
                    Some(b'0') => Ok(RustConst::Bool(false)),
                    Some(b'1') => Ok(RustConst::Bool(true)),
                    _ => bail!("Invalid bool const"),
                }
            }
            b'c' => {
                // char — hex digits followed by _
                let mut hex = String::new();
                while let Some(c) = self.peek() {
                    if c == b'_' { self.consume(); break; }
                    hex.push(c as char);
                    self.consume();
                }
                let cp = u32::from_str_radix(&hex, 16).unwrap_or(0x3F);
                Ok(RustConst::Char(char::from_u32(cp).unwrap_or('?')))
            }
            b'n' => {
                // negative integer — hex followed by _
                let mut hex = String::new();
                while let Some(c) = self.peek() {
                    if c == b'_' { self.consume(); break; }
                    hex.push(c as char);
                    self.consume();
                }
                let v = u64::from_str_radix(&hex, 16).unwrap_or(0);
                Ok(RustConst::Usize(v.wrapping_neg()))
            }
            _ => {
                // Assume this is the first hex digit of a usize const
                // collect until '_'
                let mut hex = String::new();
                hex.push(tag as char);
                while let Some(c) = self.peek() {
                    if c == b'_' { self.consume(); break; }
                    hex.push(c as char);
                    self.consume();
                }
                let v = u64::from_str_radix(&hex, 16).unwrap_or(0);
                Ok(RustConst::Usize(v))
            }
        }
    }

    /// Parse a base-62 number (a-zA-Z0-9 digits, terminated by `_`).
    fn parse_base62_number(&mut self) -> Result<u64> {
        if self.peek() == Some(b'_') {
            self.consume();
            return Ok(0);
        }
        let mut n: u64 = 0;
        loop {
            let c = self.consume().ok_or_else(|| anyhow::anyhow!("EOF in base62"))?;
            if c == b'_' { break; }
            let digit = base62_digit(c)?;
            n = n.saturating_mul(62).saturating_add(digit);
        }
        // The actual index is n+1 for backref purposes
        Ok(n.saturating_add(1))
    }

    fn parse_decimal_number(&mut self) -> Result<u64> {
        let mut n = 0u64;
        while let Some(c) = self.peek() {
            if !c.is_ascii_digit() { break; }
            n = n
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(c - b'0')))
                .ok_or_else(|| anyhow::anyhow!("decimal number overflow"))?;
            self.consume();
        }
        Ok(n)
    }

    fn parse_disambiguator(&mut self) -> Result<u64> {
        if self.peek() == Some(b's') {
            self.consume();
            Ok(self.parse_base62_number()? + 1)
        } else {
            Ok(0)
        }
    }

    fn parse_identifier(&mut self) -> Result<String> {
        // [u] <decimal-number> <bytes>
        let is_unicode = if self.peek() == Some(b'u') {
            self.consume();
            true
        } else {
            false
        };
        let len_u64 = self.parse_decimal_number()?;
        let len = usize::try_from(len_u64)
            .map_err(|_| anyhow::anyhow!("Identifier length {len_u64} overflows usize"))?;
        if self.pos + len > self.input.len() {
            bail!("Identifier length {len} OOB");
        }
        let bytes = &self.input[self.pos..self.pos + len];
        self.pos += len;
        if is_unicode {
            // Punycode-like encoding — simplified: just treat as UTF-8
            Ok(decode_identifier_unicode(bytes))
        } else {
            Ok(std::str::from_utf8(bytes)
                .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in identifier: {e}"))?
                .to_owned())
        }
    }
}

fn base62_digit(c: u8) -> Result<u64> {
    Ok(match c {
        b'0'..=b'9' => u64::from(c - b'0'),
        b'a'..=b'z' => u64::from(c - b'a') + 10,
        b'A'..=b'Z' => u64::from(c - b'A') + 36,
        _ => bail!("Invalid base62 digit '{}'", c as char),
    })
}

fn decode_identifier_unicode(bytes: &[u8]) -> String {
    // Full punycode decoding is complex — for now, do basic substitution of
    // unicode escape sequences encoded as _<hex>_
    let s = std::str::from_utf8(bytes).unwrap_or("");
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' && chars.peek().is_some_and(char::is_ascii_hexdigit) {
            let mut hex = String::new();
            while chars.peek().is_some_and(char::is_ascii_hexdigit) {
                hex.push(chars.next().unwrap());
            }
            if chars.peek() == Some(&'_') { chars.next(); }
            if let Ok(cp) = u32::from_str_radix(&hex, 16)
                && let Some(uc) = char::from_u32(cp) {
                result.push(uc);
                continue;
            }
            result.push('_');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }
    result
}

// ── Legacy hash mangling ──────────────────────────────────────────────────────

/// Strip the Rust legacy hash suffix from a demangled name.
///
/// Legacy symbols look like: `_ZN4crate7module3fooE17hABCDEF0123456789E`
/// The hash is the last component starting with 'h' followed by 16 hex digits.
#[must_use]
pub fn strip_rust_hash(demangled: &str) -> String {
    // Find the last "::" separator
    if let Some(pos) = demangled.rfind("::") {
        let last_part = &demangled[pos + 2..];
        if is_rust_hash(last_part) {
            return demangled[..pos].to_owned();
        }
    }
    demangled.to_owned()
}

fn is_rust_hash(s: &str) -> bool {
    // Rust legacy hashes are 'h' followed by 15 or 16 hex digits
    if s.len() != 16 && s.len() != 17 { return false; }
    let bytes = s.as_bytes();
    bytes[0] == b'h' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// # Errors
/// Returns an error if the symbol is not a valid Rust v0 mangled symbol.
pub fn demangle_rust_v0(symbol: &str) -> Result<String> {
    let s = if symbol.starts_with(&format!("__{RUST_V0_PREFIX}")) {
        &symbol[3..]
    } else if symbol.starts_with(RUST_V0_PREFIX) {
        &symbol[2..]
    } else {
        bail!("Not a Rust v0 symbol: {symbol}");
    };
    // Strip trailing vendor suffix (".llvm." or similar)
    let s = s.split('.').next().unwrap_or(s);
    let mut parser = RustV0Parser::new(s.as_bytes());
    let sym = parser.parse_symbol()?;
    Ok(sym.to_string_repr())
}

/// # Errors
/// Returns an error if the symbol is not a valid legacy Rust mangled symbol.
pub fn demangle_rust_legacy(symbol: &str) -> Result<String> {
    // Legacy Rust uses Itanium ABI — last component is the hash
    // Basic heuristic: look for ::h<16 hex>E pattern
    if !symbol.starts_with(RUST_LEGACY_PREFIX) && !symbol.starts_with(&format!("__{RUST_LEGACY_PREFIX}")) {
        bail!("Not a legacy Rust symbol: {symbol}");
    }
    // Naive decode: strip _ZN prefix, read length-prefixed name components
    let s = symbol.trim_start_matches("__ZN").trim_start_matches(RUST_LEGACY_PREFIX);
    let mut pos = 0;
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    while pos < bytes.len() {
        if bytes[pos] == b'E' { break; }
        // read length
        let mut len = 0usize;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            len = len * 10 + (bytes[pos] - b'0') as usize;
            pos += 1;
        }
        if pos + len > bytes.len() { break; }
        let part = std::str::from_utf8(&bytes[pos..pos + len]).unwrap_or("?");
        parts.push(part.to_owned());
        pos += len;
    }
    if parts.is_empty() {
        bail!("Could not parse legacy symbol: {symbol}");
    }
    // strip hash suffix
    let joined = parts.join("::");
    Ok(strip_rust_hash(&joined))
}

/// Auto-detect and demangle a Rust symbol (v0 or legacy).
///
/// # Errors
/// Returns an error if the symbol is not a recognized Rust mangled symbol.
pub fn demangle_rust(symbol: &str) -> Result<String> {
    if symbol.starts_with(RUST_V0_PREFIX) || symbol.starts_with(&format!("__{RUST_V0_PREFIX}")) {
        demangle_rust_v0(symbol)
    } else if symbol.starts_with(RUST_LEGACY_PREFIX) || symbol.starts_with(&format!("__{RUST_LEGACY_PREFIX}")) {
        // Could be legacy Rust — check for hash
        let r = demangle_rust_legacy(symbol)?;
        if r.contains("::h") || !r.contains("::") {
            return Ok(r);
        }
        Ok(r)
    } else {
        bail!("Not a recognized Rust symbol: {symbol}")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_hash_present() {
        let s = "std::collections::HashMap::insert::h1a2b3c4d5e6f7890";
        assert_eq!(strip_rust_hash(s), "std::collections::HashMap::insert");
    }

    #[test]
    fn test_strip_hash_absent() {
        let s = "std::io::Read::read";
        assert_eq!(strip_rust_hash(s), s);
    }

    #[test]
    fn test_is_rust_hash() {
        assert!(is_rust_hash("h1a2b3c4d5e6f789"));
        assert!(!is_rust_hash("h1a2b"));
        assert!(!is_rust_hash("not_a_hash!!!!"));
    }

    #[test]
    fn test_basic_type_repr() {
        assert_eq!(BasicType::I32.to_string_repr(), "i32");
        assert_eq!(BasicType::Bool.to_string_repr(), "bool");
        assert_eq!(BasicType::F64.to_string_repr(), "f64");
        assert_eq!(BasicType::Never.to_string_repr(), "!");
    }

    #[test]
    fn test_rust_type_ref_repr() {
        let t = RustType::Ref {
            lifetime: None,
            inner: Box::new(RustType::Basic(BasicType::I32)),
        };
        assert_eq!(t.to_string_repr(), "&i32");
    }

    #[test]
    fn test_rust_type_slice_repr() {
        let t = RustType::Slice(Box::new(RustType::Basic(BasicType::U8)));
        assert_eq!(t.to_string_repr(), "[u8]");
    }

    #[test]
    fn test_demangle_rust_not_v0() {
        assert!(demangle_rust("malloc").is_err());
    }

    #[test]
    fn test_legacy_symbol_detection() {
        // Not a valid Rust legacy symbol but should not panic
        let r = demangle_rust_legacy("_ZN4core3fooE");
        let _ = r;
    }

    #[test]
    fn test_base62_digit() {
        assert_eq!(base62_digit(b'0').unwrap(), 0);
        assert_eq!(base62_digit(b'a').unwrap(), 10);
        assert_eq!(base62_digit(b'A').unwrap(), 36);
        assert!(base62_digit(b'!').is_err());
    }
}
