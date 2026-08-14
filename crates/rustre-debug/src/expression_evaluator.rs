// expression_evaluator.rs — GDB-style debugger expression evaluator
// Part of rustre-debug crate
//
// Supports parsing and evaluating expressions like:
//   $rax + 4
//   *(int*)($rsp + 8)
//   my_struct->field[2]
//   (char*)ptr
//   sizeof(int)
//   a > b ? a : b

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Public types re-exported
// ---------------------------------------------------------------------------

use self::error::{DebugError, DebugResult};

// ---------------------------------------------------------------------------
// Size / integer width
// ---------------------------------------------------------------------------

/// Byte width of an operand or memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Size {
    B1  = 1,
    B2  = 2,
    B4  = 4,
    B8  = 8,
    B16 = 16,
}

impl Size {
    #[must_use]
    pub const fn bytes(self) -> u64 { self as u64 }

    #[must_use]
    pub const fn bits(self) -> u64 { (self as u64) * 8 }

    #[must_use]
    pub const fn from_bytes(n: u64) -> Option<Self> {
        match n {
            1  => Some(Self::B1),
            2  => Some(Self::B2),
            4  => Some(Self::B4),
            8  => Some(Self::B8),
            16 => Some(Self::B16),
            _  => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Type system (minimal, used for pretty-printing and pointer arithmetic)
// ---------------------------------------------------------------------------

/// Opaque type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId(pub u32);

/// Primitive C-like type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Void,
    Bool,
    Int   { signed: bool, size: Size },
    Float { size: Size },
    Ptr   { pointee: TypeId },
    Array { element: TypeId, count: Option<u64> },
    Struct { name: String, fields: Vec<StructField> },
    Union  { name: String, fields: Vec<StructField> },
    Enum   { name: String, base: TypeId },
    /// A bitfield: `length` bits at bit `position` within the storage unit
    /// `base` (e.g. `unsigned flags : 3`).
    Bitfield { base: TypeId, position: u8, length: u8 },
    FnPtr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    pub name:   String,
    pub ty:     TypeId,
    pub offset: u64,   // byte offset within struct
}

/// Flat registry of types referenced during evaluation.
#[derive(Debug, Default)]
pub struct TypeSystem {
    types:   Vec<TypeKind>,
    by_name: HashMap<String, TypeId>,
    // Well-known primitive IDs cached for performance
    void_id:  Option<TypeId>,
    u8_id:    Option<TypeId>,
    i8_id:    Option<TypeId>,
    u16_id:   Option<TypeId>,
    i16_id:   Option<TypeId>,
    u32_id:   Option<TypeId>,
    i32_id:   Option<TypeId>,
    u64_id:   Option<TypeId>,
    i64_id:   Option<TypeId>,
    f32_id:   Option<TypeId>,
    f64_id:   Option<TypeId>,
    bool_id:  Option<TypeId>,
    char_ptr: Option<TypeId>,
}

impl TypeSystem {
    /// Create a `TypeSystem` pre-populated with C primitives.
    #[must_use]
    pub fn with_primitives() -> Self {
        let mut ts = Self::default();
        let void  = ts.insert_named("void",  TypeKind::Void);
        let bool_ = ts.insert_named("bool",  TypeKind::Bool);
        let u8_   = ts.insert_named("u8",    TypeKind::Int { signed: false, size: Size::B1 });
        let i8_   = ts.insert_named("i8",    TypeKind::Int { signed: true,  size: Size::B1 });
        let u16_  = ts.insert_named("u16",   TypeKind::Int { signed: false, size: Size::B2 });
        let i16_  = ts.insert_named("i16",   TypeKind::Int { signed: true,  size: Size::B2 });
        let u32_  = ts.insert_named("u32",   TypeKind::Int { signed: false, size: Size::B4 });
        let i32_  = ts.insert_named("i32",   TypeKind::Int { signed: true,  size: Size::B4 });
        let u64_  = ts.insert_named("u64",   TypeKind::Int { signed: false, size: Size::B8 });
        let i64_  = ts.insert_named("i64",   TypeKind::Int { signed: true,  size: Size::B8 });
        let f32_  = ts.insert_named("f32",   TypeKind::Float { size: Size::B4 });
        let f64_  = ts.insert_named("f64",   TypeKind::Float { size: Size::B8 });
        // Aliases
        ts.insert_named("char",  TypeKind::Int { signed: true,  size: Size::B1 });
        ts.insert_named("short", TypeKind::Int { signed: true,  size: Size::B2 });
        ts.insert_named("int",   TypeKind::Int { signed: true,  size: Size::B4 });
        ts.insert_named("long",  TypeKind::Int { signed: true,  size: Size::B8 });
        ts.insert_named("unsigned int",   TypeKind::Int { signed: false, size: Size::B4 });
        ts.insert_named("unsigned long",  TypeKind::Int { signed: false, size: Size::B8 });
        ts.insert_named("unsigned short", TypeKind::Int { signed: false, size: Size::B2 });
        ts.insert_named("unsigned char",  TypeKind::Int { signed: false, size: Size::B1 });
        ts.insert_named("float",  TypeKind::Float { size: Size::B4 });
        ts.insert_named("double", TypeKind::Float { size: Size::B8 });
        // <stdint.h> spellings. Without these a perfectly ordinary
        // `*(uint64_t*)($x0 + 16)` fails: the *pointer* cast silently degrades
        // to a generic u64 pointee, and — worse — `deref_size_from_operand`
        // would read 8 bytes for `(uint32_t*)`. Registering the names makes the
        // width come from the type instead of from a default.
        for (name, signed, size) in [
            ("int8_t",   true,  Size::B1), ("uint8_t",   false, Size::B1),
            ("int16_t",  true,  Size::B2), ("uint16_t",  false, Size::B2),
            ("int32_t",  true,  Size::B4), ("uint32_t",  false, Size::B4),
            ("int64_t",  true,  Size::B8), ("uint64_t",  false, Size::B8),
            ("intptr_t", true,  Size::B8), ("uintptr_t", false, Size::B8),
            ("ssize_t",  true,  Size::B8), ("size_t",    false, Size::B8),
        ] {
            ts.insert_named(name, TypeKind::Int { signed, size });
        }
        // char* convenience
        let char_id = ts.by_name["char"];
        let char_ptr_id = ts.intern(TypeKind::Ptr { pointee: char_id });
        ts.by_name.insert("char*".into(), char_ptr_id);
        // Named pointer types for every primitive, so a `(u32*)p` cast resolves
        // to a real u32 pointer (pointee width used by `[]` indexing and result
        // typing) instead of collapsing to a generic u64 pointer.
        for (name, id) in [
            ("void", void), ("bool", bool_), ("u8", u8_), ("i8", i8_),
            ("u16", u16_), ("i16", i16_), ("u32", u32_), ("i32", i32_),
            ("u64", u64_), ("i64", i64_), ("f32", f32_), ("f64", f64_),
            ("char", char_id), ("short", ts.by_name["short"]), ("int", ts.by_name["int"]),
            ("long", ts.by_name["long"]), ("float", ts.by_name["float"]), ("double", ts.by_name["double"]),
        ] {
            let ptr = ts.intern(TypeKind::Ptr { pointee: id });
            ts.by_name.entry(format!("{name}*")).or_insert(ptr);
        }
        // Same for the <stdint.h> spellings, so `(uint64_t*)p` resolves to a
        // real pointer type whose pointee width drives `[]` and `*`.
        for name in [
            "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
            "int64_t", "uint64_t", "intptr_t", "uintptr_t", "ssize_t", "size_t",
        ] {
            let Some(&id) = ts.by_name.get(name) else { continue };
            let ptr = ts.ptr_to(id);
            ts.by_name.entry(format!("{name}*")).or_insert(ptr);
        }

        ts.void_id  = Some(void);
        ts.bool_id  = Some(bool_);
        ts.u8_id    = Some(u8_);
        ts.i8_id    = Some(i8_);
        ts.u16_id   = Some(u16_);
        ts.i16_id   = Some(i16_);
        ts.u32_id   = Some(u32_);
        ts.i32_id   = Some(i32_);
        ts.u64_id   = Some(u64_);
        ts.i64_id   = Some(i64_);
        ts.f32_id   = Some(f32_);
        ts.f64_id   = Some(f64_);
        ts.char_ptr = Some(char_ptr_id);
        ts
    }

    fn intern(&mut self, kind: TypeKind) -> TypeId {
        let id = TypeId(u32::try_from(self.types.len()).unwrap_or(u32::MAX));
        self.types.push(kind);
        id
    }

    fn insert_named(&mut self, name: &str, kind: TypeKind) -> TypeId {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = self.intern(kind);
        self.by_name.insert(name.into(), id);
        id
    }

    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<TypeId> {
        self.by_name.get(name).copied()
    }

    #[must_use]
    pub fn get(&self, id: TypeId) -> Option<&TypeKind> {
        self.types.get(id.0 as usize)
    }

    /// Intern (or reuse) an array type `element[count]`.
    pub fn array_of(&mut self, element: TypeId, count: u64) -> TypeId {
        for (i, k) in self.types.iter().enumerate() {
            if let TypeKind::Array { element: e, count: c } = k
                && *e == element && *c == Some(count)
            {
                return TypeId(u32::try_from(i).unwrap_or(u32::MAX));
            }
        }
        self.intern(TypeKind::Array { element, count: Some(count) })
    }

    pub fn ptr_to(&mut self, inner: TypeId) -> TypeId {
        // Check for existing ptr type with same pointee
        for (i, k) in self.types.iter().enumerate() {
            if let TypeKind::Ptr { pointee } = k && *pointee == inner {
                return TypeId(u32::try_from(i).unwrap_or(u32::MAX));
            }
        }
        self.intern(TypeKind::Ptr { pointee: inner })
    }

    /// Forward-declare a struct: register an (initially empty) struct under
    /// `name` plus its `name*` pointer type, returning the struct's stable
    /// `TypeId`. Lets self/mutually-referential members resolve `Name*` before
    /// the fields are filled with [`Self::set_struct_fields`]. Returns the
    /// existing id if `name` is already registered.
    pub fn forward_declare_struct(&mut self, name: &str) -> TypeId {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = self.insert_named(name, TypeKind::Struct { name: name.to_string(), fields: Vec::new() });
        let ptr = self.ptr_to(id);
        self.by_name.entry(format!("{name}*")).or_insert(ptr);
        id
    }

    /// Fill the fields of a struct previously created by
    /// [`Self::forward_declare_struct`]. No-op if `id` isn't a struct.
    pub fn set_struct_fields(&mut self, id: TypeId, new_fields: Vec<StructField>) {
        if let Some(TypeKind::Struct { fields, .. }) = self.types.get_mut(id.0 as usize) {
            *fields = new_fields;
        }
    }

    /// Register a struct type under `name`, plus a named pointer type `name*`
    /// (so a `(name*)ptr` cast resolves and enables `->field` access). Returns
    /// the struct's `TypeId`. Re-defining a name returns the existing id.
    pub fn define_struct(&mut self, name: &str, fields: Vec<StructField>) -> TypeId {
        let id = self.insert_named(name, TypeKind::Struct { name: name.to_string(), fields });
        let ptr = self.ptr_to(id);
        self.by_name.entry(format!("{name}*")).or_insert(ptr);
        id
    }

    #[must_use]
    pub fn size_of(&self, id: TypeId) -> Option<u64> {
        match self.get(id)? {
            TypeKind::Void  => Some(0),
            TypeKind::Bool  => Some(1),
            TypeKind::Int { size, .. } | TypeKind::Float { size } => Some(size.bytes()),
            TypeKind::Ptr   { .. } | TypeKind::FnPtr => Some(8), // assume 64-bit
            TypeKind::Array { element, count: Some(n) } => {
                Some(self.size_of(*element)? * n)
            }
            TypeKind::Array { .. } => None,
            TypeKind::Struct { fields, .. } => {
                // size = offset of last field + size of last field (simplified)
                fields.iter().filter_map(|f| self.size_of(f.ty).map(|s| f.offset + s))
                    .max()
            }
            TypeKind::Union { fields, .. } => {
                fields.iter().filter_map(|f| self.size_of(f.ty)).max()
            }
            TypeKind::Enum { base, .. } | TypeKind::Bitfield { base, .. } => self.size_of(*base),
        }
    }

    /// Intern a bitfield type: `length` bits at bit `position` within `base`.
    pub fn bitfield_of(&mut self, base: TypeId, position: u8, length: u8) -> TypeId {
        self.intern(TypeKind::Bitfield { base, position, length })
    }

    #[must_use]
    pub fn pointee(&self, id: TypeId) -> Option<TypeId> {
        match self.get(id)? {
            TypeKind::Ptr { pointee } => Some(*pointee),
            _ => None,
        }
    }

    #[must_use]
    pub fn struct_field(&self, id: TypeId, name: &str) -> Option<&StructField> {
        match self.get(id)? {
            TypeKind::Struct { fields, .. } | TypeKind::Union { fields, .. } => {
                fields.iter().find(|f| f.name == name)
            }
            _ => None,
        }
    }

    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_u64(&self) -> TypeId {
        self.u64_id.expect("primitives not initialised")
    }
    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_i64(&self) -> TypeId {
        self.i64_id.expect("primitives not initialised")
    }
    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_bool(&self) -> TypeId {
        self.bool_id.expect("primitives not initialised")
    }
    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_char_ptr(&self) -> TypeId {
        self.char_ptr.expect("primitives not initialised")
    }
    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_void(&self) -> TypeId {
        self.void_id.expect("primitives not initialised")
    }
    /// # Panics
    /// Panics if primitives were not initialised via [`Self::with_primitives`].
    #[must_use]
    pub const fn primitive_f64(&self) -> TypeId {
        self.f64_id.expect("primitives not initialised")
    }
}

// ---------------------------------------------------------------------------
// Traits for register state and memory access
// ---------------------------------------------------------------------------

/// Read-only view of register values at a debug stop.
pub trait RegisterState {
    fn read_register(&self, name: &str) -> Option<u64>;
    fn all_registers(&self) -> Vec<(String, u64)>;
}

/// Read-only view of process memory.
pub trait MemoryProvider {
    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_bytes(&self, addr: u64, len: usize) -> DebugResult<Vec<u8>>;

    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_u8 (&self, addr: u64) -> DebugResult<u8>  {
        let b = self.read_bytes(addr, 1)?;
        let arr: [u8; 1] = <[u8; 1]>::try_from(b.as_slice())
            .map_err(|_| DebugError(format!("short read at {:#x}: got {} bytes, expected 1", addr, b.len())))?;
        Ok(arr[0])
    }
    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_u16(&self, addr: u64) -> DebugResult<u16> {
        let b = self.read_bytes(addr, 2)?;
        let arr: [u8; 2] = <[u8; 2]>::try_from(b.as_slice())
            .map_err(|_| DebugError(format!("short read at {:#x}: got {} bytes, expected 2", addr, b.len())))?;
        Ok(u16::from_le_bytes(arr))
    }
    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_u32(&self, addr: u64) -> DebugResult<u32> {
        let b = self.read_bytes(addr, 4)?;
        let arr: [u8; 4] = <[u8; 4]>::try_from(b.as_slice())
            .map_err(|_| DebugError(format!("short read at {:#x}: got {} bytes, expected 4", addr, b.len())))?;
        Ok(u32::from_le_bytes(arr))
    }
    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_u64(&self, addr: u64) -> DebugResult<u64> {
        let b = self.read_bytes(addr, 8)?;
        let arr: [u8; 8] = <[u8; 8]>::try_from(b.as_slice())
            .map_err(|_| DebugError(format!("short read at {:#x}: got {} bytes, expected 8", addr, b.len())))?;
        Ok(u64::from_le_bytes(arr))
    }
    /// # Errors
    /// Returns a [`DebugError`] if the read fails.
    fn read_cstring(&self, addr: u64, max_len: usize) -> DebugResult<String> {
        let mut result = Vec::with_capacity(max_len.min(256));
        for i in 0..max_len {
            let byte = self.read_u8(addr + i as u64)?;
            if byte == 0 { break; }
            result.push(byte);
        }
        Ok(String::from_utf8_lossy(&result).into_owned())
    }
}

/// Read-only symbol table for symbol resolution.
pub trait SymbolTable {
    fn lookup_symbol(&self, name: &str) -> Option<u64>;
    fn reverse_lookup(&self, addr: u64) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    IntLit(u64),
    FloatLit(f64),
    StringLit(String),
    // Identifiers / keywords
    Ident(String),
    Register(String),   // $rax
    // Operators
    Plus, Minus, Star, Slash, Percent,
    Amp, Pipe, Caret, Tilde, Bang,
    AmpAmp, PipePipe,
    LtLt, GtGt,
    Eq, Ne, Lt, Gt, Le, Ge,
    Question, Colon,
    Dot, Arrow,          // .  ->
    // Delimiters
    LParen, RParen, LBracket, RBracket, LBrace, RBrace,
    Comma, Semicolon,
    // Special
    Eof,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntLit(v)    => write!(f, "{v}"),
            Self::FloatLit(v)  => write!(f, "{v}"),
            Self::StringLit(s) => write!(f, "\"{s}\""),
            Self::Ident(s)     => write!(f, "{s}"),
            Self::Register(s)  => write!(f, "${s}"),
            Self::Plus         => write!(f, "+"),
            Self::Minus        => write!(f, "-"),
            Self::Star         => write!(f, "*"),
            Self::Slash        => write!(f, "/"),
            Self::Percent      => write!(f, "%"),
            Self::Amp          => write!(f, "&"),
            Self::Pipe         => write!(f, "|"),
            Self::Caret        => write!(f, "^"),
            Self::Tilde        => write!(f, "~"),
            Self::Bang         => write!(f, "!"),
            Self::AmpAmp       => write!(f, "&&"),
            Self::PipePipe     => write!(f, "||"),
            Self::LtLt         => write!(f, "<<"),
            Self::GtGt         => write!(f, ">>"),
            Self::Eq           => write!(f, "=="),
            Self::Ne           => write!(f, "!="),
            Self::Lt           => write!(f, "<"),
            Self::Gt           => write!(f, ">"),
            Self::Le           => write!(f, "<="),
            Self::Ge           => write!(f, ">="),
            Self::Question     => write!(f, "?"),
            Self::Colon        => write!(f, ":"),
            Self::Dot          => write!(f, "."),
            Self::Arrow        => write!(f, "->"),
            Self::LParen       => write!(f, "("),
            Self::RParen       => write!(f, ")"),
            Self::LBracket     => write!(f, "["),
            Self::RBracket     => write!(f, "]"),
            Self::LBrace       => write!(f, "{{"),
            Self::RBrace       => write!(f, "}}"),
            Self::Comma        => write!(f, ","),
            Self::Semicolon    => write!(f, ";"),
            Self::Eof          => write!(f, "<eof>"),
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer / Tokenizer
// ---------------------------------------------------------------------------

pub struct Lexer<'a> {
    input: &'a [u8],
    pos:   usize,
}

impl<'a> Lexer<'a> {
    #[must_use]
    pub const fn new(input: &'a str) -> Self {
        Self { input: input.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<u8> {
        self.input.get(self.pos + 1).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let ch = self.input.get(self.pos).copied();
        if ch.is_some() { self.pos += 1; }
        ch
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() { self.advance(); } else { break; }
        }
    }

    fn read_number(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let mut has_dot = false;
        let mut is_float = false;

        if self.peek() == Some(b'0') && matches!(self.peek2(), Some(b'x' | b'X')) {
            self.advance(); self.advance(); // skip 0x
            let hex_start = self.pos;
            while let Some(c) = self.peek() {
                if c.is_ascii_hexdigit() { self.advance(); } else { break; }
            }
            let s = std::str::from_utf8(&self.input[hex_start..self.pos]).unwrap();
            let v = u64::from_str_radix(s, 16)
                .map_err(|_| LexError::Overflow(format!("0x{s}")))?;
            return Ok(Token::IntLit(v));
        }

        if self.peek() == Some(b'0') && matches!(self.peek2(), Some(b'b' | b'B')) {
            self.advance(); self.advance(); // skip 0b
            let bin_start = self.pos;
            while let Some(c) = self.peek() {
                if c == b'0' || c == b'1' { self.advance(); } else { break; }
            }
            let s = std::str::from_utf8(&self.input[bin_start..self.pos]).unwrap();
            let v = u64::from_str_radix(s, 2)
                .map_err(|_| LexError::Overflow(format!("0b{s}")))?;
            return Ok(Token::IntLit(v));
        }

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance();
            } else if c == b'.' && !has_dot && self.peek2().is_some_and(|x| x.is_ascii_digit()) {
                has_dot = true; is_float = true; self.advance();
            } else if matches!(c, b'e' | b'E') && !is_float {
                is_float = true; self.advance();
                if matches!(self.peek(), Some(b'+' | b'-')) { self.advance(); }
            } else if c == b'f' || c == b'F' {
                self.advance(); is_float = true; break;
            } else {
                break;
            }
        }

        let s = std::str::from_utf8(&self.input[start..self.pos]).unwrap()
            .trim_end_matches(['f', 'F']);
        // Same contract as the `0x`/`0b` paths above: a literal that does not
        // parse is an error, never a silent 0. In a breakpoint condition a
        // fabricated 0 does not fail — it makes the breakpoint stop on a
        // condition nobody wrote.
        if is_float {
            let v = s
                .parse::<f64>()
                .map_err(|_| LexError::Overflow(s.to_string()))?;
            Ok(Token::FloatLit(v))
        } else {
            let v = s
                .parse::<u64>()
                .map_err(|_| LexError::Overflow(s.to_string()))?;
            Ok(Token::IntLit(v))
        }
    }

    fn read_ident(&mut self) -> Token {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' { self.advance(); } else { break; }
        }
        let s = std::str::from_utf8(&self.input[start..self.pos]).unwrap().to_string();
        Token::Ident(s)
    }

    fn read_register(&mut self) -> Token {
        self.advance(); // skip $
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' { self.advance(); } else { break; }
        }
        let name = std::str::from_utf8(&self.input[start..self.pos]).unwrap().to_string();
        Token::Register(name)
    }

    fn read_string(&mut self) -> Token {
        self.advance(); // skip opening "
        let mut s = String::new();
        while let Some(c) = self.advance() {
            if c == b'"' { break; }
            if c == b'\\' {
                match self.advance() {
                    Some(b'n')  => s.push('\n'),
                    Some(b't')  => s.push('\t'),
                    Some(b'r')  => s.push('\r'),
                    Some(b'\\') => s.push('\\'),
                    Some(b'"')  => s.push('"'),
                    Some(other) => { s.push('\\'); s.push(other as char); }
                    None        => break,
                }
            } else {
                s.push(c as char);
            }
        }
        Token::StringLit(s)
    }

    /// Tokenize the entire input string into a `Vec<Token>`.
    ///
    /// # Errors
    /// Returns a [`LexError`] on unexpected characters or integer overflow.
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::with_capacity(self.input.len() / 4 + 1);
        loop {
            self.skip_whitespace();
            let Some(c) = self.peek() else {
                tokens.push(Token::Eof);
                break;
            };
            let tok = match c {
                b'0'..=b'9' => self.read_number()?,
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.read_ident(),
                b'$' => self.read_register(),
                b'"' => self.read_string(),
                b'+' => { self.advance(); Token::Plus    },
                b'-' => {
                    self.advance();
                    if self.peek() == Some(b'>') { self.advance(); Token::Arrow } else { Token::Minus }
                }
                b'*' => { self.advance(); Token::Star    },
                b'/' => {
                    self.advance();
                    if self.peek() == Some(b'/') {
                        // line comment — skip to end
                        while self.peek().is_some_and(|x| x != b'\n') { self.advance(); }
                        continue;
                    }
                    Token::Slash
                }
                b'%' => { self.advance(); Token::Percent },
                b'&' => {
                    self.advance();
                    if self.peek() == Some(b'&') { self.advance(); Token::AmpAmp } else { Token::Amp }
                }
                b'|' => {
                    self.advance();
                    if self.peek() == Some(b'|') { self.advance(); Token::PipePipe } else { Token::Pipe }
                }
                b'^' => { self.advance(); Token::Caret  },
                b'~' => { self.advance(); Token::Tilde  },
                b'!' => {
                    self.advance();
                    if self.peek() == Some(b'=') { self.advance(); Token::Ne } else { Token::Bang }
                }
                b'<' => {
                    self.advance();
                    if self.peek() == Some(b'<') { self.advance(); Token::LtLt }
                    else if self.peek() == Some(b'=') { self.advance(); Token::Le }
                    else { Token::Lt }
                }
                b'>' => {
                    self.advance();
                    if self.peek() == Some(b'>') { self.advance(); Token::GtGt }
                    else if self.peek() == Some(b'=') { self.advance(); Token::Ge }
                    else { Token::Gt }
                }
                b'=' => {
                    self.advance();
                    if self.peek() == Some(b'=') { self.advance(); Token::Eq } else {
                        return Err(LexError::UnexpectedChar('='));
                    }
                }
                b'?' => { self.advance(); Token::Question },
                b':' => { self.advance(); Token::Colon   },
                b'.' => { self.advance(); Token::Dot     },
                b'(' => { self.advance(); Token::LParen  },
                b')' => { self.advance(); Token::RParen  },
                b'[' => { self.advance(); Token::LBracket},
                b']' => { self.advance(); Token::RBracket},
                b'{' => { self.advance(); Token::LBrace  },
                b'}' => { self.advance(); Token::RBrace  },
                b',' => { self.advance(); Token::Comma   },
                b';' => { self.advance(); Token::Semicolon},
                other => return Err(LexError::UnexpectedChar(other as char)),
            };
            tokens.push(tok);
        }
        Ok(tokens)
    }
}

#[derive(Debug, Clone)]
pub enum LexError {
    UnexpectedChar(char),
    Overflow(String),
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedChar(c) => write!(f, "unexpected character: {c:?}"),
            Self::Overflow(s) => write!(f, "integer literal overflow: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// Binary operators in order of precedence (lowest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    // Logical
    Or, And,
    // Bitwise
    BitOr, BitXor, BitAnd,
    // Comparison
    Eq, Ne, Lt, Gt, Le, Ge,
    // Shift
    Shl, Shr,
    // Arithmetic
    Add, Sub, Mul, Div, Rem,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Or     => "||", Self::And   => "&&",
            Self::BitOr  => "|",  Self::BitXor => "^", Self::BitAnd => "&",
            Self::Eq     => "==", Self::Ne     => "!=",
            Self::Lt     => "<",  Self::Gt      => ">",
            Self::Le     => "<=", Self::Ge      => ">=",
            Self::Shl    => "<<", Self::Shr     => ">>",
            Self::Add    => "+",  Self::Sub      => "-",
            Self::Mul    => "*",  Self::Div      => "/",  Self::Rem => "%",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp { Neg, Not, BitNot, AddrOf }

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Neg => write!(f, "-"), Self::Not => write!(f, "!"),
            Self::BitNot => write!(f, "~"), Self::AddrOf => write!(f, "&") }
    }
}

/// A C-style type annotation that can appear in cast expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum CastType {
    Named(String),         // (int), (char)
    Pointer(Box<Self>),    // (int*)
    Const(Box<Self>),      // (const int*)
}

impl CastType {
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Named(s)   => s.clone(),
            Self::Pointer(t) => format!("{}*", t.as_str()),
            Self::Const(t)   => format!("const {}", t.as_str()),
        }
    }
}

/// Expression AST node.
#[derive(Debug, Clone)]
pub enum ExprAst {
    /// Integer literal: 0, 42, 0x1234
    Lit(u64),
    /// Float literal: 1.5, 3.14
    FloatLit(f64),
    /// String literal: "hello"
    StringLit(String),
    /// Symbol name: main, `g_counter`  (resolved via symbol table → address)
    Sym(String),
    /// Register: $rax, $rsp, $rbp
    Reg(String),
    /// Dereference with access size: *ptr, *(u32*)ptr
    Deref(Box<Self>, Size),
    /// Struct field via dot: `struct_var`.field
    Field(Box<Self>, String),
    /// Arrow dereference: ptr->field  (syntactic sugar for (*ptr).field)
    Arrow(Box<Self>, String),
    /// Array index: `arr[i]`
    Index(Box<Self>, Box<Self>),
    /// C-style cast: (int)val, (char*)ptr
    Cast(CastType, Box<Self>),
    /// Binary operation
    BinOp(BinOp, Box<Self>, Box<Self>),
    /// Unary operation
    UnOp(UnOp, Box<Self>),
    /// Function-like call: sizeof(int), sizeof(expr)
    Call(String, Vec<Self>),
    /// Ternary: cond ? then : else
    Ternary(Box<Self>, Box<Self>, Box<Self>),
}

impl fmt::Display for ExprAst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lit(v)           => write!(f, "{v}"),
            Self::FloatLit(v)      => write!(f, "{v}"),
            Self::StringLit(s)     => write!(f, "\"{s}\""),
            Self::Sym(s)           => write!(f, "{s}"),
            Self::Reg(r)           => write!(f, "${r}"),
            Self::Deref(e, _)      => write!(f, "*{e}"),
            Self::Field(e, n)      => write!(f, "{e}.{n}"),
            Self::Arrow(e, n)      => write!(f, "{e}->{n}"),
            Self::Index(a, i)      => write!(f, "{a}[{i}]"),
            Self::Cast(t, e)       => write!(f, "({}){e}", t.as_str()),
            Self::BinOp(op, l, r)  => write!(f, "({l} {op} {r})"),
            Self::UnOp(op, e)      => write!(f, "{op}{e}"),
            Self::Call(n, args)    => {
                write!(f, "{n}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Ternary(c, t, e) => write!(f, "({c} ? {t} : {e})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub struct Parser {
    tokens: Vec<Token>,
    pos:    usize,
}

#[derive(Debug, Clone)]
pub enum ParseError {
    UnexpectedToken { expected: String, got: Token },
    UnexpectedEof,
    InvalidCastType(String),
    Other(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedToken { expected, got } =>
                write!(f, "expected {expected}, got {got}"),
            Self::UnexpectedEof => write!(f, "unexpected end of expression"),
            Self::InvalidCastType(s) => write!(f, "invalid cast type: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl Parser {
    #[must_use]
    pub const fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn peek2(&self) -> &Token {
        self.tokens.get(self.pos + 1).unwrap_or(&Token::Eof)
    }

    /// Look ahead two tokens without consuming. Useful for two-token disambiguation
    /// (e.g. distinguishing `(` cast-type `)` from a parenthesized expression).
    #[must_use]
    pub fn lookahead2(&self) -> (&Token, &Token) {
        (self.peek(), self.peek2())
    }

    fn advance(&mut self) -> &Token {
        if self.pos >= self.tokens.len() {
            return &Token::Eof;
        }
        let idx = self.pos;
        self.pos += 1;
        &self.tokens[idx]
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        let tok = self.advance().clone();
        if tok == *expected { Ok(()) } else {
            Err(ParseError::UnexpectedToken { expected: format!("{expected}"), got: tok })
        }
    }

    // -----------------------------------------------------------------------
    // Try to parse a cast type like (int), (char*), (unsigned int*)
    // Returns None if it's not a cast (i.e., ordinary paren expr).
    // -----------------------------------------------------------------------
    fn try_parse_cast_type(&mut self) -> Option<CastType> {
        // We're past the '(' already when called
        let saved = self.pos;
        let result = self.parse_cast_type_inner();
        if result.is_none() {
            self.pos = saved;
        }
        result
    }

    fn parse_cast_type_inner(&mut self) -> Option<CastType> {
        // Accept: [const] <base_type_name> [*]*
        let is_const = if let Token::Ident(s) = self.peek() {
            if s == "const" { self.advance(); true } else { false }
        } else { false };

        let base = if let Token::Ident(name) = self.peek().clone() {
            // Multi-word: unsigned int / unsigned long / unsigned short / unsigned char
            let mut full = name;
            self.advance();
            if (full == "unsigned" || full == "signed") && let Token::Ident(next) = self.peek().clone() && matches!(next.as_str(), "int"|"long"|"short"|"char") {
                full.push(' ');
                full.push_str(&next);
                self.advance();
            }
            // Also allow "long long"
            if full == "long" && let Token::Ident(next) = self.peek().clone() && next == "long" {
                full.push_str(" long"); self.advance();
            }
            CastType::Named(full)
        } else {
            return None;
        };

        // Pointer stars
        let mut ty = if is_const { CastType::Const(Box::new(base)) } else { base };
        while self.peek() == &Token::Star {
            self.advance();
            ty = CastType::Pointer(Box::new(ty));
        }

        // Must be followed by ')'
        if self.peek() == &Token::RParen {
            self.advance();
            Some(ty)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Recursive-descent expression parser
    // -----------------------------------------------------------------------

    /// # Errors
    ///
    /// Returns `ParseError` if the expression is malformed.
    pub fn parse_expr(&mut self) -> Result<ExprAst, ParseError> {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<ExprAst, ParseError> {
        let cond = self.parse_or()?;
        if self.peek() == &Token::Question {
            self.advance();
            let then = self.parse_ternary()?;
            self.expect(&Token::Colon)?;
            let else_ = self.parse_ternary()?;
            Ok(ExprAst::Ternary(Box::new(cond), Box::new(then), Box::new(else_)))
        } else {
            Ok(cond)
        }
    }

    fn parse_or(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_and()?;
        while self.peek() == &Token::PipePipe {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = ExprAst::BinOp(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_bitor()?;
        while self.peek() == &Token::AmpAmp {
            self.advance();
            let rhs = self.parse_bitor()?;
            lhs = ExprAst::BinOp(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_bitor(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_bitxor()?;
        while self.peek() == &Token::Pipe {
            self.advance();
            let rhs = self.parse_bitxor()?;
            lhs = ExprAst::BinOp(BinOp::BitOr, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_bitxor(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_bitand()?;
        while self.peek() == &Token::Caret {
            self.advance();
            let rhs = self.parse_bitand()?;
            lhs = ExprAst::BinOp(BinOp::BitXor, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_bitand(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_equality()?;
        while self.peek() == &Token::Amp {
            self.advance();
            let rhs = self.parse_equality()?;
            lhs = ExprAst::BinOp(BinOp::BitAnd, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_equality(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_relational()?;
        loop {
            let op = match self.peek() {
                Token::Eq => BinOp::Eq,
                Token::Ne => BinOp::Ne,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_relational()?;
            lhs = ExprAst::BinOp(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_relational(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_shift()?;
        loop {
            let op = match self.peek() {
                Token::Lt => BinOp::Lt,
                Token::Gt => BinOp::Gt,
                Token::Le => BinOp::Le,
                Token::Ge => BinOp::Ge,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_shift()?;
            lhs = ExprAst::BinOp(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_shift(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_additive()?;
        loop {
            let op = match self.peek() {
                Token::LtLt => BinOp::Shl,
                Token::GtGt => BinOp::Shr,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_additive()?;
            lhs = ExprAst::BinOp(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_additive(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            let op = match self.peek() {
                Token::Plus  => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_multiplicative()?;
            lhs = ExprAst::BinOp(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self) -> Result<ExprAst, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star    => BinOp::Mul,
                Token::Slash   => BinOp::Div,
                Token::Percent => BinOp::Rem,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_unary()?;
            lhs = ExprAst::BinOp(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<ExprAst, ParseError> {
        match self.peek().clone() {
            Token::Minus => { self.advance(); let e = self.parse_unary()?; Ok(ExprAst::UnOp(UnOp::Neg,    Box::new(e))) }
            Token::Bang  => { self.advance(); let e = self.parse_unary()?; Ok(ExprAst::UnOp(UnOp::Not,    Box::new(e))) }
            Token::Tilde => { self.advance(); let e = self.parse_unary()?; Ok(ExprAst::UnOp(UnOp::BitNot, Box::new(e))) }
            Token::Amp   => { self.advance(); let e = self.parse_unary()?; Ok(ExprAst::UnOp(UnOp::AddrOf, Box::new(e))) }
            Token::Star  => {
                self.advance();
                let e = self.parse_unary()?;
                // Size the read from a pointer cast if present (`*(u8*)p` reads 1
                // byte), else default to pointer width.
                let size = deref_size_from_operand(&e);
                Ok(ExprAst::Deref(Box::new(e), size))
            }
            Token::LParen => {
                self.advance(); // consume '('
                // Try cast
                if let Some(cast_ty) = self.try_parse_cast_type() {
                    let e = self.parse_unary()?;
                    return Ok(ExprAst::Cast(cast_ty, Box::new(e)));
                }
                // Otherwise ordinary paren expr — chain any postfix operators
                // so `((T*)p)->field`, `(expr).field`, `(expr)[i]` parse.
                let e = self.parse_ternary()?;
                self.expect(&Token::RParen)?;
                self.parse_postfix_ops(e)
            }
            _ => self.parse_postfix()
        }
    }

    fn parse_postfix(&mut self) -> Result<ExprAst, ParseError> {
        let base = self.parse_primary()?;
        self.parse_postfix_ops(base)
    }

    /// Apply any trailing postfix operators (`.field`, `->field`, `[i]`) to an
    /// already-parsed base — shared by `parse_postfix` and the parenthesised-
    /// group path so `((T*)p)->field` works.
    fn parse_postfix_ops(&mut self, mut base: ExprAst) -> Result<ExprAst, ParseError> {
        loop {
            base = match self.peek().clone() {
                Token::Dot => {
                    self.advance();
                    let name = match self.advance().clone() {
                        Token::Ident(s) => s,
                        t => return Err(ParseError::UnexpectedToken {
                            expected: "field name".into(), got: t }),
                    };
                    ExprAst::Field(Box::new(base), name)
                }
                Token::Arrow => {
                    self.advance();
                    let name = match self.advance().clone() {
                        Token::Ident(s) => s,
                        t => return Err(ParseError::UnexpectedToken {
                            expected: "field name".into(), got: t }),
                    };
                    ExprAst::Arrow(Box::new(base), name)
                }
                Token::LBracket => {
                    self.advance();
                    let idx = self.parse_ternary()?;
                    self.expect(&Token::RBracket)?;
                    ExprAst::Index(Box::new(base), Box::new(idx))
                }
                _ => break,
            };
        }
        Ok(base)
    }

    fn parse_primary(&mut self) -> Result<ExprAst, ParseError> {
        match self.peek().clone() {
            Token::IntLit(v)    => { self.advance(); Ok(ExprAst::Lit(v)) }
            Token::FloatLit(v)  => { self.advance(); Ok(ExprAst::FloatLit(v)) }
            Token::StringLit(s) => { self.advance(); Ok(ExprAst::StringLit(s)) }
            Token::Register(r)  => { self.advance(); Ok(ExprAst::Reg(r)) }
            Token::Ident(name) => {
                self.advance();
                if self.peek() == &Token::LParen {
                    // function call or sizeof
                    self.advance();
                    if name == "sizeof" {
                        // sizeof can have a type or expression
                        let saved = self.pos;
                        if let Some(cast_ty) = self.try_parse_cast_type() {
                            return Ok(ExprAst::Call("sizeof".into(),
                                vec![ExprAst::Sym(cast_ty.as_str())]));
                        }
                        self.pos = saved;
                        let e = self.parse_ternary()?;
                        self.expect(&Token::RParen)?;
                        return Ok(ExprAst::Call("sizeof".into(), vec![e]));
                    }
                    let mut args = Vec::new();
                    if self.peek() != &Token::RParen {
                        args.push(self.parse_ternary()?);
                        while self.peek() == &Token::Comma {
                            self.advance();
                            args.push(self.parse_ternary()?);
                        }
                    }
                    self.expect(&Token::RParen)?;
                    Ok(ExprAst::Call(name, args))
                } else {
                    Ok(ExprAst::Sym(name))
                }
            }
            Token::LParen => {
                self.advance();
                if let Some(cast_ty) = self.try_parse_cast_type() {
                    let e = self.parse_unary()?;
                    return Ok(ExprAst::Cast(cast_ty, Box::new(e)));
                }
                let e = self.parse_ternary()?;
                self.expect(&Token::RParen)?;
                Ok(e)
            }
            Token::Eof => Err(ParseError::UnexpectedEof),
            other => Err(ParseError::UnexpectedToken {
                expected: "expression".into(), got: other }),
        }
    }
}

/// Convenience: parse a complete expression string.
///
/// # Errors
/// Derive a dereference read width from a `*(T*)…` operand: for a single
/// pointer cast to a named element type, the read width is `sizeof(T)`. For a
/// pointer-to-pointer (`(int**)`), any non-cast operand, or an unknown type
/// name, the width defaults to pointer size (8 bytes).
fn deref_size_from_operand(e: &ExprAst) -> Size {
    let ExprAst::Cast(ct, _) = e else { return Size::B8 };
    // Strip leading `const`.
    let mut outer = ct;
    while let CastType::Const(inner) = outer { outer = inner; }
    let CastType::Pointer(pointee) = outer else { return Size::B8 };
    let mut p = pointee.as_ref();
    while let CastType::Const(inner) = p { p = inner; }
    let CastType::Named(name) = p else { return Size::B8 }; // (int**) etc → ptr width
    scalar_width_of_name(name).unwrap_or(Size::B8) // pointer / unknown
}

/// Width of a named scalar C type, or `None` when the name is not one this
/// module knows.
///
/// Matched on the WHOLE normalised name, never on a substring. The previous
/// version asked `name.contains("char")`, which is true of `wchar_t`: a
/// `(wchar_t*)p` dereference read ONE byte and reported it as the character,
/// on every platform. Dereferencing a wide string is an ordinary thing to do in
/// a debugger, and the answer came back plausible and wrong. `contains("short")`
/// had the same shape for any user type whose name happens to contain it.
///
/// Two widths are platform-dependent and were previously fixed:
/// * `long` / `unsigned long` is 4 bytes on Windows (LLP64) and 8 on Unix
///   (LP64) — it fell into the 8-byte default, so every `(long*)p` read on
///   Windows pulled in four bytes of whatever follows;
/// * `wchar_t` is 2 bytes on Windows and 4 on Unix.
///
/// `None` for anything else — a struct, an enum, a typedef this module has
/// never heard of. The caller keeps its documented 8-byte fallback, but the
/// distinction is now expressible instead of being hidden inside a chain of
/// `contains`.
#[must_use]
pub fn scalar_width_of_name(name: &str) -> Option<Size> {
    // Normalise: lowercase, single spaces, and the qualifiers that do not
    // change a width stripped from the front.
    let lowered = name.to_ascii_lowercase();
    let mut words: Vec<&str> = lowered.split_whitespace().collect();
    while matches!(words.first(), Some(&"const" | &"volatile" | &"signed" | &"unsigned")) {
        words.remove(0);
    }
    let normalised = words.join(" ");
    let long_is_8 = !cfg!(target_os = "windows");
    let wchar_is_4 = !cfg!(target_os = "windows");
    Some(match normalised.as_str() {
        "char" | "u8" | "i8" | "int8_t" | "uint8_t" | "bool" | "_bool" => Size::B1,
        "short" | "short int" | "u16" | "i16" | "int16_t" | "uint16_t" | "char16_t" => Size::B2,
        "int" | "u32" | "i32" | "int32_t" | "uint32_t" | "float" | "f32" | "char32_t" => {
            Size::B4
        }
        "wchar_t" => {
            if wchar_is_4 { Size::B4 } else { Size::B2 }
        }
        "long" | "long int" => {
            if long_is_8 { Size::B8 } else { Size::B4 }
        }
        "long long" | "long long int" | "u64" | "i64" | "int64_t" | "uint64_t" | "double"
        | "f64" | "size_t" | "ssize_t" | "intptr_t" | "uintptr_t" | "ptrdiff_t" => Size::B8,
        _ => return None,
    })
}

/// Returns an [`EvalError`] on lex or parse failure.
pub fn parse_expression(input: &str) -> Result<ExprAst, EvalError> {
    let mut lexer = Lexer::new(input);
    let tokens = lexer.tokenize().map_err(|e| EvalError::ParseFailed(e.to_string()))?;
    let mut parser = Parser::new(tokens);
    parser.parse_expr().map_err(|e| EvalError::ParseFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Typed value (result of evaluation)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TypedValue {
    pub value:      u64,
    pub type_id:    TypeId,
    /// True if this value is a memory address (lvalue / pointer context).
    pub is_address: bool,
    /// Raw bit pattern for floats.
    float_bits: Option<u64>,
}

impl TypedValue {
    #[must_use]
    pub const fn int(value: u64, type_id: TypeId) -> Self {
        Self { value, type_id, is_address: false, float_bits: None }
    }

    #[must_use]
    pub const fn address(addr: u64, type_id: TypeId) -> Self {
        Self { value: addr, type_id, is_address: true, float_bits: None }
    }

    #[must_use]
    pub fn float_f32(v: f32, type_id: TypeId) -> Self {
        let bits = u64::from(v.to_bits());
        Self { value: bits, type_id, is_address: false, float_bits: Some(bits) }
    }

    #[must_use]
    pub const fn float_f64(v: f64, type_id: TypeId) -> Self {
        let bits = v.to_bits();
        Self { value: bits, type_id, is_address: false, float_bits: Some(bits) }
    }

    #[must_use]
    pub const fn as_bool(&self) -> bool { self.value != 0 }

    #[must_use]
    pub const fn as_i64(&self) -> i64 { self.value.cast_signed() }

    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.float_bits.map(f64::from_bits)
    }

    #[must_use]
    pub fn as_f32(&self) -> Option<f32> {
        self.float_bits.map(|b| f32::from_bits(u32::try_from(b).unwrap_or(u32::MAX)))
    }
}

// ---------------------------------------------------------------------------
// Evaluation errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EvalError {
    ParseFailed(String),
    UndefinedRegister(String),
    UndefinedSymbol(String),
    MemoryReadError { addr: u64, reason: String },
    TypeMismatch    { expected: String, got: String },
    UnknownType(String),
    UnknownField    { type_name: String, field: String },
    DivisionByZero,
    /// `i64::MIN / -1` (and `%`): the quotient is not representable. Kept
    /// distinct from `DivisionByZero` because it is a different defect —
    /// reporting it as "division by zero" would misdescribe the operands.
    DivisionOverflow,
    UnsupportedOperation(String),
    WatchLimit,
    Other(String),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseFailed(s)       => write!(f, "parse error: {s}"),
            Self::UndefinedRegister(r) => write!(f, "undefined register: ${r}"),
            Self::UndefinedSymbol(s)   => write!(f, "undefined symbol: {s}"),
            Self::MemoryReadError { addr, reason } =>
                write!(f, "memory read at 0x{addr:x} failed: {reason}"),
            Self::TypeMismatch { expected, got } =>
                write!(f, "type mismatch: expected {expected}, got {got}"),
            Self::UnknownType(t)       => write!(f, "unknown type: {t}"),
            Self::UnknownField { type_name, field } =>
                write!(f, "unknown field: {type_name}.{field}"),
            Self::DivisionByZero       => write!(f, "division by zero"),
            Self::DivisionOverflow     => write!(f, "division overflow: i64::MIN / -1 is not representable"),
            Self::UnsupportedOperation(s) => write!(f, "unsupported operation: {s}"),
            Self::WatchLimit           => write!(f, "watch expression limit reached"),
            Self::Other(s)             => write!(f, "{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

pub struct EvalContext<'a> {
    pub registers: &'a dyn RegisterState,
    pub memory:    &'a dyn MemoryProvider,
    pub symbols:   &'a dyn SymbolTable,
    pub types:     &'a TypeSystem,
}

impl<'a> EvalContext<'a> {
    #[must_use]
    pub fn new(
        registers: &'a dyn RegisterState,
        memory:    &'a dyn MemoryProvider,
        symbols:   &'a dyn SymbolTable,
        types:     &'a TypeSystem,
    ) -> Self {
        Self { registers, memory, symbols, types }
    }
}

// ---------------------------------------------------------------------------
// Main evaluator
// ---------------------------------------------------------------------------

pub struct ExprEvaluator;

impl ExprEvaluator {
    fn eval_deref(base: &TypedValue, size: Size, ctx: &EvalContext<'_>) -> Result<TypedValue, EvalError> {
        let addr = base.value;
        let pointee_ty = ctx.types.pointee(base.type_id).unwrap_or_else(|| ctx.types.primitive_u64());
        // Dereferencing a pointer to an aggregate yields the aggregate lvalue
        // (its address), so `(*sp).field` chains — don't read it as a scalar.
        if Self::is_aggregate(pointee_ty, ctx) {
            return Ok(TypedValue::address(addr, pointee_ty));
        }
        let raw = match size {
            Size::B1  => ctx.memory.read_u8(addr).map(u64::from),
            Size::B2  => ctx.memory.read_u16(addr).map(u64::from),
            Size::B4  => ctx.memory.read_u32(addr).map(u64::from),
            Size::B8 | Size::B16 => ctx.memory.read_u64(addr),
        }.map_err(|e| EvalError::MemoryReadError { addr, reason: e.to_string() })?;
        Ok(Self::scalar_value(raw, pointee_ty, size.bytes(), ctx))
    }

    /// Sign-extend `raw` (a zero-extended `nbytes`-byte read) to 64 bits when
    /// `ty` is a SIGNED integer narrower than 8 bytes, so e.g. `*(i8*)p` of 0xFF
    /// evaluates to -1 (0xFFFF…FF), not 255. No-op for unsigned/8-byte/non-int.
    fn sign_extend_for(raw: u64, ty: TypeId, nbytes: u64, ctx: &EvalContext<'_>) -> u64 {
        if let Some(TypeKind::Int { signed: true, .. }) = ctx.types.get(ty) {
            if (1..8).contains(&nbytes) {
                let bits = nbytes * 8;
                let shift = 64 - bits;
                return ((raw << shift) as i64 >> shift) as u64;
            }
        }
        raw
    }

    /// Build a scalar `TypedValue` from a raw `nbytes`-byte read of type `ty`:
    /// Float types reinterpret the bits as f32/f64; signed ints sign-extend;
    /// everything else stays a zero-extended int.
    fn scalar_value(raw: u64, ty: TypeId, nbytes: u64, ctx: &EvalContext<'_>) -> TypedValue {
        match ctx.types.get(ty) {
            Some(TypeKind::Float { size: Size::B4 }) => {
                TypedValue::float_f32(f32::from_bits(raw as u32), ty)
            }
            Some(TypeKind::Float { .. }) => TypedValue::float_f64(f64::from_bits(raw), ty),
            _ => TypedValue::int(Self::sign_extend_for(raw, ty, nbytes, ctx), ty),
        }
    }

    /// True if `ty` is an aggregate (struct/union/array) — a field of such a
    /// type is not scalar and must be kept as an ADDRESS so further `.field` /
    /// `->field` / `[i]` can chain (nested member access), rather than eagerly
    /// read as an integer.
    /// The element type reached by `[]`: an array's element, a pointer's
    /// pointee, else `u64` (a raw address indexed as a u64 array).
    fn element_type(ty: TypeId, ctx: &EvalContext<'_>) -> TypeId {
        match ctx.types.get(ty) {
            Some(TypeKind::Array { element, .. }) => *element,
            _ => ctx.types.pointee(ty).unwrap_or_else(|| ctx.types.primitive_u64()),
        }
    }

    fn is_aggregate(ty: TypeId, ctx: &EvalContext<'_>) -> bool {
        matches!(
            ctx.types.get(ty),
            Some(TypeKind::Struct { .. } | TypeKind::Union { .. } | TypeKind::Array { .. })
        )
    }

    /// Given the address and type of a resolved member, either read it (scalar)
    /// or keep it as an address (aggregate) so member access can chain.
    fn member_value(addr: u64, field_ty: TypeId, ctx: &EvalContext<'_>) -> Result<TypedValue, EvalError> {
        if Self::is_aggregate(field_ty, ctx) {
            return Ok(TypedValue::address(addr, field_ty));
        }
        // Bitfield: read the storage unit, then extract `length` bits at `position`.
        if let Some(TypeKind::Bitfield { base, position, length }) = ctx.types.get(field_ty) {
            let (base, position, length) = (*base, *position, *length);
            let nbytes = ctx.types.size_of(base).unwrap_or(4);
            let raw = Self::read_sized(ctx.memory, addr, Size::from_bytes(nbytes).unwrap_or(Size::B4))?;
            let mask = if length >= 64 { u64::MAX } else { (1u64 << length) - 1 };
            return Ok(TypedValue::int((raw >> position) & mask, base));
        }
        let nbytes = ctx.types.size_of(field_ty).unwrap_or(8);
        let sz = Size::from_bytes(nbytes).unwrap_or(Size::B8);
        let raw = Self::read_sized(ctx.memory, addr, sz)?;
        Ok(Self::scalar_value(raw, field_ty, nbytes, ctx))
    }

    /// Compute the ADDRESS (and type) of an lvalue expression without reading
    /// its value — backs `&expr`. Returns `(addr, type_id)`. Errors for
    /// non-addressable operands (literals, registers, arithmetic).
    fn eval_address(ast: &ExprAst, ctx: &EvalContext<'_>) -> Result<(u64, TypeId), EvalError> {
        match ast {
            // *p → the address is p itself.
            ExprAst::Deref(inner, _) => {
                let p = Self::eval(inner, ctx)?;
                Ok((p.value, ctx.types.pointee(p.type_id).unwrap_or_else(|| ctx.types.primitive_u64())))
            }
            // ptr->field → ptr.value + offset(field)
            ExprAst::Arrow(ptr_expr, field) => {
                let ptr = Self::eval(ptr_expr, ctx)?;
                let struct_ty = ctx.types.pointee(ptr.type_id).ok_or_else(|| EvalError::TypeMismatch {
                    expected: "pointer".into(), got: format!("{:?}", ptr.type_id) })?;
                let sf = ctx.types.struct_field(struct_ty, field).ok_or_else(|| EvalError::UnknownField {
                    type_name: format!("{struct_ty:?}"), field: field.clone() })?;
                Ok((ptr.value.wrapping_add(sf.offset), sf.ty))
            }
            // base.field → address(base) + offset(field)
            ExprAst::Field(base_expr, field) => {
                let (base_addr, base_ty) = Self::eval_address(base_expr, ctx)?;
                let sf = ctx.types.struct_field(base_ty, field).ok_or_else(|| EvalError::UnknownField {
                    type_name: format!("{base_ty:?}"), field: field.clone() })?;
                Ok((base_addr.wrapping_add(sf.offset), sf.ty))
            }
            // arr[i] → arr + i*sizeof(elem)
            ExprAst::Index(arr_expr, idx_expr) => {
                let arr = Self::eval(arr_expr, ctx)?;
                let idx = Self::eval(idx_expr, ctx)?;
                let elem_ty = Self::element_type(arr.type_id, ctx);
                let elem_size = ctx.types.size_of(elem_ty).unwrap_or(8);
                Ok((arr.value.wrapping_add(idx.value.wrapping_mul(elem_size)), elem_ty))
            }
            // A symbol names a storage location.
            ExprAst::Sym(name) => ctx.symbols.lookup_symbol(name)
                .map(|a| (a, ctx.types.primitive_u64()))
                .ok_or_else(|| EvalError::UndefinedSymbol(name.clone())),
            _ => Err(EvalError::Other("cannot take the address of this expression".into())),
        }
    }

    fn eval_field(base: &TypedValue, field_name: &str, ctx: &EvalContext<'_>) -> Result<TypedValue, EvalError> {
        let ty = base.type_id;
        let sf = ctx.types.struct_field(ty, field_name).ok_or_else(|| EvalError::UnknownField {
            type_name: format!("{ty:?}"),
            field: field_name.to_owned(),
        })?;
        let addr = base.value.wrapping_add(sf.offset);
        Self::member_value(addr, sf.ty, ctx)
    }

    fn eval_arrow(ptr: &TypedValue, field_name: &str, ctx: &EvalContext<'_>) -> Result<TypedValue, EvalError> {
        let struct_ty = ctx.types.pointee(ptr.type_id).ok_or_else(|| EvalError::TypeMismatch {
            expected: "pointer".into(),
            got: format!("{:?}", ptr.type_id),
        })?;
        let sf = ctx.types.struct_field(struct_ty, field_name).ok_or_else(|| EvalError::UnknownField {
            type_name: format!("{struct_ty:?}"),
            field: field_name.to_owned(),
        })?;
        let addr = ptr.value.wrapping_add(sf.offset);
        Self::member_value(addr, sf.ty, ctx)
    }

    /// # Errors
    /// Returns an [`EvalError`] if evaluation fails.
    pub fn eval(ast: &ExprAst, ctx: &EvalContext<'_>) -> Result<TypedValue, EvalError> {
        match ast {
            ExprAst::Lit(v) =>
                Ok(TypedValue::int(*v, ctx.types.primitive_u64())),
            ExprAst::FloatLit(v) =>
                Ok(TypedValue::float_f64(*v, ctx.types.primitive_f64())),
            ExprAst::StringLit(_s) =>
                Ok(TypedValue::address(0, ctx.types.primitive_char_ptr())),
            ExprAst::Reg(name) => {
                let v = ctx.registers.read_register(name)
                    .ok_or_else(|| EvalError::UndefinedRegister(name.clone()))?;
                Ok(TypedValue::int(v, ctx.types.primitive_u64()))
            }
            ExprAst::Sym(name) => {
                ctx.symbols.lookup_symbol(name).map_or_else(
                    || Err(EvalError::UndefinedSymbol(name.clone())),
                    |addr| Ok(TypedValue::address(addr, ctx.types.primitive_u64())),
                )
            }
            ExprAst::Deref(inner, size) => Self::eval_deref(&Self::eval(inner, ctx)?, *size, ctx),
            ExprAst::Field(base_expr, field_name) =>
                Self::eval_field(&Self::eval(base_expr, ctx)?, field_name, ctx),
            ExprAst::Arrow(ptr_expr, field_name) =>
                Self::eval_arrow(&Self::eval(ptr_expr, ctx)?, field_name, ctx),
            ExprAst::Index(arr_expr, idx_expr) => {
                let arr = Self::eval(arr_expr, ctx)?;
                let idx = Self::eval(idx_expr, ctx)?;
                let elem_ty = Self::element_type(arr.type_id, ctx);
                let elem_size = ctx.types.size_of(elem_ty).unwrap_or(8);
                let addr = arr.value.wrapping_add(idx.value.wrapping_mul(elem_size));
                // An array-of-aggregate element yields the element's address so
                // `arr[i].field` chains; a scalar element is read.
                if Self::is_aggregate(elem_ty, ctx) {
                    return Ok(TypedValue::address(addr, elem_ty));
                }
                let raw = Self::read_sized(ctx.memory, addr, Size::from_bytes(elem_size).unwrap_or(Size::B8))?;
                Ok(Self::scalar_value(raw, elem_ty, elem_size, ctx))
            }
            ExprAst::Cast(cast_ty, inner) => {
                let val = Self::eval(inner, ctx)?;
                // Strip `const` qualifiers — they don't change the value.
                let mut ty = cast_ty;
                while let CastType::Const(t) = ty { ty = t; }
                match ty {
                    // Pointer cast, e.g. `(u64*)ptr` / `(int*)0x1000`: the result
                    // is an address. Named pointer types can't be constructed
                    // with an immutable TypeSystem, so mark it an address of the
                    // generic u64 pointee (a subsequent `*` reads pointer width).
                    // This makes `*(T*)ptr` evaluate instead of erroring on an
                    // "unknown type 'T*'" lookup.
                    CastType::Pointer(_) => {
                        // If the full pointer type name is registered (e.g. a
                        // struct pointer "Foo*" from define_struct), use it so
                        // `->field` resolves; otherwise a generic u64-pointee
                        // address (still never errors).
                        let ptr_id = ctx.types.lookup_name(&ty.as_str())
                            .unwrap_or_else(|| ctx.types.primitive_u64());
                        Ok(TypedValue::address(val.value, ptr_id))
                    }
                    CastType::Named(name) => {
                        let target_id = ctx.types.lookup_name(name)
                            .ok_or_else(|| EvalError::UnknownType(name.clone()))?;
                        Ok(TypedValue::int(Self::apply_cast(val.value, val.type_id, target_id, ctx), target_id))
                    }
                    CastType::Const(_) => unreachable!("const stripped above"),
                }
            }
            ExprAst::BinOp(op, lhs, rhs) => {
                let l = Self::eval(lhs, ctx)?;
                let r = Self::eval(rhs, ctx)?;
                let result = Self::apply_binop(*op, &l, &r, ctx)?;
                let bool_ty = ctx.types.primitive_bool();
                let ty = match op {
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt |
                    BinOp::Le | BinOp::Ge | BinOp::And | BinOp::Or => bool_ty,
                    _ => l.type_id,
                };
                Ok(TypedValue::int(result, ty))
            }
            ExprAst::UnOp(UnOp::AddrOf, inner) => {
                // Address-of computes the operand's storage address WITHOUT
                // reading it (so `&x->y` is the field's address, not its value).
                let (addr, _ty) = Self::eval_address(inner, ctx)?;
                Ok(TypedValue::address(addr, ctx.types.primitive_u64()))
            }
            ExprAst::UnOp(op, inner) => {
                let val = Self::eval(inner, ctx)?;
                let result = match op {
                    UnOp::Neg    => (-(val.value.cast_signed())).cast_unsigned(),
                    UnOp::Not    => u64::from(val.value == 0),
                    UnOp::BitNot => !val.value,
                    UnOp::AddrOf => val.value, // unreachable — handled above
                };
                let ty = if *op == UnOp::Not { ctx.types.primitive_bool() } else { val.type_id };
                Ok(TypedValue::int(result, ty))
            }
            ExprAst::Call(name, args) => Self::eval_call(name, args, ctx),
            ExprAst::Ternary(cond, then, else_) => {
                if Self::eval(cond, ctx)?.as_bool() { Self::eval(then, ctx) } else { Self::eval(else_, ctx) }
            }
        }
    }

    fn read_sized(mem: &dyn MemoryProvider, addr: u64, size: Size) -> Result<u64, EvalError> {
        match size {
            Size::B1  => mem.read_u8(addr).map(u64::from),
            Size::B2  => mem.read_u16(addr).map(u64::from),
            Size::B4  => mem.read_u32(addr).map(u64::from),
            Size::B8 | Size::B16 => mem.read_u64(addr),
        }.map_err(|e| EvalError::MemoryReadError { addr, reason: e.to_string() })
    }

    fn apply_cast(
        val:       u64,
        _from:     TypeId,
        to:        TypeId,
        ctx:       &EvalContext<'_>,
    ) -> u64 {
        match ctx.types.get(to) {
            Some(TypeKind::Int { signed, size }) => {
                let mask = match size {
                    Size::B1  => 0xFF,
                    Size::B2  => 0xFFFF,
                    Size::B4  => 0xFFFF_FFFF,
                    Size::B8 | Size::B16 => u64::MAX,
                };
                let truncated = val & mask;
                if *signed {
                    // sign-extend
                    let bits = size.bits().min(64);
                    let sign_bit = 1u64 << (bits - 1);
                    if truncated & sign_bit != 0 {
                        return truncated | !mask;
                    }
                }
                truncated
            }
            Some(TypeKind::Float { size: Size::B4 }) => {
                let f = f32::from_bits(u32::try_from(val & 0xFFFF_FFFF).unwrap_or(u32::MAX));
                u64::from(f.to_bits())
            }
            Some(TypeKind::Float { .. }) => f64::from_bits(val).to_bits(),
            Some(TypeKind::Bool) => u64::from(val != 0),
            _ => val,
        }
    }

    fn apply_binop(
        op:  BinOp,
        l:   &TypedValue,
        r:   &TypedValue,
        ctx: &EvalContext<'_>,
    ) -> Result<u64, EvalError> {
        let lv = l.value.cast_signed();
        let rv = r.value.cast_signed();
        let lu = l.value;
        let ru = r.value;
        // Check if either operand is a pointer for pointer arithmetic
        let l_is_ptr = matches!(ctx.types.get(l.type_id), Some(TypeKind::Ptr { .. }));
        let r_is_ptr = matches!(ctx.types.get(r.type_id), Some(TypeKind::Ptr { .. }));
        // `.filter(|&s| s != 0)` matters: `size_of` maps `TypeKind::Void` to
        // `Some(0)`, and zero-sized structs are representable too, so a bare
        // `unwrap_or(1)` (which only covers `None`) left `ptr_stride == 0`
        // and made the pointer-difference divide below panic on the entirely
        // ordinary expression `(void*)a - (void*)b`. A zero-sized pointee has
        // no meaningful element count, so fall back to a byte difference.
        let ptr_stride: u64 = if l_is_ptr {
            ctx.types.pointee(l.type_id)
                .and_then(|id| ctx.types.size_of(id))
                .filter(|&s| s != 0)
                .unwrap_or(1)
        } else { 1 };
        let result = match op {
            BinOp::Add    => if l_is_ptr { lu.wrapping_add(ru.wrapping_mul(ptr_stride)) } else { lu.wrapping_add(ru) },
            BinOp::Sub    => if l_is_ptr && !r_is_ptr { lu.wrapping_sub(ru.wrapping_mul(ptr_stride)) }
                             else if l_is_ptr && r_is_ptr { lu.wrapping_sub(ru) / ptr_stride }
                             else { lu.wrapping_sub(ru) },
            BinOp::Mul    => lv.wrapping_mul(rv).cast_unsigned(),
            // `checked_div`/`checked_rem` cover BOTH failure modes: the
            // divisor being zero, and `i64::MIN / -1` overflowing — the
            // latter panics in release too, and the old `rv == 0` guard did
            // not catch it.
            BinOp::Div    => {
                if rv == 0 { return Err(EvalError::DivisionByZero); }
                lv.checked_div(rv).ok_or(EvalError::DivisionOverflow)?.cast_unsigned()
            }
            BinOp::Rem    => {
                if rv == 0 { return Err(EvalError::DivisionByZero); }
                lv.checked_rem(rv).ok_or(EvalError::DivisionOverflow)?.cast_unsigned()
            }
            // One answer per question: both evaluators in this crate share
            // `crate::shift_left_64`/`shift_right_64`, which do NOT mask the
            // count. Masking made `x >> 64` return `x` — the original value,
            // presented as a computed one.
            BinOp::Shl    => crate::shift_left_64(lu, ru),
            BinOp::Shr    => crate::shift_right_64(lu, ru),
            BinOp::BitAnd => lu & ru,
            BinOp::BitOr  => lu | ru,
            BinOp::BitXor => lu ^ ru,
            BinOp::Eq     => u64::from(lu == ru),
            BinOp::Ne     => u64::from(lu != ru),
            BinOp::Lt     => u64::from(lv <  rv),
            BinOp::Gt     => u64::from(lv >  rv),
            BinOp::Le     => u64::from(lv <= rv),
            BinOp::Ge     => u64::from(lv >= rv),
            BinOp::And    => u64::from(lu != 0 && ru != 0),
            BinOp::Or     => u64::from(lu != 0 || ru != 0),
        };
        Ok(result)
    }

    fn eval_call(
        name: &str,
        args: &[ExprAst],
        ctx:  &EvalContext<'_>,
    ) -> Result<TypedValue, EvalError> {
        match name {
            "sizeof" => {
                if args.len() != 1 {
                    return Err(EvalError::UnsupportedOperation("sizeof requires 1 argument".into()));
                }
                let sz = match &args[0] {
                    ExprAst::Sym(type_name) => {
                        let ty_id = ctx.types.lookup_name(type_name)
                            .ok_or_else(|| EvalError::UnknownType(type_name.clone()))?;
                        ctx.types.size_of(ty_id).unwrap_or(0)
                    }
                    other => {
                        let val = Self::eval(other, ctx)?;
                        ctx.types.size_of(val.type_id).unwrap_or(8)
                    }
                };
                Ok(TypedValue::int(sz, ctx.types.primitive_u64()))
            }
            "offsetof" => {
                if args.len() != 2 {
                    return Err(EvalError::UnsupportedOperation("offsetof requires 2 arguments".into()));
                }
                let (type_name, field_name) = match (&args[0], &args[1]) {
                    (ExprAst::Sym(t), ExprAst::Sym(f)) => (t.clone(), f.clone()),
                    _ => return Err(EvalError::UnsupportedOperation("offsetof args must be names".into())),
                };
                let ty_id = ctx.types.lookup_name(&type_name)
                    .ok_or_else(|| EvalError::UnknownType(type_name.clone()))?;
                let sf = ctx.types.struct_field(ty_id, &field_name)
                    .ok_or(EvalError::UnknownField { type_name, field: field_name })?;
                Ok(TypedValue::int(sf.offset, ctx.types.primitive_u64()))
            }
            _ => Err(EvalError::UnsupportedOperation(format!("function {name} not available"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Pretty printer
// ---------------------------------------------------------------------------

/// Format a `TypedValue` for display, taking type into account.
#[must_use]
pub fn pretty_print(val: &TypedValue, ctx: &EvalContext<'_>) -> String {
    match ctx.types.get(val.type_id) {
        Some(TypeKind::Ptr { pointee }) => {
            // Try to display as string if char*
            let is_char_ptr = matches!(ctx.types.get(*pointee), Some(TypeKind::Int { size: Size::B1, .. }));
            if is_char_ptr && val.value != 0 && let Ok(s) = ctx.memory.read_cstring(val.value, 256) {
                return format!("0x{:x} \"{s}\"", val.value);
            }
            format!("0x{:016x}", val.value)
        }
        Some(TypeKind::Int { signed: true, size }) => {
            let mask = match size {
                Size::B1 => 0xFFu64, Size::B2 => 0xFFFFu64,
                Size::B4 => 0xFFFF_FFFFu64, _ => u64::MAX,
            };
            let sign_bit = 1u64 << (size.bits().min(64) - 1);
            let v = val.value & mask;
            if v & sign_bit != 0 {
                let sv = (v | !mask).cast_signed();
                format!("{sv} (0x{v:x})")
            } else {
                format!("{v} (0x{v:x})")
            }
        }
        Some(TypeKind::Int { signed: false, .. }) =>
            format!("{} (0x{:x})", val.value, val.value),
        Some(TypeKind::Float { size: Size::B4 }) => {
            let f = f32::from_bits(u32::try_from(val.value).unwrap_or(u32::MAX));
            format!("{f}")
        }
        Some(TypeKind::Float { .. }) => {
            let f = f64::from_bits(val.value);
            format!("{f}")
        }
        Some(TypeKind::Bool) =>
            if val.value != 0 { "true".into() } else { "false".into() },
        _ => format!("0x{:x}", val.value),
    }
}

// ---------------------------------------------------------------------------
// Watch expressions
// ---------------------------------------------------------------------------

const MAX_WATCHES: usize = 256;

/// A single watch expression with its last evaluated value.
#[derive(Debug, Clone)]
pub struct Watch {
    pub id:         u32,
    pub expression: String,
    pub ast:        ExprAst,
    pub last_value: Option<TypedValue>,
    pub enabled:    bool,
    pub hit_count:  u64,
}

/// Change event emitted when a watch expression value changes.
#[derive(Debug, Clone)]
pub struct WatchChange {
    pub watch_id:  u32,
    pub expr:      String,
    pub old_value: Option<TypedValue>,
    pub new_value: TypedValue,
}

/// Registry of watch expressions.
pub struct WatchRegistry {
    watches: Vec<Watch>,
    next_id: u32,
}

impl Default for WatchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self { watches: Vec::new(), next_id: 1 }
    }

    /// # Errors
    /// Returns [`EvalError::WatchLimit`] if the watch limit is reached, or a parse error.
    pub fn register(&mut self, expression: &str) -> Result<u32, EvalError> {
        if self.watches.len() >= MAX_WATCHES {
            return Err(EvalError::WatchLimit);
        }
        let ast = parse_expression(expression)?;
        let id = self.next_id;
        self.next_id += 1;
        self.watches.push(Watch {
            id,
            expression: expression.to_string(),
            ast,
            last_value: None,
            enabled:    true,
            hit_count:  0,
        });
        Ok(id)
    }

    pub fn remove(&mut self, id: u32) -> bool {
        if let Some(pos) = self.watches.iter().position(|w| w.id == id) {
            self.watches.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn enable(&mut self, id: u32, enabled: bool) {
        if let Some(w) = self.watches.iter_mut().find(|w| w.id == id) {
            w.enabled = enabled;
        }
    }

    /// Re-evaluate all watches. Returns list of changed watches.
    pub fn evaluate_all(&mut self, ctx: &EvalContext<'_>) -> Vec<WatchChange> {
        let mut changes = Vec::new();
        for watch in &mut self.watches {
            if !watch.enabled { continue; }
            if let Ok(evaluated) = ExprEvaluator::eval(&watch.ast, ctx) {
                let value_changed = watch.last_value.as_ref()
                    .is_none_or(|prev| prev.value != evaluated.value);
                if value_changed {
                    changes.push(WatchChange {
                        watch_id:  watch.id,
                        expr:      watch.expression.clone(),
                        old_value: watch.last_value.clone(),
                        new_value: evaluated.clone(),
                    });
                    watch.hit_count += 1;
                    watch.last_value = Some(evaluated);
                }
            }
        }
        changes
    }

    #[must_use]
    pub fn watches(&self) -> &[Watch] { &self.watches }

    #[must_use]
    pub fn get(&self, id: u32) -> Option<&Watch> {
        self.watches.iter().find(|w| w.id == id)
    }
}

// ---------------------------------------------------------------------------
// High-level ExprEvaluator with state (convenience wrapper)
// ---------------------------------------------------------------------------

/// Stateful expression evaluator that holds references to debug context.
/// Typical usage: create once per debug stop and evaluate multiple expressions.
pub struct DebugExprEvaluator<'a> {
    ctx:     EvalContext<'a>,
    watches: &'a mut WatchRegistry,
}

impl<'a> DebugExprEvaluator<'a> {
    #[must_use]
    pub fn new(
        registers: &'a dyn RegisterState,
        memory:    &'a dyn MemoryProvider,
        symbols:   &'a dyn SymbolTable,
        types:     &'a TypeSystem,
        watches:   &'a mut WatchRegistry,
    ) -> Self {
        Self {
            ctx: EvalContext::new(registers, memory, symbols, types),
            watches,
        }
    }

    /// # Errors
    /// Returns an [`EvalError`] if parsing or evaluation fails.
    pub fn eval_str(&self, expr: &str) -> Result<TypedValue, EvalError> {
        let ast = parse_expression(expr)?;
        ExprEvaluator::eval(&ast, &self.ctx)
    }

    /// # Errors
    /// Returns an [`EvalError`] if parsing or evaluation fails.
    pub fn eval_str_pretty(&self, expr: &str) -> Result<String, EvalError> {
        let val = self.eval_str(expr)?;
        Ok(pretty_print(&val, &self.ctx))
    }

    /// # Errors
    /// Returns an [`EvalError`] if evaluation fails.
    pub fn eval_ast(&self, ast: &ExprAst) -> Result<TypedValue, EvalError> {
        ExprEvaluator::eval(ast, &self.ctx)
    }

    pub fn poll_watches(&mut self) -> Vec<WatchChange> {
        self.watches.evaluate_all(&self.ctx)
    }
}

// ---------------------------------------------------------------------------
// Error module stub (imported at top)
// ---------------------------------------------------------------------------

pub mod error {
    use std::fmt;

    #[derive(Debug, Clone)]
    pub struct DebugError(pub String);
    impl fmt::Display for DebugError { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) } }
    impl std::error::Error for DebugError {}

    pub type DebugResult<T> = Result<T, DebugError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRegs(HashMap<String, u64>);
    impl RegisterState for FakeRegs {
        fn read_register(&self, name: &str) -> Option<u64> { self.0.get(name).copied() }
        fn all_registers(&self) -> Vec<(String, u64)> { self.0.iter().map(|(k,v)| (k.clone(), *v)).collect() }
    }

    struct FakeMem(Vec<u8>);
    impl MemoryProvider for FakeMem {
        fn read_bytes(&self, addr: u64, len: usize) -> DebugResult<Vec<u8>> {
            let start = usize::try_from(addr).unwrap_or(usize::MAX);
            Ok(self.0.get(start..start+len).unwrap_or(&[]).to_vec())
        }
    }

    struct FakeSym(HashMap<String, u64>);
    impl SymbolTable for FakeSym {
        fn lookup_symbol(&self, name: &str) -> Option<u64> { self.0.get(name).copied() }
        fn reverse_lookup(&self, _addr: u64) -> Option<String> { None }
    }

    fn make_ctx<'a>(
        regs: &'a FakeRegs,
        mem:  &'a FakeMem,
        sym:  &'a FakeSym,
        ts:   &'a TypeSystem,
    ) -> EvalContext<'a> {
        EvalContext::new(regs, mem, sym, ts)
    }

    #[test]
    fn test_integer_literals() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("42").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 42);

        let v = ExprEvaluator::eval(&parse_expression("0xFF").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 255);

        let v = ExprEvaluator::eval(&parse_expression("0b1010").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 10);
    }

    #[test]
    fn pointer_cast_deref_evaluates() {
        // `*(u64*)addr` and `*(int*)addr` must EVALUATE (not error on an unknown
        // "u64*" type) — the audit's `*(int*)0x1000` shape. Pointer casts resolve
        // to an address; the deref reads pointer width from that address.
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        // 8 bytes at offset 0 = 0x0102030405060708 (little-endian).
        let mem  = FakeMem(vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("*(u64*)0").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0x0102_0304_0506_0708);
        // The cast element type now sizes the read width:
        assert_eq!(ExprEvaluator::eval(&parse_expression("*(u8*)0").unwrap(), &ctx).unwrap().value, 0x08);
        assert_eq!(ExprEvaluator::eval(&parse_expression("*(char*)0").unwrap(), &ctx).unwrap().value, 0x08);
        assert_eq!(ExprEvaluator::eval(&parse_expression("*(u16*)0").unwrap(), &ctx).unwrap().value, 0x0708);
        assert_eq!(ExprEvaluator::eval(&parse_expression("*(int*)0").unwrap(), &ctx).unwrap().value, 0x0506_0708);
        // const-qualified pointer cast also works (and sizes by element).
        let v = ExprEvaluator::eval(&parse_expression("*(const int*)0").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0x0506_0708);
        // A plain value cast still works and is unaffected.
        let v = ExprEvaluator::eval(&parse_expression("(int)258").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 258);
    }

    #[test]
    fn float_deref_reads_float_value() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        // f64 1.5 = 0x3FF8000000000000 (LE) at 0; f32 2.5 = 0x40200000 (LE) at 8.
        let mut bytes = 1.5f64.to_bits().to_le_bytes().to_vec();
        bytes.extend_from_slice(&2.5f32.to_bits().to_le_bytes());
        let mem  = FakeMem(bytes);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let d = ExprEvaluator::eval(&parse_expression("*(f64*)0").unwrap(), &ctx).unwrap();
        assert_eq!(d.as_f64(), Some(1.5), "*(f64*)0 reads 1.5");
        let f = ExprEvaluator::eval(&parse_expression("*(f32*)8").unwrap(), &ctx).unwrap();
        assert_eq!(f.as_f32(), Some(2.5), "*(f32*)8 reads 2.5 (f32 value)");
    }

    #[test]
    fn bitfield_member_extraction() {
        // struct F { u32 storage; flags:3 @bit0; mid:4 @bit3; } over a u32 = 0xAB.
        let mut ts = TypeSystem::with_primitives();
        let u32_id = ts.lookup_name("u32").unwrap();
        let flags = ts.bitfield_of(u32_id, 0, 3);
        let mid = ts.bitfield_of(u32_id, 3, 4);
        ts.define_struct("F", vec![
            StructField { name: "flags".into(), ty: flags, offset: 0 },
            StructField { name: "mid".into(),   ty: mid,   offset: 0 },
        ]);
        let regs = FakeRegs(HashMap::new());
        let mem = FakeMem(vec![0xAB, 0, 0, 0]); // 0b1010_1011
        let sym = FakeSym(HashMap::new());
        let ctx = make_ctx(&regs, &mem, &sym, &ts);

        // bits[0..3] = 0b011 = 3; bits[3..7] = 0b0101 = 5.
        assert_eq!(ExprEvaluator::eval(&parse_expression("((F*)0)->flags").unwrap(), &ctx).unwrap().value, 3);
        assert_eq!(ExprEvaluator::eval(&parse_expression("((F*)0)->mid").unwrap(), &ctx).unwrap().value, 5);
    }

    #[test]
    fn array_field_indexing() {
        // struct S { u32 a[3]; } — `((S*)0)->a[2]` reads the 3rd u32.
        let mut ts = TypeSystem::with_primitives();
        let u32_id = ts.lookup_name("u32").unwrap();
        let arr = ts.array_of(u32_id, 3);
        ts.define_struct("S", vec![StructField { name: "a".into(), ty: arr, offset: 0 }]);
        let regs = FakeRegs(HashMap::new());
        // a[0]=1, a[1]=2, a[2]=3 (LE u32s).
        let mem = FakeMem(vec![1,0,0,0, 2,0,0,0, 3,0,0,0]);
        let sym = FakeSym(HashMap::new());
        let ctx = make_ctx(&regs, &mem, &sym, &ts);

        // `->a` is the array (an aggregate address); `[i]` steps u32 (4 bytes).
        assert_eq!(ExprEvaluator::eval(&parse_expression("((S*)0)->a[0]").unwrap(), &ctx).unwrap().value, 1);
        assert_eq!(ExprEvaluator::eval(&parse_expression("((S*)0)->a[2]").unwrap(), &ctx).unwrap().value, 3);
        // &a[2] is base + 2*4 = 8.
        assert_eq!(ExprEvaluator::eval(&parse_expression("&((S*)0)->a[2]").unwrap(), &ctx).unwrap().value, 8);
    }

    #[test]
    fn signed_deref_sign_extends() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        // 0xFF at 0, 0xFFFF at 2..4, 0x7F at 4.
        let mem  = FakeMem(vec![0xFF, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        // Signed byte 0xFF → -1 (as_i64), value bits all set.
        let v = ExprEvaluator::eval(&parse_expression("*(i8*)0").unwrap(), &ctx).unwrap();
        assert_eq!(v.as_i64(), -1, "*(i8*)0 of 0xFF is -1");
        // Unsigned byte 0xFF → 255 (no sign extension).
        let v = ExprEvaluator::eval(&parse_expression("*(u8*)0").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0xFF, "*(u8*)0 stays 255");
        // Signed i16 0xFFFF at offset 2 → -1.
        let v = ExprEvaluator::eval(&parse_expression("*(i16*)2").unwrap(), &ctx).unwrap();
        assert_eq!(v.as_i64(), -1, "*(i16*)2 of 0xFFFF is -1");
        // Positive signed byte 0x7F stays 127.
        let v = ExprEvaluator::eval(&parse_expression("*(i8*)4").unwrap(), &ctx).unwrap();
        assert_eq!(v.as_i64(), 127, "*(i8*)4 of 0x7F is 127");
    }

    #[test]
    fn array_index_uses_cast_element_width() {
        // 8 bytes = two u32 elements: [0x04030201, 0x08070605].
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        // `(u32*)0` now resolves to a real u32 pointer, so [1] steps 4 bytes.
        assert_eq!(ExprEvaluator::eval(&parse_expression("((u32*)0)[0]").unwrap(), &ctx).unwrap().value, 0x0403_0201);
        assert_eq!(ExprEvaluator::eval(&parse_expression("((u32*)0)[1]").unwrap(), &ctx).unwrap().value, 0x0807_0605);
        // u8 elements step 1 byte.
        assert_eq!(ExprEvaluator::eval(&parse_expression("((u8*)0)[4]").unwrap(), &ctx).unwrap().value, 0x05);
    }

    #[test]
    fn struct_pointer_field_access() {
        let mut ts = TypeSystem::with_primitives();
        let u32_id = ts.lookup_name("u32").unwrap();
        ts.define_struct("Point", vec![
            StructField { name: "x".into(), ty: u32_id, offset: 0 },
            StructField { name: "y".into(), ty: u32_id, offset: 4 },
        ]);
        let regs = FakeRegs(HashMap::new());
        // x=0x11111111 @0, y=0x22222222 @4 (little-endian).
        let mem = FakeMem(vec![
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        ]);
        let sym = FakeSym(HashMap::new());
        let ctx = make_ctx(&regs, &mem, &sym, &ts);

        let y = ExprEvaluator::eval(&parse_expression("((Point*)0)->y").unwrap(), &ctx).unwrap();
        assert_eq!(y.value, 0x2222_2222, "->y reads u32 at offset 4");
        let x = ExprEvaluator::eval(&parse_expression("((Point*)0)->x").unwrap(), &ctx).unwrap();
        assert_eq!(x.value, 0x1111_1111, "->x reads u32 at offset 0");
    }

    #[test]
    fn nested_struct_field_access() {
        // struct Inner { u32 v; }  struct Outer { Inner in; u32 tag; }
        let mut ts = TypeSystem::with_primitives();
        let u32_id = ts.lookup_name("u32").unwrap();
        let inner = ts.define_struct("Inner", vec![
            StructField { name: "v".into(), ty: u32_id, offset: 0 },
        ]);
        ts.define_struct("Outer", vec![
            StructField { name: "in".into(), ty: inner, offset: 0 },
            StructField { name: "tag".into(), ty: u32_id, offset: 4 },
        ]);
        let regs = FakeRegs(HashMap::new());
        // in.v = 0x0000002A @0, tag = 0x00000063 @4.
        let mem = FakeMem(vec![0x2A, 0, 0, 0, 0x63, 0, 0, 0]);
        let sym = FakeSym(HashMap::new());
        let ctx = make_ctx(&regs, &mem, &sym, &ts);

        // The struct-typed member `->in` yields an address; `.v` then reads it.
        let v = ExprEvaluator::eval(&parse_expression("((Outer*)0)->in.v").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0x2A, "->in.v reads nested u32");
        let tag = ExprEvaluator::eval(&parse_expression("((Outer*)0)->tag").unwrap(), &ctx).unwrap();
        assert_eq!(tag.value, 0x63, "->tag reads the scalar field");

        // Address-of a member yields its ADDRESS, not its value.
        let addr = ExprEvaluator::eval(&parse_expression("&((Outer*)0)->tag").unwrap(), &ctx).unwrap();
        assert_eq!(addr.value, 4, "&->tag is base(0) + offset(4)");
        assert!(addr.is_address, "address-of yields an address value");
        let inner_addr = ExprEvaluator::eval(&parse_expression("&((Outer*)0)->in.v").unwrap(), &ctx).unwrap();
        assert_eq!(inner_addr.value, 0, "&->in.v is offset 0");

        // Explicit struct deref yields the struct lvalue, so `(*sp).field` chains.
        let via_deref = ExprEvaluator::eval(&parse_expression("(*(Outer*)0).tag").unwrap(), &ctx).unwrap();
        assert_eq!(via_deref.value, 0x63, "(*sp).tag reads the scalar field via explicit deref");
    }

    #[test]
    fn test_register_read() {
        let ts   = TypeSystem::with_primitives();
        let mut r = HashMap::new(); r.insert("rax".into(), 0xDEAD_BEEF);
        let regs = FakeRegs(r);
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("$rax").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0xDEAD_BEEF);
    }

    #[test]
    fn test_arithmetic() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("3 + 4 * 2").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 11);

        let v = ExprEvaluator::eval(&parse_expression("(3 + 4) * 2").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 14);
    }

    #[test]
    fn test_ternary() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("1 ? 10 : 20").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 10);
        let v = ExprEvaluator::eval(&parse_expression("0 ? 10 : 20").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 20);
    }

    #[test]
    fn test_sizeof() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("sizeof(int)").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 4);
        let v = ExprEvaluator::eval(&parse_expression("sizeof(u64)").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 8);
    }

    #[test]
    fn test_watch_registry() {
        let ts   = TypeSystem::with_primitives();
        let mut r = HashMap::new(); r.insert("rax".into(), 0u64);
        let regs = FakeRegs(r);
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);
        let mut wr = WatchRegistry::new();
        let id = wr.register("$rax").unwrap();
        let changes = wr.evaluate_all(&ctx);
        // First eval always produces a change (None -> Some)
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].watch_id, id);
        // Second eval with same value: no change
        let changes2 = wr.evaluate_all(&ctx);
        assert_eq!(changes2.len(), 0);
    }

    #[test]
    fn test_division_by_zero() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let result = ExprEvaluator::eval(&parse_expression("5 / 0").unwrap(), &ctx);
        assert!(matches!(result, Err(EvalError::DivisionByZero)));
    }

    /// `i64::MIN / -1` overflows the signed result (the quotient is
    /// `i64::MAX + 1`), which panics in Rust in RELEASE as well as debug —
    /// the `rv == 0` guard above does not cover it. Reachable straight from
    /// an untrusted `debug.evaluate` expression string, so an unguarded
    /// panic here takes the whole debug server down rather than returning
    /// an error to the caller.
    #[test]
    fn signed_division_overflow_is_an_error_not_a_panic() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        // 0x8000000000000000 is i64::MIN reinterpreted; `- 1` is the divisor.
        let result = ExprEvaluator::eval(
            &parse_expression("0x8000000000000000 / -1").unwrap(), &ctx);
        assert!(matches!(result, Err(EvalError::DivisionOverflow)), "got {result:?}");

        // `%` has the identical overflow case.
        let result = ExprEvaluator::eval(
            &parse_expression("0x8000000000000000 % -1").unwrap(), &ctx);
        assert!(matches!(result, Err(EvalError::DivisionOverflow)), "got {result:?}");
    }

    /// Pointer-minus-pointer divides by the pointee's stride. `size_of` maps
    /// `TypeKind::Void` to `Some(0)`, and the `unwrap_or(1)` fallback only
    /// covers `None` — so `void* - void*` divided by zero and panicked.
    /// `(void*)` is an entirely ordinary cast, not a crafted edge case.
    #[test]
    fn void_pointer_difference_does_not_divide_by_zero() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(
            &parse_expression("(void*)16 - (void*)8").unwrap(), &ctx).unwrap();
        // A zero-sized pointee has no meaningful element count; falling back
        // to a byte difference (stride 1) is the useful answer.
        assert_eq!(v.value, 8);
    }

    #[test]
    fn test_lexer_complete() {
        let mut lexer = Lexer::new("$rsp + 0x10");
        let tokens = lexer.tokenize().unwrap();
        assert!(tokens.contains(&Token::Register("rsp".into())));
        assert!(tokens.contains(&Token::Plus));
        assert!(tokens.contains(&Token::IntLit(0x10)));
    }

    /// A decimal literal that does not fit must be rejected, exactly as the
    /// hex and binary forms already are.
    ///
    /// `0x…` and `0b…` map a parse failure to `LexError::Overflow`, but the
    /// decimal path used `parse::<u64>().unwrap_or(0)`. So `$rax == 2^64`
    /// silently became `$rax == 0` — a conditional breakpoint that does not
    /// fail, does not warn, and stops on a condition the user never wrote.
    /// Wrong-and-quiet is the worst outcome for a breakpoint condition:
    /// an error is visible, a zero is not.
    #[test]
    fn an_out_of_range_decimal_literal_is_rejected_like_hex_and_binary() {
        // 2^64: one past u64::MAX.
        let too_big = "18446744073709551616";
        assert!(
            matches!(
                Lexer::new(too_big).tokenize(),
                Err(LexError::Overflow(_))
            ),
            "a decimal literal that overflows u64 must be an error, not 0 — \
             the 0x/0b forms already report Overflow for the same input"
        );
        // The equivalent hex literal is the reference behaviour.
        assert!(matches!(
            Lexer::new("0x10000000000000000").tokenize(),
            Err(LexError::Overflow(_))
        ));

        // u64::MAX itself still lexes: the boundary must not move.
        assert_eq!(
            Lexer::new("18446744073709551615").tokenize().unwrap().first(),
            Some(&Token::IntLit(u64::MAX))
        );

        // A malformed float ("1e" with no exponent digits) was likewise
        // turned into 0.0 by `unwrap_or`.
        assert!(
            Lexer::new("1e").tokenize().is_err(),
            "an incomplete exponent is a syntax error, not the value 0.0"
        );
    }

    #[test]
    fn test_unary_ops() {
        let ts   = TypeSystem::with_primitives();
        let regs = FakeRegs(HashMap::new());
        let mem  = FakeMem(vec![0u8; 64]);
        let sym  = FakeSym(HashMap::new());
        let ctx  = make_ctx(&regs, &mem, &sym, &ts);

        let v = ExprEvaluator::eval(&parse_expression("!0").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 1);
        let v = ExprEvaluator::eval(&parse_expression("!5").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, 0);
        let v = ExprEvaluator::eval(&parse_expression("~0").unwrap(), &ctx).unwrap();
        assert_eq!(v.value, u64::MAX);
    }

    /// A cast dereference must size the read by the WHOLE type name.
    ///
    /// The old classifier asked `name.contains("char")`, which is true of
    /// `wchar_t`: `(wchar_t*)p` read ONE byte and reported it as the character.
    /// Dereferencing a wide string is an ordinary thing to do in a debugger,
    /// and the answer came back plausible and wrong. Any user type whose name
    /// merely contains "char" or "short" had the same fate.
    #[test]
    fn a_type_name_is_matched_whole_not_by_substring() {
        assert_eq!(scalar_width_of_name("char"), Some(Size::B1));
        assert_eq!(scalar_width_of_name("unsigned char"), Some(Size::B1));
        assert_eq!(scalar_width_of_name("short"), Some(Size::B2));

        // wchar_t contains "char" and is NOT one byte anywhere.
        let wide = scalar_width_of_name("wchar_t").expect("wchar_t is a known type");
        assert_ne!(wide, Size::B1, "wchar_t is never a single byte");
        if cfg!(target_os = "windows") {
            assert_eq!(wide, Size::B2);
        } else {
            assert_eq!(wide, Size::B4);
        }

        // Names that merely CONTAIN a keyword are not that type at all.
        assert_eq!(scalar_width_of_name("charset_t"), None);
        assert_eq!(scalar_width_of_name("shortcut_t"), None);
        assert_eq!(scalar_width_of_name("my_float_wrapper"), None);
        assert_eq!(scalar_width_of_name("struct sockaddr"), None);
    }

    /// `long` is 4 bytes on Windows and 8 on Unix. It used to be 8 everywhere,
    /// so every `(long*)p` read on Windows pulled in four bytes of whatever
    /// follows the variable.
    #[test]
    fn long_is_sized_for_the_platform_this_build_targets() {
        let expected = if cfg!(target_os = "windows") { Size::B4 } else { Size::B8 };
        assert_eq!(scalar_width_of_name("long"), Some(expected));
        assert_eq!(scalar_width_of_name("unsigned long"), Some(expected));
        assert_eq!(scalar_width_of_name("long int"), Some(expected));
        // long long is 8 on both.
        assert_eq!(scalar_width_of_name("long long"), Some(Size::B8));
        assert_eq!(scalar_width_of_name("unsigned long long"), Some(Size::B8));
    }

    /// Qualifiers do not change a width and must not hide the type.
    #[test]
    fn qualifiers_are_stripped_before_the_name_is_matched() {
        assert_eq!(scalar_width_of_name("const unsigned int"), Some(Size::B4));
        assert_eq!(scalar_width_of_name("  volatile   signed   char  "), Some(Size::B1));
        assert_eq!(scalar_width_of_name("CONST INT"), Some(Size::B4));
    }

}
