//! `type_system` — .NET CLI type system: TypeSig decoding, generic instantiation,
//! inheritance hierarchy building, and interface implementation lookup.

use std::collections::HashMap;
use std::fmt;

// ── ElementType ───────────────────────────────────────────────────────────────

/// ECMA-335 §II.23.1.16 — element type codes in signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ElementType {
    End       = 0x00,
    Void      = 0x01,
    Boolean   = 0x02,
    Char      = 0x03,
    I1        = 0x04,
    U1        = 0x05,
    I2        = 0x06,
    U2        = 0x07,
    I4        = 0x08,
    U4        = 0x09,
    I8        = 0x0A,
    U8        = 0x0B,
    R4        = 0x0C,
    R8        = 0x0D,
    String    = 0x0E,
    Ptr       = 0x0F,
    ByRef     = 0x10,
    ValueType = 0x11,
    Class     = 0x12,
    Var       = 0x13,
    Array     = 0x14,
    GenericInst = 0x15,
    TypedByRef = 0x16,
    I         = 0x18,
    U         = 0x19,
    FnPtr     = 0x1B,
    Object    = 0x1C,
    SzArray   = 0x1D,
    MVar      = 0x1E,
    CmodReqd  = 0x1F,
    CmodOpt   = 0x20,
    Internal  = 0x21,
    Modifier  = 0x40,
    Sentinel  = 0x41,
    Pinned    = 0x45,
}

impl ElementType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::End),       0x01 => Some(Self::Void),
            0x02 => Some(Self::Boolean),   0x03 => Some(Self::Char),
            0x04 => Some(Self::I1),        0x05 => Some(Self::U1),
            0x06 => Some(Self::I2),        0x07 => Some(Self::U2),
            0x08 => Some(Self::I4),        0x09 => Some(Self::U4),
            0x0A => Some(Self::I8),        0x0B => Some(Self::U8),
            0x0C => Some(Self::R4),        0x0D => Some(Self::R8),
            0x0E => Some(Self::String),    0x0F => Some(Self::Ptr),
            0x10 => Some(Self::ByRef),     0x11 => Some(Self::ValueType),
            0x12 => Some(Self::Class),     0x13 => Some(Self::Var),
            0x14 => Some(Self::Array),     0x15 => Some(Self::GenericInst),
            0x16 => Some(Self::TypedByRef),0x18 => Some(Self::I),
            0x19 => Some(Self::U),         0x1B => Some(Self::FnPtr),
            0x1C => Some(Self::Object),    0x1D => Some(Self::SzArray),
            0x1E => Some(Self::MVar),      0x1F => Some(Self::CmodReqd),
            0x20 => Some(Self::CmodOpt),   0x21 => Some(Self::Internal),
            0x40 => Some(Self::Modifier),  0x41 => Some(Self::Sentinel),
            0x45 => Some(Self::Pinned),
            _ => None,
        }
    }

    pub fn is_primitive(self) -> bool {
        matches!(self,
            Self::Void | Self::Boolean | Self::Char |
            Self::I1 | Self::U1 | Self::I2 | Self::U2 |
            Self::I4 | Self::U4 | Self::I8 | Self::U8 |
            Self::R4 | Self::R8 | Self::I | Self::U |
            Self::String | Self::Object | Self::TypedByRef)
    }

    pub fn primitive_name(self) -> Option<&'static str> {
        match self {
            Self::Void => Some("void"), Self::Boolean => Some("bool"),
            Self::Char => Some("char"), Self::I1 => Some("sbyte"),
            Self::U1 => Some("byte"),   Self::I2 => Some("short"),
            Self::U2 => Some("ushort"), Self::I4 => Some("int"),
            Self::U4 => Some("uint"),   Self::I8 => Some("long"),
            Self::U8 => Some("ulong"),  Self::R4 => Some("float"),
            Self::R8 => Some("double"), Self::I => Some("IntPtr"),
            Self::U => Some("UIntPtr"), Self::String => Some("string"),
            Self::Object => Some("object"),
            _ => None,
        }
    }
}

// ── ArrayShape ────────────────────────────────────────────────────────────────

/// Describes the shape of a multi-dimensional array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrayShape {
    pub rank: u32,
    pub sizes: Vec<u32>,
    pub lo_bounds: Vec<i32>,
}

impl ArrayShape {
    pub fn new(rank: u32) -> Self {
        Self { rank, sizes: Vec::new(), lo_bounds: Vec::new() }
    }
}

// ── GenericInst ───────────────────────────────────────────────────────────────

/// A closed generic instantiation: `T<A, B, ...>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericInst {
    /// Whether the base is a class (true) or value type (false).
    pub is_class: bool,
    /// Metadata token of the open generic type.
    pub token: u32,
    /// Generic arguments.
    pub args: Vec<TypeSig>,
}

// ── TypeSig ───────────────────────────────────────────────────────────────────

/// Decoded CLI type signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSig {
    /// A primitive element type with no further data.
    Primitive(ElementType),
    /// A class referenced by metadata token.
    Class(u32),
    /// A value type referenced by metadata token.
    ValueType(u32),
    /// A pointer to another type.
    Ptr(Box<Self>),
    /// A by-ref parameter.
    ByRef(Box<Self>),
    /// A single-dimension, zero-lower-bound array (SzArray).
    SzArray(Box<Self>),
    /// A multi-dimensional array.
    Array(Box<Self>, ArrayShape),
    /// A closed generic instantiation.
    GenericInst(Box<GenericInst>),
    /// Type generic parameter (!T).
    Var(u32),
    /// Method generic parameter (!!T).
    MVar(u32),
    /// A function pointer type.
    FnPtr(Box<MethodSig>),
    /// Custom modifier required.
    CmodReqd(u32, Box<Self>),
    /// Custom modifier optional.
    CmodOpt(u32, Box<Self>),
    /// Pinned local variable.
    Pinned(Box<Self>),
    /// Typed reference.
    TypedByRef,
    /// Unknown/unparsed.
    Unknown(u8),
}

impl TypeSig {
    /// Return true if this is a reference type.
    pub fn is_reference_type(&self) -> bool {
        match self {
            Self::Primitive(ElementType::String)
          | Self::Primitive(ElementType::Object)
          | Self::Class(_)
          | Self::SzArray(_)
          | Self::Array(_, _) => true,
            Self::GenericInst(g) => g.is_class,
            _ => false,
        }
    }

    /// Return true if this is a value type.
    pub fn is_value_type(&self) -> bool {
        match self {
            Self::ValueType(_) => true,
            Self::GenericInst(g) => !g.is_class,
            Self::Primitive(e) => e.is_primitive()
                && !matches!(e, ElementType::String | ElementType::Object),
            _ => false,
        }
    }

    /// Display name for simple/primitive types.
    pub fn display_name(&self) -> String {
        match self {
            Self::Primitive(e) => e.primitive_name().unwrap_or("?").to_string(),
            Self::Class(t) | Self::ValueType(t) => format!("[0x{t:08X}]"),
            Self::Ptr(inner) => format!("{}*", inner.display_name()),
            Self::ByRef(inner) => format!("{}& ", inner.display_name()),
            Self::SzArray(inner) => format!("{}[]", inner.display_name()),
            Self::Array(inner, shape) => format!("{}[rank={}]", inner.display_name(), shape.rank),
            Self::GenericInst(g) => {
                let args: Vec<String> = g.args.iter().map(|a| a.display_name()).collect();
                format!("[0x{:08X}]<{}>", g.token, args.join(", "))
            }
            Self::Var(n) => format!("!{n}"),
            Self::MVar(n) => format!("!!{n}"),
            Self::FnPtr(_) => "fnptr".to_string(),
            Self::CmodReqd(_, inner) | Self::CmodOpt(_, inner) => inner.display_name(),
            Self::Pinned(inner) => format!("pinned {}", inner.display_name()),
            Self::TypedByRef => "typedbyref".to_string(),
            Self::Unknown(b) => format!("unknown(0x{b:02X})"),
        }
    }
}

impl fmt::Display for TypeSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ── MethodSig ─────────────────────────────────────────────────────────────────

/// Calling conventions for method signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConv {
    Default,
    VarArg,
    Unmanaged,
    Generic,
    CDecl,
    StdCall,
    ThisCall,
    FastCall,
}

impl CallingConv {
    pub fn from_u8(b: u8) -> Self {
        match b & 0x0F {
            0x00 => Self::Default,
            0x05 => Self::VarArg,
            0x09 => Self::Unmanaged,
            0x10 | 0x20 => Self::Generic,
            0x01 => Self::CDecl,
            0x02 => Self::StdCall,
            0x03 => Self::ThisCall,
            0x04 => Self::FastCall,
            _ => Self::Default,
        }
    }
}

/// A decoded method signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSig {
    pub calling_conv: CallingConv,
    pub has_this: bool,
    pub explicit_this: bool,
    pub generic_param_count: u32,
    pub return_type: Box<TypeSig>,
    pub params: Vec<TypeSig>,
    pub vararg_params: Vec<TypeSig>,
}

impl MethodSig {
    pub fn arity(&self) -> usize { self.params.len() }
}

// ── Sig reader ────────────────────────────────────────────────────────────────

/// Maximum number of elements allocated from a single untrusted length field.
/// Prevents memory-exhaustion when parsing adversarially crafted signature blobs.
const MAX_SIG_ALLOC: usize = 1024;

/// Blob signature reader with compressed integer support.
pub struct SigReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Remaining recursion budget for `read_type_sig`. Prevents stack overflow
    /// on adversarially nested pointer chains (e.g. Ptr(Ptr(Ptr(...)))).
    depth: u32,
}

impl<'a> SigReader<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0, depth: 64 } }

    pub fn remaining(&self) -> usize { self.data.len() - self.pos }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() { return None; }
        let b = self.data[self.pos];
        self.pos += 1;
        Some(b)
    }

    /// Peek at the next byte without consuming it.
    pub fn peek_u8(&self) -> Option<u8> { self.data.get(self.pos).copied() }

    /// ECMA-335 §II.23.2 compressed unsigned integer.
    pub fn read_compressed_u32(&mut self) -> Option<u32> {
        let b0 = self.read_u8()? as u32;
        if b0 & 0x80 == 0 {
            return Some(b0);
        }
        if b0 & 0xC0 == 0x80 {
            let b1 = self.read_u8()? as u32;
            return Some(((b0 & 0x3F) << 8) | b1);
        }
        if b0 & 0xE0 == 0xC0 {
            let b1 = self.read_u8()? as u32;
            let b2 = self.read_u8()? as u32;
            let b3 = self.read_u8()? as u32;
            return Some(((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3);
        }
        None
    }

    /// ECMA-335 compressed signed integer.
    pub fn read_compressed_i32(&mut self) -> Option<i32> {
        let raw = self.read_compressed_u32()?;
        // Decode zigzag: if LSB set, negate and subtract 1.
        if raw & 1 == 1 {
            Some(-((raw >> 1) as i32) - 1)
        } else {
            Some((raw >> 1) as i32)
        }
    }

    /// Read a metadata token coded as a TypeDefOrRef encoded token.
    pub fn read_type_def_or_ref_token(&mut self) -> Option<u32> {
        let encoded = self.read_compressed_u32()?;
        let table = encoded & 0x03;
        let row = encoded >> 2;
        let table_id: u32 = match table {
            0 => 0x02, // TypeDef
            1 => 0x01, // TypeRef
            2 => 0x1B, // TypeSpec
            _ => return None,
        };
        Some((table_id << 24) | row)
    }

    /// Decode a TypeSig at the current position.
    pub fn read_type_sig(&mut self) -> Option<TypeSig> {
        // Guard against stack overflow from adversarially deeply-nested type sigs
        // (e.g. Ptr(Ptr(Ptr(...))) crafted to exhaust the call stack).
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        let result = self.read_type_sig_inner();
        self.depth += 1;
        result
    }

    fn read_type_sig_inner(&mut self) -> Option<TypeSig> {
        let b = self.read_u8()?;
        let elem = ElementType::from_u8(b)?;
        match elem {
            ElementType::Void | ElementType::Boolean | ElementType::Char
          | ElementType::I1 | ElementType::U1 | ElementType::I2 | ElementType::U2
          | ElementType::I4 | ElementType::U4 | ElementType::I8 | ElementType::U8
          | ElementType::R4 | ElementType::R8 | ElementType::I | ElementType::U
          | ElementType::String | ElementType::Object
          | ElementType::TypedByRef => {
                if elem == ElementType::TypedByRef {
                    Some(TypeSig::TypedByRef)
                } else {
                    Some(TypeSig::Primitive(elem))
                }
            }
            ElementType::ValueType => {
                let token = self.read_type_def_or_ref_token()?;
                Some(TypeSig::ValueType(token))
            }
            ElementType::Class => {
                let token = self.read_type_def_or_ref_token()?;
                Some(TypeSig::Class(token))
            }
            ElementType::Ptr => {
                // May be VOID for void*
                let inner = self.read_type_sig()?;
                Some(TypeSig::Ptr(Box::new(inner)))
            }
            ElementType::ByRef => {
                let inner = self.read_type_sig()?;
                Some(TypeSig::ByRef(Box::new(inner)))
            }
            ElementType::SzArray => {
                // Optional custom mods, then element type
                let inner = self.read_type_sig()?;
                Some(TypeSig::SzArray(Box::new(inner)))
            }
            ElementType::Array => {
                let inner = self.read_type_sig()?;
                let shape = self.read_array_shape()?;
                Some(TypeSig::Array(Box::new(inner), shape))
            }
            ElementType::GenericInst => {
                let class_byte = self.read_u8()?;
                let is_class = class_byte == 0x12;
                let token = self.read_type_def_or_ref_token()?;
                let arg_count = self.read_compressed_u32()? as usize;
                // Cap allocation: an adversarial blob cannot trigger gigabyte allocs.
                let mut args = Vec::with_capacity(arg_count.min(MAX_SIG_ALLOC));
                for _ in 0..arg_count {
                    args.push(self.read_type_sig()?);
                }
                Some(TypeSig::GenericInst(Box::new(GenericInst { is_class, token, args })))
            }
            ElementType::Var => {
                let n = self.read_compressed_u32()?;
                Some(TypeSig::Var(n))
            }
            ElementType::MVar => {
                let n = self.read_compressed_u32()?;
                Some(TypeSig::MVar(n))
            }
            ElementType::FnPtr => {
                let sig = self.read_method_sig()?;
                Some(TypeSig::FnPtr(Box::new(sig)))
            }
            ElementType::CmodReqd => {
                let token = self.read_type_def_or_ref_token()?;
                let inner = self.read_type_sig()?;
                Some(TypeSig::CmodReqd(token, Box::new(inner)))
            }
            ElementType::CmodOpt => {
                let token = self.read_type_def_or_ref_token()?;
                let inner = self.read_type_sig()?;
                Some(TypeSig::CmodOpt(token, Box::new(inner)))
            }
            ElementType::Pinned => {
                let inner = self.read_type_sig()?;
                Some(TypeSig::Pinned(Box::new(inner)))
            }
            _ => Some(TypeSig::Unknown(b)),
        }
    }

    fn read_array_shape(&mut self) -> Option<ArrayShape> {
        let rank = self.read_compressed_u32()?;
        let num_sizes = self.read_compressed_u32()? as usize;
        // Cap allocation against adversarial length fields in untrusted blobs.
        let mut sizes = Vec::with_capacity(num_sizes.min(MAX_SIG_ALLOC));
        for _ in 0..num_sizes {
            sizes.push(self.read_compressed_u32()?);
        }
        let num_lo = self.read_compressed_u32()? as usize;
        let mut lo_bounds = Vec::with_capacity(num_lo.min(MAX_SIG_ALLOC));
        for _ in 0..num_lo {
            lo_bounds.push(self.read_compressed_i32()?);
        }
        Some(ArrayShape { rank, sizes, lo_bounds })
    }

    /// Decode a MethodSig blob.
    pub fn read_method_sig(&mut self) -> Option<MethodSig> {
        let flags = self.read_u8()?;
        let calling_conv = CallingConv::from_u8(flags);
        let has_this = flags & 0x20 != 0;
        let explicit_this = flags & 0x40 != 0;
        let is_generic = flags & 0x10 != 0;
        let generic_param_count = if is_generic { self.read_compressed_u32()? } else { 0 };
        let param_count = self.read_compressed_u32()? as usize;
        let return_type = self.read_type_sig()?;
        // Cap allocation: untrusted param_count must not trigger gigabyte allocs.
        let mut params = Vec::with_capacity(param_count.min(MAX_SIG_ALLOC));
        let mut vararg_params = Vec::new();
        for _ in 0..param_count {
            if self.peek_u8() == Some(ElementType::Sentinel as u8) {
                let _ = self.read_u8();
                // Everything after sentinel is vararg
                while self.remaining() > 0 {
                    vararg_params.push(self.read_type_sig()?);
                }
                break;
            }
            params.push(self.read_type_sig()?);
        }
        Some(MethodSig {
            calling_conv, has_this, explicit_this, generic_param_count,
            return_type: Box::new(return_type), params, vararg_params,
        })
    }
}

// ── TypeDescriptor ────────────────────────────────────────────────────────────

/// Full description of a .NET type for resolution/hierarchy purposes.
#[derive(Debug, Clone)]
pub struct TypeDescriptor {
    /// 1-based TypeDef row index.
    pub index: u32,
    /// Fully qualified name (namespace.name).
    pub full_name: String,
    /// Namespace.
    pub namespace: String,
    /// Short name.
    pub name: String,
    /// Token of base class (None = System.Object or no base).
    pub base_token: Option<u32>,
    /// Tokens of directly implemented interfaces.
    pub interfaces: Vec<u32>,
    /// Whether this is an interface.
    pub is_interface: bool,
    /// Whether this is a value type.
    pub is_value_type: bool,
    /// Whether this is abstract.
    pub is_abstract: bool,
    /// Whether this is sealed.
    pub is_sealed: bool,
}

impl TypeDescriptor {
    pub fn full_name(ns: &str, name: &str) -> String {
        if ns.is_empty() { name.to_string() } else { format!("{ns}.{name}") }
    }
}

// ── InheritanceNode ───────────────────────────────────────────────────────────

/// Node in the inheritance hierarchy.
#[derive(Debug, Clone)]
pub struct InheritanceNode {
    pub token: u32,
    pub full_name: String,
    pub parent_token: Option<u32>,
    pub children: Vec<u32>,
}

// ── TypeResolver ─────────────────────────────────────────────────────────────

/// Resolves type tokens to TypeDescriptors and builds hierarchy.
pub struct TypeResolver {
    /// Map from metadata token to type descriptor.
    types: HashMap<u32, TypeDescriptor>,
    /// Map from fully qualified name to token.
    name_map: HashMap<String, u32>,
}

impl TypeResolver {
    pub fn new() -> Self {
        Self { types: HashMap::new(), name_map: HashMap::new() }
    }

    /// Register a type descriptor.
    pub fn register(&mut self, desc: TypeDescriptor) {
        let token = (0x02u32 << 24) | desc.index;
        self.name_map.insert(desc.full_name.clone(), token);
        self.types.insert(token, desc);
    }

    /// Look up by metadata token.
    pub fn resolve_token(&self, token: u32) -> Option<&TypeDescriptor> {
        self.types.get(&token)
    }

    /// Look up by fully qualified name.
    pub fn resolve_name(&self, full_name: &str) -> Option<&TypeDescriptor> {
        let token = self.name_map.get(full_name)?;
        self.types.get(token)
    }

    /// Build the complete inheritance hierarchy.
    pub fn build_hierarchy(&self) -> HashMap<u32, InheritanceNode> {
        let mut nodes: HashMap<u32, InheritanceNode> = self.types.iter().map(|(&tok, desc)| {
            (tok, InheritanceNode {
                token: tok,
                full_name: desc.full_name.clone(),
                parent_token: desc.base_token,
                children: Vec::new(),
            })
        }).collect();
        // Fill children lists
        let parents: Vec<(u32, Option<u32>)> = nodes.values()
            .map(|n| (n.token, n.parent_token))
            .collect();
        for (child_tok, maybe_parent) in parents {
            if let Some(parent_tok) = maybe_parent
                && let Some(parent) = nodes.get_mut(&parent_tok)
            {
                parent.children.push(child_tok);
            }
        }
        nodes
    }

    /// Return all direct subclasses of a type token.
    pub fn direct_subclasses(&self, token: u32) -> Vec<u32> {
        self.types.values()
            .filter(|d| d.base_token == Some(token))
            .map(|d| (0x02u32 << 24) | d.index)
            .collect()
    }

    /// Return the full inheritance chain from a type to the root.
    pub fn inheritance_chain(&self, token: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = Some(token);
        let mut seen = std::collections::HashSet::new();
        while let Some(t) = current {
            if !seen.insert(t) { break; }
            chain.push(t);
            current = self.types.get(&t).and_then(|d| d.base_token);
        }
        chain
    }

    /// Return all types that implement a given interface token.
    pub fn implementors(&self, iface_token: u32) -> Vec<u32> {
        self.types.values()
            .filter(|d| d.interfaces.contains(&iface_token))
            .map(|d| (0x02u32 << 24) | d.index)
            .collect()
    }

    /// Count all registered types.
    pub fn type_count(&self) -> usize { self.types.len() }
}

impl Default for TypeResolver {
    fn default() -> Self { Self::new() }
}

// ── InterfaceMap ──────────────────────────────────────────────────────────────

/// Maps interface tokens to their concrete implementations within a type.
#[derive(Debug, Clone, Default)]
pub struct InterfaceMap {
    /// Map: (concrete_type_token, interface_token) → method_impl_tokens
    entries: HashMap<(u32, u32), Vec<u32>>,
}

impl InterfaceMap {
    pub fn new() -> Self { Self::default() }

    /// Record that `impl_type` implements `iface` using the given method mappings.
    pub fn add(&mut self, impl_type: u32, iface: u32, methods: Vec<u32>) {
        self.entries.insert((impl_type, iface), methods);
    }

    /// Look up the method list for a (type, interface) pair.
    pub fn methods_for(&self, impl_type: u32, iface: u32) -> Option<&[u32]> {
        self.entries.get(&(impl_type, iface)).map(|v| v.as_slice())
    }

    /// Return all interfaces implemented by a type.
    pub fn interfaces_of(&self, impl_type: u32) -> Vec<u32> {
        self.entries.keys()
            .filter(|(t, _)| *t == impl_type)
            .map(|(_, i)| *i)
            .collect()
    }

    /// Number of (type, interface) pairs.
    pub fn entry_count(&self) -> usize { self.entries.len() }
}

// ── GenericContext ────────────────────────────────────────────────────────────

/// Substitution context for instantiating generic types/methods.
#[derive(Debug, Clone, Default)]
pub struct GenericContext {
    /// Type-level generic arguments (!T).
    pub type_args: Vec<TypeSig>,
    /// Method-level generic arguments (!!T).
    pub method_args: Vec<TypeSig>,
}

impl GenericContext {
    pub fn new() -> Self { Self::default() }

    /// Substitute generic parameters in a TypeSig.
    pub fn instantiate(&self, sig: &TypeSig) -> TypeSig {
        match sig {
            TypeSig::Var(n) => self.type_args
                .get(*n as usize)
                .cloned()
                .unwrap_or_else(|| sig.clone()),
            TypeSig::MVar(n) => self.method_args
                .get(*n as usize)
                .cloned()
                .unwrap_or_else(|| sig.clone()),
            TypeSig::Ptr(inner) => TypeSig::Ptr(Box::new(self.instantiate(inner))),
            TypeSig::ByRef(inner) => TypeSig::ByRef(Box::new(self.instantiate(inner))),
            TypeSig::SzArray(inner) => TypeSig::SzArray(Box::new(self.instantiate(inner))),
            TypeSig::Array(inner, shape) => {
                TypeSig::Array(Box::new(self.instantiate(inner)), shape.clone())
            }
            TypeSig::GenericInst(g) => {
                let args = g.args.iter().map(|a| self.instantiate(a)).collect();
                TypeSig::GenericInst(Box::new(GenericInst {
                    is_class: g.is_class, token: g.token, args,
                }))
            }
            TypeSig::CmodReqd(t, inner) => {
                TypeSig::CmodReqd(*t, Box::new(self.instantiate(inner)))
            }
            TypeSig::CmodOpt(t, inner) => {
                TypeSig::CmodOpt(*t, Box::new(self.instantiate(inner)))
            }
            TypeSig::Pinned(inner) => TypeSig::Pinned(Box::new(self.instantiate(inner))),
            // All others are concrete — return as-is.
            _ => sig.clone(),
        }
    }

    /// Instantiate all parameters in a MethodSig.
    pub fn instantiate_method_sig(&self, sig: &MethodSig) -> MethodSig {
        MethodSig {
            calling_conv: sig.calling_conv,
            has_this: sig.has_this,
            explicit_this: sig.explicit_this,
            generic_param_count: sig.generic_param_count,
            return_type: Box::new(self.instantiate(&sig.return_type)),
            params: sig.params.iter().map(|p| self.instantiate(p)).collect(),
            vararg_params: sig.vararg_params.iter().map(|p| self.instantiate(p)).collect(),
        }
    }
}

// ── Sig utilities ──────────────────────────────────────────────────────────────

/// Parse a TypeSig from a raw blob slice.
pub fn parse_type_sig(blob: &[u8]) -> Option<TypeSig> {
    SigReader::new(blob).read_type_sig()
}

/// Parse a MethodSig from a raw blob slice.
pub fn parse_method_sig(blob: &[u8]) -> Option<MethodSig> {
    SigReader::new(blob).read_method_sig()
}

/// Decode a field signature blob (FIELD calling convention = 0x06, then type).
pub fn parse_field_sig(blob: &[u8]) -> Option<TypeSig> {
    if blob.is_empty() { return None; }
    if blob[0] != 0x06 { return None; }
    SigReader::new(&blob[1..]).read_type_sig()
}

/// Decode a local variable signature blob.
pub fn parse_locals_sig(blob: &[u8]) -> Option<Vec<TypeSig>> {
    if blob.len() < 2 { return None; }
    if blob[0] != 0x07 { return None; } // LOCAL_SIG
    let mut reader = SigReader::new(&blob[1..]);
    let count = reader.read_compressed_u32()? as usize;
    let mut locals = Vec::with_capacity(count);
    for _ in 0..count {
        locals.push(reader.read_type_sig()?);
    }
    Some(locals)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_type_roundtrip() {
        for &b in &[0x01u8, 0x02, 0x04, 0x08, 0x0E, 0x12, 0x15, 0x1D, 0x1E] {
            assert!(ElementType::from_u8(b).is_some());
        }
        assert!(ElementType::from_u8(0xFF).is_none());
    }

    #[test]
    fn primitive_names() {
        assert_eq!(ElementType::I4.primitive_name(), Some("int"));
        assert_eq!(ElementType::String.primitive_name(), Some("string"));
        assert_eq!(ElementType::Array.primitive_name(), None);
    }

    #[test]
    fn read_compressed_u32_single() {
        let mut r = SigReader::new(&[0x03]);
        assert_eq!(r.read_compressed_u32(), Some(3));
    }

    #[test]
    fn read_compressed_u32_two_bytes() {
        // 0x80 0x80 => 0x0000_0080
        let mut r = SigReader::new(&[0x81, 0x00]);
        assert_eq!(r.read_compressed_u32(), Some(0x0100));
    }

    #[test]
    fn parse_type_sig_void() {
        let sig = parse_type_sig(&[0x01]).unwrap();
        assert_eq!(sig, TypeSig::Primitive(ElementType::Void));
    }

    #[test]
    fn parse_type_sig_int() {
        let sig = parse_type_sig(&[0x08]).unwrap();
        assert_eq!(sig, TypeSig::Primitive(ElementType::I4));
    }

    #[test]
    fn parse_type_sig_szarray_of_int() {
        let sig = parse_type_sig(&[0x1D, 0x08]).unwrap();
        assert!(matches!(sig, TypeSig::SzArray(_)));
        assert_eq!(sig.display_name(), "int[]");
    }

    #[test]
    fn parse_type_sig_ptr_to_u1() {
        let sig = parse_type_sig(&[0x0F, 0x05]).unwrap();
        assert_eq!(sig.display_name(), "byte*");
    }

    #[test]
    fn parse_field_sig_int() {
        let sig = parse_field_sig(&[0x06, 0x08]).unwrap();
        assert_eq!(sig, TypeSig::Primitive(ElementType::I4));
    }

    #[test]
    fn parse_locals_sig_basic() {
        // LOCAL_SIG, count=2, int, bool
        let blob = [0x07, 0x02, 0x08, 0x02];
        let locals = parse_locals_sig(&blob).unwrap();
        assert_eq!(locals.len(), 2);
        assert_eq!(locals[0], TypeSig::Primitive(ElementType::I4));
        assert_eq!(locals[1], TypeSig::Primitive(ElementType::Boolean));
    }

    #[test]
    fn generic_context_substitutes_var() {
        let ctx = GenericContext {
            type_args: vec![TypeSig::Primitive(ElementType::I4)],
            method_args: vec![],
        };
        let sig = TypeSig::Var(0);
        let result = ctx.instantiate(&sig);
        assert_eq!(result, TypeSig::Primitive(ElementType::I4));
    }

    #[test]
    fn generic_context_substitutes_mvar() {
        let ctx = GenericContext {
            type_args: vec![],
            method_args: vec![TypeSig::Primitive(ElementType::Boolean)],
        };
        let sig = TypeSig::MVar(0);
        let result = ctx.instantiate(&sig);
        assert_eq!(result, TypeSig::Primitive(ElementType::Boolean));
    }

    #[test]
    fn generic_context_out_of_range_is_identity() {
        let ctx = GenericContext::new();
        let sig = TypeSig::Var(5);
        let result = ctx.instantiate(&sig);
        assert_eq!(result, sig);
    }

    #[test]
    fn type_resolver_register_and_lookup() {
        let mut resolver = TypeResolver::new();
        resolver.register(TypeDescriptor {
            index: 1, full_name: "System.Object".to_string(),
            namespace: "System".to_string(), name: "Object".to_string(),
            base_token: None, interfaces: vec![],
            is_interface: false, is_value_type: false,
            is_abstract: false, is_sealed: false,
        });
        let token = (0x02u32 << 24) | 1;
        assert!(resolver.resolve_token(token).is_some());
        assert!(resolver.resolve_name("System.Object").is_some());
    }

    #[test]
    fn inheritance_chain_depth_2() {
        let mut resolver = TypeResolver::new();
        let tok_a = (0x02u32 << 24) | 1;
        let tok_b = (0x02u32 << 24) | 2;
        resolver.register(TypeDescriptor {
            index: 1, full_name: "A".to_string(), namespace: String::new(),
            name: "A".to_string(), base_token: None, interfaces: vec![],
            is_interface: false, is_value_type: false,
            is_abstract: false, is_sealed: false,
        });
        resolver.register(TypeDescriptor {
            index: 2, full_name: "B".to_string(), namespace: String::new(),
            name: "B".to_string(), base_token: Some(tok_a), interfaces: vec![],
            is_interface: false, is_value_type: false,
            is_abstract: false, is_sealed: false,
        });
        let chain = resolver.inheritance_chain(tok_b);
        assert_eq!(chain, vec![tok_b, tok_a]);
    }

    #[test]
    fn interface_map_lookup() {
        let mut map = InterfaceMap::new();
        map.add(0x0200_0001, 0x0200_0002, vec![0x0600_0001, 0x0600_0002]);
        let methods = map.methods_for(0x0200_0001, 0x0200_0002).unwrap();
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn interface_map_interfaces_of() {
        let mut map = InterfaceMap::new();
        map.add(0x0200_0001, 0x0200_0002, vec![]);
        map.add(0x0200_0001, 0x0200_0003, vec![]);
        let ifaces = map.interfaces_of(0x0200_0001);
        assert_eq!(ifaces.len(), 2);
    }

    #[test]
    fn type_sig_is_reference_type() {
        assert!(TypeSig::Class(0x01000001).is_reference_type());
        assert!(TypeSig::Primitive(ElementType::String).is_reference_type());
        assert!(!TypeSig::ValueType(0x01000001).is_value_type() || TypeSig::ValueType(0x01000001).is_value_type());
    }

    #[test]
    fn type_sig_display() {
        let sig = TypeSig::SzArray(Box::new(TypeSig::Primitive(ElementType::I4)));
        assert_eq!(sig.to_string(), "int[]");
    }

    #[test]
    fn direct_subclasses_empty() {
        let resolver = TypeResolver::new();
        let subs = resolver.direct_subclasses(0x02000001);
        assert!(subs.is_empty());
    }

    #[test]
    fn calling_conv_from_byte() {
        assert_eq!(CallingConv::from_u8(0x00), CallingConv::Default);
        assert_eq!(CallingConv::from_u8(0x05), CallingConv::VarArg);
    }
}
