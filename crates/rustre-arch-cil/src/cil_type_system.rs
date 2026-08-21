//! CIL .NET type system — ECMA-335 element types, signature parsing.
//!
//! Implements the full `CorElementType` enumeration, recursive `CilType`
//! parser, method signature decoder, and type introspection helpers.

use std::fmt;

// ── CorElementType ────────────────────────────────────────────────────────────

/// ECMA-335 §II.23.1.16 — all 49 element type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CorElementType {
    End         = 0x00,
    Void        = 0x01,
    Boolean     = 0x02,
    Char        = 0x03,
    I1          = 0x04,
    U1          = 0x05,
    I2          = 0x06,
    U2          = 0x07,
    I4          = 0x08,
    U4          = 0x09,
    I8          = 0x0A,
    U8          = 0x0B,
    R4          = 0x0C,
    R8          = 0x0D,
    String      = 0x0E,
    Ptr         = 0x0F,
    ByRef       = 0x10,
    ValueType   = 0x11,
    Class       = 0x12,
    Var         = 0x13,
    Array       = 0x14,
    GenericInst = 0x15,
    TypedByRef  = 0x16,
    I           = 0x18,
    U           = 0x19,
    FnPtr       = 0x1B,
    Object      = 0x1C,
    SzArray     = 0x1D,
    MVar        = 0x1E,
    CModReqd    = 0x1F,
    CModOpt     = 0x20,
    Internal    = 0x21,
    Modifier    = 0x40,
    Sentinel    = 0x41,
    Pinned      = 0x45,
    Type        = 0x50,
    Boxed       = 0x51,
    Reserved    = 0x52,
    Field       = 0x53,
    Property    = 0x54,
    Enum        = 0x55,
}

impl CorElementType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::End),
            0x01 => Some(Self::Void),
            0x02 => Some(Self::Boolean),
            0x03 => Some(Self::Char),
            0x04 => Some(Self::I1),
            0x05 => Some(Self::U1),
            0x06 => Some(Self::I2),
            0x07 => Some(Self::U2),
            0x08 => Some(Self::I4),
            0x09 => Some(Self::U4),
            0x0A => Some(Self::I8),
            0x0B => Some(Self::U8),
            0x0C => Some(Self::R4),
            0x0D => Some(Self::R8),
            0x0E => Some(Self::String),
            0x0F => Some(Self::Ptr),
            0x10 => Some(Self::ByRef),
            0x11 => Some(Self::ValueType),
            0x12 => Some(Self::Class),
            0x13 => Some(Self::Var),
            0x14 => Some(Self::Array),
            0x15 => Some(Self::GenericInst),
            0x16 => Some(Self::TypedByRef),
            0x18 => Some(Self::I),
            0x19 => Some(Self::U),
            0x1B => Some(Self::FnPtr),
            0x1C => Some(Self::Object),
            0x1D => Some(Self::SzArray),
            0x1E => Some(Self::MVar),
            0x1F => Some(Self::CModReqd),
            0x20 => Some(Self::CModOpt),
            0x21 => Some(Self::Internal),
            0x40 => Some(Self::Modifier),
            0x41 => Some(Self::Sentinel),
            0x45 => Some(Self::Pinned),
            0x50 => Some(Self::Type),
            0x51 => Some(Self::Boxed),
            0x52 => Some(Self::Reserved),
            0x53 => Some(Self::Field),
            0x54 => Some(Self::Property),
            0x55 => Some(Self::Enum),
            _ => None,
        }
    }
}

// ── CilType ───────────────────────────────────────────────────────────────────

/// A parsed .NET type from a CIL signature blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CilType {
    Void,
    Boolean,
    Char,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Single,
    Double,
    String,
    Object,
    TypedRef,
    IntPtr,
    UIntPtr,
    /// VALUETYPE token → type name
    ValueType(String),
    /// CLASS token → type name
    Class(String),
    /// PTR modifier
    Ptr(Box<Self>),
    /// BYREF modifier
    ByRef(Box<Self>),
    /// Single-dimensional zero-lower-bound array (SZARRAY)
    SzArray(Box<Self>),
    /// Multi-dimensional array (ARRAY)
    Array { element: Box<Self>, rank: u32 },
    /// GENERICINST — class/struct name + type args
    Generic(String, Vec<Self>),
    /// MVAR — method type parameter index
    MVar(u32),
    /// VAR — type parameter index
    Var(u32),
    /// Unrecognised or unsupported element type (raw byte)
    Unknown(u8),
}

impl fmt::Display for CilType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void        => write!(f, "void"),
            Self::Boolean     => write!(f, "bool"),
            Self::Char        => write!(f, "char"),
            Self::Int8        => write!(f, "int8"),
            Self::UInt8       => write!(f, "uint8"),
            Self::Int16       => write!(f, "int16"),
            Self::UInt16      => write!(f, "uint16"),
            Self::Int32       => write!(f, "int32"),
            Self::UInt32      => write!(f, "uint32"),
            Self::Int64       => write!(f, "int64"),
            Self::UInt64      => write!(f, "uint64"),
            Self::Single      => write!(f, "float32"),
            Self::Double      => write!(f, "float64"),
            Self::String      => write!(f, "string"),
            Self::Object      => write!(f, "object"),
            Self::TypedRef    => write!(f, "typedref"),
            Self::IntPtr      => write!(f, "native int"),
            Self::UIntPtr     => write!(f, "native uint"),
            Self::ValueType(n) => write!(f, "valuetype {n}"),
            Self::Class(n)    => write!(f, "class {n}"),
            Self::Ptr(t)      => write!(f, "{t}*"),
            Self::ByRef(t)    => write!(f, "{t}&"),
            Self::SzArray(t)  => write!(f, "{t}[]"),
            Self::Array { element, rank } => {
                write!(f, "{element}")?;
                write!(f, "[")?;
                for i in 0..*rank {
                    if i > 0 { write!(f, ",")?; }
                }
                write!(f, "]")
            }
            Self::Generic(name, args) => {
                write!(f, "{name}<")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 { write!(f, ",")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ">")
            }
            Self::MVar(n) => write!(f, "!!{n}"),
            Self::Var(n)  => write!(f, "!{n}"),
            Self::Unknown(b) => write!(f, "unknown({b:#04x})"),
        }
    }
}

impl CilType {
    /// True for primitive value types and user-defined value types.
    #[must_use]
    pub const fn is_value_type(&self) -> bool {
        matches!(
            self,
            Self::Boolean
                | Self::Char
                | Self::Int8
                | Self::UInt8
                | Self::Int16
                | Self::UInt16
                | Self::Int32
                | Self::UInt32
                | Self::Int64
                | Self::UInt64
                | Self::Single
                | Self::Double
                | Self::IntPtr
                | Self::UIntPtr
                | Self::TypedRef
                | Self::ValueType(_)
        )
    }

    /// True for managed reference types.
    #[must_use]
    pub const fn is_reference_type(&self) -> bool {
        matches!(
            self,
            Self::String
                | Self::Object
                | Self::Class(_)
                | Self::SzArray(_)
                | Self::Array { .. }
                | Self::Generic(_, _)
        )
    }

    /// True if the type is a managed pointer (`ByRef`).
    #[must_use]
    pub const fn is_by_ref(&self) -> bool {
        matches!(self, Self::ByRef(_))
    }

    /// True if the type is an unmanaged pointer (Ptr).
    #[must_use]
    pub const fn is_ptr(&self) -> bool {
        matches!(self, Self::Ptr(_))
    }

    /// Strip one level of pointer/byref indirection.
    #[must_use]
    pub fn pointee(&self) -> Option<&Self> {
        match self {
            Self::Ptr(inner) | Self::ByRef(inner) => Some(inner.as_ref()),
            _ => None,
        }
    }
}

/// Return the stack size (in bytes) required by a type on the evaluation stack.
/// Returns `None` for void, typed-ref, and generic params where size is unknown.
#[must_use]
pub const fn type_size_in_bytes(t: &CilType) -> Option<u32> {
    match t {
        CilType::Boolean | CilType::Int8 | CilType::UInt8 => Some(1),
        CilType::Char | CilType::Int16 | CilType::UInt16  => Some(2),
        CilType::Int32 | CilType::UInt32 | CilType::Single => Some(4),
        CilType::Int64 | CilType::UInt64 | CilType::Double | CilType::IntPtr | CilType::UIntPtr
        | CilType::Ptr(_) | CilType::ByRef(_)
        | CilType::String | CilType::Object
        | CilType::Class(_) | CilType::SzArray(_) | CilType::Array { .. } => Some(8),
        // 64-bit ptr
        CilType::TypedRef    => Some(16), // two pointers
        _ => None,
    }
}

// ── Compressed integer decoding (ECMA-335 §II.23.2) ──────────────────────────

/// Decode a compressed unsigned integer from a signature blob.
/// Returns `(value, bytes_consumed)`.
#[must_use]
pub fn decode_compressed_uint(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
    if pos >= bytes.len() {
        return None;
    }
    let b0 = u32::from(bytes[pos]);
    if b0 & 0x80 == 0 {
        // 1-byte: 0xxxxxxx
        Some((b0, 1))
    } else if b0 & 0xC0 == 0x80 {
        // 2-byte: 10xxxxxx xxxxxxxx
        if pos + 1 >= bytes.len() { return None; }
        let val = ((b0 & 0x3F) << 8) | u32::from(bytes[pos + 1]);
        Some((val, 2))
    } else if b0 & 0xE0 == 0xC0 {
        // 4-byte: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if pos + 3 >= bytes.len() { return None; }
        let val = ((b0 & 0x1F) << 24)
            | (u32::from(bytes[pos + 1]) << 16)
            | (u32::from(bytes[pos + 2]) << 8)
            | u32::from(bytes[pos + 3]);
        Some((val, 4))
    } else {
        None
    }
}

/// Decode a token from a compressed token in a signature blob (§II.23.2.8).
pub fn decode_type_def_or_ref_encoded(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let (val, consumed) = decode_compressed_uint(bytes, *pos)?;
    *pos += consumed;
    // Low 2 bits encode table: 0=TypeDef, 1=TypeRef, 2=TypeSpec
    let table = val & 0x3;
    let row   = val >> 2;
    let table_name = match table {
        0 => "TypeDef",
        1 => "TypeRef",
        2 => "TypeSpec",
        _ => "Unknown",
    };
    Some(format!("[{table_name}:{row}]"))
}

// ── Signature parser ──────────────────────────────────────────────────────────

/// Maximum nesting depth for recursive type signature parsing.
/// Prevents stack overflow on adversarially crafted signature blobs.
const MAX_SIG_DEPTH: usize = 64;

/// Parse a single type from a signature blob at `pos`.
pub fn parse_sig_type(bytes: &[u8], pos: &mut usize) -> CilType {
    parse_sig_type_inner(bytes, pos, 0)
}

fn parse_sig_type_inner(bytes: &[u8], pos: &mut usize, depth: usize) -> CilType {
    if depth > MAX_SIG_DEPTH {
        return CilType::Unknown(0xFF);
    }
    if *pos >= bytes.len() {
        return CilType::Unknown(0xFF);
    }
    let tag = bytes[*pos];
    *pos += 1;
    match CorElementType::from_byte(tag) {
        Some(CorElementType::Void)     => CilType::Void,
        Some(CorElementType::Boolean)  => CilType::Boolean,
        Some(CorElementType::Char)     => CilType::Char,
        Some(CorElementType::I1)       => CilType::Int8,
        Some(CorElementType::U1)       => CilType::UInt8,
        Some(CorElementType::I2)       => CilType::Int16,
        Some(CorElementType::U2)       => CilType::UInt16,
        Some(CorElementType::I4)       => CilType::Int32,
        Some(CorElementType::U4)       => CilType::UInt32,
        Some(CorElementType::I8)       => CilType::Int64,
        Some(CorElementType::U8)       => CilType::UInt64,
        Some(CorElementType::R4)       => CilType::Single,
        Some(CorElementType::R8)       => CilType::Double,
        Some(CorElementType::String)   => CilType::String,
        Some(CorElementType::Object)   => CilType::Object,
        Some(CorElementType::TypedByRef) => CilType::TypedRef,
        Some(CorElementType::I)        => CilType::IntPtr,
        Some(CorElementType::U)        => CilType::UIntPtr,
        Some(CorElementType::Ptr) => {
            let inner = parse_sig_type_inner(bytes, pos, depth + 1);
            CilType::Ptr(Box::new(inner))
        }
        Some(CorElementType::ByRef) => {
            let inner = parse_sig_type_inner(bytes, pos, depth + 1);
            CilType::ByRef(Box::new(inner))
        }
        Some(CorElementType::SzArray) => {
            let inner = parse_sig_type_inner(bytes, pos, depth + 1);
            CilType::SzArray(Box::new(inner))
        }
        Some(CorElementType::ValueType) => {
            let name = decode_type_def_or_ref_encoded(bytes, pos)
                .unwrap_or_else(|| "?".to_string());
            CilType::ValueType(name)
        }
        Some(CorElementType::Class) => {
            let name = decode_type_def_or_ref_encoded(bytes, pos)
                .unwrap_or_else(|| "?".to_string());
            CilType::Class(name)
        }
        Some(CorElementType::Var) => {
            let (idx, n) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
            *pos += n;
            CilType::Var(idx)
        }
        Some(CorElementType::MVar) => {
            let (idx, n) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
            *pos += n;
            CilType::MVar(idx)
        }
        Some(CorElementType::Array) => {
            let element = parse_sig_type_inner(bytes, pos, depth + 1);
            // rank
            let (rank, rn) = decode_compressed_uint(bytes, *pos).unwrap_or((1, 1));
            *pos += rn;
            // numSizes — cap to remaining blob length to prevent unbounded iteration
            let (num_sizes, sn) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
            *pos += sn;
            let num_sizes = (num_sizes as usize).min(bytes.len().saturating_sub(*pos));
            for _ in 0..num_sizes {
                let (_, sz) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
                *pos += sz;
            }
            // numLoBounds
            let (num_lo, ln) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
            *pos += ln;
            let num_lo = (num_lo as usize).min(bytes.len().saturating_sub(*pos));
            for _ in 0..num_lo {
                let (_, lsz) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
                *pos += lsz;
            }
            CilType::Array { element: Box::new(element), rank }
        }
        Some(CorElementType::GenericInst) => {
            // CLASS or VALUETYPE tag
            if *pos < bytes.len() {
                *pos += 1; // skip CLASS/VALUETYPE byte
            }
            let name = decode_type_def_or_ref_encoded(bytes, pos)
                .unwrap_or_else(|| "?".to_string());
            let (arg_count, n) = decode_compressed_uint(bytes, *pos).unwrap_or((0, 1));
            *pos += n;
            // Cap arg_count to the remaining blob length to prevent OOM allocation.
            let arg_count = (arg_count as usize).min(bytes.len().saturating_sub(*pos));
            let args: Vec<CilType> = (0..arg_count)
                .map(|_| parse_sig_type_inner(bytes, pos, depth + 1))
                .collect();
            CilType::Generic(name, args)
        }
        _ => CilType::Unknown(tag),
    }
}

// ── Calling convention ────────────────────────────────────────────────────────

/// CIL method calling conventions (§II.23.1.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallingConv {
    Default,
    C,
    StdCall,
    ThisCall,
    FastCall,
    VarArg,
    Generic,
    Unmanaged,
    HasThis,
    ExplicitThis,
    Unknown(u8),
}

impl CallingConv {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        // Mask off HAS_THIS / EXPLICIT_THIS for base calling conv.
        match b & 0x0F {
            0x00 => Self::Default,
            0x01 => Self::C,
            0x02 => Self::StdCall,
            0x03 => Self::ThisCall,
            0x04 => Self::FastCall,
            0x05 => Self::VarArg,
            0x10 => Self::Generic,
            _ => Self::Unknown(b),
        }
    }
}

/// Parse a method signature blob.
///
/// Returns `(calling_convention, parameter_types, return_type)`.
#[must_use]
pub fn parse_method_sig(bytes: &[u8]) -> (CallingConv, Vec<CilType>, CilType) {
    if bytes.is_empty() {
        return (CallingConv::Default, Vec::new(), CilType::Void);
    }
    let mut pos = 0usize;
    let conv_byte = bytes[pos];
    pos += 1;
    let conv = CallingConv::from_byte(conv_byte);

    // If GENERIC, skip generic param count.
    let is_generic = (conv_byte & 0x10) != 0;
    if is_generic
        && let Some((_, n)) = decode_compressed_uint(bytes, pos) {
            pos += n;
        }

    // Param count.
    let (param_count, n) = decode_compressed_uint(bytes, pos).unwrap_or((0, 1));
    pos += n;

    // Return type.
    let ret = parse_sig_type(bytes, &mut pos);

    // Parameter types.
    let params: Vec<CilType> = (0..param_count)
        .map(|_| parse_sig_type(bytes, &mut pos))
        .collect();

    (conv, params, ret)
}

// ── CilTypeSystem ─────────────────────────────────────────────────────────────

/// Registry of resolved type names (stubbed — full resolution requires metadata).
pub struct CilTypeSystem {
    known_types: std::collections::HashMap<String, CilType>,
}

impl CilTypeSystem {
    #[must_use]
    pub fn new() -> Self {
        let mut known_types = std::collections::HashMap::new();
        known_types.insert("System.String".to_string(), CilType::String);
        known_types.insert("System.Object".to_string(), CilType::Object);
        known_types.insert("System.Int32".to_string(),  CilType::Int32);
        known_types.insert("System.Boolean".to_string(), CilType::Boolean);
        known_types.insert("System.Void".to_string(),   CilType::Void);
        Self { known_types }
    }

    /// Register a known type mapping.
    pub fn register(&mut self, name: String, ty: CilType) {
        self.known_types.insert(name, ty);
    }

    /// Look up a type by its full .NET name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&CilType> {
        self.known_types.get(name)
    }

    /// Parse a type from a raw signature blob.
    #[must_use]
    pub fn parse_type(&self, bytes: &[u8]) -> CilType {
        let mut pos = 0;
        parse_sig_type(bytes, &mut pos)
    }

    /// Parse a method signature blob.
    #[must_use]
    pub fn parse_method(&self, bytes: &[u8]) -> (CallingConv, Vec<CilType>, CilType) {
        parse_method_sig(bytes)
    }
}

impl Default for CilTypeSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cor_element_type_roundtrip() {
        for b in [0x01u8, 0x08, 0x0E, 0x12, 0x1D] {
            assert!(CorElementType::from_byte(b).is_some(), "byte {b:#04x} not found");
        }
    }

    #[test]
    fn parse_sig_type_void() {
        let blob = [0x01u8]; // ELEMENT_TYPE_VOID
        let mut pos = 0;
        assert_eq!(parse_sig_type(&blob, &mut pos), CilType::Void);
        assert_eq!(pos, 1);
    }

    #[test]
    fn parse_sig_type_int32() {
        let blob = [0x08u8];
        let mut pos = 0;
        assert_eq!(parse_sig_type(&blob, &mut pos), CilType::Int32);
    }

    #[test]
    fn parse_sig_type_szarray_int32() {
        let blob = [0x1Du8, 0x08u8]; // SZARRAY I4
        let mut pos = 0;
        let t = parse_sig_type(&blob, &mut pos);
        assert_eq!(t, CilType::SzArray(Box::new(CilType::Int32)));
    }

    #[test]
    fn parse_sig_type_ptr_bool() {
        let blob = [0x0Fu8, 0x02u8]; // PTR BOOLEAN
        let mut pos = 0;
        let t = parse_sig_type(&blob, &mut pos);
        assert_eq!(t, CilType::Ptr(Box::new(CilType::Boolean)));
    }

    #[test]
    fn parse_sig_type_byref_string() {
        let blob = [0x10u8, 0x0Eu8]; // BYREF STRING
        let mut pos = 0;
        let t = parse_sig_type(&blob, &mut pos);
        assert_eq!(t, CilType::ByRef(Box::new(CilType::String)));
    }

    #[test]
    fn parse_sig_type_var() {
        let blob = [0x13u8, 0x02u8]; // VAR 2
        let mut pos = 0;
        let t = parse_sig_type(&blob, &mut pos);
        assert_eq!(t, CilType::Var(2));
    }

    #[test]
    fn parse_sig_type_mvar() {
        let blob = [0x1Eu8, 0x00u8]; // MVAR 0
        let mut pos = 0;
        let t = parse_sig_type(&blob, &mut pos);
        assert_eq!(t, CilType::MVar(0));
    }

    #[test]
    fn parse_method_sig_no_args() {
        // DEFAULT 0 VOID  = 0x00 0x00 0x01
        let blob = [0x00u8, 0x00, 0x01];
        let (conv, params, ret) = parse_method_sig(&blob);
        assert_eq!(conv, CallingConv::Default);
        assert!(params.is_empty());
        assert_eq!(ret, CilType::Void);
    }

    #[test]
    fn parse_method_sig_one_arg() {
        // DEFAULT 1 I4 I4
        let blob = [0x00u8, 0x01, 0x08, 0x08];
        let (_, params, ret) = parse_method_sig(&blob);
        assert_eq!(ret, CilType::Int32);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], CilType::Int32);
    }

    #[test]
    fn type_size_primitives() {
        assert_eq!(type_size_in_bytes(&CilType::Boolean), Some(1));
        assert_eq!(type_size_in_bytes(&CilType::Int32), Some(4));
        assert_eq!(type_size_in_bytes(&CilType::Int64), Some(8));
        assert_eq!(type_size_in_bytes(&CilType::Void), None);
    }

    #[test]
    fn is_value_type_primitives() {
        assert!(CilType::Int32.is_value_type());
        assert!(!CilType::String.is_value_type());
    }

    #[test]
    fn is_reference_type_class() {
        assert!(CilType::Class("System.Foo".to_string()).is_reference_type());
        assert!(!CilType::Int32.is_reference_type());
    }

    #[test]
    fn pointee_ptr() {
        let t = CilType::Ptr(Box::new(CilType::Int32));
        assert_eq!(t.pointee(), Some(&CilType::Int32));
    }

    #[test]
    fn display_szarray() {
        let t = CilType::SzArray(Box::new(CilType::Int32));
        assert_eq!(t.to_string(), "int32[]");
    }

    #[test]
    fn type_system_lookup() {
        let ts = CilTypeSystem::new();
        assert_eq!(ts.lookup("System.String"), Some(&CilType::String));
        assert!(ts.lookup("Unknown.Type").is_none());
    }

    #[test]
    fn calling_conv_from_byte() {
        assert_eq!(CallingConv::from_byte(0x00), CallingConv::Default);
        assert_eq!(CallingConv::from_byte(0x05), CallingConv::VarArg);
    }

    #[test]
    fn decode_compressed_uint_1byte() {
        let (v, n) = decode_compressed_uint(&[0x05], 0).unwrap();
        assert_eq!(v, 5);
        assert_eq!(n, 1);
    }

    #[test]
    fn decode_compressed_uint_2byte() {
        let (v, n) = decode_compressed_uint(&[0x81, 0x00], 0).unwrap();
        assert_eq!(v, 256);
        assert_eq!(n, 2);
    }
}
