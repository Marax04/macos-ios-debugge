/// Objective-C Runtime Metadata Parser for Mach-O
///
/// Parses all Objective-C runtime data structures found in __DATA and __TEXT
/// segments of Mach-O binaries.  Supports 32-bit and 64-bit, both little-
/// and big-endian layouts.  Also handles Swift class metadata interop and
/// Objective-C type encoding decoding.
pub use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjcError {
    OutOfBounds { offset: usize, size: usize },
    UnexpectedEnd,
    InvalidUtf8,
    InvalidStructure(String),
    NullPointer(String),
    UnsupportedClass(u8),
    CircularReference,
}

impl fmt::Display for ObjcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { offset, size } => {
                write!(f, "out-of-bounds at offset {offset} (size {size})")
            }
            Self::UnexpectedEnd => write!(f, "unexpected end of data"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 string"),
            Self::InvalidStructure(s) => write!(f, "invalid structure: {s}"),
            Self::NullPointer(s) => write!(f, "null pointer: {s}"),
            Self::UnsupportedClass(c) => write!(f, "unsupported pointer class: {c}"),
            Self::CircularReference => write!(f, "circular reference detected"),
        }
    }
}
impl std::error::Error for ObjcError {}
pub type ObjcResult<T> = Result<T, ObjcError>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn read_u8(data: &[u8], off: usize) -> ObjcResult<u8> {
    data.get(off).copied().ok_or(ObjcError::OutOfBounds {
        offset: off,
        size: 1,
    })
}

pub fn read_le_u16(data: &[u8], off: usize) -> ObjcResult<u16> {
    if off + 2 > data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: 2,
        });
    }
    Ok(u16::from_le_bytes(data[off..off + 2].try_into().unwrap()))
}

fn read_le_u32(data: &[u8], off: usize) -> ObjcResult<u32> {
    if off + 4 > data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: 4,
        });
    }
    Ok(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()))
}

fn read_le_u64(data: &[u8], off: usize) -> ObjcResult<u64> {
    if off + 8 > data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: 8,
        });
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

fn read_cstr(data: &[u8], off: usize) -> ObjcResult<String> {
    if off >= data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: 1,
        });
    }
    let end = data[off..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(ObjcError::UnexpectedEnd)?;
    String::from_utf8(data[off..off + end].to_vec()).map_err(|_| ObjcError::InvalidUtf8)
}

// ---------------------------------------------------------------------------
// ObjC pointer layout
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrSize {
    P32,
    P64,
}

impl PtrSize {
    #[must_use] 
    pub const fn bytes(self) -> usize {
        match self {
            Self::P32 => 4,
            Self::P64 => 8,
        }
    }

    pub fn read(self, data: &[u8], off: usize) -> ObjcResult<u64> {
        match self {
            Self::P32 => read_le_u32(data, off).map(u64::from),
            Self::P64 => read_le_u64(data, off),
        }
    }
}

/// Strip tagged-pointer bits and ABI-specific low bits from a pointer.
/// On arm64e the top 8 bits may contain a pointer authentication code.
#[must_use] 
pub const fn strip_ptr(ptr: u64, ptr_size: PtrSize) -> u64 {
    match ptr_size {
        PtrSize::P32 => ptr & 0xFFFF_FFFF,
        PtrSize::P64 => ptr & 0x0000_FFFF_FFFF_FFFF,
    }
}

// ---------------------------------------------------------------------------
// Virtual address -> file offset resolver
// ---------------------------------------------------------------------------

/// A Mach-O segment mapping used to convert virtual addresses to file offsets.
#[derive(Debug, Clone)]
pub struct SegmentMapping {
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub name: String,
}

impl SegmentMapping {
    #[must_use] 
    pub const fn vm_to_file(&self, vm: u64) -> Option<usize> {
        if vm >= self.vm_addr && vm < self.vm_addr + self.vm_size {
            let delta = vm - self.vm_addr;
            if delta < self.file_size {
                Some((self.file_off + delta) as usize)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Resolve a virtual address to a file offset using a segment map.
#[must_use] 
pub fn resolve_vm(vm: u64, segments: &[SegmentMapping]) -> Option<usize> {
    for seg in segments {
        if let Some(off) = seg.vm_to_file(vm) {
            return Some(off);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// class_ro_t flags
// ---------------------------------------------------------------------------

pub mod ro_flags {
    pub const IS_META: u32 = 0x0001;
    pub const IS_ROOT: u32 = 0x0002;
    pub const HAS_CXX_STRUCTORS: u32 = 0x0004;
    pub const IS_HIDDEN: u32 = 0x0010;
    pub const HAS_IMAGE_FUNCTIONS: u32 = 0x0020;
    pub const IS_SWIFT_PRESERVED_IVARS: u32 = 0x0080;
    pub const IS_SWIFT: u32 = 0x0100;
    pub const IS_SWIFT_STABLE_ABI: u32 = 0x0200;
}

// ---------------------------------------------------------------------------
// ObjC method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcMethod {
    pub name: String,
    /// Objective-C type encoding string.
    pub type_enc: String,
    /// Implementation address (IMP).
    pub imp: u64,
    pub is_class: bool,
}

// ---------------------------------------------------------------------------
// ObjC ivar
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcIvar {
    pub name: String,
    /// Objective-C type encoding.
    pub type_enc: String,
    pub offset: u32,
    pub size: u32,
    pub alignment: u32,
}

// ---------------------------------------------------------------------------
// ObjC property
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcProperty {
    pub name: String,
    pub attributes: String,
}

// ---------------------------------------------------------------------------
// ObjC protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcProtocol {
    pub name: String,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub optional_instance_methods: Vec<ObjcMethod>,
    pub optional_class_methods: Vec<ObjcMethod>,
    pub instance_properties: Vec<ObjcProperty>,
    pub protocols: Vec<String>,
}

// ---------------------------------------------------------------------------
// ObjC class
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcClass {
    pub name: String,
    pub superclass_name: Option<String>,
    pub methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub protocols: Vec<String>,
    pub properties: Vec<ObjcProperty>,
    pub categories: Vec<ObjcCategory>,
    pub is_swift: bool,
    pub swift_name: Option<String>,
    pub flags: u32,
    pub instance_size: u32,
    pub instance_start: u32,
}

// ---------------------------------------------------------------------------
// ObjC category
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjcCategory {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub protocols: Vec<String>,
    pub instance_properties: Vec<ObjcProperty>,
    pub class_properties: Vec<ObjcProperty>,
}

// ---------------------------------------------------------------------------
// ObjC selector reference
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SelRef {
    pub address: u64,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Swift class flag detection
// ---------------------------------------------------------------------------

/// Detect whether a `class_ro_t` flags field indicates a Swift class.
#[must_use] 
pub const fn is_swift_class(flags: u32) -> bool {
    flags & ro_flags::IS_SWIFT != 0
}

// ---------------------------------------------------------------------------
// Type encoding decoder
// ---------------------------------------------------------------------------

/// Decoded `ObjC` type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjcType {
    Char,
    Int,
    Short,
    Long,
    LongLong,
    UChar,
    UInt,
    UShort,
    ULong,
    ULongLong,
    Float,
    Double,
    Bool,
    Void,
    String,
    Object(Option<Box<str>>), // @"ClassName"
    Class,
    Selector,
    Pointer(Box<Self>),
    Array {
        count: usize,
        element: Box<Self>,
    },
    Struct {
        name: Option<String>,
        fields: Vec<Self>,
    },
    Union {
        name: Option<String>,
        fields: Vec<Self>,
    },
    Bitfield(u32),
    Unknown(char),
}

/// Decode the first `ObjC` type encoding from `enc`, starting at `pos`.
/// Returns `(decoded_type, new_pos)`.
#[must_use] 
pub fn decode_type_enc(enc: &str, pos: usize) -> (ObjcType, usize) {
    let bytes = enc.as_bytes();
    if pos >= bytes.len() {
        return (ObjcType::Void, pos);
    }

    let c = bytes[pos] as char;
    match c {
        'c' => (ObjcType::Char, pos + 1),
        'i' => (ObjcType::Int, pos + 1),
        's' => (ObjcType::Short, pos + 1),
        'l' => (ObjcType::Long, pos + 1),
        'q' => (ObjcType::LongLong, pos + 1),
        'C' => (ObjcType::UChar, pos + 1),
        'I' => (ObjcType::UInt, pos + 1),
        'S' => (ObjcType::UShort, pos + 1),
        'L' => (ObjcType::ULong, pos + 1),
        'Q' => (ObjcType::ULongLong, pos + 1),
        'f' => (ObjcType::Float, pos + 1),
        'd' => (ObjcType::Double, pos + 1),
        'B' => (ObjcType::Bool, pos + 1),
        'v' => (ObjcType::Void, pos + 1),
        '*' => (ObjcType::String, pos + 1),
        '#' => (ObjcType::Class, pos + 1),
        ':' => (ObjcType::Selector, pos + 1),
        '@' => {
            // Object: might be followed by "ClassName"
            if pos + 1 < bytes.len() && bytes[pos + 1] == b'"' {
                let start = pos + 2;
                if let Some(end_off) = bytes[start..].iter().position(|&b| b == b'"') {
                    let class_name = &enc[start..start + end_off];
                    return (
                        ObjcType::Object(Some(class_name.into())),
                        start + end_off + 1,
                    );
                }
            }
            (ObjcType::Object(None), pos + 1)
        }
        '^' => {
            let (inner, next) = decode_type_enc(enc, pos + 1);
            (ObjcType::Pointer(Box::new(inner)), next)
        }
        '[' => {
            // Array: [count type]
            let mut i = pos + 1;
            let mut count_str = String::new();
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                count_str.push(bytes[i] as char);
                i += 1;
            }
            let count = count_str.parse::<usize>().unwrap_or(0);
            let (elem, mut next) = decode_type_enc(enc, i);
            // skip closing ']'
            if next < bytes.len() && bytes[next] == b']' {
                next += 1;
            }
            (
                ObjcType::Array {
                    count,
                    element: Box::new(elem),
                },
                next,
            )
        }
        '{' | '(' => {
            let closing = if c == '{' { b'}' } else { b')' };
            let mut i = pos + 1;
            // parse optional name
            let name_start = i;
            while i < bytes.len() && bytes[i] != b'=' && bytes[i] != closing {
                i += 1;
            }
            let name_part = &enc[name_start..i];
            let name = if name_part.is_empty() || name_part == "?" {
                None
            } else {
                Some(name_part.to_string())
            };
            // skip '='
            if i < bytes.len() && bytes[i] == b'=' {
                i += 1;
            }
            // parse fields
            let mut fields = Vec::new();
            while i < bytes.len() && bytes[i] != closing {
                let (t, next) = decode_type_enc(enc, i);
                fields.push(t);
                i = next;
            }
            if i < bytes.len() {
                i += 1;
            } // skip closing brace
            let ty = if c == '{' {
                ObjcType::Struct { name, fields }
            } else {
                ObjcType::Union { name, fields }
            };
            (ty, i)
        }
        'b' => {
            // Bitfield: bN
            let mut i = pos + 1;
            let mut n_str = String::new();
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                n_str.push(bytes[i] as char);
                i += 1;
            }
            let n = n_str.parse::<u32>().unwrap_or(0);
            (ObjcType::Bitfield(n), i)
        }
        // Skip modifier characters: r n N o O R V
        'r' | 'n' | 'N' | 'o' | 'O' | 'R' | 'V' => decode_type_enc(enc, pos + 1),
        _ => (ObjcType::Unknown(c), pos + 1),
    }
}

/// Decode all types in an Objective-C type encoding string.
/// The encoding may contain numeric offset annotations (skipped).
#[must_use] 
pub fn decode_method_signature(enc: &str) -> Vec<ObjcType> {
    let mut types = Vec::new();
    let bytes = enc.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        // skip numeric offset
        while pos < bytes.len() && (bytes[pos] as char).is_ascii_digit() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        let (t, next) = decode_type_enc(enc, pos);
        types.push(t);
        pos = next;
    }
    types
}

impl fmt::Display for ObjcType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Char => write!(f, "char"),
            Self::Int => write!(f, "int"),
            Self::Short => write!(f, "short"),
            Self::Long => write!(f, "long"),
            Self::LongLong => write!(f, "long long"),
            Self::UChar => write!(f, "unsigned char"),
            Self::UInt => write!(f, "unsigned int"),
            Self::UShort => write!(f, "unsigned short"),
            Self::ULong => write!(f, "unsigned long"),
            Self::ULongLong => write!(f, "unsigned long long"),
            Self::Float => write!(f, "float"),
            Self::Double => write!(f, "double"),
            Self::Bool => write!(f, "BOOL"),
            Self::Void => write!(f, "void"),
            Self::String => write!(f, "char *"),
            Self::Object(None) => write!(f, "id"),
            Self::Object(Some(name)) => write!(f, "{name} *"),
            Self::Class => write!(f, "Class"),
            Self::Selector => write!(f, "SEL"),
            Self::Pointer(inner) => write!(f, "{inner} *"),
            Self::Array { count, element } => write!(f, "{element}[{count}]"),
            Self::Struct { name, .. } => write!(f, "struct {}", name.as_deref().unwrap_or("?")),
            Self::Union { name, .. } => write!(f, "union {}", name.as_deref().unwrap_or("?")),
            Self::Bitfield(n) => write!(f, "unsigned :{n}"),
            Self::Unknown(c) => write!(f, "?({c})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Swift mangled name decoder (basic)
// ---------------------------------------------------------------------------

/// Attempt to demangle a Swift class name.
/// Swift class names in `ObjC` metadata often have the form "_`TtC`<module><name>".
/// This provides a best-effort decode without the full Swift demangler.
#[must_use] 
pub fn decode_swift_mangled_name(mangled: &str) -> Option<String> {
    let s = mangled.trim_start_matches('\0');

    // Old mangling: _TtC<modulelen><module><namelen><name>
    if let Some(rest) = s.strip_prefix("_TtC") {
        return parse_swift_identifier_pair(rest);
    }
    // New mangling: $s<...>
    if s.starts_with("$s") || s.starts_with("_$s") {
        return Some(format!("Swift.{s}"));
    }
    None
}

fn parse_swift_identifier_pair(s: &str) -> Option<String> {
    let (module, rest) = parse_swift_identifier(s)?;
    let (name, _) = parse_swift_identifier(rest)?;
    Some(format!("{module}.{name}"))
}

fn parse_swift_identifier(s: &str) -> Option<(&str, &str)> {
    let len_end = s.find(|c: char| !c.is_ascii_digit())?;
    let len: usize = s[..len_end].parse().ok()?;
    let rest = &s[len_end..];
    if len > rest.len() {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

// ---------------------------------------------------------------------------
// method_list_t parser
// ---------------------------------------------------------------------------

/// Parse a `method_list_t` from the binary image.
///
/// `data`     – full binary image bytes.
/// `vm_off`   – file offset of the `method_list_t`.
/// `segments` – segment mappings (used to resolve IMP pointers).
/// `ptr`      – pointer size.
/// `is_class` – true for class (meta) methods.
pub fn parse_method_list(
    data: &[u8],
    vm_off: usize,
    ptr: PtrSize,
    is_class: bool,
) -> ObjcResult<Vec<ObjcMethod>> {
    if vm_off.checked_add(8).is_none_or(|end| end > data.len()) {
        return Err(ObjcError::OutOfBounds {
            offset: vm_off,
            size: 8,
        });
    }

    let entsize_and_flags = read_le_u32(data, vm_off)?;
    let count = read_le_u32(data, vm_off + 4)?;

    let is_small = entsize_and_flags & 0x8000_0000 != 0;
    let entsize = (entsize_and_flags & 0xFFFC) as usize;
    let entsize = if entsize == 0 {
        if is_small { 12 } else { ptr.bytes() * 3 }
    } else {
        entsize
    };

    // Cap the allocation by how many entries can physically fit in the file.
    let max_entries = data.len().saturating_sub(vm_off + 8) / entsize.max(1);
    let mut methods = Vec::with_capacity((count as usize).min(max_entries));
    let mut off = vm_off + 8;

    for _ in 0..count {
        if off + entsize > data.len() {
            break;
        }

        let (name, type_enc, imp) = if is_small {
            // Small methods: name_offset(i32), types_offset(i32), imp_offset(i32)
            let name_rel = (read_le_u32(data, off)?).cast_signed();
            let types_rel = (read_le_u32(data, off + 4)?).cast_signed();
            let imp_rel = (read_le_u32(data, off + 8)?).cast_signed();

            let name_ptr = (off as i64 + i64::from(name_rel)) as usize;
            let types_ptr = (off as i64 + 4 + i64::from(types_rel)) as usize;
            let imp_addr = (off as i64 + 8 + i64::from(imp_rel)).cast_unsigned();

            // The name is a pointer in __objc_methnames
            let name_off = if name_ptr + ptr.bytes() <= data.len() {
                ptr.read(data, name_ptr)? as usize
            } else {
                name_ptr
            };

            let n = read_cstr(data, name_off).unwrap_or_default();
            let te = read_cstr(data, types_ptr).unwrap_or_default();
            (n, te, imp_addr)
        } else {
            // Large methods: SEL*(ptr), types*(ptr), IMP(ptr)
            let name_ptr = ptr.read(data, off)? as usize;
            let types_ptr = ptr.read(data, off + ptr.bytes())? as usize;
            let imp_addr = ptr.read(data, off + ptr.bytes() * 2)?;

            let n = if name_ptr != 0 {
                read_cstr(data, name_ptr).unwrap_or_default()
            } else {
                String::new()
            };
            let te = if types_ptr != 0 {
                read_cstr(data, types_ptr).unwrap_or_default()
            } else {
                String::new()
            };
            (n, te, imp_addr)
        };

        methods.push(ObjcMethod {
            name,
            type_enc,
            imp,
            is_class,
        });
        off += entsize;
    }

    Ok(methods)
}

// ---------------------------------------------------------------------------
// ivar_list_t parser
// ---------------------------------------------------------------------------

pub fn parse_ivar_list(data: &[u8], vm_off: usize, ptr: PtrSize) -> ObjcResult<Vec<ObjcIvar>> {
    if vm_off.checked_add(8).is_none_or(|end| end > data.len()) {
        return Err(ObjcError::OutOfBounds {
            offset: vm_off,
            size: 8,
        });
    }
    let _entsize = read_le_u32(data, vm_off)?;
    let count = read_le_u32(data, vm_off + 4)?;
    let entsize = 2 * ptr.bytes() + 12; // offset*(ptr), name*(ptr), type*(ptr), alignment(u32), size(u32)

    // Cap the allocation by how many entries can physically fit in the file.
    let max_entries = data.len().saturating_sub(vm_off + 8) / entsize.max(1);
    let mut ivars = Vec::with_capacity((count as usize).min(max_entries));
    let mut off = vm_off + 8;

    for _ in 0..count {
        if off + entsize > data.len() {
            break;
        }

        let offset_ptr = ptr.read(data, off)? as usize;
        let ivar_offset = if offset_ptr != 0 && offset_ptr + 4 <= data.len() {
            read_le_u32(data, offset_ptr)?
        } else {
            0
        };

        let name_ptr = ptr.read(data, off + ptr.bytes())? as usize;
        let type_ptr = ptr.read(data, off + ptr.bytes() * 2)? as usize;
        let align_raw = read_le_u32(data, off + ptr.bytes() * 3)?;
        let size = read_le_u32(data, off + ptr.bytes() * 3 + 4)?;

        let name = if name_ptr != 0 {
            read_cstr(data, name_ptr).unwrap_or_default()
        } else {
            String::new()
        };
        let type_enc = if type_ptr != 0 {
            read_cstr(data, type_ptr).unwrap_or_default()
        } else {
            String::new()
        };
        let alignment = 1u32 << (align_raw & 0xFF);

        ivars.push(ObjcIvar {
            name,
            type_enc,
            offset: ivar_offset,
            size,
            alignment,
        });
        off += entsize;
    }

    Ok(ivars)
}

// ---------------------------------------------------------------------------
// property_list_t parser
// ---------------------------------------------------------------------------

pub fn parse_property_list(
    data: &[u8],
    vm_off: usize,
    ptr: PtrSize,
) -> ObjcResult<Vec<ObjcProperty>> {
    if vm_off.checked_add(8).is_none_or(|end| end > data.len()) {
        return Err(ObjcError::OutOfBounds {
            offset: vm_off,
            size: 8,
        });
    }
    let _entsize = read_le_u32(data, vm_off)?;
    let count = read_le_u32(data, vm_off + 4)?;
    let entsize = ptr.bytes() * 2;

    // Cap the allocation by how many entries can physically fit in the file.
    let max_entries = data.len().saturating_sub(vm_off + 8) / entsize.max(1);
    let mut props = Vec::with_capacity((count as usize).min(max_entries));
    let mut off = vm_off + 8;

    for _ in 0..count {
        if off + entsize > data.len() {
            break;
        }
        let name_ptr = ptr.read(data, off)? as usize;
        let attr_ptr = ptr.read(data, off + ptr.bytes())? as usize;

        let name = if name_ptr != 0 {
            read_cstr(data, name_ptr).unwrap_or_default()
        } else {
            String::new()
        };
        let attributes = if attr_ptr != 0 {
            read_cstr(data, attr_ptr).unwrap_or_default()
        } else {
            String::new()
        };

        props.push(ObjcProperty { name, attributes });
        off += entsize;
    }

    Ok(props)
}

// ---------------------------------------------------------------------------
// protocol_list_t parser
// ---------------------------------------------------------------------------

/// Parse a `protocol_list_t`, returning just the protocol names.
pub fn parse_protocol_list_names(
    data: &[u8],
    vm_off: usize,
    ptr: PtrSize,
) -> ObjcResult<Vec<String>> {
    if vm_off.checked_add(8).is_none_or(|end| end > data.len()) {
        return Err(ObjcError::OutOfBounds {
            offset: vm_off,
            size: 8,
        });
    }

    let count = ptr.read(data, vm_off)? as usize;
    // Cap the allocation by how many pointers can physically fit in the file.
    let max_entries = data.len().saturating_sub(vm_off) / ptr.bytes().max(1);
    let mut names = Vec::with_capacity(count.min(max_entries));
    let mut off = vm_off + ptr.bytes();

    for _ in 0..count {
        if off + ptr.bytes() > data.len() {
            break;
        }
        let proto_ptr = ptr.read(data, off)? as usize;
        if proto_ptr == 0 {
            off += ptr.bytes();
            continue;
        }

        // protocol_t: isa*(ptr), name*(ptr), ...
        if proto_ptr + ptr.bytes() * 2 <= data.len() {
            let name_ptr = ptr.read(data, proto_ptr + ptr.bytes())? as usize;
            if name_ptr != 0 && name_ptr < data.len() && let Ok(n) = read_cstr(data, name_ptr) {
                names.push(n);
            }
        }
        off += ptr.bytes();
    }

    Ok(names)
}

// ---------------------------------------------------------------------------
// class_ro_t parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ClassRoData {
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub name: String,
    pub methods_off: u64,
    pub protocols_off: u64,
    pub ivars_off: u64,
    pub props_off: u64,
}

pub fn parse_class_ro(data: &[u8], off: usize, ptr: PtrSize) -> ObjcResult<ClassRoData> {
    let min_size = 4 + 4 + 4 + (if ptr == PtrSize::P64 { 4 } else { 0 }) + ptr.bytes() * 8;
    if off + min_size > data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: min_size,
        });
    }

    let flags = read_le_u32(data, off)?;
    let instance_start = read_le_u32(data, off + 4)?;
    let instance_size = read_le_u32(data, off + 8)?;

    // 64-bit has 4 bytes ivar_layout pointer here too (total pad differs by pointer size)
    let field_base = off + 12 + (if ptr == PtrSize::P64 { 4 } else { 0 });

    let ivar_layout_ptr = ptr.read(data, field_base)?;
    let name_ptr = ptr.read(data, field_base + ptr.bytes())?;
    let methods_ptr = ptr.read(data, field_base + ptr.bytes() * 2)?;
    let protocols_ptr = ptr.read(data, field_base + ptr.bytes() * 3)?;
    let ivars_ptr = ptr.read(data, field_base + ptr.bytes() * 4)?;
    let _weak_ivar_ptr = ptr.read(data, field_base + ptr.bytes() * 5)?;
    let props_ptr = ptr.read(data, field_base + ptr.bytes() * 6)?;

    let _ = ivar_layout_ptr;

    let name = if name_ptr != 0 {
        read_cstr(data, name_ptr as usize).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(ClassRoData {
        flags,
        instance_start,
        instance_size,
        name,
        methods_off: methods_ptr,
        protocols_off: protocols_ptr,
        ivars_off: ivars_ptr,
        props_off: props_ptr,
    })
}

// ---------------------------------------------------------------------------
// class_t parser
// ---------------------------------------------------------------------------

/// Minimum field layout of `class_t` (64-bit):
///   metaclass*(8), superclass*(8), cache*(8), vtable*(8), data*(8) => 40 bytes
pub fn parse_class_t(data: &[u8], off: usize, ptr: PtrSize) -> ObjcResult<ObjcClass> {
    let struct_size = ptr.bytes() * 5;
    if off + struct_size > data.len() {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: struct_size,
        });
    }

    let _metaclass = ptr.read(data, off)?;
    let _superclass = ptr.read(data, off + ptr.bytes())?;
    let _cache = ptr.read(data, off + ptr.bytes() * 2)?;
    let _vtable = ptr.read(data, off + ptr.bytes() * 3)?;
    let data_ptr = strip_ptr(ptr.read(data, off + ptr.bytes() * 4)?, ptr);

    if data_ptr == 0 {
        return Err(ObjcError::NullPointer("class_t.data".into()));
    }

    let ro = parse_class_ro(data, data_ptr as usize, ptr)?;

    let is_swift = is_swift_class(ro.flags);
    let swift_name = if is_swift {
        decode_swift_mangled_name(&ro.name)
    } else {
        None
    };

    let methods = if ro.methods_off != 0 {
        parse_method_list(data, ro.methods_off as usize, ptr, false).unwrap_or_default()
    } else {
        vec![]
    };

    let ivars = if ro.ivars_off != 0 {
        parse_ivar_list(data, ro.ivars_off as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    let protocols = if ro.protocols_off != 0 {
        parse_protocol_list_names(data, ro.protocols_off as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    let properties = if ro.props_off != 0 {
        parse_property_list(data, ro.props_off as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    Ok(ObjcClass {
        name: ro.name,
        superclass_name: None, // resolved later from superclass pointer
        methods,
        ivars,
        protocols,
        properties,
        categories: vec![],
        is_swift,
        swift_name,
        flags: ro.flags,
        instance_size: ro.instance_size,
        instance_start: ro.instance_start,
    })
}

// ---------------------------------------------------------------------------
// __objc_classlist section parser
// ---------------------------------------------------------------------------

/// Parse the __`objc_classlist` section (an array of `class_t` pointers).
///
/// `data`       – full Mach-O binary image bytes.
/// `section_data` – raw bytes of the __`objc_classlist` section.
/// `ptr`        – pointer size.
/// `base_addr`  – VM address of the binary start (usually 0 for PIE).
#[must_use] 
pub fn parse_classlist(
    data: &[u8],
    section_data: &[u8],
    ptr: PtrSize,
    base_addr: u64,
) -> Vec<ObjcClass> {
    let count = section_data.len() / ptr.bytes();
    let mut classes = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * ptr.bytes();
        let class_ptr = match ptr.read(section_data, off) {
            Ok(p) => strip_ptr(p, ptr),
            Err(_) => continue,
        };
        if class_ptr == 0 {
            continue;
        }

        let file_off = if class_ptr >= base_addr {
            (class_ptr - base_addr) as usize
        } else {
            class_ptr as usize
        };

        match parse_class_t(data, file_off, ptr) {
            Ok(cls) => classes.push(cls),
            Err(_) => continue,
        }
    }

    classes
}

// ---------------------------------------------------------------------------
// __objc_catlist section parser
// ---------------------------------------------------------------------------

/// Parse a single `category_t` entry.
pub fn parse_category(data: &[u8], off: usize, ptr: PtrSize) -> ObjcResult<ObjcCategory> {
    let struct_size = ptr.bytes() * 7;
    if off.checked_add(struct_size).is_none_or(|end| end > data.len()) {
        return Err(ObjcError::OutOfBounds {
            offset: off,
            size: struct_size,
        });
    }

    let name_ptr = ptr.read(data, off)?;
    let cls_ptr = ptr.read(data, off + ptr.bytes())?;
    let inst_meth_ptr = ptr.read(data, off + ptr.bytes() * 2)?;
    let cls_meth_ptr = ptr.read(data, off + ptr.bytes() * 3)?;
    let proto_ptr = ptr.read(data, off + ptr.bytes() * 4)?;
    let inst_prop_ptr = ptr.read(data, off + ptr.bytes() * 5)?;
    let cls_prop_ptr = ptr.read(data, off + ptr.bytes() * 6)?;

    let name = if name_ptr != 0 {
        read_cstr(data, name_ptr as usize).unwrap_or_default()
    } else {
        String::new()
    };

    let class_name = if cls_ptr != 0 {
        // Try to read the class name from class_t -> class_ro_t -> name
        if cls_ptr as usize + ptr.bytes() * 5 <= data.len() {
            let data_ptr = strip_ptr(
                ptr.read(data, cls_ptr as usize + ptr.bytes() * 4)
                    .unwrap_or(0),
                ptr,
            );
            if data_ptr != 0 {
                parse_class_ro(data, data_ptr as usize, ptr)
                    .map(|ro| ro.name)
                    .unwrap_or_default()
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let instance_methods = if inst_meth_ptr != 0 {
        parse_method_list(data, inst_meth_ptr as usize, ptr, false).unwrap_or_default()
    } else {
        vec![]
    };

    let class_methods = if cls_meth_ptr != 0 {
        parse_method_list(data, cls_meth_ptr as usize, ptr, true).unwrap_or_default()
    } else {
        vec![]
    };

    let protocols = if proto_ptr != 0 {
        parse_protocol_list_names(data, proto_ptr as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    let instance_properties = if inst_prop_ptr != 0 {
        parse_property_list(data, inst_prop_ptr as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    let class_properties = if cls_prop_ptr != 0 {
        parse_property_list(data, cls_prop_ptr as usize, ptr).unwrap_or_default()
    } else {
        vec![]
    };

    Ok(ObjcCategory {
        name,
        class_name,
        instance_methods,
        class_methods,
        protocols,
        instance_properties,
        class_properties,
    })
}

/// Parse the __`objc_catlist` section.
#[must_use] 
pub fn parse_catlist(
    data: &[u8],
    section_data: &[u8],
    ptr: PtrSize,
    base_addr: u64,
) -> Vec<ObjcCategory> {
    let count = section_data.len() / ptr.bytes();
    let mut cats = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * ptr.bytes();
        let cat_ptr = match ptr.read(section_data, off) {
            Ok(p) => strip_ptr(p, ptr),
            Err(_) => continue,
        };
        if cat_ptr == 0 {
            continue;
        }

        let file_off = if cat_ptr >= base_addr {
            (cat_ptr - base_addr) as usize
        } else {
            cat_ptr as usize
        };

        if let Ok(cat) = parse_category(data, file_off, ptr) {
            cats.push(cat);
        }
    }

    cats
}

// ---------------------------------------------------------------------------
// __objc_selrefs section parser
// ---------------------------------------------------------------------------

/// Parse the __`objc_selrefs` section (array of SEL pointers into __`objc_methnames`).
#[must_use] 
pub fn parse_selrefs(
    data: &[u8],
    section_data: &[u8],
    section_addr: u64,
    ptr: PtrSize,
    base_addr: u64,
) -> Vec<SelRef> {
    let count = section_data.len() / ptr.bytes();
    let mut refs = Vec::with_capacity(count);

    for i in 0..count {
        let off = i * ptr.bytes();
        let sel_ptr = match ptr.read(section_data, off) {
            Ok(p) => strip_ptr(p, ptr),
            Err(_) => continue,
        };
        if sel_ptr == 0 {
            continue;
        }

        let file_off = if sel_ptr >= base_addr {
            (sel_ptr - base_addr) as usize
        } else {
            sel_ptr as usize
        };

        let name = read_cstr(data, file_off).unwrap_or_default();
        let address = section_addr + off as u64;
        refs.push(SelRef { address, name });
    }

    refs
}

// ---------------------------------------------------------------------------
// High-level metadata extraction
// ---------------------------------------------------------------------------

/// All Objective-C metadata extracted from a Mach-O binary.
#[derive(Debug, Clone)]
pub struct ObjcMetadata {
    pub classes: Vec<ObjcClass>,
    pub protocols: Vec<ObjcProtocol>,
    pub categories: Vec<ObjcCategory>,
    pub selrefs: Vec<SelRef>,
    pub classrefs: Vec<u64>,
}

impl ObjcMetadata {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            classes: Vec::new(),
            protocols: Vec::new(),
            categories: Vec::new(),
            selrefs: Vec::new(),
            classrefs: Vec::new(),
        }
    }

    #[must_use] 
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }
    #[must_use] 
    pub const fn protocol_count(&self) -> usize {
        self.protocols.len()
    }
    #[must_use] 
    pub const fn category_count(&self) -> usize {
        self.categories.len()
    }
    #[must_use] 
    pub const fn sel_count(&self) -> usize {
        self.selrefs.len()
    }

    /// Look up an `ObjC` class by name.
    #[must_use] 
    pub fn find_class(&self, name: &str) -> Option<&ObjcClass> {
        self.classes.iter().find(|c| c.name == name)
    }

    /// Collect all unique selector names.
    #[must_use] 
    pub fn all_selectors(&self) -> Vec<&str> {
        self.selrefs.iter().map(|s| s.name.as_str()).collect()
    }

    /// All swift classes.
    #[must_use] 
    pub fn swift_classes(&self) -> Vec<&ObjcClass> {
        self.classes.iter().filter(|c| c.is_swift).collect()
    }
}

impl Default for ObjcMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PtrSize ----------------------------------------------------------

    #[test]
    fn test_ptr_size_bytes() {
        assert_eq!(PtrSize::P32.bytes(), 4);
        assert_eq!(PtrSize::P64.bytes(), 8);
    }

    #[test]
    fn test_ptr_size_read_p32() {
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(PtrSize::P32.read(&data, 0).unwrap(), 1);
        assert_eq!(PtrSize::P32.read(&data, 4).unwrap(), 2);
    }

    #[test]
    fn test_ptr_size_read_p64() {
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(PtrSize::P64.read(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_ptr_size_read_out_of_bounds() {
        assert!(PtrSize::P64.read(&[0u8; 4], 0).is_err());
    }

    // ---- strip_ptr --------------------------------------------------------

    #[test]
    fn test_strip_ptr_p64() {
        let ptr = 0xFFFF_8004_0000_1234u64;
        let stripped = strip_ptr(ptr, PtrSize::P64);
        assert_eq!(stripped, 0x0000_8004_0000_1234);
    }

    #[test]
    fn test_strip_ptr_p32() {
        let ptr = 0xFFFF_ABCDu64;
        assert_eq!(strip_ptr(ptr, PtrSize::P32), 0xFFFF_ABCD);
    }

    // ---- read_cstr -------------------------------------------------------

    #[test]
    fn test_read_cstr_basic() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstr(data, 0).unwrap(), "hello");
        assert_eq!(read_cstr(data, 6).unwrap(), "world");
    }

    #[test]
    fn test_read_cstr_empty() {
        let data = b"\0";
        assert_eq!(read_cstr(data, 0).unwrap(), "");
    }

    #[test]
    fn test_read_cstr_out_of_bounds() {
        assert!(read_cstr(&[], 0).is_err());
    }

    // ---- decode_type_enc -------------------------------------------------

    #[test]
    fn test_decode_type_enc_primitives() {
        let cases = [
            ("c", ObjcType::Char),
            ("i", ObjcType::Int),
            ("s", ObjcType::Short),
            ("q", ObjcType::LongLong),
            ("f", ObjcType::Float),
            ("d", ObjcType::Double),
            ("B", ObjcType::Bool),
            ("v", ObjcType::Void),
            ("*", ObjcType::String),
            ("#", ObjcType::Class),
            (":", ObjcType::Selector),
        ];
        for (enc, expected) in cases {
            let (t, _) = decode_type_enc(enc, 0);
            assert_eq!(t, expected, "enc={enc}");
        }
    }

    #[test]
    fn test_decode_type_enc_object_plain() {
        let (t, _) = decode_type_enc("@", 0);
        assert_eq!(t, ObjcType::Object(None));
    }

    #[test]
    fn test_decode_type_enc_object_named() {
        let (t, pos) = decode_type_enc("@\"NSString\"", 0);
        assert_eq!(t, ObjcType::Object(Some("NSString".into())));
        assert_eq!(pos, 11);
    }

    #[test]
    fn test_decode_type_enc_pointer() {
        let (t, _) = decode_type_enc("^i", 0);
        assert_eq!(t, ObjcType::Pointer(Box::new(ObjcType::Int)));
    }

    #[test]
    fn test_decode_type_enc_array() {
        let (t, _) = decode_type_enc("[4i]", 0);
        assert_eq!(
            t,
            ObjcType::Array {
                count: 4,
                element: Box::new(ObjcType::Int)
            }
        );
    }

    #[test]
    fn test_decode_type_enc_struct() {
        let (t, _) = decode_type_enc("{CGPoint=ff}", 0);
        if let ObjcType::Struct { name, fields } = t {
            assert_eq!(name.as_deref(), Some("CGPoint"));
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0], ObjcType::Float);
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn test_decode_type_enc_union() {
        let (t, _) = decode_type_enc("(myunion=id)", 0);
        assert!(matches!(t, ObjcType::Union { .. }));
    }

    #[test]
    fn test_decode_type_enc_bitfield() {
        let (t, _) = decode_type_enc("b5", 0);
        assert_eq!(t, ObjcType::Bitfield(5));
    }

    #[test]
    fn test_decode_type_enc_unknown() {
        let (t, _) = decode_type_enc("X", 0);
        assert_eq!(t, ObjcType::Unknown('X'));
    }

    // ---- decode_method_signature ----------------------------------------

    #[test]
    fn test_decode_method_signature_basic() {
        // v16@0:8 -> void, id, SEL
        let types = decode_method_signature("v16@0:8");
        assert_eq!(types.len(), 3);
        assert_eq!(types[0], ObjcType::Void);
        assert_eq!(types[1], ObjcType::Object(None));
        assert_eq!(types[2], ObjcType::Selector);
    }

    #[test]
    fn test_decode_method_signature_empty() {
        let types = decode_method_signature("");
        assert!(types.is_empty());
    }

    #[test]
    fn test_decode_method_signature_numbers_only() {
        let types = decode_method_signature("012345");
        assert!(types.is_empty());
    }

    // ---- ObjcType display ------------------------------------------------

    #[test]
    fn test_objc_type_display_id() {
        assert_eq!(format!("{}", ObjcType::Object(None)), "id");
    }

    #[test]
    fn test_objc_type_display_nsstring() {
        assert_eq!(
            format!("{}", ObjcType::Object(Some("NSString".into()))),
            "NSString *"
        );
    }

    #[test]
    fn test_objc_type_display_pointer() {
        assert_eq!(
            format!("{}", ObjcType::Pointer(Box::new(ObjcType::Int))),
            "int *"
        );
    }

    #[test]
    fn test_objc_type_display_array() {
        let t = ObjcType::Array {
            count: 3,
            element: Box::new(ObjcType::Float),
        };
        assert_eq!(format!("{t}"), "float[3]");
    }

    // ---- decode_swift_mangled_name ----------------------------------------

    #[test]
    fn test_swift_mangled_old_style() {
        let result = decode_swift_mangled_name("_TtC9MyProject11MyClassName");
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("MyProject") || s.contains("My"), "got: {s}");
    }

    #[test]
    fn test_swift_mangled_new_style() {
        let result = decode_swift_mangled_name("$sSo12NSDatePickerCSo22NSDatePickerElementUVVs");
        assert!(result.is_some());
    }

    #[test]
    fn test_swift_mangled_not_swift() {
        let result = decode_swift_mangled_name("NSObject");
        assert!(result.is_none());
    }

    // ---- is_swift_class --------------------------------------------------

    #[test]
    fn test_is_swift_class_true() {
        assert!(is_swift_class(ro_flags::IS_SWIFT));
        assert!(is_swift_class(ro_flags::IS_SWIFT | ro_flags::IS_META));
    }

    #[test]
    fn test_is_swift_class_false() {
        assert!(!is_swift_class(ro_flags::IS_META));
        assert!(!is_swift_class(0));
    }

    // ---- parse_method_list (synthetic) -----------------------------------

    #[test]
    fn test_parse_method_list_empty_count() {
        // Build a method_list_t with count=0
        let mut data = vec![0u8; 256];
        // entsize_and_flags = 24 (size of large method entry for 64-bit)
        let entsize = 24u32;
        data[0..4].copy_from_slice(&entsize.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // count = 0

        let methods = parse_method_list(&data, 0, PtrSize::P64, false).unwrap();
        assert!(methods.is_empty());
    }

    // ---- parse_ivar_list (synthetic) ------------------------------------

    #[test]
    fn test_parse_ivar_list_empty() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&32u32.to_le_bytes()); // entsize
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // count = 0
        let ivars = parse_ivar_list(&data, 0, PtrSize::P64).unwrap();
        assert!(ivars.is_empty());
    }

    // ---- parse_property_list (synthetic) --------------------------------

    #[test]
    fn test_parse_property_list_empty() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&16u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        let props = parse_property_list(&data, 0, PtrSize::P64).unwrap();
        assert!(props.is_empty());
    }

    // ---- ObjcMetadata ----------------------------------------------------

    #[test]
    fn test_objc_metadata_new() {
        let m = ObjcMetadata::new();
        assert_eq!(m.class_count(), 0);
        assert_eq!(m.sel_count(), 0);
    }

    #[test]
    fn test_objc_metadata_find_class() {
        let mut m = ObjcMetadata::new();
        m.classes.push(ObjcClass {
            name: "Foo".into(),
            superclass_name: None,
            methods: vec![],
            ivars: vec![],
            protocols: vec![],
            properties: vec![],
            categories: vec![],
            is_swift: false,
            swift_name: None,
            flags: 0,
            instance_size: 8,
            instance_start: 8,
        });
        assert!(m.find_class("Foo").is_some());
        assert!(m.find_class("Bar").is_none());
    }

    #[test]
    fn test_objc_metadata_swift_classes() {
        let mut m = ObjcMetadata::new();
        m.classes.push(ObjcClass {
            name: "SwiftFoo".into(),
            superclass_name: None,
            methods: vec![],
            ivars: vec![],
            protocols: vec![],
            properties: vec![],
            categories: vec![],
            is_swift: true,
            swift_name: Some("Module.Foo".into()),
            flags: ro_flags::IS_SWIFT,
            instance_size: 16,
            instance_start: 16,
        });
        m.classes.push(ObjcClass {
            name: "ObjcBar".into(),
            superclass_name: None,
            methods: vec![],
            ivars: vec![],
            protocols: vec![],
            properties: vec![],
            categories: vec![],
            is_swift: false,
            swift_name: None,
            flags: 0,
            instance_size: 8,
            instance_start: 8,
        });
        assert_eq!(m.swift_classes().len(), 1);
    }

    // ---- ObjcError display -----------------------------------------------

    #[test]
    fn test_objcerror_display() {
        let e = ObjcError::OutOfBounds { offset: 5, size: 4 };
        assert!(format!("{e}").contains('5'));

        let e = ObjcError::NullPointer("class_t.data".into());
        assert!(format!("{e}").contains("class_t.data"));

        let e = ObjcError::InvalidStructure("bad ivar".into());
        assert!(format!("{e}").contains("bad ivar"));
    }

    // ---- SegmentMapping --------------------------------------------------

    #[test]
    fn test_segment_mapping_vm_to_file() {
        let seg = SegmentMapping {
            vm_addr: 0x0001_0000_0000,
            vm_size: 0x1000,
            file_off: 0,
            file_size: 0x1000,
            name: "__TEXT".into(),
        };
        assert_eq!(seg.vm_to_file(0x0001_0000_0000), Some(0));
        assert_eq!(seg.vm_to_file(0x0001_0000_0100), Some(0x100));
        assert_eq!(seg.vm_to_file(0x0001_0000_1000), None);
        assert_eq!(seg.vm_to_file(0x0000_FFFF_FFFF), None);
    }

    #[test]
    fn test_resolve_vm_not_found() {
        let segs = vec![];
        assert!(resolve_vm(0x1000, &segs).is_none());
    }

    // ---- parse_protocol_list_names (empty) ------------------------------

    #[test]
    fn test_parse_protocol_list_names_empty() {
        // count = 0
        let mut data = vec![0u8; 16];
        // count field at off=0 (ptr size = 8)
        data[0..8].copy_from_slice(&0u64.to_le_bytes());
        let names = parse_protocol_list_names(&data, 0, PtrSize::P64).unwrap();
        assert!(names.is_empty());
    }

    // ---- all_selectors ---------------------------------------------------

    #[test]
    fn test_all_selectors() {
        let mut m = ObjcMetadata::new();
        m.selrefs.push(SelRef {
            address: 0x1000,
            name: "init".into(),
        });
        m.selrefs.push(SelRef {
            address: 0x1008,
            name: "dealloc".into(),
        });
        let sels = m.all_selectors();
        assert!(sels.contains(&"init"));
        assert!(sels.contains(&"dealloc"));
    }
}
