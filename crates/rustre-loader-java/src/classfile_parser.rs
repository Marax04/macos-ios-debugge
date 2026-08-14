//! Java `.class` file parser.
//!
//! Parses the binary format defined in *The Java Virtual Machine Specification*
//! (JVMS), §4.  Supports class files from Java 1 (version 45) through Java 21
//! (version 65).
//!
//! # Wire format
//!
//! ```text
//! ClassFile {
//!   u4 magic;                      // 0xCAFE_BABE
//!   u2 minor_version;
//!   u2 major_version;
//!   u2 constant_pool_count;
//!   cp_info constant_pool[count-1];
//!   u2 access_flags;
//!   u2 this_class;                 // CP index
//!   u2 super_class;                // CP index (0 for java/lang/Object)
//!   u2 interfaces_count;
//!   u2 interfaces[interfaces_count];
//!   u2 fields_count;
//!   field_info fields[fields_count];
//!   u2 methods_count;
//!   method_info methods[methods_count];
//!   u2 attributes_count;
//!   attribute_info attributes[attributes_count];
//! }
//! ```

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl ParseError {
    fn new(offset: usize, msg: impl Into<String>) -> Self {
        Self { offset, message: msg.into() }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "class file parse error at offset {:#x}: {}", self.offset, self.message)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor
// ─────────────────────────────────────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self { Cursor { data, pos: 0 } }

    const fn pos(&self) -> usize { self.pos }

    const fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.data.len() {
            return Err(ParseError::new(self.pos, "unexpected EOF (u8)"));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, ParseError> {
        let hi = u16::from(self.read_u8()?);
        let lo = u16::from(self.read_u8()?);
        Ok((hi << 8) | lo)
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let hi = u32::from(self.read_u16()?);
        let lo = u32::from(self.read_u16()?);
        Ok((hi << 16) | lo)
    }

    fn read_i32(&mut self) -> Result<i32, ParseError> {
        Ok(self.read_u32()? as i32)
    }

    fn read_i64(&mut self) -> Result<i64, ParseError> {
        let hi = i64::from(self.read_u32()?);
        let lo = i64::from(self.read_u32()?);
        Ok((hi << 32) | lo)
    }

    fn read_f32(&mut self) -> Result<f32, ParseError> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    fn read_f64(&mut self) -> Result<f64, ParseError> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, ParseError> {
        if self.pos + n > self.data.len() {
            return Err(ParseError::new(self.pos, format!("unexpected EOF reading {n} bytes")));
        }
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(bytes)
    }

    fn skip(&mut self, n: usize) -> Result<(), ParseError> {
        if self.pos + n > self.data.len() {
            return Err(ParseError::new(self.pos, format!("cannot skip {n} bytes")));
        }
        self.pos += n;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant Pool
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the constant pool.
///
/// Some entries (Long, Double) occupy two slots; the second slot is `Hole`.
#[derive(Debug, Clone)]
pub enum CpEntry {
    /// Tag 1 — `CONSTANT_Utf8`
    Utf8(String),
    /// Tag 3 — `CONSTANT_Integer`
    Integer(i32),
    /// Tag 4 — `CONSTANT_Float`
    Float(f32),
    /// Tag 5 — `CONSTANT_Long` (occupies 2 slots)
    Long(i64),
    /// Tag 6 — `CONSTANT_Double` (occupies 2 slots)
    Double(f64),
    /// Tag 7 — `CONSTANT_Class`
    Class { name_index: u16 },
    /// Tag 8 — `CONSTANT_String`
    StringRef { string_index: u16 },
    /// Tag 9 — `CONSTANT_Fieldref`
    Fieldref { class_index: u16, name_and_type_index: u16 },
    /// Tag 10 — `CONSTANT_Methodref`
    Methodref { class_index: u16, name_and_type_index: u16 },
    /// Tag 11 — `CONSTANT_InterfaceMethodref`
    InterfaceMethodref { class_index: u16, name_and_type_index: u16 },
    /// Tag 12 — `CONSTANT_NameAndType`
    NameAndType { name_index: u16, descriptor_index: u16 },
    /// Tag 15 — `CONSTANT_MethodHandle`
    MethodHandle { reference_kind: u8, reference_index: u16 },
    /// Tag 16 — `CONSTANT_MethodType`
    MethodType { descriptor_index: u16 },
    /// Tag 17 — `CONSTANT_Dynamic`
    Dynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    /// Tag 18 — `CONSTANT_InvokeDynamic`
    InvokeDynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    /// Tag 19 — `CONSTANT_Module`
    Module { name_index: u16 },
    /// Tag 20 — `CONSTANT_Package`
    Package { name_index: u16 },
    /// Placeholder for the second slot of a Long or Double entry.
    Hole,
}

impl CpEntry {
    /// Constant pool tag value.
    #[must_use] 
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Utf8(_)                 => 1,
            Self::Integer(_)              => 3,
            Self::Float(_)                => 4,
            Self::Long(_)                 => 5,
            Self::Double(_)               => 6,
            Self::Class { .. }            => 7,
            Self::StringRef { .. }        => 8,
            Self::Fieldref { .. }         => 9,
            Self::Methodref { .. }        => 10,
            Self::InterfaceMethodref {..} => 11,
            Self::NameAndType { .. }      => 12,
            Self::MethodHandle { .. }     => 15,
            Self::MethodType { .. }       => 16,
            Self::Dynamic { .. }          => 17,
            Self::InvokeDynamic { .. }    => 18,
            Self::Module { .. }           => 19,
            Self::Package { .. }          => 20,
            Self::Hole                    => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribute
// ─────────────────────────────────────────────────────────────────────────────

/// A raw attribute (not fully decoded).
#[derive(Debug, Clone)]
pub struct RawAttribute {
    pub name_index: u16,
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldInfo / MethodInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Field access flags (subset of JVMS Table 4.5-A).
#[derive(Debug, Clone, Copy)]
pub struct FieldFlags(pub u16);

impl FieldFlags {
    #[must_use] 
    pub const fn is_public(&self)    -> bool { self.0 & 0x0001 != 0 }
    #[must_use] 
    pub const fn is_private(&self)   -> bool { self.0 & 0x0002 != 0 }
    #[must_use] 
    pub const fn is_protected(&self) -> bool { self.0 & 0x0004 != 0 }
    #[must_use] 
    pub const fn is_static(&self)    -> bool { self.0 & 0x0008 != 0 }
    #[must_use] 
    pub const fn is_final(&self)     -> bool { self.0 & 0x0010 != 0 }
    #[must_use] 
    pub const fn is_volatile(&self)  -> bool { self.0 & 0x0040 != 0 }
    #[must_use] 
    pub const fn is_transient(&self) -> bool { self.0 & 0x0080 != 0 }
    #[must_use] 
    pub const fn is_synthetic(&self) -> bool { self.0 & 0x1000 != 0 }
    #[must_use] 
    pub const fn is_enum(&self)      -> bool { self.0 & 0x4000 != 0 }
}

/// A field in a Java class file.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub flags: FieldFlags,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<RawAttribute>,
}

/// Method access flags (subset of JVMS Table 4.6-A).
#[derive(Debug, Clone, Copy)]
pub struct MethodFlags(pub u16);

impl MethodFlags {
    #[must_use] 
    pub const fn is_public(&self)       -> bool { self.0 & 0x0001 != 0 }
    #[must_use] 
    pub const fn is_private(&self)      -> bool { self.0 & 0x0002 != 0 }
    #[must_use] 
    pub const fn is_protected(&self)    -> bool { self.0 & 0x0004 != 0 }
    #[must_use] 
    pub const fn is_static(&self)       -> bool { self.0 & 0x0008 != 0 }
    #[must_use] 
    pub const fn is_final(&self)        -> bool { self.0 & 0x0010 != 0 }
    #[must_use] 
    pub const fn is_synchronized(&self) -> bool { self.0 & 0x0020 != 0 }
    #[must_use] 
    pub const fn is_bridge(&self)       -> bool { self.0 & 0x0040 != 0 }
    #[must_use] 
    pub const fn is_varargs(&self)      -> bool { self.0 & 0x0080 != 0 }
    #[must_use] 
    pub const fn is_native(&self)       -> bool { self.0 & 0x0100 != 0 }
    #[must_use] 
    pub const fn is_abstract(&self)     -> bool { self.0 & 0x0400 != 0 }
    #[must_use] 
    pub const fn is_strict(&self)       -> bool { self.0 & 0x0800 != 0 }
    #[must_use] 
    pub const fn is_synthetic(&self)    -> bool { self.0 & 0x1000 != 0 }
}

/// A method in a Java class file.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub flags: MethodFlags,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<RawAttribute>,
    /// Parsed bytecode, if a `Code` attribute was found.
    pub code: Option<CodeAttribute>,
}

/// Decoded `Code` attribute.
#[derive(Debug, Clone)]
pub struct CodeAttribute {
    pub max_stack: u16,
    pub max_locals: u16,
    pub bytecode: Vec<u8>,
    pub exception_table: Vec<ExceptionEntry>,
    pub attributes: Vec<RawAttribute>,
}

/// One entry in the exception table.
#[derive(Debug, Clone)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16,  // 0 = finally
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassFile
// ─────────────────────────────────────────────────────────────────────────────

/// Class access flags (subset of JVMS Table 4.1-B).
#[derive(Debug, Clone, Copy)]
pub struct ClassFlags(pub u16);

impl ClassFlags {
    #[must_use] 
    pub const fn is_public(&self)     -> bool { self.0 & 0x0001 != 0 }
    #[must_use] 
    pub const fn is_final(&self)      -> bool { self.0 & 0x0010 != 0 }
    #[must_use] 
    pub const fn is_super(&self)      -> bool { self.0 & 0x0020 != 0 }
    #[must_use] 
    pub const fn is_interface(&self)  -> bool { self.0 & 0x0200 != 0 }
    #[must_use] 
    pub const fn is_abstract(&self)   -> bool { self.0 & 0x0400 != 0 }
    #[must_use] 
    pub const fn is_synthetic(&self)  -> bool { self.0 & 0x1000 != 0 }
    #[must_use] 
    pub const fn is_annotation(&self) -> bool { self.0 & 0x2000 != 0 }
    #[must_use] 
    pub const fn is_enum(&self)       -> bool { self.0 & 0x4000 != 0 }
    #[must_use] 
    pub const fn is_module(&self)     -> bool { self.0 & 0x8000 != 0 }
}

/// A fully parsed Java `.class` file.
#[derive(Debug, Clone)]
pub struct ClassFile {
    pub magic: u32,
    pub minor_version: u16,
    pub major_version: u16,
    /// Constant pool (1-indexed; index 0 is unused, represented as `Hole`).
    pub constant_pool: Vec<CpEntry>,
    pub flags: ClassFlags,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub attributes: Vec<RawAttribute>,
}

impl ClassFile {
    /// Java version as a human-readable string.
    #[must_use] 
    pub fn java_version(&self) -> String {
        match self.major_version {
            45 => "Java 1".into(),
            46 => "Java 1.2".into(),
            47 => "Java 1.3".into(),
            48 => "Java 1.4".into(),
            49 => "Java 5".into(),
            50 => "Java 6".into(),
            51 => "Java 7".into(),
            52 => "Java 8".into(),
            53 => "Java 9".into(),
            54 => "Java 10".into(),
            55 => "Java 11".into(),
            56 => "Java 12".into(),
            57 => "Java 13".into(),
            58 => "Java 14".into(),
            59 => "Java 15".into(),
            60 => "Java 16".into(),
            61 => "Java 17".into(),
            62 => "Java 18".into(),
            63 => "Java 19".into(),
            64 => "Java 20".into(),
            65 => "Java 21".into(),
            n  => format!("Java (major={n})"),
        }
    }

    /// Resolve a CP index to a UTF-8 string, or `None`.
    #[must_use] 
    pub fn utf8(&self, index: u16) -> Option<&str> {
        match self.constant_pool.get(index as usize)? {
            CpEntry::Utf8(s) => Some(s),
            _ => None,
        }
    }

    /// Return the binary name of the class (e.g., `"java/lang/Object"`).
    #[must_use] 
    pub fn class_name(&self) -> Option<&str> {
        match self.constant_pool.get(self.this_class as usize)? {
            CpEntry::Class { name_index } => self.utf8(*name_index),
            _ => None,
        }
    }

    /// Return the binary name of the superclass, or `None` for `Object`.
    #[must_use] 
    pub fn super_name(&self) -> Option<&str> {
        if self.super_class == 0 { return None; }
        match self.constant_pool.get(self.super_class as usize)? {
            CpEntry::Class { name_index } => self.utf8(*name_index),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassParser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a Java class file from a byte slice.
pub struct ClassParser;

impl ClassParser {
    /// Parse a `.class` file and return the decoded [`ClassFile`].
    pub fn parse(data: &[u8]) -> Result<ClassFile, ParseError> {
        let mut cur = Cursor::new(data);

        let magic = cur.read_u32()?;
        if magic != 0xCAFE_BABE {
            return Err(ParseError::new(0, format!("bad magic: {magic:#010x}")));
        }

        let minor_version = cur.read_u16()?;
        let major_version = cur.read_u16()?;

        let cp_count = cur.read_u16()? as usize;
        let constant_pool = Self::parse_constant_pool(&mut cur, cp_count)?;

        let flags = ClassFlags(cur.read_u16()?);
        let this_class = cur.read_u16()?;
        let super_class = cur.read_u16()?;

        let iface_count = cur.read_u16()? as usize;
        let mut interfaces = Vec::with_capacity(iface_count);
        for _ in 0..iface_count { interfaces.push(cur.read_u16()?); }

        let field_count = cur.read_u16()? as usize;
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count { fields.push(Self::parse_field(&mut cur)?); }

        let method_count = cur.read_u16()? as usize;
        let mut methods = Vec::with_capacity(method_count);
        for _ in 0..method_count { methods.push(Self::parse_method(&mut cur, &constant_pool)?); }

        let attr_count = cur.read_u16()? as usize;
        let mut attributes = Vec::with_capacity(attr_count);
        for _ in 0..attr_count { attributes.push(Self::parse_raw_attr(&mut cur)?); }

        Ok(ClassFile {
            magic,
            minor_version,
            major_version,
            constant_pool,
            flags,
            this_class,
            super_class,
            interfaces,
            fields,
            methods,
            attributes,
        })
    }

    fn parse_constant_pool(cur: &mut Cursor, count: usize) -> Result<Vec<CpEntry>, ParseError> {
        // Index 0 is unused; fill with a placeholder.
        let mut pool = vec![CpEntry::Hole];
        let mut i = 1usize;
        while i < count {
            let tag = cur.read_u8()?;
            let entry = match tag {
                1 => {
                    let len = cur.read_u16()? as usize;
                    let bytes = cur.read_bytes(len)?;
                    let s = String::from_utf8_lossy(&bytes).into_owned();
                    CpEntry::Utf8(s)
                }
                3 => CpEntry::Integer(cur.read_i32()?),
                4 => CpEntry::Float(cur.read_f32()?),
                5 => { let v = cur.read_i64()?; pool.push(CpEntry::Long(v)); pool.push(CpEntry::Hole); i += 2; continue; }
                6 => { let v = cur.read_f64()?; pool.push(CpEntry::Double(v)); pool.push(CpEntry::Hole); i += 2; continue; }
                7  => CpEntry::Class          { name_index: cur.read_u16()? },
                8  => CpEntry::StringRef      { string_index: cur.read_u16()? },
                9  => CpEntry::Fieldref       { class_index: cur.read_u16()?, name_and_type_index: cur.read_u16()? },
                10 => CpEntry::Methodref      { class_index: cur.read_u16()?, name_and_type_index: cur.read_u16()? },
                11 => CpEntry::InterfaceMethodref { class_index: cur.read_u16()?, name_and_type_index: cur.read_u16()? },
                12 => CpEntry::NameAndType    { name_index: cur.read_u16()?, descriptor_index: cur.read_u16()? },
                15 => CpEntry::MethodHandle   { reference_kind: cur.read_u8()?, reference_index: cur.read_u16()? },
                16 => CpEntry::MethodType     { descriptor_index: cur.read_u16()? },
                17 => CpEntry::Dynamic        { bootstrap_method_attr_index: cur.read_u16()?, name_and_type_index: cur.read_u16()? },
                18 => CpEntry::InvokeDynamic  { bootstrap_method_attr_index: cur.read_u16()?, name_and_type_index: cur.read_u16()? },
                19 => CpEntry::Module         { name_index: cur.read_u16()? },
                20 => CpEntry::Package        { name_index: cur.read_u16()? },
                t  => return Err(ParseError::new(cur.pos(), format!("unknown CP tag {t}"))),
            };
            pool.push(entry);
            i += 1;
        }
        Ok(pool)
    }

    fn parse_raw_attr(cur: &mut Cursor) -> Result<RawAttribute, ParseError> {
        let name_index = cur.read_u16()?;
        let length = cur.read_u32()? as usize;
        if length > cur.remaining() {
            // Truncated attribute: skip whatever's left and surface as empty data
            // rather than failing the whole class file.
            let avail = cur.remaining();
            cur.skip(avail)?;
            return Ok(RawAttribute { name_index, data: Vec::new() });
        }
        let data = cur.read_bytes(length)?;
        Ok(RawAttribute { name_index, data })
    }

    fn parse_field(cur: &mut Cursor) -> Result<FieldInfo, ParseError> {
        let flags = FieldFlags(cur.read_u16()?);
        let name_index = cur.read_u16()?;
        let descriptor_index = cur.read_u16()?;
        let attr_count = cur.read_u16()? as usize;
        let mut attributes = Vec::with_capacity(attr_count);
        for _ in 0..attr_count { attributes.push(Self::parse_raw_attr(cur)?); }
        Ok(FieldInfo { flags, name_index, descriptor_index, attributes })
    }

    fn parse_method(cur: &mut Cursor, cp: &[CpEntry]) -> Result<MethodInfo, ParseError> {
        let flags = MethodFlags(cur.read_u16()?);
        let name_index = cur.read_u16()?;
        let descriptor_index = cur.read_u16()?;
        let attr_count = cur.read_u16()? as usize;
        let mut attributes = Vec::with_capacity(attr_count);
        let mut code = None;

        for _ in 0..attr_count {
            let attr = Self::parse_raw_attr(cur)?;
            // Try to decode Code attribute
            let attr_name = match cp.get(attr.name_index as usize) {
                Some(CpEntry::Utf8(s)) => s.as_str(),
                _ => "",
            };
            if attr_name == "Code" {
                code = Self::decode_code_attr(&attr.data).ok();
            }
            attributes.push(attr);
        }

        Ok(MethodInfo { flags, name_index, descriptor_index, attributes, code })
    }

    fn decode_code_attr(data: &[u8]) -> Result<CodeAttribute, ParseError> {
        let mut cur = Cursor::new(data);
        let max_stack  = cur.read_u16()?;
        let max_locals = cur.read_u16()?;
        let code_len   = cur.read_u32()? as usize;
        let bytecode   = cur.read_bytes(code_len)?;

        let exc_count = cur.read_u16()? as usize;
        let mut exception_table = Vec::with_capacity(exc_count);
        for _ in 0..exc_count {
            exception_table.push(ExceptionEntry {
                start_pc:   cur.read_u16()?,
                end_pc:     cur.read_u16()?,
                handler_pc: cur.read_u16()?,
                catch_type: cur.read_u16()?,
            });
        }

        let attr_count = cur.read_u16()? as usize;
        let mut attributes = Vec::with_capacity(attr_count);
        for _ in 0..attr_count { attributes.push(Self::parse_raw_attr(&mut cur)?); }

        Ok(CodeAttribute { max_stack, max_locals, bytecode, exception_table, attributes })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid class file bytes: java/lang/Object (Java 8, no fields, no methods).
    fn minimal_class_bytes() -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        // magic
        b.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        // minor, major (Java 8 = 52)
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x34]);
        // constant_pool_count = 3 (entries 1 and 2)
        b.extend_from_slice(&[0x00, 0x03]);
        // CP#1: Utf8 "Hello"
        b.push(1);
        b.extend_from_slice(&[0x00, 0x05]);
        b.extend_from_slice(b"Hello");
        // CP#2: Class { name_index=1 }
        b.push(7);
        b.extend_from_slice(&[0x00, 0x01]);
        // access_flags (public)
        b.extend_from_slice(&[0x00, 0x21]);
        // this_class = 2
        b.extend_from_slice(&[0x00, 0x02]);
        // super_class = 0 (Object itself)
        b.extend_from_slice(&[0x00, 0x00]);
        // interfaces_count = 0
        b.extend_from_slice(&[0x00, 0x00]);
        // fields_count = 0
        b.extend_from_slice(&[0x00, 0x00]);
        // methods_count = 0
        b.extend_from_slice(&[0x00, 0x00]);
        // attributes_count = 0
        b.extend_from_slice(&[0x00, 0x00]);
        b
    }

    #[test]
    fn test_parse_minimal() {
        let bytes = minimal_class_bytes();
        let cf = ClassParser::parse(&bytes).expect("parse failed");
        assert_eq!(cf.magic, 0xCAFE_BABE);
        assert_eq!(cf.major_version, 52);
        assert_eq!(cf.java_version(), "Java 8");
    }

    #[test]
    fn test_class_name_resolved() {
        let bytes = minimal_class_bytes();
        let cf = ClassParser::parse(&bytes).unwrap();
        assert_eq!(cf.class_name(), Some("Hello"));
    }

    #[test]
    fn test_super_class_zero() {
        let bytes = minimal_class_bytes();
        let cf = ClassParser::parse(&bytes).unwrap();
        assert!(cf.super_name().is_none());
    }

    #[test]
    fn test_bad_magic() {
        let mut bytes = minimal_class_bytes();
        bytes[0] = 0xDE;
        let err = ClassParser::parse(&bytes).unwrap_err();
        assert!(err.message.contains("bad magic"));
    }

    #[test]
    fn test_utf8_lookup() {
        let bytes = minimal_class_bytes();
        let cf = ClassParser::parse(&bytes).unwrap();
        assert_eq!(cf.utf8(1), Some("Hello"));
        assert_eq!(cf.utf8(99), None);
    }

    #[test]
    fn test_class_flags() {
        let bytes = minimal_class_bytes();
        let cf = ClassParser::parse(&bytes).unwrap();
        assert!(cf.flags.is_public());
        assert!(cf.flags.is_super()); // 0x0021 = public + super
        assert!(!cf.flags.is_interface());
    }

    #[test]
    fn test_java_version_labels() {
        let versions = vec![
            (52, "Java 8"), (55, "Java 11"), (61, "Java 17"), (65, "Java 21"),
        ];
        for (mv, label) in versions {
            let mut bytes = minimal_class_bytes();
            bytes[7] = mv;
            let cf = ClassParser::parse(&bytes).unwrap();
            assert_eq!(cf.java_version(), label);
        }
    }

    #[test]
    fn test_truncated_input() {
        let bytes = &[0xCA, 0xFE, 0xBA]; // truncated
        assert!(ClassParser::parse(bytes).is_err());
    }
}
