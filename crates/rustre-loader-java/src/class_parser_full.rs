//! Full Java `.class` file parser — all 19 constant-pool tags, access flags,
//! fields, methods and every standard attribute up to Java 21 / class-file 65.

use std::collections::HashMap;
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ClassParseError {
    #[error("unexpected end of data at offset {0}")]
    UnexpectedEof(usize),
    #[error("invalid magic: expected 0xCAFEBABE, got 0x{0:08X}")]
    BadMagic(u32),
    #[error("unknown constant-pool tag {0}")]
    UnknownCpTag(u8),
    #[error("constant-pool index {0} out of range (pool size {1})")]
    CpIndexOutOfRange(u16, usize),
    #[error("invalid UTF-8 in constant pool entry {0}")]
    BadUtf8(u16),
    #[error("unknown attribute '{0}'")]
    UnknownAttribute(String),
    #[error("malformed attribute '{0}': {1}")]
    MalformedAttribute(String, String),
}

// ── Low-level reader ─────────────────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos:  usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    /// Number of bytes still available from the current cursor position.
    pub const fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }

    fn u8(&mut self) -> Result<u8, ClassParseError> {
        if self.pos >= self.data.len() {
            return Err(ClassParseError::UnexpectedEof(self.pos));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, ClassParseError> {
        let hi = u16::from(self.u8()?);
        let lo = u16::from(self.u8()?);
        Ok((hi << 8) | lo)
    }

    fn u32(&mut self) -> Result<u32, ClassParseError> {
        let a = u32::from(self.u8()?);
        let b = u32::from(self.u8()?);
        let c = u32::from(self.u8()?);
        let d = u32::from(self.u8()?);
        Ok((a << 24) | (b << 16) | (c << 8) | d)
    }

    fn i32(&mut self) -> Result<i32, ClassParseError> {
        Ok(self.u32()? as i32)
    }

    fn i64(&mut self) -> Result<i64, ClassParseError> {
        let hi = i64::from(self.u32()?);
        let lo = i64::from(self.u32()?);
        Ok((hi << 32) | lo)
    }

    fn f32(&mut self) -> Result<f32, ClassParseError> {
        Ok(f32::from_bits(self.u32()?))
    }

    fn f64(&mut self) -> Result<f64, ClassParseError> {
        Ok(f64::from_bits(self.i64()? as u64))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ClassParseError> {
        if self.pos + n > self.data.len() {
            return Err(ClassParseError::UnexpectedEof(self.pos));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    const fn skip(&mut self, n: usize) -> Result<(), ClassParseError> {
        if self.pos + n > self.data.len() {
            return Err(ClassParseError::UnexpectedEof(self.pos));
        }
        self.pos += n;
        Ok(())
    }

    const fn pos(&self) -> usize { self.pos }
}

// ── Constant pool ─────────────────────────────────────────────────────────────

/// All 19 JVMS constant-pool tags (+ placeholder for Long/Double slot 2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CpEntry {
    /// tag 1 — mutf-8 string
    Utf8(String),
    /// tag 3
    Integer(i32),
    /// tag 4
    Float(f32),
    /// tag 5 — occupies two slots
    Long(i64),
    /// tag 6 — occupies two slots
    Double(f64),
    /// tag 7 — `name_index` → Utf8
    Class { name_index: u16 },
    /// tag 8 — `string_index` → Utf8
    String { string_index: u16 },
    /// tag 9
    Fieldref { class_index: u16, name_and_type_index: u16 },
    /// tag 10
    Methodref { class_index: u16, name_and_type_index: u16 },
    /// tag 11
    InterfaceMethodref { class_index: u16, name_and_type_index: u16 },
    /// tag 12
    NameAndType { name_index: u16, descriptor_index: u16 },
    /// tag 15
    MethodHandle { reference_kind: u8, reference_index: u16 },
    /// tag 16
    MethodType { descriptor_index: u16 },
    /// tag 17 — `bootstrap_method_attr_index` + `name_and_type_index`
    Dynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    /// tag 18
    InvokeDynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    /// tag 19
    Module { name_index: u16 },
    /// tag 20
    Package { name_index: u16 },
    /// Phantom second slot for Long / Double
    Unusable,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstantPool(pub Vec<Option<CpEntry>>);

impl ConstantPool {
    /// 1-based lookup (slot 0 is always None).
    pub fn get(&self, idx: u16) -> Result<&CpEntry, ClassParseError> {
        let i = idx as usize;
        self.0
            .get(i)
            .and_then(|e| e.as_ref())
            .ok_or(ClassParseError::CpIndexOutOfRange(idx, self.0.len()))
    }

    pub fn utf8(&self, idx: u16) -> Result<&str, ClassParseError> {
        match self.get(idx)? {
            CpEntry::Utf8(s) => Ok(s.as_str()),
            _ => Err(ClassParseError::BadUtf8(idx)),
        }
    }

    pub fn class_name(&self, idx: u16) -> Result<&str, ClassParseError> {
        match self.get(idx)? {
            CpEntry::Class { name_index } => self.utf8(*name_index),
            _ => Err(ClassParseError::CpIndexOutOfRange(idx, self.0.len())),
        }
    }
}

fn parse_mutf8(bytes: &[u8]) -> String {
    // Modified UTF-8: 6-byte CESU-8 for supplementary, 2-byte null, rest standard.
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 && i + 1 < bytes.len() && bytes[i + 1] == 0 {
            // shouldn't appear in valid mutf8 — just skip
            i += 2;
            continue;
        }
        if b & 0x80 == 0 {
            out.push(b as char);
            i += 1;
        } else if b & 0xE0 == 0xC0 && i + 1 < bytes.len() {
            let c = ((u32::from(b) & 0x1F) << 6) | (u32::from(bytes[i + 1]) & 0x3F);
            out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
            i += 2;
        } else if b & 0xF0 == 0xE0 && i + 2 < bytes.len() {
            // Check for CESU-8 surrogate pair (0xED 0xA0.. 0xED 0xB0..)
            if b == 0xED
                && (bytes[i + 1] & 0xF0) == 0xA0
                && i + 5 < bytes.len()
                && bytes[i + 3] == 0xED
                && (bytes[i + 4] & 0xF0) == 0xB0
            {
                let hi = (((u32::from(bytes[i + 1]) & 0x0F) << 6) | (u32::from(bytes[i + 2]) & 0x3F)) + 0x40;
                let lo = ((u32::from(bytes[i + 4]) & 0x0F) << 6) | (u32::from(bytes[i + 5]) & 0x3F);
                let cp = (hi << 10) | lo;
                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                i += 6;
            } else {
                let c = ((u32::from(b) & 0x0F) << 12)
                    | ((u32::from(bytes[i + 1]) & 0x3F) << 6)
                    | (u32::from(bytes[i + 2]) & 0x3F);
                out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                i += 3;
            }
        } else {
            out.push('\u{FFFD}');
            i += 1;
        }
    }
    out
}

fn parse_constant_pool(r: &mut Reader<'_>) -> Result<ConstantPool, ClassParseError> {
    let count = r.u16()? as usize;
    let mut pool: Vec<Option<CpEntry>> = vec![None; count]; // slot 0 unused
    let mut i = 1usize;
    while i < count {
        let tag = r.u8()?;
        let entry = match tag {
            1 => {
                let len = r.u16()? as usize;
                let raw = r.bytes(len)?;
                CpEntry::Utf8(parse_mutf8(raw))
            }
            3 => CpEntry::Integer(r.i32()?),
            4 => CpEntry::Float(r.f32()?),
            5 => {
                let v = CpEntry::Long(r.i64()?);
                if i + 1 >= count {
                    return Err(ClassParseError::UnexpectedEof(r.pos()));
                }
                pool[i] = Some(v);
                pool[i + 1] = Some(CpEntry::Unusable);
                i += 2;
                continue;
            }
            6 => {
                let v = CpEntry::Double(r.f64()?);
                if i + 1 >= count {
                    return Err(ClassParseError::UnexpectedEof(r.pos()));
                }
                pool[i] = Some(v);
                pool[i + 1] = Some(CpEntry::Unusable);
                i += 2;
                continue;
            }
            7  => CpEntry::Class { name_index: r.u16()? },
            8  => CpEntry::String { string_index: r.u16()? },
            9  => CpEntry::Fieldref { class_index: r.u16()?, name_and_type_index: r.u16()? },
            10 => CpEntry::Methodref { class_index: r.u16()?, name_and_type_index: r.u16()? },
            11 => CpEntry::InterfaceMethodref { class_index: r.u16()?, name_and_type_index: r.u16()? },
            12 => CpEntry::NameAndType { name_index: r.u16()?, descriptor_index: r.u16()? },
            15 => CpEntry::MethodHandle { reference_kind: r.u8()?, reference_index: r.u16()? },
            16 => CpEntry::MethodType { descriptor_index: r.u16()? },
            17 => CpEntry::Dynamic {
                bootstrap_method_attr_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            18 => CpEntry::InvokeDynamic {
                bootstrap_method_attr_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            19 => CpEntry::Module { name_index: r.u16()? },
            20 => CpEntry::Package { name_index: r.u16()? },
            t  => return Err(ClassParseError::UnknownCpTag(t)),
        };
        pool[i] = Some(entry);
        i += 1;
    }
    Ok(ConstantPool(pool))
}

// ── Access flags ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct AccessFlags: u16 {
        const PUBLIC       = 0x0001;
        const PRIVATE      = 0x0002;
        const PROTECTED    = 0x0004;
        const STATIC       = 0x0008;
        const FINAL        = 0x0010;
        const SUPER        = 0x0020; // ACC_SYNCHRONIZED for methods
        const VOLATILE     = 0x0040; // ACC_BRIDGE
        const TRANSIENT    = 0x0080; // ACC_VARARGS
        const NATIVE       = 0x0100;
        const INTERFACE    = 0x0200;
        const ABSTRACT     = 0x0400;
        const STRICT       = 0x0800;
        const SYNTHETIC    = 0x1000;
        const ANNOTATION   = 0x2000;
        const ENUM         = 0x4000;
        const MODULE       = 0x8000;
    }
}

// ── Annotation types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ElementValue {
    Byte(i32),
    Char(i32),
    Double(f64),
    Float(f32),
    Int(i32),
    Long(i64),
    Short(i32),
    Boolean(i32),
    String(String),
    EnumConst { type_name: String, const_name: String },
    ClassInfo(String),
    AnnotationValue(Box<Annotation>),
    ArrayValue(Vec<Self>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ElementValuePair {
    pub name:  String,
    pub value: ElementValue,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Annotation {
    pub type_descriptor: String,
    pub elements:        Vec<ElementValuePair>,
}

fn parse_element_value(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<ElementValue, ClassParseError> {
    let tag = r.u8()? as char;
    match tag {
        'B' | 'C' | 'I' | 'S' | 'Z' => {
            let ci = r.u16()?;
            let v = match cp.get(ci)? {
                CpEntry::Integer(i) => *i,
                _ => 0,
            };
            Ok(match tag {
                'B' => ElementValue::Byte(v),
                'C' => ElementValue::Char(v),
                'S' => ElementValue::Short(v),
                'Z' => ElementValue::Boolean(v),
                _   => ElementValue::Int(v),
            })
        }
        'D' => {
            let ci = r.u16()?;
            let v = match cp.get(ci)? { CpEntry::Double(d) => *d, _ => 0.0 };
            Ok(ElementValue::Double(v))
        }
        'F' => {
            let ci = r.u16()?;
            let v = match cp.get(ci)? { CpEntry::Float(f) => *f, _ => 0.0 };
            Ok(ElementValue::Float(v))
        }
        'J' => {
            let ci = r.u16()?;
            let v = match cp.get(ci)? { CpEntry::Long(l) => *l, _ => 0 };
            Ok(ElementValue::Long(v))
        }
        's' => {
            let ci = r.u16()?;
            Ok(ElementValue::String(cp.utf8(ci)?.to_owned()))
        }
        'e' => {
            let ti = r.u16()?;
            let ni = r.u16()?;
            Ok(ElementValue::EnumConst {
                type_name:  cp.utf8(ti)?.to_owned(),
                const_name: cp.utf8(ni)?.to_owned(),
            })
        }
        'c' => {
            let ci = r.u16()?;
            Ok(ElementValue::ClassInfo(cp.utf8(ci)?.to_owned()))
        }
        '@' => {
            Ok(ElementValue::AnnotationValue(Box::new(parse_annotation(r, cp)?)))
        }
        '[' => {
            let n = r.u16()? as usize;
            let mut vals = Vec::with_capacity(n);
            for _ in 0..n {
                vals.push(parse_element_value(r, cp)?);
            }
            Ok(ElementValue::ArrayValue(vals))
        }
        _ => Ok(ElementValue::Int(0)),
    }
}

fn parse_annotation(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<Annotation, ClassParseError> {
    let type_idx = r.u16()?;
    let type_descriptor = cp.utf8(type_idx)?.to_owned();
    let n_pairs = r.u16()? as usize;
    let mut elements = Vec::with_capacity(n_pairs);
    for _ in 0..n_pairs {
        let name_idx = r.u16()?;
        let name = cp.utf8(name_idx)?.to_owned();
        let value = parse_element_value(r, cp)?;
        elements.push(ElementValuePair { name, value });
    }
    Ok(Annotation { type_descriptor, elements })
}

fn parse_annotations(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<Vec<Annotation>, ClassParseError> {
    let n = r.u16()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(parse_annotation(r, cp)?);
    }
    Ok(out)
}

// ── Attributes ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExceptionTableEntry {
    pub start_pc:   u16,
    pub end_pc:     u16,
    pub handler_pc: u16,
    pub catch_type: u16, // 0 = finally
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LineNumberEntry {
    pub start_pc:    u16,
    pub line_number: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalVar {
    pub start_pc:    u16,
    pub length:      u16,
    pub name:        String,
    pub descriptor:  String,
    pub index:       u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalVarType {
    pub start_pc:  u16,
    pub length:    u16,
    pub name:      String,
    pub signature: String,
    pub index:     u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodParameter {
    pub name:         Option<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeAttribute {
    pub max_stack:       u16,
    pub max_locals:      u16,
    pub code:            Vec<u8>,
    pub exception_table: Vec<ExceptionTableEntry>,
    pub attributes:      Vec<Attribute>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapMethod {
    pub bootstrap_method_ref: u16,
    pub arguments:            Vec<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InnerClassEntry {
    pub inner_class_info:   u16,
    pub outer_class_info:   u16,
    pub inner_name:         u16,
    pub inner_class_access: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordComponentInfo {
    pub name:       String,
    pub descriptor: String,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleRequires {
    pub module_index:   u16,
    pub flags:          u16,
    pub version_index:  u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleExports {
    pub package_index: u16,
    pub flags:         u16,
    pub to_indices:    Vec<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleOpens {
    pub package_index: u16,
    pub flags:         u16,
    pub to_indices:    Vec<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleProvides {
    pub provides_index: u16,
    pub with_indices:   Vec<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleAttribute {
    pub module_name_index:    u16,
    pub module_flags:         u16,
    pub module_version_index: u16,
    pub requires:             Vec<ModuleRequires>,
    pub exports:              Vec<ModuleExports>,
    pub opens:                Vec<ModuleOpens>,
    pub uses_indices:         Vec<u16>,
    pub provides:             Vec<ModuleProvides>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Attribute {
    ConstantValue(u16),
    Code(CodeAttribute),
    Exceptions(Vec<u16>),
    SourceFile(String),
    LineNumberTable(Vec<LineNumberEntry>),
    LocalVariableTable(Vec<LocalVar>),
    LocalVariableTypeTable(Vec<LocalVarType>),
    Synthetic,
    Deprecated,
    Signature(String),
    RuntimeVisibleAnnotations(Vec<Annotation>),
    RuntimeInvisibleAnnotations(Vec<Annotation>),
    RuntimeVisibleParameterAnnotations(Vec<Vec<Annotation>>),
    RuntimeInvisibleParameterAnnotations(Vec<Vec<Annotation>>),
    AnnotationDefault(ElementValue),
    MethodParameters(Vec<MethodParameter>),
    BootstrapMethods(Vec<BootstrapMethod>),
    InnerClasses(Vec<InnerClassEntry>),
    EnclosingMethod { class_index: u16, method_index: u16 },
    NestHost(u16),
    NestMembers(Vec<u16>),
    PermittedSubclasses(Vec<u16>),
    Record(Vec<RecordComponentInfo>),
    Module(ModuleAttribute),
    ModulePackages(Vec<u16>),
    ModuleMainClass(u16),
    StackMapTable(Vec<u8>),
    Unknown { name: String, data: Vec<u8> },
}

fn parse_code_attribute(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<CodeAttribute, ClassParseError> {
    let max_stack  = r.u16()?;
    let max_locals = r.u16()?;
    let code_len   = r.u32()? as usize;
    let code       = r.bytes(code_len)?.to_vec();

    let exc_count = r.u16()? as usize;
    let mut exception_table = Vec::with_capacity(exc_count);
    for _ in 0..exc_count {
        exception_table.push(ExceptionTableEntry {
            start_pc:   r.u16()?,
            end_pc:     r.u16()?,
            handler_pc: r.u16()?,
            catch_type: r.u16()?,
        });
    }

    let attributes = parse_attributes(r, cp)?;
    Ok(CodeAttribute { max_stack, max_locals, code, exception_table, attributes })
}

fn parse_attribute(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<Attribute, ClassParseError> {
    let name_idx = r.u16()?;
    let name     = cp.utf8(name_idx)?.to_owned();
    let len      = r.u32()? as usize;
    if len > r.remaining() {
        return Err(ClassParseError::UnexpectedEof(r.pos()));
    }
    let start    = r.pos();

    let attr = match name.as_str() {
        "ConstantValue" => {
            Attribute::ConstantValue(r.u16()?)
        }
        "Code" => {
            Attribute::Code(parse_code_attribute(r, cp)?)
        }
        "Exceptions" => {
            let n = r.u16()? as usize;
            let mut exc = Vec::with_capacity(n);
            for _ in 0..n { exc.push(r.u16()?); }
            Attribute::Exceptions(exc)
        }
        "SourceFile" => {
            let idx = r.u16()?;
            Attribute::SourceFile(cp.utf8(idx)?.to_owned())
        }
        "LineNumberTable" => {
            let n = r.u16()? as usize;
            let mut table = Vec::with_capacity(n);
            for _ in 0..n {
                table.push(LineNumberEntry { start_pc: r.u16()?, line_number: r.u16()? });
            }
            Attribute::LineNumberTable(table)
        }
        "LocalVariableTable" => {
            let n = r.u16()? as usize;
            let mut table = Vec::with_capacity(n);
            for _ in 0..n {
                table.push(LocalVar {
                    start_pc:   r.u16()?,
                    length:     r.u16()?,
                    name:       cp.utf8(r.u16()?)?.to_owned(),
                    descriptor: cp.utf8(r.u16()?)?.to_owned(),
                    index:      r.u16()?,
                });
            }
            Attribute::LocalVariableTable(table)
        }
        "LocalVariableTypeTable" => {
            let n = r.u16()? as usize;
            let mut table = Vec::with_capacity(n);
            for _ in 0..n {
                table.push(LocalVarType {
                    start_pc:  r.u16()?,
                    length:    r.u16()?,
                    name:      cp.utf8(r.u16()?)?.to_owned(),
                    signature: cp.utf8(r.u16()?)?.to_owned(),
                    index:     r.u16()?,
                });
            }
            Attribute::LocalVariableTypeTable(table)
        }
        "Synthetic"  => { r.skip(len - (r.pos() - start))?; Attribute::Synthetic }
        "Deprecated" => { r.skip(len - (r.pos() - start))?; Attribute::Deprecated }
        "Signature"  => {
            let idx = r.u16()?;
            Attribute::Signature(cp.utf8(idx)?.to_owned())
        }
        "RuntimeVisibleAnnotations" => {
            Attribute::RuntimeVisibleAnnotations(parse_annotations(r, cp)?)
        }
        "RuntimeInvisibleAnnotations" => {
            Attribute::RuntimeInvisibleAnnotations(parse_annotations(r, cp)?)
        }
        "RuntimeVisibleParameterAnnotations" => {
            let np = r.u8()? as usize;
            let mut params = Vec::with_capacity(np);
            for _ in 0..np { params.push(parse_annotations(r, cp)?); }
            Attribute::RuntimeVisibleParameterAnnotations(params)
        }
        "RuntimeInvisibleParameterAnnotations" => {
            let np = r.u8()? as usize;
            let mut params = Vec::with_capacity(np);
            for _ in 0..np { params.push(parse_annotations(r, cp)?); }
            Attribute::RuntimeInvisibleParameterAnnotations(params)
        }
        "AnnotationDefault" => {
            Attribute::AnnotationDefault(parse_element_value(r, cp)?)
        }
        "MethodParameters" => {
            let n = r.u8()? as usize;
            let mut params = Vec::with_capacity(n);
            for _ in 0..n {
                let ni = r.u16()?;
                let fl = r.u16()?;
                params.push(MethodParameter {
                    name: if ni == 0 { None } else { Some(cp.utf8(ni)?.to_owned()) },
                    access_flags: fl,
                });
            }
            Attribute::MethodParameters(params)
        }
        "BootstrapMethods" => {
            let n = r.u16()? as usize;
            let mut bsms = Vec::with_capacity(n);
            for _ in 0..n {
                let mr = r.u16()?;
                let na = r.u16()? as usize;
                let mut args = Vec::with_capacity(na);
                for _ in 0..na { args.push(r.u16()?); }
                bsms.push(BootstrapMethod { bootstrap_method_ref: mr, arguments: args });
            }
            Attribute::BootstrapMethods(bsms)
        }
        "InnerClasses" => {
            let n = r.u16()? as usize;
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                entries.push(InnerClassEntry {
                    inner_class_info:   r.u16()?,
                    outer_class_info:   r.u16()?,
                    inner_name:         r.u16()?,
                    inner_class_access: r.u16()?,
                });
            }
            Attribute::InnerClasses(entries)
        }
        "EnclosingMethod" => {
            Attribute::EnclosingMethod {
                class_index:  r.u16()?,
                method_index: r.u16()?,
            }
        }
        "NestHost" => Attribute::NestHost(r.u16()?),
        "NestMembers" => {
            let n = r.u16()? as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n { v.push(r.u16()?); }
            Attribute::NestMembers(v)
        }
        "PermittedSubclasses" => {
            let n = r.u16()? as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n { v.push(r.u16()?); }
            Attribute::PermittedSubclasses(v)
        }
        "Record" => {
            let n = r.u16()? as usize;
            let mut comps = Vec::with_capacity(n);
            for _ in 0..n {
                let ni = r.u16()?;
                let di = r.u16()?;
                let attrs = parse_attributes(r, cp)?;
                comps.push(RecordComponentInfo {
                    name:       cp.utf8(ni)?.to_owned(),
                    descriptor: cp.utf8(di)?.to_owned(),
                    attributes: attrs,
                });
            }
            Attribute::Record(comps)
        }
        "Module" => {
            Attribute::Module(parse_module_attribute(r, cp)?)
        }
        "ModulePackages" => {
            let n = r.u16()? as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n { v.push(r.u16()?); }
            Attribute::ModulePackages(v)
        }
        "ModuleMainClass" => Attribute::ModuleMainClass(r.u16()?),
        "StackMapTable" => {
            let end = start + len;
            let consumed = r.pos() - start;
            let remaining = len.saturating_sub(consumed);
            let data = r.bytes(remaining)?.to_vec();
            debug_assert!(r.pos() <= end, "StackMapTable overran declared length");
            Attribute::StackMapTable(data)
        }
        _ => {
            let end = start + len;
            let consumed = r.pos() - start;
            let remaining = len.saturating_sub(consumed);
            let data = r.bytes(remaining)?.to_vec();
            debug_assert!(r.pos() <= end, "Unknown attribute overran declared length");
            Attribute::Unknown { name, data }
        }
    };

    // Ensure we consumed exactly `len` bytes.
    let consumed = r.pos() - start;
    if consumed < len {
        r.skip(len - consumed)?;
    }

    Ok(attr)
}

fn parse_attributes(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<Vec<Attribute>, ClassParseError> {
    let n = r.u16()? as usize;
    let mut attrs = Vec::with_capacity(n);
    for _ in 0..n {
        attrs.push(parse_attribute(r, cp)?);
    }
    Ok(attrs)
}

fn parse_module_attribute(r: &mut Reader<'_>, _cp: &ConstantPool) -> Result<ModuleAttribute, ClassParseError> {
    let module_name_index    = r.u16()?;
    let module_flags         = r.u16()?;
    let module_version_index = r.u16()?;

    let nr = r.u16()? as usize;
    let mut requires = Vec::with_capacity(nr);
    for _ in 0..nr {
        requires.push(ModuleRequires {
            module_index:  r.u16()?,
            flags:         r.u16()?,
            version_index: r.u16()?,
        });
    }

    let ne = r.u16()? as usize;
    let mut exports = Vec::with_capacity(ne);
    for _ in 0..ne {
        let pi = r.u16()?;
        let fl = r.u16()?;
        let nt = r.u16()? as usize;
        let mut to_indices = Vec::with_capacity(nt);
        for _ in 0..nt { to_indices.push(r.u16()?); }
        exports.push(ModuleExports { package_index: pi, flags: fl, to_indices });
    }

    let no = r.u16()? as usize;
    let mut opens = Vec::with_capacity(no);
    for _ in 0..no {
        let pi = r.u16()?;
        let fl = r.u16()?;
        let nt = r.u16()? as usize;
        let mut to_indices = Vec::with_capacity(nt);
        for _ in 0..nt { to_indices.push(r.u16()?); }
        opens.push(ModuleOpens { package_index: pi, flags: fl, to_indices });
    }

    let nu = r.u16()? as usize;
    let mut uses_indices = Vec::with_capacity(nu);
    for _ in 0..nu { uses_indices.push(r.u16()?); }

    let np = r.u16()? as usize;
    let mut provides = Vec::with_capacity(np);
    for _ in 0..np {
        let pi = r.u16()?;
        let nw = r.u16()? as usize;
        let mut with_indices = Vec::with_capacity(nw);
        for _ in 0..nw { with_indices.push(r.u16()?); }
        provides.push(ModuleProvides { provides_index: pi, with_indices });
    }

    Ok(ModuleAttribute {
        module_name_index,
        module_flags,
        module_version_index,
        requires,
        exports,
        opens,
        uses_indices,
        provides,
    })
}

// ── Field / Method ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldInfo {
    pub access_flags: AccessFlags,
    pub name:         String,
    pub descriptor:   String,
    pub attributes:   Vec<Attribute>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodInfo {
    pub access_flags: AccessFlags,
    pub name:         String,
    pub descriptor:   String,
    pub attributes:   Vec<Attribute>,
}

impl MethodInfo {
    /// Returns the `Code` attribute, if any.
    #[must_use]
    pub fn code(&self) -> Option<&CodeAttribute> {
        self.attributes.iter().find_map(|a| {
            if let Attribute::Code(c) = a { Some(c) } else { None }
        })
    }

    /// Returns exception class indices listed in the `Exceptions` attribute.
    #[must_use]
    pub fn checked_exceptions(&self) -> &[u16] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::Exceptions(e) = a { Some(e.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub fn signature(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| {
            if let Attribute::Signature(s) = a { Some(s.as_str()) } else { None }
        })
    }

    #[must_use]
    pub fn visible_annotations(&self) -> &[Annotation] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::RuntimeVisibleAnnotations(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }
}

fn parse_field(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<FieldInfo, ClassParseError> {
    let raw_flags   = r.u16()?;
    let access_flags = AccessFlags::from_bits_truncate(raw_flags);
    let name        = cp.utf8(r.u16()?)?.to_owned();
    let descriptor  = cp.utf8(r.u16()?)?.to_owned();
    let attributes  = parse_attributes(r, cp)?;
    Ok(FieldInfo { access_flags, name, descriptor, attributes })
}

fn parse_method(r: &mut Reader<'_>, cp: &ConstantPool) -> Result<MethodInfo, ClassParseError> {
    let raw_flags    = r.u16()?;
    let access_flags = AccessFlags::from_bits_truncate(raw_flags);
    let name         = cp.utf8(r.u16()?)?.to_owned();
    let descriptor   = cp.utf8(r.u16()?)?.to_owned();
    let attributes   = parse_attributes(r, cp)?;
    Ok(MethodInfo { access_flags, name, descriptor, attributes })
}

// ── ClassFile ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClassFile {
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: ConstantPool,
    pub access_flags:  AccessFlags,
    pub this_class:    u16,
    pub super_class:   u16,
    pub interfaces:    Vec<u16>,
    pub fields:        Vec<FieldInfo>,
    pub methods:       Vec<MethodInfo>,
    pub attributes:    Vec<Attribute>,
}

impl ClassFile {
    /// Parse a complete `.class` byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, ClassParseError> {
        let mut r = Reader::new(data);

        let magic = r.u32()?;
        if magic != 0xCAFE_BABE {
            return Err(ClassParseError::BadMagic(magic));
        }

        let minor_version = r.u16()?;
        let major_version = r.u16()?;

        let constant_pool = parse_constant_pool(&mut r)?;

        let raw_flags    = r.u16()?;
        let access_flags = AccessFlags::from_bits_truncate(raw_flags);
        let this_class   = r.u16()?;
        let super_class  = r.u16()?;

        let iface_count = r.u16()? as usize;
        let mut interfaces = Vec::with_capacity(iface_count);
        for _ in 0..iface_count { interfaces.push(r.u16()?); }

        let field_count = r.u16()? as usize;
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count { fields.push(parse_field(&mut r, &constant_pool)?); }

        let method_count = r.u16()? as usize;
        let mut methods = Vec::with_capacity(method_count);
        for _ in 0..method_count { methods.push(parse_method(&mut r, &constant_pool)?); }

        let attributes = parse_attributes(&mut r, &constant_pool)?;

        Ok(Self {
            minor_version,
            major_version,
            constant_pool,
            access_flags,
            this_class,
            super_class,
            interfaces,
            fields,
            methods,
            attributes,
        })
    }

    // ── Convenience accessors ────────────────────────────────────────────────

    #[must_use]
    pub fn this_class_name(&self) -> Option<&str> {
        self.constant_pool.class_name(self.this_class).ok()
    }

    #[must_use]
    pub fn super_class_name(&self) -> Option<&str> {
        if self.super_class == 0 { return None; }
        self.constant_pool.class_name(self.super_class).ok()
    }

    #[must_use]
    pub fn interface_names(&self) -> Vec<&str> {
        self.interfaces
            .iter()
            .filter_map(|&i| self.constant_pool.class_name(i).ok())
            .collect()
    }

    #[must_use]
    pub fn source_file(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| {
            if let Attribute::SourceFile(s) = a { Some(s.as_str()) } else { None }
        })
    }

    #[must_use]
    pub fn signature(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| {
            if let Attribute::Signature(s) = a { Some(s.as_str()) } else { None }
        })
    }

    #[must_use]
    pub fn bootstrap_methods(&self) -> &[BootstrapMethod] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::BootstrapMethods(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub fn inner_classes(&self) -> &[InnerClassEntry] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::InnerClasses(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub fn nest_members(&self) -> &[u16] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::NestMembers(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub fn permitted_subclasses(&self) -> &[u16] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::PermittedSubclasses(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub fn record_components(&self) -> &[RecordComponentInfo] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::Record(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    /// Resolve the runtime-visible annotations on the class.
    #[must_use]
    pub fn visible_annotations(&self) -> &[Annotation] {
        self.attributes.iter().find_map(|a| {
            if let Attribute::RuntimeVisibleAnnotations(v) = a { Some(v.as_slice()) } else { None }
        }).unwrap_or(&[])
    }

    #[must_use]
    pub const fn java_version(&self) -> u16 { self.major_version.saturating_sub(44) }

    #[must_use]
    pub const fn is_interface(&self) -> bool { self.access_flags.contains(AccessFlags::INTERFACE) }

    #[must_use]
    pub const fn is_enum(&self)      -> bool { self.access_flags.contains(AccessFlags::ENUM)      }

    #[must_use]
    pub const fn is_annotation(&self)-> bool { self.access_flags.contains(AccessFlags::ANNOTATION)}

    #[must_use]
    pub fn is_record(&self)    -> bool { !self.record_components().is_empty() }

    #[must_use]
    pub const fn is_module(&self)    -> bool { self.access_flags.contains(AccessFlags::MODULE)    }

    /// Find a method by name + descriptor.
    #[must_use]
    pub fn find_method(&self, name: &str, descriptor: &str) -> Option<&MethodInfo> {
        self.methods.iter().find(|m| m.name == name && m.descriptor == descriptor)
    }

    /// Collect all string constants referenced by `ldc/ldc_w` instructions.
    #[must_use]
    pub fn string_literals(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for method in &self.methods {
            if let Some(code) = method.code() {
                let bytes = &code.code;
                let mut pc = 0usize;
                while pc < bytes.len() {
                    let op = bytes[pc];
                    match op {
                        // ldc
                        0x12 if pc + 1 < bytes.len() => {
                            let idx = u16::from(bytes[pc + 1]);
                            if let Ok(CpEntry::String { string_index }) = self.constant_pool.get(idx)
                                && let Ok(s) = self.constant_pool.utf8(*string_index) {
                                    out.push(s);
                                }
                            pc += 2;
                        }
                        // ldc_w
                        0x13 if pc + 2 < bytes.len() => {
                            let idx = (u16::from(bytes[pc + 1]) << 8) | u16::from(bytes[pc + 2]);
                            if let Ok(CpEntry::String { string_index }) = self.constant_pool.get(idx)
                                && let Ok(s) = self.constant_pool.utf8(*string_index) {
                                    out.push(s);
                                }
                            pc += 3;
                        }
                        _ => pc += 1,
                    }
                }
            }
        }
        out
    }

    /// Build a mapping from cp-index → resolved class name for all Class entries.
    #[must_use]
    pub fn referenced_classes(&self) -> HashMap<u16, &str> {
        let mut map = HashMap::new();
        for (i, entry) in self.constant_pool.0.iter().enumerate() {
            if let Some(CpEntry::Class { name_index }) = entry
                && let Ok(s) = self.constant_pool.utf8(*name_index) {
                    map.insert(i as u16, s);
                }
        }
        map
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_bad_magic() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x41];
        let err = ClassFile::parse(&data).unwrap_err();
        assert!(matches!(err, ClassParseError::BadMagic(_)));
    }

    #[test]
    fn reject_truncated() {
        let data = [0xCA, 0xFE, 0xBA, 0xBE]; // magic only
        let err = ClassFile::parse(&data).unwrap_err();
        assert!(matches!(err, ClassParseError::UnexpectedEof(_)));
    }

    #[test]
    fn parse_mutf8_basic() {
        assert_eq!(parse_mutf8(b"Hello"), "Hello");
        // null character encoded as 0xC0 0x80
        assert_eq!(parse_mutf8(&[0xC0, 0x80]), "\0");
    }

    #[test]
    fn access_flags_roundtrip() {
        let f = AccessFlags::PUBLIC | AccessFlags::FINAL | AccessFlags::SYNTHETIC;
        assert_eq!(f.bits(), 0x1011);
        assert!(f.contains(AccessFlags::PUBLIC));
        assert!(!f.contains(AccessFlags::PRIVATE));
    }
}
