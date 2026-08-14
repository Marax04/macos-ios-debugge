//! Full Java `.class` file parser.
//!
//! Parses every field defined by the JVMS §4.

use std::collections::HashMap;
use std::fmt;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClassParseError {
    #[error("invalid magic: expected 0xCAFEBABE got {0:#010x}")]
    InvalidMagic(u32),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("invalid constant pool tag {tag} at index {index}")]
    InvalidCpTag { tag: u8, index: usize },
    #[error("constant pool index {0} out of range")]
    CpIndexOutOfRange(usize),
    #[error("invalid attribute at offset {0}: {1}")]
    InvalidAttribute(usize, String),
}

// ── Constant pool ─────────────────────────────────────────────────────────────

/// A single constant pool entry (JVMS §4.4).
#[derive(Debug, Clone)]
pub enum CpEntry {
    Class(u16),
    Fieldref(u16, u16),
    Methodref(u16, u16),
    InterfaceMethodref(u16, u16),
    String(u16),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    NameAndType(u16, u16),
    Utf8(std::string::String),
    MethodHandle(u8, u16),
    MethodType(u16),
    Dynamic(u16, u16),
    InvokeDynamic(u16, u16),
    Module(u16),
    Package(u16),
    /// Placeholder for the second slot of Long/Double, or unknown tag.
    Unused,
}

impl CpEntry {
    /// Return the JVMS §4.4 numeric tag for this constant pool entry.
    #[must_use] 
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Utf8(_) => 1,
            Self::Integer(_) => 3,
            Self::Float(_) => 4,
            Self::Long(_) => 5,
            Self::Double(_) => 6,
            Self::Class(_) => 7,
            Self::String(_) => 8,
            Self::Fieldref(_, _) => 9,
            Self::Methodref(_, _) => 10,
            Self::InterfaceMethodref(_, _) => 11,
            Self::NameAndType(_, _) => 12,
            Self::MethodHandle(_, _) => 15,
            Self::MethodType(_) => 16,
            Self::Dynamic(_, _) => 17,
            Self::InvokeDynamic(_, _) => 18,
            Self::Module(_) => 19,
            Self::Package(_) => 20,
            Self::Unused => 0,
        }
    }
}

impl fmt::Display for CpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class(i) => write!(f, "Class#{i}"),
            Self::Fieldref(c, n) => write!(f, "Fieldref #{c}.#{n}"),
            Self::Methodref(c, n) => write!(f, "Methodref #{c}.#{n}"),
            Self::InterfaceMethodref(c, n) => write!(f, "InterfaceMethodref #{c}.#{n}"),
            Self::String(i) => write!(f, "String#{i}"),
            Self::Integer(v) => write!(f, "Integer({v})"),
            Self::Float(v) => write!(f, "Float({v})"),
            Self::Long(v) => write!(f, "Long({v})"),
            Self::Double(v) => write!(f, "Double({v})"),
            Self::NameAndType(n, d) => write!(f, "NameAndType #{n}:#{d}"),
            Self::Utf8(s) => write!(f, "Utf8({s:?})"),
            Self::MethodHandle(k, i) => write!(f, "MethodHandle kind={k} #{i}"),
            Self::MethodType(i) => write!(f, "MethodType#{i}"),
            Self::Dynamic(b, n) => write!(f, "Dynamic bsm={b} #{n}"),
            Self::InvokeDynamic(b, n) => write!(f, "InvokeDynamic bsm={b} #{n}"),
            Self::Module(i) => write!(f, "Module#{i}"),
            Self::Package(i) => write!(f, "Package#{i}"),
            Self::Unused => write!(f, "<unused>"),
        }
    }
}

// ── Attribute ────────────────────────────────────────────────────────────────

/// Raw attribute from a class/field/method.
#[derive(Debug, Clone)]
pub struct AttributeInfo {
    pub name: std::string::String,
    pub data: Vec<u8>,
}

impl AttributeInfo {
    fn parse(data: &[u8], pos: &mut usize, cp: &[CpEntry]) -> Result<Self, ClassParseError> {
        if *pos + 6 > data.len() {
            return Err(ClassParseError::Truncated(*pos));
        }
        let name_idx = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let len = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
            as usize;
        *pos += 4;
        let name = resolve_utf8_str(cp, name_idx).to_string();
        if *pos + len > data.len() {
            return Err(ClassParseError::Truncated(*pos));
        }
        let attr_data = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(Self { name, data: attr_data })
    }
}

// ── ExceptionEntry ────────────────────────────────────────────────────────────

/// One row in the exception table of a Code attribute.
#[derive(Debug, Clone)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16,
}

// ── CodeAttribute ────────────────────────────────────────────────────────────

/// Parsed `Code` attribute (JVMS §4.7.3).
#[derive(Debug, Clone)]
pub struct CodeAttribute {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub exception_table: Vec<ExceptionEntry>,
    pub attributes: Vec<AttributeInfo>,
}

// ── FieldInfo / MethodInfo ────────────────────────────────────────────────────

/// A field declared in the class (JVMS §4.5).
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<AttributeInfo>,
}

impl FieldInfo {
    #[must_use] 
    pub fn name<'a>(&self, cp: &'a [CpEntry]) -> &'a str {
        resolve_utf8_str(cp, self.name_index as usize)
    }
    #[must_use] 
    pub fn descriptor<'a>(&self, cp: &'a [CpEntry]) -> &'a str {
        resolve_utf8_str(cp, self.descriptor_index as usize)
    }
}

/// A method declared in the class (JVMS §4.6).
#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<AttributeInfo>,
}

impl MethodInfo {
    #[must_use] 
    pub fn name<'a>(&self, cp: &'a [CpEntry]) -> &'a str {
        resolve_utf8_str(cp, self.name_index as usize)
    }
    #[must_use] 
    pub fn descriptor<'a>(&self, cp: &'a [CpEntry]) -> &'a str {
        resolve_utf8_str(cp, self.descriptor_index as usize)
    }
    /// Return the Code attribute data for this method, if present.
    #[must_use] 
    pub fn code_attribute_raw(&self) -> Option<&[u8]> {
        self.attributes.iter().find(|a| a.name == "Code").map(|a| a.data.as_slice())
    }
}

// ── ClassFile ────────────────────────────────────────────────────────────────

/// Fully parsed Java `.class` file.
#[derive(Debug, Clone)]
pub struct ClassFile {
    pub magic: u32,
    pub minor_version: u16,
    pub major_version: u16,
    /// 1-based; index 0 is `CpEntry::Unused` sentinel.
    pub constant_pool: Vec<CpEntry>,
    pub access_flags: u16,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub attributes: Vec<AttributeInfo>,
}

impl ClassFile {
    /// Parse a `.class` file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ClassParseError> {
        ClassFileParser::new(data).parse()
    }

    /// Resolve the binary class name of `this_class`.
    #[must_use] 
    pub fn resolve_class_name(&self) -> &str {
        self.resolve_utf8_via_class(self.this_class as usize)
    }

    /// Resolve the binary class name of `super_class` (empty if 0).
    #[must_use] 
    pub fn resolve_super_name(&self) -> &str {
        if self.super_class == 0 {
            ""
        } else {
            self.resolve_utf8_via_class(self.super_class as usize)
        }
    }

    fn resolve_utf8_via_class(&self, class_idx: usize) -> &str {
        match self.constant_pool.get(class_idx) {
            Some(CpEntry::Class(name_idx)) => {
                resolve_utf8_str(&self.constant_pool, *name_idx as usize)
            }
            _ => "",
        }
    }

    /// Resolve a UTF-8 string at the given constant pool index.
    #[must_use] 
    pub fn resolve_utf8(&self, idx: usize) -> &str {
        resolve_utf8_str(&self.constant_pool, idx)
    }

    /// Attempt to parse a `Code` attribute from its raw data.
    pub fn parse_code_attribute(data: &[u8]) -> Result<CodeAttribute, ClassParseError> {
        let mut pos = 0usize;
        if data.len() < 8 {
            return Err(ClassParseError::Truncated(0));
        }
        let max_stack = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let max_locals = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let code_length =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + code_length > data.len() {
            return Err(ClassParseError::Truncated(pos));
        }
        let code = data[pos..pos + code_length].to_vec();
        pos += code_length;
        if pos + 2 > data.len() {
            return Err(ClassParseError::Truncated(pos));
        }
        let exc_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let mut exception_table = Vec::with_capacity(exc_count);
        for _ in 0..exc_count {
            if pos + 8 > data.len() {
                return Err(ClassParseError::Truncated(pos));
            }
            exception_table.push(ExceptionEntry {
                start_pc: u16::from_be_bytes([data[pos], data[pos + 1]]),
                end_pc: u16::from_be_bytes([data[pos + 2], data[pos + 3]]),
                handler_pc: u16::from_be_bytes([data[pos + 4], data[pos + 5]]),
                catch_type: u16::from_be_bytes([data[pos + 6], data[pos + 7]]),
            });
            pos += 8;
        }
        if pos + 2 > data.len() {
            return Err(ClassParseError::Truncated(pos));
        }
        let attr_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        // No real CP here; parse raw without name resolution
        let mut attributes = Vec::with_capacity(attr_count);
        for _ in 0..attr_count {
            if pos + 6 > data.len() {
                break;
            }
            let _name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let alen =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;
            if pos + alen > data.len() {
                break;
            }
            attributes.push(AttributeInfo {
                name: format!("attr#{_name_idx}"),
                data: data[pos..pos + alen].to_vec(),
            });
            pos += alen;
        }
        Ok(CodeAttribute { max_stack, max_locals, code, exception_table, attributes })
    }

    /// Collect all string literals from the constant pool.
    #[must_use] 
    pub fn string_literals(&self) -> Vec<&str> {
        self.constant_pool
            .iter()
            .filter_map(|e| {
                if let CpEntry::Utf8(s) = e { Some(s.as_str()) } else { None }
            })
            .collect()
    }

    /// Collect all method call signatures as "ClassName.methodName".
    #[must_use] 
    pub fn method_refs(&self) -> Vec<std::string::String> {
        let cp = &self.constant_pool;
        let mut out = Vec::new();
        for e in cp {
            if let CpEntry::Methodref(class_idx, nat_idx) = e {
                let class_name = match cp.get(*class_idx as usize) {
                    Some(CpEntry::Class(ni)) => resolve_utf8_str(cp, *ni as usize),
                    _ => continue,
                };
                let method_name = match cp.get(*nat_idx as usize) {
                    Some(CpEntry::NameAndType(ni, _)) => resolve_utf8_str(cp, *ni as usize),
                    _ => continue,
                };
                out.push(format!("{class_name}.{method_name}"));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Collect interface names this class implements.
    #[must_use] 
    pub fn interface_names(&self) -> Vec<&str> {
        self.interfaces
            .iter()
            .map(|&idx| self.resolve_utf8_via_class(idx as usize))
            .collect()
    }

    /// Return the source file name, if the `SourceFile` attribute is present.
    #[must_use] 
    pub fn source_file(&self) -> Option<&str> {
        let attr = self.attributes.iter().find(|a| a.name == "SourceFile")?;
        if attr.data.len() < 2 {
            return None;
        }
        let idx = u16::from_be_bytes([attr.data[0], attr.data[1]]) as usize;
        Some(resolve_utf8_str(&self.constant_pool, idx))
    }

    /// Simple obfuscation heuristic: fraction of very short method/field names.
    #[must_use] 
    pub fn obfuscation_score(&self) -> f64 {
        let cp = &self.constant_pool;
        let method_names: Vec<&str> = self
            .methods
            .iter()
            .map(|m| resolve_utf8_str(cp, m.name_index as usize))
            .filter(|n| *n != "<init>" && *n != "<clinit>")
            .collect();
        let total = method_names.len();
        if total == 0 {
            return 0.0;
        }
        let short = method_names.iter().filter(|n| n.len() <= 2).count();
        short as f64 / total as f64
    }

    /// Return a histogram of constant pool tag values (JVMS §4.4) keyed by tag id.
    ///
    /// Useful for quick structural fingerprinting of the class file and for
    /// detecting obfuscators that synthesise unusually skewed CP distributions.
    #[must_use] 
    pub fn cp_tag_histogram(&self) -> HashMap<u8, usize> {
        let mut map: HashMap<u8, usize> = HashMap::new();
        for entry in &self.constant_pool {
            *map.entry(entry.tag()).or_insert(0) += 1;
        }
        map
    }
}

// ── ClassFileParser ───────────────────────────────────────────────────────────

/// Low-level parser for Java `.class` files.
pub struct ClassFileParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ClassFileParser<'a> {
    #[must_use] 
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ClassParseError> {
        if self.pos >= self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, ClassParseError> {
        if self.pos + 2 > self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, ClassParseError> {
        if self.pos + 4 > self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_i32(&mut self) -> Result<i32, ClassParseError> {
        self.read_u32().map(|v| v as i32)
    }

    fn read_i64(&mut self) -> Result<i64, ClassParseError> {
        if self.pos + 8 > self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let hi = i64::from(self.read_u32()?);
        let lo = i64::from(self.read_u32()?);
        Ok((hi << 32) | (lo & 0xFFFF_FFFF))
    }

    fn read_f32(&mut self) -> Result<f32, ClassParseError> {
        self.read_u32().map(f32::from_bits)
    }

    fn read_f64(&mut self) -> Result<f64, ClassParseError> {
        if self.pos + 8 > self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let hi = u64::from(self.read_u32()?);
        let lo = u64::from(self.read_u32()?);
        Ok(f64::from_bits((hi << 32) | lo))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ClassParseError> {
        if self.pos + len > self.data.len() {
            return Err(ClassParseError::Truncated(self.pos));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn parse_cp(&mut self, count: usize) -> Result<Vec<CpEntry>, ClassParseError> {
        let mut cp: Vec<CpEntry> = Vec::with_capacity(count + 1);
        cp.push(CpEntry::Unused); // index 0 is unused
        let mut i = 1usize;
        while i < count {
            let tag_pos = self.pos;
            let tag = self.read_u8()?;
            let entry = match tag {
                1 => {
                    let len = self.read_u16()? as usize;
                    let bytes = self.read_bytes(len)?;
                    let s = std::string::String::from_utf8_lossy(bytes).into_owned();
                    CpEntry::Utf8(s)
                }
                3 => CpEntry::Integer(self.read_i32()?),
                4 => CpEntry::Float(self.read_f32()?),
                5 => {
                    let v = self.read_i64()?;
                    cp.push(CpEntry::Long(v));
                    cp.push(CpEntry::Unused);
                    i += 2;
                    continue;
                }
                6 => {
                    let v = self.read_f64()?;
                    cp.push(CpEntry::Double(v));
                    cp.push(CpEntry::Unused);
                    i += 2;
                    continue;
                }
                7 => CpEntry::Class(self.read_u16()?),
                8 => CpEntry::String(self.read_u16()?),
                9 => {
                    let c = self.read_u16()?;
                    let n = self.read_u16()?;
                    CpEntry::Fieldref(c, n)
                }
                10 => {
                    let c = self.read_u16()?;
                    let n = self.read_u16()?;
                    CpEntry::Methodref(c, n)
                }
                11 => {
                    let c = self.read_u16()?;
                    let n = self.read_u16()?;
                    CpEntry::InterfaceMethodref(c, n)
                }
                12 => {
                    let n = self.read_u16()?;
                    let d = self.read_u16()?;
                    CpEntry::NameAndType(n, d)
                }
                15 => {
                    let k = self.read_u8()?;
                    let r = self.read_u16()?;
                    CpEntry::MethodHandle(k, r)
                }
                16 => CpEntry::MethodType(self.read_u16()?),
                17 => {
                    let b = self.read_u16()?;
                    let n = self.read_u16()?;
                    CpEntry::Dynamic(b, n)
                }
                18 => {
                    let b = self.read_u16()?;
                    let n = self.read_u16()?;
                    CpEntry::InvokeDynamic(b, n)
                }
                19 => CpEntry::Module(self.read_u16()?),
                20 => CpEntry::Package(self.read_u16()?),
                other => {
                    return Err(ClassParseError::InvalidCpTag { tag: other, index: i });
                }
            };
            let _ = tag_pos;
            cp.push(entry);
            i += 1;
        }
        Ok(cp)
    }

    fn parse_members(&mut self, cp: &[CpEntry]) -> Result<Vec<FieldInfo>, ClassParseError> {
        let count = self.read_u16()? as usize;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let access_flags = self.read_u16()?;
            let name_index = self.read_u16()?;
            let descriptor_index = self.read_u16()?;
            let attr_count = self.read_u16()? as usize;
            let mut attributes = Vec::with_capacity(attr_count);
            for _ in 0..attr_count {
                attributes.push(AttributeInfo::parse(self.data, &mut self.pos, cp)?);
            }
            members.push(FieldInfo { access_flags, name_index, descriptor_index, attributes });
        }
        Ok(members)
    }

    fn parse_methods(&mut self, cp: &[CpEntry]) -> Result<Vec<MethodInfo>, ClassParseError> {
        let count = self.read_u16()? as usize;
        let mut methods = Vec::with_capacity(count);
        for _ in 0..count {
            let access_flags = self.read_u16()?;
            let name_index = self.read_u16()?;
            let descriptor_index = self.read_u16()?;
            let attr_count = self.read_u16()? as usize;
            let mut attributes = Vec::with_capacity(attr_count);
            for _ in 0..attr_count {
                attributes.push(AttributeInfo::parse(self.data, &mut self.pos, cp)?);
            }
            methods.push(MethodInfo { access_flags, name_index, descriptor_index, attributes });
        }
        Ok(methods)
    }

    fn parse_attributes(&mut self, cp: &[CpEntry]) -> Result<Vec<AttributeInfo>, ClassParseError> {
        let count = self.read_u16()? as usize;
        let mut attrs = Vec::with_capacity(count);
        for _ in 0..count {
            attrs.push(AttributeInfo::parse(self.data, &mut self.pos, cp)?);
        }
        Ok(attrs)
    }

    pub fn parse(mut self) -> Result<ClassFile, ClassParseError> {
        let magic = self.read_u32()?;
        if magic != 0xCAFE_BABE {
            return Err(ClassParseError::InvalidMagic(magic));
        }
        let minor_version = self.read_u16()?;
        let major_version = self.read_u16()?;
        let cp_count = self.read_u16()? as usize;
        let constant_pool = self.parse_cp(cp_count)?;
        let access_flags = self.read_u16()?;
        let this_class = self.read_u16()?;
        let super_class = self.read_u16()?;
        let iface_count = self.read_u16()? as usize;
        let mut interfaces = Vec::with_capacity(iface_count);
        for _ in 0..iface_count {
            interfaces.push(self.read_u16()?);
        }
        let fields_raw = self.parse_members(&constant_pool)?;
        let fields = fields_raw; // already FieldInfo
        let methods = self.parse_methods(&constant_pool)?;
        let attributes = self.parse_attributes(&constant_pool)?;
        Ok(ClassFile {
            magic,
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
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_utf8_str(cp: &[CpEntry], idx: usize) -> &str {
    match cp.get(idx) {
        Some(CpEntry::Utf8(s)) => s.as_str(),
        _ => "",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_class(extra: &[u8]) -> Vec<u8> {
        // magic + minor + major + cp_count=1 (only sentinel) + access_flags + this=0 + super=0
        // + iface_count=0 + field_count=0 + method_count=0 + attr_count=0
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        v.extend_from_slice(&[0x00, 0x01]); // cp_count = 1 → no real entries
        v.extend_from_slice(&[0x00, 0x21]); // access_flags = PUBLIC|SUPER
        v.extend_from_slice(&[0x00, 0x00]); // this_class = 0
        v.extend_from_slice(&[0x00, 0x00]); // super_class = 0
        v.extend_from_slice(&[0x00, 0x00]); // iface_count = 0
        v.extend_from_slice(&[0x00, 0x00]); // field_count = 0
        v.extend_from_slice(&[0x00, 0x00]); // method_count = 0
        v.extend_from_slice(&[0x00, 0x00]); // attr_count = 0
        v.extend_from_slice(extra);
        v
    }

    fn class_with_utf8(name: &str) -> Vec<u8> {
        // cp entry 1: Utf8(name), entry 2: Class(1), entry 3: Utf8("java/lang/Object"), entry 4: Class(3)
        let name_bytes = name.as_bytes();
        let obj_bytes = b"java/lang/Object";
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        v.extend_from_slice(&[0x00, 0x05]); // cp_count = 5
        // Entry 1: Utf8(name)
        v.push(1);
        v.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(name_bytes);
        // Entry 2: Class(1)
        v.push(7);
        v.extend_from_slice(&[0x00, 0x01]);
        // Entry 3: Utf8("java/lang/Object")
        v.push(1);
        v.extend_from_slice(&(obj_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(obj_bytes);
        // Entry 4: Class(3)
        v.push(7);
        v.extend_from_slice(&[0x00, 0x03]);
        // access + this + super + 0s
        v.extend_from_slice(&[0x00, 0x21, 0x00, 0x02, 0x00, 0x04]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v
    }

    #[test]
    fn test_parse_minimal_class() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.magic, 0xCAFE_BABE);
        assert_eq!(cf.major_version, 52);
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x34];
        assert!(matches!(ClassFile::parse(&data), Err(ClassParseError::InvalidMagic(_))));
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0xCA, 0xFE];
        assert!(matches!(ClassFile::parse(&data), Err(ClassParseError::Truncated(_))));
    }

    #[test]
    fn test_class_name_resolution() {
        let data = class_with_utf8("com/example/Main");
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.resolve_class_name(), "com/example/Main");
    }

    #[test]
    fn test_super_name_resolution() {
        let data = class_with_utf8("com/example/Main");
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.resolve_super_name(), "java/lang/Object");
    }

    #[test]
    fn test_cp_utf8_entry() {
        let data = class_with_utf8("HelloWorld");
        let cf = ClassFile::parse(&data).unwrap();
        assert!(matches!(cf.constant_pool.get(1), Some(CpEntry::Utf8(s)) if s == "HelloWorld"));
    }

    #[test]
    fn test_cp_class_entry() {
        let data = class_with_utf8("HelloWorld");
        let cf = ClassFile::parse(&data).unwrap();
        assert!(matches!(cf.constant_pool.get(2), Some(CpEntry::Class(1))));
    }

    #[test]
    fn test_no_fields() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert!(cf.fields.is_empty());
    }

    #[test]
    fn test_no_methods() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert!(cf.methods.is_empty());
    }

    #[test]
    fn test_no_interfaces() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert!(cf.interfaces.is_empty());
    }

    #[test]
    fn test_access_flags() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.access_flags, 0x0021); // PUBLIC | SUPER
    }

    #[test]
    fn test_cp_display_utf8() {
        let e = CpEntry::Utf8("test".into());
        assert!(e.to_string().contains("test"));
    }

    #[test]
    fn test_cp_display_integer() {
        let e = CpEntry::Integer(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_cp_display_methodref() {
        let e = CpEntry::Methodref(1, 2);
        let s = e.to_string();
        assert!(s.contains("Methodref"));
    }

    #[test]
    fn test_parse_code_attribute_minimal() {
        // max_stack=1, max_locals=1, code=[0x01 aconst_null, 0xB0 areturn], exc_count=0, attr_count=0
        let mut data = vec![0x00, 0x01, 0x00, 0x01];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // code_length=2
        data.extend_from_slice(&[0x01, 0xB0]); // aconst_null, areturn
        data.extend_from_slice(&[0x00, 0x00]); // exc_count=0
        data.extend_from_slice(&[0x00, 0x00]); // attr_count=0
        let ca = ClassFile::parse_code_attribute(&data).unwrap();
        assert_eq!(ca.max_stack, 1);
        assert_eq!(ca.max_locals, 1);
        assert_eq!(ca.code, vec![0x01, 0xB0]);
        assert!(ca.exception_table.is_empty());
    }

    #[test]
    fn test_string_literals_empty_cp() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        let lits = cf.string_literals();
        assert!(lits.is_empty());
    }

    #[test]
    fn test_string_literals_with_cp() {
        let data = class_with_utf8("Hello");
        let cf = ClassFile::parse(&data).unwrap();
        let lits = cf.string_literals();
        assert!(lits.contains(&"Hello"));
    }

    #[test]
    fn test_obfuscation_score_no_methods() {
        let data = minimal_class(&[]);
        let cf = ClassFile::parse(&data).unwrap();
        assert_eq!(cf.obfuscation_score(), 0.0);
    }

    #[test]
    fn test_cp_entry_tag_consistency() {
        let entries: &[CpEntry] = &[
            CpEntry::Utf8("x".into()),
            CpEntry::Integer(1),
            CpEntry::Float(1.0),
            CpEntry::Class(1),
            CpEntry::String(1),
        ];
        let tags: Vec<u8> = entries.iter().map(super::CpEntry::tag).collect();
        assert_eq!(tags, vec![1, 3, 4, 7, 8]);
    }
}
