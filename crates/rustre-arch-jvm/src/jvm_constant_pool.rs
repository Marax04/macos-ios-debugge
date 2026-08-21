//! `jvm_constant_pool` — parse and resolve JVM `.class` file constant pools.
//!
//! Implements the full JVM §4.4 constant pool format including all 17 tag types.
//! The entry point is [`JvmConstantPool::parse`], which decodes the binary
//! constant-pool from a slice of class-file bytes starting just after the
//! `constant_pool_count` field.  Individual entries can be resolved with
//! [`JvmConstantPool::resolve_utf8`], [`JvmConstantPool::resolve_class`], etc.

use crate::numeric;
use std::collections::HashMap;
use std::fmt;

// ── ConstantTag ───────────────────────────────────────────────────────────────

/// Tag byte values for JVM constant-pool entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConstantTag {
    Utf8 = 1,
    Integer = 3,
    Float = 4,
    Long = 5,
    Double = 6,
    Class = 7,
    String = 8,
    Fieldref = 9,
    Methodref = 10,
    InterfaceMethodref = 11,
    NameAndType = 12,
    MethodHandle = 15,
    MethodType = 16,
    Dynamic = 17,
    InvokeDynamic = 18,
    Module = 19,
    Package = 20,
}

impl ConstantTag {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Utf8,
            3 => Self::Integer,
            4 => Self::Float,
            5 => Self::Long,
            6 => Self::Double,
            7 => Self::Class,
            8 => Self::String,
            9 => Self::Fieldref,
            10 => Self::Methodref,
            11 => Self::InterfaceMethodref,
            12 => Self::NameAndType,
            15 => Self::MethodHandle,
            16 => Self::MethodType,
            17 => Self::Dynamic,
            18 => Self::InvokeDynamic,
            19 => Self::Module,
            20 => Self::Package,
            _ => return None,
        })
    }

    /// Returns `true` for Long/Double — wide entries occupy two slots.
    #[must_use] 
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "Utf8",
            Self::Integer => "Integer",
            Self::Float => "Float",
            Self::Long => "Long",
            Self::Double => "Double",
            Self::Class => "Class",
            Self::String => "String",
            Self::Fieldref => "Fieldref",
            Self::Methodref => "Methodref",
            Self::InterfaceMethodref => "InterfaceMethodref",
            Self::NameAndType => "NameAndType",
            Self::MethodHandle => "MethodHandle",
            Self::MethodType => "MethodType",
            Self::Dynamic => "Dynamic",
            Self::InvokeDynamic => "InvokeDynamic",
            Self::Module => "Module",
            Self::Package => "Package",
        }
    }
}

impl fmt::Display for ConstantTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── ConstantEntry ─────────────────────────────────────────────────────────────

/// A single decoded constant-pool entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantEntry {
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    /// `name_index`
    Class(u16),
    /// `string_index`
    String(u16),
    /// `class_index`, `name_and_type_index`
    Fieldref(u16, u16),
    /// `class_index`, `name_and_type_index`
    Methodref(u16, u16),
    /// `class_index`, `name_and_type_index`
    InterfaceMethodref(u16, u16),
    /// `name_index`, `descriptor_index`
    NameAndType(u16, u16),
    /// `reference_kind`, `reference_index`
    MethodHandle(u8, u16),
    /// `descriptor_index`
    MethodType(u16),
    /// `bootstrap_method_attr_index`, `name_and_type_index`
    Dynamic(u16, u16),
    /// `bootstrap_method_attr_index`, `name_and_type_index`
    InvokeDynamic(u16, u16),
    /// `name_index`
    Module(u16),
    /// `name_index`
    Package(u16),
    /// Placeholder for wide-entry second slot (Long/Double occupy two indices).
    Unusable,
}

impl ConstantEntry {
    #[must_use] 
    pub const fn tag(&self) -> Option<ConstantTag> {
        Some(match self {
            Self::Utf8(_) => ConstantTag::Utf8,
            Self::Integer(_) => ConstantTag::Integer,
            Self::Float(_) => ConstantTag::Float,
            Self::Long(_) => ConstantTag::Long,
            Self::Double(_) => ConstantTag::Double,
            Self::Class(_) => ConstantTag::Class,
            Self::String(_) => ConstantTag::String,
            Self::Fieldref(_, _) => ConstantTag::Fieldref,
            Self::Methodref(_, _) => ConstantTag::Methodref,
            Self::InterfaceMethodref(_, _) => ConstantTag::InterfaceMethodref,
            Self::NameAndType(_, _) => ConstantTag::NameAndType,
            Self::MethodHandle(_, _) => ConstantTag::MethodHandle,
            Self::MethodType(_) => ConstantTag::MethodType,
            Self::Dynamic(_, _) => ConstantTag::Dynamic,
            Self::InvokeDynamic(_, _) => ConstantTag::InvokeDynamic,
            Self::Module(_) => ConstantTag::Module,
            Self::Package(_) => ConstantTag::Package,
            Self::Unusable => return None,
        })
    }
}

impl fmt::Display for ConstantEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(s) => write!(f, "Utf8({s:?})"),
            Self::Integer(v) => write!(f, "Integer({v})"),
            Self::Float(v) => write!(f, "Float({v})"),
            Self::Long(v) => write!(f, "Long({v})"),
            Self::Double(v) => write!(f, "Double({v})"),
            Self::Class(i) => write!(f, "Class(#{i})"),
            Self::String(i) => write!(f, "String(#{i})"),
            Self::Fieldref(c, n) => write!(f, "Fieldref(#{c}, #{n})"),
            Self::Methodref(c, n) => write!(f, "Methodref(#{c}, #{n})"),
            Self::InterfaceMethodref(c, n) => write!(f, "InterfaceMethodref(#{c}, #{n})"),
            Self::NameAndType(n, d) => write!(f, "NameAndType(#{n}, #{d})"),
            Self::MethodHandle(k, i) => write!(f, "MethodHandle(kind={k}, #{i})"),
            Self::MethodType(d) => write!(f, "MethodType(#{d})"),
            Self::Dynamic(b, n) => write!(f, "Dynamic(bsm={b}, #{n})"),
            Self::InvokeDynamic(b, n) => write!(f, "InvokeDynamic(bsm={b}, #{n})"),
            Self::Module(i) => write!(f, "Module(#{i})"),
            Self::Package(i) => write!(f, "Package(#{i})"),
            Self::Unusable => f.write_str("<unusable>"),
        }
    }
}

// ── ParseError ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpParseError {
    Truncated { at: usize },
    UnknownTag { tag: u8, index: u16 },
    InvalidUtf8 { index: u16 },
    InvalidIndex { index: u16, max: u16 },
    ZeroIndex,
}

impl fmt::Display for CpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "truncated at byte offset {at}"),
            Self::UnknownTag { tag, index } => write!(f, "unknown tag 0x{tag:02x} at cp#{index}"),
            Self::InvalidUtf8 { index } => write!(f, "invalid UTF-8 in Utf8 entry cp#{index}"),
            Self::InvalidIndex { index, max } => write!(f, "index #{index} out of range (max={max})"),
            Self::ZeroIndex => f.write_str("constant pool index 0 is reserved"),
        }
    }
}

// ── JvmConstantPool ───────────────────────────────────────────────────────────

/// A parsed JVM constant pool.
///
/// Indices follow JVM convention: 1-based, range `[1, count)`.
/// `entries[0]` is unused (`Unusable`).  Wide entries (Long/Double) occupy
/// index `n` and `n+1`; the second slot is `Unusable`.
#[derive(Debug, Clone)]
pub struct JvmConstantPool {
    /// `entries[i]` corresponds to constant-pool index `i`.
    entries: Vec<ConstantEntry>,
    /// Cache of resolved class names (`cp_index` → name).
    class_name_cache: HashMap<u16, String>,
}

impl JvmConstantPool {
    /// Largest valid 1-based constant-pool index.
    ///
    /// `constant_pool_count` is a `u16`, so a maximal 65536-entry pool would
    /// make `entries.len() as u16` wrap to `0` and the following `- 1`
    /// underflow — a panic in debug and a wrap in release, reachable from
    /// attacker-supplied class-file bytes. Both steps are saturating here.
    #[must_use]
    pub fn max_index(&self) -> u16 {
        u16::try_from(self.entries.len())
            .unwrap_or(u16::MAX)
            .saturating_sub(1)
    }

    /// Parse the constant pool from `bytes`, which must start **at the first
    /// constant-pool entry** (i.e. immediately after the `constant_pool_count`
    /// field in the class file).
    ///
    /// `count` is the `constant_pool_count` field value — the pool contains
    /// `count - 1` actual entries.
    ///
    /// Returns the pool and the number of bytes consumed.
    pub fn parse(bytes: &[u8], count: u16) -> Result<(Self, usize), CpParseError> {
        if count == 0 {
            return Ok((Self { entries: vec![ConstantEntry::Unusable], class_name_cache: HashMap::new() }, 0));
        }

        let n_entries = (count as usize).saturating_sub(1);
        let mut entries: Vec<ConstantEntry> = vec![ConstantEntry::Unusable]; // index 0 unused
        entries.reserve(n_entries);

        let mut pos = 0usize;
        let mut cp_index: u16 = 1;

        while (entries.len() as u16) <= count.saturating_sub(1) && cp_index < count {
            if pos >= bytes.len() {
                return Err(CpParseError::Truncated { at: pos });
            }

            let tag_byte = bytes[pos];
            pos += 1;
            let tag = ConstantTag::from_u8(tag_byte)
                .ok_or(CpParseError::UnknownTag { tag: tag_byte, index: cp_index })?;

            let entry = match tag {
                ConstantTag::Utf8 => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let s = std::str::from_utf8(&bytes[pos..pos + len])
                        .map_err(|_| CpParseError::InvalidUtf8 { index: cp_index })?
                        .to_owned();
                    pos += len;
                    ConstantEntry::Utf8(s)
                }
                ConstantTag::Integer => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let v = i32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::Integer(v)
                }
                ConstantTag::Float => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let bits = u32::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::Float(f32::from_bits(bits))
                }
                ConstantTag::Long => {
                    if pos + 8 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let v = i64::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3],
                                               bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]);
                    pos += 8;
                    ConstantEntry::Long(v)
                }
                ConstantTag::Double => {
                    if pos + 8 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let bits = u64::from_be_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3],
                                                  bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]);
                    pos += 8;
                    ConstantEntry::Double(f64::from_bits(bits))
                }
                ConstantTag::Class => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let idx = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    pos += 2;
                    ConstantEntry::Class(idx)
                }
                ConstantTag::String => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let idx = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    pos += 2;
                    ConstantEntry::String(idx)
                }
                ConstantTag::Fieldref => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let c = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let n = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::Fieldref(c, n)
                }
                ConstantTag::Methodref => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let c = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let n = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::Methodref(c, n)
                }
                ConstantTag::InterfaceMethodref => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let c = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let n = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::InterfaceMethodref(c, n)
                }
                ConstantTag::NameAndType => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let n = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let d = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::NameAndType(n, d)
                }
                ConstantTag::MethodHandle => {
                    if pos + 3 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let kind = bytes[pos];
                    let idx = u16::from_be_bytes([bytes[pos+1], bytes[pos+2]]);
                    pos += 3;
                    ConstantEntry::MethodHandle(kind, idx)
                }
                ConstantTag::MethodType => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let d = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    pos += 2;
                    ConstantEntry::MethodType(d)
                }
                ConstantTag::Dynamic => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let b = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let n = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::Dynamic(b, n)
                }
                ConstantTag::InvokeDynamic => {
                    if pos + 4 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let b = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    let n = u16::from_be_bytes([bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    ConstantEntry::InvokeDynamic(b, n)
                }
                ConstantTag::Module => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let i = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    pos += 2;
                    ConstantEntry::Module(i)
                }
                ConstantTag::Package => {
                    if pos + 2 > bytes.len() { return Err(CpParseError::Truncated { at: pos }); }
                    let i = u16::from_be_bytes([bytes[pos], bytes[pos+1]]);
                    pos += 2;
                    ConstantEntry::Package(i)
                }
            };

            let is_wide = tag.is_wide();
            entries.push(entry);
            cp_index += 1;
            if is_wide {
                // Wide entries occupy two slots; second is unusable.
                entries.push(ConstantEntry::Unusable);
                cp_index += 1;
            }
        }

        let pool = Self {
            entries,
            class_name_cache: HashMap::new(),
        };
        Ok((pool, pos))
    }

    /// Number of slots in the pool (includes the index-0 placeholder).
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.len() <= 1
    }

    /// Access entry at 1-based `index`, or `None` if out of range.
    #[must_use] 
    pub fn get(&self, index: u16) -> Option<&ConstantEntry> {
        self.entries.get(index as usize)
    }

    /// Resolve a `Utf8` entry at `index` to a `&str`.
    pub fn resolve_utf8(&self, index: u16) -> Result<&str, CpParseError> {
        if index == 0 { return Err(CpParseError::ZeroIndex); }
        match self.entries.get(index as usize) {
            Some(ConstantEntry::Utf8(s)) => Ok(s.as_str()),
            // Wrong tag and out-of-range index are the same diagnostic.
            Some(_) | None => Err(CpParseError::InvalidIndex { index, max: self.max_index() }),
        }
    }

    /// Resolve a `Class` entry at `index` to its class name string.
    pub fn resolve_class(&mut self, index: u16) -> Result<String, CpParseError> {
        if let Some(cached) = self.class_name_cache.get(&index) {
            return Ok(cached.clone());
        }
        let name_index = match self.entries.get(index as usize) {
            Some(ConstantEntry::Class(i)) => *i,
            _ => return Err(CpParseError::InvalidIndex { index, max: self.max_index() }),
        };
        let name = self.resolve_utf8(name_index)?.to_owned();
        self.class_name_cache.insert(index, name.clone());
        Ok(name)
    }

    /// Resolve a `NameAndType` entry to `(name, descriptor)`.
    pub fn resolve_name_and_type(&self, index: u16) -> Result<(&str, &str), CpParseError> {
        match self.entries.get(index as usize) {
            Some(ConstantEntry::NameAndType(n, d)) => {
                Ok((self.resolve_utf8(*n)?, self.resolve_utf8(*d)?))
            }
            _ => Err(CpParseError::InvalidIndex { index, max: self.max_index() }),
        }
    }

    /// Resolve a `Methodref` or `Interfaceref` to `(class_index, name, descriptor)`.
    pub fn resolve_method_ref(&mut self, index: u16) -> Result<(u16, String, String), CpParseError> {
        let (class_index, nat_index) = match self.entries.get(index as usize) {
            Some(ConstantEntry::Methodref(c, n) | ConstantEntry::InterfaceMethodref(c, n)) => (*c, *n),
            _ => return Err(CpParseError::InvalidIndex { index, max: self.max_index() }),
        };
        let (name, desc) = self.resolve_name_and_type(nat_index)?;
        let (name, desc) = (name.to_owned(), desc.to_owned());
        let class_name = self.resolve_class(class_index)?;
        let _ = class_name;
        Ok((class_index, name, desc))
    }

    /// Collect all `Utf8` strings in the pool.
    #[must_use] 
    pub fn all_utf8(&self) -> Vec<(u16, &str)> {
        self.entries.iter().enumerate().filter_map(|(i, e)| {
            if let ConstantEntry::Utf8(s) = e {
                Some((numeric::usize_to_u16(i), s.as_str()))
            } else {
                None
            }
        }).collect()
    }

    /// Count entries by tag.
    #[must_use] 
    pub fn tag_counts(&self) -> HashMap<String, usize> {
        let mut m: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            if let Some(tag) = e.tag() {
                *m.entry(tag.to_string()).or_insert(0) += 1;
            }
        }
        m
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal constant-pool byte buffer:
    /// cp#1 = Utf8("Hello"), cp#2 = Utf8("World")
    fn simple_cp_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        // Entry 1: Utf8 "Hello"
        v.push(1u8); // tag
        v.extend_from_slice(&(5u16).to_be_bytes()); // length
        v.extend_from_slice(b"Hello");
        // Entry 2: Utf8 "World"
        v.push(1u8);
        v.extend_from_slice(&(5u16).to_be_bytes());
        v.extend_from_slice(b"World");
        v
    }

    /// Build a cp with one Integer entry.
    fn integer_cp_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.push(3u8); // Integer tag
        v.extend_from_slice(&42i32.to_be_bytes());
        v
    }

    /// Build a cp with Class -> Utf8 chain.
    fn class_cp_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        // cp#1 = Class(#2)
        v.push(7u8);
        v.extend_from_slice(&2u16.to_be_bytes());
        // cp#2 = Utf8("java/lang/Object")
        let name = b"java/lang/Object";
        v.push(1u8);
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        v
    }

    #[test]
    fn parse_two_utf8_entries() {
        let bytes = simple_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        assert_eq!(cp.resolve_utf8(1).unwrap(), "Hello");
        assert_eq!(cp.resolve_utf8(2).unwrap(), "World");
    }

    #[test]
    fn parse_integer_entry() {
        let bytes = integer_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 2).unwrap();
        assert_eq!(cp.get(1), Some(&ConstantEntry::Integer(42)));
    }

    #[test]
    fn parse_class_entry() {
        let bytes = class_cp_bytes();
        let (mut cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        let name = cp.resolve_class(1).unwrap();
        assert_eq!(name, "java/lang/Object");
    }

    #[test]
    fn parse_long_occupies_two_slots() {
        let mut v = Vec::new();
        v.push(5u8); // Long
        v.extend_from_slice(&100i64.to_be_bytes());
        let (cp, _) = JvmConstantPool::parse(&v, 3).unwrap(); // count=3 → 2 slots used
        assert_eq!(cp.get(1), Some(&ConstantEntry::Long(100)));
        assert_eq!(cp.get(2), Some(&ConstantEntry::Unusable));
    }

    #[test]
    fn parse_float_entry() {
        let mut v = Vec::new();
        v.push(4u8); // Float
        v.extend_from_slice(&1.5f32.to_bits().to_be_bytes());
        let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
        if let Some(ConstantEntry::Float(f)) = cp.get(1) {
            assert!((*f - 1.5f32).abs() < 1e-6);
        } else {
            panic!("expected Float entry");
        }
    }

    #[test]
    fn parse_methodref_entry() {
        let mut v = Vec::new();
        v.push(10u8); // Methodref
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes());
        let (cp, _) = JvmConstantPool::parse(&v, 2).unwrap();
        assert_eq!(cp.get(1), Some(&ConstantEntry::Methodref(1, 2)));
    }

    #[test]
    fn resolve_utf8_zero_index_errors() {
        let bytes = simple_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        assert_eq!(cp.resolve_utf8(0), Err(CpParseError::ZeroIndex));
    }

    #[test]
    fn resolve_utf8_out_of_range_errors() {
        let bytes = simple_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        assert!(cp.resolve_utf8(99).is_err());
    }

    #[test]
    fn all_utf8_returns_all_strings() {
        let bytes = simple_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        let utf8s = cp.all_utf8();
        assert_eq!(utf8s.len(), 2);
        let strings: Vec<&str> = utf8s.iter().map(|(_, s)| *s).collect();
        assert!(strings.contains(&"Hello"));
        assert!(strings.contains(&"World"));
    }

    #[test]
    fn tag_counts_utf8() {
        let bytes = simple_cp_bytes();
        let (cp, _) = JvmConstantPool::parse(&bytes, 3).unwrap();
        let counts = cp.tag_counts();
        assert_eq!(counts.get("Utf8").copied().unwrap_or(0), 2);
    }

    #[test]
    fn empty_pool() {
        let (cp, consumed) = JvmConstantPool::parse(&[], 0).unwrap();
        assert!(cp.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn truncated_entry_error() {
        let v = vec![1u8, 0, 10]; // Utf8 claims 10 bytes but none follow
        let result = JvmConstantPool::parse(&v, 2);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_tag_error() {
        let v = vec![0xFFu8];
        let result = JvmConstantPool::parse(&v, 2);
        assert!(matches!(result, Err(CpParseError::UnknownTag { .. })));
    }

    #[test]
    fn constant_tag_is_wide() {
        assert!(ConstantTag::Long.is_wide());
        assert!(ConstantTag::Double.is_wide());
        assert!(!ConstantTag::Integer.is_wide());
        assert!(!ConstantTag::Utf8.is_wide());
    }

    #[test]
    fn constant_tag_name() {
        assert_eq!(ConstantTag::Methodref.name(), "Methodref");
        assert_eq!(ConstantTag::InvokeDynamic.name(), "InvokeDynamic");
    }

    #[test]
    fn constant_entry_display_utf8() {
        let e = ConstantEntry::Utf8("hello".into());
        assert!(e.to_string().contains("Utf8"));
    }

    #[test]
    fn bytes_consumed_matches_input_length() {
        let bytes = simple_cp_bytes();
        let (_cp, consumed) = JvmConstantPool::parse(&bytes, 3).unwrap();
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn nameandtype_resolution() {
        let mut v = Vec::new();
        // cp#1 = NameAndType(#2, #3)
        v.push(12u8);
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes());
        // cp#2 = Utf8("<init>")
        let name = b"<init>";
        v.push(1u8); v.extend_from_slice(&(name.len() as u16).to_be_bytes()); v.extend_from_slice(name);
        // cp#3 = Utf8("()V")
        let desc = b"()V";
        v.push(1u8); v.extend_from_slice(&(desc.len() as u16).to_be_bytes()); v.extend_from_slice(desc);

        let (cp, _) = JvmConstantPool::parse(&v, 4).unwrap();
        let (n, d) = cp.resolve_name_and_type(1).unwrap();
        assert_eq!(n, "<init>");
        assert_eq!(d, "()V");
    }
}
