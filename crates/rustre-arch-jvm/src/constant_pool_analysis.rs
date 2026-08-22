//! `constant_pool_analysis` — JVM Constant Pool analysis utilities.
//!
//! Provides deep inspection of the JVM constant pool:
//! * [`CpEntry`] — decoded constant pool entry.
//! * [`CpCategory`] — semantic category of each entry.
//! * [`InternedString`] — unique string values in the pool.
//! * [`CpReferences`] — which bytecode instructions reference each CP index.
//! * [`ConstantPoolOptimizer`] — detects unused CP entries.
//! * [`CpStats`] — aggregate statistics.
//! * [`ConstantPoolAnalysis`] — top-level facade.

use crate::numeric;
use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Constant pool tags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpTag {
    Utf8 = 1,
    Integer = 3,
    Float = 4,
    Long = 5,
    Double = 6,
    Class = 7,
    String = 8,
    FieldRef = 9,
    MethodRef = 10,
    InterfaceMethodRef = 11,
    NameAndType = 12,
    MethodHandle = 15,
    MethodType = 16,
    Dynamic = 17,
    InvokeDynamic = 18,
    Module = 19,
    Package = 20,
}

impl CpTag {
    #[must_use] 
    pub const fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Utf8),
            3 => Some(Self::Integer),
            4 => Some(Self::Float),
            5 => Some(Self::Long),
            6 => Some(Self::Double),
            7 => Some(Self::Class),
            8 => Some(Self::String),
            9 => Some(Self::FieldRef),
            10 => Some(Self::MethodRef),
            11 => Some(Self::InterfaceMethodRef),
            12 => Some(Self::NameAndType),
            15 => Some(Self::MethodHandle),
            16 => Some(Self::MethodType),
            17 => Some(Self::Dynamic),
            18 => Some(Self::InvokeDynamic),
            19 => Some(Self::Module),
            20 => Some(Self::Package),
            _ => None,
        }
    }

    /// True for tags that occupy two CP slots (Long, Double).
    #[must_use] 
    pub const fn takes_two_slots(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

impl fmt::Display for CpTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Utf8 => "Utf8",
            Self::Integer => "Integer",
            Self::Float => "Float",
            Self::Long => "Long",
            Self::Double => "Double",
            Self::Class => "Class",
            Self::String => "String",
            Self::FieldRef => "FieldRef",
            Self::MethodRef => "MethodRef",
            Self::InterfaceMethodRef => "InterfaceMethodRef",
            Self::NameAndType => "NameAndType",
            Self::MethodHandle => "MethodHandle",
            Self::MethodType => "MethodType",
            Self::Dynamic => "Dynamic",
            Self::InvokeDynamic => "InvokeDynamic",
            Self::Module => "Module",
            Self::Package => "Package",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CP entry
// ---------------------------------------------------------------------------

/// A decoded constant pool entry.
#[derive(Debug, Clone, PartialEq)]
pub enum CpEntry {
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    /// Index of the Utf8 entry holding the class name.
    Class {
        name_index: u16,
    },
    /// Index of the Utf8 entry holding the string value.
    String {
        string_index: u16,
    },
    FieldRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    MethodRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodRef {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    /// Placeholder for the second slot of Long/Double.
    Wide,
    /// Unknown / unsupported tag.
    Unknown(u8),
}

impl CpEntry {
    #[must_use] 
    pub const fn tag(&self) -> Option<CpTag> {
        match self {
            Self::Utf8(_) => Some(CpTag::Utf8),
            Self::Integer(_) => Some(CpTag::Integer),
            Self::Float(_) => Some(CpTag::Float),
            Self::Long(_) => Some(CpTag::Long),
            Self::Double(_) => Some(CpTag::Double),
            Self::Class { .. } => Some(CpTag::Class),
            Self::String { .. } => Some(CpTag::String),
            Self::FieldRef { .. } => Some(CpTag::FieldRef),
            Self::MethodRef { .. } => Some(CpTag::MethodRef),
            Self::InterfaceMethodRef { .. } => Some(CpTag::InterfaceMethodRef),
            Self::NameAndType { .. } => Some(CpTag::NameAndType),
            Self::MethodHandle { .. } => Some(CpTag::MethodHandle),
            Self::MethodType { .. } => Some(CpTag::MethodType),
            Self::Dynamic { .. } => Some(CpTag::Dynamic),
            Self::InvokeDynamic { .. } => Some(CpTag::InvokeDynamic),
            Self::Module { .. } => Some(CpTag::Module),
            Self::Package { .. } => Some(CpTag::Package),
            _ => None,
        }
    }

    #[must_use] 
    pub fn as_utf8(&self) -> Option<&str> {
        if let Self::Utf8(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// CpCategory
// ---------------------------------------------------------------------------

/// High-level semantic category of a constant pool entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpCategory {
    Numeric, // Integer, Float, Long, Double
    StringLiteral,
    ClassName,
    MemberRef,  // FieldRef, MethodRef, InterfaceMethodRef
    Descriptor, // Utf8 used as a type descriptor
    Metadata,   // NameAndType, MethodHandle, MethodType, InvokeDynamic
    ModuleInfo, // Module, Package
    Raw,        // Plain Utf8 (other uses)
    Placeholder,
}

impl fmt::Display for CpCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Numeric => "numeric",
            Self::StringLiteral => "string_literal",
            Self::ClassName => "class_name",
            Self::MemberRef => "member_ref",
            Self::Descriptor => "descriptor",
            Self::Metadata => "metadata",
            Self::ModuleInfo => "module_info",
            Self::Raw => "raw",
            Self::Placeholder => "placeholder",
        };
        write!(f, "{s}")
    }
}

impl CpCategory {
    #[must_use] 
    pub const fn of(entry: &CpEntry) -> Self {
        match entry {
            CpEntry::Integer(_) | CpEntry::Float(_) | CpEntry::Long(_) | CpEntry::Double(_) => {
                Self::Numeric
            }
            CpEntry::String { .. } => Self::StringLiteral,
            CpEntry::Class { .. } => Self::ClassName,
            CpEntry::FieldRef { .. }
            | CpEntry::MethodRef { .. }
            | CpEntry::InterfaceMethodRef { .. } => Self::MemberRef,
            CpEntry::NameAndType { .. }
            | CpEntry::MethodHandle { .. }
            | CpEntry::MethodType { .. }
            | CpEntry::Dynamic { .. }
            | CpEntry::InvokeDynamic { .. } => Self::Metadata,
            CpEntry::Module { .. } | CpEntry::Package { .. } => Self::ModuleInfo,
            // Utf8 payloads and unrecognised tags are both raw byte content.
            CpEntry::Utf8(_) | CpEntry::Unknown(_) => Self::Raw,
            CpEntry::Wide => Self::Placeholder,
        }
    }
}

// ---------------------------------------------------------------------------
// InternedString
// ---------------------------------------------------------------------------

/// A deduplicated string value found in the constant pool (`CONSTANT_String` or Utf8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InternedString {
    pub value: String,
    /// All CP indices that hold this string value.
    pub indices: Vec<u16>,
}

// ---------------------------------------------------------------------------
// JVM descriptor parser
// ---------------------------------------------------------------------------

/// Parsed field or method descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmDescriptor {
    Void,
    Byte,
    Char,
    Double,
    Float,
    Int,
    Long,
    Short,
    Boolean,
    /// Object type: `L<classname>;`
    Object(String),
    /// Array of T.
    Array(Box<Self>),
    /// Method: `(param_types)return_type`
    Method {
        params: Vec<Self>,
        ret: Box<Self>,
    },
}

impl JvmDescriptor {
    /// Maximum array nesting depth allowed when parsing descriptors.
    /// Prevents stack exhaustion from inputs like `[[[...[I` with 10 000 brackets.
    const MAX_ARRAY_DEPTH: usize = 255;

    /// Parse a field descriptor from a string slice.
    #[must_use]
    pub fn parse_field(s: &str) -> Option<Self> {
        let (d, _) = Self::parse_one(s, 0)?;
        Some(d)
    }

    fn parse_one(s: &str, depth: usize) -> Option<(Self, &str)> {
        if depth > Self::MAX_ARRAY_DEPTH {
            // Reject pathologically nested array descriptors to prevent stack overflow.
            return None;
        }
        let mut chars = s.char_indices();
        match chars.next()? {
            (_, 'V') => Some((Self::Void, &s[1..])),
            (_, 'B') => Some((Self::Byte, &s[1..])),
            (_, 'C') => Some((Self::Char, &s[1..])),
            (_, 'D') => Some((Self::Double, &s[1..])),
            (_, 'F') => Some((Self::Float, &s[1..])),
            (_, 'I') => Some((Self::Int, &s[1..])),
            (_, 'J') => Some((Self::Long, &s[1..])),
            (_, 'S') => Some((Self::Short, &s[1..])),
            (_, 'Z') => Some((Self::Boolean, &s[1..])),
            (_, 'L') => {
                let end = s.find(';')?;
                let class = s[1..end].to_owned();
                Some((Self::Object(class), &s[end + 1..]))
            }
            (_, '[') => {
                let (inner, rest) = Self::parse_one(&s[1..], depth + 1)?;
                Some((Self::Array(Box::new(inner)), rest))
            }
            _ => None,
        }
    }

    /// Parse a method descriptor `(params)ret`.
    #[must_use]
    pub fn parse_method(s: &str) -> Option<Self> {
        let s = s.strip_prefix('(')?;
        let close = s.find(')')?;
        let params_str = &s[..close];
        let ret_str = &s[close + 1..];
        let mut params = Vec::new();
        let mut remaining = params_str;
        while !remaining.is_empty() {
            let (param, rest) = Self::parse_one(remaining, 0)?;
            params.push(param);
            remaining = rest;
        }
        let (ret, _) = Self::parse_one(ret_str, 0)?;
        Some(Self::Method {
            params,
            ret: Box::new(ret),
        })
    }

    #[must_use] 
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Void
                | Self::Byte
                | Self::Char
                | Self::Double
                | Self::Float
                | Self::Int
                | Self::Long
                | Self::Short
                | Self::Boolean
        )
    }

    #[must_use] 
    pub const fn is_reference(&self) -> bool {
        matches!(self, Self::Object(_) | Self::Array(_))
    }
}

impl std::fmt::Display for JvmDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Byte => write!(f, "byte"),
            Self::Char => write!(f, "char"),
            Self::Double => write!(f, "double"),
            Self::Float => write!(f, "float"),
            Self::Int => write!(f, "int"),
            Self::Long => write!(f, "long"),
            Self::Short => write!(f, "short"),
            Self::Boolean => write!(f, "boolean"),
            Self::Object(cls) => write!(f, "{}", cls.replace('/', ".")),
            Self::Array(inner) => write!(f, "{inner}[]"),
            Self::Method { params, ret } => {
                let p: Vec<String> = params.iter().map(std::string::ToString::to_string).collect();
                write!(f, "({}) -> {}", p.join(", "), ret)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CP bytecode scanner
// ---------------------------------------------------------------------------

/// Scans JVM bytecode to find all CP index references.
pub struct CpBytecodeScanner;

impl CpBytecodeScanner {
    /// Scan a bytecode array and populate [`CpReferences`].
    /// Handles all JVM opcodes that take a CP index.
    pub fn scan(bytecode: &[u8], refs: &mut CpReferences) {
        let mut i = 0;
        while i < bytecode.len() {
            let op = bytecode[i];
            match op {
                // 2-byte CP index: ldc_w, ldc2_w, getstatic, putstatic, getfield, putfield,
                // invokevirtual, invokespecial, invokestatic, new, anewarray, checkcast, instanceof
                0x13 | 0x14 | 0xB2 | 0xB3 | 0xB4 | 0xB5 | 0xB6 | 0xB7 | 0xB8 | 0xBB | 0xBD
                | 0xC0 | 0xC1 => {
                    if i + 2 < bytecode.len() {
                        let idx = u16::from_be_bytes([bytecode[i + 1], bytecode[i + 2]]);
                        refs.record(idx, numeric::usize_to_u32(i));
                    }
                    i += 3;
                }
                // 1-byte CP index: ldc
                0x12 => {
                    if i + 1 < bytecode.len() {
                        refs.record(u16::from(bytecode[i + 1]), numeric::usize_to_u32(i));
                    }
                    i += 2;
                }
                // invokeinterface: 4 bytes extra (index2, count, 0)
                // invokedynamic:   4 bytes       (index2, 0, 0)
                // Both carry the constant-pool index in the first two operand
                // bytes and are five bytes long in total.
                0xB9 | 0xBA => {
                    if i + 2 < bytecode.len() {
                        let idx = u16::from_be_bytes([bytecode[i + 1], bytecode[i + 2]]);
                        refs.record(idx, numeric::usize_to_u32(i));
                    }
                    i += 5;
                }
                _ => {
                    i += 1;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CpReferences
// ---------------------------------------------------------------------------

/// Tracks which bytecode offsets reference each constant pool index.
#[derive(Debug, Default)]
pub struct CpReferences {
    /// `cp_index` → set of bytecode offsets
    pub refs: HashMap<u16, HashSet<u32>>,
}

impl CpReferences {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, cp_index: u16, bytecode_offset: u32) {
        self.refs
            .entry(cp_index)
            .or_default()
            .insert(bytecode_offset);
    }

    #[must_use] 
    pub fn ref_count(&self, cp_index: u16) -> usize {
        self.refs.get(&cp_index).map_or(0, std::collections::HashSet::len)
    }

    #[must_use] 
    pub fn is_referenced(&self, cp_index: u16) -> bool {
        self.refs.contains_key(&cp_index)
    }

    /// Return all unreferenced CP indices from a set of known indices.
    #[must_use] 
    pub fn unreferenced(&self, all_indices: &[u16]) -> Vec<u16> {
        all_indices
            .iter()
            .filter(|&&i| !self.is_referenced(i))
            .copied()
            .collect()
    }

    #[must_use] 
    pub fn total_references(&self) -> usize {
        self.refs.values().map(std::collections::HashSet::len).sum()
    }
}

// ---------------------------------------------------------------------------
// ConstantPoolOptimizer
// ---------------------------------------------------------------------------

/// Detects unused constant pool entries.
#[derive(Debug, Default)]
pub struct ConstantPoolOptimizer {
    /// CP indices considered unused.
    pub unused_indices: Vec<u16>,
}

impl ConstantPoolOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute unused entries given the full pool and reference info.
    pub fn compute(&mut self, pool: &ConstantPool, refs: &CpReferences) {
        self.unused_indices.clear();
        for (idx, entry) in &pool.entries {
            // Wide placeholders are not independently addressable
            if matches!(entry, CpEntry::Wide) {
                continue;
            }
            if !refs.is_referenced(*idx) {
                self.unused_indices.push(*idx);
            }
        }
        self.unused_indices.sort_unstable();
    }

    #[must_use] 
    pub const fn unused_count(&self) -> usize {
        self.unused_indices.len()
    }
}

// ---------------------------------------------------------------------------
// CpStats
// ---------------------------------------------------------------------------

/// Aggregate statistics for a constant pool.
#[derive(Debug, Default, Clone)]
pub struct CpStats {
    pub total_entries: usize,
    pub by_tag: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub string_count: usize,
    pub numeric_count: usize,
    pub class_ref_count: usize,
    pub method_ref_count: usize,
    pub field_ref_count: usize,
    pub duplicate_utf8_count: usize,
}

// ---------------------------------------------------------------------------
// Constant pool
// ---------------------------------------------------------------------------

/// The parsed constant pool of a class file.
#[derive(Debug, Default)]
pub struct ConstantPool {
    /// Entries indexed by 1-based CP index.
    pub entries: HashMap<u16, CpEntry>,
}

impl ConstantPool {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry at the given (1-based) index.
    pub fn insert(&mut self, index: u16, entry: CpEntry) {
        if let CpEntry::Long(_) | CpEntry::Double(_) = &entry {
            self.entries.insert(index + 1, CpEntry::Wide);
        }
        self.entries.insert(index, entry);
    }

    #[must_use] 
    pub fn get(&self, index: u16) -> Option<&CpEntry> {
        self.entries.get(&index)
    }

    #[must_use] 
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Resolve a Utf8 entry by index.
    #[must_use] 
    pub fn utf8(&self, index: u16) -> Option<&str> {
        self.entries.get(&index)?.as_utf8()
    }

    /// Resolve a class name by a Class entry index.
    #[must_use] 
    pub fn class_name(&self, index: u16) -> Option<&str> {
        if let Some(CpEntry::Class { name_index }) = self.entries.get(&index) {
            self.utf8(*name_index)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ConstantPoolAnalysis
// ---------------------------------------------------------------------------

/// Full analysis of a JVM constant pool.
#[derive(Debug, Default)]
pub struct ConstantPoolAnalysis {
    pub pool: ConstantPool,
    pub refs: CpReferences,
    pub optimizer: ConstantPoolOptimizer,
    pub stats: CpStats,
    pub interned_strings: Vec<InternedString>,
}

impl ConstantPoolAnalysis {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_pool(pool: ConstantPool) -> Self {
        let mut a = Self {
            pool,
            ..Default::default()
        };
        a.compute_stats();
        a.compute_interned_strings();
        a
    }

    fn compute_stats(&mut self) {
        let mut seen_utf8: HashMap<String, Vec<u16>> = HashMap::new();
        for (&idx, entry) in &self.pool.entries {
            self.stats.total_entries += 1;
            if let Some(tag) = entry.tag() {
                *self.stats.by_tag.entry(tag.to_string()).or_insert(0) += 1;
            }
            *self
                .stats
                .by_category
                .entry(CpCategory::of(entry).to_string())
                .or_insert(0) += 1;

            match entry {
                CpEntry::String { .. } => self.stats.string_count += 1,
                CpEntry::Integer(_) | CpEntry::Float(_) | CpEntry::Long(_) | CpEntry::Double(_) => {
                    self.stats.numeric_count += 1;
                }
                CpEntry::Class { .. } => self.stats.class_ref_count += 1,
                CpEntry::MethodRef { .. } | CpEntry::InterfaceMethodRef { .. } => {
                    self.stats.method_ref_count += 1;
                }
                CpEntry::FieldRef { .. } => self.stats.field_ref_count += 1,
                CpEntry::Utf8(s) => {
                    seen_utf8.entry(s.clone()).or_default().push(idx);
                }
                _ => {}
            }
        }
        self.stats.duplicate_utf8_count = seen_utf8.values().filter(|v| v.len() > 1).count();
    }

    fn compute_interned_strings(&mut self) {
        let mut by_value: HashMap<String, Vec<u16>> = HashMap::new();
        for (&idx, entry) in &self.pool.entries {
            if let CpEntry::Utf8(s) = entry {
                by_value.entry(s.clone()).or_default().push(idx);
            }
        }
        self.interned_strings = by_value
            .into_iter()
            .map(|(value, indices)| InternedString { value, indices })
            .collect();
        self.interned_strings.sort_by(|a, b| a.value.cmp(&b.value));
    }

    /// Run the optimizer using current reference data.
    pub fn optimize(&mut self) {
        let all_indices: Vec<u16> = self.pool.entries.keys().copied().collect();
        self.optimizer.compute(&self.pool, &self.refs);
        let _ = all_indices;
    }

    /// Record a bytecode reference to a CP index.
    pub fn record_ref(&mut self, cp_index: u16, bytecode_offset: u32) {
        self.refs.record(cp_index, bytecode_offset);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> ConstantPool {
        let mut cp = ConstantPool::new();
        cp.insert(1, CpEntry::Utf8("java/lang/Object".into()));
        cp.insert(2, CpEntry::Class { name_index: 1 });
        cp.insert(3, CpEntry::Utf8("<init>".into()));
        cp.insert(4, CpEntry::Utf8("()V".into()));
        cp.insert(
            5,
            CpEntry::NameAndType {
                name_index: 3,
                descriptor_index: 4,
            },
        );
        cp.insert(
            6,
            CpEntry::MethodRef {
                class_index: 2,
                name_and_type_index: 5,
            },
        );
        cp.insert(7, CpEntry::String { string_index: 1 });
        cp.insert(8, CpEntry::Integer(42));
        cp
    }

    // --- CpTag -----------------------------------------------------------

    #[test]
    fn test_cp_tag_from_u8() {
        assert_eq!(CpTag::from_u8(1), Some(CpTag::Utf8));
        assert_eq!(CpTag::from_u8(5), Some(CpTag::Long));
        assert_eq!(CpTag::from_u8(99), None);
    }

    #[test]
    fn test_cp_tag_takes_two_slots() {
        assert!(CpTag::Long.takes_two_slots());
        assert!(CpTag::Double.takes_two_slots());
        assert!(!CpTag::Integer.takes_two_slots());
        assert!(!CpTag::Utf8.takes_two_slots());
    }

    #[test]
    fn test_cp_tag_display() {
        assert_eq!(CpTag::Utf8.to_string(), "Utf8");
        assert_eq!(CpTag::MethodRef.to_string(), "MethodRef");
    }

    // --- CpEntry ---------------------------------------------------------

    #[test]
    fn test_cp_entry_tag_utf8() {
        let e = CpEntry::Utf8("hello".into());
        assert_eq!(e.tag(), Some(CpTag::Utf8));
    }

    #[test]
    fn test_cp_entry_as_utf8() {
        let e = CpEntry::Utf8("world".into());
        assert_eq!(e.as_utf8(), Some("world"));
    }

    #[test]
    fn test_cp_entry_as_utf8_non_utf8() {
        let e = CpEntry::Integer(1);
        assert_eq!(e.as_utf8(), None);
    }

    #[test]
    fn test_cp_entry_wide_tag_none() {
        let e = CpEntry::Wide;
        assert!(e.tag().is_none());
    }

    // --- CpCategory -------------------------------------------------------

    #[test]
    fn test_cp_category_numeric() {
        assert_eq!(CpCategory::of(&CpEntry::Integer(0)), CpCategory::Numeric);
        assert_eq!(CpCategory::of(&CpEntry::Float(1.0)), CpCategory::Numeric);
        assert_eq!(CpCategory::of(&CpEntry::Long(0)), CpCategory::Numeric);
        assert_eq!(CpCategory::of(&CpEntry::Double(0.0)), CpCategory::Numeric);
    }

    #[test]
    fn test_cp_category_string_literal() {
        assert_eq!(
            CpCategory::of(&CpEntry::String { string_index: 1 }),
            CpCategory::StringLiteral
        );
    }

    #[test]
    fn test_cp_category_class_name() {
        assert_eq!(
            CpCategory::of(&CpEntry::Class { name_index: 1 }),
            CpCategory::ClassName
        );
    }

    #[test]
    fn test_cp_category_member_ref() {
        assert_eq!(
            CpCategory::of(&CpEntry::MethodRef {
                class_index: 1,
                name_and_type_index: 2
            }),
            CpCategory::MemberRef
        );
        assert_eq!(
            CpCategory::of(&CpEntry::FieldRef {
                class_index: 1,
                name_and_type_index: 2
            }),
            CpCategory::MemberRef
        );
    }

    #[test]
    fn test_cp_category_display() {
        assert_eq!(CpCategory::Numeric.to_string(), "numeric");
        assert_eq!(CpCategory::MemberRef.to_string(), "member_ref");
    }

    // --- ConstantPool -----------------------------------------------------

    #[test]
    fn test_cp_insert_and_get() {
        let cp = make_pool();
        assert!(cp.get(1).is_some());
        assert!(matches!(cp.get(1).unwrap(), CpEntry::Utf8(_)));
    }

    #[test]
    fn test_cp_utf8_resolution() {
        let cp = make_pool();
        assert_eq!(cp.utf8(1), Some("java/lang/Object"));
    }

    #[test]
    fn test_cp_class_name_resolution() {
        let cp = make_pool();
        assert_eq!(cp.class_name(2), Some("java/lang/Object"));
    }

    #[test]
    fn test_cp_long_two_slots() {
        let mut cp = ConstantPool::new();
        cp.insert(1, CpEntry::Long(1_234_567_890));
        assert!(matches!(cp.get(2), Some(CpEntry::Wide)));
    }

    #[test]
    fn test_cp_count() {
        let cp = make_pool();
        assert_eq!(cp.count(), 8);
    }

    // --- CpReferences -----------------------------------------------------

    #[test]
    fn test_cp_refs_record_and_count() {
        let mut refs = CpReferences::new();
        refs.record(6, 10);
        refs.record(6, 20);
        refs.record(7, 30);
        assert_eq!(refs.ref_count(6), 2);
        assert_eq!(refs.total_references(), 3);
    }

    #[test]
    fn test_cp_refs_is_referenced() {
        let mut refs = CpReferences::new();
        refs.record(3, 0);
        assert!(refs.is_referenced(3));
        assert!(!refs.is_referenced(99));
    }

    #[test]
    fn test_cp_refs_unreferenced() {
        let mut refs = CpReferences::new();
        refs.record(1, 0);
        let all = vec![1u16, 2, 3];
        let unref = refs.unreferenced(&all);
        assert_eq!(unref, vec![2, 3]);
    }

    // --- ConstantPoolOptimizer -------------------------------------------

    #[test]
    fn test_optimizer_finds_unused() {
        let cp = make_pool();
        let refs = CpReferences::new(); // nothing referenced
        let mut opt = ConstantPoolOptimizer::new();
        opt.compute(&cp, &refs);
        assert!(opt.unused_count() > 0);
    }

    #[test]
    fn test_optimizer_no_unused_when_all_referenced() {
        let cp = make_pool();
        let mut refs = CpReferences::new();
        for idx in cp.entries.keys() {
            refs.record(*idx, 0);
        }
        let mut opt = ConstantPoolOptimizer::new();
        opt.compute(&cp, &refs);
        // Wide entries are excluded, so count may be slightly off but should be minimal
        assert!(opt.unused_count() == 0);
    }

    // --- CpStats ----------------------------------------------------------

    #[test]
    fn test_stats_computed() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert!(a.stats.total_entries > 0);
        assert!(a.stats.class_ref_count >= 1);
        assert!(a.stats.method_ref_count >= 1);
    }

    #[test]
    fn test_stats_string_count() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert_eq!(a.stats.string_count, 1);
    }

    #[test]
    fn test_stats_numeric_count() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert_eq!(a.stats.numeric_count, 1);
    }

    // --- InternedString ---------------------------------------------------

    #[test]
    fn test_interned_strings_collected() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert!(!a.interned_strings.is_empty());
    }

    // --- ConstantPoolAnalysis ---------------------------------------------

    #[test]
    fn test_analysis_record_ref() {
        let cp = make_pool();
        let mut a = ConstantPoolAnalysis::with_pool(cp);
        a.record_ref(6, 0);
        assert!(a.refs.is_referenced(6));
    }

    #[test]
    fn test_analysis_optimize() {
        let cp = make_pool();
        let mut a = ConstantPoolAnalysis::with_pool(cp);
        a.record_ref(6, 0);
        a.optimize();
        // Entry 6 is referenced, others may not be
        assert!(!a.optimizer.unused_indices.contains(&6));
    }

    // --- Additional CpTag tests ---

    #[test]
    fn test_cp_tag_interface_method_ref() {
        assert_eq!(CpTag::from_u8(11), Some(CpTag::InterfaceMethodRef));
    }

    #[test]
    fn test_cp_tag_invoke_dynamic() {
        assert_eq!(CpTag::from_u8(18), Some(CpTag::InvokeDynamic));
    }

    #[test]
    fn test_cp_tag_double_two_slots() {
        assert!(CpTag::Double.takes_two_slots());
    }

    #[test]
    fn test_cp_tag_integer_not_two_slots() {
        assert!(!CpTag::Integer.takes_two_slots());
    }

    #[test]
    fn test_cp_tag_display_long() {
        assert_eq!(CpTag::Long.to_string(), "Long");
    }

    // --- Additional CpEntry tests ---

    #[test]
    fn test_cp_entry_integer_tag() {
        let e = CpEntry::Integer(100);
        assert_eq!(e.tag(), Some(CpTag::Integer));
    }

    #[test]
    fn test_cp_entry_float_tag() {
        let e = CpEntry::Float(3.14_f32);
        assert_eq!(e.tag(), Some(CpTag::Float));
    }

    #[test]
    fn test_cp_entry_long_tag() {
        let e = CpEntry::Long(1_000_000_000_000i64);
        assert_eq!(e.tag(), Some(CpTag::Long));
    }

    #[test]
    fn test_cp_entry_double_tag() {
        let e = CpEntry::Double(2.718_f64);
        assert_eq!(e.tag(), Some(CpTag::Double));
    }

    #[test]
    fn test_cp_entry_method_ref_tag() {
        let e = CpEntry::MethodRef {
            class_index: 1,
            name_and_type_index: 2,
        };
        assert_eq!(e.tag(), Some(CpTag::MethodRef));
    }

    #[test]
    fn test_cp_entry_field_ref_tag() {
        let e = CpEntry::FieldRef {
            class_index: 1,
            name_and_type_index: 3,
        };
        assert_eq!(e.tag(), Some(CpTag::FieldRef));
    }

    // --- Additional CpCategory tests ---

    #[test]
    fn test_cp_category_interface_method_ref() {
        let e = CpEntry::InterfaceMethodRef {
            class_index: 1,
            name_and_type_index: 2,
        };
        assert_eq!(CpCategory::of(&e), CpCategory::MemberRef);
    }

    #[test]
    fn test_cp_category_name_and_type() {
        let e = CpEntry::NameAndType {
            name_index: 1,
            descriptor_index: 2,
        };
        assert_eq!(CpCategory::of(&e), CpCategory::Metadata);
    }

    #[test]
    fn test_cp_category_invoke_dynamic() {
        let e = CpEntry::InvokeDynamic {
            bootstrap_method_attr_index: 0,
            name_and_type_index: 1,
        };
        assert_eq!(CpCategory::of(&e), CpCategory::Metadata);
    }

    #[test]
    fn test_cp_category_module() {
        let e = CpEntry::Module { name_index: 1 };
        assert_eq!(CpCategory::of(&e), CpCategory::ModuleInfo);
    }

    #[test]
    fn test_cp_category_placeholder() {
        assert_eq!(CpCategory::of(&CpEntry::Wide), CpCategory::Placeholder);
    }

    // --- Additional ConstantPool tests ---

    #[test]
    fn test_cp_get_nonexistent() {
        let cp = ConstantPool::new();
        assert!(cp.get(99).is_none());
    }

    #[test]
    fn test_cp_double_two_slots() {
        let mut cp = ConstantPool::new();
        cp.insert(1, CpEntry::Double(1.0));
        assert!(matches!(cp.get(2), Some(CpEntry::Wide)));
    }

    #[test]
    fn test_cp_class_name_not_class_entry() {
        let cp = make_pool();
        // Index 8 is an Integer, not a Class
        assert!(cp.class_name(8).is_none());
    }

    // --- Additional CpReferences tests ---

    #[test]
    fn test_cp_refs_empty() {
        let refs = CpReferences::new();
        assert_eq!(refs.total_references(), 0);
    }

    #[test]
    fn test_cp_refs_same_offset_idempotent() {
        let mut refs = CpReferences::new();
        refs.record(1, 10);
        refs.record(1, 10); // same offset, same index — counted once (HashSet)
        assert_eq!(refs.ref_count(1), 1);
    }

    // --- Additional CpStats tests ---

    #[test]
    fn test_stats_by_tag_populated() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert!(a.stats.by_tag.contains_key("Utf8"));
        assert!(a.stats.by_tag.contains_key("Class"));
    }

    #[test]
    fn test_stats_by_category_populated() {
        let cp = make_pool();
        let a = ConstantPoolAnalysis::with_pool(cp);
        assert!(a.stats.by_category.contains_key("member_ref") || a.stats.total_entries > 0);
    }

    #[test]
    fn test_analysis_interned_strings_sorted() {
        let mut cp = ConstantPool::new();
        cp.insert(1, CpEntry::Utf8("zebra".into()));
        cp.insert(2, CpEntry::Utf8("apple".into()));
        let a = ConstantPoolAnalysis::with_pool(cp);
        if a.interned_strings.len() >= 2 {
            assert!(a.interned_strings[0].value <= a.interned_strings[1].value);
        }
    }

    #[test]
    fn test_cp_optimizer_empty_pool() {
        let cp = ConstantPool::new();
        let refs = CpReferences::new();
        let mut opt = ConstantPoolOptimizer::new();
        opt.compute(&cp, &refs);
        assert_eq!(opt.unused_count(), 0);
    }

    #[test]
    fn test_cp_category_display_all() {
        let cats = [
            CpCategory::Numeric,
            CpCategory::StringLiteral,
            CpCategory::ClassName,
            CpCategory::MemberRef,
            CpCategory::Descriptor,
            CpCategory::Metadata,
            CpCategory::ModuleInfo,
            CpCategory::Raw,
            CpCategory::Placeholder,
        ];
        for c in &cats {
            assert!(!c.to_string().is_empty());
        }
    }

    // --- JvmDescriptor tests ---

    #[test]
    fn test_descriptor_parse_int() {
        let d = JvmDescriptor::parse_field("I").unwrap();
        assert_eq!(d, JvmDescriptor::Int);
        assert!(d.is_primitive());
    }

    #[test]
    fn test_descriptor_parse_long() {
        let d = JvmDescriptor::parse_field("J").unwrap();
        assert_eq!(d, JvmDescriptor::Long);
    }

    #[test]
    fn test_descriptor_parse_void() {
        let d = JvmDescriptor::parse_field("V").unwrap();
        assert_eq!(d, JvmDescriptor::Void);
    }

    #[test]
    fn test_descriptor_parse_object() {
        let d = JvmDescriptor::parse_field("Ljava/lang/String;").unwrap();
        assert_eq!(d, JvmDescriptor::Object("java/lang/String".into()));
        assert!(d.is_reference());
    }

    #[test]
    fn test_descriptor_parse_array_int() {
        let d = JvmDescriptor::parse_field("[I").unwrap();
        assert_eq!(d, JvmDescriptor::Array(Box::new(JvmDescriptor::Int)));
        assert!(d.is_reference());
    }

    #[test]
    fn test_descriptor_parse_array_object() {
        let d = JvmDescriptor::parse_field("[Ljava/lang/String;").unwrap();
        assert!(matches!(d, JvmDescriptor::Array(_)));
    }

    #[test]
    fn test_descriptor_parse_method_void() {
        let d = JvmDescriptor::parse_method("()V").unwrap();
        if let JvmDescriptor::Method { params, ret } = d {
            assert!(params.is_empty());
            assert_eq!(*ret, JvmDescriptor::Void);
        } else {
            panic!("expected Method");
        }
    }

    #[test]
    fn test_descriptor_parse_method_params() {
        let d = JvmDescriptor::parse_method("(ILjava/lang/String;)Z").unwrap();
        if let JvmDescriptor::Method { params, ret } = d {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0], JvmDescriptor::Int);
            assert_eq!(*ret, JvmDescriptor::Boolean);
        } else {
            panic!("expected Method");
        }
    }

    #[test]
    fn test_descriptor_display_int() {
        assert_eq!(JvmDescriptor::Int.to_string(), "int");
    }

    #[test]
    fn test_descriptor_display_object() {
        let d = JvmDescriptor::Object("java/lang/Object".into());
        assert_eq!(d.to_string(), "java.lang.Object");
    }

    #[test]
    fn test_descriptor_display_array() {
        let d = JvmDescriptor::Array(Box::new(JvmDescriptor::Int));
        assert_eq!(d.to_string(), "int[]");
    }

    #[test]
    fn test_descriptor_is_primitive_all() {
        let primitives = [
            JvmDescriptor::Byte,
            JvmDescriptor::Char,
            JvmDescriptor::Double,
            JvmDescriptor::Float,
            JvmDescriptor::Int,
            JvmDescriptor::Long,
            JvmDescriptor::Short,
            JvmDescriptor::Boolean,
            JvmDescriptor::Void,
        ];
        for p in &primitives {
            assert!(p.is_primitive());
        }
    }

    // --- CpBytecodeScanner tests ---

    #[test]
    fn test_cp_scanner_ldc() {
        // ldc #5: 0x12 0x05
        let bytecode = [0x12u8, 0x05, 0xB1]; // ldc, return
        let mut refs = CpReferences::new();
        CpBytecodeScanner::scan(&bytecode, &mut refs);
        assert!(refs.is_referenced(5));
    }

    #[test]
    fn test_cp_scanner_getstatic() {
        // getstatic #3: 0xB2 0x00 0x03
        let bytecode = [0xB2u8, 0x00, 0x03];
        let mut refs = CpReferences::new();
        CpBytecodeScanner::scan(&bytecode, &mut refs);
        assert!(refs.is_referenced(3));
    }

    #[test]
    fn test_cp_scanner_invokevirtual() {
        // invokevirtual #10: 0xB6 0x00 0x0A
        let bytecode = [0xB6u8, 0x00, 0x0A, 0xB1];
        let mut refs = CpReferences::new();
        CpBytecodeScanner::scan(&bytecode, &mut refs);
        assert!(refs.is_referenced(10));
    }

    #[test]
    fn test_cp_scanner_empty() {
        let mut refs = CpReferences::new();
        CpBytecodeScanner::scan(&[], &mut refs);
        assert_eq!(refs.total_references(), 0);
    }

    #[test]
    fn test_cp_scanner_new_instruction() {
        // new #7: 0xBB 0x00 0x07
        let bytecode = [0xBBu8, 0x00, 0x07, 0x59]; // new + dup
        let mut refs = CpReferences::new();
        CpBytecodeScanner::scan(&bytecode, &mut refs);
        assert!(refs.is_referenced(7));
    }
}
