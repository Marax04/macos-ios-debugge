//! Swift type metadata recovery for Mach-O binaries.
//!
//! Parses Swift 5 ABI sections:
//!   `__swift5_types`   — nominal type descriptors (Class/Struct/Enum/Protocol)
//!   `__swift5_proto`   — protocol conformance records
//!   `__swift5_fieldmd` — field descriptor records
//!   `__swift5_typeref` — type reference strings
//!   `__swift5_reflstr` — reflection string pool
//!   `__swift5_assocty` — associated type records
//!   `__swift5_replace` — dynamic replacement scope records
//!   `__swift5_entry`   — entry-point info

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SwiftMetadataError {
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("invalid mangled name: {0}")]
    InvalidMangledName(String),
    #[error("unknown type kind: {0:#x}")]
    UnknownTypeKind(u32),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("section not found: {0}")]
    SectionNotFound(String),
    #[error("invalid relative pointer at offset {0:#x}")]
    InvalidRelPtr(u64),
}

pub type Result<T> = std::result::Result<T, SwiftMetadataError>;

// ─── Byte-reading primitives ──────────────────────────────────────────────────

/// Read a single byte from `data` at offset `off`.
///
/// # Errors
/// Returns [`SwiftMetadataError::Truncated`] if `off` is out of range.
#[inline]
pub fn read_u8(data: &[u8], off: usize) -> Result<u8> {
    data.get(off)
        .copied()
        .ok_or(SwiftMetadataError::Truncated(off))
}

#[inline]
fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    let b = data
        .get(off..off + 2)
        .ok_or(SwiftMetadataError::Truncated(off))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(SwiftMetadataError::Truncated(off))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn read_i32_le(data: &[u8], off: usize) -> Result<i32> {
    read_u32_le(data, off).map(u32::cast_signed)
}

#[inline]
fn read_u64_le(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or(SwiftMetadataError::Truncated(off))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_cstring(data: &[u8], off: usize) -> Result<String> {
    let slice = data.get(off..).ok_or(SwiftMetadataError::Truncated(off))?;
    let end = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or(SwiftMetadataError::Truncated(off))?;
    std::str::from_utf8(&slice[..end])
        .map(std::borrow::ToOwned::to_owned)
        .map_err(|e| SwiftMetadataError::Parse(e.to_string()))
}

/// Resolve a 32-bit signed relative pointer stored at `field_off` within a
/// section whose first byte maps to `sec_va`.
///
/// `resolved_va` = (`sec_va` + `field_off`) + rel32
fn resolve_rel32(data: &[u8], field_off: usize, sec_va: u64) -> Result<u64> {
    let rel = read_i32_le(data, field_off)?;
    if rel == 0 {
        return Ok(0);
    }
    let field_va = sec_va + field_off as u64;
    Ok(field_va.wrapping_add(i64::from(rel).cast_unsigned()))
}

#[must_use]
pub fn lookup_str<S: std::hash::BuildHasher>(
    va: u64,
    a: &HashMap<u64, String, S>,
    b: &HashMap<u64, String, S>,
) -> Option<String> {
    a.get(&va).cloned().or_else(|| b.get(&va).cloned())
}

// ─── SwiftTypeKind ────────────────────────────────────────────────────────────

/// The kind of Swift type descriptor (low 5 bits of `ContextDescriptorFlags`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwiftTypeKind {
    Struct,
    Class,
    Enum,
    Protocol,
    OpaqueType,
    Extension,
    Anonymous,
    Module,
    Unknown(u32),
}

impl SwiftTypeKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x1F {
            0x00 => Self::Module,
            0x01 => Self::Extension,
            0x02 => Self::Anonymous,
            0x03 | 0x1F => Self::Protocol,
            0x10 => Self::Struct,
            0x11 => Self::Enum,
            0x12 => Self::Class,
            0x1E => Self::OpaqueType,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn keyword(&self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Enum => "enum",
            Self::Protocol => "protocol",
            Self::OpaqueType => "opaque",
            Self::Extension => "extension",
            Self::Anonymous => "/* anonymous */",
            Self::Module => "/* module */",
            Self::Unknown(_) => "/* unknown */",
        }
    }

    #[must_use]
    pub const fn is_class(&self) -> bool {
        matches!(self, Self::Class)
    }
    #[must_use]
    pub const fn is_struct(&self) -> bool {
        matches!(self, Self::Struct)
    }
    #[must_use]
    pub const fn is_enum(&self) -> bool {
        matches!(self, Self::Enum)
    }
    #[must_use]
    pub const fn is_protocol(&self) -> bool {
        matches!(self, Self::Protocol)
    }
    #[must_use]
    pub const fn has_fields(&self) -> bool {
        matches!(self, Self::Struct | Self::Class | Self::Enum)
    }
}

impl fmt::Display for SwiftTypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.keyword())
    }
}

// ─── Generic parameters & requirements ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenericParamKind {
    Type,
    PackCount,
    Pack,
    Unknown(u8),
}

impl GenericParamKind {
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw & 0x3F {
            0x00 => Self::Type,
            0x01 => Self::PackCount,
            0x02 => Self::Pack,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftGenericParam {
    pub index: u32,
    pub name: String,
    pub kind: GenericParamKind,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenericRequirementKind {
    /// Conformance to a protocol.
    Conformance,
    /// Same-type constraint.
    SameType,
    /// Base-class constraint.
    BaseClass,
    /// Same-conformance constraint.
    SameConformance,
    /// Layout constraint (class, trivial, etc.).
    Layout,
    Unknown(u32),
}

impl GenericRequirementKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x0F {
            0x00 => Self::Conformance,
            0x01 => Self::SameType,
            0x02 => Self::BaseClass,
            0x03 => Self::SameConformance,
            0x1F => Self::Layout,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftGenericRequirement {
    pub kind: GenericRequirementKind,
    pub subject: String,
    pub constraint: String,
    pub flags: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwiftGenericContext {
    pub params: Vec<SwiftGenericParam>,
    pub requirements: Vec<SwiftGenericRequirement>,
}

impl SwiftGenericContext {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

// ─── Field records ────────────────────────────────────────────────────────────

/// Flags on a `FieldRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRecordFlags(pub u32);

impl FieldRecordFlags {
    #[must_use]
    pub const fn is_indirect_enum_case(&self) -> bool {
        (self.0 & 0x0001) != 0
    }
    #[must_use]
    pub const fn is_var(&self) -> bool {
        (self.0 & 0x0002) != 0
    }
    #[must_use]
    pub const fn is_artificial(&self) -> bool {
        (self.0 & 0x0004) != 0
    }
}

/// One field (struct member, enum case, class stored property).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftField {
    pub name: String,
    /// Raw mangled type name (e.g. `$sSSSg`).
    pub type_name: String,
    /// Human-readable demangled type name.
    pub type_display: String,
    pub flags: FieldRecordFlags,
    /// Byte offset within the value layout (if known from field-offset vector).
    pub offset: Option<u32>,
}

impl SwiftField {
    #[must_use]
    pub const fn is_indirect_case(&self) -> bool {
        self.flags.is_indirect_enum_case()
    }
    #[must_use]
    pub const fn is_var(&self) -> bool {
        self.flags.is_var()
    }

    #[must_use]
    pub const fn declaration_keyword(&self) -> &'static str {
        if self.is_var() { "var" } else { "let" }
    }
}

impl fmt::Display for SwiftField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.declaration_keyword(),
            self.name,
            self.type_display
        )
    }
}

// ─── FieldDescriptor ──────────────────────────────────────────────────────────

/// The `FieldDescriptor` struct that lives in `__swift5_fieldmd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftFieldDescriptor {
    /// Mangled name of the owning type.
    pub mangled_type_name: String,
    /// Mangled name of the superclass (classes only).
    pub superclass: Option<String>,
    /// Kind byte from the header (mirrors the type kind).
    pub kind: u16,
    pub field_record_size: u16,
    pub fields: Vec<SwiftField>,
    /// VM address of this descriptor in the binary.
    pub vm_addr: u64,
}

impl SwiftFieldDescriptor {
    #[must_use]
    pub const fn num_fields(&self) -> usize {
        self.fields.len()
    }
}

// ─── Protocol conformance records ────────────────────────────────────────────

/// A protocol conformance record from `__swift5_proto`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftProtocolConformance {
    pub type_name: String,
    pub protocol_name: String,
    pub witness_table_offset: u64,
    pub conformance_flags: u32,
    pub conditional_requirements: Vec<String>,
}

// ─── Associated type descriptors ─────────────────────────────────────────────

/// One associated-type binding inside an associated-type descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociatedTypeRecord {
    pub name: String,
    pub substituted_type: String,
}

/// An associated-type descriptor from `__swift5_assocty`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftAssociatedTypeDescriptor {
    pub conforming_type: String,
    pub protocol_name: String,
    pub records: Vec<AssociatedTypeRecord>,
}

// ─── Replacement records ──────────────────────────────────────────────────────

/// A dynamic-replacement record from `__swift5_replace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftReplacementRecord {
    pub replacement_function: u64,
    pub original_function: u64,
    pub replacement_scope: u64,
    pub flags: u32,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// The entry-point record from `__swift5_entry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftEntryPoint {
    pub function_address: u64,
    pub flags: u32,
}

// ─── VTable entries ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VTableEntryKind {
    Method,
    Init,
    Getter,
    Setter,
    ModifyCoroutine,
    ReadCoroutine,
    Unknown(u32),
}

impl VTableEntryKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match (flags >> 4) & 0x0F {
            0x00 => Self::Method,
            0x01 => Self::Init,
            0x02 => Self::Getter,
            0x03 => Self::Setter,
            0x04 => Self::ModifyCoroutine,
            0x05 => Self::ReadCoroutine,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftVTableEntry {
    pub flags: u32,
    pub impl_address: u64,
    pub kind: VTableEntryKind,
    pub is_override: bool,
    pub is_dynamic: bool,
}

impl SwiftVTableEntry {
    const fn from_raw(flags: u32, impl_address: u64) -> Self {
        Self {
            flags,
            impl_address,
            kind: VTableEntryKind::from_flags(flags),
            is_override: (flags & (1 << 2)) != 0,
            is_dynamic: (flags & (1 << 3)) != 0,
        }
    }
}

// ─── Protocol requirements ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolRequirementKind {
    BaseProtocol,
    Method,
    Init,
    Getter,
    Setter,
    ReadCoroutine,
    ModifyCoroutine,
    AssociatedTypeAccessFunction,
    AssociatedConformanceAccessFunction,
    Unknown(u32),
}

impl ProtocolRequirementKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x0F {
            0x00 => Self::BaseProtocol,
            0x01 => Self::Method,
            0x02 => Self::Init,
            0x03 => Self::Getter,
            0x04 => Self::Setter,
            0x05 => Self::ReadCoroutine,
            0x06 => Self::ModifyCoroutine,
            0x07 => Self::AssociatedTypeAccessFunction,
            0x08 => Self::AssociatedConformanceAccessFunction,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftProtocolRequirement {
    pub flags: u32,
    pub kind: ProtocolRequirementKind,
    pub default_impl: Option<u64>,
    pub is_instance: bool,
}

// ─── ObjC bridge stubs ────────────────────────────────────────────────────────

/// Synthetic `ObjC` class stub emitted for `@objc`-bridged Swift classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcMetadataStub {
    /// `ObjC` class name as it appears in the `ObjC` runtime.
    pub class_name: String,
    /// Original Swift mangled / qualified name.
    pub swift_class_name: String,
    pub is_root: bool,
    pub superclass_name: Option<String>,
    /// Bridged selector strings.
    pub selectors: Vec<String>,
}

// ─── SwiftTypeDescriptor (main output type) ───────────────────────────────────

/// A nominal Swift type descriptor produced by the parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftTypeDescriptor {
    /// Simple unqualified name.
    pub name: String,
    /// Raw mangled name (may start with `$s`).
    pub mangled_name: String,
    pub kind: SwiftTypeKind,
    pub fields: Vec<SwiftField>,
    pub generic_params: Vec<SwiftGenericParam>,
    pub generic_requirements: Vec<SwiftGenericRequirement>,
    /// Protocol names this type conforms to.
    pub conformances: Vec<String>,
    /// Virtual-dispatch table entries (classes only).
    pub vtable: Vec<SwiftVTableEntry>,
    /// Protocol requirements (protocols only).
    pub protocol_requirements: Vec<SwiftProtocolRequirement>,
    /// Byte offset of this descriptor in the binary image.
    pub descriptor_offset: u64,
    pub module_name: Option<String>,
    /// Superclass type (classes only) as a demangled name.
    pub superclass: Option<String>,
    pub num_empty_cases: u32,
    /// `true` if the `ObjC` runtime can see this class.
    pub objc_bridged: bool,
    /// Synthetic `ObjC` stubs (populated when `objc_bridged` is true).
    pub objc_stubs: Vec<ObjcMetadataStub>,
}

impl SwiftTypeDescriptor {
    #[must_use]
    pub fn fully_qualified_name(&self) -> String {
        self.module_name
            .as_ref()
            .map_or_else(|| self.name.clone(), |m| format!("{}.{}", m, self.name))
    }

    #[must_use]
    pub const fn is_generic(&self) -> bool {
        !self.generic_params.is_empty()
    }

    #[must_use]
    pub fn conforms_to(&self, protocol: &str) -> bool {
        self.conformances.iter().any(|c| c == protocol)
    }

    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }

    // ── Mock constructors (for tests / stubs) ──────────────────────────────

    #[must_use]
    pub fn mock_struct(name: &str, module: &str) -> Self {
        Self {
            name: name.to_string(),
            mangled_name: format!("$s{}{}V", module.len(), name),
            kind: SwiftTypeKind::Struct,
            fields: vec![
                SwiftField {
                    name: "id".to_string(),
                    type_name: "$sSiD".to_string(),
                    type_display: "Int".to_string(),
                    flags: FieldRecordFlags(0x02),
                    offset: Some(0),
                },
                SwiftField {
                    name: "name".to_string(),
                    type_name: "$sSSD".to_string(),
                    type_display: "String".to_string(),
                    flags: FieldRecordFlags(0x02),
                    offset: Some(8),
                },
            ],
            generic_params: vec![],
            generic_requirements: vec![],
            conformances: vec!["Codable".to_string(), "Equatable".to_string()],
            vtable: vec![],
            protocol_requirements: vec![],
            descriptor_offset: 0x1001_0000,
            module_name: Some(module.to_string()),
            superclass: None,
            num_empty_cases: 0,
            objc_bridged: false,
            objc_stubs: vec![],
        }
    }

    #[must_use]
    pub fn mock_class(name: &str, module: &str) -> Self {
        Self {
            name: name.to_string(),
            mangled_name: format!("$s{}{}C", module.len(), name),
            kind: SwiftTypeKind::Class,
            fields: vec![SwiftField {
                name: "delegate".to_string(),
                type_name: "$sSQySo12UIViewControllerCGD".to_string(),
                type_display: "UIViewController?".to_string(),
                flags: FieldRecordFlags(0x02),
                offset: Some(16),
            }],
            generic_params: vec![],
            generic_requirements: vec![],
            conformances: vec![],
            vtable: vec![
                SwiftVTableEntry::from_raw(0x00, 0x1000_0100),
                SwiftVTableEntry::from_raw(0x01, 0x1000_0200),
            ],
            protocol_requirements: vec![],
            descriptor_offset: 0x1002_0000,
            module_name: Some(module.to_string()),
            superclass: Some("UIViewController".to_string()),
            num_empty_cases: 0,
            objc_bridged: true,
            objc_stubs: vec![ObjcMetadataStub {
                class_name: name.to_string(),
                swift_class_name: format!("{module}.{name}"),
                is_root: false,
                superclass_name: Some("UIViewController".to_string()),
                selectors: vec!["viewDidLoad".to_string(), "init".to_string()],
            }],
        }
    }

    #[must_use]
    pub fn mock_enum(name: &str, module: &str) -> Self {
        Self {
            name: name.to_string(),
            mangled_name: format!("$s{}{}O", module.len(), name),
            kind: SwiftTypeKind::Enum,
            fields: vec![
                SwiftField {
                    name: "success".to_string(),
                    type_name: "$sSiD".to_string(),
                    type_display: "Int".to_string(),
                    flags: FieldRecordFlags(0x00),
                    offset: None,
                },
                SwiftField {
                    name: "failure".to_string(),
                    type_name: "$ss5ErrorPD".to_string(),
                    type_display: "Error".to_string(),
                    flags: FieldRecordFlags(0x01),
                    offset: None,
                },
            ],
            generic_params: vec![SwiftGenericParam {
                index: 0,
                name: "T".to_string(),
                kind: GenericParamKind::Type,
                constraints: vec!["Sendable".to_string()],
            }],
            generic_requirements: vec![],
            conformances: vec![],
            vtable: vec![],
            protocol_requirements: vec![],
            descriptor_offset: 0x1003_0000,
            module_name: Some(module.to_string()),
            superclass: None,
            num_empty_cases: 0,
            objc_bridged: false,
            objc_stubs: vec![],
        }
    }

    #[must_use]
    pub fn mock_protocol(name: &str, module: &str) -> Self {
        Self {
            name: name.to_string(),
            mangled_name: format!("$s{}{}P", module.len(), name),
            kind: SwiftTypeKind::Protocol,
            fields: vec![],
            generic_params: vec![],
            generic_requirements: vec![],
            conformances: vec![],
            vtable: vec![],
            protocol_requirements: vec![SwiftProtocolRequirement {
                flags: 0x01,
                kind: ProtocolRequirementKind::Method,
                default_impl: None,
                is_instance: true,
            }],
            descriptor_offset: 0x1004_0000,
            module_name: Some(module.to_string()),
            superclass: None,
            num_empty_cases: 0,
            objc_bridged: false,
            objc_stubs: vec![],
        }
    }
}

impl fmt::Display for SwiftTypeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind.keyword(), self.name)?;
        if !self.generic_params.is_empty() {
            let ps: Vec<_> = self.generic_params.iter().map(|p| p.name.clone()).collect();
            write!(f, "<{}>", ps.join(", "))?;
        }
        if let Some(sup) = &self.superclass {
            write!(f, ": {sup}")?;
        }
        writeln!(f, " {{")?;
        for field in &self.fields {
            writeln!(f, "    {field}")?;
        }
        write!(f, "}}")
    }
}

// ─── Mangled name demangler (minimal recursive-descent) ───────────────────────

/// A node in the Swift mangled-name AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MangledNode {
    Module(String),
    Identifier(String),
    Nominal {
        module: Box<Self>,
        name: Box<Self>,
        generic_args: Vec<Self>,
    },
    Tuple(Vec<Self>),
    FunctionType {
        params: Vec<Self>,
        result: Box<Self>,
        is_throwing: bool,
        is_async: bool,
    },
    Optional(Box<Self>),
    ImplicitlyUnwrappedOptional(Box<Self>),
    Metatype(Box<Self>),
    ExistentialMetatype(Box<Self>),
    Builtin(String),
    Protocol {
        module: Box<Self>,
        name: Box<Self>,
    },
    BoundGeneric {
        base: Box<Self>,
        args: Vec<Self>,
    },
    Unknown(String),
}

impl MangledNode {
    #[must_use]
    pub fn to_swift_type(&self) -> String {
        match self {
            Self::Module(m) => m.clone(),
            Self::Identifier(i) => i.clone(),
            Self::Nominal {
                module: _,
                name,
                generic_args,
            } => {
                let base = name.to_swift_type();
                if generic_args.is_empty() {
                    base
                } else {
                    let args: Vec<_> = generic_args.iter().map(Self::to_swift_type).collect();
                    format!("{}<{}>", base, args.join(", "))
                }
            }
            Self::Tuple(elems) => {
                let parts: Vec<_> = elems.iter().map(Self::to_swift_type).collect();
                format!("({})", parts.join(", "))
            }
            Self::FunctionType {
                params,
                result,
                is_throwing,
                is_async,
            } => {
                let ps: Vec<_> = params.iter().map(Self::to_swift_type).collect();
                let mut qual = String::new();
                if *is_async {
                    qual.push_str("async ");
                }
                if *is_throwing {
                    qual.push_str("throws ");
                }
                format!("({}) {}-> {}", ps.join(", "), qual, result.to_swift_type())
            }
            Self::Optional(inner) => format!("{}?", inner.to_swift_type()),
            Self::ImplicitlyUnwrappedOptional(inner) => format!("{}!", inner.to_swift_type()),
            Self::Metatype(inner) => format!("{}.Type", inner.to_swift_type()),
            Self::ExistentialMetatype(inner) => format!("{}.Protocol", inner.to_swift_type()),
            Self::Builtin(s) => s.clone(),
            Self::Protocol { module: _, name } => name.to_swift_type(),
            Self::BoundGeneric { base, args } => {
                let b = base.to_swift_type();
                let a: Vec<_> = args.iter().map(Self::to_swift_type).collect();
                format!("{}<{}>", b, a.join(", "))
            }
            Self::Unknown(s) => format!("<{s}>"),
        }
    }
}

struct MangledParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> MangledParser<'a> {
    const fn new(s: &'a str) -> Self {
        MangledParser {
            src: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.src.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn consume_digits(&mut self) -> &'a str {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("")
    }

    fn parse_length_prefixed_ident(&mut self) -> String {
        let digits = self.consume_digits();
        let len: usize = digits.parse().unwrap_or(0);
        if len == 0 {
            return String::new();
        }
        let start = self.pos;
        let end = (start + len).min(self.src.len());
        self.pos = end;
        std::str::from_utf8(&self.src[start..end])
            .unwrap_or("?")
            .to_owned()
    }

    fn parse_substitution(&mut self) -> MangledNode {
        match self.advance() {
            Some(b'i') => MangledNode::Builtin("Int".into()),
            Some(b'u') => MangledNode::Builtin("UInt".into()),
            Some(b'b') => MangledNode::Builtin("Bool".into()),
            Some(b'f') => MangledNode::Builtin("Float".into()),
            Some(b'd') => MangledNode::Builtin("Double".into()),
            Some(b'S') => MangledNode::Builtin("String".into()),
            Some(b'q') => MangledNode::Builtin("Optional".into()),
            Some(b'a') => MangledNode::Builtin("Array".into()),
            Some(b'D') => MangledNode::Builtin("Dictionary".into()),
            Some(b's') => MangledNode::Module("Swift".into()),
            Some(b'e') => MangledNode::Builtin("Error".into()),
            Some(b'v') => MangledNode::Builtin("Void".into()),
            Some(b'g') => MangledNode::Builtin("AnyObject".into()),
            Some(b'p') => MangledNode::Builtin("Any".into()),
            Some(c) => MangledNode::Unknown(format!("S{}", c as char)),
            None => MangledNode::Unknown("S".into()),
        }
    }

    fn parse_node(&mut self) -> MangledNode {
        match self.peek() {
            Some(b'S') => {
                self.advance();
                self.parse_substitution()
            }
            Some(b'O' | b'q') => {
                self.advance();
                MangledNode::Optional(Box::new(self.parse_node()))
            }
            Some(b'Q') => {
                self.advance();
                MangledNode::ImplicitlyUnwrappedOptional(Box::new(self.parse_node()))
            }
            Some(b'X') => {
                self.advance();
                match self.peek() {
                    Some(b'M') => {
                        self.advance();
                        MangledNode::Metatype(Box::new(self.parse_node()))
                    }
                    Some(b'P') => {
                        self.advance();
                        MangledNode::ExistentialMetatype(Box::new(self.parse_node()))
                    }
                    _ => MangledNode::Unknown("X?".into()),
                }
            }
            Some(b'T') => {
                self.advance();
                self.parse_tuple()
            }
            Some(b'y') => {
                self.advance();
                MangledNode::Tuple(Vec::new())
            } // empty tuple = Void
            Some(b'$') => {
                self.advance();
                if self.peek() == Some(b's') {
                    self.advance();
                }
                self.parse_node()
            }
            Some(c) if c.is_ascii_digit() => {
                let ident = self.parse_length_prefixed_ident();
                MangledNode::Identifier(ident)
            }
            _ => MangledNode::Unknown(format!("pos={}", self.pos)),
        }
    }

    fn parse_tuple(&mut self) -> MangledNode {
        let mut elems = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'_' | b'd') => break,
                _ => elems.push(self.parse_node()),
            }
        }
        if self.peek() == Some(b'_') {
            self.advance();
        }
        MangledNode::Tuple(elems)
    }
}

/// Attempt a minimal Swift name demangle (handles `$s` prefix and basic suffixes).
#[must_use]
pub fn demangle_swift_name(mangled: &str) -> String {
    if !mangled.starts_with("$s") && !mangled.starts_with("_$s") {
        return mangled.to_string();
    }
    let s = mangled.trim_start_matches('_').trim_start_matches("$s");
    let mut result = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c.is_ascii_digit() {
            let mut num_str = c.to_string();
            while let Some(&(_, nc)) = chars.peek() {
                if nc.is_ascii_digit() {
                    num_str.push(nc);
                    chars.next();
                } else {
                    break;
                }
            }
            let len: usize = num_str.parse().unwrap_or(0);
            if len == 0 {
                break;
            }
            let start = i + num_str.len();
            let segment: String = s.chars().skip(start).take(len).collect();
            if !result.is_empty() {
                result.push('.');
            }
            result.push_str(&segment);
            for _ in 0..len.saturating_sub(1) {
                chars.next();
            }
        } else {
            match c {
                'V' | 'C' | 'O' | 'P' => break,
                _ => {}
            }
        }
    }
    if result.is_empty() {
        mangled.to_string()
    } else {
        result
    }
}

/// Full demangling via the AST parser.
#[must_use]
pub fn decode_mangled_type(mangled: &str) -> MangledNode {
    let cleaned = mangled.trim_start_matches('_').trim_start_matches("$s");
    let mut parser = MangledParser::new(cleaned);
    parser.parse_node()
}

#[must_use]
pub fn mangled_to_display(mangled: &str) -> String {
    // Try the AST parser first; fall back to the simple demangle.
    let node = decode_mangled_type(mangled);
    let via_ast = node.to_swift_type();
    if via_ast.starts_with('<') || via_ast.starts_with("pos=") {
        demangle_swift_name(mangled)
    } else {
        via_ast
    }
}

// ─── Section constants ────────────────────────────────────────────────────────

pub mod sections {
    pub const SWIFT5_TYPES: &str = "__swift5_types";
    pub const SWIFT5_PROTOS: &str = "__swift5_protos";
    pub const SWIFT5_PROTO: &str = "__swift5_proto";
    pub const SWIFT5_FIELDMD: &str = "__swift5_fieldmd";
    pub const SWIFT5_TYPEREF: &str = "__swift5_typeref";
    pub const SWIFT5_BUILTIN: &str = "__swift5_builtin";
    pub const SWIFT5_REFLSTR: &str = "__swift5_reflstr";
    pub const SWIFT5_ASSOCTY: &str = "__swift5_assocty";
    pub const SWIFT5_REPLACE: &str = "__swift5_replace";
    pub const SWIFT5_ENTRY: &str = "__swift5_entry";
}

// ─── Section data carrier ─────────────────────────────────────────────────────

/// Raw section bytes + its virtual address.
#[derive(Debug, Clone)]
pub struct SectionData<'a> {
    pub name: &'static str,
    /// Raw bytes of the section.
    pub data: &'a [u8],
    /// Virtual address of `data[0]` in the loaded image.
    pub vm_addr: u64,
}

impl<'a> SectionData<'a> {
    #[must_use]
    pub const fn new(name: &'static str, data: &'a [u8], vm_addr: u64) -> Self {
        SectionData {
            name,
            data,
            vm_addr,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// All Swift 5 sections that may be present in a Mach-O image.
#[derive(Default)]
pub struct Swift5Sections<'a> {
    pub types: Option<SectionData<'a>>,
    pub proto: Option<SectionData<'a>>,
    pub fieldmd: Option<SectionData<'a>>,
    pub typeref: Option<SectionData<'a>>,
    pub reflstr: Option<SectionData<'a>>,
    pub assocty: Option<SectionData<'a>>,
    pub replace: Option<SectionData<'a>>,
    pub entry: Option<SectionData<'a>>,
}

// ─── String-table parsers ─────────────────────────────────────────────────────

/// Parse a flat pool of null-terminated strings into a `VA → String` map.
#[must_use]
pub fn parse_string_pool(sec: &SectionData<'_>) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let mut off = 0usize;
    while off < sec.data.len() {
        let va = sec.vm_addr + off as u64;
        match read_cstring(sec.data, off) {
            Ok(s) => {
                let advance = s.len() + 1;
                map.insert(va, s);
                off += advance;
            }
            Err(_) => break,
        }
    }
    map
}

// ─── FieldDescriptor parser ───────────────────────────────────────────────────

fn parse_field_descriptor_at<S: std::hash::BuildHasher>(
    data: &[u8],
    off: usize,
    sec_va: u64,
    strs: &HashMap<u64, String, S>,
) -> Result<(SwiftFieldDescriptor, usize)> {
    // FieldDescriptor layout:
    //  +0x00  i32  mangled_type_name  (rel ptr)
    //  +0x04  i32  superclass         (rel ptr, 0 = none)
    //  +0x08  u16  kind
    //  +0x0A  u16  field_record_size
    //  +0x0C  u32  num_fields
    //  +0x10  [num_fields × field_record_size]  FieldRecord entries

    let type_name_va = resolve_rel32(data, off, sec_va)?;
    let superclass_va = resolve_rel32(data, off + 4, sec_va)?;
    let kind = read_u16_le(data, off + 8)?;
    let rec_size = read_u16_le(data, off + 10)? as usize;
    let num_fields = read_u32_le(data, off + 12)? as usize;

    let mangled_type_name = strs
        .get(&type_name_va)
        .cloned()
        .unwrap_or_else(|| format!("@{type_name_va:#x}"));
    let superclass = if superclass_va != 0 {
        Some(
            strs.get(&superclass_va)
                .cloned()
                .unwrap_or_else(|| format!("@{superclass_va:#x}")),
        )
    } else {
        None
    };

    let rec_base = off + 16;
    let effective_rec_size = rec_size.max(12);
    let mut fields = Vec::with_capacity(num_fields);

    for i in 0..num_fields {
        let roff = rec_base + i * effective_rec_size;
        if roff + 12 > data.len() {
            break;
        }

        let flags_raw = read_u32_le(data, roff)?;
        let name_va = resolve_rel32(data, roff + 4, sec_va + (roff + 4 - off) as u64)?;
        let type_va = resolve_rel32(data, roff + 8, sec_va + (roff + 8 - off) as u64)?;

        let name = strs
            .get(&name_va)
            .cloned()
            .unwrap_or_else(|| format!("field_{i}"));
        let type_name = if type_va != 0 {
            strs.get(&type_va)
                .cloned()
                .unwrap_or_else(|| format!("@{type_va:#x}"))
        } else {
            String::new()
        };
        let type_display = mangled_to_display(&type_name);

        fields.push(SwiftField {
            name,
            type_display,
            type_name,
            flags: FieldRecordFlags(flags_raw),
            offset: None,
        });
    }

    let total = 16 + num_fields * effective_rec_size;
    let fd = SwiftFieldDescriptor {
        mangled_type_name,
        superclass,
        kind,
        field_record_size: u16::try_from(rec_size).unwrap_or(u16::MAX),
        fields,
        vm_addr: sec_va + off as u64,
    };
    Ok((fd, total))
}

/// Parse `__swift5_fieldmd` as a packed sequence of `FieldDescriptor` structs.
#[must_use]
pub fn parse_fieldmd<S: std::hash::BuildHasher>(
    sec: &SectionData<'_>,
    strs: &HashMap<u64, String, S>,
) -> Vec<SwiftFieldDescriptor> {
    let mut result = Vec::new();
    let mut off = 0usize;
    while off + 16 <= sec.data.len() {
        match parse_field_descriptor_at(sec.data, off, sec.vm_addr, strs) {
            Ok((fd, sz)) => {
                off += sz.max(16);
                result.push(fd);
            }
            Err(_) => {
                off += 4;
            }
        }
    }
    result
}

// ─── Protocol conformance parser ──────────────────────────────────────────────

fn parse_conformance_at<S: std::hash::BuildHasher>(
    data: &[u8],
    off: usize,
    sec_va: u64,
    strs: &HashMap<u64, String, S>,
) -> Result<SwiftProtocolConformance> {
    // ConformanceDescriptor:
    //  +0x00  i32  type_ref        (rel ptr to mangled type name)
    //  +0x04  i32  protocol_ref    (rel ptr to protocol descriptor)
    //  +0x08  i32  witness_table   (rel ptr, 0 = no pattern)
    //  +0x0C  u32  conformance_flags

    let type_va = resolve_rel32(data, off, sec_va)?;
    let proto_va = resolve_rel32(data, off + 4, sec_va)?;
    let witness_va = resolve_rel32(data, off + 8, sec_va)?;
    let flags = read_u32_le(data, off + 12)?;

    let type_name = strs
        .get(&type_va)
        .cloned()
        .unwrap_or_else(|| format!("@{type_va:#x}"));
    let protocol_name = strs
        .get(&proto_va)
        .cloned()
        .unwrap_or_else(|| format!("@{proto_va:#x}"));

    Ok(SwiftProtocolConformance {
        type_name,
        protocol_name,
        witness_table_offset: witness_va,
        conformance_flags: flags,
        conditional_requirements: vec![],
    })
}

/// Parse `__swift5_proto` (array of 4-byte relative pointers to conformance records).
#[must_use]
pub fn parse_proto<S: std::hash::BuildHasher>(
    sec: &SectionData<'_>,
    strs: &HashMap<u64, String, S>,
) -> Vec<SwiftProtocolConformance> {
    let mut records = Vec::new();
    let mut off = 0usize;
    while off + 4 <= sec.data.len() {
        // Each entry is a relative pointer to a conformance record inline in this section
        // or in a companion section; attempt inline parse.
        if off + 16 <= sec.data.len()
            && let Ok(rec) = parse_conformance_at(sec.data, off, sec.vm_addr, strs)
        {
            records.push(rec);
        }
        off += 16;
    }
    records
}

// ─── Associated type parser ───────────────────────────────────────────────────

/// Parse `__swift5_assocty` as a packed sequence of associated-type descriptors.
#[must_use]
pub fn parse_assocty<S: std::hash::BuildHasher>(
    sec: &SectionData<'_>,
    strs: &HashMap<u64, String, S>,
) -> Vec<SwiftAssociatedTypeDescriptor> {
    let mut result = Vec::new();
    let mut off = 0usize;

    while off + 16 <= sec.data.len() {
        let Ok(type_va) = resolve_rel32(sec.data, off, sec.vm_addr) else {
            break;
        };
        let Ok(proto_va) = resolve_rel32(sec.data, off + 4, sec.vm_addr) else {
            break;
        };
        let num_assoc = match read_u32_le(sec.data, off + 8) {
            Ok(n) => n as usize,
            Err(_) => break,
        };
        let rec_size = match read_u32_le(sec.data, off + 12) {
            Ok(s) => s as usize,
            Err(_) => break,
        };

        let conforming_type = strs
            .get(&type_va)
            .cloned()
            .unwrap_or_else(|| format!("@{type_va:#x}"));
        let protocol_name = strs
            .get(&proto_va)
            .cloned()
            .unwrap_or_else(|| format!("@{proto_va:#x}"));

        let effective_rec = rec_size.max(8);
        let rec_base = off + 16;
        let mut records = Vec::with_capacity(num_assoc);

        for i in 0..num_assoc {
            let roff = rec_base + i * effective_rec;
            if roff + 8 > sec.data.len() {
                break;
            }
            let Ok(name_va) = resolve_rel32(sec.data, roff, sec.vm_addr + (roff - off) as u64)
            else {
                break;
            };
            let Ok(sub_va) =
                resolve_rel32(sec.data, roff + 4, sec.vm_addr + (roff + 4 - off) as u64)
            else {
                break;
            };
            let name = strs
                .get(&name_va)
                .cloned()
                .unwrap_or_else(|| format!("assoc_{i}"));
            let substituted_type = strs
                .get(&sub_va)
                .cloned()
                .unwrap_or_else(|| format!("@{sub_va:#x}"));
            records.push(AssociatedTypeRecord {
                name,
                substituted_type,
            });
        }

        let total = 16 + num_assoc * effective_rec;
        result.push(SwiftAssociatedTypeDescriptor {
            conforming_type,
            protocol_name,
            records,
        });
        off += total.max(16);
    }

    result
}

// ─── Replacement record parser ────────────────────────────────────────────────

/// Parse `__swift5_replace` (header + array of 16-byte replacement records).
#[must_use]
pub fn parse_replace(sec: &SectionData<'_>) -> Vec<SwiftReplacementRecord> {
    let mut result = Vec::new();
    if sec.data.len() < 8 {
        return result;
    }

    let Ok(_flags) = read_u32_le(sec.data, 0) else {
        return result;
    };
    let num_recs = match read_u32_le(sec.data, 4) {
        Ok(v) => v as usize,
        Err(_) => return result,
    };

    let base = 8usize;
    for i in 0..num_recs {
        let off = base + i * 16;
        if off + 16 > sec.data.len() {
            break;
        }
        let replacement = resolve_rel32(sec.data, off, sec.vm_addr + off as u64).unwrap_or(0);
        let original = resolve_rel32(sec.data, off + 4, sec.vm_addr + off as u64 + 4).unwrap_or(0);
        let scope = resolve_rel32(sec.data, off + 8, sec.vm_addr + off as u64 + 8).unwrap_or(0);
        let flags = read_u32_le(sec.data, off + 12).unwrap_or(0);
        result.push(SwiftReplacementRecord {
            replacement_function: replacement,
            original_function: original,
            replacement_scope: scope,
            flags,
        });
    }
    result
}

// ─── Entry-point parser ───────────────────────────────────────────────────────

/// Parse `__swift5_entry` (4-byte relative ptr + 4-byte flags).
#[must_use]
pub fn parse_entry(sec: &SectionData<'_>) -> Option<SwiftEntryPoint> {
    if sec.data.len() < 8 {
        return None;
    }
    let fn_addr = resolve_rel32(sec.data, 0, sec.vm_addr).ok()?;
    let flags = read_u32_le(sec.data, 4).ok()?;
    Some(SwiftEntryPoint {
        function_address: fn_addr,
        flags,
    })
}

// ─── Generic-context parser ───────────────────────────────────────────────────

/// Parse a `GenericContextDescriptorHeader` + params + requirements starting at `off`.
/// Returns (`GenericContext`, `new_offset`).
fn parse_generic_context(data: &[u8], off: usize, _sec_va: u64) -> (SwiftGenericContext, usize) {
    if off + 8 > data.len() {
        return (SwiftGenericContext::default(), off);
    }
    let num_params = match read_u16_le(data, off) {
        Ok(n) => n as usize,
        Err(_) => return (SwiftGenericContext::default(), off),
    };
    let num_reqs = match read_u16_le(data, off + 2) {
        Ok(n) => n as usize,
        Err(_) => return (SwiftGenericContext::default(), off),
    };
    let Ok(_key_args) = read_u16_le(data, off + 4) else {
        return (SwiftGenericContext::default(), off);
    };
    let Ok(_extra_args) = read_u16_le(data, off + 6) else {
        return (SwiftGenericContext::default(), off);
    };

    let mut cur = off + 8;

    let mut params = Vec::with_capacity(num_params);
    for i in 0..num_params {
        let kind_byte = data.get(cur).copied().unwrap_or(0);
        cur += 1;
        params.push(SwiftGenericParam {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            name: format!("T{i}"),
            kind: GenericParamKind::from_raw(kind_byte),
            constraints: Vec::new(),
        });
    }

    // Align to 4 bytes.
    let rem = cur % 4;
    if rem != 0 {
        cur += 4 - rem;
    }

    let mut requirements = Vec::with_capacity(num_reqs);
    for _ in 0..num_reqs {
        if cur + 12 > data.len() {
            break;
        }
        let flags = read_u32_le(data, cur).unwrap_or(0);
        cur += 12;
        requirements.push(SwiftGenericRequirement {
            kind: GenericRequirementKind::from_flags(flags),
            subject: String::new(),
            constraint: String::new(),
            flags,
        });
    }

    (
        SwiftGenericContext {
            params,
            requirements,
        },
        cur,
    )
}

// ─── Nominal type descriptor parser ──────────────────────────────────────────

fn parse_vtable(
    data: &[u8],
    base_off: usize,
    sec_va: u64,
    vtable_off: usize,
) -> Vec<SwiftVTableEntry> {
    let mut entries = Vec::new();
    let mut cur = base_off + vtable_off;
    loop {
        if cur + 8 > data.len() {
            break;
        }
        let flags = read_u32_le(data, cur).unwrap_or(0);
        if flags == 0 && read_u32_le(data, cur + 4).unwrap_or(0) == 0 {
            break;
        }
        let impl_addr = resolve_rel32(data, cur + 4, sec_va + (cur + 4) as u64).unwrap_or(0);
        entries.push(SwiftVTableEntry::from_raw(flags, impl_addr));
        cur += 8;
    }
    entries
}

struct ClassDescriptorCtx<'a, S: std::hash::BuildHasher> {
    data: &'a [u8],
    off: usize,
    sec_va: u64,
    strs: &'a HashMap<u64, String, S>,
    flags: u32,
    name: String,
    name_va: u64,
    fields: Vec<SwiftField>,
    generic: SwiftGenericContext,
    kind: SwiftTypeKind,
    descriptor_offset: u64,
}

fn build_class_descriptor<S: std::hash::BuildHasher>(
    ctx: ClassDescriptorCtx<'_, S>,
) -> SwiftTypeDescriptor {
    let ClassDescriptorCtx {
        data,
        off,
        sec_va,
        strs,
        flags,
        name,
        name_va,
        fields,
        generic,
        kind,
        descriptor_offset,
    } = ctx;
    let superclass_va = if off + 0x18 <= data.len() {
        resolve_rel32(data, off + 0x14, sec_va).unwrap_or(0)
    } else {
        0
    };
    let superclass = if superclass_va != 0 {
        Some(
            strs.get(&superclass_va)
                .cloned()
                .unwrap_or_else(|| format!("@{superclass_va:#x}")),
        )
    } else {
        None
    };

    let has_vtable = (flags & (1 << 16)) != 0;
    let vtable = if has_vtable && off + 0x38 < data.len() {
        let vt_off = read_u32_le(data, off + 0x2C).unwrap_or(0) as usize;
        parse_vtable(data, off, sec_va, vt_off)
    } else {
        Vec::new()
    };

    let objc_bridged = (flags & (1 << 1)) != 0;
    let objc_stubs = if objc_bridged {
        vec![ObjcMetadataStub {
            class_name: name.clone(),
            swift_class_name: name.clone(),
            is_root: superclass.is_none(),
            superclass_name: superclass.clone(),
            selectors: vtable
                .iter()
                .enumerate()
                .map(|(i, _)| format!("method_{i}"))
                .collect(),
        }]
    } else {
        Vec::new()
    };

    SwiftTypeDescriptor {
        name,
        mangled_name: strs.get(&name_va).cloned().unwrap_or_default(),
        kind,
        fields,
        generic_params: generic.params,
        generic_requirements: generic.requirements,
        conformances: Vec::new(),
        vtable,
        protocol_requirements: Vec::new(),
        descriptor_offset,
        module_name: None,
        superclass,
        num_empty_cases: 0,
        objc_bridged,
        objc_stubs,
    }
}

struct ProtocolDescriptorCtx<'a, S: std::hash::BuildHasher> {
    data: &'a [u8],
    off: usize,
    sec_va: u64,
    strs: &'a HashMap<u64, String, S>,
    name: String,
    name_va: u64,
    generic: SwiftGenericContext,
    kind: SwiftTypeKind,
    descriptor_offset: u64,
}

fn build_protocol_descriptor<S: std::hash::BuildHasher>(
    ctx: ProtocolDescriptorCtx<'_, S>,
) -> SwiftTypeDescriptor {
    let ProtocolDescriptorCtx {
        data,
        off,
        sec_va,
        strs,
        name,
        name_va,
        generic,
        kind,
        descriptor_offset,
    } = ctx;
    let num_reqs = if off + 0x1C <= data.len() {
        read_u32_le(data, off + 0x1C).unwrap_or(0) as usize
    } else {
        0
    };

    let req_base = off + 0x20;
    let mut protocol_requirements = Vec::with_capacity(num_reqs);
    for i in 0..num_reqs {
        let roff = req_base + i * 8;
        if roff + 8 > data.len() {
            break;
        }
        let req_flags = read_u32_le(data, roff).unwrap_or(0);
        let def_impl = resolve_rel32(data, roff + 4, sec_va + (roff + 4) as u64).unwrap_or(0);
        protocol_requirements.push(SwiftProtocolRequirement {
            flags: req_flags,
            kind: ProtocolRequirementKind::from_flags(req_flags),
            default_impl: if def_impl != 0 { Some(def_impl) } else { None },
            is_instance: (req_flags & (1 << 4)) == 0,
        });
    }

    SwiftTypeDescriptor {
        name,
        mangled_name: strs.get(&name_va).cloned().unwrap_or_default(),
        kind,
        fields: Vec::new(),
        generic_params: generic.params,
        generic_requirements: generic.requirements,
        conformances: Vec::new(),
        vtable: Vec::new(),
        protocol_requirements,
        descriptor_offset,
        module_name: None,
        superclass: None,
        num_empty_cases: 0,
        objc_bridged: false,
        objc_stubs: Vec::new(),
    }
}

fn parse_nominal_descriptor<S: std::hash::BuildHasher>(
    data: &[u8],
    off: usize,
    sec_va: u64,
    strs: &HashMap<u64, String, S>,
    field_descs: &[SwiftFieldDescriptor],
) -> Result<SwiftTypeDescriptor> {
    // ContextDescriptorFlags (+0x00, u32):
    //   bits 0-4  = kind
    //   bit  7    = is_unique
    //   bit  8    = is_generic
    //   bit  15   = has_generic_context (some encodings use bit 8)
    // +0x04  i32  parent       (rel ptr, 0 = top-level)
    // +0x08  i32  name         (rel ptr to string)
    // +0x0C  i32  access_fn   (rel ptr)
    // +0x10  i32  fields_desc (rel ptr to FieldDescriptor or 0)

    let flags = read_u32_le(data, off)?;
    let kind = SwiftTypeKind::from_flags(flags);
    let is_generic = (flags & (1 << 8)) != 0;

    let _parent_va = resolve_rel32(data, off + 4, sec_va)?;
    let name_va = resolve_rel32(data, off + 8, sec_va)?;
    let _access_va = resolve_rel32(data, off + 12, sec_va)?;
    let fields_va = resolve_rel32(data, off + 16, sec_va)?;

    let name = strs
        .get(&name_va)
        .cloned()
        .unwrap_or_else(|| format!("Type@{:#x}", sec_va + off as u64));

    // Attempt to match the field descriptor by VA.
    let fields: Vec<SwiftField> = if fields_va != 0 {
        field_descs
            .iter()
            .find(|fd| fd.vm_addr == fields_va)
            .map(|fd| fd.fields.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Parse generic context starting right after the 5-word base (0x14).
    let (generic, _after_generic) = if is_generic && off + 0x14 < data.len() {
        parse_generic_context(data, off + 0x14, sec_va)
    } else {
        (SwiftGenericContext::default(), off + 0x14)
    };

    let descriptor_offset = sec_va + off as u64;

    match kind {
        SwiftTypeKind::Class => Ok(build_class_descriptor(ClassDescriptorCtx {
            data,
            off,
            sec_va,
            strs,
            flags,
            name,
            name_va,
            fields,
            generic,
            kind,
            descriptor_offset,
        })),

        SwiftTypeKind::Enum => {
            let num_empty = if off + 0x1C <= data.len() {
                read_u32_le(data, off + 0x18).unwrap_or(0)
            } else {
                0
            };
            Ok(SwiftTypeDescriptor {
                name,
                mangled_name: strs.get(&name_va).cloned().unwrap_or_default(),
                kind,
                fields,
                generic_params: generic.params,
                generic_requirements: generic.requirements,
                conformances: Vec::new(),
                vtable: Vec::new(),
                protocol_requirements: Vec::new(),
                descriptor_offset,
                module_name: None,
                superclass: None,
                num_empty_cases: num_empty,
                objc_bridged: false,
                objc_stubs: Vec::new(),
            })
        }

        SwiftTypeKind::Protocol => Ok(build_protocol_descriptor(ProtocolDescriptorCtx {
            data,
            off,
            sec_va,
            strs,
            name,
            name_va,
            generic,
            kind,
            descriptor_offset,
        })),

        // Struct, Extension, OpaqueType, Module, Anonymous, Unknown
        _ => Ok(SwiftTypeDescriptor {
            name,
            mangled_name: strs.get(&name_va).cloned().unwrap_or_default(),
            kind,
            fields,
            generic_params: generic.params,
            generic_requirements: generic.requirements,
            conformances: Vec::new(),
            vtable: Vec::new(),
            protocol_requirements: Vec::new(),
            descriptor_offset,
            module_name: None,
            superclass: None,
            num_empty_cases: 0,
            objc_bridged: false,
            objc_stubs: Vec::new(),
        }),
    }
}

/// Parse `__swift5_types` (array of 4-byte relative ptrs to inline descriptors).
#[must_use]
pub fn parse_types<S: std::hash::BuildHasher>(
    sec: &SectionData<'_>,
    strs: &HashMap<u64, String, S>,
    field_descs: &[SwiftFieldDescriptor],
) -> Vec<SwiftTypeDescriptor> {
    let mut types = Vec::new();
    let mut off = 0usize;
    while off + 4 <= sec.data.len() {
        if off + 20 <= sec.data.len()
            && let Ok(t) = parse_nominal_descriptor(sec.data, off, sec.vm_addr, strs, field_descs)
        {
            off += descriptor_size(&t);
            types.push(t);
            continue;
        }
        off += 4;
    }
    types
}

/// Heuristic size of a descriptor record (minimum 20 bytes, grows with vtable etc.)
const fn descriptor_size(t: &SwiftTypeDescriptor) -> usize {
    let base = 20usize;
    match &t.kind {
        SwiftTypeKind::Class => base + 28 + t.vtable.len() * 8,
        SwiftTypeKind::Struct | SwiftTypeKind::Enum => base + 8,
        SwiftTypeKind::Protocol => base + 8 + t.protocol_requirements.len() * 8,
        _ => base,
    }
}

// ─── TypeMetadata runtime representation ──────────────────────────────────────

/// Runtime kind values encoded in the first word of `TypeMetadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeMetadataKind {
    Class,
    Struct,
    Enum,
    Optional,
    ForeignClass,
    Opaque,
    Tuple,
    Function,
    Existential,
    Metatype,
    ObjcClassWrapper,
    ExistentialMetatype,
    HeapLocalVariable,
    HeapGenericLocalVariable,
    ErrorObject,
    Unknown(u64),
}

impl TypeMetadataKind {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        match raw {
            0x200 => Self::Struct,
            0x201 => Self::Enum,
            0x202 => Self::Optional,
            0x203 => Self::ForeignClass,
            0x300 => Self::Opaque,
            0x301 => Self::Tuple,
            0x302 => Self::Function,
            0x303 => Self::Existential,
            0x304 => Self::Metatype,
            0x305 => Self::ObjcClassWrapper,
            0x306 => Self::ExistentialMetatype,
            0x400 => Self::HeapLocalVariable,
            0x500 => Self::HeapGenericLocalVariable,
            0x501 => Self::ErrorObject,
            other if other < 0x200 => Self::Class,
            other => Self::Unknown(other),
        }
    }
}

/// A `TypeMetadata` record (value read from the running process or linked image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeMetadata {
    pub vm_addr: u64,
    pub kind: TypeMetadataKind,
    pub descriptor_address: Option<u64>,
    pub vtable_pointer: Option<u64>,
}

impl TypeMetadata {
    #[must_use]
    pub fn parse(data: &[u8], data_base_va: u64, address: u64) -> Option<Self> {
        if address < data_base_va {
            return None;
        }
        let off = usize::try_from(address - data_base_va).ok()?;
        if off + 8 > data.len() {
            return None;
        }
        let first_word = read_u64_le(data, off).ok()?;
        let kind = TypeMetadataKind::from_raw(first_word);
        let (vtable_pointer, descriptor_address) = match &kind {
            TypeMetadataKind::Class => (
                Some(first_word),
                if address >= 8 {
                    Some(address - 8)
                } else {
                    None
                },
            ),
            _ => (None, None),
        };
        Some(Self {
            vm_addr: address,
            kind,
            descriptor_address,
            vtable_pointer,
        })
    }
}

// ─── Top-level parser ─────────────────────────────────────────────────────────

/// Results from parsing all Swift 5 sections.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SwiftMetadataResult {
    pub types: Vec<SwiftTypeDescriptor>,
    pub conformances: Vec<SwiftProtocolConformance>,
    pub field_descriptors: Vec<SwiftFieldDescriptor>,
    pub associated_types: Vec<SwiftAssociatedTypeDescriptor>,
    pub replacement_records: Vec<SwiftReplacementRecord>,
    pub entry_point: Option<SwiftEntryPoint>,
    pub typeref_strings: HashMap<u64, String>,
    pub reflstr_strings: HashMap<u64, String>,
}

impl SwiftMetadataResult {
    /// Merge typeref and reflstr string pools into one map.
    #[must_use]
    pub fn all_strings(&self) -> HashMap<u64, String> {
        let mut merged = self.typeref_strings.clone();
        merged.extend(self.reflstr_strings.clone());
        merged
    }

    /// Collect all `ObjC` stubs from bridged classes.
    #[must_use]
    pub fn objc_stubs(&self) -> Vec<&ObjcMetadataStub> {
        self.types
            .iter()
            .flat_map(|t| t.objc_stubs.iter())
            .collect()
    }

    /// Find a type by simple name or fully-qualified name.
    #[must_use]
    pub fn find_type(&self, name: &str) -> Option<&SwiftTypeDescriptor> {
        self.types
            .iter()
            .find(|t| t.name == name || t.fully_qualified_name() == name)
    }
}

/// Parse all Swift 5 metadata sections and return a combined result.
#[must_use]
pub fn parse_swift_metadata(sections: &Swift5Sections<'_>) -> SwiftMetadataResult {
    let mut result = SwiftMetadataResult::default();

    // 1. String pools.
    if let Some(ref s) = sections.typeref {
        result.typeref_strings = parse_string_pool(s);
    }
    if let Some(ref s) = sections.reflstr {
        result.reflstr_strings = parse_string_pool(s);
    }

    let strs = result.all_strings();

    // 2. Field descriptors.
    if let Some(ref s) = sections.fieldmd {
        result.field_descriptors = parse_fieldmd(s, &strs);
    }

    // 3. Nominal type descriptors.
    if let Some(ref s) = sections.types {
        result.types = parse_types(s, &strs, &result.field_descriptors);
    }

    // 4. Protocol conformances.
    if let Some(ref s) = sections.proto {
        result.conformances = parse_proto(s, &strs);
    }

    // 5. Associated types.
    if let Some(ref s) = sections.assocty {
        result.associated_types = parse_assocty(s, &strs);
    }

    // 6. Dynamic replacements.
    if let Some(ref s) = sections.replace {
        result.replacement_records = parse_replace(s);
    }

    // 7. Entry point.
    if let Some(ref s) = sections.entry {
        result.entry_point = parse_entry(s);
    }

    result
}

// ─── Compatibility re-exports (SwiftMetadataParser facade) ───────────────────

/// High-level parser facade compatible with older callers.
pub struct SwiftMetadataParser {
    types: Vec<SwiftTypeDescriptor>,
    conformances: Vec<SwiftProtocolConformance>,
    builtins: Vec<SwiftBuiltinTypeDescriptor>,
}

/// A built-in Swift type descriptor from `__swift5_builtin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftBuiltinTypeDescriptor {
    pub name: String,
    pub size: u32,
    pub alignment: u32,
    pub stride: u32,
    pub num_extra_inhabitants: u32,
    pub is_bitwise_takable: bool,
}

impl SwiftMetadataParser {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            types: Vec::new(),
            conformances: Vec::new(),
            builtins: Vec::new(),
        }
    }

    pub fn add_types(&mut self, types: Vec<SwiftTypeDescriptor>) {
        self.types.extend(types);
    }
    pub fn add_conformances(&mut self, c: Vec<SwiftProtocolConformance>) {
        self.conformances.extend(c);
    }
    pub fn add_builtins(&mut self, b: Vec<SwiftBuiltinTypeDescriptor>) {
        self.builtins.extend(b);
    }

    #[must_use]
    pub fn all_types(&self) -> &[SwiftTypeDescriptor] {
        &self.types
    }
    #[must_use]
    pub fn all_conformances(&self) -> &[SwiftProtocolConformance] {
        &self.conformances
    }

    #[must_use]
    pub fn find_type(&self, name: &str) -> Option<&SwiftTypeDescriptor> {
        self.types
            .iter()
            .find(|t| t.name == name || t.fully_qualified_name() == name)
    }

    #[must_use]
    pub fn types_conforming_to(&self, protocol: &str) -> Vec<&SwiftTypeDescriptor> {
        self.types
            .iter()
            .filter(|t| t.conforms_to(protocol))
            .collect()
    }

    #[must_use]
    pub fn conformances_for(&self, type_name: &str) -> Vec<&SwiftProtocolConformance> {
        self.conformances
            .iter()
            .filter(|c| c.type_name == type_name)
            .collect()
    }

    #[must_use]
    pub fn types_by_kind(&self) -> HashMap<String, Vec<&SwiftTypeDescriptor>> {
        let mut map: HashMap<String, Vec<&SwiftTypeDescriptor>> = HashMap::new();
        for t in &self.types {
            map.entry(t.kind.keyword().to_string()).or_default().push(t);
        }
        map
    }

    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.types.len()
    }

    #[must_use]
    pub fn mock() -> Self {
        let mut parser = Self::new();
        parser.add_types(vec![
            SwiftTypeDescriptor::mock_struct("User", "MyApp"),
            SwiftTypeDescriptor::mock_class("ViewController", "MyApp"),
            SwiftTypeDescriptor::mock_enum("Result", "MyApp"),
        ]);
        parser.add_conformances(vec![SwiftProtocolConformance {
            type_name: "MyApp.User".to_string(),
            protocol_name: "Codable".to_string(),
            witness_table_offset: 0x1004_0000,
            conformance_flags: 0,
            conditional_requirements: vec![],
        }]);
        parser.add_builtins(vec![SwiftBuiltinTypeDescriptor {
            name: "Swift.Int".to_string(),
            size: 8,
            alignment: 8,
            stride: 8,
            num_extra_inhabitants: 0,
            is_bitwise_takable: true,
        }]);
        parser
    }
}

impl Default for SwiftMetadataParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SwiftTypeKind ─────────────────────────────────────────────────────────

    #[test]
    fn test_swift_type_kind_from_flags() {
        assert_eq!(SwiftTypeKind::from_flags(0x10), SwiftTypeKind::Struct);
        assert_eq!(SwiftTypeKind::from_flags(0x11), SwiftTypeKind::Enum);
        assert_eq!(SwiftTypeKind::from_flags(0x12), SwiftTypeKind::Class);
        assert_eq!(SwiftTypeKind::from_flags(0x1F), SwiftTypeKind::Protocol);
        assert_eq!(SwiftTypeKind::from_flags(0x00), SwiftTypeKind::Module);
        assert_eq!(SwiftTypeKind::from_flags(0x01), SwiftTypeKind::Extension);
    }

    #[test]
    fn test_swift_type_kind_keyword() {
        assert_eq!(SwiftTypeKind::Struct.keyword(), "struct");
        assert_eq!(SwiftTypeKind::Class.keyword(), "class");
        assert_eq!(SwiftTypeKind::Enum.keyword(), "enum");
        assert_eq!(SwiftTypeKind::Protocol.keyword(), "protocol");
        assert_eq!(SwiftTypeKind::Extension.keyword(), "extension");
        assert_eq!(SwiftTypeKind::Module.keyword(), "/* module */");
    }

    #[test]
    fn test_swift_type_kind_display() {
        assert_eq!(format!("{}", SwiftTypeKind::Struct), "struct");
        assert_eq!(format!("{}", SwiftTypeKind::Protocol), "protocol");
    }

    #[test]
    fn test_swift_type_kind_predicates() {
        assert!(SwiftTypeKind::Class.is_class());
        assert!(!SwiftTypeKind::Class.is_struct());
        assert!(SwiftTypeKind::Struct.has_fields());
        assert!(SwiftTypeKind::Enum.has_fields());
        assert!(!SwiftTypeKind::Protocol.has_fields());
    }

    // ── GenericParamKind ──────────────────────────────────────────────────────

    #[test]
    fn test_generic_param_kind_from_raw() {
        assert!(matches!(
            GenericParamKind::from_raw(0x00),
            GenericParamKind::Type
        ));
        assert!(matches!(
            GenericParamKind::from_raw(0x01),
            GenericParamKind::PackCount
        ));
        assert!(matches!(
            GenericParamKind::from_raw(0x02),
            GenericParamKind::Pack
        ));
        assert!(matches!(
            GenericParamKind::from_raw(0xFF),
            GenericParamKind::Unknown(_)
        ));
    }

    // ── FieldRecordFlags ──────────────────────────────────────────────────────

    #[test]
    fn test_field_record_flags() {
        let f = FieldRecordFlags(0x03);
        assert!(f.is_indirect_enum_case());
        assert!(f.is_var());
        assert!(!f.is_artificial());

        let g = FieldRecordFlags(0x04);
        assert!(g.is_artificial());
        assert!(!g.is_var());
    }

    // ── SwiftField ────────────────────────────────────────────────────────────

    #[test]
    fn test_swift_field_keyword() {
        let var_field = SwiftField {
            name: "x".into(),
            type_name: "$sSi".into(),
            type_display: "Int".into(),
            flags: FieldRecordFlags(0x02),
            offset: Some(0),
        };
        assert_eq!(var_field.declaration_keyword(), "var");
        assert!(var_field.is_var());

        let let_field = SwiftField {
            name: "y".into(),
            type_name: "$sSS".into(),
            type_display: "String".into(),
            flags: FieldRecordFlags(0x00),
            offset: None,
        };
        assert_eq!(let_field.declaration_keyword(), "let");
    }

    #[test]
    fn test_swift_field_display() {
        let f = SwiftField {
            name: "count".into(),
            type_name: "$sSi".into(),
            type_display: "Int".into(),
            flags: FieldRecordFlags(0x02),
            offset: None,
        };
        let s = format!("{f}");
        assert!(s.contains("var"));
        assert!(s.contains("count"));
        assert!(s.contains("Int"));
    }

    // ── Mock descriptors ──────────────────────────────────────────────────────

    #[test]
    fn test_mock_struct_fields() {
        let t = SwiftTypeDescriptor::mock_struct("User", "MyApp");
        assert_eq!(t.field_count(), 2);
        assert!(!t.is_generic());
        assert!(t.conforms_to("Codable"));
        assert!(t.conforms_to("Equatable"));
        assert!(!t.conforms_to("Hashable"));
    }

    #[test]
    fn test_mock_class_vtable_and_stubs() {
        let t = SwiftTypeDescriptor::mock_class("ViewController", "MyApp");
        assert_eq!(t.vtable.len(), 2);
        assert!(t.objc_bridged);
        assert_eq!(t.objc_stubs.len(), 1);
        assert_eq!(
            t.objc_stubs[0].superclass_name,
            Some("UIViewController".into())
        );
    }

    #[test]
    fn test_mock_enum_generic() {
        let t = SwiftTypeDescriptor::mock_enum("Result", "MyApp");
        assert!(t.is_generic());
        assert_eq!(t.generic_params[0].name, "T");
        assert_eq!(t.num_empty_cases, 0);
    }

    #[test]
    fn test_mock_protocol_requirements() {
        let t = SwiftTypeDescriptor::mock_protocol("Drawable", "MyApp");
        assert_eq!(t.protocol_requirements.len(), 1);
        assert!(matches!(
            t.protocol_requirements[0].kind,
            ProtocolRequirementKind::Method
        ));
    }

    #[test]
    fn test_fully_qualified_name() {
        let t = SwiftTypeDescriptor::mock_struct("User", "MyApp");
        assert_eq!(t.fully_qualified_name(), "MyApp.User");
    }

    #[test]
    fn test_fully_qualified_name_no_module() {
        let mut t = SwiftTypeDescriptor::mock_struct("Foo", "Bar");
        t.module_name = None;
        assert_eq!(t.fully_qualified_name(), "Foo");
    }

    // ── Demangling ────────────────────────────────────────────────────────────

    #[test]
    fn test_demangle_passthrough() {
        assert_eq!(demangle_swift_name("_NSObject"), "_NSObject");
        assert_eq!(demangle_swift_name("SomeClass"), "SomeClass");
    }

    #[test]
    fn test_demangle_simple_swift_name() {
        let s = demangle_swift_name("$s5MyApp4UserV");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_mangled_node_optional() {
        let n = MangledNode::Optional(Box::new(MangledNode::Builtin("Int".into())));
        assert_eq!(n.to_swift_type(), "Int?");
    }

    #[test]
    fn test_mangled_node_metatype() {
        let n = MangledNode::Metatype(Box::new(MangledNode::Builtin("String".into())));
        assert_eq!(n.to_swift_type(), "String.Type");
    }

    #[test]
    fn test_mangled_node_existential_metatype() {
        let n = MangledNode::ExistentialMetatype(Box::new(MangledNode::Builtin("Any".into())));
        assert_eq!(n.to_swift_type(), "Any.Protocol");
    }

    #[test]
    fn test_mangled_node_tuple() {
        let n = MangledNode::Tuple(vec![
            MangledNode::Builtin("Int".into()),
            MangledNode::Builtin("Bool".into()),
        ]);
        assert_eq!(n.to_swift_type(), "(Int, Bool)");
    }

    #[test]
    fn test_mangled_node_function_type() {
        let n = MangledNode::FunctionType {
            params: vec![MangledNode::Builtin("Int".into())],
            result: Box::new(MangledNode::Builtin("Bool".into())),
            is_throwing: false,
            is_async: true,
        };
        let s = n.to_swift_type();
        assert!(s.contains("async"));
        assert!(s.contains("Bool"));
    }

    #[test]
    fn test_mangled_node_nominal_generic() {
        let n = MangledNode::Nominal {
            module: Box::new(MangledNode::Module("Swift".into())),
            name: Box::new(MangledNode::Identifier("Array".into())),
            generic_args: vec![MangledNode::Builtin("Int".into())],
        };
        assert_eq!(n.to_swift_type(), "Array<Int>");
    }

    #[test]
    fn test_decode_mangled_type_builtin() {
        let node = decode_mangled_type("$sSi");
        assert_eq!(node.to_swift_type(), "Int");
    }

    #[test]
    fn test_mangled_to_display_no_panic() {
        let _ = mangled_to_display("$sSSSg");
        let _ = mangled_to_display("");
        let _ = mangled_to_display("NSObject");
    }

    // ── String pool ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_string_pool_basic() {
        let data = b"alpha\0beta\0gamma\0";
        let sec = SectionData::new("__swift5_reflstr", data, 0x1000);
        let map = parse_string_pool(&sec);
        assert_eq!(map.get(&0x1000).unwrap(), "alpha");
        assert_eq!(map.get(&0x1006).unwrap(), "beta");
        assert_eq!(map.get(&0x100B).unwrap(), "gamma");
    }

    #[test]
    fn test_parse_string_pool_empty_section() {
        let sec = SectionData::new("__swift5_typeref", &[], 0x2000);
        let map = parse_string_pool(&sec);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_string_pool_single_string() {
        let data = b"Hello\0";
        let sec = SectionData::new("__swift5_reflstr", data, 0x3000);
        let map = parse_string_pool(&sec);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&0x3000).unwrap(), "Hello");
    }

    // ── Replacement records ───────────────────────────────────────────────────

    #[test]
    fn test_parse_replace_empty_header() {
        let data = [0u8; 8];
        let sec = SectionData::new("__swift5_replace", &data, 0x4000);
        assert!(parse_replace(&sec).is_empty());
    }

    #[test]
    fn test_parse_replace_too_short() {
        let data = [0u8; 4];
        let sec = SectionData::new("__swift5_replace", &data, 0x4000);
        assert!(parse_replace(&sec).is_empty());
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_entry_too_short() {
        let data = [0u8; 4];
        let sec = SectionData::new("__swift5_entry", &data, 0x5000);
        assert!(parse_entry(&sec).is_none());
    }

    #[test]
    fn test_parse_entry_valid_zero_rel() {
        let data = [0u8; 8]; // rel32=0, flags=0
        let sec = SectionData::new("__swift5_entry", &data, 0x5000);
        // rel32=0 → function_address=0 (null)
        let ep = parse_entry(&sec).unwrap();
        assert_eq!(ep.flags, 0);
    }

    // ── TypeMetadataKind ──────────────────────────────────────────────────────

    #[test]
    fn test_type_metadata_kind_struct() {
        assert_eq!(TypeMetadataKind::from_raw(0x200), TypeMetadataKind::Struct);
    }

    #[test]
    fn test_type_metadata_kind_function() {
        assert_eq!(
            TypeMetadataKind::from_raw(0x302),
            TypeMetadataKind::Function
        );
    }

    #[test]
    fn test_type_metadata_kind_class_pointer() {
        // Values below 0x200 are class pointers in the runtime ABI.
        assert_eq!(TypeMetadataKind::from_raw(0x01), TypeMetadataKind::Class);
        assert_eq!(TypeMetadataKind::from_raw(0x100), TypeMetadataKind::Class);
    }

    #[test]
    fn test_type_metadata_kind_unknown() {
        assert!(matches!(
            TypeMetadataKind::from_raw(0xDEAD),
            TypeMetadataKind::Unknown(_)
        ));
    }

    // ── TypeMetadata parse ────────────────────────────────────────────────────

    #[test]
    fn test_type_metadata_parse_out_of_range() {
        let data = vec![0u8; 16];
        assert!(TypeMetadata::parse(&data, 0x1000, 0x0FFF).is_none()); // below base
    }

    #[test]
    fn test_type_metadata_parse_truncated() {
        let data = vec![0u8; 4]; // < 8 bytes
        assert!(TypeMetadata::parse(&data, 0x1000, 0x1000).is_none());
    }

    #[test]
    fn test_type_metadata_parse_struct_kind() {
        let mut data = vec![0u8; 16];
        // Write kind = 0x200 (Struct) at offset 0.
        data[0] = 0x00;
        data[1] = 0x02; // LE: 0x0200
        let meta = TypeMetadata::parse(&data, 0x1000, 0x1000).unwrap();
        assert_eq!(meta.kind, TypeMetadataKind::Struct);
    }

    // ── SwiftMetadataResult ───────────────────────────────────────────────────

    #[test]
    fn test_metadata_result_default_empty() {
        let r = SwiftMetadataResult::default();
        assert!(r.types.is_empty());
        assert!(r.conformances.is_empty());
        assert!(r.entry_point.is_none());
    }

    #[test]
    fn test_metadata_result_all_strings_merge() {
        let mut r = SwiftMetadataResult::default();
        r.typeref_strings.insert(0x1000, "TypeA".into());
        r.reflstr_strings.insert(0x2000, "TypeB".into());
        let merged = r.all_strings();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_metadata_result_find_type_none() {
        let r = SwiftMetadataResult::default();
        assert!(r.find_type("NonExistent").is_none());
    }

    #[test]
    fn test_metadata_result_objc_stubs_collected() {
        let mut r = SwiftMetadataResult::default();
        r.types.push(SwiftTypeDescriptor::mock_class("MyVC", "App"));
        let stubs = r.objc_stubs();
        assert!(!stubs.is_empty());
        assert_eq!(stubs[0].class_name, "MyVC");
    }

    // ── SwiftMetadataParser ───────────────────────────────────────────────────

    #[test]
    fn test_parser_type_count() {
        let p = SwiftMetadataParser::mock();
        assert_eq!(p.type_count(), 3);
    }

    #[test]
    fn test_parser_find_type_by_name() {
        let p = SwiftMetadataParser::mock();
        assert!(p.find_type("User").is_some());
        assert!(p.find_type("NonExistent").is_none());
    }

    #[test]
    fn test_parser_find_type_by_fqn() {
        let p = SwiftMetadataParser::mock();
        assert!(p.find_type("MyApp.User").is_some());
    }

    #[test]
    fn test_parser_types_conforming_to() {
        let p = SwiftMetadataParser::mock();
        let codable = p.types_conforming_to("Codable");
        assert!(!codable.is_empty());
        assert!(codable.iter().any(|t| t.name == "User"));
    }

    #[test]
    fn test_parser_conformances_for() {
        let p = SwiftMetadataParser::mock();
        let confs = p.conformances_for("MyApp.User");
        assert_eq!(confs.len(), 1);
        assert_eq!(confs[0].protocol_name, "Codable");
    }

    #[test]
    fn test_parser_types_by_kind() {
        let p = SwiftMetadataParser::mock();
        let by_kind = p.types_by_kind();
        assert!(by_kind.contains_key("struct"));
        assert!(by_kind.contains_key("class"));
        assert!(by_kind.contains_key("enum"));
    }

    // ── Sections constants ────────────────────────────────────────────────────

    #[test]
    fn test_sections_constants() {
        assert_eq!(sections::SWIFT5_TYPES, "__swift5_types");
        assert_eq!(sections::SWIFT5_PROTO, "__swift5_proto");
        assert_eq!(sections::SWIFT5_FIELDMD, "__swift5_fieldmd");
        assert_eq!(sections::SWIFT5_REFLSTR, "__swift5_reflstr");
        assert_eq!(sections::SWIFT5_ASSOCTY, "__swift5_assocty");
        assert_eq!(sections::SWIFT5_REPLACE, "__swift5_replace");
        assert_eq!(sections::SWIFT5_ENTRY, "__swift5_entry");
    }

    // ── Byte helpers ──────────────────────────────────────────────────────────

    #[test]
    fn test_read_u32_le() {
        let data = [0x01u8, 0x00, 0x00, 0x00];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_read_u32_le_max() {
        let data = [0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(read_i32_le(&data, 0).unwrap(), i32::MAX);
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u64_le() {
        let data = [1u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(read_u64_le(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_read_cstring() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstring(data, 0).unwrap(), "hello");
        assert_eq!(read_cstring(data, 6).unwrap(), "world");
    }

    #[test]
    fn test_read_cstring_unterminated() {
        let data = b"noeol";
        assert!(read_cstring(data, 0).is_err());
    }

    #[test]
    fn test_read_truncated_errors() {
        let data = [0u8; 2];
        assert!(read_u32_le(&data, 0).is_err());
        assert!(read_u64_le(&data, 0).is_err());
    }

    // ── VTableEntry kind ─────────────────────────────────────────────────────

    #[test]
    fn test_vtable_entry_kind() {
        assert!(matches!(
            VTableEntryKind::from_flags(0x00),
            VTableEntryKind::Method
        ));
        assert!(matches!(
            VTableEntryKind::from_flags(0x10),
            VTableEntryKind::Init
        ));
        assert!(matches!(
            VTableEntryKind::from_flags(0x20),
            VTableEntryKind::Getter
        ));
        assert!(matches!(
            VTableEntryKind::from_flags(0x30),
            VTableEntryKind::Setter
        ));
    }

    // ── ProtocolRequirementKind ───────────────────────────────────────────────

    #[test]
    fn test_protocol_requirement_kind() {
        assert!(matches!(
            ProtocolRequirementKind::from_flags(0x00),
            ProtocolRequirementKind::BaseProtocol
        ));
        assert!(matches!(
            ProtocolRequirementKind::from_flags(0x01),
            ProtocolRequirementKind::Method
        ));
        assert!(matches!(
            ProtocolRequirementKind::from_flags(0x07),
            ProtocolRequirementKind::AssociatedTypeAccessFunction
        ));
    }

    // ── GenericRequirementKind ────────────────────────────────────────────────

    #[test]
    fn test_generic_requirement_kind() {
        assert!(matches!(
            GenericRequirementKind::from_flags(0x00),
            GenericRequirementKind::Conformance
        ));
        assert!(matches!(
            GenericRequirementKind::from_flags(0x01),
            GenericRequirementKind::SameType
        ));
        assert!(matches!(
            GenericRequirementKind::from_flags(0x02),
            GenericRequirementKind::BaseClass
        ));
    }

    // ── Swift5Sections default ────────────────────────────────────────────────

    #[test]
    fn test_swift5_sections_default_all_none() {
        let s = Swift5Sections::default();
        assert!(s.types.is_none());
        assert!(s.proto.is_none());
        assert!(s.fieldmd.is_none());
        assert!(s.typeref.is_none());
        assert!(s.reflstr.is_none());
        assert!(s.assocty.is_none());
        assert!(s.replace.is_none());
        assert!(s.entry.is_none());
    }

    // ── SectionData ───────────────────────────────────────────────────────────

    #[test]
    fn test_section_data_len() {
        let data = [0u8; 64];
        let sec = SectionData::new("__swift5_types", &data, 0x1000);
        assert_eq!(sec.len(), 64);
        assert!(!sec.is_empty());
    }

    #[test]
    fn test_section_data_empty() {
        let sec = SectionData::new("__swift5_types", &[], 0x1000);
        assert!(sec.is_empty());
    }

    // ── parse_swift_metadata integration (empty sections) ────────────────────

    #[test]
    fn test_parse_swift_metadata_all_none_sections() {
        let sections = Swift5Sections::default();
        let result = parse_swift_metadata(&sections);
        assert!(result.types.is_empty());
        assert!(result.conformances.is_empty());
        assert!(result.entry_point.is_none());
    }

    // ── ObjcMetadataStub ──────────────────────────────────────────────────────

    #[test]
    fn test_objc_stub_is_root_when_no_superclass() {
        let stub = ObjcMetadataStub {
            class_name: "MyClass".into(),
            swift_class_name: "App.MyClass".into(),
            is_root: true,
            superclass_name: None,
            selectors: vec![],
        };
        assert!(stub.is_root);
        assert!(stub.superclass_name.is_none());
    }

    // ── SwiftBuiltinTypeDescriptor ────────────────────────────────────────────

    #[test]
    fn test_builtin_type_in_parser_mock() {
        let p = SwiftMetadataParser::mock();
        assert_eq!(p.builtins.len(), 1);
        assert_eq!(p.builtins[0].name, "Swift.Int");
        assert_eq!(p.builtins[0].size, 8);
        assert!(p.builtins[0].is_bitwise_takable);
    }

    // ── lookup_str ────────────────────────────────────────────────────────────

    #[test]
    fn test_lookup_str_prefers_first_map() {
        let mut a = HashMap::new();
        let mut b = HashMap::new();
        a.insert(0x1000u64, "from_a".to_string());
        b.insert(0x1000u64, "from_b".to_string());
        assert_eq!(lookup_str(0x1000, &a, &b).unwrap(), "from_a");
    }

    #[test]
    fn test_lookup_str_falls_back_to_second_map() {
        let a = HashMap::new();
        let mut b = HashMap::new();
        b.insert(0x2000u64, "from_b".to_string());
        assert_eq!(lookup_str(0x2000, &a, &b).unwrap(), "from_b");
    }

    #[test]
    fn test_lookup_str_not_found() {
        let a: HashMap<u64, String> = HashMap::new();
        let b: HashMap<u64, String> = HashMap::new();
        assert!(lookup_str(0x9999, &a, &b).is_none());
    }
}
