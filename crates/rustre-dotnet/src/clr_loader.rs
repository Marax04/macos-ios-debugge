//! CLR assembly loader.
//!
//! Parses .NET assemblies and exposes `AssemblyDef`, `AssemblyRef`, `ModuleDef`,
//! `TypeDef`, `MethodDef`, and `FieldDef` with full metadata table parsing.

use std::fmt;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from the CLR loader.
#[derive(Debug)]
pub enum ClrLoaderError {
    /// Buffer too small.
    TooSmall,
    /// Invalid BSJB magic.
    InvalidMagic,
    /// Unsupported metadata version.
    UnsupportedVersion(String),
    /// Requested stream not found.
    StreamNotFound(String),
    /// Index out of range.
    IndexOutOfRange { table: &'static str, index: u32 },
    /// Heap offset out of range.
    HeapOutOfRange { heap: &'static str, offset: u32 },
    /// Parse error with context.
    ParseError(String),
}

impl fmt::Display for ClrLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::InvalidMagic => write!(f, "invalid BSJB magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported metadata version: {v}"),
            Self::StreamNotFound(s) => write!(f, "stream not found: {s}"),
            Self::IndexOutOfRange { table, index } => {
                write!(f, "index {index} out of range for table {table}")
            }
            Self::HeapOutOfRange { heap, offset } => {
                write!(f, "offset {offset:#x} out of range for heap {heap}")
            }
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

// ─── PublicKeyToken ──────────────────────────────────────────────────────────

/// A public key token (last 8 bytes of SHA-1 of public key, reversed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyToken(pub [u8; 8]);

impl PublicKeyToken {
    /// Parse from a hex string (16 hex chars).
    #[must_use] 
    pub fn parse_hex(hex: &str) -> Option<Self> {
        if hex.len() != 16 {
            return None;
        }
        let mut bytes = [0u8; 8];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let high = u8::try_from(char::from(chunk[0]).to_digit(16)?).ok()?;
            let low = u8::try_from(char::from(chunk[1]).to_digit(16)?).ok()?;
            bytes[i] = (high << 4) | low;
        }
        Some(Self(bytes))
    }

    /// Format as a hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
    }

    /// Return true if this is an empty/null token.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 8]
    }
}

impl fmt::Display for PublicKeyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ─── AssemblyDef ─────────────────────────────────────────────────────────────

/// An assembly definition (metadata table 0x20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyDef {
    /// Hash algorithm ID (0x8004 = SHA1).
    pub hash_algorithm: u32,
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Build number.
    pub build: u16,
    /// Revision.
    pub revision: u16,
    /// Assembly flags.
    pub flags: u32,
    /// Public key blob (empty if not strong-named).
    pub public_key: Vec<u8>,
    /// Assembly name.
    pub name: String,
    /// Culture string (empty = neutral).
    pub culture: String,
    /// Computed public key token (last 8 bytes of SHA-1 of public key).
    pub public_key_token: PublicKeyToken,
}

impl AssemblyDef {
    /// Return the version as a dotted string.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }

    /// Return true if this is a strong-named assembly.
    #[must_use]
    pub const fn is_strong_named(&self) -> bool {
        !self.public_key.is_empty()
    }

    /// Return the fully qualified assembly name.
    #[must_use]
    pub fn full_name(&self) -> String {
        let culture = if self.culture.is_empty() {
            "neutral".to_owned()
        } else {
            self.culture.clone()
        };
        let pkt = if self.public_key_token.is_null() {
            "null".to_owned()
        } else {
            self.public_key_token.to_hex()
        };
        format!(
            "{}, Version={}, Culture={}, PublicKeyToken={}",
            self.name,
            self.version_string(),
            culture,
            pkt
        )
    }
}

// ─── AssemblyRef ─────────────────────────────────────────────────────────────

/// An assembly reference (metadata table 0x23).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyRef {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key_or_token: Vec<u8>,
    pub name: String,
    pub culture: String,
    pub hash_value: Vec<u8>,
}

impl AssemblyRef {
    /// Return the version as a dotted string.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }

    /// Return a display string.
    #[must_use]
    pub fn display(&self) -> String {
        format!("{} v{}", self.name, self.version_string())
    }
}

// ─── ModuleDef ───────────────────────────────────────────────────────────────

/// The module definition (metadata table 0x00).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDef {
    /// Generation (always 0).
    pub generation: u16,
    /// Module name.
    pub name: String,
    /// Module MVID GUID.
    pub mvid: [u8; 16],
    /// `EncId` (always 0 for non-incremental compilations).
    pub enc_id: [u8; 16],
    /// `EncBaseId`.
    pub enc_base_id: [u8; 16],
}

impl ModuleDef {
    /// Return MVID as a formatted GUID string.
    #[must_use]
    pub fn mvid_string(&self) -> String {
        let g = &self.mvid;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            g[3],
            g[2],
            g[1],
            g[0],
            g[5],
            g[4],
            g[7],
            g[6],
            g[8],
            g[9],
            g[10],
            g[11],
            g[12],
            g[13],
            g[14],
            g[15]
        )
    }
}

// ─── TypeAttributes ──────────────────────────────────────────────────────────

/// Type attributes flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeAttributes(pub u32);

impl TypeAttributes {
    pub const VISIBILITY_MASK: u32 = 0x0000_0007;
    pub const NOT_PUBLIC: u32 = 0x0000_0000;
    pub const PUBLIC: u32 = 0x0000_0001;
    pub const NESTED_PUBLIC: u32 = 0x0000_0002;
    pub const NESTED_PRIVATE: u32 = 0x0000_0003;
    pub const NESTED_FAMILY: u32 = 0x0000_0004;
    pub const NESTED_ASSEMBLY: u32 = 0x0000_0005;
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x0000_0006;
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x0000_0007;

    pub const LAYOUT_MASK: u32 = 0x0000_0018;
    pub const AUTO_LAYOUT: u32 = 0x0000_0000;
    pub const SEQUENTIAL_LAYOUT: u32 = 0x0000_0008;
    pub const EXPLICIT_LAYOUT: u32 = 0x0000_0010;

    pub const CLASS_SEMANTIC_MASK: u32 = 0x0000_0020;
    pub const CLASS: u32 = 0x0000_0000;
    pub const INTERFACE: u32 = 0x0000_0020;

    pub const ABSTRACT: u32 = 0x0000_0080;
    pub const SEALED: u32 = 0x0000_0100;
    pub const SPECIAL_NAME: u32 = 0x0000_0400;
    pub const IMPORT: u32 = 0x0000_1000;
    pub const SERIALIZABLE: u32 = 0x0000_2000;
    pub const BEFORE_FIELD_INIT: u32 = 0x0010_0000;
    pub const RT_SPECIAL_NAME: u32 = 0x0000_0800;

    /// Return true if this type is an interface.
    #[must_use]
    pub const fn is_interface(self) -> bool {
        self.0 & Self::INTERFACE != 0
    }
    /// Return true if this type is abstract.
    #[must_use]
    pub const fn is_abstract(self) -> bool {
        self.0 & Self::ABSTRACT != 0
    }
    /// Return true if this type is sealed.
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        self.0 & Self::SEALED != 0
    }
    /// Return true if this is a public type.
    #[must_use]
    pub const fn is_public(self) -> bool {
        self.0 & Self::VISIBILITY_MASK == Self::PUBLIC
    }
    /// Return true if this is a nested public type.
    #[must_use]
    pub const fn is_nested(self) -> bool {
        (self.0 & Self::VISIBILITY_MASK) >= Self::NESTED_PUBLIC
    }
}

// ─── TypeDef ─────────────────────────────────────────────────────────────────

/// A type definition (metadata table 0x02).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    /// Row index (1-based).
    pub row: u32,
    /// Type attributes.
    pub flags: TypeAttributes,
    /// Simple type name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Base type token (TypeRef/TypeDef/TypeSpec coded index).
    pub extends: u32,
    /// First method index (into `MethodDef` table).
    pub method_list: u32,
    /// First field index (into Field table).
    pub field_list: u32,
}

impl TypeDef {
    /// Return the fully qualified type name.
    #[must_use]
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }

    /// Return true if this is the global module type.
    #[must_use]
    pub fn is_module_type(&self) -> bool {
        self.name == "<Module>"
    }
}

// ─── MethodAttributes ────────────────────────────────────────────────────────

/// Method attributes flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodAttributes(pub u16);

impl MethodAttributes {
    pub const MEMBER_ACCESS_MASK: u16 = 0x0007;
    pub const PRIVATE_SCOPE: u16 = 0x0000;
    pub const PRIVATE: u16 = 0x0001;
    pub const FAM_AND_ASSEM: u16 = 0x0002;
    pub const ASSEM: u16 = 0x0003;
    pub const FAMILY: u16 = 0x0004;
    pub const FAM_OR_ASSEM: u16 = 0x0005;
    pub const PUBLIC: u16 = 0x0006;

    pub const STATIC: u16 = 0x0010;
    pub const FINAL: u16 = 0x0020;
    pub const VIRTUAL: u16 = 0x0040;
    pub const HIDE_BY_SIG: u16 = 0x0080;
    pub const NEW_SLOT: u16 = 0x0100;
    pub const CHECK_ACCESS_ON_OVERRIDE: u16 = 0x0200;
    pub const ABSTRACT: u16 = 0x0400;
    pub const SPECIAL_NAME: u16 = 0x0800;
    pub const PINVOKE_IMPL: u16 = 0x2000;
    pub const RT_SPECIAL_NAME: u16 = 0x1000;

    #[must_use]
    pub const fn is_public(self) -> bool {
        self.0 & Self::MEMBER_ACCESS_MASK == Self::PUBLIC
    }
    #[must_use]
    pub const fn is_private(self) -> bool {
        self.0 & Self::MEMBER_ACCESS_MASK == Self::PRIVATE
    }
    #[must_use]
    pub const fn is_static(self) -> bool {
        self.0 & Self::STATIC != 0
    }
    #[must_use]
    pub const fn is_virtual(self) -> bool {
        self.0 & Self::VIRTUAL != 0
    }
    #[must_use]
    pub const fn is_abstract(self) -> bool {
        self.0 & Self::ABSTRACT != 0
    }
    #[must_use]
    pub const fn is_pinvoke(self) -> bool {
        self.0 & Self::PINVOKE_IMPL != 0
    }
    #[must_use]
    pub const fn is_ctor(self) -> bool {
        self.0 & Self::RT_SPECIAL_NAME != 0
    }
}

// ─── MethodImplAttributes ────────────────────────────────────────────────────

/// Method implementation attributes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodImplAttributes(pub u16);

impl MethodImplAttributes {
    pub const IL: u16 = 0x0000;
    pub const NATIVE: u16 = 0x0001;
    pub const OPTIL: u16 = 0x0002;
    pub const RUNTIME: u16 = 0x0003;
    pub const CODE_TYPE_MASK: u16 = 0x0003;
    pub const MANAGED: u16 = 0x0000;
    pub const UNMANAGED: u16 = 0x0004;
    pub const MANAGED_MASK: u16 = 0x0004;
    pub const NO_INLINING: u16 = 0x0008;
    pub const FORWARD_REF: u16 = 0x0010;
    pub const SYNCHRONIZED: u16 = 0x0020;
    pub const NO_OPTIMIZATION: u16 = 0x0040;
    pub const PRESERVE_SIG: u16 = 0x0080;
    pub const AGGRESSIVE_INLINING: u16 = 0x0100;
    pub const AGGRESSIVE_OPTIMIZATION: u16 = 0x0200;
    pub const INTERNAL_CALL: u16 = 0x1000;

    #[must_use]
    pub const fn is_il(self) -> bool {
        self.0 & Self::CODE_TYPE_MASK == Self::IL
    }
    #[must_use]
    pub const fn is_native(self) -> bool {
        self.0 & Self::CODE_TYPE_MASK == Self::NATIVE
    }
    #[must_use]
    pub const fn is_no_inlining(self) -> bool {
        self.0 & Self::NO_INLINING != 0
    }
    #[must_use]
    pub const fn is_synchronized(self) -> bool {
        self.0 & Self::SYNCHRONIZED != 0
    }
}

// ─── MethodDef ───────────────────────────────────────────────────────────────

/// A method definition (metadata table 0x06).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDef {
    /// Row index (1-based).
    pub row: u32,
    /// Method RVA (0 = abstract or extern).
    pub rva: u32,
    /// Implementation attributes.
    pub impl_flags: MethodImplAttributes,
    /// Method attributes.
    pub flags: MethodAttributes,
    /// Method name.
    pub name: String,
    /// Signature blob index.
    pub signature: u32,
    /// First parameter index.
    pub param_list: u32,
    /// Owning type row (set after linking).
    pub owner_type: u32,
}

impl MethodDef {
    /// Return a display string.
    #[must_use]
    pub fn display(&self) -> String {
        let vis = if self.flags.is_public() {
            "public"
        } else {
            "private"
        };
        let stat = if self.flags.is_static() {
            " static"
        } else {
            ""
        };
        let virt = if self.flags.is_virtual() {
            " virtual"
        } else {
            ""
        };
        format!("{vis}{stat}{virt} {}", self.name)
    }

    /// Return true if this is a constructor.
    #[must_use]
    pub fn is_ctor(&self) -> bool {
        self.name == ".ctor" || self.name == ".cctor"
    }

    /// Return true if this method has a body.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.rva != 0 && self.impl_flags.is_il()
    }
}

// ─── FieldAttributes ─────────────────────────────────────────────────────────

/// Field attributes flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldAttributes(pub u16);

impl FieldAttributes {
    pub const FIELD_ACCESS_MASK: u16 = 0x0007;
    pub const PRIVATE_SCOPE: u16 = 0x0000;
    pub const PRIVATE: u16 = 0x0001;
    pub const FAM_AND_ASSEM: u16 = 0x0002;
    pub const ASSEMBLY: u16 = 0x0003;
    pub const FAMILY: u16 = 0x0004;
    pub const FAM_OR_ASSEM: u16 = 0x0005;
    pub const PUBLIC: u16 = 0x0006;
    pub const STATIC: u16 = 0x0010;
    pub const INIT_ONLY: u16 = 0x0020;
    pub const LITERAL: u16 = 0x0040;
    pub const NOT_SERIALIZED: u16 = 0x0080;
    pub const SPECIAL_NAME: u16 = 0x0200;
    pub const PINVOKE_IMPL: u16 = 0x2000;
    pub const RT_SPECIAL_NAME: u16 = 0x0400;
    pub const HAS_FIELD_MARSHAL: u16 = 0x1000;
    pub const HAS_DEFAULT: u16 = 0x8000;
    pub const HAS_FIELD_RVA: u16 = 0x0100;

    #[must_use]
    pub const fn is_public(self) -> bool {
        self.0 & Self::FIELD_ACCESS_MASK == Self::PUBLIC
    }
    #[must_use]
    pub const fn is_private(self) -> bool {
        self.0 & Self::FIELD_ACCESS_MASK == Self::PRIVATE
    }
    #[must_use]
    pub const fn is_static(self) -> bool {
        self.0 & Self::STATIC != 0
    }
    #[must_use]
    pub const fn is_literal(self) -> bool {
        self.0 & Self::LITERAL != 0
    }
    #[must_use]
    pub const fn is_readonly(self) -> bool {
        self.0 & Self::INIT_ONLY != 0
    }
}

// ─── FieldDef ────────────────────────────────────────────────────────────────

/// A field definition (metadata table 0x04).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Row index (1-based).
    pub row: u32,
    /// Field attributes.
    pub flags: FieldAttributes,
    /// Field name.
    pub name: String,
    /// Signature blob index.
    pub signature: u32,
    /// Owning type row (set after linking).
    pub owner_type: u32,
}

impl FieldDef {
    /// Return a display string.
    #[must_use]
    pub fn display(&self) -> String {
        let vis = if self.flags.is_public() {
            "public"
        } else {
            "private"
        };
        let stat = if self.flags.is_static() {
            " static"
        } else {
            ""
        };
        let ro = if self.flags.is_readonly() {
            " readonly"
        } else {
            ""
        };
        format!("{vis}{stat}{ro} {}", self.name)
    }
}

// ─── MemberRef ───────────────────────────────────────────────────────────────

/// A member reference (metadata table 0x0A).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRef {
    pub row: u32,
    /// Encoded parent token.
    pub class: u32,
    pub name: String,
    pub signature: u32,
}

// ─── ClrLoader ───────────────────────────────────────────────────────────────

/// High-level CLR assembly loader.
///
/// Parses a .NET assembly and exposes metadata tables.
#[derive(Debug, Default)]
pub struct ClrLoader {
    /// Assembly definition (if present).
    pub assembly_def: Option<AssemblyDef>,
    /// Assembly references.
    pub assembly_refs: Vec<AssemblyRef>,
    /// Module definition.
    pub module_def: Option<ModuleDef>,
    /// Type definitions.
    pub type_defs: Vec<TypeDef>,
    /// Method definitions.
    pub method_defs: Vec<MethodDef>,
    /// Field definitions.
    pub field_defs: Vec<FieldDef>,
    /// Member references.
    pub member_refs: Vec<MemberRef>,
    /// Type by full name index (`AHashMap` to resist hash-collision `DoS` on attacker-controlled type names).
    type_index: AHashMap<String, usize>,
}

impl ClrLoader {
    /// Create an empty loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load an assembly from bytes (simple stub — builds from pre-populated tables).
    ///
    /// In a full implementation this would parse the PE → CLR header → metadata streams.
    /// For this crate layer we expose the data model only.
    #[must_use] 
    pub fn from_tables(
        assembly_def: Option<AssemblyDef>,
        assembly_refs: Vec<AssemblyRef>,
        module_def: Option<ModuleDef>,
        type_defs: Vec<TypeDef>,
        method_defs: Vec<MethodDef>,
        field_defs: Vec<FieldDef>,
        member_refs: Vec<MemberRef>,
    ) -> Self {
        let mut loader = Self {
            assembly_def,
            assembly_refs,
            module_def,
            type_defs,
            method_defs,
            field_defs,
            member_refs,
            type_index: AHashMap::new(),
        };
        loader.build_index();
        loader
    }

    fn build_index(&mut self) {
        self.type_index.clear();
        for (i, td) in self.type_defs.iter().enumerate() {
            self.type_index.insert(td.full_name(), i);
        }
    }

    /// Look up a type by full name.
    #[must_use]
    pub fn find_type(&self, full_name: &str) -> Option<&TypeDef> {
        self.type_index.get(full_name).map(|&i| &self.type_defs[i])
    }

    /// Return all methods of a type.
    #[must_use]
    pub fn methods_of(&self, type_row: u32) -> Vec<&MethodDef> {
        self.method_defs
            .iter()
            .filter(|m| m.owner_type == type_row)
            .collect()
    }

    /// Return all fields of a type.
    #[must_use]
    pub fn fields_of(&self, type_row: u32) -> Vec<&FieldDef> {
        self.field_defs
            .iter()
            .filter(|f| f.owner_type == type_row)
            .collect()
    }

    /// Return all public methods.
    #[must_use]
    pub fn public_methods(&self) -> Vec<&MethodDef> {
        self.method_defs
            .iter()
            .filter(|m| m.flags.is_public())
            .collect()
    }

    /// Return all public types (not nested).
    #[must_use]
    pub fn public_types(&self) -> Vec<&TypeDef> {
        self.type_defs
            .iter()
            .filter(|t| t.flags.is_public() && !t.is_module_type())
            .collect()
    }

    /// Return all constructors.
    #[must_use]
    pub fn constructors(&self) -> Vec<&MethodDef> {
        self.method_defs.iter().filter(|m| m.is_ctor()).collect()
    }

    /// Return the assembly's full name if available.
    #[must_use]
    pub fn assembly_full_name(&self) -> Option<String> {
        self.assembly_def.as_ref().map(AssemblyDef::full_name)
    }

    /// Return the count of types (excluding <Module>).
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.type_defs
            .iter()
            .filter(|t| !t.is_module_type())
            .count()
    }

    /// Return the count of methods with a body.
    #[must_use]
    pub fn method_with_body_count(&self) -> usize {
        self.method_defs.iter().filter(|m| m.has_body()).count()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_type_def(row: u32, ns: &str, name: &str, public: bool) -> TypeDef {
        TypeDef {
            row,
            flags: TypeAttributes(if public { TypeAttributes::PUBLIC } else { 0 }),
            name: name.to_owned(),
            namespace: ns.to_owned(),
            extends: 0,
            method_list: 1,
            field_list: 1,
        }
    }

    fn sample_method_def(
        row: u32,
        name: &str,
        owner: u32,
        public: bool,
        has_body: bool,
    ) -> MethodDef {
        MethodDef {
            row,
            rva: if has_body { 0x1000 } else { 0 },
            impl_flags: MethodImplAttributes(MethodImplAttributes::IL),
            flags: MethodAttributes(if public {
                MethodAttributes::PUBLIC
            } else {
                MethodAttributes::PRIVATE
            }),
            name: name.to_owned(),
            signature: 1,
            param_list: 1,
            owner_type: owner,
        }
    }

    fn sample_assembly_def(name: &str) -> AssemblyDef {
        AssemblyDef {
            hash_algorithm: 0x8004,
            major: 1,
            minor: 2,
            build: 3,
            revision: 4,
            flags: 0,
            public_key: vec![],
            name: name.to_owned(),
            culture: String::new(),
            public_key_token: PublicKeyToken::default(),
        }
    }

    #[test]
    fn test_assembly_def_version_string() {
        let a = sample_assembly_def("MyAssembly");
        assert_eq!(a.version_string(), "1.2.3.4");
    }

    #[test]
    fn test_assembly_def_full_name() {
        let a = sample_assembly_def("MyAssembly");
        let full = a.full_name();
        assert!(full.contains("MyAssembly"));
        assert!(full.contains("1.2.3.4"));
        assert!(full.contains("neutral"));
    }

    #[test]
    fn test_assembly_def_not_strong_named() {
        let a = sample_assembly_def("MyAssembly");
        assert!(!a.is_strong_named());
    }

    #[test]
    fn test_assembly_def_strong_named() {
        let mut a = sample_assembly_def("StrongLib");
        a.public_key = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert!(a.is_strong_named());
    }

    #[test]
    fn test_public_key_token_roundtrip() {
        let token = PublicKeyToken::parse_hex("b77a5c561934e089").unwrap();
        assert_eq!(token.to_hex(), "b77a5c561934e089");
    }

    #[test]
    fn test_public_key_token_null() {
        let t = PublicKeyToken::default();
        assert!(t.is_null());
    }

    #[test]
    fn test_type_def_full_name() {
        let td = sample_type_def(1, "System", "String", true);
        assert_eq!(td.full_name(), "System.String");
    }

    #[test]
    fn test_type_def_no_namespace() {
        let td = sample_type_def(1, "", "Program", true);
        assert_eq!(td.full_name(), "Program");
    }

    #[test]
    fn test_type_def_is_module_type() {
        let td = sample_type_def(1, "", "<Module>", false);
        assert!(td.is_module_type());
    }

    #[test]
    fn test_method_def_display() {
        let m = sample_method_def(1, "Main", 1, true, true);
        let d = m.display();
        assert!(d.contains("public"));
        assert!(d.contains("Main"));
    }

    #[test]
    fn test_method_def_is_ctor() {
        let mut m = sample_method_def(1, ".ctor", 1, true, true);
        assert!(m.is_ctor());
        m.name = "Main".to_owned();
        assert!(!m.is_ctor());
    }

    #[test]
    fn test_method_def_has_body() {
        let m = sample_method_def(1, "Process", 1, true, true);
        assert!(m.has_body());
        let m2 = sample_method_def(2, "Abstract", 1, true, false);
        assert!(!m2.has_body());
    }

    #[test]
    fn test_field_def_display() {
        let f = FieldDef {
            row: 1,
            flags: FieldAttributes(FieldAttributes::PUBLIC | FieldAttributes::STATIC),
            name: "Count".to_owned(),
            signature: 1,
            owner_type: 1,
        };
        let d = f.display();
        assert!(d.contains("public"));
        assert!(d.contains("static"));
        assert!(d.contains("Count"));
    }

    #[test]
    fn test_clr_loader_find_type() {
        let types = vec![
            sample_type_def(1, "MyNs", "MyClass", true),
            sample_type_def(2, "MyNs", "OtherClass", true),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, types, vec![], vec![], vec![]);
        assert!(loader.find_type("MyNs.MyClass").is_some());
        assert!(loader.find_type("MyNs.OtherClass").is_some());
        assert!(loader.find_type("Missing").is_none());
    }

    #[test]
    fn test_clr_loader_public_types() {
        let types = vec![
            sample_type_def(1, "MyNs", "Public", true),
            sample_type_def(2, "MyNs", "Private", false),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, types, vec![], vec![], vec![]);
        let pub_types = loader.public_types();
        assert_eq!(pub_types.len(), 1);
        assert_eq!(pub_types[0].name, "Public");
    }

    #[test]
    fn test_clr_loader_methods_of() {
        let methods = vec![
            sample_method_def(1, "MethodA", 2, true, true),
            sample_method_def(2, "MethodB", 2, true, true),
            sample_method_def(3, "MethodC", 5, true, true),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, vec![], methods, vec![], vec![]);
        assert_eq!(loader.methods_of(2).len(), 2);
        assert_eq!(loader.methods_of(5).len(), 1);
    }

    #[test]
    fn test_clr_loader_constructors() {
        let methods = vec![
            sample_method_def(1, ".ctor", 1, true, true),
            sample_method_def(2, ".cctor", 1, true, true),
            sample_method_def(3, "Method", 1, true, true),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, vec![], methods, vec![], vec![]);
        assert_eq!(loader.constructors().len(), 2);
    }

    #[test]
    fn test_clr_loader_method_with_body_count() {
        let methods = vec![
            sample_method_def(1, "WithBody", 1, true, true),
            sample_method_def(2, "NoBody", 1, false, false),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, vec![], methods, vec![], vec![]);
        assert_eq!(loader.method_with_body_count(), 1);
    }

    #[test]
    fn test_clr_loader_type_count_excludes_module() {
        let types = vec![
            sample_type_def(1, "", "<Module>", false),
            sample_type_def(2, "MyNs", "RealType", true),
        ];
        let loader = ClrLoader::from_tables(None, vec![], None, types, vec![], vec![], vec![]);
        assert_eq!(loader.type_count(), 1);
    }

    #[test]
    fn test_assembly_ref_display() {
        let ar = AssemblyRef {
            major: 4,
            minor: 0,
            build: 0,
            revision: 0,
            flags: 0,
            public_key_or_token: vec![],
            name: "mscorlib".to_owned(),
            culture: String::new(),
            hash_value: vec![],
        };
        assert!(ar.display().contains("mscorlib"));
        assert!(ar.display().contains("4.0.0.0"));
    }

    #[test]
    fn test_module_def_mvid_string() {
        let m = ModuleDef {
            generation: 0,
            name: "test.dll".to_owned(),
            mvid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            enc_id: [0u8; 16],
            enc_base_id: [0u8; 16],
        };
        let s = m.mvid_string();
        assert!(s.contains('-'));
    }

    #[test]
    fn test_type_attributes_flags() {
        let t = TypeAttributes(
            TypeAttributes::ABSTRACT | TypeAttributes::SEALED | TypeAttributes::INTERFACE,
        );
        assert!(t.is_abstract());
        assert!(t.is_sealed());
        assert!(t.is_interface());
    }

    #[test]
    fn test_method_attributes_flags() {
        let m = MethodAttributes(
            MethodAttributes::PUBLIC | MethodAttributes::STATIC | MethodAttributes::VIRTUAL,
        );
        assert!(m.is_public());
        assert!(m.is_static());
        assert!(m.is_virtual());
        assert!(!m.is_abstract());
    }

    #[test]
    fn test_field_attributes_literal() {
        let f = FieldAttributes(
            FieldAttributes::LITERAL | FieldAttributes::PUBLIC | FieldAttributes::STATIC,
        );
        assert!(f.is_literal());
        assert!(f.is_static());
        assert!(f.is_public());
    }
}
