//! `dotnet_type_system` â€” .NET type system model (semantic / analysis layer).
//!
//! Builds a rich type model from decoded metadata tables: type resolution,
//! inheritance chains, interface implementation, generic parameter tracking,
//! method resolution order (MRO), field layout, nested type trees, and
//! assembly dependency graphs.
//!
//! # Design note â€” relation to `dotnet_type_loader`
//! [`dotnet_type_loader`] is the **table-walking / data-extraction** layer:
//! it reads `TypeDef`, `TypeRef`, `InterfaceImpl`, and `NestedClass` rows
//! and produces flat typed records.  This module (`dotnet_type_system`) is the
//! **semantic analysis** layer built on top: it resolves inheritance chains,
//! computes MRO, tracks generic parameters, and models the full type graph.
//! The two modules are intentionally distinct pipeline stages.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::DotnetLoaderError;

// ---------------------------------------------------------------------------
// Type visibility / accessibility
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeVisibility {
    NotPublic = 0,
    Public = 1,
    NestedPublic = 2,
    NestedPrivate = 3,
    NestedFamily = 4,
    NestedAssembly = 5,
    NestedFamANDAssem = 6,
    NestedFamORAssem = 7,
}

impl TypeVisibility {
    #[must_use] 
    pub const fn from_flags(flags: u32) -> Self {
        match flags & 0x7 {
            1 => Self::Public,
            2 => Self::NestedPublic,
            3 => Self::NestedPrivate,
            4 => Self::NestedFamily,
            5 => Self::NestedAssembly,
            6 => Self::NestedFamANDAssem,
            7 => Self::NestedFamORAssem,
            _ => Self::NotPublic,
        }
    }
    #[must_use] 
    pub const fn is_public_visible(&self) -> bool {
        matches!(self, Self::Public | Self::NestedPublic | Self::NestedFamORAssem)
    }
    #[must_use] 
    pub const fn is_nested(&self) -> bool {
        !matches!(self, Self::NotPublic | Self::Public)
    }
}

// ---------------------------------------------------------------------------
// Type layout / semantics flags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeLayout {
    Auto,
    Sequential,
    Explicit,
}

impl TypeLayout {
    #[must_use] 
    pub const fn from_flags(flags: u32) -> Self {
        match (flags >> 3) & 0x3 {
            1 => Self::Sequential, 2 => Self::Explicit, _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSemantics {
    Class,
    Interface,
    Enum,
    ValueType,
    Delegate,
    Attribute,
    Module,
    Unknown,
}

// ---------------------------------------------------------------------------
// Method access flags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodAccess {
    CompilerControlled = 0,
    Private = 1,
    FamANDAssem = 2,
    Assem = 3,
    Family = 4,
    FamORAssem = 5,
    Public = 6,
}

impl MethodAccess {
    #[must_use] 
    pub const fn from_flags(flags: u16) -> Self {
        match flags & 0x7 {
            1 => Self::Private, 2 => Self::FamANDAssem, 3 => Self::Assem,
            4 => Self::Family, 5 => Self::FamORAssem, 6 => Self::Public, _ => Self::CompilerControlled,
        }
    }
}

// ---------------------------------------------------------------------------
// Type reference (resolved vs. external)
// ---------------------------------------------------------------------------

/// A fully-qualified type reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeRef {
    pub namespace: String,
    pub name: String,
    /// None = defined in this assembly; Some = assembly name
    pub assembly: Option<String>,
}

impl TypeRef {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self { namespace: namespace.into(), name: name.into(), assembly: None }
    }
    pub fn external(namespace: impl Into<String>, name: impl Into<String>, assembly: impl Into<String>) -> Self {
        Self { namespace: namespace.into(), name: name.into(), assembly: Some(assembly.into()) }
    }
    #[must_use] 
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() { self.name.clone() }
        else { format!("{}.{}", self.namespace, self.name) }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_name())?;
        if let Some(asm) = &self.assembly { write!(f, " [{asm}]")?; }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Field descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDescriptor {
    pub row: u32,
    pub name: String,
    pub flags: u16,
    pub signature_blob: Vec<u8>,
    /// Decoded field type (if resolved).
    pub type_name: Option<String>,
    pub offset: Option<u32>,
    pub is_static: bool,
    pub is_init_only: bool,
    pub is_literal: bool,
}

impl FieldDescriptor {
    #[must_use] 
    pub const fn from_raw(row: u32, name: String, flags: u16, sig: Vec<u8>) -> Self {
        Self {
            row, name, flags, signature_blob: sig,
            type_name: None, offset: None,
            is_static: (flags & 0x10) != 0,
            is_init_only: (flags & 0x20) != 0,
            is_literal: (flags & 0x40) != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Method descriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDescriptor {
    pub row: u32,
    pub name: String,
    pub flags: u16,
    pub impl_flags: u16,
    pub signature_blob: Vec<u8>,
    pub rva: u32,
    pub param_start: u32,
    pub param_count: u16,
}

impl MethodDescriptor {
    #[must_use] 
    pub const fn access(&self) -> MethodAccess { MethodAccess::from_flags(self.flags) }
    #[must_use] 
    pub const fn is_virtual(&self) -> bool { (self.flags & 0x40) != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool { (self.flags & 0x400) != 0 }
    #[must_use] 
    pub const fn is_static(&self) -> bool { (self.flags & 0x10) != 0 }
    #[must_use] 
    pub const fn is_final(&self) -> bool { (self.flags & 0x20) != 0 }
    #[must_use] 
    pub const fn is_special_name(&self) -> bool { (self.flags & 0x800) != 0 }
    #[must_use] 
    pub fn is_ctor(&self) -> bool { self.name == ".ctor" || self.name == ".cctor" }
    #[must_use] 
    pub const fn has_body(&self) -> bool { self.rva != 0 && (self.impl_flags & 3) == 0 }
}

// ---------------------------------------------------------------------------
// Generic parameter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericParam {
    pub number: u16,
    pub flags: u16,
    pub owner_token: u32,
    pub name: String,
}

impl GenericParam {
    #[must_use] 
    pub const fn variance(&self) -> u8 { (self.flags & 3) as u8 }
    #[must_use] 
    pub const fn is_covariant(&self) -> bool { self.variance() == 1 }
    #[must_use] 
    pub const fn is_contravariant(&self) -> bool { self.variance() == 2 }
    #[must_use] 
    pub const fn has_default_ctor_constraint(&self) -> bool { (self.flags & 0x10) != 0 }
    #[must_use] 
    pub const fn has_ref_type_constraint(&self) -> bool { (self.flags & 4) != 0 }
    #[must_use] 
    pub const fn has_value_type_constraint(&self) -> bool { (self.flags & 8) != 0 }
}

// ---------------------------------------------------------------------------
// Type definition node
// ---------------------------------------------------------------------------

/// Full description of a `TypeDef` in the assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    /// `TypeDef` RID (1-based row index).
    pub rid: u32,
    pub namespace: String,
    pub name: String,
    pub flags: u32,
    pub extends: Option<TypeRef>,
    pub fields: Vec<FieldDescriptor>,
    pub methods: Vec<MethodDescriptor>,
    pub interfaces: Vec<TypeRef>,
    pub generic_params: Vec<GenericParam>,
    pub nested_types: Vec<u32>,
    /// Enclosing type RID (if nested).
    pub enclosing_rid: Option<u32>,
    pub semantics: TypeSemantics,
    pub layout: TypeLayout,
    pub visibility: TypeVisibility,
    /// Packed size (if explicit layout).
    pub class_size: Option<u32>,
    pub packing_size: Option<u16>,
}

impl TypeDef {
    #[must_use] 
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() { self.name.clone() }
        else { format!("{}.{}", self.namespace, self.name) }
    }
    #[must_use] 
    pub const fn is_interface(&self) -> bool { (self.flags & 0x20) != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool { (self.flags & 0x80) != 0 }
    #[must_use] 
    pub const fn is_sealed(&self) -> bool { (self.flags & 0x100) != 0 }
    #[must_use] 
    pub const fn is_value_type(&self) -> bool { matches!(self.semantics, TypeSemantics::ValueType | TypeSemantics::Enum) }
    #[must_use] 
    pub const fn method_count(&self) -> usize { self.methods.len() }
    #[must_use] 
    pub const fn field_count(&self) -> usize { self.fields.len() }
    pub fn virtual_methods(&self) -> impl Iterator<Item = &MethodDescriptor> {
        self.methods.iter().filter(|m| m.is_virtual())
    }
    pub fn static_methods(&self) -> impl Iterator<Item = &MethodDescriptor> {
        self.methods.iter().filter(|m| m.is_static())
    }
    pub fn instance_fields(&self) -> impl Iterator<Item = &FieldDescriptor> {
        self.fields.iter().filter(|f| !f.is_static)
    }
    #[must_use] 
    pub fn find_method(&self, name: &str) -> Option<&MethodDescriptor> {
        self.methods.iter().find(|m| m.name == name)
    }
    #[must_use] 
    pub fn find_field(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields.iter().find(|f| f.name == name)
    }
}

// ---------------------------------------------------------------------------
// Type system builder
// ---------------------------------------------------------------------------

/// The fully-constructed type model for an assembly.
#[derive(Debug, Default)]
pub struct TypeSystem {
    /// RID â†’ `TypeDef`
    types_by_rid: BTreeMap<u32, TypeDef>,
    /// Full name â†’ RID
    name_index: HashMap<String, u32>,
    /// Cached inheritance graph: `child_rid` â†’ `parent_rid`
    inheritance: HashMap<u32, u32>,
}

impl TypeSystem {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    pub fn insert(&mut self, typedef: TypeDef) {
        let rid = typedef.rid;
        self.name_index.insert(typedef.full_name(), rid);
        self.types_by_rid.insert(rid, typedef);
    }

    #[must_use] 
    pub fn get_by_rid(&self, rid: u32) -> Option<&TypeDef> {
        self.types_by_rid.get(&rid)
    }

    #[must_use] 
    pub fn get_by_name(&self, full_name: &str) -> Option<&TypeDef> {
        self.name_index.get(full_name).and_then(|rid| self.types_by_rid.get(rid))
    }

    #[must_use] 
    pub fn type_count(&self) -> usize { self.types_by_rid.len() }

    pub fn all_types(&self) -> impl Iterator<Item = &TypeDef> {
        self.types_by_rid.values()
    }

    pub fn interfaces(&self) -> impl Iterator<Item = &TypeDef> {
        self.types_by_rid.values().filter(|t| t.is_interface())
    }

    pub fn build_inheritance_cache(&mut self) {
        for (rid, td) in &self.types_by_rid {
            if let Some(ext) = &td.extends
                && let Some(parent_rid) = self.name_index.get(&ext.full_name()) {
                    self.inheritance.insert(*rid, *parent_rid);
                }
        }
    }

    /// Get the chain of parent types (base classes), from immediate parent upward.
    #[must_use] 
    pub fn inheritance_chain(&self, rid: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut current = rid;
        let mut visited: HashSet<u32> = HashSet::new();
        while let Some(&parent) = self.inheritance.get(&current) {
            if visited.contains(&parent) { break; }
            visited.insert(parent);
            chain.push(parent);
            current = parent;
        }
        chain
    }

    /// C3 linearization (simplified) â€” topological sort for MRO.
    #[must_use] 
    pub fn mro(&self, rid: u32) -> Vec<u32> {
        let mut order = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        queue.push_back(rid);
        while let Some(id) = queue.pop_front() {
            if visited.contains(&id) { continue; }
            visited.insert(id);
            order.push(id);
            if let Some(&parent) = self.inheritance.get(&id) {
                queue.push_back(parent);
            }
            if let Some(td) = self.types_by_rid.get(&id) {
                for iface in &td.interfaces {
                    if let Some(&irid) = self.name_index.get(&iface.full_name()) {
                        queue.push_back(irid);
                    }
                }
            }
        }
        order
    }

    /// Find all types that directly implement an interface (by full name).
    #[must_use] 
    pub fn implementors_of(&self, iface_name: &str) -> Vec<u32> {
        self.types_by_rid.values()
            .filter(|td| td.interfaces.iter().any(|i| i.full_name() == iface_name))
            .map(|td| td.rid)
            .collect()
    }

    /// Find all types that directly extend a given type (by full name).
    #[must_use] 
    pub fn subclasses_of(&self, base_name: &str) -> Vec<u32> {
        self.types_by_rid.values()
            .filter(|td| td.extends.as_ref().is_some_and(|e| e.full_name() == base_name))
            .map(|td| td.rid)
            .collect()
    }

    /// Get all nested types of a given type.
    #[must_use] 
    pub fn nested_types_of(&self, rid: u32) -> Vec<&TypeDef> {
        self.types_by_rid.get(&rid)
            .map(|td| td.nested_types.iter().filter_map(|&nrid| self.types_by_rid.get(&nrid)).collect())
            .unwrap_or_default()
    }

    /// Compute a virtual dispatch table for a type (all virtual methods,
    /// including inherited ones not overridden).
    #[must_use] 
    pub fn vtable_for(&self, rid: u32) -> Vec<(String, u32)> {
        let mut vtable: HashMap<String, (String, u32)> = HashMap::new();
        // Walk MRO in reverse (base first)
        let mut mro = self.mro(rid);
        mro.reverse();
        for type_rid in &mro {
            if let Some(td) = self.types_by_rid.get(type_rid) {
                for m in td.virtual_methods() {
                    let key = format!("{}()", m.name);
                    vtable.insert(key, (m.name.clone(), *type_rid));
                }
            }
        }
        vtable.into_values().collect()
    }

    /// Build a simple field layout for value types with sequential layout.
    #[must_use] 
    pub fn compute_field_layout(&self, rid: u32) -> Vec<(String, u32, String)> {
        let Some(td) = self.types_by_rid.get(&rid) else { return vec![] };
        let mut offset = 0u32;
        let mut layout = Vec::new();
        for f in td.instance_fields() {
            let size = estimate_field_size(f);
            layout.push((f.name.clone(), offset, f.type_name.clone().unwrap_or_default()));
            offset += size;
        }
        layout
    }
}

fn estimate_field_size(f: &FieldDescriptor) -> u32 {
    let tn = f.type_name.as_deref().unwrap_or("");
    match tn {
        "System.Boolean" | "System.Byte" | "System.SByte" => 1,
        "System.Char" | "System.Int16" | "System.UInt16" => 2,
        "System.Int32" | "System.UInt32" | "System.Single" => 4,
        "System.Int64" | "System.UInt64" | "System.Double" | "System.DateTime" | "System.IntPtr" | "System.UIntPtr" => 8,
        "System.Decimal" => 16,
        _ if tn.contains("[]") || tn.contains('*') => 8,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Assembly reference graph
// ---------------------------------------------------------------------------

/// An external assembly reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyRef {
    pub row: u32,
    pub name: String,
    pub version: (u16, u16, u16, u16),
    pub public_key_token: Vec<u8>,
    pub culture: String,
}

impl AssemblyRef {
    #[must_use] 
    pub fn version_string(&self) -> String {
        format!("{}.{}.{}.{}", self.version.0, self.version.1, self.version.2, self.version.3)
    }
    #[must_use] 
    pub fn token_hex(&self) -> String {
        self.public_key_token.iter().map(|b| format!("{b:02X}")).collect()
    }
}

/// The full assembly dependency graph.
#[derive(Debug, Default, Clone)]
pub struct AssemblyDepGraph {
    pub refs: Vec<AssemblyRef>,
    pub forward_edges: HashMap<String, Vec<String>>,
}

impl AssemblyDepGraph {
    pub fn add_ref(&mut self, from: &str, aref: AssemblyRef) {
        self.forward_edges.entry(from.to_owned()).or_default().push(aref.name.clone());
        self.refs.push(aref);
    }

    #[must_use] 
    pub fn transitive_deps(&self, root: &str) -> Vec<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(root.to_owned());
        let mut result = Vec::new();
        while let Some(name) = queue.pop_front() {
            if visited.contains(&name) { continue; }
            visited.insert(name.clone());
            result.push(name.clone());
            if let Some(deps) = self.forward_edges.get(&name) {
                for d in deps { queue.push_back(d.clone()); }
            }
        }
        result
    }

    #[must_use] 
    pub fn has_ref(&self, name: &str) -> bool {
        self.refs.iter().any(|r| r.name == name)
    }

    #[must_use] 
    pub fn find_ref(&self, name: &str) -> Option<&AssemblyRef> {
        self.refs.iter().find(|r| r.name == name)
    }
}

// ---------------------------------------------------------------------------
// Simple type sig decoder (element types from ECMA-335 Â§II.23.1.16)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ElementType {
    End = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0A,
    U8 = 0x0B,
    R4 = 0x0C,
    R8 = 0x0D,
    String = 0x0E,
    Ptr = 0x0F,
    ByRef = 0x10,
    ValueType = 0x11,
    Class = 0x12,
    Var = 0x13,
    Array = 0x14,
    GenericInst = 0x15,
    TypedByRef = 0x16,
    I = 0x18,
    U = 0x19,
    FnPtr = 0x1B,
    Object = 0x1C,
    SzArray = 0x1D,
    MVar = 0x1E,
    CModReqd = 0x1F,
    CModOpt = 0x20,
    Internal = 0x21,
    Modifier = 0x40,
    Sentinel = 0x41,
    Pinned = 0x45,
    Unknown(u8),
}

impl ElementType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::End, 0x01 => Self::Void, 0x02 => Self::Boolean,
            0x03 => Self::Char, 0x04 => Self::I1, 0x05 => Self::U1,
            0x06 => Self::I2, 0x07 => Self::U2, 0x08 => Self::I4,
            0x09 => Self::U4, 0x0A => Self::I8, 0x0B => Self::U8,
            0x0C => Self::R4, 0x0D => Self::R8, 0x0E => Self::String,
            0x0F => Self::Ptr, 0x10 => Self::ByRef, 0x11 => Self::ValueType,
            0x12 => Self::Class, 0x13 => Self::Var, 0x14 => Self::Array,
            0x15 => Self::GenericInst, 0x16 => Self::TypedByRef,
            0x18 => Self::I, 0x19 => Self::U, 0x1B => Self::FnPtr,
            0x1C => Self::Object, 0x1D => Self::SzArray, 0x1E => Self::MVar,
            0x1F => Self::CModReqd, 0x20 => Self::CModOpt, 0x21 => Self::Internal,
            0x40 => Self::Modifier, 0x41 => Self::Sentinel, 0x45 => Self::Pinned,
            o => Self::Unknown(o),
        }
    }

    #[must_use] 
    pub const fn to_csharp_name(&self) -> &'static str {
        match self {
            Self::Void => "void", Self::Boolean => "bool", Self::Char => "char",
            Self::I1 => "sbyte", Self::U1 => "byte", Self::I2 => "short",
            Self::U2 => "ushort", Self::I4 => "int", Self::U4 => "uint",
            Self::I8 => "long", Self::U8 => "ulong", Self::R4 => "float",
            Self::R8 => "double", Self::String => "string", Self::Object => "object",
            Self::I => "nint", Self::U => "nuint",
            _ => "?",
        }
    }

    #[must_use] 
    pub const fn is_primitive(&self) -> bool {
        matches!(self, Self::Boolean | Self::Char | Self::I1 | Self::U1 |
            Self::I2 | Self::U2 | Self::I4 | Self::U4 |
            Self::I8 | Self::U8 | Self::R4 | Self::R8 | Self::I | Self::U)
    }
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_csharp_name())
    }
}

// ---------------------------------------------------------------------------
// TypeSig (simplified) decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeSigNode {
    Primitive(ElementType),
    ByRef(Box<Self>),
    Pointer(Box<Self>),
    SzArray(Box<Self>),
    ClassOrValue { coded_index: u32, is_value: bool },
    GenericInst { base: Box<Self>, args: Vec<Self> },
    Var(u32),
    MVar(u32),
    FnPtr,
    Array { elem: Box<Self>, rank: u32 },
    Object,
    String,
    Void,
    TypedByRef,
    Unknown(u8),
}

impl TypeSigNode {
    pub fn to_display(&self, resolver: &dyn Fn(u32) -> String) -> String {
        match self {
            Self::Primitive(e) => e.to_csharp_name().to_owned(),
            Self::Void => "void".to_owned(),
            Self::String => "string".to_owned(),
            Self::Object => "object".to_owned(),
            Self::TypedByRef => "TypedReference".to_owned(),
            Self::ByRef(inner) => format!("ref {}", inner.to_display(resolver)),
            Self::Pointer(inner) => format!("{}*", inner.to_display(resolver)),
            Self::SzArray(elem) => format!("{}[]", elem.to_display(resolver)),
            Self::Array { elem, rank } => {
                let dims = ",".repeat((*rank as usize).saturating_sub(1));
                format!("{}[{dims}]", elem.to_display(resolver))
            }
            Self::ClassOrValue { coded_index, .. } => resolver(*coded_index),
            Self::GenericInst { base, args } => {
                let base_str = base.to_display(resolver);
                let args_str: Vec<_> = args.iter().map(|a| a.to_display(resolver)).collect();
                format!("{}<{}>", base_str, args_str.join(", "))
            }
            Self::Var(n) => format!("T{n}"),
            Self::MVar(n) => format!("M{n}"),
            Self::FnPtr => "delegate*".to_owned(),
            Self::Unknown(b) => format!("?0x{b:02X}"),
        }
    }
}

/// Read a compressed unsigned int from a blob.
fn read_compressed_uint(data: &[u8]) -> Option<(u32, usize)> {
    let b0 = u32::from(*data.first()?);
    if (b0 & 0x80) == 0 { return Some((b0, 1)); }
    if data.len() < 2 { return None; }
    if (b0 & 0xC0) == 0x80 {
        let b1 = u32::from(data[1]);
        return Some(((b0 & 0x3F) << 8 | b1, 2));
    }
    if data.len() < 4 { return None; }
    let b1 = u32::from(data[1]); let b2 = u32::from(data[2]); let b3 = u32::from(data[3]);
    Some(((b0 & 0x1F) << 24 | b1 << 16 | b2 << 8 | b3, 4))
}

#[must_use] 
pub fn decode_type_sig(blob: &[u8]) -> Option<TypeSigNode> {
    decode_type_sig_at(blob, &mut 0)
}

/// Maximum recursion depth for nested type signatures.
const MAX_SIG_DEPTH: u32 = 64;

fn decode_type_sig_at(blob: &[u8], pos: &mut usize) -> Option<TypeSigNode> {
    decode_type_sig_at_depth(blob, pos, 0)
}

fn decode_type_sig_at_depth(blob: &[u8], pos: &mut usize, depth: u32) -> Option<TypeSigNode> {
    if depth >= MAX_SIG_DEPTH { return None; }
    if *pos >= blob.len() { return None; }
    let et = ElementType::from_u8(blob[*pos]);
    *pos += 1;
    match et {
        ElementType::Void => Some(TypeSigNode::Void),
        ElementType::String => Some(TypeSigNode::String),
        ElementType::Object => Some(TypeSigNode::Object),
        ElementType::TypedByRef => Some(TypeSigNode::TypedByRef),
        ElementType::FnPtr => Some(TypeSigNode::FnPtr),
        ElementType::Boolean | ElementType::Char | ElementType::I1 | ElementType::U1 |
        ElementType::I2 | ElementType::U2 | ElementType::I4 | ElementType::U4 |
        ElementType::I8 | ElementType::U8 | ElementType::R4 | ElementType::R8 |
        ElementType::I | ElementType::U => Some(TypeSigNode::Primitive(et)),
        ElementType::ByRef => {
            let inner = decode_type_sig_at_depth(blob, pos, depth + 1)?;
            Some(TypeSigNode::ByRef(Box::new(inner)))
        }
        ElementType::Ptr => {
            let inner = decode_type_sig_at_depth(blob, pos, depth + 1)?;
            Some(TypeSigNode::Pointer(Box::new(inner)))
        }
        ElementType::SzArray => {
            let elem = decode_type_sig_at_depth(blob, pos, depth + 1)?;
            Some(TypeSigNode::SzArray(Box::new(elem)))
        }
        ElementType::Array => {
            let elem = decode_type_sig_at_depth(blob, pos, depth + 1)?;
            let (rank, rn) = read_compressed_uint(&blob[*pos..])?;
            *pos += rn;
            // skip bounds
            let (num_sizes, sn) = read_compressed_uint(&blob[*pos..])?;
            *pos += sn;
            for _ in 0..num_sizes {
                let (_, n) = read_compressed_uint(&blob[*pos..])?; *pos += n;
            }
            let (num_lbounds, ln) = read_compressed_uint(&blob[*pos..])?;
            *pos += ln;
            for _ in 0..num_lbounds {
                let (_, n) = read_compressed_uint(&blob[*pos..])?; *pos += n;
            }
            Some(TypeSigNode::Array { elem: Box::new(elem), rank })
        }
        ElementType::Class | ElementType::ValueType => {
            let (coded, n) = read_compressed_uint(&blob[*pos..])?;
            *pos += n;
            Some(TypeSigNode::ClassOrValue { coded_index: coded, is_value: et == ElementType::ValueType })
        }
        ElementType::GenericInst => {
            let base = decode_type_sig_at_depth(blob, pos, depth + 1)?;
            let (argc, n) = read_compressed_uint(&blob[*pos..])?;
            *pos += n;
            // Cap pre-allocation: each generic argument consumes >= 1 byte.
            let mut args = Vec::with_capacity((argc as usize).min(blob.len().saturating_sub(*pos)));
            for _ in 0..argc {
                args.push(decode_type_sig_at_depth(blob, pos, depth + 1)?);
            }
            Some(TypeSigNode::GenericInst { base: Box::new(base), args })
        }
        ElementType::Var => {
            let (n, sz) = read_compressed_uint(&blob[*pos..])?;
            *pos += sz;
            Some(TypeSigNode::Var(n))
        }
        ElementType::MVar => {
            let (n, sz) = read_compressed_uint(&blob[*pos..])?;
            *pos += sz;
            Some(TypeSigNode::MVar(n))
        }
        ElementType::CModReqd | ElementType::CModOpt => {
            // skip the modifier token, then decode the type
            let (_, n) = read_compressed_uint(&blob[*pos..])?;
            *pos += n;
            decode_type_sig_at_depth(blob, pos, depth + 1)
        }
        ElementType::Pinned => decode_type_sig_at_depth(blob, pos, depth + 1),
        ElementType::Unknown(b) => Some(TypeSigNode::Unknown(b)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Method signature decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSigDecoded {
    pub calling_convention: u8,
    pub is_instance: bool,
    pub is_explicit_this: bool,
    pub has_varargs: bool,
    pub generic_param_count: Option<u32>,
    pub return_type: TypeSigNode,
    pub params: Vec<TypeSigNode>,
}

#[must_use] 
pub fn decode_method_sig(blob: &[u8]) -> Option<MethodSigDecoded> {
    if blob.is_empty() { return None; }
    let mut pos = 0usize;
    let flags = blob[pos]; pos += 1;
    let is_instance = (flags & 0x20) != 0;
    let is_explicit_this = (flags & 0x40) != 0;
    let has_varargs = (flags & 0x5) == 0x5;
    let cc = flags & 0x0F;
    let generic_param_count = if (flags & 0x10) != 0 {
        let (n, sz) = read_compressed_uint(&blob[pos..])?;
        pos += sz;
        Some(n)
    } else { None };
    let (param_count, pn) = read_compressed_uint(&blob[pos..])?;
    pos += pn;
    let return_type = decode_type_sig_at(blob, &mut pos)?;
    // Cap pre-allocation: each parameter consumes >= 1 byte of the blob.
    let mut params = Vec::with_capacity((param_count as usize).min(blob.len().saturating_sub(pos)));
    for _ in 0..param_count {
        if let Some(p) = decode_type_sig_at(blob, &mut pos) {
            params.push(p);
        } else { break; }
    }
    Some(MethodSigDecoded { calling_convention: cc, is_instance, is_explicit_this, has_varargs, generic_param_count, return_type, params })
}

/// Decode a type-signature blob, returning a structured loader error when the
/// blob cannot be parsed instead of an opaque `None`.
///
/// # Errors
/// Returns [`DotnetLoaderError::ParseError`] when the blob is malformed.
pub fn decode_type_sig_checked(blob: &[u8]) -> Result<TypeSigNode, DotnetLoaderError> {
    decode_type_sig(blob)
        .ok_or_else(|| DotnetLoaderError::ParseError("invalid type signature blob".into()))
}

/// Decode a method-signature blob, returning a structured loader error on
/// failure.
///
/// # Errors
/// Returns [`DotnetLoaderError::ParseError`] when the blob is malformed.
pub fn decode_method_sig_checked(blob: &[u8]) -> Result<MethodSigDecoded, DotnetLoaderError> {
    decode_method_sig(blob)
        .ok_or_else(|| DotnetLoaderError::ParseError("invalid method signature blob".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_typedef(rid: u32, ns: &str, name: &str) -> TypeDef {
        TypeDef {
            rid, namespace: ns.to_owned(), name: name.to_owned(), flags: 1,
            extends: None, fields: vec![], methods: vec![], interfaces: vec![],
            generic_params: vec![], nested_types: vec![], enclosing_rid: None,
            semantics: TypeSemantics::Class, layout: TypeLayout::Auto,
            visibility: TypeVisibility::Public, class_size: None, packing_size: None,
        }
    }

    #[test]
    fn test_type_system_lookup() {
        let mut ts = TypeSystem::new();
        ts.insert(make_typedef(1, "Foo", "Bar"));
        ts.insert(make_typedef(2, "Foo", "Baz"));
        assert!(ts.get_by_rid(1).is_some());
        assert_eq!(ts.get_by_name("Foo.Bar").unwrap().rid, 1);
        assert_eq!(ts.type_count(), 2);
    }

    #[test]
    fn test_inheritance_chain() {
        let mut ts = TypeSystem::new();
        let mut base = make_typedef(1, "System", "Object");
        base.flags = 1;
        ts.insert(base);
        let mut derived = make_typedef(2, "Foo", "Derived");
        derived.extends = Some(TypeRef::new("System", "Object"));
        ts.insert(derived);
        ts.build_inheritance_cache();
        let chain = ts.inheritance_chain(2);
        assert_eq!(chain, vec![1]);
    }

    #[test]
    fn test_subclasses() {
        let mut ts = TypeSystem::new();
        ts.insert(make_typedef(1, "System", "Exception"));
        let mut child = make_typedef(2, "Foo", "MyException");
        child.extends = Some(TypeRef::new("System", "Exception"));
        ts.insert(child);
        let subs = ts.subclasses_of("System.Exception");
        assert_eq!(subs, vec![2]);
    }

    #[test]
    fn test_decode_type_sig_primitive() {
        let blob = [0x08u8]; // I4
        let sig = decode_type_sig(&blob).unwrap();
        if let TypeSigNode::Primitive(e) = sig { assert_eq!(e, ElementType::I4); }
        else { panic!(); }
    }

    #[test]
    fn test_decode_type_sig_szarray_int() {
        let blob = [0x1Du8, 0x08u8]; // SzArray I4 = int[]
        let sig = decode_type_sig(&blob).unwrap();
        if let TypeSigNode::SzArray(inner) = sig {
            if let TypeSigNode::Primitive(e) = *inner { assert_eq!(e, ElementType::I4); }
            else { panic!(); }
        } else { panic!(); }
    }

    #[test]
    fn test_decode_method_sig() {
        // instance, 1 param, return void, param int
        // 0x20 (HASTHIS) | 0x00 = 0x20, param_count=1, void=0x01, int=0x08
        let blob = [0x20u8, 0x01, 0x01, 0x08];
        let sig = decode_method_sig(&blob).unwrap();
        assert!(sig.is_instance);
        assert_eq!(sig.params.len(), 1);
        assert!(matches!(sig.return_type, TypeSigNode::Void));
        if let TypeSigNode::Primitive(e) = &sig.params[0] { assert_eq!(*e, ElementType::I4); }
        else { panic!(); }
    }

    #[test]
    fn test_element_type_display() {
        assert_eq!(ElementType::I4.to_csharp_name(), "int");
        assert_eq!(ElementType::String.to_csharp_name(), "string");
        assert_eq!(ElementType::R8.to_csharp_name(), "double");
    }

    #[test]
    fn test_assembly_dep_graph() {
        let mut g = AssemblyDepGraph::default();
        g.add_ref("MyApp", AssemblyRef { row: 1, name: "System.Runtime".into(), version: (7,0,0,0), public_key_token: vec![], culture: String::new() });
        g.add_ref("MyApp", AssemblyRef { row: 2, name: "Newtonsoft.Json".into(), version: (13,0,0,0), public_key_token: vec![], culture: String::new() });
        assert!(g.has_ref("System.Runtime"));
        assert_eq!(g.refs.len(), 2);
    }

    #[test]
    fn test_field_layout() {
        let mut ts = TypeSystem::new();
        let mut td = make_typedef(1, "Foo", "Point");
        td.layout = TypeLayout::Sequential;
        td.fields.push(FieldDescriptor {
            row: 1, name: "X".into(), flags: 0, signature_blob: vec![],
            type_name: Some("System.Int32".into()), offset: None,
            is_static: false, is_init_only: false, is_literal: false,
        });
        td.fields.push(FieldDescriptor {
            row: 2, name: "Y".into(), flags: 0, signature_blob: vec![],
            type_name: Some("System.Int32".into()), offset: None,
            is_static: false, is_init_only: false, is_literal: false,
        });
        ts.insert(td);
        let layout = ts.compute_field_layout(1);
        assert_eq!(layout.len(), 2);
        assert_eq!(layout[0].1, 0);
        assert_eq!(layout[1].1, 4);
    }
}
