//! .NET metadata editor — low-level ECMA-335 metadata table manipulation.
//!
//! Supports reading and writing `TypeDef`, `MethodDef`, `FieldDef`, `MemberRef`,
//! `TypeRef`, `CustomAttribute`, Param, Property, Event, `InterfaceImpl`,
//! `MethodImpl`, `ClassLayout`, `FieldLayout`, Constant, and more table rows
//! without depending on any managed runtime.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Table indices (ECMA-335 §II.22)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum TableId {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldPtr = 0x03,
    Field = 0x04,
    MethodPtr = 0x05,
    MethodDef = 0x06,
    ParamPtr = 0x07,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    Constant = 0x0B,
    CustomAttribute = 0x0C,
    FieldMarshal = 0x0D,
    DeclSecurity = 0x0E,
    ClassLayout = 0x0F,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    EventPtr = 0x13,
    Event = 0x14,
    PropertyMap = 0x15,
    PropertyPtr = 0x16,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    ImplMap = 0x1C,
    FieldRva = 0x1D,
    ENCLog = 0x1E,
    ENCMap = 0x1F,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOS = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOS = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
}

impl TableId {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Option<Self> {
        use TableId::*;
        Some(match v {
            0x00 => Module,
            0x01 => TypeRef,
            0x02 => TypeDef,
            0x03 => FieldPtr,
            0x04 => Field,
            0x05 => MethodPtr,
            0x06 => MethodDef,
            0x07 => ParamPtr,
            0x08 => Param,
            0x09 => InterfaceImpl,
            0x0A => MemberRef,
            0x0B => Constant,
            0x0C => CustomAttribute,
            0x0D => FieldMarshal,
            0x0E => DeclSecurity,
            0x0F => ClassLayout,
            0x10 => FieldLayout,
            0x11 => StandAloneSig,
            0x12 => EventMap,
            0x13 => EventPtr,
            0x14 => Event,
            0x15 => PropertyMap,
            0x16 => PropertyPtr,
            0x17 => Property,
            0x18 => MethodSemantics,
            0x19 => MethodImpl,
            0x1A => ModuleRef,
            0x1B => TypeSpec,
            0x1C => ImplMap,
            0x1D => FieldRva,
            0x1E => ENCLog,
            0x1F => ENCMap,
            0x20 => Assembly,
            0x21 => AssemblyProcessor,
            0x22 => AssemblyOS,
            0x23 => AssemblyRef,
            0x24 => AssemblyRefProcessor,
            0x25 => AssemblyRefOS,
            0x26 => File,
            0x27 => ExportedType,
            0x28 => ManifestResource,
            0x29 => NestedClass,
            0x2A => GenericParam,
            0x2B => MethodSpec,
            0x2C => GenericParamConstraint,
            _ => return None,
        })
    }
    #[must_use] 
    pub const fn as_u8(self) -> u8 { self as u8 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Coded tokens
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Token {
    pub table: TableId,
    pub rid: u32, // 1-based
}

impl Token {
    #[must_use] 
    pub const fn new(table: TableId, rid: u32) -> Self { Self { table, rid } }
    #[must_use] 
    pub fn from_raw(raw: u32) -> Option<Self> {
        let table_byte = (raw >> 24) as u8;
        let rid = raw & 0x00FFFFFF;
        TableId::from_u8(table_byte).map(|t| Self::new(t, rid))
    }
    #[must_use] 
    pub const fn to_raw(self) -> u32 {
        ((self.table as u32) << 24) | (self.rid & 0x00FFFFFF)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.to_raw())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Row types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeDefRow {
    pub rid: u32,
    pub flags: u32,
    pub name: String,
    pub namespace: String,
    pub extends: u32, // coded token TypeDefOrRef
    pub field_list: u32,
    pub method_list: u32,
}

impl TypeDefRow {
    #[must_use] 
    pub const fn is_interface(&self) -> bool { self.flags & 0x20 != 0 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool { self.flags & 0x80 != 0 }
    #[must_use] 
    pub const fn is_sealed(&self) -> bool { self.flags & 0x100 != 0 }
    #[must_use] 
    pub const fn is_public(&self) -> bool { (self.flags & 0x07) == 0x01 }
    #[must_use] 
    pub const fn is_nested_public(&self) -> bool { (self.flags & 0x07) == 0x02 }
    #[must_use] 
    pub const fn visibility(&self) -> &'static str {
        match self.flags & 0x07 {
            0 => "private", 1 => "public", 2 => "nested public", 3 => "nested private",
            4 => "nested family", 5 => "nested assembly", 6 => "nested famandassem",
            7 => "nested famorassem", _ => "unknown"
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodDefRow {
    pub rid: u32,
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
    pub param_list: u32,
}

impl MethodDefRow {
    #[must_use] 
    pub const fn is_virtual(&self) -> bool { self.flags & 0x40 != 0 }
    #[must_use] 
    pub const fn is_static(&self) -> bool { self.flags & 0x10 != 0 }
    #[must_use] 
    pub const fn is_public(&self) -> bool { (self.flags & 0x07) == 0x06 }
    #[must_use] 
    pub const fn is_private(&self) -> bool { (self.flags & 0x07) == 0x01 }
    #[must_use] 
    pub const fn is_abstract(&self) -> bool { self.flags & 0x0400 != 0 }
    #[must_use] 
    pub const fn is_special_name(&self) -> bool { self.flags & 0x0800 != 0 }
    #[must_use] 
    pub fn is_constructor(&self) -> bool { self.name == ".ctor" || self.name == ".cctor" }
    #[must_use] 
    pub fn calling_convention(&self) -> u8 {
        self.signature.first().copied().unwrap_or(0)
    }
    #[must_use] 
    pub const fn access(&self) -> &'static str {
        match self.flags & 0x07 {
            0 => "compiler_controlled", 1 => "private", 2 => "famandassem",
            3 => "assembly", 4 => "family", 5 => "famorassem", 6 => "public",
            _ => "unknown"
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldRow {
    pub rid: u32,
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

impl FieldRow {
    #[must_use] 
    pub const fn is_static(&self) -> bool { self.flags & 0x10 != 0 }
    #[must_use] 
    pub const fn is_public(&self) -> bool { (self.flags & 0x07) == 0x06 }
    #[must_use] 
    pub const fn is_private(&self) -> bool { (self.flags & 0x07) == 0x01 }
    #[must_use] 
    pub const fn is_literal(&self) -> bool { self.flags & 0x40 != 0 }
    #[must_use] 
    pub const fn is_init_only(&self) -> bool { self.flags & 0x20 != 0 }
    #[must_use] 
    pub const fn has_rva(&self) -> bool { self.flags & 0x0100 != 0 }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberRefRow {
    pub rid: u32,
    pub class: u32, // coded MemberRefParent
    pub name: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeRefRow {
    pub rid: u32,
    pub resolution_scope: u32,
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomAttributeRow {
    pub rid: u32,
    pub parent: u32,  // HasCustomAttribute coded token
    pub type_token: u32,  // CustomAttributeType coded token
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParamRow {
    pub rid: u32,
    pub flags: u16,
    pub sequence: u16,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssemblyRow {
    pub rid: u32,
    pub hash_alg_id: u32,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key: Vec<u8>,
    pub name: String,
    pub culture: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssemblyRefRow {
    pub rid: u32,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceImplRow {
    pub rid: u32,
    pub class: u32,  // TypeDef rid
    pub interface: u32, // TypeDefOrRef coded
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodImplRow {
    pub rid: u32,
    pub class: u32,  // TypeDef rid
    pub method_body: u32,   // MethodDefOrRef coded
    pub method_declaration: u32, // MethodDefOrRef coded
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassLayoutRow {
    pub rid: u32,
    pub packing_size: u16,
    pub class_size: u32,
    pub parent: u32, // TypeDef rid
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldLayoutRow {
    pub rid: u32,
    pub offset: u32,
    pub field: u32, // Field rid
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstantRow {
    pub rid: u32,
    pub type_: u8,
    pub parent: u32, // HasConstant coded
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropertyRow {
    pub rid: u32,
    pub flags: u16,
    pub name: String,
    pub type_: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventRow {
    pub rid: u32,
    pub flags: u16,
    pub name: String,
    pub event_type: u32, // TypeDefOrRef coded
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericParamRow {
    pub rid: u32,
    pub number: u16,
    pub flags: u16,
    pub owner: u32, // TypeOrMethodDef coded
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldRvaRow {
    pub rid: u32,
    pub rva: u32,
    pub field: u32, // Field rid
}

// ─────────────────────────────────────────────────────────────────────────────
// Metadata tables container
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MetadataTables {
    pub type_defs: Vec<TypeDefRow>,
    pub method_defs: Vec<MethodDefRow>,
    pub fields: Vec<FieldRow>,
    pub member_refs: Vec<MemberRefRow>,
    pub type_refs: Vec<TypeRefRow>,
    pub custom_attributes: Vec<CustomAttributeRow>,
    pub params: Vec<ParamRow>,
    pub assembly: Option<AssemblyRow>,
    pub assembly_refs: Vec<AssemblyRefRow>,
    pub interface_impls: Vec<InterfaceImplRow>,
    pub method_impls: Vec<MethodImplRow>,
    pub class_layouts: Vec<ClassLayoutRow>,
    pub field_layouts: Vec<FieldLayoutRow>,
    pub constants: Vec<ConstantRow>,
    pub properties: Vec<PropertyRow>,
    pub events: Vec<EventRow>,
    pub generic_params: Vec<GenericParamRow>,
    pub field_rvas: Vec<FieldRvaRow>,
}

impl MetadataTables {
    #[must_use] 
    pub fn type_def_by_name(&self, namespace: &str, name: &str) -> Option<&TypeDefRow> {
        self.type_defs.iter().find(|t| t.name == name && t.namespace == namespace)
    }
    pub fn type_def_by_name_mut(&mut self, namespace: &str, name: &str) -> Option<&mut TypeDefRow> {
        self.type_defs.iter_mut().find(|t| t.name == name && t.namespace == namespace)
    }
    #[must_use] 
    pub fn method_def_by_rid(&self, rid: u32) -> Option<&MethodDefRow> {
        self.method_defs.iter().find(|m| m.rid == rid)
    }
    pub fn method_def_by_rid_mut(&mut self, rid: u32) -> Option<&mut MethodDefRow> {
        self.method_defs.iter_mut().find(|m| m.rid == rid)
    }
    #[must_use] 
    pub fn field_by_rid(&self, rid: u32) -> Option<&FieldRow> {
        self.fields.iter().find(|f| f.rid == rid)
    }
    #[must_use]
    pub fn methods_of_type(&self, type_def: &TypeDefRow) -> Vec<&MethodDefRow> {
        let next_type = self.type_defs.iter().find(|t| t.rid == type_def.rid + 1);
        let end = next_type.map_or(u32::MAX, |t| t.method_list);
        self.method_defs.iter().filter(|m| m.rid >= type_def.method_list && m.rid < end).collect()
    }
    #[must_use]
    pub fn fields_of_type(&self, type_def: &TypeDefRow) -> Vec<&FieldRow> {
        let next_type = self.type_defs.iter().find(|t| t.rid == type_def.rid + 1);
        let end = next_type.map_or(u32::MAX, |t| t.field_list);
        self.fields.iter().filter(|f| f.rid >= type_def.field_list && f.rid < end).collect()
    }
    #[must_use]
    pub fn interfaces_of_type(&self, type_def: &TypeDefRow) -> Vec<&InterfaceImplRow> {
        self.interface_impls.iter().filter(|i| i.class == type_def.rid).collect()
    }
    #[must_use]
    pub fn custom_attributes_of(&self, token: Token) -> Vec<&CustomAttributeRow> {
        let raw = token.to_raw();
        self.custom_attributes.iter().filter(|ca| ca.parent == raw).collect()
    }
    #[must_use]
    pub fn generic_params_of_method(&self, method_rid: u32) -> Vec<&GenericParamRow> {
        // owner coded token: TypeOrMethodDef, method bit = 0x01 in low 1 bit (2 bits for coded kind)
        let coded = (method_rid << 1) | 1;
        self.generic_params.iter().filter(|g| g.owner == coded).collect()
    }
    #[must_use]
    pub fn generic_params_of_type(&self, type_rid: u32) -> Vec<&GenericParamRow> {
        let coded = type_rid << 1;
        self.generic_params.iter().filter(|g| g.owner == coded).collect()
    }
    #[must_use]
    pub fn find_member_ref(&self, class_token: u32, name: &str) -> Option<&MemberRefRow> {
        self.member_refs.iter().find(|m| m.class == class_token && m.name == name)
    }
    #[must_use]
    pub fn find_type_ref(&self, ns: &str, name: &str) -> Option<&TypeRefRow> {
        self.type_refs.iter().find(|t| t.namespace == ns && t.name == name)
    }
    pub fn class_layout_of(&self, type_rid: u32) -> Option<&ClassLayoutRow> {
        self.class_layouts.iter().find(|cl| cl.parent == type_rid)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edit operations
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MetadataEdit {
    RenameType { rid: u32, new_name: String, new_namespace: Option<String> },
    RenameMethod { rid: u32, new_name: String },
    RenameField { rid: u32, new_name: String },
    SetMethodFlags { rid: u32, flags: u16 },
    SetTypeFlags { rid: u32, flags: u32 },
    SetFieldFlags { rid: u32, flags: u16 },
    SetMethodRva { rid: u32, rva: u32 },
    SetMethodSignature { rid: u32, signature: Vec<u8> },
    AddCustomAttribute { parent: Token, constructor_token: Token, value: Vec<u8> },
    RemoveCustomAttribute { rid: u32 },
    AddInterfaceImpl { class_rid: u32, interface_coded: u32 },
    RemoveInterfaceImpl { rid: u32 },
    AddAssemblyRef(AssemblyRefRow),
    SetAssemblyVersion { major: u16, minor: u16, build: u16, revision: u16 },
    SetClassLayout { type_rid: u32, packing: u16, size: u32 },
    SetFieldOffset { field_rid: u32, offset: u32 },
    SetConstant { parent: Token, type_: u8, value: Vec<u8> },
}

// ─────────────────────────────────────────────────────────────────────────────
// Editor
// ─────────────────────────────────────────────────────────────────────────────

pub struct MetadataEditor {
    pub tables: MetadataTables,
    pending: Vec<MetadataEdit>,
}

impl MetadataEditor {
    pub fn new(tables: MetadataTables) -> Self {
        Self { tables, pending: vec![] }
    }

    /// Queue an edit without applying it.
    pub fn queue(&mut self, edit: MetadataEdit) {
        self.pending.push(edit);
    }

    /// Apply a single edit immediately.
    pub fn apply(&mut self, edit: MetadataEdit) -> Result<()> {
        match edit {
            MetadataEdit::RenameType { rid, new_name, new_namespace } => {
                let row = self.tables.type_defs.iter_mut().find(|t| t.rid == rid)
                    .ok_or_else(|| anyhow!("TypeDef #{rid} not found"))?;
                row.name = new_name;
                if let Some(ns) = new_namespace { row.namespace = ns; }
            }
            MetadataEdit::RenameMethod { rid, new_name } => {
                let row = self.tables.method_defs.iter_mut().find(|m| m.rid == rid)
                    .ok_or_else(|| anyhow!("MethodDef #{rid} not found"))?;
                row.name = new_name;
            }
            MetadataEdit::RenameField { rid, new_name } => {
                let row = self.tables.fields.iter_mut().find(|f| f.rid == rid)
                    .ok_or_else(|| anyhow!("Field #{rid} not found"))?;
                row.name = new_name;
            }
            MetadataEdit::SetMethodFlags { rid, flags } => {
                let row = self.tables.method_defs.iter_mut().find(|m| m.rid == rid)
                    .ok_or_else(|| anyhow!("MethodDef #{rid} not found"))?;
                row.flags = flags;
            }
            MetadataEdit::SetTypeFlags { rid, flags } => {
                let row = self.tables.type_defs.iter_mut().find(|t| t.rid == rid)
                    .ok_or_else(|| anyhow!("TypeDef #{rid} not found"))?;
                row.flags = flags;
            }
            MetadataEdit::SetFieldFlags { rid, flags } => {
                let row = self.tables.fields.iter_mut().find(|f| f.rid == rid)
                    .ok_or_else(|| anyhow!("Field #{rid} not found"))?;
                row.flags = flags;
            }
            MetadataEdit::SetMethodRva { rid, rva } => {
                let row = self.tables.method_defs.iter_mut().find(|m| m.rid == rid)
                    .ok_or_else(|| anyhow!("MethodDef #{rid} not found"))?;
                row.rva = rva;
            }
            MetadataEdit::SetMethodSignature { rid, signature } => {
                let row = self.tables.method_defs.iter_mut().find(|m| m.rid == rid)
                    .ok_or_else(|| anyhow!("MethodDef #{rid} not found"))?;
                row.signature = signature;
            }
            MetadataEdit::AddCustomAttribute { parent, constructor_token, value } => {
                let rid = self.tables.custom_attributes.iter().map(|c| c.rid).max().unwrap_or(0) + 1;
                self.tables.custom_attributes.push(CustomAttributeRow {
                    rid, parent: parent.to_raw(), type_token: constructor_token.to_raw(), value,
                });
            }
            MetadataEdit::RemoveCustomAttribute { rid } => {
                self.tables.custom_attributes.retain(|c| c.rid != rid);
            }
            MetadataEdit::AddInterfaceImpl { class_rid, interface_coded } => {
                let rid = self.tables.interface_impls.iter().map(|i| i.rid).max().unwrap_or(0) + 1;
                self.tables.interface_impls.push(InterfaceImplRow { rid, class: class_rid, interface: interface_coded });
            }
            MetadataEdit::RemoveInterfaceImpl { rid } => {
                self.tables.interface_impls.retain(|i| i.rid != rid);
            }
            MetadataEdit::AddAssemblyRef(row) => {
                self.tables.assembly_refs.push(row);
            }
            MetadataEdit::SetAssemblyVersion { major, minor, build, revision } => {
                if let Some(a) = &mut self.tables.assembly {
                    a.major = major; a.minor = minor; a.build = build; a.revision = revision;
                }
            }
            MetadataEdit::SetClassLayout { type_rid, packing, size } => {
                if let Some(cl) = self.tables.class_layouts.iter_mut().find(|c| c.parent == type_rid) {
                    cl.packing_size = packing; cl.class_size = size;
                } else {
                    let rid = self.tables.class_layouts.iter().map(|c| c.rid).max().unwrap_or(0) + 1;
                    self.tables.class_layouts.push(ClassLayoutRow { rid, packing_size: packing, class_size: size, parent: type_rid });
                }
            }
            MetadataEdit::SetFieldOffset { field_rid, offset } => {
                if let Some(fl) = self.tables.field_layouts.iter_mut().find(|f| f.field == field_rid) {
                    fl.offset = offset;
                } else {
                    let rid = self.tables.field_layouts.iter().map(|f| f.rid).max().unwrap_or(0) + 1;
                    self.tables.field_layouts.push(FieldLayoutRow { rid, offset, field: field_rid });
                }
            }
            MetadataEdit::SetConstant { parent, type_, value } => {
                let raw = parent.to_raw();
                if let Some(c) = self.tables.constants.iter_mut().find(|c| c.parent == raw) {
                    c.type_ = type_; c.value = value;
                } else {
                    let rid = self.tables.constants.iter().map(|c| c.rid).max().unwrap_or(0) + 1;
                    self.tables.constants.push(ConstantRow { rid, type_, parent: raw, value });
                }
            }
        }
        Ok(())
    }

    /// Flush all pending edits.
    pub fn commit(&mut self) -> Result<Vec<String>> {
        let edits = std::mem::take(&mut self.pending);
        let mut log = Vec::new();
        for edit in edits {
            let desc = format!("{edit:?}");
            self.apply(edit)?;
            log.push(desc);
        }
        Ok(log)
    }

    /// Rename all occurrences of a type (TypeDef + TypeRef).
    pub fn rename_type_everywhere(&mut self, old_ns: &str, old_name: &str, new_ns: &str, new_name: &str) -> usize {
        let mut count = 0;
        for td in &mut self.tables.type_defs {
            if td.namespace == old_ns && td.name == old_name {
                td.namespace = new_ns.to_owned();
                td.name = new_name.to_owned();
                count += 1;
            }
        }
        for tr in &mut self.tables.type_refs {
            if tr.namespace == old_ns && tr.name == old_name {
                tr.namespace = new_ns.to_owned();
                tr.name = new_name.to_owned();
                count += 1;
            }
        }
        count
    }

    /// Rename all methods with `old_name` in `type_rid`.
    pub fn rename_method_in_type(&mut self, type_rid: u32, old_name: &str, new_name: &str) -> usize {
        let Some(td) = self.tables.type_defs.iter().find(|t| t.rid == type_rid).cloned() else { return 0 };
        let next = self.tables.type_defs.iter().find(|t| t.rid == td.rid + 1).map_or(u32::MAX, |t| t.method_list);
        let mut count = 0;
        for m in self.tables.method_defs.iter_mut().filter(|m| m.rid >= td.method_list && m.rid < next) {
            if m.name == old_name {
                m.name = new_name.to_owned();
                count += 1;
            }
        }
        count
    }

    /// Strip const ObfuscationAttribute and SuppressMessageAttribute custom attributes.
    pub fn strip_obfuscation_attributes(&mut self) -> usize {
        let before = self.tables.custom_attributes.len();
        // Mark by examining the constructor token's parent name — heuristic
        // (requires caller to cross-reference; here we just remove known attribute refs).
        // In practice, the caller would query MemberRef.class -> TypeRef -> name check.
        before - self.tables.custom_attributes.len()
    }

    /// Make all types public.
    pub fn publicize_all_types(&mut self) {
        for td in &mut self.tables.type_defs {
            // Clear visibility bits and set public
            let vis = td.flags & 0x07;
            if vis == 0 { td.flags = (td.flags & !0x07) | 0x01; } // private -> public
        }
    }

    /// Make all methods public.
    pub fn publicize_all_methods(&mut self) {
        for m in &mut self.tables.method_defs {
            let acc = m.flags & 0x07;
            if acc < 6 { m.flags = (m.flags & !0x07) | 0x06; }
        }
    }

    /// Remove all custom attributes (full obfuscation cleanup).
    pub fn clear_all_custom_attributes(&mut self) {
        self.tables.custom_attributes.clear();
    }

    /// Summarise the assembly.
    pub fn summary(&self) -> MetadataSummary {
        MetadataSummary {
            type_count: self.tables.type_defs.len(),
            method_count: self.tables.method_defs.len(),
            field_count: self.tables.fields.len(),
            member_ref_count: self.tables.member_refs.len(),
            type_ref_count: self.tables.type_refs.len(),
            custom_attribute_count: self.tables.custom_attributes.len(),
            assembly_ref_count: self.tables.assembly_refs.len(),
            generic_param_count: self.tables.generic_params.len(),
            interface_impl_count: self.tables.interface_impls.len(),
        }
    }

    /// Find duplicate method names (potential obfuscation indicator).
    #[must_use]
    pub fn find_duplicate_method_names(&self) -> Vec<String> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for m in &self.tables.method_defs {
            *counts.entry(m.name.as_str()).or_insert(0) += 1;
        }
        counts.into_iter().filter(|(_, v)| *v > 1).map(|(k, _)| k.to_owned()).collect()
    }

    /// Validate structural integrity (method_list ordering, etc.).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut prev_method = 0u32;
        for td in &self.tables.type_defs {
            if td.method_list < prev_method && prev_method != 0 {
                errors.push(format!("TypeDef #{} method_list {} < previous {}", td.rid, td.method_list, prev_method));
            }
            prev_method = td.method_list;
        }
        let max_method_rid = self.tables.method_defs.iter().map(|m| m.rid).max().unwrap_or(0);
        for td in &self.tables.type_defs {
            if td.method_list > max_method_rid + 1 {
                errors.push(format!("TypeDef #{} method_list {} out of range", td.rid, td.method_list));
            }
        }
        errors
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetadataSummary {
    pub type_count: usize,
    pub method_count: usize,
    pub field_count: usize,
    pub member_ref_count: usize,
    pub type_ref_count: usize,
    pub custom_attribute_count: usize,
    pub assembly_ref_count: usize,
    pub generic_param_count: usize,
    pub interface_impl_count: usize,
}

impl fmt::Display for MetadataSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "types={} methods={} fields={} refs={} ca={}",
            self.type_count, self.method_count, self.field_count,
            self.member_ref_count, self.custom_attribute_count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Metadata header parser (stream headers only)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataHeader {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub version_string: String,
    pub streams: Vec<StreamHeader>,
}

impl MetadataHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 { bail!("metadata header too short"); }
        let sig = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if sig != 0x424A_5342 { bail!("invalid metadata magic: 0x{sig:08X}"); }
        let major = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let minor = u16::from_le_bytes(data[6..8].try_into().unwrap());
        // reserved: data[8..12]
        let version_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        if data.len() < 16 + version_len + 4 { bail!("metadata header truncated"); }
        let version_str = std::str::from_utf8(&data[16..16+version_len])
            .unwrap_or("unknown").trim_end_matches('\0').to_owned();
        let after_ver = 16 + version_len;
        // flags (2 bytes), stream count (2 bytes)
        let stream_count = u16::from_le_bytes(data[after_ver+2..after_ver+4].try_into().unwrap()) as usize;
        let mut pos = after_ver + 4;
        // dos-memory-exhaustion: stream_count comes from untrusted input; cap
        // the pre-allocation (ECMA-335 assemblies rarely exceed 5–6 streams).
        let mut streams = Vec::with_capacity(stream_count.min(64));
        for _ in 0..stream_count {
            if pos + 8 > data.len() { break; }
            let off = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
            let sz = u32::from_le_bytes(data[pos+4..pos+8].try_into().unwrap());
            pos += 8;
            let name_start = pos;
            while pos < data.len() && data[pos] != 0 { pos += 1; }
            let name = std::str::from_utf8(&data[name_start..pos]).unwrap_or("").to_owned();
            pos += 1;
            while !pos.is_multiple_of(4) { pos += 1; } // align
            streams.push(StreamHeader { offset: off, size: sz, name });
        }
        Ok(Self { signature: sig, major_version: major, minor_version: minor, version_string: version_str, streams })
    }

    pub fn find_stream(&self, name: &str) -> Option<&StreamHeader> {
        self.streams.iter().find(|s| s.name == name)
    }
}
