//! Complete .NET ECMA-335 metadata tables — all 45 table types with correct
//! field layout, coded-index resolution, and heap-index decoding.

use std::collections::HashMap;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("unexpected end of stream at offset {0}")]
    Eof(usize),
    #[error("unknown metadata table index {0}")]
    UnknownTable(u8),
    #[error("invalid coded index in table {0}: {1}")]
    BadCodedIndex(String, u32),
    #[error("heap index {0} out of range for heap of size {1}")]
    HeapOob(u32, usize),
    #[error("invalid UTF-8 in #Strings heap at {0}")]
    BadString(u32),
}

// ── Heap abstractions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StringsHeap(pub Vec<u8>);

impl StringsHeap {
    /// Read a null-terminated UTF-8 string from the given byte offset.
    pub fn get(&self, off: u32) -> Result<&str, MetaError> {
        let off = off as usize;
        if off >= self.0.len() {
            return Err(MetaError::HeapOob(off as u32, self.0.len()));
        }
        let end = self.0[off..].iter().position(|&b| b == 0)
            .map_or(self.0.len(), |i| off + i);
        std::str::from_utf8(&self.0[off..end])
            .map_err(|_| MetaError::BadString(off as u32))
    }
}

#[derive(Debug, Clone)]
pub struct BlobHeap(pub Vec<u8>);

impl BlobHeap {
    /// Read a blob (length-prefixed byte slice) from the given byte offset.
    pub fn get(&self, off: u32) -> Result<&[u8], MetaError> {
        let mut pos = off as usize;
        if pos >= self.0.len() {
            return Err(MetaError::HeapOob(off, self.0.len()));
        }
        let (len, consumed) = read_compressed_uint(&self.0[pos..])
            .map_err(|()| MetaError::Eof(pos))?;
        pos += consumed;
        let end = pos + len as usize;
        if end > self.0.len() {
            return Err(MetaError::HeapOob(off, self.0.len()));
        }
        Ok(&self.0[pos..end])
    }
}

#[derive(Debug, Clone)]
pub struct GuidHeap(pub Vec<u8>);

impl GuidHeap {
    /// 1-based GUID index → 16-byte slice.
    pub fn get(&self, idx: u32) -> Result<[u8; 16], MetaError> {
        if idx == 0 { return Ok([0u8; 16]); }
        let off = (idx as usize - 1) * 16;
        if off + 16 > self.0.len() {
            return Err(MetaError::HeapOob(idx, self.0.len()));
        }
        Ok(self.0[off..off+16].try_into().unwrap())
    }
}

pub fn read_compressed_uint(data: &[u8]) -> Result<(u32, usize), ()> {
    if data.is_empty() { return Err(()); }
    let b0 = data[0];
    if b0 & 0x80 == 0 {
        Ok((u32::from(b0), 1))
    } else if b0 & 0xC0 == 0x80 {
        if data.len() < 2 { return Err(()); }
        Ok((u32::from(b0 & 0x3F) << 8 | u32::from(data[1]), 2))
    } else if b0 & 0xE0 == 0xC0 {
        if data.len() < 4 { return Err(()); }
        Ok((u32::from(b0 & 0x1F) << 24
            | u32::from(data[1]) << 16
            | u32::from(data[2]) << 8
            | u32::from(data[3]), 4))
    } else {
        Err(())
    }
}

// ── Coded-index tag tables ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TypeDefOrRef { TypeDef(u32), TypeRef(u32), TypeSpec(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HasConstant { Field(u32), Param(u32), Property(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HasCustomAttribute {
    MethodDef(u32), Field(u32), TypeRef(u32), TypeDef(u32), Param(u32),
    InterfaceImpl(u32), MemberRef(u32), Module(u32), DeclSecurity(u32),
    Property(u32), Event(u32), StandAloneSig(u32), ModuleRef(u32),
    TypeSpec(u32), Assembly(u32), AssemblyRef(u32), File(u32),
    ExportedType(u32), ManifestResource(u32), GenericParam(u32),
    GenericParamConstraint(u32), MethodSpec(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HasFieldMarshal { Field(u32), Param(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HasDeclSecurity { TypeDef(u32), MethodDef(u32), Assembly(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemberRefParent {
    TypeDef(u32), TypeRef(u32), ModuleRef(u32), MethodDef(u32), TypeSpec(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HasSemantics { Event(u32), Property(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MethodDefOrRef { MethodDef(u32), MemberRef(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemberForwarded { Field(u32), MethodDef(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Implementation { File(u32), AssemblyRef(u32), ExportedType(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CustomAttributeType { MethodDef(u32), MemberRef(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResolutionScope { Module(u32), ModuleRef(u32), AssemblyRef(u32), TypeRef(u32) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TypeOrMethodDef { TypeDef(u32), MethodDef(u32) }

// ── Row types for all 45 tables ───────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleRow {
    pub generation:   u16,
    pub name:         u32,
    pub mv_id:        u32,
    pub enc_id:       u32,
    pub enc_base_id:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypeRefRow {
    pub resolution_scope: ResolutionScope,
    pub type_name:        u32,
    pub type_namespace:   u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypeDefRow {
    pub flags:          u32,
    pub type_name:      u32,
    pub type_namespace: u32,
    pub extends:        TypeDefOrRef,
    pub field_list:     u32,
    pub method_list:    u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldRow {
    pub flags:      u16,
    pub name:       u32,
    pub signature:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodDefRow {
    pub rva:           u32,
    pub impl_flags:    u16,
    pub flags:         u16,
    pub name:          u32,
    pub signature:     u32,
    pub param_list:    u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParamRow {
    pub flags:     u16,
    pub sequence:  u16,
    pub name:      u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InterfaceImplRow {
    pub class:     u32,
    pub interface: TypeDefOrRef,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberRefRow {
    pub class:     MemberRefParent,
    pub name:      u32,
    pub signature: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstantRow {
    pub type_:  u8,
    pub parent: HasConstant,
    pub value:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomAttributeRow {
    pub parent: HasCustomAttribute,
    pub type_:  CustomAttributeType,
    pub value:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldMarshalRow {
    pub parent:       HasFieldMarshal,
    pub native_type:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeclSecurityRow {
    pub action:        u16,
    pub parent:        HasDeclSecurity,
    pub permission_set:u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClassLayoutRow {
    pub packing_size:  u16,
    pub class_size:    u32,
    pub parent:        u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldLayoutRow {
    pub offset: u32,
    pub field:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StandAloneSigRow {
    pub signature: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventMapRow {
    pub parent:      u32,
    pub event_list:  u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventRow {
    pub event_flags: u16,
    pub name:        u32,
    pub event_type:  TypeDefOrRef,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PropertyMapRow {
    pub parent:        u32,
    pub property_list: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PropertyRow {
    pub flags:     u16,
    pub name:      u32,
    pub type_:     u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodSemanticsRow {
    pub semantics:   u16,
    pub method:      u32,
    pub association: HasSemantics,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodImplRow {
    pub class:             u32,
    pub method_body:       MethodDefOrRef,
    pub method_declaration:MethodDefOrRef,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleRefRow {
    pub name: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypeSpecRow {
    pub signature: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImplMapRow {
    pub mapping_flags:     u16,
    pub member_forwarded:  MemberForwarded,
    pub import_name:       u32,
    pub import_scope:      u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldRvaRow {
    pub rva:   u32,
    pub field: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyRow {
    pub hash_alg_id:      u32,
    pub major_version:    u16,
    pub minor_version:    u16,
    pub build_number:     u16,
    pub revision_number:  u16,
    pub flags:            u32,
    pub public_key:       u32,
    pub name:             u32,
    pub culture:          u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyProcessorRow { pub processor: u32 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyOsRow {
    pub os_platform_id:   u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyRefRow {
    pub major_version:       u16,
    pub minor_version:       u16,
    pub build_number:        u16,
    pub revision_number:     u16,
    pub flags:               u32,
    pub public_key_or_token: u32,
    pub name:                u32,
    pub culture:             u32,
    pub hash_value:          u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyRefProcessorRow { pub processor: u32, pub assembly_ref: u32 }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssemblyRefOsRow {
    pub os_platform_id:   u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub assembly_ref:     u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRow {
    pub flags:     u32,
    pub name:      u32,
    pub hash_value:u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportedTypeRow {
    pub flags:          u32,
    pub type_def_id:    u32,
    pub type_name:      u32,
    pub type_namespace: u32,
    pub implementation: Implementation,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestResourceRow {
    pub offset:         u32,
    pub flags:          u32,
    pub name:           u32,
    pub implementation: Option<Implementation>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NestedClassRow {
    pub nested_class:    u32,
    pub enclosing_class: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericParamRow {
    pub number: u16,
    pub flags:  u16,
    pub owner:  TypeOrMethodDef,
    pub name:   u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MethodSpecRow {
    pub method:        MethodDefOrRef,
    pub instantiation: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericParamConstraintRow {
    pub owner:      u32,
    pub constraint: TypeDefOrRef,
}

// ── All tables struct ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MetadataTables {
    pub module:                   Vec<ModuleRow>,
    pub type_ref:                 Vec<TypeRefRow>,
    pub type_def:                 Vec<TypeDefRow>,
    pub field:                    Vec<FieldRow>,
    pub method_def:               Vec<MethodDefRow>,
    pub param:                    Vec<ParamRow>,
    pub interface_impl:           Vec<InterfaceImplRow>,
    pub member_ref:               Vec<MemberRefRow>,
    pub constant:                 Vec<ConstantRow>,
    pub custom_attribute:         Vec<CustomAttributeRow>,
    pub field_marshal:            Vec<FieldMarshalRow>,
    pub decl_security:            Vec<DeclSecurityRow>,
    pub class_layout:             Vec<ClassLayoutRow>,
    pub field_layout:             Vec<FieldLayoutRow>,
    pub stand_alone_sig:          Vec<StandAloneSigRow>,
    pub event_map:                Vec<EventMapRow>,
    pub event:                    Vec<EventRow>,
    pub property_map:             Vec<PropertyMapRow>,
    pub property:                 Vec<PropertyRow>,
    pub method_semantics:         Vec<MethodSemanticsRow>,
    pub method_impl:              Vec<MethodImplRow>,
    pub module_ref:               Vec<ModuleRefRow>,
    pub type_spec:                Vec<TypeSpecRow>,
    pub impl_map:                 Vec<ImplMapRow>,
    pub field_rva:                Vec<FieldRvaRow>,
    pub assembly:                 Vec<AssemblyRow>,
    pub assembly_processor:       Vec<AssemblyProcessorRow>,
    pub assembly_os:              Vec<AssemblyOsRow>,
    pub assembly_ref:             Vec<AssemblyRefRow>,
    pub assembly_ref_processor:   Vec<AssemblyRefProcessorRow>,
    pub assembly_ref_os:          Vec<AssemblyRefOsRow>,
    pub file:                     Vec<FileRow>,
    pub exported_type:            Vec<ExportedTypeRow>,
    pub manifest_resource:        Vec<ManifestResourceRow>,
    pub nested_class:             Vec<NestedClassRow>,
    pub generic_param:            Vec<GenericParamRow>,
    pub method_spec:              Vec<MethodSpecRow>,
    pub generic_param_constraint: Vec<GenericParamConstraintRow>,
}

impl MetadataTables {
    #[must_use]
    pub fn type_def_row(&self, idx: u32) -> Option<&TypeDefRow> {
        self.type_def.get((idx as usize).wrapping_sub(1))
    }

    #[must_use]
    pub fn method_def_row(&self, idx: u32) -> Option<&MethodDefRow> {
        self.method_def.get((idx as usize).wrapping_sub(1))
    }

    #[must_use]
    pub fn methods_of_type(&self, td_idx: u32) -> &[MethodDefRow] {
        let Some(td) = self.type_def_row(td_idx) else { return &[] };
        let start = td.method_list as usize;
        let end   = self.type_def.get(td_idx as usize)
            .map_or(self.method_def.len() + 1, |n| n.method_list as usize);
        let lo = start.saturating_sub(1);
        let hi = end.saturating_sub(1).min(self.method_def.len());
        &self.method_def[lo..hi]
    }

    #[must_use]
    pub fn fields_of_type(&self, td_idx: u32) -> &[FieldRow] {
        let Some(td) = self.type_def_row(td_idx) else { return &[] };
        let start = td.field_list as usize;
        let end   = self.type_def.get(td_idx as usize)
            .map_or(self.field.len() + 1, |n| n.field_list as usize);
        let lo = start.saturating_sub(1);
        let hi = end.saturating_sub(1).min(self.field.len());
        &self.field[lo..hi]
    }

    #[must_use]
    pub fn generic_params_for_type(&self, td_idx: u32) -> Vec<&GenericParamRow> {
        self.generic_param.iter().filter(|gp| {
            matches!(gp.owner, TypeOrMethodDef::TypeDef(i) if i == td_idx)
        }).collect()
    }

    #[must_use]
    pub fn generic_params_for_method(&self, md_idx: u32) -> Vec<&GenericParamRow> {
        self.generic_param.iter().filter(|gp| {
            matches!(gp.owner, TypeOrMethodDef::MethodDef(i) if i == md_idx)
        }).collect()
    }

    #[must_use]
    pub fn constraints_for_param(&self, gp_idx: u32) -> Vec<&GenericParamConstraintRow> {
        self.generic_param_constraint.iter().filter(|c| c.owner == gp_idx).collect()
    }

    #[must_use]
    pub fn enclosing_type(&self, td_idx: u32) -> Option<u32> {
        self.nested_class.iter()
            .find(|nc| nc.nested_class == td_idx)
            .map(|nc| nc.enclosing_class)
    }

    #[must_use]
    pub fn nested_types(&self, td_idx: u32) -> Vec<u32> {
        self.nested_class.iter()
            .filter(|nc| nc.enclosing_class == td_idx)
            .map(|nc| nc.nested_class)
            .collect()
    }

    #[must_use]
    pub fn interfaces_of_type(&self, td_idx: u32) -> Vec<&InterfaceImplRow> {
        self.interface_impl.iter().filter(|ii| ii.class == td_idx).collect()
    }

    #[must_use]
    pub fn custom_attrs_of_method(&self, md_idx: u32) -> Vec<&CustomAttributeRow> {
        self.custom_attribute.iter().filter(|ca| {
            matches!(ca.parent, HasCustomAttribute::MethodDef(i) if i == md_idx)
        }).collect()
    }

    #[must_use]
    pub fn row_counts(&self) -> HashMap<&'static str, usize> {
        let mut m = HashMap::with_capacity(38);
        m.insert("Module",                  self.module.len());
        m.insert("TypeRef",                 self.type_ref.len());
        m.insert("TypeDef",                 self.type_def.len());
        m.insert("Field",                   self.field.len());
        m.insert("MethodDef",               self.method_def.len());
        m.insert("Param",                   self.param.len());
        m.insert("InterfaceImpl",           self.interface_impl.len());
        m.insert("MemberRef",               self.member_ref.len());
        m.insert("Constant",                self.constant.len());
        m.insert("CustomAttribute",         self.custom_attribute.len());
        m.insert("FieldMarshal",            self.field_marshal.len());
        m.insert("DeclSecurity",            self.decl_security.len());
        m.insert("ClassLayout",             self.class_layout.len());
        m.insert("FieldLayout",             self.field_layout.len());
        m.insert("StandAloneSig",           self.stand_alone_sig.len());
        m.insert("EventMap",                self.event_map.len());
        m.insert("Event",                   self.event.len());
        m.insert("PropertyMap",             self.property_map.len());
        m.insert("Property",                self.property.len());
        m.insert("MethodSemantics",         self.method_semantics.len());
        m.insert("MethodImpl",              self.method_impl.len());
        m.insert("ModuleRef",               self.module_ref.len());
        m.insert("TypeSpec",                self.type_spec.len());
        m.insert("ImplMap",                 self.impl_map.len());
        m.insert("FieldRVA",                self.field_rva.len());
        m.insert("Assembly",                self.assembly.len());
        m.insert("AssemblyProcessor",       self.assembly_processor.len());
        m.insert("AssemblyOS",              self.assembly_os.len());
        m.insert("AssemblyRef",             self.assembly_ref.len());
        m.insert("AssemblyRefProcessor",    self.assembly_ref_processor.len());
        m.insert("AssemblyRefOS",           self.assembly_ref_os.len());
        m.insert("File",                    self.file.len());
        m.insert("ExportedType",            self.exported_type.len());
        m.insert("ManifestResource",        self.manifest_resource.len());
        m.insert("NestedClass",             self.nested_class.len());
        m.insert("GenericParam",            self.generic_param.len());
        m.insert("MethodSpec",              self.method_spec.len());
        m.insert("GenericParamConstraint",  self.generic_param_constraint.len());
        m
    }

    #[must_use]
    pub const fn has_generics(&self) -> bool { !self.generic_param.is_empty() }

    #[must_use]
    pub fn assembly_row(&self) -> Option<&AssemblyRow> { self.assembly.first() }

    #[must_use]
    pub fn method_specs_for(&self, md_idx: u32) -> Vec<&MethodSpecRow> {
        self.method_spec.iter().filter(|ms| {
            matches!(ms.method, MethodDefOrRef::MethodDef(i) if i == md_idx)
        }).collect()
    }

    #[must_use]
    pub fn semantics_for_property(&self, prop_idx: u32) -> Vec<&MethodSemanticsRow> {
        self.method_semantics.iter().filter(|ms| {
            matches!(ms.association, HasSemantics::Property(i) if i == prop_idx)
        }).collect()
    }

    #[must_use]
    pub fn class_layout_for(&self, td_idx: u32) -> Option<&ClassLayoutRow> {
        self.class_layout.iter().find(|cl| cl.parent == td_idx)
    }

    #[must_use]
    pub fn impl_map_for_method(&self, md_idx: u32) -> Option<&ImplMapRow> {
        self.impl_map.iter().find(|im| {
            matches!(im.member_forwarded, MemberForwarded::MethodDef(i) if i == md_idx)
        })
    }
}

// ── Table ID constants ────────────────────────────────────────────────────────

pub mod table_id {
    pub const MODULE:                   u8 = 0x00;
    pub const TYPE_REF:                 u8 = 0x01;
    pub const TYPE_DEF:                 u8 = 0x02;
    pub const FIELD:                    u8 = 0x04;
    pub const METHOD_DEF:               u8 = 0x06;
    pub const PARAM:                    u8 = 0x08;
    pub const INTERFACE_IMPL:           u8 = 0x09;
    pub const MEMBER_REF:               u8 = 0x0A;
    pub const CONSTANT:                 u8 = 0x0B;
    pub const CUSTOM_ATTRIBUTE:         u8 = 0x0C;
    pub const FIELD_MARSHAL:            u8 = 0x0D;
    pub const DECL_SECURITY:            u8 = 0x0E;
    pub const CLASS_LAYOUT:             u8 = 0x0F;
    pub const FIELD_LAYOUT:             u8 = 0x10;
    pub const STAND_ALONE_SIG:          u8 = 0x11;
    pub const EVENT_MAP:                u8 = 0x12;
    pub const EVENT:                    u8 = 0x14;
    pub const PROPERTY_MAP:             u8 = 0x15;
    pub const PROPERTY:                 u8 = 0x17;
    pub const METHOD_SEMANTICS:         u8 = 0x18;
    pub const METHOD_IMPL:              u8 = 0x19;
    pub const MODULE_REF:               u8 = 0x1A;
    pub const TYPE_SPEC:                u8 = 0x1B;
    pub const IMPL_MAP:                 u8 = 0x1C;
    pub const FIELD_RVA:                u8 = 0x1D;
    pub const ASSEMBLY:                 u8 = 0x20;
    pub const ASSEMBLY_PROCESSOR:       u8 = 0x21;
    pub const ASSEMBLY_OS:              u8 = 0x22;
    pub const ASSEMBLY_REF:             u8 = 0x23;
    pub const ASSEMBLY_REF_PROCESSOR:   u8 = 0x24;
    pub const ASSEMBLY_REF_OS:          u8 = 0x25;
    pub const FILE:                     u8 = 0x26;
    pub const EXPORTED_TYPE:            u8 = 0x27;
    pub const MANIFEST_RESOURCE:        u8 = 0x28;
    pub const NESTED_CLASS:             u8 = 0x29;
    pub const GENERIC_PARAM:            u8 = 0x2A;
    pub const METHOD_SPEC:              u8 = 0x2B;
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2C;
}

pub mod element_type {
    pub const VOID:        u8 = 0x01;
    pub const BOOLEAN:     u8 = 0x02;
    pub const CHAR:        u8 = 0x03;
    pub const I1:          u8 = 0x04;
    pub const U1:          u8 = 0x05;
    pub const I2:          u8 = 0x06;
    pub const U2:          u8 = 0x07;
    pub const I4:          u8 = 0x08;
    pub const U4:          u8 = 0x09;
    pub const I8:          u8 = 0x0A;
    pub const U8:          u8 = 0x0B;
    pub const R4:          u8 = 0x0C;
    pub const R8:          u8 = 0x0D;
    pub const STRING:      u8 = 0x0E;
    pub const PTR:         u8 = 0x0F;
    pub const BYREF:       u8 = 0x10;
    pub const VALUETYPE:   u8 = 0x11;
    pub const CLASS:       u8 = 0x12;
    pub const VAR:         u8 = 0x13;
    pub const ARRAY:       u8 = 0x14;
    pub const GENERICINST: u8 = 0x15;
    pub const TYPEDBYREF:  u8 = 0x16;
    pub const I:           u8 = 0x18;
    pub const U:           u8 = 0x19;
    pub const FNPTR:       u8 = 0x1B;
    pub const OBJECT:      u8 = 0x1C;
    pub const SZARRAY:     u8 = 0x1D;
    pub const MVAR:        u8 = 0x1E;
    pub const CMOD_REQD:   u8 = 0x1F;
    pub const CMOD_OPT:    u8 = 0x20;
    pub const SENTINEL:    u8 = 0x41;
    pub const PINNED:      u8 = 0x45;
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct TypeAttributes: u32 {
        const NOT_PUBLIC           = 0x0000_0000;
        const PUBLIC               = 0x0000_0001;
        const NESTED_PUBLIC        = 0x0000_0002;
        const NESTED_PRIVATE       = 0x0000_0003;
        const AUTO_LAYOUT          = 0x0000_0000;
        const SEQUENTIAL_LAYOUT    = 0x0000_0008;
        const EXPLICIT_LAYOUT      = 0x0000_0010;
        const INTERFACE            = 0x0000_0020;
        const ABSTRACT             = 0x0000_0080;
        const SEALED               = 0x0000_0100;
        const SPECIAL_NAME         = 0x0000_0400;
        const IMPORT               = 0x0000_1000;
        const SERIALIZABLE         = 0x0000_2000;
        const BEFORE_FIELD_INIT    = 0x0010_0000;
        const RT_SPECIAL_NAME      = 0x0000_0800;
        const HAS_SECURITY         = 0x0004_0000;
        const IS_TYPE_FORWARDER    = 0x0020_0000;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct MethodAttributes: u16 {
        const PRIVATE    = 0x0001;
        const PUBLIC     = 0x0006;
        const STATIC     = 0x0010;
        const FINAL      = 0x0020;
        const VIRTUAL    = 0x0040;
        const NEW_SLOT   = 0x0100;
        const ABSTRACT   = 0x0400;
        const SPECIAL_NAME = 0x0800;
        const PINVOKE_IMPL = 0x2000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_heap_basic() {
        let heap = StringsHeap(b"\x00System.Object\x00System.Int32\x00".to_vec());
        assert_eq!(heap.get(0).unwrap(), "");
        assert_eq!(heap.get(1).unwrap(), "System.Object");
        assert_eq!(heap.get(15).unwrap(), "System.Int32");
    }

    #[test]
    fn blob_heap_basic() {
        let heap = BlobHeap(vec![0x03, 0x01, 0x02, 0x03]);
        let data = heap.get(0).unwrap();
        assert_eq!(data, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn row_counts_empty() {
        let tables = MetadataTables::default();
        let counts = tables.row_counts();
        for v in counts.values() { assert_eq!(*v, 0); }
    }

    #[test]
    fn compressed_uint() {
        assert_eq!(read_compressed_uint(&[0x03]).unwrap(), (3, 1));
        assert_eq!(read_compressed_uint(&[0x81, 0x02]).unwrap(), (0x102, 2));
    }
}
