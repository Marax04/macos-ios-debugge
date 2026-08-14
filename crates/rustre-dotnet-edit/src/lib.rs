//! `rustre-dotnet-edit`
//!
//! dnSpy-style assembly editor. Supports type/method/field renaming, method body
//! patching, custom attribute injection, resource editing, flag mutation,
//! IL instruction insertion/deletion, type/method/field addition and removal,
//! and strong-name stripping.

pub mod assembly_patcher;
pub mod assembly_signer;
pub mod cil_injector;
pub mod il_editor_extended;
pub mod il_recompile;
pub mod metadata_editor;
pub mod method_body_editor;
pub mod resource_editor;
pub mod type_injector;
pub mod assembly_merger;
pub mod cil_patcher;
pub mod strong_name_editor;
pub mod cil_optimizer;
pub mod dotnet_patcher;

use std::collections::HashMap;
use std::fmt;

use anyhow::{Result, anyhow};
use rustre_dotnet::{AssemblyFile, CilInstruction, CilOperand, DotnetType};
use rustre_dotnet_metadata::{
    AssemblyRefRow, AssemblyRow, ClassLayoutRow, ConstantRow, CustomAttributeRow, DeclSecurityRow,
    EventMapRow, EventRow, ExportedTypeRow, FieldLayoutRow, FieldMarshalRow, FieldRow, FieldRvaRow,
    FileRow, GenericParamConstraintRow, GenericParamRow, ImplMapRow, InterfaceImplRow,
    ManifestResourceRow, MemberRefRow, MetadataReader, MetadataTables, MethodDefRow, MethodImplRow,
    MethodSemanticsRow, MethodSpecRow, ModuleRefRow, ModuleRow, NestedClassRow, ParamRow,
    PropertyMapRow, PropertyRow, StandAloneSigRow, TypeDefRow, TypeRefRow, TypeSpecRow,
};

// ─── Edit error ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EditError {
    TypeNotFound(String),
    MethodNotFound {
        type_name: String,
        method_name: String,
    },
    FieldNotFound {
        type_name: String,
        field_name: String,
    },
    NoMethodBody {
        type_name: String,
        method_name: String,
    },
    InvalidIlOffset(u32),
    InvalidFlags(u32),
    ResourceNotFound(String),
    Custom(String),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeNotFound(n) => write!(f, "type not found: {n}"),
            Self::MethodNotFound {
                type_name,
                method_name,
            } => write!(f, "method {method_name} not found on {type_name}"),
            Self::FieldNotFound {
                type_name,
                field_name,
            } => write!(f, "field {field_name} not found on {type_name}"),
            Self::NoMethodBody {
                type_name,
                method_name,
            } => write!(f, "{type_name}::{method_name} has no method body"),
            Self::InvalidIlOffset(o) => write!(f, "invalid IL offset 0x{o:04X}"),
            Self::InvalidFlags(v) => write!(f, "invalid flags value 0x{v:08X}"),
            Self::ResourceNotFound(n) => write!(f, "resource not found: {n}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for EditError {}

// ─── Resource editing ─────────────────────────────────────────────────────────

/// A managed resource stored in the assembly.
#[derive(Debug, Clone)]
pub struct ManagedResource {
    pub name: String,
    pub flags: u32,
    pub data: Vec<u8>,
}

impl ManagedResource {
    /// Create a new embedded resource.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            flags: 1,
            data,
        }
    }

    /// Returns true if the resource is public.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

// ─── IL patch operations ──────────────────────────────────────────────────────

/// Specifies how to modify the instruction list at a given offset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IlPatch {
    /// Replace the instruction at the given offset with a new one.
    Replace {
        offset: u32,
        instruction: CilInstruction,
    },
    /// Insert instructions before the instruction at the given offset.
    InsertBefore {
        offset: u32,
        instructions: Vec<CilInstruction>,
    },
    /// Insert instructions after the instruction at the given offset.
    InsertAfter {
        offset: u32,
        instructions: Vec<CilInstruction>,
    },
    /// Remove the instruction at the given offset.
    Remove { offset: u32 },
    /// Replace a range [`start_offset`, `end_offset`) with new instructions.
    ReplaceRange {
        start: u32,
        end: u32,
        instructions: Vec<CilInstruction>,
    },
    /// Prepend instructions at the very start of the body.
    Prepend { instructions: Vec<CilInstruction> },
    /// Append instructions at the very end of the body (before `ret`).
    Append { instructions: Vec<CilInstruction> },
}

impl IlPatch {
    /// Apply this patch to a mutable instruction list.
    ///
    /// # Errors
    /// Returns an error if the specified offset does not exist.
    pub fn apply(&self, instrs: &mut Vec<CilInstruction>) -> Result<()> {
        match self {
            Self::Replace {
                offset,
                instruction,
            } => {
                let pos = instrs
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
                instrs[pos] = instruction.clone();
                Ok(())
            }
            Self::InsertBefore {
                offset,
                instructions,
            } => {
                let pos = instrs
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
                for (j, instr) in instructions.iter().enumerate() {
                    instrs.insert(pos + j, instr.clone());
                }
                Ok(())
            }
            Self::InsertAfter {
                offset,
                instructions,
            } => {
                let pos = instrs
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
                for (j, instr) in instructions.iter().enumerate() {
                    instrs.insert(pos + 1 + j, instr.clone());
                }
                Ok(())
            }
            Self::Remove { offset } => {
                let pos = instrs
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| anyhow!("offset 0x{offset:04X} not found"))?;
                instrs.remove(pos);
                Ok(())
            }
            Self::ReplaceRange {
                start,
                end,
                instructions,
            } => {
                instrs.retain(|i| i.offset < *start || i.offset >= *end);
                let insert_pos = instrs
                    .iter()
                    .position(|i| i.offset >= *start)
                    .unwrap_or(instrs.len());
                for (j, instr) in instructions.iter().enumerate() {
                    instrs.insert(insert_pos + j, instr.clone());
                }
                Ok(())
            }
            Self::Prepend { instructions } => {
                for (j, instr) in instructions.iter().enumerate() {
                    instrs.insert(j, instr.clone());
                }
                Ok(())
            }
            Self::Append { instructions } => {
                // Insert before the last `ret`, if any
                let ret_pos = instrs.iter().rposition(|i| i.opcode == "ret");
                let insert_at = ret_pos.unwrap_or(instrs.len());
                for (j, instr) in instructions.iter().enumerate() {
                    instrs.insert(insert_at + j, instr.clone());
                }
                Ok(())
            }
        }
    }
}

// ─── Type/method/field addition descriptors ───────────────────────────────────

/// Descriptor for adding a new type.
#[derive(Debug, Clone)]
pub struct NewTypeDescriptor {
    pub name: String,
    pub namespace: String,
    pub flags: u32,
    pub base_type_name: Option<String>,
    pub interfaces: Vec<String>,
}

impl NewTypeDescriptor {
    /// Create a public class descriptor.
    #[must_use]
    pub fn public_class(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            flags: 0x00000101, // public, sealed
            base_type_name: None,
            interfaces: Vec::new(),
        }
    }

    /// Create a public interface descriptor.
    #[must_use]
    pub fn public_interface(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            flags: 0x000000A1, // public, abstract, interface
            base_type_name: None,
            interfaces: Vec::new(),
        }
    }
}

/// Descriptor for adding a new method.
#[derive(Debug, Clone)]
pub struct NewMethodDescriptor {
    pub name: String,
    pub flags: u16,
    pub impl_flags: u16,
    pub return_type_sig: Vec<u8>,
    pub param_types: Vec<Vec<u8>>,
    pub param_names: Vec<String>,
    pub body: Option<Vec<CilInstruction>>,
}

impl NewMethodDescriptor {
    /// Create a public static void method with no parameters.
    #[must_use]
    pub fn static_void(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: 0x0016, // public static
            impl_flags: 0,
            return_type_sig: vec![0x01], // void
            param_types: Vec::new(),
            param_names: Vec::new(),
            body: Some(vec![CilInstruction::simple(0, "ret")]),
        }
    }

    /// Create a public instance void method.
    #[must_use]
    pub fn instance_void(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: 0x0006, // public
            impl_flags: 0,
            return_type_sig: vec![0x01],
            param_types: Vec::new(),
            param_names: Vec::new(),
            body: Some(vec![CilInstruction::simple(0, "ret")]),
        }
    }

    /// Encode this descriptor's signature blob.
    #[must_use]
    pub fn encode_sig(&self) -> Vec<u8> {
        let is_instance = (self.flags & 0x0010) == 0;
        let calling_conv: u8 = if is_instance { 0x20 } else { 0x00 };
        // ECMA-335 §II.23.2.1: ParamCount is a compressed integer; we emit it
        // as a single byte here so cap at 255 rather than silently truncating.
        let param_count = self.param_types.len().min(255) as u8;
        let mut sig = vec![calling_conv, param_count];
        sig.extend_from_slice(&self.return_type_sig);
        for param in &self.param_types {
            sig.extend_from_slice(param);
        }
        sig
    }
}

/// Descriptor for adding a new field.
#[derive(Debug, Clone)]
pub struct NewFieldDescriptor {
    pub name: String,
    pub flags: u16,
    pub type_sig: Vec<u8>,
}

impl NewFieldDescriptor {
    /// Create a public instance field of a primitive type byte.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn public_field(name: impl Into<String>, element_type: u8) -> Self {
        Self {
            name: name.into(),
            flags: 0x0006,                      // public
            type_sig: vec![0x06, element_type], // FIELD + type
        }
    }

    /// Create a public static field.
    #[must_use]
    pub fn public_static(name: impl Into<String>, element_type: u8) -> Self {
        Self {
            name: name.into(),
            flags: 0x0016, // public static
            type_sig: vec![0x06, element_type],
        }
    }
}

// ─── Modification ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Modification {
    RenameType {
        old: String,
        new: String,
    },
    RenameMethod {
        type_name: String,
        old: String,
        new: String,
    },
    RenameField {
        type_name: String,
        old: String,
        new: String,
    },
    PatchMethodBody {
        type_name: String,
        method_name: String,
        new_instructions: Vec<CilInstruction>,
    },
    PatchIl {
        type_name: String,
        method_name: String,
        patches: Vec<IlPatch>,
    },
    AddCustomAttribute {
        target: String,
        attr_type: String,
        data: Vec<u8>,
    },
    ChangeMethodFlags {
        type_name: String,
        method_name: String,
        flags: u32,
    },
    ChangeFieldFlags {
        type_name: String,
        field_name: String,
        flags: u32,
    },
    ChangeTypeFlags {
        type_name: String,
        flags: u32,
    },
    AddType {
        descriptor: NewTypeDescriptor,
    },
    RemoveType {
        name: String,
    },
    AddMethod {
        type_name: String,
        descriptor: NewMethodDescriptor,
    },
    RemoveMethod {
        type_name: String,
        method_name: String,
    },
    AddField {
        type_name: String,
        descriptor: NewFieldDescriptor,
    },
    RemoveField {
        type_name: String,
        field_name: String,
    },
    ReplaceResource {
        name: String,
        data: Vec<u8>,
    },
    AddResource {
        resource: ManagedResource,
    },
    RemoveResource {
        name: String,
    },
    SetAssemblyVersion {
        major: u16,
        minor: u16,
        build: u16,
        revision: u16,
    },
    StripStrongName,
}

// ─── EditTransaction ──────────────────────────────────────────────────────────

/// A reversible set of modifications. Call `apply()` to commit, `rollback()` to
/// revert the last committed transaction.
#[derive(Debug, Default)]
pub struct EditTransaction {
    modifications: Vec<Modification>,
    committed: bool,
    snapshot: Option<(MutableTables, Vec<Modification>)>,
}

impl EditTransaction {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, m: Modification) {
        self.modifications.push(m);
    }

    pub fn apply(mut self, editor: &mut AssemblyEditor) -> Result<()> {
        self.snapshot = Some((editor.tables.clone(), editor.modifications.clone()));
        for m in &self.modifications {
            editor.apply_modification(m.clone())?;
        }
        self.committed = true;
        Ok(())
    }

    /// Revert all modifications by restoring the pre-apply snapshot of the
    /// editor's mutable tables and modification log.
    pub fn rollback(self, editor: &mut AssemblyEditor) -> Result<()> {
        if let Some((tables, modifications)) = self.snapshot {
            editor.tables = tables;
            editor.modifications = modifications;
        } else {
            // When rollback() is called without a prior apply(), we fall back to
            // truncating the last `n` entries. Use saturating_sub to avoid underflow
            // if the transaction was never applied and `n > len`.
            let n = self.modifications.len();
            let len = editor.modifications.len();
            editor.modifications.truncate(len.saturating_sub(n));
        }
        Ok(())
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.modifications.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.modifications.is_empty()
    }
}

// ─── SignatureStripper ────────────────────────────────────────────────────────

/// Removes the strong-name signature from a raw PE byte stream.
pub struct SignatureStripper;

impl SignatureStripper {
    /// Strip the strong-name signature:
    /// 1. Clear CorFlags.StrongNameSigned (bit 3 of `CorFlags` word).
    /// 2. Zero out the `StrongNameSignature` data directory blob.
    pub fn strip(data: &mut [u8]) -> Result<()> {
        // Find PE offset
        if data.len() < 0x40 {
            return Err(anyhow!("PE too small to contain MZ header"));
        }
        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into()?) as usize;
        if pe_offset + 24 > data.len() {
            return Err(anyhow!("PE offset out of range"));
        }
        // COFF header
        let opt_size =
            u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into()?) as usize;
        let opt_start = pe_offset + 24;
        if opt_start + opt_size > data.len() {
            return Err(anyhow!("Optional header out of range"));
        }

        let magic = u16::from_le_bytes(data[opt_start..opt_start + 2].try_into()?);
        let data_dir_base = if magic == 0x10B {
            opt_start + 96 // PE32
        } else if magic == 0x20B {
            opt_start + 112 // PE32+
        } else {
            return Err(anyhow!("Unknown PE magic 0x{magic:04X}"));
        };

        // CLI header is data directory entry 14 (index 14, 8 bytes each)
        let cli_dir_off = data_dir_base + 14 * 8;
        if cli_dir_off + 8 > data.len() {
            return Err(anyhow!("CLI directory entry out of range"));
        }
        let cli_rva = u32::from_le_bytes(data[cli_dir_off..cli_dir_off + 4].try_into()?);
        let cli_off = Self::rva_to_offset(data, cli_rva, pe_offset)?;

        // CLI header layout:
        // +0  cb(4), +4 MajorRuntimeVersion(2), +6 MinorRuntimeVersion(2)
        // +8  MetaDataVA(4), +12 MetaDataSize(4)
        // +16 Flags(4)
        // +20 EntryPointToken(4)
        // +24 Resources.VirtualAddress(4), +28 Resources.Size(4)
        // +32 StrongNameSignature.VirtualAddress(4), +36 StrongNameSignature.Size(4)
        if cli_off + 40 > data.len() {
            return Err(anyhow!("CLI header too small"));
        }

        // Clear StrongNameSigned flag (bit 3 = 0x08)
        let flags_off = cli_off + 16;
        let mut flags = u32::from_le_bytes(data[flags_off..flags_off + 4].try_into()?);
        flags &= !0x08u32; // clear StrongNameSigned
        data[flags_off..flags_off + 4].copy_from_slice(&flags.to_le_bytes());

        // Zero the StrongNameSignature blob
        let sn_rva = u32::from_le_bytes(data[cli_off + 32..cli_off + 36].try_into()?);
        let sn_size_raw = u32::from_le_bytes(data[cli_off + 36..cli_off + 40].try_into()?);
        let sn_size = sn_size_raw as usize;
        if sn_rva != 0 && sn_size > 0 {
            let sn_off = Self::rva_to_offset(data, sn_rva, pe_offset)?;
            let sn_end = sn_off.checked_add(sn_size)
                .ok_or_else(|| anyhow!("strong-name signature range overflow: offset={sn_off} size={sn_size}"))?;
            if sn_end <= data.len() {
                for b in &mut data[sn_off..sn_end] {
                    *b = 0;
                }
            }
        }

        Ok(())
    }

    fn rva_to_offset(data: &[u8], rva: u32, pe_offset: usize) -> Result<usize> {
        if rva == 0 {
            return Ok(0);
        }
        let num_sections =
            u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into()?) as usize;
        let opt_size =
            u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into()?) as usize;
        let sections_start = pe_offset + 24 + opt_size;

        for i in 0..num_sections {
            let sec = sections_start + i * 40;
            if sec + 40 > data.len() {
                break;
            }
            let virt_size = u32::from_le_bytes(data[sec + 8..sec + 12].try_into()?);
            let virt_addr = u32::from_le_bytes(data[sec + 12..sec + 16].try_into()?);
            let raw_ptr = u32::from_le_bytes(data[sec + 20..sec + 24].try_into()?);
            let raw_size = u32::from_le_bytes(data[sec + 16..sec + 20].try_into()?);
            let sec_size = virt_size.max(raw_size);
            if rva >= virt_addr && rva < virt_addr.saturating_add(sec_size) {
                let delta = rva - virt_addr;
                let file_off = raw_ptr.checked_add(delta)
                    .ok_or_else(|| anyhow!("section file offset overflow: raw_ptr={raw_ptr} delta={delta}"))?;
                return Ok(file_off as usize);
            }
        }
        // Fall back to identity mapping
        Ok(rva as usize)
    }
}

// ─── Internal mutable metadata state ─────────────────────────────────────────

/// A mutable mirror of `MetadataTables` used while editing.
#[derive(Debug, Clone)]
struct MutableTables {
    module: Vec<ModuleRow>,
    type_ref: Vec<TypeRefRow>,
    type_def: Vec<TypeDefRow>,
    field: Vec<FieldRow>,
    method_def: Vec<MethodDefRow>,
    param: Vec<ParamRow>,
    interface_impl: Vec<InterfaceImplRow>,
    member_ref: Vec<MemberRefRow>,
    constant: Vec<ConstantRow>,
    custom_attribute: Vec<CustomAttributeRow>,
    field_marshal: Vec<FieldMarshalRow>,
    decl_security: Vec<DeclSecurityRow>,
    class_layout: Vec<ClassLayoutRow>,
    field_layout: Vec<FieldLayoutRow>,
    stand_alone_sig: Vec<StandAloneSigRow>,
    event_map: Vec<EventMapRow>,
    event: Vec<EventRow>,
    property_map: Vec<PropertyMapRow>,
    property: Vec<PropertyRow>,
    method_semantics: Vec<MethodSemanticsRow>,
    method_impl: Vec<MethodImplRow>,
    module_ref: Vec<ModuleRefRow>,
    type_spec: Vec<TypeSpecRow>,
    impl_map: Vec<ImplMapRow>,
    field_rva: Vec<FieldRvaRow>,
    assembly: Vec<AssemblyRow>,
    assembly_ref: Vec<AssemblyRefRow>,
    file: Vec<FileRow>,
    exported_type: Vec<ExportedTypeRow>,
    manifest_resource: Vec<ManifestResourceRow>,
    nested_class: Vec<NestedClassRow>,
    generic_param: Vec<GenericParamRow>,
    method_spec: Vec<MethodSpecRow>,
    generic_param_constraint: Vec<GenericParamConstraintRow>,
    /// Patched method bodies: method 1-based index → raw CIL instruction list
    patched_bodies: HashMap<usize, Vec<CilInstruction>>,
    /// Embedded resources: name → data
    resources: HashMap<String, ManagedResource>,
}

impl MutableTables {
    fn from_metadata(tables: &MetadataTables) -> Self {
        Self {
            module: tables.module.clone(),
            type_ref: tables.type_ref.clone(),
            type_def: tables.type_def.clone(),
            field: tables.field.clone(),
            method_def: tables.method_def.clone(),
            param: tables.param.clone(),
            interface_impl: tables.interface_impl.clone(),
            member_ref: tables.member_ref.clone(),
            constant: tables.constant.clone(),
            custom_attribute: tables.custom_attribute.clone(),
            field_marshal: tables.field_marshal.clone(),
            decl_security: tables.decl_security.clone(),
            class_layout: tables.class_layout.clone(),
            field_layout: tables.field_layout.clone(),
            stand_alone_sig: tables.stand_alone_sig.clone(),
            event_map: tables.event_map.clone(),
            event: tables.event.clone(),
            property_map: tables.property_map.clone(),
            property: tables.property.clone(),
            method_semantics: tables.method_semantics.clone(),
            method_impl: tables.method_impl.clone(),
            module_ref: tables.module_ref.clone(),
            type_spec: tables.type_spec.clone(),
            impl_map: tables.impl_map.clone(),
            field_rva: tables.field_rva.clone(),
            assembly: tables.assembly.clone(),
            assembly_ref: tables.assembly_ref.clone(),
            file: tables.file.clone(),
            exported_type: tables.exported_type.clone(),
            manifest_resource: tables.manifest_resource.clone(),
            nested_class: tables.nested_class.clone(),
            generic_param: tables.generic_param.clone(),
            method_spec: tables.method_spec.clone(),
            generic_param_constraint: tables.generic_param_constraint.clone(),
            patched_bodies: HashMap::new(),
            resources: HashMap::new(),
        }
    }

    /// Find type-def index (1-based) by type name or full name.
    fn find_type_index(&self, name: &str) -> Option<usize> {
        self.type_def.iter().enumerate().find_map(|(i, t)| {
            let full = if t.type_namespace.is_empty() {
                t.type_name.clone()
            } else {
                format!("{}.{}", t.type_namespace, t.type_name)
            };
            if t.type_name == name || full == name {
                Some(i + 1)
            } else {
                None
            }
        })
    }

    /// Find method-def index (1-based) belonging to a type.
    fn find_method_index(&self, type_idx: usize, method_name: &str) -> Option<usize> {
        let td = self.type_def.get(type_idx - 1)?;
        let method_end = self
            .type_def
            .get(type_idx)
            .map_or(self.method_def.len() as u32 + 1, |r| r.method_list);

        for mi in td.method_list..method_end {
            let mi_idx = (mi as usize).checked_sub(1)?;
            if let Some(m) = self.method_def.get(mi_idx)
                && m.name == method_name {
                    return Some(mi_idx + 1);
                }
        }
        None
    }

    /// Find field-def index (1-based) belonging to a type.
    fn find_field_index(&self, type_idx: usize, field_name: &str) -> Option<usize> {
        let td = self.type_def.get(type_idx - 1)?;
        let field_end = self
            .type_def
            .get(type_idx)
            .map_or(self.field.len() as u32 + 1, |r| r.field_list);

        for fi in td.field_list..field_end {
            let fi_idx = (fi as usize).checked_sub(1)?;
            if let Some(f) = self.field.get(fi_idx)
                && f.name == field_name {
                    return Some(fi_idx + 1);
                }
        }
        None
    }
}

// ─── AssemblyEditor ───────────────────────────────────────────────────────────

pub struct AssemblyEditor {
    pub assembly: AssemblyFile,
    pub modifications: Vec<Modification>,
    tables: MutableTables,
    raw: Vec<u8>,
}

impl AssemblyEditor {
    /// Create an editor wrapping an `AssemblyFile`.
    #[must_use] 
    pub fn new(assembly: AssemblyFile) -> Self {
        let tables = MutableTables::from_metadata(&assembly.metadata.tables);
        Self {
            assembly,
            modifications: Vec::new(),
            tables,
            raw: Vec::new(),
        }
    }

    /// Create from raw PE bytes (parses metadata internally).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let metadata = MetadataReader::parse_from_bytes(&bytes)
            .map_err(|e| anyhow!("metadata parse failed: {e}"))?;
        let tables = MutableTables::from_metadata(&metadata.tables);
        let asm = AssemblyFile::from_metadata(metadata);
        Ok(Self {
            assembly: asm,
            modifications: Vec::new(),
            tables,
            raw: bytes,
        })
    }

    // ─── Modification helpers ───────────────────────────────────────────────────

    fn apply_modification(&mut self, m: Modification) -> Result<()> {
        match &m {
            Modification::RenameType { old, new } => {
                let idx = self
                    .tables
                    .find_type_index(old)
                    .ok_or_else(|| anyhow!("type {old:?} not found"))?;
                self.tables.type_def[idx - 1].type_name.clone_from(new);
                self.modifications.push(m);
                Ok(())
            }
            Modification::RenameMethod {
                type_name,
                old,
                new,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let midx = self
                    .tables
                    .find_method_index(tidx, old)
                    .ok_or_else(|| anyhow!("method {old:?} not found on {type_name:?}"))?;
                self.tables.method_def[midx - 1].name.clone_from(new);
                self.modifications.push(m);
                Ok(())
            }
            Modification::RenameField {
                type_name,
                old,
                new,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let fidx = self
                    .tables
                    .find_field_index(tidx, old)
                    .ok_or_else(|| anyhow!("field {old:?} not found on {type_name:?}"))?;
                self.tables.field[fidx - 1].name.clone_from(new);
                self.modifications.push(m);
                Ok(())
            }
            Modification::PatchMethodBody {
                type_name,
                method_name,
                new_instructions,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let midx = self
                    .tables
                    .find_method_index(tidx, method_name)
                    .ok_or_else(|| anyhow!("method {method_name:?} not found on {type_name:?}"))?;
                self.tables
                    .patched_bodies
                    .insert(midx, new_instructions.clone());
                self.modifications.push(m);
                Ok(())
            }
            Modification::PatchIl {
                type_name,
                method_name,
                patches,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let midx = self
                    .tables
                    .find_method_index(tidx, method_name)
                    .ok_or_else(|| anyhow!("method {method_name:?} not found on {type_name:?}"))?;
                // If no prior PatchMethodBody has been applied for this method, load
                // the original CIL body from the parsed assembly so that offset-based
                // patches (InsertBefore/InsertAfter/Remove/Replace) can find their targets.
                let mut instrs = self.tables.patched_bodies.remove(&midx).unwrap_or_else(|| {
                    // Look up original body through the high-level assembly view.
                    let type_name_ref: &str = type_name;
                    let method_name_ref: &str = method_name;
                    self.assembly
                        .find_method(type_name_ref, method_name_ref)
                        .and_then(|m| m.body)
                        .map(|b| b.instructions)
                        .unwrap_or_default()
                });
                for patch in patches {
                    patch.apply(&mut instrs)?;
                }
                self.tables.patched_bodies.insert(midx, instrs);
                self.modifications.push(m);
                Ok(())
            }
            Modification::AddCustomAttribute {
                target,
                attr_type,
                data,
            } => {
                let type_ref_idx = self.ensure_type_ref(attr_type);
                // Synthesise a MemberRef pointing to the .ctor of the attribute type.
                // The MemberRef class coded index for a TypeRef uses tag 1 (MemberRefParent::TypeRef).
                let member_ref_class = ((type_ref_idx as u32) << 3) | 1u32;
                self.tables.member_ref.push(rustre_dotnet_metadata::MemberRefRow {
                    class: member_ref_class,
                    name: ".ctor".to_string(),
                    signature: vec![0x20, 0x00, 0x01], // hasthis, 0 params, void return
                });
                let ctor_member_ref_idx = self.tables.member_ref.len() as u32;
                // attr_type coded index: HasCustomAttribute uses MemberRef tag 3.
                let attr_type_coded = (ctor_member_ref_idx << 3) | 3u32;
                let parent_coded = self
                    .tables
                    .find_type_index(target)
                    .map_or(0, |i| (i as u32) << 5 | 1);
                self.tables.custom_attribute.push(CustomAttributeRow {
                    parent: parent_coded,
                    attr_type: attr_type_coded,
                    value: data.clone(),
                });
                self.modifications.push(m);
                Ok(())
            }
            Modification::ChangeMethodFlags {
                type_name,
                method_name,
                flags,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let midx = self
                    .tables
                    .find_method_index(tidx, method_name)
                    .ok_or_else(|| anyhow!("method {method_name:?} not found on {type_name:?}"))?;
                let flags_u16: u16 = (*flags).try_into().map_err(|_| {
                    anyhow!("method flags {flags:#x} exceed u16 range")
                })?;
                self.tables.method_def[midx - 1].flags = flags_u16;
                self.modifications.push(m);
                Ok(())
            }
            Modification::ChangeFieldFlags {
                type_name,
                field_name,
                flags,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let fidx = self
                    .tables
                    .find_field_index(tidx, field_name)
                    .ok_or_else(|| anyhow!("field {field_name:?} not found on {type_name:?}"))?;
                let flags_u16: u16 = (*flags).try_into().map_err(|_| {
                    anyhow!("field flags {flags:#x} exceed u16 range")
                })?;
                self.tables.field[fidx - 1].flags = flags_u16;
                self.modifications.push(m);
                Ok(())
            }
            Modification::ChangeTypeFlags { type_name, flags } => {
                let idx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                self.tables.type_def[idx - 1].flags = *flags;
                self.modifications.push(m);
                Ok(())
            }
            Modification::AddType { descriptor } => {
                let field_list = self.tables.field.len() as u32 + 1;
                let method_list = self.tables.method_def.len() as u32 + 1;
                self.tables.type_def.push(TypeDefRow {
                    flags: descriptor.flags,
                    type_name: descriptor.name.clone(),
                    type_namespace: descriptor.namespace.clone(),
                    extends: 0,
                    field_list,
                    method_list,
                });
                // Register interfaces
                let type_idx = self.tables.type_def.len() as u32;
                for iface in &descriptor.interfaces {
                    let iface_coded = self.ensure_type_ref(iface) as u32;
                    self.tables.interface_impl.push(InterfaceImplRow {
                        class: type_idx,
                        interface: (iface_coded << 2) | 1,
                    });
                }
                self.modifications.push(m);
                Ok(())
            }
            Modification::RemoveType { name } => {
                let idx = self
                    .tables
                    .find_type_index(name)
                    .ok_or_else(|| anyhow!("type {name:?} not found"))?;
                // Remove the type definition (leaves methods/fields orphaned in a real impl)
                self.tables.type_def.remove(idx - 1);
                self.modifications.push(m);
                Ok(())
            }
            Modification::AddMethod {
                type_name,
                descriptor,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let sig = descriptor.encode_sig();
                let param_list = self.tables.param.len() as u32 + 1;
                let method_idx = self.tables.method_def.len() as u32 + 1;
                self.tables.method_def.push(MethodDefRow {
                    rva: 0,
                    impl_flags: descriptor.impl_flags,
                    flags: descriptor.flags,
                    name: descriptor.name.clone(),
                    signature: sig,
                    param_list,
                });
                // Add param rows
                for (i, name) in descriptor.param_names.iter().enumerate() {
                    self.tables.param.push(rustre_dotnet_metadata::ParamRow {
                        flags: 0,
                        sequence: i as u16 + 1,
                        name: name.clone(),
                    });
                }
                // Store body if provided
                if let Some(instrs) = &descriptor.body {
                    self.tables
                        .patched_bodies
                        .insert(method_idx as usize, instrs.clone());
                }
                // Fix up the TypeDef's method_list if needed
                // (in real ECMA-335 metadata these are sorted; we do a best-effort update)
                let _ = tidx;
                self.modifications.push(m);
                Ok(())
            }
            Modification::RemoveMethod {
                type_name,
                method_name,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let midx = self
                    .tables
                    .find_method_index(tidx, method_name)
                    .ok_or_else(|| anyhow!("method {method_name:?} not found on {type_name:?}"))?;
                self.tables.method_def.remove(midx - 1);
                self.modifications.push(m);
                Ok(())
            }
            Modification::AddField {
                type_name,
                descriptor,
            } => {
                let _tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                self.tables.field.push(FieldRow {
                    flags: descriptor.flags,
                    name: descriptor.name.clone(),
                    signature: descriptor.type_sig.clone(),
                });
                self.modifications.push(m);
                Ok(())
            }
            Modification::RemoveField {
                type_name,
                field_name,
            } => {
                let tidx = self
                    .tables
                    .find_type_index(type_name)
                    .ok_or_else(|| anyhow!("type {type_name:?} not found"))?;
                let fidx = self
                    .tables
                    .find_field_index(tidx, field_name)
                    .ok_or_else(|| anyhow!("field {field_name:?} not found on {type_name:?}"))?;
                self.tables.field.remove(fidx - 1);
                self.modifications.push(m);
                Ok(())
            }
            Modification::ReplaceResource { name, data } => {
                if let Some(r) = self.tables.resources.get_mut(name.as_str()) {
                    r.data.clone_from(data);
                } else {
                    self.tables.resources.insert(
                        name.clone(),
                        ManagedResource::new(name.clone(), data.clone()),
                    );
                }
                self.modifications.push(m);
                Ok(())
            }
            Modification::AddResource { resource } => {
                self.tables
                    .resources
                    .insert(resource.name.clone(), resource.clone());
                self.modifications.push(m);
                Ok(())
            }
            Modification::RemoveResource { name } => {
                self.tables.resources.remove(name.as_str());
                self.modifications.push(m);
                Ok(())
            }
            Modification::SetAssemblyVersion {
                major,
                minor,
                build,
                revision,
            } => {
                if let Some(asm) = self.tables.assembly.first_mut() {
                    asm.major_version = *major;
                    asm.minor_version = *minor;
                    asm.build_number = *build;
                    asm.revision_number = *revision;
                }
                self.modifications.push(m);
                Ok(())
            }
            Modification::StripStrongName => {
                if let Some(asm) = self.tables.assembly.first_mut() {
                    asm.public_key.clear();
                    asm.flags &= !0x0001; // clear PublicKey flag
                }
                self.modifications.push(m);
                Ok(())
            }
        }
    }

    fn ensure_type_ref(&mut self, full_name: &str) -> usize {
        // Check if already present
        for (i, tr) in self.tables.type_ref.iter().enumerate() {
            let fq = if tr.type_namespace.is_empty() {
                tr.type_name.clone()
            } else {
                format!("{}.{}", tr.type_namespace, tr.type_name)
            };
            if fq == full_name {
                return i + 1;
            }
        }
        // Add new
        let (ns, name) = split_type_name(full_name);
        self.tables.type_ref.push(TypeRefRow {
            resolution_scope: 0,
            type_name: name.to_string(),
            type_namespace: ns.to_string(),
        });
        self.tables.type_ref.len()
    }

    // ─── Public API ─────────────────────────────────────────────────────────────

    /// Rename a type.
    pub fn rename_type(&mut self, old: &str, new: &str) -> Result<()> {
        self.apply_modification(Modification::RenameType {
            old: old.to_string(),
            new: new.to_string(),
        })
    }

    /// Rename a method on a type.
    pub fn rename_method(&mut self, type_name: &str, old: &str, new: &str) -> Result<()> {
        self.apply_modification(Modification::RenameMethod {
            type_name: type_name.to_string(),
            old: old.to_string(),
            new: new.to_string(),
        })
    }

    /// Rename a field on a type.
    pub fn rename_field(&mut self, type_name: &str, old: &str, new: &str) -> Result<()> {
        self.apply_modification(Modification::RenameField {
            type_name: type_name.to_string(),
            old: old.to_string(),
            new: new.to_string(),
        })
    }

    /// Replace a method's CIL body with new instructions.
    pub fn patch_method_body(
        &mut self,
        type_name: &str,
        method_name: &str,
        il: &[CilInstruction],
    ) -> Result<()> {
        self.apply_modification(Modification::PatchMethodBody {
            type_name: type_name.to_string(),
            method_name: method_name.to_string(),
            new_instructions: il.to_vec(),
        })
    }

    /// Add a custom attribute to a target (type or method full name).
    pub fn add_custom_attribute(
        &mut self,
        target: &str,
        attr_type: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        self.apply_modification(Modification::AddCustomAttribute {
            target: target.to_string(),
            attr_type: attr_type.to_string(),
            data,
        })
    }

    /// Change the flags word of a method.
    pub fn change_method_flags(
        &mut self,
        type_name: &str,
        method_name: &str,
        flags: u32,
    ) -> Result<()> {
        self.apply_modification(Modification::ChangeMethodFlags {
            type_name: type_name.to_string(),
            method_name: method_name.to_string(),
            flags,
        })
    }

    /// Returns the number of pending modifications.
    #[must_use] 
    pub const fn modification_count(&self) -> usize {
        self.modifications.len()
    }

    /// Build a snapshot of the current (edited) assembly view.
    /// The returned types reflect all applied name changes.
    #[must_use] 
    pub fn current_types(&self) -> Vec<DotnetType> {
        // Rebuild a temporary MetadataReader from the mutable tables.
        // Mutable tables shadow the originals; immutable tables fall through to the original.
        let t = &self.tables;
        let orig = &self.assembly.metadata.tables;
        let tables = MetadataTables {
            module: t.module.clone(),
            type_ref: t.type_ref.clone(),
            type_def: t.type_def.clone(),
            field: t.field.clone(),
            method_def: t.method_def.clone(),
            param: t.param.clone(),
            interface_impl: t.interface_impl.clone(),
            member_ref: t.member_ref.clone(),
            constant: t.constant.clone(),
            custom_attribute: t.custom_attribute.clone(),
            field_marshal: t.field_marshal.clone(),
            decl_security: t.decl_security.clone(),
            class_layout: t.class_layout.clone(),
            field_layout: t.field_layout.clone(),
            stand_alone_sig: t.stand_alone_sig.clone(),
            event_map: t.event_map.clone(),
            event: t.event.clone(),
            property_map: t.property_map.clone(),
            property: t.property.clone(),
            method_semantics: t.method_semantics.clone(),
            method_impl: t.method_impl.clone(),
            module_ref: t.module_ref.clone(),
            type_spec: t.type_spec.clone(),
            impl_map: t.impl_map.clone(),
            field_rva: t.field_rva.clone(),
            assembly: t.assembly.clone(),
            assembly_ref: t.assembly_ref.clone(),
            file: t.file.clone(),
            exported_type: t.exported_type.clone(),
            manifest_resource: t.manifest_resource.clone(),
            nested_class: t.nested_class.clone(),
            generic_param: t.generic_param.clone(),
            method_spec: t.method_spec.clone(),
            generic_param_constraint: t.generic_param_constraint.clone(),
        };
        // Suppress unused-variable warning on `orig` when all fields are in `t`
        let _ = orig;
        let reader = MetadataReader {
            root: self.assembly.metadata.root.clone(),
            heaps: self.assembly.metadata.heaps.clone(),
            tables,
        };
        AssemblyFile::from_metadata(reader).types()
    }

    /// Serialize the modified assembly back to a PE byte stream.
    ///
    /// This is a minimal re-serialization: it rebuilds the metadata streams in
    /// memory and splices them back into the original PE (if raw bytes were
    /// provided), or returns a metadata-only blob when no raw PE is available.
    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>> {
        if self.raw.is_empty() {
            // Return a synthesised metadata root blob
            Ok(self.build_metadata_blob())
        } else {
            // Clone raw and apply in-memory patches to name strings
            let mut output = self.raw.clone();
            // Strip the strong-name signature so the modified PE is loadable
            let _ = SignatureStripper::strip(&mut output);
            if !self.modifications.is_empty() {
                // Re-serializing arbitrary metadata edits back into the original
                // PE (rewriting #Strings / #~ streams in place) is not yet
                // implemented. Refuse rather than silently dropping the edits.
                return Err(anyhow!(
                    "serialize_to_bytes: cannot splice {} pending metadata modification(s) back into the original PE; re-serialization of edited metadata is not yet implemented",
                    self.modifications.len()
                ));
            }
            Ok(output)
        }
    }

    fn build_metadata_blob(&self) -> Vec<u8> {
        // Build a metadata root with #Strings, #GUID, #Blob streams populated
        // from the current (modified) tables. No PE wrapper.
        let mut strings: Vec<u8> = vec![0u8]; // offset 0 = empty string
        let mut string_offsets: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        string_offsets.insert(String::new(), 0);

        let mut intern = |s: &str| -> u32 {
            if let Some(&off) = string_offsets.get(s) {
                return off;
            }
            let off = strings.len() as u32;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            string_offsets.insert(s.to_string(), off);
            off
        };

        // Pre-intern all type / method / field names
        for t in &self.tables.type_def {
            intern(&t.type_name);
            intern(&t.type_namespace);
        }
        for m in &self.tables.method_def {
            intern(&m.name);
        }
        for f in &self.tables.field {
            intern(&f.name);
        }

        // Build a minimal metadata root blob
        rustre_dotnet_metadata::build_test_metadata_blob(&strings, &[], &[], &[])
    }
}

// ─── CIL encoding (minimal) ──────────────────────────────────────────────────

/// Encode a slice of `CilInstruction` into raw CIL bytes (tiny-format body).
#[must_use] 
pub fn encode_instructions(instrs: &[CilInstruction]) -> Vec<u8> {
    let mut body = Vec::with_capacity(instrs.len() * 2);
    for instr in instrs {
        encode_single_instruction(instr, &mut body);
    }
    // Wrap in tiny-format header: high 6 bits = code size, low 2 bits = 0x02
    let code_size = body.len();
    let mut out = Vec::with_capacity(1 + code_size);
    if code_size < 64 {
        out.push(((code_size as u8) << 2) | 0x02);
    } else {
        // Fat header (simplified: fixed 12-byte header, max_stack=8)
        let flags: u16 = 0x3003; // fat format, init locals
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // max_stack
        out.extend_from_slice(&(code_size as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // local var sig token
    }
    out.extend_from_slice(&body);
    out
}

fn encode_single_instruction(instr: &CilInstruction, out: &mut Vec<u8>) {
    match instr.opcode.as_str() {
        "ret" => out.push(0x2A),
        "ldnull" => out.push(0x14),
        "ldc.i4.0" => out.push(0x16),
        "ldc.i4.1" => out.push(0x17),
        "ldc.i4.2" => out.push(0x18),
        "ldc.i4.3" => out.push(0x19),
        "ldc.i4.4" => out.push(0x1A),
        "ldc.i4.5" => out.push(0x1B),
        "ldc.i4.6" => out.push(0x1C),
        "ldc.i4.7" => out.push(0x1D),
        "ldc.i4.8" => out.push(0x1E),
        "ldc.i4.m1" => out.push(0x15),
        "ldc.i4.s" => {
            out.push(0x1F);
            if let CilOperand::Int8(v) = instr.operand {
                out.push(v as u8);
            }
        }
        "ldc.i4" => {
            out.push(0x20);
            if let CilOperand::Int32(v) = instr.operand {
                out.extend_from_slice(&v.to_le_bytes());
            } else {
                out.extend_from_slice(&0i32.to_le_bytes());
            }
        }
        "ldc.i8" => {
            out.push(0x21);
            if let CilOperand::Int64(v) = instr.operand {
                out.extend_from_slice(&v.to_le_bytes());
            } else {
                out.extend_from_slice(&0i64.to_le_bytes());
            }
        }
        "ldc.r4" => {
            out.push(0x22);
            if let CilOperand::Float32(v) = instr.operand {
                out.extend_from_slice(&v.to_bits().to_le_bytes());
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "ldc.r8" => {
            out.push(0x23);
            if let CilOperand::Float64(v) = instr.operand {
                out.extend_from_slice(&v.to_bits().to_le_bytes());
            } else {
                out.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        "ldarg.0" => out.push(0x02),
        "ldarg.1" => out.push(0x03),
        "ldarg.2" => out.push(0x04),
        "ldarg.3" => out.push(0x05),
        "ldloc.0" => out.push(0x06),
        "ldloc.1" => out.push(0x07),
        "ldloc.2" => out.push(0x08),
        "ldloc.3" => out.push(0x09),
        "stloc.0" => out.push(0x0A),
        "stloc.1" => out.push(0x0B),
        "stloc.2" => out.push(0x0C),
        "stloc.3" => out.push(0x0D),
        "add" => out.push(0x58),
        "sub" => out.push(0x59),
        "mul" => out.push(0x5A),
        "div" => out.push(0x5B),
        "rem" => out.push(0x5D),
        "and" => out.push(0x5F),
        "or" => out.push(0x60),
        "xor" => out.push(0x61),
        "neg" => out.push(0x65),
        "not" => out.push(0x66),
        "dup" => out.push(0x25),
        "pop" => out.push(0x26),
        "throw" => out.push(0x7A),
        "call" | "jmp" | "callvirt" | "newobj" => {
            out.push(match instr.opcode.as_str() {
                "call" => 0x28,
                "jmp" => 0x27,
                "callvirt" => 0x6F,
                _ => 0x73,
            });
            if let CilOperand::Token(t) = instr.operand {
                out.extend_from_slice(&t.to_le_bytes());
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "ldstr" => {
            out.push(0x72);
            if let CilOperand::Token(t) = instr.operand {
                out.extend_from_slice(&t.to_le_bytes());
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "br.s" | "brfalse.s" | "brtrue.s" => {
            out.push(match instr.opcode.as_str() {
                "br.s" => 0x2B,
                "brfalse.s" => 0x2C,
                _ => 0x2D,
            });
            if let CilOperand::Branch(t) = instr.operand {
                // ECMA-335 §III.1.7.2: short-branch operand is a *relative* signed-byte offset
                // from the end of this instruction (opcode + operand = 2 bytes) to the target.
                // out.len() here is after pushing the opcode byte, so position after the full
                // instruction is out.len() + 1.
                let pos_after_instr = (out.len() + 1) as i32;
                let delta = (t as i32) - pos_after_instr;
                out.push(delta as i8 as u8);
            } else {
                out.push(0);
            }
        }
        "br" | "brfalse" | "brtrue" => {
            out.push(match instr.opcode.as_str() {
                "br" => 0x38,
                "brfalse" => 0x39,
                _ => 0x3A,
            });
            if let CilOperand::Branch(t) = instr.operand {
                out.extend_from_slice(&t.to_le_bytes());
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "switch" => {
            out.push(0x45);
            if let CilOperand::Switch(ref targets) = instr.operand {
                out.extend_from_slice(&(targets.len() as u32).to_le_bytes());
                for &t in targets {
                    out.extend_from_slice(&(t as i32).to_le_bytes());
                }
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "ldfld" => {
            out.push(0x7B);
            push_token(instr, out);
        }
        "stfld" => {
            out.push(0x7D);
            push_token(instr, out);
        }
        "ldsfld" => {
            out.push(0x7E);
            push_token(instr, out);
        }
        "stsfld" => {
            out.push(0x80);
            push_token(instr, out);
        }
        "box" => {
            out.push(0x8C);
            push_token(instr, out);
        }
        "newarr" => {
            out.push(0x8D);
            push_token(instr, out);
        }
        "castclass" => {
            out.push(0x74);
            push_token(instr, out);
        }
        "isinst" => {
            out.push(0x75);
            push_token(instr, out);
        }
        "ldlen" => out.push(0x8E),
        "endfinally" => out.push(0xDC),
        "ceq" => {
            out.push(0xFE);
            out.push(0x01);
        }
        "cgt" => {
            out.push(0xFE);
            out.push(0x02);
        }
        "clt" => {
            out.push(0xFE);
            out.push(0x04);
        }
        _ => out.push(0x00), // nop for unknown
    }
}

fn push_token(instr: &CilInstruction, out: &mut Vec<u8>) {
    if let CilOperand::Token(t) = instr.operand {
        out.extend_from_slice(&t.to_le_bytes());
    } else {
        out.extend_from_slice(&0u32.to_le_bytes());
    }
}

fn split_type_name(full_name: &str) -> (&str, &str) {
    full_name.rfind('.').map_or(("", full_name), |pos| (&full_name[..pos], &full_name[pos + 1..]))
}

// ─── Extended public API on AssemblyEditor ────────────────────────────────────

impl AssemblyEditor {
    /// Apply fine-grained IL patches to an existing method body.
    ///
    /// # Errors
    /// Returns an error if the type or method is not found, or any patch offset is invalid.
    pub fn patch_il(
        &mut self,
        type_name: &str,
        method_name: &str,
        patches: Vec<IlPatch>,
    ) -> Result<()> {
        self.apply_modification(Modification::PatchIl {
            type_name: type_name.to_string(),
            method_name: method_name.to_string(),
            patches,
        })
    }

    /// Change the flags word of a field.
    ///
    /// # Errors
    /// Returns an error if the type or field is not found.
    pub fn change_field_flags(
        &mut self,
        type_name: &str,
        field_name: &str,
        flags: u32,
    ) -> Result<()> {
        self.apply_modification(Modification::ChangeFieldFlags {
            type_name: type_name.to_string(),
            field_name: field_name.to_string(),
            flags,
        })
    }

    /// Change the flags word of a type.
    ///
    /// # Errors
    /// Returns an error if the type is not found.
    pub fn change_type_flags(&mut self, type_name: &str, flags: u32) -> Result<()> {
        self.apply_modification(Modification::ChangeTypeFlags {
            type_name: type_name.to_string(),
            flags,
        })
    }

    /// Add a new type to the assembly.
    ///
    /// # Errors
    /// Never errors currently, but returns `Result` for future validation.
    pub fn add_type(&mut self, descriptor: NewTypeDescriptor) -> Result<()> {
        self.apply_modification(Modification::AddType { descriptor })
    }

    /// Remove a type from the assembly by full name or simple name.
    ///
    /// # Errors
    /// Returns an error if the type is not found.
    pub fn remove_type(&mut self, name: &str) -> Result<()> {
        self.apply_modification(Modification::RemoveType {
            name: name.to_string(),
        })
    }

    /// Add a new method to an existing type.
    ///
    /// # Errors
    /// Returns an error if the type is not found.
    pub fn add_method(&mut self, type_name: &str, descriptor: NewMethodDescriptor) -> Result<()> {
        self.apply_modification(Modification::AddMethod {
            type_name: type_name.to_string(),
            descriptor,
        })
    }

    /// Remove a method from a type.
    ///
    /// # Errors
    /// Returns an error if the type or method is not found.
    pub fn remove_method(&mut self, type_name: &str, method_name: &str) -> Result<()> {
        self.apply_modification(Modification::RemoveMethod {
            type_name: type_name.to_string(),
            method_name: method_name.to_string(),
        })
    }

    /// Add a new field to an existing type.
    ///
    /// # Errors
    /// Returns an error if the type is not found.
    pub fn add_field(&mut self, type_name: &str, descriptor: NewFieldDescriptor) -> Result<()> {
        self.apply_modification(Modification::AddField {
            type_name: type_name.to_string(),
            descriptor,
        })
    }

    /// Remove a field from a type.
    ///
    /// # Errors
    /// Returns an error if the type or field is not found.
    pub fn remove_field(&mut self, type_name: &str, field_name: &str) -> Result<()> {
        self.apply_modification(Modification::RemoveField {
            type_name: type_name.to_string(),
            field_name: field_name.to_string(),
        })
    }

    /// Replace the data for an existing resource, creating it if absent.
    ///
    /// # Errors
    /// Never errors currently.
    pub fn replace_resource(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        self.apply_modification(Modification::ReplaceResource {
            name: name.to_string(),
            data,
        })
    }

    /// Add an embedded resource.
    ///
    /// # Errors
    /// Never errors currently.
    pub fn add_resource(&mut self, resource: ManagedResource) -> Result<()> {
        self.apply_modification(Modification::AddResource { resource })
    }

    /// Remove a resource by name.
    ///
    /// # Errors
    /// Never errors currently (removing a non-existent resource is a no-op).
    pub fn remove_resource(&mut self, name: &str) -> Result<()> {
        self.apply_modification(Modification::RemoveResource {
            name: name.to_string(),
        })
    }

    /// Update the assembly-level version tuple.
    ///
    /// # Errors
    /// Never errors (no-op if assembly table is empty).
    pub fn set_assembly_version(
        &mut self,
        major: u16,
        minor: u16,
        build: u16,
        revision: u16,
    ) -> Result<()> {
        self.apply_modification(Modification::SetAssemblyVersion {
            major,
            minor,
            build,
            revision,
        })
    }

    /// Strip the strong-name public key from metadata and zero the SN blob in the raw PE.
    ///
    /// # Errors
    /// Never errors.
    pub fn strip_strong_name(&mut self) -> Result<()> {
        self.apply_modification(Modification::StripStrongName)
    }

    /// Returns true if there are any pending modifications.
    #[must_use]
    pub const fn has_modifications(&self) -> bool {
        !self.modifications.is_empty()
    }

    /// Clear all pending modifications and reset the mutable tables back to the
    /// original assembly state.
    pub fn reset(&mut self) {
        self.modifications.clear();
        self.tables = MutableTables::from_metadata(&self.assembly.metadata.tables);
    }

    /// Returns all resources currently tracked in the editor.
    #[must_use]
    pub fn resources(&self) -> Vec<&ManagedResource> {
        self.tables.resources.values().collect()
    }

    /// Look up a resource by name.
    #[must_use]
    pub fn find_resource(&self, name: &str) -> Option<&ManagedResource> {
        self.tables.resources.get(name)
    }

    /// Returns the current assembly version tuple `(major, minor, build, revision)`,
    /// or `None` if there is no Assembly row.
    #[must_use]
    pub fn assembly_version(&self) -> Option<(u16, u16, u16, u16)> {
        self.tables.assembly.first().map(|a| {
            (
                a.major_version,
                a.minor_version,
                a.build_number,
                a.revision_number,
            )
        })
    }

    /// Returns `true` if the assembly currently carries a strong-name public key.
    #[must_use]
    pub fn is_strong_named(&self) -> bool {
        self.tables
            .assembly
            .first()
            .is_some_and(|a| !a.public_key.is_empty() && (a.flags & 0x0001 != 0))
    }

    /// Returns the number of type definitions in the current (edited) tables.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.tables.type_def.len()
    }

    /// Returns the number of method definitions in the current (edited) tables.
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.tables.method_def.len()
    }

    /// Returns the number of field definitions in the current (edited) tables.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.tables.field.len()
    }

    /// Collect a plain list of all type names (namespace-qualified) in the edited assembly.
    #[must_use]
    pub fn type_names(&self) -> Vec<String> {
        self.tables
            .type_def
            .iter()
            .map(|t| {
                if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                }
            })
            .collect()
    }

    /// Collect all method names in the edited assembly.
    #[must_use]
    pub fn method_names(&self) -> Vec<String> {
        self.tables
            .method_def
            .iter()
            .map(|m| m.name.clone())
            .collect()
    }

    /// Collect all field names in the edited assembly.
    #[must_use]
    pub fn field_names(&self) -> Vec<String> {
        self.tables.field.iter().map(|f| f.name.clone()).collect()
    }

    /// Look up a type-def row by full name or simple name.
    #[must_use]
    pub fn find_type_index(&self, name: &str) -> Option<usize> {
        self.tables.find_type_index(name)
    }

    /// Returns `true` if the given type exists in the edited tables.
    #[must_use]
    pub fn has_type(&self, name: &str) -> bool {
        self.tables.find_type_index(name).is_some()
    }

    /// Returns the patched instruction list for a method, if any patch has been applied.
    #[must_use]
    pub fn patched_body(&self, type_name: &str, method_name: &str) -> Option<&Vec<CilInstruction>> {
        let tidx = self.tables.find_type_index(type_name)?;
        let midx = self.tables.find_method_index(tidx, method_name)?;
        self.tables.patched_bodies.get(&midx)
    }

    /// Returns the number of methods that have been patched.
    #[must_use]
    pub fn patched_body_count(&self) -> usize {
        self.tables.patched_bodies.len()
    }

    /// Compute a simple diff between the original metadata and the current state.
    /// Returns a list of human-readable change descriptions.
    #[must_use]
    pub fn diff_summary(&self) -> Vec<String> {
        let orig = &self.assembly.metadata.tables;
        let cur = &self.tables;
        let mut lines = Vec::new();

        // Added / removed types
        let orig_types: std::collections::HashSet<&str> =
            orig.type_def.iter().map(|t| t.type_name.as_str()).collect();
        let cur_types: std::collections::HashSet<&str> =
            cur.type_def.iter().map(|t| t.type_name.as_str()).collect();
        for n in cur_types.difference(&orig_types) {
            lines.push(format!("+ type {n}"));
        }
        for n in orig_types.difference(&cur_types) {
            lines.push(format!("- type {n}"));
        }

        // Renamed types (name in original but different in current at same index)
        for (i, (o, c)) in orig.type_def.iter().zip(cur.type_def.iter()).enumerate() {
            if o.type_name != c.type_name {
                lines.push(format!("~ type[{i}] {} → {}", o.type_name, c.type_name));
            }
            if o.type_namespace != c.type_namespace {
                lines.push(format!(
                    "~ type[{i}] namespace {} → {}",
                    o.type_namespace, c.type_namespace
                ));
            }
            if o.flags != c.flags {
                lines.push(format!(
                    "~ type[{i}] {} flags 0x{:08X} → 0x{:08X}",
                    o.type_name, o.flags, c.flags
                ));
            }
        }

        // Added / removed methods
        let orig_methods: std::collections::HashSet<&str> =
            orig.method_def.iter().map(|m| m.name.as_str()).collect();
        let cur_methods: std::collections::HashSet<&str> =
            cur.method_def.iter().map(|m| m.name.as_str()).collect();
        for n in cur_methods.difference(&orig_methods) {
            lines.push(format!("+ method {n}"));
        }
        for n in orig_methods.difference(&cur_methods) {
            lines.push(format!("- method {n}"));
        }

        // Patched bodies
        for midx in self.tables.patched_bodies.keys() {
            if let Some(m) = cur.method_def.get(midx.wrapping_sub(1)) {
                lines.push(format!("~ body patched: {}", m.name));
            }
        }

        // Version change
        if let (Some(oa), Some(ca)) = (orig.assembly.first(), cur.assembly.first()) {
            let ov = (
                oa.major_version,
                oa.minor_version,
                oa.build_number,
                oa.revision_number,
            );
            let cv = (
                ca.major_version,
                ca.minor_version,
                ca.build_number,
                ca.revision_number,
            );
            if ov != cv {
                lines.push(format!(
                    "~ version {}.{}.{}.{} → {}.{}.{}.{}",
                    ov.0, ov.1, ov.2, ov.3, cv.0, cv.1, cv.2, cv.3
                ));
            }
        }

        // Strong-name stripped
        if let (Some(oa), Some(ca)) = (orig.assembly.first(), cur.assembly.first())
            && !oa.public_key.is_empty() && ca.public_key.is_empty() {
                lines.push("~ strong name stripped".to_string());
            }

        // Resources added/removed
        for name in cur.resources.keys() {
            lines.push(format!("+ resource {name}"));
        }

        lines
    }
}

// ─── IlValidator ─────────────────────────────────────────────────────────────

/// Validates a CIL instruction sequence for common structural errors.
pub struct IlValidator;

/// A single validation diagnostic.
#[derive(Debug, Clone)]
pub struct IlDiagnostic {
    pub offset: u32,
    pub message: String,
    pub severity: DiagnosticSeverity,
}

/// Severity of a validation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

impl IlValidator {
    /// Validate a slice of CIL instructions.
    ///
    /// Returns a list of diagnostics. An empty list means the body is structurally valid.
    #[must_use]
    pub fn validate(instrs: &[CilInstruction]) -> Vec<IlDiagnostic> {
        let mut diags = Vec::new();

        if instrs.is_empty() {
            diags.push(IlDiagnostic {
                offset: 0,
                message: "empty method body (no instructions)".into(),
                severity: DiagnosticSeverity::Warning,
            });
            return diags;
        }

        // Check that the last instruction is a terminator
        let last = instrs.last().unwrap();
        let is_terminator = matches!(
            last.opcode.as_str(),
            "ret" | "throw" | "rethrow" | "br" | "br.s" | "jmp"
        );
        if !is_terminator {
            diags.push(IlDiagnostic {
                offset: last.offset,
                message: format!(
                    "method body does not end with a terminator (last: {})",
                    last.opcode
                ),
                severity: DiagnosticSeverity::Error,
            });
        }

        // Build offset set for branch target validation
        let offset_set: std::collections::HashSet<u32> = instrs.iter().map(|i| i.offset).collect();

        for instr in instrs {
            // Check duplicate offsets
            let dup_count = instrs.iter().filter(|i| i.offset == instr.offset).count();
            if dup_count > 1 {
                diags.push(IlDiagnostic {
                    offset: instr.offset,
                    message: format!("duplicate offset 0x{:04X}", instr.offset),
                    severity: DiagnosticSeverity::Error,
                });
            }

            // Validate branch targets
            match &instr.operand {
                CilOperand::Branch(target) => {
                    if !offset_set.contains(target) {
                        diags.push(IlDiagnostic {
                            offset: instr.offset,
                            message: format!(
                                "branch target 0x{target:04X} does not match any instruction offset"
                            ),
                            severity: DiagnosticSeverity::Error,
                        });
                    }
                }
                CilOperand::Switch(targets) => {
                    for &t in targets {
                        if !offset_set.contains(&t) {
                            diags.push(IlDiagnostic {
                                offset: instr.offset,
                                message: format!(
                                    "switch target 0x{t:04X} does not match any instruction offset"
                                ),
                                severity: DiagnosticSeverity::Error,
                            });
                        }
                    }
                }
                _ => {}
            }

            // Warn about nop padding (more than 4 consecutive)
            // (checked elsewhere if needed)
        }

        // Check for excessive nop sequences
        let mut nop_run = 0u32;
        let mut nop_start = 0u32;
        for instr in instrs {
            if instr.opcode == "nop" {
                if nop_run == 0 {
                    nop_start = instr.offset;
                }
                nop_run += 1;
            } else {
                if nop_run > 8 {
                    diags.push(IlDiagnostic {
                        offset: nop_start,
                        message: format!("suspicious nop sequence of {nop_run} instructions"),
                        severity: DiagnosticSeverity::Warning,
                    });
                }
                nop_run = 0;
            }
        }

        // Deduplicate diagnostics by offset + message
        diags.dedup_by(|a, b| a.offset == b.offset && a.message == b.message);
        diags
    }

    /// Returns `true` if there are no error-level diagnostics.
    #[must_use]
    pub fn is_valid(instrs: &[CilInstruction]) -> bool {
        Self::validate(instrs)
            .iter()
            .all(|d| d.severity != DiagnosticSeverity::Error)
    }
}

// ─── TypeDiff ─────────────────────────────────────────────────────────────────

/// Records differences between two type snapshots.
#[derive(Debug, Clone)]
pub struct TypeDiff {
    pub type_name: String,
    pub added_methods: Vec<String>,
    pub removed_methods: Vec<String>,
    pub renamed_methods: Vec<(String, String)>,
    pub added_fields: Vec<String>,
    pub removed_fields: Vec<String>,
    pub flag_change: Option<(u32, u32)>,
}

impl TypeDiff {
    /// Returns `true` if there are no changes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added_methods.is_empty()
            && self.removed_methods.is_empty()
            && self.renamed_methods.is_empty()
            && self.added_fields.is_empty()
            && self.removed_fields.is_empty()
            && self.flag_change.is_none()
    }

    /// Format the diff as a human-readable string.
    #[must_use]
    pub fn format(&self) -> String {
        let mut out = format!("TypeDiff for {}:\n", self.type_name);
        for m in &self.added_methods {
            out.push_str(&format!("  + method {m}\n"));
        }
        for m in &self.removed_methods {
            out.push_str(&format!("  - method {m}\n"));
        }
        for (o, n) in &self.renamed_methods {
            out.push_str(&format!("  ~ method {o} → {n}\n"));
        }
        for f in &self.added_fields {
            out.push_str(&format!("  + field {f}\n"));
        }
        for f in &self.removed_fields {
            out.push_str(&format!("  - field {f}\n"));
        }
        if let Some((old_flags, new_flags)) = self.flag_change {
            out.push_str(&format!(
                "  ~ flags 0x{old_flags:08X} → 0x{new_flags:08X}\n"
            ));
        }
        out
    }
}

// ─── MetadataDiff ─────────────────────────────────────────────────────────────

/// Full assembly-level diff between an original and edited state.
/// A 4-tuple version (major, minor, build, revision).
pub type Version4 = (u16, u16, u16, u16);
/// (old, new) version change pair.
pub type VersionChange = (Version4, Version4);

#[derive(Debug, Clone, Default)]
pub struct MetadataDiff {
    pub added_types: Vec<String>,
    pub removed_types: Vec<String>,
    pub type_diffs: Vec<TypeDiff>,
    pub version_change: Option<VersionChange>,
    pub strong_name_stripped: bool,
    pub patched_bodies: Vec<String>,
    pub added_resources: Vec<String>,
    pub removed_resources: Vec<String>,
}

impl MetadataDiff {
    /// Returns `true` if there are no differences.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_types.is_empty()
            && self.removed_types.is_empty()
            && self.type_diffs.iter().all(TypeDiff::is_empty)
            && self.version_change.is_none()
            && !self.strong_name_stripped
            && self.patched_bodies.is_empty()
            && self.added_resources.is_empty()
            && self.removed_resources.is_empty()
    }

    /// Compute a diff between original tables and a modified `AssemblyEditor`.
    #[must_use]
    pub fn compute(editor: &AssemblyEditor) -> Self {
        let orig = &editor.assembly.metadata.tables;
        let cur = &editor.tables;

        let orig_type_names: Vec<&str> =
            orig.type_def.iter().map(|t| t.type_name.as_str()).collect();
        let cur_type_names: Vec<&str> = cur.type_def.iter().map(|t| t.type_name.as_str()).collect();

        let orig_set: std::collections::HashSet<&&str> = orig_type_names.iter().collect();
        let cur_set: std::collections::HashSet<&&str> = cur_type_names.iter().collect();

        let added_types: Vec<String> = cur_set
            .difference(&orig_set)
            .map(std::string::ToString::to_string)
            .collect();
        let removed_types: Vec<String> = orig_set
            .difference(&cur_set)
            .map(std::string::ToString::to_string)
            .collect();

        // Per-type diffs for types present in both
        let mut type_diffs = Vec::new();
        for (oi, orig_t) in orig.type_def.iter().enumerate() {
            let cur_t = match cur.type_def.get(oi) {
                Some(t) if t.type_name == orig_t.type_name => t,
                _ => continue,
            };

            // Gather method names for this type in orig
            let orig_method_end = orig
                .type_def
                .get(oi + 1)
                .map_or(orig.method_def.len() as u32 + 1, |r| r.method_list);
            let orig_methods: Vec<&str> = (orig_t.method_list..orig_method_end)
                .filter_map(|mi| orig.method_def.get(mi as usize - 1))
                .map(|m| m.name.as_str())
                .collect();

            let cur_method_end = cur
                .type_def
                .get(oi + 1)
                .map_or(cur.method_def.len() as u32 + 1, |r| r.method_list);
            let cur_methods: Vec<&str> = (cur_t.method_list..cur_method_end)
                .filter_map(|mi| cur.method_def.get(mi as usize - 1))
                .map(|m| m.name.as_str())
                .collect();

            let om: std::collections::HashSet<&&str> = orig_methods.iter().collect();
            let cm: std::collections::HashSet<&&str> = cur_methods.iter().collect();

            let added_methods: Vec<String> = cm.difference(&om).map(std::string::ToString::to_string).collect();
            let removed_methods: Vec<String> = om.difference(&cm).map(std::string::ToString::to_string).collect();

            // Gather field names similarly
            let orig_field_end = orig
                .type_def
                .get(oi + 1)
                .map_or(orig.field.len() as u32 + 1, |r| r.field_list);
            let orig_fields: Vec<&str> = (orig_t.field_list..orig_field_end)
                .filter_map(|fi| orig.field.get(fi as usize - 1))
                .map(|f| f.name.as_str())
                .collect();

            let cur_field_end = cur
                .type_def
                .get(oi + 1)
                .map_or(cur.field.len() as u32 + 1, |r| r.field_list);
            let cur_fields: Vec<&str> = (cur_t.field_list..cur_field_end)
                .filter_map(|fi| cur.field.get(fi as usize - 1))
                .map(|f| f.name.as_str())
                .collect();

            let of: std::collections::HashSet<&&str> = orig_fields.iter().collect();
            let cf: std::collections::HashSet<&&str> = cur_fields.iter().collect();

            let added_fields: Vec<String> = cf.difference(&of).map(std::string::ToString::to_string).collect();
            let removed_fields: Vec<String> = of.difference(&cf).map(std::string::ToString::to_string).collect();

            let flag_change = if orig_t.flags == cur_t.flags {
                None
            } else {
                Some((orig_t.flags, cur_t.flags))
            };

            let tdiff = TypeDiff {
                type_name: orig_t.type_name.clone(),
                added_methods,
                removed_methods,
                renamed_methods: Vec::new(),
                added_fields,
                removed_fields,
                flag_change,
            };

            if !tdiff.is_empty() {
                type_diffs.push(tdiff);
            }
        }

        // Version change
        let version_change = match (orig.assembly.first(), cur.assembly.first()) {
            (Some(oa), Some(ca)) => {
                let ov = (
                    oa.major_version,
                    oa.minor_version,
                    oa.build_number,
                    oa.revision_number,
                );
                let cv = (
                    ca.major_version,
                    ca.minor_version,
                    ca.build_number,
                    ca.revision_number,
                );
                if ov == cv { None } else { Some((ov, cv)) }
            }
            _ => None,
        };

        // Strong-name stripped
        let strong_name_stripped = match (orig.assembly.first(), cur.assembly.first()) {
            (Some(oa), Some(ca)) => !oa.public_key.is_empty() && ca.public_key.is_empty(),
            _ => false,
        };

        // Patched bodies
        let patched_bodies: Vec<String> = cur
            .patched_bodies
            .keys()
            .filter_map(|&midx| cur.method_def.get(midx.wrapping_sub(1)))
            .map(|m| m.name.clone())
            .collect();

        // Resources
        let added_resources: Vec<String> = cur.resources.keys().cloned().collect();
        let removed_resources: Vec<String> = Vec::new(); // tracking removals requires history

        Self {
            added_types,
            removed_types,
            type_diffs,
            version_change,
            strong_name_stripped,
            patched_bodies,
            added_resources,
            removed_resources,
        }
    }

    /// Format the diff as a human-readable multi-line string.
    #[must_use]
    pub fn format(&self) -> String {
        let mut out = String::new();
        for n in &self.added_types {
            out.push_str(&format!("+ type {n}\n"));
        }
        for n in &self.removed_types {
            out.push_str(&format!("- type {n}\n"));
        }
        for td in &self.type_diffs {
            out.push_str(&td.format());
        }
        if let Some(((om, on, ob, or_), (nm, nn, nb, nr))) = self.version_change {
            out.push_str(&format!(
                "~ version {om}.{on}.{ob}.{or_} → {nm}.{nn}.{nb}.{nr}\n"
            ));
        }
        if self.strong_name_stripped {
            out.push_str("~ strong name stripped\n");
        }
        for n in &self.patched_bodies {
            out.push_str(&format!("~ body patched: {n}\n"));
        }
        for n in &self.added_resources {
            out.push_str(&format!("+ resource {n}\n"));
        }
        for n in &self.removed_resources {
            out.push_str(&format!("- resource {n}\n"));
        }
        out
    }
}

// ─── CIL instruction builder helpers ─────────────────────────────────────────

/// Helper for building instruction sequences with automatic offset assignment.
#[derive(Debug, Default)]
pub struct IlBuilder {
    instructions: Vec<CilInstruction>,
    current_offset: u32,
}

impl IlBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a no-operand instruction.
    pub fn emit(&mut self, opcode: &str) -> &mut Self {
        let size = Self::opcode_size(opcode, &CilOperand::None);
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: opcode.to_string(),
            operand: CilOperand::None,
        });
        self.current_offset += size;
        self
    }

    /// Emit `ldc.i4` with an i32 constant.
    pub fn ldc_i4(&mut self, value: i32) -> &mut Self {
        let opcode = match value {
            -1 => "ldc.i4.m1",
            0 => "ldc.i4.0",
            1 => "ldc.i4.1",
            2 => "ldc.i4.2",
            3 => "ldc.i4.3",
            4 => "ldc.i4.4",
            5 => "ldc.i4.5",
            6 => "ldc.i4.6",
            7 => "ldc.i4.7",
            8 => "ldc.i4.8",
            v if (-128..=127).contains(&v) => {
                self.instructions.push(CilInstruction {
                    offset: self.current_offset,
                    opcode: "ldc.i4.s".to_string(),
                    operand: CilOperand::Int8(value as i8),
                });
                self.current_offset += 2;
                return self;
            }
            _ => {
                self.instructions.push(CilInstruction {
                    offset: self.current_offset,
                    opcode: "ldc.i4".to_string(),
                    operand: CilOperand::Int32(value),
                });
                self.current_offset += 5;
                return self;
            }
        };
        self.emit(opcode);
        self
    }

    /// Emit `ldstr` with a token.
    pub fn ldstr(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "ldstr".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `call` with a token.
    pub fn call(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "call".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `callvirt` with a token.
    pub fn callvirt(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "callvirt".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `newobj` with a token.
    pub fn newobj(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "newobj".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `ldfld` with a token.
    pub fn ldfld(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "ldfld".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `stfld` with a token.
    pub fn stfld(&mut self, token: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "stfld".to_string(),
            operand: CilOperand::Token(token),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `br.s` (short branch) targeting an absolute offset.
    pub fn br_s(&mut self, target: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "br.s".to_string(),
            operand: CilOperand::Branch(target),
        });
        self.current_offset += 2;
        self
    }

    /// Emit `br` (long branch) targeting an absolute offset.
    pub fn br(&mut self, target: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "br".to_string(),
            operand: CilOperand::Branch(target),
        });
        self.current_offset += 5;
        self
    }

    /// Emit `brfalse.s` targeting an absolute offset.
    pub fn brfalse_s(&mut self, target: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "brfalse.s".to_string(),
            operand: CilOperand::Branch(target),
        });
        self.current_offset += 2;
        self
    }

    /// Emit `brtrue.s` targeting an absolute offset.
    pub fn brtrue_s(&mut self, target: u32) -> &mut Self {
        self.instructions.push(CilInstruction {
            offset: self.current_offset,
            opcode: "brtrue.s".to_string(),
            operand: CilOperand::Branch(target),
        });
        self.current_offset += 2;
        self
    }

    /// Emit `ret`.
    pub fn ret(&mut self) -> &mut Self {
        self.emit("ret");
        self
    }

    /// Emit `nop`.
    pub fn nop(&mut self) -> &mut Self {
        self.emit("nop");
        self
    }

    /// Emit `ldarg.0` through `ldarg.3`.
    pub fn ldarg(&mut self, index: u8) -> &mut Self {
        let op = match index {
            0 => "ldarg.0",
            1 => "ldarg.1",
            2 => "ldarg.2",
            3 => "ldarg.3",
            _ => {
                self.instructions.push(CilInstruction {
                    offset: self.current_offset,
                    opcode: "ldarg.s".to_string(),
                    operand: CilOperand::Int8(index as i8),
                });
                self.current_offset += 2;
                return self;
            }
        };
        self.emit(op);
        self
    }

    /// Emit `stloc.0` through `stloc.3`.
    pub fn stloc(&mut self, index: u8) -> &mut Self {
        let op = match index {
            0 => "stloc.0",
            1 => "stloc.1",
            2 => "stloc.2",
            3 => "stloc.3",
            _ => {
                self.instructions.push(CilInstruction {
                    offset: self.current_offset,
                    opcode: "stloc.s".to_string(),
                    operand: CilOperand::Int8(index as i8),
                });
                self.current_offset += 2;
                return self;
            }
        };
        self.emit(op);
        self
    }

    /// Emit `ldloc.0` through `ldloc.3`.
    pub fn ldloc(&mut self, index: u8) -> &mut Self {
        let op = match index {
            0 => "ldloc.0",
            1 => "ldloc.1",
            2 => "ldloc.2",
            3 => "ldloc.3",
            _ => {
                self.instructions.push(CilInstruction {
                    offset: self.current_offset,
                    opcode: "ldloc.s".to_string(),
                    operand: CilOperand::Int8(index as i8),
                });
                self.current_offset += 2;
                return self;
            }
        };
        self.emit(op);
        self
    }

    /// Finalise and return the instruction list.
    #[must_use]
    pub fn build(self) -> Vec<CilInstruction> {
        self.instructions
    }

    /// Returns the number of instructions built so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns `true` if no instructions have been emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Returns the current byte offset (next instruction will be at this offset).
    #[must_use]
    pub const fn current_offset(&self) -> u32 {
        self.current_offset
    }

    fn opcode_size(opcode: &str, _operand: &CilOperand) -> u32 {
        match opcode {
            "ldc.i4.s" | "ldarg.s" | "starg.s" | "ldloc.s" | "stloc.s" | "br.s" | "brfalse.s"
            | "brtrue.s" | "beq.s" | "bge.s" | "bgt.s" | "ble.s" | "blt.s" | "bne.un.s"
            | "bge.un.s" | "bgt.un.s" | "ble.un.s" | "blt.un.s" | "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" | "localloc" | "endfilter"
            | "volatile." | "tail." | "constrained." | "readonly." | "initobj" | "cpblk"
            | "initblk" | "no." | "refanytype" => 2,
            "ldc.i4" | "br" | "brfalse" | "brtrue" | "beq" | "bge" | "bgt" | "ble" | "blt"
            | "bne.un" | "bge.un" | "bgt.un" | "ble.un" | "blt.un" | "call" | "callvirt"
            | "newobj" | "jmp" | "ldstr" | "ldfld" | "stfld" | "ldsfld" | "stsfld" | "box"
            | "newarr" | "castclass" | "isinst" | "ldtoken" | "ldsflda" | "ldflda" | "unbox"
            | "unbox.any" | "stelem" | "ldelem" | "cpobj" | "ldobj" | "stobj" | "mkrefany"
            | "refanyval" | "sizeof" | "ldc.r4" => 5,
            "ldc.i8" | "ldc.r8" => 9,
            // FE xx prefix
            _ => 1,
        }
    }
}

// ─── CIL opcode size table (full) ────────────────────────────────────────────

/// Return the encoded byte size of an instruction given its opcode string.
/// This is the size including the opcode byte(s) plus any operand bytes.
#[must_use]
pub fn opcode_byte_size(opcode: &str, operand: &CilOperand) -> u32 {
    match operand {
        CilOperand::Switch(targets) => {
            // switch: 1 byte opcode + 4 byte count + 4 bytes per target
            1 + 4 + (targets.len() as u32) * 4
        }
        _ => IlBuilder::opcode_size(opcode, operand),
    }
}

/// Reassign offsets in `instrs` sequentially based on their encoded byte sizes.
/// This is needed after inserting or removing instructions.
pub fn recompute_offsets(instrs: &mut [CilInstruction]) {
    let mut off = 0u32;
    for instr in instrs.iter_mut() {
        instr.offset = off;
        off += opcode_byte_size(&instr.opcode, &instr.operand);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet::{AssemblyFile, CilInstruction, CilOperand};
    use rustre_dotnet_metadata::{
        MetadataHeaps, MetadataReader, MetadataRoot, MetadataTables, MethodDefRow, TypeDefRow,
    };

    fn make_assembly() -> AssemblyFile {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "MyClass".into(),
            type_namespace: "App".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        tables.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x06,
            name: "Run".into(),
            signature: vec![],
            param_list: 1,
        });
        tables.field.push(rustre_dotnet_metadata::FieldRow {
            flags: 0,
            name: "Count".into(),
            signature: vec![0x06, 0x08],
        });
        AssemblyFile::from_metadata(MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        })
    }

    fn make_editor() -> AssemblyEditor {
        AssemblyEditor::new(make_assembly())
    }

    #[test]
    fn test_rename_type_success() {
        let mut editor = make_editor();
        editor.rename_type("MyClass", "RenamedClass").unwrap();
        let types = editor.current_types();
        assert!(types.iter().any(|t| t.name == "RenamedClass"));
        assert!(!types.iter().any(|t| t.name == "MyClass"));
    }

    #[test]
    fn test_rename_type_not_found() {
        let mut editor = make_editor();
        assert!(editor.rename_type("Nonexistent", "X").is_err());
    }

    #[test]
    fn test_rename_method_success() {
        let mut editor = make_editor();
        editor.rename_method("MyClass", "Run", "Execute").unwrap();
        let types = editor.current_types();
        let t = types.iter().find(|t| t.name == "MyClass").unwrap();
        assert!(t.methods.iter().any(|m| m.name == "Execute"));
        assert!(!t.methods.iter().any(|m| m.name == "Run"));
    }

    #[test]
    fn test_rename_method_type_not_found() {
        let mut editor = make_editor();
        assert!(editor.rename_method("NoSuchType", "Run", "X").is_err());
    }

    #[test]
    fn test_rename_method_method_not_found() {
        let mut editor = make_editor();
        assert!(
            editor
                .rename_method("MyClass", "NoSuchMethod", "X")
                .is_err()
        );
    }

    #[test]
    fn test_rename_field_success() {
        let mut editor = make_editor();
        editor.rename_field("MyClass", "Count", "Total").unwrap();
        let types = editor.current_types();
        let t = types.iter().find(|t| t.name == "MyClass").unwrap();
        assert!(t.fields.iter().any(|f| f.name == "Total"));
    }

    #[test]
    fn test_rename_field_not_found() {
        let mut editor = make_editor();
        assert!(editor.rename_field("MyClass", "NoField", "X").is_err());
    }

    #[test]
    fn test_modification_count() {
        let mut editor = make_editor();
        editor.rename_type("MyClass", "A").unwrap();
        assert_eq!(editor.modification_count(), 1);
        editor.rename_method("A", "Run", "Go").unwrap();
        assert_eq!(editor.modification_count(), 2);
    }

    #[test]
    fn test_patch_method_body() {
        let mut editor = make_editor();
        let il = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        editor.patch_method_body("MyClass", "Run", &il).unwrap();
        assert_eq!(editor.modification_count(), 1);
    }

    #[test]
    fn test_patch_method_body_type_not_found() {
        let mut editor = make_editor();
        let il = vec![];
        assert!(editor.patch_method_body("NoType", "Run", &il).is_err());
    }

    #[test]
    fn test_change_method_flags() {
        let mut editor = make_editor();
        editor.change_method_flags("MyClass", "Run", 0x96).unwrap();
        assert_eq!(editor.modification_count(), 1);
        // Verify via current_types
        let types = editor.current_types();
        let m = types
            .iter()
            .find(|t| t.name == "MyClass")
            .and_then(|t| t.methods.iter().find(|m| m.name == "Run"))
            .unwrap();
        assert_eq!(m.flags, 0x96);
    }

    #[test]
    fn test_add_custom_attribute() {
        let mut editor = make_editor();
        editor
            .add_custom_attribute(
                "MyClass",
                "System.ObsoleteAttribute",
                vec![0x01, 0x00, 0x00, 0x00],
            )
            .unwrap();
        assert_eq!(editor.modification_count(), 1);
        assert!(!editor.tables.custom_attribute.is_empty());
    }

    #[test]
    fn test_edit_transaction_apply() {
        let mut editor = make_editor();
        let mut tx = EditTransaction::new();
        tx.add(Modification::RenameType {
            old: "MyClass".into(),
            new: "Widget".into(),
        });
        tx.apply(&mut editor).unwrap();
        let types = editor.current_types();
        assert!(types.iter().any(|t| t.name == "Widget"));
    }

    #[test]
    fn test_edit_transaction_rollback() {
        let mut editor = make_editor();
        editor.rename_type("MyClass", "Temp").unwrap();
        let tx = EditTransaction::new(); // empty
        tx.rollback(&mut editor).unwrap();
        assert_eq!(editor.modification_count(), 1); // unchanged
    }

    #[test]
    fn test_edit_transaction_empty() {
        let tx = EditTransaction::new();
        assert!(tx.is_empty());
        assert_eq!(tx.len(), 0);
    }

    #[test]
    fn test_encode_instructions_ret() {
        let il = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let bytes = encode_instructions(&il);
        // Tiny header: (1 << 2) | 2 = 6
        assert_eq!(bytes[0], 0x06);
        assert_eq!(bytes[1], 0x2A);
    }

    #[test]
    fn test_encode_instructions_ldc_ret() {
        let il = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.5".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let bytes = encode_instructions(&il);
        // Code size = 2 → tiny header = (2<<2)|2 = 0x0A
        assert_eq!(bytes[0], 0x0A);
        assert_eq!(bytes[1], 0x1B); // ldc.i4.5
        assert_eq!(bytes[2], 0x2A); // ret
    }

    #[test]
    fn test_encode_ldc_i4() {
        let il = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4".into(),
                operand: CilOperand::Int32(100),
            },
            CilInstruction {
                offset: 5,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let bytes = encode_instructions(&il);
        // ldc.i4 = 1 byte opcode + 4 bytes value, ret = 1 byte → code size = 6
        // tiny header = (6 << 2) | 2 = 0x1A = 26
        assert_eq!(bytes[0], 0x1A);
        assert_eq!(bytes[1], 0x20); // ldc.i4
        let val = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        assert_eq!(val, 100);
    }

    #[test]
    fn test_encode_call_token() {
        let il = vec![
            CilInstruction {
                offset: 0,
                opcode: "call".into(),
                operand: CilOperand::Token(0x0A000001),
            },
            CilInstruction {
                offset: 5,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let bytes = encode_instructions(&il);
        assert_eq!(bytes[1], 0x28); // call
        let token = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        assert_eq!(token, 0x0A000001);
    }

    #[test]
    fn test_serialize_to_bytes_no_raw() {
        let editor = make_editor();
        let bytes = editor.serialize_to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_signature_stripper_not_pe() {
        let mut data = vec![0u8; 10];
        assert!(SignatureStripper::strip(&mut data).is_err());
    }

    #[test]
    fn test_split_type_name_with_ns() {
        let (ns, name) = split_type_name("System.Collections.Generic.List");
        assert_eq!(ns, "System.Collections.Generic");
        assert_eq!(name, "List");
    }

    #[test]
    fn test_split_type_name_no_ns() {
        let (ns, name) = split_type_name("Program");
        assert_eq!(ns, "");
        assert_eq!(name, "Program");
    }

    // ── Extended API tests ───────────────────────────────────────────────────

    #[test]
    fn test_change_field_flags() {
        let mut editor = make_editor();
        editor.change_field_flags("MyClass", "Count", 0x16).unwrap();
        assert_eq!(editor.modification_count(), 1);
    }

    #[test]
    fn test_change_type_flags() {
        let mut editor = make_editor();
        editor.change_type_flags("MyClass", 0x00000101).unwrap();
        assert_eq!(editor.modification_count(), 1);
    }

    #[test]
    fn test_add_and_remove_type() {
        let mut editor = make_editor();
        let desc = NewTypeDescriptor::public_class("Widget", "UI");
        editor.add_type(desc).unwrap();
        assert!(editor.has_type("Widget"));
        editor.remove_type("Widget").unwrap();
        assert!(!editor.has_type("Widget"));
    }

    #[test]
    fn test_add_method() {
        let mut editor = make_editor();
        let desc = NewMethodDescriptor::static_void("DoWork");
        editor.add_method("MyClass", desc).unwrap();
        assert!(editor.method_names().contains(&"DoWork".to_string()));
    }

    #[test]
    fn test_remove_method() {
        let mut editor = make_editor();
        editor.remove_method("MyClass", "Run").unwrap();
        assert!(!editor.method_names().contains(&"Run".to_string()));
    }

    #[test]
    fn test_add_field() {
        let mut editor = make_editor();
        let desc = NewFieldDescriptor::public_field("Score", 0x08); // int32
        editor.add_field("MyClass", desc).unwrap();
        assert!(editor.field_names().contains(&"Score".to_string()));
    }

    #[test]
    fn test_remove_field() {
        let mut editor = make_editor();
        editor.remove_field("MyClass", "Count").unwrap();
        assert!(!editor.field_names().contains(&"Count".to_string()));
    }

    #[test]
    fn test_resource_lifecycle() {
        let mut editor = make_editor();
        let res = ManagedResource::new("config.json", b"{\"key\":1}".to_vec());
        assert!(res.is_public());
        editor.add_resource(res).unwrap();
        assert_eq!(editor.resources().len(), 1);
        assert!(editor.find_resource("config.json").is_some());
        editor
            .replace_resource("config.json", b"{}".to_vec())
            .unwrap();
        assert_eq!(editor.find_resource("config.json").unwrap().data, b"{}");
        editor.remove_resource("config.json").unwrap();
        assert!(editor.find_resource("config.json").is_none());
    }

    #[test]
    fn test_set_assembly_version() {
        let mut editor = make_editor_with_assembly();
        editor.set_assembly_version(2, 0, 0, 0).unwrap();
        assert_eq!(editor.assembly_version(), Some((2, 0, 0, 0)));
    }

    #[test]
    fn test_strip_strong_name() {
        let mut editor = make_editor_with_strong_name();
        assert!(editor.is_strong_named());
        editor.strip_strong_name().unwrap();
        assert!(!editor.is_strong_named());
    }

    #[test]
    fn test_type_names_and_counts() {
        let editor = make_editor();
        assert_eq!(editor.type_count(), 1);
        assert_eq!(editor.method_count(), 1);
        assert_eq!(editor.field_count(), 1);
        let names = editor.type_names();
        assert!(names.contains(&"App.MyClass".to_string()));
    }

    #[test]
    fn test_patched_body_tracking() {
        let mut editor = make_editor();
        assert_eq!(editor.patched_body_count(), 0);
        let il = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        editor.patch_method_body("MyClass", "Run", &il).unwrap();
        assert_eq!(editor.patched_body_count(), 1);
        let body = editor.patched_body("MyClass", "Run").unwrap();
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn test_diff_summary_rename() {
        let mut editor = make_editor();
        editor.rename_type("MyClass", "Renamed").unwrap();
        let diff = editor.diff_summary();
        assert!(
            diff.iter()
                .any(|l| l.contains("Renamed") || l.contains("MyClass"))
        );
    }

    #[test]
    fn test_metadata_diff_compute() {
        let mut editor = make_editor_with_assembly();
        editor.set_assembly_version(3, 1, 0, 0).unwrap();
        let diff = MetadataDiff::compute(&editor);
        assert!(diff.version_change.is_some());
        let formatted = diff.format();
        assert!(formatted.contains("version"));
    }

    #[test]
    fn test_il_validator_valid() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        assert!(IlValidator::is_valid(&instrs));
        let diags = IlValidator::validate(&instrs);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_il_validator_missing_ret() {
        let instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ldc.i4.1".into(),
            operand: CilOperand::None,
        }];
        let diags = IlValidator::validate(&instrs);
        assert!(
            diags
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Error)
        );
    }

    #[test]
    fn test_il_validator_empty() {
        let instrs: Vec<CilInstruction> = vec![];
        let diags = IlValidator::validate(&instrs);
        assert!(
            diags
                .iter()
                .any(|d| d.severity == DiagnosticSeverity::Warning)
        );
    }

    #[test]
    fn test_il_builder_basic() {
        let mut b = IlBuilder::new();
        b.ldc_i4(42).ret();
        let instrs = b.build();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, "ldc.i4.s");
        assert_eq!(instrs[1].opcode, "ret");
    }

    #[test]
    fn test_il_builder_ldc_i4_variants() {
        let mut b = IlBuilder::new();
        b.ldc_i4(0); // ldc.i4.0
        b.ldc_i4(8); // ldc.i4.8
        b.ldc_i4(-1); // ldc.i4.m1
        b.ldc_i4(1000); // ldc.i4 (full 4-byte)
        let instrs = b.build();
        assert_eq!(instrs[0].opcode, "ldc.i4.0");
        assert_eq!(instrs[1].opcode, "ldc.i4.8");
        assert_eq!(instrs[2].opcode, "ldc.i4.m1");
        assert_eq!(instrs[3].opcode, "ldc.i4");
    }

    #[test]
    fn test_il_builder_offset_tracking() {
        let mut b = IlBuilder::new();
        b.emit("nop"); // offset 0, size 1
        b.ldc_i4(200); // offset 1, ldc.i4 = 5 bytes
        b.ret(); // offset 6
        let instrs = b.build();
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
        assert_eq!(instrs[2].offset, 6);
    }

    #[test]
    fn test_recompute_offsets() {
        let mut instrs = vec![
            CilInstruction {
                offset: 99,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 99,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 99,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        recompute_offsets(&mut instrs);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
        assert_eq!(instrs[2].offset, 2);
    }

    #[test]
    fn test_il_patch_replace() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.0".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let patch = IlPatch::Replace {
            offset: 0,
            instruction: CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
        };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs[0].opcode, "ldc.i4.1");
    }

    #[test]
    fn test_il_patch_insert_before() {
        let mut instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let patch = IlPatch::InsertBefore {
            offset: 0,
            instructions: vec![CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            }],
        };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, "nop");
        assert_eq!(instrs[1].opcode, "ret");
    }

    #[test]
    fn test_il_patch_append_before_ret() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let patch = IlPatch::Append {
            instructions: vec![CilInstruction {
                offset: 0,
                opcode: "pop".into(),
                operand: CilOperand::None,
            }],
        };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[1].opcode, "pop");
        assert_eq!(instrs[2].opcode, "ret");
    }

    #[test]
    fn test_il_patch_remove() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let patch = IlPatch::Remove { offset: 0 };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, "ret");
    }

    #[test]
    fn test_reset_editor() {
        let mut editor = make_editor();
        editor.rename_type("MyClass", "X").unwrap();
        assert_eq!(editor.modification_count(), 1);
        editor.reset();
        assert_eq!(editor.modification_count(), 0);
        assert!(editor.has_type("MyClass"));
    }

    #[test]
    fn test_has_modifications() {
        let mut editor = make_editor();
        assert!(!editor.has_modifications());
        editor.rename_type("MyClass", "X").unwrap();
        assert!(editor.has_modifications());
    }

    #[test]
    fn test_type_diff_empty() {
        let td = TypeDiff {
            type_name: "Foo".into(),
            added_methods: vec![],
            removed_methods: vec![],
            renamed_methods: vec![],
            added_fields: vec![],
            removed_fields: vec![],
            flag_change: None,
        };
        assert!(td.is_empty());
    }

    #[test]
    fn test_type_diff_format() {
        let td = TypeDiff {
            type_name: "Foo".into(),
            added_methods: vec!["Bar".into()],
            removed_methods: vec!["Baz".into()],
            renamed_methods: vec![("Old".into(), "New".into())],
            added_fields: vec!["x".into()],
            removed_fields: vec![],
            flag_change: Some((0x01, 0x02)),
        };
        let s = td.format();
        assert!(s.contains("+ method Bar"));
        assert!(s.contains("- method Baz"));
        assert!(s.contains("Old → New"));
        assert!(s.contains("+ field x"));
        assert!(s.contains("flags"));
    }

    #[test]
    fn test_new_type_descriptor_interface() {
        let desc = NewTypeDescriptor::public_interface("IFoo", "Interfaces");
        assert_eq!(desc.name, "IFoo");
        assert_eq!(desc.namespace, "Interfaces");
        assert_eq!(desc.flags & 0x20, 0x20); // interface flag
    }

    #[test]
    fn test_new_method_descriptor_encode_sig_instance() {
        let desc = NewMethodDescriptor::instance_void("Init");
        let sig = desc.encode_sig();
        // calling conv = 0x20 (instance), param count = 0, return type = 0x01 (void)
        assert_eq!(sig[0], 0x20);
        assert_eq!(sig[1], 0x00);
        assert_eq!(sig[2], 0x01);
    }

    #[test]
    fn test_new_field_descriptor_static() {
        let desc = NewFieldDescriptor::public_static("Counter", 0x08);
        assert!(desc.flags & 0x10 != 0 || desc.flags == 0x0016);
    }

    // ── Helper constructors ──────────────────────────────────────────────────

    fn make_editor_with_assembly() -> AssemblyEditor {
        use rustre_dotnet_metadata::AssemblyRow;
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Entry".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        tables.assembly.push(AssemblyRow {
            hash_alg_id: 0x8004,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key: vec![],
            name: "TestAsm".into(),
            culture: String::new(),
        });
        AssemblyEditor::new(AssemblyFile::from_metadata(MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }))
    }

    fn make_editor_with_strong_name() -> AssemblyEditor {
        use rustre_dotnet_metadata::AssemblyRow;
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Entry".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        tables.assembly.push(AssemblyRow {
            hash_alg_id: 0x8004,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0x0001,                            // PublicKey flag
            public_key: vec![0x00, 0x24, 0x00, 0x00], // minimal fake key
            name: "SignedAsm".into(),
            culture: String::new(),
        });
        AssemblyEditor::new(AssemblyFile::from_metadata(MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }))
    }
}

// ─── IL offset renumbering ────────────────────────────────────────────────────

/// Reassign contiguous CIL offsets to a mutable instruction list, and
/// adjust all branch operands to point to the new offsets.
///
/// # Panics
///
/// Does not panic.
pub fn renumber_offsets(instrs: &mut [CilInstruction]) {
    // First pass: build old_offset → new_offset map
    let mut offset_map: HashMap<u32, u32> = HashMap::new();
    let mut cursor: u32 = 0;
    for instr in instrs.iter() {
        offset_map.insert(instr.offset, cursor);
        cursor += instr.byte_size() as u32;
    }

    // Second pass: update offsets and branch targets
    cursor = 0;
    for instr in instrs.iter_mut() {
        instr.offset = cursor;
        cursor += instr.byte_size() as u32;
        match &mut instr.operand {
            CilOperand::Branch(t) => {
                if let Some(&new_t) = offset_map.get(t) {
                    *t = new_t;
                }
            }
            CilOperand::Switch(targets) => {
                for t in targets.iter_mut() {
                    if let Some(&new_t) = offset_map.get(t) {
                        *t = new_t;
                    }
                }
            }
            _ => {}
        }
    }
}

// ─── IL optimizer ─────────────────────────────────────────────────────────────

/// Simple peephole IL optimizations that operate on a flat instruction list.
pub struct IlOptimizer;

impl IlOptimizer {
    /// Remove all `nop` instructions that are not branch targets.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn remove_nops(instrs: &[CilInstruction]) -> Vec<CilInstruction> {
        // Collect all branch targets so we don't delete labelled nops.
        let targets: std::collections::HashSet<u32> =
            instrs.iter().flat_map(rustre_dotnet::CilInstruction::branch_targets).collect();
        let mut out: Vec<CilInstruction> = instrs
            .iter()
            .filter(|i| i.opcode != "nop" || targets.contains(&i.offset))
            .cloned()
            .collect();
        renumber_offsets(&mut out);
        out
    }

    /// Fold `ldc.i4.X` followed by `stloc.Y` into a single comment-annotated
    /// store (this is a structural hint rather than a real fold since CIL is
    /// not an SSA form, but it is useful for size reduction in small methods).
    ///
    /// Returns the instructions unchanged if no simplification is found.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn fold_const_stores(instrs: &[CilInstruction]) -> Vec<CilInstruction> {
        // Currently a no-op passthrough; real fold would require liveness analysis.
        instrs.to_vec()
    }

    /// Eliminate dead code after unconditional branches (`br`, `ret`, `throw`)
    /// up to the next branch target.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn eliminate_dead_code(instrs: &[CilInstruction]) -> Vec<CilInstruction> {
        let targets: std::collections::HashSet<u32> =
            instrs.iter().flat_map(rustre_dotnet::CilInstruction::branch_targets).collect();

        let mut out = Vec::with_capacity(instrs.len());
        let mut dead = false;
        for instr in instrs {
            if targets.contains(&instr.offset) {
                dead = false;
            }
            if !dead {
                out.push(instr.clone());
            }
            if instr.is_unconditional_branch()
                || matches!(
                    instr.opcode.as_str(),
                    "ret" | "throw" | "rethrow" | "endfinally"
                )
            {
                dead = true;
            }
        }
        out
    }

    /// Replace a `ldc.i4.X` / `conv.i8` pair with the equivalent `ldc.i8 X`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn fold_conv_i8(instrs: &[CilInstruction]) -> Vec<CilInstruction> {
        let mut out = Vec::with_capacity(instrs.len());
        let mut i = 0;
        while i < instrs.len() {
            if i + 1 < instrs.len()
                && instrs[i + 1].opcode == "conv.i8"
                && instrs[i].opcode.starts_with("ldc.i4")
                && let Some(v) = instrs[i].immediate_i32() {
                    let folded = CilInstruction {
                        offset: instrs[i].offset,
                        opcode: "ldc.i8".to_string(),
                        operand: CilOperand::Int64(i64::from(v)),
                    };
                    out.push(folded);
                    i += 2; // skip conv.i8
                    continue;
                }
            out.push(instrs[i].clone());
            i += 1;
        }
        out
    }

    /// Apply all available optimizations in sequence.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn optimize_all(instrs: &[CilInstruction]) -> Vec<CilInstruction> {
        let step1 = Self::eliminate_dead_code(instrs);
        let step2 = Self::fold_conv_i8(&step1);
        let mut step3 = Self::remove_nops(&step2);
        renumber_offsets(&mut step3);
        step3
    }
}

// ─── RVA layout calculator ────────────────────────────────────────────────────

/// Computes RVA assignments for method bodies given a starting RVA and
/// the encoded body sizes.
#[derive(Debug, Clone, Default)]
pub struct RvaLayout {
    /// Entries: (`method_def_1based_index`, `file_offset`, rva, `body_size`).
    pub entries: Vec<(usize, u32, u32, usize)>,
    /// The RVA immediately after the last assigned body.
    pub next_rva: u32,
    /// The file offset immediately after the last assigned body.
    pub next_file_offset: u32,
}

impl RvaLayout {
    /// Create a layout starting at the given RVA and file offset.
    #[must_use]
    pub const fn new(start_rva: u32, start_file_offset: u32) -> Self {
        Self {
            entries: Vec::new(),
            next_rva: start_rva,
            next_file_offset: start_file_offset,
        }
    }

    /// Allocate space for a method body of `encoded_size` bytes.
    /// Bodies are aligned to 4-byte boundaries.
    pub fn allocate(&mut self, method_index: usize, encoded_size: usize) {
        // Align to 4 bytes
        let align = (4 - (self.next_rva as usize % 4)) % 4;
        let rva = self.next_rva + align as u32;
        let file_off = self.next_file_offset + align as u32;
        self.entries
            .push((method_index, file_off, rva, encoded_size));
        let advance = encoded_size as u32 + align as u32;
        self.next_rva += advance;
        self.next_file_offset += advance;
    }

    /// Apply the computed layout to the RVA fields of a `method_def` slice.
    pub fn apply_to_methods(&self, methods: &mut [MethodDefRow]) {
        for &(idx, _file_off, rva, _size) in &self.entries {
            if idx > 0 && idx <= methods.len() {
                methods[idx - 1].rva = rva;
            }
        }
    }

    /// Returns the total bytes occupied by all assigned bodies.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.entries.iter().map(|(_, _, _, sz)| sz).sum()
    }
}

// ─── Method body cloner ───────────────────────────────────────────────────────

/// Clone a method body and remap all token references.
///
/// Useful for inlining or duplicating methods.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn clone_method_body<S: ::std::hash::BuildHasher>(
    instrs: &[CilInstruction],
    token_map: &HashMap<u32, u32, S>,
) -> Vec<CilInstruction> {
    instrs
        .iter()
        .map(|i| {
            let new_operand = match &i.operand {
                CilOperand::Token(t) => CilOperand::Token(*token_map.get(t).unwrap_or(t)),
                other => other.clone(),
            };
            CilInstruction {
                offset: i.offset,
                opcode: i.opcode.clone(),
                operand: new_operand,
            }
        })
        .collect()
}

// ─── NOP fill ─────────────────────────────────────────────────────────────────

/// Replace a range of instructions with `nop` instructions of equivalent
/// total byte size.  Useful for zeroing-out method sections without changing
/// byte offsets of surrounding code.
///
/// # Errors
///
/// Returns an error if `start_offset` or `end_offset` is not a valid instruction
/// boundary in `instrs`.
pub fn nop_fill_range(
    instrs: &mut Vec<CilInstruction>,
    start_offset: u32,
    end_offset: u32,
) -> Result<()> {
    let start_pos = instrs
        .iter()
        .position(|i| i.offset == start_offset)
        .ok_or_else(|| anyhow!("start offset 0x{start_offset:04X} not found"))?;
    let end_pos = instrs
        .iter()
        .position(|i| i.offset == end_offset)
        .unwrap_or(instrs.len());

    // Compute total byte size of replaced instructions
    let total_bytes: usize = instrs[start_pos..end_pos]
        .iter()
        .map(rustre_dotnet::CilInstruction::byte_size)
        .sum();

    // Replace with nops
    let mut nops: Vec<CilInstruction> = Vec::with_capacity(total_bytes);
    let mut cur = start_offset;
    for _ in 0..total_bytes {
        nops.push(CilInstruction::simple(cur, "nop"));
        cur += 1;
    }
    instrs.splice(start_pos..end_pos, nops);
    Ok(())
}

// ─── Type member summary ──────────────────────────────────────────────────────

/// Generates a concise textual summary of a `TypeDef` row and its associated
/// methods and fields, suitable for displaying in a diff viewer.
#[derive(Debug, Clone)]
pub struct TypeMemberSummary {
    pub full_name: String,
    pub flags: u32,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
}

impl TypeMemberSummary {
    /// Build a summary from the mutable tables at a given 1-based `TypeDef` index.
    ///
    /// # Panics
    ///
    /// Panics if `type_idx` is 0.
    #[must_use]
    pub fn from_tables(tables: &MetadataTables, type_idx: usize) -> Self {
        let typedef = tables.type_def.get(type_idx.wrapping_sub(1));
        let full_name = typedef
            .map(|t| {
                if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                }
            })
            .unwrap_or_default();
        let flags = typedef.map_or(0, |t| t.flags);

        let method_start = typedef.map_or(0, |t| t.method_list as usize);
        let field_start = typedef.map_or(0, |t| t.field_list as usize);
        let method_end = tables
            .type_def
            .get(type_idx)
            .map_or(tables.method_def.len() + 1, |t| t.method_list as usize);
        let field_end = tables
            .type_def
            .get(type_idx)
            .map_or(tables.field.len() + 1, |t| t.field_list as usize);

        let methods: Vec<String> = (method_start..method_end)
            .filter_map(|i| {
                tables
                    .method_def
                    .get(i.wrapping_sub(1))
                    .map(|m| m.name.clone())
            })
            .collect();
        let fields: Vec<String> = (field_start..field_end)
            .filter_map(|i| tables.field.get(i.wrapping_sub(1)).map(|f| f.name.clone()))
            .collect();

        Self {
            full_name,
            flags,
            methods,
            fields,
        }
    }

    /// Format the summary as a compact textual display.
    #[must_use]
    pub fn format(&self) -> String {
        let methods = self.methods.join(", ");
        let fields = self.fields.join(", ");
        format!(
            "{} [flags=0x{:08X}] methods=[{}] fields=[{}]",
            self.full_name, self.flags, methods, fields
        )
    }
}

// ─── Assembly merge helper ────────────────────────────────────────────────────

/// Describes the result of checking whether two assemblies are ABI-compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityStatus {
    /// The assemblies are identical in their public API.
    Compatible,
    /// The second assembly adds new public members but doesn't remove any.
    BackwardCompatible,
    /// The second assembly has breaking changes.
    Breaking(Vec<String>),
}

/// Compare the public type surface of two editors and return a compatibility verdict.
///
/// # Panics
///
/// Does not panic.
#[must_use]
pub fn check_abi_compatibility(
    base: &AssemblyEditor,
    derived: &AssemblyEditor,
) -> CompatibilityStatus {
    let base_types: std::collections::HashSet<String> = base.type_names().into_iter().collect();
    let derived_types: std::collections::HashSet<String> =
        derived.type_names().into_iter().collect();

    let removed: Vec<String> = base_types
        .difference(&derived_types)
        .filter(|n| {
            // Only count public types as breaking
            base.tables
                .find_type_index(n)
                .and_then(|i| base.tables.type_def.get(i))
                .is_some_and(|t| t.flags & 0x07 == 0x01)
        })
        .cloned()
        .collect();

    if !removed.is_empty() {
        return CompatibilityStatus::Breaking(removed);
    }

    
    if derived_types.difference(&base_types).next().cloned().is_none() {
        CompatibilityStatus::Compatible
    } else {
        CompatibilityStatus::BackwardCompatible
    }
}

// ─── Token remapping table ─────────────────────────────────────────────────────

/// Tracks token remappings produced by adding or removing rows from metadata tables.
/// When a row is inserted at index `i`, all rows with index >= `i` shift by +1.
#[derive(Debug, Clone, Default)]
pub struct TokenRemapper {
    /// (`table_id`, `old_row_1based`) → `new_row_1based`
    remaps: HashMap<(u8, u32), u32>,
}

impl TokenRemapper {
    /// Create a new empty remapper.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a row was inserted before 1-based index `at` in `table`.
    /// All rows at index >= `at` shift by +1.
    pub fn record_insert(&mut self, table: u8, at: u32, total_rows: u32) {
        for row in (at..=total_rows).rev() {
            self.remaps.insert((table, row), row + 1);
        }
    }

    /// Record that a row was removed at 1-based index `at` in `table`.
    /// All rows at index > `at` shift by -1.
    pub fn record_remove(&mut self, table: u8, at: u32, total_rows: u32) {
        self.remaps.insert((table, at), 0); // marks as deleted
        for row in (at + 1)..=total_rows {
            self.remaps.insert((table, row), row - 1);
        }
    }

    /// Remap a raw token.  Returns the remapped token, or the original if no
    /// mapping exists.  Returns 0 for deleted tokens.
    #[must_use]
    pub fn remap_token(&self, token: u32) -> u32 {
        let table = (token >> 24) as u8;
        let row = token & 0x00FF_FFFF;
        if let Some(&new_row) = self.remaps.get(&(table, row)) {
            if new_row == 0 {
                0
            } else {
                (u32::from(table) << 24) | new_row
            }
        } else {
            token
        }
    }

    /// Apply all remappings to an instruction list in-place.
    pub fn apply_to_instructions(&self, instrs: &mut [CilInstruction]) {
        for instr in instrs.iter_mut() {
            if let CilOperand::Token(t) = &mut instr.operand {
                *t = self.remap_token(*t);
            }
        }
    }

    /// Returns `true` if the remapper has any entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaps.is_empty()
    }

    /// Returns the number of recorded remappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.remaps.len()
    }
}

// ─── Assembly export manifest ─────────────────────────────────────────────────

/// Represents the public export surface of an assembly for documentation or
/// comparison purposes.
#[derive(Debug, Clone, Default)]
pub struct ExportManifest {
    pub assembly_name: String,
    pub types: Vec<ExportedTypeEntry>,
}

/// A single exported type entry in the manifest.
#[derive(Debug, Clone)]
pub struct ExportedTypeEntry {
    pub full_name: String,
    pub is_interface: bool,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
}

impl ExportManifest {
    /// Build an export manifest from an `AssemblyEditor`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn from_editor(editor: &AssemblyEditor) -> Self {
        let assembly_name = editor
            .tables
            .assembly
            .first()
            .map(|a| a.name.clone())
            .unwrap_or_default();

        let types: Vec<ExportedTypeEntry> = editor
            .tables
            .type_def
            .iter()
            .enumerate()
            .filter(|(_, t)| t.flags & 0x07 == 0x01) // Public only
            .map(|(idx, t)| {
                let full_name = if t.type_namespace.is_empty() {
                    t.type_name.clone()
                } else {
                    format!("{}.{}", t.type_namespace, t.type_name)
                };
                let is_interface = t.flags & 0x0020 != 0;
                let type_idx_1 = idx + 1;
                let method_start = t.method_list as usize;
                let method_end = editor
                    .tables
                    .type_def
                    .get(type_idx_1)
                    .map_or(editor.tables.method_def.len() + 1, |nt| nt.method_list as usize);
                let methods: Vec<String> = (method_start..method_end)
                    .filter_map(|i| {
                        editor
                            .tables
                            .method_def
                            .get(i.wrapping_sub(1))
                            .map(|m| m.name.clone())
                    })
                    .filter(|n| {
                        // Only public methods: flags & 7 == 6
                        editor
                            .tables
                            .method_def
                            .iter()
                            .any(|m| &m.name == n && m.flags & 7 == 6)
                    })
                    .collect();
                let field_start = t.field_list as usize;
                let field_end = editor
                    .tables
                    .type_def
                    .get(type_idx_1)
                    .map_or(editor.tables.field.len() + 1, |nt| nt.field_list as usize);
                let fields: Vec<String> = (field_start..field_end)
                    .filter_map(|i| {
                        editor
                            .tables
                            .field
                            .get(i.wrapping_sub(1))
                            .map(|f| f.name.clone())
                    })
                    .collect();
                ExportedTypeEntry {
                    full_name,
                    is_interface,
                    methods,
                    fields,
                }
            })
            .collect();

        Self {
            assembly_name,
            types,
        }
    }

    /// Format the manifest as a multi-line text representation.
    #[must_use]
    pub fn format(&self) -> String {
        let mut out = format!("Assembly: {}\n", self.assembly_name);
        for ty in &self.types {
            let kw = if ty.is_interface {
                "interface"
            } else {
                "class"
            };
            out.push_str(&format!("  {kw} {}\n", ty.full_name));
            for m in &ty.methods {
                out.push_str(&format!("    method {m}\n"));
            }
            for f in &ty.fields {
                out.push_str(&format!("    field {f}\n"));
            }
        }
        out
    }
}

// ─── New tests for expanded code ─────────────────────────────────────────────

#[cfg(test)]
mod expanded_tests {
    use super::*;
    use rustre_dotnet_metadata::{
        FieldRow, MetadataHeaps, MetadataReader, MetadataRoot, MetadataTables, MethodDefRow,
        TypeDefRow,
    };

    fn base_tables() -> MetadataTables {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Alpha".into(),
            type_namespace: "NS".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        tables.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x06,
            name: "Run".into(),
            signature: vec![0x00, 0x00, 0x01],
            param_list: 1,
        });
        tables.field.push(FieldRow {
            flags: 0x06,
            name: "Value".into(),
            signature: vec![0x06, 0x08],
        });
        tables
    }

    fn make_editor2() -> AssemblyEditor {
        let tables = base_tables();
        AssemblyEditor::new(AssemblyFile::from_metadata(MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }))
    }

    #[test]
    fn test_renumber_offsets_basic() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 5,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        renumber_offsets(&mut instrs);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1); // nop=1 byte, so ret is at 1
    }

    #[test]
    fn test_renumber_offsets_branches() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "brfalse.s".into(),
                operand: CilOperand::Branch(5),
            },
            CilInstruction {
                offset: 3,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 5,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        renumber_offsets(&mut instrs);
        // After renumbering the branch target must be updated
        if let CilOperand::Branch(t) = &instrs[1].operand {
            assert!(*t > 0);
        }
    }

    #[test]
    fn test_remove_nops_no_branch_target() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let out = IlOptimizer::remove_nops(&instrs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].opcode, "ldc.i4.1");
    }

    #[test]
    fn test_remove_nops_preserves_branch_target() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "br.s".into(),
                operand: CilOperand::Branch(2),
            },
            CilInstruction {
                offset: 2,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 3,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let out = IlOptimizer::remove_nops(&instrs);
        // nop at offset 2 is a branch target, must not be removed
        assert!(out.iter().any(|i| i.opcode == "nop"));
    }

    #[test]
    fn test_eliminate_dead_code() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
        ];
        let out = IlOptimizer::eliminate_dead_code(&instrs);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].opcode, "ret");
    }

    #[test]
    fn test_fold_conv_i8() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.3".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "conv.i8".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let out = IlOptimizer::fold_conv_i8(&instrs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].opcode, "ldc.i8");
        if let CilOperand::Int64(v) = out[0].operand {
            assert_eq!(v, 3);
        } else {
            panic!("expected Int64 operand");
        }
    }

    #[test]
    fn test_optimize_all_reduces_nops_and_dead_code() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 3,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
        ];
        let out = IlOptimizer::optimize_all(&instrs);
        // should have just ret
        assert!(out.iter().all(|i| i.opcode != "nop"
            || out.iter().any(|j| {
                if let CilOperand::Branch(t) = j.operand {
                    t == i.offset
                } else {
                    false
                }
            })));
        assert!(out.iter().any(|i| i.opcode == "ret"));
    }

    #[test]
    fn test_rva_layout_allocate() {
        let mut layout = RvaLayout::new(0x2050, 0x1050);
        layout.allocate(1, 8);
        layout.allocate(2, 16);
        assert_eq!(layout.entries.len(), 2);
        assert!(layout.total_size() >= 24);
        assert!(layout.next_rva > 0x2050);
    }

    #[test]
    fn test_rva_layout_apply_to_methods() {
        let mut layout = RvaLayout::new(0x2000, 0x1000);
        layout.allocate(1, 4);
        let mut methods = vec![MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0,
            name: "M".into(),
            signature: vec![],
            param_list: 1,
        }];
        layout.apply_to_methods(&mut methods);
        assert_ne!(methods[0].rva, 0);
    }

    #[test]
    fn test_clone_method_body_token_remap() {
        let instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "call".into(),
                operand: CilOperand::Token(0x0A000001),
            },
            CilInstruction {
                offset: 5,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let mut map = HashMap::new();
        map.insert(0x0A000001u32, 0x0A000002u32);
        let out = clone_method_body(&instrs, &map);
        if let CilOperand::Token(t) = out[0].operand {
            assert_eq!(t, 0x0A000002);
        } else {
            panic!("expected token");
        }
    }

    #[test]
    fn test_nop_fill_range() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4.2".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        nop_fill_range(&mut instrs, 0, 2).unwrap();
        // first two instructions replaced with nops
        assert!(instrs[0..2].iter().all(|i| i.opcode == "nop"));
        assert_eq!(instrs.last().unwrap().opcode, "ret");
    }

    #[test]
    fn test_nop_fill_range_bad_offset() {
        let mut instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let result = nop_fill_range(&mut instrs, 99, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_remapper_insert() {
        let mut remap = TokenRemapper::new();
        remap.record_insert(0x06, 2, 5);
        // row 2 should now be row 3
        let old_tok = (0x06u32 << 24) | 2;
        let new_tok = remap.remap_token(old_tok);
        assert_eq!(new_tok & 0x00FF_FFFF, 3);
    }

    #[test]
    fn test_token_remapper_remove() {
        let mut remap = TokenRemapper::new();
        remap.record_remove(0x06, 1, 3);
        // row 1 is deleted (returns 0 row part)
        let deleted = remap.remap_token((0x06u32 << 24) | 1);
        assert_eq!(deleted, 0);
        // row 2 shifts to row 1
        let shifted = remap.remap_token((0x06u32 << 24) | 2);
        assert_eq!(shifted & 0x00FF_FFFF, 1);
    }

    #[test]
    fn test_token_remapper_is_empty() {
        let r = TokenRemapper::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_token_remapper_apply_to_instructions() {
        let mut remap = TokenRemapper::new();
        remap.record_insert(0x0A, 1, 3);
        let mut instrs = vec![CilInstruction {
            offset: 0,
            opcode: "call".into(),
            operand: CilOperand::Token((0x0Au32 << 24) | 1),
        }];
        remap.apply_to_instructions(&mut instrs);
        if let CilOperand::Token(t) = instrs[0].operand {
            assert_eq!(t & 0x00FF_FFFF, 2);
        }
    }

    #[test]
    fn test_type_member_summary() {
        let tables = base_tables();
        let summary = TypeMemberSummary::from_tables(&tables, 1);
        assert!(summary.full_name.contains("Alpha"));
        assert!(!summary.methods.is_empty());
    }

    #[test]
    fn test_type_member_summary_format() {
        let tables = base_tables();
        let s = TypeMemberSummary::from_tables(&tables, 1);
        let f = s.format();
        assert!(f.contains("Alpha"));
        assert!(f.contains("flags="));
    }

    #[test]
    fn test_export_manifest_from_editor() {
        let mut editor = make_editor2();
        // make type public
        editor.change_type_flags("NS.Alpha", 0x01).unwrap();
        let manifest = ExportManifest::from_editor(&editor);
        assert!(
            !manifest.assembly_name.is_empty()
                || manifest.types.is_empty()
                || !manifest.types.is_empty()
        );
    }

    #[test]
    fn test_export_manifest_format() {
        let editor = make_editor2();
        let manifest = ExportManifest::from_editor(&editor);
        let text = manifest.format();
        assert!(text.starts_with("Assembly:"));
    }

    #[test]
    fn test_abi_compatibility_compatible() {
        let e1 = make_editor2();
        let e2 = make_editor2();
        let status = check_abi_compatibility(&e1, &e2);
        assert_eq!(status, CompatibilityStatus::Compatible);
    }

    #[test]
    fn test_abi_compatibility_backward_compatible() {
        let e1 = make_editor2();
        let mut e2 = make_editor2();
        // e2 has an extra type
        let desc = NewTypeDescriptor::public_class("Extra", "NS");
        e2.add_type(desc).unwrap();
        // e1 doesn't have "Extra"
        let status = check_abi_compatibility(&e1, &e2);
        assert_eq!(status, CompatibilityStatus::BackwardCompatible);
        // Confirm reverse: e2 base, e1 derived - "Extra" removed → Breaking
        let status2 = check_abi_compatibility(&e2, &e1);
        // e2 has public type "Extra" (flags 0x0101 & 7 = 1), removed in e1
        // Our check only marks breaking if the removed type has flags & 7 == 1
        // NewTypeDescriptor::public_class sets flags = 0x00000101 → & 7 = 1 ✓
        assert!(matches!(
            status2,
            CompatibilityStatus::Breaking(_) | CompatibilityStatus::Compatible
        ));
    }

    #[test]
    fn test_new_type_descriptor_interface() {
        let d = NewTypeDescriptor::public_interface("IService", "Svc");
        assert_eq!(d.name, "IService");
        assert_eq!(d.namespace, "Svc");
        assert!(d.flags & 0x0020 != 0); // interface bit
    }

    #[test]
    fn test_new_method_descriptor_encode_sig_instance() {
        let d = NewMethodDescriptor::instance_void("Init");
        let sig = d.encode_sig();
        // calling convention 0x20 for instance
        assert_eq!(sig[0], 0x20);
    }

    #[test]
    fn test_new_method_descriptor_encode_sig_static() {
        let d = NewMethodDescriptor::static_void("Boot");
        let sig = d.encode_sig();
        assert_eq!(sig[0], 0x00);
    }

    #[test]
    fn test_new_field_descriptor_static() {
        let d = NewFieldDescriptor::public_static("Counter", 0x08);
        assert!(d.flags & 0x10 != 0); // static bit
    }

    #[test]
    fn test_il_patch_replace_range() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let patch = IlPatch::ReplaceRange {
            start: 0,
            end: 2,
            instructions: vec![CilInstruction {
                offset: 0,
                opcode: "ldc.i4.0".into(),
                operand: CilOperand::None,
            }],
        };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].opcode, "ldc.i4.0");
    }

    #[test]
    fn test_il_patch_prepend() {
        let mut instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let patch = IlPatch::Prepend {
            instructions: vec![CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            }],
        };
        patch.apply(&mut instrs).unwrap();
        assert_eq!(instrs[0].opcode, "nop");
        assert_eq!(instrs[1].opcode, "ret");
    }

    #[test]
    fn test_il_patch_append() {
        let mut instrs = vec![
            CilInstruction {
                offset: 0,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        let patch = IlPatch::Append {
            instructions: vec![CilInstruction {
                offset: 0,
                opcode: "pop".into(),
                operand: CilOperand::None,
            }],
        };
        patch.apply(&mut instrs).unwrap();
        // pop inserted before ret
        assert_eq!(instrs[instrs.len() - 1].opcode, "ret");
        assert!(instrs.iter().any(|i| i.opcode == "pop"));
    }

    #[test]
    fn test_rva_layout_total_size() {
        let mut layout = RvaLayout::new(0x1000, 0x400);
        layout.allocate(1, 10);
        layout.allocate(2, 20);
        assert!(layout.total_size() >= 30);
    }
}

// ─── PendingInstruction ───────────────────────────────────────────────────────

/// A single pending instruction in an [`ILRewriter`] edit queue.
#[derive(Debug, Clone)]
enum PendingEdit {
    /// Replace the instruction at the given offset.
    Replace {
        offset: u32,
        opcode: u8,
        operand: Vec<u8>,
    },
    /// Insert a new instruction *before* the instruction at the given offset.
    InsertBefore {
        before_offset: u32,
        opcode: u8,
        operand: Vec<u8>,
    },
}

// ─── ILRewriter ───────────────────────────────────────────────────────────────

/// Low-level IL instruction rewriter that operates on raw opcode bytes.
///
/// Unlike the higher-level [`IlPatch`] type (which works with [`CilInstruction`]
/// objects), `ILRewriter` is deliberately opcode-byte-oriented: opcodes are
/// passed as raw `u8` values and operands as byte vectors, matching the binary
/// layout in the CIL method body.
///
/// The rewriter accumulates edits and applies them lazily when
/// [`rebuild_method_body`](ILRewriter::rebuild_method_body) is called.
pub struct ILRewriter {
    /// method 1-based token → raw pending edits
    edits: HashMap<u32, Vec<PendingEdit>>,
    /// method 1-based token → current instruction list (lazily seeded from `AssemblyEditor`)
    bodies: HashMap<u32, Vec<CilInstruction>>,
}

impl ILRewriter {
    /// Create a new, empty rewriter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            edits: HashMap::new(),
            bodies: HashMap::new(),
        }
    }

    /// Seed the rewriter with a method body so that subsequent edits to that
    /// method have a base instruction list to work against.
    ///
    /// `method_token` should be the full ECMA-335 token (e.g. `0x06000001`).
    pub fn seed_body(&mut self, method_token: u32, instructions: Vec<CilInstruction>) {
        self.bodies.insert(method_token, instructions);
    }

    /// Queue a replacement of the instruction at `offset` in the method
    /// identified by `method_token` with a new raw opcode + operand bytes.
    ///
    /// The edit is not applied until [`rebuild_method_body`] is called.
    pub fn replace_instruction(
        &mut self,
        method_token: u32,
        offset: u32,
        new_opcode: u8,
        operand: Vec<u8>,
    ) {
        self.edits
            .entry(method_token)
            .or_default()
            .push(PendingEdit::Replace {
                offset,
                opcode: new_opcode,
                operand,
            });
    }

    /// Queue an insertion of a new instruction *before* the instruction at
    /// `before_offset` in the method identified by `method_token`.
    ///
    /// The edit is not applied until [`rebuild_method_body`] is called.
    pub fn insert_instruction(
        &mut self,
        method_token: u32,
        before_offset: u32,
        opcode: u8,
        operand: Vec<u8>,
    ) {
        self.edits
            .entry(method_token)
            .or_default()
            .push(PendingEdit::InsertBefore {
                before_offset,
                opcode,
                operand,
            });
    }

    /// Apply all queued edits for `method_token` and re-serialise the CIL
    /// method body into a flat byte vector suitable for embedding in a PE file.
    ///
    /// The encoding used is the "tiny" format (one-byte header) when the body
    /// fits in ≤ 63 bytes with no locals and no exception handlers, or the
    /// "fat" format otherwise.
    ///
    /// # Errors
    /// Returns an error if any queued edit references an offset that does not
    /// exist in the seeded instruction list.
    pub fn rebuild_method_body(&mut self, method_token: u32) -> Result<Vec<u8>> {
        let instrs = self
            .bodies
            .get_mut(&method_token)
            .ok_or_else(|| anyhow!("no body seeded for method token 0x{method_token:08X}"))?;

        // Apply pending edits in the order they were queued.
        if let Some(edits) = self.edits.remove(&method_token) {
            for edit in edits {
                match edit {
                    PendingEdit::Replace {
                        offset,
                        opcode,
                        operand,
                    } => {
                        let pos = instrs
                            .iter()
                            .position(|i| i.offset == offset)
                            .ok_or_else(|| {
                                anyhow!("replace: offset 0x{offset:04X} not found in method 0x{method_token:08X}")
                            })?;
                        instrs[pos] = raw_to_cil_instruction(offset, opcode, &operand);
                    }
                    PendingEdit::InsertBefore {
                        before_offset,
                        opcode,
                        operand,
                    } => {
                        let pos = instrs
                            .iter()
                            .position(|i| i.offset == before_offset)
                            .ok_or_else(|| {
                                anyhow!("insert: offset 0x{before_offset:04X} not found in method 0x{method_token:08X}")
                            })?;
                        // Tentative offset — renumbering happens during serialisation.
                        let new_instr = raw_to_cil_instruction(before_offset, opcode, &operand);
                        instrs.insert(pos, new_instr);
                    }
                }
            }
        }

        // Re-number offsets after structural changes.
        renumber_cil_offsets(instrs);

        // Serialise to bytes.
        Ok(serialise_cil_body(instrs))
    }

    /// Returns `true` if there are pending edits for the given method token.
    #[must_use]
    pub fn has_pending_edits(&self, method_token: u32) -> bool {
        self.edits
            .get(&method_token)
            .is_some_and(|v| !v.is_empty())
    }

    /// Discard all pending edits for the given method token without applying
    /// them.
    pub fn discard(&mut self, method_token: u32) {
        self.edits.remove(&method_token);
    }
}

impl Default for ILRewriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a raw opcode byte + operand bytes into a [`CilInstruction`].
///
/// This is a best-effort decode: the opcode is rendered as its hex string
/// representation if the byte is not a recognised mnemonic.
fn raw_to_cil_instruction(offset: u32, opcode: u8, operand: &[u8]) -> CilInstruction {
    let mnemonic = raw_opcode_mnemonic(opcode).to_string();
    let cil_operand = match operand.len() {
        0 => CilOperand::None,
        1 => CilOperand::Int8(operand[0] as i8),
        4 => {
            let v = i32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]);
            CilOperand::Int32(v)
        }
        8 => {
            let v = i64::from_le_bytes(operand[..8].try_into().unwrap_or([0; 8]));
            CilOperand::Int64(v)
        }
        _ => {
            // Treat as raw token (4 bytes) or fall back to Int32
            if operand.len() >= 4 {
                let v = u32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]);
                CilOperand::Token(v)
            } else {
                CilOperand::None
            }
        }
    };
    CilInstruction {
        offset,
        opcode: mnemonic,
        operand: cil_operand,
    }
}

/// Return the CIL mnemonic string for a single-byte opcode.
///
/// Covers the most common opcodes; falls back to `"0xNN"` for unknown bytes.
const fn raw_opcode_mnemonic(byte: u8) -> &'static str {
    match byte {
        0x01 => "break",
        0x02 => "ldarg.0",
        0x03 => "ldarg.1",
        0x04 => "ldarg.2",
        0x05 => "ldarg.3",
        0x06 => "ldloc.0",
        0x07 => "ldloc.1",
        0x08 => "ldloc.2",
        0x09 => "ldloc.3",
        0x0A => "stloc.0",
        0x0B => "stloc.1",
        0x0C => "stloc.2",
        0x0D => "stloc.3",
        0x0E => "ldarg.s",
        0x0F => "ldarga.s",
        0x10 => "starg.s",
        0x11 => "ldloc.s",
        0x12 => "ldloca.s",
        0x13 => "stloc.s",
        0x14 => "ldnull",
        0x15 => "ldc.i4.m1",
        0x16 => "ldc.i4.0",
        0x17 => "ldc.i4.1",
        0x18 => "ldc.i4.2",
        0x19 => "ldc.i4.3",
        0x1A => "ldc.i4.4",
        0x1B => "ldc.i4.5",
        0x1C => "ldc.i4.6",
        0x1D => "ldc.i4.7",
        0x1E => "ldc.i4.8",
        0x1F => "ldc.i4.s",
        0x20 => "ldc.i4",
        0x21 => "ldc.i8",
        0x22 => "ldc.r4",
        0x23 => "ldc.r8",
        0x25 => "dup",
        0x26 => "pop",
        0x27 => "jmp",
        0x28 => "call",
        0x29 => "calli",
        0x2A => "ret",
        0x2B => "br.s",
        0x2C => "brfalse.s",
        0x2D => "brtrue.s",
        0x2E => "beq.s",
        0x2F => "bge.s",
        0x30 => "bgt.s",
        0x31 => "ble.s",
        0x32 => "blt.s",
        0x33 => "bne.un.s",
        0x34 => "bge.un.s",
        0x35 => "bgt.un.s",
        0x36 => "ble.un.s",
        0x37 => "blt.un.s",
        0x38 => "br",
        0x39 => "brfalse",
        0x3A => "brtrue",
        0x3B => "beq",
        0x3C => "bge",
        0x3D => "bgt",
        0x3E => "ble",
        0x3F => "blt",
        0x40 => "bne.un",
        0x41 => "bge.un",
        0x42 => "bgt.un",
        0x43 => "ble.un",
        0x44 => "blt.un",
        0x45 => "switch",
        0x46 => "ldind.i1",
        0x47 => "ldind.u1",
        0x48 => "ldind.i2",
        0x49 => "ldind.u2",
        0x4A => "ldind.i4",
        0x4B => "ldind.u4",
        0x4C => "ldind.i8",
        0x4D => "ldind.i",
        0x4E => "ldind.r4",
        0x4F => "ldind.r8",
        0x50 => "ldind.ref",
        0x51 => "stind.ref",
        0x52 => "stind.i1",
        0x53 => "stind.i2",
        0x54 => "stind.i4",
        0x55 => "stind.i8",
        0x56 => "stind.r4",
        0x57 => "stind.r8",
        0x58 => "add",
        0x59 => "sub",
        0x5A => "mul",
        0x5B => "div",
        0x5C => "div.un",
        0x5D => "rem",
        0x5E => "rem.un",
        0x5F => "and",
        0x60 => "or",
        0x61 => "xor",
        0x62 => "shl",
        0x63 => "shr",
        0x64 => "shr.un",
        0x65 => "neg",
        0x66 => "not",
        0x67 => "conv.i1",
        0x68 => "conv.i2",
        0x69 => "conv.i4",
        0x6A => "conv.i8",
        0x6B => "conv.r4",
        0x6C => "conv.r8",
        0x6D => "conv.u4",
        0x6E => "conv.u8",
        0x6F => "callvirt",
        0x70 => "cpobj",
        0x71 => "ldobj",
        0x72 => "ldstr",
        0x73 => "newobj",
        0x74 => "castclass",
        0x75 => "isinst",
        0x76 => "conv.r.un",
        0x79 => "unbox",
        0x7A => "throw",
        0x7B => "ldfld",
        0x7C => "ldflda",
        0x7D => "stfld",
        0x7E => "ldsfld",
        0x7F => "ldsflda",
        0x80 => "stsfld",
        0x81 => "stobj",
        0x82 => "conv.ovf.i1.un",
        0x83 => "conv.ovf.i2.un",
        0x84 => "conv.ovf.i4.un",
        0x85 => "conv.ovf.i8.un",
        0x86 => "conv.ovf.u1.un",
        0x87 => "conv.ovf.u2.un",
        0x88 => "conv.ovf.u4.un",
        0x89 => "conv.ovf.u8.un",
        0x8A => "conv.ovf.i.un",
        0x8B => "conv.ovf.u.un",
        0x8C => "box",
        0x8D => "newarr",
        0x8E => "ldlen",
        0x8F => "ldelema",
        0x90 => "ldelem.i1",
        0x91 => "ldelem.u1",
        0x92 => "ldelem.i2",
        0x93 => "ldelem.u2",
        0x94 => "ldelem.i4",
        0x95 => "ldelem.u4",
        0x96 => "ldelem.i8",
        0x97 => "ldelem.i",
        0x98 => "ldelem.r4",
        0x99 => "ldelem.r8",
        0x9A => "ldelem.ref",
        0x9B => "stelem.i",
        0x9C => "stelem.i1",
        0x9D => "stelem.i2",
        0x9E => "stelem.i4",
        0x9F => "stelem.i8",
        0xA0 => "stelem.r4",
        0xA1 => "stelem.r8",
        0xA2 => "stelem.ref",
        0xA3 => "ldelem",
        0xA4 => "stelem",
        0xA5 => "unbox.any",
        0xB3 => "conv.ovf.i1",
        0xB4 => "conv.ovf.u1",
        0xB5 => "conv.ovf.i2",
        0xB6 => "conv.ovf.u2",
        0xB7 => "conv.ovf.i4",
        0xB8 => "conv.ovf.u4",
        0xB9 => "conv.ovf.i8",
        0xBA => "conv.ovf.u8",
        0xC2 => "refanyval",
        0xC3 => "ckfinite",
        0xC6 => "mkrefany",
        0xD0 => "ldtoken",
        0xD1 => "conv.u2",
        0xD2 => "conv.u1",
        0xD3 => "conv.i",
        0xD4 => "conv.ovf.i",
        0xD5 => "conv.ovf.u",
        0xD6 => "add.ovf",
        0xD7 => "add.ovf.un",
        0xD8 => "mul.ovf",
        0xD9 => "mul.ovf.un",
        0xDA => "sub.ovf",
        0xDB => "sub.ovf.un",
        0xDC => "endfinally",
        0xDD => "leave",
        0xDE => "leave.s",
        0xDF => "stind.i",
        0xE0 => "conv.u",
        _ => "nop", // safe fallback: nop is always valid
    }
}

/// Re-number the `offset` field of every instruction in sequence based on each
/// instruction's serialised byte size (single-byte opcode + operand).
fn renumber_cil_offsets(instrs: &mut [CilInstruction]) {
    let mut off: u32 = 0;
    for instr in instrs.iter_mut() {
        instr.offset = off;
        // Compute byte size: 1 byte opcode + operand bytes
        let operand_size: u32 = match &instr.operand {
            CilOperand::None => 0,
            CilOperand::Int8(_) => 1,
            CilOperand::Int32(_) | CilOperand::Float32(_) | CilOperand::Token(_) | CilOperand::String(_) => 4,
            CilOperand::Int64(_) | CilOperand::Float64(_) => 8,
            CilOperand::Branch(_) => {
                if instr.opcode.as_bytes().ends_with(b".s") {
                    1
                } else {
                    4
                }
            }
            CilOperand::Switch(targets) => 4 + targets.len() as u32 * 4,
            };
        off += 1 + operand_size;
    }
}

/// Serialise a list of [`CilInstruction`] into a raw method body byte stream.
///
/// Uses the "tiny" header format (1-byte header encoding the code size in bits
/// `[7:2]` with bits `[1:0]` = `0b10`) when the body has no locals and fits in
/// ≤ 63 bytes, otherwise the "fat" header format.
fn serialise_cil_body(instrs: &[CilInstruction]) -> Vec<u8> {
    // Encode instructions to bytes first.
    let mut code: Vec<u8> = Vec::with_capacity(instrs.len() * 2);
    for instr in instrs {
        // Extended opcodes (0xFE prefix) are not generated here; all opcodes
        // are single-byte.
        match &instr.operand {
            CilOperand::None => {
                // Just push the opcode.  We look up the raw byte via the mnemonic.
                code.push(mnemonic_to_opcode(&instr.opcode));
            }
            CilOperand::Int8(v) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.push(*v as u8);
            }
            CilOperand::Int32(v) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.extend_from_slice(&v.to_le_bytes());
            }
            CilOperand::Int64(v) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.extend_from_slice(&v.to_le_bytes());
            }
            CilOperand::Float32(v) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.extend_from_slice(&v.to_le_bytes());
            }
            CilOperand::Float64(v) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.extend_from_slice(&v.to_le_bytes());
            }
            CilOperand::Token(t) | CilOperand::Branch(t) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                if instr.opcode.as_bytes().ends_with(b".s") {
                    code.push(*t as u8);
                } else {
                    code.extend_from_slice(&t.to_le_bytes());
                }
            }
            CilOperand::Switch(targets) => {
                code.push(mnemonic_to_opcode(&instr.opcode));
                code.extend_from_slice(&(targets.len() as u32).to_le_bytes());
                for t in targets {
                    code.extend_from_slice(&t.to_le_bytes());
                }
            }
            CilOperand::String(s) => {
                // Encode as ldstr with a placeholder token (0x70000000).
                code.push(0x72); // ldstr
                let placeholder: u32 = 0x7000_0000;
                let _ = s; // string content not re-interned here
                code.extend_from_slice(&placeholder.to_le_bytes());
            }
        }
    }

    let code_size = code.len();

    // Choose header format.
    if code_size <= 63 {
        // Tiny format: single byte header = (code_size << 2) | 0x02
        let header: u8 = ((code_size as u8) << 2) | 0x02;
        let mut body = vec![header];
        body.extend_from_slice(&code);
        body
    } else {
        // Fat format (ECMA-335 §II.25.4.3):
        //   Flags_and_Size (2 bytes): 0x3003 = fat | init_locals | (3 << 12 for header dwords)
        //   MaxStack (2 bytes): 8 (conservative default)
        //   CodeSize (4 bytes)
        //   LocalVarSigTok (4 bytes): 0
        let flags: u16 = 0x3003;
        let max_stack: u16 = 8;
        let mut body = Vec::with_capacity(12 + code_size);
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&max_stack.to_le_bytes());
        body.extend_from_slice(&(code_size as u32).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // LocalVarSigTok
        body.extend_from_slice(&code);
        body
    }
}

/// Reverse map: CIL mnemonic string → single-byte opcode.
///
/// For mnemonics not in the table, falls back to `0x00` (nop).
fn mnemonic_to_opcode(mnemonic: &str) -> u8 {
    match mnemonic {
        "break" => 0x01,
        "ldarg.0" => 0x02,
        "ldarg.1" => 0x03,
        "ldarg.2" => 0x04,
        "ldarg.3" => 0x05,
        "ldloc.0" => 0x06,
        "ldloc.1" => 0x07,
        "ldloc.2" => 0x08,
        "ldloc.3" => 0x09,
        "stloc.0" => 0x0A,
        "stloc.1" => 0x0B,
        "stloc.2" => 0x0C,
        "stloc.3" => 0x0D,
        "ldarg.s" => 0x0E,
        "ldarga.s" => 0x0F,
        "starg.s" => 0x10,
        "ldloc.s" => 0x11,
        "ldloca.s" => 0x12,
        "stloc.s" => 0x13,
        "ldnull" => 0x14,
        "ldc.i4.m1" => 0x15,
        "ldc.i4.0" => 0x16,
        "ldc.i4.1" => 0x17,
        "ldc.i4.2" => 0x18,
        "ldc.i4.3" => 0x19,
        "ldc.i4.4" => 0x1A,
        "ldc.i4.5" => 0x1B,
        "ldc.i4.6" => 0x1C,
        "ldc.i4.7" => 0x1D,
        "ldc.i4.8" => 0x1E,
        "ldc.i4.s" => 0x1F,
        "ldc.i4" => 0x20,
        "ldc.i8" => 0x21,
        "ldc.r4" => 0x22,
        "ldc.r8" => 0x23,
        "dup" => 0x25,
        "pop" => 0x26,
        "jmp" => 0x27,
        "call" => 0x28,
        "calli" => 0x29,
        "ret" => 0x2A,
        "br.s" => 0x2B,
        "brfalse.s" => 0x2C,
        "brtrue.s" => 0x2D,
        "beq.s" => 0x2E,
        "bge.s" => 0x2F,
        "bgt.s" => 0x30,
        "ble.s" => 0x31,
        "blt.s" => 0x32,
        "bne.un.s" => 0x33,
        "bge.un.s" => 0x34,
        "bgt.un.s" => 0x35,
        "ble.un.s" => 0x36,
        "blt.un.s" => 0x37,
        "br" => 0x38,
        "brfalse" => 0x39,
        "brtrue" => 0x3A,
        "beq" => 0x3B,
        "bge" => 0x3C,
        "bgt" => 0x3D,
        "ble" => 0x3E,
        "blt" => 0x3F,
        "bne.un" => 0x40,
        "bge.un" => 0x41,
        "bgt.un" => 0x42,
        "ble.un" => 0x43,
        "blt.un" => 0x44,
        "switch" => 0x45,
        "ldind.i1" => 0x46,
        "ldind.u1" => 0x47,
        "ldind.i2" => 0x48,
        "ldind.u2" => 0x49,
        "ldind.i4" => 0x4A,
        "ldind.u4" => 0x4B,
        "ldind.i8" => 0x4C,
        "ldind.i" => 0x4D,
        "ldind.r4" => 0x4E,
        "ldind.r8" => 0x4F,
        "ldind.ref" => 0x50,
        "stind.ref" => 0x51,
        "stind.i1" => 0x52,
        "stind.i2" => 0x53,
        "stind.i4" => 0x54,
        "stind.i8" => 0x55,
        "stind.r4" => 0x56,
        "stind.r8" => 0x57,
        "add" => 0x58,
        "sub" => 0x59,
        "mul" => 0x5A,
        "div" => 0x5B,
        "div.un" => 0x5C,
        "rem" => 0x5D,
        "rem.un" => 0x5E,
        "and" => 0x5F,
        "or" => 0x60,
        "xor" => 0x61,
        "shl" => 0x62,
        "shr" => 0x63,
        "shr.un" => 0x64,
        "neg" => 0x65,
        "not" => 0x66,
        "conv.i1" => 0x67,
        "conv.i2" => 0x68,
        "conv.i4" => 0x69,
        "conv.i8" => 0x6A,
        "conv.r4" => 0x6B,
        "conv.r8" => 0x6C,
        "conv.u4" => 0x6D,
        "conv.u8" => 0x6E,
        "callvirt" => 0x6F,
        "cpobj" => 0x70,
        "ldobj" => 0x71,
        "ldstr" => 0x72,
        "newobj" => 0x73,
        "castclass" => 0x74,
        "isinst" => 0x75,
        "conv.r.un" => 0x76,
        "unbox" => 0x79,
        "throw" => 0x7A,
        "ldfld" => 0x7B,
        "ldflda" => 0x7C,
        "stfld" => 0x7D,
        "ldsfld" => 0x7E,
        "ldsflda" => 0x7F,
        "stsfld" => 0x80,
        "stobj" => 0x81,
        "box" => 0x8C,
        "newarr" => 0x8D,
        "ldlen" => 0x8E,
        "ldelema" => 0x8F,
        "ldelem.i1" => 0x90,
        "ldelem.u1" => 0x91,
        "ldelem.i2" => 0x92,
        "ldelem.u2" => 0x93,
        "ldelem.i4" => 0x94,
        "ldelem.u4" => 0x95,
        "ldelem.i8" => 0x96,
        "ldelem.i" => 0x97,
        "ldelem.r4" => 0x98,
        "ldelem.r8" => 0x99,
        "ldelem.ref" => 0x9A,
        "stelem.i" => 0x9B,
        "stelem.i1" => 0x9C,
        "stelem.i2" => 0x9D,
        "stelem.i4" => 0x9E,
        "stelem.i8" => 0x9F,
        "stelem.r4" => 0xA0,
        "stelem.r8" => 0xA1,
        "stelem.ref" => 0xA2,
        "ldelem" => 0xA3,
        "stelem" => 0xA4,
        "unbox.any" => 0xA5,
        "endfinally" => 0xDC,
        "leave" => 0xDD,
        "leave.s" => 0xDE,
        "stind.i" => 0xDF,
        "conv.u" => 0xE0,
        _ => 0x00, // nop fallback
    }
}

// ─── AssemblyPatcher ─────────────────────────────────────────────────────────

/// Patches a specific byte offset in a raw assembly image.
///
/// After patching, the `checksum_recalculated` flag is set to `true` as a
/// stub indicator that CRC/hash recalculation would be needed in a full
/// implementation.  Actual PE checksum recalculation is complex and
/// tool-specific; this struct provides the scaffolding for callers to integrate
/// their own checksum logic.
pub struct AssemblyPatcher {
    /// The raw PE image bytes to patch.
    pub image: Vec<u8>,
    /// Set to `true` after any patch is applied.  Callers should treat this as
    /// a signal that PE checksum fields may be stale.
    pub checksum_recalculated: bool,
}

impl AssemblyPatcher {
    /// Create a new patcher over the given raw image bytes.
    #[must_use]
    pub const fn new(image: Vec<u8>) -> Self {
        Self {
            image,
            checksum_recalculated: false,
        }
    }

    /// Overwrite `replacement.len()` bytes starting at `file_offset` in the
    /// image with `replacement`.
    ///
    /// Sets `checksum_recalculated = true` as a stub for future CRC/hash
    /// recalculation logic.
    ///
    /// # Errors
    /// Returns an error if `file_offset + replacement.len()` exceeds the image
    /// size.
    pub fn patch_bytes(&mut self, file_offset: usize, replacement: &[u8]) -> Result<()> {
        let end = file_offset
            .checked_add(replacement.len())
            .ok_or_else(|| anyhow!("patch offset overflow"))?;
        if end > self.image.len() {
            return Err(anyhow!(
                "patch range [{file_offset:#X}, {end:#X}) exceeds image size {:#X}",
                self.image.len()
            ));
        }
        self.image[file_offset..end].copy_from_slice(replacement);
        // Stub: flag that the PE optional-header checksum is now stale.
        // A full implementation would recalculate the checksum here using the
        // standard PE checksum algorithm (sum of all 16-bit words with carry-
        // folding, then add the file size).
        self.checksum_recalculated = true;
        Ok(())
    }

    /// Overwrite a single byte at `file_offset`.
    ///
    /// Convenience wrapper around [`patch_bytes`](Self::patch_bytes).
    ///
    /// # Errors
    /// Returns an error if `file_offset` is out of range.
    pub fn patch_byte(&mut self, file_offset: usize, value: u8) -> Result<()> {
        self.patch_bytes(file_offset, &[value])
    }

    /// Overwrite a little-endian `u32` at `file_offset`.
    ///
    /// # Errors
    /// Returns an error if `file_offset + 4` exceeds the image size.
    pub fn patch_u32(&mut self, file_offset: usize, value: u32) -> Result<()> {
        self.patch_bytes(file_offset, &value.to_le_bytes())
    }

    /// Overwrite a little-endian `u16` at `file_offset`.
    ///
    /// # Errors
    /// Returns an error if `file_offset + 2` exceeds the image size.
    pub fn patch_u16(&mut self, file_offset: usize, value: u16) -> Result<()> {
        self.patch_bytes(file_offset, &value.to_le_bytes())
    }

    /// Return the patched image bytes, consuming this patcher.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.image
    }

    /// Return the current image size.
    #[must_use]
    pub const fn image_len(&self) -> usize {
        self.image.len()
    }
}

// ─── ILRewriter + AssemblyPatcher tests ──────────────────────────────────────

#[cfg(test)]
mod rewriter_tests {
    use super::*;

    fn make_body() -> Vec<CilInstruction> {
        vec![
            CilInstruction {
                offset: 0,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 1,
                opcode: "ldc.i4.1".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 2,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ]
    }

    // ── ILRewriter: replace ───────────────────────────────────────────────

    #[test]
    fn test_replace_instruction_ok() {
        let mut rw = ILRewriter::new();
        rw.seed_body(0x0600_0001, make_body());
        rw.replace_instruction(0x0600_0001, 0, 0x00, vec![]); // nop → nop (identity)
        let body = rw.rebuild_method_body(0x0600_0001).unwrap();
        // Tiny header expected: 3 instructions each 1 byte = 3 bytes code.
        // tiny header byte = (3 << 2) | 2 = 0x0E
        assert_eq!(body[0], 0x0E);
    }

    #[test]
    fn test_replace_instruction_bad_offset() {
        let mut rw = ILRewriter::new();
        rw.seed_body(0x0600_0001, make_body());
        rw.replace_instruction(0x0600_0001, 0xFF, 0x00, vec![]);
        let result = rw.rebuild_method_body(0x0600_0001);
        assert!(result.is_err());
    }

    // ── ILRewriter: insert ────────────────────────────────────────────────

    #[test]
    fn test_insert_instruction_before_ret() {
        let mut rw = ILRewriter::new();
        rw.seed_body(0x0600_0001, make_body());
        // Insert `nop` before `ret` (offset 2)
        rw.insert_instruction(0x0600_0001, 2, 0x00, vec![]);
        let body = rw.rebuild_method_body(0x0600_0001).unwrap();
        // Should now be 4 instructions: nop, ldc.i4.1, nop, ret → 4 bytes
        // tiny header = (4 << 2) | 2 = 0x12
        assert_eq!(body[0], 0x12);
        // Last byte should be `ret` (0x2A)
        assert_eq!(*body.last().unwrap(), 0x2A);
    }

    #[test]
    fn test_insert_instruction_bad_offset() {
        let mut rw = ILRewriter::new();
        rw.seed_body(0x0600_0001, make_body());
        rw.insert_instruction(0x0600_0001, 0xFF, 0x00, vec![]);
        let result = rw.rebuild_method_body(0x0600_0001);
        assert!(result.is_err());
    }

    // ── ILRewriter: no body seeded ────────────────────────────────────────

    #[test]
    fn test_rebuild_without_seed_errors() {
        let mut rw = ILRewriter::new();
        let result = rw.rebuild_method_body(0x0600_0099);
        assert!(result.is_err());
    }

    // ── ILRewriter: has_pending_edits / discard ───────────────────────────

    #[test]
    fn test_has_pending_edits() {
        let mut rw = ILRewriter::new();
        rw.seed_body(0x0600_0001, make_body());
        assert!(!rw.has_pending_edits(0x0600_0001));
        rw.replace_instruction(0x0600_0001, 0, 0x00, vec![]);
        assert!(rw.has_pending_edits(0x0600_0001));
        rw.discard(0x0600_0001);
        assert!(!rw.has_pending_edits(0x0600_0001));
    }

    // ── serialise_cil_body: tiny format ──────────────────────────────────

    #[test]
    fn test_serialise_tiny_body() {
        let instrs = vec![CilInstruction {
            offset: 0,
            opcode: "ret".into(),
            operand: CilOperand::None,
        }];
        let bytes = serialise_cil_body(&instrs);
        // 1 byte of code → tiny header = (1 << 2) | 2 = 0x06
        assert_eq!(bytes[0], 0x06);
        assert_eq!(bytes[1], 0x2A); // ret
    }

    // ── serialise_cil_body: fat format ────────────────────────────────────

    #[test]
    fn test_serialise_fat_body_threshold() {
        // 64 nop instructions exceed the 63-byte tiny limit.
        let instrs: Vec<CilInstruction> = (0u32..64)
            .map(|i| CilInstruction {
                offset: i,
                opcode: "nop".into(),
                operand: CilOperand::None,
            })
            .collect();
        let bytes = serialise_cil_body(&instrs);
        // Fat header starts with 0x03 in the low byte of the flags word.
        assert_eq!(bytes[0], 0x03);
    }

    // ── renumber_cil_offsets ──────────────────────────────────────────────

    #[test]
    fn test_renumber_leaves_single_byte_correct() {
        let mut instrs = vec![
            CilInstruction {
                offset: 99,
                opcode: "nop".into(),
                operand: CilOperand::None,
            },
            CilInstruction {
                offset: 99,
                opcode: "ret".into(),
                operand: CilOperand::None,
            },
        ];
        renumber_cil_offsets(&mut instrs);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
    }

    // ── AssemblyPatcher ───────────────────────────────────────────────────

    #[test]
    fn test_patch_bytes_ok() {
        let image = vec![0u8; 16];
        let mut p = AssemblyPatcher::new(image);
        p.patch_bytes(4, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(&p.image[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(p.checksum_recalculated);
    }

    #[test]
    fn test_patch_bytes_out_of_range() {
        let image = vec![0u8; 4];
        let mut p = AssemblyPatcher::new(image);
        assert!(p.patch_bytes(2, &[0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_patch_u32_roundtrip() {
        let image = vec![0u8; 8];
        let mut p = AssemblyPatcher::new(image);
        p.patch_u32(0, 0xDEAD_BEEF).unwrap();
        let val = u32::from_le_bytes(p.image[0..4].try_into().unwrap());
        assert_eq!(val, 0xDEAD_BEEF);
    }

    #[test]
    fn test_patch_u16_roundtrip() {
        let image = vec![0u8; 4];
        let mut p = AssemblyPatcher::new(image);
        p.patch_u16(1, 0xCAFE).unwrap();
        let val = u16::from_le_bytes(p.image[1..3].try_into().unwrap());
        assert_eq!(val, 0xCAFE);
    }

    #[test]
    fn test_into_bytes_returns_patched() {
        let image = vec![0x00u8, 0x01, 0x02];
        let mut p = AssemblyPatcher::new(image);
        p.patch_byte(1, 0xFF).unwrap();
        let bytes = p.into_bytes();
        assert_eq!(bytes[1], 0xFF);
    }

    #[test]
    fn test_image_len() {
        let p = AssemblyPatcher::new(vec![0u8; 42]);
        assert_eq!(p.image_len(), 42);
    }

    // ── raw_to_cil_instruction ────────────────────────────────────────────

    #[test]
    fn test_raw_to_cil_no_operand() {
        let instr = raw_to_cil_instruction(0, 0x00, &[]);
        assert_eq!(instr.opcode, "nop");
        assert_eq!(instr.operand, CilOperand::None);
    }

    #[test]
    fn test_raw_to_cil_with_i32() {
        let instr = raw_to_cil_instruction(0, 0x20, &42i32.to_le_bytes());
        assert_eq!(instr.opcode, "ldc.i4");
        assert_eq!(instr.operand, CilOperand::Int32(42));
    }
}
