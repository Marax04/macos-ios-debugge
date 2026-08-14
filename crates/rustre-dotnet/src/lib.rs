//! `rustre-dotnet`
//!
//! High-level .NET assembly model built on top of `rustre-dotnet-metadata`.
//! Provides ergonomic access to types, methods, fields, properties, events,
//! generic instantiations, custom attributes, and CIL method bodies.

pub mod cil_control_flow;
pub mod cil_stack_analyzer;
pub mod clr_analysis;
pub mod clr_jit_analysis;
pub mod clr_loader;
pub mod dotnet_heap_analyzer;
pub mod dotnet_il_printer;
pub mod dotnet_metadata_tables;
pub mod dotnet_packer_detection;
pub mod dotnet_string_decrypt;
pub mod il_decoder;
pub mod obfuscation_remover;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use ahash::AHashMap;
use anyhow::{Context, Result};
use rustre_dotnet_metadata::{FieldRow, MetadataReader, MethodDefRow, TypeDefRow};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DotnetError {
    TypeNotFound(String),
    MethodNotFound {
        type_name: String,
        method_name: String,
    },
    FieldNotFound {
        type_name: String,
        field_name: String,
    },
    InvalidSignature(String),
    IoError(std::io::Error),
}

impl fmt::Display for DotnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeNotFound(n) => write!(f, "type not found: {n}"),
            Self::MethodNotFound {
                type_name,
                method_name,
            } => {
                write!(f, "method {method_name} not found on type {type_name}")
            }
            Self::FieldNotFound {
                type_name,
                field_name,
            } => {
                write!(f, "field {field_name} not found on type {type_name}")
            }
            Self::InvalidSignature(s) => write!(f, "invalid signature: {s}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for DotnetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DotnetError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

// ─── CIL operand / instruction ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CilOperand {
    None,
    Int8(i8),
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    String(String),
    Token(u32),
    Branch(u32),
    Switch(Vec<u32>),
}

impl fmt::Display for CilOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, ""),
            Self::Int8(v) => write!(f, "{v}"),
            Self::Int32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}L"),
            Self::Float32(v) => write!(f, "{v}f"),
            Self::Float64(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Token(t) => write!(f, "0x{t:08X}"),
            Self::Branch(t) => write!(f, "IL_{t:04X}"),
            Self::Switch(targets) => {
                write!(f, "[")?;
                for (i, t) in targets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "IL_{t:04X}")?;
                }
                write!(f, "]")
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CilInstruction {
    pub offset: u32,
    pub opcode: String,
    pub operand: CilOperand,
}

impl CilInstruction {
    /// Create a no-operand instruction.
    #[must_use]
    pub fn simple(offset: u32, opcode: &str) -> Self {
        Self {
            offset,
            opcode: opcode.to_string(),
            operand: CilOperand::None,
        }
    }

    /// Create a branch instruction.
    #[must_use]
    pub fn branch(offset: u32, opcode: &str, target: u32) -> Self {
        Self {
            offset,
            opcode: opcode.to_string(),
            operand: CilOperand::Branch(target),
        }
    }

    /// Create a token-operand instruction.
    #[must_use]
    pub fn with_token(offset: u32, opcode: &str, token: u32) -> Self {
        Self {
            offset,
            opcode: opcode.to_string(),
            operand: CilOperand::Token(token),
        }
    }

    /// Create a 32-bit integer operand instruction.
    #[must_use]
    pub fn with_i32(offset: u32, opcode: &str, value: i32) -> Self {
        Self {
            offset,
            opcode: opcode.to_string(),
            operand: CilOperand::Int32(value),
        }
    }

    /// Returns true if this instruction is an unconditional branch.
    #[must_use]
    pub fn is_unconditional_branch(&self) -> bool {
        matches!(
            self.opcode.as_str(),
            "br" | "br.s" | "jmp" | "leave" | "leave.s"
        )
    }

    /// Returns true if this instruction is any kind of branch.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        matches!(
            self.opcode.as_str(),
            "br" | "br.s"
                | "brfalse"
                | "brfalse.s"
                | "brtrue"
                | "brtrue.s"
                | "beq"
                | "beq.s"
                | "bne.un"
                | "bne.un.s"
                | "bge"
                | "bge.s"
                | "bge.un"
                | "bge.un.s"
                | "bgt"
                | "bgt.s"
                | "bgt.un"
                | "bgt.un.s"
                | "ble"
                | "ble.s"
                | "ble.un"
                | "ble.un.s"
                | "blt"
                | "blt.s"
                | "blt.un"
                | "blt.un.s"
                | "leave"
                | "leave.s"
                | "switch"
        )
    }

    /// Returns true if this instruction terminates a basic block.
    #[must_use]
    pub fn is_terminator(&self) -> bool {
        self.is_branch()
            || matches!(
                self.opcode.as_str(),
                "ret" | "throw" | "rethrow" | "endfinally" | "endfilter"
            )
    }

    /// Returns all branch targets for this instruction.
    #[must_use]
    pub fn branch_targets(&self) -> Vec<u32> {
        match &self.operand {
            CilOperand::Branch(t) => vec![*t],
            CilOperand::Switch(targets) => targets.clone(),
            _ => vec![],
        }
    }

    /// Returns the instruction size in bytes (opcode + operand).
    #[must_use]
    pub fn byte_size(&self) -> usize {
        let opcode_size = if self.opcode.starts_with("prefix") {
            2
        } else {
            1
        };
        let operand_size = match &self.operand {
            CilOperand::None => 0,
            CilOperand::Int8(_) => 1,
            CilOperand::Int32(_) | CilOperand::Float32(_) | CilOperand::Token(_) | CilOperand::String(_) => 4,
            CilOperand::Int64(_) | CilOperand::Float64(_) => 8,
            CilOperand::Branch(_) => {
                if std::path::Path::new(&self.opcode)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("s"))
                {
                    1
                } else {
                    4
                }
            }
            CilOperand::Switch(targets) => 4 + targets.len() * 4,
            // treated as token
        };
        opcode_size + operand_size
    }
}

impl fmt::Display for CilInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04X}: {}", self.offset, self.opcode)?;
        if self.operand != CilOperand::None {
            write!(f, " {}", self.operand)?;
        }
        Ok(())
    }
}

// ─── Method body ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LocalVar {
    pub index: u32,
    pub type_name: String,
    pub is_pinned: bool,
}

impl LocalVar {
    /// Create a new local variable descriptor.
    #[must_use]
    pub fn new(index: u32, type_name: impl Into<String>) -> Self {
        Self {
            index,
            type_name: type_name.into(),
            is_pinned: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExceptionHandlerKind {
    #[default]
    Catch,
    Filter,
    Finally,
    Fault,
}

impl fmt::Display for ExceptionHandlerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catch => write!(f, "catch"),
            Self::Filter => write!(f, "filter"),
            Self::Finally => write!(f, "finally"),
            Self::Fault => write!(f, "fault"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExceptionHandler {
    pub kind: ExceptionHandlerKind,
    pub try_start: u32,
    pub try_end: u32,
    pub handler_start: u32,
    pub handler_end: u32,
    pub catch_type: Option<String>,
    pub filter_start: Option<u32>,
}

impl ExceptionHandler {
    /// Returns true if this handler protects the given offset.
    #[must_use]
    pub const fn protects(&self, offset: u32) -> bool {
        offset >= self.try_start && offset < self.try_end
    }

    /// Returns true if the given offset is inside the handler region.
    #[must_use]
    pub const fn handles(&self, offset: u32) -> bool {
        offset >= self.handler_start && offset < self.handler_end
    }
}

#[derive(Debug, Clone, Default)]
pub struct MethodBody {
    pub locals: Vec<LocalVar>,
    pub instructions: Vec<CilInstruction>,
    pub exception_handlers: Vec<ExceptionHandler>,
    pub max_stack: u16,
    pub init_locals: bool,
}

impl MethodBody {
    /// Return the instruction at the given CIL offset, if present.
    #[must_use]
    pub fn instruction_at(&self, offset: u32) -> Option<&CilInstruction> {
        self.instructions.iter().find(|i| i.offset == offset)
    }

    /// Return all instructions in the try-block protecting the given offset.
    #[must_use]
    pub fn try_instructions_for(&self, handler: &ExceptionHandler) -> Vec<&CilInstruction> {
        self.instructions
            .iter()
            .filter(|i| handler.protects(i.offset))
            .collect()
    }

    /// Return the set of all branch targets in this body.
    #[must_use]
    pub fn branch_targets(&self) -> Vec<u32> {
        let mut targets: Vec<u32> = self
            .instructions
            .iter()
            .flat_map(CilInstruction::branch_targets)
            .collect();
        targets.sort_unstable();
        targets.dedup();
        targets
    }

    /// Build a map from offset to instruction index.
    #[must_use]
    pub fn offset_map(&self) -> HashMap<u32, usize> {
        self.instructions
            .iter()
            .enumerate()
            .map(|(i, instr)| (instr.offset, i))
            .collect()
    }

    /// Count the instructions by opcode.
    #[must_use]
    pub fn opcode_histogram(&self) -> HashMap<&str, usize> {
        let mut map: HashMap<&str, usize> = HashMap::new();
        for instr in &self.instructions {
            *map.entry(instr.opcode.as_str()).or_insert(0) += 1;
        }
        map
    }

    /// Returns true if the body has any exception handlers.
    #[must_use]
    pub const fn has_exception_handlers(&self) -> bool {
        !self.exception_handlers.is_empty()
    }

    /// Returns true if the body has any try/finally blocks.
    #[must_use]
    pub fn has_finally(&self) -> bool {
        self.exception_handlers
            .iter()
            .any(|eh| eh.kind == ExceptionHandlerKind::Finally)
    }

    /// Returns the total byte size of all instructions.
    #[must_use]
    pub fn code_size(&self) -> usize {
        self.instructions.iter().map(CilInstruction::byte_size).sum()
    }
}

// ─── Method signature ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MethodSignature {
    pub return_type: String,
    pub params: Vec<(String, String)>, // (name, type)
    pub is_static: bool,
    pub is_vararg: bool,
    pub generic_param_count: u32,
}

impl MethodSignature {
    /// Format this signature as a C#-style string.
    #[must_use]
    pub fn format(&self, method_name: &str) -> String {
        let params = self
            .params
            .iter()
            .map(|(name, ty)| format!("{ty} {name}"))
            .collect::<Vec<_>>()
            .join(", ");
        if self.is_static {
            format!("static {} {}({params})", self.return_type, method_name)
        } else {
            format!("{} {}({params})", self.return_type, method_name)
        }
    }

    /// Returns the number of parameters (excluding `this` for instance methods).
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Returns true if this method returns void.
    #[must_use]
    pub fn returns_void(&self) -> bool {
        self.return_type == "void" || self.return_type == "System.Void"
    }
}

// ─── Generic parameter ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GenericParam {
    pub number: u16,
    pub name: String,
    pub flags: u16,
    pub constraints: Vec<String>,
}

impl GenericParam {
    /// Returns true if the parameter is constrained to be a reference type.
    #[must_use]
    pub const fn is_reference_type_constrained(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Returns true if the parameter is constrained to be a value type.
    #[must_use]
    pub const fn is_value_type_constrained(&self) -> bool {
        self.flags & 0x0008 != 0
    }

    /// Returns true if the parameter requires a default constructor.
    #[must_use]
    pub const fn has_default_constructor_constraint(&self) -> bool {
        self.flags & 0x0010 != 0
    }
}

// ─── Generic instantiation ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GenericInstantiation {
    pub open_type: String,
    pub type_arguments: Vec<String>,
}

impl GenericInstantiation {
    /// Format as a C#-style generic type name.
    #[must_use]
    pub fn format(&self) -> String {
        format!("{}<{}>", self.open_type, self.type_arguments.join(", "))
    }

    /// Returns the arity (number of type arguments).
    #[must_use]
    pub const fn arity(&self) -> usize {
        self.type_arguments.len()
    }
}

// ─── Custom attribute ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttributeArgument {
    pub name: Option<String>,
    pub value: AttributeValue,
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Bool(bool),
    Byte(u8),
    SByte(i8),
    Char(char),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Single(f32),
    Double(f64),
    String(String),
    Type(String),
    Array(Vec<Self>),
    Null,
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{v}"),
            Self::Byte(v) => write!(f, "{v}"),
            Self::SByte(v) => write!(f, "{v}"),
            Self::Char(v) => write!(f, "'{v}'"),
            Self::Int16(v) => write!(f, "{v}"),
            Self::UInt16(v) => write!(f, "{v}"),
            Self::Int32(v) => write!(f, "{v}"),
            Self::UInt32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}L"),
            Self::UInt64(v) => write!(f, "{v}UL"),
            Self::Single(v) => write!(f, "{v}f"),
            Self::Double(v) => write!(f, "{v}"),
            Self::String(v) => write!(f, "\"{v}\""),
            Self::Type(v) => write!(f, "typeof({v})"),
            Self::Array(vs) => {
                write!(f, "[")?;
                for (i, v) in vs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Self::Null => write!(f, "null"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CustomAttribute {
    pub attr_type: String,
    pub positional_args: Vec<AttributeValue>,
    pub named_args: Vec<AttributeArgument>,
    pub raw_blob: Vec<u8>,
}

impl CustomAttribute {
    /// Parse a `CustomAttribute` row from its raw blob.
    ///
    /// This is a simplified parser that reads fixed-layout attributes.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn from_blob(attr_type: impl Into<String>, blob: Vec<u8>) -> Self {
        Self {
            attr_type: attr_type.into(),
            positional_args: Vec::new(),
            named_args: Vec::new(),
            raw_blob: blob,
        }
    }

    /// Returns true if this attribute has the given type name (simple or fully qualified).
    #[must_use]
    pub fn is_type(&self, name: &str) -> bool {
        self.attr_type == name
            || self.attr_type.ends_with(&format!(".{name}"))
            || self.attr_type.ends_with(&format!("::{name}"))
    }
}

// ─── Security declaration ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityDeclaration {
    pub action: u16,
    pub permission_set: Vec<u8>,
}

// ─── Property / Event ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PropertyModel {
    pub name: String,
    pub type_name: String,
    pub flags: u16,
    pub getter: Option<String>,
    pub setter: Option<String>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub has_default: bool,
    pub default_value: Option<AttributeValue>,
}

impl PropertyModel {
    /// Returns true if the property has a getter.
    #[must_use]
    pub const fn has_getter(&self) -> bool {
        self.getter.is_some()
    }

    /// Returns true if the property has a setter.
    #[must_use]
    pub const fn has_setter(&self) -> bool {
        self.setter.is_some()
    }

    /// Returns true if the property is read-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.has_getter() && !self.has_setter()
    }

    /// Returns true if the property is write-only.
    #[must_use]
    pub const fn is_write_only(&self) -> bool {
        self.has_setter() && !self.has_getter()
    }

    /// Returns the C# property signature string.
    #[must_use]
    pub fn signature(&self) -> String {
        let accessors = match (self.has_getter(), self.has_setter()) {
            (true, true) => "{ get; set; }",
            (true, false) => "{ get; }",
            (false, true) => "{ set; }",
            (false, false) => "{ }",
        };
        format!("{} {} {accessors}", self.type_name, self.name)
    }
}

#[derive(Debug, Clone)]
pub struct EventModel {
    pub name: String,
    pub type_name: String,
    pub flags: u16,
    pub add: Option<String>,
    pub remove: Option<String>,
    pub raise: Option<String>,
    pub custom_attributes: Vec<CustomAttribute>,
}

impl EventModel {
    /// Returns true if the event has an add accessor.
    #[must_use]
    pub const fn has_add(&self) -> bool {
        self.add.is_some()
    }

    /// Returns true if the event has a remove accessor.
    #[must_use]
    pub const fn has_remove(&self) -> bool {
        self.remove.is_some()
    }
}

// ─── High-level method / field / type ─────────────────────────────────────────

/// Decoded method-definition flags (from `MethodDef.Flags`).
///
/// Stored as a raw `u32` so the struct carries no bool fields (which would
/// trigger the `struct_excessive_bools` lint).  All individual bits are
/// exposed as `const fn` methods.
#[derive(Debug, Clone, Copy, Default)]
pub struct MethodFlags {
    /// Raw `MethodDef.Flags` value.
    pub raw: u32,
}

impl MethodFlags {
    /// Parse flags from a raw `MethodDef.Flags` u32.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    #[must_use] pub const fn is_public(&self)           -> bool { (self.raw & 0x0007) == 0x06 }
    #[must_use] pub const fn is_private(&self)          -> bool { (self.raw & 0x0007) == 0x01 }
    #[must_use] pub const fn is_protected(&self)        -> bool { (self.raw & 0x0007) == 0x04 }
    #[must_use] pub const fn is_internal(&self)         -> bool { (self.raw & 0x0007) == 0x03 }
    #[must_use] pub const fn is_static(&self)           -> bool { self.raw & 0x0010 != 0 }
    #[must_use] pub const fn is_virtual(&self)          -> bool { self.raw & 0x0040 != 0 }
    #[must_use] pub const fn is_abstract(&self)         -> bool { self.raw & 0x0400 != 0 }
    #[must_use] pub const fn is_sealed(&self)           -> bool { self.raw & 0x0020 != 0 }
    #[must_use] pub const fn is_final(&self)            -> bool { self.raw & 0x0020 != 0 }
    #[must_use] pub const fn is_special_name(&self)     -> bool { self.raw & 0x0800 != 0 }
    #[must_use] pub const fn is_rt_special_name(&self)  -> bool { self.raw & 0x1000 != 0 }
    #[must_use] pub const fn is_pinvoke(&self)          -> bool { self.raw & 0x2000 != 0 }
    /// `RTSpecialName` set and access flags non-zero indicates .ctor.
    #[must_use] pub const fn is_constructor(&self)      -> bool {
        (self.raw & 0x1000 != 0) && (self.raw & 0x0007) != 0
    }
    #[must_use] pub const fn is_class_constructor(&self) -> bool { false }

    /// Returns the C# access modifier string.
    #[must_use]
    pub const fn access_modifier(&self) -> &'static str {
        if self.is_public() {
            "public"
        } else if self.is_protected() {
            "protected"
        } else if self.is_internal() {
            "internal"
        } else {
            "private"
        }
    }
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct DotnetMethod {
    pub name: String,
    pub signature: MethodSignature,
    pub body: Option<MethodBody>,
    pub flags: u32,
    pub rva: u32,
    pub impl_flags: u16,
    pub custom_attributes: Vec<CustomAttribute>,
    pub generic_params: Vec<GenericParam>,
    pub overrides: Vec<String>,
}

impl DotnetMethod {
    /// Returns true if the method is a constructor.
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name == ".ctor"
    }

    /// Returns true if the method is a static constructor.
    #[must_use]
    pub fn is_static_constructor(&self) -> bool {
        self.name == ".cctor"
    }

    /// Returns true if the method is a property accessor.
    #[must_use]
    pub fn is_property_accessor(&self) -> bool {
        self.name.starts_with("get_") || self.name.starts_with("set_")
    }

    /// Returns true if the method is an event accessor.
    #[must_use]
    pub fn is_event_accessor(&self) -> bool {
        self.name.starts_with("add_")
            || self.name.starts_with("remove_")
            || self.name.starts_with("raise_")
    }

    /// Returns the parsed `MethodFlags` for this method.
    #[must_use]
    pub const fn method_flags(&self) -> MethodFlags {
        MethodFlags::from_raw(self.flags)
    }

    /// Returns true if the method is static.
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Returns true if the method is virtual.
    #[must_use]
    pub const fn is_virtual(&self) -> bool {
        self.flags & 0x0040 != 0
    }

    /// Returns true if the method is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// Returns true if the method has a body.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.body.is_some()
    }

    /// Returns the instruction count, or 0 if there is no body.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.body
            .as_ref()
            .map_or(0, |b| b.instructions.len())
    }

    /// Returns the number of parameters.
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.signature.params.len()
    }

    /// Returns all branch instructions in the body.
    #[must_use]
    pub fn branch_instructions(&self) -> Vec<&CilInstruction> {
        self.body
            .as_ref()
            .map(|b| b.instructions.iter().filter(|i| i.is_branch()).collect())
            .unwrap_or_default()
    }

    /// Returns true if this method has any custom attributes.
    #[must_use]
    pub const fn has_custom_attributes(&self) -> bool {
        !self.custom_attributes.is_empty()
    }

    /// Returns the first custom attribute matching the given type name, if any.
    #[must_use]
    pub fn get_custom_attribute(&self, attr_type: &str) -> Option<&CustomAttribute> {
        self.custom_attributes.iter().find(|a| a.is_type(attr_type))
    }
}


/// Decoded field-definition flags (from `Field.Flags`).
///
/// Stored as a raw `u16` to avoid `struct_excessive_bools`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FieldFlags {
    /// Raw `Field.Flags` value.
    pub raw: u16,
}

impl FieldFlags {
    /// Parse field flags from the raw `Field.Flags` u16.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self { raw }
    }

    #[must_use] pub const fn is_public(&self)          -> bool { (self.raw as u32) & 0x0007 == 0x06 }
    #[must_use] pub const fn is_private(&self)         -> bool { (self.raw as u32) & 0x0007 == 0x01 }
    #[must_use] pub const fn is_protected(&self)       -> bool { (self.raw as u32) & 0x0007 == 0x04 }
    #[must_use] pub const fn is_internal(&self)        -> bool { (self.raw as u32) & 0x0007 == 0x03 }
    #[must_use] pub const fn is_static(&self)          -> bool { self.raw & 0x0010 != 0 }
    #[must_use] pub const fn is_init_only(&self)       -> bool { self.raw & 0x0020 != 0 }
    #[must_use] pub const fn is_literal(&self)         -> bool { self.raw & 0x0040 != 0 }
    #[must_use] pub const fn is_not_serialized(&self)  -> bool { self.raw & 0x0080 != 0 }
    #[must_use] pub const fn is_special_name(&self)    -> bool { self.raw & 0x0200 != 0 }
    #[must_use] pub const fn has_default(&self)        -> bool { self.raw & 0x8000 != 0 }
    #[must_use] pub const fn has_field_rva(&self)      -> bool { self.raw & 0x0100 != 0 }

    /// Returns the C# access modifier string.
    #[must_use]
    pub const fn access_modifier(&self) -> &'static str {
        if self.is_public() {
            "public"
        } else if self.is_protected() {
            "protected"
        } else if self.is_internal() {
            "internal"
        } else {
            "private"
        }
    }
}

#[derive(Debug, Clone)]
#[derive(Default)]
pub struct DotnetField {
    pub name: String,
    pub type_name: String,
    pub flags: u32,
    pub is_static: bool,
    pub custom_attributes: Vec<CustomAttribute>,
    pub marshal_info: Option<MarshalInfo>,
    pub constant_value: Option<AttributeValue>,
    pub field_rva: Option<u32>,
    pub offset: Option<u32>,
}

impl DotnetField {
    /// Returns true if this field is a constant (literal).
    #[must_use]
    pub const fn is_literal(&self) -> bool {
        self.flags & 0x0040 != 0
    }

    /// Returns true if this field is read-only.
    #[must_use]
    pub const fn is_init_only(&self) -> bool {
        self.flags & 0x0020 != 0
    }

    /// Returns the parsed `FieldFlags`.
    #[must_use]
    pub fn field_flags(&self) -> FieldFlags {
        FieldFlags::from_raw(u16::try_from(self.flags).unwrap_or(u16::MAX))
    }

    /// Formats this field as a C# declaration.
    #[must_use]
    pub fn format(&self) -> String {
        let mods = if self.is_static {
            "public static"
        } else {
            "public"
        };
        format!("{mods} {} {};", self.type_name, self.name)
    }
}


// ─── Marshal info ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MarshalInfo {
    pub native_type: u8,
    pub blob: Vec<u8>,
}

// ─── Class layout ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ClassLayout {
    pub packing_size: u16,
    pub class_size: u32,
}

// ─── Type flags ───────────────────────────────────────────────────────────────

/// Decoded type-definition flags (from `TypeDef.Flags`).
///
/// Stored as a raw `u32` to avoid `struct_excessive_bools`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TypeFlags {
    /// Raw `TypeDef.Flags` value.
    pub raw: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TypeVisibility {
    #[default]
    NotPublic,
    Public,
    NestedPublic,
    NestedPrivate,
    NestedFamily,
    NestedAssembly,
    NestedFamilyAndAssembly,
    NestedFamilyOrAssembly,
}

impl TypeFlags {
    /// Parse type flags from a raw `TypeDef.Flags` u32.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    /// Returns the type visibility.
    #[must_use]
    pub const fn visibility(&self) -> TypeVisibility {
        match self.raw & 0x0007 {
            0x01 => TypeVisibility::Public,
            0x02 => TypeVisibility::NestedPublic,
            0x03 => TypeVisibility::NestedPrivate,
            0x04 => TypeVisibility::NestedFamily,
            0x05 => TypeVisibility::NestedAssembly,
            0x06 => TypeVisibility::NestedFamilyAndAssembly,
            0x07 => TypeVisibility::NestedFamilyOrAssembly,
            _ => TypeVisibility::NotPublic,
        }
    }

    #[must_use] pub const fn is_sealed(&self)           -> bool { self.raw & 0x0100 != 0 }
    #[must_use] pub const fn is_abstract(&self)         -> bool { self.raw & 0x0080 != 0 }
    #[must_use] pub const fn is_interface(&self)        -> bool { self.raw & 0x0020 != 0 }
    #[must_use] pub const fn is_explicit_layout(&self)  -> bool { (self.raw & 0x0018) == 0x0010 }
    #[must_use] pub const fn is_sequential_layout(&self)-> bool { (self.raw & 0x0018) == 0x0008 }
    #[must_use] pub const fn is_unicode(&self)          -> bool { self.raw & 0x0001_0000 != 0 }
    #[must_use] pub const fn is_ansi(&self)             -> bool { self.raw & 0x0002_0000 == 0 }
    #[must_use] pub const fn is_auto_class(&self)       -> bool { self.raw & 0x0003_0000 == 0x0002_0000 }
    #[must_use] pub const fn is_serializable(&self)     -> bool { self.raw & 0x0000_2000 != 0 }
    #[must_use] pub const fn is_before_field_init(&self)-> bool { self.raw & 0x0010_0000 != 0 }
    #[must_use] pub const fn is_rt_special_name(&self)  -> bool { self.raw & 0x0000_0800 != 0 }
    #[must_use] pub const fn is_special_name(&self)     -> bool { self.raw & 0x0000_0400 != 0 }
    #[must_use] pub const fn is_import(&self)           -> bool { self.raw & 0x0000_1000 != 0 }
    #[must_use] pub const fn has_security(&self)        -> bool { self.raw & 0x0004_0000 != 0 }
}

// ─── High-level type ──────────────────────────────────────────────────────────

/// The semantic kind of a .NET type (replaces five bool fields on `DotnetType`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DotnetTypeKind {
    #[default]
    Class,
    Interface,
    Struct,
    Enum,
    Delegate,
}

#[derive(Debug, Clone)]
pub struct DotnetType {
    pub name: String,
    pub namespace: String,
    pub full_name: String,
    pub base_type: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<DotnetMethod>,
    pub fields: Vec<DotnetField>,
    pub properties: Vec<PropertyModel>,
    pub events: Vec<EventModel>,
    pub nested_types: Vec<String>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub generic_params: Vec<GenericParam>,
    /// The semantic kind of this type (replaces the individual `is_class`/`is_interface`/… bools).
    pub kind_tag: DotnetTypeKind,
    pub flags: u32,
    pub layout: Option<ClassLayout>,
}

impl DotnetType {
    /// Returns true if this type is a class.
    #[must_use] pub fn is_class(&self)     -> bool { self.kind_tag == DotnetTypeKind::Class }
    /// Returns true if this type is an interface.
    #[must_use] pub fn is_interface(&self) -> bool { self.kind_tag == DotnetTypeKind::Interface }
    /// Returns true if this type is a struct.
    #[must_use] pub fn is_struct(&self)    -> bool { self.kind_tag == DotnetTypeKind::Struct }
    /// Returns true if this type is an enum.
    #[must_use] pub fn is_enum(&self)      -> bool { self.kind_tag == DotnetTypeKind::Enum }
    /// Returns true if this type is a delegate.
    #[must_use] pub fn is_delegate(&self)  -> bool { self.kind_tag == DotnetTypeKind::Delegate }

    /// Returns the C# access modifier.
    #[must_use]
    pub const fn access_modifier(&self) -> &'static str {
        let flags = TypeFlags::from_raw(self.flags);
        match flags.visibility() {
            TypeVisibility::Public | TypeVisibility::NestedPublic => "public",
            TypeVisibility::NestedPrivate => "private",
            TypeVisibility::NestedFamily => "protected",
            TypeVisibility::NestedAssembly | TypeVisibility::NotPublic => "internal",
            TypeVisibility::NestedFamilyOrAssembly => "protected internal",
            TypeVisibility::NestedFamilyAndAssembly => "private protected",
        }
    }

    /// Returns the kind keyword: "class", "interface", "struct", "enum", or "delegate".
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self.kind_tag {
            DotnetTypeKind::Interface => "interface",
            DotnetTypeKind::Enum      => "enum",
            DotnetTypeKind::Struct    => "struct",
            DotnetTypeKind::Delegate  => "delegate",
            DotnetTypeKind::Class     => "class",
        }
    }

    /// Returns true if the type is abstract.
    #[must_use]
    pub const fn is_abstract(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Returns true if the type is sealed.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Find a method by name.
    #[must_use]
    pub fn find_method(&self, name: &str) -> Option<&DotnetMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Find all methods matching a name (overloads).
    #[must_use]
    pub fn find_methods(&self, name: &str) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.name == name).collect()
    }

    /// Find a field by name.
    #[must_use]
    pub fn find_field(&self, name: &str) -> Option<&DotnetField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Find a property by name.
    #[must_use]
    pub fn find_property(&self, name: &str) -> Option<&PropertyModel> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// Find an event by name.
    #[must_use]
    pub fn find_event(&self, name: &str) -> Option<&EventModel> {
        self.events.iter().find(|e| e.name == name)
    }

    /// Returns all constructors.
    #[must_use]
    pub fn constructors(&self) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.is_constructor()).collect()
    }

    /// Returns the static constructor, if present.
    #[must_use]
    pub fn static_constructor(&self) -> Option<&DotnetMethod> {
        self.methods.iter().find(|m| m.is_static_constructor())
    }

    /// Returns all static methods.
    #[must_use]
    pub fn static_methods(&self) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.is_static()).collect()
    }

    /// Returns all instance methods (excluding constructors).
    #[must_use]
    pub fn instance_methods(&self) -> Vec<&DotnetMethod> {
        self.methods
            .iter()
            .filter(|m| !m.is_static() && !m.is_constructor() && !m.is_static_constructor())
            .collect()
    }

    /// Returns all virtual methods.
    #[must_use]
    pub fn virtual_methods(&self) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.is_virtual()).collect()
    }

    /// Returns all abstract methods.
    #[must_use]
    pub fn abstract_methods(&self) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.is_abstract()).collect()
    }

    /// Returns all static fields.
    #[must_use]
    pub fn static_fields(&self) -> Vec<&DotnetField> {
        self.fields.iter().filter(|f| f.is_static).collect()
    }

    /// Returns all instance fields.
    #[must_use]
    pub fn instance_fields(&self) -> Vec<&DotnetField> {
        self.fields.iter().filter(|f| !f.is_static).collect()
    }

    /// Returns all constant (literal) fields.
    #[must_use]
    pub fn constant_fields(&self) -> Vec<&DotnetField> {
        self.fields.iter().filter(|f| f.is_literal()).collect()
    }

    /// Returns the first custom attribute of the given type, if present.
    #[must_use]
    pub fn get_custom_attribute(&self, attr_type: &str) -> Option<&CustomAttribute> {
        self.custom_attributes.iter().find(|a| a.is_type(attr_type))
    }

    /// Returns true if the type has any custom attributes.
    #[must_use]
    pub const fn has_custom_attributes(&self) -> bool {
        !self.custom_attributes.is_empty()
    }

    /// Returns true if the type implements a given interface.
    #[must_use]
    pub fn implements(&self, interface_name: &str) -> bool {
        self.interfaces
            .iter()
            .any(|i| i == interface_name || i.ends_with(&format!(".{interface_name}")))
    }

    /// Returns the total method count including inherited (stub — returns only direct).
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.methods.len()
    }

    /// Returns the total field count.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ─── Assembly information ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AssemblyVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

impl fmt::Display for AssemblyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyInfo {
    pub name: String,
    pub version: AssemblyVersion,
    pub culture: String,
    pub public_key: Vec<u8>,
    pub hash_alg: u32,
    pub flags: u32,
}

impl AssemblyInfo {
    /// Returns true if the assembly is strong-named.
    #[must_use]
    pub const fn is_strong_named(&self) -> bool {
        !self.public_key.is_empty()
    }

    /// Returns true if the assembly is a retargetable assembly.
    #[must_use]
    pub const fn is_retargetable(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Returns the simple display name with version.
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{}, Version={}", self.name, self.version)
    }
}

// ─── Assembly reference ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AssemblyReference {
    pub name: String,
    pub version: AssemblyVersion,
    pub culture: String,
    pub public_key_or_token: Vec<u8>,
    pub hash_value: Vec<u8>,
    pub flags: u32,
}

impl AssemblyReference {
    /// Returns true if this reference is to a retargetable assembly.
    #[must_use]
    pub const fn is_retargetable(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Returns the display string for this reference.
    #[must_use]
    pub fn display_name(&self) -> String {
        format!("{}, Version={}", self.name, self.version)
    }
}

// ─── Module info ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ModuleInfo {
    pub name: String,
    pub mvid: [u8; 16],
}

// ─── CIL opcode table (full ECMA-335 §III) ───────────────────────────────────

const fn opcode_name(op: u16) -> &'static str {
    match op {
        0x00 => "nop",        0x01 => "break",
        0x02 => "ldarg.0",    0x03 => "ldarg.1",
        0x04 => "ldarg.2",    0x05 => "ldarg.3",
        0x06 => "ldloc.0",    0x07 => "ldloc.1",
        0x08 => "ldloc.2",    0x09 => "ldloc.3",
        0x0A => "stloc.0",    0x0B => "stloc.1",
        0x0C => "stloc.2",    0x0D => "stloc.3",
        0x0E => "ldarg.s",    0x0F => "ldarga.s",
        0x10 => "starg.s",    0x11 => "ldloc.s",
        0x12 => "ldloca.s",   0x13 => "stloc.s",
        0x14 => "ldnull",     0x15 => "ldc.i4.m1",
        0x16 => "ldc.i4.0",   0x17 => "ldc.i4.1",
        0x18 => "ldc.i4.2",   0x19 => "ldc.i4.3",
        0x1A => "ldc.i4.4",   0x1B => "ldc.i4.5",
        0x1C => "ldc.i4.6",   0x1D => "ldc.i4.7",
        0x1E => "ldc.i4.8",   0x1F => "ldc.i4.s",
        0x20 => "ldc.i4",     0x21 => "ldc.i8",
        0x22 => "ldc.r4",     0x23 => "ldc.r8",
        0x25 => "dup",        0x26 => "pop",
        0x27 => "jmp",        0x28 => "call",
        0x29 => "calli",      0x2A => "ret",
        0x2B => "br.s",       0x2C => "brfalse.s",
        0x2D => "brtrue.s",   0x2E => "beq.s",
        0x2F => "bge.s",      0x30 => "bgt.s",
        0x31 => "ble.s",      0x32 => "blt.s",
        0x33 => "bne.un.s",   0x34 => "bge.un.s",
        0x35 => "bgt.un.s",   0x36 => "ble.un.s",
        0x37 => "blt.un.s",   0x38 => "br",
        0x39 => "brfalse",    0x3A => "brtrue",
        0x3B => "beq",        0x3C => "bge",
        0x3D => "bgt",        0x3E => "ble",
        0x3F => "blt",        0x40 => "bne.un",
        0x41 => "bge.un",     0x42 => "bgt.un",
        0x43 => "ble.un",     0x44 => "blt.un",
        0x45 => "switch",     0x46 => "ldind.i1",
        0x47 => "ldind.u1",   0x48 => "ldind.i2",
        0x49 => "ldind.u2",   0x4A => "ldind.i4",
        0x4B => "ldind.u4",   0x4C => "ldind.i8",
        0x4D => "ldind.i",    0x4E => "ldind.r4",
        0x4F => "ldind.r8",   0x50 => "ldind.ref",
        _ => opcode_name_hi(op),
    }
}

const fn opcode_name_hi(op: u16) -> &'static str {
    match op {
        0x51 => "stind.ref",  0x52 => "stind.i1",
        0x53 => "stind.i2",   0x54 => "stind.i4",
        0x55 => "stind.i8",   0x56 => "stind.r4",
        0x57 => "stind.r8",   0x58 => "add",
        0x59 => "sub",        0x5A => "mul",
        0x5B => "div",        0x5C => "div.un",
        0x5D => "rem",        0x5E => "rem.un",
        0x5F => "and",        0x60 => "or",
        0x61 => "xor",        0x62 => "shl",
        0x63 => "shr",        0x64 => "shr.un",
        0x65 => "neg",        0x66 => "not",
        0x67 => "conv.i1",    0x68 => "conv.i2",
        0x69 => "conv.i4",    0x6A => "conv.i8",
        0x6B => "conv.r4",    0x6C => "conv.r8",
        0x6D => "conv.u4",    0x6E => "conv.u8",
        0x6F => "callvirt",   0x70 => "cpobj",
        0x71 => "ldobj",      0x72 => "ldstr",
        0x73 => "newobj",     0x74 => "castclass",
        0x75 => "isinst",     0x76 => "conv.r.un",
        0x79 => "unbox",      0x7A => "throw",
        0x7B => "ldfld",      0x7C => "ldflda",
        0x7D => "stfld",      0x7E => "ldsfld",
        0x7F => "ldsflda",    0x80 => "stsfld",
        0x81 => "stobj",      0x82 => "conv.ovf.i1.un",
        0x83 => "conv.ovf.i2.un", 0x84 => "conv.ovf.i4.un",
        0x85 => "conv.ovf.i8.un", 0x86 => "conv.ovf.u1.un",
        0x87 => "conv.ovf.u2.un", 0x88 => "conv.ovf.u4.un",
        0x89 => "conv.ovf.u8.un", 0x8A => "conv.ovf.i.un",
        0x8B => "conv.ovf.u.un",  0x8C => "box",
        0x8D => "newarr",     0x8E => "ldlen",
        0x8F => "ldelema",    0x90 => "ldelem.i1",
        0x91 => "ldelem.u1",  0x92 => "ldelem.i2",
        0x93 => "ldelem.u2",  0x94 => "ldelem.i4",
        0x95 => "ldelem.u4",  0x96 => "ldelem.i8",
        0x97 => "ldelem.i",   0x98 => "ldelem.r4",
        0x99 => "ldelem.r8",  0x9A => "ldelem.ref",
        0x9B => "stelem.i",   0x9C => "stelem.i1",
        0x9D => "stelem.i2",  0x9E => "stelem.i4",
        0x9F => "stelem.i8",  0xA0 => "stelem.r4",
        0xA1 => "stelem.r8",  0xA2 => "stelem.ref",
        0xA3 => "ldelem",     0xA4 => "stelem",
        0xA5 => "unbox.any",  0xB3 => "conv.ovf.i1",
        0xB4 => "conv.ovf.u1", 0xB5 => "conv.ovf.i2",
        0xB6 => "conv.ovf.u2", 0xB7 => "conv.ovf.i4",
        0xB8 => "conv.ovf.u4", 0xB9 => "conv.ovf.i8",
        0xBA => "conv.ovf.u8", 0xC2 => "refanyval",
        0xC3 => "ckfinite",   0xC6 => "mkrefany",
        0xD0 => "ldtoken",    0xD1 => "conv.u2",
        0xD2 => "conv.u1",    0xD3 => "conv.i",
        0xD4 => "conv.ovf.i", 0xD5 => "conv.ovf.u",
        0xD6 => "add.ovf",    0xD7 => "add.ovf.un",
        0xD8 => "mul.ovf",    0xD9 => "mul.ovf.un",
        0xDA => "sub.ovf",    0xDB => "sub.ovf.un",
        0xDC => "endfinally", 0xDD => "leave",
        0xDE => "leave.s",    0xDF => "stind.i",
        0xE0 => "conv.u",     0xFE => "prefix1",
        _ => "unknown",
    }
}

const fn prefix1_opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "arglist",
        0x01 => "ceq",
        0x02 => "cgt",
        0x03 => "cgt.un",
        0x04 => "clt",
        0x05 => "clt.un",
        0x06 => "ldftn",
        0x07 => "ldvirtftn",
        0x09 => "ldarg",
        0x0A => "ldarga",
        0x0B => "starg",
        0x0C => "ldloc",
        0x0D => "ldloca",
        0x0E => "stloc",
        0x0F => "localloc",
        0x11 => "endfilter",
        0x12 => "unaligned.",
        0x13 => "volatile.",
        0x14 => "tail.",
        0x15 => "initobj",
        0x16 => "constrained.",
        0x17 => "cpblk",
        0x18 => "initblk",
        0x19 => "no.",
        0x1A => "rethrow",
        0x1C => "sizeof",
        0x1D => "refanytype",
        0x1E => "readonly.",
        _ => "prefix.unknown",
    }
}

// ─── CIL body parser ──────────────────────────────────────────────────────────

const fn decode_element_type(b: u8) -> &'static str {
    match b {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "sbyte",
        0x05 => "byte",
        0x06 => "short",
        0x07 => "ushort",
        0x08 => "int",
        0x09 => "uint",
        0x0A => "long",
        0x0B => "ulong",
        0x0C => "float",
        0x0D => "double",
        0x0E => "string",
        0x0F => "TypedReference",
        0x10 | 0x18 => "IntPtr",
        0x11 => "valuetype",
        0x12 => "class",
        0x13 => "T",
        0x14 => "array",
        0x15 => "Generic",
        0x16 => "TypedByRef",
        0x19 => "UIntPtr",
        0x1B => "FnPtr",
        0x1C => "object",
        0x1D => "SzArray",
        0x1E => "MVar",
        0x1F => "RequiredModifier",
        0x20 => "OptionalModifier",
        0x41 => "Sentinel",
        0x45 => "Pinned",
        _ => "unknown",
    }
}

fn parse_method_body(data: &[u8], rva: u32) -> Option<MethodBody> {
    if rva == 0 || data.is_empty() {
        return None;
    }
    let mut body = MethodBody::default();
    let bytes = data;
    if bytes.is_empty() {
        return Some(body);
    }

    let first = bytes[0];
    let (code_start, code_len, max_stack, init_locals) = if first & 0x03 == 0x02 {
        let code_size = usize::from(first >> 2);
        (1usize, code_size, 8u16, false)
    } else if first & 0x03 == 0x03 {
        if bytes.len() < 12 {
            return None;
        }
        let flags = u16::from_le_bytes([bytes[0], bytes[1]]);
        // Fat header size field is in units of 4 bytes; must be at least 3 (= 12 bytes).
        let header_size = ((flags >> 12) as usize).max(3) * 4;
        if header_size > bytes.len() {
            return None;
        }
        let ms = u16::from_le_bytes([bytes[2], bytes[3]]);
        let code_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let il = (flags & 0x0010) != 0;
        (header_size, code_size, ms, il)
    } else {
        return None;
    };

    body.max_stack = max_stack;
    body.init_locals = init_locals;

    let end = (code_start + code_len).min(bytes.len());
    let code = &bytes[code_start..end];
    let mut pos = 0usize;
    let base_offset = 0u32;

    while pos < code.len() {
        let instr_offset = base_offset + u32::try_from(pos).unwrap_or(u32::MAX);
        let op_byte = code[pos];
        pos += 1;

        if op_byte == 0xFE && pos < code.len() {
            let sub = code[pos];
            pos += 1;
            let name = prefix1_opcode_name(sub).to_string();
            let operand = if matches!(
                sub,
                0x06 | 0x07 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x0E | 0x15 | 0x16 | 0x1C
            ) {
                if pos + 4 <= code.len() {
                    let t = u32::from_le_bytes(code[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    CilOperand::Token(t)
                } else {
                    CilOperand::None
                }
            } else if sub == 0x12 {
                if pos < code.len() {
                    pos += 1;
                }
                CilOperand::None
            } else {
                CilOperand::None
            };
            body.instructions.push(CilInstruction {
                offset: instr_offset,
                opcode: name,
                operand,
            });
            continue;
        }

        let (name, operand) = decode_operand(op_byte, code, &mut pos, base_offset);
        body.instructions.push(CilInstruction {
            offset: instr_offset,
            opcode: name,
            operand,
        });
    }

    Some(body)
}

fn decode_operand(op: u8, code: &[u8], pos: &mut usize, base: u32) -> (String, CilOperand) {
    let name = opcode_name(u16::from(op)).to_string();
    let operand = match op {
        0x0E | 0x0F | 0x10 | 0x11 | 0x12 | 0x13 | 0x1F => {
            if *pos < code.len() {
                let v = code[*pos].cast_signed();
                *pos += 1;
                if op == 0x1F { CilOperand::Int8(v) } else { CilOperand::Int32(i32::from(v.cast_unsigned())) }
            } else { CilOperand::None }
        }
        0x20 => {
            if *pos + 4 <= code.len() {
                let v = i32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                *pos += 4; CilOperand::Int32(v)
            } else { CilOperand::None }
        }
        0x21 => {
            if *pos + 8 <= code.len() {
                let v = i64::from_le_bytes(code[*pos..*pos + 8].try_into().unwrap());
                *pos += 8; CilOperand::Int64(v)
            } else { CilOperand::None }
        }
        0x22 => {
            if *pos + 4 <= code.len() {
                let bits = u32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                *pos += 4; CilOperand::Float32(f32::from_bits(bits))
            } else { CilOperand::None }
        }
        0x23 => {
            if *pos + 8 <= code.len() {
                let bits = u64::from_le_bytes(code[*pos..*pos + 8].try_into().unwrap());
                *pos += 8; CilOperand::Float64(f64::from_bits(bits))
            } else { CilOperand::None }
        }
        0x2B..=0x37 | 0xDE => {
            if *pos < code.len() {
                let delta = code[*pos].cast_signed();
                *pos += 1;
                let raw = i64::try_from(*pos).unwrap_or(i64::MAX) + i64::from(delta) + i64::from(base);
                CilOperand::Branch(u32::try_from(raw).unwrap_or(u32::MAX))
            } else { CilOperand::None }
        }
        0x38..=0x44 | 0xDD => {
            if *pos + 4 <= code.len() {
                let delta = i32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                *pos += 4;
                let raw = i64::try_from(*pos).unwrap_or(i64::MAX) + i64::from(delta) + i64::from(base);
                CilOperand::Branch(u32::try_from(raw).unwrap_or(u32::MAX))
            } else { CilOperand::None }
        }
        _ => decode_operand_hi(op, code, pos, base),
    };
    (name, operand)
}

// Switch and token operand decoding (continuation of decode_operand).
fn decode_operand_hi(op: u8, code: &[u8], pos: &mut usize, base: u32) -> CilOperand {
    match op {
        0x45 => {
            if *pos + 4 <= code.len() {
                let n_u32 = u32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                *pos += 4;
                let n = usize::try_from(n_u32).unwrap_or(usize::MAX / 4);
                let targets_bytes = n.saturating_mul(4);
                let after_raw = i64::try_from((*pos).saturating_add(targets_bytes))
                    .unwrap_or(i64::MAX)
                    .saturating_add(i64::from(base));
                let available = code.len().saturating_sub(*pos) / 4;
                let n = n.min(available);
                let mut targets = Vec::with_capacity(n);
                for _ in 0..n {
                    if *pos + 4 <= code.len() {
                        let delta = i32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                        *pos += 4;
                        targets.push(u32::try_from(after_raw.saturating_add(i64::from(delta))).unwrap_or(u32::MAX));
                    }
                }
                CilOperand::Switch(targets)
            } else { CilOperand::None }
        }
        0x27..=0x29
        | 0x6F..=0x75
        | 0x79
        | 0x7B..=0x80
        | 0x81
        | 0x8C
        | 0x8D
        | 0x8F
        | 0xA3..=0xA5
        | 0xC2
        | 0xC6
        | 0xD0 => {
            if *pos + 4 <= code.len() {
                let t = u32::from_le_bytes(code[*pos..*pos + 4].try_into().unwrap());
                *pos += 4; CilOperand::Token(t)
            } else { CilOperand::None }
        }
        _ => CilOperand::None,
    }
}

// ─── Signature decoder ────────────────────────────────────────────────────────

fn decode_element_type_from_blob(sig: &[u8], pos: &mut usize) -> String {
    decode_element_type_from_blob_depth(sig, pos, 0)
}

fn decode_element_type_from_blob_depth(sig: &[u8], pos: &mut usize, depth: u32) -> String {
    // Guard against unbounded recursion from malformed nested SzArray / Generic types.
    if depth > 32 {
        return "object".to_string();
    }
    if *pos >= sig.len() {
        return "void".to_string();
    }
    let b = sig[*pos];
    *pos += 1;
    match b {
        0x1D => {
            // SzArray — decode element type
            let elem = decode_element_type_from_blob_depth(sig, pos, depth + 1);
            format!("{elem}[]")
        }
        0x11 | 0x12 => {
            // valuetype / class — skip type token (compressed uint)
            skip_compressed_uint(sig, pos);
            decode_element_type(b).to_string()
        }
        0x15 => {
            // Generic instantiation: GENERICINST (class|valuetype) Type TypeArgCount Type*
            *pos += 1; // class or valuetype byte
            skip_compressed_uint(sig, pos); // open type token
            let count = read_compressed_uint(sig, pos);
            // Cap the arg count to remaining bytes to avoid excessive allocations.
            let count = count.min(u32::try_from(sig.len().saturating_sub(*pos)).unwrap_or(u32::MAX));
            let mut args = Vec::new();
            for _ in 0..count {
                args.push(decode_element_type_from_blob_depth(sig, pos, depth + 1));
            }
            format!("Generic<{}>", args.join(", "))
        }
        _ => decode_element_type(b).to_string(),
    }
}

fn skip_compressed_uint(sig: &[u8], pos: &mut usize) {
    if *pos >= sig.len() {
        return;
    }
    let b = sig[*pos];
    if b & 0x80 == 0 {
        *pos += 1;
    } else if b & 0xC0 == 0x80 {
        *pos += 2;
    } else {
        *pos += 4;
    }
}

fn read_compressed_uint(sig: &[u8], pos: &mut usize) -> u32 {
    if *pos >= sig.len() {
        return 0;
    }
    let b = sig[*pos];
    if b & 0x80 == 0 {
        *pos += 1;
        u32::from(b)
    } else if b & 0xC0 == 0x80 {
        if *pos + 2 > sig.len() {
            return 0;
        }
        let v = (u32::from(b & 0x3F) << 8) | u32::from(sig[*pos + 1]);
        *pos += 2;
        v
    } else if *pos + 4 <= sig.len() {
        let v = (u32::from(b & 0x1F) << 24)
            | (u32::from(sig[*pos + 1]) << 16)
            | (u32::from(sig[*pos + 2]) << 8)
            | u32::from(sig[*pos + 3]);
        *pos += 4;
        v
    } else {
        0
    }
}

fn decode_method_signature(
    sig: &[u8],
    param_names: &[String],
    _method_name: &str,
) -> MethodSignature {
    if sig.is_empty() {
        return MethodSignature::default();
    }
    let mut pos = 0usize;
    let calling_conv = sig[pos];
    pos += 1;
    let is_static = (calling_conv & 0x60) == 0;
    let is_vararg = (calling_conv & 0x07) == 0x05;
    let has_generics = (calling_conv & 0x10) != 0;
    let generic_param_count = if has_generics {
        read_compressed_uint(sig, &mut pos)
    } else {
        0
    };

    let param_count = read_compressed_uint(sig, &mut pos) as usize;
    let return_type = decode_element_type_from_blob(sig, &mut pos);

    let mut params = Vec::with_capacity(param_count);
    for i in 0..param_count {
        if pos < sig.len() && sig[pos] == 0x41 {
            // SENTINEL for vararg
            pos += 1;
        }
        let type_name = decode_element_type_from_blob(sig, &mut pos);
        let pname = param_names
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("arg{i}"));
        params.push((pname, type_name));
    }
    MethodSignature {
        return_type,
        params,
        is_static,
        is_vararg,
        generic_param_count,
    }
}

// ─── AssemblyFile ─────────────────────────────────────────────────────────────

pub struct AssemblyFile {
    pub metadata: MetadataReader,
    pub path: PathBuf,
    raw: Vec<u8>,
}

impl AssemblyFile {
    /// Open a .NET assembly from disk and parse its metadata.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or metadata is invalid.
    pub fn open(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read(path).with_context(|| format!("reading assembly {}", path.display()))?;
        let metadata = MetadataReader::parse_from_bytes(&raw)
            .with_context(|| format!("parsing metadata for {}", path.display()))?;
        Ok(Self {
            metadata,
            path: path.to_path_buf(),
            raw,
        })
    }

    /// Construct directly from already-parsed metadata (useful for tests).
    #[must_use]
    pub const fn from_metadata(metadata: MetadataReader) -> Self {
        Self {
            metadata,
            path: PathBuf::new(),
            raw: Vec::new(),
        }
    }

    /// Return all type definitions in the assembly.
    #[must_use]
    pub fn types(&self) -> Vec<DotnetType> {
        let tables = &self.metadata.tables;
        let mut result = Vec::with_capacity(tables.type_def.len());
        let type_count = tables.type_def.len();

        for (idx, typedef) in tables.type_def.iter().enumerate() {
            let method_end = tables
                .type_def
                .get(idx + 1)
                .map_or_else(|| u32::try_from(tables.method_def.len()).unwrap_or(u32::MAX).saturating_add(1), |r| r.method_list);
            let field_end = tables
                .type_def
                .get(idx + 1)
                .map_or_else(|| u32::try_from(tables.field.len()).unwrap_or(u32::MAX).saturating_add(1), |r| r.field_list);

            let methods = self.build_methods_for(
                typedef,
                &tables.method_def,
                &tables.param,
                typedef.method_list,
                method_end,
            );
            let fields = Self::build_fields_for(&tables.field, typedef.field_list, field_end);
            let (base_type, interfaces) = self.resolve_hierarchy(typedef, idx, type_count);
            let kind_tag = classify_type(typedef, base_type.as_deref());

            let full_name = if typedef.type_namespace.is_empty() {
                typedef.type_name.clone()
            } else {
                format!("{}.{}", typedef.type_namespace, typedef.type_name)
            };

            let properties = Self::build_properties_for(idx + 1, &methods);
            let events = Self::build_events_for(idx + 1, &methods);

            result.push(DotnetType {
                name: typedef.type_name.clone(),
                namespace: typedef.type_namespace.clone(),
                full_name,
                base_type,
                interfaces,
                methods,
                fields,
                properties,
                events,
                nested_types: self.find_nested_types(idx + 1),
                custom_attributes: Vec::new(),
                generic_params: Vec::new(),
                kind_tag,
                flags: typedef.flags,
                layout: None,
            });
        }
        result
    }

    fn build_methods_for(
        &self,
        _typedef: &TypeDefRow,
        method_defs: &[MethodDefRow],
        params: &[rustre_dotnet_metadata::ParamRow],
        start: u32,
        end: u32,
    ) -> Vec<DotnetMethod> {
        let mut result = Vec::new();
        for i in start..end {
            let idx = (i as usize).wrapping_sub(1);
            if idx >= method_defs.len() {
                break;
            }
            let mrow = &method_defs[idx];

            let next_param = method_defs
                .get(idx + 1)
                .map_or_else(|| u32::try_from(params.len()).unwrap_or(u32::MAX).saturating_add(1), |m| m.param_list);
            let param_names: Vec<String> = (mrow.param_list..next_param)
                .filter_map(|pi| {
                    let pi = (pi as usize).wrapping_sub(1);
                    params.get(pi).map(|p| p.name.clone())
                })
                .collect();

            let sig = decode_method_signature(&mrow.signature, &param_names, &mrow.name);
            let body = if mrow.rva != 0 && !self.raw.is_empty() {
                let off = self.rva_to_file_offset(mrow.rva);
                off.and_then(|o| {
                    let slice = self.raw.get(o..).unwrap_or(&[]);
                    parse_method_body(slice, mrow.rva)
                })
            } else {
                None
            };

            result.push(DotnetMethod {
                name: mrow.name.clone(),
                signature: sig,
                body,
                flags: u32::from(mrow.flags),
                rva: mrow.rva,
                impl_flags: mrow.impl_flags,
                custom_attributes: Vec::new(),
                generic_params: Vec::new(),
                overrides: Vec::new(),
            });
        }
        result
    }

    fn build_fields_for(field_defs: &[FieldRow], start: u32, end: u32) -> Vec<DotnetField> {
        let mut result = Vec::new();
        for i in start..end {
            let idx = (i as usize).wrapping_sub(1);
            if idx >= field_defs.len() {
                break;
            }
            let frow = &field_defs[idx];
            let type_name = decode_field_type(&frow.signature);
            let is_static = (frow.flags & 0x0010) != 0;
            result.push(DotnetField {
                name: frow.name.clone(),
                type_name,
                flags: u32::from(frow.flags),
                is_static,
                custom_attributes: Vec::new(),
                marshal_info: None,
                constant_value: None,
                field_rva: None,
                offset: None,
            });
        }
        result
    }

    fn build_properties_for(
        _type_idx: usize,
        methods: &[DotnetMethod],
    ) -> Vec<PropertyModel> {
        let mut map: AHashMap<String, PropertyModel> = AHashMap::new();
        for m in methods {
            if let Some(name) = m.name.strip_prefix("get_") {
                let entry = map
                    .entry(name.to_string())
                    .or_insert_with(|| PropertyModel {
                        name: name.to_string(),
                        type_name: m.signature.return_type.clone(),
                        flags: 0,
                        getter: None,
                        setter: None,
                        custom_attributes: Vec::new(),
                        has_default: false,
                        default_value: None,
                    });
                entry.getter = Some(m.name.clone());
            } else if let Some(name) = m.name.strip_prefix("set_") {
                let entry = map
                    .entry(name.to_string())
                    .or_insert_with(|| PropertyModel {
                        name: name.to_string(),
                        type_name: m
                            .signature
                            .params
                            .first()
                            .map(|(_, t)| t.clone())
                            .unwrap_or_default(),
                        flags: 0,
                        getter: None,
                        setter: None,
                        custom_attributes: Vec::new(),
                        has_default: false,
                        default_value: None,
                    });
                entry.setter = Some(m.name.clone());
            }
        }
        let mut props: Vec<PropertyModel> = map.into_values().collect();
        props.sort_by(|a, b| a.name.cmp(&b.name));
        props
    }

    fn build_events_for(_type_idx: usize, methods: &[DotnetMethod]) -> Vec<EventModel> {
        let mut map: AHashMap<String, EventModel> = AHashMap::new();
        for m in methods {
            if let Some(name) = m.name.strip_prefix("add_") {
                let entry = map.entry(name.to_string()).or_insert_with(|| EventModel {
                    name: name.to_string(),
                    type_name: m
                        .signature
                        .params
                        .first()
                        .map(|(_, t)| t.clone())
                        .unwrap_or_default(),
                    flags: 0,
                    add: None,
                    remove: None,
                    raise: None,
                    custom_attributes: Vec::new(),
                });
                entry.add = Some(m.name.clone());
            } else if let Some(name) = m.name.strip_prefix("remove_") {
                let entry = map.entry(name.to_string()).or_insert_with(|| EventModel {
                    name: name.to_string(),
                    type_name: m
                        .signature
                        .params
                        .first()
                        .map(|(_, t)| t.clone())
                        .unwrap_or_default(),
                    flags: 0,
                    add: None,
                    remove: None,
                    raise: None,
                    custom_attributes: Vec::new(),
                });
                entry.remove = Some(m.name.clone());
            } else if let Some(name) = m.name.strip_prefix("raise_") {
                let entry = map.entry(name.to_string()).or_insert_with(|| EventModel {
                    name: name.to_string(),
                    type_name: String::new(),
                    flags: 0,
                    add: None,
                    remove: None,
                    raise: None,
                    custom_attributes: Vec::new(),
                });
                entry.raise = Some(m.name.clone());
            }
        }
        let mut evts: Vec<EventModel> = map.into_values().collect();
        evts.sort_by(|a, b| a.name.cmp(&b.name));
        evts
    }

    fn find_nested_types(&self, enclosing_idx: usize) -> Vec<String> {
        self.metadata
            .tables
            .nested_class
            .iter()
            .filter(|nc| nc.enclosing_class as usize == enclosing_idx)
            .filter_map(|nc| {
                let inner_idx = (nc.nested_class as usize).wrapping_sub(1);
                self.metadata.tables.type_def.get(inner_idx).map(|td| {
                    if td.type_namespace.is_empty() {
                        td.type_name.clone()
                    } else {
                        format!("{}.{}", td.type_namespace, td.type_name)
                    }
                })
            })
            .collect()
    }

    fn resolve_hierarchy(
        &self,
        typedef: &TypeDefRow,
        idx: usize,
        _type_count: usize,
    ) -> (Option<String>, Vec<String>) {
        let base_type = if typedef.extends == 0 {
            None
        } else {
            self.resolve_type_ref_name(typedef.extends)
        };

        let interfaces: Vec<String> = self
            .metadata
            .tables
            .interface_impl
            .iter()
            .filter(|ii| ii.class == (u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1)))
            .filter_map(|ii| self.resolve_type_ref_name(ii.interface))
            .collect();

        (base_type, interfaces)
    }

    fn resolve_type_ref_name(&self, coded: u32) -> Option<String> {
        let tag = coded & 0x3;
        let idx = (coded >> 2) as usize;
        match tag {
            0 => self
                .metadata
                .tables
                .type_def
                .get(idx.wrapping_sub(1))
                .map(|r| {
                    if r.type_namespace.is_empty() {
                        r.type_name.clone()
                    } else {
                        format!("{}.{}", r.type_namespace, r.type_name)
                    }
                }),
            1 => self
                .metadata
                .tables
                .type_ref
                .get(idx.wrapping_sub(1))
                .map(|r| {
                    if r.type_namespace.is_empty() {
                        r.type_name.clone()
                    } else {
                        format!("{}.{}", r.type_namespace, r.type_name)
                    }
                }),
            _ => None,
        }
    }

    fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        if self.raw.is_empty() {
            return None;
        }
        let data = &self.raw;
        if data.len() < 0x40 {
            return None;
        }
        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if pe_offset + 24 > data.len() {
            return None;
        }
        let num_sections =
            u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
        let opt_size =
            u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
        let sections_start = pe_offset + 24 + opt_size;

        for i in 0..num_sections {
            let sec = sections_start + i * 40;
            if sec + 40 > data.len() {
                break;
            }
            let virt_size = u32::from_le_bytes(data[sec + 8..sec + 12].try_into().ok()?);
            let virt_addr = u32::from_le_bytes(data[sec + 12..sec + 16].try_into().ok()?);
            let raw_ptr = u32::from_le_bytes(data[sec + 20..sec + 24].try_into().ok()?);
            let raw_size = u32::from_le_bytes(data[sec + 16..sec + 20].try_into().ok()?);
            let sec_size = if virt_size == 0 { raw_size } else { virt_size };
            if rva >= virt_addr && rva < virt_addr.saturating_add(sec_size) {
                // All three values are u32; the subtraction is safe (rva >= virt_addr),
                // but adding raw_ptr could overflow u32, so promote to u64 first.
                let file_offset = u64::from(rva - virt_addr) + u64::from(raw_ptr);
                return usize::try_from(file_offset).ok();
            }
        }
        None
    }

    /// Find a type by name (checks both short name and full qualified name).
    #[must_use]
    pub fn find_type(&self, name: &str) -> Option<DotnetType> {
        self.types()
            .into_iter()
            .find(|t| t.name == name || t.full_name == name)
    }

    /// Find a method on a named type.
    #[must_use]
    pub fn find_method(&self, type_name: &str, method_name: &str) -> Option<DotnetMethod> {
        self.find_type(type_name)?
            .methods
            .into_iter()
            .find(|m| m.name == method_name)
    }

    /// Return the assembly name if available.
    #[must_use]
    pub fn assembly_name(&self) -> Option<&str> {
        self.metadata
            .tables
            .assembly
            .first()
            .map(|a| a.name.as_str())
    }

    /// Return structured `AssemblyInfo` if the assembly table is present.
    #[must_use]
    pub fn assembly_info(&self) -> Option<AssemblyInfo> {
        self.metadata.tables.assembly.first().map(|a| AssemblyInfo {
            name: a.name.clone(),
            version: AssemblyVersion {
                major: a.major_version,
                minor: a.minor_version,
                build: a.build_number,
                revision: a.revision_number,
            },
            culture: a.culture.clone(),
            public_key: a.public_key.clone(),
            hash_alg: a.hash_alg_id,
            flags: a.flags,
        })
    }

    /// Return all assembly references.
    #[must_use]
    pub fn assembly_references(&self) -> Vec<AssemblyReference> {
        self.metadata
            .tables
            .assembly_ref
            .iter()
            .map(|r| AssemblyReference {
                name: r.name.clone(),
                version: AssemblyVersion {
                    major: r.major_version,
                    minor: r.minor_version,
                    build: r.build_number,
                    revision: r.revision_number,
                },
                culture: r.culture.clone(),
                public_key_or_token: r.public_key_or_token.clone(),
                hash_value: r.hash_value.clone(),
                flags: r.flags,
            })
            .collect()
    }

    /// Return all type names in this assembly (fully qualified).
    #[must_use]
    pub fn type_names(&self) -> Vec<String> {
        self.metadata
            .tables
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

    /// Return the number of types defined in this assembly.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.metadata.tables.type_def.len()
    }

    /// Return the number of methods defined across all types.
    #[must_use]
    pub const fn method_count(&self) -> usize {
        self.metadata.tables.method_def.len()
    }

    /// Return the number of fields defined across all types.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.metadata.tables.field.len()
    }

    /// Returns true if the assembly has a strong-name signature.
    #[must_use]
    pub fn is_strong_named(&self) -> bool {
        self.metadata
            .tables
            .assembly
            .first()
            .is_some_and(|a| !a.public_key.is_empty())
    }

    /// Returns the module name if the Module table has an entry.
    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.metadata.tables.module.first().map(|m| m.name.as_str())
    }

    /// Returns all member references.
    #[must_use]
    pub fn member_references(&self) -> Vec<MemberReference> {
        self.metadata
            .tables
            .member_ref
            .iter()
            .map(|mr| MemberReference {
                name: mr.name.clone(),
                class_token: mr.class,
                signature: mr.signature.clone(),
            })
            .collect()
    }

    /// Resolve all type references to their string names.
    #[must_use]
    pub fn type_references(&self) -> Vec<String> {
        self.metadata
            .tables
            .type_ref
            .iter()
            .map(|tr| {
                if tr.type_namespace.is_empty() {
                    tr.type_name.clone()
                } else {
                    format!("{}.{}", tr.type_namespace, tr.type_name)
                }
            })
            .collect()
    }

    /// Returns all nested class relationships as (nested, enclosing) name pairs.
    #[must_use]
    pub fn nested_class_relationships(&self) -> Vec<(String, String)> {
        self.metadata
            .tables
            .nested_class
            .iter()
            .filter_map(|nc| {
                let nested = self
                    .metadata
                    .tables
                    .type_def
                    .get((nc.nested_class as usize).wrapping_sub(1))
                    .map(|t| t.type_name.clone())?;
                let enclosing = self
                    .metadata
                    .tables
                    .type_def
                    .get((nc.enclosing_class as usize).wrapping_sub(1))
                    .map(|t| t.type_name.clone())?;
                Some((nested, enclosing))
            })
            .collect()
    }

    /// Returns the raw PE bytes (empty slice if loaded from metadata only).
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns true if raw PE bytes are available.
    #[must_use]
    pub const fn has_raw_bytes(&self) -> bool {
        !self.raw.is_empty()
    }
}

// ─── Member reference ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemberReference {
    pub name: String,
    pub class_token: u32,
    pub signature: Vec<u8>,
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

fn decode_field_type(sig: &[u8]) -> String {
    if sig.len() < 2 {
        return "object".to_string();
    }
    let type_byte = if sig[0] == 0x06 { sig[1] } else { sig[0] };
    match type_byte {
        0x1D => {
            // SzArray
            let elem = if sig.len() > 2 {
                decode_element_type(sig[2])
            } else {
                "object"
            };
            format!("{elem}[]")
        }
        _ => decode_element_type(type_byte).to_string(),
    }
}

fn classify_type(
    typedef: &TypeDefRow,
    base_type: Option<&str>,
) -> DotnetTypeKind {
    let flags = typedef.flags;
    let is_interface = (flags & 0x0020) != 0;
    if is_interface {
        return DotnetTypeKind::Interface;
    }

    let base = base_type.unwrap_or("");
    if base.ends_with("Enum") || base == "System.Enum" {
        return DotnetTypeKind::Enum;
    }
    if base.ends_with("Delegate")
        || base.ends_with("MulticastDelegate")
        || base == "System.Delegate"
        || base == "System.MulticastDelegate"
    {
        return DotnetTypeKind::Delegate;
    }
    if base.ends_with("ValueType") || base == "System.ValueType" {
        return DotnetTypeKind::Struct;
    }
    DotnetTypeKind::Class
}

// ─── Assembly resolver ────────────────────────────────────────────────────────

/// Resolves assemblies by name from a set of search paths.
pub struct AssemblyResolver {
    search_paths: Vec<PathBuf>,
    cache: AHashMap<String, AssemblyFile>,
}

impl AssemblyResolver {
    /// Create a new resolver with the given search directories.
    #[must_use]
    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self {
            search_paths,
            cache: AHashMap::new(),
        }
    }

    /// Add a search path.
    pub fn add_path(&mut self, path: impl Into<PathBuf>) {
        self.search_paths.push(path.into());
    }

    /// Attempt to resolve an assembly by name.
    ///
    /// # Errors
    /// Returns an error if the assembly cannot be found or parsed.
    /// # Panics
    /// Panics if invariants are violated.
    pub fn resolve(&mut self, name: &str) -> Result<&AssemblyFile> {
        if !self.cache.contains_key(name) {
            let asm = self.load(name)?;
            self.cache.insert(name.to_string(), asm);
        }
        Ok(self.cache.get(name).unwrap())
    }

    fn load(&self, name: &str) -> Result<AssemblyFile> {
        for dir in &self.search_paths {
            for ext in &["dll", "exe"] {
                let path = dir.join(format!("{name}.{ext}"));
                // Avoid TOCTOU: open directly rather than exists()-then-open().
                if let Ok(asm) = AssemblyFile::open(&path) { return Ok(asm); }
            }
        }
        anyhow::bail!("assembly {name:?} not found in search paths")
    }

    /// Returns the names of all cached assemblies.
    #[must_use]
    pub fn cached_names(&self) -> Vec<&str> {
        self.cache.keys().map(std::string::String::as_str).collect()
    }
}

// ─── Basic block ──────────────────────────────────────────────────────────────

/// A contiguous sequence of instructions with no internal branches.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_offset: u32,
    pub end_offset: u32,
    pub instructions: Vec<CilInstruction>,
    pub successors: Vec<u32>,
}

impl BasicBlock {
    /// Build a basic block list from a method body.
    /// # Panics
    /// Panics if invariants are violated.
    #[must_use]
    pub fn from_body(body: &MethodBody) -> Vec<Self> {
        if body.instructions.is_empty() {
            return Vec::new();
        }

        // First pass: collect all block-starting offsets
        let mut leaders: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        leaders.insert(body.instructions[0].offset);

        for instr in &body.instructions {
            if instr.is_terminator() {
                // The instruction after a terminator starts a new block
                if let Some(next) = body.instructions.iter().find(|i| i.offset > instr.offset) {
                    leaders.insert(next.offset);
                }
                // Targets start new blocks
                for target in instr.branch_targets() {
                    leaders.insert(target);
                }
            }
        }

        // Second pass: build blocks
        let mut blocks = Vec::new();
        let leader_vec: Vec<u32> = leaders.into_iter().collect();

        for (i, &leader) in leader_vec.iter().enumerate() {
            let end = leader_vec.get(i + 1).copied();
            let instrs: Vec<CilInstruction> = body
                .instructions
                .iter()
                .filter(|instr| instr.offset >= leader && end.is_none_or(|e| instr.offset < e))
                .cloned()
                .collect();

            if instrs.is_empty() {
                continue;
            }

            let last = instrs.last().unwrap();
            let mut successors = last.branch_targets();
            if !last.is_unconditional_branch()
                && !matches!(last.opcode.as_str(), "ret" | "throw" | "rethrow")
                && let Some(&next_leader) = leader_vec.get(i + 1) {
                    successors.push(next_leader);
                }

            let end_offset = last.offset;
            blocks.push(Self {
                start_offset: leader,
                end_offset,
                instructions: instrs,
                successors,
            });
        }
        blocks
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_dotnet_metadata::{
        AssemblyRow, MetadataHeaps, MetadataRoot, MetadataTables, MethodDefRow, TypeDefRow,
        TypeRefRow,
    };

    fn make_reader() -> MetadataReader {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Greeter".into(),
            type_namespace: "Demo".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        tables.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x06,
            name: "Hello".into(),
            signature: vec![0x00, 0x01, 0x01],
            param_list: 1,
        });
        tables.param.push(rustre_dotnet_metadata::ParamRow {
            flags: 0,
            sequence: 1,
            name: "name".into(),
        });
        MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        }
    }

    #[test]
    fn test_assembly_file_from_metadata() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert_eq!(asm.path, PathBuf::new());
    }

    #[test]
    fn test_types_returns_all() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let types = asm.types();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "Greeter");
    }

    #[test]
    fn test_type_full_name() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let t = &asm.types()[0];
        assert_eq!(t.full_name, "Demo.Greeter");
    }

    #[test]
    fn test_find_type_by_short_name() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert!(asm.find_type("Greeter").is_some());
    }

    #[test]
    fn test_find_type_by_full_name() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert!(asm.find_type("Demo.Greeter").is_some());
    }

    #[test]
    fn test_find_type_missing() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert!(asm.find_type("NonExistent").is_none());
    }

    #[test]
    fn test_find_method() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let m = asm.find_method("Greeter", "Hello");
        assert!(m.is_some());
        assert_eq!(m.unwrap().name, "Hello");
    }

    #[test]
    fn test_find_method_missing() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert!(asm.find_method("Greeter", "Goodbye").is_none());
    }

    #[test]
    fn test_type_is_class() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let t = &asm.types()[0];
        assert!(t.is_class());
        assert!(!t.is_interface());
        assert!(!t.is_enum());
    }

    #[test]
    fn test_type_interface_flag() {
        let mut tables = MetadataTables::default();
        tables.type_def.push(TypeDefRow {
            flags: 0x0020,
            type_name: "IFoo".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let asm = AssemblyFile::from_metadata(reader);
        let t = &asm.types()[0];
        assert!(t.is_interface());
        assert!(!t.is_class());
    }

    #[test]
    fn test_type_enum_detection() {
        let mut tables = MetadataTables::default();
        tables.type_ref.push(TypeRefRow {
            resolution_scope: 0,
            type_name: "Enum".into(),
            type_namespace: "System".into(),
        });
        tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Color".into(),
            type_namespace: "MyApp".into(),
            extends: 0b0101,
            field_list: 1,
            method_list: 1,
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let asm = AssemblyFile::from_metadata(reader);
        let t = &asm.types()[0];
        assert!(t.is_enum());
    }

    #[test]
    fn test_method_flags_stored() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let m = asm.find_method("Greeter", "Hello").unwrap();
        assert_eq!(m.flags, 0x06);
    }

    #[test]
    fn test_method_rva_zero_no_body() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        let m = asm.find_method("Greeter", "Hello").unwrap();
        assert!(m.body.is_none());
    }

    #[test]
    fn test_cil_operand_equality() {
        assert_eq!(CilOperand::Int32(42), CilOperand::Int32(42));
        assert_ne!(CilOperand::Int32(1), CilOperand::Int32(2));
    }

    #[test]
    fn test_cil_instruction_fields() {
        let instr = CilInstruction {
            offset: 0,
            opcode: "ldarg.0".into(),
            operand: CilOperand::None,
        };
        assert_eq!(instr.opcode, "ldarg.0");
        assert_eq!(instr.offset, 0);
    }

    #[test]
    fn test_parse_method_body_tiny() {
        let body_bytes = vec![0x0Au8, 0x17, 0x2A];
        let body = parse_method_body(&body_bytes, 1).unwrap();
        assert_eq!(body.instructions.len(), 2);
        assert_eq!(body.instructions[0].opcode, "ldc.i4.1");
        assert_eq!(body.instructions[1].opcode, "ret");
    }

    #[test]
    fn test_parse_method_body_empty_rva() {
        assert!(parse_method_body(&[], 0).is_none());
    }

    #[test]
    fn test_assembly_name_absent() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert!(asm.assembly_name().is_none());
    }

    #[test]
    fn test_assembly_name_present() {
        let mut tables = MetadataTables::default();
        tables.assembly.push(AssemblyRow {
            name: "MyAssembly".into(),
            ..Default::default()
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let asm = AssemblyFile::from_metadata(reader);
        assert_eq!(asm.assembly_name(), Some("MyAssembly"));
    }

    #[test]
    fn test_open_nonexistent_path() {
        let result = AssemblyFile::open(Path::new("/nonexistent/path/file.dll"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_element_type_primitives() {
        assert_eq!(decode_element_type(0x08), "int");
        assert_eq!(decode_element_type(0x0E), "string");
        assert_eq!(decode_element_type(0x02), "bool");
        assert_eq!(decode_element_type(0x01), "void");
    }

    #[test]
    fn test_classify_type_delegate() {
        let typedef = TypeDefRow {
            flags: 0x01,
            type_name: "MyDelegate".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        };
        let base = Some("System.MulticastDelegate".to_string());
        let kind = classify_type(&typedef, base.as_deref());
        assert_eq!(kind, DotnetTypeKind::Delegate);
    }

    #[test]
    fn test_local_var_default() {
        let lv = LocalVar::default();
        assert_eq!(lv.index, 0);
        assert!(lv.type_name.is_empty());
    }

    #[test]
    fn test_exception_handler_default() {
        let eh = ExceptionHandler::default();
        assert_eq!(eh.kind, ExceptionHandlerKind::Catch);
        assert!(eh.catch_type.is_none());
    }

    #[test]
    fn test_cil_instruction_is_branch() {
        let br = CilInstruction::branch(0, "br", 10);
        assert!(br.is_branch());
        assert!(br.is_unconditional_branch());
        let nop = CilInstruction::simple(0, "nop");
        assert!(!nop.is_branch());
    }

    #[test]
    fn test_cil_instruction_byte_size() {
        let nop = CilInstruction::simple(0, "nop");
        assert_eq!(nop.byte_size(), 1);
        let ldc = CilInstruction::with_i32(0, "ldc.i4", 42);
        assert_eq!(ldc.byte_size(), 5);
    }

    #[test]
    fn test_method_body_branch_targets() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction::simple(0, "nop"),
                CilInstruction::branch(1, "br", 10),
                CilInstruction::simple(5, "ret"),
            ],
            ..Default::default()
        };
        let targets = body.branch_targets();
        assert!(targets.contains(&10));
    }

    #[test]
    fn test_method_body_offset_map() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction::simple(0, "nop"),
                CilInstruction::simple(1, "ret"),
            ],
            ..Default::default()
        };
        let map = body.offset_map();
        assert_eq!(map[&0], 0);
        assert_eq!(map[&1], 1);
    }

    #[test]
    fn test_type_kind() {
        let mut t = DotnetType {
            name: "Foo".into(),
            namespace: String::new(),
            full_name: "Foo".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: DotnetTypeKind::Class,
            flags: 0x01,
            layout: None,
        };
        assert_eq!(t.kind(), "class");
        t.kind_tag = DotnetTypeKind::Interface;
        assert_eq!(t.kind(), "interface");
    }

    #[test]
    fn test_assembly_info() {
        let mut tables = MetadataTables::default();
        tables.assembly.push(AssemblyRow {
            name: "TestLib".into(),
            major_version: 2,
            minor_version: 3,
            build_number: 4,
            revision_number: 5,
            ..Default::default()
        });
        let reader = MetadataReader {
            root: MetadataRoot {
                major_version: 1,
                minor_version: 1,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables,
        };
        let asm = AssemblyFile::from_metadata(reader);
        let info = asm.assembly_info().unwrap();
        assert_eq!(info.name, "TestLib");
        assert_eq!(info.version.major, 2);
        assert_eq!(info.version.to_string(), "2.3.4.5");
    }

    #[test]
    fn test_type_count_and_method_count() {
        let reader = make_reader();
        let asm = AssemblyFile::from_metadata(reader);
        assert_eq!(asm.type_count(), 1);
        assert_eq!(asm.method_count(), 1);
    }

    #[test]
    fn test_basic_block_from_simple_body() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction::simple(0, "nop"),
                CilInstruction::simple(1, "ldc.i4.1"),
                CilInstruction::simple(2, "ret"),
            ],
            ..Default::default()
        };
        let blocks = BasicBlock::from_body(&body);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_offset, 0);
        assert_eq!(blocks[0].instructions.len(), 3);
    }

    #[test]
    fn test_basic_block_with_branch() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction::simple(0, "ldc.i4.1"),
                CilInstruction {
                    offset: 1,
                    opcode: "brfalse".into(),
                    operand: CilOperand::Branch(5),
                },
                CilInstruction::simple(5, "nop"),
                CilInstruction::simple(6, "ret"),
            ],
            ..Default::default()
        };
        let blocks = BasicBlock::from_body(&body);
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_generic_instantiation_format() {
        let gi = GenericInstantiation {
            open_type: "List".into(),
            type_arguments: vec!["int".into(), "string".into()],
        };
        assert_eq!(gi.format(), "List<int, string>");
        assert_eq!(gi.arity(), 2);
    }

    #[test]
    fn test_custom_attribute_is_type() {
        let attr = CustomAttribute::from_blob("System.ObsoleteAttribute", vec![]);
        assert!(attr.is_type("ObsoleteAttribute"));
        assert!(attr.is_type("System.ObsoleteAttribute"));
        assert!(!attr.is_type("SomethingElse"));
    }

    #[test]
    fn test_property_model_signature() {
        let prop = PropertyModel {
            name: "Name".into(),
            type_name: "string".into(),
            flags: 0,
            getter: Some("get_Name".into()),
            setter: Some("set_Name".into()),
            custom_attributes: vec![],
            has_default: false,
            default_value: None,
        };
        assert!(prop.has_getter());
        assert!(prop.has_setter());
        assert!(!prop.is_read_only());
        assert!(prop.signature().contains("Name"));
    }

    #[test]
    fn test_dotnet_error_display() {
        let e = DotnetError::TypeNotFound("Foo".into());
        assert!(e.to_string().contains("Foo"));
    }

    #[test]
    fn test_method_signature_returns_void() {
        let sig = MethodSignature {
            return_type: "void".into(),
            ..Default::default()
        };
        assert!(sig.returns_void());
        let sig2 = MethodSignature {
            return_type: "int".into(),
            ..Default::default()
        };
        assert!(!sig2.returns_void());
    }

    #[test]
    fn test_field_flags_from_raw() {
        let flags = FieldFlags::from_raw(0x06 | 0x10); // public + static
        assert!(flags.is_public());
        assert!(flags.is_static());
        assert!(!flags.is_literal());
    }
}

// ─── Parameter definition ─────────────────────────────────────────────────────

/// A method parameter with full metadata.
#[derive(Debug, Clone, Default)]
pub struct ParameterDef {
    /// Parameter index (0 = return value, 1+ = actual params).
    pub index: u16,
    /// Parameter name.
    pub name: String,
    /// Raw parameter flags (ECMA-335 §23.1.13).
    pub flags: u16,
    /// The CLR type name of this parameter.
    pub type_name: String,
    /// Optional default value.
    pub default_value: Option<AttributeValue>,
    /// Custom attributes on this parameter.
    pub custom_attributes: Vec<CustomAttribute>,
    /// Optional marshal info.
    pub marshal_info: Option<MarshalInfo>,
}

impl ParameterDef {
    /// Returns `true` if this is an `[in]` parameter.
    #[must_use]
    pub const fn is_in(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// Returns `true` if this is an `[out]` parameter.
    #[must_use]
    pub const fn is_out(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    /// Returns `true` if this is an `[optional]` parameter.
    #[must_use]
    pub const fn is_optional(&self) -> bool {
        self.flags & 0x0010 != 0
    }

    /// Returns `true` if this parameter has a default value.
    #[must_use]
    pub const fn has_default(&self) -> bool {
        self.flags & 0x1000 != 0
    }

    /// Returns `true` if this is the return value pseudo-parameter (index == 0).
    #[must_use]
    pub const fn is_return_value(&self) -> bool {
        self.index == 0
    }

    /// Formats the parameter as a C# declaration.
    #[must_use]
    pub fn format(&self) -> String {
        let mut mods = String::new();
        if self.is_in() && self.is_out() {
            mods.push_str("ref ");
        } else if self.is_out() {
            mods.push_str("out ");
        }
        format!("{}{} {}", mods, self.type_name, self.name)
    }
}

// ─── Binding redirect ─────────────────────────────────────────────────────────

/// A binding redirect for strong-named assembly resolution.
#[derive(Debug, Clone)]
pub struct BindingRedirect {
    /// The name of the assembly being redirected.
    pub assembly_name: String,
    /// The old version range minimum.
    pub old_version_min: AssemblyVersion,
    /// The old version range maximum.
    pub old_version_max: AssemblyVersion,
    /// The new (redirected) version.
    pub new_version: AssemblyVersion,
    /// Optional public key token.
    pub public_key_token: Option<String>,
    /// Optional culture.
    pub culture: Option<String>,
}

impl BindingRedirect {
    /// Returns `true` if the given version falls within the old version range.
    #[must_use]
    pub const fn matches(&self, ver: &AssemblyVersion) -> bool {
        let min = &self.old_version_min;
        let max = &self.old_version_max;
        (ver.major > min.major || (ver.major == min.major && ver.minor >= min.minor))
            && (ver.major < max.major || (ver.major == max.major && ver.minor <= max.minor))
    }

    /// Returns the canonical XML form of this binding redirect.
    #[must_use]
    pub fn to_config_xml(&self) -> String {
        let name = &self.assembly_name;
        let old_min = &self.old_version_min;
        let old_max = &self.old_version_max;
        let new_v = &self.new_version;
        format!(
            "<dependentAssembly>\n  <assemblyIdentity name=\"{name}\" />\n  \
             <bindingRedirect oldVersion=\"{old_min}-{old_max}\" newVersion=\"{new_v}\" />\n\
             </dependentAssembly>"
        )
    }
}

// ─── Type hierarchy navigation ────────────────────────────────────────────────

/// A node in an assembly's type inheritance tree.
#[derive(Debug, Clone)]
pub struct TypeHierarchyNode {
    /// Fully-qualified type name.
    pub full_name: String,
    /// Fully-qualified base type name, if any.
    pub base: Option<String>,
    /// Direct subtypes known in this assembly.
    pub children: Vec<String>,
}

impl TypeHierarchyNode {
    /// Create a leaf node (no children).
    #[must_use]
    pub fn leaf(full_name: impl Into<String>, base: Option<String>) -> Self {
        Self {
            full_name: full_name.into(),
            base,
            children: Vec::new(),
        }
    }

    /// Returns `true` if this type is a root (has no base type).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.base.is_none()
    }

    /// Returns `true` if this type is a leaf (has no known children).
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

/// Build a type hierarchy from a flat list of types.
#[must_use]
pub fn build_type_hierarchy(types: &[DotnetType]) -> Vec<TypeHierarchyNode> {
    let mut nodes: AHashMap<String, TypeHierarchyNode> = types
        .iter()
        .map(|t| {
            let node = TypeHierarchyNode {
                full_name: t.full_name.clone(),
                base: t.base_type.clone(),
                children: Vec::new(),
            };
            (t.full_name.clone(), node)
        })
        .collect();

    let bases: Vec<(String, String)> = nodes
        .values()
        .filter_map(|n| n.base.as_ref().map(|b| (b.clone(), n.full_name.clone())))
        .collect();

    for (base, child) in bases {
        if let Some(parent) = nodes.get_mut(&base) {
            parent.children.push(child);
        }
    }

    let mut result: Vec<TypeHierarchyNode> = nodes.into_values().collect();
    result.sort_by(|a, b| a.full_name.cmp(&b.full_name));
    result
}

// ─── Resolved type reference ──────────────────────────────────────────────────

/// The result of resolving a `TypeRef` to a full definition.
#[derive(Debug, Clone)]
pub enum ResolvedTypeRef {
    /// Resolved to a type in the same assembly.
    InAssembly(String),
    /// Resolved to a type in an external assembly.
    External { assembly: String, full_name: String },
    /// Could not be resolved.
    Unknown(String),
}

impl ResolvedTypeRef {
    /// Returns the full name regardless of where it was found.
    #[must_use]
    pub fn full_name(&self) -> &str {
        match self {
            Self::InAssembly(n) | Self::Unknown(n) => n,
            Self::External { full_name, .. } => full_name,
        }
    }

    /// Returns `true` if the type was successfully resolved.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

// ─── Metadata token utilities ─────────────────────────────────────────────────

/// Table tag constants for CLI metadata tokens.
pub mod token_table {
    /// Module table (0x00).
    pub const MODULE: u8 = 0x00;
    /// `TypeRef` table (0x01).
    pub const TYPE_REF: u8 = 0x01;
    /// `TypeDef` table (0x02).
    pub const TYPE_DEF: u8 = 0x02;
    /// Field table (0x04).
    pub const FIELD: u8 = 0x04;
    /// `MethodDef` table (0x06).
    pub const METHOD_DEF: u8 = 0x06;
    /// Param table (0x08).
    pub const PARAM: u8 = 0x08;
    /// `InterfaceImpl` table (0x09).
    pub const INTERFACE_IMPL: u8 = 0x09;
    /// `MemberRef` table (0x0A).
    pub const MEMBER_REF: u8 = 0x0A;
    /// Constant table (0x0B).
    pub const CONSTANT: u8 = 0x0B;
    /// `CustomAttribute` table (0x0C).
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0C;
    /// `FieldMarshal` table (0x0D).
    pub const FIELD_MARSHAL: u8 = 0x0D;
    /// `DeclSecurity` table (0x0E).
    pub const DECL_SECURITY: u8 = 0x0E;
    /// `ClassLayout` table (0x0F).
    pub const CLASS_LAYOUT: u8 = 0x0F;
    /// `StandAloneSig` table (0x11).
    pub const STAND_ALONE_SIG: u8 = 0x11;
    /// Event table (0x14).
    pub const EVENT: u8 = 0x14;
    /// Property table (0x17).
    pub const PROPERTY: u8 = 0x17;
    /// `MethodSemantics` table (0x18).
    pub const METHOD_SEMANTICS: u8 = 0x18;
    /// `TypeSpec` table (0x1B).
    pub const TYPE_SPEC: u8 = 0x1B;
    /// Assembly table (0x20).
    pub const ASSEMBLY: u8 = 0x20;
    /// `AssemblyRef` table (0x23).
    pub const ASSEMBLY_REF: u8 = 0x23;
    /// File table (0x26).
    pub const FILE: u8 = 0x26;
    /// `ExportedType` table (0x27).
    pub const EXPORTED_TYPE: u8 = 0x27;
    /// `ManifestResource` table (0x28).
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    /// `GenericParam` table (0x2A).
    pub const GENERIC_PARAM: u8 = 0x2A;
    /// `MethodSpec` table (0x2B).
    pub const METHOD_SPEC: u8 = 0x2B;
    /// `GenericParamConstraint` table (0x2C).
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2C;
    /// `UserString` heap (0x70).
    pub const USER_STRING: u8 = 0x70;
}

/// Decode a CLI metadata token into `(table_id, row_index)`.
#[must_use]
pub const fn decode_token(token: u32) -> (u8, u32) {
    let table = (token >> 24) as u8;
    let row = token & 0x00FF_FFFF;
    (table, row)
}

/// Encode a `(table_id, row_index)` pair into a CLI metadata token.
#[must_use]
pub fn encode_token(table: u8, row: u32) -> u32 {
    (u32::from(table) << 24) | (row & 0x00FF_FFFF)
}

/// Returns the human-readable table name for a given table tag.
#[must_use]
pub const fn token_table_name(table: u8) -> &'static str {
    match table {
        token_table::MODULE => "Module",
        token_table::TYPE_REF => "TypeRef",
        token_table::TYPE_DEF => "TypeDef",
        token_table::FIELD => "Field",
        token_table::METHOD_DEF => "MethodDef",
        token_table::PARAM => "Param",
        token_table::INTERFACE_IMPL => "InterfaceImpl",
        token_table::MEMBER_REF => "MemberRef",
        token_table::CONSTANT => "Constant",
        token_table::CUSTOM_ATTRIBUTE => "CustomAttribute",
        token_table::FIELD_MARSHAL => "FieldMarshal",
        token_table::DECL_SECURITY => "DeclSecurity",
        token_table::CLASS_LAYOUT => "ClassLayout",
        token_table::STAND_ALONE_SIG => "StandAloneSig",
        token_table::EVENT => "Event",
        token_table::PROPERTY => "Property",
        token_table::METHOD_SEMANTICS => "MethodSemantics",
        token_table::TYPE_SPEC => "TypeSpec",
        token_table::ASSEMBLY => "Assembly",
        token_table::ASSEMBLY_REF => "AssemblyRef",
        token_table::FILE => "File",
        token_table::EXPORTED_TYPE => "ExportedType",
        token_table::MANIFEST_RESOURCE => "ManifestResource",
        token_table::GENERIC_PARAM => "GenericParam",
        token_table::METHOD_SPEC => "MethodSpec",
        token_table::GENERIC_PARAM_CONSTRAINT => "GenericParamConstraint",
        token_table::USER_STRING => "UserString",
        _ => "<unknown>",
    }
}

// ─── Signature helpers ────────────────────────────────────────────────────────

/// Element type constants (ECMA-335 §II.23.1.16).
pub mod element_type {
    #[path = "../csharp_reconstructor.rs"]
    pub mod csharp_reconstructor;
    /// End-of-list marker.
    pub const END: u8 = 0x00;
    /// `void`.
    pub const VOID: u8 = 0x01;
    /// `bool`.
    pub const BOOLEAN: u8 = 0x02;
    /// `char`.
    pub const CHAR: u8 = 0x03;
    /// `sbyte` (int8).
    pub const I1: u8 = 0x04;
    /// `byte` (uint8).
    pub const U1: u8 = 0x05;
    /// `short` (int16).
    pub const I2: u8 = 0x06;
    /// `ushort` (uint16).
    pub const U2: u8 = 0x07;
    /// `int` (int32).
    pub const I4: u8 = 0x08;
    /// `uint` (uint32).
    pub const U4: u8 = 0x09;
    /// `long` (int64).
    pub const I8: u8 = 0x0A;
    /// `ulong` (uint64).
    pub const U8: u8 = 0x0B;
    /// `float` (float32).
    pub const R4: u8 = 0x0C;
    /// `double` (float64).
    pub const R8: u8 = 0x0D;
    /// `string`.
    pub const STRING: u8 = 0x0E;
    /// Unmanaged pointer.
    pub const PTR: u8 = 0x0F;
    /// Managed reference (`ref`).
    pub const BYREF: u8 = 0x10;
    /// Value type (struct/enum).
    pub const VALUETYPE: u8 = 0x11;
    /// Reference type (class).
    pub const CLASS: u8 = 0x12;
    /// Type variable `!T` (generic method parameter).
    pub const VAR: u8 = 0x13;
    /// Multi-dimensional array.
    pub const ARRAY: u8 = 0x14;
    /// Generic instantiation.
    pub const GENERICINST: u8 = 0x15;
    /// `System.TypedReference`.
    pub const TYPEDBYREF: u8 = 0x16;
    /// `System.IntPtr`.
    pub const I: u8 = 0x18;
    /// `System.UIntPtr`.
    pub const U: u8 = 0x19;
    /// Function pointer.
    pub const FNPTR: u8 = 0x1B;
    /// `object`.
    pub const OBJECT: u8 = 0x1C;
    /// Single-dimension zero-lower-bound array (`T[]`).
    pub const SZARRAY: u8 = 0x1D;
    /// Method type variable `!!T`.
    pub const MVAR: u8 = 0x1E;
    /// Required custom modifier.
    pub const CMOD_REQD: u8 = 0x1F;
    /// Optional custom modifier.
    pub const CMOD_OPT: u8 = 0x20;
    /// Vararg sentinel.
    pub const SENTINEL: u8 = 0x41;
    /// Pinned type.
    pub const PINNED: u8 = 0x45;
}

/// Convert an element type byte to a CLR fully-qualified type name.
#[must_use]
pub const fn element_type_name(et: u8) -> &'static str {
    match et {
        element_type::VOID => "System.Void",
        element_type::BOOLEAN => "System.Boolean",
        element_type::CHAR => "System.Char",
        element_type::I1 => "System.SByte",
        element_type::U1 => "System.Byte",
        element_type::I2 => "System.Int16",
        element_type::U2 => "System.UInt16",
        element_type::I4 => "System.Int32",
        element_type::U4 => "System.UInt32",
        element_type::I8 => "System.Int64",
        element_type::U8 => "System.UInt64",
        element_type::R4 => "System.Single",
        element_type::R8 => "System.Double",
        element_type::STRING => "System.String",
        element_type::OBJECT => "System.Object",
        element_type::TYPEDBYREF => "System.TypedReference",
        element_type::I => "System.IntPtr",
        element_type::U => "System.UIntPtr",
        _ => "<unknown>",
    }
}

/// Convert an element type byte to its C# short keyword.
#[must_use]
pub const fn element_type_to_csharp(et: u8) -> &'static str {
    match et {
        element_type::VOID => "void",
        element_type::BOOLEAN => "bool",
        element_type::CHAR => "char",
        element_type::I1 => "sbyte",
        element_type::U1 => "byte",
        element_type::I2 => "short",
        element_type::U2 => "ushort",
        element_type::I4 => "int",
        element_type::U4 => "uint",
        element_type::I8 => "long",
        element_type::U8 => "ulong",
        element_type::R4 => "float",
        element_type::R8 => "double",
        element_type::STRING => "string",
        element_type::OBJECT => "object",
        _ => "<unknown>",
    }
}

// ─── CilInstruction additional helpers ───────────────────────────────────────

impl CilInstruction {
    /// Returns `true` if this instruction loads a constant.
    #[must_use]
    pub fn is_load_const(&self) -> bool {
        matches!(
            self.opcode.as_str(),
            "ldc.i4.m1"
                | "ldc.i4.0"
                | "ldc.i4.1"
                | "ldc.i4.2"
                | "ldc.i4.3"
                | "ldc.i4.4"
                | "ldc.i4.5"
                | "ldc.i4.6"
                | "ldc.i4.7"
                | "ldc.i4.8"
                | "ldc.i4.s"
                | "ldc.i4"
                | "ldc.i8"
                | "ldc.r4"
                | "ldc.r8"
                | "ldnull"
                | "ldstr"
        )
    }

    /// Returns `true` if this is a call-type instruction.
    #[must_use]
    pub fn is_call(&self) -> bool {
        matches!(
            self.opcode.as_str(),
            "call" | "callvirt" | "calli" | "newobj"
        )
    }

    /// Returns the metadata token for this instruction, if it has one.
    #[must_use]
    pub const fn token(&self) -> Option<u32> {
        match self.operand {
            CilOperand::Token(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the immediate integer value for `ldc.i4.X` opcodes.
    #[must_use]
    pub fn immediate_i32(&self) -> Option<i32> {
        match self.opcode.as_str() {
            "ldc.i4.m1" => Some(-1),
            "ldc.i4.0" => Some(0),
            "ldc.i4.1" => Some(1),
            "ldc.i4.2" => Some(2),
            "ldc.i4.3" => Some(3),
            "ldc.i4.4" => Some(4),
            "ldc.i4.5" => Some(5),
            "ldc.i4.6" => Some(6),
            "ldc.i4.7" => Some(7),
            "ldc.i4.8" => Some(8),
            "ldc.i4.s" => {
                if let CilOperand::Int8(n) = self.operand {
                    Some(i32::from(n))
                } else {
                    None
                }
            }
            "ldc.i4" => {
                if let CilOperand::Int32(n) = self.operand {
                    Some(n)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

// ─── MethodBody additional helpers ───────────────────────────────────────────

impl MethodBody {
    /// Returns all unique metadata tokens used as call sites.
    #[must_use]
    pub fn call_sites(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for instr in &self.instructions {
            if instr.is_call()
                && let Some(tok) = instr.token()
                    && !out.contains(&tok) {
                        out.push(tok);
                    }
        }
        out
    }

    /// Returns all unique metadata tokens accessed as fields.
    #[must_use]
    pub fn field_access_tokens(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for instr in &self.instructions {
            if matches!(
                instr.opcode.as_str(),
                "ldfld" | "stfld" | "ldsfld" | "stsfld"
            )
                && let Some(tok) = instr.token()
                    && !out.contains(&tok) {
                        out.push(tok);
                    }
        }
        out
    }
}

// ─── DotnetMethod additional helpers ─────────────────────────────────────────

impl DotnetMethod {
    /// Returns `true` if the method is decorated with `[Obsolete]`.
    #[must_use]
    pub fn is_obsolete(&self) -> bool {
        self.custom_attributes
            .iter()
            .any(|a| a.is_type("ObsoleteAttribute") || a.is_type("System.ObsoleteAttribute"))
    }

    /// Returns the first custom attribute of the given type name.
    #[must_use]
    pub fn first_attribute(&self, type_name: &str) -> Option<&CustomAttribute> {
        self.custom_attributes.iter().find(|a| a.is_type(type_name))
    }

    /// Returns a rich string summary of the method.
    #[must_use]
    pub fn summary(&self) -> String {
        let mods: Vec<&str> = {
            let mut v = Vec::new();
            if self.is_static() {
                v.push("static");
            }
            if self.is_abstract() {
                v.push("abstract");
            }
            if self.is_virtual() {
                v.push("virtual");
            }
            v
        };
        let mods_str = mods.join(" ");
        let sep = if mods_str.is_empty() { "" } else { " " };
        let params: Vec<String> = self
            .signature
            .params
            .iter()
            .map(|(n, t)| format!("{t} {n}"))
            .collect();
        format!(
            "{}{sep}{} {}({})",
            mods_str,
            self.signature.return_type,
            self.name,
            params.join(", ")
        )
    }
}

// ─── DotnetType additional helpers ───────────────────────────────────────────

impl DotnetType {
    /// Returns `true` if the type has generic parameters.
    #[must_use]
    pub const fn is_generic(&self) -> bool {
        !self.generic_params.is_empty()
    }

    /// Returns the generic arity (number of type parameters).
    #[must_use]
    pub const fn generic_arity(&self) -> usize {
        self.generic_params.len()
    }

    /// Returns `true` if the type is decorated with `[Obsolete]`.
    #[must_use]
    pub fn is_obsolete(&self) -> bool {
        self.custom_attributes
            .iter()
            .any(|a| a.is_type("ObsoleteAttribute") || a.is_type("System.ObsoleteAttribute"))
    }

    /// Returns the first custom attribute of the given type name.
    #[must_use]
    pub fn first_attribute(&self, type_name: &str) -> Option<&CustomAttribute> {
        self.custom_attributes.iter().find(|a| a.is_type(type_name))
    }

    /// Returns property names.
    #[must_use]
    pub fn property_names(&self) -> Vec<&str> {
        self.properties.iter().map(|p| p.name.as_str()).collect()
    }

    /// Returns event names.
    #[must_use]
    pub fn event_names(&self) -> Vec<&str> {
        self.events.iter().map(|e| e.name.as_str()).collect()
    }

    /// Find all methods with the given name.
    #[must_use]
    pub fn methods_named(&self, name: &str) -> Vec<&DotnetMethod> {
        self.methods.iter().filter(|m| m.name == name).collect()
    }
}

// ─── AssemblyFile additional helpers ─────────────────────────────────────────

impl AssemblyFile {
    /// Returns all types in sorted order.
    #[must_use]
    pub fn all_types_sorted(&self) -> Vec<DotnetType> {
        let mut out: Vec<DotnetType> = self.types();
        out.sort_by(|a, b| a.full_name.cmp(&b.full_name));
        out
    }

    /// Returns the type hierarchy for all types in the assembly.
    #[must_use]
    pub fn type_hierarchy(&self) -> Vec<TypeHierarchyNode> {
        let types: Vec<DotnetType> = self.types();
        build_type_hierarchy(&types)
    }

    /// Returns all assembly references as display names.
    #[must_use]
    pub fn reference_display_names(&self) -> Vec<String> {
        self.assembly_references()
            .into_iter()
            .map(|r| r.display_name())
            .collect()
    }

    /// Find all methods across all types with the given name.
    #[must_use]
    pub fn find_methods_named(&self, name: &str) -> Vec<DotnetMethod> {
        self.types()
            .into_iter()
            .flat_map(|t| {
                t.methods
                    .into_iter()
                    .filter(|m| m.name == name)
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_parameter_def_flags_out() {
        let p = ParameterDef {
            index: 1,
            flags: 0x0002,
            type_name: "int".into(),
            ..Default::default()
        };
        assert!(p.is_out());
        assert!(!p.is_in());
        assert!(!p.is_optional());
        assert!(!p.is_return_value());
    }

    #[test]
    fn test_parameter_def_return_value() {
        let p = ParameterDef {
            index: 0,
            ..Default::default()
        };
        assert!(p.is_return_value());
    }

    #[test]
    fn test_parameter_def_format_out() {
        let p = ParameterDef {
            index: 1,
            flags: 0x0002,
            name: "result".into(),
            type_name: "int".into(),
            ..Default::default()
        };
        assert!(p.format().contains("out"));
        assert!(p.format().contains("int"));
        assert!(p.format().contains("result"));
    }

    #[test]
    fn test_binding_redirect_matches() {
        let r = BindingRedirect {
            assembly_name: "mscorlib".into(),
            old_version_min: AssemblyVersion {
                major: 1,
                minor: 0,
                build: 0,
                revision: 0,
            },
            old_version_max: AssemblyVersion {
                major: 3,
                minor: 9,
                build: 0,
                revision: 0,
            },
            new_version: AssemblyVersion {
                major: 4,
                minor: 0,
                build: 0,
                revision: 0,
            },
            public_key_token: None,
            culture: None,
        };
        let v2 = AssemblyVersion {
            major: 2,
            minor: 0,
            build: 0,
            revision: 0,
        };
        let v5 = AssemblyVersion {
            major: 5,
            minor: 0,
            build: 0,
            revision: 0,
        };
        assert!(r.matches(&v2));
        assert!(!r.matches(&v5));
    }

    #[test]
    fn test_binding_redirect_xml() {
        let r = BindingRedirect {
            assembly_name: "Newtonsoft.Json".into(),
            old_version_min: AssemblyVersion::default(),
            old_version_max: AssemblyVersion {
                major: 12,
                minor: 0,
                build: 0,
                revision: 0,
            },
            new_version: AssemblyVersion {
                major: 13,
                minor: 0,
                build: 0,
                revision: 0,
            },
            public_key_token: None,
            culture: None,
        };
        let xml = r.to_config_xml();
        assert!(xml.contains("Newtonsoft.Json"));
        assert!(xml.contains("dependentAssembly"));
    }

    #[test]
    fn test_type_hierarchy_build() {
        let make_type = |name: &str, base: Option<&str>| DotnetType {
            full_name: name.into(),
            name: name.into(),
            base_type: base.map(str::to_string),
            namespace: String::new(),
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };

        let types = vec![make_type("Animal", None), make_type("Dog", Some("Animal"))];
        let h = build_type_hierarchy(&types);
        assert_eq!(h.len(), 2);
        let animal = h.iter().find(|n| n.full_name == "Animal").unwrap();
        assert!(animal.children.contains(&"Dog".to_string()));
    }

    #[test]
    fn test_type_hierarchy_node_is_root() {
        let n = TypeHierarchyNode::leaf("Base", None);
        assert!(n.is_root());
        assert!(n.is_leaf());
    }

    #[test]
    fn test_resolved_type_ref() {
        let r = ResolvedTypeRef::InAssembly("System.Int32".into());
        assert_eq!(r.full_name(), "System.Int32");
        assert!(r.is_resolved());

        let e = ResolvedTypeRef::External {
            assembly: "mscorlib".into(),
            full_name: "System.String".into(),
        };
        assert_eq!(e.full_name(), "System.String");
        assert!(e.is_resolved());

        let u = ResolvedTypeRef::Unknown("X.Y".into());
        assert!(!u.is_resolved());
        assert_eq!(u.full_name(), "X.Y");
    }

    #[test]
    fn test_token_decode_encode() {
        let tok = encode_token(0x06, 1);
        let (table, row) = decode_token(tok);
        assert_eq!(table, 0x06);
        assert_eq!(row, 1);
    }

    #[test]
    fn test_token_table_name() {
        assert_eq!(token_table_name(token_table::METHOD_DEF), "MethodDef");
        assert_eq!(token_table_name(token_table::TYPE_DEF), "TypeDef");
        assert_eq!(token_table_name(0xFF), "<unknown>");
    }

    #[test]
    fn test_element_type_name() {
        assert_eq!(element_type_name(element_type::I4), "System.Int32");
        assert_eq!(element_type_name(element_type::STRING), "System.String");
        assert_eq!(element_type_name(element_type::VOID), "System.Void");
    }

    #[test]
    fn test_element_type_to_csharp() {
        assert_eq!(element_type_to_csharp(element_type::I4), "int");
        assert_eq!(element_type_to_csharp(element_type::BOOLEAN), "bool");
        assert_eq!(element_type_to_csharp(element_type::STRING), "string");
    }

    #[test]
    fn test_cil_instruction_is_load_const() {
        assert!(CilInstruction::simple(0, "ldc.i4.0").is_load_const());
        assert!(CilInstruction::simple(0, "ldnull").is_load_const());
        assert!(!CilInstruction::simple(0, "add").is_load_const());
    }

    #[test]
    fn test_cil_instruction_is_call() {
        assert!(CilInstruction::simple(0, "call").is_call());
        assert!(CilInstruction::simple(0, "callvirt").is_call());
        assert!(!CilInstruction::simple(0, "ret").is_call());
    }

    #[test]
    fn test_cil_instruction_token() {
        let i = CilInstruction {
            offset: 0,
            opcode: "call".into(),
            operand: CilOperand::Token(0x0A00_0001),
        };
        assert_eq!(i.token(), Some(0x0A00_0001));
    }

    #[test]
    fn test_cil_instruction_immediate_i32() {
        assert_eq!(
            CilInstruction::simple(0, "ldc.i4.5").immediate_i32(),
            Some(5)
        );
        assert_eq!(
            CilInstruction::simple(0, "ldc.i4.m1").immediate_i32(),
            Some(-1)
        );
        assert_eq!(CilInstruction::simple(0, "nop").immediate_i32(), None);
    }

    #[test]
    fn test_method_body_call_sites() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction {
                    offset: 0,
                    opcode: "call".into(),
                    operand: CilOperand::Token(0x0A00_0001),
                },
                CilInstruction {
                    offset: 5,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(body.call_sites(), vec![0x0A00_0001]);
    }

    #[test]
    fn test_method_body_field_access_tokens() {
        let body = MethodBody {
            instructions: vec![
                CilInstruction {
                    offset: 0,
                    opcode: "ldarg.0".into(),
                    operand: CilOperand::None,
                },
                CilInstruction {
                    offset: 1,
                    opcode: "ldfld".into(),
                    operand: CilOperand::Token(0x0400_0001),
                },
                CilInstruction {
                    offset: 6,
                    opcode: "ret".into(),
                    operand: CilOperand::None,
                },
            ],
            ..Default::default()
        };
        let tokens = body.field_access_tokens();
        assert!(tokens.contains(&0x0400_0001));
    }

    #[test]
    fn test_dotnet_method_is_obsolete() {
        let m = DotnetMethod {
            name: "OldMethod".into(),
            custom_attributes: vec![CustomAttribute::from_blob(
                "System.ObsoleteAttribute",
                vec![],
            )],
            ..Default::default()
        };
        assert!(m.is_obsolete());
    }

    #[test]
    fn test_dotnet_method_summary() {
        let m = DotnetMethod {
            name: "Add".into(),
            signature: MethodSignature {
                return_type: "int".into(),
                params: vec![("a".into(), "int".into()), ("b".into(), "int".into())],
                is_static: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let s = m.summary();
        assert!(s.contains("Add"));
        assert!(s.contains("int"));
    }

    #[test]
    fn test_dotnet_type_is_generic() {
        let t_base = DotnetType {
            name: "Pair".into(),
            namespace: String::new(),
            full_name: "Pair".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![
                GenericParam {
                    number: 0,
                    name: "T".into(),
                    flags: 0,
                    constraints: vec![],
                },
                GenericParam {
                    number: 1,
                    name: "U".into(),
                    flags: 0,
                    constraints: vec![],
                },
            ],
            kind_tag: DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        assert!(t_base.is_generic());
        assert_eq!(t_base.generic_arity(), 2);
    }

    #[test]
    fn test_dotnet_type_event_names() {
        let ev = EventModel {
            name: "Click".into(),
            type_name: "EventHandler".into(),
            flags: 0,
            add: Some("add_Click".into()),
            remove: Some("remove_Click".into()),
            raise: None,
            custom_attributes: vec![],
        };
        let t = DotnetType {
            name: "Button".into(),
            namespace: String::new(),
            full_name: "Button".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![],
            events: vec![ev],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        assert_eq!(t.event_names(), vec!["Click"]);
    }

    #[test]
    fn test_dotnet_type_property_names() {
        let prop = PropertyModel {
            name: "Width".into(),
            type_name: "int".into(),
            flags: 0,
            getter: Some("get_Width".into()),
            setter: None,
            custom_attributes: vec![],
            has_default: false,
            default_value: None,
        };
        let t = DotnetType {
            name: "Box".into(),
            namespace: String::new(),
            full_name: "Box".into(),
            base_type: None,
            interfaces: vec![],
            methods: vec![],
            fields: vec![],
            properties: vec![prop],
            events: vec![],
            nested_types: vec![],
            custom_attributes: vec![],
            generic_params: vec![],
            kind_tag: DotnetTypeKind::Class,
            flags: 0,
            layout: None,
        };
        assert_eq!(t.property_names(), vec!["Width"]);
    }
}

// ─── Obfuscator detection ─────────────────────────────────────────────────────

/// Known .NET obfuscators that can be detected from assembly metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscatorKind {
    /// `ConfuserEx` / Confuser — detected via `__Cctor` method or Unicode type names.
    ConfuserEx,
    /// Dotfuscator by `PreEmptive` Solutions — detected via assembly reference name.
    Dotfuscator,
    /// `SmartAssembly` by Red Gate — detected via `SA_Library` type.
    SmartAssembly,
}

impl fmt::Display for ObfuscatorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfuserEx => write!(f, "ConfuserEx"),
            Self::Dotfuscator => write!(f, "Dotfuscator"),
            Self::SmartAssembly => write!(f, "SmartAssembly"),
        }
    }
}

// ─── DotNetAnalysisResult ─────────────────────────────────────────────────────

/// Summary produced by [`DotNetAssemblyAnalyzer::analyze`].
#[derive(Debug, Clone)]
pub struct DotNetAnalysisResult {
    /// Simple module name from the Module table (e.g. `"MyApp.exe"`).
    pub module_name: String,
    /// Module version ID (MVID) as a 16-byte array.
    pub mvid: [u8; 16],
    /// All high-level type definitions in the assembly.
    pub types: Vec<DotnetType>,
    /// Total number of method definitions in the assembly.
    pub methods_count: usize,
    /// `true` if at least one known obfuscator signature was detected.
    pub has_obfuscation: bool,
    /// Which obfuscators were detected (may contain multiple).
    pub detected_obfuscators: Vec<ObfuscatorKind>,
}

impl DotNetAnalysisResult {
    /// Returns `true` if a specific obfuscator kind was detected.
    #[must_use]
    pub fn has_obfuscator(&self, kind: &ObfuscatorKind) -> bool {
        self.detected_obfuscators.contains(kind)
    }
}

// ─── DotNetAssemblyAnalyzer ───────────────────────────────────────────────────

/// High-level .NET assembly analyser.
///
/// Wraps both metadata parsing and CIL analysis into a single entry point and
/// adds obfuscator-detection heuristics for the most common packers.
pub struct DotNetAssemblyAnalyzer;

impl DotNetAssemblyAnalyzer {
    /// Parse and analyse a raw PE byte slice.
    ///
    /// # Errors
    /// Returns an error if the bytes do not represent a valid .NET assembly.
    pub fn analyze(bytes: &[u8]) -> anyhow::Result<DotNetAnalysisResult> {
        let metadata = rustre_dotnet_metadata::MetadataReader::parse_from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("metadata parse failed: {e}"))?;

        let assembly = AssemblyFile::from_metadata(metadata.clone());

        let module_name = metadata
            .tables
            .module
            .first()
            .map(|m| m.name.clone())
            .unwrap_or_default();

        let mvid = metadata
            .heaps
            .guid
            .get(metadata.tables.module.first().map_or(0, |m| m.mvid))
            .unwrap_or([0u8; 16]);

        let types = assembly.types();
        let methods_count = metadata.tables.method_def.len();

        let detected_obfuscators = Self::detect_obfuscators(&metadata, &types);
        let has_obfuscation = !detected_obfuscators.is_empty();

        Ok(DotNetAnalysisResult {
            module_name,
            mvid,
            types,
            methods_count,
            has_obfuscation,
            detected_obfuscators,
        })
    }

    /// Run all obfuscator heuristics and return a deduplicated list of matches.
    fn detect_obfuscators(
        metadata: &rustre_dotnet_metadata::MetadataReader,
        types: &[DotnetType],
    ) -> Vec<ObfuscatorKind> {
        let mut found = Vec::new();

        if Self::detect_confuserex(metadata, types) {
            found.push(ObfuscatorKind::ConfuserEx);
        }
        if Self::detect_dotfuscator(metadata) {
            found.push(ObfuscatorKind::Dotfuscator);
        }
        if Self::detect_smartassembly(types) {
            found.push(ObfuscatorKind::SmartAssembly);
        }

        found
    }

    /// `ConfuserEx` heuristics:
    /// 1. Presence of a method literally named `__Cctor` (module initialiser shim).
    /// 2. Type names that contain non-ASCII / Unicode characters (obfuscated identifiers).
    fn detect_confuserex(
        metadata: &rustre_dotnet_metadata::MetadataReader,
        types: &[DotnetType],
    ) -> bool {
        // Heuristic 1: __Cctor method in any type
        for t in types {
            if t.methods.iter().any(|m| m.name == "__Cctor") {
                return true;
            }
        }
        // Heuristic 2: type name with non-ASCII codepoints
        for row in &metadata.tables.type_def {
            if row.type_name.chars().any(|c| c as u32 > 0x7F) {
                return true;
            }
        }
        false
    }

    /// Dotfuscator heuristic: one of the assembly references has "Dotfuscator"
    /// in its name (`PreEmptive` injects a reference to its runtime library).
    fn detect_dotfuscator(metadata: &rustre_dotnet_metadata::MetadataReader) -> bool {
        metadata
            .tables
            .assembly_ref
            .iter()
            .any(|ar| ar.name.contains("Dotfuscator"))
    }

    /// `SmartAssembly` heuristic: presence of a type named `SA_Library`.
    fn detect_smartassembly(types: &[DotnetType]) -> bool {
        types.iter().any(|t| t.name == "SA_Library")
    }
}

// ─── EncryptedString ──────────────────────────────────────────────────────────

/// A potential encrypted string located in a method body.
#[derive(Debug, Clone)]
pub struct EncryptedString {
    /// Byte offset of the `ldsfld` instruction that loads the encrypted table.
    pub ldsfld_offset: u32,
    /// Raw ciphertext bytes extracted from the field's `FieldRVA` data, if resolvable.
    pub ciphertext: Vec<u8>,
    /// Token of the static field being loaded (used as a correlation key).
    pub field_token: u32,
}

// ─── DotNetStringDecryptor ────────────────────────────────────────────────────

/// Finds common .NET string-encryption patterns in assembly method bodies.
///
/// The pattern detected is:
/// ```text
///   ldsfld   <static_field_token>   ; load encrypted string table
///   ldc.i4   <index>                ; push table index / key
///   stsfld   <static_field_token>   ; store back (constant manipulation)
/// ```
/// This two-instruction idiom (`ldsfld` followed immediately by `stsfld` on the
/// same field with a constant in between) is emitted by several obfuscators
/// (`ConfuserEx`, eazfuscator) as the initialisation sequence for lazy-decryption
/// string tables.
pub struct DotNetStringDecryptor<'a> {
    assembly: &'a AssemblyFile,
}

impl<'a> DotNetStringDecryptor<'a> {
    /// Wrap an [`AssemblyFile`] for encrypted-string scanning.
    #[must_use]
    pub const fn new(assembly: &'a AssemblyFile) -> Self {
        Self { assembly }
    }

    /// Scan every method body in the assembly and return all suspected
    /// encrypted-string access sites.
    ///
    /// Each element describes one `ldsfld` instruction that is immediately
    /// followed by a constant-push and then an `stsfld` on the same field —
    /// the canonical obfuscator string-table manipulation pattern.
    #[must_use]
    pub fn find_encrypted_strings(&self) -> Vec<EncryptedString> {
        let mut results = Vec::new();

        for dtype in self.assembly.types() {
            for method in &dtype.methods {
                let Some(body) = &method.body else { continue };
                let instrs = &body.instructions;

                // Slide a 3-instruction window over the body.
                for window in instrs.windows(3) {
                    let [a, b, c] = window else { continue };

                    // Pattern: ldsfld <field_token>
                    //          ldc.i4.* or ldc.i4 <any constant>
                    //          stsfld <same field_token>
                    if a.opcode != "ldsfld" {
                        continue;
                    }
                    let CilOperand::Token(load_token) = a.operand else {
                        continue;
                    };

                    if !b.is_load_const() {
                        continue;
                    }

                    if c.opcode != "stsfld" {
                        continue;
                    }
                    let CilOperand::Token(store_token) = c.operand else {
                        continue;
                    };

                    if load_token != store_token {
                        continue;
                    }

                    // Try to resolve the FieldRVA for the field token so we can
                    // extract the raw ciphertext.  FieldRVA table id = 0x1D.
                    let field_idx = (load_token & 0x00FF_FFFF) as usize; // 1-based
                    let ciphertext = Self::resolve_field_rva_data(self.assembly, field_idx);

                    results.push(EncryptedString {
                        ldsfld_offset: a.offset,
                        ciphertext,
                        field_token: load_token,
                    });
                }
            }
        }

        results
    }

    /// Attempt to extract the raw bytes pointed to by a `FieldRVA` entry for the
    /// given 1-based field index.  Returns an empty `Vec` if no RVA is present
    /// or the assembly was not loaded from disk (no raw bytes available).
    fn resolve_field_rva_data(assembly: &AssemblyFile, field_1based: usize) -> Vec<u8> {
        let tables = &assembly.metadata.tables;
        // Find a FieldRVA row whose `field` matches this 1-based index.
        let Some(rva_row) = tables
            .field_rva
            .iter()
            .find(|r| r.field as usize == field_1based)
        else {
            return Vec::new();
        };
        // Without raw bytes we cannot resolve RVAs to file offsets.
        let raw = assembly.raw_bytes();
        if raw.is_empty() {
            return Vec::new();
        }
        // Retrieve the field signature to determine the data size.
        let sig_len = tables
            .field
            .get(field_1based.wrapping_sub(1))
            .map_or(0, |f| f.signature.len());
        // Minimal heuristic: read up to 256 bytes from the RVA offset.
        let estimated_len = sig_len.clamp(16, 256);
        let off = rva_row.rva as usize;
        if off + estimated_len <= raw.len() {
            raw[off..off + estimated_len].to_vec()
        } else if off < raw.len() {
            raw[off..].to_vec()
        } else {
            Vec::new()
        }
    }
}

// ─── DotNetAssemblyAnalyzer / DotNetStringDecryptor tests ─────────────────────

#[cfg(test)]
mod analyzer_tests {
    use super::*;
    use rustre_dotnet_metadata::{
        AssemblyRefRow, MetadataHeaps, MetadataReader, MetadataRoot, MetadataTables, MethodDefRow,
        TypeDefRow,
    };

    fn base_reader() -> MetadataReader {
        MetadataReader {
            root: MetadataRoot {
                major_version: 2,
                minor_version: 0,
                streams: vec![],
            },
            heaps: MetadataHeaps::default(),
            tables: MetadataTables::default(),
        }
    }

    // ── ObfuscatorKind display ────────────────────────────────────────────

    #[test]
    fn test_obfuscator_display() {
        assert_eq!(ObfuscatorKind::ConfuserEx.to_string(), "ConfuserEx");
        assert_eq!(ObfuscatorKind::Dotfuscator.to_string(), "Dotfuscator");
        assert_eq!(ObfuscatorKind::SmartAssembly.to_string(), "SmartAssembly");
    }

    // ── ConfuserEx: __Cctor method ────────────────────────────────────────

    #[test]
    fn test_detect_confuserex_via_cctor() {
        let mut reader = base_reader();
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "MyClass".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        reader.tables.method_def.push(MethodDefRow {
            rva: 0,
            impl_flags: 0,
            flags: 0x06,
            name: "__Cctor".into(),
            signature: vec![],
            param_list: 1,
        });
        let asm = AssemblyFile::from_metadata(reader);
        let types = asm.types();
        assert!(DotNetAssemblyAnalyzer::detect_confuserex(
            &asm.metadata,
            &types,
        ));
    }

    // ── ConfuserEx: Unicode type name ─────────────────────────────────────

    #[test]
    fn test_detect_confuserex_via_unicode_type_name() {
        let mut reader = base_reader();
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "\u{200B}Hidden".into(), // zero-width space prefix
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        let asm = AssemblyFile::from_metadata(reader);
        let types = asm.types();
        assert!(DotNetAssemblyAnalyzer::detect_confuserex(
            &asm.metadata,
            &types,
        ));
    }

    // ── Dotfuscator detection ─────────────────────────────────────────────

    #[test]
    fn test_detect_dotfuscator() {
        let mut reader = base_reader();
        reader.tables.assembly_ref.push(AssemblyRefRow {
            name: "PreEmptive.Dotfuscator.Runtime".into(),
            ..Default::default()
        });
        let asm = AssemblyFile::from_metadata(reader);
        assert!(DotNetAssemblyAnalyzer::detect_dotfuscator(&asm.metadata));
    }

    #[test]
    fn test_no_dotfuscator_without_ref() {
        let asm = AssemblyFile::from_metadata(base_reader());
        assert!(!DotNetAssemblyAnalyzer::detect_dotfuscator(&asm.metadata));
    }

    // ── SmartAssembly detection ───────────────────────────────────────────

    #[test]
    fn test_detect_smartassembly() {
        let mut reader = base_reader();
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "SA_Library".into(),
            type_namespace: String::new(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        let asm = AssemblyFile::from_metadata(reader);
        let types = asm.types();
        assert!(DotNetAssemblyAnalyzer::detect_smartassembly(&types));
    }

    // ── No obfuscation on clean assembly ─────────────────────────────────

    #[test]
    fn test_no_obfuscation_clean() {
        let mut reader = base_reader();
        reader.tables.type_def.push(TypeDefRow {
            flags: 0x01,
            type_name: "Program".into(),
            type_namespace: "MyApp".into(),
            extends: 0,
            field_list: 1,
            method_list: 1,
        });
        let asm = AssemblyFile::from_metadata(reader);
        let types = asm.types();
        assert!(!DotNetAssemblyAnalyzer::detect_confuserex(
            &asm.metadata,
            &types
        ));
        assert!(!DotNetAssemblyAnalyzer::detect_dotfuscator(&asm.metadata));
        assert!(!DotNetAssemblyAnalyzer::detect_smartassembly(&types));
    }

    // ── DotNetAnalysisResult helpers ──────────────────────────────────────

    #[test]
    fn test_has_obfuscator_true() {
        let result = DotNetAnalysisResult {
            module_name: "test.dll".into(),
            mvid: [0u8; 16],
            types: vec![],
            methods_count: 0,
            has_obfuscation: true,
            detected_obfuscators: vec![ObfuscatorKind::ConfuserEx],
        };
        assert!(result.has_obfuscator(&ObfuscatorKind::ConfuserEx));
        assert!(!result.has_obfuscator(&ObfuscatorKind::Dotfuscator));
    }

    // ── DotNetStringDecryptor ─────────────────────────────────────────────

    #[test]
    fn test_find_encrypted_strings_empty_body() {
        let asm = AssemblyFile::from_metadata(base_reader());
        let decryptor = DotNetStringDecryptor::new(&asm);
        assert!(decryptor.find_encrypted_strings().is_empty());
    }

    #[test]
    fn test_raw_bytes_empty_for_in_memory_assembly() {
        let asm = AssemblyFile::from_metadata(base_reader());
        assert!(asm.raw_bytes().is_empty());
    }
}
