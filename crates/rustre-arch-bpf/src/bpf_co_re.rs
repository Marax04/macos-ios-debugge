//! BPF CO-RE (Compile Once – Run Everywhere) relocation support.
//!
//! CO-RE allows BPF programs compiled with BTF type information to be
//! relocated at load time to match the layout of kernel structures on the
//! running kernel.
//!
//! This module provides:
//! - [`BtfKind`] — BTF type kinds
//! - [`BtfType`] — a parsed BTF type descriptor
//! - [`BtfParser`] — BTF binary parser
//! - [`CoReReloc`] — a single CO-RE relocation record
//! - [`CoReRelocKind`] — kind of relocation
//! - [`CoReApplier`] — applies relocations to a BPF instruction stream
//! - [`KernelBtf`] — simplified kernel BTF representation

// ---------------------------------------------------------------------------
// BtfKind
// ---------------------------------------------------------------------------

/// BTF type kind as defined in `include/uapi/linux/btf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtfKind {
    Unknown = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKind {
    /// Parse from a 5-bit kind field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x1f {
            1 => Self::Int,
            2 => Self::Ptr,
            3 => Self::Array,
            4 => Self::Struct,
            5 => Self::Union,
            6 => Self::Enum,
            7 => Self::Fwd,
            8 => Self::Typedef,
            9 => Self::Volatile,
            10 => Self::Const,
            11 => Self::Restrict,
            12 => Self::Func,
            13 => Self::FuncProto,
            14 => Self::Var,
            15 => Self::Datasec,
            16 => Self::Float,
            17 => Self::DeclTag,
            18 => Self::TypeTag,
            19 => Self::Enum64,
            _ => Self::Unknown,
        }
    }

    /// `true` if this kind has a `VLen` (variable-length members).
    #[must_use]
    pub const fn has_vlen(self) -> bool {
        matches!(
            self,
            Self::Struct
                | Self::Union
                | Self::Enum
                | Self::FuncProto
                | Self::Datasec
                | Self::Enum64
        )
    }

    /// `true` if this is a composite type (struct/union).
    #[must_use]
    pub const fn is_composite(self) -> bool {
        matches!(self, Self::Struct | Self::Union)
    }

    /// `true` if this is a modifier (pointer, volatile, const, restrict, typedef).
    #[must_use]
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::Ptr | Self::Volatile | Self::Const | Self::Restrict | Self::Typedef
        )
    }
}

impl std::fmt::Display for BtfKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Int => "int",
            Self::Ptr => "ptr",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Fwd => "fwd",
            Self::Typedef => "typedef",
            Self::Volatile => "volatile",
            Self::Const => "const",
            Self::Restrict => "restrict",
            Self::Func => "func",
            Self::FuncProto => "func_proto",
            Self::Var => "var",
            Self::Datasec => "datasec",
            Self::Float => "float",
            Self::DeclTag => "decl_tag",
            Self::TypeTag => "type_tag",
            Self::Enum64 => "enum64",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// BtfMember / BtfEnumVariant
// ---------------------------------------------------------------------------

/// A member (field) of a BTF struct or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMember {
    /// Field name.
    pub name: String,
    /// Type ID of the field.
    pub type_id: u32,
    /// Bit offset within the parent type.
    pub bit_offset: u32,
    /// Bit size (for bitfields, 0 otherwise).
    pub bit_size: u8,
}

/// An enumerator variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfEnumVariant {
    pub name: String,
    pub value: i64,
}

/// An array descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfArray {
    /// Element type ID.
    pub elem_type_id: u32,
    /// Index type ID (must be an integer).
    pub index_type_id: u32,
    /// Number of elements.
    pub num_elems: u32,
}

// ---------------------------------------------------------------------------
// BtfType
// ---------------------------------------------------------------------------

/// A fully parsed BTF type.
#[derive(Debug, Clone)]
pub struct BtfType {
    /// Type ID (1-based, assigned by the BTF header).
    pub id: u32,
    /// Type name (empty if anonymous).
    pub name: String,
    /// Type kind.
    pub kind: BtfKind,
    /// Size (bytes) for Int/Struct/Union/Enum/Float; referenced type ID for Ptr/Typedef etc.
    pub size_or_type: u32,
    /// Struct/union members.
    pub members: Vec<BtfMember>,
    /// Enum variants.
    pub variants: Vec<BtfEnumVariant>,
    /// Array descriptor.
    pub array: Option<BtfArray>,
    /// Function argument type IDs (for `FuncProto`).
    pub params: Vec<u32>,
    /// Return type ID (for `FuncProto`).
    pub ret_type_id: u32,
}

impl BtfType {
    /// Create a minimal BTF type.
    #[must_use]
    pub fn new(id: u32, name: impl Into<String>, kind: BtfKind, size_or_type: u32) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            size_or_type,
            members: Vec::new(),
            variants: Vec::new(),
            array: None,
            params: Vec::new(),
            ret_type_id: 0,
        }
    }

    /// `true` if this is a struct or union with named members.
    #[must_use]
    pub const fn is_aggregate(&self) -> bool {
        self.kind.is_composite()
    }

    /// Look up a member by name.
    #[must_use]
    pub fn find_member(&self, name: &str) -> Option<&BtfMember> {
        self.members.iter().find(|m| m.name == name)
    }

    /// Byte offset of a field (returns the `bit_offset` / 8 for non-bitfields).
    #[must_use]
    pub fn field_byte_offset(&self, name: &str) -> Option<u32> {
        self.find_member(name).map(|m| m.bit_offset / 8)
    }

    /// `true` if any member has the given name.
    #[must_use]
    pub fn has_field(&self, name: &str) -> bool {
        self.find_member(name).is_some()
    }
}

// ---------------------------------------------------------------------------
// BtfParser
// ---------------------------------------------------------------------------

/// Simplified in-memory BTF type table.
///
/// In a real implementation this would parse the binary BTF blob from
/// a BPF program's ELF section.  Here we provide a builder API for testing.
#[derive(Debug, Default)]
pub struct BtfParser {
    types: Vec<BtfType>,
    next_id: u32,
}

impl BtfParser {
    /// Create an empty BTF type table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            types: Vec::new(),
            next_id: 1,
        }
    }

    /// Add a type, assigning the next available ID.  Returns the assigned ID.
    #[must_use]
    pub fn add_type(&mut self, mut t: BtfType) -> u32 {
        let id = self.next_id;
        t.id = id;
        self.next_id += 1;
        self.types.push(t);
        id
    }

    /// Build an `Int` type.
    #[must_use]
    pub fn add_int(&mut self, name: &str, size_bytes: u32) -> u32 {
        self.add_type(BtfType::new(0, name, BtfKind::Int, size_bytes))
    }

    /// Build a `Struct` type with the given members.
    #[must_use]
    pub fn add_struct(&mut self, name: &str, size_bytes: u32, members: Vec<BtfMember>) -> u32 {
        let mut t = BtfType::new(0, name, BtfKind::Struct, size_bytes);
        t.members = members;
        self.add_type(t)
    }

    /// Build a `Ptr` type pointing to `target_type_id`.
    #[must_use]
    pub fn add_ptr(&mut self, name: &str, target_type_id: u32) -> u32 {
        self.add_type(BtfType::new(0, name, BtfKind::Ptr, target_type_id))
    }

    /// Look up a type by ID (1-based).
    #[must_use]
    pub fn get_type(&self, id: u32) -> Option<&BtfType> {
        self.types.iter().find(|t| t.id == id)
    }

    /// Look up a type by name.
    #[must_use]
    pub fn get_type_by_name(&self, name: &str) -> Option<&BtfType> {
        self.types.iter().find(|t| t.name == name)
    }

    /// Total number of types.
    #[must_use]
    pub const fn type_count(&self) -> usize {
        self.types.len()
    }

    /// All type IDs.
    #[must_use]
    pub fn type_ids(&self) -> Vec<u32> {
        self.types.iter().map(|t| t.id).collect()
    }

    /// Resolve a typedef/const/volatile/restrict chain to the base type.
    #[must_use]
    pub fn resolve_type(&self, id: u32) -> Option<&BtfType> {
        let mut cur = id;
        for _ in 0..32 {
            let t = self.get_type(cur)?;
            if t.kind.is_modifier() {
                cur = t.size_or_type;
            } else {
                return Some(t);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// CO-RE relocation kinds
// ---------------------------------------------------------------------------

/// Kind of CO-RE relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoReRelocKind {
    /// Field byte offset.
    FieldByteOffset,
    /// Field byte size.
    FieldByteSize,
    /// Existence of a field (0 or 1).
    FieldExists,
    /// Field bit offset (for bitfields).
    FieldBitOffset,
    /// Field bit size (for bitfields).
    FieldBitSize,
    /// Signed/unsigned flag.
    FieldSigned,
    /// Local type ID matches kernel type ID.
    TypeIdLocal,
    /// Remote (kernel) type ID.
    TypeIdKernel,
    /// Byte size of the type.
    TypeSize,
    /// Whether the type exists in the kernel.
    TypeExists,
    /// Enum value.
    EnumvalValue,
    /// Whether an enum value exists.
    EnumvalExists,
}

impl CoReRelocKind {
    /// Parse from a raw integer.
    #[must_use]
    pub const fn from_raw(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::FieldByteOffset),
            1 => Some(Self::FieldByteSize),
            2 => Some(Self::FieldExists),
            3 => Some(Self::FieldBitOffset),
            4 => Some(Self::FieldBitSize),
            5 => Some(Self::FieldSigned),
            6 => Some(Self::TypeIdLocal),
            7 => Some(Self::TypeIdKernel),
            8 => Some(Self::TypeSize),
            9 => Some(Self::TypeExists),
            10 => Some(Self::EnumvalValue),
            11 => Some(Self::EnumvalExists),
            _ => None,
        }
    }

    /// `true` if this relocation targets a struct/union field.
    #[must_use]
    pub const fn is_field_reloc(self) -> bool {
        matches!(
            self,
            Self::FieldByteOffset
                | Self::FieldByteSize
                | Self::FieldExists
                | Self::FieldBitOffset
                | Self::FieldBitSize
                | Self::FieldSigned
        )
    }

    /// `true` if this relocation targets a type.
    #[must_use]
    pub const fn is_type_reloc(self) -> bool {
        matches!(
            self,
            Self::TypeIdLocal | Self::TypeIdKernel | Self::TypeSize | Self::TypeExists
        )
    }
}

impl std::fmt::Display for CoReRelocKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FieldByteOffset => "field_byte_offset",
            Self::FieldByteSize => "field_byte_size",
            Self::FieldExists => "field_exists",
            Self::FieldBitOffset => "field_bit_offset",
            Self::FieldBitSize => "field_bit_size",
            Self::FieldSigned => "field_signed",
            Self::TypeIdLocal => "type_id_local",
            Self::TypeIdKernel => "type_id_kernel",
            Self::TypeSize => "type_size",
            Self::TypeExists => "type_exists",
            Self::EnumvalValue => "enumval_value",
            Self::EnumvalExists => "enumval_exists",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CoReReloc
// ---------------------------------------------------------------------------

/// A single CO-RE relocation record (from `.BTF.ext`).
#[derive(Debug, Clone)]
pub struct CoReReloc {
    /// Byte offset of the BPF instruction to patch.
    pub insn_off: u32,
    /// BTF type ID of the local (compiled) type.
    pub type_id: u32,
    /// Dot-separated access string (e.g. "0:3:1").
    pub access_str: String,
    /// Kind of relocation.
    pub kind: CoReRelocKind,
}

impl CoReReloc {
    /// Create a new CO-RE relocation record.
    #[must_use]
    pub fn new(insn_off: u32, type_id: u32, access_str: &str, kind: CoReRelocKind) -> Self {
        Self {
            insn_off,
            type_id,
            access_str: access_str.to_string(),
            kind,
        }
    }

    /// Parse the access string into a list of integer indices.
    ///
    /// Returns `None` if any token is not a valid integer.
    #[must_use]
    pub fn parse_access_indices(&self) -> Option<Vec<u32>> {
        self.access_str
            .split(':')
            .map(|s| s.parse::<u32>().ok())
            .collect()
    }

    /// `true` if this relocation is for a field offset.
    #[must_use]
    pub fn is_field_offset(&self) -> bool {
        self.kind == CoReRelocKind::FieldByteOffset
    }
}

// ---------------------------------------------------------------------------
// KernelBtf
// ---------------------------------------------------------------------------

/// Simplified representation of the kernel's BTF type database.
///
/// In production this would be loaded from `/sys/kernel/btf/vmlinux`.
/// Here it wraps a [`BtfParser`] populated with well-known types.
#[derive(Debug, Default)]
pub struct KernelBtf {
    /// The underlying type table.
    pub btf: BtfParser,
}

impl KernelBtf {
    /// Create an empty kernel BTF database.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            btf: BtfParser::new(),
        }
    }

    /// Populate with a minimal set of Linux kernel types for testing.
    ///
    /// # Panics
    ///
    /// Panics if the type table does not contain the expected `u64` or `u32` types
    /// after they are added (which should never happen in normal usage).
    #[must_use]
    pub fn with_common_types(mut self) -> Self {
        // u8, u16, u32, u64
        let _ = self.btf.add_int("u8", 1);
        let _ = self.btf.add_int("u16", 2);
        let _ = self.btf.add_int("u32", 4);
        let _ = self.btf.add_int("u64", 8);
        let _ = self.btf.add_int("s32", 4);
        let _ = self.btf.add_int("s64", 8);
        // struct task_struct (simplified: only a few fields)
        let u64_id = self.btf.get_type_by_name("u64").unwrap().id;
        let u32_id = self.btf.get_type_by_name("u32").unwrap().id;
        let _ = self.btf.add_struct(
            "task_struct",
            9216,
            vec![
                BtfMember {
                    name: "pid".into(),
                    type_id: u32_id,
                    bit_offset: 1760,
                    bit_size: 0,
                },
                BtfMember {
                    name: "tgid".into(),
                    type_id: u32_id,
                    bit_offset: 1792,
                    bit_size: 0,
                },
                BtfMember {
                    name: "comm".into(),
                    type_id: u32_id,
                    bit_offset: 4672,
                    bit_size: 0,
                },
                BtfMember {
                    name: "state".into(),
                    type_id: u64_id,
                    bit_offset: 0,
                    bit_size: 0,
                },
            ],
        );
        // struct sk_buff (simplified)
        let _ = self.btf.add_struct(
            "sk_buff",
            232,
            vec![
                BtfMember {
                    name: "len".into(),
                    type_id: u32_id,
                    bit_offset: 512,
                    bit_size: 0,
                },
                BtfMember {
                    name: "data_len".into(),
                    type_id: u32_id,
                    bit_offset: 544,
                    bit_size: 0,
                },
                BtfMember {
                    name: "protocol".into(),
                    type_id: u32_id,
                    bit_offset: 640,
                    bit_size: 0,
                },
            ],
        );
        self
    }

    /// Look up a type by name.
    #[must_use]
    pub fn get_type(&self, name: &str) -> Option<&BtfType> {
        self.btf.get_type_by_name(name)
    }

    /// Resolve a field byte offset for `struct_name::field_name`.
    #[must_use]
    pub fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u32> {
        self.btf
            .get_type_by_name(struct_name)?
            .field_byte_offset(field_name)
    }

    /// `true` if the struct has the given field.
    #[must_use]
    pub fn field_exists(&self, struct_name: &str, field_name: &str) -> bool {
        self.btf
            .get_type_by_name(struct_name)
            .is_some_and(|t| t.has_field(field_name))
    }
}

// ---------------------------------------------------------------------------
// BPF instruction (simplified)
// ---------------------------------------------------------------------------

/// A simplified 64-bit BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    /// Opcode byte.
    pub opcode: u8,
    /// Destination register (4-bit).
    pub dst_reg: u8,
    /// Source register (4-bit).
    pub src_reg: u8,
    /// 16-bit signed offset.
    pub off: i16,
    /// 32-bit immediate.
    pub imm: i32,
}

impl BpfInsn {
    /// Create a new BPF instruction.
    #[must_use]
    pub const fn new(opcode: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_reg,
            src_reg,
            off,
            imm,
        }
    }

    /// Encode to 8 bytes (little-endian).
    #[must_use]
    pub const fn encode(&self) -> [u8; 8] {
        let regs = (self.dst_reg & 0xf) | ((self.src_reg & 0xf) << 4);
        let off_bytes = self.off.to_le_bytes();
        let imm_bytes = self.imm.to_le_bytes();
        [
            self.opcode,
            regs,
            off_bytes[0],
            off_bytes[1],
            imm_bytes[0],
            imm_bytes[1],
            imm_bytes[2],
            imm_bytes[3],
        ]
    }

    /// Decode from 8 bytes.
    #[must_use]
    pub const fn decode(bytes: &[u8; 8]) -> Self {
        let opcode = bytes[0];
        let dst_reg = bytes[1] & 0xf;
        let src_reg = (bytes[1] >> 4) & 0xf;
        let off = i16::from_le_bytes([bytes[2], bytes[3]]);
        let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self {
            opcode,
            dst_reg,
            src_reg,
            off,
            imm,
        }
    }
}

// ---------------------------------------------------------------------------
// CoReApplier
// ---------------------------------------------------------------------------

/// Result of applying a single CO-RE relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoReApplyResult {
    /// Relocation applied successfully; new immediate value.
    Applied { new_imm: i32 },
    /// Field does not exist in kernel; instruction should be poisoned.
    FieldMissing,
    /// Type does not exist in kernel.
    TypeMissing,
    /// Relocation kind not supported.
    Unsupported,
    /// Access string parse error.
    ParseError,
}

/// Applies CO-RE relocations to a BPF instruction stream.
pub struct CoReApplier<'a> {
    kernel_btf: &'a KernelBtf,
}

impl<'a> CoReApplier<'a> {
    /// Create an applier backed by `kernel_btf`.
    #[must_use]
    pub const fn new(kernel_btf: &'a KernelBtf) -> Self {
        Self { kernel_btf }
    }

    /// Apply a single relocation to `insns` (instruction index = `reloc.insn_off` / 8).
    ///
    /// Modifies `insns` in place and returns the result.
    #[must_use]
    pub fn apply(&self, reloc: &CoReReloc, insns: &mut [BpfInsn]) -> CoReApplyResult {
        let insn_idx = usize::try_from(reloc.insn_off / 8).unwrap_or(usize::MAX);
        if insn_idx >= insns.len() {
            return CoReApplyResult::Unsupported;
        }

        match reloc.kind {
            CoReRelocKind::FieldByteOffset => {
                // Parse access string: first index = struct member index or 0 (array deref)
                let Some(indices) = reloc.parse_access_indices() else {
                    return CoReApplyResult::ParseError;
                };
                // Look up the struct type and member
                let Some(type_info) = self.kernel_btf.btf.get_type(reloc.type_id) else {
                    return CoReApplyResult::TypeMissing;
                };
                let member_idx = *indices.first().unwrap_or(&0) as usize;
                let Some(member) = type_info.members.get(member_idx) else {
                    return CoReApplyResult::FieldMissing;
                };
                let byte_off = member.bit_offset / 8;
                // A u32 byte offset that doesn't fit in i32 would corrupt the
                // instruction immediate.  Clamp to i32::MAX so callers get a
                // detectable (too-large) value rather than a wrapped negative.
                let new_imm = i32::try_from(byte_off).unwrap_or(i32::MAX);
                insns[insn_idx].imm = new_imm;
                CoReApplyResult::Applied { new_imm }
            }

            CoReRelocKind::FieldExists => {
                let Some(type_info) = self.kernel_btf.btf.get_type(reloc.type_id) else {
                    insns[insn_idx].imm = 0;
                    return CoReApplyResult::Applied { new_imm: 0 };
                };
                let exists = !type_info.members.is_empty();
                let new_imm = i32::from(exists);
                insns[insn_idx].imm = new_imm;
                CoReApplyResult::Applied { new_imm }
            }

            CoReRelocKind::TypeSize => {
                let Some(type_info) = self.kernel_btf.btf.get_type(reloc.type_id) else {
                    return CoReApplyResult::TypeMissing;
                };
                let new_imm = type_info.size_or_type.cast_signed();
                insns[insn_idx].imm = new_imm;
                CoReApplyResult::Applied { new_imm }
            }

            CoReRelocKind::TypeExists => {
                let exists = self.kernel_btf.btf.get_type(reloc.type_id).is_some();
                let new_imm = i32::from(exists);
                insns[insn_idx].imm = new_imm;
                CoReApplyResult::Applied { new_imm }
            }

            CoReRelocKind::FieldByteSize => {
                let Some(indices) = reloc.parse_access_indices() else {
                    return CoReApplyResult::ParseError;
                };
                let Some(type_info) = self.kernel_btf.btf.get_type(reloc.type_id) else {
                    return CoReApplyResult::TypeMissing;
                };
                let member_idx = *indices.first().unwrap_or(&0) as usize;
                let Some(member) = type_info.members.get(member_idx) else {
                    return CoReApplyResult::FieldMissing;
                };
                let member_type = self.kernel_btf.btf.get_type(member.type_id);
                let size = member_type.map_or(4, |t| t.size_or_type);
                let new_imm = size.cast_signed();
                insns[insn_idx].imm = new_imm;
                CoReApplyResult::Applied { new_imm }
            }

            _ => CoReApplyResult::Unsupported,
        }
    }

    /// Apply all relocations in `relocs` to `insns`.
    #[must_use]
    pub fn apply_all(
        &self,
        relocs: &[CoReReloc],
        insns: &mut [BpfInsn],
    ) -> Vec<CoReApplyResult> {
        relocs.iter().map(|r| self.apply(r, insns)).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel() -> KernelBtf {
        KernelBtf::new().with_common_types()
    }

    // ── 1. BtfKind basics ───────────────────────────────────────────────────
    #[test]
    fn test_btf_kind_from_bits() {
        assert_eq!(BtfKind::from_bits(1), BtfKind::Int);
        assert_eq!(BtfKind::from_bits(4), BtfKind::Struct);
        assert_eq!(BtfKind::from_bits(0), BtfKind::Unknown);
        assert_eq!(BtfKind::from_bits(19), BtfKind::Enum64);
    }

    #[test]
    fn test_btf_kind_has_vlen() {
        assert!(BtfKind::Struct.has_vlen());
        assert!(BtfKind::Enum.has_vlen());
        assert!(!BtfKind::Int.has_vlen());
        assert!(!BtfKind::Ptr.has_vlen());
    }

    #[test]
    fn test_btf_kind_is_composite() {
        assert!(BtfKind::Struct.is_composite());
        assert!(BtfKind::Union.is_composite());
        assert!(!BtfKind::Int.is_composite());
    }

    #[test]
    fn test_btf_kind_is_modifier() {
        assert!(BtfKind::Ptr.is_modifier());
        assert!(BtfKind::Const.is_modifier());
        assert!(BtfKind::Typedef.is_modifier());
        assert!(!BtfKind::Struct.is_modifier());
    }

    #[test]
    fn test_btf_kind_display() {
        assert_eq!(format!("{}", BtfKind::Struct), "struct");
        assert_eq!(format!("{}", BtfKind::FuncProto), "func_proto");
    }

    // ── 2. BtfType ──────────────────────────────────────────────────────────
    #[test]
    fn test_btf_type_new() {
        let t = BtfType::new(1, "u32", BtfKind::Int, 4);
        assert_eq!(t.id, 1);
        assert_eq!(t.kind, BtfKind::Int);
        assert_eq!(t.size_or_type, 4);
    }

    #[test]
    fn test_btf_type_find_member() {
        let mut t = BtfType::new(1, "foo", BtfKind::Struct, 8);
        t.members.push(BtfMember {
            name: "x".into(),
            type_id: 1,
            bit_offset: 0,
            bit_size: 0,
        });
        t.members.push(BtfMember {
            name: "y".into(),
            type_id: 1,
            bit_offset: 32,
            bit_size: 0,
        });
        assert!(t.find_member("x").is_some());
        assert!(t.find_member("z").is_none());
    }

    #[test]
    fn test_btf_type_field_byte_offset() {
        let mut t = BtfType::new(1, "s", BtfKind::Struct, 8);
        t.members.push(BtfMember {
            name: "a".into(),
            type_id: 1,
            bit_offset: 64,
            bit_size: 0,
        });
        assert_eq!(t.field_byte_offset("a"), Some(8));
    }

    #[test]
    fn test_btf_type_has_field() {
        let mut t = BtfType::new(1, "s", BtfKind::Struct, 4);
        t.members.push(BtfMember {
            name: "field".into(),
            type_id: 1,
            bit_offset: 0,
            bit_size: 0,
        });
        assert!(t.has_field("field"));
        assert!(!t.has_field("other"));
    }

    // ── 3. BtfParser ────────────────────────────────────────────────────────
    #[test]
    fn test_btf_parser_add_int() {
        let mut p = BtfParser::new();
        let id = p.add_int("u32", 4);
        assert_eq!(id, 1);
        let t = p.get_type(1).unwrap();
        assert_eq!(t.name, "u32");
        assert_eq!(t.kind, BtfKind::Int);
    }

    #[test]
    fn test_btf_parser_add_struct() {
        let mut p = BtfParser::new();
        let u32_id = p.add_int("u32", 4);
        let id = p.add_struct(
            "task",
            16,
            vec![BtfMember {
                name: "pid".into(),
                type_id: u32_id,
                bit_offset: 0,
                bit_size: 0,
            }],
        );
        let t = p.get_type(id).unwrap();
        assert_eq!(t.kind, BtfKind::Struct);
        assert_eq!(t.members.len(), 1);
    }

    #[test]
    fn test_btf_parser_type_count() {
        let mut p = BtfParser::new();
        let _ = p.add_int("u8", 1);
        let _ = p.add_int("u32", 4);
        assert_eq!(p.type_count(), 2);
    }

    #[test]
    fn test_btf_parser_get_type_by_name() {
        let mut p = BtfParser::new();
        let _ = p.add_int("s64", 8);
        let t = p.get_type_by_name("s64").unwrap();
        assert_eq!(t.name, "s64");
    }

    #[test]
    fn test_btf_parser_resolve_const() {
        let mut p = BtfParser::new();
        let int_id = p.add_int("u32", 4);
        let const_id = p.add_type(BtfType::new(0, "", BtfKind::Const, int_id));
        let resolved = p.resolve_type(const_id).unwrap();
        assert_eq!(resolved.kind, BtfKind::Int);
    }

    // ── 4. CoReRelocKind ────────────────────────────────────────────────────
    #[test]
    fn test_core_reloc_kind_from_raw() {
        assert_eq!(
            CoReRelocKind::from_raw(0),
            Some(CoReRelocKind::FieldByteOffset)
        );
        assert_eq!(CoReRelocKind::from_raw(8), Some(CoReRelocKind::TypeSize));
        assert_eq!(CoReRelocKind::from_raw(99), None);
    }

    #[test]
    fn test_core_reloc_kind_is_field_reloc() {
        assert!(CoReRelocKind::FieldByteOffset.is_field_reloc());
        assert!(CoReRelocKind::FieldExists.is_field_reloc());
        assert!(!CoReRelocKind::TypeSize.is_field_reloc());
    }

    #[test]
    fn test_core_reloc_kind_is_type_reloc() {
        assert!(CoReRelocKind::TypeSize.is_type_reloc());
        assert!(!CoReRelocKind::FieldByteOffset.is_type_reloc());
    }

    #[test]
    fn test_core_reloc_kind_display() {
        assert_eq!(
            format!("{}", CoReRelocKind::FieldByteOffset),
            "field_byte_offset"
        );
        assert_eq!(format!("{}", CoReRelocKind::TypeExists), "type_exists");
    }

    // ── 5. CoReReloc ─────────────────────────────────────────────────────────
    #[test]
    fn test_core_reloc_parse_access() {
        let r = CoReReloc::new(0, 1, "0:3:1", CoReRelocKind::FieldByteOffset);
        let idx = r.parse_access_indices().unwrap();
        assert_eq!(idx, vec![0, 3, 1]);
    }

    #[test]
    fn test_core_reloc_parse_access_invalid() {
        let r = CoReReloc::new(0, 1, "0:abc", CoReRelocKind::FieldByteOffset);
        assert!(r.parse_access_indices().is_none());
    }

    #[test]
    fn test_core_reloc_is_field_offset() {
        let r = CoReReloc::new(0, 1, "0", CoReRelocKind::FieldByteOffset);
        assert!(r.is_field_offset());
        let r2 = CoReReloc::new(0, 1, "0", CoReRelocKind::TypeSize);
        assert!(!r2.is_field_offset());
    }

    // ── 6. KernelBtf ─────────────────────────────────────────────────────────
    #[test]
    fn test_kernel_btf_with_common_types() {
        let k = kernel();
        assert!(k.get_type("task_struct").is_some());
        assert!(k.get_type("sk_buff").is_some());
        assert!(k.get_type("u32").is_some());
    }

    #[test]
    fn test_kernel_btf_field_offset() {
        let k = kernel();
        let off = k.field_offset("task_struct", "pid").unwrap();
        assert_eq!(off, 1760 / 8); // 220
    }

    #[test]
    fn test_kernel_btf_field_exists() {
        let k = kernel();
        assert!(k.field_exists("task_struct", "pid"));
        assert!(!k.field_exists("task_struct", "nonexistent_field"));
    }

    // ── 7. BpfInsn encode/decode ─────────────────────────────────────────────
    #[test]
    fn test_bpf_insn_encode_decode() {
        let insn = BpfInsn::new(0x18, 1, 0, 0, 42);
        let enc = insn.encode();
        let dec = BpfInsn::decode(&enc);
        assert_eq!(dec, insn);
    }

    #[test]
    fn test_bpf_insn_regs() {
        let insn = BpfInsn::new(0x61, 3, 2, 0, 0);
        let enc = insn.encode();
        let dec = BpfInsn::decode(&enc);
        assert_eq!(dec.dst_reg, 3);
        assert_eq!(dec.src_reg, 2);
    }

    // ── 8. CoReApplier ───────────────────────────────────────────────────────
    #[test]
    fn test_applier_field_exists_type_present() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let task_id = k.btf.get_type_by_name("task_struct").unwrap().id;
        let reloc = CoReReloc::new(0, task_id, "0", CoReRelocKind::FieldExists);
        let mut insns = vec![BpfInsn::new(0xb7, 1, 0, 0, 0)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::Applied { new_imm: 1 });
    }

    #[test]
    fn test_applier_type_size() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let task_id = k.btf.get_type_by_name("task_struct").unwrap().id;
        let reloc = CoReReloc::new(0, task_id, "0", CoReRelocKind::TypeSize);
        let mut insns = vec![BpfInsn::new(0xb7, 1, 0, 0, 0)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::Applied { new_imm: 9216 });
    }

    #[test]
    fn test_applier_type_exists_true() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let u32_id = k.btf.get_type_by_name("u32").unwrap().id;
        let reloc = CoReReloc::new(0, u32_id, "0", CoReRelocKind::TypeExists);
        let mut insns = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::Applied { new_imm: 1 });
    }

    #[test]
    fn test_applier_type_exists_false() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        // Type ID 9999 does not exist
        let reloc = CoReReloc::new(0, 9999, "0", CoReRelocKind::TypeExists);
        let mut insns = vec![BpfInsn::new(0xb7, 0, 0, 0, 1)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::Applied { new_imm: 0 });
        assert_eq!(insns[0].imm, 0);
    }

    #[test]
    fn test_applier_type_missing_returns_error() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let reloc = CoReReloc::new(0, 9999, "0", CoReRelocKind::TypeSize);
        let mut insns = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::TypeMissing);
    }

    #[test]
    fn test_applier_out_of_range_insn() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let reloc = CoReReloc::new(8, 1, "0", CoReRelocKind::TypeExists);
        let mut insns = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)]; // only 1 insn
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::Unsupported);
    }

    #[test]
    fn test_applier_apply_all() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let u32_id = k.btf.get_type_by_name("u32").unwrap().id;
        let relocs = vec![
            CoReReloc::new(0, u32_id, "0", CoReRelocKind::TypeExists),
            CoReReloc::new(8, u32_id, "0", CoReRelocKind::TypeSize),
        ];
        let mut insns = vec![
            BpfInsn::new(0xb7, 0, 0, 0, 0),
            BpfInsn::new(0xb7, 1, 0, 0, 0),
        ];
        let results = applier.apply_all(&relocs, &mut insns);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], CoReApplyResult::Applied { new_imm: 1 });
        assert_eq!(results[1], CoReApplyResult::Applied { new_imm: 4 });
    }

    // ── Additional tests ─────────────────────────────────────────────────────

    #[test]
    fn test_btf_kind_from_bits_all() {
        for b in 0u8..=19 {
            let k = BtfKind::from_bits(b);
            assert_eq!(k as u8, if b <= 19 { b } else { 0 });
        }
    }

    #[test]
    fn test_btf_type_is_aggregate() {
        let s = BtfType::new(1, "s", BtfKind::Struct, 8);
        assert!(s.is_aggregate());
        let i = BtfType::new(2, "i", BtfKind::Int, 4);
        assert!(!i.is_aggregate());
    }

    #[test]
    fn test_btf_parser_add_ptr() {
        let mut p = BtfParser::new();
        let int_id = p.add_int("u32", 4);
        let ptr_id = p.add_ptr("u32_ptr", int_id);
        let t = p.get_type(ptr_id).unwrap();
        assert_eq!(t.kind, BtfKind::Ptr);
        assert_eq!(t.size_or_type, int_id);
    }

    #[test]
    fn test_btf_parser_type_ids() {
        let mut p = BtfParser::new();
        let _ = p.add_int("a", 1);
        let _ = p.add_int("b", 2);
        let ids = p.type_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }

    #[test]
    fn test_kernel_btf_default() {
        let k = KernelBtf::default();
        assert_eq!(k.btf.type_count(), 0);
    }

    #[test]
    fn test_bpf_insn_offset_encoding() {
        let insn = BpfInsn::new(0x05, 0, 0, -10, 0);
        let enc = insn.encode();
        let dec = BpfInsn::decode(&enc);
        assert_eq!(dec.off, -10);
    }

    #[test]
    fn test_core_reloc_kind_all_from_raw() {
        for i in 0u32..=11 {
            assert!(
                CoReRelocKind::from_raw(i).is_some(),
                "kind {i} should parse"
            );
        }
        assert!(CoReRelocKind::from_raw(12).is_none());
    }

    #[test]
    fn test_applier_field_byte_size_missing_type() {
        let k = kernel();
        let applier = CoReApplier::new(&k);
        let reloc = CoReReloc::new(0, 9999, "0", CoReRelocKind::FieldByteSize);
        let mut insns = vec![BpfInsn::new(0xb7, 0, 0, 0, 0)];
        let res = applier.apply(&reloc, &mut insns);
        assert_eq!(res, CoReApplyResult::TypeMissing);
    }

    #[test]
    fn test_btf_member_fields() {
        let m = BtfMember {
            name: "foo".into(),
            type_id: 5,
            bit_offset: 128,
            bit_size: 0,
        };
        assert_eq!(m.name, "foo");
        assert_eq!(m.type_id, 5);
        assert_eq!(m.bit_offset, 128);
    }

    #[test]
    fn test_btf_array_fields() {
        let a = BtfArray {
            elem_type_id: 1,
            index_type_id: 2,
            num_elems: 10,
        };
        assert_eq!(a.num_elems, 10);
    }

    #[test]
    fn test_btf_enum_variant_fields() {
        let v = BtfEnumVariant {
            name: "A".into(),
            value: 0,
        };
        assert_eq!(v.name, "A");
    }
}
