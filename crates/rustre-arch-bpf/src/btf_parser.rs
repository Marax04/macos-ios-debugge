//! BPF Type Format (BTF) section parser.
//!
//! BTF is a compact type description format stored in the `.BTF` ELF section
//! (and optionally `.BTF.ext` for line information).  The Linux kernel uses BTF
//! to verify BPF programs, expose map layout, and drive the `bpftool` introspection
//! tooling.
//!
//! This module parses:
//! * The BTF header, string section, and type section.
//! * All type kinds: `INT`, `PTR`, `ARRAY`, `STRUCT`, `UNION`, `ENUM`, `FWD`,
//!   `TYPEDEF`, `VOLATILE`, `CONST`, `RESTRICT`, `FUNC`, `FUNC_PROTO`,
//!   `VAR`, `DATASEC`, `FLOAT`, `DECL_TAG`, `TYPE_TAG`, `ENUM64`.
//! * Function prototype recovery from `FUNC` + `FUNC_PROTO` chains.
//! * Pretty-printed C type reconstruction.

use std::collections::HashMap;
use std::fmt;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    TooShort { needed: usize, got: usize },
    BadMagic(u16),
    UnsupportedVersion(u8),
    BadStringOffset(u32),
    BadTypeId(u32),
    UnknownKind(u8),
    InvalidIntEncoding(u32),
    Malformed(String),
}

impl fmt::Display for BtfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } =>
                write!(f, "BTF: buffer too short (need {needed}, have {got})"),
            Self::BadMagic(m) =>
                write!(f, "BTF: bad magic 0x{m:04X} (expected 0xEB9F)"),
            Self::UnsupportedVersion(v) =>
                write!(f, "BTF: unsupported version {v} (expected 1)"),
            Self::BadStringOffset(o) =>
                write!(f, "BTF: string offset {o} out of range"),
            Self::BadTypeId(id) =>
                write!(f, "BTF: type ID {id} out of range"),
            Self::UnknownKind(k) =>
                write!(f, "BTF: unknown type kind {k}"),
            Self::InvalidIntEncoding(e) =>
                write!(f, "BTF: invalid INT encoding flags 0x{e:08X}"),
            Self::Malformed(s) =>
                write!(f, "BTF: malformed record: {s}"),
        }
    }
}

// ── BTF header ────────────────────────────────────────────────────────────────

const BTF_MAGIC: u16 = 0xEB9F;
const BTF_VERSION: u8 = 1;

/// Parsed BTF header (24 bytes, little-endian).
#[derive(Debug, Clone)]
pub struct BtfHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    /// Offset from end of header to start of type section.
    pub type_off: u32,
    pub type_len: u32,
    /// Offset from end of header to start of string section.
    pub str_off: u32,
    pub str_len: u32,
}

impl BtfHeader {
    fn parse(data: &[u8]) -> Result<Self, BtfError> {
        if data.len() < 24 {
            return Err(BtfError::TooShort { needed: 24, got: data.len() });
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        let version = data[2];
        if version != BTF_VERSION {
            return Err(BtfError::UnsupportedVersion(version));
        }
        Ok(Self {
            magic,
            version,
            flags: data[3],
            hdr_len: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            type_off: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            type_len: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            str_off: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            str_len: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        })
    }
}

// ── Type kinds ────────────────────────────────────────────────────────────────

/// All BTF type kinds as defined by `include/uapi/linux/btf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtfKind {
    Int       = 1,
    Ptr       = 2,
    Array     = 3,
    Struct    = 4,
    Union     = 5,
    Enum      = 6,
    Fwd       = 7,
    Typedef   = 8,
    Volatile  = 9,
    Const     = 10,
    Restrict  = 11,
    Func      = 12,
    FuncProto = 13,
    Var       = 14,
    Datasec   = 15,
    Float     = 16,
    DeclTag   = 17,
    TypeTag   = 18,
    Enum64    = 19,
}

impl BtfKind {
    const fn from_u8(v: u8) -> Result<Self, BtfError> {
        Ok(match v {
            1  => Self::Int,
            2  => Self::Ptr,
            3  => Self::Array,
            4  => Self::Struct,
            5  => Self::Union,
            6  => Self::Enum,
            7  => Self::Fwd,
            8  => Self::Typedef,
            9  => Self::Volatile,
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
            _  => return Err(BtfError::UnknownKind(v)),
        })
    }
}

// ── Integer encoding flags ────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Encoding flags for `BTF_KIND_INT` (stored in 4-byte extra word).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IntEncoding: u32 {
        const SIGNED   = 1 << 0;
        const CHAR     = 1 << 1;
        const BOOL     = 1 << 2;
    }
}

// ── Member / parameter / enum value records ───────────────────────────────────

/// A struct/union member.
#[derive(Debug, Clone)]
pub struct BtfMember {
    pub name: String,
    pub type_id: u32,
    /// Bit offset (or byte offset × 8 for non-bitfield members).
    pub bit_offset: u32,
    /// Bit size for bitfield members; 0 = not a bitfield.
    pub bitfield_size: u32,
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct BtfParam {
    pub name: String,
    pub type_id: u32,
}

/// An enum value.
#[derive(Debug, Clone)]
pub struct BtfEnumValue {
    pub name: String,
    pub value: i64,
}

/// A variable within a DATASEC.
#[derive(Debug, Clone)]
pub struct BtfVarInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

// ── Concrete type data ─────────────────────────────────────────────────────────

/// The type-specific payload for a BTF type record.
#[derive(Debug, Clone)]
pub enum BtfTypeData {
    Int {
        encoding: IntEncoding,
        offset: u8,   // bit offset within the storage type
        bits: u8,     // number of bits
    },
    Ptr {
        pointee: u32, // type_id of the pointed-to type
    },
    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },
    Struct {
        size: u32,
        members: Vec<BtfMember>,
    },
    Union {
        size: u32,
        members: Vec<BtfMember>,
    },
    Enum {
        size: u32,
        signed: bool,
        values: Vec<BtfEnumValue>,
    },
    Enum64 {
        size: u32,
        signed: bool,
        values: Vec<BtfEnumValue>,
    },
    Fwd {
        is_union: bool,
    },
    Typedef { type_id: u32 },
    Volatile { type_id: u32 },
    Const    { type_id: u32 },
    Restrict { type_id: u32 },
    Func {
        type_id: u32,   // points to FUNC_PROTO
        linkage: u8,    // 0=static, 1=global, 2=extern
    },
    FuncProto {
        ret_type_id: u32,
        params: Vec<BtfParam>,
    },
    Var {
        type_id: u32,
        linkage: u8,
    },
    Datasec {
        size: u32,
        vars: Vec<BtfVarInfo>,
    },
    Float { size: u32 },
    DeclTag {
        type_id: u32,
        component_idx: i32, // -1 = applies to the whole type
        tag: String,
    },
    TypeTag {
        type_id: u32,
        tag: String,
    },
}

/// A single BTF type record.
#[derive(Debug, Clone)]
pub struct BtfType {
    /// 1-based type ID (ID 0 = void).
    pub id: u32,
    /// Name from the string section (may be empty).
    pub name: String,
    /// Type kind.
    pub kind: BtfKind,
    /// Kind-specific payload.
    pub data: BtfTypeData,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parsed BTF section.
#[derive(Debug, Clone)]
pub struct BtfSection {
    pub header: BtfHeader,
    /// All types, indexed by their 1-based ID (index 0 is unused / void).
    pub types: Vec<BtfType>,
    /// Raw string section.
    pub strings: Vec<u8>,
}

impl BtfSection {
    /// Parse a raw `.BTF` section.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is too short, has an invalid magic/version,
    /// contains an unknown type kind, or is otherwise malformed.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        let hdr = BtfHeader::parse(data)?;
        let hdr_end = hdr.hdr_len as usize;

        let str_start = hdr_end
            .checked_add(hdr.str_off as usize)
            .ok_or_else(|| BtfError::Malformed("string section offset overflow".into()))?;
        let str_end = str_start
            .checked_add(hdr.str_len as usize)
            .ok_or_else(|| BtfError::Malformed("string section end overflow".into()))?;
        if str_end > data.len() {
            return Err(BtfError::TooShort { needed: str_end, got: data.len() });
        }
        let strings = data[str_start..str_end].to_vec();

        let type_start = hdr_end
            .checked_add(hdr.type_off as usize)
            .ok_or_else(|| BtfError::Malformed("type section offset overflow".into()))?;
        let type_end = type_start
            .checked_add(hdr.type_len as usize)
            .ok_or_else(|| BtfError::Malformed("type section end overflow".into()))?;
        if type_end > data.len() {
            return Err(BtfError::TooShort { needed: type_end, got: data.len() });
        }
        let type_data = &data[type_start..type_end];

        let types = Self::parse_types(type_data, &strings)?;

        Ok(Self { header: hdr, types, strings })
    }

    fn get_str(strings: &[u8], off: u32) -> Result<String, BtfError> {
        let off = off as usize;
        if off >= strings.len() {
            return Err(BtfError::BadStringOffset(u32::try_from(off).unwrap_or(u32::MAX)));
        }
        let end = strings[off..].iter().position(|&b| b == 0)
            .map_or(strings.len(), |i| off + i);
        Ok(String::from_utf8_lossy(&strings[off..end]).into_owned())
    }

    fn read_u32(data: &[u8], off: usize) -> Result<u32, BtfError> {
        if off + 4 > data.len() {
            return Err(BtfError::TooShort { needed: off + 4, got: data.len() });
        }
        Ok(u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]))
    }

    /// Maximum number of variable-length records (members/params/values) allowed
    /// per type entry.  The BTF spec uses a 16-bit `vlen` field (max 65535), but
    /// pre-allocating 65535 entries per type would allow a `DoS` via a crafted BTF
    /// section that contains many large-`vlen` type records.  Cap conservatively.
    const MAX_VLEN: usize = 4096;

    fn parse_struct_members(
        data: &[u8], strings: &[u8], vlen: usize, pos: &mut usize, kind_flag: bool,
    ) -> Result<Vec<BtfMember>, BtfError> {
        let mut members = Vec::with_capacity(vlen);
        for _ in 0..vlen {
            if *pos + 12 > data.len() {
                return Err(BtfError::TooShort { needed: *pos + 12, got: data.len() });
            }
            let mname_off  = Self::read_u32(data, *pos)?;
            let mtype_id   = Self::read_u32(data, *pos + 4)?;
            let raw_offset = Self::read_u32(data, *pos + 8)?;
            *pos += 12;
            let member_name = Self::get_str(strings, mname_off)?;
            let (bit_offset, bitfield_size) = if kind_flag {
                (raw_offset >> 8, raw_offset & 0xFF)
            } else {
                (raw_offset, 0)
            };
            members.push(BtfMember { name: member_name, type_id: mtype_id, bit_offset, bitfield_size });
        }
        Ok(members)
    }

    fn parse_enum_values(
        data: &[u8], strings: &[u8], vlen: usize, pos: &mut usize, signed: bool,
    ) -> Result<Vec<BtfEnumValue>, BtfError> {
        let mut values = Vec::with_capacity(vlen);
        for _ in 0..vlen {
            if *pos + 8 > data.len() {
                return Err(BtfError::TooShort { needed: *pos + 8, got: data.len() });
            }
            let vname_off = Self::read_u32(data, *pos)?;
            let raw_val   = Self::read_u32(data, *pos + 4)?;
            *pos += 8;
            let vname = Self::get_str(strings, vname_off)?;
            let value = if signed { i64::from(raw_val.cast_signed()) } else { i64::from(raw_val) };
            values.push(BtfEnumValue { name: vname, value });
        }
        Ok(values)
    }

    fn parse_enum64_values(
        data: &[u8], strings: &[u8], vlen: usize, pos: &mut usize,
    ) -> Result<Vec<BtfEnumValue>, BtfError> {
        let mut values = Vec::with_capacity(vlen);
        for _ in 0..vlen {
            if *pos + 12 > data.len() {
                return Err(BtfError::TooShort { needed: *pos + 12, got: data.len() });
            }
            let vname_off = Self::read_u32(data, *pos)?;
            let val_lo    = Self::read_u32(data, *pos + 4)?;
            let val_hi    = Self::read_u32(data, *pos + 8)?;
            *pos += 12;
            let vname = Self::get_str(strings, vname_off)?;
            let raw = (u64::from(val_hi) << 32) | u64::from(val_lo);
            values.push(BtfEnumValue { name: vname, value: raw.cast_signed() });
        }
        Ok(values)
    }

    fn parse_func_proto_params(
        data: &[u8], strings: &[u8], vlen: usize, pos: &mut usize,
    ) -> Result<Vec<BtfParam>, BtfError> {
        let mut params = Vec::with_capacity(vlen);
        for _ in 0..vlen {
            if *pos + 8 > data.len() {
                return Err(BtfError::TooShort { needed: *pos + 8, got: data.len() });
            }
            let pname_off = Self::read_u32(data, *pos)?;
            let ptype_id  = Self::read_u32(data, *pos + 4)?;
            *pos += 8;
            let pname = Self::get_str(strings, pname_off)?;
            params.push(BtfParam { name: pname, type_id: ptype_id });
        }
        Ok(params)
    }

    fn parse_datasec_vars(
        data: &[u8], vlen: usize, pos: &mut usize,
    ) -> Result<Vec<BtfVarInfo>, BtfError> {
        let mut vars = Vec::with_capacity(vlen);
        for _ in 0..vlen {
            if *pos + 12 > data.len() {
                return Err(BtfError::TooShort { needed: *pos + 12, got: data.len() });
            }
            let vtype_id = Self::read_u32(data, *pos)?;
            let voffset  = Self::read_u32(data, *pos + 4)?;
            let vsize    = Self::read_u32(data, *pos + 8)?;
            *pos += 12;
            vars.push(BtfVarInfo { type_id: vtype_id, offset: voffset, size: vsize });
        }
        Ok(vars)
    }

    fn parse_types(data: &[u8], strings: &[u8]) -> Result<Vec<BtfType>, BtfError> {
        let mut types = Vec::new();
        let mut pos = 0usize;
        let mut next_id = 1u32;

        while pos + 12 <= data.len() {
            let name_off  = Self::read_u32(data, pos)?;
            let info      = Self::read_u32(data, pos + 4)?;
            let size_type = Self::read_u32(data, pos + 8)?;
            pos += 12;

            let kind_raw  = ((info >> 24) & 0x1F) as u8;
            let vlen_raw  = (info & 0xFFFF) as usize;
            let kind_flag = (info >> 31) != 0;
            if vlen_raw > Self::MAX_VLEN {
                return Err(BtfError::Malformed(format!(
                    "vlen {vlen_raw} exceeds maximum {}", Self::MAX_VLEN
                )));
            }

            let kind = BtfKind::from_u8(kind_raw)?;
            let name = Self::get_str(strings, name_off)?;

            let type_data = match kind {
                BtfKind::Int => {
                    let enc_raw = Self::read_u32(data, pos)?;
                    pos += 4;
                    let enc_bits = u8::try_from(enc_raw & 0xFF).unwrap_or(u8::MAX);
                    let enc_off  = u8::try_from((enc_raw >> 16) & 0xFF).unwrap_or(u8::MAX);
                    let encoding = IntEncoding::from_bits_truncate(enc_raw >> 24);
                    BtfTypeData::Int { encoding, offset: enc_off, bits: enc_bits }
                }
                BtfKind::Ptr      => BtfTypeData::Ptr       { pointee: size_type },
                BtfKind::Typedef  => BtfTypeData::Typedef   { type_id: size_type },
                BtfKind::Volatile => BtfTypeData::Volatile  { type_id: size_type },
                BtfKind::Const    => BtfTypeData::Const     { type_id: size_type },
                BtfKind::Restrict => BtfTypeData::Restrict  { type_id: size_type },
                BtfKind::Fwd      => BtfTypeData::Fwd { is_union: kind_flag },
                BtfKind::Float    => BtfTypeData::Float { size: size_type },
                BtfKind::Array => {
                    if pos + 12 > data.len() {
                        return Err(BtfError::TooShort { needed: pos + 12, got: data.len() });
                    }
                    let elem_type  = Self::read_u32(data, pos)?;
                    let index_type = Self::read_u32(data, pos + 4)?;
                    let nelems     = Self::read_u32(data, pos + 8)?;
                    pos += 12;
                    BtfTypeData::Array { elem_type, index_type, nelems }
                }
                BtfKind::Struct | BtfKind::Union => {
                    let members = Self::parse_struct_members(data, strings, vlen_raw, &mut pos, kind_flag)?;
                    if kind == BtfKind::Struct {
                        BtfTypeData::Struct { size: size_type, members }
                    } else {
                        BtfTypeData::Union { size: size_type, members }
                    }
                }
                BtfKind::Enum => {
                    let values = Self::parse_enum_values(data, strings, vlen_raw, &mut pos, kind_flag)?;
                    BtfTypeData::Enum { size: size_type, signed: kind_flag, values }
                }
                BtfKind::Enum64 => {
                    let values = Self::parse_enum64_values(data, strings, vlen_raw, &mut pos)?;
                    BtfTypeData::Enum64 { size: size_type, signed: kind_flag, values }
                }
                BtfKind::Func => {
                    let linkage = u8::try_from((info >> 16) & 0xF).unwrap_or(u8::MAX);
                    BtfTypeData::Func { type_id: size_type, linkage }
                }
                BtfKind::FuncProto => {
                    let params = Self::parse_func_proto_params(data, strings, vlen_raw, &mut pos)?;
                    BtfTypeData::FuncProto { ret_type_id: size_type, params }
                }
                BtfKind::Var => {
                    let linkage_raw = Self::read_u32(data, pos)?;
                    pos += 4;
                    BtfTypeData::Var { type_id: size_type, linkage: u8::try_from(linkage_raw).unwrap_or(u8::MAX) }
                }
                BtfKind::Datasec => {
                    let vars = Self::parse_datasec_vars(data, vlen_raw, &mut pos)?;
                    BtfTypeData::Datasec { size: size_type, vars }
                }
                BtfKind::DeclTag => {
                    let component_idx = (Self::read_u32(data, pos)?).cast_signed();
                    pos += 4;
                    BtfTypeData::DeclTag { type_id: size_type, component_idx, tag: name.clone() }
                }
                BtfKind::TypeTag => {
                    BtfTypeData::TypeTag { type_id: size_type, tag: name.clone() }
                }
            };

            types.push(BtfType { id: next_id, name, kind, data: type_data });
            next_id += 1;
        }

        if pos != data.len() {
            return Err(BtfError::Malformed(format!(
                "trailing {} byte(s) after last type record", data.len() - pos
            )));
        }

        Ok(types)
    }

    /// Look up a type by its 1-based ID (returns None for ID 0 = void).
    #[must_use]
    pub fn get_type(&self, id: u32) -> Option<&BtfType> {
        if id == 0 { return None; }
        self.types.get((id - 1) as usize)
    }

    /// Resolve typedef/volatile/const/restrict chains to the underlying type.
    #[must_use]
    pub fn resolve(&self, mut id: u32) -> Option<&BtfType> {
        for _ in 0..32 {
            let t = self.get_type(id)?;
            id = match &t.data {
                BtfTypeData::Typedef  { type_id }
                | BtfTypeData::Volatile { type_id }
                | BtfTypeData::Const    { type_id }
                | BtfTypeData::Restrict { type_id } => *type_id,
                _ => return Some(t),
            };
        }
        None // circular reference guard
    }

    /// Get the size in bytes of a type (0 for void, pointers assume 8 bytes).
    #[must_use]
    pub fn size_of(&self, id: u32) -> usize {
        if id == 0 { return 0; }
        let Some(t) = self.get_type(id) else { return 0 };
        match &t.data {
            BtfTypeData::Int    { bits, .. }    => (*bits as usize).div_ceil(8),
            BtfTypeData::Ptr    { .. }           => 8,
            BtfTypeData::Array  { elem_type, nelems, .. } => {
                self.size_of(*elem_type).saturating_mul(*nelems as usize)
            }
            BtfTypeData::Float  { size }
            | BtfTypeData::Struct { size, .. }
            | BtfTypeData::Union  { size, .. }
            | BtfTypeData::Enum   { size, .. }
            | BtfTypeData::Enum64 { size, .. }  => *size as usize,
            BtfTypeData::Typedef  { type_id }
            | BtfTypeData::Volatile { type_id }
            | BtfTypeData::Const    { type_id }
            | BtfTypeData::Restrict { type_id } => self.size_of(*type_id),
            _ => 0,
        }
    }

    /// Maximum recursion depth for C type reconstruction.  BTF types can form
    /// chains (Ptr→Typedef→Const→…) and a crafted section could create cycles
    /// that were not caught by `resolve()` (which is not called here).
    const MAX_TYPE_DEPTH: u32 = 64;

    /// Reconstruct a C type declaration string for a given type ID.
    #[must_use]
    pub fn to_c_type(&self, id: u32) -> String {
        self.to_c_type_inner(id, "", 0)
    }

    fn to_c_type_inner(&self, id: u32, var_name: &str, depth: u32) -> String {
        if depth > Self::MAX_TYPE_DEPTH {
            return format!("/* type_{id} (depth limit) */ {var_name}").trim_end().to_string();
        }
        if id == 0 { return format!("void {var_name}").trim_end().to_string(); }
        let Some(t) = self.get_type(id) else { return format!("type_{id} {var_name}").trim_end().to_string() };

        match &t.data {
            BtfTypeData::Int { encoding, bits, .. } => {
                let base = if encoding.contains(IntEncoding::BOOL) {
                    "_Bool".to_string()
                } else if encoding.contains(IntEncoding::CHAR) {
                    if encoding.contains(IntEncoding::SIGNED) { "signed char".to_string() } else { "char".to_string() }
                } else {
                    let s = if encoding.contains(IntEncoding::SIGNED) { "s" } else { "u" };
                    format!("{s}{bits}")
                };
                if var_name.is_empty() { base } else { format!("{base} {var_name}") }
            }
            BtfTypeData::Float { size } => {
                let base = match size { 4 => "float", 8 => "double", _ => "long double" };
                if var_name.is_empty() { base.to_string() } else { format!("{base} {var_name}") }
            }
            BtfTypeData::Ptr { pointee } => {
                if *pointee == 0 {
                    format!("void *{var_name}").trim_end().to_string()
                } else {
                    let inner = self.to_c_type_inner(*pointee, &format!("*{var_name}"), depth + 1);
                    inner.trim_end().to_string()
                }
            }
            BtfTypeData::Array { elem_type, nelems, .. } => {
                let new_name = format!("{var_name}[{nelems}]");
                self.to_c_type_inner(*elem_type, &new_name, depth + 1)
            }
            BtfTypeData::Struct { .. } => {
                let n = if t.name.is_empty() { "<anon>".to_string() } else { t.name.clone() };
                format!("struct {n} {var_name}").trim_end().to_string()
            }
            BtfTypeData::Union { .. } => {
                let n = if t.name.is_empty() { "<anon>".to_string() } else { t.name.clone() };
                format!("union {n} {var_name}").trim_end().to_string()
            }
            BtfTypeData::Enum { .. } => {
                let n = if t.name.is_empty() { "<anon>".to_string() } else { t.name.clone() };
                format!("enum {n} {var_name}").trim_end().to_string()
            }
            BtfTypeData::Typedef { type_id } => {
                if t.name.is_empty() {
                    self.to_c_type_inner(*type_id, var_name, depth + 1)
                } else {
                    format!("{} {var_name}", t.name).trim_end().to_string()
                }
            }
            BtfTypeData::Const    { type_id } =>
                format!("const {}", self.to_c_type_inner(*type_id, var_name, depth + 1)),
            BtfTypeData::Volatile { type_id } =>
                format!("volatile {}", self.to_c_type_inner(*type_id, var_name, depth + 1)),
            BtfTypeData::Restrict { type_id } =>
                format!("restrict {}", self.to_c_type_inner(*type_id, var_name, depth + 1)),
            BtfTypeData::Func { type_id, .. } => {
                // Show as: ret_type name(params)
                self.func_proto_string(*type_id, &t.name, depth + 1)
            }
            BtfTypeData::FuncProto { ret_type_id, params } => {
                let ret = self.to_c_type_inner(*ret_type_id, "", depth + 1);
                let args: Vec<_> = params.iter()
                    .map(|p| self.to_c_type_inner(p.type_id, &p.name, depth + 1))
                    .collect();
                let args_str = if args.is_empty() { "void".to_string() } else { args.join(", ") };
                format!("{ret} (*{var_name})({args_str})").trim_end().to_string()
            }
            BtfTypeData::Fwd { is_union } => {
                let kw = if *is_union { "union" } else { "struct" };
                format!("{kw} {}", t.name)
            }
            _ => format!("/* {kind:?} */ {var_name}", kind = t.kind).trim_end().to_string(),
        }
    }

    fn func_proto_string(&self, proto_id: u32, func_name: &str, depth: u32) -> String {
        let Some(proto) = self.get_type(proto_id) else {
            return format!("void {func_name}(...)");
        };
        match &proto.data {
            BtfTypeData::FuncProto { ret_type_id, params } => {
                let ret = self.to_c_type_inner(*ret_type_id, "", depth + 1);
                let args: Vec<_> = params.iter()
                    .map(|p| {
                        if p.name.is_empty() {
                            self.to_c_type_inner(p.type_id, "", depth + 1)
                        } else {
                            self.to_c_type_inner(p.type_id, &p.name, depth + 1)
                        }
                    })
                    .collect();
                let args_str = if args.is_empty() { "void".to_string() } else { args.join(", ") };
                format!("{ret} {func_name}({args_str})")
            }
            _ => format!("void {func_name}(...)"),
        }
    }

    /// Collect all `FUNC` types and return their C prototypes.
    #[must_use]
    pub fn function_prototypes(&self) -> Vec<(u32, String)> {
        self.types.iter()
            .filter(|t| t.kind == BtfKind::Func)
            .map(|t| (t.id, self.to_c_type(t.id)))
            .collect()
    }

    /// Find a type by name and kind.
    #[must_use]
    pub fn find_by_name(&self, name: &str, kind: BtfKind) -> Option<&BtfType> {
        self.types.iter().find(|t| t.kind == kind && t.name == name)
    }

    /// Summarise all types: kind → count.
    #[must_use]
    pub fn kind_counts(&self) -> HashMap<BtfKind, usize> {
        let mut map = HashMap::new();
        for t in &self.types {
            *map.entry(t.kind).or_insert(0) += 1;
        }
        map
    }

    /// Dump a human-readable summary of one type.
    #[must_use]
    pub fn describe_type(&self, id: u32) -> String {
        let Some(t) = self.get_type(id) else { return format!("[{id}] void"); };
        let c = self.to_c_type(id);
        format!("[{id}] {:?} '{}' -> {c}", t.kind, t.name)
    }

    /// Expand a struct/union and emit all members with their C types and offsets.
    #[must_use]
    pub fn expand_struct(&self, id: u32) -> Vec<String> {
        let Some(t) = self.resolve(id) else { return vec![] };
        let (BtfTypeData::Struct { members, .. } | BtfTypeData::Union { members, .. }) = &t.data else {
            return vec![];
        };
        members.iter().map(|m| {
            let ty = self.to_c_type_inner(m.type_id, &m.name, 0);
            let off_bytes = m.bit_offset / 8;
            if m.bitfield_size > 0 {
                format!("  +{off_bytes:#06x}  {ty} : {}", m.bitfield_size)
            } else {
                format!("  +{off_bytes:#06x}  {ty};")
            }
        }).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_btf_int_section() -> Vec<u8> {
        // Minimal BTF section: header + one INT type (u32) + one string "u32\0".
        let mut data = Vec::new();
        // Header (24 bytes).
        data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        data.push(BTF_VERSION);
        data.push(0); // flags
        data.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        data.extend_from_slice(&0u32.to_le_bytes());  // type_off (relative to hdr_end)
        data.extend_from_slice(&16u32.to_le_bytes()); // type_len (12 common + 4 INT extra)
        data.extend_from_slice(&16u32.to_le_bytes()); // str_off
        data.extend_from_slice(&5u32.to_le_bytes());  // str_len ("u32\0\0")

        // Type record: name_off=1 (skip null at offset 0), info=(1 << 24) = INT, size=4.
        data.extend_from_slice(&1u32.to_le_bytes());        // name_off
        let info: u32 = (BtfKind::Int as u32) << 24;
        data.extend_from_slice(&info.to_le_bytes());        // info
        data.extend_from_slice(&4u32.to_le_bytes());        // size
        // INT extra: encoding=SIGNED|32bits, offset=0.
        let int_enc: u32 = (IntEncoding::SIGNED.bits() << 24) | 32u32;
        data.extend_from_slice(&int_enc.to_le_bytes());     // int extra

        // String section: "\0u32\0".
        data.push(0u8);
        data.extend_from_slice(b"u32\0");
        data.push(0); // pad

        data
    }

    #[test]
    fn parse_int_type() {
        let data = make_btf_int_section();
        let btf = BtfSection::parse(&data).expect("parse failed");
        assert_eq!(btf.types.len(), 1);
        let t = &btf.types[0];
        assert_eq!(t.kind, BtfKind::Int);
        assert_eq!(t.name, "u32");
    }

    #[test]
    fn bad_magic_error() {
        let mut data = make_btf_int_section();
        data[0] = 0xFF;
        let err = BtfSection::parse(&data).unwrap_err();
        assert!(matches!(err, BtfError::BadMagic(_)));
    }

    #[test]
    fn size_of_int() {
        let data = make_btf_int_section();
        let btf = BtfSection::parse(&data).unwrap();
        assert_eq!(btf.size_of(1), 4);
    }

    #[test]
    fn void_type() {
        let data = make_btf_int_section();
        let btf = BtfSection::parse(&data).unwrap();
        assert_eq!(btf.to_c_type(0), "void");
        assert_eq!(btf.size_of(0), 0);
    }

    #[test]
    fn get_type_oob_returns_none() {
        let data = make_btf_int_section();
        let btf = BtfSection::parse(&data).unwrap();
        assert!(btf.get_type(999).is_none());
    }
}
