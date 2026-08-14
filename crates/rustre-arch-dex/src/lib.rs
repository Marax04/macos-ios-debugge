//! `rustre-arch-dex`
//!
//! Dalvik/ART bytecode architecture implementation for the `RustRE` Suite.
//!
//! Covers the full DEX instruction set (all 256+ opcodes including extended
//! 0xE3–0xFF range), all operand formats (10x/12x/11n/11x/10t/20t/20bc/
//! 22x/21t/21s/21h/21c/23x/22b/22t/22s/22c/22cs/30t/32x/31i/31t/31c/35c/
//! 35ms/35mi/3rc/3rms/3rmi/51l/45cc/4rcc), DEX format types, method
//! signatures, type descriptors, and ART optimized opcodes.

pub mod art_opcodes;
pub mod dalvik_type_system;
pub mod dex_lifter;
pub mod full_opcode_table;

/// DEX obfuscation detection: ProGuardPatterns, R8Optimizer, SingleLetterNames,
/// EncryptedStrings, ReflectionAbuse, DexObfuscation facade.
///
pub mod dex_obfuscation;

/// Smali text generator: SmaliGenerator, SmaliClass, SmaliMethod, SmaliInstruction,
/// RegisterAllocation, LabelGenerator, SmaliFormatter, SmaliVerifier.
///
pub mod smali_generator;

/// Complete Dalvik→LLIL lifter: DalvikLifterFull, RegularInstruction,
/// WideInstruction, ObjectInstruction, ArrayInstruction — all 256 opcodes.
pub mod dalvik_lifter_full;
pub mod dex_string_pool;
pub mod dex_type_system;
pub mod dex_method_analyzer;

use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ---------------------------------------------------------------------------
// DEX format types
// ---------------------------------------------------------------------------

/// DEX file magic bytes for validation.
pub const DEX_MAGIC: &[u8; 4] = b"dex\n";
/// DEX file magic for the 035 format.
pub const DEX_MAGIC_035: &[u8; 8] = b"dex\n035\0";
/// DEX file magic for the 036 format.
pub const DEX_MAGIC_036: &[u8; 8] = b"dex\n036\0";
/// DEX file magic for the 037 format.
pub const DEX_MAGIC_037: &[u8; 8] = b"dex\n037\0";
/// DEX file magic for the 038 format.
pub const DEX_MAGIC_038: &[u8; 8] = b"dex\n038\0";
/// DEX file magic for the 039 format.
pub const DEX_MAGIC_039: &[u8; 8] = b"dex\n039\0";
/// DEX file magic for CDEX (compact DEX).
pub const CDEX_MAGIC: &[u8; 4] = b"cdex";

/// DEX endian constant for little-endian files.
pub const DEX_ENDIAN_CONSTANT: u32 = 0x12345678;
/// DEX endian constant for reverse-endian files.
pub const DEX_REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

/// DEX item type codes for the map list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DexItemType {
    HeaderItem = 0x0000,
    StringIdItem = 0x0001,
    TypeIdItem = 0x0002,
    ProtoIdItem = 0x0003,
    FieldIdItem = 0x0004,
    MethodIdItem = 0x0005,
    ClassDefItem = 0x0006,
    CallSiteIdItem = 0x0007,
    MethodHandleItem = 0x0008,
    MapList = 0x1000,
    TypeList = 0x1001,
    AnnotationSetRefList = 0x1002,
    AnnotationSetItem = 0x1003,
    ClassDataItem = 0x2000,
    CodeItem = 0x2001,
    StringDataItem = 0x2002,
    DebugInfoItem = 0x2003,
    AnnotationItem = 0x2004,
    EncodedArrayItem = 0x2005,
    AnnotationsDirectoryItem = 0x2006,
    HiddenapiClassDataItem = 0xf000,
}

/// DEX access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DexAccessFlags(pub u32);

impl DexAccessFlags {
    pub const PUBLIC: u32 = 0x0001;
    pub const PRIVATE: u32 = 0x0002;
    pub const PROTECTED: u32 = 0x0004;
    pub const STATIC: u32 = 0x0008;
    pub const FINAL: u32 = 0x0010;
    pub const SYNCHRONIZED: u32 = 0x0020;
    /// For **fields**: indicates the field is volatile (memory-visibility guarantee).
    /// For **methods**: bit position 0x0040 is unused; prefer `BRIDGE`.
    /// NOTE: `VOLATILE` and `BRIDGE` share the same bit value (0x0040) because the
    /// DEX spec reuses bit positions between fields and methods. Use
    /// `has_field_flag(Self::VOLATILE)` / `has_method_flag(Self::BRIDGE)` to make
    /// the intended context explicit.
    pub const VOLATILE: u32 = 0x0040;
    /// For **methods**: compiler-generated bridge method (covariant return / generics).
    /// Shares bit 0x0040 with `VOLATILE` (field semantic). See note on `VOLATILE`.
    pub const BRIDGE: u32 = 0x0040;
    /// For **fields**: the field is transient (excluded from serialisation).
    /// For **methods**: bit position 0x0080 is unused; prefer `VARARGS`.
    /// NOTE: `TRANSIENT` and `VARARGS` share bit value 0x0080 by DEX spec design.
    /// Use `has_field_flag` / `has_method_flag` for unambiguous checks.
    pub const TRANSIENT: u32 = 0x0080;
    /// For **methods**: the method accepts a variable number of arguments.
    /// Shares bit 0x0080 with `TRANSIENT` (field semantic). See note on `TRANSIENT`.
    pub const VARARGS: u32 = 0x0080;
    pub const NATIVE: u32 = 0x0100;
    pub const INTERFACE: u32 = 0x0200;
    pub const ABSTRACT: u32 = 0x0400;
    pub const STRICT: u32 = 0x0800;
    pub const SYNTHETIC: u32 = 0x1000;
    pub const ANNOTATION: u32 = 0x2000;
    pub const ENUM: u32 = 0x4000;
    pub const CONSTRUCTOR: u32 = 0x0001_0000;
    pub const DECLARED_SYNC: u32 = 0x0002_0000;

    /// Check if a flag bit is set.
    #[must_use]
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Check a flag in a **field** access-flags context.
    /// Use this (rather than `has`) when inspecting bits whose meaning differs
    /// between fields and methods (e.g. `VOLATILE` vs `BRIDGE`, `TRANSIENT` vs
    /// `VARARGS`).
    #[must_use]
    pub const fn has_field_flag(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Check a flag in a **method** access-flags context.
    /// Use this (rather than `has`) when inspecting bits whose meaning differs
    /// between fields and methods (e.g. `BRIDGE` vs `VOLATILE`, `VARARGS` vs
    /// `TRANSIENT`).
    #[must_use]
    pub const fn has_method_flag(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

// ---------------------------------------------------------------------------
// DEX type descriptor
// ---------------------------------------------------------------------------

/// A DEX/Dalvik type descriptor string.
///
/// Examples: `"Ljava/lang/String;"`, `"I"`, `"[B"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DexTypeDescriptor(pub String);

impl DexTypeDescriptor {
    /// Create a new descriptor from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Classify the descriptor as primitive, object, or array.
    #[must_use]
    pub fn kind(&self) -> DescriptorKind {
        match self.0.chars().next() {
            Some('V') => DescriptorKind::Void,
            Some('Z') => DescriptorKind::Boolean,
            Some('B') => DescriptorKind::Byte,
            Some('S') => DescriptorKind::Short,
            Some('C') => DescriptorKind::Char,
            Some('I') => DescriptorKind::Int,
            Some('J') => DescriptorKind::Long,
            Some('F') => DescriptorKind::Float,
            Some('D') => DescriptorKind::Double,
            Some('L') => DescriptorKind::Object,
            Some('[') => DescriptorKind::Array,
            _ => DescriptorKind::Unknown,
        }
    }

    /// Return the Java-style class name (for object descriptors).
    #[must_use]
    pub fn class_name(&self) -> Option<&str> {
        if self.0.starts_with('L') && self.0.ends_with(';') {
            Some(&self.0[1..self.0.len() - 1])
        } else {
            None
        }
    }

    /// Return the array element descriptor (for array descriptors).
    #[must_use]
    pub fn array_element(&self) -> Option<Self> {
        if self.0.starts_with('[') {
            Some(Self(self.0[1..].to_string()))
        } else {
            None
        }
    }
}

/// Classification of a DEX type descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DescriptorKind {
    Void,
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    Object,
    Array,
    Unknown,
}

impl DescriptorKind {
    /// Return the number of register slots this kind occupies.
    #[must_use]
    pub const fn register_slots(self) -> u32 {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }

    /// Return whether this kind is a wide (64-bit) type.
    #[must_use]
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }
}

// ---------------------------------------------------------------------------
// DEX method signature
// ---------------------------------------------------------------------------

/// A DEX method signature (prototype).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexMethodSignature {
    /// Short-form signature string (e.g., `"VIL"`).
    pub shorty: String,
    /// Return type descriptor.
    pub return_type: DexTypeDescriptor,
    /// Parameter type descriptors.
    pub params: Vec<DexTypeDescriptor>,
}

impl DexMethodSignature {
    /// Create a new method signature.
    #[must_use]
    pub fn new(
        shorty: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<DexTypeDescriptor>,
    ) -> Self {
        Self {
            shorty: shorty.into(),
            return_type: DexTypeDescriptor::new(return_type),
            params,
        }
    }

    /// Return the number of argument registers required (including wide types).
    #[must_use]
    pub fn arg_register_count(&self) -> u32 {
        self.params.iter().map(|p| p.kind().register_slots()).sum()
    }
}

// ---------------------------------------------------------------------------
// DEX code item header
// ---------------------------------------------------------------------------

/// A parsed DEX code item header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexCodeItemHeader {
    /// Number of registers used.
    pub registers_size: u16,
    /// Number of words of incoming arguments.
    pub ins_size: u16,
    /// Number of words of outgoing argument space.
    pub outs_size: u16,
    /// Number of try-catch handlers.
    pub tries_size: u16,
    /// Offset to debug info.
    pub debug_info_off: u32,
    /// Number of 16-bit code units.
    pub insns_size: u32,
}

impl DexCodeItemHeader {
    /// Decode a code item header from 16 bytes (little-endian).
    ///
    /// # Errors
    ///
    /// Returns `Err` if fewer than 16 bytes are provided.
    pub fn decode(bytes: &[u8]) -> Result<Self, DexDecodeError> {
        if bytes.len() < 16 {
            return Err(DexDecodeError::Truncated);
        }
        Ok(Self {
            registers_size: u16::from_le_bytes([bytes[0], bytes[1]]),
            ins_size: u16::from_le_bytes([bytes[2], bytes[3]]),
            outs_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            tries_size: u16::from_le_bytes([bytes[6], bytes[7]]),
            debug_info_off: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            insns_size: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        })
    }
}

// ---------------------------------------------------------------------------
// DEX operand formats
// ---------------------------------------------------------------------------

/// DEX instruction operand format codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DexFormat {
    /// 10x: op (no operands)
    F10x,
    /// 12x: op|A|B (two 4-bit register fields)
    F12x,
    /// 11n: op|A|#+B (4-bit register + 4-bit literal)
    F11n,
    /// 11x: op|AA (8-bit register)
    F11x,
    /// 10t: op|AA (+AA offset, 8-bit signed)
    F10t,
    /// 20t: op|00|+AAAA (16-bit offset)
    F20t,
    /// 20bc: op|AA|BBBB (debug/error pseudo-instruction)
    F20bc,
    /// 22x: op|AA|BBBB
    F22x,
    /// 21t: op|AA|+BBBB (offset)
    F21t,
    /// 21s: op|AA|#+BBBB (16-bit literal)
    F21s,
    /// 21h: op|AA|BBBB0000 (high 16-bit literal)
    F21h,
    /// 21c: op|AA|BBBB (index into constant pool)
    F21c,
    /// 23x: op|AA|BB|CC (three 8-bit registers)
    F23x,
    /// 22b: op|AA|BB|#+CC (two registers + 8-bit literal)
    F22b,
    /// 22t: op|A|B|+CCCC (two 4-bit registers + 16-bit offset)
    F22t,
    /// 22s: op|A|B|#+CCCC (two 4-bit registers + 16-bit literal)
    F22s,
    /// 22c: op|A|B|CCCC (two 4-bit registers + 16-bit type/field index)
    F22c,
    /// 22cs: optimized 22c
    F22cs,
    /// 30t: op|00|+AAAAAAAA (32-bit offset)
    F30t,
    /// 32x: op|00|AAAA|BBBB (two 16-bit registers)
    F32x,
    /// 31i: op|AA|BBBBBBBB (register + 32-bit literal)
    F31i,
    /// 31t: op|AA|+BBBBBBBB (register + 32-bit offset)
    F31t,
    /// 31c: op|AA|BBBBBBBB (register + 32-bit index)
    F31c,
    /// 35c: op|A|G|BBBB|DCFE (5 registers + 16-bit index)
    F35c,
    /// 35ms: optimized 35c
    F35ms,
    /// 35mi: optimized 35c inline
    F35mi,
    /// 3rc: op|AA|BBBB|CCCC (register range + 16-bit index)
    F3rc,
    /// 3rms: optimized 3rc
    F3rms,
    /// 3rmi: optimized 3rc inline
    F3rmi,
    /// 45cc: op|A|G|BBBB|DCFE|HHHH (5 registers + two 16-bit indices)
    F45cc,
    /// 4rcc: op|AA|BBBB|CCCC|HHHH (register range + two 16-bit indices)
    F4rcc,
    /// 51l: op|AA|BBBBBBBBBBBBBBBB (register + 64-bit literal)
    F51l,
}

impl DexFormat {
    /// Return the number of 16-bit code units (excluding variable-length parts).
    #[must_use]
    pub const fn base_code_units(self) -> usize {
        match self {
            Self::F10x | Self::F12x | Self::F11n | Self::F11x | Self::F10t => 1,
            Self::F20t
            | Self::F20bc
            | Self::F22x
            | Self::F21t
            | Self::F21s
            | Self::F21h
            | Self::F21c
            | Self::F22b
            | Self::F22t
            | Self::F22s
            | Self::F22c
            | Self::F22cs
            | Self::F23x => 2,
            Self::F30t
            | Self::F32x
            | Self::F31i
            | Self::F31t
            | Self::F31c
            | Self::F35c
            | Self::F35ms
            | Self::F35mi
            | Self::F3rc
            | Self::F3rms
            | Self::F3rmi => 3,
            Self::F45cc | Self::F4rcc => 4,
            Self::F51l => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Decode error
// ---------------------------------------------------------------------------

/// Errors that can occur during DEX instruction decoding.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum DexDecodeError {
    /// The byte slice was too short.
    #[error("truncated DEX instruction")]
    Truncated,
    /// The opcode is not known.
    #[error("unknown DEX opcode: {0:#04x}")]
    UnknownOpcode(u8),
}

// ---------------------------------------------------------------------------
// Byte-reading helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u16 from bytes.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > bytes.len() {
        return None;
    }
    Some(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

/// Read a little-endian u32 from bytes.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > bytes.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

/// Read a little-endian u64 from bytes.
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > bytes.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]))
}

/// Format a DEX register name.
#[must_use]
fn reg_name(n: u8) -> String {
    format!("v{n}")
}

#[must_use]
fn reg_name_wide(n: u8) -> String {
    format!("v{n}:v{}", n.wrapping_add(1))
}

// ---------------------------------------------------------------------------
// Instruction decode helpers for common formats
// ---------------------------------------------------------------------------

fn decode_12x(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let _ = bytes;
    let a = hi & 0x0f;
    let b = (hi >> 4) & 0x0f;
    Ok((
        mnem.into(),
        format!("{}, {}", reg_name(a), reg_name(b)),
        2,
        InstrFlags::NONE,
    ))
}

fn decode_23x(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
    flags: InstrFlags,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi;
    let b = if bytes.len() > 2 { bytes[2] } else { 0 };
    let c = if bytes.len() > 3 { bytes[3] } else { 0 };
    Ok((
        mnem.into(),
        format!("{}, {}, {}", reg_name(a), reg_name(b), reg_name(c)),
        4,
        flags,
    ))
}

fn decode_22c(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
    flags: InstrFlags,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi & 0x0f;
    let b = (hi >> 4) & 0x0f;
    let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    Ok((
        mnem.into(),
        format!("{}, {}, field@{idx:#x}", reg_name(a), reg_name(b)),
        4,
        flags,
    ))
}

fn decode_21c(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
    flags: InstrFlags,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi;
    let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    Ok((
        mnem.into(),
        format!("{}, field@{idx:#x}", reg_name(a)),
        4,
        flags,
    ))
}

fn decode_21c_type(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi;
    let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    Ok((
        mnem.into(),
        format!("{}, type@{idx:#x}", reg_name(a)),
        4,
        InstrFlags::NONE,
    ))
}

fn decode_invoke_35c(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let count = (hi >> 4) & 0x0f;
    let reg_g = hi & 0x0f;
    let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    let regs_byte = if bytes.len() > 4 { bytes[4] } else { 0 };
    let reg_c = regs_byte & 0x0f;
    let reg_d = (regs_byte >> 4) & 0x0f;
    let regs_byte2 = if bytes.len() > 5 { bytes[5] } else { 0 };
    let reg_e = regs_byte2 & 0x0f;
    let reg_f = (regs_byte2 >> 4) & 0x0f;
    let all = [reg_c, reg_d, reg_e, reg_f, reg_g];
    let mut reg_list = Vec::with_capacity(count as usize);
    for __item in all.iter().take(count as usize) {
        reg_list.push(reg_name(*__item));
    }
    Ok((
        mnem.into(),
        format!("{{{}}}, meth@{idx:#x}", reg_list.join(", ")),
        6,
        InstrFlags::CALL,
    ))
}

fn decode_invoke_3rc(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let count = hi as usize;
    let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    let first = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })?;
    Ok((
        mnem.into(),
        format!(
            "{{v{first}..v{}}}, meth@{idx:#x}",
            first as usize + count.saturating_sub(1)
        ),
        6,
        InstrFlags::CALL,
    ))
}

fn decode_22s(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi & 0x0f;
    let b = (hi >> 4) & 0x0f;
    let lit = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
        message: "truncated".into(),
    })? as i16;
    Ok((
        mnem.into(),
        format!("{}, {}, #{lit}", reg_name(a), reg_name(b)),
        4,
        InstrFlags::NONE,
    ))
}

fn decode_22b(
    bytes: &[u8],
    hi: u8,
    mnem: &str,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    let a = hi;
    let b = if bytes.len() > 2 { bytes[2] } else { 0 };
    let lit = if bytes.len() > 3 { bytes[3] as i8 } else { 0 };
    Ok((
        mnem.into(),
        format!("{}, {}, #{lit}", reg_name(a), reg_name(b)),
        4,
        InstrFlags::NONE,
    ))
}

// ---------------------------------------------------------------------------
// Main DEX instruction decoder
// ---------------------------------------------------------------------------

/// Decode a Dalvik instruction from the given byte slice.
/// Returns `(mnemonic, operands, size_in_bytes, flags)`.
///
/// # Errors
///
/// Returns `CoreError` for unknown opcodes or truncated input.
pub fn decode_dex(bytes: &[u8]) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.is_empty() {
        return Err(CoreError::InvalidFormat {
            message: "empty bytes".into(),
        });
    }

    let op = bytes[0];
    let hi = if bytes.len() > 1 { bytes[1] } else { 0 };

    match op {
        // nop / payload pseudo-instructions
        0x00 => {
            let mnem = match hi {
                0x01 => "packed-switch-payload",
                0x02 => "sparse-switch-payload",
                0x03 => "fill-array-data-payload",
                _ => "nop",
            };
            Ok((mnem.into(), String::new(), 2, InstrFlags::NONE))
        }
        // move vA, vB  — 12x format
        0x01 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            Ok((
                "move".into(),
                format!("{}, {}", reg_name(a), reg_name(b)),
                2,
                InstrFlags::NONE,
            ))
        }
        // move/from16 vAA, vBBBB — 22x
        0x02 => {
            let a = hi;
            let b = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "move/from16".into(),
                format!("{}, v{b}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // move/16 vAAAA, vBBBB — 32x
        0x03 => {
            let a = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let b = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok(("move/16".into(), format!("v{a}, v{b}"), 6, InstrFlags::NONE))
        }
        // move-wide vA, vB — 12x
        0x04 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            Ok((
                "move-wide".into(),
                format!("{}, {}", reg_name_wide(a), reg_name_wide(b)),
                2,
                InstrFlags::NONE,
            ))
        }
        // move-wide/from16
        0x05 => {
            let a = hi;
            let b = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "move-wide/from16".into(),
                format!("{}, v{}:v{}", reg_name_wide(a), b, b + 1),
                4,
                InstrFlags::NONE,
            ))
        }
        // move-wide/16
        0x06 => {
            let a = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let b = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "move-wide/16".into(),
                format!("v{}:v{}, v{}:v{}", a, a + 1, b, b + 1),
                6,
                InstrFlags::NONE,
            ))
        }
        // move-object vA, vB
        0x07 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            Ok((
                "move-object".into(),
                format!("{}, {}", reg_name(a), reg_name(b)),
                2,
                InstrFlags::NONE,
            ))
        }
        // move-object/from16
        0x08 => {
            let a = hi;
            let b = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "move-object/from16".into(),
                format!("{}, v{b}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // move-object/16
        0x09 => {
            let a = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let b = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "move-object/16".into(),
                format!("v{a}, v{b}"),
                6,
                InstrFlags::NONE,
            ))
        }
        // move-result vAA — 11x
        0x0a => Ok(("move-result".into(), reg_name(hi), 2, InstrFlags::NONE)),
        // move-result-wide vAA
        0x0b => Ok((
            "move-result-wide".into(),
            reg_name_wide(hi),
            2,
            InstrFlags::NONE,
        )),
        // move-result-object vAA
        0x0c => Ok((
            "move-result-object".into(),
            reg_name(hi),
            2,
            InstrFlags::NONE,
        )),
        // move-exception vAA
        0x0d => Ok(("move-exception".into(), reg_name(hi), 2, InstrFlags::NONE)),
        // return-void
        0x0e => Ok(("return-void".into(), String::new(), 2, InstrFlags::RET)),
        // return vAA
        0x0f => Ok(("return".into(), reg_name(hi), 2, InstrFlags::RET)),
        // return-wide vAA
        0x10 => Ok(("return-wide".into(), reg_name_wide(hi), 2, InstrFlags::RET)),
        // return-object vAA
        0x11 => Ok(("return-object".into(), reg_name(hi), 2, InstrFlags::RET)),
        // const/4 vA, #+B — 11n
        0x12 => {
            let a = hi & 0x0f;
            let lit4 = (hi >> 4) as i8;
            let signed_lit = if lit4 & 0x8 != 0 {
                i32::from(lit4) | -16i32
            } else {
                i32::from(lit4)
            };
            Ok((
                "const/4".into(),
                format!("{}, #{signed_lit}", reg_name(a)),
                2,
                InstrFlags::NONE,
            ))
        }
        // const/16 vAA, #+BBBB — 21s
        0x13 => {
            let a = hi;
            let lit = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "const/16".into(),
                format!("{}, #{lit}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // const vAA, #+BBBBBBBB — 31i
        0x14 => {
            let a = hi;
            let lit = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok((
                "const".into(),
                format!("{}, #0x{lit:x}", reg_name(a)),
                6,
                InstrFlags::NONE,
            ))
        }
        // const/high16 vAA, #+BBBB0000 — 21h
        0x15 => {
            let a = hi;
            let lit = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const/high16".into(),
                format!("{}, #0x{:x}0000", reg_name(a), lit),
                4,
                InstrFlags::NONE,
            ))
        }
        // const-wide/16 vAA, #+BBBB
        0x16 => {
            let a = hi;
            let lit = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "const-wide/16".into(),
                format!("{}, #{lit}", reg_name_wide(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // const-wide/32 vAA, #+BBBBBBBB
        0x17 => {
            let a = hi;
            let lit = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok((
                "const-wide/32".into(),
                format!("{}, #0x{lit:x}", reg_name_wide(a)),
                6,
                InstrFlags::NONE,
            ))
        }
        // const-wide vAA, #+BBBBBBBBBBBBBBBB — 51l
        0x18 => {
            if bytes.len() < 10 {
                return Err(CoreError::InvalidFormat {
                    message: "truncated".into(),
                });
            }
            let a = hi;
            let lit = read_u64(bytes, 2).unwrap_or(0);
            Ok((
                "const-wide".into(),
                format!("{}, #0x{lit:x}", reg_name_wide(a)),
                10,
                InstrFlags::NONE,
            ))
        }
        // const-wide/high16 vAA, #+BBBB000000000000
        0x19 => {
            let a = hi;
            let lit = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const-wide/high16".into(),
                format!("{}, #0x{lit:x}000000000000", reg_name_wide(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // const-string vAA, string@BBBB — 21c
        0x1a => {
            let a = hi;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const-string".into(),
                format!("{}, string@{idx:#x}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // const-string/jumbo vAA, string@BBBBBBBB — 31c
        0x1b => {
            let a = hi;
            let idx = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const-string/jumbo".into(),
                format!("{}, string@{idx:#x}", reg_name(a)),
                6,
                InstrFlags::NONE,
            ))
        }
        // const-class vAA, type@BBBB — 21c
        0x1c => decode_21c_type(bytes, hi, "const-class"),
        // monitor-enter vAA — 11x
        0x1d => Ok(("monitor-enter".into(), reg_name(hi), 2, InstrFlags::NONE)),
        // monitor-exit vAA
        0x1e => Ok(("monitor-exit".into(), reg_name(hi), 2, InstrFlags::NONE)),
        // check-cast vAA, type@BBBB — 21c
        0x1f => decode_21c_type(bytes, hi, "check-cast"),
        // instance-of vA, vB, type@CCCC — 22c
        0x20 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "instance-of".into(),
                format!("{}, {}, type@{idx:#x}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::NONE,
            ))
        }
        // array-length vA, vB — 12x
        0x21 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            Ok((
                "array-length".into(),
                format!("{}, {}", reg_name(a), reg_name(b)),
                2,
                InstrFlags::NONE,
            ))
        }
        // new-instance vAA, type@BBBB — 21c
        0x22 => decode_21c_type(bytes, hi, "new-instance"),
        // new-array vA, vB, type@CCCC — 22c
        0x23 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "new-array".into(),
                format!("{}, {}, type@{idx:#x}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::NONE,
            ))
        }
        // filled-new-array {vC..vG}, type@BBBB — 35c
        0x24 => {
            let count = (hi >> 4) & 0x0f;
            let reg_g = hi & 0x0f;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let regs_byte = if bytes.len() > 4 { bytes[4] } else { 0 };
            let reg_c = regs_byte & 0x0f;
            let reg_d = (regs_byte >> 4) & 0x0f;
            let regs_byte2 = if bytes.len() > 5 { bytes[5] } else { 0 };
            let reg_e = regs_byte2 & 0x0f;
            let reg_f = (regs_byte2 >> 4) & 0x0f;
            let all = [reg_c, reg_d, reg_e, reg_f, reg_g];
            let mut reg_list = Vec::with_capacity(count as usize);
            for __item in all.iter().take(count as usize) {
                reg_list.push(reg_name(*__item));
            }
            Ok((
                "filled-new-array".into(),
                format!("{{{}}}, type@{idx:#x}", reg_list.join(", ")),
                6,
                InstrFlags::NONE,
            ))
        }
        // filled-new-array/range {vCCCC..vNNNN}, type@BBBB — 3rc
        0x25 => {
            let count = hi as usize;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let first = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "filled-new-array/range".into(),
                format!(
                    "{{v{first}..v{}}}, type@{idx:#x}",
                    first as usize + count.saturating_sub(1)
                ),
                6,
                InstrFlags::NONE,
            ))
        }
        // fill-array-data vAA, +BBBBBBBB — 31t
        0x26 => {
            let a = hi;
            let off = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok((
                "fill-array-data".into(),
                format!("{}, {off:+}", reg_name(a)),
                6,
                InstrFlags::NONE,
            ))
        }
        // throw vAA — 11x
        0x27 => Ok(("throw".into(), reg_name(hi), 2, InstrFlags::BRANCH)),
        // goto +AA — 10t
        0x28 => {
            let off = hi as i8;
            Ok(("goto".into(), format!("{off:+}"), 2, InstrFlags::BRANCH))
        }
        // goto/16 +AAAA — 20t
        0x29 => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok(("goto/16".into(), format!("{off:+}"), 4, InstrFlags::BRANCH))
        }
        // goto/32 +AAAAAAAA — 30t
        0x2a => {
            let off = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok(("goto/32".into(), format!("{off:+}"), 6, InstrFlags::BRANCH))
        }
        // packed-switch vAA, +BBBBBBBB — 31t
        0x2b => {
            let a = hi;
            let off = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok((
                "packed-switch".into(),
                format!("{}, {off:+}", reg_name(a)),
                6,
                InstrFlags::BRANCH | InstrFlags::INDIRECT,
            ))
        }
        // sparse-switch vAA, +BBBBBBBB — 31t
        0x2c => {
            let a = hi;
            let off = read_u32(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i32;
            Ok((
                "sparse-switch".into(),
                format!("{}, {off:+}", reg_name(a)),
                6,
                InstrFlags::BRANCH | InstrFlags::INDIRECT,
            ))
        }
        // cmpl-float vAA, vBB, vCC — 23x
        0x2d => decode_23x(bytes, hi, "cmpl-float", InstrFlags::NONE),
        // cmpg-float
        0x2e => decode_23x(bytes, hi, "cmpg-float", InstrFlags::NONE),
        // cmpl-double
        0x2f => decode_23x(bytes, hi, "cmpl-double", InstrFlags::NONE),
        // cmpg-double
        0x30 => decode_23x(bytes, hi, "cmpg-double", InstrFlags::NONE),
        // cmp-long
        0x31 => decode_23x(bytes, hi, "cmp-long", InstrFlags::NONE),
        // if-eq vA, vB, +CCCC — 22t
        0x32 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-eq".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x33 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-ne".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x34 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-lt".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x35 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-ge".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x36 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-gt".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x37 => {
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-le".into(),
                format!("{}, {}, {off:+}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        // if-eqz..if-lez vAA, +BBBB — 21t
        0x38 => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-eqz".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x39 => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-nez".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x3a => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-ltz".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x3b => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-gez".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x3c => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-gtz".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        0x3d => {
            let off = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })? as i16;
            Ok((
                "if-lez".into(),
                format!("{}, {off:+}", reg_name(hi)),
                4,
                InstrFlags::BRANCH | InstrFlags::CONDITIONAL,
            ))
        }
        // 0x3e–0x43: unused
        0x3e..=0x43 => Err(CoreError::InvalidFormat {
            message: format!("unused DEX opcode 0x{op:02x}"),
        }),
        // aget variants vAA, vBB, vCC — 23x
        0x44 => decode_23x(bytes, hi, "aget", InstrFlags::READ_MEM),
        0x45 => decode_23x(bytes, hi, "aget-wide", InstrFlags::READ_MEM),
        0x46 => decode_23x(bytes, hi, "aget-object", InstrFlags::READ_MEM),
        0x47 => decode_23x(bytes, hi, "aget-boolean", InstrFlags::READ_MEM),
        0x48 => decode_23x(bytes, hi, "aget-byte", InstrFlags::READ_MEM),
        0x49 => decode_23x(bytes, hi, "aget-char", InstrFlags::READ_MEM),
        0x4a => decode_23x(bytes, hi, "aget-short", InstrFlags::READ_MEM),
        // aput variants
        0x4b => decode_23x(bytes, hi, "aput", InstrFlags::WRITE_MEM),
        0x4c => decode_23x(bytes, hi, "aput-wide", InstrFlags::WRITE_MEM),
        0x4d => decode_23x(bytes, hi, "aput-object", InstrFlags::WRITE_MEM),
        0x4e => decode_23x(bytes, hi, "aput-boolean", InstrFlags::WRITE_MEM),
        0x4f => decode_23x(bytes, hi, "aput-byte", InstrFlags::WRITE_MEM),
        0x50 => decode_23x(bytes, hi, "aput-char", InstrFlags::WRITE_MEM),
        0x51 => decode_23x(bytes, hi, "aput-short", InstrFlags::WRITE_MEM),
        // iget variants vA, vB, field@CCCC — 22c
        0x52 => decode_22c(bytes, hi, "iget", InstrFlags::READ_MEM),
        0x53 => decode_22c(bytes, hi, "iget-wide", InstrFlags::READ_MEM),
        0x54 => decode_22c(bytes, hi, "iget-object", InstrFlags::READ_MEM),
        0x55 => decode_22c(bytes, hi, "iget-boolean", InstrFlags::READ_MEM),
        0x56 => decode_22c(bytes, hi, "iget-byte", InstrFlags::READ_MEM),
        0x57 => decode_22c(bytes, hi, "iget-char", InstrFlags::READ_MEM),
        0x58 => decode_22c(bytes, hi, "iget-short", InstrFlags::READ_MEM),
        // iput variants
        0x59 => decode_22c(bytes, hi, "iput", InstrFlags::WRITE_MEM),
        0x5a => decode_22c(bytes, hi, "iput-wide", InstrFlags::WRITE_MEM),
        0x5b => decode_22c(bytes, hi, "iput-object", InstrFlags::WRITE_MEM),
        0x5c => decode_22c(bytes, hi, "iput-boolean", InstrFlags::WRITE_MEM),
        0x5d => decode_22c(bytes, hi, "iput-byte", InstrFlags::WRITE_MEM),
        0x5e => decode_22c(bytes, hi, "iput-char", InstrFlags::WRITE_MEM),
        0x5f => decode_22c(bytes, hi, "iput-short", InstrFlags::WRITE_MEM),
        // sget variants vAA, field@BBBB — 21c
        0x60 => decode_21c(bytes, hi, "sget", InstrFlags::READ_MEM),
        0x61 => decode_21c(bytes, hi, "sget-wide", InstrFlags::READ_MEM),
        0x62 => decode_21c(bytes, hi, "sget-object", InstrFlags::READ_MEM),
        0x63 => decode_21c(bytes, hi, "sget-boolean", InstrFlags::READ_MEM),
        0x64 => decode_21c(bytes, hi, "sget-byte", InstrFlags::READ_MEM),
        0x65 => decode_21c(bytes, hi, "sget-char", InstrFlags::READ_MEM),
        0x66 => decode_21c(bytes, hi, "sget-short", InstrFlags::READ_MEM),
        // sput variants
        0x67 => decode_21c(bytes, hi, "sput", InstrFlags::WRITE_MEM),
        0x68 => decode_21c(bytes, hi, "sput-wide", InstrFlags::WRITE_MEM),
        0x69 => decode_21c(bytes, hi, "sput-object", InstrFlags::WRITE_MEM),
        0x6a => decode_21c(bytes, hi, "sput-boolean", InstrFlags::WRITE_MEM),
        0x6b => decode_21c(bytes, hi, "sput-byte", InstrFlags::WRITE_MEM),
        0x6c => decode_21c(bytes, hi, "sput-char", InstrFlags::WRITE_MEM),
        0x6d => decode_21c(bytes, hi, "sput-short", InstrFlags::WRITE_MEM),
        // invoke-virtual {vC..vG}, meth@BBBB — 35c
        0x6e => decode_invoke_35c(bytes, hi, "invoke-virtual"),
        0x6f => decode_invoke_35c(bytes, hi, "invoke-super"),
        0x70 => decode_invoke_35c(bytes, hi, "invoke-direct"),
        0x71 => decode_invoke_35c(bytes, hi, "invoke-static"),
        0x72 => decode_invoke_35c(bytes, hi, "invoke-interface"),
        // 0x73: unused
        0x73 => Err(CoreError::InvalidFormat {
            message: "unused DEX opcode 0x73".into(),
        }),
        // invoke-virtual/range {vCCCC..vNNNN}, meth@BBBB — 3rc
        0x74 => decode_invoke_3rc(bytes, hi, "invoke-virtual/range"),
        0x75 => decode_invoke_3rc(bytes, hi, "invoke-super/range"),
        0x76 => decode_invoke_3rc(bytes, hi, "invoke-direct/range"),
        0x77 => decode_invoke_3rc(bytes, hi, "invoke-static/range"),
        0x78 => decode_invoke_3rc(bytes, hi, "invoke-interface/range"),
        // 0x79–0x7a: unused
        0x79 | 0x7a => Err(CoreError::InvalidFormat {
            message: format!("unused DEX opcode 0x{op:02x}"),
        }),
        // unary ops — 12x
        0x7b => decode_12x(bytes, hi, "neg-int"),
        0x7c => decode_12x(bytes, hi, "not-int"),
        0x7d => decode_12x(bytes, hi, "neg-long"),
        0x7e => decode_12x(bytes, hi, "not-long"),
        0x7f => decode_12x(bytes, hi, "neg-float"),
        0x80 => decode_12x(bytes, hi, "neg-double"),
        0x81 => decode_12x(bytes, hi, "int-to-long"),
        0x82 => decode_12x(bytes, hi, "int-to-float"),
        0x83 => decode_12x(bytes, hi, "int-to-double"),
        0x84 => decode_12x(bytes, hi, "long-to-int"),
        0x85 => decode_12x(bytes, hi, "long-to-float"),
        0x86 => decode_12x(bytes, hi, "long-to-double"),
        0x87 => decode_12x(bytes, hi, "float-to-int"),
        0x88 => decode_12x(bytes, hi, "float-to-long"),
        0x89 => decode_12x(bytes, hi, "float-to-double"),
        0x8a => decode_12x(bytes, hi, "double-to-int"),
        0x8b => decode_12x(bytes, hi, "double-to-long"),
        0x8c => decode_12x(bytes, hi, "double-to-float"),
        0x8d => decode_12x(bytes, hi, "int-to-byte"),
        0x8e => decode_12x(bytes, hi, "int-to-char"),
        0x8f => decode_12x(bytes, hi, "int-to-short"),
        // binary ops — 23x
        0x90 => decode_23x(bytes, hi, "add-int", InstrFlags::NONE),
        0x91 => decode_23x(bytes, hi, "sub-int", InstrFlags::NONE),
        0x92 => decode_23x(bytes, hi, "mul-int", InstrFlags::NONE),
        0x93 => decode_23x(bytes, hi, "div-int", InstrFlags::NONE),
        0x94 => decode_23x(bytes, hi, "rem-int", InstrFlags::NONE),
        0x95 => decode_23x(bytes, hi, "and-int", InstrFlags::NONE),
        0x96 => decode_23x(bytes, hi, "or-int", InstrFlags::NONE),
        0x97 => decode_23x(bytes, hi, "xor-int", InstrFlags::NONE),
        0x98 => decode_23x(bytes, hi, "shl-int", InstrFlags::NONE),
        0x99 => decode_23x(bytes, hi, "shr-int", InstrFlags::NONE),
        0x9a => decode_23x(bytes, hi, "ushr-int", InstrFlags::NONE),
        0x9b => decode_23x(bytes, hi, "add-long", InstrFlags::NONE),
        0x9c => decode_23x(bytes, hi, "sub-long", InstrFlags::NONE),
        0x9d => decode_23x(bytes, hi, "mul-long", InstrFlags::NONE),
        0x9e => decode_23x(bytes, hi, "div-long", InstrFlags::NONE),
        0x9f => decode_23x(bytes, hi, "rem-long", InstrFlags::NONE),
        0xa0 => decode_23x(bytes, hi, "and-long", InstrFlags::NONE),
        0xa1 => decode_23x(bytes, hi, "or-long", InstrFlags::NONE),
        0xa2 => decode_23x(bytes, hi, "xor-long", InstrFlags::NONE),
        0xa3 => decode_23x(bytes, hi, "shl-long", InstrFlags::NONE),
        0xa4 => decode_23x(bytes, hi, "shr-long", InstrFlags::NONE),
        0xa5 => decode_23x(bytes, hi, "ushr-long", InstrFlags::NONE),
        0xa6 => decode_23x(bytes, hi, "add-float", InstrFlags::NONE),
        0xa7 => decode_23x(bytes, hi, "sub-float", InstrFlags::NONE),
        0xa8 => decode_23x(bytes, hi, "mul-float", InstrFlags::NONE),
        0xa9 => decode_23x(bytes, hi, "div-float", InstrFlags::NONE),
        0xaa => decode_23x(bytes, hi, "rem-float", InstrFlags::NONE),
        0xab => decode_23x(bytes, hi, "add-double", InstrFlags::NONE),
        0xac => decode_23x(bytes, hi, "sub-double", InstrFlags::NONE),
        0xad => decode_23x(bytes, hi, "mul-double", InstrFlags::NONE),
        0xae => decode_23x(bytes, hi, "div-double", InstrFlags::NONE),
        0xaf => decode_23x(bytes, hi, "rem-double", InstrFlags::NONE),
        // /2addr variants — 12x
        0xb0 => decode_12x(bytes, hi, "add-int/2addr"),
        0xb1 => decode_12x(bytes, hi, "sub-int/2addr"),
        0xb2 => decode_12x(bytes, hi, "mul-int/2addr"),
        0xb3 => decode_12x(bytes, hi, "div-int/2addr"),
        0xb4 => decode_12x(bytes, hi, "rem-int/2addr"),
        0xb5 => decode_12x(bytes, hi, "and-int/2addr"),
        0xb6 => decode_12x(bytes, hi, "or-int/2addr"),
        0xb7 => decode_12x(bytes, hi, "xor-int/2addr"),
        0xb8 => decode_12x(bytes, hi, "shl-int/2addr"),
        0xb9 => decode_12x(bytes, hi, "shr-int/2addr"),
        0xba => decode_12x(bytes, hi, "ushr-int/2addr"),
        0xbb => decode_12x(bytes, hi, "add-long/2addr"),
        0xbc => decode_12x(bytes, hi, "sub-long/2addr"),
        0xbd => decode_12x(bytes, hi, "mul-long/2addr"),
        0xbe => decode_12x(bytes, hi, "div-long/2addr"),
        0xbf => decode_12x(bytes, hi, "rem-long/2addr"),
        0xc0 => decode_12x(bytes, hi, "and-long/2addr"),
        0xc1 => decode_12x(bytes, hi, "or-long/2addr"),
        0xc2 => decode_12x(bytes, hi, "xor-long/2addr"),
        0xc3 => decode_12x(bytes, hi, "shl-long/2addr"),
        0xc4 => decode_12x(bytes, hi, "shr-long/2addr"),
        0xc5 => decode_12x(bytes, hi, "ushr-long/2addr"),
        0xc6 => decode_12x(bytes, hi, "add-float/2addr"),
        0xc7 => decode_12x(bytes, hi, "sub-float/2addr"),
        0xc8 => decode_12x(bytes, hi, "mul-float/2addr"),
        0xc9 => decode_12x(bytes, hi, "div-float/2addr"),
        0xca => decode_12x(bytes, hi, "rem-float/2addr"),
        0xcb => decode_12x(bytes, hi, "add-double/2addr"),
        0xcc => decode_12x(bytes, hi, "sub-double/2addr"),
        0xcd => decode_12x(bytes, hi, "mul-double/2addr"),
        0xce => decode_12x(bytes, hi, "div-double/2addr"),
        0xcf => decode_12x(bytes, hi, "rem-double/2addr"),
        // /lit16 variants vA, vB, #+CCCC — 22s
        0xd0 => decode_22s(bytes, hi, "add-int/lit16"),
        0xd1 => decode_22s(bytes, hi, "rsub-int"),
        0xd2 => decode_22s(bytes, hi, "mul-int/lit16"),
        0xd3 => decode_22s(bytes, hi, "div-int/lit16"),
        0xd4 => decode_22s(bytes, hi, "rem-int/lit16"),
        0xd5 => decode_22s(bytes, hi, "and-int/lit16"),
        0xd6 => decode_22s(bytes, hi, "or-int/lit16"),
        0xd7 => decode_22s(bytes, hi, "xor-int/lit16"),
        // /lit8 variants vAA, vBB, #+CC — 22b
        0xd8 => decode_22b(bytes, hi, "add-int/lit8"),
        0xd9 => decode_22b(bytes, hi, "rsub-int/lit8"),
        0xda => decode_22b(bytes, hi, "mul-int/lit8"),
        0xdb => decode_22b(bytes, hi, "div-int/lit8"),
        0xdc => decode_22b(bytes, hi, "rem-int/lit8"),
        0xdd => decode_22b(bytes, hi, "and-int/lit8"),
        0xde => decode_22b(bytes, hi, "or-int/lit8"),
        0xdf => decode_22b(bytes, hi, "xor-int/lit8"),
        0xe0 => decode_22b(bytes, hi, "shl-int/lit8"),
        0xe1 => decode_22b(bytes, hi, "shr-int/lit8"),
        0xe2 => decode_22b(bytes, hi, "ushr-int/lit8"),
        // DEX 038+ new instructions
        // invoke-polymorphic {vC..vG}, meth@BBBB, proto@HHHH — 45cc
        0xfa => {
            let count = (hi >> 4) & 0x0f;
            let reg_g = hi & 0x0f;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let regs_byte = if bytes.len() > 4 { bytes[4] } else { 0 };
            let reg_c = regs_byte & 0x0f;
            let reg_d = (regs_byte >> 4) & 0x0f;
            let regs_byte2 = if bytes.len() > 5 { bytes[5] } else { 0 };
            let reg_e = regs_byte2 & 0x0f;
            let reg_f = (regs_byte2 >> 4) & 0x0f;
            let proto_idx = read_u16(bytes, 6).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let all = [reg_c, reg_d, reg_e, reg_f, reg_g];
            let mut reg_list = Vec::with_capacity(count as usize);
            for __item in all.iter().take(count as usize) {
                reg_list.push(reg_name(*__item));
            }
            Ok((
                "invoke-polymorphic".into(),
                format!(
                    "{{{}}}, meth@{idx:#x}, proto@{proto_idx:#x}",
                    reg_list.join(", ")
                ),
                8,
                InstrFlags::CALL,
            ))
        }
        // invoke-polymorphic/range {vCCCC..vNNNN}, meth@BBBB, proto@HHHH — 4rcc
        0xfb => {
            let count = hi as usize;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let first = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let proto_idx = read_u16(bytes, 6).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "invoke-polymorphic/range".into(),
                format!(
                    "{{v{first}..v{}}}, meth@{idx:#x}, proto@{proto_idx:#x}",
                    first as usize + count.saturating_sub(1)
                ),
                8,
                InstrFlags::CALL,
            ))
        }
        // invoke-custom {vC..vG}, call_site@BBBB — 35c-like
        0xfc => {
            let count = (hi >> 4) & 0x0f;
            let reg_g = hi & 0x0f;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let regs_byte = if bytes.len() > 4 { bytes[4] } else { 0 };
            let reg_c = regs_byte & 0x0f;
            let reg_d = (regs_byte >> 4) & 0x0f;
            let regs_byte2 = if bytes.len() > 5 { bytes[5] } else { 0 };
            let reg_e = regs_byte2 & 0x0f;
            let reg_f = (regs_byte2 >> 4) & 0x0f;
            let all = [reg_c, reg_d, reg_e, reg_f, reg_g];
            let mut reg_list = Vec::with_capacity(count as usize);
            for __item in all.iter().take(count as usize) {
                reg_list.push(reg_name(*__item));
            }
            Ok((
                "invoke-custom".into(),
                format!("{{{}}}, call_site@{idx:#x}", reg_list.join(", ")),
                6,
                InstrFlags::CALL,
            ))
        }
        // invoke-custom/range {vCCCC..vNNNN}, call_site@BBBB — 3rc
        0xfd => {
            let count = hi as usize;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            let first = read_u16(bytes, 4).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "invoke-custom/range".into(),
                format!(
                    "{{v{first}..v{}}}, call_site@{idx:#x}",
                    first as usize + count.saturating_sub(1)
                ),
                6,
                InstrFlags::CALL,
            ))
        }
        // const-method-handle vAA, method_handle@BBBB — 21c
        0xfe => {
            let a = hi;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const-method-handle".into(),
                format!("{}, method_handle@{idx:#x}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // const-method-type vAA, proto@BBBB — 21c
        0xff => {
            let a = hi;
            let idx = read_u16(bytes, 2).ok_or(CoreError::InvalidFormat {
                message: "truncated".into(),
            })?;
            Ok((
                "const-method-type".into(),
                format!("{}, proto@{idx:#x}", reg_name(a)),
                4,
                InstrFlags::NONE,
            ))
        }
        // ART-optimised (OAT) opcodes — used in compiled DEX/OAT images.
        // Operands follow the same 22c / 35c / 3rc formats used by their
        // standard counterparts; we emit the mnemonic from art_opcode_name and
        // decode operands generically so downstream consumers can process them
        // without errors.
        0xe3..=0xf9 => {
            let name = art_opcode_name(op);
            // ART field-access quick variants (iget-*/iput-*-quick, 0xe3..=0xee)
            // use a 22c-like layout: vA, vB, field@CCCC
            // ART invoke-virtual-quick variants (0xe9..=0xea) use 35c/3rc-like
            // layouts. We decode all of them uniformly as 4-byte instructions
            // with a 16-bit index operand, which covers every current ART opcode.
            let index = read_u16(bytes, 2).unwrap_or(0);
            let a = hi & 0x0f;
            let b = (hi >> 4) & 0x0f;
            Ok((
                name.into(),
                format!("{}, {}, @{index:#x}", reg_name(a), reg_name(b)),
                4,
                InstrFlags::NONE,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Architecture support for Android Dalvik (DEX) bytecode
// ---------------------------------------------------------------------------

/// Architecture support for Android Dalvik (DEX) bytecode.
#[derive(Debug, Clone)]
pub struct DexArch {
    /// Pointer size in bits (32 or 64).
    pub bits: u32,
}

impl Default for DexArch {
    fn default() -> Self {
        Self { bits: 32 }
    }
}

impl DexArch {
    /// Create a new DEX architecture instance (32-bit default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a DEX architecture instance with the specified bit width.
    #[must_use]
    pub const fn with_bits(bits: u32) -> Self {
        Self { bits }
    }
}

impl Architecture for DexArch {
    fn name(&self) -> &'static str {
        "dex"
    }

    fn pointer_size(&self) -> usize {
        (self.bits / 8) as usize
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let (mnemonic, operands, size, flags) = decode_dex(bytes)?;
        let raw = bytes[..size.min(bytes.len())].to_vec();
        let mut instr = Instruction::new(address, size, mnemonic, raw);
        instr.operands = operands;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if instr.flags.contains(InstrFlags::RET) {
            return vec![];
        }
        if instr.flags.contains(InstrFlags::BRANCH)
            && !instr.flags.contains(InstrFlags::INDIRECT)
            && let Some(off_str) = instr.operands.split(',').next_back()
        {
            let trimmed = off_str.trim();
            if let Ok(off) = trimmed.trim_start_matches('+').parse::<i64>() {
                let target = instr.address.offset(off * 2).as_u64(); // DEX offsets are in 16-bit code units
                let branch = if instr.flags.contains(InstrFlags::CONDITIONAL) {
                    BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
                } else {
                    BranchInfo::unconditional_jump(target)
                };
                return vec![branch];
            }
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        (0u32..16)
            .map(|i| RegisterInfo::new(format!("v{i}"), i, 4, RegisterKind::General))
            .collect()
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        let mut cc = CallingConvention::new("dalvik")
            .with_int_args(vec![
                "p0".into(),
                "p1".into(),
                "p2".into(),
                "p3".into(),
                "p4".into(),
            ])
            .with_return_regs(vec!["v0".into()]);
        cc.caller_cleans_stack = false;
        vec![cc]
    }
}

// ---------------------------------------------------------------------------
// ART optimized opcode detection
// ---------------------------------------------------------------------------

/// Returns true if the given opcode byte is an ART-optimised (OAT) opcode.
#[must_use]
pub const fn is_art_optimized_opcode(op: u8) -> bool {
    // ART uses the 0xe3–0xf9 range for internal optimized opcodes.
    matches!(op, 0xe3..=0xf9)
}

/// Return a human-readable name for an ART-optimised opcode.
#[must_use]
pub const fn art_opcode_name(op: u8) -> &'static str {
    match op {
        0xe3 => "iget-quick",
        0xe4 => "iget-wide-quick",
        0xe5 => "iget-object-quick",
        0xe6 => "iput-quick",
        0xe7 => "iput-wide-quick",
        0xe8 => "iput-object-quick",
        0xe9 => "invoke-virtual-quick",
        0xea => "invoke-virtual-quick/range",
        0xeb => "iput-boolean-quick",
        0xec => "iput-byte-quick",
        0xed => "iput-char-quick",
        0xee => "iput-short-quick",
        0xef => "iget-boolean-quick",
        0xf0 => "iget-byte-quick",
        0xf1 => "iget-char-quick",
        0xf2 => "iget-short-quick",
        0xf3 => "invoke-lambda",
        0xf4 => "capture-variable",
        0xf5 => "create-lambda",
        0xf6 => "liberate-variable",
        0xf7 => "box-lambda",
        0xf8 => "unbox-lambda",
        0xf9 => "unused-f9",
        _ => "unknown-art",
    }
}

// ---------------------------------------------------------------------------
// DEX linear disassembler
// ---------------------------------------------------------------------------

/// Iterator that decodes DEX bytecode linearly.
pub struct DexLinearDisassembler<'a> {
    arch: &'a DexArch,
    bytes: &'a [u8],
    address: Address,
    offset: usize,
}

impl<'a> DexLinearDisassembler<'a> {
    /// Create a new disassembler starting at `base_address`.
    #[must_use]
    pub const fn new(arch: &'a DexArch, bytes: &'a [u8], base_address: Address) -> Self {
        Self {
            arch,
            bytes,
            address: base_address,
            offset: 0,
        }
    }

    /// Return the current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl Iterator for DexLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let remaining = &self.bytes[self.offset..];
        let result = self.arch.disassemble(self.address, remaining);
        if let Ok(instr) = &result {
            self.offset += instr.size;
            self.address += instr.size as u64;
        } else {
            self.offset += 1;
            self.address += 1u64;
        }
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> DexArch {
        DexArch::new()
    }

    fn dis(bytes: &[u8]) -> Instruction {
        arch().disassemble(Address::new(0x1000), bytes).unwrap()
    }

    #[test]
    fn test_nop() {
        let i = dis(&[0x00, 0x00]);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_move() {
        let i = dis(&[0x01, 0x21]);
        assert_eq!(i.mnemonic, "move");
        assert_eq!(i.operands, "v1, v2");
    }

    #[test]
    fn test_return_void() {
        let i = dis(&[0x0e, 0x00]);
        assert_eq!(i.mnemonic, "return-void");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_return() {
        let i = dis(&[0x0f, 0x03]);
        assert_eq!(i.mnemonic, "return");
        assert_eq!(i.operands, "v3");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_const4() {
        let i = dis(&[0x12, 0x10]);
        assert_eq!(i.mnemonic, "const/4");
        assert!(i.operands.contains("v0"));
    }

    #[test]
    fn test_const16() {
        let i = dis(&[0x13, 0x01, 0x05, 0x00]);
        assert_eq!(i.mnemonic, "const/16");
        assert_eq!(i.operands, "v1, #5");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_const_wide() {
        // const-wide v0, #0x0102030405060708 — 51l = 10 bytes
        let mut buf = vec![0x18_u8, 0x00];
        buf.extend_from_slice(&0x0102030405060708_u64.to_le_bytes());
        let i = dis(&buf);
        assert_eq!(i.mnemonic, "const-wide");
        assert_eq!(i.size, 10);
    }

    #[test]
    fn test_goto() {
        let i = dis(&[0x28, 0x04]);
        assert_eq!(i.mnemonic, "goto");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_goto16() {
        let i = dis(&[0x29, 0x00, 0x0a, 0x00]);
        assert_eq!(i.mnemonic, "goto/16");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_goto32() {
        let i = dis(&[0x2a, 0x00, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(i.mnemonic, "goto/32");
        assert_eq!(i.size, 6);
    }

    #[test]
    fn test_if_eq() {
        let i = dis(&[0x32, 0x10, 0x05, 0x00]);
        assert_eq!(i.mnemonic, "if-eq");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_if_eqz() {
        let i = dis(&[0x38, 0x02, 0x03, 0x00]);
        assert_eq!(i.mnemonic, "if-eqz");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_invoke_virtual() {
        let i = dis(&[0x6e, 0x10, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "invoke-virtual");
        assert!(i.flags.contains(InstrFlags::CALL));
        assert_eq!(i.size, 6);
    }

    #[test]
    fn test_invoke_static() {
        let i = dis(&[0x71, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(i.mnemonic, "invoke-static");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_aget() {
        let i = dis(&[0x44, 0x02, 0x03, 0x04]);
        assert_eq!(i.mnemonic, "aget");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_aput() {
        let i = dis(&[0x4b, 0x02, 0x03, 0x04]);
        assert_eq!(i.mnemonic, "aput");
        assert!(i.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_iget() {
        let i = dis(&[0x52, 0x10, 0x01, 0x00]);
        assert_eq!(i.mnemonic, "iget");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_sget() {
        let i = dis(&[0x60, 0x01, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "sget");
        assert!(i.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_add_int() {
        let i = dis(&[0x90, 0x02, 0x03, 0x04]);
        assert_eq!(i.mnemonic, "add-int");
        assert_eq!(i.operands, "v2, v3, v4");
    }

    #[test]
    fn test_add_int_2addr() {
        let i = dis(&[0xb0, 0x21]);
        assert_eq!(i.mnemonic, "add-int/2addr");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_add_int_lit16() {
        let i = dis(&[0xd0, 0x10, 0x0a, 0x00]);
        assert_eq!(i.mnemonic, "add-int/lit16");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_add_int_lit8() {
        let i = dis(&[0xd8, 0x02, 0x01, 0x05]);
        assert_eq!(i.mnemonic, "add-int/lit8");
        assert!(i.operands.contains("v2"));
    }

    #[test]
    fn test_neg_int() {
        let i = dis(&[0x7b, 0x10]);
        assert_eq!(i.mnemonic, "neg-int");
    }

    #[test]
    fn test_int_to_long() {
        let i = dis(&[0x81, 0x20]);
        assert_eq!(i.mnemonic, "int-to-long");
    }

    #[test]
    fn test_const_string() {
        let i = dis(&[0x1a, 0x01, 0x05, 0x00]);
        assert_eq!(i.mnemonic, "const-string");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_new_instance() {
        let i = dis(&[0x22, 0x01, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "new-instance");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_check_cast() {
        let i = dis(&[0x1f, 0x01, 0x02, 0x00]);
        assert_eq!(i.mnemonic, "check-cast");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_move_result() {
        let i = dis(&[0x0a, 0x01]);
        assert_eq!(i.mnemonic, "move-result");
        assert_eq!(i.operands, "v1");
    }

    #[test]
    fn test_registers() {
        let regs = arch().registers();
        assert_eq!(regs.len(), 16);
        assert_eq!(regs[0].name, "v0");
        assert_eq!(regs[15].name, "v15");
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "dalvik");
    }

    #[test]
    fn test_arch_name() {
        assert_eq!(arch().name(), "dex");
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(arch().pointer_size(), 4);
    }

    #[test]
    fn test_endian() {
        assert_eq!(arch().endian(), Endian::Little);
    }

    #[test]
    fn test_monitor_enter() {
        let i = dis(&[0x1d, 0x01]);
        assert_eq!(i.mnemonic, "monitor-enter");
    }

    #[test]
    fn test_throw() {
        let i = dis(&[0x27, 0x01]);
        assert_eq!(i.mnemonic, "throw");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_cmp_long() {
        let i = dis(&[0x31, 0x02, 0x03, 0x04]);
        assert_eq!(i.mnemonic, "cmp-long");
    }

    #[test]
    fn test_move_wide() {
        let i = dis(&[0x04, 0x20]);
        assert_eq!(i.mnemonic, "move-wide");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_move_exception() {
        let i = dis(&[0x0d, 0x03]);
        assert_eq!(i.mnemonic, "move-exception");
        assert_eq!(i.operands, "v3");
    }

    #[test]
    fn test_unknown_opcode() {
        // 0xe3 is now handled as an ART-optimized opcode (iget-quick), so use
        // a truly unused opcode that returns Err: 0x3e is in the reserved
        // unused range 0x3e..=0x43.
        let result = arch().disassemble(Address::new(0), &[0x3e, 0x00]);
        assert!(result.is_err());
    }

    // --- Type descriptor tests ---

    #[test]
    fn test_type_descriptor_int() {
        let d = DexTypeDescriptor::new("I");
        assert_eq!(d.kind(), DescriptorKind::Int);
        assert_eq!(d.kind().register_slots(), 1);
        assert!(!d.kind().is_wide());
    }

    #[test]
    fn test_type_descriptor_long() {
        let d = DexTypeDescriptor::new("J");
        assert_eq!(d.kind(), DescriptorKind::Long);
        assert_eq!(d.kind().register_slots(), 2);
        assert!(d.kind().is_wide());
    }

    #[test]
    fn test_type_descriptor_object() {
        let d = DexTypeDescriptor::new("Ljava/lang/String;");
        assert_eq!(d.kind(), DescriptorKind::Object);
        assert_eq!(d.class_name(), Some("java/lang/String"));
    }

    #[test]
    fn test_type_descriptor_array() {
        let d = DexTypeDescriptor::new("[B");
        assert_eq!(d.kind(), DescriptorKind::Array);
        let elem = d.array_element().unwrap();
        assert_eq!(elem.kind(), DescriptorKind::Byte);
    }

    // --- Method signature tests ---

    #[test]
    fn test_method_signature_args() {
        let sig = DexMethodSignature::new(
            "VIL",
            "V",
            vec![DexTypeDescriptor::new("I"), DexTypeDescriptor::new("J")],
        );
        assert_eq!(sig.arg_register_count(), 3); // I=1, J=2
    }

    // --- Code item header ---

    #[test]
    fn test_code_item_header_decode() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&3_u16.to_le_bytes()); // registers_size
        buf[12..16].copy_from_slice(&10_u32.to_le_bytes()); // insns_size
        let hdr = DexCodeItemHeader::decode(&buf).unwrap();
        assert_eq!(hdr.registers_size, 3);
        assert_eq!(hdr.insns_size, 10);
    }

    #[test]
    fn test_code_item_header_truncated() {
        assert_eq!(
            DexCodeItemHeader::decode(&[0; 8]),
            Err(DexDecodeError::Truncated)
        );
    }

    // --- ART optimized opcodes ---

    #[test]
    fn test_art_opcode_detection() {
        assert!(is_art_optimized_opcode(0xe3));
        assert!(is_art_optimized_opcode(0xf9));
        assert!(!is_art_optimized_opcode(0xe2));
        assert!(!is_art_optimized_opcode(0xfa));
    }

    #[test]
    fn test_art_opcode_name() {
        assert_eq!(art_opcode_name(0xe3), "iget-quick");
        assert_eq!(art_opcode_name(0xe9), "invoke-virtual-quick");
    }

    // --- DEX constants ---

    #[test]
    fn test_dex_magic() {
        assert_eq!(&DEX_MAGIC[..], b"dex\n");
    }

    #[test]
    fn test_dex_endian_constants() {
        assert_eq!(DEX_ENDIAN_CONSTANT, 0x12345678);
        assert_eq!(DEX_REVERSE_ENDIAN_CONSTANT, 0x78563412);
    }

    // --- Format code units ---

    #[test]
    fn test_format_code_units() {
        assert_eq!(DexFormat::F10x.base_code_units(), 1);
        assert_eq!(DexFormat::F51l.base_code_units(), 5);
        assert_eq!(DexFormat::F35c.base_code_units(), 3);
    }

    // --- DEX access flags ---

    #[test]
    fn test_access_flags_public_static() {
        let flags = DexAccessFlags(DexAccessFlags::PUBLIC | DexAccessFlags::STATIC);
        assert!(flags.has(DexAccessFlags::PUBLIC));
        assert!(flags.has(DexAccessFlags::STATIC));
        assert!(!flags.has(DexAccessFlags::PRIVATE));
    }

    // --- Linear disassembler ---

    #[test]
    fn test_linear_disassembler() {
        let arch = DexArch::new();
        // move-result v0; return-void
        let prog = [0x0a_u8, 0x00, 0x0e, 0x00];
        let instrs: Vec<_> = DexLinearDisassembler::new(&arch, &prog, Address::new(0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[0].mnemonic, "move-result");
        assert_eq!(instrs[1].mnemonic, "return-void");
    }

    // --- New DEX 038+ instructions ---

    #[test]
    fn test_const_method_handle() {
        let i = dis(&[0xfe, 0x01, 0x05, 0x00]);
        assert_eq!(i.mnemonic, "const-method-handle");
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_const_method_type() {
        let i = dis(&[0xff, 0x01, 0x03, 0x00]);
        assert_eq!(i.mnemonic, "const-method-type");
        assert_eq!(i.size, 4);
    }
}

// ---------------------------------------------------------------------------
// DEX opcode reference table
// ---------------------------------------------------------------------------

/// Reference entry for a DEX opcode.
#[derive(Debug, Clone, Copy)]
pub struct DexOpcodeRef {
    /// Primary opcode byte.
    pub opcode: u8,
    /// Mnemonic string.
    pub mnemonic: &'static str,
    /// Instruction format (e.g., `"10x"`, `"12x"`, `"22x"`).
    pub format: &'static str,
    /// Size in 16-bit code units.
    pub units: u8,
    /// Raw semantic flags bits (BRANCH=1, CALL=2, RETURN=4, etc.).
    pub flag_bits: u32,
}

impl DexOpcodeRef {
    /// Returns the `InstrFlags` for this opcode.
    ///
    /// The table stores `flag_bits` in a compact logical encoding
    /// (BRANCH=1, CALL=2, RET=4, CONDITIONAL=8, INDIRECT=16, `READ_MEM=32`,
    /// `WRITE_MEM=64`, BARRIER=128); this maps that encoding onto the real
    /// [`InstrFlags`] bit layout.
    #[must_use]
    pub fn flags(self) -> InstrFlags {
        let mut flags = InstrFlags::NONE;
        if self.flag_bits & 1 != 0 {
            flags |= InstrFlags::BRANCH;
        }
        if self.flag_bits & 2 != 0 {
            flags |= InstrFlags::CALL;
        }
        if self.flag_bits & 4 != 0 {
            flags |= InstrFlags::RET;
        }
        if self.flag_bits & 8 != 0 {
            flags |= InstrFlags::CONDITIONAL;
        }
        if self.flag_bits & 16 != 0 {
            flags |= InstrFlags::INDIRECT;
        }
        if self.flag_bits & 32 != 0 {
            flags |= InstrFlags::READ_MEM;
        }
        if self.flag_bits & 64 != 0 {
            flags |= InstrFlags::WRITE_MEM;
        }
        if self.flag_bits & 128 != 0 {
            flags |= InstrFlags::BARRIER;
        }
        flags
    }
}

/// DEX opcode reference table (selected common opcodes).
pub static DEX_OPCODE_REF: &[DexOpcodeRef] = &[
    DexOpcodeRef {
        opcode: 0x00,
        mnemonic: "nop",
        format: "10x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x01,
        mnemonic: "move",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x02,
        mnemonic: "move/from16",
        format: "22x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x03,
        mnemonic: "move/16",
        format: "32x",
        units: 3,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x04,
        mnemonic: "move-wide",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x07,
        mnemonic: "move-object",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x0a,
        mnemonic: "move-result",
        format: "11x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x0e,
        mnemonic: "return-void",
        format: "10x",
        units: 1,
        flag_bits: 4,
    },
    DexOpcodeRef {
        opcode: 0x0f,
        mnemonic: "return",
        format: "11x",
        units: 1,
        flag_bits: 4,
    },
    DexOpcodeRef {
        opcode: 0x10,
        mnemonic: "return-wide",
        format: "11x",
        units: 1,
        flag_bits: 4,
    },
    DexOpcodeRef {
        opcode: 0x11,
        mnemonic: "return-object",
        format: "11x",
        units: 1,
        flag_bits: 4,
    },
    DexOpcodeRef {
        opcode: 0x12,
        mnemonic: "const/4",
        format: "11n",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x13,
        mnemonic: "const/16",
        format: "21s",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x14,
        mnemonic: "const",
        format: "31i",
        units: 3,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x15,
        mnemonic: "const/high16",
        format: "21h",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x16,
        mnemonic: "const-wide/16",
        format: "21s",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x1a,
        mnemonic: "const-string",
        format: "21c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x1c,
        mnemonic: "const-class",
        format: "21c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x1d,
        mnemonic: "monitor-enter",
        format: "11x",
        units: 1,
        flag_bits: 128,
    },
    DexOpcodeRef {
        opcode: 0x1e,
        mnemonic: "monitor-exit",
        format: "11x",
        units: 1,
        flag_bits: 128,
    },
    DexOpcodeRef {
        opcode: 0x1f,
        mnemonic: "check-cast",
        format: "21c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x20,
        mnemonic: "instance-of",
        format: "22c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x21,
        mnemonic: "array-length",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x22,
        mnemonic: "new-instance",
        format: "21c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x23,
        mnemonic: "new-array",
        format: "22c",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x27,
        mnemonic: "throw",
        format: "11x",
        units: 1,
        flag_bits: 4,
    },
    DexOpcodeRef {
        opcode: 0x28,
        mnemonic: "goto",
        format: "10t",
        units: 1,
        flag_bits: 1,
    },
    DexOpcodeRef {
        opcode: 0x29,
        mnemonic: "goto/16",
        format: "20t",
        units: 2,
        flag_bits: 1,
    },
    DexOpcodeRef {
        opcode: 0x2a,
        mnemonic: "goto/32",
        format: "30t",
        units: 3,
        flag_bits: 1,
    },
    DexOpcodeRef {
        opcode: 0x2b,
        mnemonic: "packed-switch",
        format: "31t",
        units: 3,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x2c,
        mnemonic: "sparse-switch",
        format: "31t",
        units: 3,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x32,
        mnemonic: "if-eq",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x33,
        mnemonic: "if-ne",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x34,
        mnemonic: "if-lt",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x35,
        mnemonic: "if-ge",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x36,
        mnemonic: "if-gt",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x37,
        mnemonic: "if-le",
        format: "22t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x38,
        mnemonic: "if-eqz",
        format: "21t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x39,
        mnemonic: "if-nez",
        format: "21t",
        units: 2,
        flag_bits: 1 | 8,
    },
    DexOpcodeRef {
        opcode: 0x44,
        mnemonic: "aget",
        format: "23x",
        units: 2,
        flag_bits: 32,
    },
    DexOpcodeRef {
        opcode: 0x4a,
        mnemonic: "aput",
        format: "23x",
        units: 2,
        flag_bits: 64,
    },
    DexOpcodeRef {
        opcode: 0x52,
        mnemonic: "iget",
        format: "22c",
        units: 2,
        flag_bits: 32,
    },
    DexOpcodeRef {
        opcode: 0x59,
        mnemonic: "iput",
        format: "22c",
        units: 2,
        flag_bits: 64,
    },
    DexOpcodeRef {
        opcode: 0x60,
        mnemonic: "sget",
        format: "21c",
        units: 2,
        flag_bits: 32,
    },
    DexOpcodeRef {
        opcode: 0x67,
        mnemonic: "sput",
        format: "21c",
        units: 2,
        flag_bits: 64,
    },
    DexOpcodeRef {
        opcode: 0x6e,
        mnemonic: "invoke-virtual",
        format: "35c",
        units: 3,
        flag_bits: 2,
    },
    DexOpcodeRef {
        opcode: 0x6f,
        mnemonic: "invoke-super",
        format: "35c",
        units: 3,
        flag_bits: 2,
    },
    DexOpcodeRef {
        opcode: 0x70,
        mnemonic: "invoke-direct",
        format: "35c",
        units: 3,
        flag_bits: 2,
    },
    DexOpcodeRef {
        opcode: 0x71,
        mnemonic: "invoke-static",
        format: "35c",
        units: 3,
        flag_bits: 2,
    },
    DexOpcodeRef {
        opcode: 0x72,
        mnemonic: "invoke-interface",
        format: "35c",
        units: 3,
        flag_bits: 2 | 16,
    },
    DexOpcodeRef {
        opcode: 0x74,
        mnemonic: "invoke-virtual/range",
        format: "3rc",
        units: 3,
        flag_bits: 2,
    },
    DexOpcodeRef {
        opcode: 0x78,
        mnemonic: "invoke-interface/range",
        format: "3rc",
        units: 3,
        flag_bits: 2 | 16,
    },
    DexOpcodeRef {
        opcode: 0x7b,
        mnemonic: "neg-int",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x7c,
        mnemonic: "not-int",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x90,
        mnemonic: "add-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x91,
        mnemonic: "sub-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x92,
        mnemonic: "mul-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x93,
        mnemonic: "div-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x94,
        mnemonic: "rem-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x95,
        mnemonic: "and-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x96,
        mnemonic: "or-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x97,
        mnemonic: "xor-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x98,
        mnemonic: "shl-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x99,
        mnemonic: "shr-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0x9a,
        mnemonic: "ushr-int",
        format: "23x",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0xb0,
        mnemonic: "add-int/2addr",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0xb1,
        mnemonic: "sub-int/2addr",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0xb4,
        mnemonic: "and-int/2addr",
        format: "12x",
        units: 1,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0xd0,
        mnemonic: "add-int/lit16",
        format: "22s",
        units: 2,
        flag_bits: 0,
    },
    DexOpcodeRef {
        opcode: 0xd8,
        mnemonic: "add-int/lit8",
        format: "22b",
        units: 2,
        flag_bits: 0,
    },
];

/// Look up a DEX opcode reference entry.
#[must_use]
pub fn lookup_dex_opcode(opcode: u8) -> Option<&'static DexOpcodeRef> {
    DEX_OPCODE_REF.iter().find(|e| e.opcode == opcode)
}

// ---------------------------------------------------------------------------
// DEX method signature parser
// ---------------------------------------------------------------------------

/// The return-type kind of a DEX method descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexReturnType {
    /// void return.
    Void,
    /// Primitive type.
    Primitive(char),
    /// Object reference.
    Object(String),
    /// Array type.
    Array(Box<Self>),
}

impl DexReturnType {
    /// Parse the return-type from a DEX method descriptor string
    /// (the portion after the closing `)`).
    #[must_use]
    pub fn parse(descriptor: &str) -> Option<Self> {
        Self::parse_with_depth(descriptor, 0)
    }

    fn parse_with_depth(descriptor: &str, depth: usize) -> Option<Self> {
        // Guard against deeply-nested array descriptors from untrusted input.
        const MAX_ARRAY_DEPTH: usize = 255;
        if depth > MAX_ARRAY_DEPTH {
            return None;
        }
        let s = descriptor.trim();
        if s.is_empty() {
            return None;
        }
        match s.chars().next()? {
            'V' => Some(Self::Void),
            'Z' | 'B' | 'S' | 'C' | 'I' | 'J' | 'F' | 'D' => {
                Some(Self::Primitive(s.chars().next()?))
            }
            'L' => {
                let end = s.find(';')?;
                Some(Self::Object(s[1..end].to_string()))
            }
            '[' => {
                let inner = Self::parse_with_depth(&s[1..], depth + 1)?;
                Some(Self::Array(Box::new(inner)))
            }
            _ => None,
        }
    }

    /// Returns `true` if this return type is `void`.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }
}

/// Count the number of parameters in a DEX method descriptor
/// (the portion between `(` and `)`).
#[must_use]
pub fn dex_param_count(descriptor: &str) -> usize {
    // Use char-aware positions. `find` returns byte offsets, which are safe to
    // add 1 to only for single-byte chars like '(' and ')'.
    let start = match descriptor.find('(') {
        Some(pos) => pos + 1, // '(' is ASCII (1 byte), so pos+1 is always a char boundary
        None => return 0,     // No opening paren — not a valid descriptor
    };
    let end = match descriptor.find(')') {
        Some(pos) => pos,
        None => descriptor.len(),
    };
    let end = end.max(start); // ensure end >= start to avoid panic on malformed input
    let params = &descriptor[start..end];
    let mut count = 0;
    let mut chars = params.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            'Z' | 'B' | 'S' | 'C' | 'I' | 'J' | 'F' | 'D' => count += 1,
            'L' => {
                count += 1;
                while chars.next().is_some_and(|x| x != ';') {}
            }
            '[' => {
                // Skip dimension indicators
                while chars.peek() == Some(&'[') {
                    chars.next();
                }
                if chars.peek() == Some(&'L') {
                    chars.next();
                    while chars.next().is_some_and(|x| x != ';') {}
                } else {
                    chars.next();
                }
                count += 1;
            }
            _ => {}
        }
    }
    count
}

// ---------------------------------------------------------------------------
// DEX basic block finder
// ---------------------------------------------------------------------------

/// A DEX basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexBasicBlock {
    /// Byte offset of the first instruction.
    pub start: usize,
    /// Byte offset past the last instruction.
    pub end: usize,
    /// Instruction count.
    pub instr_count: usize,
}

impl DexBasicBlock {
    /// Byte length of this block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns `true` if this block is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instr_count == 0
    }
}

/// Split DEX bytecode into basic blocks.
///
/// # Errors
///
/// Returns `DexDecodeError` on decode failure.
pub fn dex_find_blocks(code: &[u8]) -> Result<Vec<DexBasicBlock>, DexDecodeError> {
    // Heuristic: average block ~8 instructions of avg size 4 bytes => code.len()/32
    let mut blocks = Vec::with_capacity((code.len() / 32).max(4));
    let mut off = 0usize;
    let mut blk_start = 0usize;
    let mut blk_instrs = 0usize;
    while off < code.len() {
        let (_, _, sz, flags) = decode_dex(&code[off..]).map_err(|_| DexDecodeError::Truncated)?;
        off += sz;
        blk_instrs += 1;
        if flags.intersects(InstrFlags::BRANCH | InstrFlags::RET) {
            blocks.push(DexBasicBlock {
                start: blk_start,
                end: off,
                instr_count: blk_instrs,
            });
            blk_start = off;
            blk_instrs = 0;
        }
    }
    if blk_instrs > 0 {
        blocks.push(DexBasicBlock {
            start: blk_start,
            end: off,
            instr_count: blk_instrs,
        });
    }
    Ok(blocks)
}

// ---------------------------------------------------------------------------
// DEX register naming conventions
// ---------------------------------------------------------------------------

/// Format a DEX register name using the `v` convention.
#[must_use]
pub fn dex_vreg(n: u8) -> String {
    format!("v{n}")
}

/// Format a DEX parameter register name using the `p` convention.
///
/// `p0` = first parameter, which is `this` for instance methods.
#[must_use]
pub fn dex_preg(n: u8) -> String {
    format!("p{n}")
}

/// Return the parameter register numbers for a method given the total
/// register count and parameter count (including `this` for non-static).
#[must_use]
pub fn dex_param_regs(total_regs: u8, param_count: u8) -> Vec<u8> {
    let first = total_regs.saturating_sub(param_count);
    (first..total_regs).collect()
}

// ---------------------------------------------------------------------------
// DEX well-known class/method references
// ---------------------------------------------------------------------------

/// A well-known Android/Java class reference used in DEX analysis.
#[derive(Debug, Clone, Copy)]
pub struct DexWellKnownClass {
    /// DEX descriptor (e.g., `"Ljava/lang/String;"`).
    pub descriptor: &'static str,
    /// Human-readable name.
    pub name: &'static str,
}

/// Well-known Android/Java classes used in DEX analysis.
pub static DEX_WELL_KNOWN_CLASSES: &[DexWellKnownClass] = &[
    DexWellKnownClass {
        descriptor: "Ljava/lang/Object;",
        name: "Object",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/String;",
        name: "String",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/StringBuilder;",
        name: "StringBuilder",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Integer;",
        name: "Integer",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Long;",
        name: "Long",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Boolean;",
        name: "Boolean",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Math;",
        name: "Math",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/System;",
        name: "System",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Exception;",
        name: "Exception",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/RuntimeException;",
        name: "RuntimeException",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/NullPointerException;",
        name: "NullPointerException",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Class;",
        name: "Class",
    },
    DexWellKnownClass {
        descriptor: "Ljava/lang/Thread;",
        name: "Thread",
    },
    DexWellKnownClass {
        descriptor: "Ljava/util/List;",
        name: "List",
    },
    DexWellKnownClass {
        descriptor: "Ljava/util/ArrayList;",
        name: "ArrayList",
    },
    DexWellKnownClass {
        descriptor: "Ljava/util/HashMap;",
        name: "HashMap",
    },
    DexWellKnownClass {
        descriptor: "Landroid/content/Context;",
        name: "Context",
    },
    DexWellKnownClass {
        descriptor: "Landroid/app/Activity;",
        name: "Activity",
    },
    DexWellKnownClass {
        descriptor: "Landroid/util/Log;",
        name: "Log",
    },
    DexWellKnownClass {
        descriptor: "Landroid/os/Bundle;",
        name: "Bundle",
    },
    DexWellKnownClass {
        descriptor: "Landroid/os/Handler;",
        name: "Handler",
    },
    DexWellKnownClass {
        descriptor: "Landroid/os/Looper;",
        name: "Looper",
    },
    DexWellKnownClass {
        descriptor: "Landroid/content/Intent;",
        name: "Intent",
    },
    DexWellKnownClass {
        descriptor: "Landroid/view/View;",
        name: "View",
    },
    DexWellKnownClass {
        descriptor: "Ljava/io/IOException;",
        name: "IOException",
    },
    DexWellKnownClass {
        descriptor: "Ljava/io/InputStream;",
        name: "InputStream",
    },
    DexWellKnownClass {
        descriptor: "Ljava/io/OutputStream;",
        name: "OutputStream",
    },
    DexWellKnownClass {
        descriptor: "Ljava/net/URL;",
        name: "URL",
    },
];

/// Look up a well-known class by DEX descriptor.
#[must_use]
pub fn lookup_dex_class(descriptor: &str) -> Option<&'static DexWellKnownClass> {
    DEX_WELL_KNOWN_CLASSES
        .iter()
        .find(|c| c.descriptor == descriptor)
}

// ---------------------------------------------------------------------------
// DEX method stats
// ---------------------------------------------------------------------------

/// Statistics gathered from a DEX method body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DexMethodStats {
    /// Total instruction count.
    pub instruction_count: usize,
    /// Number of invoke-* instructions (calls).
    pub call_count: usize,
    /// Number of conditional branches.
    pub conditional_branch_count: usize,
    /// Number of unconditional branches.
    pub unconditional_branch_count: usize,
    /// Number of return/throw instructions.
    pub terminator_count: usize,
    /// Number of memory read instructions.
    pub read_count: usize,
    /// Number of memory write instructions.
    pub write_count: usize,
}

impl DexMethodStats {
    /// Compute statistics from raw DEX bytecode.
    ///
    /// # Errors
    ///
    /// Returns `DexDecodeError` on decode failure.
    pub fn from_bytes(code: &[u8]) -> Result<Self, DexDecodeError> {
        let mut s = Self::default();
        let mut off = 0;
        while off < code.len() {
            let (_, _, sz, flags) =
                decode_dex(&code[off..]).map_err(|_| DexDecodeError::Truncated)?;
            off += sz;
            s.instruction_count += 1;
            if flags.contains(InstrFlags::CALL) {
                s.call_count += 1;
            }
            if flags.contains(InstrFlags::BRANCH) {
                if flags.contains(InstrFlags::CONDITIONAL) {
                    s.conditional_branch_count += 1;
                } else {
                    s.unconditional_branch_count += 1;
                }
            }
            if flags.contains(InstrFlags::RET) {
                s.terminator_count += 1;
            }
            if flags.contains(InstrFlags::READ_MEM) {
                s.read_count += 1;
            }
            if flags.contains(InstrFlags::WRITE_MEM) {
                s.write_count += 1;
            }
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// DEX idiom detection
// ---------------------------------------------------------------------------

/// DEX instruction idioms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexIdiom {
    /// `const/4 v0, 0` → zero-init.
    ZeroInit,
    /// `if-eqz vX, :label` → null check.
    NullCheck,
    /// `invoke-virtual {vX}, Ljava/lang/String;->length()I` → string length.
    StringLength,
    /// `new-instance vX, Ljava/lang/StringBuilder;` → string builder.
    StringBuilderNew,
    /// `goto :label` (unconditional back-edge → loop).
    BackEdgeLoop,
    /// Generic unrecognized idiom.
    General,
}

/// Identify a DEX idiom from the first instruction's mnemonic.
#[must_use]
pub fn identify_dex_idiom(mnemonic: &str, operands: &str) -> DexIdiom {
    match mnemonic {
        "const/4" if operands.ends_with(", 0") || operands.ends_with(",0") => DexIdiom::ZeroInit,
        "if-eqz" | "if-nez" => DexIdiom::NullCheck,
        "new-instance" if operands.contains("StringBuilder") => DexIdiom::StringBuilderNew,
        "goto" => DexIdiom::BackEdgeLoop,
        _ => DexIdiom::General,
    }
}

// ---------------------------------------------------------------------------
// DEX ART code item helper extension
// ---------------------------------------------------------------------------

/// Minimum bytes needed for a valid DEX code item header.
pub const DEX_CODE_ITEM_HEADER_SIZE: usize = 16;

impl DexCodeItemHeader {
    /// Returns `true` if this code item contains exception handlers.
    #[must_use]
    pub const fn has_try_blocks(&self) -> bool {
        self.tries_size > 0
    }
}

// ---------------------------------------------------------------------------
// DEX ART-specific annotations
// ---------------------------------------------------------------------------

/// Visibility values for DEX annotations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexAnnotationVisibility {
    /// Build-time only.
    Build = 0x00,
    /// Runtime-visible.
    Runtime = 0x01,
    /// System-internal.
    System = 0x02,
}

impl DexAnnotationVisibility {
    /// Decode from raw byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Build),
            0x01 => Some(Self::Runtime),
            0x02 => Some(Self::System),
            _ => None,
        }
    }
    /// Return the string name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Runtime => "runtime",
            Self::System => "system",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dex_extended_tests {
    use super::*;

    #[test]
    fn test_opcode_ref_nop() {
        let e = lookup_dex_opcode(0x00).unwrap();
        assert_eq!(e.mnemonic, "nop");
        assert_eq!(e.units, 1);
    }

    #[test]
    fn test_opcode_ref_return_void() {
        let e = lookup_dex_opcode(0x0e).unwrap();
        assert_eq!(e.mnemonic, "return-void");
        assert!(e.flags().contains(InstrFlags::RET));
    }

    #[test]
    fn test_opcode_ref_invoke_virtual() {
        let e = lookup_dex_opcode(0x6e).unwrap();
        assert_eq!(e.mnemonic, "invoke-virtual");
        assert!(e.flags().contains(InstrFlags::CALL));
    }

    #[test]
    fn test_opcode_ref_iget_read() {
        let e = lookup_dex_opcode(0x52).unwrap();
        assert!(e.flags().contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_opcode_ref_missing() {
        assert!(lookup_dex_opcode(0xEE).is_none());
    }

    #[test]
    fn test_opcode_ref_table_size() {
        assert!(DEX_OPCODE_REF.len() >= 50);
    }

    #[test]
    fn test_return_type_void() {
        assert_eq!(DexReturnType::parse("V"), Some(DexReturnType::Void));
        assert!(DexReturnType::parse("V").unwrap().is_void());
    }

    #[test]
    fn test_return_type_int() {
        assert_eq!(
            DexReturnType::parse("I"),
            Some(DexReturnType::Primitive('I'))
        );
    }

    #[test]
    fn test_return_type_object() {
        let r = DexReturnType::parse("Ljava/lang/String;").unwrap();
        assert_eq!(r, DexReturnType::Object("java/lang/String".into()));
    }

    #[test]
    fn test_return_type_array() {
        let r = DexReturnType::parse("[I").unwrap();
        assert_eq!(
            r,
            DexReturnType::Array(Box::new(DexReturnType::Primitive('I')))
        );
    }

    #[test]
    fn test_param_count_empty() {
        assert_eq!(dex_param_count("()V"), 0);
    }

    #[test]
    fn test_param_count_primitives() {
        assert_eq!(dex_param_count("(IIZ)V"), 3);
    }

    #[test]
    fn test_param_count_object() {
        assert_eq!(dex_param_count("(Ljava/lang/String;)V"), 1);
    }

    #[test]
    fn test_param_count_mixed() {
        assert_eq!(dex_param_count("(ILjava/lang/String;Z)I"), 3);
    }

    #[test]
    fn test_dex_vreg() {
        assert_eq!(dex_vreg(3), "v3");
    }

    #[test]
    fn test_dex_preg() {
        assert_eq!(dex_preg(0), "p0");
    }

    #[test]
    fn test_param_regs() {
        let r = dex_param_regs(8, 3);
        assert_eq!(r, vec![5, 6, 7]);
    }

    #[test]
    fn test_well_known_string() {
        let c = lookup_dex_class("Ljava/lang/String;").unwrap();
        assert_eq!(c.name, "String");
    }

    #[test]
    fn test_well_known_activity() {
        let c = lookup_dex_class("Landroid/app/Activity;").unwrap();
        assert_eq!(c.name, "Activity");
    }

    #[test]
    fn test_well_known_missing() {
        assert!(lookup_dex_class("Lcom/unknown/Foo;").is_none());
    }

    #[test]
    fn test_well_known_table_size() {
        assert!(DEX_WELL_KNOWN_CLASSES.len() >= 20);
    }

    #[test]
    fn test_method_stats_return_void() {
        // return-void
        let code = [0x0e_u8, 0x00];
        let s = DexMethodStats::from_bytes(&code).unwrap();
        assert_eq!(s.instruction_count, 1);
        assert_eq!(s.terminator_count, 1);
    }

    #[test]
    fn test_idiom_zero_init() {
        assert_eq!(identify_dex_idiom("const/4", "v0, 0"), DexIdiom::ZeroInit);
    }

    #[test]
    fn test_idiom_null_check() {
        assert_eq!(
            identify_dex_idiom("if-eqz", "v0, :label"),
            DexIdiom::NullCheck
        );
    }

    #[test]
    fn test_idiom_string_builder() {
        assert_eq!(
            identify_dex_idiom("new-instance", "v0, Ljava/lang/StringBuilder;"),
            DexIdiom::StringBuilderNew
        );
    }

    #[test]
    fn test_idiom_goto() {
        assert_eq!(identify_dex_idiom("goto", ":label"), DexIdiom::BackEdgeLoop);
    }

    #[test]
    fn test_code_item_header_decode() {
        let mut data = vec![0u8; 16];
        // registers_size = 4, ins_size = 1, outs_size = 2, tries_size = 0
        data[0] = 4;
        data[2] = 1;
        data[4] = 2;
        data[6] = 0;
        // insns_size at offset 12
        data[12] = 0x10;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x00;
        let h = DexCodeItemHeader::decode(&data).unwrap();
        assert_eq!(h.registers_size, 4);
        assert_eq!(h.ins_size, 1);
        assert_eq!(h.insns_size, 16);
        assert!(!h.has_try_blocks());
    }

    #[test]
    fn test_code_item_header_truncated() {
        assert!(DexCodeItemHeader::decode(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_annotation_visibility() {
        assert_eq!(
            DexAnnotationVisibility::from_byte(0x01),
            Some(DexAnnotationVisibility::Runtime)
        );
        assert_eq!(DexAnnotationVisibility::Runtime.name(), "runtime");
    }

    #[test]
    fn test_annotation_visibility_unknown() {
        assert!(DexAnnotationVisibility::from_byte(0xFF).is_none());
    }

    #[test]
    fn test_blocks_return_void() {
        let code = [0x0e_u8, 0x00]; // return-void
        let blocks = dex_find_blocks(&code).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instr_count, 1);
    }

    #[test]
    fn test_blocks_empty() {
        let blocks = dex_find_blocks(&[]).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_opcode_if_eq_conditional() {
        let e = lookup_dex_opcode(0x32).unwrap();
        assert!(e.flags().contains(InstrFlags::CONDITIONAL));
    }
}

// ---------------------------------------------------------------------------
// DEX string descriptor utilities
// ---------------------------------------------------------------------------

/// Convert a DEX internal class name to a Java-style name.
/// E.g., `"java/lang/String"` → `"java.lang.String"`.
#[must_use]
pub fn dex_internal_to_java_name(internal: &str) -> String {
    internal.replace('/', ".")
}

/// Convert a Java-style class name to a DEX descriptor.
/// E.g., `"java.lang.String"` → `"Ljava/lang/String;"`.
#[must_use]
pub fn java_name_to_dex_descriptor(java_name: &str) -> String {
    format!("L{};", java_name.replace('.', "/"))
}

/// Strip the package from a DEX descriptor, returning the simple class name.
/// E.g., `"Ljava/lang/String;"` → `"String"`.
#[must_use]
pub fn dex_simple_class_name(descriptor: &str) -> &str {
    let stripped = descriptor.trim_start_matches('L').trim_end_matches(';');
    stripped.rsplit('/').next().unwrap_or(stripped)
}

// ---------------------------------------------------------------------------
// DEX instruction timing/cycle-cost estimator
// ---------------------------------------------------------------------------

/// Estimated relative cost (cycle weight) for a DEX instruction.
///
/// Costs are heuristic and intended for relative comparison only.
#[must_use]
pub fn dex_instr_cost(mnemonic: &str) -> u32 {
    match mnemonic {
        "nop" => 0,
        "move" | "move/from16" | "move-object" => 1,
        "const/4" | "const/16" | "const" | "const-string" => 2,
        "return-void" | "return" | "return-wide" | "return-object" => 1,
        "goto" | "goto/16" | "goto/32" => 2,
        "if-eq" | "if-ne" | "if-lt" | "if-ge" | "if-gt" | "if-le" => 3,
        "if-eqz" | "if-nez" | "if-ltz" | "if-gez" | "if-gtz" | "if-lez" => 3,
        "aget" | "aget-wide" | "aget-object" | "aget-boolean" | "aget-char" => 5,
        "aput" | "aput-wide" | "aput-object" | "aput-boolean" | "aput-char" => 5,
        "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-char" => 4,
        "iput" | "iput-wide" | "iput-object" | "iput-boolean" | "iput-char" => 4,
        "sget" | "sget-wide" | "sget-object" | "sget-boolean" | "sget-char" => 6,
        "sput" | "sput-wide" | "sput-object" | "sput-boolean" | "sput-char" => 6,
        "invoke-virtual" | "invoke-super" | "invoke-interface" => 20,
        "invoke-direct" | "invoke-static" => 15,
        "new-instance" => 25,
        "new-array" => 20,
        "check-cast" => 8,
        "instance-of" => 8,
        "array-length" => 3,
        "filled-new-array" => 20,
        "throw" => 10,
        "monitor-enter" | "monitor-exit" => 12,
        "add-int" | "sub-int" | "mul-int" | "and-int" | "or-int" | "xor-int" => 2,
        "div-int" | "rem-int" => 8,
        "neg-int" | "not-int" => 1,
        "shl-int" | "shr-int" | "ushr-int" => 2,
        "add-long" | "sub-long" | "mul-long" | "and-long" | "or-long" | "xor-long" => 3,
        "div-long" | "rem-long" => 12,
        "add-float" | "sub-float" | "mul-float" => 4,
        "div-float" | "rem-float" => 10,
        "add-double" | "sub-double" | "mul-double" => 5,
        "div-double" | "rem-double" => 12,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// DEX complexity analyzer
// ---------------------------------------------------------------------------

/// Complexity metrics for a DEX method body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DexComplexityMetrics {
    /// Cyclomatic complexity (1 + conditionals).
    pub cyclomatic: usize,
    /// Total instruction count.
    pub instruction_count: usize,
    /// Estimated total cycle cost.
    pub estimated_cost: u32,
}

impl DexComplexityMetrics {
    /// Compute complexity from raw DEX bytecode.
    ///
    /// # Errors
    ///
    /// Returns `DexDecodeError` on decode failure.
    pub fn from_bytes(code: &[u8]) -> Result<Self, DexDecodeError> {
        let mut m = Self {
            cyclomatic: 1,
            ..Self::default()
        };
        let mut off = 0;
        while off < code.len() {
            let (mne, _, sz, flags) =
                decode_dex(&code[off..]).map_err(|_| DexDecodeError::Truncated)?;
            off += sz;
            m.instruction_count += 1;
            m.estimated_cost += dex_instr_cost(&mne);
            if flags.contains(InstrFlags::CONDITIONAL) {
                m.cyclomatic += 1;
            }
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// DEX method calling convention
// ---------------------------------------------------------------------------

/// DEX/Android ABI parameter-passing conventions for a given method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexCallingConv {
    /// Total registers in the method frame.
    pub frame_size: u16,
    /// Number of parameter registers (last N registers).
    pub param_count: u8,
    /// True if this is an instance method (`v[frame_size - param_count]` is `this`).
    pub is_instance: bool,
}

impl DexCallingConv {
    /// Compute the calling convention from a method's register/parameter counts.
    #[must_use]
    pub const fn compute(frame_size: u16, param_count: u8, is_instance: bool) -> Self {
        Self {
            frame_size,
            param_count,
            is_instance,
        }
    }

    /// Returns the register index for the `this` pointer (if instance method).
    #[must_use]
    pub fn this_register(&self) -> Option<u16> {
        if self.is_instance && self.frame_size >= u16::from(self.param_count) {
            Some(self.frame_size - u16::from(self.param_count))
        } else {
            None
        }
    }

    /// Returns the register index for the Nth parameter (0-based, after `this`).
    #[must_use]
    pub fn param_register(&self, n: u8) -> Option<u16> {
        let base = self.frame_size.checked_sub(u16::from(self.param_count))?;
        let offset = if self.is_instance { n + 1 } else { n };
        base.checked_add(u16::from(offset))
    }
}

// ---------------------------------------------------------------------------
// DEX smali-style output helpers
// ---------------------------------------------------------------------------

/// Format a DEX register as smali `vN`.
#[must_use]
pub fn smali_reg(n: u16) -> String {
    format!("v{n}")
}

/// Format a smali method reference.
#[must_use]
pub fn smali_method_ref(class: &str, method: &str, proto: &str) -> String {
    format!("{class}->{method}{proto}")
}

/// Format a smali field reference.
#[must_use]
pub fn smali_field_ref(class: &str, field: &str, field_type: &str) -> String {
    format!("{class}->{field}:{field_type}")
}

// ---------------------------------------------------------------------------
// DEX annotation element types
// ---------------------------------------------------------------------------

/// DEX annotation value type (`encoded_value` type byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DexAnnotationValueType {
    /// signed 1-byte integer.
    Byte = 0x00,
    /// signed 2-byte integer.
    Short = 0x02,
    /// unsigned 2-byte integer (char).
    Char = 0x03,
    /// signed 4-byte integer.
    Int = 0x04,
    /// signed 8-byte integer.
    Long = 0x06,
    /// IEEE 754 32-bit float.
    Float = 0x10,
    /// IEEE 754 64-bit double.
    Double = 0x11,
    /// 4-byte string index.
    String = 0x17,
    /// 4-byte type index.
    Type = 0x18,
    /// 4-byte field index.
    Field = 0x19,
    /// 4-byte method index.
    Method = 0x1a,
    /// 4-byte enum field index.
    Enum = 0x1b,
    /// Sub-annotation.
    Annotation = 0x1c,
    /// null.
    Null = 0x1e,
    /// bool.
    Boolean = 0x1f,
}

impl DexAnnotationValueType {
    /// Decode from type nibble byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b & 0x1f {
            0x00 => Some(Self::Byte),
            0x02 => Some(Self::Short),
            0x03 => Some(Self::Char),
            0x04 => Some(Self::Int),
            0x06 => Some(Self::Long),
            0x10 => Some(Self::Float),
            0x11 => Some(Self::Double),
            0x17 => Some(Self::String),
            0x18 => Some(Self::Type),
            0x19 => Some(Self::Field),
            0x1a => Some(Self::Method),
            0x1b => Some(Self::Enum),
            0x1c => Some(Self::Annotation),
            0x1e => Some(Self::Null),
            0x1f => Some(Self::Boolean),
            _ => None,
        }
    }

    /// Returns `true` if this value type is a reference.
    #[must_use]
    pub const fn is_reference(self) -> bool {
        matches!(
            self,
            Self::String | Self::Type | Self::Field | Self::Method | Self::Enum | Self::Annotation
        )
    }
}

// ---------------------------------------------------------------------------
// DEX constant pool IDs
// ---------------------------------------------------------------------------

/// DEX method-handle kinds (DEX 038+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DexMethodHandleKind {
    StaticPut = 0x00,
    StaticGet = 0x01,
    InstancePut = 0x02,
    InstanceGet = 0x03,
    InvokeStatic = 0x04,
    InvokeInstance = 0x05,
    InvokeConstructor = 0x06,
    InvokeDirect = 0x07,
    InvokeInterface = 0x08,
}

impl DexMethodHandleKind {
    /// Decode from raw `u16`.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x00 => Some(Self::StaticPut),
            0x01 => Some(Self::StaticGet),
            0x02 => Some(Self::InstancePut),
            0x03 => Some(Self::InstanceGet),
            0x04 => Some(Self::InvokeStatic),
            0x05 => Some(Self::InvokeInstance),
            0x06 => Some(Self::InvokeConstructor),
            0x07 => Some(Self::InvokeDirect),
            0x08 => Some(Self::InvokeInterface),
            _ => None,
        }
    }

    /// Returns `true` if this is an invocation kind.
    #[must_use]
    pub const fn is_invoke(self) -> bool {
        matches!(
            self,
            Self::InvokeStatic
                | Self::InvokeInstance
                | Self::InvokeConstructor
                | Self::InvokeDirect
                | Self::InvokeInterface
        )
    }
}

// ---------------------------------------------------------------------------
// DEX call graph analysis
// ---------------------------------------------------------------------------

/// An entry in a DEX call graph for a method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexCallSite {
    /// Caller method descriptor.
    pub caller: String,
    /// Callee reference as encoded in the instruction.
    pub callee_ref: u32,
    /// Type of invoke instruction.
    pub invoke_type: &'static str,
    /// Byte offset of the invoke instruction within the method body.
    pub offset: usize,
}

/// Extract call sites from a raw DEX method body.
///
/// Returns a list of all invoke-* instruction locations.
///
/// # Errors
///
/// Returns `DexDecodeError` on decode failure.
pub fn dex_extract_call_sites(
    caller: &str,
    code: &[u8],
) -> Result<Vec<DexCallSite>, DexDecodeError> {
    let mut sites = Vec::new();
    let mut off = 0;
    while off < code.len() {
        let (mne, ops, sz, _flags) =
            decode_dex(&code[off..]).map_err(|_| DexDecodeError::Truncated)?;
        if mne.starts_with("invoke-") {
            // Extract the method reference index from operands
            let ref_idx = ops
                .split(',')
                .next_back()
                .and_then(|s| s.trim().trim_start_matches('#').parse::<u32>().ok())
                .unwrap_or(0);
            sites.push(DexCallSite {
                caller: caller.to_string(),
                callee_ref: ref_idx,
                invoke_type: match mne.as_str() {
                    "invoke-virtual" => "virtual",
                    "invoke-static" => "static",
                    "invoke-direct" => "direct",
                    "invoke-super" => "super",
                    "invoke-interface" => "interface",
                    _ => "unknown",
                },
                offset: off,
            });
        }
        off += sz;
    }
    Ok(sites)
}

// ---------------------------------------------------------------------------
// Tests for extended functionality
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dex_extra_tests {
    use super::*;

    #[test]
    fn test_internal_to_java() {
        assert_eq!(
            dex_internal_to_java_name("java/lang/String"),
            "java.lang.String"
        );
    }

    #[test]
    fn test_java_to_descriptor() {
        assert_eq!(
            java_name_to_dex_descriptor("java.lang.String"),
            "Ljava/lang/String;"
        );
    }

    #[test]
    fn test_simple_class_name() {
        assert_eq!(dex_simple_class_name("Ljava/lang/String;"), "String");
    }

    #[test]
    fn test_simple_class_name_no_package() {
        assert_eq!(dex_simple_class_name("LMyClass;"), "MyClass");
    }

    #[test]
    fn test_instr_cost_nop() {
        assert_eq!(dex_instr_cost("nop"), 0);
    }

    #[test]
    fn test_instr_cost_invoke_virtual() {
        assert!(dex_instr_cost("invoke-virtual") > dex_instr_cost("add-int"));
    }

    #[test]
    fn test_complexity_metrics() {
        // return-void
        let code = [0x0e_u8, 0x00];
        let m = DexComplexityMetrics::from_bytes(&code).unwrap();
        assert_eq!(m.cyclomatic, 1);
        assert_eq!(m.instruction_count, 1);
    }

    #[test]
    fn test_calling_conv_this() {
        let cc = DexCallingConv::compute(5, 2, true);
        assert_eq!(cc.this_register(), Some(3));
    }

    #[test]
    fn test_calling_conv_param() {
        let cc = DexCallingConv::compute(5, 2, true);
        assert_eq!(cc.param_register(0), Some(4));
    }

    #[test]
    fn test_smali_reg() {
        assert_eq!(smali_reg(3), "v3");
    }

    #[test]
    fn test_smali_method_ref() {
        let r = smali_method_ref("Ljava/lang/String;", "length", "()I");
        assert_eq!(r, "Ljava/lang/String;->length()I");
    }

    #[test]
    fn test_smali_field_ref() {
        let r = smali_field_ref("Lcom/example/Foo;", "bar", "I");
        assert_eq!(r, "Lcom/example/Foo;->bar:I");
    }

    #[test]
    fn test_annotation_value_type_int() {
        let t = DexAnnotationValueType::from_byte(0x04).unwrap();
        assert_eq!(t, DexAnnotationValueType::Int);
        assert!(!t.is_reference());
    }

    #[test]
    fn test_annotation_value_type_string() {
        let t = DexAnnotationValueType::from_byte(0x17).unwrap();
        assert!(t.is_reference());
    }

    #[test]
    fn test_annotation_value_type_unknown() {
        assert!(DexAnnotationValueType::from_byte(0x0F).is_none());
    }

    #[test]
    fn test_method_handle_kind() {
        let k = DexMethodHandleKind::from_u16(0x04).unwrap();
        assert_eq!(k, DexMethodHandleKind::InvokeStatic);
        assert!(k.is_invoke());
    }

    #[test]
    fn test_method_handle_kind_static_put_not_invoke() {
        let k = DexMethodHandleKind::from_u16(0x00).unwrap();
        assert!(!k.is_invoke());
    }

    #[test]
    fn test_method_handle_kind_unknown() {
        assert!(DexMethodHandleKind::from_u16(0x09).is_none());
    }

    #[test]
    fn test_call_sites_return_void() {
        // Just return-void – no calls
        let code = [0x0e_u8, 0x00];
        let sites = dex_extract_call_sites("LFoo;->bar()V", &code).unwrap();
        assert!(sites.is_empty());
    }

    #[test]
    fn test_code_item_has_try_blocks() {
        let h = DexCodeItemHeader {
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            tries_size: 1,
            debug_info_off: 0,
            insns_size: 4,
        };
        assert!(h.has_try_blocks());
    }

    #[test]
    fn test_code_item_no_try_blocks() {
        let h = DexCodeItemHeader {
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            tries_size: 0,
            debug_info_off: 0,
            insns_size: 4,
        };
        assert!(!h.has_try_blocks());
    }

    #[test]
    fn test_param_count_array() {
        // ([B)V = one array param
        assert_eq!(dex_param_count("([B)V"), 1);
    }

    #[test]
    fn test_dex_opcode_ref_sget() {
        let e = lookup_dex_opcode(0x60).unwrap();
        assert_eq!(e.mnemonic, "sget");
        assert!(e.flags().contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_annotation_visibility_build() {
        let v = DexAnnotationVisibility::from_byte(0).unwrap();
        assert_eq!(v.name(), "build");
    }
}

// ---------------------------------------------------------------------------
// DEX well-known Android API methods
// ---------------------------------------------------------------------------

/// A well-known Android/Java API method reference.
#[derive(Debug, Clone, Copy)]
pub struct DexWellKnownMethod {
    /// DEX descriptor of the class.
    pub class: &'static str,
    /// Method name.
    pub method: &'static str,
    /// Method prototype (e.g., `"(I)Ljava/lang/String;"`).
    pub proto: &'static str,
    /// Short description.
    pub description: &'static str,
}

/// Well-known Android/Java API methods referenced in DEX analysis.
pub static DEX_WELL_KNOWN_METHODS: &[DexWellKnownMethod] = &[
    DexWellKnownMethod {
        class: "Landroid/util/Log;",
        method: "d",
        proto: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.d (debug)",
    },
    DexWellKnownMethod {
        class: "Landroid/util/Log;",
        method: "i",
        proto: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.i (info)",
    },
    DexWellKnownMethod {
        class: "Landroid/util/Log;",
        method: "e",
        proto: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.e (error)",
    },
    DexWellKnownMethod {
        class: "Landroid/util/Log;",
        method: "w",
        proto: "(Ljava/lang/String;Ljava/lang/String;)I",
        description: "Log.w (warning)",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "length",
        proto: "()I",
        description: "String.length",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "equals",
        proto: "(Ljava/lang/Object;)Z",
        description: "String.equals",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "charAt",
        proto: "(I)C",
        description: "String.charAt",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "substring",
        proto: "(II)Ljava/lang/String;",
        description: "String.substring",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "indexOf",
        proto: "(I)I",
        description: "String.indexOf",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "contains",
        proto: "(Ljava/lang/CharSequence;)Z",
        description: "String.contains",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "startsWith",
        proto: "(Ljava/lang/String;)Z",
        description: "String.startsWith",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "endsWith",
        proto: "(Ljava/lang/String;)Z",
        description: "String.endsWith",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/String;",
        method: "trim",
        proto: "()Ljava/lang/String;",
        description: "String.trim",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/Integer;",
        method: "parseInt",
        proto: "(Ljava/lang/String;)I",
        description: "Integer.parseInt",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/Integer;",
        method: "valueOf",
        proto: "(I)Ljava/lang/Integer;",
        description: "Integer.valueOf",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/Object;",
        method: "toString",
        proto: "()Ljava/lang/String;",
        description: "Object.toString",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/Object;",
        method: "equals",
        proto: "(Ljava/lang/Object;)Z",
        description: "Object.equals",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/Object;",
        method: "hashCode",
        proto: "()I",
        description: "Object.hashCode",
    },
    DexWellKnownMethod {
        class: "Ljava/util/ArrayList;",
        method: "<init>",
        proto: "()V",
        description: "ArrayList constructor",
    },
    DexWellKnownMethod {
        class: "Ljava/util/ArrayList;",
        method: "add",
        proto: "(Ljava/lang/Object;)Z",
        description: "ArrayList.add",
    },
    DexWellKnownMethod {
        class: "Ljava/util/ArrayList;",
        method: "get",
        proto: "(I)Ljava/lang/Object;",
        description: "ArrayList.get",
    },
    DexWellKnownMethod {
        class: "Ljava/util/ArrayList;",
        method: "size",
        proto: "()I",
        description: "ArrayList.size",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/StringBuilder;",
        method: "<init>",
        proto: "()V",
        description: "StringBuilder constructor",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/StringBuilder;",
        method: "append",
        proto: "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        description: "StringBuilder.append",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/StringBuilder;",
        method: "toString",
        proto: "()Ljava/lang/String;",
        description: "StringBuilder.toString",
    },
    DexWellKnownMethod {
        class: "Landroid/content/Context;",
        method: "getSystemService",
        proto: "(Ljava/lang/String;)Ljava/lang/Object;",
        description: "Context.getSystemService",
    },
    DexWellKnownMethod {
        class: "Landroid/content/Intent;",
        method: "<init>",
        proto: "(Landroid/content/Context;Ljava/lang/Class;)V",
        description: "Intent constructor",
    },
    DexWellKnownMethod {
        class: "Landroid/app/Activity;",
        method: "onCreate",
        proto: "(Landroid/os/Bundle;)V",
        description: "Activity.onCreate",
    },
    DexWellKnownMethod {
        class: "Landroid/app/Activity;",
        method: "startActivity",
        proto: "(Landroid/content/Intent;)V",
        description: "Activity.startActivity",
    },
    DexWellKnownMethod {
        class: "Ljava/lang/System;",
        method: "exit",
        proto: "(I)V",
        description: "System.exit",
    },
];

/// Look up a well-known method.
#[must_use]
pub fn lookup_dex_method(class: &str, method: &str) -> Option<&'static DexWellKnownMethod> {
    DEX_WELL_KNOWN_METHODS
        .iter()
        .find(|m| m.class == class && m.method == method)
}

// ---------------------------------------------------------------------------
// DEX packed-switch / sparse-switch payload helpers
// ---------------------------------------------------------------------------

/// The payload identifier for a packed-switch payload.
pub const DEX_PACKED_SWITCH_IDENT: u16 = 0x0100;
/// The payload identifier for a sparse-switch payload.
pub const DEX_SPARSE_SWITCH_IDENT: u16 = 0x0200;
/// The payload identifier for a fill-array-data payload.
pub const DEX_FILL_ARRAY_DATA_IDENT: u16 = 0x0300;

/// Returns the size in 16-bit code units of a packed-switch payload.
///
/// Formula: `2 + size` (where `size` is the number of entries).
#[must_use]
pub const fn packed_switch_payload_size(entries: u16) -> u32 {
    4 + entries as u32 * 2
}

/// Returns the size in 16-bit code units of a sparse-switch payload.
///
/// Formula: `2 + size * 4` (where `size` is the number of entries).
#[must_use]
pub const fn sparse_switch_payload_size(entries: u16) -> u32 {
    2 + entries as u32 * 4
}

// ---------------------------------------------------------------------------
// DEX register liveness (simplified)
// ---------------------------------------------------------------------------

/// Simple register usage bitmask (supports up to 64 registers).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DexRegSet(pub u64);

impl DexRegSet {
    /// Mark register `r` as live.
    pub const fn set(&mut self, r: u8) {
        if r < 64 {
            self.0 |= 1u64 << r;
        }
    }

    /// Clear register `r`.
    pub const fn clear(&mut self, r: u8) {
        if r < 64 {
            self.0 &= !(1u64 << r);
        }
    }

    /// Returns `true` if register `r` is live.
    #[must_use]
    pub const fn contains(self, r: u8) -> bool {
        if r >= 64 {
            return false;
        }
        (self.0 >> r) & 1 == 1
    }

    /// Returns the number of live registers.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` if no registers are live.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// Tests for new functionality
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dex_final_tests {
    use super::*;

    #[test]
    fn test_well_known_method_log_d() {
        let m = lookup_dex_method("Landroid/util/Log;", "d").unwrap();
        assert!(m.description.contains("debug"));
    }

    #[test]
    fn test_well_known_method_string_length() {
        let m = lookup_dex_method("Ljava/lang/String;", "length").unwrap();
        assert_eq!(m.proto, "()I");
    }

    #[test]
    fn test_well_known_method_missing() {
        assert!(lookup_dex_method("LFake;", "nothing").is_none());
    }

    #[test]
    fn test_well_known_method_table_size() {
        assert!(DEX_WELL_KNOWN_METHODS.len() >= 25);
    }

    #[test]
    fn test_packed_switch_size() {
        assert_eq!(packed_switch_payload_size(3), 10);
    }

    #[test]
    fn test_sparse_switch_size() {
        assert_eq!(sparse_switch_payload_size(2), 10);
    }

    #[test]
    fn test_packed_switch_ident() {
        assert_eq!(DEX_PACKED_SWITCH_IDENT, 0x0100);
    }

    #[test]
    fn test_sparse_switch_ident() {
        assert_eq!(DEX_SPARSE_SWITCH_IDENT, 0x0200);
    }

    #[test]
    fn test_reg_set_set_contains() {
        let mut rs = DexRegSet::default();
        rs.set(3);
        assert!(rs.contains(3));
        assert!(!rs.contains(4));
    }

    #[test]
    fn test_reg_set_clear() {
        let mut rs = DexRegSet::default();
        rs.set(5);
        rs.clear(5);
        assert!(!rs.contains(5));
    }

    #[test]
    fn test_reg_set_count() {
        let mut rs = DexRegSet::default();
        rs.set(0);
        rs.set(7);
        rs.set(15);
        assert_eq!(rs.count(), 3);
    }

    #[test]
    fn test_reg_set_is_empty() {
        assert!(DexRegSet::default().is_empty());
    }

    #[test]
    fn test_reg_set_out_of_range() {
        let mut rs = DexRegSet::default();
        rs.set(200); // should not panic
        assert!(!rs.contains(200));
    }

    #[test]
    fn test_calling_conv_static() {
        let cc = DexCallingConv::compute(4, 2, false);
        assert_eq!(cc.this_register(), None);
        assert_eq!(cc.param_register(0), Some(2));
    }

    #[test]
    fn test_complexity_with_branch() {
        // nop (0x00,0x00), then return-void (0x0e,0x00)
        let code = [0x00_u8, 0x00, 0x0e, 0x00];
        let m = DexComplexityMetrics::from_bytes(&code).unwrap();
        assert_eq!(m.instruction_count, 2);
        assert_eq!(m.cyclomatic, 1);
    }

    #[test]
    fn test_string_descriptor_roundtrip() {
        let desc = java_name_to_dex_descriptor("java.lang.Object");
        assert_eq!(desc, "Ljava/lang/Object;");
        let back = dex_internal_to_java_name("java/lang/Object");
        assert_eq!(back, "java.lang.Object");
    }

    #[test]
    fn test_instr_cost_new_instance() {
        assert!(dex_instr_cost("new-instance") > dex_instr_cost("nop"));
    }
}
