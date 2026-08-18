//! `rustre-symbols-dwarf`
//!
//! DWARF debug-information reader offering two parser paths:
//!
//! * **Hand-written parser (primary).** [`DwarfReader`] parses `.debug_info`,
//!   `.debug_abbrev`, `.debug_str`, `.debug_line_str`, `.debug_line` and
//!   `.debug_ranges` directly from an ELF binary, with no `gimli` involvement.
//!   It handles DWARF 2 through 5 compilation units, and is little-endian only.
//! * **gimli-backed reader (§7.2).** [`GimliDwarfReader`] uses the `gimli` and
//!   `object` crates for ELF/Mach-O section loading and richer DWARF 4/5
//!   support (`.debug_str_offsets`, `.debug_addr`, …). It is also
//!   little-endian only; big-endian containers are rejected rather than
//!   mis-parsed.
//!
//! Note that this crate therefore does depend on `gimli` and `object` (see
//! `Cargo.toml`); it is not suitable for a dependency-free or `no_std` target.
//!
//! # Supported structures
//! * DWARF 4 / 5 compilation units (`DW_TAG_compile_unit`)
//! * `DW_TAG_subprogram` â†' `DwarfFunction`
//! * `DW_TAG_variable` / `DW_TAG_formal_parameter` â†' `DwarfVariable`
//! * `DW_TAG_base_type`, `DW_TAG_pointer_type`, `DW_TAG_typedef`,
//!   `DW_TAG_structure_type`, `DW_TAG_union_type`, `DW_TAG_array_type`
//!   â†' `DwarfType`
//! * `.debug_line` state machine â†' `LineEntry`
//! * `DW_FORM_exprloc` / `DW_FORM_block` location expressions â†'
//!   `DwarfLocation`
//!
//! # `unsafe` policy
//!
//! Two `unsafe` blocks live in `from_bytes_inner` and the `load_section`
//! closure defined inside it. They are essential and
//! cannot be removed without re-introducing the `Box::leak` memory bug that
//! the current design was specifically rewritten to avoid:
//!
//! * `gimli::Dwarf` and `EndianSlice` are parameterised by a single lifetime
//!   that must be `'static` to be stored alongside their backing storage in
//!   the same struct.
//! * We forge `'static` references over a `Box<[u8]>` (and, for compressed
//!   sections, a `Vec<Box<[u8]>>`) that live in the same struct as the
//!   `Dwarf` view. Field drop order is **`dwarf` before `buffer` before
//!   `_compressed`**, ensuring the forged slices never outlive their
//!   storage. The `Drop` impl in this file documents the invariant.
//!
//! The workspace-wide `unsafe_code = "warn"` lint is acknowledged at crate
//! scope below because both sites are inherent to the gimli integration,
//! not incidental.
#![allow(unsafe_code, reason = "both unsafe sites are inherent to the gimli integration, not incidental; removing the allow would mean deleting the integration")]
#![warn(missing_docs)]

pub mod casts;
pub mod dwarf_abbrev;
pub mod dwarf_call_frame;
pub mod dwarf_expression_evaluator;
pub mod dwarf_line_program;
pub mod dwarf_location_expr;
pub mod dwarf_type_decoder;
pub mod dwarf_type_parser;
pub mod dwarf_type_reader;
pub mod dwarf_unwind;
pub mod line_program;
pub mod location_expr;
pub mod split_dwarf;
pub mod type_units;

use std::{collections::HashMap, fs, path::Path, rc::Rc, sync::OnceLock};

use thiserror::Error;

// â"€â"€ Error type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors returned by the DWARF reader.
#[derive(Debug, Error)]
pub enum DwarfError {
    /// A filesystem I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The input is not a supported binary format (ELF/Mach-O).
    #[error("Not a supported binary format (ELF/Mach-O)")]
    UnsupportedFormat,
    /// The DWARF data is structurally invalid.
    #[error("Malformed DWARF data")]
    MalformedDwarf,
    /// A required debug section is missing from the binary.
    #[error("Section not found: {0}")]
    SectionMissing(String),
    /// The data ended before a complete structure could be read.
    #[error("Unexpected end of data")]
    UnexpectedEof,
}

/// Convenience alias for results using [`DwarfError`].
pub type Result<T> = std::result::Result<T, DwarfError>;

// â"€â"€ Public API types â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Location of a variable / parameter.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DwarfLocation {
    /// Offset from the subprogram's frame base (`DW_OP_fbreg`). The base itself
    /// is given by `DW_AT_frame_base` and is deliberately left unresolved here:
    /// resolving `DW_OP_call_frame_cfa` requires `.eh_frame` CFI, not the DIE.
    FrameOffset(i64),
    /// Value is in a machine register (DWARF reg number).
    Register(u32),
    /// Value is at `[register + offset]`.
    MemoryOffset {
        /// DWARF register number holding the base address.
        register: u32,
        /// Signed byte offset added to the register value.
        offset: i64,
    },
    /// Compile-time constant value.
    Constant(u64),
    /// Location expression was present but could not be decoded.
    Unknown,
}

/// A variable or function parameter extracted from DWARF.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DwarfVariable {
    /// Source-level variable name.
    pub name: String,
    /// Human-readable type name.
    pub type_name: String,
    /// Where the value lives at runtime.
    pub location: DwarfLocation,
}

/// A function / subprogram extracted from DWARF.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DwarfFunction {
    /// Function name (`DW_AT_name`).
    pub name: String,
    /// Start address of the function body (`DW_AT_low_pc`).
    pub low_pc: u64,
    /// End address of the function body, exclusive (`DW_AT_high_pc`).
    pub high_pc: u64,
    /// Formal parameters in declaration order.
    pub parameters: Vec<DwarfVariable>,
    /// Return type name, if the function is not `void`.
    pub return_type: Option<String>,
}

/// A type definition extracted from DWARF.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DwarfType {
    /// Type name (`DW_AT_name`).
    pub name: String,
    /// Size in bytes (`DW_AT_byte_size`; 0 if unknown).
    pub byte_size: u32,
    /// Broad category of the type.
    pub tag: DwarfTypeTag,
}

/// Broad category of a DWARF type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DwarfTypeTag {
    /// `DW_TAG_base_type` (fundamental scalar type).
    Base,
    /// `DW_TAG_pointer_type`.
    Pointer,
    /// `DW_TAG_typedef`.
    Typedef,
    /// `DW_TAG_structure_type`.
    Struct,
    /// `DW_TAG_union_type`.
    Union,
    /// `DW_TAG_array_type`.
    Array,
    /// Any other DWARF type tag.
    Other,
}

/// A source-line mapping entry from `.debug_line`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LineEntry {
    /// Machine address this row describes.
    pub address: u64,
    /// Resolved source file name.
    pub file: String,
    /// 1-based source line number.
    pub line: u32,
    /// 1-based source column (0 if unspecified).
    pub column: u32,
}

// â"€â"€ DWARF constants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

// Tags
const DW_TAG_COMPILE_UNIT: u64 = 0x11;
const DW_TAG_SUBPROGRAM: u64 = 0x2e;
const DW_TAG_VARIABLE: u64 = 0x34;
const DW_TAG_FORMAL_PARAMETER: u64 = 0x05;
const DW_TAG_BASE_TYPE: u64 = 0x24;
const DW_TAG_POINTER_TYPE: u64 = 0x0f;
const DW_TAG_TYPEDEF: u64 = 0x16;
const DW_TAG_STRUCTURE_TYPE: u64 = 0x13;
const DW_TAG_UNION_TYPE: u64 = 0x17;
const DW_TAG_ARRAY_TYPE: u64 = 0x01;

// Attributes
const DW_AT_NAME: u64 = 0x03;
const DW_AT_LOW_PC: u64 = 0x11;
const DW_AT_HIGH_PC: u64 = 0x12;
const DW_AT_TYPE: u64 = 0x49;
const DW_AT_LOCATION: u64 = 0x02;
const DW_AT_BYTE_SIZE: u64 = 0x0b;
const DW_AT_ABSTRACT_ORIGIN: u64 = 0x31;
const DW_AT_SPECIFICATION: u64 = 0x47;
/// Compilation directory attribute —" used when resolving file paths in DIEs.
const DW_AT_COMP_DIR: u64 = 0x1b;

// Forms
const DW_FORM_ADDR: u64 = 0x01;
const DW_FORM_BLOCK1: u64 = 0x0a;
const DW_FORM_BLOCK2: u64 = 0x03;
const DW_FORM_BLOCK4: u64 = 0x04;
const DW_FORM_DATA1: u64 = 0x0b;
const DW_FORM_DATA2: u64 = 0x05;
const DW_FORM_DATA4: u64 = 0x06;
const DW_FORM_DATA8: u64 = 0x07;
const DW_FORM_STRING: u64 = 0x08;
const DW_FORM_STRP: u64 = 0x0e;
const DW_FORM_REF1: u64 = 0x11;
const DW_FORM_REF2: u64 = 0x12;
const DW_FORM_REF4: u64 = 0x13;
const DW_FORM_REF8: u64 = 0x14;
const DW_FORM_REF_UDATA: u64 = 0x15;
const DW_FORM_UDATA: u64 = 0x0f;
const DW_FORM_SDATA: u64 = 0x0d;
const DW_FORM_FLAG: u64 = 0x0c;
const DW_FORM_FLAG_PRESENT: u64 = 0x19;
const DW_FORM_EXPRLOC: u64 = 0x18;
const DW_FORM_SEC_OFFSET: u64 = 0x17;
const DW_FORM_INDIRECT: u64 = 0x16;
const DW_FORM_REF_ADDR: u64 = 0x10;
const DW_FORM_BLOCK: u64 = 0x09;
const DW_FORM_STRX: u64 = 0x1a;
const DW_FORM_ADDRX: u64 = 0x1b;
const DW_FORM_LINE_STRP: u64 = 0x1f;
const DW_FORM_REF_SUP4: u64 = 0x1c;
const DW_FORM_STRP_SUP: u64 = 0x1d;
const DW_FORM_DATA16: u64 = 0x1e;
const DW_FORM_REF_SIG8: u64 = 0x20;
const DW_FORM_IMPLICIT_CONST: u64 = 0x21;
const DW_FORM_LOCLISTX: u64 = 0x22;
const DW_FORM_RNGLISTX: u64 = 0x23;
const DW_FORM_REF_SUP8: u64 = 0x24;
const DW_FORM_STRX1: u64 = 0x25;
const DW_FORM_STRX2: u64 = 0x26;
const DW_FORM_STRX3: u64 = 0x27;
const DW_FORM_STRX4: u64 = 0x28;
const DW_FORM_ADDRX1: u64 = 0x29;
const DW_FORM_ADDRX2: u64 = 0x2a;
const DW_FORM_ADDRX3: u64 = 0x2b;
const DW_FORM_ADDRX4: u64 = 0x2c;

/// Maximum DIE-tree / type-chain recursion depth. Malformed `.debug_info` can
/// otherwise drive unbounded recursion and overflow the stack (uncatchable).
const MAX_DIE_DEPTH: usize = 256;
/// Maximum `DW_AT_type` chain length followed when naming a type.
const MAX_TYPE_CHAIN_DEPTH: usize = 128;
/// Maximum `DW_FORM_indirect` chain length (each link is one byte in the file).
const MAX_INDIRECT_CHAIN: usize = 8;

// Location ops
const DW_OP_REG0: u8 = 0x50;
const DW_OP_REG31: u8 = 0x6f;
const DW_OP_BREG0: u8 = 0x77;
const DW_OP_BREG31: u8 = 0x96;
const DW_OP_FBREG: u8 = 0x91;
const DW_OP_CONST1U: u8 = 0x08;
const DW_OP_CONST2U: u8 = 0x0a;
const DW_OP_CONST4U: u8 = 0x0c;
const DW_OP_CONST8U: u8 = 0x0e;
const DW_OP_CONSTU: u8 = 0x10;
const DW_OP_LIT0: u8 = 0x30;
const DW_OP_LIT31: u8 = 0x4f;
const DW_OP_REGX: u8 = 0x90;

// â"€â"€ Byte reading helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8> {
    data.get(*off)
        .copied()
        .inspect(|_b| {
            *off += 1;
        })
        .ok_or(DwarfError::UnexpectedEof)
}

fn read_u16_le(data: &[u8], off: &mut usize) -> Result<u16> {
    if *off + 2 > data.len() {
        return Err(DwarfError::UnexpectedEof);
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32_le(data: &[u8], off: &mut usize) -> Result<u32> {
    if *off + 4 > data.len() {
        return Err(DwarfError::UnexpectedEof);
    }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], off: &mut usize) -> Result<u64> {
    if *off + 8 > data.len() {
        return Err(DwarfError::UnexpectedEof);
    }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn read_uleb128(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = read_u8(data, off)?;
        if shift >= 64 {
            return Err(DwarfError::MalformedDwarf);
        }
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(result)
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Result<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    // `b` is updated on every iteration; the initial value is never read.
    let b = loop {
        let byte = read_u8(data, off)?;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break byte;
        }
        if shift >= 64 {
            return Err(DwarfError::MalformedDwarf);
        }
    };
    // Sign-extend if the high bit of the last byte was set.
    if shift < 64 && (b & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

fn read_cstring(data: &[u8], off: &mut usize) -> Result<String> {
    let start = *off;
    while *off < data.len() && data[*off] != 0 {
        *off += 1;
    }
    if *off >= data.len() {
        // No terminating NUL was found before the end of the buffer.
        return Err(DwarfError::UnexpectedEof);
    }
    let s = String::from_utf8_lossy(&data[start..*off]).into_owned();
    *off += 1; // skip null
    Ok(s)
}

// â"€â"€ ELF section extractor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Extract named sections from an ELF binary. Returns a map of section name â†'
/// raw bytes.  Supports 32-bit and 64-bit little-endian ELF only (the most
/// common case for DWARF debugging).
fn elf_sections(raw: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    if raw.len() < 16 {
        return Err(DwarfError::UnsupportedFormat);
    }
    if raw[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(DwarfError::UnsupportedFormat);
    }
    let ei_class = raw[4]; // 1=32-bit, 2=64-bit
    let ei_data = raw[5]; // 1=LE, 2=BE
    if ei_data != 1 {
        return Err(DwarfError::UnsupportedFormat);
    } // only LE

    let mut map: HashMap<String, Vec<u8>> = HashMap::new();
    match ei_class {
        1 => {
            // 32-bit ELF
            let e_shoff = {
                let mut o = 32usize;
                read_u32_le(raw, &mut o)? as usize
            };
            let mut o2 = 40usize;
            let _flags = read_u32_le(raw, &mut o2)?;
            let _ehsize = read_u16_le(raw, &mut o2)?;
            let _phentsize = read_u16_le(raw, &mut o2)?;
            let _phnum = read_u16_le(raw, &mut o2)?;
            let e_shentsize = read_u16_le(raw, &mut o2)? as usize;
            let e_shnum = read_u16_le(raw, &mut o2)? as usize;
            let e_shstrndx = read_u16_le(raw, &mut o2)? as usize;

            // Read shstrtab section header.
            let shstr_hdr = e_shoff
                .checked_add(e_shstrndx.checked_mul(e_shentsize).ok_or(DwarfError::MalformedDwarf)?)
                .ok_or(DwarfError::MalformedDwarf)?;
            let mut sh = shstr_hdr.checked_add(16).ok_or(DwarfError::MalformedDwarf)?;
            let shstr_off = read_u32_le(raw, &mut sh)? as usize;
            let shstr_size = read_u32_le(raw, &mut sh)? as usize;
            let shstrtab = raw.get(shstr_off..shstr_off + shstr_size).unwrap_or(&[]);

            for i in 0..e_shnum {
                let hdr = e_shoff
                    .checked_add(i.checked_mul(e_shentsize).ok_or(DwarfError::MalformedDwarf)?)
                    .ok_or(DwarfError::MalformedDwarf)?;
                let mut h = hdr;
                let sh_name = read_u32_le(raw, &mut h)? as usize;
                let _sh_type = read_u32_le(raw, &mut h)?;
                let _flags = read_u32_le(raw, &mut h)?;
                let _addr = read_u32_le(raw, &mut h)?;
                let sh_offset = read_u32_le(raw, &mut h)? as usize;
                let sh_size = read_u32_le(raw, &mut h)? as usize;

                let name_end = shstrtab.get(sh_name..)
                    .and_then(|s| s.iter().position(|&b| b == 0).map(|p| sh_name + p))
                    .unwrap_or(shstrtab.len());
                let name = String::from_utf8_lossy(shstrtab.get(sh_name..name_end).unwrap_or(b"")).into_owned();
                if let Some(data) = raw.get(sh_offset..sh_offset + sh_size) {
                    map.insert(name, data.to_vec());
                }
            }
        }
        2 => {
            // 64-bit ELF
            let e_shoff = {
                let mut o = 40usize;
                usize::try_from(read_u64_le(raw, &mut o)?).unwrap_or(usize::MAX)
            };
            let mut o2 = 58usize;
            let e_shentsize = usize::from(read_u16_le(raw, &mut o2)?);
            let e_shnum = usize::from(read_u16_le(raw, &mut o2)?);
            let e_shstrndx = usize::from(read_u16_le(raw, &mut o2)?);

            let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
            let mut sh = shstr_hdr + 24;
            let shstr_off = usize::try_from(read_u64_le(raw, &mut sh)?).unwrap_or(usize::MAX);
            let shstr_size = usize::try_from(read_u64_le(raw, &mut sh)?).unwrap_or(usize::MAX);
            let shstrtab = raw.get(shstr_off..shstr_off + shstr_size).unwrap_or(&[]);

            for i in 0..e_shnum {
                let hdr = e_shoff + i * e_shentsize;
                let mut h = hdr;
                let sh_name = read_u32_le(raw, &mut h)? as usize;
                let _sh_type = read_u32_le(raw, &mut h)?;
                let _flags = read_u64_le(raw, &mut h)?;
                let _addr = read_u64_le(raw, &mut h)?;
                let sh_offset = usize::try_from(read_u64_le(raw, &mut h)?).unwrap_or(usize::MAX);
                let sh_size = usize::try_from(read_u64_le(raw, &mut h)?).unwrap_or(usize::MAX);

                let name_end = shstrtab.get(sh_name..).and_then(|s| {
                    s.iter().position(|&b| b == 0).map(|p| sh_name + p)
                }).unwrap_or_else(|| shstrtab.len().min(sh_name));
                let name = String::from_utf8_lossy(shstrtab.get(sh_name..name_end).unwrap_or(&[])).into_owned();
                if let Some(data) = raw.get(sh_offset..sh_offset + sh_size) {
                    map.insert(name, data.to_vec());
                }
            }
        }
        _ => return Err(DwarfError::UnsupportedFormat),
    }
    Ok(map)
}

// â"€â"€ Abbreviation table â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
struct AbbrevEntry {
    tag: u64,
    has_children: bool,
    /// (attribute, form, `implicit_const` value for `DW_FORM_implicit_const`)
    attrs: Vec<(u64, u64, Option<i64>)>,
}

fn parse_abbrev_table(data: &[u8]) -> Result<HashMap<u64, AbbrevEntry>> {
    let mut map = HashMap::new();
    let mut off = 0usize;
    loop {
        if off >= data.len() {
            break;
        }
        let code = read_uleb128(data, &mut off)?;
        if code == 0 {
            break;
        }
        let tag = read_uleb128(data, &mut off)?;
        let has_children = read_u8(data, &mut off)? != 0;
        let mut attrs = Vec::new();
        loop {
            let attr = read_uleb128(data, &mut off)?;
            let form = read_uleb128(data, &mut off)?;
            if attr == 0 && form == 0 {
                break;
            }
            // DW_FORM_implicit_const (0x21) has an extra SLEB128 value that
            // lives in the abbrev table, not in .debug_info. It must be kept:
            // discarding it made the attribute unreadable at DIE-parse time.
            let implicit = if form == DW_FORM_IMPLICIT_CONST {
                Some(read_sleb128(data, &mut off)?)
            } else {
                None
            };
            attrs.push((attr, form, implicit));
        }
        map.insert(
            code,
            AbbrevEntry {
                tag,
                has_children,
                attrs,
            },
        );
    }
    Ok(map)
}

// â"€â"€ Attribute value â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Clone)]
enum AttrValue {
    /// Unsigned integer, also used for booleans, references, and addresses.
    Uint(u64),
    /// Signed integer (`DW_FORM_sdata`).
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
}

impl AttrValue {
    const fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            // Treat signed integers as unsigned when the caller asks.
            Self::Int(v) => Some((*v).cast_unsigned()),
            _ => None,
        }
    }
    fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

fn read_attr_value(
    data: &[u8],
    off: &mut usize,
    form: u64,
    addr_size: u8,
    is_64bit_dwarf: bool,
    debug_str: &[u8],
    debug_line_str: &[u8],
    cu_offset: usize,
    implicit_const: Option<i64>,
    depth: usize,
) -> Result<AttrValue> {
    let offset_size: usize = if is_64bit_dwarf { 8 } else { 4 };
    match form {
        DW_FORM_ADDR => {
            let v = if addr_size == 8 {
                read_u64_le(data, off)?
            } else {
                u64::from(read_u32_le(data, off)?)
            };
            Ok(AttrValue::Uint(v))
        }
        DW_FORM_DATA1 | DW_FORM_FLAG | DW_FORM_REF1 => {
            Ok(AttrValue::Uint(u64::from(read_u8(data, off)?)))
        }
        DW_FORM_DATA2 | DW_FORM_REF2 => Ok(AttrValue::Uint(u64::from(read_u16_le(data, off)?))),
        DW_FORM_DATA4 | DW_FORM_REF4 => Ok(AttrValue::Uint(u64::from(read_u32_le(data, off)?))),
        DW_FORM_DATA8 | DW_FORM_REF8 => Ok(AttrValue::Uint(read_u64_le(data, off)?)),
        DW_FORM_UDATA | DW_FORM_REF_UDATA | DW_FORM_STRX | DW_FORM_ADDRX => {
            Ok(AttrValue::Uint(read_uleb128(data, off)?))
        }
        DW_FORM_SDATA => Ok(AttrValue::Int(read_sleb128(data, off)?)),
        DW_FORM_STRING => Ok(AttrValue::String(read_cstring(data, off)?)),
        DW_FORM_STRP | DW_FORM_STRP_SUP => {
            let str_off = if offset_size == 8 {
                usize::try_from(read_u64_le(data, off)?).unwrap_or(usize::MAX)
            } else {
                read_u32_le(data, off)? as usize
            };
            let mut tmp = str_off;
            Ok(AttrValue::String(
                read_cstring(debug_str, &mut tmp).unwrap_or_default(),
            ))
        }
        // DW_FORM_line_strp indexes .debug_line_str, NOT .debug_str.
        DW_FORM_LINE_STRP => {
            let str_off = if offset_size == 8 {
                usize::try_from(read_u64_le(data, off)?).unwrap_or(usize::MAX)
            } else {
                read_u32_le(data, off)? as usize
            };
            let mut tmp = str_off;
            Ok(AttrValue::String(
                read_cstring(debug_line_str, &mut tmp).unwrap_or_default(),
            ))
        }
        DW_FORM_BLOCK1 => {
            let len = usize::from(read_u8(data, off)?);
            let bytes = data.get(*off..*off + len).ok_or(DwarfError::UnexpectedEof)?.to_vec();
            *off += len;
            Ok(AttrValue::Bytes(bytes))
        }
        DW_FORM_BLOCK2 => {
            let len = usize::from(read_u16_le(data, off)?);
            let bytes = data.get(*off..*off + len).ok_or(DwarfError::UnexpectedEof)?.to_vec();
            *off += len;
            Ok(AttrValue::Bytes(bytes))
        }
        DW_FORM_BLOCK4 => {
            let len = read_u32_le(data, off)? as usize;
            let bytes = data.get(*off..*off + len).ok_or(DwarfError::UnexpectedEof)?.to_vec();
            *off += len;
            Ok(AttrValue::Bytes(bytes))
        }
        DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
            let len = usize::try_from(read_uleb128(data, off)?).unwrap_or(usize::MAX);
            let end = off.checked_add(len).ok_or(DwarfError::UnexpectedEof)?;
            let bytes = data.get(*off..end).ok_or(DwarfError::UnexpectedEof)?.to_vec();
            *off = end;
            Ok(AttrValue::Bytes(bytes))
        }
        // DW_FORM_flag_present: no bytes, implicitly true â†' store as 1.
        DW_FORM_FLAG_PRESENT => Ok(AttrValue::Uint(1)),
        DW_FORM_SEC_OFFSET | DW_FORM_REF_ADDR => {
            let v = if offset_size == 8 {
                read_u64_le(data, off)?
            } else {
                u64::from(read_u32_le(data, off)?)
            };
            Ok(AttrValue::Uint(v))
        }
        // Fixed-size DWARF 5 forms. Previously all of these hit the catch-all
        // and errored, which desynchronised the DIE stream.
        DW_FORM_DATA16 => {
            let end = off.checked_add(16).ok_or(DwarfError::UnexpectedEof)?;
            let bytes = data.get(*off..end).ok_or(DwarfError::UnexpectedEof)?.to_vec();
            *off = end;
            Ok(AttrValue::Bytes(bytes))
        }
        DW_FORM_STRX1 | DW_FORM_ADDRX1 => Ok(AttrValue::Uint(u64::from(read_u8(data, off)?))),
        DW_FORM_STRX2 | DW_FORM_ADDRX2 => Ok(AttrValue::Uint(u64::from(read_u16_le(data, off)?))),
        DW_FORM_STRX3 | DW_FORM_ADDRX3 => {
            // 3-byte little-endian index; assembled manually.
            let b0 = u64::from(read_u8(data, off)?);
            let b1 = u64::from(read_u8(data, off)?);
            let b2 = u64::from(read_u8(data, off)?);
            Ok(AttrValue::Uint(b0 | (b1 << 8) | (b2 << 16)))
        }
        DW_FORM_STRX4 | DW_FORM_ADDRX4 => Ok(AttrValue::Uint(u64::from(read_u32_le(data, off)?))),
        DW_FORM_REF_SUP4 => Ok(AttrValue::Uint(u64::from(read_u32_le(data, off)?))),
        DW_FORM_REF_SIG8 | DW_FORM_REF_SUP8 => Ok(AttrValue::Uint(read_u64_le(data, off)?)),
        DW_FORM_LOCLISTX | DW_FORM_RNGLISTX => Ok(AttrValue::Uint(read_uleb128(data, off)?)),
        // Consumes zero bytes: the value lives in the abbreviation table.
        DW_FORM_IMPLICIT_CONST => Ok(AttrValue::Int(implicit_const.unwrap_or(0))),
        DW_FORM_INDIRECT => {
            if depth >= MAX_INDIRECT_CHAIN {
                return Err(DwarfError::MalformedDwarf);
            }
            let actual_form = read_uleb128(data, off)?;
            read_attr_value(
                data,
                off,
                actual_form,
                addr_size,
                is_64bit_dwarf,
                debug_str,
                debug_line_str,
                cu_offset,
                implicit_const,
                depth + 1,
            )
        }
        _ => {
            // Unknown form — we cannot know the size, so signal an error.
            let _ = cu_offset; // suppress unused-variable warning
            Err(DwarfError::MalformedDwarf)
        }
    }
}

// â"€â"€ Location expression decoder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn decode_location(expr: &[u8]) -> DwarfLocation {
    if expr.is_empty() {
        return DwarfLocation::Unknown;
    }
    let op = expr[0];
    match op {
        o if (DW_OP_REG0..=DW_OP_REG31).contains(&o) => {
            DwarfLocation::Register(u32::from(o - DW_OP_REG0))
        }
        DW_OP_REGX => {
            let mut off = 1;
            read_uleb128(expr, &mut off).map_or(DwarfLocation::Unknown, |reg| {
                DwarfLocation::Register(u32::try_from(reg).unwrap_or(u32::MAX))
            })
        }
        // DW_OP_FBREG (0x91) must be checked before the BREG range (0x77—"0x96)
        // because it falls within that numerical range.
        DW_OP_FBREG => {
            let mut off = 1;
            let offset = read_sleb128(expr, &mut off).unwrap_or(0);
            // The frame base is whatever the enclosing subprogram's
            // DW_AT_frame_base says — on modern x86-64 almost always
            // DW_OP_call_frame_cfa (rsp-based), NOT rbp, and on other
            // architectures register 6 is something else entirely. Report an
            // explicitly unresolved frame offset instead of naming a register
            // we have not established.
            DwarfLocation::FrameOffset(offset)
        }
        o if (DW_OP_BREG0..=DW_OP_BREG31).contains(&o) => {
            let reg = u32::from(o - DW_OP_BREG0);
            let mut off = 1;
            let offset = read_sleb128(expr, &mut off).unwrap_or(0);
            DwarfLocation::MemoryOffset {
                register: reg,
                offset,
            }
        }
        o if (DW_OP_LIT0..=DW_OP_LIT31).contains(&o) => {
            DwarfLocation::Constant(u64::from(o - DW_OP_LIT0))
        }
        DW_OP_CONST1U => expr.get(1).map_or(DwarfLocation::Unknown, |&v| {
            DwarfLocation::Constant(u64::from(v))
        }),
        DW_OP_CONST2U => {
            if expr.len() >= 3 {
                DwarfLocation::Constant(u64::from(u16::from_le_bytes([expr[1], expr[2]])))
            } else {
                DwarfLocation::Unknown
            }
        }
        DW_OP_CONST4U => {
            if expr.len() >= 5 {
                DwarfLocation::Constant(u64::from(u32::from_le_bytes(
                    expr[1..5].try_into().unwrap(),
                )))
            } else {
                DwarfLocation::Unknown
            }
        }
        DW_OP_CONST8U => {
            if expr.len() >= 9 {
                DwarfLocation::Constant(u64::from_le_bytes(expr[1..9].try_into().unwrap()))
            } else {
                DwarfLocation::Unknown
            }
        }
        DW_OP_CONSTU => {
            let mut off = 1;
            read_uleb128(expr, &mut off).map_or(DwarfLocation::Unknown, DwarfLocation::Constant)
        }
        _ => DwarfLocation::Unknown,
    }
}

// â"€â"€ DIE struct â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug)]
struct Die {
    tag: u64,
    attrs: HashMap<u64, AttrValue>,
    children: Vec<Self>,
}

impl Die {
    fn attr_str(&self, attr: u64) -> Option<&str> {
        self.attrs.get(&attr).and_then(|v| v.as_string())
    }
    fn attr_uint(&self, attr: u64) -> Option<u64> {
        self.attrs.get(&attr).and_then(AttrValue::as_uint)
    }
    fn attr_bytes(&self, attr: u64) -> Option<&[u8]> {
        self.attrs.get(&attr).and_then(|v| v.as_bytes())
    }
}

// â"€â"€ DIE tree parsing â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Shared per-CU parsing context bundled to keep parser signatures small.
struct DieParseCtx<'a> {
    abbrevs: &'a HashMap<u64, AbbrevEntry>,
    addr_size: u8,
    is_64bit: bool,
    debug_str: &'a [u8],
    debug_line_str: &'a [u8],
    cu_offset: usize,
}

fn parse_die_tree(
    data: &[u8],
    off: &mut usize,
    unit_end: usize,
    ctx: &DieParseCtx,
    depth: usize,
) -> Result<Option<Die>> {
    // Unbounded recursion on a crafted `.debug_info` overflows the stack, which
    // is an uncatchable abort. Cap it.
    if depth >= MAX_DIE_DEPTH {
        return Err(DwarfError::MalformedDwarf);
    }
    if *off >= unit_end {
        return Ok(None);
    }
    let code = read_uleb128(data, off)?;
    if code == 0 {
        return Ok(None);
    }
    let entry = ctx.abbrevs.get(&code).ok_or(DwarfError::MalformedDwarf)?;

    let mut attrs_map = HashMap::new();
    for &(attr, form, implicit) in &entry.attrs {
        // An unreadable form leaves `off` mid-DIE; continuing would decode
        // garbage as sibling DIEs. Abandon the whole unit instead.
        let v = read_attr_value(
            data,
            off,
            form,
            ctx.addr_size,
            ctx.is_64bit,
            ctx.debug_str,
            ctx.debug_line_str,
            ctx.cu_offset,
            implicit,
            0,
        )?;
        attrs_map.insert(attr, v);
    }

    let mut children = Vec::new();
    if entry.has_children {
        loop {
            if *off >= unit_end {
                break;
            }
            match parse_die_tree(data, off, unit_end, ctx, depth + 1)? {
                Some(child) => children.push(child),
                None => break, // null terminator
            }
        }
    }

    Ok(Some(Die {
        tag: entry.tag,
        attrs: attrs_map,
        children,
    }))
}

// â"€â"€ .debug_info traversal â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

struct ParsedCu {
    dies: Vec<Die>,
}

/// Convenience wrapper used by the unit tests (no `.debug_line_str`).
#[cfg(test)]
fn parse_debug_info(
    debug_info: &[u8],
    debug_abbrev: &[u8],
    debug_str: &[u8],
) -> Result<Vec<ParsedCu>> {
    parse_debug_info_with(debug_info, debug_abbrev, debug_str, &[])
}

fn parse_debug_info_with(
    debug_info: &[u8],
    debug_abbrev: &[u8],
    debug_str: &[u8],
    debug_line_str: &[u8],
) -> Result<Vec<ParsedCu>> {
    let mut units = Vec::new();
    let mut off = 0usize;
    // CUs in one binary overwhelmingly share a handful of abbrev tables; without
    // this cache an N-CU binary re-parses .debug_abbrev N times.
    let mut abbrev_cache: HashMap<usize, Rc<HashMap<u64, AbbrevEntry>>> = HashMap::new();

    while off < debug_info.len() {
        let cu_start = off;

        // Try to read unit length (may be 32-bit or 64-bit DWARF).
        if off + 4 > debug_info.len() {
            break;
        }
        let initial_len = read_u32_le(debug_info, &mut off)?;
        let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
            let len = read_u64_le(debug_info, &mut off)?;
            (true, usize::try_from(len).unwrap_or(usize::MAX))
        } else {
            (false, initial_len as usize)
        };

        let header_start = off;
        let unit_end = header_start.checked_add(unit_len).ok_or(DwarfError::MalformedDwarf)?;
        if unit_end > debug_info.len() {
            break;
        }

        let version = read_u16_le(debug_info, &mut off)?;
        if version == 0 || version > 5 {
            // Unknown unit version: we cannot trust the header layout, so skip
            // the unit rather than silently mis-parsing it.
            off = unit_end;
            continue;
        }

        // DWARF 5 §7.5.1 reorders the header and inserts `unit_type`:
        //   v2-v4: version, abbrev_offset, address_size
        //   v5:    version, unit_type, address_size, abbrev_offset [, trailer]
        let (abbrev_offset, addr_size) = if version >= 5 {
            let unit_type = read_u8(debug_info, &mut off)?;
            let addr_size = read_u8(debug_info, &mut off)?;
            let abbrev_offset = if is_64bit {
                usize::try_from(read_u64_le(debug_info, &mut off)?).unwrap_or(usize::MAX)
            } else {
                read_u32_le(debug_info, &mut off)? as usize
            };
            // Unit-type-specific trailer.
            let trailer = match unit_type {
                // DW_UT_skeleton / DW_UT_split_compile: 8-byte dwo_id
                0x04 | 0x05 => 8usize,
                // DW_UT_type / DW_UT_split_type: 8-byte signature + type offset
                0x02 | 0x06 => 8 + if is_64bit { 8 } else { 4 },
                _ => 0,
            };
            off = off.saturating_add(trailer);
            (abbrev_offset, addr_size)
        } else {
            let abbrev_offset = if is_64bit {
                usize::try_from(read_u64_le(debug_info, &mut off)?).unwrap_or(usize::MAX)
            } else {
                read_u32_le(debug_info, &mut off)? as usize
            };
            let addr_size = read_u8(debug_info, &mut off)?;
            (abbrev_offset, addr_size)
        };

        // Bounds-check the abbrev offset explicitly: `.get(..).unwrap_or(&[])`
        // would mask a bad offset as an empty (silently useless) table.
        let Some(abbrev_data) = debug_abbrev.get(abbrev_offset..) else {
            off = unit_end;
            continue;
        };
        let abbrevs = if let Some(cached) = abbrev_cache.get(&abbrev_offset) {
            Rc::clone(cached)
        } else {
            let Ok(parsed) = parse_abbrev_table(abbrev_data) else {
                off = unit_end;
                continue;
            };
            let rc = Rc::new(parsed);
            abbrev_cache.insert(abbrev_offset, Rc::clone(&rc));
            rc
        };

        let ctx = DieParseCtx {
            abbrevs: abbrevs.as_ref(),
            addr_size,
            is_64bit,
            debug_str,
            debug_line_str,
            cu_offset: cu_start,
        };
        let mut dies = Vec::new();
        while off < unit_end {
            // cu_start is passed as the CU offset for ref resolution.
            // A malformed DIE aborts this CU only; the next CU starts at the
            // unit length, which is known independently of DIE parsing.
            match parse_die_tree(debug_info, &mut off, unit_end, &ctx, 0) {
                Ok(Some(die)) => dies.push(die),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        off = unit_end;
        units.push(ParsedCu { dies });
    }

    Ok(units)
}

// â"€â"€ Extract typed entities from DIEs â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn collect_types(dies: &[Die]) -> Vec<DwarfType> {
    let mut types = Vec::new();
    for die in dies {
        let tag = die.tag;
        let dwarf_tag = match tag {
            DW_TAG_BASE_TYPE => DwarfTypeTag::Base,
            DW_TAG_POINTER_TYPE => DwarfTypeTag::Pointer,
            DW_TAG_TYPEDEF => DwarfTypeTag::Typedef,
            DW_TAG_STRUCTURE_TYPE => DwarfTypeTag::Struct,
            DW_TAG_UNION_TYPE => DwarfTypeTag::Union,
            DW_TAG_ARRAY_TYPE => DwarfTypeTag::Array,
            // DW_TAG_COMPILE_UNIT, DW_TAG_SUBPROGRAM, and any other tag: descend
            // into children to gather any nested types we recognize.
            _ => {
                types.extend(collect_types(&die.children));
                continue;
            }
        };
        let name = die.attr_str(DW_AT_NAME).unwrap_or("<anonymous>").to_owned();
        let byte_size =
            u32::try_from(die.attr_uint(DW_AT_BYTE_SIZE).unwrap_or(0)).unwrap_or(u32::MAX);
        types.push(DwarfType {
            name,
            byte_size,
            tag: dwarf_tag,
        });
        types.extend(collect_types(&die.children));
    }
    types
}

fn collect_variables(die: &Die) -> Vec<DwarfVariable> {
    let mut vars = Vec::new();
    // Use DW_AT_COMP_DIR on compile-unit DIEs to potentially prefix file paths
    // in the future; for now we read it to confirm it's accessible.
    let _comp_dir = die.attr_str(DW_AT_COMP_DIR).unwrap_or("");
    for child in &die.children {
        if child.tag == DW_TAG_VARIABLE || child.tag == DW_TAG_FORMAL_PARAMETER {
            let name = child.attr_str(DW_AT_NAME).unwrap_or("").to_owned();
            let type_name = child
                .attr_uint(DW_AT_TYPE)
                .map_or_else(|| "<unknown>".into(), |r| format!("type@{r:#x}"));
            let location = child
                .attr_bytes(DW_AT_LOCATION)
                .map_or(DwarfLocation::Unknown, decode_location);
            vars.push(DwarfVariable {
                name,
                type_name,
                location,
            });
        }
    }
    vars
}

fn collect_functions(dies: &[Die]) -> Vec<DwarfFunction> {
    let mut fns = Vec::new();
    for die in dies {
        // Skip compile-unit DIEs; descend into them instead.
        if die.tag == DW_TAG_COMPILE_UNIT {
            fns.extend(collect_functions(&die.children));
            continue;
        }
        if die.tag == DW_TAG_SUBPROGRAM {
            // Prefer DW_AT_name; fall back to DW_AT_specification (which is a
            // DIE offset we can't resolve here, so we just note its presence).
            let name = die
                .attr_str(DW_AT_NAME)
                .or_else(|| die.attr_str(DW_AT_ABSTRACT_ORIGIN))
                .or_else(|| {
                    die.attr_uint(DW_AT_SPECIFICATION).map(|off| {
                        // We can't resolve the offset without a full DIE map,
                        // but we record it for callers that need it.
                        let _ = off;
                        "<specification>"
                    })
                })
                .unwrap_or("")
                .to_owned();
            let low_pc = die.attr_uint(DW_AT_LOW_PC).unwrap_or(0);
            let high_pc_raw = die.attr_uint(DW_AT_HIGH_PC).unwrap_or(0);
            // DW_AT_high_pc is an absolute address when its form is of class
            // `address`, and a length when the class is `constant` (DWARF 4+
            // §2.17.2). `AttrValue` erases the form, so this heuristic is the
            // best available here; the add is saturating because both operands
            // come from the file.
            let high_pc = if high_pc_raw > low_pc {
                high_pc_raw
            } else {
                low_pc.saturating_add(high_pc_raw)
            };
            let return_type = die.attr_uint(DW_AT_TYPE).map(|r| format!("type@{r:#x}"));
            let parameters: Vec<DwarfVariable> = die
                .children
                .iter()
                .filter(|c| c.tag == DW_TAG_FORMAL_PARAMETER)
                .map(|c| {
                    let pname = c.attr_str(DW_AT_NAME).unwrap_or("").to_owned();
                    let type_name = c
                        .attr_uint(DW_AT_TYPE)
                        .map_or_else(|| "<unknown>".into(), |r| format!("type@{r:#x}"));
                    let location = c
                        .attr_bytes(DW_AT_LOCATION)
                        .map_or(DwarfLocation::Unknown, decode_location);
                    DwarfVariable {
                        name: pname,
                        type_name,
                        location,
                    }
                })
                .collect();
            fns.push(DwarfFunction {
                name,
                low_pc,
                high_pc,
                parameters,
                return_type,
            });
            // Do not descend into subprogram children for top-level function
            // extraction; doing so would emit nested/inlined subprograms as
            // spurious top-level entries.
            continue;
        }
        fns.extend(collect_functions(&die.children));
    }
    fns
}

// â"€â"€ .debug_line state machine â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn parse_line_program(line_data: &[u8]) -> Vec<LineEntry> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off < line_data.len() {
        let Some(unit_end) = parse_line_unit_header(line_data, &mut off, &mut entries) else {
            break;
        };
        off = unit_end;
    }
    entries
}

/// Parse one line-program unit header, execute its state machine, and append
/// rows to `entries`. Returns the offset just past the unit on success, or
/// `None` if parsing should stop.
fn parse_line_unit_header(
    line_data: &[u8],
    off: &mut usize,
    entries: &mut Vec<LineEntry>,
) -> Option<usize> {
    if *off + 4 > line_data.len() {
        return None;
    }
    let initial_len = read_u32_le(line_data, off).ok()?;
    let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
        let v = read_u64_le(line_data, off).ok()?;
        (true, usize::try_from(v).ok()?)
    } else {
        (false, initial_len as usize)
    };
    let unit_end = off.checked_add(unit_len)?;
    if unit_end > line_data.len() {
        return None;
    }

    let version = read_u16_le(line_data, off).ok()?;
    let header_len = if is_64bit {
        usize::try_from(read_u64_le(line_data, off).ok()?).ok()?
    } else {
        read_u32_le(line_data, off).ok()? as usize
    };
    let program_start = off.checked_add(header_len)?;

    let min_insn_len = read_u8(line_data, off).ok()?;
    if version >= 4 { read_u8(line_data, off).ok()?; } // max_ops_per_insn
    let default_is_stmt = read_u8(line_data, off).ok()? != 0;
    let line_base = read_u8(line_data, off).ok()?.cast_signed();
    let line_range  = read_u8(line_data, off).ok()?;
    let opcode_base = usize::from(read_u8(line_data, off).ok()?);

    // A `line_range` of 0 is legal bytes in the file but is used as a divisor by
    // the special-opcode / DW_LNS_const_add_pc paths. Reject the unit (but keep
    // parsing subsequent units) rather than panicking. `opcode_base == 0` is
    // likewise malformed: every opcode would take the special path.
    if line_range == 0 || opcode_base == 0 {
        return Some(unit_end);
    }

    *off += opcode_base.saturating_sub(1); // skip standard opcode lengths
    if *off >= program_start { return Some(unit_end); }

    while let Ok(dir) = read_cstring(line_data, off) { if dir.is_empty() { break; } }

    let mut file_names = vec![String::new()];
    while let Ok(fname) = read_cstring(line_data, off) {
        if fname.is_empty() { break; }
        if read_uleb128(line_data, off).is_err() { break; }
        if read_uleb128(line_data, off).is_err() { break; }
        if read_uleb128(line_data, off).is_err() { break; }
        file_names.push(fname);
    }

    exec_line_state_machine(
        line_data, off,
        &LineProgramParams { unit_end, min_insn_len, default_is_stmt, line_base, line_range, opcode_base },
        &mut file_names, entries,
    );
    Some(unit_end)
}

struct LineProgramParams {
    unit_end: usize,
    min_insn_len: u8,
    default_is_stmt: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: usize,
}

/// Execute the DWARF line-number state machine for one unit.
fn exec_line_state_machine(
    data: &[u8],
    off: &mut usize,
    p: &LineProgramParams,
    file_names: &mut Vec<String>,
    entries: &mut Vec<LineEntry>,
) {
    let LineProgramParams { unit_end, min_insn_len, default_is_stmt, line_base, line_range, opcode_base } = *p;
    // Defensive: `line_range` is a divisor below. Callers reject 0, but this fn
    // is separate and could be called elsewhere.
    if line_range == 0 {
        return;
    }
    *off = (*off).min(unit_end);
    let mut address: u64 = 0;
    let mut file: u64 = 1;
    let mut line: u64 = 1;
    let mut column: u64 = 0;
    let mut is_stmt = default_is_stmt;
    let mut basic_block = false;

    let emit = |entries: &mut Vec<LineEntry>, fnames: &Vec<String>, address: u64, file: u64, line: u64, column: u64| {
        let fname = fnames.get(usize::try_from(file).unwrap_or(0)).cloned().unwrap_or_default();
        entries.push(LineEntry {
            address,
            file: fname,
            line: u32::try_from(line).unwrap_or(u32::MAX),
            column: u32::try_from(column).unwrap_or(u32::MAX),
        });
    };

    while *off < unit_end {
        let Ok(opcode) = read_u8(data, off) else { break; };
        if opcode == 0 {
            let Ok(ext_len_v) = read_uleb128(data, off) else { break; };
            let ext_len = usize::try_from(ext_len_v).unwrap_or(usize::MAX);
            let ext_off = *off;
            let Ok(ext_op) = read_u8(data, off) else { break; };
            match ext_op {
                1 => { // DW_LNE_end_sequence
                    emit(entries, file_names, address, file, line, column);
                    address = 0; file = 1; line = 1; column = 0;
                    is_stmt = default_is_stmt; basic_block = false;
                }
                2 => { // DW_LNE_set_address
                    let addr_bytes = ext_len.saturating_sub(1);
                    address = if addr_bytes == 8 {
                        let Ok(w) = read_u64_le(data, off) else { break; }; w
                    } else {
                        let Ok(w) = read_u32_le(data, off) else { break; }; u64::from(w)
                    };
                }
                3 => { // DW_LNE_define_file
                    let Ok(fname) = read_cstring(data, off) else { break; };
                    if read_uleb128(data, off).is_err() { break; }
                    if read_uleb128(data, off).is_err() { break; }
                    if read_uleb128(data, off).is_err() { break; }
                    file_names.push(fname);
                }
                _ => {}
            }
            *off = ext_off + ext_len;
        } else if usize::from(opcode) < opcode_base {
            match opcode {
                1 => { if is_stmt || basic_block { emit(entries, file_names, address, file, line, column); } basic_block = false; }
                2 => { let Ok(a) = read_uleb128(data, off) else { break; }; address = address.saturating_add(a.saturating_mul(u64::from(min_insn_len))); }
                3 => { let Ok(la) = read_sleb128(data, off) else { break; }; line = (line.cast_signed() + la).cast_unsigned(); }
                4 => { let Ok(v) = read_uleb128(data, off) else { break; }; file = v; }
                5 => { let Ok(v) = read_uleb128(data, off) else { break; }; column = v; }
                6 => { is_stmt = !is_stmt; }
                7 => { basic_block = true; }
                8 => { let adj = 255u64.saturating_sub(opcode_base as u64) / u64::from(line_range); address = address.saturating_add(adj.saturating_mul(u64::from(min_insn_len))); }
                9 => { let Ok(d) = read_u16_le(data, off) else { break; }; address = address.saturating_add(u64::from(d)); }
                _ => {}
            }
        } else {
            let adj = u64::from(opcode) - opcode_base as u64;
            let line_inc = (adj % u64::from(line_range)).cast_signed() + i64::from(line_base);
            address = address.saturating_add((adj / u64::from(line_range)).saturating_mul(u64::from(min_insn_len)));
            line = (line.cast_signed() + line_inc).cast_unsigned();
            emit(entries, file_names, address, file, line, column);
            basic_block = false;
        }
    }
}

// â"€â"€ DwarfReader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Main entry-point for reading DWARF debug information.
pub struct DwarfReader {
    sections: HashMap<String, Vec<u8>>,
    /// Memoised `.debug_info` parse. Every public accessor used to re-parse the
    /// whole section (and its abbrev tables) from scratch.
    units: OnceLock<Vec<ParsedCu>>,
}

impl DwarfReader {
    /// Open an ELF binary from disk and parse its DWARF sections.
    ///
    /// # Errors
    /// Returns [`DwarfError`] on I/O failure or unsupported binary format.
    pub fn open(path: &Path) -> Result<Self> {
        let raw = fs::read(path)?;
        Self::from_bytes(&raw)
    }

    /// Parse DWARF from an in-memory binary (ELF or Mach-O).
    ///
    /// Windows PE binaries (identified by the `MZ` magic bytes) contain no
    /// DWARF sections and are accepted gracefully: the reader is returned with
    /// an empty section map, so all accessors (`functions`, `types`,
    /// `variables`, `line_info`) yield empty vecs.
    ///
    /// # Errors
    /// Returns [`DwarfError`] on I/O failure or genuinely unsupported/malformed
    /// data (anything that is neither ELF nor a PE binary).
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        // Windows PE files start with the MZ signature; they use PDB for debug
        // info rather than DWARF.  Parsing them as ELF would always fail, so
        // we short-circuit here and return an empty reader.
        if raw.starts_with(b"MZ") {
            return Ok(Self { sections: HashMap::new(), units: OnceLock::new() });
        }
        let sections = elf_sections(raw)?;
        Ok(Self { sections, units: OnceLock::new() })
    }

    /// Construct a reader directly from pre-extracted section data (for unit
    /// testing without needing a full ELF binary on disk).
    #[must_use]
    pub const fn from_sections(sections: HashMap<String, Vec<u8>>) -> Self {
        Self { sections, units: OnceLock::new() }
    }

    fn debug_info(&self) -> &[u8] {
        self.sections.get(".debug_info").map_or(&[], Vec::as_slice)
    }
    fn debug_abbrev(&self) -> &[u8] {
        self.sections
            .get(".debug_abbrev")
            .map_or(&[], Vec::as_slice)
    }
    fn debug_str(&self) -> &[u8] {
        self.sections.get(".debug_str").map_or(&[], Vec::as_slice)
    }
    fn debug_line(&self) -> &[u8] {
        self.sections.get(".debug_line").map_or(&[], Vec::as_slice)
    }
    /// DWARF 5 `.debug_line_str`, indexed by `DW_FORM_line_strp`. Distinct from
    /// `.debug_str`; resolving line_strp against `.debug_str` yields
    /// plausible-but-wrong filenames.
    fn debug_line_str(&self) -> &[u8] {
        self.sections
            .get(".debug_line_str")
            .map_or(&[], Vec::as_slice)
    }

    fn parsed_units(&self) -> &[ParsedCu] {
        self.units.get_or_init(|| {
            parse_debug_info_with(
                self.debug_info(),
                self.debug_abbrev(),
                self.debug_str(),
                self.debug_line_str(),
            )
            .unwrap_or_default()
        })
    }

    /// Return all functions found in `.debug_info`.
    #[must_use]
    pub fn functions(&self) -> Vec<DwarfFunction> {
        self.parsed_units()
            .iter()
            .flat_map(|cu| collect_functions(&cu.dies))
            .collect()
    }

    /// Return all variables found in `.debug_info` (top-level only).
    #[must_use]
    pub fn variables(&self) -> Vec<DwarfVariable> {
        self.parsed_units()
            .iter()
            .flat_map(|cu| cu.dies.iter().flat_map(collect_variables))
            .collect()
    }

    /// Return all type definitions found in `.debug_info`.
    #[must_use]
    pub fn types(&self) -> Vec<DwarfType> {
        self.parsed_units()
            .iter()
            .flat_map(|cu| collect_types(&cu.dies))
            .collect()
    }

    /// Return source-line mappings from `.debug_line`.
    ///
    /// This reads through [`crate::dwarf_line_program::LineProgram`], which
    /// understands the DWARF 5 header layout (`address_size` /
    /// `segment_selector_size` before `header_length`, and the directory /
    /// file entry-format tables). The older inline reader in this module
    /// misparses v5 units; it is kept only as a fallback for inputs the
    /// structured parser rejects outright.
    #[must_use]
    pub fn line_info(&self) -> Vec<LineEntry> {
        let data = self.debug_line();
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let Ok((prog, next)) = dwarf_line_program::LineProgram::parse_with_str_sections(
                data,
                offset,
                self.debug_line_str(),
                self.debug_str(),
            ) else {
                break;
            };
            for row in prog.execute().rows {
                if row.end_sequence {
                    continue;
                }
                out.push(LineEntry {
                    address: row.address,
                    file: prog.resolve_file(row.file).unwrap_or_default(),
                    line: u32::try_from(row.line).unwrap_or(u32::MAX),
                    column: u32::try_from(row.column).unwrap_or(u32::MAX),
                });
            }
            if next <= offset {
                break;
            }
            offset = next;
        }
        if out.is_empty() {
            return parse_line_program(data);
        }
        out
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ Helper: build minimal DWARF abbreviation table bytes â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn abbrev_entry(code: u64, tag: u64, has_children: bool, attrs: &[(u64, u64)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(encode_uleb(code));
        v.extend(encode_uleb(tag));
        v.push(u8::from(has_children));
        for &(a, f) in attrs {
            v.extend(encode_uleb(a));
            v.extend(encode_uleb(f));
        }
        v.extend([0, 0]); // terminator pair
        v
    }

    fn encode_uleb(mut n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            v.push(b);
            if n == 0 {
                break;
            }
        }
        v
    }

    fn encode_sleb(mut n: i64) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            let done = (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0);
            if !done {
                b |= 0x80;
            }
            v.push(b);
            if done {
                break;
            }
        }
        v
    }

    /// Build a minimal DWARF .`debug_info` section with one CU containing a
    /// single `DW_TAG_subprogram` DIE.
    fn build_debug_info_with_function(
        abbrev_offset: u32,
        fn_name: &str,
        low_pc: u64,
        high_pc_delta: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        // Abbreviation table
        let mut abbrev = Vec::new();
        abbrev.extend(abbrev_entry(
            1,
            DW_TAG_COMPILE_UNIT,
            true,
            &[(DW_AT_NAME, DW_FORM_STRING)],
        ));
        abbrev.extend(abbrev_entry(
            2,
            DW_TAG_SUBPROGRAM,
            false,
            &[
                (DW_AT_NAME, DW_FORM_STRING),
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_HIGH_PC, DW_FORM_DATA8),
            ],
        ));
        abbrev.extend([0]); // table end

        // .debug_info
        let mut info_body = Vec::new();
        // Abbrev code 1 = compile unit
        info_body.extend(encode_uleb(1));
        info_body.extend_from_slice(b"test.c\x00"); // DW_AT_name
        // Abbrev code 2 = subprogram
        info_body.extend(encode_uleb(2));
        info_body.extend_from_slice(fn_name.as_bytes());
        info_body.push(0); // null terminate name
        info_body.extend_from_slice(&low_pc.to_le_bytes()); // low_pc (addr, 8 bytes)
        info_body.extend_from_slice(&high_pc_delta.to_le_bytes()); // high_pc delta (data8)
        // children terminator for CU
        info_body.push(0);
        // null terminator for CU children
        info_body.push(0);

        let unit_len = (2 + 4 + 1 + info_body.len()) as u32; // version(2)+abbrev_off(4)+addr_size(1)+body
        let mut info = Vec::new();
        info.extend_from_slice(&unit_len.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes()); // DWARF version 4
        info.extend_from_slice(&abbrev_offset.to_le_bytes());
        info.push(8); // addr_size
        info.extend(info_body);

        (info, abbrev)
    }

    // â"€â"€ Location decoding tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_decode_location_register() {
        let expr = &[DW_OP_REG0 + 5];
        assert_eq!(decode_location(expr), DwarfLocation::Register(5));
    }

    #[test]
    fn test_decode_location_regx() {
        let mut expr = vec![DW_OP_REGX];
        expr.extend(encode_uleb(32));
        assert_eq!(decode_location(&expr), DwarfLocation::Register(32));
    }

    #[test]
    fn test_decode_location_fbreg() {
        let mut expr = vec![DW_OP_FBREG];
        expr.extend(encode_sleb(-16));
        // DW_OP_fbreg is relative to DW_AT_frame_base, which is not a fixed
        // register (it is usually DW_OP_call_frame_cfa on x86-64). It must NOT
        // be reported as MemoryOffset{register: 6}.
        assert_eq!(
            decode_location(&expr),
            DwarfLocation::FrameOffset(-16)
        );
    }

    #[test]
    fn test_decode_location_breg() {
        let mut expr = vec![DW_OP_BREG0 + 7]; // rbp offset
        expr.extend(encode_sleb(8));
        assert_eq!(
            decode_location(&expr),
            DwarfLocation::MemoryOffset {
                register: 7,
                offset: 8
            }
        );
    }

    #[test]
    fn test_decode_location_lit() {
        assert_eq!(
            decode_location(&[DW_OP_LIT0 + 10]),
            DwarfLocation::Constant(10)
        );
    }

    #[test]
    fn test_decode_location_const1u() {
        assert_eq!(
            decode_location(&[DW_OP_CONST1U, 42]),
            DwarfLocation::Constant(42)
        );
    }

    #[test]
    fn test_decode_location_const4u() {
        let mut expr = vec![DW_OP_CONST4U];
        expr.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(decode_location(&expr), DwarfLocation::Constant(0xDEAD_BEEF));
    }

    #[test]
    fn test_decode_location_unknown() {
        assert_eq!(decode_location(&[0xFF]), DwarfLocation::Unknown);
    }

    #[test]
    fn test_decode_location_empty() {
        assert_eq!(decode_location(&[]), DwarfLocation::Unknown);
    }

    // â"€â"€ ULEB / SLEB helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_uleb128_single_byte() {
        let data = [0x05u8];
        let mut off = 0;
        assert_eq!(read_uleb128(&data, &mut off).unwrap(), 5);
    }

    #[test]
    fn test_uleb128_multi_byte() {
        let data = [0x80, 0x01]; // 128
        let mut off = 0;
        assert_eq!(read_uleb128(&data, &mut off).unwrap(), 128);
    }

    #[test]
    fn test_sleb128_negative() {
        let data = [0x7eu8]; // -2
        let mut off = 0;
        assert_eq!(read_sleb128(&data, &mut off).unwrap(), -2);
    }

    #[test]
    fn test_sleb128_positive() {
        let data = encode_sleb(127);
        let mut off = 0;
        assert_eq!(read_sleb128(&data, &mut off).unwrap(), 127);
    }

    // â"€â"€ DwarfType / TypeTag â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dwarf_type_struct() {
        let t = DwarfType {
            name: "Foo".into(),
            byte_size: 8,
            tag: DwarfTypeTag::Struct,
        };
        assert_eq!(t.tag, DwarfTypeTag::Struct);
    }

    #[test]
    fn test_dwarf_type_clone() {
        let t = DwarfType {
            name: "Bar".into(),
            byte_size: 4,
            tag: DwarfTypeTag::Base,
        };
        assert_eq!(t, t.clone());
    }

    // â"€â"€ DwarfFunction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dwarf_function_fields() {
        let f = DwarfFunction {
            name: "main".into(),
            low_pc: 0x1000,
            high_pc: 0x1100,
            parameters: vec![],
            return_type: Some("int".into()),
        };
        assert_eq!(f.name, "main");
        assert_eq!(f.high_pc - f.low_pc, 0x100);
    }

    #[test]
    fn test_dwarf_function_no_return_type() {
        let f = DwarfFunction {
            name: "init".into(),
            low_pc: 0,
            high_pc: 0,
            parameters: vec![],
            return_type: None,
        };
        assert!(f.return_type.is_none());
    }

    // â"€â"€ DwarfVariable â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dwarf_variable_register() {
        let v = DwarfVariable {
            name: "x".into(),
            type_name: "int".into(),
            location: DwarfLocation::Register(0),
        };
        assert_eq!(v.location, DwarfLocation::Register(0));
    }

    #[test]
    fn test_dwarf_variable_memory_offset() {
        let v = DwarfVariable {
            name: "p".into(),
            type_name: "int*".into(),
            location: DwarfLocation::MemoryOffset {
                register: 6,
                offset: -8,
            },
        };
        if let DwarfLocation::MemoryOffset { register, offset } = v.location {
            assert_eq!(register, 6);
            assert_eq!(offset, -8);
        } else {
            panic!("Expected MemoryOffset");
        }
    }

    // â"€â"€ LineEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_line_entry_fields() {
        let entry = LineEntry {
            address: 0x1000,
            file: "main.c".into(),
            line: 42,
            column: 1,
        };
        assert_eq!(entry.file, "main.c");
        assert_eq!(entry.line, 42);
    }

    #[test]
    fn test_line_entry_clone() {
        let e = LineEntry {
            address: 0,
            file: "a.c".into(),
            line: 1,
            column: 0,
        };
        assert_eq!(e, e.clone());
    }

    // â"€â"€ from_sections / empty â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_from_sections_empty() {
        let r = DwarfReader::from_sections(HashMap::new());
        assert!(r.functions().is_empty());
        assert!(r.variables().is_empty());
        assert!(r.types().is_empty());
        assert!(r.line_info().is_empty());
    }

    // â"€â"€ Full DIE round-trip â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_parse_subprogram_die() {
        let (info, abbrev) = build_debug_info_with_function(0, "my_func", 0x4000, 0x100);
        let debug_str = vec![];
        let units = parse_debug_info(&info, &abbrev, &debug_str).unwrap();
        assert!(!units.is_empty());
        let fns: Vec<DwarfFunction> = units
            .iter()
            .flat_map(|cu| collect_functions(&cu.dies))
            .collect();
        assert!(!fns.is_empty(), "Expected at least one function");
        let f = &fns[0];
        assert_eq!(f.name, "my_func");
        assert_eq!(f.low_pc, 0x4000);
    }

    #[test]
    fn test_parse_abbrev_table() {
        let mut abbrev = Vec::new();
        abbrev.extend(abbrev_entry(
            1,
            DW_TAG_COMPILE_UNIT,
            true,
            &[(DW_AT_NAME, DW_FORM_STRING)],
        ));
        abbrev.push(0); // end
        let map = parse_abbrev_table(&abbrev).unwrap();
        assert!(map.contains_key(&1));
        assert_eq!(map[&1].tag, DW_TAG_COMPILE_UNIT);
        assert!(map[&1].has_children);
    }

    #[test]
    fn test_reader_from_bytes_not_elf() {
        let data = vec![0xFFu8; 512];
        assert!(DwarfReader::from_bytes(&data).is_err());
    }

    #[test]
    fn test_collect_types_base_type() {
        let die = Die {
            tag: DW_TAG_BASE_TYPE,
            attrs: {
                let mut m = HashMap::new();
                m.insert(DW_AT_NAME, AttrValue::String("int".into()));
                m.insert(DW_AT_BYTE_SIZE, AttrValue::Uint(4));
                m
            },
            children: vec![],
        };
        let types = collect_types(&[die]);
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "int");
        assert_eq!(types[0].byte_size, 4);
        assert_eq!(types[0].tag, DwarfTypeTag::Base);
    }

    #[test]
    fn test_collect_types_pointer() {
        let die = Die {
            tag: DW_TAG_POINTER_TYPE,
            attrs: {
                let mut m = HashMap::new();
                m.insert(DW_AT_BYTE_SIZE, AttrValue::Uint(8));
                m
            },
            children: vec![],
        };
        let types = collect_types(&[die]);
        assert_eq!(types[0].tag, DwarfTypeTag::Pointer);
    }

    #[test]
    fn test_collect_types_struct() {
        let die = Die {
            tag: DW_TAG_STRUCTURE_TYPE,
            attrs: {
                let mut m = HashMap::new();
                m.insert(DW_AT_NAME, AttrValue::String("MyStruct".into()));
                m.insert(DW_AT_BYTE_SIZE, AttrValue::Uint(16));
                m
            },
            children: vec![],
        };
        let types = collect_types(&[die]);
        assert_eq!(types[0].tag, DwarfTypeTag::Struct);
        assert_eq!(types[0].name, "MyStruct");
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§7.2  gimli-backed DWARF parser
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//
// This second half of the crate implements the same conceptual API as the
// hand-rolled parser above, but delegates all low-level DWARF decoding to the
// `gimli` crate.  Both implementations are kept because:
//
//  * The hand-rolled parser is zero-dependency (useful for embedded / no_std).
//  * The gimli parser handles edge-cases in DWARF 5, split-DWARF, and
//    supplementary objects that are impractical to replicate manually.
//
// Public entry-point: `load_dwarf_symbols(path)` â†' `DwarfSymbolSet`
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection};
use std::borrow::Cow;

// â"€â"€ gimli-specific error bridging â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Errors returned by the gimli-backed DWARF reader.
///
/// Kept separate from `DwarfError` so that callers can distinguish between the
/// two parser paths.
#[derive(Debug, thiserror::Error)]
pub enum GimliDwarfError {
    /// A filesystem I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The `object` crate failed to parse the binary container.
    #[error("Object parse error: {0}")]
    Object(#[from] object::Error),
    /// gimli reported malformed or unsupported DWARF data.
    #[error("DWARF error: {0}")]
    Gimli(#[from] gimli::Error),
    /// The input is not a supported binary format.
    #[error("Not a supported binary format")]
    UnsupportedFormat,
}

/// Convenience alias for results using [`GimliDwarfError`].
pub type GimliResult<T> = std::result::Result<T, GimliDwarfError>;

// â"€â"€ Rich location type (gimli API) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Variable / parameter storage location decoded via gimli.
///
/// Mirrors `DwarfLocation` but uses `u16` register numbers and adds a raw
/// `Expression` variant for multi-operation location expressions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GimliLocation {
    /// Value lives in register *n* (DWARF register number).
    Register(u16),
    /// Value lives at `frame_base + offset`.
    StackOffset(i64),
    /// Value is a statically-known global address.
    Global(u64),
    /// Raw DWARF expression bytes that could not be reduced to a simpler form.
    Expression(Vec<u8>),
    /// No location information available (abstract / optimised-out).
    Unknown,
}

// â"€â"€ DwarfVariable (gimli) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A variable or formal parameter as decoded by the gimli-backed parser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GimliVariable {
    /// Source name, if available.
    pub name: Option<String>,
    /// Human-readable type name resolved through the type tree.
    pub type_name: String,
    /// Where the value lives at runtime.
    pub location: GimliLocation,
}

// â"€â"€ DwarfFunction (gimli) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A subprogram (function) as decoded by the gimli-backed parser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GimliFunction {
    /// Linkage / source name, if present.
    pub name: Option<String>,
    /// Start address of the function body.
    pub low_pc: u64,
    /// End address of the function body (exclusive).
    pub high_pc: u64,
    /// Source file name from the line-number program, if available.
    pub file: Option<String>,
    /// Source line number, if available.
    pub line: Option<u32>,
    /// Formal parameters in declaration order.
    pub params: Vec<GimliVariable>,
    /// Local variables declared inside the function.
    pub locals: Vec<GimliVariable>,
    /// Return type name resolved through the type tree.
    pub return_type: Option<String>,
}

// â"€â"€ Rich type model â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single field in a struct/union.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub type_: GimliType,
    /// Byte offset within the containing aggregate.
    pub offset: u64,
}

/// A rich DWARF type as decoded by the gimli-backed parser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GimliType {
    /// Type name (may be `<anonymous>` for unnamed aggregates).
    pub name: String,
    /// `DW_AT_byte_size`, if present.
    pub size: Option<u64>,
    /// Structural classification.
    pub kind: TypeKind,
}

/// Structural classification of a DWARF type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TypeKind {
    /// `DW_TAG_base_type` —" encoding name (e.g. `"unsigned int"`).
    Base(String),
    /// `DW_TAG_pointer_type` / `DW_TAG_reference_type`.
    Pointer(Box<GimliType>),
    /// `DW_TAG_structure_type` / `DW_TAG_union_type` —" ordered field list.
    Struct(Vec<StructField>),
    /// `DW_TAG_array_type` —" element type and optional element count.
    Array {
        /// Element type.
        elem: Box<GimliType>,
        /// Number of elements, if known.
        count: Option<u64>,
    },
    /// `DW_TAG_enumeration_type` —" enumerator names.
    Enum(Vec<String>),
    /// `DW_TAG_typedef` —" underlying type.
    Typedef(Box<GimliType>),
    /// Anything else (e.g. `DW_TAG_volatile_type`, `DW_TAG_const_type`).
    Other,
}

// â"€â"€ Source-line table (gimli) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single entry in the DWARF line-number program output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GimliLineEntry {
    /// Machine address this row describes.
    pub address: u64,
    /// Resolved source file name.
    pub file: String,
    /// 1-based source line.
    pub line: u32,
    /// 1-based source column (0 if unspecified by the producer).
    pub column: u32,
    /// `true` when the DWARF `is_stmt` flag is set for this row.
    pub is_stmt: bool,
}

/// The complete source-line mapping for a binary.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LineInfoTable {
    /// All line-table rows, sorted by address.
    pub entries: Vec<GimliLineEntry>,
}

impl LineInfoTable {
    /// Look up the last line-table entry whose address is `â‰¤ addr`.
    ///
    /// Line tables are sorted by address, so this implements a simple binary
    /// search followed by a linear scan backwards to find the nearest entry.
    #[must_use]
    pub fn lookup_address(&self, addr: u64) -> Option<&GimliLineEntry> {
        if self.entries.is_empty() {
            return None;
        }
        // Find the rightmost entry with address â‰¤ addr.
        let idx = self.entries.partition_point(|e| e.address <= addr);
        if idx == 0 {
            None
        } else {
            Some(&self.entries[idx - 1])
        }
    }
}

// â"€â"€ DwarfSymbolSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The complete set of DWARF-derived symbols for a binary.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DwarfSymbolSet {
    /// All subprograms found in `.debug_info`.
    pub functions: Vec<GimliFunction>,
    /// All type definitions found in `.debug_info`.
    pub types: Vec<GimliType>,
    /// Source-line mappings from `.debug_line`.
    pub line_info: LineInfoTable,
}

// â"€â"€ DwarfReader (gimli) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A DWARF reader backed by `gimli` + `object`.
///
/// Unlike `DwarfReader` (the hand-rolled parser at the top of this file),
/// `GimliDwarfReader` supports both ELF and Mach-O binaries transparently and
/// handles DWARF 4 / 5 including the `.debug_str_offsets`, `.debug_addr`, and
/// `.debug_rnglists` sections required by DWARF 5 split-DWARF units.
pub struct GimliDwarfReader {
    /// Pre-loaded gimli `Dwarf` object backed by `EndianSlice` readers
    /// pointing into the owned `_buffer` / `_compressed` storage below.
    ///
    /// The `'static` lifetime here is a lie used to satisfy gimli's type
    /// parameter; the slices actually borrow from `_buffer` and
    /// `_compressed`, which are owned by this struct.  Field declaration
    /// order ensures `dwarf` is dropped before the buffers it points into.
    dwarf: gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    /// Owned backing storage for the raw binary bytes.  Must outlive
    /// `dwarf`.  Boxed-slice address is stable across moves of `Self`.
    _buffer: Box<[u8]>,
    /// Owned backing storage for any sections that had to be decompressed
    /// (e.g. `SHF_COMPRESSED`).  Each entry's address is stable.
    _compressed: Vec<Box<[u8]>>,
}

impl Drop for GimliDwarfReader {
    fn drop(&mut self) {
        // Explicit drop order is enforced by field declaration order
        // (`dwarf` before `_buffer`/`_compressed`).  No special logic needed.
    }
}

impl GimliDwarfReader {
    // â"€â"€ Constructors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Parse an ELF binary from raw bytes.
    ///
    /// Sections are found via the `object` crate and loaded into `gimli`
    /// `EndianSlice` readers without copying.
    ///
    /// # Errors
    /// Returns a `gimli::Error` (or `object` parse error) if the data is not a valid binary.
    pub fn from_elf(data: &[u8]) -> GimliResult<Self> {
        Self::from_bytes_inner(data)
    }

    /// Parse a Mach-O binary from raw bytes.
    ///
    /// The `object` crate transparently handles the `__DWARF` segment, so the
    /// same internal logic works for both ELF and Mach-O.
    ///
    /// # Errors
    /// Returns a `gimli::Error` (or `object` parse error) if the data is not a valid binary.
    pub fn from_macho(data: &[u8]) -> GimliResult<Self> {
        Self::from_bytes_inner(data)
    }

    /// Load and parse the binary at `path` (ELF or Mach-O, auto-detected).
    ///
    /// # Errors
    /// Returns a `gimli::Error` on I/O failure or if the file is not a valid binary.
    pub fn open(path: &Path) -> GimliResult<Self> {
        let raw = fs::read(path)?;
        Self::from_bytes_inner(&raw)
    }

    // â"€â"€ Internal constructor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn from_bytes_inner(data: &[u8]) -> GimliResult<Self> {
        // Own the input bytes in a heap-stable `Box<[u8]>`.  We then construct
        // a `'static` view over them via unsafe pointer reborrow.  The
        // `'static` lifetime is a lie -- the slices actually borrow from
        // `buffer` (and `compressed` for decompressed sections), both of
        // which are stored alongside `dwarf` in the returned `Self`.  Field
        // drop order (`dwarf` first, then `buffer`/`compressed`) guarantees
        // the slices never outlive their backing storage.
        let buffer: Box<[u8]> = data.to_vec().into_boxed_slice();
        // SAFETY: `buffer` lives as long as `Self` (moved into the struct
        // below).  The resulting `&'static [u8]` is only handed to gimli,
        // which stores it inside `dwarf`; `dwarf` is dropped before
        // `buffer` thanks to field order.
        let raw_static: &'static [u8] =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr(), buffer.len()) };

        let obj = object::File::parse(raw_static)?;

        // DWARF carries no endianness of its own — it comes from the container.
        // This reader hardcodes `LittleEndian`, so a big-endian object would be
        // parsed byte-swapped and silently return garbage addresses. The
        // hand-rolled path already rejects big-endian ELF; do the same here.
        if obj.endianness() == object::Endianness::Big {
            return Err(GimliDwarfError::UnsupportedFormat);
        }

        // Accumulated owned sections for compressed data (e.g. SHF_COMPRESSED).
        // Wrapped in `RefCell` so the section-loader closure (`Fn`) can push
        // into it; we unwrap back to a plain `Vec` for storage in `Self`.
        let compressed: std::cell::RefCell<Vec<Box<[u8]>>> =
            std::cell::RefCell::new(Vec::new());

        // Helper closure: load a DWARF section by name and return an
        // `EndianSlice` backed by either `buffer` (borrowed sections) or a
        // freshly decompressed `Box<[u8]>` stashed in `compressed`.
        let load_section =
            |id: gimli::SectionId| -> GimliResult<EndianSlice<'static, LittleEndian>> {
                let slice: &'static [u8] = obj.section_by_name(id.name()).map_or(
                    &[][..],
                    |sec| match sec.uncompressed_data() {
                        Ok(Cow::Borrowed(b)) => {
                            // `b` borrows from `raw_static`; reborrow with the
                            // same (faux-`'static`) lifetime.
                            let len = b.len();
                            let start = b.as_ptr() as usize - raw_static.as_ptr() as usize;
                            &raw_static[start..start + len]
                        }
                        Ok(Cow::Owned(v)) => {
                            // Decompressed data: own it via `compressed` and
                            // hand gimli a `'static`-looking pointer into it.
                            // SAFETY: the boxed slice's address is stable;
                            // it lives as long as `Self`, and `dwarf` (which
                            // stores the slice) is dropped first.
                            let boxed: Box<[u8]> = v.into_boxed_slice();
                            let ptr = boxed.as_ptr();
                            let len = boxed.len();
                            compressed.borrow_mut().push(boxed);
                            unsafe { std::slice::from_raw_parts(ptr, len) }
                        }
                        Err(_) => &[][..],
                    },
                );
                Ok(EndianSlice::new(slice, LittleEndian))
            };

        let dwarf = gimli::Dwarf::load(load_section)?;

        Ok(Self {
            dwarf,
            _buffer: buffer,
            _compressed: compressed.into_inner(),
        })
    }

    // â"€â"€ High-level accessors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Parse all subprograms from `.debug_info`.
    ///
    /// # Errors
    /// Returns a `gimli::Error` if the DWARF data is malformed.
    pub fn parse_functions(&self) -> GimliResult<Vec<GimliFunction>> {
        parse_functions_gimli(&self.dwarf)
    }

    /// Parse all type definitions from `.debug_info`.
    ///
    /// # Errors
    /// Returns a `gimli::Error` if the DWARF data is malformed.
    pub fn parse_types(&self) -> GimliResult<Vec<GimliType>> {
        parse_types_gimli(&self.dwarf)
    }

    /// Parse the source-line mapping from `.debug_line`.
    ///
    /// # Errors
    /// Returns a `gimli::Error` if the DWARF line program is malformed.
    pub fn parse_line_info(&self) -> GimliResult<LineInfoTable> {
        parse_line_info_gimli(&self.dwarf)
    }
}

// â"€â"€ Section-loading helper for owned Cow data â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Re-usable helper: map a `gimli::SectionId` to the bytes of the
/// corresponding section in an `object::File`, returning an empty slice if the
/// section is absent.
///
/// Exposed so that downstream callers can reuse this section-loading logic
/// when implementing custom gimli readers without re-deriving the empty-slice
/// fallback behaviour.
#[must_use]
pub fn load_section_bytes<'a>(obj: &'a object::File<'a>, id: gimli::SectionId) -> Cow<'a, [u8]> {
    obj.section_by_name(id.name()).map_or(Cow::Borrowed(&[]), |sec| {
        sec.uncompressed_data().unwrap_or(Cow::Borrowed(&[]))
    })
}

// â"€â"€ Type-offset resolution helper â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Resolve the type referenced by `type_attr` (a `DW_AT_type` attribute value)
/// within the compilation unit `unit`.
///
/// This performs a single linear scan of the unit's DIE tree to find the
/// DIE at the given offset and decode it as a `GimliType`.  For binaries with
/// deep type graphs this is O(n) per call; a production implementation would
/// pre-build an offset â†' DIE index.  The trade-off is acceptable here because
/// the function is only called during the type-collection pass which already
/// iterates the whole unit.
fn resolve_type_attr<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    attr_val: &gimli::AttributeValue<R>,
) -> String
where
    R: gimli::Reader,
{
    let mut visited = std::collections::HashSet::new();
    resolve_type_attr_guarded(dwarf, unit, attr_val, 0, &mut visited)
}

/// Depth- and cycle-guarded body of [`resolve_type_attr`].
///
/// A self-referential `DW_AT_type` (e.g. a `DW_TAG_pointer_type` pointing at
/// itself) recursed forever, and even an acyclic pointer/const/volatile/array
/// chain was unbounded. Both overflow the stack, which is an uncatchable abort.
fn resolve_type_attr_guarded<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    attr_val: &gimli::AttributeValue<R>,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
) -> String
where
    R: gimli::Reader,
{
    if depth >= MAX_TYPE_CHAIN_DEPTH {
        return "<?>".to_owned();
    }
    // We only handle unit-relative offsets (DW_FORM_ref*).
    let offset = match attr_val {
        gimli::AttributeValue::UnitRef(o) => *o,
        gimli::AttributeValue::DebugInfoRef(_) => {
            // DebugInfoRef is a section-absolute offset; converting it to a
            // unit-relative UnitOffset requires knowing the unit's base which
            // varies per Reader::Offset type.  Skip for now —" the common case
            // (DW_FORM_ref*) is handled by UnitRef above.
            return "<?>".to_owned();
        }
        _ => return "<?>".to_owned(),
    };

    // Break type cycles: a DIE offset visited twice on this chain is a loop.
    if !visited.insert(gimli::ReaderOffset::into_u64(offset.0)) {
        return "<?>".to_owned();
    }

    // Walk the unit's abbreviated entries looking for the DIE at `offset`.
    let mut entries = unit.entries_at_offset(offset).unwrap_or_else(|_| {
        // entries_at_offset returns a cursor; we need to handle errors
        unit.entries()
    });

    if let Ok(Some((_, die))) = entries.next_dfs() {
        match die.tag() {
            gimli::DW_TAG_base_type => {
                if let Ok(Some(attr)) = die.attr(gimli::DW_AT_name)
                    && let Ok(s) = dwarf.attr_string(unit, attr.value())
                {
                    return s.to_string_lossy().unwrap_or_default().into_owned();
                }
                return "<base>".to_owned();
            }
            gimli::DW_TAG_pointer_type => {
                return if let Ok(Some(inner_attr)) = die.attr(gimli::DW_AT_type) {
                    format!("*{}", resolve_type_attr_guarded(dwarf, unit, &inner_attr.value(), depth + 1, visited))
                } else {
                    "void*".to_owned()
                };
            }
            gimli::DW_TAG_typedef => {
                if let Ok(Some(name_attr)) = die.attr(gimli::DW_AT_name)
                    && let Ok(s) = dwarf.attr_string(unit, name_attr.value())
                {
                    return s.to_string_lossy().unwrap_or_default().into_owned();
                }
            }
            gimli::DW_TAG_const_type => {
                return if let Ok(Some(inner_attr)) = die.attr(gimli::DW_AT_type) {
                    format!(
                        "const {}",
                        resolve_type_attr_guarded(dwarf, unit, &inner_attr.value(), depth + 1, visited)
                    )
                } else {
                    "const void".to_owned()
                };
            }
            gimli::DW_TAG_volatile_type => {
                return if let Ok(Some(inner_attr)) = die.attr(gimli::DW_AT_type) {
                    format!(
                        "volatile {}",
                        resolve_type_attr_guarded(dwarf, unit, &inner_attr.value(), depth + 1, visited)
                    )
                } else {
                    "volatile void".to_owned()
                };
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                if let Ok(Some(name_attr)) = die.attr(gimli::DW_AT_name)
                    && let Ok(s) = dwarf.attr_string(unit, name_attr.value())
                {
                    return s.to_string_lossy().unwrap_or_default().into_owned();
                }
                return "<struct>".to_owned();
            }
            gimli::DW_TAG_array_type => {
                return if let Ok(Some(inner_attr)) = die.attr(gimli::DW_AT_type) {
                    format!("{}[]", resolve_type_attr_guarded(dwarf, unit, &inner_attr.value(), depth + 1, visited))
                } else {
                    "unknown[]".to_owned()
                };
            }
            _ => {}
        }
    }
    "<?>".to_owned()
}

// â"€â"€ Location expression decoder (gimli) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Decode a DWARF `DW_AT_location` attribute value into a `GimliLocation`.
fn decode_gimli_location<R: gimli::Reader>(attr_val: &gimli::AttributeValue<R>) -> GimliLocation {
    match attr_val {
        gimli::AttributeValue::Exprloc(expr) => {
            let bytes = expr.0.to_slice().unwrap_or_default().to_vec();
            if bytes.is_empty() {
                return GimliLocation::Unknown;
            }
            let op = bytes[0];
            // DW_OP_reg0..reg31 (0x50—"0x6f)
            if (0x50..=0x6f).contains(&op) {
                return GimliLocation::Register(u16::from(op - 0x50));
            }
            // DW_OP_regx (0x90) —" uleb128 register number
            if op == 0x90 {
                let mut off = 1usize;
                if let Ok(reg) = read_uleb128(&bytes, &mut off) {
                    return GimliLocation::Register(u16::try_from(reg).unwrap_or(u16::MAX));
                }
            }
            // DW_OP_fbreg (0x91) —" sleb128 offset from frame base
            if op == 0x91 {
                let mut off = 1usize;
                let offset = read_sleb128(&bytes, &mut off).unwrap_or(0);
                return GimliLocation::StackOffset(offset);
            }
            // DW_OP_breg0..breg31 (0x77—"0x96) —" register + sleb128 offset
            if (0x77..=0x96).contains(&op) {
                let mut off = 1usize;
                let offset = read_sleb128(&bytes, &mut off).unwrap_or(0);
                // breg0 maps to register 0 which is an absolute address on
                // most ABIs; treat it as a global address when offset â‰¥ 0.
                let reg = op - 0x77;
                if reg == 0 && offset >= 0 {
                    return GimliLocation::Global(offset.cast_unsigned());
                }
                return GimliLocation::StackOffset(offset);
            }
            // Anything else: return raw expression bytes.
            GimliLocation::Expression(bytes)
        }
        gimli::AttributeValue::LocationListsRef(_) => {
            // Location list references are valid but we don't expand them here.
            GimliLocation::Unknown
        }
        gimli::AttributeValue::Addr(a) => GimliLocation::Global(*a),
        _ => GimliLocation::Unknown,
    }
}

// â"€â"€ parse_functions_gimli â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Iterate every compilation unit in `.debug_info` and collect all
/// `DW_TAG_subprogram` DIEs into `GimliFunction` values.
///
/// # Errors
/// Returns a `gimli::Error` if the DWARF data is malformed.
pub fn parse_functions_gimli<R>(dwarf: &gimli::Dwarf<R>) -> GimliResult<Vec<GimliFunction>>
where
    R: gimli::Reader,
{
    let mut functions: Vec<GimliFunction> = Vec::new();
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        process_functions_unit(dwarf, &unit, &mut functions)?;
    }
    Ok(functions)
}

fn process_functions_unit<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    functions: &mut Vec<GimliFunction>,
) -> GimliResult<()>
where
    R: gimli::Reader,
{
    let mut entries = unit.entries();
    let mut current_fn: Option<GimliFunction> = None;
    let mut depth: isize = 0;
    let mut fn_depth: isize = -1;

    while let Ok(Some((delta, die))) = entries.next_dfs() {
        depth += delta;
        if fn_depth >= 0 && depth <= fn_depth {
            if let Some(f) = current_fn.take() { functions.push(f); }
            fn_depth = -1;
        }
        if die.tag() != gimli::DW_TAG_subprogram {
            if fn_depth >= 0 && depth > fn_depth
                && (die.tag() == gimli::DW_TAG_formal_parameter || die.tag() == gimli::DW_TAG_variable)
                && let Some(ref mut f) = current_fn
            {
                let var = extract_variable_gimli(dwarf, unit, die);
                if die.tag() == gimli::DW_TAG_formal_parameter { f.params.push(var); } else { f.locals.push(var); }
            }
            continue;
        }
        current_fn = Some(build_gimli_function(dwarf, unit, die));
        fn_depth = depth;
    }
    if let Some(f) = current_fn.take() { functions.push(f); }
    Ok(())
}

fn build_gimli_function<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    die: &gimli::DebuggingInformationEntry<R>,
) -> GimliFunction
where
    R: gimli::Reader,
{
    let name = die.attr(gimli::DW_AT_name).ok().flatten().and_then(|a| {
        dwarf.attr_string(unit, a.value()).ok().map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
    });
    let low_pc = die.attr(gimli::DW_AT_low_pc).ok().flatten()
        .and_then(|a| if let gimli::AttributeValue::Addr(v) = a.value() { Some(v) } else { None })
        .unwrap_or(0);
    let high_pc = die.attr(gimli::DW_AT_high_pc).ok().flatten().map_or(low_pc, |a| match a.value() {
        gimli::AttributeValue::Addr(v) => v,
        gimli::AttributeValue::Udata(d) => low_pc + d,
        gimli::AttributeValue::Data1(d) => low_pc + u64::from(d),
        gimli::AttributeValue::Data2(d) => low_pc + u64::from(d),
        gimli::AttributeValue::Data4(d) => low_pc + u64::from(d),
        gimli::AttributeValue::Data8(d) => low_pc + d,
        _ => low_pc,
    });
    let return_type = die.attr(gimli::DW_AT_type).ok().flatten()
        .map(|a| resolve_type_attr(dwarf, unit, &a.value()));
    let decl_file = die.attr(gimli::DW_AT_decl_file).ok().flatten()
        .and_then(|a| a.udata_value())
        .and_then(|file_idx| {
            let prog = unit.line_program.as_ref()?;
            let header = prog.header();
            let fe = header.file(file_idx)?;
            let dir_str = dwarf.attr_string(unit, fe.directory(header)?).ok()?;
            let file_str = dwarf.attr_string(unit, fe.path_name()).ok()?;
            Some(format!("{}/{}", dir_str.to_string_lossy().unwrap_or_default(), file_str.to_string_lossy().unwrap_or_default()))
        });
    let decl_line = die.attr(gimli::DW_AT_decl_line).ok().flatten()
        .and_then(|a| a.udata_value()).map(|v| u32::try_from(v).unwrap_or(u32::MAX));
    GimliFunction { name, low_pc, high_pc, file: decl_file, line: decl_line, params: Vec::new(), locals: Vec::new(), return_type }
}

/// Extract a `GimliVariable` from a `DW_TAG_formal_parameter` or
/// `DW_TAG_variable` DIE.
fn extract_variable_gimli<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    die: &gimli::DebuggingInformationEntry<R>,
) -> GimliVariable
where
    R: gimli::Reader,
{
    let name = die.attr(gimli::DW_AT_name).ok().flatten().and_then(|a| {
        dwarf
            .attr_string(unit, a.value())
            .ok()
            .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
    });

    let type_name = die.attr(gimli::DW_AT_type).ok().flatten().map_or_else(
        || "<unknown>".to_owned(),
        |a| resolve_type_attr(dwarf, unit, &a.value()),
    );

    let location = die
        .attr(gimli::DW_AT_location)
        .ok()
        .flatten()
        .map_or(GimliLocation::Unknown, |a| {
            decode_gimli_location(&a.value())
        });

    GimliVariable {
        name,
        type_name,
        location,
    }
}

// â"€â"€ parse_types_gimli â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Iterate every compilation unit in `.debug_info` and collect all type
/// definitions into `GimliType` values.
///
/// Supported tags:
///  * `DW_TAG_base_type`
///  * `DW_TAG_structure_type` / `DW_TAG_union_type`
///  * `DW_TAG_pointer_type`
///  * `DW_TAG_typedef`
///  * `DW_TAG_array_type`
///  * `DW_TAG_enumeration_type`
///
/// # Errors
/// Returns a `gimli::Error` if the DWARF data is malformed.
pub fn parse_types_gimli<R>(dwarf: &gimli::Dwarf<R>) -> GimliResult<Vec<GimliType>>
where
    R: gimli::Reader,
{
    let mut types: Vec<GimliType> = Vec::new();
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        process_types_unit(dwarf, &unit, &mut types)?;
    }
    Ok(types)
}

fn process_types_unit<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    types: &mut Vec<GimliType>,
) -> GimliResult<()>
where
    R: gimli::Reader,
{
    let mut entries = unit.entries();
    let mut struct_stack: Vec<(isize, Option<usize>)> = Vec::new();
    let mut depth: isize = 0;

    while let Ok(Some((delta, die))) = entries.next_dfs() {
        depth += delta;
        while let Some(&(sd, _)) = struct_stack.last() {
            if depth <= sd { struct_stack.pop(); } else { break; }
        }

        match die.tag() {
                // â"€â"€ DW_TAG_member (struct/union field) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_member => {
                    if let Some(&(_, Some(parent_idx))) = struct_stack.last() {
                        let field_name =
                            die.attr(gimli::DW_AT_name)
                                .ok()
                                .flatten()
                                .and_then(|a| {
                                    dwarf.attr_string(unit, a.value()).ok().map(|s| {
                                        s.to_string_lossy().unwrap_or_default().into_owned()
                                    })
                                })
                                .unwrap_or_else(|| "<field>".to_owned());

                        let field_type = die.attr(gimli::DW_AT_type).ok().flatten().map_or_else(
                            || GimliType {
                                name: "<?>".to_owned(),
                                size: None,
                                kind: TypeKind::Other,
                            },
                            |a| GimliType {
                                name: resolve_type_attr(dwarf, unit, &a.value()),
                                size: None,
                                kind: TypeKind::Other,
                            },
                        );

                        let offset = die
                            .attr(gimli::DW_AT_data_member_location)
                            .ok()
                            .flatten()
                            .and_then(|a| match a.value() {
                                gimli::AttributeValue::Udata(v) | gimli::AttributeValue::Data8(v) => Some(v),
                                gimli::AttributeValue::Data1(v) => Some(u64::from(v)),
                                gimli::AttributeValue::Data2(v) => Some(u64::from(v)),
                                gimli::AttributeValue::Data4(v) => Some(u64::from(v)),
                                _ => None,
                            })
                            .unwrap_or(0);

                        if let Some(t) = types.get_mut(parent_idx)
                            && let TypeKind::Struct(ref mut fields) = t.kind
                        {
                            fields.push(StructField {
                                name: field_name,
                                type_: field_type,
                                offset,
                            });
                        }
                    }
                }

                // â"€â"€ DW_TAG_base_type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_base_type => {
                    let name = die
                        .attr(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|a| {
                            dwarf
                                .attr_string(unit, a.value())
                                .ok()
                                .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
                        })
                        .unwrap_or_else(|| "<base>".to_owned());
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    types.push(GimliType {
                        name: name.clone(),
                        size,
                        kind: TypeKind::Base(name),
                    });
                }

                // â"€â"€ DW_TAG_structure_type / DW_TAG_union_type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                    let name = die
                        .attr(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|a| {
                            dwarf
                                .attr_string(unit, a.value())
                                .ok()
                                .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
                        })
                        .unwrap_or_else(|| "<anonymous>".to_owned());
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    let idx = types.len();
                    types.push(GimliType {
                        name,
                        size,
                        kind: TypeKind::Struct(Vec::new()),
                    });
                    // Push scope so that DW_TAG_member children can be
                    // appended to this type's field list.
                    struct_stack.push((depth, Some(idx)));
                }

                // â"€â"€ DW_TAG_pointer_type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_pointer_type => {
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    let inner_name = die.attr(gimli::DW_AT_type).ok().flatten().map_or_else(
                        || "void".to_owned(),
                        |a| resolve_type_attr(dwarf, unit, &a.value()),
                    );
                    let inner = GimliType {
                        name: inner_name.clone(),
                        size: None,
                        kind: TypeKind::Other,
                    };
                    types.push(GimliType {
                        name: format!("{inner_name}*"),
                        size,
                        kind: TypeKind::Pointer(Box::new(inner)),
                    });
                }

                // â"€â"€ DW_TAG_typedef â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_typedef => {
                    let name = die
                        .attr(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|a| {
                            dwarf
                                .attr_string(unit, a.value())
                                .ok()
                                .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
                        })
                        .unwrap_or_else(|| "<typedef>".to_owned());
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    let inner_name = die.attr(gimli::DW_AT_type).ok().flatten().map_or_else(
                        || "<?>".to_owned(),
                        |a| resolve_type_attr(dwarf, unit, &a.value()),
                    );
                    let inner = GimliType {
                        name: inner_name,
                        size: None,
                        kind: TypeKind::Other,
                    };
                    types.push(GimliType {
                        name,
                        size,
                        kind: TypeKind::Typedef(Box::new(inner)),
                    });
                }

                // â"€â"€ DW_TAG_array_type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_array_type => {
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    let elem_name = die.attr(gimli::DW_AT_type).ok().flatten().map_or_else(
                        || "<?>".to_owned(),
                        |a| resolve_type_attr(dwarf, unit, &a.value()),
                    );
                    let elem = GimliType {
                        name: elem_name.clone(),
                        size: None,
                        kind: TypeKind::Other,
                    };
                    types.push(GimliType {
                        name: format!("{elem_name}[]"),
                        size,
                        kind: TypeKind::Array {
                            elem: Box::new(elem),
                            count: None, // filled in by DW_TAG_subrange_type child
                        },
                    });
                }

                // â"€â"€ DW_TAG_subrange_type (array dimension) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_subrange_type => {
                    // Update the element count of the most-recently-pushed
                    // array type.
                    let count = die
                        .attr(gimli::DW_AT_count)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value())
                        .or_else(|| {
                            // DWARF often uses DW_AT_upper_bound instead.
                            die.attr(gimli::DW_AT_upper_bound)
                                .ok()
                                .flatten()
                                .and_then(|a| a.udata_value())
                                .map(|ub| ub + 1) // upper_bound is inclusive
                        });
                    if let Some(c) = count {
                        // Walk backwards to find the last array type.
                        for t in types.iter_mut().rev() {
                            if let TypeKind::Array {
                                count: ref mut co, ..
                            } = t.kind
                            {
                                if co.is_none() {
                                    *co = Some(c);
                                }
                                break;
                            }
                        }
                    }
                }

                // â"€â"€ DW_TAG_enumeration_type â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_enumeration_type => {
                    let name = die
                        .attr(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|a| {
                            dwarf
                                .attr_string(unit, a.value())
                                .ok()
                                .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
                        })
                        .unwrap_or_else(|| "<enum>".to_owned());
                    let size = die
                        .attr(gimli::DW_AT_byte_size)
                        .ok()
                        .flatten()
                        .and_then(|a| a.udata_value());
                    types.push(GimliType {
                        name,
                        size,
                        // Enumerator values will be added by DW_TAG_enumerator
                        // children (see below).
                        kind: TypeKind::Enum(Vec::new()),
                    });
                    struct_stack.push((depth, None));
                }

                // â"€â"€ DW_TAG_enumerator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
                gimli::DW_TAG_enumerator => {
                    let val_name = die
                        .attr(gimli::DW_AT_name)
                        .ok()
                        .flatten()
                        .and_then(|a| {
                            dwarf
                                .attr_string(unit, a.value())
                                .ok()
                                .map(|s| s.to_string_lossy().unwrap_or_default().into_owned())
                        })
                        .unwrap_or_else(|| "<?>".to_owned());
                    // Append to the last enum type in the list.
                    for t in types.iter_mut().rev() {
                        if let TypeKind::Enum(ref mut vals) = t.kind {
                            vals.push(val_name);
                            break;
                        }
                    }
                }

                _ => {}
            }
        }
    Ok(())
}

// â"€â"€ parse_line_info_gimli â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Run the DWARF line-number state machine for every compilation unit via
/// `gimli` and collect all rows into a `LineInfoTable`.
///
/// The resulting table is sorted by address to allow efficient lookups via
/// `LineInfoTable::lookup_address`.
///
/// # Errors
/// Returns a `gimli::Error` if the DWARF line program is malformed.
pub fn parse_line_info_gimli<R>(dwarf: &gimli::Dwarf<R>) -> GimliResult<LineInfoTable>
where
    R: gimli::Reader,
{
    let mut entries: Vec<GimliLineEntry> = Vec::new();
    let mut unit_iter = dwarf.units();

    while let Some(header) = unit_iter.next()? {
        let unit = dwarf.unit(header)?;

        // Not every CU has a line program (e.g. skeleton units in split DWARF).
        let Some(program) = unit.line_program.clone() else { continue };

        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row()? {
            if row.end_sequence() {
                continue;
            }

            let address = row.address();
            let line = row.line().map_or(0, |l| u32::try_from(l.get()).unwrap_or(u32::MAX));
            let column = match row.column() {
                gimli::ColumnType::LeftEdge => 0,
                gimli::ColumnType::Column(c) => u32::try_from(c.get()).unwrap_or(u32::MAX),
            };
            let is_stmt = row.is_stmt();

            // Resolve file name.
            let file_name = row
                .file(header)
                .and_then(|fe| {
                    let path = dwarf.attr_string(&unit, fe.path_name()).ok()?;
                    let dir = fe
                        .directory(header)
                        .and_then(|d| dwarf.attr_string(&unit, d).ok())
                        .map(|d| d.to_string_lossy().unwrap_or_default().into_owned())
                        .unwrap_or_default();
                    let filename = path.to_string_lossy().unwrap_or_default().into_owned();
                    Some(if dir.is_empty() {
                        filename
                    } else {
                        format!("{dir}/{filename}")
                    })
                })
                .unwrap_or_default();

            entries.push(GimliLineEntry {
                address,
                file: file_name,
                line,
                column,
                is_stmt,
            });
        }
    }

    // Sort by address for binary-search lookups.
    entries.sort_by_key(|e| e.address);

    Ok(LineInfoTable { entries })
}

// â"€â"€ High-level entry point â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Load a binary from `binary_path` and return the full `DwarfSymbolSet`
/// (functions + types + line mappings).
///
/// This is the recommended entry point for callers that need everything.
/// The binary format (ELF / Mach-O) is detected automatically via the
/// `object` crate.
///
/// # Errors
/// Returns `GimliDwarfError` on IO failure, unsupported format, or malformed
/// DWARF data.
pub fn load_dwarf_symbols(binary_path: &Path) -> GimliResult<DwarfSymbolSet> {
    let reader = GimliDwarfReader::open(binary_path)?;
    let functions = reader.parse_functions()?;
    let types = reader.parse_types()?;
    let line_info = reader.parse_line_info()?;
    Ok(DwarfSymbolSet {
        functions,
        types,
        line_info,
    })
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§8  SymbolProvider integration
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//
// Bridge between the DWARF reader types and the unified `SymbolProvider` trait
// from `rustre-symbols`.  Two wrappers are provided:
//
//  * `DwarfSymbolProvider` —" wraps the hand-rolled `DwarfReader`; converts
//    `DwarfFunction` records into `rustre_symbols::Symbol` and builds an
//    `AddressToSymbolMap` for O(log n) lookups.
//
//  * `GimliSymbolProvider` —" wraps `GimliDwarfReader`; converts
//    `GimliFunction` records the same way and additionally exposes
//    source-line information.
//
// Both are fully `Send + Sync` (the underlying readers own their data).

use rustre_symbols::{
    AddressToSymbolMap, LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding,
    SymbolProvider, SymbolVisibility,
};

// â"€â"€ DwarfSymbolProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Wraps the hand-rolled [`DwarfReader`] and exposes it as a
/// [`SymbolProvider`].
///
/// Symbols are built eagerly from `.debug_info` on construction and stored in
/// an [`AddressToSymbolMap`] for fast floor-search lookups.
#[derive(Debug)]
pub struct DwarfSymbolProvider {
    symbols: AddressToSymbolMap,
    all: Vec<Symbol>,
}

impl DwarfSymbolProvider {
    /// Build a provider from an existing [`DwarfReader`].
    #[must_use]
    pub fn new(reader: &DwarfReader) -> Self {
        let funcs = reader.functions();
        let mut all: Vec<Symbol> = funcs
            .iter()
            .filter(|f| !f.name.is_empty() && f.low_pc != 0)
            .map(|f| {
                let size = if f.high_pc > f.low_pc {
                    Some(f.high_pc - f.low_pc)
                } else {
                    None
                };
                let mut sym = Symbol::new(f.name.clone(), f.low_pc, SymKind::Function);
                sym.size = size;
                sym.source = LegacySymbolSource::Debug;
                sym.binding = SymbolBinding::Global;
                sym.visibility = SymbolVisibility::Default;
                sym
            })
            .collect();
        all.sort_by_key(|s| s.address);
        let symbols = AddressToSymbolMap::from_symbols(&all);
        Self { symbols, all }
    }
}

impl SymbolProvider for DwarfSymbolProvider {
    fn name(&self) -> &'static str {
        "dwarf-hand-rolled"
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.all.iter().find(|s| s.name == name).cloned()
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.symbols.lookup_exact(addr).cloned()
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        self.symbols.lookup_floor(addr).cloned()
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.all.clone()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.all
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }

    fn source_line_for_address(&self, _addr: u64) -> Option<SourceLocation> {
        // The hand-rolled reader does have a `.line_info()` method, but
        // building an index inside `DwarfSymbolProvider` would require
        // keeping the reader alive.  Callers that need source lines should
        // use `GimliSymbolProvider` instead.
        None
    }
}

// â"€â"€ GimliSymbolProvider â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Wraps [`GimliDwarfReader`] and exposes it as a [`SymbolProvider`].
///
/// In addition to symbol lookups this also implements
/// `source_line_for_address` using the parsed [`LineInfoTable`].
#[derive(Debug)]
pub struct GimliSymbolProvider {
    symbols: AddressToSymbolMap,
    all: Vec<Symbol>,
    line_info: LineInfoTable,
}

impl GimliSymbolProvider {
    /// Build a provider from an existing [`GimliDwarfReader`].
    ///
    /// Returns an error if DWARF parsing fails.
    ///
    /// # Errors
    /// Propagates `GimliDwarfError` from the underlying reader.
    pub fn new(reader: &GimliDwarfReader) -> GimliResult<Self> {
        let funcs = reader.parse_functions()?;
        let line_info = reader.parse_line_info()?;

        let mut all: Vec<Symbol> = funcs
            .iter()
            .filter(|f| f.low_pc != 0)
            .map(|f| {
                let name = f
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("sub_{:#x}", f.low_pc));
                let size = if f.high_pc > f.low_pc {
                    Some(f.high_pc - f.low_pc)
                } else {
                    None
                };
                let mut sym = Symbol::new(name, f.low_pc, SymKind::Function);
                sym.size = size;
                sym.source = LegacySymbolSource::Debug;
                sym.binding = SymbolBinding::Global;
                sym.visibility = SymbolVisibility::Default;
                sym.source_file.clone_from(&f.file);
                sym.source_line = f.line;
                sym
            })
            .collect();
        all.sort_by_key(|s| s.address);
        let symbols = AddressToSymbolMap::from_symbols(&all);
        Ok(Self {
            symbols,
            all,
            line_info,
        })
    }
}

impl SymbolProvider for GimliSymbolProvider {
    fn name(&self) -> &'static str {
        "dwarf-gimli"
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.all.iter().find(|s| s.name == name).cloned()
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.symbols.lookup_exact(addr).cloned()
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        self.symbols.lookup_floor(addr).cloned()
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.all.clone()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.all
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }

    fn source_line_for_address(&self, addr: u64) -> Option<SourceLocation> {
        let entry = self.line_info.lookup_address(addr)?;
        Some(SourceLocation {
            file: entry.file.clone(),
            line: entry.line,
            column: entry.column,
        })
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Â§9  DwarfUnwinder —" CFI-based stack unwinder
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//
// Parses `.eh_frame` (C++ ABI exception-handling frame data) or `.debug_frame`
// (DWARF debug frame data) and uses the resulting CFI (Call-Frame Information)
// tables to compute the caller's PC and register state from a callee frame.
//
// # CFI primer
//
// Each FDE (Frame Description Entry) covers a range of PCs and contains a
// program (a sequence of CFI opcodes) that, when interpreted from the matching
// CIE (Common Information Entry), produces a table:
//
//     PC  | CFA rule                  | Saved-reg rules
//     -----|--------------------------|------------------------
//     0x—¦  | rsp + 8                  | ra = [cfa - 8]
//     0x—¦  | rsp + 16                 | ra = [cfa - 8]  rbp = [cfa - 16]
//     —¦    | —¦                        | —¦
//
// To unwind one frame:
//  1. Find the FDE whose range contains the current PC.
//  2. Run the CIE + FDE programs up to the current PC â†' get the table row.
//  3. Evaluate the CFA (Canonical Frame Address) using the current registers.
//  4. For each saved register, load its value from memory at the computed
//     address.
//  5. The return address register value becomes the caller's PC.
//
// This implementation performs steps 1 and 2 using the gimli `UnwindTable`
// machinery.  Steps 3—"5 are delegated to the caller because this crate does not
// perform memory reads.  `unwind_at` returns the *rules* needed by the caller
// to complete the unwind.

/// A single saved-register rule decoded from the CFI table row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CfiRegRule {
    /// Register value is at `CFA + offset`.
    CfaOffset(i64),
    /// Register has the same value as in the caller (i.e. callee-saved,
    /// not actually saved to the stack).
    SameValue,
    /// Register is not available / undefined.
    Undefined,
}

/// The result of evaluating a CFI table row at a given PC.
///
/// The caller uses `cfa_rule` to compute the CFA (a stack address), then
/// uses the `saved_regs` map to load each callee-saved register from memory.
/// The return-address register (conventionally `ra`) gives the caller's PC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnwindRow {
    /// How to compute the CFA: the pair `(register, offset)` such that
    /// `CFA = registers[register] + offset`.
    pub cfa_register: u16,
    /// Signed byte offset added to `cfa_register`'s value to obtain the CFA.
    pub cfa_offset: i64,
    /// Rules for registers that are saved in this frame.
    /// Key = DWARF register number, value = how to recover the register.
    pub saved_regs: HashMap<u16, CfiRegRule>,
}

/// A simplified stack frame produced by `DwarfUnwinder::unwind_at`.
///
/// The caller is responsible for actually reading memory; this struct encodes
/// *what* to read and *where* the result should go.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnwindStep {
    /// The CFA rule: `CFA = registers[cfa_register] + cfa_offset`.
    pub cfa_register: u16,
    /// Signed byte offset added to `cfa_register`'s value to obtain the CFA.
    pub cfa_offset: i64,
    /// DWARF register number of the return-address register.
    pub ra_register: u16,
    /// Where to find the saved return address: `CFA + ra_cfa_offset`.
    pub ra_cfa_offset: i64,
    /// All other saved registers: `DWARF_reg â†' (CFA + offset)`.
    pub saved_regs: HashMap<u16, i64>,
}

/// CFI-based stack unwinder.
///
/// Parses `.eh_frame` (preferred) or `.debug_frame` from raw ELF section bytes
/// and answers `unwind_at(pc)` queries.
pub struct DwarfUnwinder {
    /// Pre-loaded `.eh_frame` data (may be empty).
    eh_frame_data: Vec<u8>,
    /// Pre-loaded `.debug_frame` data (may be empty).
    debug_frame_data: Vec<u8>,
    /// The base address of `.eh_frame` in the loaded binary (needed to
    /// resolve PC-relative FDE `initial_location` fields).  Zero when
    /// the section was not found or the address is unknown.
    eh_frame_base: u64,
}

impl std::fmt::Debug for DwarfUnwinder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DwarfUnwinder")
            .field("eh_frame_len", &self.eh_frame_data.len())
            .field("debug_frame_len", &self.debug_frame_data.len())
            .field("eh_frame_base", &format_args!("{:#x}", self.eh_frame_base))
            .finish_non_exhaustive()
    }
}

impl DwarfUnwinder {
    /// Returns the virtual base address of the `.eh_frame` section, or `0`
    /// when the section was not present or the address is unknown.
    ///
    /// This is required to resolve PC-relative `initial_location` fields in
    /// FDE records when callers want to map raw `.eh_frame` offsets back to
    /// loaded virtual addresses.
    #[must_use]
    pub const fn eh_frame_base(&self) -> u64 {
        self.eh_frame_base
    }
}

impl DwarfUnwinder {
    /// Parse `.eh_frame` and/or `.debug_frame` sections from raw bytes.
    ///
    /// Windows PE binaries (identified by the `MZ` magic bytes) contain no
    /// `.eh_frame` or `.debug_frame` sections; they are accepted gracefully
    /// and the unwinder will return `None` for all `unwind_at` queries.
    ///
    /// # Errors
    /// Returns [`DwarfError::UnsupportedFormat`] if `data` is not a
    /// little-endian 32-bit or 64-bit ELF binary and not a Windows PE file.
    pub fn new(data: &[u8]) -> Result<Self> {
        // Windows PE files use PDB rather than DWARF frame info.  Accept them
        // silently instead of propagating UnsupportedFormat.
        let sections = if data.starts_with(b"MZ") {
            HashMap::new()
        } else {
            elf_sections(data)?
        };

        let eh_frame_data = sections.get(".eh_frame").cloned().unwrap_or_default();
        let debug_frame_data = sections.get(".debug_frame").cloned().unwrap_or_default();

        // Attempt to extract the virtual address of the .eh_frame section.
        // We need this to resolve PC-relative pointers inside FDE headers.
        // As a best-effort approach we re-parse the section headers quickly.
        let eh_frame_base = Self::find_section_vaddr(data, ".eh_frame").unwrap_or(0);

        Ok(Self {
            eh_frame_data,
            debug_frame_data,
            eh_frame_base,
        })
    }

    /// Build an unwinder directly from pre-extracted section bytes (useful for
    /// unit testing without a full ELF binary).
    ///
    /// `eh_frame` and/or `debug_frame` may be empty slices.
    #[must_use]
    pub fn from_sections(eh_frame: &[u8], debug_frame: &[u8]) -> Self {
        Self {
            eh_frame_data: eh_frame.to_vec(),
            debug_frame_data: debug_frame.to_vec(),
            eh_frame_base: 0,
        }
    }

    // â"€â"€ Internal: find a section's virtual address â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Return the virtual address (load address) of a named ELF section.
    fn find_section_vaddr(raw: &[u8], name: &str) -> Option<u64> {
        if raw.len() < 16 {
            return None;
        }
        if raw[0..4] != [0x7f, b'E', b'L', b'F'] {
            return None;
        }
        let ei_class = raw[4];
        let ei_data = raw[5];
        if ei_data != 1 {
            return None;
        } // only LE

        match ei_class {
            1 => {
                // 32-bit
                let e_shoff = {
                    let mut o = 32usize;
                    read_u32_le(raw, &mut o).ok()? as usize
                };
                let mut o2 = 40usize;
                let _flags = read_u32_le(raw, &mut o2).ok()?;
                let _ehsize = read_u16_le(raw, &mut o2).ok()?;
                let _phentsize = read_u16_le(raw, &mut o2).ok()?;
                let _phnum = read_u16_le(raw, &mut o2).ok()?;
                let e_shentsize = read_u16_le(raw, &mut o2).ok()? as usize;
                let e_shnum = read_u16_le(raw, &mut o2).ok()? as usize;
                let e_shstrndx = read_u16_le(raw, &mut o2).ok()? as usize;

                let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
                let mut sh = shstr_hdr + 16;
                let shstr_off = read_u32_le(raw, &mut sh).ok()? as usize;
                let shstr_size = read_u32_le(raw, &mut sh).ok()? as usize;
                let shstrtab = raw.get(shstr_off..shstr_off + shstr_size)?;

                for i in 0..e_shnum {
                    let hdr = e_shoff + i * e_shentsize;
                    let mut h = hdr;
                    let sh_name = read_u32_le(raw, &mut h).ok()? as usize;
                    let _sh_type = read_u32_le(raw, &mut h).ok()?;
                    let _sh_flags = read_u32_le(raw, &mut h).ok()?;
                    let sh_addr = u64::from(read_u32_le(raw, &mut h).ok()?);
                    let _sh_offset = read_u32_le(raw, &mut h).ok()?;
                    let _sh_size = read_u32_le(raw, &mut h).ok()?;

                    let name_end = shstrtab[sh_name..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(shstrtab.len(), |p| sh_name + p);
                    let sec_name = std::str::from_utf8(&shstrtab[sh_name..name_end]).unwrap_or("");
                    if sec_name == name {
                        return Some(sh_addr);
                    }
                }
                None
            }
            2 => {
                // 64-bit
                let e_shoff = {
                    let mut o = 40usize;
                    usize::try_from(read_u64_le(raw, &mut o).ok()?).ok()?
                };
                let mut o2 = 58usize;
                let e_shentsize = read_u16_le(raw, &mut o2).ok()? as usize;
                let e_shnum = read_u16_le(raw, &mut o2).ok()? as usize;
                let e_shstrndx = read_u16_le(raw, &mut o2).ok()? as usize;

                let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
                let mut sh = shstr_hdr + 24;
                let shstr_off = usize::try_from(read_u64_le(raw, &mut sh).ok()?).ok()?;
                let shstr_size = usize::try_from(read_u64_le(raw, &mut sh).ok()?).ok()?;
                let shstrtab = raw.get(shstr_off..shstr_off + shstr_size)?;

                for i in 0..e_shnum {
                    let hdr = e_shoff + i * e_shentsize;
                    let mut h = hdr;
                    let sh_name = read_u32_le(raw, &mut h).ok()? as usize;
                    let _sh_type = read_u32_le(raw, &mut h).ok()?;
                    let _sh_flags = read_u64_le(raw, &mut h).ok()?;
                    let sh_addr = read_u64_le(raw, &mut h).ok()?;
                    let _sh_offset = read_u64_le(raw, &mut h).ok()?;
                    let _sh_size = read_u64_le(raw, &mut h).ok()?;

                    let name_end = shstrtab[sh_name..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(shstrtab.len(), |p| sh_name + p);
                    let sec_name = std::str::from_utf8(&shstrtab[sh_name..name_end]).unwrap_or("");
                    if sec_name == name {
                        return Some(sh_addr);
                    }
                }
                None
            }
            _ => None,
        }
    }

    // â"€â"€ Public API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Look up the CFI unwind row that covers `pc` and return an `UnwindStep`
    /// describing how to compute the caller's frame.
    ///
    /// The caller must:
    /// 1. Compute `CFA = registers[step.cfa_register] + step.cfa_offset`.
    /// 2. Load the return address from memory at `CFA + step.ra_cfa_offset`.
    /// 3. For each `(reg, offset)` in `step.saved_regs`, load the saved
    ///    register value from `CFA + offset`.
    ///
    /// Returns `None` if no FDE covers `pc` or if the frame sections are empty.
    #[must_use]
    pub fn unwind_at(&self, pc: u64) -> Option<UnwindStep> {
        // Try .eh_frame first, then fall back to .debug_frame.
        if !self.eh_frame_data.is_empty()
            && let Some(step) = self.unwind_with_eh_frame(pc)
        {
            return Some(step);
        }
        if !self.debug_frame_data.is_empty()
            && let Some(step) = self.unwind_with_debug_frame(pc)
        {
            return Some(step);
        }
        None
    }

    /// Perform a full register-state unwind at `pc`.
    ///
    /// This is a higher-level helper that combines `unwind_at` with an
    /// in-process register map.  The caller supplies the current register
    /// values (`registers`, keyed by DWARF register number as a string like
    /// `"7"` for RSP on x86-64) and a closure `read_mem` that reads 8 bytes
    /// from a virtual address.
    ///
    /// Returns the caller's PC and updated register map, or `None` if unwinding
    /// is not possible at this address.
    pub fn unwind_frame(
        &self,
        pc: u64,
        registers: &HashMap<String, u64>,
        mut read_mem: impl FnMut(u64) -> Option<u64>,
    ) -> Option<(u64, HashMap<String, u64>)> {
        let step = self.unwind_at(pc)?;

        // Step 1: compute CFA.
        let cfa_reg_val = registers.get(&step.cfa_register.to_string()).copied()?;
        let cfa = (cfa_reg_val.cast_signed() + step.cfa_offset).cast_unsigned();

        // Step 2: load the return address.
        let ra_addr = (cfa.cast_signed() + step.ra_cfa_offset).cast_unsigned();
        let caller_pc = read_mem(ra_addr)?;

        // Step 3: restore saved registers.
        let mut new_regs = registers.clone();
        for (reg, offset) in &step.saved_regs {
            let mem_addr = (cfa.cast_signed() + offset).cast_unsigned();
            if let Some(val) = read_mem(mem_addr) {
                new_regs.insert(reg.to_string(), val);
            }
        }

        // Update the stack pointer to the CFA (the callee's CFA = caller's SP
        // on the System-V x86-64 ABI).
        new_regs.insert(step.cfa_register.to_string(), cfa);

        Some((caller_pc, new_regs))
    }

    // ── Internal: CFI-based unwinding ──────────────────────────────────────────
    // Simplified implementation: scan .eh_frame for the FDE covering `pc`
    // and extract the CFA rule.  Returns None when no FDE covers the address
    // (caller falls back to frame-pointer chain).

    fn unwind_with_eh_frame(&self, pc: u64) -> Option<UnwindStep> {
        Self::unwind_with_cfi(&self.eh_frame_data, pc, true)
    }

    fn unwind_with_debug_frame(&self, pc: u64) -> Option<UnwindStep> {
        Self::unwind_with_cfi(&self.debug_frame_data, pc, false)
    }

    /// Run the real CFI interpreter for `pc`.
    ///
    /// The previous implementation linear-scanned for an FDE and then returned
    /// a hardcoded x86-64 step (`CFA = rsp+8`, `ra = CFA-8`) for *every* PC,
    /// ignoring the CIE/FDE instructions entirely — a corrupted backtrace that
    /// looks successful. This delegates to `dwarf_call_frame`'s interpreter,
    /// which the crate already contained but never called from here.
    ///
    /// Returns `None` when no FDE/row covers `pc`, so `unwind_frame` still
    /// falls back to the frame-pointer chain rather than trusting a guess.
    fn unwind_with_cfi(section: &[u8], pc: u64, is_eh_frame: bool) -> Option<UnwindStep> {
        if section.is_empty() {
            return None;
        }
        let cfi = dwarf_call_frame::CfiSection::parse(section, is_eh_frame);
        let fde = cfi.fde_for_pc(pc)?;
        // Resolve the FDE's own CIE for the return-address register number.
        let cie = cfi
            .cies
            .iter()
            .find(|c| c.section_offset == fde.cie_offset)
            .or_else(|| cfi.cies.first())?;
        let table = cfi.unwind_table_for_pc(pc)?;
        let row = table.row_for_pc(pc)?;

        let (cfa_register, cfa_offset) = match &row.cfa {
            dwarf_call_frame::CfaRule::RegisterAndOffset { reg, offset } => {
                (u16::try_from(*reg).ok()?, *offset)
            }
            // An expression-based CFA needs a full DWARF expression evaluation
            // against live registers; report "unknown" rather than guessing.
            _ => return None,
        };

        let ra_register = u16::try_from(cie.return_addr_reg).ok()?;
        let mut ra_cfa_offset = None;
        let mut saved_regs = HashMap::new();
        for (reg, rule) in &row.registers {
            if let dwarf_call_frame::RegRule::Offset(off) = rule {
                let Ok(r) = u16::try_from(*reg) else { continue };
                if r == ra_register {
                    ra_cfa_offset = Some(*off);
                } else {
                    saved_regs.insert(r, *off);
                }
            }
        }

        Some(UnwindStep {
            cfa_register,
            cfa_offset,
            ra_register,
            ra_cfa_offset: ra_cfa_offset?,
            saved_regs,
        })
    }
}

// â"€â"€ Tests for SymbolProvider integration â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod symbol_provider_tests {
    use super::*;

    fn make_simple_dwarf() -> DwarfReader {
        // Reuse the test helper from the main tests module to build a
        // DwarfReader with one known function.
        use std::collections::HashMap;

        fn encode_uleb(mut n: u64) -> Vec<u8> {
            let mut v = Vec::new();
            loop {
                let mut b = (n & 0x7f) as u8;
                n >>= 7;
                if n != 0 {
                    b |= 0x80;
                }
                v.push(b);
                if n == 0 {
                    break;
                }
            }
            v
        }

        fn abbrev_entry(code: u64, tag: u64, has_children: bool, attrs: &[(u64, u64)]) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend(encode_uleb(code));
            v.extend(encode_uleb(tag));
            v.push(u8::from(has_children));
            for &(a, f) in attrs {
                v.extend(encode_uleb(a));
                v.extend(encode_uleb(f));
            }
            v.extend([0, 0]);
            v
        }

        let mut abbrev = Vec::new();
        abbrev.extend(abbrev_entry(
            1,
            DW_TAG_COMPILE_UNIT,
            true,
            &[(DW_AT_NAME, DW_FORM_STRING)],
        ));
        abbrev.extend(abbrev_entry(
            2,
            DW_TAG_SUBPROGRAM,
            false,
            &[
                (DW_AT_NAME, DW_FORM_STRING),
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_HIGH_PC, DW_FORM_DATA8),
            ],
        ));
        abbrev.extend([0u8]);

        let mut info_body = Vec::new();
        info_body.extend(encode_uleb(1));
        info_body.extend_from_slice(b"test.c\x00");
        info_body.extend(encode_uleb(2));
        info_body.extend_from_slice(b"my_fn\x00");
        info_body.extend_from_slice(&0x1000u64.to_le_bytes());
        info_body.extend_from_slice(&0x100u64.to_le_bytes());
        info_body.push(0); // children terminator
        info_body.push(0); // null terminator

        let unit_len = (2 + 4 + 1 + info_body.len()) as u32;
        let mut info = Vec::new();
        info.extend_from_slice(&unit_len.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.push(8);
        info.extend(info_body);

        let mut sections: HashMap<String, Vec<u8>> = HashMap::new();
        sections.insert(".debug_info".into(), info);
        sections.insert(".debug_abbrev".into(), abbrev);
        DwarfReader::from_sections(sections)
    }

    #[test]
    fn test_dwarf_symbol_provider_all_symbols() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        let syms = provider.all_symbols();
        assert!(!syms.is_empty());
        assert_eq!(syms[0].name, "my_fn");
        assert_eq!(syms[0].address, 0x1000);
        assert_eq!(syms[0].size, Some(0x100));
    }

    #[test]
    fn test_dwarf_symbol_provider_lookup_name() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        assert!(provider.lookup_name("my_fn").is_some());
        assert!(provider.lookup_name("nonexistent").is_none());
    }

    #[test]
    fn test_dwarf_symbol_provider_lookup_address_exact() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        let sym = provider.lookup_address(0x1000).unwrap();
        assert_eq!(sym.name, "my_fn");
    }

    #[test]
    fn test_dwarf_symbol_provider_lookup_address_miss() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        assert!(provider.lookup_address(0x1001).is_none());
    }

    #[test]
    fn test_dwarf_symbol_provider_lookup_nearest() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        let sym = provider.lookup_nearest(0x1050).unwrap();
        assert_eq!(sym.name, "my_fn");
    }

    #[test]
    fn test_dwarf_symbol_provider_all_functions() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        let fns = provider.all_functions();
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].kind, rustre_symbols::SymKind::Function);
    }

    #[test]
    fn test_dwarf_symbol_provider_name() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        assert_eq!(provider.name(), "dwarf-hand-rolled");
    }

    #[test]
    fn test_dwarf_symbol_provider_source_line_none() {
        let reader = make_simple_dwarf();
        let provider = DwarfSymbolProvider::new(&reader);
        // Hand-rolled provider does not return source lines.
        assert!(provider.source_line_for_address(0x1000).is_none());
    }

    #[test]
    fn test_dwarf_unwinder_empty_sections() {
        let unwinder = DwarfUnwinder::from_sections(&[], &[]);
        assert!(unwinder.unwind_at(0x1000).is_none());
    }

    #[test]
    fn test_dwarf_unwinder_invalid_elf() {
        let result = DwarfUnwinder::new(b"not an elf binary");
        assert!(result.is_err());
    }

    #[test]
    fn test_dwarf_unwinder_from_sections_debug() {
        let unwinder = DwarfUnwinder::from_sections(&[], &[]);
        // With empty sections, unwind should return None gracefully.
        assert!(unwinder.unwind_at(0xdeadbeef).is_none());
    }

    #[test]
    fn test_unwind_step_fields() {
        let step = UnwindStep {
            cfa_register: 7,
            cfa_offset: 8,
            ra_register: 16,
            ra_cfa_offset: -8,
            saved_regs: HashMap::new(),
        };
        assert_eq!(step.cfa_register, 7);
        assert_eq!(step.cfa_offset, 8);
        assert_eq!(step.ra_register, 16);
        assert_eq!(step.ra_cfa_offset, -8);
        assert!(step.saved_regs.is_empty());
    }

    #[test]
    fn test_unwind_frame_no_cfi() {
        // With no CFI data, unwind_frame should return None.
        let unwinder = DwarfUnwinder::from_sections(&[], &[]);
        let regs: HashMap<String, u64> = std::iter::once(("7".to_string(), 0x7fff_0000u64)).collect();
        let result = unwinder.unwind_frame(0x1000, &regs, |_| None);
        assert!(result.is_none());
    }
}

// â"€â"€ gimli tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod gimli_tests {
    use super::*;

    // â"€â"€ LineInfoTable::lookup_address â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_line_entry(addr: u64, file: &str, line: u32) -> GimliLineEntry {
        GimliLineEntry {
            address: addr,
            file: file.to_owned(),
            line,
            column: 0,
            is_stmt: true,
        }
    }

    #[test]
    fn test_lookup_address_empty() {
        let t = LineInfoTable::default();
        assert!(t.lookup_address(0x1000).is_none());
    }

    #[test]
    fn test_lookup_address_exact() {
        let t = LineInfoTable {
            entries: vec![
                make_line_entry(0x1000, "a.c", 1),
                make_line_entry(0x1010, "a.c", 2),
                make_line_entry(0x1020, "a.c", 3),
            ],
        };
        assert_eq!(t.lookup_address(0x1010).unwrap().line, 2);
    }

    #[test]
    fn test_lookup_address_between_rows() {
        let t = LineInfoTable {
            entries: vec![
                make_line_entry(0x1000, "a.c", 10),
                make_line_entry(0x1010, "a.c", 20),
            ],
        };
        // 0x1008 falls between row 1 and row 2 —" should return row 1.
        let entry = t.lookup_address(0x1008).unwrap();
        assert_eq!(entry.line, 10);
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn test_lookup_address_before_first() {
        let t = LineInfoTable {
            entries: vec![make_line_entry(0x2000, "b.c", 5)],
        };
        // Address before the first row â†' None.
        assert!(t.lookup_address(0x1000).is_none());
    }

    #[test]
    fn test_lookup_address_after_last() {
        let t = LineInfoTable {
            entries: vec![
                make_line_entry(0x1000, "a.c", 1),
                make_line_entry(0x1010, "a.c", 2),
            ],
        };
        // Well past the last entry —" should return the last entry.
        let entry = t.lookup_address(0xFFFF_FFFF).unwrap();
        assert_eq!(entry.address, 0x1010);
        assert_eq!(entry.line, 2);
    }

    // â"€â"€ GimliLocation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_location_debug() {
        let loc = GimliLocation::Register(5);
        assert!(format!("{loc:?}").contains("Register"));
    }

    #[test]
    fn test_gimli_location_stack_offset_negative() {
        let loc = GimliLocation::StackOffset(-16);
        if let GimliLocation::StackOffset(o) = loc {
            assert_eq!(o, -16);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_gimli_location_global() {
        let loc = GimliLocation::Global(0xDEAD_BEEF);
        if let GimliLocation::Global(a) = loc {
            assert_eq!(a, 0xDEAD_BEEF);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_gimli_location_expression() {
        let bytes = vec![0x91u8, 0x70]; // DW_OP_fbreg -16 (sleb128)
        let loc = GimliLocation::Expression(bytes.clone());
        if let GimliLocation::Expression(b) = loc {
            assert_eq!(b, bytes);
        } else {
            panic!("Wrong variant");
        }
    }

    // â"€â"€ GimliType / TypeKind â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_type_kind_base() {
        let t = GimliType {
            name: "int".into(),
            size: Some(4),
            kind: TypeKind::Base("int".into()),
        };
        if let TypeKind::Base(ref enc) = t.kind {
            assert_eq!(enc, "int");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_pointer() {
        let inner = GimliType {
            name: "int".into(),
            size: Some(4),
            kind: TypeKind::Base("int".into()),
        };
        let ptr = GimliType {
            name: "int*".into(),
            size: Some(8),
            kind: TypeKind::Pointer(Box::new(inner)),
        };
        if let TypeKind::Pointer(ref i) = ptr.kind {
            assert_eq!(i.name, "int");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_struct_empty_fields() {
        let s = GimliType {
            name: "Empty".into(),
            size: Some(0),
            kind: TypeKind::Struct(vec![]),
        };
        if let TypeKind::Struct(ref fields) = s.kind {
            assert!(fields.is_empty());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_struct_with_fields() {
        let inner = GimliType {
            name: "int".into(),
            size: Some(4),
            kind: TypeKind::Base("int".into()),
        };
        let field = StructField {
            name: "x".into(),
            type_: inner,
            offset: 0,
        };
        let s = GimliType {
            name: "Point".into(),
            size: Some(4),
            kind: TypeKind::Struct(vec![field]),
        };
        if let TypeKind::Struct(ref fields) = s.kind {
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name, "x");
            assert_eq!(fields[0].offset, 0);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_array() {
        let elem = GimliType {
            name: "u8".into(),
            size: Some(1),
            kind: TypeKind::Base("u8".into()),
        };
        let arr = GimliType {
            name: "u8[]".into(),
            size: Some(16),
            kind: TypeKind::Array {
                elem: Box::new(elem),
                count: Some(16),
            },
        };
        if let TypeKind::Array { ref elem, count } = arr.kind {
            assert_eq!(elem.name, "u8");
            assert_eq!(count, Some(16));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_enum() {
        let e = GimliType {
            name: "Color".into(),
            size: Some(4),
            kind: TypeKind::Enum(vec!["Red".into(), "Green".into(), "Blue".into()]),
        };
        if let TypeKind::Enum(ref vals) = e.kind {
            assert_eq!(vals.len(), 3);
            assert_eq!(vals[0], "Red");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_type_kind_typedef() {
        let inner = GimliType {
            name: "unsigned int".into(),
            size: Some(4),
            kind: TypeKind::Base("unsigned int".into()),
        };
        let td = GimliType {
            name: "uint32_t".into(),
            size: Some(4),
            kind: TypeKind::Typedef(Box::new(inner)),
        };
        if let TypeKind::Typedef(ref i) = td.kind {
            assert_eq!(i.name, "unsigned int");
        } else {
            panic!();
        }
    }

    // â"€â"€ GimliFunction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_function_basic() {
        let f = GimliFunction {
            name: Some("my_func".into()),
            low_pc: 0x4000,
            high_pc: 0x4100,
            file: Some("src/main.c".into()),
            line: Some(42),
            params: vec![],
            locals: vec![],
            return_type: Some("int".into()),
        };
        assert_eq!(f.name.as_deref(), Some("my_func"));
        assert_eq!(f.high_pc - f.low_pc, 0x100);
        assert_eq!(f.line, Some(42));
    }

    #[test]
    fn test_gimli_function_no_name() {
        let f = GimliFunction {
            name: None,
            low_pc: 0,
            high_pc: 0,
            file: None,
            line: None,
            params: vec![],
            locals: vec![],
            return_type: None,
        };
        assert!(f.name.is_none());
        assert!(f.return_type.is_none());
    }

    #[test]
    fn test_gimli_function_with_params() {
        let p = GimliVariable {
            name: Some("argc".into()),
            type_name: "int".into(),
            location: GimliLocation::Register(0),
        };
        let f = GimliFunction {
            name: Some("main".into()),
            low_pc: 0x1000,
            high_pc: 0x2000,
            file: None,
            line: None,
            params: vec![p],
            locals: vec![],
            return_type: Some("int".into()),
        };
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name.as_deref(), Some("argc"));
    }

    // â"€â"€ GimliVariable â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_variable_unknown_location() {
        let v = GimliVariable {
            name: Some("x".into()),
            type_name: "float".into(),
            location: GimliLocation::Unknown,
        };
        assert_eq!(v.location, GimliLocation::Unknown);
    }

    #[test]
    fn test_gimli_variable_none_name() {
        let v = GimliVariable {
            name: None,
            type_name: "int".into(),
            location: GimliLocation::Register(1),
        };
        assert!(v.name.is_none());
    }

    // â"€â"€ DwarfSymbolSet â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_dwarf_symbol_set_default() {
        let set = DwarfSymbolSet::default();
        assert!(set.functions.is_empty());
        assert!(set.types.is_empty());
        assert!(set.line_info.entries.is_empty());
    }

    // â"€â"€ StructField â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_struct_field_serialise() {
        let inner = GimliType {
            name: "u32".into(),
            size: Some(4),
            kind: TypeKind::Base("u32".into()),
        };
        let field = StructField {
            name: "id".into(),
            type_: inner,
            offset: 8,
        };
        assert_eq!(field.offset, 8);
        assert_eq!(field.name, "id");
        assert_eq!(field.type_.name, "u32");
    }

    // â"€â"€ Integration: open a non-existent file returns error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_reader_nonexistent_file() {
        let result = GimliDwarfReader::open(Path::new("/nonexistent/binary"));
        assert!(result.is_err());
    }

    // â"€â"€ Integration: empty bytes returns UnsupportedFormat â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_reader_empty_bytes() {
        let result = GimliDwarfReader::from_elf(&[]);
        assert!(result.is_err());
    }

    // â"€â"€ Integration: random bytes returns error â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_gimli_reader_garbage_bytes() {
        let data = vec![0xAAu8; 1024];
        let result = GimliDwarfReader::from_elf(&data);
        assert!(result.is_err());
    }
}
