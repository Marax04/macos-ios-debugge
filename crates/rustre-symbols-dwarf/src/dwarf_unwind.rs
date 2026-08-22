//! `dwarf_unwind` — DWARF unwind info parser (.`eh_frame` / .`debug_frame`).
//!
//! Parses:
//! * CIE (Common Information Entry): augmentation, code/data alignment factors,
//!   return address register, initial call-frame instructions
//! * FDE (Frame Description Entry): PC range, LSDA pointer, call-frame instructions
//! * CFA tracking: register+offset or expression rules
//! * Register restoration rules: `same/offset/register/expression/val_expression/undefined`
//! * Prologue and epilogue recognition via CFA tracking simulation
//!
//! # Parallel implementations
//!
//! This crate ships more than one CFI implementation: see also `dwarf_call_frame`.
//! None of them is wired into [`crate::DwarfReader`], which uses its own
//! inline copy, so each carries an independent bug set and a fix applied
//! here does not propagate. Pick one deliberately and stay on it.
//! `dwarf_call_frame` is the path the crate itself consumes; prefer it.

use std::collections::HashMap;

use crate::casts::{u64_to_i64, u64_to_u32, u64_to_usize};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced while parsing CFI (`.eh_frame` / `.debug_frame`) data.
#[derive(Debug, thiserror::Error)]
pub enum UnwindError {
    /// The data ended unexpectedly at the given offset.
    #[error("truncated unwind data at offset {0}")]
    Truncated(usize),
    /// A CIE or FDE at the given offset is structurally invalid.
    #[error("corrupt CIE/FDE at offset {0}")]
    Corrupt(usize),
    /// The CIE augmentation string contains an unrecognized character.
    #[error("unknown augmentation character '{0}'")]
    UnknownAugmentation(char),
}

/// Convenience result alias for unwind parsing.
pub type Result<T> = std::result::Result<T, UnwindError>;

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], off: &mut usize) -> Result<u8> {
    let v = *data.get(*off).ok_or(UnwindError::Truncated(*off))?;
    *off += 1;
    Ok(v)
}

fn read_u16_le(data: &[u8], off: &mut usize) -> Result<u16> {
    if *off + 2 > data.len() { return Err(UnwindError::Truncated(*off)); }
    let v = u16::from_le_bytes(data[*off..*off + 2].try_into().unwrap());
    *off += 2;
    Ok(v)
}

fn read_u32_le(data: &[u8], off: &mut usize) -> Result<u32> {
    if *off + 4 > data.len() { return Err(UnwindError::Truncated(*off)); }
    let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], off: &mut usize) -> Result<u64> {
    if *off + 8 > data.len() { return Err(UnwindError::Truncated(*off)); }
    let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

fn read_uleb128(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = read_u8(data, off)?;
        result |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
        if shift >= 64 { break; }
    }
    Ok(result)
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Result<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let b = loop {
        let byte = read_u8(data, off)?;
        result |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 { break byte; }
        if shift >= 64 { break byte; }
    };
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
    let s = String::from_utf8_lossy(&data[start..*off]).into_owned();
    if *off < data.len() { *off += 1; }
    Ok(s)
}

// ── CFA rule ──────────────────────────────────────────────────────────────────

/// The rule defining the Canonical Frame Address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CfaRule {
    /// CFA = register + offset.
    RegisterOffset {
        /// DWARF register number the CFA is based on.
        register: u32,
        /// Signed byte offset added to the register value.
        offset: i64,
    },
    /// CFA is defined by a DWARF expression.
    Expression(Vec<u8>),
}

// ── Register rule ─────────────────────────────────────────────────────────────

/// How to restore a register at a given program point.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RegisterRule {
    /// Register value is undefined (not recoverable).
    Undefined,
    /// Register value is unchanged (same as before the frame).
    SameValue,
    /// Register is at `[CFA + offset]`.
    Offset(i64),
    /// Register is at `[CFA + offset]` as a value (not address).
    ValOffset(i64),
    /// Register value is in another register.
    Register(u32),
    /// Register value is defined by a DWARF expression.
    Expression(Vec<u8>),
    /// Register value is defined by a DWARF value expression.
    ValExpression(Vec<u8>),
    /// Architecture-specific.
    Architectural,
}

// ── Call frame row ────────────────────────────────────────────────────────────

/// A row in the call frame table at a particular program location.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallFrameRow {
    /// Program counter value at which this row applies.
    pub pc: u64,
    /// CFA rule at this point.
    pub cfa: CfaRule,
    /// Register rules at this point (keyed by DWARF register number).
    pub regs: HashMap<u32, RegisterRule>,
}

// ── CIE ───────────────────────────────────────────────────────────────────────

/// A parsed Common Information Entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Cie {
    /// Byte offset in the section.
    pub offset: usize,
    /// CIE version (1, 3, or 4).
    pub version: u8,
    /// Augmentation string.
    pub augmentation: String,
    /// Code alignment factor (multiply `DW_CFA_advance_loc` by this).
    pub code_alignment_factor: u64,
    /// Data alignment factor (multiply column offset by this for signed offsets).
    pub data_alignment_factor: i64,
    /// Return address register.
    pub return_address_register: u32,
    /// LSDA encoding (from 'L' augmentation).
    pub lsda_encoding: Option<u8>,
    /// FDE address encoding (from 'R' augmentation).
    pub fde_encoding: Option<u8>,
    /// Personality function pointer (from 'P' augmentation).
    pub personality: Option<u64>,
    /// Initial call frame program instructions.
    pub initial_instructions: Vec<u8>,
    /// Row produced by initial instructions.
    pub initial_row: CallFrameRow,
}

// ── FDE ───────────────────────────────────────────────────────────────────────

/// A parsed Frame Description Entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Fde {
    /// Byte offset in the section.
    pub offset: usize,
    /// CIE offset this FDE references.
    pub cie_offset: usize,
    /// Initial PC of the described region.
    pub initial_location: u64,
    /// Range of PCs covered (`initial_location..initial_location+address_range`).
    pub address_range: u64,
    /// LSDA pointer (if present).
    pub lsda: Option<u64>,
    /// Call-frame instructions for this FDE.
    pub instructions: Vec<u8>,
    /// Full call-frame table rows.
    pub rows: Vec<CallFrameRow>,
}

impl Fde {
    /// Return the closing PC address.
    #[must_use]
    pub const fn end_pc(&self) -> u64 {
        self.initial_location.wrapping_add(self.address_range)
    }

    /// Find the call-frame row for a given PC.
    #[must_use]
    pub fn row_at_pc(&self, pc: u64) -> Option<&CallFrameRow> {
        self.rows.iter().rev().find(|r| r.pc <= pc)
    }
}

// ── Call-frame instruction constants ─────────────────────────────────────────

// High 2 bits determine the class.
const DW_CFA_ADVANCE_LOC: u8 = 0x40;  // 01xxxxxx
const DW_CFA_OFFSET: u8 = 0x80;       // 10xxxxxx
const DW_CFA_RESTORE: u8 = 0xC0;      // 11xxxxxx

// Explicit opcodes (high bits = 00).
const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_SET_LOC: u8 = 0x01;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
const DW_CFA_UNDEFINED: u8 = 0x07;
const DW_CFA_SAME_VALUE: u8 = 0x08;
const DW_CFA_REGISTER: u8 = 0x09;
const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
const DW_CFA_RESTORE_STATE: u8 = 0x0b;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
const DW_CFA_EXPRESSION: u8 = 0x10;
const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
const DW_CFA_DEF_CFA_SF: u8 = 0x12;
const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
const DW_CFA_VAL_OFFSET: u8 = 0x14;
const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
const DW_CFA_GNU_ARGS_SIZE: u8 = 0x2e;
const DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED: u8 = 0x2f;

// ── Call-frame instruction executor ──────────────────────────────────────────

/// Execute a stream of call-frame instructions, starting from `initial_row`.
///
/// Returns the complete table of call-frame rows.
#[must_use] 
pub fn execute_cfi(
    instructions: &[u8],
    initial_row: &CallFrameRow,
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    addr_size: u8,
) -> Vec<CallFrameRow> {
    let mut rows: Vec<CallFrameRow> = Vec::new();
    let mut current = initial_row.clone();
    let mut state_stack: Vec<CallFrameRow> = Vec::new();
    let mut off = 0usize;

    while off < instructions.len() {
        let byte = match instructions.get(off) {
            Some(&b) => b,
            None => break,
        };
        off += 1;

        if byte & 0xC0 == DW_CFA_ADVANCE_LOC {
            let delta = u64::from(byte & 0x3f) * code_alignment_factor;
            current.pc = current.pc.wrapping_add(delta);
            rows.push(current.clone());
        } else if byte & 0xC0 == DW_CFA_OFFSET {
            let reg = u32::from(byte & 0x3f);
            let offset = u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0))
                * data_alignment_factor;
            current.regs.insert(reg, RegisterRule::Offset(offset));
        } else if byte & 0xC0 == DW_CFA_RESTORE {
            let reg = u32::from(byte & 0x3f);
            if let Some(r) = initial_row.regs.get(&reg) {
                current.regs.insert(reg, r.clone());
            } else {
                current.regs.insert(reg, RegisterRule::Undefined);
            }
        } else {
            match byte {
                DW_CFA_NOP => {}
                DW_CFA_SET_LOC => {
                    let new_pc = if addr_size == 8 {
                        read_u64_le(instructions, &mut off).unwrap_or(0)
                    } else {
                        u64::from(read_u32_le(instructions, &mut off).unwrap_or(0))
                    };
                    current.pc = new_pc;
                    rows.push(current.clone());
                }
                DW_CFA_ADVANCE_LOC1 => {
                    let delta = u64::from(read_u8(instructions, &mut off).unwrap_or(0))
                        * code_alignment_factor;
                    current.pc = current.pc.wrapping_add(delta);
                    rows.push(current.clone());
                }
                DW_CFA_ADVANCE_LOC2 => {
                    let delta = u64::from(read_u16_le(instructions, &mut off).unwrap_or(0))
                        * code_alignment_factor;
                    current.pc = current.pc.wrapping_add(delta);
                    rows.push(current.clone());
                }
                DW_CFA_ADVANCE_LOC4 => {
                    let delta = u64::from(read_u32_le(instructions, &mut off).unwrap_or(0))
                        * code_alignment_factor;
                    current.pc = current.pc.wrapping_add(delta);
                    rows.push(current.clone());
                }
                DW_CFA_OFFSET_EXTENDED => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0))
                        * data_alignment_factor;
                    current.regs.insert(reg, RegisterRule::Offset(offset));
                }
                DW_CFA_RESTORE_EXTENDED => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let rule = initial_row.regs.get(&reg)
                        .cloned()
                        .unwrap_or(RegisterRule::Undefined);
                    current.regs.insert(reg, rule);
                }
                DW_CFA_UNDEFINED => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    current.regs.insert(reg, RegisterRule::Undefined);
                }
                DW_CFA_SAME_VALUE => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    current.regs.insert(reg, RegisterRule::SameValue);
                }
                DW_CFA_REGISTER => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let src = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    current.regs.insert(reg, RegisterRule::Register(src));
                }
                DW_CFA_REMEMBER_STATE => {
                    state_stack.push(current.clone());
                }
                DW_CFA_RESTORE_STATE => {
                    if let Some(saved) = state_stack.pop() {
                        let pc = current.pc;
                        current = saved;
                        current.pc = pc;
                    }
                }
                DW_CFA_DEF_CFA => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0));
                    current.cfa = CfaRule::RegisterOffset { register: reg, offset };
                }
                DW_CFA_DEF_CFA_REGISTER => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    if let CfaRule::RegisterOffset { offset, .. } = current.cfa {
                        current.cfa = CfaRule::RegisterOffset { register: reg, offset };
                    }
                }
                DW_CFA_DEF_CFA_OFFSET => {
                    let offset = u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0));
                    if let CfaRule::RegisterOffset { register, .. } = current.cfa {
                        current.cfa = CfaRule::RegisterOffset { register, offset };
                    }
                }
                DW_CFA_DEF_CFA_EXPRESSION => {
                    let len = u64_to_usize(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let expr = instructions.get(off..off + len).unwrap_or(&[]).to_vec();
                    off += len;
                    current.cfa = CfaRule::Expression(expr);
                }
                DW_CFA_EXPRESSION => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let len = u64_to_usize(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let expr = instructions.get(off..off + len).unwrap_or(&[]).to_vec();
                    off += len;
                    current.regs.insert(reg, RegisterRule::Expression(expr));
                }
                DW_CFA_OFFSET_EXTENDED_SF => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = read_sleb128(instructions, &mut off).unwrap_or(0)
                        * data_alignment_factor;
                    current.regs.insert(reg, RegisterRule::Offset(offset));
                }
                DW_CFA_DEF_CFA_SF => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = read_sleb128(instructions, &mut off).unwrap_or(0)
                        * data_alignment_factor;
                    current.cfa = CfaRule::RegisterOffset { register: reg, offset };
                }
                DW_CFA_DEF_CFA_OFFSET_SF => {
                    let offset = read_sleb128(instructions, &mut off).unwrap_or(0)
                        * data_alignment_factor;
                    if let CfaRule::RegisterOffset { register, .. } = current.cfa {
                        current.cfa = CfaRule::RegisterOffset { register, offset };
                    }
                }
                DW_CFA_VAL_OFFSET => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0))
                        * data_alignment_factor;
                    current.regs.insert(reg, RegisterRule::ValOffset(offset));
                }
                DW_CFA_VAL_OFFSET_SF => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = read_sleb128(instructions, &mut off).unwrap_or(0)
                        * data_alignment_factor;
                    current.regs.insert(reg, RegisterRule::ValOffset(offset));
                }
                DW_CFA_VAL_EXPRESSION => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let len = u64_to_usize(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let expr = instructions.get(off..off + len).unwrap_or(&[]).to_vec();
                    off += len;
                    current.regs.insert(reg, RegisterRule::ValExpression(expr));
                }
                DW_CFA_GNU_ARGS_SIZE => {
                    read_uleb128(instructions, &mut off).ok();
                }
                DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED => {
                    let reg = u64_to_u32(read_uleb128(instructions, &mut off).unwrap_or(0));
                    let offset = -(u64_to_i64(read_uleb128(instructions, &mut off).unwrap_or(0))
                        * data_alignment_factor);
                    current.regs.insert(reg, RegisterRule::Offset(offset));
                }
                _ => {}
            }
        }
    }

    rows
}

// ── CIE parser ────────────────────────────────────────────────────────────────

/// Parse one CIE from a raw .`eh_frame` or .`debug_frame` section.
/// `base_off` is the offset of this entry within the section.
pub fn parse_cie(data: &[u8], base_off: usize, is_eh_frame: bool, addr_size: u8) -> Result<Cie> {
    let mut off = base_off;

    // Read initial_len.
    let initial_len = read_u32_le(data, &mut off)?;
    let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
        (true, u64_to_usize(read_u64_le(data, &mut off)?))
    } else {
        (false, initial_len as usize)
    };
    let unit_end = off + unit_len;

    // CIE ID: 0 for .eh_frame, 0xFFFFFFFF for .debug_frame.
    let cie_id = if is_64bit {
        u64_to_u32(read_u64_le(data, &mut off)?)
    } else {
        read_u32_le(data, &mut off)?
    };

    // Validate the CIE ID against the section flavour. We don't hard-error
    // on mismatch (some toolchains emit oddities), but mismatches are
    // recorded as a debug-assertion to catch regressions.
    let expected_id: u32 = if is_eh_frame { 0 } else { 0xFFFF_FFFF };
    debug_assert!(
        cie_id == expected_id || cie_id == 0,
        "CIE ID {cie_id:#x} does not match section flavour (eh_frame={is_eh_frame})"
    );

    let version = read_u8(data, &mut off)?;
    let augmentation = read_cstring(data, &mut off)?;

    if version >= 4 {
        let _addr_size_field = read_u8(data, &mut off)?;
        let _seg_selector_size = read_u8(data, &mut off)?;
    }

    let code_alignment_factor = read_uleb128(data, &mut off)?;
    let data_alignment_factor = read_sleb128(data, &mut off)?;

    let return_address_register = if version == 1 {
        u32::from(read_u8(data, &mut off)?)
    } else {
        u64_to_u32(read_uleb128(data, &mut off)?)
    };

    // Parse augmentation data.
    let mut lsda_encoding = None;
    let mut fde_encoding = None;
    let mut personality = None;

    if augmentation.starts_with('z') {
        let aug_len = u64_to_usize(read_uleb128(data, &mut off)?);
        let aug_end = off + aug_len;
        for ch in augmentation.chars().skip(1) {
            if off >= aug_end { break; }
            match ch {
                'L' => {
                    lsda_encoding = Some(read_u8(data, &mut off)?);
                }
                'R' => {
                    fde_encoding = Some(read_u8(data, &mut off)?);
                }
                'P' => {
                    let enc = read_u8(data, &mut off)?;
                    // Read personality pointer (simplified: 4 or 8 bytes)
                    let ptr = if enc & 0x07 == 0x04 {
                        u64::from(read_u32_le(data, &mut off)?)
                    } else {
                        read_u64_le(data, &mut off)?
                    };
                    personality = Some(ptr);
                }
                _ => {}
            }
        }
        off = aug_end; // skip any remaining augmentation bytes
    }

    let initial_instructions = data.get(off..unit_end).unwrap_or(&[]).to_vec();

    let initial_row = CallFrameRow {
        pc: 0,
        cfa: CfaRule::RegisterOffset { register: 7, offset: 8 }, // common x86-64 default
        regs: HashMap::new(),
    };
    let rows = execute_cfi(
        &initial_instructions,
        &initial_row,
        code_alignment_factor,
        data_alignment_factor,
        addr_size,
    );

    Ok(Cie {
        offset: base_off,
        version,
        augmentation,
        code_alignment_factor,
        data_alignment_factor,
        return_address_register,
        lsda_encoding,
        fde_encoding,
        personality,
        initial_instructions,
        initial_row: rows.last().cloned().unwrap_or(initial_row),
    })
}

// ── FDE parser ────────────────────────────────────────────────────────────────

/// Parse one FDE using its corresponding CIE.
pub fn parse_fde(
    data: &[u8],
    base_off: usize,
    cie: &Cie,
    addr_size: u8,
) -> Result<Fde> {
    let mut off = base_off;

    let initial_len = read_u32_le(data, &mut off)?;
    let (is_64bit, unit_len) = if initial_len == 0xFFFF_FFFF {
        (true, u64_to_usize(read_u64_le(data, &mut off)?))
    } else {
        (false, initial_len as usize)
    };
    let unit_end = off + unit_len;

    // CIE pointer (skip).
    if is_64bit { read_u64_le(data, &mut off)?; } else { read_u32_le(data, &mut off)?; }

    // PC range.
    let initial_location = if addr_size == 8 {
        read_u64_le(data, &mut off)?
    } else {
        u64::from(read_u32_le(data, &mut off)?)
    };
    let address_range = if addr_size == 8 {
        read_u64_le(data, &mut off)?
    } else {
        u64::from(read_u32_le(data, &mut off)?)
    };

    // Parse augmentation data if CIE has 'z'.
    let mut lsda = None;
    if cie.augmentation.starts_with('z') {
        let aug_len = u64_to_usize(read_uleb128(data, &mut off)?);
        let aug_end = off + aug_len;
        for ch in cie.augmentation.chars().skip(1) {
            if off >= aug_end { break; }
            if ch == 'L' {
                lsda = Some(if addr_size == 8 {
                    read_u64_le(data, &mut off)?
                } else {
                    u64::from(read_u32_le(data, &mut off)?)
                });
            }
        }
        off = aug_end;
    }

    let instructions = data.get(off..unit_end).unwrap_or(&[]).to_vec();
    let rows = execute_cfi(
        &instructions,
        &cie.initial_row,
        cie.code_alignment_factor,
        cie.data_alignment_factor,
        addr_size,
    );

    // Prepend the initial row (adjusted to actual initial_location).
    let mut all_rows = vec![CallFrameRow {
        pc: initial_location,
        cfa: cie.initial_row.cfa.clone(),
        regs: cie.initial_row.regs.clone(),
    }];
    let mut adjusted_rows = rows;
    for r in &mut adjusted_rows {
        r.pc = r.pc.wrapping_add(initial_location);
    }
    all_rows.extend(adjusted_rows);

    Ok(Fde {
        offset: base_off,
        cie_offset: cie.offset,
        initial_location,
        address_range,
        lsda,
        instructions,
        rows: all_rows,
    })
}

// ── Prologue/epilogue detection ───────────────────────────────────────────────

/// Classify a function region from its call-frame rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FunctionRegion {
    /// Frame setup: the CFA has not yet stabilized.
    Prologue,
    /// Main function body with a stable CFA.
    Body,
    /// Frame teardown before return.
    Epilogue,
}

/// Detect prologue / body / epilogue for each row in an FDE.
///
/// Heuristic:
/// - Prologue: CFA offset is still growing (not yet stabilized).
/// - Epilogue: CFA register changes back to SP.
/// - Body: everything in between.
#[must_use]
pub fn classify_rows(rows: &[CallFrameRow]) -> Vec<(u64, FunctionRegion)> {
    let mut out = Vec::new();
    if rows.is_empty() {
        return out;
    }

    // Find the "stable" CFA (the one used in the body).
    let stable_cfa = rows.iter().max_by_key(|r| match r.cfa {
        CfaRule::RegisterOffset { offset, .. } => offset,
        _ => 0,
    }).map(|r| r.cfa.clone());

    let mut prologue_done = false;
    let mut last_cfa = rows[0].cfa.clone();

    for row in rows {
        let region = if prologue_done {
            // Epilogue heuristic: CFA register switches to SP (reg 7 on x86-64)
            // or offset decreases.
            match (&row.cfa, &stable_cfa) {
                (CfaRule::RegisterOffset { register: r, .. },
                 Some(CfaRule::RegisterOffset { offset: stable_off, .. })) => {
                    // A register switch back to SP (reg 7 on x86-64) is a
                    // strong epilogue signal even before the offset shrinks.
                    let reg_switched_to_sp = *r == 7
                        && !matches!(last_cfa, CfaRule::RegisterOffset { register: 7, .. });
                    if let CfaRule::RegisterOffset { offset: cur_off, .. } = row.cfa {
                        if reg_switched_to_sp || cur_off < *stable_off {
                            FunctionRegion::Epilogue
                        } else {
                            FunctionRegion::Body
                        }
                    } else {
                        FunctionRegion::Body
                    }
                }
                _ => FunctionRegion::Body,
            }
        } else {
            // Prologue: CFA not yet stable.
            match (&row.cfa, &stable_cfa) {
                (CfaRule::RegisterOffset { offset: o1, .. },
                 Some(CfaRule::RegisterOffset { offset: o2, .. })) if o1 == o2 => {
                    prologue_done = true;
                    FunctionRegion::Body
                }
                _ => FunctionRegion::Prologue,
            }
        };
        out.push((row.pc, region));
        last_cfa.clone_from(&row.cfa);
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casts::i64_to_u64;

    #[test]
    fn test_i64_to_u64_roundtrip_for_unwind_offsets() {
        // CFI offsets are signed (data_alignment_factor * column) but addresses
        // and PC values are unsigned. This helper bridges the two domains.
        assert_eq!(i64_to_u64(0), 0u64);
        assert_eq!(i64_to_u64(8), 8u64);
        assert_eq!(i64_to_u64(-1), u64::MAX);
    }

    fn make_initial_row() -> CallFrameRow {
        CallFrameRow {
            pc: 0,
            cfa: CfaRule::RegisterOffset { register: 7, offset: 8 },
            regs: HashMap::new(),
        }
    }

    #[test]
    fn test_cfa_rule_reg_offset() {
        let rule = CfaRule::RegisterOffset { register: 6, offset: 16 };
        if let CfaRule::RegisterOffset { register, offset } = rule {
            assert_eq!(register, 6);
            assert_eq!(offset, 16);
        }
    }

    #[test]
    fn test_execute_def_cfa() {
        // DW_CFA_def_cfa rsp(7), 8
        let mut insns = Vec::new();
        insns.push(DW_CFA_DEF_CFA);
        insns.push(7); // reg 7 = rsp (ULEB128 1 byte)
        insns.push(8); // offset 8 (ULEB128 1 byte)
        let initial = make_initial_row();
        let rows = execute_cfi(&insns, &initial, 1, -8, 8);
        // No PC-advance, so no rows emitted.
        assert!(rows.is_empty());
    }

    #[test]
    fn test_execute_advance_loc1() {
        let mut insns = Vec::new();
        insns.push(DW_CFA_ADVANCE_LOC1);
        insns.push(4); // delta=4 code units * 1 = 4 bytes
        let initial = make_initial_row();
        let rows = execute_cfi(&insns, &initial, 1, -8, 8);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pc, 4);
    }

    #[test]
    fn test_execute_offset_register() {
        // DW_CFA_offset reg6(rbp), offset 16 (factor -8 → 16/-8 = -2 units)
        let mut insns = Vec::new();
        insns.push(DW_CFA_OFFSET | 6); // offset op for reg 6
        insns.push(2); // ULEB128(2) * (-8) = -16
        let initial = make_initial_row();
        let rows = execute_cfi(&insns, &initial, 1, -8, 8);
        // No advance → no rows, but register rule should be in "current"
        // We can only test indirectly through advance
        assert!(rows.is_empty()); // no PC advance was issued
    }

    #[test]
    fn test_execute_remember_restore() {
        let mut insns = Vec::new();
        insns.push(DW_CFA_REMEMBER_STATE);
        insns.push(DW_CFA_DEF_CFA);
        insns.push(6); // reg 6
        insns.push(16); // offset 16
        insns.push(DW_CFA_ADVANCE_LOC1); insns.push(8);
        insns.push(DW_CFA_RESTORE_STATE);
        insns.push(DW_CFA_ADVANCE_LOC1); insns.push(4);
        let initial = make_initial_row();
        let rows = execute_cfi(&insns, &initial, 1, -8, 8);
        assert_eq!(rows.len(), 2);
        // Second row should have restored CFA = reg7+8
        if let CfaRule::RegisterOffset { register, offset } = &rows[1].cfa {
            assert_eq!(*register, 7);
            assert_eq!(*offset, 8);
        }
    }

    #[test]
    fn test_fde_row_at_pc() {
        let rows = vec![
            CallFrameRow { pc: 0x1000, cfa: CfaRule::RegisterOffset { register: 7, offset: 8 }, regs: HashMap::new() },
            CallFrameRow { pc: 0x1010, cfa: CfaRule::RegisterOffset { register: 6, offset: 16 }, regs: HashMap::new() },
            CallFrameRow { pc: 0x1020, cfa: CfaRule::RegisterOffset { register: 6, offset: 16 }, regs: HashMap::new() },
        ];
        let fde = Fde {
            offset: 0,
            cie_offset: 0,
            initial_location: 0x1000,
            address_range: 0x30,
            lsda: None,
            instructions: vec![],
            rows,
        };
        assert_eq!(fde.row_at_pc(0x1000).map(|r| r.pc), Some(0x1000));
        assert_eq!(fde.row_at_pc(0x1015).map(|r| r.pc), Some(0x1010));
        assert!(fde.row_at_pc(0x0FFF).is_none());
    }

    #[test]
    fn test_classify_rows_body() {
        let rows = vec![
            CallFrameRow { pc: 0x1000, cfa: CfaRule::RegisterOffset { register: 7, offset: 8 }, regs: HashMap::new() },
            CallFrameRow { pc: 0x1004, cfa: CfaRule::RegisterOffset { register: 6, offset: 16 }, regs: HashMap::new() },
            CallFrameRow { pc: 0x1008, cfa: CfaRule::RegisterOffset { register: 6, offset: 16 }, regs: HashMap::new() },
        ];
        let classified = classify_rows(&rows);
        assert_eq!(classified.len(), 3);
    }

    #[test]
    fn test_register_rule_variants() {
        let r1 = RegisterRule::Offset(-8);
        let r2 = RegisterRule::SameValue;
        let r3 = RegisterRule::Register(5);
        assert_ne!(r1, r2);
        assert_ne!(r2, r3);
    }

    #[test]
    fn test_fde_end_pc() {
        let fde = Fde {
            offset: 0, cie_offset: 0,
            initial_location: 0x1000,
            address_range: 0x100,
            lsda: None,
            instructions: vec![],
            rows: vec![],
        };
        assert_eq!(fde.end_pc(), 0x1100);
    }
}
