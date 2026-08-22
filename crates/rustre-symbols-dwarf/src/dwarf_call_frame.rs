//! DWARF Call Frame Information (CFI) parser for `.debug_frame` and `.eh_frame`.
//!
//! CFI encodes how to restore callee-saved registers and the CFA (Canonical
//! Frame Address) at any point in a function, enabling precise stack unwinding
//! without frame pointers.
//!
//! Types: [`Cie`], [`Fde`], [`CfaRule`], [`RegRule`], [`UnwindRow`],
//! [`UnwindTable`], [`CfiSection`].

use std::collections::HashMap;
use std::fmt;

use crate::dwarf_abbrev::{read_sleb128, read_uleb128};

// ─── DW_CFA opcodes ───────────────────────────────────────────────────────────

/// A decoded Call Frame Instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfaInsn {
    // ── CFA definition ────────────────────────────────────────────────────────
    /// `DW_CFA_def_cfa`: CFA = reg + offset.
    DefCfa {
        /// Register number the CFA is based on.
        reg: u32,
        /// Non-factored byte offset added to the register.
        offset: u64,
    },
    /// `DW_CFA_def_cfa_register`: change register, keep offset.
    DefCfaRegister(u32),
    /// `DW_CFA_def_cfa_offset`: change offset, keep register.
    DefCfaOffset(u64),
    /// `DW_CFA_def_cfa_offset_sf`: signed factored offset.
    DefCfaOffsetSf(i64),
    /// `DW_CFA_def_cfa_sf`: CFA = reg + `factored_offset` * `data_alignment`.
    DefCfaSf {
        /// Register number the CFA is based on.
        reg: u32,
        /// Signed factored offset (multiplied by the CIE data alignment).
        offset: i64,
    },
    /// `DW_CFA_def_cfa_expression`: CFA = DWARF expression result.
    DefCfaExpression(Vec<u8>),

    // ── Register rules ────────────────────────────────────────────────────────
    /// `DW_CFA_undefined`: register has undefined value.
    Undefined(u32),
    /// `DW_CFA_same_value`: register is unchanged from caller.
    SameValue(u32),
    /// `DW_CFA_offset(reg)`: reg at CFA + offset * `data_align`.
    Offset {
        /// Register number the rule applies to.
        reg: u32,
        /// Unsigned factored offset from the CFA.
        offset: u64,
    },
    /// `DW_CFA_offset_extended_sf`: signed factored.
    OffsetSf {
        /// Register number the rule applies to.
        reg: u32,
        /// Signed factored offset from the CFA.
        offset: i64,
    },
    /// `DW_CFA_val_offset(reg)`: value = CFA + offset * `data_align`.
    ValOffset {
        /// Register number the rule applies to.
        reg: u32,
        /// Unsigned factored offset from the CFA.
        offset: u64,
    },
    /// `DW_CFA_val_offset_sf`: signed.
    ValOffsetSf {
        /// Register number the rule applies to.
        reg: u32,
        /// Signed factored offset from the CFA.
        offset: i64,
    },
    /// `DW_CFA_register`: reg1 is saved in reg2.
    Register {
        /// Register whose saved value is described.
        reg1: u32,
        /// Register holding the saved value.
        reg2: u32,
    },
    /// `DW_CFA_expression`: register recovered via expression.
    Expression {
        /// Register number the rule applies to.
        reg: u32,
        /// Raw DWARF expression bytes yielding the save location.
        expr: Vec<u8>,
    },
    /// `DW_CFA_val_expression`.
    ValExpression {
        /// Register number the rule applies to.
        reg: u32,
        /// Raw DWARF expression bytes yielding the register value.
        expr: Vec<u8>,
    },
    /// `DW_CFA_restore(reg)`.
    Restore(u32),
    /// `DW_CFA_restore_extended`.
    RestoreExtended(u32),

    // ── Row management ────────────────────────────────────────────────────────
    /// `DW_CFA_advance_loc(delta)`: advance location by delta * `code_align`.
    AdvanceLoc(u8),
    /// `DW_CFA_advance_loc1`.
    AdvanceLoc1(u8),
    /// `DW_CFA_advance_loc2`.
    AdvanceLoc2(u16),
    /// `DW_CFA_advance_loc4`.
    AdvanceLoc4(u32),
    /// `DW_CFA_set_loc(addr)`.
    SetLoc(u64),
    /// `DW_CFA_remember_state`.
    RememberState,
    /// `DW_CFA_restore_state`.
    RestoreState,
    /// `DW_CFA_nop`.
    Nop,
}

/// Decode a sequence of CFA instructions from `data[pos..]`.
#[must_use]
pub fn decode_cfa_insns(data: &[u8], pos: &mut usize, end: usize, addr_size: u8) -> Vec<CfaInsn> {
    let mut insns = Vec::new();
    while *pos < end && *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        let high2 = byte >> 6;
        let low6 = byte & 0x3F;

        let insn = match high2 {
            0x01 => CfaInsn::AdvanceLoc(low6),
            0x02 => {
                let off = read_uleb128(data, pos).unwrap_or(0);
                CfaInsn::Offset { reg: u32::from(low6), offset: off }
            }
            0x03 => CfaInsn::Restore(u32::from(low6)),
            0x00 => decode_extended_cfa_insn(data, pos, low6, addr_size),
            _ => CfaInsn::Nop,
        };
        insns.push(insn);
    }
    insns
}

fn read_block_insn(data: &[u8], pos: &mut usize) -> Vec<u8> {
    let len = usize::try_from(read_uleb128(data, pos).unwrap_or(0)).unwrap_or(usize::MAX);
    // checked_add: a crafted ULEB can make `*pos + len` wrap around and turn
    // the bounds check into an out-of-order slice (panic).
    match pos.checked_add(len) {
        Some(end) if end <= data.len() => {
            let b = data[*pos..end].to_vec();
            *pos = end;
            b
        }
        _ => Vec::new(),
    }
}

fn read_addr_insn(data: &[u8], pos: &mut usize, addr_size: u8) -> u64 {
    match addr_size {
        2 => {
            if *pos + 2 <= data.len() {
                let v = u64::from(u16::from_le_bytes(data[*pos..*pos+2].try_into().unwrap_or([0;2])));
                *pos += 2;
                v
            } else { 0 }
        }
        4 => {
            if *pos + 4 <= data.len() {
                let v = u64::from(u32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap_or([0;4])));
                *pos += 4;
                v
            } else { 0 }
        }
        _ => {
            if *pos + 8 <= data.len() {
                let v = u64::from_le_bytes(data[*pos..*pos+8].try_into().unwrap_or([0;8]));
                *pos += 8;
                v
            } else { 0 }
        }
    }
}

/// Read a DWARF register number (a ULEB128, so up to `u64`) as the `u32` the
/// rule tables are keyed by.
///
/// Narrowing with `as u32` would DISCARD the high bits, so `0x1_0000_0006`
/// would land on register 6 — on x86-64 that is rbp — and a bogus register
/// number in a hostile `.eh_frame` would silently overwrite the unwind rule of
/// a real callee-saved register. Saturating instead keeps an out-of-range
/// number out of the range of every architecture's real registers.
fn read_register(data: &[u8], pos: &mut usize) -> u32 {
    u32::try_from(read_uleb128(data, pos).unwrap_or(0)).unwrap_or(u32::MAX)
}

fn decode_extended_cfa_insn(data: &[u8], pos: &mut usize, op: u8, addr_size: u8) -> CfaInsn {
    match op {
        0x00 => CfaInsn::Nop,
        0x01 => CfaInsn::SetLoc(read_addr_insn(data, pos, addr_size)),
        0x02 => {
            let d = if *pos < data.len() { let v = data[*pos]; *pos += 1; v } else { 0 };
            CfaInsn::AdvanceLoc1(d)
        }
        0x03 => {
            let d = if *pos + 2 <= data.len() {
                let v = u16::from_le_bytes(data[*pos..*pos+2].try_into().unwrap_or([0;2]));
                *pos += 2; v
            } else { 0 };
            CfaInsn::AdvanceLoc2(d)
        }
        0x04 => {
            let d = if *pos + 4 <= data.len() {
                let v = u32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap_or([0;4]));
                *pos += 4; v
            } else { 0 };
            CfaInsn::AdvanceLoc4(d)
        }
        0x05 => {
            let reg = read_register(data, pos);
            let off = read_uleb128(data, pos).unwrap_or(0);
            CfaInsn::Offset { reg, offset: off }
        }
        0x06 => CfaInsn::Restore(read_register(data, pos)),
        0x07 => CfaInsn::Undefined(read_register(data, pos)),
        0x08 => CfaInsn::SameValue(read_register(data, pos)),
        0x09 => {
            let r1 = read_register(data, pos);
            let r2 = read_register(data, pos);
            CfaInsn::Register { reg1: r1, reg2: r2 }
        }
        0x0A => CfaInsn::RememberState,
        0x0B => CfaInsn::RestoreState,
        0x0C => {
            let reg = read_register(data, pos);
            let off = read_uleb128(data, pos).unwrap_or(0);
            CfaInsn::DefCfa { reg, offset: off }
        }
        0x0D => CfaInsn::DefCfaRegister(read_register(data, pos)),
        0x0E => CfaInsn::DefCfaOffset(read_uleb128(data, pos).unwrap_or(0)),
        0x0F => CfaInsn::DefCfaExpression(read_block_insn(data, pos)),
        0x10 => {
            let reg = read_register(data, pos);
            CfaInsn::Expression { reg, expr: read_block_insn(data, pos) }
        }
        0x11 => {
            let reg = read_register(data, pos);
            let off = read_sleb128(data, pos).unwrap_or(0);
            CfaInsn::OffsetSf { reg, offset: off }
        }
        0x12 => {
            let reg = read_register(data, pos);
            let off = read_uleb128(data, pos).unwrap_or(0);
            CfaInsn::ValOffset { reg, offset: off }
        }
        0x13 => {
            let reg = read_register(data, pos);
            let off = read_sleb128(data, pos).unwrap_or(0);
            CfaInsn::ValOffsetSf { reg, offset: off }
        }
        0x14 => {
            let reg = read_register(data, pos);
            CfaInsn::ValExpression { reg, expr: read_block_insn(data, pos) }
        }
        0x15 => CfaInsn::RestoreExtended(read_register(data, pos)),
        0x19 => {
            let reg = read_register(data, pos);
            let off = read_sleb128(data, pos).unwrap_or(0);
            CfaInsn::DefCfaSf { reg, offset: off }
        }
        0x1A => CfaInsn::DefCfaOffsetSf(read_sleb128(data, pos).unwrap_or(0)),
        _ => CfaInsn::Nop,
    }
}

// ─── CIE ──────────────────────────────────────────────────────────────────────

/// Common Information Entry: shared header referenced by FDEs.
#[derive(Debug, Clone)]
pub struct Cie {
    /// Byte offset of this CIE within the CFI section.
    pub section_offset: usize,
    /// CIE format version (1 for `.eh_frame`, 3-5 for `.debug_frame`).
    pub version: u8,
    /// Augmentation string (e.g. `"zR"`).
    pub augmentation: String,
    /// Target address size in bytes.
    pub addr_size: u8,
    /// Segment selector size in bytes (DWARF 4+; usually 0).
    pub segment_size: u8,
    /// Code alignment factor applied to advance-location deltas.
    pub code_align: u64,
    /// Data alignment factor applied to factored register offsets.
    pub data_align: i64,
    /// Column (register number) holding the return address.
    pub return_addr_reg: u32,
    /// Initial CFI instructions establishing the default rules for every FDE.
    pub initial_insns: Vec<CfaInsn>,
    /// `DW_EH_PE` pointer encoding from the `'R'` augmentation, if present.
    pub fde_ptr_encoding: Option<u8>,
}

impl Cie {
    /// Parse one CIE at `data[*pos..]`, advancing `pos` past the entry.
    ///
    /// Returns `None` on a terminator, a non-CIE entry, or truncated data.
    pub fn parse(data: &[u8], pos: &mut usize, is_eh_frame: bool) -> Option<Self> {
        let section_offset = *pos;
        let (length, is_64bit) = read_frame_length(data, pos)?;
        if length == 0 { return None; }
        // `length` is an attacker-controlled file field. `*pos + length`
        // WRAPS in release (overflow-checks off), yielding a SMALL `end`
        // that is then used as the decode bound AND written back to the
        // cursor, rewinding the parse below the entry it just consumed.
        let end = usize::try_from(length).ok().and_then(|l| pos.checked_add(l))?;
        if end > data.len() { return None; }
        let offset_size = if is_64bit { 8usize } else { 4 };

        let cie_id = if is_64bit {
            if *pos + 8 > data.len() { return None; }
            let v = u64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?);
            *pos += 8; v
        } else {
            if *pos + 4 > data.len() { return None; }
            let v = u64::from(u32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?));
            *pos += 4; v
        };
        let _ = offset_size;
        let expected: u64 = if is_eh_frame { 0 } else if is_64bit { u64::MAX } else { 0xFFFF_FFFF };
        if cie_id != expected { *pos = end; return None; }

        let version = *data.get(*pos)?; *pos += 1;
        let aug_start = *pos;
        while *pos < data.len() && data[*pos] != 0 { *pos += 1; }
        let augmentation = std::str::from_utf8(&data[aug_start..*pos]).unwrap_or("").to_string();
        *pos += 1;

        let (addr_size, segment_size) = if version >= 4 {
            let a = *data.get(*pos)?; *pos += 1;
            let s = *data.get(*pos)?; *pos += 1;
            (a, s)
        } else {
            (if is_64bit { 8u8 } else { 4 }, 0u8)
        };

        let code_align = read_uleb128(data, pos)?;
        let data_align = read_sleb128(data, pos)?;
        let return_addr_reg = read_uleb128(data, pos)? as u32;

        let mut fde_ptr_encoding = None;
        if augmentation.starts_with('z') {
            let aug_len = read_uleb128(data, pos)? as usize;
            let aug_end = pos.saturating_add(aug_len).min(data.len());
            let mut ap = *pos;
            for ch in augmentation.chars().skip(1) {
                if ap >= aug_end { break; }
                match ch {
                    'L' => { ap += 1; }
                    'P' => {
                        let enc = data[ap]; ap += 1;
                        // The personality routine pointer may use a
                        // variable-length uleb/sleb encoding, so skip it with a
                        // real decoder rather than a fixed size.
                        if skip_encoded_ptr(data, &mut ap, enc, addr_size).is_none() { break; }
                    }
                    'R' => { fde_ptr_encoding = Some(data[ap]); ap += 1; }
                    _ => {}
                }
            }
            *pos = aug_end;
        }

        let initial_insns = decode_cfa_insns(data, pos, end, addr_size);
        *pos = end;
        Some(Self { section_offset, version, augmentation, addr_size, segment_size,
                   code_align, data_align, return_addr_reg, initial_insns, fde_ptr_encoding })
    }
}

/// Size in bytes of a DW_EH_PE-encoded pointer, per the low nibble.
/// The previous table was wrong (it read 0x03 as 2 and 0x07/0x08 as 8); the real
/// encoding is 0x02=udata2, 0x03=udata4, 0x04=udata8, with 0x0A/0x0B/0x0C the
/// signed counterparts. Returns `None` for the variable-length uleb/sleb
/// encodings (0x01/0x09), which must be decoded rather than skipped.
const fn ptr_enc_size(enc: u8, addr_size: u8) -> Option<usize> {
    if enc == DW_EH_PE_OMIT { return Some(0); }
    match enc & 0x0F {
        0x01 | 0x09 => None, // uleb128 / sleb128: variable length
        0x02 | 0x0A => Some(2),
        0x03 | 0x0B => Some(4),
        0x04 | 0x0C => Some(8),
        _ => Some(addr_size as usize),
    }
}

const DW_EH_PE_OMIT: u8 = 0xFF;

/// Advance `pos` past one DW_EH_PE-encoded pointer without interpreting it.
/// Handles the variable-length uleb/sleb encodings, which a fixed size table
/// cannot.
fn skip_encoded_ptr(data: &[u8], pos: &mut usize, enc: u8, addr_size: u8) -> Option<()> {
    match ptr_enc_size(enc, addr_size) {
        Some(n) => {
            let end = pos.checked_add(n)?;
            if end > data.len() { return None; }
            *pos = end;
            Some(())
        }
        None => {
            read_uleb128(data, pos)?; // same byte length as the sleb128 case
            Some(())
        }
    }
}

impl fmt::Display for Cie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CIE@{:#x} v={} aug={:?} addr={} code_align={} data_align={}",
               self.section_offset, self.version, self.augmentation,
               self.addr_size, self.code_align, self.data_align)
    }
}

fn read_frame_length(data: &[u8], pos: &mut usize) -> Option<(u64, bool)> {
    if *pos + 4 > data.len() { return None; }
    let init = u32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?);
    *pos += 4;
    if init == 0xFFFF_FFFF {
        if *pos + 8 > data.len() { return None; }
        let l = u64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?);
        *pos += 8;
        Some((l, true))
    } else {
        Some((u64::from(init), false))
    }
}

// ─── FDE ──────────────────────────────────────────────────────────────────────

/// Frame Description Entry: covers a specific PC range.
#[derive(Debug, Clone)]
pub struct Fde {
    /// Byte offset of this FDE within the CFI section.
    pub section_offset: usize,
    /// Section offset of the CIE this FDE references.
    pub cie_offset: usize,
    /// First PC covered by this FDE.
    pub pc_begin: u64,
    /// Number of code bytes covered starting at `pc_begin`.
    pub pc_range: u64,
    /// CFI instructions specific to this FDE (applied after the CIE's).
    pub instructions: Vec<CfaInsn>,
}

impl Fde {
    /// Parse one FDE at `data[*pos..]` using its CIE, advancing `pos` past it.
    pub fn parse(data: &[u8], pos: &mut usize, cie: &Cie, is_eh_frame: bool) -> Option<Self> {
        Self::parse_at(data, pos, cie, is_eh_frame, 0)
    }

    /// Like [`Fde::parse`], but supplied with the section's virtual base address
    /// so `DW_EH_PE_pcrel` encodings resolve to real addresses.
    pub fn parse_at(
        data: &[u8],
        pos: &mut usize,
        cie: &Cie,
        is_eh_frame: bool,
        section_vaddr: u64,
    ) -> Option<Self> {
        let section_offset = *pos;
        let (length, is_64bit) = read_frame_length(data, pos)?;
        if length == 0 { return None; }
        // `length` is an attacker-controlled file field. `*pos + length`
        // WRAPS in release (overflow-checks off), yielding a SMALL `end`
        // that is then used as the decode bound AND written back to the
        // cursor, rewinding the parse below the entry it just consumed.
        let end = usize::try_from(length).ok().and_then(|l| pos.checked_add(l))?;
        if end > data.len() { return None; }
        if is_64bit { if *pos + 8 > data.len() { return None; } *pos += 8; }
        else        { if *pos + 4 > data.len() { return None; } *pos += 4; }

        // `.eh_frame` uses the CIE's 'R' augmentation encoding; `.debug_frame`
        // always uses plain addr_size-wide absolute addresses.
        let (pc_begin, pc_range) = if is_eh_frame {
            let enc = cie.fde_ptr_encoding.unwrap_or(0x00);
            let begin = read_addr_encoded(data, pos, cie.addr_size, enc, section_vaddr, true)?;
            let range = read_addr_encoded(data, pos, cie.addr_size, enc, section_vaddr, false)?;
            (begin, range)
        } else {
            let begin = read_addr_plain_fde(data, pos, cie.addr_size)?;
            let range = read_addr_plain_fde(data, pos, cie.addr_size)?;
            (begin, range)
        };

        if cie.augmentation.starts_with('z') {
            let aug_len = read_uleb128(data, pos)? as usize;
            *pos = pos.saturating_add(aug_len).min(data.len());
        }

        let instructions = decode_cfa_insns(data, pos, end, cie.addr_size);
        *pos = end;
        Some(Self { section_offset, cie_offset: section_offset, pc_begin, pc_range, instructions })
    }

    /// Whether `pc` falls within this FDE's `[pc_begin, pc_begin + pc_range)`.
    #[must_use]
    pub const fn covers(&self, pc: u64) -> bool {
        // Both fields come straight from the file; a plain `+` panics on
        // overflow under overflow-checks. `is_some_and` is not const-callable,
        // so this is written as a match.
        match self.pc_begin.checked_add(self.pc_range) {
            Some(end) => pc >= self.pc_begin && pc < end,
            None => pc >= self.pc_begin,
        }
    }
}

impl fmt::Display for Fde {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FDE@{:#x} pc=[{:#x}..{:#x})", self.section_offset,
               self.pc_begin, self.pc_begin.saturating_add(self.pc_range))
    }
}

/// Read a DW_EH_PE-encoded pointer, honouring BOTH nibbles.
///
/// The low nibble selects size and signedness; the high nibble selects the base
/// the value is relative to. `section_vaddr` is the virtual address the section
/// is loaded at (0 if unknown), used for `DW_EH_PE_pcrel`. The by-far most common
/// `.eh_frame` encoding is `pcrel|sdata4` (0x1B), which the old code did not
/// handle at all: it consumed 8 bytes for a 4-byte field and treated a signed
/// displacement as an absolute address.
fn read_addr_encoded(
    data: &[u8],
    pos: &mut usize,
    addr_size: u8,
    enc: u8,
    section_vaddr: u64,
    apply_base: bool,
) -> Option<u64> {
    if enc == DW_EH_PE_OMIT { return None; }
    // DW_EH_PE_indirect (0x80): the value is the address OF the pointer. We
    // cannot dereference it here; refuse rather than return the slot address.
    if enc & 0x80 != 0 { return None; }

    let field_off = *pos;
    let raw: i128 = match enc & 0x0F {
        0x01 => i128::from(read_uleb128(data, pos)?),
        0x09 => i128::from(read_sleb128(data, pos)?),
        0x02 => { let e = pos.checked_add(2)?; if e > data.len() { return None; }
                  let v = u16::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        0x0A => { let e = pos.checked_add(2)?; if e > data.len() { return None; }
                  let v = i16::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        0x03 => { let e = pos.checked_add(4)?; if e > data.len() { return None; }
                  let v = u32::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        0x0B => { let e = pos.checked_add(4)?; if e > data.len() { return None; }
                  let v = i32::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        0x04 => { let e = pos.checked_add(8)?; if e > data.len() { return None; }
                  let v = u64::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        0x0C => { let e = pos.checked_add(8)?; if e > data.len() { return None; }
                  let v = i64::from_le_bytes(data[*pos..e].try_into().ok()?); *pos = e; i128::from(v) }
        // 0x00 = DW_EH_PE_absptr: native address size.
        _ => i128::from(read_addr_plain_fde(data, pos, addr_size)?),
    };

    if !apply_base {
        // pc_range shares the encoding but is a length, not a displacement.
        return u64::try_from(raw & i128::from(u64::MAX)).ok();
    }

    let base: i128 = match enc & 0x70 {
        0x00 => 0, // absptr
        0x10 => i128::from(section_vaddr) + i128::try_from(field_off).ok()?, // pcrel
        // textrel/datarel/funcrel/aligned: base unknown here. Treating the
        // value as absolute would be a lie, so refuse.
        _ => return None,
    };
    u64::try_from((raw + base) & i128::from(u64::MAX)).ok()
}

fn read_addr_plain_fde(data: &[u8], pos: &mut usize, addr_size: u8) -> Option<u64> {
    match addr_size {
        2 => { if *pos+2>data.len(){return None;} let v=u64::from(u16::from_le_bytes(data[*pos..*pos+2].try_into().ok()?)); *pos+=2; Some(v) }
        4 => { if *pos+4>data.len(){return None;} let v=u64::from(u32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?)); *pos+=4; Some(v) }
        _ => { if *pos+8>data.len(){return None;} let v=u64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?); *pos+=8; Some(v) }
    }
}

// ─── CfaRule / RegRule ────────────────────────────────────────────────────────

/// How to compute the CFA (Canonical Frame Address) at a given location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfaRule {
    /// CFA = value of `reg` plus `offset`.
    RegisterAndOffset {
        /// Register number the CFA is based on.
        reg: u32,
        /// Signed byte offset added to the register value.
        offset: i64,
    },
    /// CFA is the result of evaluating a DWARF expression.
    Expression(Vec<u8>),
    /// No CFA rule has been established.
    Undefined,
}

impl fmt::Display for CfaRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterAndOffset { reg, offset } => write!(f, "r{reg}+{offset}"),
            Self::Expression(e) => write!(f, "expr[{}]", e.len()),
            Self::Undefined => write!(f, "undef"),
        }
    }
}

/// How to recover a register's caller value at a given location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegRule {
    /// Register value is undefined (not recoverable).
    Undefined,
    /// Register is unchanged from the caller.
    SameValue,
    /// Register is saved at memory address CFA + offset.
    Offset(i64),
    /// Register value equals CFA + offset (not a memory load).
    ValOffset(i64),
    /// Register is saved in another register.
    Register(u32),
    /// Save location is given by a DWARF expression.
    Expression(Vec<u8>),
    /// Register value is given by a DWARF expression.
    ValExpression(Vec<u8>),
}

impl fmt::Display for RegRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined => write!(f, "undef"),
            Self::SameValue => write!(f, "same"),
            Self::Offset(o) => write!(f, "[cfa+{o}]"),
            Self::ValOffset(o) => write!(f, "cfa+{o}"),
            Self::Register(r) => write!(f, "r{r}"),
            Self::Expression(e) => write!(f, "expr[{}]", e.len()),
            Self::ValExpression(e) => write!(f, "val_expr[{}]", e.len()),
        }
    }
}

// ─── UnwindRow ────────────────────────────────────────────────────────────────

/// One row of the unwind table: the rules in effect from `address` onward.
#[derive(Debug, Clone)]
pub struct UnwindRow {
    /// First PC at which this row's rules apply.
    pub address: u64,
    /// Rule for computing the CFA at this location.
    pub cfa: CfaRule,
    /// Per-register recovery rules, keyed by DWARF register number.
    pub registers: HashMap<u32, RegRule>,
}

impl UnwindRow {
    fn new(address: u64) -> Self {
        Self { address, cfa: CfaRule::Undefined, registers: HashMap::new() }
    }
    fn clone_for_advance(&self, new_addr: u64) -> Self {
        Self { address: new_addr, cfa: self.cfa.clone(), registers: self.registers.clone() }
    }
}

impl fmt::Display for UnwindRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnwindRow @ {:#x}  cfa={}", self.address, self.cfa)
    }
}

// ─── UnwindTable ─────────────────────────────────────────────────────────────

/// Materialized unwind table for one FDE: one [`UnwindRow`] per location range.
#[derive(Debug, Default)]
pub struct UnwindTable {
    /// Rows in ascending address order.
    pub rows: Vec<UnwindRow>,
}

impl UnwindTable {
    /// Create an empty unwind table.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Find the row whose rules are in effect at `pc`.
    #[must_use]
    pub fn row_for_pc(&self, pc: u64) -> Option<&UnwindRow> {
        self.rows.iter().rev().find(|r| r.address <= pc)
    }

    /// Run the CIE's initial instructions then the FDE's instructions,
    /// producing the full row-per-range unwind table.
    #[must_use]
    pub fn build(cie: &Cie, fde: &Fde) -> Self {
        let mut table = Self::new();
        let mut current = UnwindRow::new(fde.pc_begin);
        let mut state_stack: Vec<UnwindRow> = Vec::new();
        let empty_initial = HashMap::new();
        apply_cfa_insns(&cie.initial_insns, &mut current, &mut state_stack, &mut table,
                        cie.code_align, cie.data_align, &empty_initial);
        // DW_CFA_restore restores the rule the CIE's initial instructions
        // established, which is not the same as "no rule". Snapshot it here.
        let initial_regs = current.registers.clone();
        current.address = fde.pc_begin;
        apply_cfa_insns(&fde.instructions, &mut current, &mut state_stack, &mut table,
                        cie.code_align, cie.data_align, &initial_regs);
        table.rows.push(current);
        table
    }
}

fn apply_cfa_insns(insns: &[CfaInsn], current: &mut UnwindRow,
                   state_stack: &mut Vec<UnwindRow>, table: &mut UnwindTable,
                   code_align: u64, data_align: i64,
                   initial_regs: &HashMap<u32, RegRule>) {
    for insn in insns {
        match insn {
            CfaInsn::Nop => {}
            CfaInsn::AdvanceLoc(d) => {
                // code_align is an unvalidated ULEB from the CIE, so this
                // product is attacker-controlled. Skip the row on overflow
                // rather than fabricating a saturated address.
                let Some(na) = u64::from(*d)
                    .checked_mul(code_align)
                    .and_then(|delta| current.address.checked_add(delta))
                else { continue };
                let row = current.clone_for_advance(na);
                table.rows.push(std::mem::replace(current, row));
            }
            CfaInsn::AdvanceLoc1(d) => {
                // code_align is an unvalidated ULEB from the CIE, so this
                // product is attacker-controlled. Skip the row on overflow
                // rather than fabricating a saturated address.
                let Some(na) = u64::from(*d)
                    .checked_mul(code_align)
                    .and_then(|delta| current.address.checked_add(delta))
                else { continue };
                let row = current.clone_for_advance(na);
                table.rows.push(std::mem::replace(current, row));
            }
            CfaInsn::AdvanceLoc2(d) => {
                // code_align is an unvalidated ULEB from the CIE, so this
                // product is attacker-controlled. Skip the row on overflow
                // rather than fabricating a saturated address.
                let Some(na) = u64::from(*d)
                    .checked_mul(code_align)
                    .and_then(|delta| current.address.checked_add(delta))
                else { continue };
                let row = current.clone_for_advance(na);
                table.rows.push(std::mem::replace(current, row));
            }
            CfaInsn::AdvanceLoc4(d) => {
                // code_align is an unvalidated ULEB from the CIE, so this
                // product is attacker-controlled. Skip the row on overflow
                // rather than fabricating a saturated address.
                let Some(na) = u64::from(*d)
                    .checked_mul(code_align)
                    .and_then(|delta| current.address.checked_add(delta))
                else { continue };
                let row = current.clone_for_advance(na);
                table.rows.push(std::mem::replace(current, row));
            }
            CfaInsn::SetLoc(addr) => {
                let row = current.clone_for_advance(*addr);
                table.rows.push(std::mem::replace(current, row));
            }
            CfaInsn::DefCfa { reg, offset } => {
                current.cfa = CfaRule::RegisterAndOffset { reg: *reg, offset: (*offset).cast_signed() };
            }
            CfaInsn::DefCfaRegister(reg) => {
                if let CfaRule::RegisterAndOffset { reg: ref mut r, .. } = current.cfa { *r = *reg; }
            }
            CfaInsn::DefCfaOffset(off) => {
                if let CfaRule::RegisterAndOffset { offset: ref mut o, .. } = current.cfa { *o = (*off).cast_signed(); }
            }
            CfaInsn::DefCfaOffsetSf(off) => {
                if let CfaRule::RegisterAndOffset { offset: ref mut o, .. } = current.cfa { *o = *off * data_align; }
            }
            CfaInsn::DefCfaSf { reg, offset } => {
                current.cfa = CfaRule::RegisterAndOffset { reg: *reg, offset: *offset * data_align };
            }
            CfaInsn::DefCfaExpression(e) => { current.cfa = CfaRule::Expression(e.clone()); }
            CfaInsn::Undefined(r) => { current.registers.insert(*r, RegRule::Undefined); }
            CfaInsn::SameValue(r) => { current.registers.insert(*r, RegRule::SameValue); }
            CfaInsn::Offset { reg, offset } => {
                current.registers.insert(*reg, RegRule::Offset((*offset).cast_signed() * data_align));
            }
            CfaInsn::OffsetSf { reg, offset } => {
                current.registers.insert(*reg, RegRule::Offset(*offset * data_align));
            }
            CfaInsn::ValOffset { reg, offset } => {
                current.registers.insert(*reg, RegRule::ValOffset((*offset).cast_signed() * data_align));
            }
            CfaInsn::ValOffsetSf { reg, offset } => {
                current.registers.insert(*reg, RegRule::ValOffset(*offset * data_align));
            }
            CfaInsn::Register { reg1, reg2 } => {
                current.registers.insert(*reg1, RegRule::Register(*reg2));
            }
            CfaInsn::Expression { reg, expr } => {
                current.registers.insert(*reg, RegRule::Expression(expr.clone()));
            }
            CfaInsn::ValExpression { reg, expr } => {
                current.registers.insert(*reg, RegRule::ValExpression(expr.clone()));
            }
            CfaInsn::Restore(r) | CfaInsn::RestoreExtended(r) => {
                match initial_regs.get(r) {
                    Some(rule) => { current.registers.insert(*r, rule.clone()); }
                    None => { current.registers.remove(r); }
                }
            }
            CfaInsn::RememberState => { state_stack.push(current.clone()); }
            CfaInsn::RestoreState => {
                if let Some(saved) = state_stack.pop() {
                    let addr = current.address;
                    *current = saved;
                    current.address = addr;
                }
            }
        }
    }
}

// ─── CfiSection ───────────────────────────────────────────────────────────────

/// A fully parsed `.debug_frame` or `.eh_frame` section: all CIEs and FDEs.
#[derive(Debug, Default)]
pub struct CfiSection {
    /// All CIEs found in the section.
    pub cies: Vec<Cie>,
    /// All FDEs found in the section.
    pub fdes: Vec<Fde>,
}

impl CfiSection {
    /// Create an empty CFI section.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Parse an entire CFI section, collecting every CIE and FDE.
    #[must_use]
    pub fn parse(data: &[u8], is_eh_frame: bool) -> Self {
        let mut section = Self::new();
        let mut pos = 0usize;
        let mut cie_map: HashMap<usize, usize> = HashMap::new();

        while pos < data.len() {
            let entry_start = pos;
            let (length, is_64bit) = match read_frame_length(data, &mut pos) {
                Some(v) => v, None => break,
            };
            if length == 0 { break; }
            // Checked for the same reason: a wrapped `end` PASSES the
            // `end > data.len()` test below and then rewinds `pos`.
            let Some(end) = usize::try_from(length).ok().and_then(|l| pos.checked_add(l)) else { break };
            if end > data.len() { break; }
            let offset_size = if is_64bit { 8usize } else { 4 };
            if pos + offset_size > data.len() { break; }

            let cie_id = if is_64bit {
                u64::from_le_bytes(data[pos..pos+8].try_into().unwrap_or([0;8]))
            } else {
                u64::from(u32::from_le_bytes(data[pos..pos+4].try_into().unwrap_or([0;4])))
            };
            let is_cie = if is_eh_frame { cie_id == 0 } else { cie_id == u64::MAX || cie_id == 0xFFFF_FFFF };

            if is_cie {
                pos = entry_start;
                if let Some(cie) = Cie::parse(data, &mut pos, is_eh_frame) {
                    cie_map.insert(cie.section_offset, section.cies.len());
                    section.cies.push(cie);
                } else { pos = end; }
            } else {
                let cie_ptr = if is_eh_frame {
                    pos.saturating_sub(cie_id as usize)
                } else { cie_id as usize };

                if let Some(&idx) = cie_map.get(&cie_ptr) {
                    let cie = section.cies[idx].clone();
                    pos = entry_start;
                    if let Some(mut fde) = Fde::parse(data, &mut pos, &cie, is_eh_frame) {
                        // Fde::parse defaults cie_offset to the FDE's own
                        // offset; record the real pointer so unwind_table_for_pc
                        // pairs it with the CIE it references, not merely the
                        // first CIE in the section.
                        fde.cie_offset = cie_ptr;
                        section.fdes.push(fde);
                    } else { pos = end; }
                } else { pos = end; }
            }
        }
        section
    }

    /// Find the FDE covering `pc`, if any.
    #[must_use]
    pub fn fde_for_pc(&self, pc: u64) -> Option<&Fde> {
        self.fdes.iter().find(|f| f.covers(pc))
    }

    /// Build the unwind table for the FDE covering `pc`, paired with its CIE.
    #[must_use]
    pub fn unwind_table_for_pc(&self, pc: u64) -> Option<UnwindTable> {
        let fde = self.fde_for_pc(pc)?;
        let cie = self.cies.iter()
            .find(|c| c.section_offset == fde.cie_offset)
            .or_else(|| self.cies.first())?;
        Some(UnwindTable::build(cie, fde))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfa_insn_advance_loc_high() {
        let data = [0x41u8]; // high2=01, low6=1
        let mut pos = 0;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        assert_eq!(insns[0], CfaInsn::AdvanceLoc(1));
    }

    #[test]
    fn cfa_insn_nop() {
        let data = [0x00u8];
        let mut pos = 0;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        assert_eq!(insns[0], CfaInsn::Nop);
    }

    #[test]
    fn cfa_insn_def_cfa() {
        let data = [0x0Cu8, 0x07, 0x08]; // DW_CFA_def_cfa reg=7 offset=8
        let mut pos = 0;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        assert_eq!(insns[0], CfaInsn::DefCfa { reg: 7, offset: 8 });
    }

    #[test]
    fn cfa_insn_remember_restore() {
        let data = [0x0Au8, 0x0Bu8]; // remember, restore
        let mut pos = 0;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        assert_eq!(insns[0], CfaInsn::RememberState);
        assert_eq!(insns[1], CfaInsn::RestoreState);
    }

    #[test]
    fn cfa_rule_display() {
        let r = CfaRule::RegisterAndOffset { reg: 7, offset: -8 };
        assert!(r.to_string().contains("r7"));
        assert!(r.to_string().contains("-8"));
    }

    #[test]
    fn cfa_rule_expr_display() {
        assert!(CfaRule::Expression(vec![1,2,3]).to_string().contains("expr"));
        assert_eq!(CfaRule::Undefined.to_string(), "undef");
    }

    #[test]
    fn reg_rule_display_variants() {
        assert_eq!(RegRule::SameValue.to_string(), "same");
        assert_eq!(RegRule::Offset(-8).to_string(), "[cfa+-8]");
        assert_eq!(RegRule::Register(6).to_string(), "r6");
        assert!(RegRule::Expression(vec![]).to_string().contains("expr"));
    }

    #[test]
    fn unwind_table_empty_row_for_pc() {
        let t = UnwindTable::new();
        assert!(t.row_for_pc(0x1000).is_none());
    }

    #[test]
    fn unwind_table_row_lookup() {
        let mut t = UnwindTable::new();
        let mut r = UnwindRow::new(0x1000);
        r.cfa = CfaRule::RegisterAndOffset { reg: 7, offset: 8 };
        t.rows.push(r);
        assert!(t.row_for_pc(0x1000).is_some());
        assert!(t.row_for_pc(0x2000).is_some());
        assert!(t.row_for_pc(0x0FFF).is_none());
    }

    #[test]
    fn fde_covers() {
        let fde = Fde {
            section_offset: 0,
            cie_offset: 0,
            pc_begin: 0x1000,
            pc_range: 0x100,
            instructions: vec![],
        };
        assert!(fde.covers(0x1000));
        assert!(fde.covers(0x10FF));
        assert!(!fde.covers(0x1100));
    }

    #[test]
    fn fde_display() {
        let f = Fde { section_offset: 0x20, cie_offset: 0, pc_begin: 0x4000, pc_range: 0x80, instructions: vec![] };
        assert!(f.to_string().contains("0x4000"));
    }

    #[test]
    fn cie_display() {
        let c = Cie { section_offset: 0, version: 1, augmentation: String::new(),
                      addr_size: 8, segment_size: 0, code_align: 1, data_align: -8,
                      return_addr_reg: 16, initial_insns: vec![], fde_ptr_encoding: None };
        assert!(c.to_string().contains("CIE"));
    }

    #[test]
    fn cfi_section_empty_data() {
        let s = CfiSection::parse(&[], false);
        assert!(s.cies.is_empty());
        assert!(s.fdes.is_empty());
    }

    #[test]
    fn cfi_section_terminator() {
        let data = [0u8; 4]; // zero length = terminator
        let s = CfiSection::parse(&data, false);
        assert!(s.cies.is_empty());
    }

    #[test]
    fn unwind_table_build_advances() {
        // Build a CIE + FDE with one AdvanceLoc + DefCfa instruction
        let cie = Cie {
            section_offset: 0, version: 1, augmentation: String::new(),
            addr_size: 8, segment_size: 0, code_align: 1, data_align: -8,
            return_addr_reg: 16, fde_ptr_encoding: None,
            initial_insns: vec![CfaInsn::DefCfa { reg: 7, offset: 8 }],
        };
        let fde = Fde {
            section_offset: 0x40, cie_offset: 0, pc_begin: 0x1000, pc_range: 0x50,
            instructions: vec![CfaInsn::AdvanceLoc(4), CfaInsn::DefCfaOffset(16)],
        };
        let table = UnwindTable::build(&cie, &fde);
        assert!(!table.rows.is_empty());
        let row = table.row_for_pc(0x1000).unwrap();
        // Initial CFA = r7+8
        assert!(matches!(row.cfa, CfaRule::RegisterAndOffset { reg: 7, .. }));
    }
}

#[cfg(test)]
mod frame_length_wrap_tests {
    use super::*;

    /// A 64-bit-format CFI entry whose `length` is chosen so that
    /// `pos + length as usize` WRAPS around usize.
    fn wrapping_entry() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // 64-bit format marker
        v.extend_from_slice(&(u64::MAX - 8).to_le_bytes()); // length: pos + length wraps
        v.extend_from_slice(&0u64.to_le_bytes()); // cie_id == 0 -> CIE in .eh_frame
        v.resize(64, 0);
        v
    }

    /// `end = *pos + length as usize` overflows (release builds have
    /// overflow-checks OFF), so `end` becomes a SMALL number instead of a huge
    /// one. It is then used both as the instruction-decode bound and as the
    /// cursor (`*pos = end`), which REWINDS the parse below the entry it just
    /// consumed. A length that cannot fit the section must be rejected.
    #[test]
    fn cie_parse_rejects_wrapping_length() {
        let data = wrapping_entry();
        let mut pos = 0usize;
        assert!(
            Cie::parse(&data, &mut pos, true).is_none(),
            "Cie::parse accepted a length whose end offset overflows usize"
        );
    }

    /// The section scanner has the same shape, and there the wrapped `end`
    /// slips past an explicit bound test: `if end > data.len() { break; }`
    /// PASSES because `end` wrapped small. Nothing may be recovered from it.
    #[test]
    fn cfi_section_parse_rejects_wrapping_length() {
        let data = wrapping_entry();
        let section = CfiSection::parse(&data, true);
        assert_eq!(
            (section.cies.len(), section.fdes.len()),
            (0, 0),
            "CfiSection::parse accepted an entry with an overflowing length"
        );
    }

    /// The cursor must never move backwards: a rewind is what turns the
    /// wrapped `end` into a non-terminating scan on some inputs.
    #[test]
    fn cie_parse_never_rewinds_cursor() {
        let data = wrapping_entry();
        let mut pos = 0usize;
        let _ = Cie::parse(&data, &mut pos, true);
        assert!(pos >= 12, "cursor rewound to {pos}, below the entry header it consumed");
    }
}

#[cfg(test)]
mod register_truncation_tests {
    use super::*;

    /// Encode `v` as ULEB128.
    fn uleb(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 { b |= 0x80; }
            out.push(b);
            if v == 0 { break; }
        }
    }

    /// A DWARF register number is a ULEB128 — i.e. up to u64. Narrowing it with
    /// `as u32` DISCARDS the high bits, so `0x1_0000_0006` becomes `6`. The rule
    /// is then installed on register 6 (rbp on x86-64): a bogus register number
    /// in a hostile .eh_frame silently OVERWRITES the unwind rule of a real
    /// callee-saved register. Out-of-range numbers must not alias a real one.
    #[test]
    fn oversized_register_number_does_not_alias_a_real_register() {
        let mut data = vec![0x05u8]; // DW_CFA_offset_extended
        uleb(0x1_0000_0006, &mut data); // register: truncates to 6
        uleb(1, &mut data); // offset
        let mut pos = 0usize;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        assert_eq!(insns.len(), 1);
        match insns[0] {
            CfaInsn::Offset { reg, .. } => assert_ne!(
                reg, 6,
                "register 0x1_0000_0006 was truncated onto real register 6"
            ),
            ref other => panic!("unexpected insn {other:?}"),
        }
    }

    /// Same defect through the rule-application path: the truncated number must
    /// not end up as a rule for the real register it aliases.
    #[test]
    fn oversized_register_number_does_not_install_rule_on_real_register() {
        let mut data = vec![0x05u8];
        uleb(0x1_0000_0006, &mut data);
        uleb(1, &mut data);
        let mut pos = 0usize;
        let insns = decode_cfa_insns(&data, &mut pos, data.len(), 8);
        let mut row = UnwindRow::new(0);
        let mut stack: Vec<UnwindRow> = Vec::new();
        let mut table = UnwindTable::default();
        let initial: HashMap<u32, RegRule> = HashMap::new();
        apply_cfa_insns(&insns, &mut row, &mut stack, &mut table, 1, -8, &initial);
        assert!(
            !row.registers.contains_key(&6),
            "a rule was installed on real register 6 from an out-of-range number"
        );
    }
}
