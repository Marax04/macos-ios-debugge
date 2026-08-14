//! MSP430 addressing modes: `Msp430AddrMode`, `EffectiveAddress`,
//! `decode_src_mode()`, `decode_dst_mode()`.
//!
//! This module provides a high-level, type-safe encoding of the MSP430
//! addressing mode system including the constant generator (R2/R3 shortcuts)
//! and MSP430X 20-bit extensions. It is kept independent of the instruction
//! decoder so other modules can reuse the addressing logic.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Msp430AddrMode ────────────────────────────────────────────────────────────

/// Addressing mode for a source or destination operand.
///
/// The values here follow the MSP430 hardware manual. Constant-generator
/// values are folded directly into the `Constant` variant so that callers
/// never need to special-case register 2 / register 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Msp430AddrMode {
    /// `Rn` — register direct.
    RegisterDirect { reg: u8 },
    /// `offset(Rn)` — register indexed (with a following 16-bit word).
    Indexed { reg: u8, offset: i16 },
    /// `&ADDR` — absolute (Rn = SR / R2 with AS=01 or AD=1).
    Absolute { addr: u16 },
    /// `@Rn` — register indirect.
    Indirect { reg: u8 },
    /// `@Rn+` — register indirect with auto-increment.
    IndirectAutoInc { reg: u8 },
    /// `#N` — immediate (PC indirect auto-increment).
    Immediate { value: u16 },
    /// `ADDR` — symbolic (PC-relative indexed).
    Symbolic { addr: u16 },
    /// Constant-generator value (never requires an extension word).
    Constant { value: i8 },
}

impl Msp430AddrMode {
    /// Return the number of additional 16-bit extension words this mode
    /// consumes following the base instruction word.
    #[must_use]
    pub const fn extension_words(self) -> usize {
        match self {
            Self::RegisterDirect { .. }
            | Self::Indirect { .. }
            | Self::IndirectAutoInc { .. }
            | Self::Constant { .. } => 0,
            Self::Indexed { .. }
            | Self::Absolute { .. }
            | Self::Immediate { .. }
            | Self::Symbolic { .. } => 1,
        }
    }

    /// Return `true` if this mode reads from memory.
    #[must_use]
    pub const fn reads_memory(self) -> bool {
        matches!(
            self,
            Self::Indexed { .. }
                | Self::Absolute { .. }
                | Self::Indirect { .. }
                | Self::IndirectAutoInc { .. }
                | Self::Symbolic { .. }
        )
    }

    /// Return `true` if this mode is valid as a destination.
    #[must_use]
    pub const fn is_valid_destination(self) -> bool {
        // Only RegisterDirect, Indexed, Absolute, Symbolic are valid dsts.
        matches!(
            self,
            Self::RegisterDirect { .. }
                | Self::Indexed { .. }
                | Self::Absolute { .. }
                | Self::Symbolic { .. }
        )
    }

    /// Return `true` if this mode modifies a register as a side-effect
    /// (only `IndirectAutoInc`).
    #[must_use]
    pub const fn has_auto_increment(self) -> bool {
        matches!(self, Self::IndirectAutoInc { .. })
    }

    /// Return the register involved, if any.
    #[must_use]
    pub const fn register(self) -> Option<u8> {
        match self {
            Self::RegisterDirect { reg }
            | Self::Indexed { reg, .. }
            | Self::Indirect { reg }
            | Self::IndirectAutoInc { reg } => Some(reg),
            _ => None,
        }
    }

    /// Return a short mode name for display purposes.
    #[must_use]
    pub const fn mode_name(self) -> &'static str {
        match self {
            Self::RegisterDirect { .. } => "Rn",
            Self::Indexed { .. } => "offset(Rn)",
            Self::Absolute { .. } => "&ADDR",
            Self::Indirect { .. } => "@Rn",
            Self::IndirectAutoInc { .. } => "@Rn+",
            Self::Immediate { .. } => "#N",
            Self::Symbolic { .. } => "ADDR",
            Self::Constant { .. } => "#const",
        }
    }
}

impl fmt::Display for Msp430AddrMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterDirect { reg } => write!(f, "R{reg}"),
            Self::Indexed { reg, offset } => write!(f, "{offset}(R{reg})"),
            Self::Absolute { addr } => write!(f, "&{addr:#06X}"),
            Self::Indirect { reg } => write!(f, "@R{reg}"),
            Self::IndirectAutoInc { reg } => write!(f, "@R{reg}+"),
            Self::Immediate { value } => write!(f, "#{value:#06X}"),
            Self::Symbolic { addr } => write!(f, "{addr:#06X}"),
            Self::Constant { value } => write!(f, "#{value}"),
        }
    }
}

// ── EffectiveAddress ──────────────────────────────────────────────────────────

/// The effective address (EA) computed from an addressing mode together with
/// the current program-counter and register state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectiveAddress {
    /// EA is a concrete 16-bit address.
    Concrete(u16),
    /// EA is a concrete 20-bit address (MSP430X).
    Concrete20(u32),
    /// EA comes from a register and is not statically known.
    Register(u8),
    /// EA is the constant value embedded in the addressing mode.
    Immediate(i16),
    /// EA cannot be resolved statically.
    Unknown,
}

impl EffectiveAddress {
    /// Return the concrete 16-bit address if this EA is statically known.
    #[must_use]
    pub const fn as_u16(&self) -> Option<u16> {
        match self {
            Self::Concrete(a) => Some(*a),
            _ => None,
        }
    }

    /// Return the concrete 20-bit address if this EA is statically known.
    #[must_use]
    pub const fn as_u20(&self) -> Option<u32> {
        match self {
            Self::Concrete(a) => Some(*a as u32),
            Self::Concrete20(a) => Some(*a),
            _ => None,
        }
    }

    /// Return `true` if the EA is statically resolved.
    #[must_use]
    pub const fn is_concrete(&self) -> bool {
        matches!(self, Self::Concrete(_) | Self::Concrete20(_))
    }
}

impl fmt::Display for EffectiveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concrete(a) => write!(f, "{a:#06X}"),
            Self::Concrete20(a) => write!(f, "{a:#07X}"),
            Self::Register(r) => write!(f, "R{r}"),
            Self::Immediate(v) => write!(f, "#{v}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ── Constant generator table ───────────────────────────────────────────────────

/// Decode the constant-generator (CG) value for a given (register, `as_bits`)
/// pair.  Returns `Some(constant_value)` for the special CG combinations.
///
/// Constant generator table:
/// | Reg | AS | Value |
/// |-----|----|-------|
/// | R2  | 00 | — (SR register mode, not CG) |
/// | R2  | 01 | — (SR indexed, not CG) |
/// | R2  | 10 | 4     |
/// | R2  | 11 | 8     |
/// | R3  | 00 | 0     |
/// | R3  | 01 | 1     |
/// | R3  | 10 | 2     |
/// | R3  | 11 | −1    |
#[must_use]
pub const fn constant_generator_value(reg: u8, as_bits: u8) -> Option<i8> {
    match (reg, as_bits) {
        (2, 2) => Some(4),
        (2, 3) => Some(8),
        (3, 0) => Some(0),
        (3, 1) => Some(1),
        (3, 2) => Some(2),
        (3, 3) => Some(-1),
        _ => None,
    }
}

// ── decode_src_mode ────────────────────────────────────────────────────────────

/// Decode the source addressing mode from the raw instruction fields.
///
/// # Parameters
/// - `as_bits`: 2-bit addressing-mode selector for the source (bits 5-4 of the
///   base instruction word for Format I, bits 5-4 of Format II).
/// - `reg`: 4-bit source register index (0–15).
/// - `ext_word`: The extension word following the base instruction word, if
///   available. Supply `None` when the mode does not require one.
/// - `pc`: The address of the instruction (needed for symbolic mode).
///
/// # Returns
/// The decoded [`Msp430AddrMode`] for the source operand.
#[must_use]
pub fn decode_src_mode(as_bits: u8, reg: u8, ext_word: Option<u16>, pc: u16) -> Msp430AddrMode {
    // Check constant generator first.
    if let Some(c) = constant_generator_value(reg, as_bits) {
        return Msp430AddrMode::Constant { value: c };
    }

    match as_bits & 0x3 {
        0 => Msp430AddrMode::RegisterDirect { reg },
        1 => {
            if reg == 2 {
                // R2 with AS=01 → absolute addressing.
                Msp430AddrMode::Absolute { addr: ext_word.unwrap_or(0) }
            } else if reg == 0 {
                // PC with AS=01 → symbolic (PC-relative).
                let offset = ext_word.unwrap_or(0) as i16;
                let target = (i32::from(pc) + 2 + i32::from(offset)) as u16;
                Msp430AddrMode::Symbolic { addr: target }
            } else {
                Msp430AddrMode::Indexed {
                    reg,
                    offset: ext_word.unwrap_or(0) as i16,
                }
            }
        }
        2 => Msp430AddrMode::Indirect { reg },
        3 => {
            if reg == 0 {
                // PC with AS=11 → immediate.
                Msp430AddrMode::Immediate { value: ext_word.unwrap_or(0) }
            } else {
                Msp430AddrMode::IndirectAutoInc { reg }
            }
        }
        _ => unreachable!("as_bits & 3 can only be 0..3"),
    }
}

// ── decode_dst_mode ────────────────────────────────────────────────────────────

/// Decode the destination addressing mode from the raw instruction fields.
///
/// For Format I (two-operand) instructions the destination has only one
/// addressing mode bit (`AD`):
/// - AD=0 → register direct.
/// - AD=1 → indexed (with extension word), or absolute if reg==2.
///
/// # Parameters
/// - `ad`: 1-bit destination addressing mode (bit 7 of the base instruction
///   word).
/// - `reg`: 4-bit destination register index.
/// - `ext_word`: Extension word, if any.
/// - `pc`: Address of the instruction (for symbolic mode, reg==0).
#[must_use]
pub fn decode_dst_mode(ad: u8, reg: u8, ext_word: Option<u16>, pc: u16) -> Msp430AddrMode {
    match ad & 1 {
        0 => Msp430AddrMode::RegisterDirect { reg },
        1 => {
            if reg == 2 {
                Msp430AddrMode::Absolute { addr: ext_word.unwrap_or(0) }
            } else if reg == 0 {
                let offset = ext_word.unwrap_or(0) as i16;
                let target = (i32::from(pc) + 2 + i32::from(offset)) as u16;
                Msp430AddrMode::Symbolic { addr: target }
            } else {
                Msp430AddrMode::Indexed {
                    reg,
                    offset: ext_word.unwrap_or(0) as i16,
                }
            }
        }
        _ => unreachable!(),
    }
}

// ── compute_effective_address ─────────────────────────────────────────────────

/// Compute the effective address for an addressing mode given a register
/// reader callback.
///
/// # Parameters
/// - `mode`: The decoded addressing mode.
/// - `read_reg`: A closure that returns the 16-bit value of register `r`.
/// - `pc_after`: The PC value after reading any extension word(s).
///
/// # Returns
/// The [`EffectiveAddress`] for this mode, which may be concrete or require
/// a register read at runtime.
#[must_use]
pub fn compute_effective_address(
    mode: Msp430AddrMode,
    read_reg: impl Fn(u8) -> u16,
    _pc_after: u16,
) -> EffectiveAddress {
    match mode {
        Msp430AddrMode::RegisterDirect { reg } => EffectiveAddress::Register(reg),
        Msp430AddrMode::Indexed { reg, offset } => {
            let base = read_reg(reg);
            EffectiveAddress::Concrete(base.wrapping_add(offset as u16))
        }
        Msp430AddrMode::Absolute { addr } => EffectiveAddress::Concrete(addr),
        Msp430AddrMode::Indirect { reg } => EffectiveAddress::Concrete(read_reg(reg)),
        Msp430AddrMode::IndirectAutoInc { reg } => EffectiveAddress::Concrete(read_reg(reg)),
        Msp430AddrMode::Immediate { value } => EffectiveAddress::Immediate(value as i16),
        Msp430AddrMode::Symbolic { addr } => EffectiveAddress::Concrete(addr),
        Msp430AddrMode::Constant { value } => EffectiveAddress::Immediate(i16::from(value)),
    }
}

// ── AddressingModeInfo ────────────────────────────────────────────────────────

/// Detailed info about an addressing mode useful for lifters and analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressingModeInfo {
    pub mode: Msp430AddrMode,
    pub extension_words: usize,
    pub reads_memory: bool,
    pub modifies_register: bool,
    pub is_constant: bool,
    pub effective_addr: Option<u16>,
}

impl AddressingModeInfo {
    #[must_use]
    pub const fn from_mode(mode: Msp430AddrMode) -> Self {
        let effective_addr = match mode {
            Msp430AddrMode::Absolute { addr } => Some(addr),
            Msp430AddrMode::Symbolic { addr } => Some(addr),
            _ => None,
        };
        Self {
            extension_words: mode.extension_words(),
            reads_memory: mode.reads_memory(),
            modifies_register: mode.has_auto_increment(),
            is_constant: matches!(mode, Msp430AddrMode::Constant { .. }),
            effective_addr,
            mode,
        }
    }
}

// ── Instruction size calculator ───────────────────────────────────────────────

/// Compute the total byte size of a Format I (two-operand) MSP430 instruction.
///
/// Returns `2 + 2*src_ext + 2*dst_ext`.
#[must_use]
pub const fn format1_size(src_mode: Msp430AddrMode, dst_mode: Msp430AddrMode) -> usize {
    2 + 2 * src_mode.extension_words() + 2 * dst_mode.extension_words()
}

/// Compute the total byte size of a Format II (single-operand) instruction.
#[must_use]
pub const fn format2_size(src_mode: Msp430AddrMode) -> usize {
    2 + 2 * src_mode.extension_words()
}

/// Compute the total byte size of a Format III (jump) instruction.
///
/// Jump instructions are always 2 bytes.
#[must_use]
pub const fn format3_size() -> usize {
    2
}

// ── Pretty-printer helpers ────────────────────────────────────────────────────

/// Format a source operand for AT&T / GNU MSP430 assembly syntax.
#[must_use]
pub fn format_src_operand(mode: Msp430AddrMode, reg_name: impl Fn(u8) -> &'static str) -> String {
    match mode {
        Msp430AddrMode::RegisterDirect { reg } => reg_name(reg).to_string(),
        Msp430AddrMode::Indexed { reg, offset } => format!("{offset}({n})", n = reg_name(reg)),
        Msp430AddrMode::Absolute { addr } => format!("&{addr:#06x}"),
        Msp430AddrMode::Indirect { reg } => format!("@{}", reg_name(reg)),
        Msp430AddrMode::IndirectAutoInc { reg } => format!("@{}+", reg_name(reg)),
        Msp430AddrMode::Immediate { value } => format!("#{value:#06x}"),
        Msp430AddrMode::Symbolic { addr } => format!("{addr:#06x}"),
        Msp430AddrMode::Constant { value } => format!("#{value}"),
    }
}

/// Format a destination operand for AT&T / GNU MSP430 assembly syntax.
#[must_use]
pub fn format_dst_operand(mode: Msp430AddrMode, reg_name: impl Fn(u8) -> &'static str) -> String {
    // Destination operands look the same as source for the modes that are valid.
    format_src_operand(mode, reg_name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_generator_r2_as2() {
        assert_eq!(constant_generator_value(2, 2), Some(4));
    }

    #[test]
    fn test_constant_generator_r3_as3() {
        assert_eq!(constant_generator_value(3, 3), Some(-1));
    }

    #[test]
    fn test_constant_generator_not_cg() {
        assert_eq!(constant_generator_value(4, 0), None);
        assert_eq!(constant_generator_value(2, 0), None);
    }

    #[test]
    fn test_decode_src_register_direct() {
        let m = decode_src_mode(0, 4, None, 0x4000);
        assert_eq!(m, Msp430AddrMode::RegisterDirect { reg: 4 });
    }

    #[test]
    fn test_decode_src_immediate() {
        let m = decode_src_mode(3, 0, Some(0x1234), 0x4000);
        assert_eq!(m, Msp430AddrMode::Immediate { value: 0x1234 });
    }

    #[test]
    fn test_decode_src_indirect() {
        let m = decode_src_mode(2, 5, None, 0x4000);
        assert_eq!(m, Msp430AddrMode::Indirect { reg: 5 });
    }

    #[test]
    fn test_decode_src_indirect_autoinc() {
        let m = decode_src_mode(3, 6, None, 0x4000);
        assert_eq!(m, Msp430AddrMode::IndirectAutoInc { reg: 6 });
    }

    #[test]
    fn test_decode_src_absolute() {
        let m = decode_src_mode(1, 2, Some(0xFFEE), 0x4000);
        assert_eq!(m, Msp430AddrMode::Absolute { addr: 0xFFEE });
    }

    #[test]
    fn test_decode_src_indexed() {
        let m = decode_src_mode(1, 7, Some(0x10), 0x4000);
        assert_eq!(m, Msp430AddrMode::Indexed { reg: 7, offset: 0x10 });
    }

    #[test]
    fn test_decode_src_constant_cg() {
        let m = decode_src_mode(2, 3, None, 0x4000);
        assert_eq!(m, Msp430AddrMode::Constant { value: 2 });
    }

    #[test]
    fn test_decode_dst_register_direct() {
        let m = decode_dst_mode(0, 12, None, 0x4000);
        assert_eq!(m, Msp430AddrMode::RegisterDirect { reg: 12 });
    }

    #[test]
    fn test_decode_dst_absolute() {
        let m = decode_dst_mode(1, 2, Some(0x0200), 0x4000);
        assert_eq!(m, Msp430AddrMode::Absolute { addr: 0x0200 });
    }

    #[test]
    fn test_extension_words() {
        assert_eq!(Msp430AddrMode::RegisterDirect { reg: 4 }.extension_words(), 0);
        assert_eq!(Msp430AddrMode::Immediate { value: 0 }.extension_words(), 1);
        assert_eq!(Msp430AddrMode::Constant { value: 1 }.extension_words(), 0);
    }

    #[test]
    fn test_format1_size() {
        let src = Msp430AddrMode::Immediate { value: 0 }; // 1 ext word
        let dst = Msp430AddrMode::RegisterDirect { reg: 4 }; // 0 ext words
        assert_eq!(format1_size(src, dst), 4);
    }

    #[test]
    fn test_mode_display() {
        let m = Msp430AddrMode::Indexed { reg: 4, offset: -2 };
        let s = format!("{m}");
        assert!(s.contains("-2"));
        assert!(s.contains("R4"));
    }

    #[test]
    fn test_effective_address_concrete() {
        let ea = EffectiveAddress::Concrete(0xFFFC);
        assert!(ea.is_concrete());
        assert_eq!(ea.as_u16(), Some(0xFFFC));
    }

    #[test]
    fn test_compute_ea_indexed() {
        let mode = Msp430AddrMode::Indexed { reg: 1, offset: 4 };
        let ea = compute_effective_address(mode, |_r| 0x0200, 0x4004);
        assert_eq!(ea.as_u16(), Some(0x0204));
    }

    #[test]
    fn test_addressing_mode_info() {
        let mode = Msp430AddrMode::IndirectAutoInc { reg: 2 };
        let info = AddressingModeInfo::from_mode(mode);
        assert!(info.reads_memory);
        assert!(info.modifies_register);
    }

    #[test]
    fn test_is_valid_destination_immediate() {
        // Immediate is not a valid destination.
        assert!(!Msp430AddrMode::Immediate { value: 0 }.is_valid_destination());
    }

    #[test]
    fn test_is_valid_destination_register() {
        assert!(Msp430AddrMode::RegisterDirect { reg: 4 }.is_valid_destination());
    }

    #[test]
    fn test_symbolic_mode_pc_relative() {
        // PC=0x4000, ext=0x0010 → target = 0x4000 + 2 + 0x10 = 0x4012
        let m = decode_src_mode(1, 0, Some(0x0010), 0x4000);
        assert_eq!(m, Msp430AddrMode::Symbolic { addr: 0x4012 });
    }
}
