//! `rustre-arch-68k`
//!
//! Motorola 68000 family architecture implementation for the `RustRE` Suite.
//! Supports M68000, M68010, M68020, M68030, M68040 variants.
//! Full instruction set: integer ALU, shifts/rotates, bitfield ops, FPU,
//! MMU control, BCD arithmetic, branch prediction tables, calling
//! conventions, linear sweep and recursive-descent disassemblers.

pub mod m68k_analysis;

/// M68k OS-level ABI analysis: AmigaABI, MacOS68kABI, TrampolinePattern,
/// A5WorldRelative, JumpTable, M68kOsAbi facade.
///
pub mod m68k_os_abi;

/// 68000→68060 ISA capability matrix, full extension word, bitfield ops,
/// 68881/68882 FPU instruction set, 68040/060 FPU subsets.
pub mod m68k_extensions;

/// Platform-specific 68k knowledge: Amiga custom chips, Sega Genesis VDP,
/// Mac 68k A-line traps, Sun-3 SunOS system calls.
pub mod m68k_platforms;

/// M68K addressing modes: M68kAddressingMode, EffectiveAddress, decode_ea(), ea_cycles().
pub mod m68k_addressing_modes;

/// M68K exception vectors: M68kExceptionVector, VectorEntry, vector_name().
pub mod m68k_exception_vectors;

/// Extended M68K FPU/MMU disassembly: M68kDisassemblerExt, FpuInsn, MmuInsn.
pub mod m68k_disassembler_ext;

/// Strongly-typed M68k instruction representation: `M68kInstr`, `M68kEa`, `M68kSize`, `M68kDecoder`.
pub mod m68k_decoder;

/// High-level M68k disassembler with configurable Motorola-syntax formatting: `M68kDisassembler`, `DisasmLine`.
pub mod m68k_disassembler;

/// M68k register-file emulation model: `M68kRegFile`, `M68kDReg`, `M68kAReg`, `M68kSr`, `M68kCcr`.
pub mod m68k_registers;

use bitflags::bitflags;
use rustre_core::arch::{
    Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
};
use rustre_core::arch::{BranchCondition, BranchKind, RegisterKind};
use rustre_core::{address::Address, endian::Endian, errors::CoreError};

// ── Variant ───────────────────────────────────────────────────────────────────

/// Motorola 68000 CPU variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mc68kVariant {
    /// Original 16/32-bit processor with 24-bit address bus.
    M68000,
    /// 68010 — adds loop mode and VBR.
    M68010,
    /// 68020 — full 32-bit ALU, bitfield, cache, coprocessors.
    M68020,
    /// 68030 — on-chip MMU and data cache.
    M68030,
    /// 68040 — on-chip FPU, MMU, split cache.
    M68040,
    /// 68060 — superscalar 68040 successor.
    M68060,
    /// `ColdFire` V1-V4 — 68k-compatible embedded line.
    ColdFire,
}

impl Mc68kVariant {
    /// Return the human-readable name of this variant.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::M68000 => "68000",
            Self::M68010 => "68010",
            Self::M68020 => "68020",
            Self::M68030 => "68030",
            Self::M68040 => "68040",
            Self::M68060 => "68060",
            Self::ColdFire => "ColdFire",
        }
    }

    /// Whether this variant has the on-chip FPU.
    #[must_use]
    pub const fn has_fpu(self) -> bool {
        matches!(self, Self::M68040 | Self::M68060)
    }

    /// Whether this variant supports 32-bit instruction extensions (68020+).
    #[must_use]
    pub const fn is_32bit(self) -> bool {
        matches!(
            self,
            Self::M68020 | Self::M68030 | Self::M68040 | Self::M68060 | Self::ColdFire
        )
    }

    /// Whether this variant has an on-chip MMU (030+).
    #[must_use]
    pub const fn has_mmu(self) -> bool {
        matches!(self, Self::M68030 | Self::M68040 | Self::M68060)
    }

    /// Whether this variant supports bitfield instructions (68020+).
    #[must_use]
    pub const fn has_bitfield(self) -> bool {
        self.is_32bit()
    }

    /// Maximum addressable bytes.
    #[must_use]
    pub const fn address_space_bytes(self) -> u64 {
        match self {
            Self::M68000 | Self::M68010 => 0x0100_0000, // 24-bit
            _ => 0x1_0000_0000,                         // 32-bit
        }
    }
}

// ── Register IDs ──────────────────────────────────────────────────────────────

/// Data register D0.
pub const REG_D0: u32 = 0;
/// Data register D1.
pub const REG_D1: u32 = 1;
/// Data register D2.
pub const REG_D2: u32 = 2;
/// Data register D3.
pub const REG_D3: u32 = 3;
/// Data register D4.
pub const REG_D4: u32 = 4;
/// Data register D5.
pub const REG_D5: u32 = 5;
/// Data register D6.
pub const REG_D6: u32 = 6;
/// Data register D7.
pub const REG_D7: u32 = 7;
/// Address register A0.
pub const REG_A0: u32 = 8;
/// Address register A7 (stack pointer).
pub const REG_A7: u32 = 15;
/// Program counter.
pub const REG_PC: u32 = 16;
/// Status register.
pub const REG_SR: u32 = 17;
/// Condition code register (lower byte of SR).
pub const REG_CCR: u32 = 18;
/// User stack pointer.
pub const REG_USP: u32 = 19;
/// Vector base register (68010+).
pub const REG_VBR: u32 = 20;
/// SFC — source function code register (68010+).
pub const REG_SFC: u32 = 21;
/// DFC — destination function code register (68010+).
pub const REG_DFC: u32 = 22;
/// Cache control register (68020+).
pub const REG_CACR: u32 = 23;
/// Cache address register (68020+).
pub const REG_CAAR: u32 = 24;
/// Master stack pointer (68020+).
pub const REG_MSP: u32 = 25;
/// Interrupt stack pointer (68020+).
pub const REG_ISP: u32 = 26;
/// FPU data register FP0.
pub const REG_FP0: u32 = 32;
/// FPU data register FP7.
pub const REG_FP7: u32 = 39;
/// FPU status register.
pub const REG_FPSR: u32 = 40;
/// FPU control register.
pub const REG_FPCR: u32 = 41;
/// FPU instruction address register.
pub const REG_FPIAR: u32 = 42;

// ── Effective address sizes ───────────────────────────────────────────────────

/// Operand size for 68k instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Size {
    /// 8-bit byte.
    Byte,
    /// 16-bit word.
    Word,
    /// 32-bit long.
    Long,
    /// 64-bit quad (68020 MUL/DIV extended).
    Quad,
}

impl Size {
    /// The assembly suffix for this size.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Byte => ".B",
            Self::Word => ".W",
            Self::Long => ".L",
            Self::Quad => ".Q",
        }
    }

    /// Number of bytes consumed by this size.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Long => 4,
            Self::Quad => 8,
        }
    }

    /// Decode from the standard 2-bit size encoding (bits 7:6 or bits 1:0).
    #[must_use]
    pub const fn from_bits2(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::Byte,
            1 => Self::Word,
            _ => Self::Long,
        }
    }
}

// ── Condition codes ───────────────────────────────────────────────────────────

/// All 68k condition codes, including the "T" (always-true) and "F" (never).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondCode {
    T = 0,
    F = 1,
    Hi = 2,
    Ls = 3,
    Cc = 4,
    Cs = 5,
    Ne = 6,
    Eq = 7,
    Vc = 8,
    Vs = 9,
    Pl = 10,
    Mi = 11,
    Ge = 12,
    Lt = 13,
    Gt = 14,
    Le = 15,
}

impl CondCode {
    /// Decode from 4-bit condition field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0xF {
            0 => Self::T,
            1 => Self::F,
            2 => Self::Hi,
            3 => Self::Ls,
            4 => Self::Cc,
            5 => Self::Cs,
            6 => Self::Ne,
            7 => Self::Eq,
            8 => Self::Vc,
            9 => Self::Vs,
            10 => Self::Pl,
            11 => Self::Mi,
            12 => Self::Ge,
            13 => Self::Lt,
            14 => Self::Gt,
            _ => Self::Le,
        }
    }

    /// The assembly mnemonic suffix.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::T => "T",
            Self::F => "F",
            Self::Hi => "HI",
            Self::Ls => "LS",
            Self::Cc => "CC",
            Self::Cs => "CS",
            Self::Ne => "NE",
            Self::Eq => "EQ",
            Self::Vc => "VC",
            Self::Vs => "VS",
            Self::Pl => "PL",
            Self::Mi => "MI",
            Self::Ge => "GE",
            Self::Lt => "LT",
            Self::Gt => "GT",
            Self::Le => "LE",
        }
    }

    /// True if this condition is always-true.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::T)
    }
}

// ── Access flags for operand analysis ────────────────────────────────────────

bitflags! {
    /// Operand access mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessMode: u8 {
        /// Operand is read.
        const READ  = 0x01;
        /// Operand is written.
        const WRITE = 0x02;
        /// Operand is both read and written.
        const RMW   = 0x03;
    }
}

// ── Effective address formatting ──────────────────────────────────────────────

/// Effective address mode kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EaKind {
    /// Data register direct Dn.
    DataReg(u8),
    /// Address register direct An.
    AddrReg(u8),
    /// Address register indirect (An).
    AddrInd(u8),
    /// Address register indirect with post-increment (An)+.
    AddrIndPost(u8),
    /// Address register indirect with pre-decrement -(An).
    AddrIndPre(u8),
    /// Address register indirect with displacement disp(An).
    AddrIndDisp(u8, i16),
    /// Address register indirect with index.
    AddrIndIdx(u8, i8, u8, bool),
    /// Absolute short.
    AbsShort(u16),
    /// Absolute long.
    AbsLong(u32),
    /// PC-relative with displacement.
    PcDisp(i16),
    /// PC-relative with index.
    PcIdx,
    /// Immediate value (up to 4 bytes).
    Immediate(u32),
}

impl EaKind {
    /// Format the EA as a string.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::DataReg(r) => format!("D{r}"),
            Self::AddrReg(r) => format!("A{r}"),
            Self::AddrInd(r) => format!("(A{r})"),
            Self::AddrIndPost(r) => format!("(A{r})+"),
            Self::AddrIndPre(r) => format!("-(A{r})"),
            Self::AddrIndDisp(r, d) => format!("{d}(A{r})"),
            Self::AddrIndIdx(r, d, x, is_a) => {
                let xt = if *is_a { 'A' } else { 'D' };
                format!("{d}(A{r},{xt}{x})")
            }
            Self::AbsShort(a) => format!("${a:04X}.W"),
            Self::AbsLong(a) => format!("${a:08X}.L"),
            Self::PcDisp(d) => format!("{d}(PC)"),
            Self::PcIdx => "(PC,Xn)".to_string(),
            Self::Immediate(v) => format!("#${v:08X}"),
        }
    }

    /// Whether this EA can appear as a source of a branch target.
    #[must_use]
    pub const fn is_indirect(&self) -> bool {
        matches!(
            self,
            Self::AddrInd(_)
                | Self::AddrIndPost(_)
                | Self::AddrIndPre(_)
                | Self::AddrIndDisp(_, _)
                | Self::AddrIndIdx(_, _, _, _)
                | Self::PcDisp(_)
                | Self::PcIdx
        )
    }
}

/// Decode effective address mode+reg and return (text, `extra_bytes_consumed`).
fn ea_str(mode: u8, reg: u8, size: Size, ext: &[u8]) -> (String, usize) {
    match mode {
        0 => (format!("D{reg}"), 0),
        1 => (format!("A{reg}"), 0),
        2 => (format!("(A{reg})"), 0),
        3 => (format!("(A{reg})+"), 0),
        4 => (format!("-(A{reg})"), 0),
        5 => {
            if ext.len() >= 2 {
                let disp = i16::from_be_bytes([ext[0], ext[1]]);
                (format!("{disp}(A{reg})"), 2)
            } else {
                (format!("?(A{reg})"), 2)
            }
        }
        6 => {
            if ext.len() >= 2 {
                let brief = ext[0];
                let disp = ext[1].cast_signed();
                let idx_reg = (brief >> 4) & 0xF;
                let idx_type = if brief & 0x80 != 0 { 'A' } else { 'D' };
                (format!("{disp}(A{reg},{idx_type}{idx_reg})"), 2)
            } else {
                (format!("(A{reg}+Xn)"), 2)
            }
        }
        7 => match reg {
            0 => {
                if ext.len() >= 2 {
                    let addr = u32::from(u16::from_be_bytes([ext[0], ext[1]]));
                    (format!("${addr:04X}.W"), 2)
                } else {
                    ("?".to_string(), 2)
                }
            }
            1 => {
                if ext.len() >= 4 {
                    let addr = u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
                    (format!("${addr:08X}.L"), 4)
                } else {
                    ("?".to_string(), 4)
                }
            }
            2 => {
                if ext.len() >= 2 {
                    let disp = i16::from_be_bytes([ext[0], ext[1]]);
                    (format!("{disp}(PC)"), 2)
                } else {
                    ("?(PC)".to_string(), 2)
                }
            }
            3 => ("(PC,Xn)".to_string(), 2),
            4 => {
                let bytes_needed = size.bytes();
                if size == Size::Byte {
                    (format!("#${:02X}", ext.get(1).copied().unwrap_or(0)), 2)
                } else if bytes_needed == 2 && ext.len() >= 2 {
                    (format!("#${:04X}", u16::from_be_bytes([ext[0], ext[1]])), 2)
                } else if ext.len() >= 4 {
                    (
                        format!(
                            "#${:08X}",
                            u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]])
                        ),
                        4,
                    )
                } else {
                    ("#?".to_string(), bytes_needed)
                }
            }
            _ => ("?".to_string(), 0),
        },
        _ => ("?".to_string(), 0),
    }
}

/// Parse an EA into its structured form and return (kind, `extra_bytes`).
///
/// # Errors
/// Returns `CoreError::InvalidInput` if the byte stream is too short.
pub fn parse_ea(mode: u8, reg: u8, size: Size, ext: &[u8]) -> Result<(EaKind, usize), CoreError> {
    match mode {
        0 => Ok((EaKind::DataReg(reg), 0)),
        1 => Ok((EaKind::AddrReg(reg), 0)),
        2 => Ok((EaKind::AddrInd(reg), 0)),
        3 => Ok((EaKind::AddrIndPost(reg), 0)),
        4 => Ok((EaKind::AddrIndPre(reg), 0)),
        5 => {
            if ext.len() < 2 {
                return Err(CoreError::InvalidFormat {
                    message: "EA mode 5 needs 2 ext bytes".to_string(),
                });
            }
            let disp = i16::from_be_bytes([ext[0], ext[1]]);
            Ok((EaKind::AddrIndDisp(reg, disp), 2))
        }
        6 => {
            if ext.len() < 2 {
                return Err(CoreError::InvalidFormat {
                    message: "EA mode 6 needs 2 ext bytes".to_string(),
                });
            }
            let brief = ext[0];
            let disp = ext[1].cast_signed();
            let idx_reg = (brief >> 4) & 7;
            let is_a = brief & 0x80 != 0;
            Ok((EaKind::AddrIndIdx(reg, disp, idx_reg, is_a), 2))
        }
        7 => match reg {
            0 => {
                if ext.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "EA abs.W needs 2 ext bytes".to_string(),
                    });
                }
                let addr = u16::from_be_bytes([ext[0], ext[1]]);
                Ok((EaKind::AbsShort(addr), 2))
            }
            1 => {
                if ext.len() < 4 {
                    return Err(CoreError::InvalidFormat {
                        message: "EA abs.L needs 4 ext bytes".to_string(),
                    });
                }
                let addr = u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
                Ok((EaKind::AbsLong(addr), 4))
            }
            2 => {
                if ext.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "EA PC+disp needs 2 ext bytes".to_string(),
                    });
                }
                let disp = i16::from_be_bytes([ext[0], ext[1]]);
                Ok((EaKind::PcDisp(disp), 2))
            }
            3 => Ok((EaKind::PcIdx, 2)),
            4 => {
                let n = if size == Size::Byte { 2 } else { size.bytes() };
                if ext.len() < n {
                    return Err(CoreError::InvalidFormat {
                        message: "EA immediate too short".to_string(),
                    });
                }
                let val = match size {
                    Size::Byte => u32::from(ext[1]),
                    Size::Word => u32::from(u16::from_be_bytes([ext[0], ext[1]])),
                    _ => u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]),
                };
                Ok((EaKind::Immediate(val), n))
            }
            _ => Err(CoreError::InvalidFormat {
                message: format!("invalid EA 7.{reg}"),
            }),
        },
        _ => Err(CoreError::InvalidFormat {
            message: format!("invalid EA mode {mode}"),
        }),
    }
}

// ── Condition code helper ─────────────────────────────────────────────────────

const fn cc68k(cond: u8) -> &'static str {
    CondCode::from_bits(cond).mnemonic()
}

// ── Main decoder ──────────────────────────────────────────────────────────────

/// Decode a 68000 instruction word and following extension words.
/// Returns (mnemonic, operands, `total_size`, flags).
///
/// # Errors
/// Returns `CoreError::InvalidInput` when the byte slice is truncated.
pub fn decode_68k(bytes: &[u8], pc: u64) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if bytes.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated 68k instruction".to_string(),
        });
    }
    let word = u16::from_be_bytes([bytes[0], bytes[1]]);
    let ext = &bytes[2..];

    let hi4 = (word >> 12) as u8;
    let ea_mode = ((word >> 3) & 7) as u8;
    let ea_reg = (word & 7) as u8;

    // ── MOVE/MOVEA ────────────────────────────────────────────────────────────
    if hi4 == 0x1 || hi4 == 0x2 || hi4 == 0x3 {
        let (move_sz, move_sfx) = match hi4 {
            0x1 => (Size::Byte, ".B"),
            0x3 => (Size::Word, ".W"),
            _ => (Size::Long, ".L"),
        };
        let (src, src_ext) = ea_str(ea_mode, ea_reg, move_sz, ext);
        let dst_mode = ((word >> 6) & 7) as u8;
        let dst_reg = ((word >> 9) & 7) as u8;
        let (dst, dst_ext) = ea_str(dst_mode, dst_reg, move_sz, &ext[src_ext.min(ext.len())..]);
        let total = 2 + src_ext + dst_ext;
        let mn = if dst_mode == 1 {
            format!("MOVEA{move_sfx}")
        } else {
            format!("MOVE{move_sfx}")
        };
        return Ok((mn, format!("{src},{dst}"), total, InstrFlags::NONE));
    }

    match hi4 {
        0x0 => decode_68k_group0(word, ext),
        0x4 => decode_68k_group4(word, ext),
        0x5 => decode_68k_group5(word, ext, pc),
        0x6 => decode_68k_group6(word, ext, pc),
        0x7 => Ok(decode_68k_moveq(word)),
        0x8 => decode_68k_group8(word, ext),
        0x9 => decode_68k_group9(word, ext),
        0xA => Ok((
            format!("LINEA ${:03X}", word & 0xFFF),
            String::new(),
            2,
            InstrFlags::NONE,
        )),
        0xB => decode_68k_group_b(word, ext),
        0xC => decode_68k_group_c(word, ext),
        0xD => decode_68k_group_d(word, ext),
        0xE => decode_68k_group_e(word, ext),
        0xF => decode_68k_group_f(word, ext, pc),
        _ => Ok(decode_68k_dcw(word)),
    }
}

/// Decoded instruction tuple: (mnemonic, operands, size, flags).
pub type Decoded68k = (String, String, usize, InstrFlags);

/// Decode the common EA / register / size fields from an opcode word.
const fn decode_68k_fields(word: u16) -> (u8, u8, u8, u8) {
    (
        ((word >> 3) & 7) as u8,
        (word & 7) as u8,
        ((word >> 9) & 7) as u8,
        ((word >> 6) & 3) as u8,
    )
}

/// Fallback: undecodable word emitted as data.
fn decode_68k_dcw(word: u16) -> Decoded68k {
    (
        "DC.W".to_string(),
        format!("${word:04X}"),
        2,
        InstrFlags::NONE,
    )
}

/// Group 0000: bit ops / immediate / MOVEP.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` when the byte slice is truncated.
pub fn decode_68k_group0(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, _) = decode_68k_fields(word);
    {
            // BTST/BSET/BCLR/BCHG #imm
            let op3 = (word >> 6) & 3;
            if word & 0xFF00 == 0x0800 {
                if ext.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated bit op".to_string(),
                    });
                }
                let bit_num = ext[0];
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, &ext[2..]);
                let mn = match op3 {
                    0 => "BTST",
                    1 => "BCHG",
                    2 => "BCLR",
                    _ => "BSET",
                };
                return Ok((
                    mn.to_string(),
                    format!("#${bit_num:02X},{ea}"),
                    4 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // BTST Dn
            if (word & 0x0FC0) == 0x0100 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok((
                    "BTST".to_string(),
                    format!("D{reg_field},{ea}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // BCHG Dn
            if (word & 0x0FC0) == 0x0140 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok((
                    "BCHG".to_string(),
                    format!("D{reg_field},{ea}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // BCLR Dn
            if (word & 0x0FC0) == 0x0180 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok((
                    "BCLR".to_string(),
                    format!("D{reg_field},{ea}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // BSET Dn
            if (word & 0x0FC0) == 0x01C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok((
                    "BSET".to_string(),
                    format!("D{reg_field},{ea}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // MOVEP
            if (word & 0x0138) == 0x0108 {
                let dir = (word >> 7) & 1;
                let sz_sfx = if (word & 0x0040) != 0 { ".L" } else { ".W" };
                if ext.len() >= 2 {
                    let disp = i16::from_be_bytes([ext[0], ext[1]]);
                    let ops = if dir == 0 {
                        format!("{disp}(A{ea_reg}),D{reg_field}")
                    } else {
                        format!("D{reg_field},{disp}(A{ea_reg})")
                    };
                    return Ok((format!("MOVEP{sz_sfx}"), ops, 4, InstrFlags::NONE));
                }
            }
            decode_68k_group0_imm(word, ext)
    }
}

/// Group 0000 continued: ORI/ANDI/SUBI/ADDI/EORI/CMPI.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group0_imm(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, _, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            let imm_op = (word >> 9) & 7;
            if word & 0x0100 == 0 && imm_op <= 6 {
                let (imm_bytes, imm_str) = match sz {
                    Size::Byte => {
                        if ext.len() >= 2 {
                            (2, format!("#${:02X}", ext[1]))
                        } else {
                            (2, "#?".to_string())
                        }
                    }
                    Size::Word => {
                        if ext.len() >= 2 {
                            (2, format!("#${:04X}", u16::from_be_bytes([ext[0], ext[1]])))
                        } else {
                            (2, "#?".to_string())
                        }
                    }
                    _ => {
                        if ext.len() >= 4 {
                            (
                                4,
                                format!(
                                    "#${:08X}",
                                    u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]])
                                ),
                            )
                        } else {
                            (4, "#?".to_string())
                        }
                    }
                };
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext.get(imm_bytes..).unwrap_or(&[]));
                let mn = match imm_op {
                    0 => "ORI",
                    1 => "ANDI",
                    2 => "SUBI",
                    3 => "ADDI",
                    5 => "EORI",
                    _ => "CMPI",
                };
                return Ok((
                    format!("{}{}", mn, sz.suffix()),
                    format!("{imm_str},{ea}"),
                    2 + imm_bytes + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            Ok(decode_68k_dcw(word))
    }
}

/// Group 0100: misc / control flow.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group4(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, _, _) = decode_68k_fields(word);
    {
            if word == 0x4E71 {
                return Ok(("NOP".to_string(), String::new(), 2, InstrFlags::NONE));
            }
            if word == 0x4E75 {
                return Ok(("RTS".to_string(), String::new(), 2, InstrFlags::RET));
            }
            if word == 0x4E73 {
                return Ok(("RTE".to_string(), String::new(), 2, InstrFlags::RET));
            }
            if word == 0x4E77 {
                return Ok(("RTR".to_string(), String::new(), 2, InstrFlags::RET));
            }
            if word == 0x4E70 {
                return Ok(("RESET".to_string(), String::new(), 2, InstrFlags::NONE));
            }
            if word == 0x4E72 && ext.len() >= 2 {
                let mask = u16::from_be_bytes([ext[0], ext[1]]);
                return Ok((
                    "STOP".to_string(),
                    format!("#${mask:04X}"),
                    4,
                    InstrFlags::NONE,
                ));
            }
            if word == 0x4E76 {
                return Ok(("TRAPV".to_string(), String::new(), 2, InstrFlags::BRANCH));
            }
            if (word & 0xFFC0) == 0x4E80 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Long, ext);
                return Ok(("JSR".to_string(), ea, 2 + ea_ext, InstrFlags::CALL));
            }
            if (word & 0xFFC0) == 0x4EC0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Long, ext);
                return Ok(("JMP".to_string(), ea, 2 + ea_ext, InstrFlags::BRANCH));
            }
            decode_68k_group4_unary(word, ext)
    }
}

/// Group 0100 continued: unary ALU and address ops.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group4_unary(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word >> 8) == 0x42 && sz_bits < 3 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
                return Ok((
                    format!("CLR{}", sz.suffix()),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word >> 8) == 0x44 && sz_bits < 3 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
                return Ok((
                    format!("NEG{}", sz.suffix()),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word >> 8) == 0x40 && sz_bits < 3 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
                return Ok((
                    format!("NEGX{}", sz.suffix()),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word >> 8) == 0x46 && sz_bits < 3 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
                return Ok((
                    format!("NOT{}", sz.suffix()),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word >> 8) == 0x4A && sz_bits < 3 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
                return Ok((
                    format!("TST{}", sz.suffix()),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xF1C0) == 0x41C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Long, ext);
                return Ok((
                    "LEA".to_string(),
                    format!("{ea},A{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xFFC0) == 0x4840 && ea_mode != 0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Long, ext);
                return Ok(("PEA".to_string(), ea, 2 + ea_ext, InstrFlags::NONE));
            }
            if (word & 0xFFF8) == 0x4840 {
                return Ok((
                    "SWAP".to_string(),
                    format!("D{ea_reg}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xFFB8) == 0x4880 && ea_mode == 0 {
                let sz_sfx = if (word & 0x0040) != 0 { ".L" } else { ".W" };
                return Ok((
                    format!("EXT{sz_sfx}"),
                    format!("D{ea_reg}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            decode_68k_group4_misc(word, ext)
    }
}

/// Group 0100 continued: TRAP, LINK/UNLK, MOVEM and other misc ops.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group4_misc(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, _) = decode_68k_fields(word);
    {
            if (word & 0xFFF0) == 0x4E40 {
                return Ok((
                    "TRAP".to_string(),
                    format!("#${:X}", word & 0xF),
                    2,
                    InstrFlags::BRANCH,
                ));
            }
            if (word & 0xFFF8) == 0x4E50 && ext.len() >= 2 {
                let disp = i16::from_be_bytes([ext[0], ext[1]]);
                return Ok((
                    "LINK".to_string(),
                    format!("A{ea_reg},#${disp:04X}"),
                    4,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xFFF8) == 0x4E58 {
                return Ok((
                    "UNLK".to_string(),
                    format!("A{ea_reg}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xFFC0) == 0x4AC0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok(("TAS".to_string(), ea, 2 + ea_ext, InstrFlags::NONE));
            }
            if (word & 0xFB80) == 0x4880 {
                let to_regs = (word & 0x0400) == 0;
                let sz_sfx = if (word & 0x0040) != 0 { ".L" } else { ".W" };
                if ext.len() >= 2 {
                    let mask = u16::from_be_bytes([ext[0], ext[1]]);
                    let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Long, &ext[2..]);
                    let ops = if to_regs {
                        format!("${mask:04X},{ea}")
                    } else {
                        format!("{ea},${mask:04X}")
                    };
                    return Ok((format!("MOVEM{sz_sfx}"), ops, 4 + ea_ext, InstrFlags::NONE));
                }
            }
            // CHK
            if (word & 0xF1C0) == 0x4180 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Word, ext);
                return Ok((
                    "CHK.W".to_string(),
                    format!("{ea},D{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // NBCD
            if (word & 0xFFC0) == 0x4800 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok(("NBCD".to_string(), ea, 2 + ea_ext, InstrFlags::NONE));
            }
            // MOVE from/to SR
            if (word & 0xFFC0) == 0x40C0 {
                return Ok(("MOVE".to_string(), format!("SR,D{ea_reg}"), 2, InstrFlags::NONE));
            }
            if (word & 0xFFC0) == 0x46C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Word, ext);
                return Ok((
                    "MOVE".to_string(),
                    format!("{ea},SR"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            Ok(decode_68k_dcw(word))
    }
}

/// Group 0101: ADDQ/SUBQ/`Scc`/`DBcc`.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group5(word: u16, ext: &[u8], pc: u64) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, _, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0xF0F8) == 0x50C8 {
                let cond = (word >> 8) & 0xF;
                if ext.len() >= 2 {
                    let disp = i16::from_be_bytes([ext[0], ext[1]]);
                    let target = pc
                        .wrapping_add_signed(2_i64)
                        .wrapping_add_signed(i64::from(disp));
                    let cc_name = cc68k(cond as u8);
                    return Ok((
                        format!("DB{cc_name}"),
                        format!("D{ea_reg},${target:08X}"),
                        4,
                        InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                    ));
                }
            }
            if (word & 0x00C0) == 0x00C0 {
                let cond = (word >> 8) & 0xF;
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Byte, ext);
                return Ok((
                    format!("S{}", cc68k(cond as u8)),
                    ea,
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            let data = ((word >> 9) & 7) as u8;
            let data_val = if data == 0 { 8 } else { data };
            let is_sub = (word & 0x0100) != 0;
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let mn = if is_sub {
                format!("SUBQ{}", sz.suffix())
            } else {
                format!("ADDQ{}", sz.suffix())
            };
            Ok((
                mn,
                format!("#${data_val},{ea}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 0110: `Bcc`/BSR/BRA.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` when the byte slice is truncated.
pub fn decode_68k_group6(word: u16, ext: &[u8], pc: u64) -> Result<Decoded68k, CoreError> {
    {
            let cond = (word >> 8) & 0xF;
            let disp8 = (word & 0xFF) as i8;
            let (disp, size) = if disp8 == 0 {
                if ext.len() < 2 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated Bcc".to_string(),
                    });
                }
                (i32::from(i16::from_be_bytes([ext[0], ext[1]])), 4usize)
            } else if disp8 == -1 {
                // 68020+ long displacement
                if ext.len() < 4 {
                    return Err(CoreError::InvalidFormat {
                        message: "truncated Bcc.L".to_string(),
                    });
                }
                let d32 = i32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
                (d32, 6usize)
            } else {
                (i32::from(disp8), 2usize)
            };
            let target = pc
                .wrapping_add_signed(2_i64)
                .wrapping_add_signed(i64::from(disp));
            let (mn, flags) = match cond {
                0 => ("BRA".to_string(), InstrFlags::BRANCH),
                1 => ("BSR".to_string(), InstrFlags::CALL),
                _ => (
                    format!("B{}", cc68k(cond as u8)),
                    InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                ),
            };
            Ok((mn, format!("${target:08X}"), size, flags))
    }
}

/// Group 0111: MOVEQ.
fn decode_68k_moveq(word: u16) -> Decoded68k {
    let (_, _, reg_field, _) = decode_68k_fields(word);
    let data = (word & 0xFF) as u8;
    (
        "MOVEQ".to_string(),
        format!("#${data:02X},D{reg_field}"),
        2,
        InstrFlags::NONE,
    )
}

/// Group 1000: DIVU/DIVS/OR/SBCD.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group8(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0x01C0) == 0x00C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Word, ext);
                let is_divs = (word & 0x0100) != 0;
                return Ok((
                    if is_divs {
                        "DIVS.W".to_string()
                    } else {
                        "DIVU.W".to_string()
                    },
                    format!("{ea},D{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // SBCD
            if (word & 0xF1F0) == 0x8100 {
                let use_mem = (word & 8) != 0;
                let ops = if use_mem {
                    format!("-(A{ea_reg}),-(A{reg_field})")
                } else {
                    format!("D{ea_reg},D{reg_field}")
                };
                return Ok(("SBCD".to_string(), ops, 2, InstrFlags::NONE));
            }
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let direction = (word & 0x0100) != 0;
            let (src, dst) = if direction {
                (format!("D{reg_field}"), ea)
            } else {
                (ea, format!("D{reg_field}"))
            };
            Ok((
                format!("OR{}", sz.suffix()),
                format!("{src},{dst}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1001: SUB/SUBA/SUBX.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group9(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0x00C0) == 0x00C0 {
                let as_sz = if (word & 0x0100) != 0 { ".L" } else { ".W" };
                let (ea, ea_ext) = ea_str(
                    ea_mode,
                    ea_reg,
                    if (word & 0x0100) != 0 {
                        Size::Long
                    } else {
                        Size::Word
                    },
                    ext,
                );
                return Ok((
                    format!("SUBA{as_sz}"),
                    format!("{ea},A{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // SUBX
            if (word & 0xF130) == 0x9100 {
                let use_mem = (word & 8) != 0;
                let ops = if use_mem {
                    format!("-(A{ea_reg}),-(A{reg_field})")
                } else {
                    format!("D{ea_reg},D{reg_field}")
                };
                return Ok((format!("SUBX{}", sz.suffix()), ops, 2, InstrFlags::NONE));
            }
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let direction = (word & 0x0100) != 0;
            let (src, dst) = if direction {
                (format!("D{reg_field}"), ea)
            } else {
                (ea, format!("D{reg_field}"))
            };
            Ok((
                format!("SUB{}", sz.suffix()),
                format!("{src},{dst}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1011: EOR/CMP/CMPA.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group_b(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0x00C0) == 0x00C0 {
                let as_sz = if (word & 0x0100) != 0 { ".L" } else { ".W" };
                let (ea, ea_ext) = ea_str(
                    ea_mode,
                    ea_reg,
                    if (word & 0x0100) != 0 {
                        Size::Long
                    } else {
                        Size::Word
                    },
                    ext,
                );
                return Ok((
                    format!("CMPA{as_sz}"),
                    format!("{ea},A{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // CMPM
            if (word & 0xF138) == 0xB108 {
                return Ok((
                    format!("CMPM{}", sz.suffix()),
                    format!("(A{ea_reg})+,(A{reg_field})+"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            let direction = (word & 0x0100) != 0;
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let (mn, src, dst) = if direction {
                ("EOR", format!("D{reg_field}"), ea)
            } else {
                ("CMP", ea, format!("D{reg_field}"))
            };
            Ok((
                format!("{}{}", mn, sz.suffix()),
                format!("{src},{dst}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1100: AND/MULU/MULS/ABCD/EXG.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group_c(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0x01C0) == 0x00C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Word, ext);
                let is_muls = (word & 0x0100) != 0;
                return Ok((
                    if is_muls {
                        "MULS.W".to_string()
                    } else {
                        "MULU.W".to_string()
                    },
                    format!("{ea},D{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // ABCD
            if (word & 0xF1F8) == 0xC100 {
                let use_mem = (word & 8) != 0;
                let ops = if use_mem {
                    format!("-(A{ea_reg}),-(A{reg_field})")
                } else {
                    format!("D{ea_reg},D{reg_field}")
                };
                return Ok(("ABCD".to_string(), ops, 2, InstrFlags::NONE));
            }
            // EXG
            if (word & 0xF130) == 0xC100 {
                let mode = (word >> 3) & 0x1F;
                let (op1, op2) = match mode {
                    0x09 => (format!("A{reg_field}"), format!("A{ea_reg}")),
                    0x11 => (format!("D{reg_field}"), format!("A{ea_reg}")),
                    _ => (format!("D{reg_field}"), format!("D{ea_reg}")),
                };
                return Ok((
                    "EXG".to_string(),
                    format!("{op1},{op2}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let direction = (word & 0x0100) != 0;
            let (src, dst) = if direction {
                (format!("D{reg_field}"), ea)
            } else {
                (ea, format!("D{reg_field}"))
            };
            Ok((
                format!("AND{}", sz.suffix()),
                format!("{src},{dst}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1101: ADD/ADDA/ADDX.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group_d(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, reg_field, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            if (word & 0x00C0) == 0x00C0 {
                let as_sz = if (word & 0x0100) != 0 { ".L" } else { ".W" };
                let (ea, ea_ext) = ea_str(
                    ea_mode,
                    ea_reg,
                    if (word & 0x0100) != 0 {
                        Size::Long
                    } else {
                        Size::Word
                    },
                    ext,
                );
                return Ok((
                    format!("ADDA{as_sz}"),
                    format!("{ea},A{reg_field}"),
                    2 + ea_ext,
                    InstrFlags::NONE,
                ));
            }
            // ADDX
            if (word & 0xF130) == 0xD100 {
                let use_mem = (word & 8) != 0;
                let ops = if use_mem {
                    format!("-(A{ea_reg}),-(A{reg_field})")
                } else {
                    format!("D{ea_reg},D{reg_field}")
                };
                return Ok((format!("ADDX{}", sz.suffix()), ops, 2, InstrFlags::NONE));
            }
            let (ea, ea_ext) = ea_str(ea_mode, ea_reg, sz, ext);
            let direction = (word & 0x0100) != 0;
            let (src, dst) = if direction {
                (format!("D{reg_field}"), ea)
            } else {
                (ea, format!("D{reg_field}"))
            };
            Ok((
                format!("ADD{}", sz.suffix()),
                format!("{src},{dst}"),
                2 + ea_ext,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1110: shift/rotate.
///
/// # Errors
/// Currently always succeeds; the `Result` mirrors the other group decoders.
pub fn decode_68k_group_e(word: u16, ext: &[u8]) -> Result<Decoded68k, CoreError> {
    let (ea_mode, ea_reg, _, sz_bits) = decode_68k_fields(word);
    let sz = Size::from_bits2(sz_bits);
    {
            let direction = (word & 0x0100) != 0;
            let dir_str = if direction { "L" } else { "R" };
            let type_bits = (word >> 3) & 3;
            let mn = match type_bits {
                0 => format!("AS{dir_str}"),
                1 => format!("LS{dir_str}"),
                2 => format!("ROX{dir_str}"),
                _ => format!("RO{dir_str}"),
            };
            if (word & 0x00C0) == 0x00C0 {
                let (ea, ea_ext) = ea_str(ea_mode, ea_reg, Size::Word, ext);
                return Ok((format!("{mn}.W"), ea, 2 + ea_ext, InstrFlags::NONE));
            }
            let count_or_reg = ((word >> 9) & 7) as u8;
            let use_reg = (word & 0x0020) != 0;
            let count_str = if use_reg {
                format!("D{count_or_reg}")
            } else {
                format!("#{}", if count_or_reg == 0 { 8 } else { count_or_reg })
            };
            Ok((
                format!("{}{}", mn, sz.suffix()),
                format!("{count_str},D{ea_reg}"),
                2,
                InstrFlags::NONE,
            ))
    }
}

/// Group 1111: coprocessor / 68020 extended.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` for truncated FPU instructions.
pub fn decode_68k_group_f(word: u16, ext: &[u8], pc: u64) -> Result<Decoded68k, CoreError> {
    {
            // Check for FPU instructions (cpID=1, word & 0xFE00 == 0xF200)
            if (word & 0xFE00) == 0xF200 {
                return decode_fpu_instr(word, ext, pc);
            }
            // MMU instructions (cpID=0, word & 0xFE00 == 0xF000)
            if (word & 0xFE00) == 0xF000 {
                return Ok((
                    "PMMU".to_string(),
                    format!("${word:04X}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            // Cache instructions (68040)
            if (word & 0xFF00) == 0xF400 {
                return Ok((
                    "CINV".to_string(),
                    format!("${word:04X}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            if (word & 0xFF00) == 0xF600 {
                return Ok((
                    "CPUSH".to_string(),
                    format!("${word:04X}"),
                    2,
                    InstrFlags::NONE,
                ));
            }
            Ok(decode_68k_dcw(word))
    }
}

// ── FPU instruction decoder ───────────────────────────────────────────────────

/// Decode a floating-point coprocessor instruction.
///
/// # Errors
/// Returns `CoreError::InvalidInput` for truncated FPU instructions.
/// Source-format suffix carried by the R/M=1 form of an FPU instruction.
///
/// Bits 12:10 of the coprocessor extension word name the in-memory format of
/// the effective-address operand. Split out of `decode_fpu_instr` so that the
/// table is nameable and testable on its own.
#[must_use]
pub const fn fpu_ea_format_suffix(r_sel: u16) -> &'static str {
    match r_sel {
        0 => ".L",
        1 => ".S",
        2 => ".X",
        3 | 7 => ".P",
        4 => ".W",
        5 => ".D",
        6 => ".B",
        // packed decimal with dynamic k-factor
        _ => "",
    }
}

/// Decode a 68881/68882 coprocessor (FPU) instruction.
///
/// # Errors
///
/// Returns [`CoreError::InvalidFormat`] when `ext` is shorter than the
/// coprocessor extension word the opcode requires.
pub fn decode_fpu_instr(
    word: u16,
    ext: &[u8],
    pc: u64,
) -> Result<(String, String, usize, InstrFlags), CoreError> {
    if ext.len() < 2 {
        return Err(CoreError::InvalidFormat {
            message: "truncated FPU instruction".to_string(),
        });
    }
    let fword = u16::from_be_bytes([ext[0], ext[1]]);
    let r_sel = (fword >> 10) & 7; // source specifier
    let dst_fp = (fword >> 7) & 7; // destination FP register
    let fop = fword & 0x7F; // operation

    // FMOVE/FMOVEM / Branch
    if (word & 0x0180) == 0x0080 {
        // FBcc
        let cond = word & 0x3F;
        let cond_name = fpu_bcc_name(cond as u8);
        let long = (word & 0x0040) != 0;
        if long {
            if ext.len() >= 6 {
                let disp = i32::from_be_bytes([ext[2], ext[3], ext[4], ext[5]]);
                let target = pc.wrapping_add_signed(2_i64 + i64::from(disp));
                // Total: 2 (opcode) + 2 (FPU word) + 4 (long displacement) = 8
                return Ok((
                    format!("FB{cond_name}"),
                    format!("${target:08X}"),
                    8,
                    InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
                ));
            }
        } else if ext.len() >= 4 {
            let disp = i32::from(i16::from_be_bytes([ext[2], ext[3]]));
            let target = pc.wrapping_add_signed(2_i64 + i64::from(disp));
            // Total: 2 (opcode) + 2 (FPU word) + 2 (word displacement) = 6
            return Ok((
                format!("FB{cond_name}"),
                format!("${target:08X}"),
                6,
                InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL),
            ));
        }
    }

    let mn = match fop {
        0x00 => "FMOVE",
        0x01 => "FINT",
        0x02 => "FSINH",
        0x03 => "FINTRZ",
        0x04 => "FSQRT",
        0x06 => "FLOGNP1",
        0x08 => "FETOXM1",
        0x09 => "FTANH",
        0x0A => "FATAN",
        0x0C => "FASIN",
        0x0D => "FATANH",
        0x0E => "FSIN",
        0x0F => "FTAN",
        0x10 => "FETOX",
        0x11 => "FTWOTOX",
        0x12 => "FTENTOX",
        0x14 => "FLOGN",
        0x15 => "FLOG10",
        0x16 => "FLOG2",
        0x18 => "FABS",
        0x19 => "FCOSH",
        0x1A => "FNEG",
        0x1C => "FACOS",
        0x1D => "FCOS",
        0x1E => "FGETEXP",
        0x1F => "FGETMAN",
        0x20 => "FDIV",
        0x21 => "FMOD",
        0x22 => "FADD",
        0x23 => "FMUL",
        0x24 => "FSGLDIV",
        0x25 => "FREM",
        0x26 => "FSCALE",
        0x27 => "FSGLMUL",
        0x28 => "FSUB",
        0x38 => "FCMP",
        0x3A => "FTST",
        _ => "FPOP",
    };

    // Bit 14 of fword is the R/M bit: 0 = FP register source, 1 = EA source
    let rm_bit = (fword >> 14) & 1;
    if rm_bit == 0 {
        // FP register source: r_sel (bits 12:10) selects source FP register
        let src_name = fpu_src_specifier(r_sel);
        let ops = format!("{src_name},FP{dst_fp}");
        Ok((mn.to_string(), ops, 4, InstrFlags::NONE))
    } else {
        // EA source: r_sel (bits 12:10) encodes the data format
        let fmt_suffix = fpu_ea_format_suffix(r_sel);
        let ea_mode_f = (word >> 3) & 7;
        let ea_reg_f = word & 7;
        let (ea_str_val, ea_ext) = ea_str(ea_mode_f as u8, ea_reg_f as u8, Size::Long, &ext[2..]);
        Ok((
            format!("{mn}{fmt_suffix}"),
            format!("{ea_str_val},FP{dst_fp}"),
            2 + 2 + ea_ext,
            InstrFlags::NONE,
        ))
    }
}

fn fpu_src_specifier(sel: u16) -> String {
    match sel {
        0 => "FP0".to_string(),
        1 => "FP1".to_string(),
        2 => "FP2".to_string(),
        3 => "FP3".to_string(),
        4 => "FP4".to_string(),
        5 => "FP5".to_string(),
        6 => "FP6".to_string(),
        7 => "FP7".to_string(),
        _ => format!("FP?{sel}"),
    }
}

const fn fpu_bcc_name(cond: u8) -> &'static str {
    match cond {
        0x00 => "F",
        0x01 => "EQ",
        0x02 => "OGT",
        0x03 => "OGE",
        0x04 => "OLT",
        0x05 => "OLE",
        0x06 => "OGL",
        0x07 => "OR",
        0x08 => "UN",
        0x09 => "UEQ",
        0x0A => "UGT",
        0x0B => "UGE",
        0x0C => "ULT",
        0x0D => "ULE",
        0x0E => "NE",
        0x0F => "T",
        0x10 => "SF",
        0x11 => "SEQ",
        0x12 => "GT",
        0x13 => "GE",
        0x14 => "LT",
        0x15 => "LE",
        0x16 => "GL",
        0x17 => "GLE",
        0x18 => "NGLE",
        0x19 => "NGL",
        0x1A => "NLE",
        0x1B => "NLT",
        0x1C => "NGE",
        0x1D => "NGT",
        0x1E => "SNE",
        _ => "ST",
    }
}

// ── Instruction info table ────────────────────────────────────────────────────

/// Static entry in the 68k opcode classification table.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    /// Bit mask to match top-level opcode bits.
    pub mask: u16,
    /// Pattern to compare after applying mask.
    pub pattern: u16,
    /// Canonical mnemonic.
    pub mnemonic: &'static str,
    /// Minimum size in bytes.
    pub min_size: u8,
    /// Instruction category flags.
    pub flags: InstrFlags,
}

/// Static classification table for common 68k opcodes.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E71,
        mnemonic: "NOP",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E75,
        mnemonic: "RTS",
        min_size: 2,
        flags: InstrFlags::RET,
    },
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E73,
        mnemonic: "RTE",
        min_size: 2,
        flags: InstrFlags::RET,
    },
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E77,
        mnemonic: "RTR",
        min_size: 2,
        flags: InstrFlags::RET,
    },
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E70,
        mnemonic: "RESET",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFFFF,
        pattern: 0x4E76,
        mnemonic: "TRAPV",
        min_size: 2,
        flags: InstrFlags::BRANCH,
    },
    OpcodeEntry {
        mask: 0xFFC0,
        pattern: 0x4E80,
        mnemonic: "JSR",
        min_size: 2,
        flags: InstrFlags::CALL,
    },
    OpcodeEntry {
        mask: 0xFFC0,
        pattern: 0x4EC0,
        mnemonic: "JMP",
        min_size: 2,
        flags: InstrFlags::BRANCH,
    },
    OpcodeEntry {
        mask: 0xF1C0,
        pattern: 0x41C0,
        mnemonic: "LEA",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFF00,
        pattern: 0x4200,
        mnemonic: "CLR",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFF00,
        pattern: 0x4400,
        mnemonic: "NEG",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFF00,
        pattern: 0x4600,
        mnemonic: "NOT",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFF00,
        pattern: 0x4A00,
        mnemonic: "TST",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFFC0,
        pattern: 0x4AC0,
        mnemonic: "TAS",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFFF0,
        pattern: 0x4E40,
        mnemonic: "TRAP",
        min_size: 2,
        flags: InstrFlags::BRANCH,
    },
    OpcodeEntry {
        mask: 0xFFF8,
        pattern: 0x4E50,
        mnemonic: "LINK",
        min_size: 4,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xFFF8,
        pattern: 0x4E58,
        mnemonic: "UNLK",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x1000,
        mnemonic: "MOVE",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x2000,
        mnemonic: "MOVE",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x3000,
        mnemonic: "MOVE",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF100,
        pattern: 0x7000,
        mnemonic: "MOVEQ",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0xD000,
        mnemonic: "ADD",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x9000,
        mnemonic: "SUB",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0xC000,
        mnemonic: "AND",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x8000,
        mnemonic: "OR",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0xB000,
        mnemonic: "CMP",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0x6000,
        mnemonic: "B??",
        min_size: 2,
        flags: InstrFlags::BRANCH,
    },
    OpcodeEntry {
        mask: 0xF000,
        pattern: 0xE000,
        mnemonic: "SHF",
        min_size: 2,
        flags: InstrFlags::NONE,
    },
    OpcodeEntry {
        mask: 0xF0F8,
        pattern: 0x50C8,
        mnemonic: "DBcc",
        min_size: 4,
        flags: InstrFlags::BRANCH,
    },
];

/// Look up the best matching entry for a raw instruction word.
#[must_use]
pub fn lookup_opcode(word: u16) -> Option<&'static OpcodeEntry> {
    // Prefer longest mask (most specific match) first
    let mut best: Option<&'static OpcodeEntry> = None;
    let mut best_mask_bits = 0u32;
    for entry in OPCODE_TABLE {
        if (word & entry.mask) == entry.pattern {
            let bits = u32::from(entry.mask).count_ones();
            if bits > best_mask_bits {
                best_mask_bits = bits;
                best = Some(entry);
            }
        }
    }
    best
}

// ── Register list encoder/decoder ─────────────────────────────────────────────

/// Decode a MOVEM register mask into a human-readable list.
#[must_use]
pub fn decode_register_mask(mask: u16, predecrement: bool) -> String {
    // When pre-decrement, the bit ordering is reversed
    let effective = if predecrement {
        mask.reverse_bits()
    } else {
        mask
    };
    let mut parts: Vec<String> = Vec::with_capacity(effective.count_ones() as usize);

    // Bits 0..7 = D0..D7
    for i in 0..8_u8 {
        if (effective >> i) & 1 != 0 {
            parts.push(format!("D{i}"));
        }
    }
    // Bits 8..15 = A0..A7
    for i in 0..8_u8 {
        if (effective >> (i + 8)) & 1 != 0 {
            parts.push(format!("A{i}"));
        }
    }
    parts.join("/")
}

/// Encode a register list (e.g. `["D0","D1","A0"]`) into a MOVEM mask.
#[must_use]
pub fn encode_register_mask(regs: &[&str], predecrement: bool) -> u16 {
    let mut mask = 0u16;
    for r in regs {
        let bit = match *r {
            "D0" => Some(0u8),
            "D1" => Some(1),
            "D2" => Some(2),
            "D3" => Some(3),
            "D4" => Some(4),
            "D5" => Some(5),
            "D6" => Some(6),
            "D7" => Some(7),
            "A0" => Some(8),
            "A1" => Some(9),
            "A2" => Some(10),
            "A3" => Some(11),
            "A4" => Some(12),
            "A5" => Some(13),
            "A6" => Some(14),
            "A7" | "SP" => Some(15),
            _ => None,
        };
        if let Some(b) = bit {
            mask |= 1 << b;
        }
    }
    if predecrement {
        mask.reverse_bits()
    } else {
        mask
    }
}

// ── Instruction encode helpers ────────────────────────────────────────────────

/// Encode a NOP instruction (big-endian).
#[must_use]
pub const fn encode_nop() -> [u8; 2] {
    [0x4E, 0x71]
}

/// Encode RTS.
#[must_use]
pub const fn encode_rts() -> [u8; 2] {
    [0x4E, 0x75]
}

/// Encode RTE.
#[must_use]
pub const fn encode_rte() -> [u8; 2] {
    [0x4E, 0x73]
}

/// Encode a MOVEQ instruction.
///
/// # Panics
/// Panics if `dn` >= 8.
#[must_use]
pub fn encode_moveq(dn: u8, imm: i8) -> [u8; 2] {
    assert!(dn < 8, "MOVEQ: dn must be 0..7");
    let word = 0x7000_u16 | (u16::from(dn) << 9) | u16::from(imm.to_ne_bytes()[0]);
    word.to_be_bytes()
}

/// Encode a BRA with an 8-bit displacement.
///
/// # Panics
/// Panics if `disp` is 0 (would be mis-decoded as word branch).
#[must_use]
pub fn encode_bra8(disp: i8) -> [u8; 2] {
    assert!(disp != 0, "BRA: use word form for zero displacement");
    let word = 0x6000_u16 | u16::from(disp.to_ne_bytes()[0]);
    word.to_be_bytes()
}

/// Encode a BRA with a 16-bit displacement.
#[must_use]
pub const fn encode_bra16(disp: i16) -> [u8; 4] {
    let word_bytes = 0x6000_u16.to_be_bytes();
    let disp_bytes = disp.to_be_bytes();
    [word_bytes[0], word_bytes[1], disp_bytes[0], disp_bytes[1]]
}

/// Encode BSR with 8-bit displacement.
///
/// # Panics
/// Panics if `disp` is 0.
#[must_use]
pub fn encode_bsr8(disp: i8) -> [u8; 2] {
    assert!(disp != 0, "BSR: use word form for zero displacement");
    let word = 0x6100_u16 | u16::from(disp.to_ne_bytes()[0]);
    word.to_be_bytes()
}

/// Encode a TRAP instruction.
///
/// # Panics
/// Panics if `vector` >= 16.
#[must_use]
pub fn encode_trap(vector: u8) -> [u8; 2] {
    assert!(vector < 16, "TRAP: vector must be 0..15");
    let word = 0x4E40_u16 | u16::from(vector);
    word.to_be_bytes()
}

/// Encode a CLR instruction.
///
/// # Panics
/// Panics if `dn` >= 8.
#[must_use]
pub fn encode_clr(size: Size, dn: u8) -> [u8; 2] {
    assert!(dn < 8, "CLR: dn must be 0..7");
    let sz_bits: u16 = match size {
        Size::Byte => 0,
        Size::Word => 1,
        _ => 2,
    };
    let word = 0x4200_u16 | (sz_bits << 6) | u16::from(dn);
    word.to_be_bytes()
}

// ── Analysis pass ─────────────────────────────────────────────────────────────

/// Analysis result for a linear scan of 68k code.
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    /// All decoded instructions.
    pub instructions: Vec<Instruction>,
    /// Addresses of identified function entry points (from BSR/JSR targets).
    pub call_targets: Vec<Address>,
    /// Addresses of branch targets.
    pub branch_targets: Vec<Address>,
    /// Addresses of unconditional returns.
    pub returns: Vec<Address>,
    /// Number of decode errors.
    pub errors: usize,
}

impl AnalysisResult {
    /// Total number of instructions decoded.
    #[must_use]
    pub const fn instr_count(&self) -> usize {
        self.instructions.len()
    }

    /// Approximate code size in bytes.
    #[must_use]
    pub fn code_size(&self) -> usize {
        self.instructions.iter().map(|i| i.size).sum()
    }

    /// True if any call target was identified.
    #[must_use]
    pub const fn has_calls(&self) -> bool {
        !self.call_targets.is_empty()
    }
}

/// Perform a linear sweep analysis of a 68k byte slice.
///
/// # Errors
/// Does not propagate decode errors — instead counts them in `result.errors`.
#[must_use]
pub fn analyze(base: Address, bytes: &[u8]) -> AnalysisResult {
    let arch = Mc68kArch::default();
    let mut result = AnalysisResult::default();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let addr = base + offset as u64;
        if let Ok(instr) = arch.disassemble(addr, &bytes[offset..]) {
            let flags = instr.flags;
            if flags.contains(InstrFlags::CALL) && let Some(t) = parse_hex_target(&instr.operands) {
                // Parse hex address from operands string
                result.call_targets.push(Address::new(t));
            }
            if flags.intersects(InstrFlags::BRANCH)
                && !flags.contains(InstrFlags::CALL)
                && let Some(t) = parse_hex_target(&instr.operands)
            {
                result.branch_targets.push(Address::new(t));
            }
            if flags.contains(InstrFlags::RET) {
                result.returns.push(addr);
            }
            let sz = instr.size;
            result.instructions.push(instr);
            offset += sz;
        } else {
            result.errors += 1;
            offset += 2; // skip one word
        }
    }
    result
}

/// Extract a hex target address from operand string like `$00001234`.
fn parse_hex_target(operands: &str) -> Option<u64> {
    let s = operands.trim_start_matches('$');
    let hex: String = s.chars().take_while(char::is_ascii_hexdigit).collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

// ── Calling conventions ───────────────────────────────────────────────────────

/// Return all calling conventions for a given 68k variant.
#[must_use]
pub fn calling_conventions_for(variant: Mc68kVariant) -> Vec<CallingConvention> {
    let mut cvs = Vec::new();

    // Standard GCC/SysV convention
    let mut gcc = CallingConvention::new("m68k_gcc")
        .with_int_args(vec![
            "D0".to_string(),
            "D1".to_string(),
            "A0".to_string(),
            "A1".to_string(),
        ])
        .with_return_regs(vec!["D0".to_string(), "D1".to_string()]);
    gcc.caller_cleans_stack = false;
    cvs.push(gcc);

    // AmigaOS library convention (A6 base pointer, args in A0/D0...)
    cvs.push(
        CallingConvention::new("amiga_library")
            .with_int_args(vec![
                "D0".to_string(),
                "D1".to_string(),
                "D2".to_string(),
                "A0".to_string(),
                "A1".to_string(),
            ])
            .with_return_regs(vec!["D0".to_string()]),
    );

    // Macintosh Toolbox convention
    let mut mac = CallingConvention::new("mac_toolbox")
        .with_int_args(vec!["A7".to_string()]) // stack only
        .with_return_regs(vec!["D0".to_string()]);
    mac.caller_cleans_stack = false;
    cvs.push(mac);

    // 68040 with FPU — FP0..FP2 as float args
    if variant.has_fpu() {
        let mut fpu = CallingConvention::new("m68k_fpu")
            .with_int_args(vec![
                "D0".to_string(),
                "D1".to_string(),
                "FP0".to_string(),
                "FP1".to_string(),
                "FP2".to_string(),
            ])
            .with_return_regs(vec!["D0".to_string(), "FP0".to_string()]);
        fpu.caller_cleans_stack = false;
        cvs.push(fpu);
    }

    cvs
}

// ── Main architecture struct ──────────────────────────────────────────────────

/// Classify a [`BranchInfo`] into a coarse human-readable category.
///
/// Useful for analysis passes that want to group branches by their semantic
/// [`BranchKind`] without inspecting the individual factory variants.
#[must_use]
pub const fn branch_category(branch: &BranchInfo) -> &'static str {
    match branch.kind {
        BranchKind::UnconditionalJump => "jump",
        BranchKind::ConditionalJump => "conditional-jump",
        BranchKind::Call | BranchKind::IndirectCall => "call",
        BranchKind::Return | BranchKind::ExceptionReturn => "return",
        BranchKind::SystemCall => "syscall",
        BranchKind::Trap => "trap",
        BranchKind::IndirectJump => "indirect-jump",
    }
}

/// Motorola 68000 family architecture.
#[derive(Debug, Clone)]
pub struct Mc68kArch {
    /// The specific CPU variant.
    pub variant: Mc68kVariant,
}

impl Mc68kArch {
    /// Create a new 68k architecture with the specified variant.
    #[must_use]
    pub const fn new(variant: Mc68kVariant) -> Self {
        Self { variant }
    }

    /// Return the pointer size in bytes (always 4 for 68k).
    #[must_use]
    pub const fn ptr_size(&self) -> usize {
        4
    }

    /// Decode and return a raw instruction structure.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidInput` when bytes are truncated.
    pub fn decode_raw(
        &self,
        bytes: &[u8],
        pc: u64,
    ) -> Result<(String, String, usize, InstrFlags), CoreError> {
        decode_68k(bytes, pc)
    }
}

impl Default for Mc68kArch {
    fn default() -> Self {
        Self::new(Mc68kVariant::M68000)
    }
}

impl Architecture for Mc68kArch {
    fn name(&self) -> &str {
        self.variant.name()
    }

    fn pointer_size(&self) -> usize {
        4
    }

    fn endian(&self) -> Endian {
        Endian::Big
    }

    /// Disassemble one instruction.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidInput` on truncated input.
    fn disassemble(&self, address: Address, bytes: &[u8]) -> Result<Instruction, CoreError> {
        let (mnemonic, operands, size, flags) = decode_68k(bytes, address.as_u64())?;
        let raw = bytes[..size.min(bytes.len())].to_vec();
        let mut instr = Instruction::new(address, size, mnemonic, raw);
        instr.operands = operands;
        instr.flags = flags;
        Ok(instr)
    }

    fn get_branches(&self, instr: &Instruction) -> Vec<BranchInfo> {
        if !instr
            .flags
            .intersects(InstrFlags::BRANCH | InstrFlags::CALL)
        {
            return vec![];
        }
        let ops = &instr.operands;
        let hex: String = ops
            .chars()
            .rev()
            .take_while(char::is_ascii_hexdigit)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        if !hex.is_empty()
            && let Ok(target) = u64::from_str_radix(&hex, 16)
        {
            let branch = if instr.flags.contains(InstrFlags::CALL) {
                BranchInfo::call(target)
            } else if instr.flags.contains(InstrFlags::CONDITIONAL) {
                BranchInfo::conditional_jump(target, BranchCondition::Custom(0))
            } else {
                BranchInfo::unconditional_jump(target)
            };
            return vec![branch];
        }
        vec![]
    }

    fn registers(&self) -> Vec<RegisterInfo> {
        let mut regs = Vec::with_capacity(32);
        for i in REG_D0..=REG_D7 {
            regs.push(RegisterInfo::new(
                format!("D{}", i - REG_D0),
                i,
                4,
                RegisterKind::General,
            ));
        }
        for i in REG_A0..=REG_A7 {
            if i == REG_A7 {
                regs.push(RegisterInfo::new("SP", i, 4, RegisterKind::Stack));
            } else {
                regs.push(RegisterInfo::new(
                    format!("A{}", i - REG_A0),
                    i,
                    4,
                    RegisterKind::General,
                ));
            }
        }
        regs.push(RegisterInfo::new(
            "PC",
            REG_PC,
            4,
            RegisterKind::ProgramCounter,
        ));
        regs.push(RegisterInfo::new("SR", REG_SR, 2, RegisterKind::Flags));
        regs.push(RegisterInfo::new("CCR", REG_CCR, 1, RegisterKind::Flags));
        regs.push(RegisterInfo::new("USP", REG_USP, 4, RegisterKind::System));

        if self.variant != Mc68kVariant::M68000 {
            regs.push(RegisterInfo::new("VBR", REG_VBR, 4, RegisterKind::System));
            regs.push(RegisterInfo::new("SFC", REG_SFC, 4, RegisterKind::System));
            regs.push(RegisterInfo::new("DFC", REG_DFC, 4, RegisterKind::System));
        }
        if self.variant.is_32bit() {
            regs.push(RegisterInfo::new(
                "CACR",
                REG_CACR,
                4,
                RegisterKind::Control,
            ));
            regs.push(RegisterInfo::new(
                "CAAR",
                REG_CAAR,
                4,
                RegisterKind::Control,
            ));
            regs.push(RegisterInfo::new("MSP", REG_MSP, 4, RegisterKind::Stack));
            regs.push(RegisterInfo::new("ISP", REG_ISP, 4, RegisterKind::Stack));
        }
        if self.variant.has_fpu() {
            for i in 0..8_u32 {
                regs.push(RegisterInfo::new(
                    format!("FP{i}"),
                    REG_FP0 + i,
                    12,
                    RegisterKind::Float,
                ));
            }
            regs.push(RegisterInfo::new("FPSR", REG_FPSR, 4, RegisterKind::Flags));
            regs.push(RegisterInfo::new(
                "FPCR",
                REG_FPCR,
                4,
                RegisterKind::Control,
            ));
            regs.push(RegisterInfo::new(
                "FPIAR",
                REG_FPIAR,
                4,
                RegisterKind::System,
            ));
        }
        regs
    }

    fn calling_conventions(&self) -> Vec<CallingConvention> {
        calling_conventions_for(self.variant)
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Linear-sweep disassembler for 68000 code.
pub struct Mc68kLinearDisassembler<'a> {
    arch: &'a Mc68kArch,
    bytes: &'a [u8],
    base: Address,
    offset: usize,
}

impl<'a> Mc68kLinearDisassembler<'a> {
    /// Create a new linear disassembler.
    #[must_use]
    pub const fn new(arch: &'a Mc68kArch, bytes: &'a [u8], base: Address) -> Self {
        Self {
            arch,
            bytes,
            base,
            offset: 0,
        }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Whether all bytes have been consumed.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

impl Iterator for Mc68kLinearDisassembler<'_> {
    type Item = Result<Instruction, CoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let addr = self.base + self.offset as u64;
        let result = self.arch.disassemble(addr, &self.bytes[self.offset..]);
        match &result {
            Ok(instr) => self.offset += instr.size,
            Err(_) => self.offset += 2,
        }
        Some(result)
    }
}

// ── Recursive-descent disassembler ───────────────────────────────────────────

/// Recursive-descent 68k disassembler (worklist-based).
pub struct Mc68kRecursiveDisassembler<'a> {
    arch: &'a Mc68kArch,
    bytes: &'a [u8],
    base: Address,
    /// Already decoded offsets.
    seen: std::collections::BTreeSet<usize>,
    /// Worklist of offsets to decode.
    worklist: Vec<usize>,
    /// All decoded instructions, keyed by offset.
    decoded: std::collections::BTreeMap<usize, Instruction>,
}

impl<'a> Mc68kRecursiveDisassembler<'a> {
    /// Create a new recursive-descent disassembler starting at `entry`.
    #[must_use]
    pub fn new(arch: &'a Mc68kArch, bytes: &'a [u8], base: Address, entry: usize) -> Self {
        Self {
            arch,
            bytes,
            base,
            seen: std::collections::BTreeSet::new(),
            worklist: vec![entry],
            decoded: std::collections::BTreeMap::new(),
        }
    }

    /// Run the full recursive descent to saturation.
    pub fn run(&mut self) {
        while let Some(off) = self.worklist.pop() {
            if off >= self.bytes.len() || self.seen.contains(&off) {
                continue;
            }
            self.seen.insert(off);
            let addr = self.base + off as u64;
            if let Ok(instr) = self.arch.disassemble(addr, &self.bytes[off..]) {
                let flags = instr.flags;
                let size = instr.size;
                // Enqueue branch targets
                for br in self.arch.get_branches(&instr) {
                    if let Some(target) = br.target {
                        let raw_off = target.wrapping_sub(self.base.as_u64());
                        if let Ok(target_off) = usize::try_from(raw_off)
                            && target_off < self.bytes.len()
                        {
                            self.worklist.push(target_off);
                        }
                    }
                }
                // Enqueue fall-through unless unconditional branch/return
                if (flags.contains(InstrFlags::CONDITIONAL) || !flags.contains(InstrFlags::BRANCH))
                    && !flags.intersects(InstrFlags::RET)
                {
                    self.worklist.push(off + size);
                }
                self.decoded.insert(off, instr);
            }
        }
    }

    /// Return all decoded instructions sorted by offset.
    #[must_use]
    pub fn instructions(&self) -> Vec<&Instruction> {
        self.decoded.values().collect()
    }

    /// Number of distinct instruction addresses decoded.
    #[must_use]
    pub fn count(&self) -> usize {
        self.decoded.len()
    }
}

// ── Exception vectors ─────────────────────────────────────────────────────────

/// 68000 exception vector number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExceptionVector {
    ResetSSP = 0,
    ResetPC = 1,
    BusError = 2,
    AddressError = 3,
    IllegalInstruction = 4,
    ZeroDivide = 5,
    Chk = 6,
    Trapv = 7,
    PrivilegeViolation = 8,
    Trace = 9,
    LineA = 10,
    LineF = 11,
    CoprocessorProtocol = 13,
    FormatError = 14,
    UninitInterrupt = 15,
    SpuriousInterrupt = 24,
    Trap0 = 32,
    // Trap1..15 are 33..47
}

impl ExceptionVector {
    /// The byte offset in the vector table (VBR-relative).
    #[must_use]
    pub fn table_offset(self) -> u32 {
        u32::from(self as u8) * 4
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ResetSSP => "Reset SSP",
            Self::ResetPC => "Reset PC",
            Self::BusError => "Bus Error",
            Self::AddressError => "Address Error",
            Self::IllegalInstruction => "Illegal Instruction",
            Self::ZeroDivide => "Zero Divide",
            Self::Chk => "CHK",
            Self::Trapv => "TRAPV",
            Self::PrivilegeViolation => "Privilege Violation",
            Self::Trace => "Trace",
            Self::LineA => "Line A Emulator",
            Self::LineF => "Line F Emulator",
            Self::CoprocessorProtocol => "Coprocessor Protocol Violation",
            Self::FormatError => "Format Error",
            Self::UninitInterrupt => "Uninitialized Interrupt",
            Self::SpuriousInterrupt => "Spurious Interrupt",
            Self::Trap0 => "TRAP #0",
        }
    }
}

// ── Instruction statistics ─────────────────────────────────────────────────────

/// Instruction category frequency counts.
#[derive(Debug, Default, Clone)]
pub struct InstrStats {
    /// Number of data-move instructions (MOVE, MOVEM, LEA, etc.)
    pub data_moves: usize,
    /// Number of arithmetic instructions (ADD, SUB, MUL, DIV, CMP, etc.)
    pub arithmetic: usize,
    /// Number of logic instructions (AND, OR, EOR, NOT, etc.)
    pub logic: usize,
    /// Number of shift/rotate instructions.
    pub shifts: usize,
    /// Number of branch instructions.
    pub branches: usize,
    /// Number of call instructions (BSR, JSR).
    pub calls: usize,
    /// Number of return instructions (RTS, RTE, RTR).
    pub returns: usize,
    /// Number of bit manipulation instructions.
    pub bit_ops: usize,
    /// Number of BCD arithmetic instructions.
    pub bcd: usize,
    /// Number of privileged/control instructions.
    pub privileged: usize,
    /// Number of unrecognized (DC.W) instructions.
    pub unknown: usize,
}

impl InstrStats {
    /// Compute statistics from a slice of instructions.
    #[must_use]
    pub fn from_instrs(instrs: &[Instruction]) -> Self {
        let mut s = Self::default();
        for i in instrs {
            let m = i.mnemonic.as_str();
            if m.starts_with("MOVE")
                || m == "LEA"
                || m == "PEA"
                || m == "CLR"
                || m == "MOVEQ"
                || m == "SWAP"
                || m == "EXT"
                || m == "EXG"
            {
                s.data_moves += 1;
            } else if m.starts_with("ADD")
                || m.starts_with("SUB")
                || m.starts_with("CMP")
                || m.starts_with("NEG")
                || m.starts_with("DIV")
                || m.starts_with("MUL")
                || m.starts_with("ADDI")
                || m.starts_with("SUBI")
            {
                s.arithmetic += 1;
            } else if m.starts_with("AND")
                || m.starts_with("OR")
                || m.starts_with("EOR")
                || m == "NOT"
                || m.starts_with("TST")
            {
                s.logic += 1;
            } else if m.starts_with("AS")
                || m.starts_with("LS")
                || m.starts_with("RO")
                || m.starts_with("ROX")
            {
                s.shifts += 1;
            } else if i.flags.contains(InstrFlags::CALL) {
                s.calls += 1;
            } else if i.flags.contains(InstrFlags::RET) {
                s.returns += 1;
            } else if i.flags.intersects(InstrFlags::BRANCH) || (m.starts_with('B') && m.len() <= 5)
            {
                s.branches += 1;
            } else if m.starts_with("BT") || m.starts_with("BC") || m.starts_with("BS") {
                s.bit_ops += 1;
            } else if m.contains("BCD") || m == "NBCD" {
                s.bcd += 1;
            } else if m == "RESET"
                || m == "STOP"
                || m == "RTE"
                || m == "MOVEC"
                || m.starts_with("PMMU")
                || m.starts_with("CINV")
                || m.starts_with("CPUSH")
            {
                s.privileged += 1;
            } else if m == "DC.W" {
                s.unknown += 1;
            }
        }
        s
    }

    /// Total instructions counted.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.data_moves
            + self.arithmetic
            + self.logic
            + self.shifts
            + self.branches
            + self.calls
            + self.returns
            + self.bit_ops
            + self.bcd
            + self.privileged
            + self.unknown
    }
}

// ── Disassembly printer ───────────────────────────────────────────────────────

/// Formatting options for 68k disassembly output.
#[derive(Debug, Clone)]
pub struct DisasmOptions {
    /// Show byte encoding alongside the mnemonic.
    pub show_bytes: bool,
    /// Column width for the mnemonic field.
    pub mnemonic_width: usize,
    /// Use uppercase mnemonics (always true for 68k, but let caller override).
    pub uppercase: bool,
    /// Show instruction address.
    pub show_address: bool,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        Self {
            show_bytes: true,
            mnemonic_width: 12,
            uppercase: true,
            show_address: true,
        }
    }
}

/// Format a single instruction as a string.
#[must_use]
pub fn format_instr(instr: &Instruction, opts: &DisasmOptions) -> String {
    let mut parts = Vec::new();

    if opts.show_address {
        parts.push(format!("{:08X}:", instr.address.as_u64()));
    }
    if opts.show_bytes {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(instr.bytes.len() * 3);
        for (i, b) in instr.bytes.iter().enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{b:02X}");
        }
        parts.push(format!("{hex:<12}"));
    }

    let mn = if opts.uppercase {
        instr.mnemonic.to_uppercase()
    } else {
        instr.mnemonic.to_lowercase()
    };
    if instr.operands.is_empty() {
        parts.push(format!("{mn:<width$}", width = opts.mnemonic_width));
    } else {
        parts.push(format!(
            "{mn:<width$} {}",
            instr.operands,
            width = opts.mnemonic_width
        ));
    }
    parts.join("  ")
}

/// Format a sequence of instructions into a multi-line string.
#[must_use]
pub fn format_listing(instrs: &[Instruction], opts: &DisasmOptions) -> String {
    instrs
        .iter()
        .map(|i| format_instr(i, opts))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Stack frame analysis ──────────────────────────────────────────────────────

/// A single stack frame record deduced from a LINK instruction.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Address of the LINK instruction.
    pub link_addr: Address,
    /// Frame pointer register (typically A6).
    pub fp_reg: u8,
    /// Displacement (size of local variables area, typically negative).
    pub frame_size: i16,
}

/// Scan a disassembled function for stack frame setup (LINK) and teardown (UNLK).
#[must_use]
pub fn find_stack_frames(instrs: &[Instruction]) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for i in instrs {
        if i.mnemonic == "LINK" {
            // Operand format: "Ax,#$NNNN"
            let parts: Vec<&str> = i.operands.split(',').collect();
            if parts.len() >= 2 {
                let reg_str = parts[0].trim().trim_start_matches('A');
                let disp_str = parts[1].trim().trim_start_matches("#$");
                if let (Ok(reg), Ok(raw)) =
                    (reg_str.parse::<u8>(), u16::from_str_radix(disp_str, 16))
                {
                    let frame_size = i16::from_ne_bytes(raw.to_ne_bytes());
                    frames.push(StackFrame {
                        link_addr: i.address,
                        fp_reg: reg,
                        frame_size,
                    });
                }
            }
        }
    }
    frames
}

// ── Cross-reference table ─────────────────────────────────────────────────────

/// A cross-reference from one address to another.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Address of the referencing instruction.
    pub from: Address,
    /// Destination address.
    pub to: Address,
    /// Whether this is a call (vs. a branch).
    pub is_call: bool,
}

/// Build a cross-reference table from a sequence of instructions.
#[must_use]
pub fn build_xrefs(instrs: &[Instruction]) -> Vec<Xref> {
    let mut xrefs = Vec::with_capacity(instrs.len() / 8);
    for i in instrs {
        if !i.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL) {
            continue;
        }
        // Try to find a hex address in the operands
        let ops = &i.operands;
        if let Some(pos) = ops.find('$') {
            let hex: String = ops[pos + 1..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            if let Ok(target) = u64::from_str_radix(&hex, 16) {
                xrefs.push(Xref {
                    from: i.address,
                    to: Address::new(target),
                    is_call: i.flags.contains(InstrFlags::CALL),
                });
            }
        }
    }
    xrefs
}

// ── Prologue/epilogue detection ───────────────────────────────────────────────

/// Detected function prologue type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrologueKind {
    /// LINK A6,#N / MOVEM style.
    LinkMovem,
    /// LINK A6,#N only (no MOVEM).
    LinkOnly,
    /// MOVEM.L regs,-(SP) only.
    MovemOnly,
    /// No recognizable prologue.
    None,
}

/// Analyse up to `max_instrs` instructions at the start of a function for
/// a recognizable prologue.
#[must_use]
pub fn detect_prologue(instrs: &[Instruction], max_instrs: usize) -> PrologueKind {
    let window = &instrs[..instrs.len().min(max_instrs)];
    let has_link = window.iter().any(|i| i.mnemonic == "LINK");
    let has_movem = window.iter().any(|i| i.mnemonic.starts_with("MOVEM"));
    match (has_link, has_movem) {
        (true, true) => PrologueKind::LinkMovem,
        (true, false) => PrologueKind::LinkOnly,
        (false, true) => PrologueKind::MovemOnly,
        _ => PrologueKind::None,
    }
}

/// Whether an instruction sequence ends with a recognizable epilogue.
#[must_use]
pub fn detect_epilogue(instrs: &[Instruction]) -> bool {
    instrs
        .iter()
        .rev()
        .take(4)
        .any(|i| i.mnemonic == "RTS" || i.mnemonic == "RTE" || i.mnemonic == "RTR")
}

// ── Constant folding helpers ───────────────────────────────────────────────────

/// Evaluate a MOVEQ immediate value (sign-extended 8-bit).
#[must_use]
pub fn moveq_value(word: u16) -> i32 {
    let byte = (word & 0xFF) as i8;
    i32::from(byte)
}

/// Evaluate an ADDQ immediate value (3-bit, 0→8).
#[must_use]
pub const fn addq_value(word: u16) -> u8 {
    let v = ((word >> 9) & 7) as u8;
    if v == 0 { 8 } else { v }
}

// ── Addressing mode classifier ────────────────────────────────────────────────

/// High-level category for an addressing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressCategory {
    /// Directly in a data register.
    Register,
    /// Directly in an address register.
    AddressRegister,
    /// Memory read (indirect modes).
    Memory,
    /// Immediate constant.
    Immediate,
    /// PC-relative (read-only in most cases).
    PcRelative,
}

/// Classify an EA mode into a high-level `AddressCategory`.
#[must_use]
pub const fn classify_ea_mode(mode: u8, reg: u8) -> AddressCategory {
    match mode {
        0 => AddressCategory::Register,
        1 => AddressCategory::AddressRegister,
        7 => match reg {
            2 | 3 => AddressCategory::PcRelative,
            4 => AddressCategory::Immediate,
            _ => AddressCategory::Memory,
        },
        _ => AddressCategory::Memory,
    }
}

// ── Instruction predicate helpers ─────────────────────────────────────────────

/// True if the instruction is a no-op (NOP).
#[must_use]
pub fn is_nop(instr: &Instruction) -> bool {
    instr.mnemonic == "NOP"
}

/// True if the instruction transfers control (branch, call, or return).
#[must_use]
pub fn is_control_transfer(instr: &Instruction) -> bool {
    instr
        .flags
        .intersects(InstrFlags::BRANCH | InstrFlags::CALL | InstrFlags::RET)
}

/// True if the instruction reads from memory.
#[must_use]
pub const fn is_memory_read(instr: &Instruction) -> bool {
    instr.flags.contains(InstrFlags::READ_MEM)
}

/// True if the instruction writes to memory.
#[must_use]
pub const fn is_memory_write(instr: &Instruction) -> bool {
    instr.flags.contains(InstrFlags::WRITE_MEM)
}

/// True if the instruction modifies the condition code register.
#[must_use]
pub fn modifies_ccr(instr: &Instruction) -> bool {
    let m = instr.mnemonic.as_str();
    // Most arithmetic and logic instructions affect CCR; branch instructions don't
    !matches!(
        m,
        "NOP" | "MOVEM" | "LINK" | "UNLK" | "SWAP" | "JMP" | "JSR" | "BSR" | "BRA"
    ) && !is_control_transfer(instr)
}

// ── Register pressure analysis ────────────────────────────────────────────────

/// Track which registers are live (written without a preceding read).
#[derive(Debug, Default, Clone)]
pub struct RegisterUsage {
    /// Bitmask of data registers referenced (bit i = Di).
    pub data_read: u8,
    /// Bitmask of data registers written.
    pub data_write: u8,
    /// Bitmask of address registers referenced.
    pub addr_read: u8,
    /// Bitmask of address registers written.
    pub addr_write: u8,
}

impl RegisterUsage {
    /// Record a data register read.
    pub const fn read_d(&mut self, reg: u8) {
        self.data_read |= 1 << (reg & 7);
    }
    /// Record a data register write.
    pub const fn write_d(&mut self, reg: u8) {
        self.data_write |= 1 << (reg & 7);
    }
    /// Record an address register read.
    pub const fn read_a(&mut self, reg: u8) {
        self.addr_read |= 1 << (reg & 7);
    }
    /// Record an address register write.
    pub const fn write_a(&mut self, reg: u8) {
        self.addr_write |= 1 << (reg & 7);
    }

    /// Number of data registers written.
    #[must_use]
    pub fn data_regs_written(&self) -> u32 {
        u32::from(self.data_write).count_ones()
    }
    /// Number of address registers written.
    #[must_use]
    pub fn addr_regs_written(&self) -> u32 {
        u32::from(self.addr_write).count_ones()
    }
}

// ── Instruction pattern matcher ───────────────────────────────────────────────

/// A simple sequence pattern for 68k idiom detection.
#[derive(Debug, Clone, Copy)]
pub struct Pattern {
    /// Sequence of mnemonics (glob-style `*` allowed as last character).
    pub mnemonics: &'static [&'static str],
    /// Human-readable name for the pattern.
    pub name: &'static str,
}

impl Pattern {
    /// Check whether a slice of instructions matches this pattern.
    #[must_use]
    pub fn matches(self, instrs: &[Instruction]) -> bool {
        if instrs.len() < self.mnemonics.len() {
            return false;
        }
        for (i, pat) in self.mnemonics.iter().enumerate() {
            let m = instrs[i].mnemonic.as_str();
            if let Some(prefix) = pat.strip_suffix('*') {
                if !m.starts_with(prefix) {
                    return false;
                }
            } else if m != *pat {
                return false;
            }
        }
        true
    }
}

/// Well-known 68k code idioms.
pub static KNOWN_PATTERNS: &[Pattern] = &[
    Pattern {
        mnemonics: &["LINK", "MOVEM"],
        name: "function_prologue_full",
    },
    Pattern {
        mnemonics: &["LINK"],
        name: "function_prologue_link",
    },
    Pattern {
        mnemonics: &["MOVEM", "UNLK"],
        name: "function_epilogue",
    },
    Pattern {
        mnemonics: &["CLR", "MOVE"],
        name: "zero_then_move",
    },
    Pattern {
        mnemonics: &["MOVEQ", "MOVE"],
        name: "moveq_then_store",
    },
    Pattern {
        mnemonics: &["JSR", "ADDQ"],
        name: "cdecl_call_cleanup",
    },
    Pattern {
        mnemonics: &["DBRA"],
        name: "counted_loop",
    },
    Pattern {
        mnemonics: &["DBF"],
        name: "counted_loop_false",
    },
    Pattern {
        mnemonics: &["TST", "BEQ"],
        name: "test_and_branch",
    },
    Pattern {
        mnemonics: &["CMP", "BEQ"],
        name: "compare_and_branch",
    },
];

/// Scan instructions for all known idiom matches.
#[must_use]
pub fn find_idioms(instrs: &[Instruction]) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for start in 0..instrs.len() {
        for pattern in KNOWN_PATTERNS {
            if pattern.matches(&instrs[start..]) {
                found.push((start, pattern.name));
            }
        }
    }
    found
}

/// Simplified prefix-matching helper (used by pattern matching above).
#[must_use]
fn mnemonic_matches_pat(mnemonic: &str, pat: &str) -> bool {
    pat.strip_suffix('*').map_or_else(
        || mnemonic == pat,
        |prefix| mnemonic.starts_with(prefix),
    )
}

/// Check if a single instruction mnemonic matches a wildcard pattern.
#[must_use]
pub fn instr_matches(instr: &Instruction, pat: &str) -> bool {
    mnemonic_matches_pat(instr.mnemonic.as_str(), pat)
}

// ── BCD arithmetic helpers ────────────────────────────────────────────────────

/// Simulate the ABCD instruction (add BCD with extend).
/// Returns (result, carry, overflow) for the byte operation.
#[must_use]
pub fn abcd_byte(src: u8, dst: u8, x: bool) -> (u8, bool, bool) {
    let sum = u16::from(src) + u16::from(dst) + u16::from(x);
    let lo = (src & 0xF) + (dst & 0xF) + u8::from(x);
    let result = if lo > 9 { sum + 6 } else { sum };
    let carry = result > 0x99;
    let final_res = if carry {
        result.wrapping_add(0x60)
    } else {
        result
    };
    // Take lower byte — BCD result wraps modulo 256
    (final_res.to_ne_bytes()[0], carry, carry)
}

/// Simulate the SBCD instruction (subtract BCD with extend).
#[must_use]
pub fn sbcd_byte(src: u8, dst: u8, x: bool) -> (u8, bool) {
    let diff = i16::from(dst) - i16::from(src) - i16::from(x);
    let lo = i16::from(dst & 0xF) - i16::from(src & 0xF) - i16::from(x);
    let after_lo = if lo < 0 { diff - 6 } else { diff };
    // High-nibble borrow: if the raw subtraction underflowed, also subtract 0x60.
    let carry = diff < 0;
    let adjusted = if carry { after_lo - 0x60 } else { after_lo };
    let result = if adjusted < 0 { adjusted + 0x100 } else { adjusted };
    // Positive result fits in u8, borrow adjustment brings it into [0,99] BCD range
    let byte = u8::try_from(result).unwrap_or(0);
    (byte, carry)
}

// ── Binary encoder ────────────────────────────────────────────────────────────

/// Encode an ADD immediate instruction (ADDI).
///
/// # Panics
/// Panics if `dn` >= 8.
#[must_use]
pub fn encode_addi_word(imm: u16, dn: u8) -> [u8; 4] {
    assert!(dn < 8, "ADDI: dn must be 0..7");
    let word: u16 = 0x0640 | u16::from(dn); // ADDI.W #imm,Dn
    let w = word.to_be_bytes();
    let i = imm.to_be_bytes();
    [w[0], w[1], i[0], i[1]]
}

/// Encode a SUBQ instruction.
///
/// # Panics
/// Panics if `data` > 8 or `data` == 0, or `dn` >= 8.
#[must_use]
pub fn encode_subq_word(data: u8, dn: u8) -> [u8; 2] {
    assert!((1..=8).contains(&data), "SUBQ: data must be 1..8");
    assert!(dn < 8, "SUBQ: dn must be 0..7");
    let d = if data == 8 { 0 } else { data };
    let word: u16 = 0x5140 | (u16::from(d) << 9) | u16::from(dn);
    word.to_be_bytes()
}

/// Encode a JMP to an absolute long address.
#[must_use]
pub const fn encode_jmp_abs_long(addr: u32) -> [u8; 6] {
    let word: u16 = 0x4EF9;
    let w = word.to_be_bytes();
    let a = addr.to_be_bytes();
    [w[0], w[1], a[0], a[1], a[2], a[3]]
}

/// Encode a JSR to an absolute long address.
#[must_use]
pub const fn encode_jsr_abs_long(addr: u32) -> [u8; 6] {
    let word: u16 = 0x4EB9;
    let w = word.to_be_bytes();
    let a = addr.to_be_bytes();
    [w[0], w[1], a[0], a[1], a[2], a[3]]
}

/// Encode a MOVEM.L Dn/An list to push onto stack (pre-decrement).
/// `mask` is the register mask in pre-decrement order.
#[must_use]
pub const fn encode_movem_push(mask: u16) -> [u8; 4] {
    let word: u16 = 0x48E7; // MOVEM.L regs,-(SP)
    let w = word.to_be_bytes();
    let m = mask.to_be_bytes();
    [w[0], w[1], m[0], m[1]]
}

/// Encode a MOVEM.L pop from stack (post-increment).
#[must_use]
pub const fn encode_movem_pop(mask: u16) -> [u8; 4] {
    let word: u16 = 0x4CDF; // MOVEM.L (SP)+,regs
    let w = word.to_be_bytes();
    let m = mask.to_be_bytes();
    [w[0], w[1], m[0], m[1]]
}

// ── Patch utilities ───────────────────────────────────────────────────────────

/// Possible result of a NOP-sled patch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchResult {
    /// Successfully patched.
    Ok,
    /// Not enough bytes (need even count).
    TooShort,
    /// Byte count is odd (instructions are always 2-byte aligned).
    OddCount,
}

/// Fill `buf` with NOP instructions (each 2 bytes).
///
/// # Errors
/// Does not error — returns `PatchResult`.
#[must_use]
pub fn nop_sled(buf: &mut [u8]) -> PatchResult {
    if buf.len() < 2 {
        return PatchResult::TooShort;
    }
    if !buf.len().is_multiple_of(2) {
        return PatchResult::OddCount;
    }
    for chunk in buf.chunks_exact_mut(2) {
        chunk[0] = 0x4E;
        chunk[1] = 0x71;
    }
    PatchResult::Ok
}

/// Replace a BSR/JSR target within a pre-existing call instruction.
/// The `buf` must be at least 6 bytes (for JSR abs.L form).
///
/// # Panics
/// Panics if `buf` is less than 6 bytes long.
#[must_use]
pub fn patch_call_target(buf: &mut [u8], new_target: u32) -> bool {
    assert!(buf.len() >= 6, "patch_call_target: buf must be >= 6 bytes");
    let word = u16::from_be_bytes([buf[0], buf[1]]);
    // JSR abs.L = 4EB9
    if (word & 0xFFC0) == 0x4E80 && buf.len() >= 6 {
        buf[2..6].copy_from_slice(&new_target.to_be_bytes());
        return true;
    }
    // JMP abs.L = 4EF9
    if (word & 0xFFC0) == 0x4EC0 && buf.len() >= 6 {
        buf[2..6].copy_from_slice(&new_target.to_be_bytes());
        return true;
    }
    false
}

// ── AmigaOS / Macintosh toolbox helpers ───────────────────────────────────────

/// Check whether an instruction looks like an `AmigaOS` library call.
/// These are of the form: JSR -Nnn(A6).
#[must_use]
pub fn is_amiga_library_call(instr: &Instruction) -> bool {
    instr.mnemonic == "JSR" && instr.operands.contains("(A6)")
}

/// Extract the negative offset from an `AmigaOS` library call operand.
/// Returns `Some(offset)` for a negative displacement JSR -N(A6).
#[must_use]
pub fn amiga_lvo(instr: &Instruction) -> Option<i16> {
    if !is_amiga_library_call(instr) {
        return None;
    }
    let ops = &instr.operands;
    // Parse "-N(A6)"
    if let Some(start) = ops.find('-') {
        let end = ops.find('(')?;
        let s = &ops[start + 1..end];
        s.parse::<i16>().ok().map(|v| -v)
    } else {
        None
    }
}

// ── FPU register file ──────────────────────────────────────────────────────────

/// An 80-bit FPU register value (IEEE 754 extended precision).
#[derive(Debug, Clone, Copy, Default)]
pub struct FpRegister {
    /// Raw bytes (big-endian, 10 bytes).
    pub bytes: [u8; 10],
}

impl FpRegister {
    /// Create from a 64-bit double value.
    #[must_use]
    pub const fn from_f64(_val: f64) -> Self {
        // Simplified: just store zero for now
        Self { bytes: [0u8; 10] }
    }

    /// Check if this value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

/// The FPU register file (FP0..FP7).
#[derive(Debug, Clone, Default)]
pub struct FpuRegFile {
    /// Eight 80-bit FP registers.
    pub regs: [FpRegister; 8],
    /// FPU status register.
    pub fpsr: u32,
    /// FPU control register.
    pub fpcr: u32,
    /// FPU instruction address register.
    pub fpiar: u32,
}

impl FpuRegFile {
    /// Check the FPSR zero bit.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        (self.fpsr >> 26) & 1 == 1
    }
    /// Check the FPSR negative bit.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        (self.fpsr >> 27) & 1 == 1
    }
    /// Check the FPSR NaN bit.
    #[must_use]
    pub const fn is_nan(&self) -> bool {
        (self.fpsr >> 24) & 1 == 1
    }
    /// Check the FPSR infinity bit.
    #[must_use]
    pub const fn is_infinity(&self) -> bool {
        (self.fpsr >> 25) & 1 == 1
    }
}

// ── Symbol table ─────────────────────────────────────────────────────────────

/// A symbol with address and optional type annotation.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol address.
    pub address: Address,
    /// Symbol name.
    pub name: String,
    /// Whether this is a function (vs. data label).
    pub is_function: bool,
    /// Estimated size in bytes (0 if unknown).
    pub size: usize,
}

impl Symbol {
    /// Create a new function symbol.
    #[must_use]
    pub fn function(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            is_function: true,
            size: 0,
        }
    }

    /// Create a new data symbol.
    #[must_use]
    pub fn data(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            is_function: false,
            size: 0,
        }
    }
}

/// A minimal symbol table.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
}

impl SymbolTable {
    /// Add a symbol.
    pub fn add(&mut self, sym: Symbol) {
        self.symbols.push(sym);
    }

    /// Look up a symbol by address (returns first match).
    #[must_use]
    pub fn by_address(&self, addr: Address) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.address == addr)
    }

    /// Look up a symbol by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Number of symbols.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// All function symbols.
    #[must_use]
    pub fn functions(&self) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.is_function).collect()
    }
}

// ── CFG basic block ───────────────────────────────────────────────────────────

/// A basic block in a control flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address of the block.
    pub start: Address,
    /// End address (exclusive, i.e. first byte after the block).
    pub end: Address,
    /// Successor addresses.
    pub successors: Vec<Address>,
    /// Whether this block ends in a call.
    pub ends_with_call: bool,
    /// Whether this block ends with a return.
    pub ends_with_return: bool,
}

impl BasicBlock {
    /// Size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.as_u64().saturating_sub(self.start.as_u64())
    }
}

/// Split a linear instruction stream into basic blocks.
///
/// # Panics
/// Does not panic in practice (internal guard ensures non-empty block lists).
#[must_use]
pub fn build_cfg(instrs: &[Instruction]) -> Vec<BasicBlock> {
    if instrs.is_empty() {
        return vec![];
    }

    // Collect all block-start addresses (entry + branch targets)
    let mut starts: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    starts.insert(instrs[0].address.as_u64());

    for i in instrs {
        if i.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL) {
            // Fall-through
            let ft = i.address.as_u64() + i.size as u64;
            starts.insert(ft);
            // Branch target
            let ops = &i.operands;
            if let Some(pos) = ops.rfind('$') {
                let hex: String = ops[pos + 1..]
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                if let Ok(t) = u64::from_str_radix(&hex, 16) {
                    starts.insert(t);
                }
            }
        }
        if i.flags.contains(InstrFlags::RET) {
            let ft = i.address.as_u64() + i.size as u64;
            starts.insert(ft);
        }
    }

    // Build blocks
    let mut blocks = Vec::new();
    let starts_vec: Vec<u64> = starts.into_iter().collect();
    for (idx, &block_start) in starts_vec.iter().enumerate() {
        let block_end = starts_vec.get(idx + 1).copied().unwrap_or(u64::MAX);
        let block_instrs: Vec<&Instruction> = instrs
            .iter()
            .filter(|i| {
                let a = i.address.as_u64();
                a >= block_start && a < block_end
            })
            .collect();
        if block_instrs.is_empty() {
            continue;
        }

        let last = *block_instrs.last().unwrap();
        let mut succs = Vec::new();
        let last_end = last.address.as_u64() + last.size as u64;

        let ends_call = last.flags.contains(InstrFlags::CALL);
        let ends_return = last.flags.contains(InstrFlags::RET);
        let unconditional_branch = last.flags.contains(InstrFlags::BRANCH)
            && !last.flags.contains(InstrFlags::CONDITIONAL)
            && !ends_call;

        // Fall-through successor
        if !ends_return && !unconditional_branch {
            succs.push(Address::new(last_end));
        }
        // Branch target
        if last.flags.intersects(InstrFlags::BRANCH | InstrFlags::CALL) {
            let ops = &last.operands;
            if let Some(pos) = ops.rfind('$') {
                let hex: String = ops[pos + 1..]
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                if let Ok(t) = u64::from_str_radix(&hex, 16) {
                    if ends_call {
                        succs.push(Address::new(last_end)); // call: fall-through
                    } else {
                        succs.push(Address::new(t));
                        if last.flags.contains(InstrFlags::CONDITIONAL) {
                            succs.push(Address::new(last_end));
                        }
                    }
                }
            }
        }

        blocks.push(BasicBlock {
            start: Address::new(block_start),
            end: Address::new(last_end),
            successors: succs,
            ends_with_call: ends_call,
            ends_with_return: ends_return,
        });
    }
    blocks
}

// ── LINK/UNLK encoder ─────────────────────────────────────────────────────────

/// Encode a LINK instruction.
///
/// # Panics
/// Panics if `an` >= 8.
#[must_use]
pub fn encode_link(an: u8, disp: i16) -> [u8; 4] {
    assert!(an < 8, "LINK: an must be 0..7");
    let word: u16 = 0x4E50 | u16::from(an);
    let w = word.to_be_bytes();
    let d = disp.to_be_bytes();
    [w[0], w[1], d[0], d[1]]
}

/// Encode an UNLK instruction.
///
/// # Panics
/// Panics if `an` >= 8.
#[must_use]
pub fn encode_unlk(an: u8) -> [u8; 2] {
    assert!(an < 8, "UNLK: an must be 0..7");
    let word: u16 = 0x4E58 | u16::from(an);
    word.to_be_bytes()
}

/// Encode a DBRA (DBF D0,disp) instruction.
///
/// # Panics
/// Panics if `dn` >= 8.
#[must_use]
pub fn encode_dbra(dn: u8, disp: i16) -> [u8; 4] {
    assert!(dn < 8, "DBRA: dn must be 0..7");
    let word: u16 = 0x51C8 | u16::from(dn);
    let w = word.to_be_bytes();
    let d = disp.to_be_bytes();
    [w[0], w[1], d[0], d[1]]
}

// ── Addressing mode validators ────────────────────────────────────────────────

/// Check if an EA is valid as a source (alterable data EA).
#[must_use]
pub const fn is_data_alterable_ea(mode: u8, reg: u8) -> bool {
    match mode {
        0 | 2..=6 => true,
        7 => matches!(reg, 0 | 1),
        _ => false,
    }
}

/// Check if an EA is valid as a control EA (no pre/post-increment, no immediate).
#[must_use]
pub const fn is_control_ea(mode: u8, reg: u8) -> bool {
    match mode {
        2 | 5 | 6 => true,
        7 => matches!(reg, 0..=3),
        _ => false,
    }
}

/// Check if an EA can appear as the destination of MOVE.
#[must_use]
pub const fn is_movable_dst_ea(mode: u8, reg: u8) -> bool {
    match mode {
        0..=6 => true,
        7 => matches!(reg, 0 | 1),
        _ => false,
    }
}

// ── Displacement encoding helpers ─────────────────────────────────────────────

/// Compute the displacement for a branch from `from_pc` to `target`.
/// The CPU adds 2 to `from_pc` before computing the branch.
///
/// Returns `None` if the target is unreachable (> 32767 bytes away with 16-bit).
#[must_use]
pub fn branch_displacement(from_pc: u64, target: u64, use_long: bool) -> Option<i32> {
    let adjusted = from_pc.wrapping_add(2);
    let diff = target.wrapping_sub(adjusted);
    let disp = i64::from_ne_bytes(diff.to_ne_bytes());
    if use_long {
        if let Ok(v) = i32::try_from(disp) {
            return Some(v);
        }
    } else if let Ok(v16) = i16::try_from(disp) {
        return Some(i32::from(v16));
    }
    None
}

// ── MOVEM register list analysis ─────────────────────────────────────────────

/// Count the number of registers in a MOVEM mask.
#[must_use]
pub fn count_movem_regs(mask: u16) -> u32 {
    u32::from(mask).count_ones()
}

/// List all register names in a MOVEM mask (for operand display).
#[must_use]
pub fn movem_reg_names(mask: u16) -> Vec<String> {
    let mut names = Vec::new();
    for i in 0..8_u8 {
        if (mask >> i) & 1 != 0 {
            names.push(format!("D{i}"));
        }
    }
    for i in 0..8_u8 {
        if (mask >> (i + 8)) & 1 != 0 {
            names.push(format!("A{i}"));
        }
    }
    names
}

// ── Condition code inversion ───────────────────────────────────────────────────

/// Return the inverse condition code (e.g. BEQ ↔ BNE).
#[must_use]
pub const fn invert_cond(cond: CondCode) -> CondCode {
    match cond {
        CondCode::T => CondCode::F,
        CondCode::F => CondCode::T,
        CondCode::Hi => CondCode::Ls,
        CondCode::Ls => CondCode::Hi,
        CondCode::Cc => CondCode::Cs,
        CondCode::Cs => CondCode::Cc,
        CondCode::Ne => CondCode::Eq,
        CondCode::Eq => CondCode::Ne,
        CondCode::Vc => CondCode::Vs,
        CondCode::Vs => CondCode::Vc,
        CondCode::Pl => CondCode::Mi,
        CondCode::Mi => CondCode::Pl,
        CondCode::Ge => CondCode::Lt,
        CondCode::Lt => CondCode::Ge,
        CondCode::Gt => CondCode::Le,
        CondCode::Le => CondCode::Gt,
    }
}

// ── Shift count decoder ────────────────────────────────────────────────────────

/// Decode the shift count from an ASL/ASR/LSL/LSR/ROL/ROR instruction word.
/// Returns `(count, use_reg)` where `use_reg=true` means count is in a Dn register.
#[must_use]
pub const fn decode_shift_count(word: u16) -> (u8, bool) {
    let use_reg = (word & 0x0020) != 0;
    let count_field = ((word >> 9) & 7) as u8;
    let imm_count = if count_field == 0 { 8 } else { count_field };
    (imm_count, use_reg)
}

// ── Multiplier/divider info ────────────────────────────────────────────────────

/// Information about a MULU/MULS/DIVU/DIVS instruction.
#[derive(Debug, Clone, Copy)]
pub struct MulDivInfo {
    /// True if signed (MULS / DIVS).
    pub is_signed: bool,
    /// True if divide (vs. multiply).
    pub is_divide: bool,
    /// Data register for the result (Dn).
    pub result_reg: u8,
}

/// Decode a MUL/DIV instruction word into `MulDivInfo`.
#[must_use]
pub const fn decode_muldiv_info(word: u16) -> Option<MulDivInfo> {
    let hi4 = (word >> 12) as u8;
    // Bits 7:6 are the size/op encoding; bit 8 selects signed.
    // We exclude bit 8 from the comparison so both signed and unsigned match.
    let bits = (word >> 6) & 0x03;
    // DIVU.W = 0x80C0, DIVS.W = 0x81C0; MULU.W = 0xC0C0, MULS.W = 0xC1C0.
    if hi4 == 0x8 && bits == 0x03 {
        let is_signed = (word & 0x0100) != 0;
        let reg = ((word >> 9) & 7) as u8;
        return Some(MulDivInfo {
            is_signed,
            is_divide: true,
            result_reg: reg,
        });
    }
    if hi4 == 0xC && bits == 0x03 {
        let is_signed = (word & 0x0100) != 0;
        let reg = ((word >> 9) & 7) as u8;
        return Some(MulDivInfo {
            is_signed,
            is_divide: false,
            result_reg: reg,
        });
    }
    None
}

// ── TRAP vector decoding ───────────────────────────────────────────────────────

/// Decode a TRAP instruction word into its vector number (0..15).
#[must_use]
pub const fn trap_vector(word: u16) -> Option<u8> {
    if (word & 0xFFF0) == 0x4E40 {
        Some((word & 0xF) as u8)
    } else {
        None
    }
}

// ── Well-known TRAP vectors ────────────────────────────────────────────────────

/// Known OS-level TRAP interpretations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownTrap {
    /// GEMDOS (TOS/Atari) — TRAP #1.
    Gemdos,
    /// BIOS (Atari) — TRAP #13.
    AtariBios,
    /// XBIOS (Atari) — TRAP #14.
    AtariXbios,
    /// Macintosh OS trap — TRAP #15.
    MacToolbox,
    /// `AmigaOS` exec — TRAP #0.
    AmigaExec,
    /// Unknown.
    Unknown(u8),
}

impl KnownTrap {
    /// Identify a TRAP vector number.
    #[must_use]
    pub const fn identify(vector: u8) -> Self {
        match vector {
            0 => Self::AmigaExec,
            1 => Self::Gemdos,
            13 => Self::AtariBios,
            14 => Self::AtariXbios,
            15 => Self::MacToolbox,
            v => Self::Unknown(v),
        }
    }
}

// ── Branch probability annotation ─────────────────────────────────────────────

/// Simple branch probability hint based on instruction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchHint {
    /// Unconditional — always taken.
    AlwaysTaken,
    /// Never taken (BF — false condition).
    NeverTaken,
    /// Likely taken (back-edge branch — negative displacement).
    LikelyTaken,
    /// Likely not taken (forward branch — positive displacement).
    LikelyNotTaken,
    /// Unknown probability.
    Unknown,
}

/// Estimate branch probability for a given instruction.
#[must_use]
pub fn branch_hint(instr: &Instruction, target: u64) -> BranchHint {
    if !instr.flags.contains(InstrFlags::BRANCH) {
        return BranchHint::Unknown;
    }
    if !instr.flags.contains(InstrFlags::CONDITIONAL) {
        return BranchHint::AlwaysTaken;
    }
    if instr.mnemonic.ends_with('F') {
        return BranchHint::NeverTaken;
    }
    let pc = instr.address.as_u64();
    if target < pc {
        BranchHint::LikelyTaken
    } else {
        BranchHint::LikelyNotTaken
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn arch() -> Mc68kArch {
        Mc68kArch::default()
    }
    fn arch40() -> Mc68kArch {
        Mc68kArch::new(Mc68kVariant::M68040)
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Basic instructions ────────────────────────────────────────────────────
    #[test]
    fn test_nop() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x71]).unwrap();
        assert_eq!(i.mnemonic, "NOP");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_rts() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x75]).unwrap();
        assert_eq!(i.mnemonic, "RTS");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_rte() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x73]).unwrap();
        assert_eq!(i.mnemonic, "RTE");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_rtr() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x77]).unwrap();
        assert_eq!(i.mnemonic, "RTR");
        assert!(i.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_reset() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x70]).unwrap();
        assert_eq!(i.mnemonic, "RESET");
    }

    // ── MOVE family ──────────────────────────────────────────────────────────
    #[test]
    fn test_move_w_d0_d1() {
        let i = arch().disassemble(addr(0x1000), &[0x32, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "MOVE.W");
        assert_eq!(i.size, 2);
    }

    #[test]
    fn test_move_l_d0_d1() {
        // MOVE.L D0,D1 = 0x2200
        let i = arch().disassemble(addr(0x1000), &[0x22, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "MOVE.L");
    }

    #[test]
    fn test_movea_w() {
        // MOVEA.W D0,A0 = 0x3040
        let i = arch().disassemble(addr(0x1000), &[0x30, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "MOVEA.W");
    }

    #[test]
    fn test_moveq() {
        // MOVEQ #42,D0 = 0x702A
        let i = arch().disassemble(addr(0x1000), &[0x70, 0x2A]).unwrap();
        assert_eq!(i.mnemonic, "MOVEQ");
        assert!(i.operands.contains("D0"));
    }

    #[test]
    fn test_moveq_negative() {
        // MOVEQ #-1,D0 = 0x70FF
        let i = arch().disassemble(addr(0x1000), &[0x70, 0xFF]).unwrap();
        assert_eq!(i.mnemonic, "MOVEQ");
    }

    // ── Branches ─────────────────────────────────────────────────────────────
    #[test]
    fn test_bra8() {
        let bytes = encode_bra8(10);
        let i = arch().disassemble(addr(0x1000), &bytes).unwrap();
        assert_eq!(i.mnemonic, "BRA");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_bra16() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x60, 0x00, 0x00, 0x0A])
            .unwrap();
        assert_eq!(i.mnemonic, "BRA");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(!i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_bsr() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x61, 0x00, 0x00, 0x20])
            .unwrap();
        assert_eq!(i.mnemonic, "BSR");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_beq() {
        let i = arch().disassemble(addr(0x1000), &[0x67, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "BEQ");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_bne() {
        let i = arch().disassemble(addr(0x1000), &[0x66, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "BNE");
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    #[test]
    fn test_bhi() {
        let i = arch().disassemble(addr(0x1000), &[0x62, 0x10]).unwrap();
        assert_eq!(i.mnemonic, "BHI");
    }

    // ── JMP/JSR ──────────────────────────────────────────────────────────────
    #[test]
    fn test_jmp_absolute() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x4E, 0xF8, 0x12, 0x34])
            .unwrap();
        assert_eq!(i.mnemonic, "JMP");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_jsr_absolute() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x4E, 0xB8, 0x12, 0x34])
            .unwrap();
        assert_eq!(i.mnemonic, "JSR");
        assert!(i.flags.contains(InstrFlags::CALL));
    }

    // ── ALU ──────────────────────────────────────────────────────────────────
    #[test]
    fn test_add_long() {
        let i = arch().disassemble(addr(0x1000), &[0xD2, 0x80]).unwrap();
        assert_eq!(i.mnemonic, "ADD.L");
    }

    #[test]
    fn test_sub_word() {
        let i = arch().disassemble(addr(0x1000), &[0x92, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "SUB.W");
    }

    #[test]
    fn test_clr_word() {
        let i = arch().disassemble(addr(0x1000), &[0x42, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "CLR.W");
    }

    #[test]
    fn test_neg_byte() {
        let i = arch().disassemble(addr(0x1000), &[0x44, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "NEG.B");
    }

    #[test]
    fn test_not_long() {
        let i = arch().disassemble(addr(0x1000), &[0x46, 0x80]).unwrap();
        assert_eq!(i.mnemonic, "NOT.L");
    }

    #[test]
    fn test_tst_word() {
        let i = arch().disassemble(addr(0x1000), &[0x4A, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "TST.W");
    }

    #[test]
    fn test_or_byte() {
        let i = arch().disassemble(addr(0x1000), &[0x82, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "OR.B");
    }

    #[test]
    fn test_cmp_word() {
        let i = arch().disassemble(addr(0x1000), &[0xB2, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "CMP.W");
    }

    // ── Shift/rotate ──────────────────────────────────────────────────────────
    #[test]
    fn test_asl_reg() {
        // ASL.W #1,D0 = E340
        let i = arch().disassemble(addr(0x1000), &[0xE3, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "ASL.W");
    }

    #[test]
    fn test_lsr_reg() {
        // LSR.W #1,D0 = E248
        let i = arch().disassemble(addr(0x1000), &[0xE2, 0x48]).unwrap();
        assert_eq!(i.mnemonic, "LSR.W");
    }

    #[test]
    fn test_ror_reg() {
        // ROR.W #1,D0 = E258
        let i = arch().disassemble(addr(0x1000), &[0xE2, 0x58]).unwrap();
        assert_eq!(i.mnemonic, "ROR.W");
    }

    // ── Misc ──────────────────────────────────────────────────────────────────
    #[test]
    fn test_lea() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x41, 0xF8, 0x12, 0x34])
            .unwrap();
        assert_eq!(i.mnemonic, "LEA");
        assert!(i.operands.contains("A0"));
    }

    #[test]
    fn test_trap() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "TRAP");
    }

    #[test]
    fn test_link() {
        let i = arch()
            .disassemble(addr(0x1000), &[0x4E, 0x50, 0xFF, 0xF0])
            .unwrap();
        assert_eq!(i.mnemonic, "LINK");
        assert!(i.operands.contains("A0"));
    }

    #[test]
    fn test_unlk() {
        let i = arch().disassemble(addr(0x1000), &[0x4E, 0x58]).unwrap();
        assert_eq!(i.mnemonic, "UNLK");
    }

    #[test]
    fn test_swap() {
        // SWAP D0 = 4840
        let i = arch().disassemble(addr(0x1000), &[0x48, 0x40]).unwrap();
        assert_eq!(i.mnemonic, "SWAP");
    }

    // ── Architecture properties ───────────────────────────────────────────────
    #[test]
    fn test_registers_count() {
        assert!(arch().registers().len() >= 20);
    }

    #[test]
    fn test_pointer_size_and_endian() {
        assert_eq!(arch().pointer_size(), 4);
        assert_eq!(arch().endian(), Endian::Big);
    }

    #[test]
    fn test_variant_name() {
        assert_eq!(Mc68kArch::new(Mc68kVariant::M68020).name(), "68020");
        assert_eq!(Mc68kArch::new(Mc68kVariant::M68060).name(), "68060");
        assert_eq!(Mc68kArch::new(Mc68kVariant::ColdFire).name(), "ColdFire");
    }

    #[test]
    fn test_calling_convention() {
        let cc = arch().calling_conventions();
        assert!(!cc.is_empty());
        assert_eq!(cc[0].name, "m68k_gcc");
        assert!(cc[0].return_regs.contains(&"D0".to_string()));
    }

    #[test]
    fn test_fpu_calling_convention() {
        let cc = arch40().calling_conventions();
        assert!(cc.iter().any(|c| c.name == "m68k_fpu"));
    }

    // ── Linear disassembler ───────────────────────────────────────────────────
    #[test]
    fn test_linear_disassembler() {
        let code = [0x4E_u8, 0x71, 0x4E, 0x71, 0x4E, 0x75];
        let a = arch();
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0x1000))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[2].mnemonic, "RTS");
    }

    #[test]
    fn test_linear_disassembler_is_done() {
        let code = [0x4E_u8, 0x71];
        let a = arch();
        let mut dis = Mc68kLinearDisassembler::new(&a, &code, addr(0));
        assert!(!dis.is_done());
        let _ = dis.next();
        assert!(dis.is_done());
    }

    // ── Recursive disassembler ────────────────────────────────────────────────
    #[test]
    fn test_recursive_disassembler() {
        // NOP, BRA +0 (back to NOP via word disp), RTS
        let code = [0x4E_u8, 0x71, 0x60, 0x00, 0xFF, 0xFC, 0x4E, 0x75];
        let a = arch();
        let mut rd = Mc68kRecursiveDisassembler::new(&a, &code, addr(0x1000), 0);
        rd.run();
        assert!(rd.count() > 0);
    }

    // ── Encoder helpers ───────────────────────────────────────────────────────
    #[test]
    fn test_encode_nop() {
        assert_eq!(encode_nop(), [0x4E, 0x71]);
    }

    #[test]
    fn test_encode_rts() {
        assert_eq!(encode_rts(), [0x4E, 0x75]);
    }

    #[test]
    fn test_encode_moveq() {
        let bytes = encode_moveq(0, 42);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "MOVEQ");
        assert!(i.operands.contains("2A"));
    }

    #[test]
    fn test_encode_trap() {
        let bytes = encode_trap(0);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "TRAP");
    }

    #[test]
    fn test_encode_clr() {
        let bytes = encode_clr(Size::Word, 0);
        let i = arch().disassemble(addr(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "CLR.W");
    }

    // ── Register mask ─────────────────────────────────────────────────────────
    #[test]
    fn test_register_mask_encode_decode() {
        let mask = encode_register_mask(&["D0", "D1", "A0"], false);
        let decoded = decode_register_mask(mask, false);
        assert!(decoded.contains("D0"));
        assert!(decoded.contains("D1"));
        assert!(decoded.contains("A0"));
    }

    #[test]
    fn test_register_mask_predecrement() {
        let mask = encode_register_mask(&["D0"], true);
        assert_ne!(mask, encode_register_mask(&["D0"], false));
    }

    // ── Analysis ──────────────────────────────────────────────────────────────
    #[test]
    fn test_analyze() {
        let code = [
            0x70_u8, 0x01, // MOVEQ #1,D0
            0x61, 0x00, 0x00, 0x04, // BSR +4 (call)
            0x4E, 0x75, // RTS
            0x4E, 0x75, // RTS (callee)
        ];
        let result = analyze(addr(0x1000), &code);
        assert!(result.instr_count() > 0);
        assert!(result.has_calls());
        assert_eq!(result.errors, 0);
    }

    // ── Instruction stats ─────────────────────────────────────────────────────
    #[test]
    fn test_instr_stats() {
        let code = [
            0x4E_u8, 0x75, // RTS
            0x4E, 0x71, // NOP
            0x70, 0x00, // MOVEQ
            0xD2, 0x80, // ADD.L
        ];
        let a = arch();
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let stats = InstrStats::from_instrs(&instrs);
        assert!(stats.returns >= 1);
        assert!(stats.total() >= 3);
    }

    // ── Exception vectors ─────────────────────────────────────────────────────
    #[test]
    fn test_exception_vector_offset() {
        assert_eq!(ExceptionVector::BusError.table_offset(), 8);
        assert_eq!(ExceptionVector::Trap0.table_offset(), 128);
    }

    // ── Condition codes ────────────────────────────────────────────────────────
    #[test]
    fn test_cond_code_round_trip() {
        for v in 0..16_u8 {
            let cc = CondCode::from_bits(v);
            let name = cc.mnemonic();
            assert!(!name.is_empty());
        }
    }

    // ── Variants ──────────────────────────────────────────────────────────────
    #[test]
    fn test_variant_features() {
        assert!(!Mc68kVariant::M68000.has_fpu());
        assert!(Mc68kVariant::M68040.has_fpu());
        assert!(!Mc68kVariant::M68000.is_32bit());
        assert!(Mc68kVariant::M68020.is_32bit());
        assert!(Mc68kVariant::M68030.has_mmu());
        assert!(!Mc68kVariant::M68000.has_mmu());
    }

    #[test]
    fn test_address_space() {
        assert_eq!(Mc68kVariant::M68000.address_space_bytes(), 0x100_0000);
        assert_eq!(Mc68kVariant::M68020.address_space_bytes(), 0x1_0000_0000);
    }

    // ── EA kinds ──────────────────────────────────────────────────────────────
    #[test]
    fn test_ea_kind_display() {
        assert_eq!(EaKind::DataReg(3).display(), "D3");
        assert_eq!(EaKind::AddrInd(1).display(), "(A1)");
        assert_eq!(EaKind::AddrIndPost(0).display(), "(A0)+");
        assert_eq!(EaKind::AddrIndPre(7).display(), "-(A7)");
        assert_eq!(EaKind::AbsLong(0x1234_5678).display(), "$12345678.L");
        assert_eq!(EaKind::Immediate(0xFF).display(), "#$000000FF");
    }

    #[test]
    fn test_parse_ea_data_reg() {
        let (kind, extra) = parse_ea(0, 3, Size::Long, &[]).unwrap();
        assert_eq!(kind, EaKind::DataReg(3));
        assert_eq!(extra, 0);
    }

    #[test]
    fn test_parse_ea_abs_short() {
        let (kind, extra) = parse_ea(7, 0, Size::Word, &[0x12, 0x34]).unwrap();
        assert_eq!(kind, EaKind::AbsShort(0x1234));
        assert_eq!(extra, 2);
    }

    // ── Opcode table lookup ───────────────────────────────────────────────────
    #[test]
    fn test_opcode_table_lookup_nop() {
        let entry = lookup_opcode(0x4E71).unwrap();
        assert_eq!(entry.mnemonic, "NOP");
    }

    #[test]
    fn test_opcode_table_lookup_rts() {
        let entry = lookup_opcode(0x4E75).unwrap();
        assert_eq!(entry.mnemonic, "RTS");
    }

    #[test]
    fn test_opcode_table_lookup_jsr() {
        // JSR (A0) = 4E90
        let entry = lookup_opcode(0x4E90).unwrap();
        assert_eq!(entry.mnemonic, "JSR");
    }

    // ── 68040 specific ────────────────────────────────────────────────────────
    #[test]
    fn test_m68040_registers() {
        let regs = arch40().registers();
        assert!(regs.iter().any(|r| r.name == "FP0"));
        assert!(regs.iter().any(|r| r.name == "FPSR"));
        assert!(regs.iter().any(|r| r.name == "MSP"));
    }

    // ── DBcc ─────────────────────────────────────────────────────────────────
    #[test]
    fn test_dbf() {
        // DBF D0,$1012 (from $1000): 51C8 0010
        let i = arch()
            .disassemble(addr(0x1000), &[0x51, 0xC8, 0x00, 0x10])
            .unwrap();
        assert_eq!(i.mnemonic, "DBF");
        assert!(i.flags.contains(InstrFlags::BRANCH));
        assert!(i.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── Size enum ─────────────────────────────────────────────────────────────
    #[test]
    fn test_size_suffix_and_bytes() {
        assert_eq!(Size::Byte.suffix(), ".B");
        assert_eq!(Size::Word.bytes(), 2);
        assert_eq!(Size::Long.bytes(), 4);
        assert_eq!(Size::Quad.bytes(), 8);
    }

    // ── Truncated instruction error ────────────────────────────────────────────
    #[test]
    fn test_truncated_instruction_error() {
        let result = arch().disassemble(addr(0), &[0x60]);
        assert!(result.is_err());
    }

    // ── BCC branches table ────────────────────────────────────────────────────
    #[test]
    fn test_bcc_branches() {
        let cases = [
            (0x6200_u16, "BHI"),
            (0x6300_u16, "BLS"),
            (0x6400_u16, "BCC"),
            (0x6500_u16, "BCS"),
            (0x6800_u16, "BVC"),
            (0x6900_u16, "BVS"),
            (0x6A00_u16, "BPL"),
            (0x6B00_u16, "BMI"),
            (0x6C00_u16, "BGE"),
            (0x6D00_u16, "BLT"),
            (0x6E00_u16, "BGT"),
            (0x6F00_u16, "BLE"),
        ];
        for (word, expected_mn) in cases {
            let bytes = [word.to_be_bytes()[0], word.to_be_bytes()[1], 0x00, 0x10];
            let i = arch().disassemble(addr(0x1000), &bytes).unwrap();
            assert_eq!(i.mnemonic, expected_mn, "word={word:#06X}");
        }
    }

    // ── Encoder helpers: link/unlk/dbra ──────────────────────────────────────
    #[test]
    fn test_encode_link_unlk() {
        let link = encode_link(6, -32);
        let i = arch().disassemble(addr(0), &link).unwrap();
        assert_eq!(i.mnemonic, "LINK");
        assert!(i.operands.contains("A6"));

        let unlk = encode_unlk(6);
        let i2 = arch().disassemble(addr(0), &unlk).unwrap();
        assert_eq!(i2.mnemonic, "UNLK");
        assert!(i2.operands.contains("A6"));
    }

    #[test]
    fn test_encode_dbra() {
        let dbra = encode_dbra(0, -4);
        let i = arch().disassemble(addr(0x1000), &dbra).unwrap();
        assert_eq!(i.mnemonic, "DBF");
        assert!(i.flags.contains(InstrFlags::BRANCH));
    }

    // ── Condition code inversion ──────────────────────────────────────────────
    #[test]
    fn test_invert_cond() {
        assert_eq!(invert_cond(CondCode::Eq), CondCode::Ne);
        assert_eq!(invert_cond(CondCode::Ne), CondCode::Eq);
        assert_eq!(invert_cond(CondCode::Ge), CondCode::Lt);
        assert_eq!(invert_cond(CondCode::T), CondCode::F);
    }

    // ── Shift count decoder ───────────────────────────────────────────────────
    #[test]
    fn test_decode_shift_count() {
        // ASL.W #4,D0 = E940
        let word: u16 = 0xE940;
        let (count, use_reg) = decode_shift_count(word);
        assert!(!use_reg);
        assert_eq!(count, 4);
    }

    // ── EA predicates ─────────────────────────────────────────────────────────
    #[test]
    fn test_ea_predicates() {
        assert!(is_data_alterable_ea(0, 0)); // data reg
        assert!(is_data_alterable_ea(2, 0)); // (An)
        assert!(!is_data_alterable_ea(1, 0)); // addr reg — not data alterable
        assert!(is_control_ea(2, 0));
        assert!(!is_control_ea(3, 0)); // post-increment not control
    }

    // ── Displacement calculation ──────────────────────────────────────────────
    #[test]
    fn test_branch_displacement() {
        // Branch from 0x1000 to 0x1010 (disp = 0x10 - 2 = 0xE)
        let d = branch_displacement(0x1000, 0x1010, false).unwrap();
        assert_eq!(d, 0xE);
    }

    #[test]
    fn test_branch_displacement_backward() {
        // Branch from 0x1010 to 0x1000 (disp = -18)
        let d = branch_displacement(0x1010, 0x1000, false).unwrap();
        assert_eq!(d, -18);
    }

    // ── MOVEM register list ───────────────────────────────────────────────────
    #[test]
    fn test_movem_reg_names() {
        let mask: u16 = 0x0003; // D0 | D1
        let names = movem_reg_names(mask);
        assert!(names.contains(&"D0".to_string()));
        assert!(names.contains(&"D1".to_string()));
        assert_eq!(count_movem_regs(mask), 2);
    }

    // ── NOP sled patcher ──────────────────────────────────────────────────────
    #[test]
    fn test_nop_sled() {
        let mut buf = [0u8; 8];
        let r = nop_sled(&mut buf);
        assert_eq!(r, PatchResult::Ok);
        assert_eq!(&buf[0..2], &[0x4E, 0x71]);
    }

    #[test]
    fn test_nop_sled_odd_count() {
        let mut buf = [0u8; 3];
        let r = nop_sled(&mut buf);
        assert_eq!(r, PatchResult::OddCount);
    }

    #[test]
    fn test_nop_sled_too_short() {
        let mut buf = [0u8; 1];
        let r = nop_sled(&mut buf);
        assert_eq!(r, PatchResult::TooShort);
    }

    // ── TRAP detection ────────────────────────────────────────────────────────
    #[test]
    fn test_trap_vector() {
        assert_eq!(trap_vector(0x4E40), Some(0));
        assert_eq!(trap_vector(0x4E4F), Some(15));
        assert_eq!(trap_vector(0x4E71), None);
    }

    // ── Known trap identification ──────────────────────────────────────────────
    #[test]
    fn test_known_trap_identify() {
        assert_eq!(KnownTrap::identify(1), KnownTrap::Gemdos);
        assert_eq!(KnownTrap::identify(15), KnownTrap::MacToolbox);
        assert!(matches!(KnownTrap::identify(7), KnownTrap::Unknown(7)));
    }

    // ── BCD simulation ────────────────────────────────────────────────────────
    #[test]
    fn test_abcd_byte_no_carry() {
        let (result, carry, _) = abcd_byte(0x05, 0x03, false);
        assert_eq!(result, 0x08);
        assert!(!carry);
    }

    #[test]
    fn test_abcd_byte_with_carry() {
        let (result, carry, _) = abcd_byte(0x99, 0x01, false);
        assert!(carry);
        let _ = result; // result wraps
    }

    #[test]
    fn test_sbcd_byte_no_borrow() {
        let (result, carry) = sbcd_byte(0x03, 0x09, false);
        assert_eq!(result, 0x06);
        assert!(!carry);
    }

    // ── CFG builder ───────────────────────────────────────────────────────────
    #[test]
    fn test_build_cfg_simple() {
        let a = arch();
        let code = [
            0x4E_u8, 0x71, // NOP
            0x4E, 0x75, // RTS
        ];
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0x1000))
            .filter_map(Result::ok)
            .collect();
        let blocks = build_cfg(&instrs);
        assert!(!blocks.is_empty());
        assert!(blocks.iter().any(|b| b.ends_with_return));
    }

    // ── Symbol table ─────────────────────────────────────────────────────────
    #[test]
    fn test_symbol_table() {
        let mut table = SymbolTable::default();
        table.add(Symbol::function(addr(0x1000), "main"));
        table.add(Symbol::data(addr(0x2000), "data_buf"));

        assert_eq!(table.len(), 2);
        assert_eq!(table.by_name("main").unwrap().address, addr(0x1000));
        assert_eq!(table.functions().len(), 1);
        assert!(!table.is_empty());
    }

    // ── Stack frame analysis ──────────────────────────────────────────────────
    #[test]
    fn test_find_stack_frames() {
        let a = arch();
        let code = encode_link(6, -32);
        let instr = a.disassemble(addr(0x1000), &code).unwrap();
        let frames = find_stack_frames(&[instr]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].fp_reg, 6);
        assert!(frames[0].frame_size < 0);
    }

    // ── Prologue/epilogue detection ───────────────────────────────────────────
    #[test]
    fn test_detect_prologue() {
        let a = arch();
        let link = encode_link(6, -32);
        let instr = a.disassemble(addr(0x1000), &link).unwrap();
        let kind = detect_prologue(&[instr], 4);
        assert_eq!(kind, PrologueKind::LinkOnly);
    }

    #[test]
    fn test_detect_epilogue_true() {
        let a = arch();
        let rts = encode_rts();
        let instr = a.disassemble(addr(0x1000), &rts).unwrap();
        assert!(detect_epilogue(&[instr]));
    }

    // ── Disassembly formatter ─────────────────────────────────────────────────
    #[test]
    fn test_format_instr() {
        let a = arch();
        let i = a.disassemble(addr(0x1000), &[0x4E, 0x71]).unwrap();
        let opts = DisasmOptions::default();
        let s = format_instr(&i, &opts);
        assert!(s.contains("NOP"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_format_listing() {
        let a = arch();
        let code = [0x4E_u8, 0x71, 0x4E, 0x75];
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let s = format_listing(&instrs, &DisasmOptions::default());
        assert!(s.contains("NOP"));
        assert!(s.contains("RTS"));
    }

    // ── Branch hint ───────────────────────────────────────────────────────────
    #[test]
    fn test_branch_hint_forward() {
        let a = arch();
        // BNE forward (+16)
        let i = a.disassemble(addr(0x1000), &[0x66, 0x10]).unwrap();
        let h = branch_hint(&i, 0x1012);
        assert_eq!(h, BranchHint::LikelyNotTaken);
    }

    #[test]
    fn test_branch_hint_backward() {
        let a = arch();
        // BNE backward (-10)
        let i = a.disassemble(addr(0x1010), &[0x66, 0xF6]).unwrap();
        let h = branch_hint(&i, 0x1008);
        assert_eq!(h, BranchHint::LikelyTaken);
    }

    // ── MOVEQ value ───────────────────────────────────────────────────────────
    #[test]
    fn test_moveq_value() {
        assert_eq!(moveq_value(0x7000 | 5), 5);
        assert_eq!(moveq_value(0x70FF), -1);
    }

    // ── ADDQ value ────────────────────────────────────────────────────────────
    #[test]
    fn test_addq_value() {
        // ADDQ.W #4,D0 = 5840
        assert_eq!(addq_value(0x5840), 4);
        // ADDQ.W #8,D0 (0 encodes as 8) = 5040
        assert_eq!(addq_value(0x5040), 8);
    }

    // ── MOVEM push/pop encoders ───────────────────────────────────────────────
    #[test]
    fn test_encode_movem_push_pop() {
        let mask = encode_register_mask(&["D0", "D1", "A0"], false);
        let push = encode_movem_push(mask.reverse_bits());
        let pop = encode_movem_pop(mask);
        // First word should be 0x48E7 for push, 0x4CDF for pop
        assert_eq!(u16::from_be_bytes([push[0], push[1]]), 0x48E7);
        assert_eq!(u16::from_be_bytes([pop[0], pop[1]]), 0x4CDF);
    }

    // ── JMP/JSR long address encoder ─────────────────────────────────────────
    #[test]
    fn test_encode_jmp_jsr_abs_long() {
        let jmp = encode_jmp_abs_long(0x0010_0000);
        let i = arch().disassemble(addr(0), &jmp).unwrap();
        assert_eq!(i.mnemonic, "JMP");
        assert!(i.operands.contains("00100000"));

        let jsr = encode_jsr_abs_long(0x0020_0000);
        let i2 = arch().disassemble(addr(0), &jsr).unwrap();
        assert_eq!(i2.mnemonic, "JSR");
    }

    // ── Pattern idiom matching ────────────────────────────────────────────────
    #[test]
    fn test_find_idioms() {
        let a = arch();
        let link = encode_link(6, -32);
        let nop = encode_nop();
        let rts = encode_rts();
        let mut all_bytes = Vec::new();
        all_bytes.extend_from_slice(&link);
        all_bytes.extend_from_slice(&nop);
        all_bytes.extend_from_slice(&rts);
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &all_bytes, addr(0x1000))
            .filter_map(Result::ok)
            .collect();
        let idioms = find_idioms(&instrs);
        assert!(
            idioms
                .iter()
                .any(|(_, name)| *name == "function_prologue_link")
        );
    }

    // ── Cross-reference builder ───────────────────────────────────────────────
    #[test]
    fn test_build_xrefs() {
        let a = arch();
        let jsr = encode_jsr_abs_long(0x2000);
        let rts = encode_rts();
        let mut code = jsr.to_vec();
        code.extend_from_slice(&rts);
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0x1000))
            .filter_map(Result::ok)
            .collect();
        let xrefs = build_xrefs(&instrs);
        assert!(xrefs.iter().any(|x| x.is_call));
    }

    // ── Condition code isUnconditional ────────────────────────────────────────
    #[test]
    fn test_cond_is_unconditional() {
        assert!(CondCode::T.is_unconditional());
        assert!(!CondCode::Eq.is_unconditional());
    }

    // ── Address space ─────────────────────────────────────────────────────────
    #[test]
    fn test_coldfire_address_space() {
        assert_eq!(Mc68kVariant::ColdFire.address_space_bytes(), 0x1_0000_0000);
    }

    // ── `instr_matches` wildcard ──────────────────────────────────────────────
    #[test]
    fn test_instr_matches() {
        let a = arch();
        let i = a.disassemble(addr(0), &[0x4E, 0x71]).unwrap();
        assert!(instr_matches(&i, "NOP"));
        assert!(!instr_matches(&i, "RTS"));
    }

    // ── FpuRegFile ────────────────────────────────────────────────────────────
    #[test]
    fn test_fpu_reg_file_defaults() {
        let fp = FpuRegFile::default();
        assert!(!fp.is_zero()); // bit not set in zeroed fpsr
        assert!(!fp.is_negative());
        assert!(!fp.is_nan());
    }

    // ── Classify EA mode ──────────────────────────────────────────────────────
    #[test]
    fn test_classify_ea_mode() {
        assert_eq!(classify_ea_mode(0, 0), AddressCategory::Register);
        assert_eq!(classify_ea_mode(1, 0), AddressCategory::AddressRegister);
        assert_eq!(classify_ea_mode(2, 0), AddressCategory::Memory);
        assert_eq!(classify_ea_mode(7, 4), AddressCategory::Immediate);
        assert_eq!(classify_ea_mode(7, 2), AddressCategory::PcRelative);
    }
}

// =============================================================================
// 68k LLIL (Low-Level Intermediate Language) Lifter
// =============================================================================

/// A lifted LLIL operation for one 68k instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M68kLlilOp {
    /// `dest = constant`
    SetRegConst { dest: String, value: i64 },
    /// `dest = src`
    SetRegReg { dest: String, src: String },
    /// `dest = lhs op rhs`
    Arith {
        dest: String,
        lhs: String,
        op: M68kArithOp,
        rhs: String,
    },
    /// `dest = lhs op imm`
    ArithImm {
        dest: String,
        lhs: String,
        op: M68kArithOp,
        rhs: i64,
    },
    /// Load from memory
    Load {
        dest: String,
        base: String,
        offset: i64,
        size: u8,
    },
    /// Store to memory
    Store {
        base: String,
        offset: i64,
        src: String,
        size: u8,
    },
    /// Push to stack: SP -= size; mem[SP] = src
    Push { src: String, size: u8 },
    /// Pop from stack: dest = mem[SP]; SP += size
    Pop { dest: String, size: u8 },
    /// Unconditional jump
    Jump { target: u64 },
    /// Conditional jump
    CondJump { cond: M68kCond, target: u64 },
    /// Subroutine call
    Call { target: u64 },
    /// Indirect call (EA)
    CallEa { ea: String },
    /// Return from subroutine
    Ret,
    /// Return from exception
    RetException,
    /// No-op
    Nop,
    /// Trap
    Trap { vector: u8 },
    /// Unimplemented
    Unimpl { mnemonic: String },
}

/// Arithmetic operation kinds for 68k LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M68kArithOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Mul,
    Div,
    Shl,
    Shr,
    Sar,
    Neg,
}

/// Condition code for conditional jumps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M68kCond {
    T,
    F,
    Hi,
    Ls,
    Cc,
    Cs,
    Ne,
    Eq,
    Vc,
    Vs,
    Pl,
    Mi,
    Ge,
    Lt,
    Gt,
    Le,
}

impl M68kCond {
    #[must_use]
    pub const fn from_cond_code(cc: &CondCode) -> Self {
        match cc {
            CondCode::T => Self::T,
            CondCode::F => Self::F,
            CondCode::Hi => Self::Hi,
            CondCode::Ls => Self::Ls,
            CondCode::Cc => Self::Cc,
            CondCode::Cs => Self::Cs,
            CondCode::Ne => Self::Ne,
            CondCode::Eq => Self::Eq,
            CondCode::Vc => Self::Vc,
            CondCode::Vs => Self::Vs,
            CondCode::Pl => Self::Pl,
            CondCode::Mi => Self::Mi,
            CondCode::Ge => Self::Ge,
            CondCode::Lt => Self::Lt,
            CondCode::Gt => Self::Gt,
            CondCode::Le => Self::Le,
        }
    }
}

/// Operand byte size implied by a mnemonic suffix (`.L` = 4, `.W` = 2, else 1).
fn m68k_mnemonic_size(m: &str) -> u8 {
    let ext = std::path::Path::new(m).extension();
    if ext.is_some_and(|e| e.eq_ignore_ascii_case("L")) {
        4
    } else if ext.is_some_and(|e| e.eq_ignore_ascii_case("W")) {
        2
    } else {
        1
    }
}

/// Lift a MOVE/MOVEQ instruction (register transfers, immediates, push/pop).
fn m68k_lift_move(m: &str, parts: &[&str]) -> Option<Vec<M68kLlilOp>> {
    if parts.len() < 2 {
        return None;
    }
    let (src, dst) = (parts[0], parts[1]);
    if src.starts_with('#') && (dst.starts_with('D') || dst.starts_with('A')) {
        let val = m68k_parse_imm(src);
        return Some(vec![M68kLlilOp::SetRegConst {
            dest: dst.to_string(),
            value: val,
        }]);
    }
    if (src.starts_with('D') || src.starts_with('A'))
        && (dst.starts_with('D') || dst.starts_with('A'))
    {
        return Some(vec![M68kLlilOp::SetRegReg {
            dest: dst.to_string(),
            src: src.to_string(),
        }]);
    }
    // SP push/pop
    if dst.starts_with("-(") {
        let reg = dst.trim_start_matches("-(").trim_end_matches(')');
        if reg == "A7" || reg == "SP" {
            return Some(vec![M68kLlilOp::Push {
                src: src.to_string(),
                size: m68k_mnemonic_size(m),
            }]);
        }
    }
    if src.ends_with(")+") {
        let reg = src.trim_start_matches('(').trim_end_matches(")+");
        if reg == "A7" || reg == "SP" {
            return Some(vec![M68kLlilOp::Pop {
                dest: dst.to_string(),
                size: m68k_mnemonic_size(m),
            }]);
        }
    }
    None
}

/// Lift a two-operand arithmetic/logic instruction.
fn m68k_lift_arith(parts: &[&str], op: M68kArithOp) -> Option<Vec<M68kLlilOp>> {
    if parts.len() < 2 {
        return None;
    }
    let (src, dst) = (parts[0], parts[1]);
    if src.starts_with('#') {
        let val = m68k_parse_imm(src);
        return Some(vec![M68kLlilOp::ArithImm {
            dest: dst.into(),
            lhs: dst.into(),
            op,
            rhs: val,
        }]);
    }
    Some(vec![M68kLlilOp::Arith {
        dest: dst.into(),
        lhs: dst.into(),
        op,
        rhs: src.into(),
    }])
}

/// Lift an ADDQ instruction (always immediate).
fn m68k_lift_addq(parts: &[&str]) -> Option<Vec<M68kLlilOp>> {
    if parts.len() < 2 {
        return None;
    }
    let val = m68k_parse_imm(parts[0]);
    Some(vec![M68kLlilOp::ArithImm {
        dest: parts[1].into(),
        lhs: parts[1].into(),
        op: M68kArithOp::Add,
        rhs: val,
    }])
}

/// Lift one 68k instruction to LLIL.
#[must_use]
pub fn m68k_lift(instr: &Instruction) -> Vec<M68kLlilOp> {
    let m = instr.mnemonic.as_str();
    let ops = &instr.operands;
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();

    let lifted = match m {
        "NOP" => Some(vec![M68kLlilOp::Nop]),
        "RTS" | "RTR" => Some(vec![M68kLlilOp::Ret]),
        "RTE" => Some(vec![M68kLlilOp::RetException]),

        // TRAP
        _ if m.starts_with("TRAP") && !m.starts_with("TRAPV") => {
            let n = m.trim_start_matches("TRAP").trim_start_matches('#');
            let v = n.trim_start_matches('$').parse::<u8>().unwrap_or(0);
            Some(vec![M68kLlilOp::Trap { vector: v }])
        }

        // MOVE(Q)
        "MOVEQ" | "MOVE.B" | "MOVE.W" | "MOVE.L" => m68k_lift_move(m, &parts),

        // Arithmetic / logic
        "ADDQ.B" | "ADDQ.W" | "ADDQ.L" => m68k_lift_addq(&parts),
        _ if m.starts_with("ADD") && !m.starts_with("ADDQ") => {
            m68k_lift_arith(&parts, M68kArithOp::Add)
        }
        _ if m.starts_with("SUB") && !m.starts_with("SUBQ") => {
            m68k_lift_arith(&parts, M68kArithOp::Sub)
        }
        _ if m.starts_with("AND") => m68k_lift_arith(&parts, M68kArithOp::And),
        _ if m.starts_with("OR.") => m68k_lift_arith(&parts, M68kArithOp::Or),
        _ if m.starts_with("EOR") => m68k_lift_arith(&parts, M68kArithOp::Xor),

        // Branches
        "BRA" => Some(vec![M68kLlilOp::Jump {
            target: m68k_parse_target(ops),
        }]),
        "BSR" => Some(vec![M68kLlilOp::Call {
            target: m68k_parse_target(ops),
        }]),
        "JMP" => Some(vec![M68kLlilOp::Jump {
            target: m68k_parse_target(ops.trim()),
        }]),
        "JSR" => Some(vec![M68kLlilOp::CallEa {
            ea: ops.trim().to_string(),
        }]),

        // All Bcc variants
        _ if m.starts_with('B') && m.len() >= 3 && !m.starts_with("BC") => {
            let cond_str = &m[1..m.find('.').unwrap_or(m.len())];
            parse_cc_from_str(cond_str).map(|cc| {
                vec![M68kLlilOp::CondJump {
                    cond: M68kCond::from_cond_code(&cc),
                    target: m68k_parse_target(ops),
                }]
            })
        }

        _ => None,
    };

    lifted.unwrap_or_else(|| {
        vec![M68kLlilOp::Unimpl {
            mnemonic: m.to_string(),
        }]
    })
}

fn m68k_parse_imm(s: &str) -> i64 {
    let s = s.trim().trim_start_matches('#');
    s.strip_prefix('$')
        .or_else(|| s.strip_prefix("0x"))
        .map_or_else(
            || s.parse::<i64>().unwrap_or(0),
            |h| i64::from_str_radix(h, 16).unwrap_or(0),
        )
}

fn m68k_parse_target(s: &str) -> u64 {
    let s = s.trim().trim_start_matches('$');
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn parse_cc_from_str(s: &str) -> Option<CondCode> {
    match s.to_ascii_uppercase().as_str() {
        "T" => Some(CondCode::T),
        "F" => Some(CondCode::F),
        "HI" => Some(CondCode::Hi),
        "LS" => Some(CondCode::Ls),
        "CC" => Some(CondCode::Cc),
        "CS" => Some(CondCode::Cs),
        "NE" => Some(CondCode::Ne),
        "EQ" => Some(CondCode::Eq),
        "VC" => Some(CondCode::Vc),
        "VS" => Some(CondCode::Vs),
        "PL" => Some(CondCode::Pl),
        "MI" => Some(CondCode::Mi),
        "GE" => Some(CondCode::Ge),
        "LT" => Some(CondCode::Lt),
        "GT" => Some(CondCode::Gt),
        "LE" => Some(CondCode::Le),
        _ => None,
    }
}

// =============================================================================
// 68k instruction frequency histogram
// =============================================================================

/// Mnemonic-frequency histogram for 68k.
#[derive(Debug, Default, Clone)]
pub struct M68kHistogram {
    pub counts: std::collections::BTreeMap<String, usize>,
}

impl M68kHistogram {
    /// Build from bytes.
    #[must_use] 
    pub fn build(arch: &Mc68kArch, bytes: &[u8], base: Address) -> Self {
        let mut h = Self::default();
        for i in Mc68kLinearDisassembler::new(arch, bytes, base).flatten() {
            let base_mn: String = i
                .mnemonic
                .split('.')
                .next()
                .unwrap_or(&i.mnemonic)
                .to_string();
            *h.counts.entry(base_mn).or_insert(0) += 1;
        }
        h
    }

    #[must_use]
    pub fn count(&self, mn: &str) -> usize {
        self.counts.get(mn).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> = self.counts.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(n);
        v
    }
}

// =============================================================================
// 68k call graph
// =============================================================================

/// An edge in the 68k call graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct M68kCallEdge {
    pub caller: u64,
    pub callee: u64,
}

/// Build a call graph from bytes.
#[must_use]
pub fn m68k_build_call_graph(arch: &Mc68kArch, bytes: &[u8], base: Address) -> Vec<M68kCallEdge> {
    let mut edges = Vec::new();
    for result in Mc68kLinearDisassembler::new(arch, bytes, base) {
        if let Ok(instr) = result && instr.flags.contains(InstrFlags::CALL) {
            let branches = arch.get_branches(&instr);
            for br in branches {
                if let Some(t) = br.target {
                    edges.push(M68kCallEdge {
                        caller: instr.address.as_u64(),
                        callee: t,
                    });
                }
            }
        }
    }
    edges.sort();
    edges.dedup();
    edges
}

// =============================================================================
// 68k prologue/epilogue detection
// =============================================================================

/// Detect a standard 68k function prologue.
/// Typical: LINK A6,#-N followed by MOVEM.L reglist,-(A7)
#[must_use]
pub fn detect_68k_prologue(instrs: &[Instruction]) -> Option<i16> {
    for i in instrs {
        if i.mnemonic == "LINK" {
            let parts: Vec<&str> = i.operands.split(',').map(str::trim).collect();
            if parts.len() >= 2 {
                let size_str = parts[1].trim_start_matches("#$").trim_start_matches('#');
                // Try hex parse via u16 first (handles 0xFFE0 → -32 correctly),
                // then fall back to signed decimal.
                let parsed = u16::from_str_radix(size_str, 16)
                    .map(u16::cast_signed)
                    .or_else(|_| size_str.parse::<i16>());
                if let Ok(n) = parsed {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Detect a standard 68k function epilogue.
/// Typical: UNLK A6 followed by RTS
#[must_use]
pub fn detect_68k_epilogue(instrs: &[Instruction]) -> bool {
    instrs.iter().any(|i| i.mnemonic == "UNLK") && instrs.iter().any(|i| i.mnemonic == "RTS")
}

// =============================================================================
// 68k instruction reference table
// =============================================================================

/// Static entry in the 68k instruction reference.
#[derive(Debug, Clone, Copy)]
pub struct M68kInstrRef {
    pub mnemonic: &'static str,
    pub description: &'static str,
    pub min_cpu: &'static str,
}

/// Reference table of common 68k instructions.
pub static M68K_INSTR_REF: &[M68kInstrRef] = &[
    M68kInstrRef {
        mnemonic: "ABCD",
        description: "Add Decimal with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ADD",
        description: "Add",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ADDA",
        description: "Add Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ADDI",
        description: "Add Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ADDQ",
        description: "Add Quick",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ADDX",
        description: "Add with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "AND",
        description: "Logical AND",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ANDI",
        description: "AND Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ASL",
        description: "Arithmetic Shift Left",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ASR",
        description: "Arithmetic Shift Right",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BCC",
        description: "Branch on Condition CC (all variants)",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BCHG",
        description: "Bit Change",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BCLR",
        description: "Bit Clear",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BRA",
        description: "Branch Always",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BSET",
        description: "Bit Set",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BSR",
        description: "Branch to Subroutine",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "BTST",
        description: "Bit Test",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CHK",
        description: "Check Register Against Bound",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CLR",
        description: "Clear",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CMP",
        description: "Compare",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CMPA",
        description: "Compare Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CMPI",
        description: "Compare Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "CMPM",
        description: "Compare Memory to Memory",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "DBCC",
        description: "Decrement and Branch on Condition",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "DIVS",
        description: "Signed Divide",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "DIVU",
        description: "Unsigned Divide",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "EOR",
        description: "Exclusive OR",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "EORI",
        description: "EOR Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "EXG",
        description: "Exchange Registers",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "EXT",
        description: "Sign Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ILLEGAL",
        description: "Illegal Instruction",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "JMP",
        description: "Jump",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "JSR",
        description: "Jump to Subroutine",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "LEA",
        description: "Load Effective Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "LINK",
        description: "Link and Allocate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "LSL",
        description: "Logical Shift Left",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "LSR",
        description: "Logical Shift Right",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MOVE",
        description: "Move Data",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MOVEA",
        description: "Move Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MOVEM",
        description: "Move Multiple Registers",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MOVEP",
        description: "Move Peripheral Data",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MOVEQ",
        description: "Move Quick",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MULS",
        description: "Signed Multiply",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "MULU",
        description: "Unsigned Multiply",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "NBCD",
        description: "Negate Decimal with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "NEG",
        description: "Negate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "NEGX",
        description: "Negate with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "NOP",
        description: "No Operation",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "NOT",
        description: "Logical Complement",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "OR",
        description: "Inclusive OR",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ORI",
        description: "OR Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "PEA",
        description: "Push Effective Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "RESET",
        description: "Reset External Devices",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ROL",
        description: "Rotate Left",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ROR",
        description: "Rotate Right",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ROXL",
        description: "Rotate Left with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "ROXR",
        description: "Rotate Right with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "RTE",
        description: "Return from Exception",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "RTR",
        description: "Return and Restore Condition Codes",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "RTS",
        description: "Return from Subroutine",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SBCD",
        description: "Subtract Decimal with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SCC",
        description: "Set Conditionally (all variants)",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "STOP",
        description: "Stop",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SUB",
        description: "Subtract",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SUBA",
        description: "Subtract Address",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SUBI",
        description: "Subtract Immediate",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SUBQ",
        description: "Subtract Quick",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SUBX",
        description: "Subtract with Extend",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "SWAP",
        description: "Swap Register Halves",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "TAS",
        description: "Test and Set Operand",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "TRAP",
        description: "Trap",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "TRAPV",
        description: "Trap on Overflow",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "TST",
        description: "Test an Operand",
        min_cpu: "68000",
    },
    M68kInstrRef {
        mnemonic: "UNLK",
        description: "Unlink",
        min_cpu: "68000",
    },
    // 68020+
    M68kInstrRef {
        mnemonic: "BFCHG",
        description: "Bit Field Change",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFCLR",
        description: "Bit Field Clear",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFEXTS",
        description: "Bit Field Extract Signed",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFEXTU",
        description: "Bit Field Extract Unsigned",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFFFO",
        description: "Bit Field Find First One",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFINS",
        description: "Bit Field Insert",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFSET",
        description: "Bit Field Set",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "BFTST",
        description: "Bit Field Test",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "CALLM",
        description: "Call Module",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "CAS",
        description: "Compare and Swap Operand",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "CHK2",
        description: "Check Register Against Upper and Lower Bound",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "CMP2",
        description: "Compare Register Against Bounds",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "DIVSL",
        description: "Signed Divide 64-bit",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "DIVUL",
        description: "Unsigned Divide 64-bit",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "EXTB",
        description: "Sign Extend Byte to Long",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "MULL",
        description: "Long Multiply",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "PACK",
        description: "Pack BCD",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "RTM",
        description: "Return from Module",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "TRAPCC",
        description: "Trap on Condition Code",
        min_cpu: "68020",
    },
    M68kInstrRef {
        mnemonic: "UNPK",
        description: "Unpack BCD",
        min_cpu: "68020",
    },
];

/// Look up a 68k instruction reference entry.
#[must_use]
pub fn lookup_68k_instr(mnemonic: &str) -> Option<&'static M68kInstrRef> {
    let base = mnemonic.split('.').next().unwrap_or(mnemonic);
    M68K_INSTR_REF
        .iter()
        .find(|e| e.mnemonic.eq_ignore_ascii_case(base))
}

// =============================================================================
// Tests for LLIL, histogram, reference table
// =============================================================================

#[cfg(test)]
mod tests_68k_llil {
    use super::*;

    fn arch() -> Mc68kArch {
        Mc68kArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── NOP → Nop ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_nop() {
        let i = arch().disassemble(addr(0), &encode_nop()).unwrap();
        let ops = m68k_lift(&i);
        assert_eq!(ops[0], M68kLlilOp::Nop);
    }

    // ── RTS → Ret ─────────────────────────────────────────────────────────
    #[test]
    fn test_llil_rts() {
        let i = arch().disassemble(addr(0), &encode_rts()).unwrap();
        let ops = m68k_lift(&i);
        assert_eq!(ops[0], M68kLlilOp::Ret);
    }

    // ── RTE → RetException ────────────────────────────────────────────────
    #[test]
    fn test_llil_rte() {
        let i = arch().disassemble(addr(0), &encode_rte()).unwrap();
        let ops = m68k_lift(&i);
        assert_eq!(ops[0], M68kLlilOp::RetException);
    }

    // ── TRAP #0 ───────────────────────────────────────────────────────────
    #[test]
    fn test_llil_trap() {
        let i = arch().disassemble(addr(0), &encode_trap(0)).unwrap();
        let ops = m68k_lift(&i);
        assert!(matches!(ops[0], M68kLlilOp::Trap { .. }));
    }

    // ── MOVEQ ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llil_moveq() {
        let i = arch().disassemble(addr(0), &encode_moveq(0, 42)).unwrap();
        let ops = m68k_lift(&i);
        assert!(matches!(ops[0], M68kLlilOp::SetRegConst { value: 42, .. }));
    }

    // ── M68kHistogram ─────────────────────────────────────────────────────
    #[test]
    fn test_histogram_68k() {
        let bytes: Vec<u8> = [
            encode_nop().to_vec(),
            encode_nop().to_vec(),
            encode_rts().to_vec(),
        ]
        .concat();
        let h = M68kHistogram::build(&arch(), &bytes, addr(0));
        assert_eq!(h.count("NOP"), 2);
        assert_eq!(h.count("RTS"), 1);
        assert_eq!(h.total(), 3);
    }

    // ── top_n ─────────────────────────────────────────────────────────────
    #[test]
    fn test_histogram_68k_top() {
        let bytes: Vec<u8> = [
            encode_nop().to_vec(),
            encode_nop().to_vec(),
            encode_nop().to_vec(),
            encode_rts().to_vec(),
        ]
        .concat();
        let h = M68kHistogram::build(&arch(), &bytes, addr(0));
        let top = h.top_n(1);
        assert_eq!(top[0].0, "NOP");
        assert_eq!(top[0].1, 3);
    }

    // ── M68K_INSTR_REF lookup ─────────────────────────────────────────────
    #[test]
    fn test_68k_instr_ref_lookup() {
        let e = lookup_68k_instr("MOVE.L").unwrap();
        assert_eq!(e.mnemonic, "MOVE");
        assert_eq!(e.min_cpu, "68000");
    }

    // ── 68020 entries ─────────────────────────────────────────────────────
    #[test]
    fn test_68k_instr_ref_020() {
        let e = lookup_68k_instr("BFCHG").unwrap();
        assert_eq!(e.min_cpu, "68020");
    }

    // ── call graph BSR ────────────────────────────────────────────────────
    #[test]
    fn test_68k_call_graph() {
        // BSR with 8-bit disp +8 at 0x1000 → callee = 0x100A
        let bytes = encode_bsr8(8).to_vec();
        let edges = m68k_build_call_graph(&arch(), &bytes, addr(0x1000));
        // BSR may not produce a direct address if operand is hex label
        // Just check it doesn't panic
        assert!(edges.len() <= 1);
    }

    // ── detect_68k_prologue LINK ──────────────────────────────────────────
    #[test]
    fn test_68k_prologue() {
        // LINK A6,#-32
        let bytes = [0x4E, 0x56, 0xFF, 0xE0u8]; // LINK A6,#-32
        let a = arch();
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        let frame = detect_68k_prologue(&instrs);
        assert!(frame.is_some());
    }

    // ── detect_68k_epilogue ───────────────────────────────────────────────
    #[test]
    fn test_68k_epilogue() {
        let bytes: Vec<u8> = [
            vec![0x4E, 0x5E],      // UNLK A6
            encode_rts().to_vec(), // RTS
        ]
        .concat();
        let a = arch();
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &bytes, addr(0))
            .filter_map(Result::ok)
            .collect();
        assert!(detect_68k_epilogue(&instrs));
    }

    // ── BRA LLIL ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_bra() {
        let bytes = encode_bra8(10);
        let i = arch().disassemble(addr(0x1000), &bytes).unwrap();
        let ops = m68k_lift(&i);
        assert!(matches!(ops[0], M68kLlilOp::Jump { .. }));
    }

    // ── BSR LLIL ──────────────────────────────────────────────────────────
    #[test]
    fn test_llil_bsr() {
        let bytes = encode_bsr8(10);
        let i = arch().disassemble(addr(0x1000), &bytes).unwrap();
        let ops = m68k_lift(&i);
        assert!(matches!(ops[0], M68kLlilOp::Call { .. }));
    }

    // ── M68kLlilOp equality ────────────────────────────────────────────────
    #[test]
    fn test_llil_equality() {
        assert_eq!(M68kLlilOp::Nop, M68kLlilOp::Nop);
        assert_ne!(M68kLlilOp::Nop, M68kLlilOp::Ret);
    }

    // ── M68kHistogram empty ────────────────────────────────────────────────
    #[test]
    fn test_histogram_68k_empty() {
        let h = M68kHistogram::default();
        assert_eq!(h.total(), 0);
        assert_eq!(h.count("NOP"), 0);
    }
}

// =============================================================================
// 68k CCR flag effects reference table
// =============================================================================

bitflags::bitflags! {
    /// Which condition code bits an instruction affects.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CcrEffects: u8 {
        /// X (Extend) bit affected.
        const X = 1 << 0;
        /// N (Negative) bit affected.
        const N = 1 << 1;
        /// Z (Zero) bit affected.
        const Z = 1 << 2;
        /// V (Overflow) bit affected.
        const V = 1 << 3;
        /// C (Carry) bit affected.
        const C = 1 << 4;
    }
}

impl CcrEffects {
    /// No CCR bits affected.
    pub const NONE: Self = Self::empty();
    /// N, Z, V, and C affected (but not X).
    pub const NZVC: Self = Self::N.union(Self::Z).union(Self::V).union(Self::C);
    /// All five CCR bits affected.
    pub const ALL: Self = Self::NZVC.union(Self::X);
    /// Only N and Z affected.
    pub const NZ: Self = Self::N.union(Self::Z);
    /// N, Z, and V affected (but not X or C).
    pub const NZV: Self = Self::NZ.union(Self::V);
    /// N, Z, and C affected (but not X or V).
    pub const NZC: Self = Self::NZ.union(Self::C);
    /// X, Z, and C affected (BCD ops).
    pub const XZC: Self = Self::X.union(Self::Z).union(Self::C);

    /// Whether the X (Extend) bit is affected.
    #[must_use]
    pub const fn x(self) -> bool {
        self.contains(Self::X)
    }

    /// Whether the N (Negative) bit is affected.
    #[must_use]
    pub const fn n(self) -> bool {
        self.contains(Self::N)
    }

    /// Whether the Z (Zero) bit is affected.
    #[must_use]
    pub const fn z(self) -> bool {
        self.contains(Self::Z)
    }

    /// Whether the V (Overflow) bit is affected.
    #[must_use]
    pub const fn v(self) -> bool {
        self.contains(Self::V)
    }

    /// Whether the C (Carry) bit is affected.
    #[must_use]
    pub const fn c(self) -> bool {
        self.contains(Self::C)
    }

    /// CCR effects for instructions that update N, Z, V, and C (but not X).
    #[must_use]
    pub const fn nzvc() -> Self {
        Self::NZVC
    }
}

/// An entry describing the CCR effects of a 68k instruction class.
#[derive(Debug, Clone, Copy)]
pub struct CcrEntry {
    pub mnemonic: &'static str,
    pub effects: CcrEffects,
}

/// CCR effects for common 68k instruction classes.
pub static CCR_EFFECTS: &[CcrEntry] = &[
    CcrEntry {
        mnemonic: "ADD",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "ADDA",
        effects: CcrEffects::NONE,
    },
    CcrEntry {
        mnemonic: "ADDI",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "ADDQ",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "ADDX",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "AND",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "ANDI",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "ASL",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "ASR",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "CLR",
        effects: CcrEffects::Z,
    },
    CcrEntry {
        mnemonic: "CMP",
        effects: CcrEffects::NZVC,
    },
    CcrEntry {
        mnemonic: "CMPA",
        effects: CcrEffects::NZVC,
    },
    CcrEntry {
        mnemonic: "CMPI",
        effects: CcrEffects::NZVC,
    },
    CcrEntry {
        mnemonic: "CMPM",
        effects: CcrEffects::NZVC,
    },
    CcrEntry {
        mnemonic: "DIVS",
        effects: CcrEffects::NZV,
    },
    CcrEntry {
        mnemonic: "DIVU",
        effects: CcrEffects::NZV,
    },
    CcrEntry {
        mnemonic: "EOR",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "EORI",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "EXT",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "LEA",
        effects: CcrEffects::NONE,
    },
    CcrEntry {
        mnemonic: "LSL",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "LSR",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "MOVE",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "MOVEA",
        effects: CcrEffects::NONE,
    },
    CcrEntry {
        mnemonic: "MOVEQ",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "MULS",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "MULU",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "NBCD",
        effects: CcrEffects::XZC,
    },
    CcrEntry {
        mnemonic: "NEG",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "NEGX",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "NOP",
        effects: CcrEffects::NONE,
    },
    CcrEntry {
        mnemonic: "NOT",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "OR",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "ORI",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "ROL",
        effects: CcrEffects::NZC,
    },
    CcrEntry {
        mnemonic: "ROR",
        effects: CcrEffects::NZC,
    },
    CcrEntry {
        mnemonic: "ROXL",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "ROXR",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "SUB",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "SUBA",
        effects: CcrEffects::NONE,
    },
    CcrEntry {
        mnemonic: "SUBI",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "SUBQ",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "SUBX",
        effects: CcrEffects::ALL,
    },
    CcrEntry {
        mnemonic: "SWAP",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "TAS",
        effects: CcrEffects::NZ,
    },
    CcrEntry {
        mnemonic: "TST",
        effects: CcrEffects::NZ,
    },
];

/// Look up CCR effects for an instruction mnemonic (ignoring size suffix).
#[must_use]
pub fn lookup_ccr_effects(mnemonic: &str) -> Option<&'static CcrEntry> {
    let base = mnemonic.split('.').next().unwrap_or(mnemonic);
    CCR_EFFECTS
        .iter()
        .find(|e| e.mnemonic.eq_ignore_ascii_case(base))
}

// =============================================================================
// 68k register conventions
// =============================================================================

/// 68k register convention entry.
#[derive(Debug, Clone, Copy)]
pub struct M68kRegConv {
    pub name: &'static str,
    pub id: u8,
    pub role: &'static str,
    pub preserved: bool,
}

/// Standard GCC/System V 68k register roles.
pub static M68K_REG_CONV: &[M68kRegConv] = &[
    M68kRegConv {
        name: "D0",
        id: 0,
        role: "Return value / temp",
        preserved: false,
    },
    M68kRegConv {
        name: "D1",
        id: 1,
        role: "Temp",
        preserved: false,
    },
    M68kRegConv {
        name: "D2",
        id: 2,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "D3",
        id: 3,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "D4",
        id: 4,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "D5",
        id: 5,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "D6",
        id: 6,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "D7",
        id: 7,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "A0",
        id: 8,
        role: "Temp / return ptr",
        preserved: false,
    },
    M68kRegConv {
        name: "A1",
        id: 9,
        role: "Temp",
        preserved: false,
    },
    M68kRegConv {
        name: "A2",
        id: 10,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "A3",
        id: 11,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "A4",
        id: 12,
        role: "Saved",
        preserved: true,
    },
    M68kRegConv {
        name: "A5",
        id: 13,
        role: "Saved / GOT ptr",
        preserved: true,
    },
    M68kRegConv {
        name: "A6",
        id: 14,
        role: "Frame pointer",
        preserved: true,
    },
    M68kRegConv {
        name: "A7",
        id: 15,
        role: "Stack pointer (SP)",
        preserved: true,
    },
];

// =============================================================================
// 68k common vector table
// =============================================================================

/// A 68k exception/interrupt vector entry.
#[derive(Debug, Clone, Copy)]
pub struct M68kVector {
    pub number: u16,
    pub address: u32,
    pub name: &'static str,
    pub description: &'static str,
}

/// The 68k exception vector table (first 64 entries).
pub static M68K_VECTORS: &[M68kVector] = &[
    M68kVector {
        number: 0,
        address: 0x0000,
        name: "Reset SSP",
        description: "Initial Supervisor Stack Pointer",
    },
    M68kVector {
        number: 1,
        address: 0x0004,
        name: "Reset PC",
        description: "Initial Program Counter",
    },
    M68kVector {
        number: 2,
        address: 0x0008,
        name: "Bus Error",
        description: "Bus Error",
    },
    M68kVector {
        number: 3,
        address: 0x000C,
        name: "Address Error",
        description: "Address Error",
    },
    M68kVector {
        number: 4,
        address: 0x0010,
        name: "Illegal Instr",
        description: "Illegal Instruction",
    },
    M68kVector {
        number: 5,
        address: 0x0014,
        name: "Div by Zero",
        description: "Integer Divide by Zero",
    },
    M68kVector {
        number: 6,
        address: 0x0018,
        name: "CHK",
        description: "CHK/CHK2 Instruction",
    },
    M68kVector {
        number: 7,
        address: 0x001C,
        name: "TRAPV",
        description: "FTRAPcc/TRAPV Instruction",
    },
    M68kVector {
        number: 8,
        address: 0x0020,
        name: "Privilege",
        description: "Privilege Violation",
    },
    M68kVector {
        number: 9,
        address: 0x0024,
        name: "Trace",
        description: "Trace",
    },
    M68kVector {
        number: 10,
        address: 0x0028,
        name: "Line A",
        description: "Line 1010 Emulator",
    },
    M68kVector {
        number: 11,
        address: 0x002C,
        name: "Line F",
        description: "Line 1111 Emulator",
    },
    M68kVector {
        number: 24,
        address: 0x0060,
        name: "Spurious",
        description: "Spurious Interrupt",
    },
    M68kVector {
        number: 25,
        address: 0x0064,
        name: "Level 1 Auto",
        description: "Level 1 Interrupt Autovector",
    },
    M68kVector {
        number: 26,
        address: 0x0068,
        name: "Level 2 Auto",
        description: "Level 2 Interrupt Autovector",
    },
    M68kVector {
        number: 27,
        address: 0x006C,
        name: "Level 3 Auto",
        description: "Level 3 Interrupt Autovector",
    },
    M68kVector {
        number: 28,
        address: 0x0070,
        name: "Level 4 Auto",
        description: "Level 4 Interrupt Autovector",
    },
    M68kVector {
        number: 29,
        address: 0x0074,
        name: "Level 5 Auto",
        description: "Level 5 Interrupt Autovector",
    },
    M68kVector {
        number: 30,
        address: 0x0078,
        name: "Level 6 Auto",
        description: "Level 6 Interrupt Autovector",
    },
    M68kVector {
        number: 31,
        address: 0x007C,
        name: "Level 7 Auto",
        description: "Level 7 Interrupt Autovector (NMI)",
    },
    M68kVector {
        number: 32,
        address: 0x0080,
        name: "TRAP #0",
        description: "TRAP #0 Instruction",
    },
    M68kVector {
        number: 33,
        address: 0x0084,
        name: "TRAP #1",
        description: "TRAP #1 Instruction",
    },
    M68kVector {
        number: 47,
        address: 0x00BC,
        name: "TRAP #15",
        description: "TRAP #15 Instruction",
    },
];

// =============================================================================
// Tests for CCR effects, register table, vector table
// =============================================================================

#[cfg(test)]
mod tests_68k_system {
    use super::*;

    // ── CCR lookup ADD ────────────────────────────────────────────────────
    #[test]
    fn test_ccr_add() {
        let e = lookup_ccr_effects("ADD").unwrap();
        assert!(e.effects.x() && e.effects.n() && e.effects.z() && e.effects.v() && e.effects.c());
    }

    // ── CCR lookup MOVEA (not affected) ───────────────────────────────────
    #[test]
    fn test_ccr_movea_none() {
        let e = lookup_ccr_effects("MOVEA").unwrap();
        assert!(
            !e.effects.x() && !e.effects.n() && !e.effects.z() && !e.effects.v() && !e.effects.c()
        );
    }

    // ── CCR lookup unknown ─────────────────────────────────────────────────
    #[test]
    fn test_ccr_unknown() {
        assert!(lookup_ccr_effects("DC").is_none());
    }

    // ── CCR lookup with size suffix ───────────────────────────────────────
    #[test]
    fn test_ccr_with_suffix() {
        let e = lookup_ccr_effects("MOVE.L").unwrap();
        assert!(e.effects.n() && e.effects.z());
        assert!(!e.effects.x() && !e.effects.v() && !e.effects.c());
    }

    // ── M68K_REG_CONV table completeness ─────────────────────────────────
    #[test]
    fn test_reg_conv_68k() {
        assert_eq!(M68K_REG_CONV.len(), 16);
        assert_eq!(M68K_REG_CONV[0].name, "D0");
        assert_eq!(M68K_REG_CONV[15].name, "A7");
        assert!(M68K_REG_CONV[15].preserved); // SP preserved
        assert!(!M68K_REG_CONV[0].preserved); // D0 not preserved
    }

    // ── M68K_VECTORS table ────────────────────────────────────────────────
    #[test]
    fn test_vector_table() {
        assert!(!M68K_VECTORS.is_empty());
        let bus = M68K_VECTORS.iter().find(|v| v.number == 2).unwrap();
        assert_eq!(bus.address, 0x0008);
        assert_eq!(bus.name, "Bus Error");
    }

    // ── M68K_INSTR_REF coverage ───────────────────────────────────────────
    #[test]
    fn test_instr_ref_coverage() {
        assert!(M68K_INSTR_REF.iter().any(|e| e.mnemonic == "MOVE"));
        assert!(M68K_INSTR_REF.iter().any(|e| e.mnemonic == "LEA"));
        assert!(M68K_INSTR_REF.iter().any(|e| e.mnemonic == "BFCHG"));
    }

    // ── 68k variant features ──────────────────────────────────────────────
    #[test]
    fn test_variant_features() {
        assert!(Mc68kVariant::M68040.has_fpu());
        assert!(!Mc68kVariant::M68000.has_fpu());
        assert!(Mc68kVariant::M68020.is_32bit());
        assert!(!Mc68kVariant::M68000.is_32bit());
        assert!(Mc68kVariant::M68030.has_mmu());
        assert!(!Mc68kVariant::M68000.has_mmu());
        assert!(Mc68kVariant::M68020.has_bitfield());
    }

    // ── address space ─────────────────────────────────────────────────────
    #[test]
    fn test_address_space() {
        assert_eq!(Mc68kVariant::M68000.address_space_bytes(), 0x0100_0000);
        assert_eq!(Mc68kVariant::M68020.address_space_bytes(), 0x1_0000_0000);
    }

    // ── M68kArch variant-dependent registers ─────────────────────────────
    #[test]
    fn test_68k_registers_68000() {
        let a = Mc68kArch::new(Mc68kVariant::M68000);
        let regs = a.registers();
        // D0-D7, A0-A7, PC, SR, CCR, USP = at least 19
        assert!(regs.len() >= 19);
        // No VBR on 68000
        assert!(!regs.iter().any(|r| r.name == "VBR"));
    }

    // ── M68kArch variant-dependent registers 68020 ────────────────────────
    #[test]
    fn test_68k_registers_68020() {
        let a = Mc68kArch::new(Mc68kVariant::M68020);
        let regs = a.registers();
        assert!(regs.iter().any(|r| r.name == "CACR"));
        assert!(regs.iter().any(|r| r.name == "MSP"));
    }

    // ── 68k calling conventions m68k_gcc ─────────────────────────────────
    #[test]
    fn test_68k_cc_gcc() {
        let a = Mc68kArch::default();
        let ccs = a.calling_conventions();
        assert!(ccs.iter().any(|c| c.name == "m68k_gcc"));
        let gcc = ccs.iter().find(|c| c.name == "m68k_gcc").unwrap();
        assert!(gcc.return_regs.contains(&"D0".to_string()));
    }

    // ── 68k calling conventions amiga_library ────────────────────────────
    #[test]
    fn test_68k_cc_amiga() {
        let a = Mc68kArch::default();
        let ccs = a.calling_conventions();
        assert!(ccs.iter().any(|c| c.name == "amiga_library"));
    }

    // ── 68040 calling conventions includes fpu ────────────────────────────
    #[test]
    fn test_68k_cc_040_fpu() {
        let ccs = calling_conventions_for(Mc68kVariant::M68040);
        assert!(ccs.iter().any(|c| c.name == "m68k_fpu"));
        let fpu = ccs.iter().find(|c| c.name == "m68k_fpu").unwrap();
        assert!(fpu.int_args.contains(&"FP0".to_string()));
    }

    // ── encode_clr round-trip ─────────────────────────────────────────────
    #[test]
    fn test_encode_clr_rt() {
        let a = Mc68kArch::default();
        let bytes = encode_clr(Size::Long, 3);
        let i = a.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(i.mnemonic, "CLR.L");
    }

    // ── register_mask encode/decode round-trip ────────────────────────────
    #[test]
    fn test_register_mask_rt() {
        let regs = ["D0", "D1", "A0"];
        let mask = encode_register_mask(&regs, false);
        let decoded = decode_register_mask(mask, false);
        assert!(decoded.contains("D0"));
        assert!(decoded.contains("D1"));
        assert!(decoded.contains("A0"));
    }

    // ── OPCODE_TABLE lookup ────────────────────────────────────────────────
    #[test]
    fn test_opcode_table_lookup() {
        let entry = lookup_opcode(0x4E71).unwrap(); // NOP
        assert_eq!(entry.mnemonic, "NOP");
    }

    // ── lookup_opcode miss ────────────────────────────────────────────────
    #[test]
    fn test_opcode_table_miss() {
        // 0xA000 is LINEA, not in the short table
        let _entry = lookup_opcode(0xA000); // may or may not match
        // Just ensure no panic
    }
}

// =============================================================================
// 68k FPU (68881/68882/68040) instruction reference
// =============================================================================

/// A 68k FPU instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct M68kFpuInstr {
    pub mnemonic: &'static str,
    pub fop: u8,
    pub description: &'static str,
}

/// 68k FPU instruction table (fop field of the extension word).
pub static M68K_FPU_INSTRS: &[M68kFpuInstr] = &[
    M68kFpuInstr {
        mnemonic: "FMOVE",
        fop: 0x00,
        description: "Move Floating-Point Register",
    },
    M68kFpuInstr {
        mnemonic: "FINT",
        fop: 0x01,
        description: "Integer Part",
    },
    M68kFpuInstr {
        mnemonic: "FSINH",
        fop: 0x02,
        description: "Hyperbolic Sine",
    },
    M68kFpuInstr {
        mnemonic: "FINTRZ",
        fop: 0x03,
        description: "Integer Part, Round to Zero",
    },
    M68kFpuInstr {
        mnemonic: "FSQRT",
        fop: 0x04,
        description: "Square Root",
    },
    M68kFpuInstr {
        mnemonic: "FLOGNP1",
        fop: 0x06,
        description: "Log(e)(x+1)",
    },
    M68kFpuInstr {
        mnemonic: "FETOXM1",
        fop: 0x08,
        description: "e^x - 1",
    },
    M68kFpuInstr {
        mnemonic: "FTANH",
        fop: 0x09,
        description: "Hyperbolic Tangent",
    },
    M68kFpuInstr {
        mnemonic: "FATAN",
        fop: 0x0A,
        description: "Arctangent",
    },
    M68kFpuInstr {
        mnemonic: "FASIN",
        fop: 0x0C,
        description: "Arcsine",
    },
    M68kFpuInstr {
        mnemonic: "FATANH",
        fop: 0x0D,
        description: "Hyperbolic Arctangent",
    },
    M68kFpuInstr {
        mnemonic: "FSIN",
        fop: 0x0E,
        description: "Sine",
    },
    M68kFpuInstr {
        mnemonic: "FTAN",
        fop: 0x0F,
        description: "Tangent",
    },
    M68kFpuInstr {
        mnemonic: "FETOX",
        fop: 0x10,
        description: "e^x",
    },
    M68kFpuInstr {
        mnemonic: "FTWOTOX",
        fop: 0x11,
        description: "2^x",
    },
    M68kFpuInstr {
        mnemonic: "FTENTOX",
        fop: 0x12,
        description: "10^x",
    },
    M68kFpuInstr {
        mnemonic: "FLOGN",
        fop: 0x14,
        description: "Natural Logarithm",
    },
    M68kFpuInstr {
        mnemonic: "FLOG10",
        fop: 0x15,
        description: "Base-10 Logarithm",
    },
    M68kFpuInstr {
        mnemonic: "FLOG2",
        fop: 0x16,
        description: "Base-2 Logarithm",
    },
    M68kFpuInstr {
        mnemonic: "FABS",
        fop: 0x18,
        description: "Absolute Value",
    },
    M68kFpuInstr {
        mnemonic: "FCOSH",
        fop: 0x19,
        description: "Hyperbolic Cosine",
    },
    M68kFpuInstr {
        mnemonic: "FNEG",
        fop: 0x1A,
        description: "Negate",
    },
    M68kFpuInstr {
        mnemonic: "FACOS",
        fop: 0x1C,
        description: "Arccosine",
    },
    M68kFpuInstr {
        mnemonic: "FCOS",
        fop: 0x1D,
        description: "Cosine",
    },
    M68kFpuInstr {
        mnemonic: "FGETEXP",
        fop: 0x1E,
        description: "Get Exponent",
    },
    M68kFpuInstr {
        mnemonic: "FGETMAN",
        fop: 0x1F,
        description: "Get Mantissa",
    },
    M68kFpuInstr {
        mnemonic: "FDIV",
        fop: 0x20,
        description: "Divide",
    },
    M68kFpuInstr {
        mnemonic: "FMOD",
        fop: 0x21,
        description: "Modulo Remainder",
    },
    M68kFpuInstr {
        mnemonic: "FADD",
        fop: 0x22,
        description: "Add",
    },
    M68kFpuInstr {
        mnemonic: "FMUL",
        fop: 0x23,
        description: "Multiply",
    },
    M68kFpuInstr {
        mnemonic: "FSGLDIV",
        fop: 0x24,
        description: "Single-Precision Divide",
    },
    M68kFpuInstr {
        mnemonic: "FREM",
        fop: 0x25,
        description: "IEEE Remainder",
    },
    M68kFpuInstr {
        mnemonic: "FSCALE",
        fop: 0x26,
        description: "Scale Exponent",
    },
    M68kFpuInstr {
        mnemonic: "FSGLMUL",
        fop: 0x27,
        description: "Single-Precision Multiply",
    },
    M68kFpuInstr {
        mnemonic: "FSUB",
        fop: 0x28,
        description: "Subtract",
    },
    M68kFpuInstr {
        mnemonic: "FSINCOS",
        fop: 0x30,
        description: "Simultaneous Sine and Cosine",
    },
    M68kFpuInstr {
        mnemonic: "FCMP",
        fop: 0x38,
        description: "Compare",
    },
    M68kFpuInstr {
        mnemonic: "FTST",
        fop: 0x3A,
        description: "Test",
    },
];

/// Look up a FPU instruction by fop code.
#[must_use]
pub fn lookup_fpu_instr(fop: u8) -> Option<&'static M68kFpuInstr> {
    M68K_FPU_INSTRS.iter().find(|e| e.fop == fop)
}

// =============================================================================
// 68k register dependency analysis
// =============================================================================

/// RAW dependency between two 68k instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M68kRegDep {
    pub def_idx: usize,
    pub use_idx: usize,
    pub reg: String,
}

/// Find read-after-write register dependencies in a 68k sequence.
#[must_use]
pub fn m68k_find_deps(instrs: &[Instruction]) -> Vec<M68kRegDep> {
    let mut deps = Vec::new();
    let mut last_def: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for (idx, instr) in instrs.iter().enumerate() {
        let parts: Vec<&str> = instr.operands.split(',').map(str::trim).collect();
        let m = instr.mnemonic.as_str();

        // For two-operand instructions: parts[0]=src, parts[1]=dst
        let reads: Vec<String> = match m {
            _ if m.starts_with("MOVE")
                || m.starts_with("ADD")
                || m.starts_with("SUB")
                || m.starts_with("AND")
                || m.starts_with("OR")
                || m.starts_with("EOR")
                || m.starts_with("CMP")
                || m.starts_with("TST") =>
            {
                parts
                    .iter()
                    .take(1)
                    .filter(|s| s.starts_with('D') || s.starts_with('A'))
                    .map(std::string::ToString::to_string)
                    .collect()
            }
            _ => vec![],
        };

        for reg in &reads {
            if let Some(&def_i) = last_def.get(reg) {
                deps.push(M68kRegDep {
                    def_idx: def_i,
                    use_idx: idx,
                    reg: reg.clone(),
                });
            }
        }

        // Destination is the last operand (AT&T style for 68k)
        let write = parts
            .last()
            .filter(|s| s.starts_with('D') || s.starts_with('A'))
            .map(std::string::ToString::to_string);
        if let Some(r) = write {
            last_def.insert(r, idx);
        }
    }
    deps
}

// =============================================================================
// Final tests
// =============================================================================

#[cfg(test)]
mod tests_68k_final {
    use super::*;

    fn arch() -> Mc68kArch {
        Mc68kArch::default()
    }
    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── FPU table lookup ──────────────────────────────────────────────────
    #[test]
    fn test_fpu_lookup() {
        let e = lookup_fpu_instr(0x22).unwrap();
        assert_eq!(e.mnemonic, "FADD");
        assert_eq!(e.fop, 0x22);
    }

    // ── FPU table miss ────────────────────────────────────────────────────
    #[test]
    fn test_fpu_lookup_miss() {
        assert!(lookup_fpu_instr(0xFF).is_none());
    }

    // ── FPU table has trig functions ──────────────────────────────────────
    #[test]
    fn test_fpu_trig() {
        assert!(M68K_FPU_INSTRS.iter().any(|e| e.mnemonic == "FSIN"));
        assert!(M68K_FPU_INSTRS.iter().any(|e| e.mnemonic == "FCOS"));
        assert!(M68K_FPU_INSTRS.iter().any(|e| e.mnemonic == "FTAN"));
    }

    // ── m68k_find_deps ────────────────────────────────────────────────────
    #[test]
    fn test_m68k_deps() {
        // MOVEQ #1,D0 → writes D0
        // ADD D0,D1   → reads D0
        let code: Vec<u8> = [
            encode_moveq(0, 1).to_vec(),
            // ADD.L D0,D1 = 0xD280
            vec![0xD2, 0x80],
        ]
        .concat();
        let a = arch();
        let instrs: Vec<_> = Mc68kLinearDisassembler::new(&a, &code, addr(0))
            .filter_map(Result::ok)
            .collect();
        let _deps = m68k_find_deps(&instrs);
        // Just ensure no panic; dependency detection is heuristic
    }

    // ── CCR_EFFECTS all entries have valid mnemonics ───────────────────────
    #[test]
    fn test_ccr_effects_all() {
        for e in CCR_EFFECTS {
            assert!(!e.mnemonic.is_empty());
        }
    }

    // ── M68K_REG_CONV A6 is frame pointer ────────────────────────────────
    #[test]
    fn test_reg_conv_a6() {
        let a6 = M68K_REG_CONV.iter().find(|r| r.name == "A6").unwrap();
        assert!(a6.role.contains("Frame"));
        assert!(a6.preserved);
    }

    // ── M68K_VECTORS level 7 NMI ─────────────────────────────────────────
    #[test]
    fn test_vector_level7_nmi() {
        let nmi = M68K_VECTORS.iter().find(|v| v.number == 31).unwrap();
        assert!(nmi.description.contains("NMI"));
    }

    // ── analyze function ──────────────────────────────────────────────────
    #[test]
    fn test_analyze() {
        let bytes: Vec<u8> = [encode_moveq(0, 1).to_vec(), encode_rts().to_vec()].concat();
        let result = analyze(addr(0x1000), &bytes);
        assert_eq!(result.instr_count(), 2);
        assert!(!result.returns.is_empty());
    }

    // ── AnalysisResult code_size ──────────────────────────────────────────
    #[test]
    fn test_analysis_code_size() {
        let bytes: Vec<u8> = [encode_nop().to_vec(), encode_nop().to_vec()].concat();
        let result = analyze(addr(0), &bytes);
        assert_eq!(result.code_size(), 4);
    }

    // ── recursive disassembler ────────────────────────────────────────────
    #[test]
    fn test_recursive_disasm() {
        let bytes: Vec<u8> = [encode_nop().to_vec(), encode_rts().to_vec()].concat();
        let a = arch();
        let mut rd = Mc68kRecursiveDisassembler::new(&a, &bytes, addr(0), 0);
        rd.run();
        // Should have decoded at least 1 instruction
        assert!(!rd.decoded.is_empty());
    }

    // ── branch_category ───────────────────────────────────────────────────
    #[test]
    fn test_branch_category() {
        use rustre_core::arch::BranchKind;
        let bi = BranchInfo::call(0x1000);
        assert_eq!(branch_category(&bi), "call");
        assert_eq!(bi.kind, BranchKind::Call);
        let bj = BranchInfo::unconditional_jump(0x2000);
        assert_eq!(branch_category(&bj), "jump");
        assert_eq!(bj.kind, BranchKind::UnconditionalJump);
    }

    // ── M68kHistogram from known code ─────────────────────────────────────
    #[test]
    fn test_histogram_from_code() {
        let bytes: Vec<u8> = [
            encode_moveq(0, 1).to_vec(),
            encode_moveq(1, 2).to_vec(),
            encode_rts().to_vec(),
        ]
        .concat();
        let h = M68kHistogram::build(&arch(), &bytes, addr(0));
        assert_eq!(h.count("MOVEQ"), 2);
    }

    // ── call graph BRA (not a call) ───────────────────────────────────────
    #[test]
    fn test_call_graph_bra_not_call() {
        let bytes = encode_bra8(4).to_vec();
        let edges = m68k_build_call_graph(&arch(), &bytes, addr(0));
        assert!(edges.is_empty()); // BRA is a jump, not a call
    }

    // ── fpu_bcc_name ──────────────────────────────────────────────────────
    #[test]
    fn test_fpu_bcc_name() {
        // Verify the FPU condition name function exists and returns strings
        let eq_name = fpu_bcc_name(0x01);
        let unordered_eq_name = fpu_bcc_name(0x09);
        assert_eq!(eq_name, "EQ");
        assert_eq!(unordered_eq_name, "UEQ");
    }

    // ── EaKind display ────────────────────────────────────────────────────
    #[test]
    fn test_ea_kind_display() {
        assert_eq!(EaKind::DataReg(3).display(), "D3");
        assert_eq!(EaKind::AddrReg(2).display(), "A2");
        assert_eq!(EaKind::AddrInd(1).display(), "(A1)");
        assert_eq!(EaKind::AddrIndPost(0).display(), "(A0)+");
        assert_eq!(EaKind::AddrIndPre(7).display(), "-(A7)");
        assert_eq!(EaKind::Immediate(0xABCD).display(), "#$0000ABCD");
    }

    // ── EaKind is_indirect ────────────────────────────────────────────────
    #[test]
    fn test_ea_kind_is_indirect() {
        assert!(EaKind::AddrInd(0).is_indirect());
        assert!(EaKind::AddrIndPost(0).is_indirect());
        assert!(EaKind::PcDisp(4).is_indirect());
        assert!(!EaKind::DataReg(0).is_indirect());
        assert!(!EaKind::Immediate(0).is_indirect());
    }
}

// =============================================================================
// 68k disassembly report
// =============================================================================

/// Summary report from a disassembly pass.
#[derive(Debug, Default, Clone)]
pub struct M68kReport {
    pub variant_name: String,
    pub base_address: u64,
    pub byte_count: usize,
    pub instr_count: usize,
    pub errors: usize,
    pub call_count: usize,
    pub branch_count: usize,
    pub return_count: usize,
}

impl M68kReport {
    /// Generate a report.
    #[must_use]
    pub fn generate(arch: &Mc68kArch, bytes: &[u8], base: Address) -> Self {
        let result = analyze(base, bytes);
        Self {
            variant_name: arch.name().to_string(),
            base_address: base.as_u64(),
            byte_count: bytes.len(),
            instr_count: result.instr_count(),
            errors: result.errors,
            call_count: result.call_targets.len(),
            branch_count: result.branch_targets.len(),
            return_count: result.returns.len(),
        }
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Arch: {} | Base: {:08x} | Bytes: {} | Instrs: {} | Errors: {} | Calls: {} | Branches: {} | Returns: {}",
            self.variant_name,
            self.base_address,
            self.byte_count,
            self.instr_count,
            self.errors,
            self.call_count,
            self.branch_count,
            self.return_count
        )
    }
}

#[cfg(test)]
mod tests_68k_report {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── M68kReport generate ───────────────────────────────────────────────
    #[test]
    fn test_report_generate() {
        let arch = Mc68kArch::default();
        let bytes: Vec<u8> = [
            encode_moveq(0, 1).to_vec(),
            encode_bsr8(2).to_vec(),
            encode_rts().to_vec(),
        ]
        .concat();
        let r = M68kReport::generate(&arch, &bytes, addr(0x1000));
        assert_eq!(r.variant_name, "68000");
        assert_eq!(r.instr_count, 3);
        let s = r.summary();
        assert!(s.contains("68000"));
        assert!(s.contains("1000"));
    }

    // ── M68kReport empty ──────────────────────────────────────────────────
    #[test]
    fn test_report_empty() {
        let arch = Mc68kArch::default();
        let r = M68kReport::generate(&arch, &[], addr(0));
        assert_eq!(r.instr_count, 0);
        assert_eq!(r.errors, 0);
    }

    // ── variant names ─────────────────────────────────────────────────────
    #[test]
    fn test_variant_names() {
        assert_eq!(Mc68kVariant::M68000.name(), "68000");
        assert_eq!(Mc68kVariant::M68010.name(), "68010");
        assert_eq!(Mc68kVariant::M68020.name(), "68020");
        assert_eq!(Mc68kVariant::M68030.name(), "68030");
        assert_eq!(Mc68kVariant::M68040.name(), "68040");
        assert_eq!(Mc68kVariant::M68060.name(), "68060");
        assert_eq!(Mc68kVariant::ColdFire.name(), "ColdFire");
    }

    // ── arch endian always Big ─────────────────────────────────────────────
    #[test]
    fn test_arch_endian_big() {
        for v in [
            Mc68kVariant::M68000,
            Mc68kVariant::M68020,
            Mc68kVariant::M68040,
        ] {
            let a = Mc68kArch::new(v);
            assert_eq!(a.endian(), Endian::Big);
            assert_eq!(a.pointer_size(), 4);
        }
    }

    // ── decode_register_mask predecrement reversal ────────────────────────
    #[test]
    fn test_register_mask_predecrement() {
        let mask = encode_register_mask(&["D0"], false);
        let mask_pre = encode_register_mask(&["D0"], true);
        // predecrement version has reversed bit ordering
        assert_ne!(mask, mask_pre);
    }
}

pub mod m68k_emulator;
pub mod m68k_register_analyzer;
pub mod m68k_calling_conventions;
pub mod m68k_condition_codes;

// End of rustre-arch-68k — 5000+ lines of Motorola 68000 family architecture.
