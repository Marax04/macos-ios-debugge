//! `m68k_disassembler_ext` — Extended M68K disassembly for FPU (68881/68882),
//! MMU (68030/68040 PMMU), and CPU32 (68332/68340) instruction sets.
//!
//! Provides:
//! - [`FpuInsn`] — Decoded FPU instruction with operand formatting.
//! - [`MmuInsn`] — Decoded MMU instruction.
//! - [`Cpu32Insn`] — Decoded CPU32 table-driven branch instruction.
//! - [`M68kDisassemblerExt`] — Facade that attempts FPU / MMU / CPU32
//!   decoding before falling back to the base decoder.

use serde::{Deserialize, Serialize};

use crate::{Size, Mc68kVariant};

// ─────────────────────────────────────────────────────────────────────────────
// FPU register / format / condition tables
// ─────────────────────────────────────────────────────────────────────────────

/// FPU data register format specifier (bits 12:10 of FPU operation word).
///
/// This is the **decoder-facing** superset of the ISA-catalog format enum.
/// When the `R/M` bit of the FPU command word is 0 the same 3-bit field
/// selects a *source FP register* rather than a memory format; that case is
/// represented by the `FpRegister` sentinel variant.
///
/// For the pure ISA-catalog view (no `FpRegister`, no `serde`, returns
/// `Option` from `from_bits`) see
/// [`crate::m68k_extensions::FpuFormat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FpuFormat {
    /// 32-bit integer (long).
    Long,
    /// Single-precision 32-bit float.
    Single,
    /// Extended-precision 96-bit float.
    Extended,
    /// Packed decimal real (12 bytes).
    PackedDecimal,
    /// 16-bit integer (word).
    Word,
    /// Double-precision 64-bit float.
    Double,
    /// 8-bit integer (byte).
    Byte,
    /// FP register.
    FpRegister,
}

impl FpuFormat {
    /// Decode from 3-bit source specifier field.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 7 {
            0 => Self::Long,
            1 => Self::Single,
            2 => Self::Extended,
            3 => Self::PackedDecimal,
            4 => Self::Word,
            5 => Self::Double,
            6 => Self::Byte,
            _ => Self::FpRegister,
        }
    }

    /// Assembly suffix for this format.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Long => ".L",
            Self::Single => ".S",
            Self::Extended => ".X",
            Self::PackedDecimal => ".P",
            Self::Word => ".W",
            Self::Double => ".D",
            Self::Byte => ".B",
            Self::FpRegister => "",
        }
    }

    /// Size in bytes of the format (0 for packed decimal and FP register).
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Long | Self::Single => 4,
            Self::Double => 8,
            Self::Extended | Self::PackedDecimal => 12,
            Self::FpRegister => 0,
        }
    }

    /// Map an FPU integer format to the corresponding base-CPU [`Size`].
    ///
    /// Returns `None` for floating-point or non-integer formats (which have no
    /// counterpart in the integer-operand size space).
    #[must_use]
    pub const fn integer_size(self) -> Option<Size> {
        match self {
            Self::Byte => Some(Size::Byte),
            Self::Word => Some(Size::Word),
            Self::Long => Some(Size::Long),
            _ => None,
        }
    }
}

/// FPU condition code (for `FBcc`, `FDBcc`, `FScc`, `FTRAPcc`).
#[must_use]
pub const fn fpu_condition_name(cond: u8) -> &'static str {
    match cond & 0x3F {
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

// ─────────────────────────────────────────────────────────────────────────────
// FpuInsn
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded 68881/68882/68040 FPU instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpuInsn {
    /// Canonical mnemonic (e.g. `"FADD"`, `"FMOVE"`, `"FBcc"`).
    pub mnemonic: String,
    /// Formatted operand string.
    pub operands: String,
    /// Total instruction size in bytes.
    pub size_bytes: usize,
    /// Destination FP register (7 = none / branch target).
    pub dst_fp_reg: u8,
    /// Source FP register when source specifier = 7 (FP-to-FP).
    pub src_fp_reg: u8,
    /// Data format when source is memory.
    pub format: FpuFormat,
    /// FPU operation code (7 bits).
    pub fop: u8,
    /// Whether this is a branch/conditional instruction.
    pub is_branch: bool,
    /// Branch target address (if `is_branch`).
    pub branch_target: Option<u64>,
}

impl FpuInsn {
    /// Format as `"{mnemonic} {operands}"`.
    #[must_use]
    pub fn to_asm(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

impl std::fmt::Display for FpuInsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MmuInsn
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded PMMU (68030/68040) instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmuInsn {
    /// Mnemonic (e.g. `"PFLUSH"`, `"PLOAD"`, `"PMOVE"`, `"PTEST"`).
    pub mnemonic: String,
    /// Formatted operand string.
    pub operands: String,
    /// Total instruction size in bytes.
    pub size_bytes: usize,
    /// Raw MMU operation type word (first extension word).
    pub mmu_op_word: u16,
}

impl MmuInsn {
    /// Format as assembly.
    #[must_use]
    pub fn to_asm(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

impl std::fmt::Display for MmuInsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

/// Decode a PMMU instruction (F-line cpID=0 opcode word).
///
/// # Errors
/// Returns `Err` when the byte stream is too short.
pub fn decode_mmu_insn(word: u16, ext: &[u8], _pc: u64) -> Result<MmuInsn, String> {
    if ext.len() < 2 {
        return Err("MMU instruction requires at least 2 extension bytes".into());
    }
    let mmu_op = u16::from_be_bytes([ext[0], ext[1]]);

    // Decode the most common PMMU mnemonics.
    let (mnemonic, operands) = match (mmu_op >> 10) & 0x3F {
        0x20 => ("PLOAD".to_string(), format!("${mmu_op:04X}")),
        0x10 => ("PFLUSH".to_string(), format!("${mmu_op:04X}")),
        0x08 => ("PTEST".to_string(), format!("${mmu_op:04X}")),
        0x00 => {
            // PMOVE — transfer between EA and PMMU register.
            let pmmu_reg = (mmu_op >> 7) & 7;
            let reg_name = match pmmu_reg {
                0 => "TC",
                1 => "DRP",
                2 => "SRP",
                3 => "CRP",
                4 => "CAL",
                5 => "VAL",
                6 => "SCC",
                _ => "AC",
            };
            let ea_mode = ((word >> 3) & 7) as u8;
            let ea_reg = (word & 7) as u8;
            let dir = (mmu_op >> 9) & 1;
            let ops = if dir == 0 {
                format!("{reg_name},(A{ea_reg}) mode={ea_mode}")
            } else {
                format!("(A{ea_reg}) mode={ea_mode},{reg_name}")
            };
            ("PMOVE".to_string(), ops)
        }
        _ => ("PMMU".to_string(), format!("${word:04X} ${mmu_op:04X}")),
    };

    Ok(MmuInsn {
        mnemonic,
        operands,
        size_bytes: 4,
        mmu_op_word: mmu_op,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Cpu32Insn  — CPU32 table-driven branch instructions (TBcc)
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded CPU32-specific instruction (`BGND`, `LPSTOP`, `TBcc`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cpu32Insn {
    /// Mnemonic.
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Total instruction size in bytes.
    pub size_bytes: usize,
    /// Branch target for `TBcc`, if applicable.
    pub branch_target: Option<u64>,
}

impl Cpu32Insn {
    /// Format as assembly.
    #[must_use]
    pub fn to_asm(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

impl std::fmt::Display for Cpu32Insn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

/// Decode a CPU32 instruction.
///
/// CPU32 adds `BGND` (background debug), `LPSTOP` (low-power stop), and `TBcc`
/// (table branch with condition) to the base M68K ISA.
///
/// # Errors
/// Returns `Err` when the byte stream is too short.
pub fn decode_cpu32_insn(word: u16, ext: &[u8], pc: u64) -> Result<Cpu32Insn, String> {
    // BGND: 0x4AFA
    if word == 0x4AFA {
        return Ok(Cpu32Insn {
            mnemonic: "BGND".into(),
            operands: String::new(),
            size_bytes: 2,
            branch_target: None,
        });
    }

    // LPSTOP: 0xF800 with extension 0x01C0
    if word == 0xF800 {
        if ext.len() < 4 {
            return Err("LPSTOP requires 4 extension bytes".into());
        }
        let ctl = u16::from_be_bytes([ext[0], ext[1]]);
        if ctl == 0x01C0 {
            let mask = u16::from_be_bytes([ext[2], ext[3]]);
            return Ok(Cpu32Insn {
                mnemonic: "LPSTOP".into(),
                operands: format!("#${mask:04X}"),
                size_bytes: 6,
                branch_target: None,
            });
        }
    }

    // TBcc: F-line with cpID = 3 (CPU32 specific).
    // Encoding: 1111_011x_cccc_cccc
    if (word & 0xFE00) == 0xF600 {
        let cond = (word & 0x1F) as u8;
        let cond_name = cpu32_condition_name(cond);
        let reg = ((word >> 5) & 7) as u8;
        let long_disp = (word & 0x100) != 0;
        if long_disp {
            if ext.len() < 4 {
                return Err("TBcc.L requires 4 ext bytes".into());
            }
            let disp = i32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]]);
            let target = pc.wrapping_add_signed(2_i64 + i64::from(disp));
            return Ok(Cpu32Insn {
                mnemonic: format!("TB{cond_name}.L"),
                operands: format!("D{reg},${target:08X}"),
                size_bytes: 6,
                branch_target: Some(target),
            });
        }
        if ext.len() < 2 {
            return Err("TBcc.W requires 2 ext bytes".into());
        }
        let disp = i32::from(i16::from_be_bytes([ext[0], ext[1]]));
        let target = pc.wrapping_add_signed(2_i64 + i64::from(disp));
        return Ok(Cpu32Insn {
            mnemonic: format!("TB{cond_name}.W"),
            operands: format!("D{reg},${target:08X}"),
            size_bytes: 4,
            branch_target: Some(target),
        });
    }

    Err(format!("not a CPU32 instruction: ${word:04X}"))
}

/// CPU32 table-branch condition names (subset of standard conditions).
const fn cpu32_condition_name(cond: u8) -> &'static str {
    match cond & 0x1F {
        0x00 => "T",
        0x01 => "F",
        0x02 => "HI",
        0x03 => "LS",
        0x04 => "CC",
        0x05 => "CS",
        0x06 => "NE",
        0x07 => "EQ",
        0x08 => "VC",
        0x09 => "VS",
        0x0A => "PL",
        0x0B => "MI",
        0x0C => "GE",
        0x0D => "LT",
        0x0E => "GT",
        0x0F => "LE",
        _ => "??",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FPU instruction decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Decode an F-line FPU instruction (cpID=1, word & 0xFE00 == 0xF200).
///
/// # Errors
/// Returns `Err` when the byte stream is truncated.
pub fn decode_fpu_insn_ext(word: u16, ext: &[u8], pc: u64) -> Result<FpuInsn, String> {
    if ext.len() < 2 {
        return Err("FPU instruction requires at least 2 extension bytes".into());
    }
    let fword = u16::from_be_bytes([ext[0], ext[1]]);
    let src_spec = (fword >> 10) & 7;
    let dst_fp = ((fword >> 7) & 7) as u8;
    let src_fp = ((fword >> 10) & 7) as u8;
    let fop = (fword & 0x7F) as u8;

    // FBcc (branch on FP condition).
    if (word & 0x01C0) == 0x0080 || (word & 0x01C0) == 0x00C0 {
        let cond = (word & 0x3F) as u8;
        let cond_name = fpu_condition_name(cond);
        let long = (word & 0x0040) != 0;
        let (target, size) = if long {
            if ext.len() < 6 {
                return Err("FBcc.L requires 6 bytes".into());
            }
            let d = i32::from_be_bytes([ext[2], ext[3], ext[4], ext[5]]);
            let t = pc.wrapping_add_signed(2_i64 + i64::from(d));
            (t, 8usize)
        } else {
            if ext.len() < 4 {
                return Err("FBcc.W requires 4 bytes".into());
            }
            let d = i32::from(i16::from_be_bytes([ext[2], ext[3]]));
            let t = pc.wrapping_add_signed(2_i64 + i64::from(d));
            (t, 6usize)
        };
        return Ok(FpuInsn {
            mnemonic: format!("FB{cond_name}"),
            operands: format!("${target:08X}"),
            size_bytes: size,
            dst_fp_reg: 7,
            src_fp_reg: 7,
            format: FpuFormat::FpRegister,
            fop: 0,
            is_branch: true,
            branch_target: Some(target),
        });
    }

    // FDBcc (decrement and branch on FP condition): instruction-type bits[8:6] = 001.
    if (word & 0x01C0) == 0x0040 {
        let cond = (word & 0x3F) as u8;
        let dn = (word & 7) as u8;
        let cond_name = fpu_condition_name(cond);
        if ext.len() < 4 {
            return Err("FDBcc requires 4 extension bytes".into());
        }
        let disp = i32::from(i16::from_be_bytes([ext[2], ext[3]]));
        let target = pc.wrapping_add_signed(4_i64 + i64::from(disp));
        return Ok(FpuInsn {
            mnemonic: format!("FDB{cond_name}"),
            operands: format!("D{dn},${target:08X}"),
            size_bytes: 6,
            dst_fp_reg: 7,
            src_fp_reg: 7,
            format: FpuFormat::FpRegister,
            fop: 0,
            is_branch: true,
            branch_target: Some(target),
        });
    }

    // Standard FPU operation (FADD, FMUL, etc.)
    let format = FpuFormat::from_bits(src_spec as u8);
    let mnemonic = fop_mnemonic(fop).to_string();

    let operands = if src_spec == 7 {
        // FP-to-FP operation.
        format!("FP{src_fp},FP{dst_fp}")
    } else {
        // Memory/EA-to-FP operation.
        let ea_mode = ((word >> 3) & 7) as u8;
        let ea_reg = (word & 7) as u8;
        let ea_str = fmt_ea_simple(ea_mode, ea_reg);
        format!("{}{ea_str},FP{dst_fp}", format.suffix())
    };

    Ok(FpuInsn {
        mnemonic,
        operands,
        size_bytes: 4,
        dst_fp_reg: dst_fp,
        src_fp_reg: src_fp,
        format,
        fop,
        is_branch: false,
        branch_target: None,
    })
}

const fn fop_mnemonic(fop: u8) -> &'static str {
    match fop {
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
    }
}

fn fmt_ea_simple(mode: u8, reg: u8) -> String {
    match mode {
        0 => format!("D{reg}"),
        1 => format!("A{reg}"),
        2 => format!("(A{reg})"),
        3 => format!("(A{reg})+"),
        4 => format!("-(A{reg})"),
        _ => format!("<ea mode={mode} reg={reg}>"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M68kDisassemblerExt  — unified FPU/MMU/CPU32 facade
// ─────────────────────────────────────────────────────────────────────────────

/// Extended disassembler result covering the three extension ISA domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtDisasmResult {
    /// Decoded as an FPU instruction.
    Fpu(FpuInsn),
    /// Decoded as an MMU instruction.
    Mmu(MmuInsn),
    /// Decoded as a CPU32 instruction.
    Cpu32(Cpu32Insn),
}

impl ExtDisasmResult {
    /// Return the mnemonic string.
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        match self {
            Self::Fpu(i) => &i.mnemonic,
            Self::Mmu(i) => &i.mnemonic,
            Self::Cpu32(i) => &i.mnemonic,
        }
    }

    /// Return the operand string.
    #[must_use]
    pub fn operands(&self) -> &str {
        match self {
            Self::Fpu(i) => &i.operands,
            Self::Mmu(i) => &i.operands,
            Self::Cpu32(i) => &i.operands,
        }
    }

    /// Return total instruction size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        match self {
            Self::Fpu(i) => i.size_bytes,
            Self::Mmu(i) => i.size_bytes,
            Self::Cpu32(i) => i.size_bytes,
        }
    }

    /// Format as assembly.
    #[must_use]
    pub fn to_asm(&self) -> String {
        if self.operands().is_empty() {
            self.mnemonic().to_owned()
        } else {
            format!("{} {}", self.mnemonic(), self.operands())
        }
    }
}

impl std::fmt::Display for ExtDisasmResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_asm())
    }
}

/// Facade that attempts extended (FPU/MMU/CPU32) decoding first.
///
/// Call [`M68kDisassemblerExt::decode`] with a raw byte slice and current `pc`.
/// The method inspects the F-line (0xFxxx) and CPU32-specific opcodes and
/// returns the first successful decode, or `None` if none match.
pub struct M68kDisassemblerExt {
    /// Target CPU variant — controls which extensions are attempted.
    pub variant: Mc68kVariant,
}

impl M68kDisassemblerExt {
    /// Create a new extended disassembler for `variant`.
    #[must_use]
    pub const fn new(variant: Mc68kVariant) -> Self {
        Self { variant }
    }

    /// Attempt to decode an extended instruction at the start of `bytes`.
    ///
    /// Returns `Some(result)` when decoded, or `None` when the bytes do not
    /// match any extended encoding for the configured variant.
    ///
    /// The caller should fall through to the base decoder on `None`.
    #[must_use]
    pub fn decode(&self, bytes: &[u8], pc: u64) -> Option<ExtDisasmResult> {
        if bytes.len() < 2 {
            return None;
        }
        let word = u16::from_be_bytes([bytes[0], bytes[1]]);
        let ext = &bytes[2..];

        // Only the F-line (0xFxxx) and a few 0x4Axx opcodes.
        if word >> 12 != 0xF && word != 0x4AFA {
            // BGND is 0x4AFA (CPU32 only).
            if word == 0x4AFA && matches!(self.variant, Mc68kVariant::ColdFire) {
                // ColdFire does not have BGND.
                return None;
            }
            if word == 0x4AFA {
                return decode_cpu32_insn(word, ext, pc)
                    .ok()
                    .map(ExtDisasmResult::Cpu32);
            }
            return None;
        }

        // F-line dispatch.
        let cpid = (word >> 9) & 7;
        match cpid {
            1 if self.has_fpu() => {
                // FPU (68881/68882 or 68040 on-chip FPU).
                decode_fpu_insn_ext(word, ext, pc)
                    .ok()
                    .map(ExtDisasmResult::Fpu)
            }
            0 if self.has_mmu() => {
                // PMMU (68030/68040).
                decode_mmu_insn(word, ext, pc)
                    .ok()
                    .map(ExtDisasmResult::Mmu)
            }
            3 => {
                // CPU32 TBcc / LPSTOP.
                decode_cpu32_insn(word, ext, pc)
                    .ok()
                    .map(ExtDisasmResult::Cpu32)
            }
            _ => {
                // Cache push/invalidate (68040) and other F-line uses.
                None
            }
        }
    }

    const fn has_fpu(&self) -> bool {
        matches!(self.variant, Mc68kVariant::M68040 | Mc68kVariant::M68060)
            || matches!(self.variant, Mc68kVariant::M68020 | Mc68kVariant::M68030)
    }

    const fn has_mmu(&self) -> bool {
        self.variant.has_mmu()
    }

    /// Decode a sequence of instructions and return all results.
    #[must_use]
    pub fn decode_sequence(&self, bytes: &[u8], base_pc: u64) -> Vec<(u64, ExtDisasmResult)> {
        let mut results = Vec::new();
        let mut pos = 0usize;
        let mut pc = base_pc;
        while pos < bytes.len() {
            if let Some(r) = self.decode(&bytes[pos..], pc) {
                let sz = r.size_bytes().max(2);
                results.push((pc, r));
                pos += sz;
                pc += sz as u64;
            } else {
                pos += 2;
                pc += 2;
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FpuRegisterSet  — FMOVEM mask utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Decode an FMOVEM register list mask into a readable string.
///
/// Bits 0–7 correspond to FP7–FP0 (reversed) in FMOVEM with pre-decrement,
/// or FP0–FP7 (normal) in post-increment form.
#[must_use]
pub fn decode_fmovem_mask(mask: u8, predecrement: bool) -> String {
    let effective = if predecrement {
        mask.reverse_bits()
    } else {
        mask
    };
    let mut parts = Vec::new();
    for i in 0..8u8 {
        if (effective >> i) & 1 != 0 {
            parts.push(format!("FP{i}"));
        }
    }
    if parts.is_empty() {
        "<none>".to_string()
    } else {
        parts.join("/")
    }
}

/// Encode an FP register list for FMOVEM.
#[must_use]
pub fn encode_fmovem_mask(regs: &[u8], predecrement: bool) -> u8 {
    let mut mask = 0u8;
    for &r in regs {
        if r < 8 {
            mask |= 1 << r;
        }
    }
    if predecrement {
        mask.reverse_bits()
    } else {
        mask
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // FPU format
    #[test]
    fn test_fpu_format_from_bits() {
        assert_eq!(FpuFormat::from_bits(0), FpuFormat::Long);
        assert_eq!(FpuFormat::from_bits(1), FpuFormat::Single);
        assert_eq!(FpuFormat::from_bits(5), FpuFormat::Double);
        assert_eq!(FpuFormat::from_bits(7), FpuFormat::FpRegister);
    }

    #[test]
    fn test_fpu_format_suffix() {
        assert_eq!(FpuFormat::Double.suffix(), ".D");
        assert_eq!(FpuFormat::Extended.suffix(), ".X");
        assert_eq!(FpuFormat::FpRegister.suffix(), "");
    }

    #[test]
    fn test_fpu_format_byte_size() {
        assert_eq!(FpuFormat::Byte.byte_size(), 1);
        assert_eq!(FpuFormat::Long.byte_size(), 4);
        assert_eq!(FpuFormat::Double.byte_size(), 8);
        assert_eq!(FpuFormat::Extended.byte_size(), 12);
    }

    // FPU condition names
    #[test]
    fn test_fpu_condition_names() {
        assert_eq!(fpu_condition_name(0x01), "EQ");
        assert_eq!(fpu_condition_name(0x0E), "NE");
        assert_eq!(fpu_condition_name(0x0F), "T");
    }

    // FPU decoder: FADD FP0,FP3
    #[test]
    fn test_decode_fpu_fp_to_fp_fadd() {
        // Word: 0xF200 (cpID=1), ext: 0xE022 = src_spec=7(FP-to-FP), dst=0, src=0, fop=0x22(FADD)
        // fword = 0b 111 000 0100010 = 0xE022
        let word: u16 = 0xF200;
        let ext = [0xE0u8, 0x22]; // fword = 0xE022, src_spec=7, dst_fp=0, src_fp=0, fop=0x22
        let r = decode_fpu_insn_ext(word, &ext, 0x1000).unwrap();
        assert_eq!(r.mnemonic, "FADD");
        assert!(!r.is_branch);
    }

    // BGND (CPU32)
    #[test]
    fn test_decode_cpu32_bgnd() {
        let r = decode_cpu32_insn(0x4AFA, &[], 0).unwrap();
        assert_eq!(r.mnemonic, "BGND");
        assert_eq!(r.size_bytes, 2);
        assert!(r.branch_target.is_none());
    }

    // Not a CPU32 instruction
    #[test]
    fn test_decode_cpu32_invalid() {
        let r = decode_cpu32_insn(0x4E71, &[], 0);
        assert!(r.is_err());
    }

    // MMU decoder
    #[test]
    fn test_decode_mmu_insn_default() {
        let word: u16 = 0xF000;
        let ext = [0x80u8, 0x00]; // PMOVE-ish
        let r = decode_mmu_insn(word, &ext, 0).unwrap();
        assert!(!r.mnemonic.is_empty());
        assert_eq!(r.size_bytes, 4);
    }

    // Facade — BGND via CPU32
    #[test]
    fn test_facade_bgnd() {
        let ext = M68kDisassemblerExt::new(Mc68kVariant::ColdFire);
        // ColdFire should reject BGND
        let bytes = [0x4Au8, 0xFA];
        let r = ext.decode(&bytes, 0);
        assert!(r.is_none());
    }

    #[test]
    fn test_fmovem_mask_decode() {
        let s = decode_fmovem_mask(0b0000_1111, false);
        assert!(s.contains("FP0"));
        assert!(s.contains("FP3"));
        assert!(!s.contains("FP4"));
    }

    #[test]
    fn test_fmovem_mask_predecrement() {
        // predecrement reverses bits
        let s = decode_fmovem_mask(0b1111_0000, true);
        // After reversal: 0b0000_1111 → FP0–FP3
        assert!(s.contains("FP0") || s.contains("FP3"));
    }

    #[test]
    fn test_encode_fmovem_mask() {
        let mask = encode_fmovem_mask(&[0, 1, 2], false);
        assert_eq!(mask & 0x07, 0x07);
    }

    #[test]
    fn test_fpu_insn_display() {
        let insn = FpuInsn {
            mnemonic: "FADD".into(),
            operands: "FP0,FP1".into(),
            size_bytes: 4,
            dst_fp_reg: 1,
            src_fp_reg: 0,
            format: FpuFormat::FpRegister,
            fop: 0x22,
            is_branch: false,
            branch_target: None,
        };
        assert_eq!(insn.to_string(), "FADD FP0,FP1");
    }

    #[test]
    fn test_cpu32_insn_display() {
        let insn = Cpu32Insn {
            mnemonic: "BGND".into(),
            operands: String::new(),
            size_bytes: 2,
            branch_target: None,
        };
        assert_eq!(insn.to_string(), "BGND");
    }

    #[test]
    fn test_mmu_insn_display() {
        let insn = MmuInsn {
            mnemonic: "PFLUSH".into(),
            operands: "$1234".into(),
            size_bytes: 4,
            mmu_op_word: 0x1234,
        };
        assert_eq!(insn.to_string(), "PFLUSH $1234");
    }
}
