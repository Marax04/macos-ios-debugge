//! Motorola 68000 family ISA extensions.
//!
//! Covers per-variant instruction availability (68000→68060), FPU coprocessor
//! instruction set (68881/68882), 68020 scaled addressing modes, bitfield
//! operations, and 68040/060 restricted FPU subsets.

use crate::Mc68kVariant;

// ── Variant capability matrix ─────────────────────────────────────────────────

bitflags::bitflags! {
    /// Feature flags for a specific 68k variant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct VariantFlags: u32 {
        /// MOVE USP, RESET, STOP, RTE privileged.
        const PRIVILEGED_OPS = 1 << 0;
        /// VBR (Vector Base Register) via MOVEC.
        const VBR            = 1 << 1;
        /// Loop mode (repeat last microstep for `DBcc`).
        const LOOP_MODE      = 1 << 2;
        /// Full 32-bit internal ALU, `BFXXX`, `CAS`, `TRAPcc`, `RTD`.
        const FULL_32BIT     = 1 << 3;
        /// Scaled-indexed addressing (d8,An,Xn.SIZE*SCALE).
        const SCALED_INDEX   = 1 << 4;
        /// On-chip data + instruction cache (CACR/CAAR).
        const CACHE          = 1 << 5;
        /// On-chip MMU (TC, TT0, TT1, MMUSR, URP, SRP).
        const MMU            = 1 << 6;
        /// On-chip FPU (FMOVE, FADD, …).
        const FPU_ONCHIP     = 1 << 7;
        /// 68881/68882 coprocessor FPU (off-chip).
        const FPU_COPRO      = 1 << 8;
        /// CINV, CPUSH cache maintenance.
        const CACHE_PUSH     = 1 << 9;
        /// 64-bit multiply/divide (MULU.L Dn:Dn, DIVS.L 64-bit).
        const WIDE_MULDIV    = 1 << 10;
        /// CHK.L 32-bit version.
        const CHK_LONG       = 1 << 11;
        /// CALLM/RTM coprocessor protocol.
        const CALLM_RTM      = 1 << 12;
        /// PFLUSHA, PLOAD, PTEST MMU instructions.
        const PTEST          = 1 << 13;
        /// Superscalar execution.
        const SUPERSCALAR    = 1 << 14;
    }
}

/// Capability descriptor for a specific 68k variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariantCaps {
    pub variant: Mc68kVariant,
    pub flags: VariantFlags,
}

impl VariantCaps {
    // Convenience accessors — kept for backward compat with match arms below.
    #[must_use] #[inline] pub const fn privileged_ops(self) -> bool { self.flags.contains(VariantFlags::PRIVILEGED_OPS) }
    #[must_use] #[inline] pub const fn vbr(self) -> bool { self.flags.contains(VariantFlags::VBR) }
    #[must_use] #[inline] pub const fn full_32bit(self) -> bool { self.flags.contains(VariantFlags::FULL_32BIT) }
    #[must_use] #[inline] pub const fn wide_muldiv(self) -> bool { self.flags.contains(VariantFlags::WIDE_MULDIV) }
    #[must_use] #[inline] pub const fn chk_long(self) -> bool { self.flags.contains(VariantFlags::CHK_LONG) }
    #[must_use] #[inline] pub const fn fpu_copro(self) -> bool { self.flags.contains(VariantFlags::FPU_COPRO) }
    #[must_use] #[inline] pub const fn fpu_onchip(self) -> bool { self.flags.contains(VariantFlags::FPU_ONCHIP) }
}

impl VariantCaps {
    #[must_use]
    pub fn for_variant(v: Mc68kVariant) -> Self {
        use VariantFlags as F;
        let flags = match v {
            Mc68kVariant::M68000 => F::PRIVILEGED_OPS,
            Mc68kVariant::M68010 => F::PRIVILEGED_OPS | F::VBR | F::LOOP_MODE,
            Mc68kVariant::M68020 => {
                F::PRIVILEGED_OPS | F::VBR | F::FULL_32BIT | F::SCALED_INDEX
                    | F::CACHE | F::FPU_COPRO | F::WIDE_MULDIV | F::CHK_LONG | F::CALLM_RTM
            }
            Mc68kVariant::M68030 => {
                F::PRIVILEGED_OPS | F::VBR | F::FULL_32BIT | F::SCALED_INDEX
                    | F::CACHE | F::MMU | F::FPU_COPRO | F::WIDE_MULDIV | F::CHK_LONG | F::PTEST
            }
            Mc68kVariant::M68040 => {
                F::PRIVILEGED_OPS | F::VBR | F::FULL_32BIT | F::SCALED_INDEX
                    | F::CACHE | F::MMU | F::FPU_ONCHIP | F::CACHE_PUSH
                    | F::WIDE_MULDIV | F::CHK_LONG | F::PTEST
            }
            Mc68kVariant::M68060 => {
                F::PRIVILEGED_OPS | F::VBR | F::FULL_32BIT | F::SCALED_INDEX
                    | F::CACHE | F::MMU | F::FPU_ONCHIP | F::CACHE_PUSH
                    | F::WIDE_MULDIV | F::CHK_LONG | F::PTEST | F::SUPERSCALAR
            }
            Mc68kVariant::ColdFire => {
                F::PRIVILEGED_OPS | F::VBR | F::FULL_32BIT
                    | F::CACHE | F::MMU | F::CACHE_PUSH | F::WIDE_MULDIV
            }
        };
        Self { variant: v, flags }
    }

    /// Whether a named instruction is available on this variant.
    #[must_use]
    pub fn has_instruction(&self, mnemonic: &str) -> bool {
        match mnemonic {
            // Always present (68000 baseline)
            "MOVE" | "MOVEA" | "MOVEQ" | "MOVEM" | "MOVEP" |
            "ADD" | "ADDA" | "ADDI" | "ADDQ" | "ADDX" |
            "SUB" | "SUBA" | "SUBI" | "SUBQ" | "SUBX" |
            "AND" | "ANDI" | "OR" | "ORI" | "EOR" | "EORI" |
            "CMP" | "CMPA" | "CMPI" | "CMPM" |
            "MULU" | "MULS" | "DIVU" | "DIVS" |
            "CLR" | "NEG" | "NEGX" | "NOT" | "TST" | "TAS" |
            "BTST" | "BSET" | "BCLR" | "BCHG" |
            "ASL" | "ASR" | "LSL" | "LSR" | "ROL" | "ROR" | "ROXL" | "ROXR" |
            "JMP" | "JSR" | "RTS" | "RTE" | "RTR" | "BSR" | "BRA" |
            "BHI" | "BLS" | "BCC" | "BCS" | "BNE" | "BEQ" |
            "BVC" | "BVS" | "BPL" | "BMI" | "BGE" | "BLT" | "BGT" | "BLE" |
            "ABCD" | "SBCD" | "NBCD" | "PACK" | "UNPK" |
            "LEA" | "PEA" | "LINK" | "UNLK" |
            "SWAP" | "EXT" |
            "CHK" | "TRAP" | "TRAPV" | "ILLEGAL" |
            "STOP" | "RESET" | "NOP" | "HALT" |
            "MOVE_USP" => true,

            // 68010+ VBR/MOVEC and RTD
            "MOVEC" | "MOVES" | "RTD" => self.vbr(),

            // 68020+ full 32-bit
            "MULU_L" | "MULS_L" | "DIVU_L" | "DIVS_L" | "DIVUL" | "DIVSL" => self.wide_muldiv(),
            "CHK_L" => self.chk_long(),
            "TRAPcc" | "TRAPCC" | "TRAPCS" | "TRAPNE" | "TRAPEQ" |
            "TRAPHI" | "TRAPLS" | "TRAPVC" | "TRAPVS" |
            "TRAPPL" | "TRAPMI" | "TRAPGE" | "TRAPLT" | "TRAPGT" | "TRAPLE" |
            "CAS" | "CAS2" | "CALLM" | "RTM" | "EXTB" |
            // Bitfield — 68020+
            "BFCHG" | "BFCLR" | "BFEXTS" | "BFEXTU" |
            "BFFFO" | "BFINS" | "BFSET" | "BFTST" => self.full_32bit(),

            // FPU instructions (68881/882 or on-chip 040/060)
            "FADD" | "FSUB" | "FMUL" | "FDIV" | "FMOVE" | "FMOVEM" |
            "FCMP" | "FTST" | "FSQRT" | "FABS" | "FNEG" |
            "FINT" | "FINTRZ" | "FSGLDIV" | "FSGLMUL" |
            "FSIN" | "FCOS" | "FTAN" | "FASIN" | "FACOS" | "FATAN" |
            "FSINH" | "FCOSH" | "FTANH" | "FATANH" |
            "FETOX" | "FLOGN" | "FLOG10" | "FLOG2" |
            "FTWOTOX" | "FTENTOX" | "FGETEXP" | "FGETMAN" |
            "FMOD" | "FREM" | "FSCALE" |
            "FBcc" | "FDBcc" | "FScc" | "FTRAPcc" |
            "FSAVE" | "FRESTORE" => self.fpu_copro() || self.fpu_onchip(),

            // 68040/060-only FPU subset (missing: trig, log, etc.)
            // When fpu_onchip but not fpu_copro, the set is restricted
            _ => false,
        }
    }
}

// ── 68020 Scaled addressing extension ────────────────────────────────────────

/// Index register scale factor (68020+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    S1 = 0,
    S2 = 1,
    S4 = 2,
    S8 = 3,
}

impl Scale {
    #[must_use]
    pub const fn from_bits(b: u8) -> Self {
        match b & 3 {
            0 => Self::S1,
            1 => Self::S2,
            2 => Self::S4,
            _ => Self::S8,
        }
    }
    #[must_use]
    pub const fn multiplier(self) -> u8 {
        match self {
            Self::S1 => 1,
            Self::S2 => 2,
            Self::S4 => 4,
            Self::S8 => 8,
        }
    }
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::S1 => "",
            Self::S2 => "*2",
            Self::S4 => "*4",
            Self::S8 => "*8",
        }
    }
}

bitflags::bitflags! {
    /// Boolean fields of a 68020 full extension word.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct FullExtFlags: u8 {
        /// Index register is address (true) or data (false).
        const IDX_IS_A = 1 << 0;
        /// Index register size: set = long, clear = word.
        const IDX_LONG = 1 << 1;
        /// Suppress base register.
        const BS       = 1 << 2;
        /// Suppress index.
        const IS_FLAG  = 1 << 3;
    }
}

/// 68020 full extension word for mode 6 (indexed with full format).
#[derive(Debug, Clone)]
pub struct FullExtWord {
    /// Base displacement size (0=none, 1=null, 2=word, 3=long).
    pub bd_size: u8,
    /// Index register number.
    pub idx_reg: u8,
    /// Boolean flags: `IDX_IS_A`, `IDX_LONG`, `BS`, `IS_FLAG`.
    pub ext_flags: FullExtFlags,
    /// Scale factor.
    pub scale: Scale,
    /// Index/indirect select.
    pub iis: u8,
}

impl FullExtWord {
    /// Index register is address (A-type).
    #[must_use] #[inline] pub const fn idx_is_a(&self) -> bool { self.ext_flags.contains(FullExtFlags::IDX_IS_A) }
    /// Index register size is long (vs word).
    #[must_use] #[inline] pub const fn idx_long(&self) -> bool { self.ext_flags.contains(FullExtFlags::IDX_LONG) }
    /// Suppress base register.
    #[must_use] #[inline] pub const fn bs(&self) -> bool { self.ext_flags.contains(FullExtFlags::BS) }
    /// Suppress index flag.
    #[must_use] #[inline] pub const fn is_flag(&self) -> bool { self.ext_flags.contains(FullExtFlags::IS_FLAG) }

    /// Parse a 68020 full extension word from 2 bytes.
    #[must_use]
    pub fn parse(hi: u8, lo: u8) -> Self {
        let mut ext_flags = FullExtFlags::empty();
        if (hi >> 7) & 1 != 0 { ext_flags |= FullExtFlags::IDX_IS_A; }
        if (hi >> 3) & 1 != 0 { ext_flags |= FullExtFlags::IDX_LONG; }
        if lo & 0x80 != 0     { ext_flags |= FullExtFlags::BS; }
        if lo & 0x40 != 0     { ext_flags |= FullExtFlags::IS_FLAG; }
        Self {
            bd_size: (lo >> 4) & 3,
            idx_reg: (hi >> 4) & 7,
            ext_flags,
            scale: Scale::from_bits((hi >> 1) & 3),
            iis: lo & 7,
        }
    }

    /// Build a disassembly string for this extension word.
    #[must_use]
    pub fn display(&self, base_reg: u8, bd: i32, od: i32) -> String {
        let idx_type = if self.idx_is_a() { 'A' } else { 'D' };
        let idx_size = if self.idx_long() { ".L" } else { ".W" };
        let scale_s = self.scale.suffix();
        let idx = format!("{idx_type}{}{idx_size}{scale_s}", self.idx_reg);

        if self.iis == 0 {
            // No memory indirect
            format!("({bd},A{base_reg},{idx})")
        } else if self.iis <= 4 {
            // Pre-indexed: ([bd,An,Xn],od)
            format!("([{bd},A{base_reg},{idx}],{od})")
        } else {
            // Post-indexed: ([bd,An],Xn,od)
            format!("([{bd},A{base_reg}],{idx},{od})")
        }
    }
}

// ── Bitfield instructions ──────────────────────────────────────────────────────

/// Bitfield instruction kind (68020+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitfieldOp {
    /// BFCHG — complement bits in field.
    Bfchg,
    /// BFCLR — clear bits in field.
    Bfclr,
    /// BFEXTS — extract signed bits into Dn.
    Bfexts,
    /// BFEXTU — extract unsigned bits into Dn.
    Bfextu,
    /// BFFFO — find first set bit, return offset.
    Bfffo,
    /// BFINS — insert bits from Dn into field.
    Bfins,
    /// BFSET — set bits in field.
    Bfset,
    /// BFTST — test bits in field, set N/Z.
    Bftst,
}

impl BitfieldOp {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Bfchg  => "BFCHG",
            Self::Bfclr  => "BFCLR",
            Self::Bfexts => "BFEXTS",
            Self::Bfextu => "BFEXTU",
            Self::Bfffo  => "BFFFO",
            Self::Bfins  => "BFINS",
            Self::Bfset  => "BFSET",
            Self::Bftst  => "BFTST",
        }
    }

    /// Whether this operation has a destination register operand.
    #[must_use]
    pub const fn has_dn(self) -> bool {
        matches!(self, Self::Bfexts | Self::Bfextu | Self::Bfffo | Self::Bfins)
    }

    /// Whether the EA is a source (false) or destination (true).
    #[must_use]
    pub const fn ea_is_dest(self) -> bool {
        matches!(self, Self::Bfins | Self::Bfclr | Self::Bfchg | Self::Bfset)
    }
}

/// Decoded bitfield operand extension word.
#[derive(Debug, Clone, Copy)]
pub struct BitfieldExt {
    /// Destination/source data register (for BFEXTS/BFEXTU/BFFFO/BFINS).
    pub dn: u8,
    /// Offset from bit 31 (0-31 immediate, or register if `off_is_reg`).
    pub offset: u8,
    /// Width (1-32 immediate, 0=32; or register if `wid_is_reg`).
    pub width: u8,
    /// True if offset is in data register.
    pub off_is_reg: bool,
    /// True if width is in data register.
    pub wid_is_reg: bool,
}

impl BitfieldExt {
    /// Parse from the 16-bit bitfield extension word.
    #[must_use]
    pub const fn parse(ext: u16) -> Self {
        Self {
            dn:         ((ext >> 12) & 7) as u8,
            off_is_reg: (ext >> 11) & 1 != 0,
            offset:     ((ext >> 6) & 31) as u8,
            wid_is_reg: (ext >> 5) & 1 != 0,
            width:      (ext & 31) as u8,
        }
    }

    /// Format the bitfield specifier as assembler text.
    #[must_use]
    pub fn display_field(&self) -> String {
        let off = if self.off_is_reg {
            format!("D{}", self.offset & 7)
        } else {
            format!("{}", self.offset)
        };
        let wid = if self.wid_is_reg {
            format!("D{}", self.width & 7)
        } else if self.width == 0 {
            "32".to_string()
        } else {
            format!("{}", self.width)
        };
        format!("{{{off}:{wid}}}")
    }
}

/// Decode a 68020 bitfield instruction word + extension word.
///
/// Returns `(mnemonic, operand_string, total_bytes)` or `None` if not a
/// bitfield instruction.
#[must_use]
pub fn decode_bitfield(word: u16, ext_bytes: &[u8]) -> Option<(String, String, usize)> {
    // Bitfield opcodes occupy bits 15:12 = 1110 (0xE) and bits 11:8 select op
    // Actually bitfield is in 0xE8x0..0xEFxx range:
    // Pattern: 1110 1xxx xxxx xxxx where bits 11:9 select operation
    if (word >> 12) != 0xE {
        return None;
    }
    let op_bits = (word >> 8) & 0xF;
    let op = match op_bits {
        0x8 => BitfieldOp::Bftst,
        0x9 => BitfieldOp::Bfextu,
        0xA => BitfieldOp::Bfchg,
        0xB => BitfieldOp::Bfexts,
        0xC => BitfieldOp::Bfclr,
        0xD => BitfieldOp::Bfffo,
        0xE => BitfieldOp::Bfset,
        0xF => BitfieldOp::Bfins,
        _ => return None,
    };
    if ext_bytes.len() < 2 {
        return None;
    }
    let ext_word = u16::from_be_bytes([ext_bytes[0], ext_bytes[1]]);
    let bfext = BitfieldExt::parse(ext_word);

    let ea_mode = ((word >> 3) & 7) as u8;
    let ea_reg  = (word & 7) as u8;
    let ea_str  = format_ea_simple(ea_mode, ea_reg);
    let field   = bfext.display_field();

    let operands = if op.has_dn() {
        if op == BitfieldOp::Bfins {
            format!("D{},{ea_str}{field}", bfext.dn)
        } else {
            format!("{ea_str}{field},D{}", bfext.dn)
        }
    } else {
        format!("{ea_str}{field}")
    };

    Some((op.mnemonic().to_string(), operands, 4))
}

fn format_ea_simple(mode: u8, reg: u8) -> String {
    match mode {
        0 => format!("D{reg}"),
        1 => format!("A{reg}"),
        2 => format!("(A{reg})"),
        3 => format!("(A{reg})+"),
        4 => format!("-(A{reg})"),
        _ => format!("ea({mode},{reg})"),
    }
}

// ── FPU instruction set (68881/68882) ─────────────────────────────────────────

/// 68881/68882 FPU data types as they appear in the coprocessor command word.
///
/// This is the ISA-catalog view of the format field (bits 12:10 of the
/// coprocessor command word when `R/M=1`).  It covers only the seven
/// integer/float memory formats used by `FMOVE` source specifiers.
///
/// For the decoder-facing variant that also models the FP-to-FP case
/// (where bits 12:10 select a source FP register rather than a data format)
/// see [`crate::m68k_disassembler_ext::FpuFormat`], which adds the
/// `FpRegister` sentinel and derives `serde::Serialize/Deserialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpuFormat {
    /// Long integer (32-bit).
    Long,
    /// Single precision (32-bit IEEE).
    Single,
    /// Extended precision (80-bit).
    Extended,
    /// Packed BCD real (12 bytes).
    Packed,
    /// Word integer (16-bit).
    Word,
    /// Double precision (64-bit IEEE).
    Double,
    /// Byte integer (8-bit).
    Byte,
}

impl FpuFormat {
    #[must_use]
    pub const fn from_bits(b: u8) -> Option<Self> {
        match b & 7 {
            0 => Some(Self::Long),
            1 => Some(Self::Single),
            2 => Some(Self::Extended),
            3 => Some(Self::Packed),
            4 => Some(Self::Word),
            5 => Some(Self::Double),
            6 => Some(Self::Byte),
            _ => None,
        }
    }
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Long     => ".L",
            Self::Single   => ".S",
            Self::Extended => ".X",
            Self::Packed   => ".P",
            Self::Word     => ".W",
            Self::Double   => ".D",
            Self::Byte     => ".B",
        }
    }
    #[must_use]
    pub const fn byte_size(self) -> usize {
        match self {
            Self::Byte              => 1,
            Self::Word              => 2,
            Self::Long | Self::Single   => 4,
            Self::Double            => 8,
            Self::Extended | Self::Packed => 12,
        }
    }
}

/// 68881 FPU operation codes (bits 6:0 of the coprocessor command word).
pub static FPU_OPS: &[(u8, &str, bool)] = &[
    // (opcode, mnemonic, is_dyadic)
    (0x00, "FMOVE",   false),
    (0x01, "FINT",    false),
    (0x02, "FSINH",   false),
    (0x03, "FINTRZ",  false),
    (0x04, "FSQRT",   false),
    (0x06, "FLOGNP1", false),
    (0x08, "FETOXM1", false),
    (0x09, "FTANH",   false),
    (0x0A, "FATAN",   false),
    (0x0C, "FASIN",   false),
    (0x0D, "FATANH",  false),
    (0x0E, "FSIN",    false),
    (0x0F, "FTAN",    false),
    (0x10, "FETOX",   false),
    (0x11, "FTWOTOX", false),
    (0x12, "FTENTOX", false),
    (0x14, "FLOGN",   false),
    (0x15, "FLOG10",  false),
    (0x16, "FLOG2",   false),
    (0x18, "FABS",    false),
    (0x19, "FCOSH",   false),
    (0x1A, "FNEG",    false),
    (0x1C, "FACOS",   false),
    (0x1D, "FCOS",    false),
    (0x1E, "FGETEXP", false),
    (0x1F, "FGETMAN", false),
    (0x20, "FDIV",    true),
    (0x21, "FMOD",    true),
    (0x22, "FADD",    true),
    (0x23, "FMUL",    true),
    (0x24, "FSGLDIV", true),
    (0x25, "FREM",    true),
    (0x26, "FSCALE",  true),
    (0x27, "FSGLMUL", true),
    (0x28, "FSUB",    true),
    (0x38, "FCMP",    true),
    (0x3A, "FTST",    false),
    // Sincos (special: writes to two FP registers)
    (0x30, "FSINCOS", false),
    (0x31, "FSINCOS", false),
    (0x32, "FSINCOS", false),
    (0x33, "FSINCOS", false),
    (0x34, "FSINCOS", false),
    (0x35, "FSINCOS", false),
    (0x36, "FSINCOS", false),
    (0x37, "FSINCOS", false),
];

/// Look up a 68881 FPU operation mnemonic.
#[must_use]
pub fn fpu_op_name(opcode: u8) -> Option<&'static str> {
    FPU_OPS.iter().find(|e| e.0 == opcode).map(|e| e.1)
}

/// 68040/68060 FPU subset — instructions directly supported in hardware.
/// Instructions NOT in this list are emulated by the 040/060 FPU emulation
/// library (`motorola_fpsp.library` on Amiga, etc.).
pub static FPU_040_SUBSET: &[&str] = &[
    "FMOVE", "FMOVEM",
    "FADD", "FSUB", "FMUL", "FDIV",
    "FABS", "FNEG", "FSQRT",
    "FCMP", "FTST",
    "FSGLDIV", "FSGLMUL",
    "FINTRZ",
    "FINT",
    // FBcc, FDBcc, FScc, FTRAPcc
    "FBF", "FBEQ", "FBOGT", "FBOGE", "FBOLT", "FBOLE",
    "FBOGL", "FBOR", "FBUN", "FBUEQ", "FBUGT", "FBUGE",
    "FBULT", "FBULE", "FBNE", "FBT",
    // FSAVE / FRESTORE (supervisor)
    "FSAVE", "FRESTORE",
];

/// Check whether an FPU instruction mnemonic is in the 68040 hardware subset.
#[must_use]
pub fn is_fpu_040_native(mnemonic: &str) -> bool {
    FPU_040_SUBSET.contains(&mnemonic)
}

/// Instructions added by 68060 but missing/emulated on 68040.
/// The 68060 also drops MOVE16 and several others.
pub static FPU_060_NATIVE_ADDS: &[&str] = &[
    // 68060 re-adds FSIN/FCOS/FTAN/FSINCOS in hardware (optional FPU module)
    "FSIN", "FCOS", "FTAN", "FSINCOS",
];

// ── 68010 differences ─────────────────────────────────────────────────────────

/// Instructions added in 68010.
pub static M68010_NEW_INSTRS: &[(&str, &str)] = &[
    ("MOVEC",  "Move control register — reads/writes VBR, SFC, DFC, CACR, CAAR, MSP, ISP"),
    ("MOVES",  "Move with address space override (supervisor)"),
    ("RTD",    "Return and deallocate — RTS + adjust SP by displacement"),
    ("BKPT",   "Breakpoint — triggers bus cycle then ILLEGAL trap (development)"),
];

/// Instructions added in 68020.
pub static M68020_NEW_INSTRS: &[(&str, &str)] = &[
    ("BFCHG",  "Bitfield complement"),
    ("BFCLR",  "Bitfield clear"),
    ("BFEXTS", "Bitfield extract signed"),
    ("BFEXTU", "Bitfield extract unsigned"),
    ("BFFFO",  "Bitfield find first one"),
    ("BFINS",  "Bitfield insert"),
    ("BFSET",  "Bitfield set"),
    ("BFTST",  "Bitfield test"),
    ("CAS",    "Compare and swap — test mem, conditionally write (multiprocessing)"),
    ("CAS2",   "Compare and swap, dual operand"),
    ("CHK2",   "Check register against bounds (both signed and unsigned)"),
    ("CMP2",   "Compare register against bounds"),
    ("DIVSL",  "Signed 32-bit divide, 64-bit dividend"),
    ("DIVUL",  "Unsigned 32-bit divide, 64-bit dividend"),
    ("EXTB",   "Sign-extend byte to long word"),
    ("PACK",   "Pack BCD digits"),
    ("UNPK",   "Unpack BCD digits"),
    ("TRAPcc", "Conditional TRAP — trap if condition true"),
    ("CALLM",  "Call module (coprocessor protocol, removed 68030+)"),
    ("RTM",    "Return from module"),
];

/// Instructions removed or restricted in 68060.
pub static M68060_REMOVED: &[(&str, &str)] = &[
    ("ABCD",    "BCD add — emulated via 060 ISP"),
    ("SBCD",    "BCD subtract — emulated"),
    ("NBCD",    "BCD negate — emulated"),
    ("PACK",    "BCD pack — emulated"),
    ("UNPK",    "BCD unpack — emulated"),
    ("MOVEP",   "Move peripheral — removed (no MOVEP support)"),
    ("MOVE16",  "128-bit line move — removed in 060"),
    ("CALLM",   "Call module — removed since 68030"),
    ("RTM",     "Return from module — removed since 68030"),
    ("CHK2",    "Check range — emulated via 060 ISP"),
    ("CMP2",    "Compare range — emulated via 060 ISP"),
    ("CAS",     "Compare and swap — emulated"),
    ("CAS2",    "Compare and swap dual — emulated"),
];

// ── Instruction class table ────────────────────────────────────────────────────

/// High-level instruction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrClass {
    DataMove,
    IntArith,
    LogicBit,
    Shift,
    Bitfield,
    Bcd,
    Branch,
    Subroutine,
    Return,
    System,
    Fpu,
    Mmu,
    Cache,
}

impl InstrClass {
    #[must_use]
    pub fn from_mnemonic(mn: &str) -> Self {
        if mn.starts_with('F') {
            return Self::Fpu;
        }
        if mn.starts_with('P') {
            return Self::Mmu;
        }
        if matches!(mn, "CINV" | "CPUSH") {
            return Self::Cache;
        }
        match mn {
            "ADD" | "ADDA" | "ADDI" | "ADDQ" | "ADDX" |
            "SUB" | "SUBA" | "SUBI" | "SUBQ" | "SUBX" |
            "MULU" | "MULS" | "DIVU" | "DIVS" |
            "DIVSL" | "DIVUL" | "MULU_L" | "MULS_L" |
            "NEG" | "NEGX" | "CLR" | "CMP" | "CMPA" | "CMPI" | "CMPM" |
            "CHK" | "CHK2" | "CMP2" | "TAS" | "TST" => Self::IntArith,

            "AND" | "ANDI" | "OR" | "ORI" | "EOR" | "EORI" | "NOT" |
            "BTST" | "BSET" | "BCLR" | "BCHG" => Self::LogicBit,

            "ASL" | "ASR" | "LSL" | "LSR" | "ROL" | "ROR" | "ROXL" | "ROXR" => Self::Shift,

            "BFCHG" | "BFCLR" | "BFEXTS" | "BFEXTU" |
            "BFFFO" | "BFINS" | "BFSET" | "BFTST" => Self::Bitfield,

            "ABCD" | "SBCD" | "NBCD" | "PACK" | "UNPK" => Self::Bcd,

            "BRA" | "Bcc" | "BHI" | "BLS" | "BCC" | "BCS" | "BNE" | "BEQ" |
            "BVC" | "BVS" | "BPL" | "BMI" | "BGE" | "BLT" | "BGT" | "BLE" |
            "DBRA" | "DBcc" | "JMP" | "Scc" | "TRAPcc" => Self::Branch,

            "BSR" | "JSR" | "CALLM" => Self::Subroutine,

            "RTS" | "RTE" | "RTR" | "RTD" | "RTM" => Self::Return,

            "RESET" | "STOP" | "NOP" | "HALT" | "TRAP" | "TRAPV" | "ILLEGAL" |
            "MOVEC" | "MOVES" | "CAS" | "CAS2" | "BKPT" => Self::System,

            _ => Self::DataMove,
        }
    }
}

// ── Variant diff helper ───────────────────────────────────────────────────────

/// Return the list of instructions added when going from `from` to `to`.
#[must_use]
pub fn added_instructions(from: Mc68kVariant, to: Mc68kVariant) -> Vec<&'static str> {
    let caps_from = VariantCaps::for_variant(from);
    let caps_to   = VariantCaps::for_variant(to);
    M68010_NEW_INSTRS.iter().map(|e| e.0)
        .chain(M68020_NEW_INSTRS.iter().map(|e| e.0))
        .filter(|mn| caps_to.has_instruction(mn) && !caps_from.has_instruction(mn))
        .collect()
}

/// Return the list of instructions removed/emulated when going from `from` to `to`.
#[must_use]
pub fn removed_instructions(_from: Mc68kVariant, to: Mc68kVariant) -> Vec<&'static str> {
    if to == Mc68kVariant::M68060 {
        M68060_REMOVED.iter().map(|e| e.0).collect()
    } else {
        vec![]
    }
}
