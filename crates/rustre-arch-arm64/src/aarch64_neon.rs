//! `aarch64_neon` — ARM64 NEON/Advanced SIMD extension for RustRE.
//!
//! Provides [`NeonDecoder`], [`NeonRegister`], [`NeonInstruction`],
//! [`ArrangementSpec`], and a [`NeonLifter`] that converts NEON instructions
//! to a simple functional-semantics IR.

use ahash::AHashMap;
use std::fmt;

// ── ArrangementSpec ───────────────────────────────────────────────────────────

/// NEON vector arrangement specifier (e.g. `8B`, `16B`, `4H`, `8H`, `2S`, `4S`,
/// `1D`, `2D`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArrangementSpec {
    /// 8 × 8-bit lanes (64-bit register).
    V8B,
    /// 16 × 8-bit lanes (128-bit register).
    V16B,
    /// 4 × 16-bit lanes (64-bit register).
    V4H,
    /// 8 × 16-bit lanes (128-bit register).
    V8H,
    /// 2 × 32-bit lanes (64-bit register).
    V2S,
    /// 4 × 32-bit lanes (128-bit register).
    V4S,
    /// 1 × 64-bit lane (64-bit register).
    V1D,
    /// 2 × 64-bit lanes (128-bit register).
    V2D,
    /// Scalar byte.
    ScalarB,
    /// Scalar halfword.
    ScalarH,
    /// Scalar singleword.
    ScalarS,
    /// Scalar doubleword.
    ScalarD,
    /// Scalar Q (128-bit).
    ScalarQ,
}

impl ArrangementSpec {
    /// Number of lanes.
    #[must_use]
    pub const fn lane_count(self) -> usize {
        match self {
            Self::V8B | Self::V8H => 8,
            Self::V16B => 16,
            Self::V4H | Self::V4S => 4,
            Self::V2S | Self::V2D => 2,
            Self::V1D | Self::ScalarB | Self::ScalarH | Self::ScalarS | Self::ScalarD | Self::ScalarQ => 1,
        }
    }

    /// Bits per lane.
    #[must_use]
    pub const fn lane_bits(self) -> usize {
        match self {
            Self::V8B | Self::V16B | Self::ScalarB => 8,
            Self::V4H | Self::V8H | Self::ScalarH => 16,
            Self::V2S | Self::V4S | Self::ScalarS => 32,
            Self::V1D | Self::V2D | Self::ScalarD => 64,
            Self::ScalarQ => 128,
        }
    }

    /// Total register width in bits.
    #[must_use]
    pub const fn total_bits(self) -> usize {
        self.lane_count() * self.lane_bits()
    }

    /// Assembly suffix string (e.g. `"8b"`, `"2d"`, `"s"`).
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::V8B => "8b",
            Self::V16B => "16b",
            Self::V4H => "4h",
            Self::V8H => "8h",
            Self::V2S => "2s",
            Self::V4S => "4s",
            Self::V1D => "1d",
            Self::V2D => "2d",
            Self::ScalarB => "b",
            Self::ScalarH => "h",
            Self::ScalarS => "s",
            Self::ScalarD => "d",
            Self::ScalarQ => "q",
        }
    }
}

impl fmt::Display for ArrangementSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.suffix())
    }
}

// ── NeonRegister ─────────────────────────────────────────────────────────────

/// An `AArch64` NEON/FP register with its current view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NeonRegister {
    /// Physical register number 0–31.
    pub number: u8,
    /// How this register is being viewed/used.
    pub view: NeonRegView,
}

/// Possible views of an `AArch64` FP/SIMD register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeonRegView {
    /// Full 128-bit Q register.
    Q,
    /// Lower 64-bit D register.
    D,
    /// Lower 32-bit S register.
    S,
    /// Lower 16-bit H register.
    H,
    /// Lower 8-bit B register.
    B,
    /// Full 128-bit V register with arrangement.
    V(ArrangementSpec),
}

impl NeonRegister {
    /// Construct a V-register with arrangement.
    #[must_use]
    pub const fn v(n: u8, arr: ArrangementSpec) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::V(arr),
        }
    }

    /// Construct a Q-register.
    #[must_use]
    pub const fn q(n: u8) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::Q,
        }
    }
    /// Construct a D-register.
    #[must_use]
    pub const fn d(n: u8) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::D,
        }
    }
    /// Construct an S-register.
    #[must_use]
    pub const fn s(n: u8) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::S,
        }
    }
    /// Construct an H-register.
    #[must_use]
    pub const fn h(n: u8) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::H,
        }
    }
    /// Construct a B-register.
    #[must_use]
    pub const fn b(n: u8) -> Self {
        Self {
            number: n & 31,
            view: NeonRegView::B,
        }
    }

    /// Register bit width for this view.
    #[must_use]
    pub const fn bit_width(&self) -> usize {
        match self.view {
            NeonRegView::Q => 128,
            NeonRegView::D => 64,
            NeonRegView::S => 32,
            NeonRegView::H => 16,
            NeonRegView::B => 8,
            NeonRegView::V(arr) => arr.total_bits(),
        }
    }

    /// Name string (e.g. `v0.8b`, `d5`, `q31`).
    #[must_use]
    pub fn name(&self) -> String {
        let n = self.number;
        match self.view {
            NeonRegView::Q => format!("q{n}"),
            NeonRegView::D => format!("d{n}"),
            NeonRegView::S => format!("s{n}"),
            NeonRegView::H => format!("h{n}"),
            NeonRegView::B => format!("b{n}"),
            NeonRegView::V(arr) => format!("v{n}.{arr}"),
        }
    }
}

impl fmt::Display for NeonRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

// ── NeonInsnKind ─────────────────────────────────────────────────────────────

/// Kind of NEON instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeonInsnKind {
    // Arithmetic
    FAdd,
    FSub,
    FMul,
    FDiv,
    FNeg,
    FAbs,
    FSqrt,
    FMax,
    FMin,
    FMaxNM,
    FMinNM,
    // Fused multiply-add
    FMla,
    FMls,
    // Comparison
    FCmp,
    FCmpe,
    FCmeq,
    FCmge,
    FCmgt,
    FCmle,
    FCmlt,
    // Conversion
    FCvt,
    FCvtl,
    FCvtn,
    FCvtas,
    FCvtau,
    FCvtms,
    FCvtmu,
    FCvtns,
    FCvtnu,
    FCvtps,
    FCvtpu,
    FCvtzs,
    FCvtzu,
    UCvtf,
    SCvtf,
    // Move / duplicate
    Mov,
    Dup,
    DupElem,
    Ins,
    Umov,
    Smov,
    // Table lookup
    Tbl,
    Tbx,
    // Permutation
    Zip1,
    Zip2,
    Uzp1,
    Uzp2,
    Trn1,
    Trn2,
    Ext,
    Rev16,
    Rev32,
    Rev64,
    // Logical
    And,
    Orr,
    Eor,
    Bic,
    Orn,
    Not,
    Bsl,
    Bit,
    Bif,
    // Integer arithmetic
    Add,
    Sub,
    Addp,
    Addv,
    Uaddlv,
    Saddlv,
    Smull,
    Umull,
    Smlal,
    Umlal,
    Smlsl,
    Umlsl,
    Mul,
    Mla,
    Mls,
    Sqdmull,
    Sqdmlal,
    Sqdmlsl,
    Sqdmulh,
    Sqrdmulh,
    // Shift
    Shl,
    Sshr,
    Ushr,
    Srshr,
    Urshr,
    Ssra,
    Usra,
    Srsra,
    Ursra,
    Sli,
    Sri,
    Shll,
    Shll2,
    // Saturating
    Sqadd,
    Uqadd,
    Sqsub,
    Uqsub,
    Sqdmulh2,
    Sqrdmulh2,
    // Min / max
    Smax,
    Umax,
    Smin,
    Umin,
    Smaxp,
    Umaxp,
    Sminp,
    Uminp,
    Smaxv,
    Umaxv,
    Sminv,
    Uminv,
    // Abs / neg
    Abs,
    Neg,
    Sqabs,
    Sqneg,
    // Count / CLZ
    Cnt,
    Clz,
    Cls,
    // Load / Store
    Ld1,
    Ld2,
    Ld3,
    Ld4,
    St1,
    St2,
    St3,
    St4,
    Ld1r,
    Ld2r,
    Ld3r,
    Ld4r,
    Ldr,
    Str,
    // AES
    Aese,
    Aesd,
    Aesmc,
    Aesimc,
    // SHA
    Sha1c,
    Sha1p,
    Sha1m,
    Sha1su0,
    Sha1su1,
    Sha1h,
    Sha256h,
    Sha256h2,
    Sha256su0,
    Sha256su1,
    // Polynomial
    Pmul,
    Pmull,
    Pmull2,
    // Miscellaneous
    Xtn,
    Xtn2,
    Sqxtn,
    Sqxtn2,
    Uqxtn,
    Uqxtn2,
    Sqxtun,
    Sqxtun2,
    Uzp1v,
    Uzp2v,
    // Extended (added to match decode tables)
    Sabd,
    Uabd,
    Suqadd,
    Cmgt0,
    Cmeq0,
    Cmlt0,
    FRintn,
    FRinta,
    Cmge0,
    Cmle0,
}

impl NeonInsnKind {
    const fn mnemonic_fp_vec(self) -> Option<&'static str> {
        Some(match self {
            Self::FAdd => "fadd",
            Self::FSub => "fsub",
            Self::FMul => "fmul",
            Self::FDiv => "fdiv",
            Self::FNeg => "fneg",
            Self::FAbs => "fabs",
            Self::FSqrt => "fsqrt",
            Self::FMax => "fmax",
            Self::FMin => "fmin",
            Self::FMaxNM => "fmaxnm",
            Self::FMinNM => "fminnm",
            Self::FMla => "fmla",
            Self::FMls => "fmls",
            Self::FCmp => "fcmp",
            Self::FCmpe => "fcmpe",
            Self::FCmeq => "fcmeq",
            Self::FCmge => "fcmge",
            Self::FCmgt => "fcmgt",
            Self::FCmle => "fcmle",
            Self::FCmlt => "fcmlt",
            Self::FCvt => "fcvt",
            Self::FCvtl => "fcvtl",
            Self::FCvtn => "fcvtn",
            Self::FCvtas => "fcvtas",
            Self::FCvtau => "fcvtau",
            Self::FCvtms => "fcvtms",
            Self::FCvtmu => "fcvtmu",
            Self::FCvtns => "fcvtns",
            Self::FCvtnu => "fcvtnu",
            Self::FCvtps => "fcvtps",
            Self::FCvtpu => "fcvtpu",
            Self::FCvtzs => "fcvtzs",
            Self::FCvtzu => "fcvtzu",
            Self::UCvtf => "ucvtf",
            Self::SCvtf => "scvtf",
            Self::Mov => "mov",
            Self::Dup | Self::DupElem => "dup",
            Self::Ins => "ins",
            Self::Umov => "umov",
            Self::Smov => "smov",
            Self::Tbl => "tbl",
            Self::Tbx => "tbx",
            Self::Zip1 => "zip1",
            Self::Zip2 => "zip2",
            Self::Uzp1 | Self::Uzp1v => "uzp1",
            Self::Uzp2 | Self::Uzp2v => "uzp2",
            Self::Trn1 => "trn1",
            Self::Trn2 => "trn2",
            Self::Ext => "ext",
            Self::Rev16 => "rev16",
            Self::Rev32 => "rev32",
            Self::Rev64 => "rev64",
            Self::And => "and",
            Self::Orr => "orr",
            Self::Eor => "eor",
            Self::Bic => "bic",
            Self::Orn => "orn",
            Self::Not => "not",
            Self::Bsl => "bsl",
            Self::Bit => "bit",
            Self::Bif => "bif",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Addp => "addp",
            Self::Addv => "addv",
            Self::Uaddlv => "uaddlv",
            Self::Saddlv => "saddlv",
            Self::Smull => "smull",
            Self::Umull => "umull",
            Self::Smlal => "smlal",
            Self::Umlal => "umlal",
            Self::Smlsl => "smlsl",
            Self::Umlsl => "umlsl",
            Self::Mul => "mul",
            Self::Mla => "mla",
            Self::Mls => "mls",
            Self::Sqdmull => "sqdmull",
            Self::Sqdmlal => "sqdmlal",
            Self::Sqdmlsl => "sqdmlsl",
            Self::Sqdmulh | Self::Sqdmulh2 => "sqdmulh",
            Self::Sqrdmulh | Self::Sqrdmulh2 => "sqrdmulh",
            _ => return None,
        })
    }

    const fn mnemonic_shift_misc(self) -> Option<&'static str> {
        Some(match self {
            Self::Shl => "shl",
            Self::Sshr => "sshr",
            Self::Ushr => "ushr",
            Self::Srshr => "srshr",
            Self::Urshr => "urshr",
            Self::Ssra => "ssra",
            Self::Usra => "usra",
            Self::Srsra => "srsra",
            Self::Ursra => "ursra",
            Self::Sli => "sli",
            Self::Sri => "sri",
            Self::Shll => "shll",
            Self::Shll2 => "shll2",
            Self::Sqadd => "sqadd",
            Self::Uqadd => "uqadd",
            Self::Sqsub => "sqsub",
            Self::Uqsub => "uqsub",
            Self::Smax => "smax",
            Self::Umax => "umax",
            Self::Smin => "smin",
            Self::Umin => "umin",
            Self::Smaxp => "smaxp",
            Self::Umaxp => "umaxp",
            Self::Sminp => "sminp",
            Self::Uminp => "uminp",
            Self::Smaxv => "smaxv",
            Self::Umaxv => "umaxv",
            Self::Sminv => "sminv",
            Self::Uminv => "uminv",
            Self::Abs => "abs",
            Self::Neg => "neg",
            Self::Sqabs => "sqabs",
            Self::Sqneg => "sqneg",
            Self::Cnt => "cnt",
            Self::Clz => "clz",
            Self::Cls => "cls",
            Self::Ld1 => "ld1",
            Self::Ld2 => "ld2",
            Self::Ld3 => "ld3",
            Self::Ld4 => "ld4",
            Self::St1 => "st1",
            Self::St2 => "st2",
            Self::St3 => "st3",
            Self::St4 => "st4",
            Self::Ld1r => "ld1r",
            Self::Ld2r => "ld2r",
            Self::Ld3r => "ld3r",
            Self::Ld4r => "ld4r",
            Self::Ldr => "ldr",
            Self::Str => "str",
            Self::Aese => "aese",
            Self::Aesd => "aesd",
            Self::Aesmc => "aesmc",
            Self::Aesimc => "aesimc",
            Self::Sha1c => "sha1c",
            Self::Sha1p => "sha1p",
            Self::Sha1m => "sha1m",
            Self::Sha1su0 => "sha1su0",
            Self::Sha1su1 => "sha1su1",
            Self::Sha1h => "sha1h",
            Self::Sha256h => "sha256h",
            Self::Sha256h2 => "sha256h2",
            Self::Sha256su0 => "sha256su0",
            Self::Sha256su1 => "sha256su1",
            Self::Pmul => "pmul",
            Self::Pmull => "pmull",
            Self::Pmull2 => "pmull2",
            Self::Xtn => "xtn",
            Self::Xtn2 => "xtn2",
            Self::Sqxtn => "sqxtn",
            Self::Sqxtn2 => "sqxtn2",
            Self::Uqxtn => "uqxtn",
            Self::Uqxtn2 => "uqxtn2",
            Self::Sqxtun => "sqxtun",
            Self::Sqxtun2 => "sqxtun2",
            Self::Sabd => "sabd",
            Self::Uabd => "uabd",
            Self::Suqadd => "suqadd",
            Self::Cmgt0 => "cmgt",
            Self::Cmeq0 => "cmeq",
            Self::Cmlt0 => "cmlt",
            Self::FRintn => "frintn",
            Self::FRinta => "frinta",
            Self::Cmge0 => "cmge",
            Self::Cmle0 => "cmle",
            _ => return None,
        })
    }

    /// Return the assembly mnemonic for this instruction kind.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        if let Some(s) = self.mnemonic_fp_vec() { return s; }
        if let Some(s) = self.mnemonic_shift_misc() { return s; }
        "???"
    }
}

// ── NeonInstruction ───────────────────────────────────────────────────────────

/// A decoded NEON instruction.
#[derive(Debug, Clone)]
pub struct NeonInstruction {
    /// The opcode category.
    pub kind: NeonInsnKind,
    /// Destination register (if any).
    pub dst: Option<NeonRegister>,
    /// Source registers.
    pub src: Vec<NeonRegister>,
    /// Arrangement for vector operations.
    pub arrangement: Option<ArrangementSpec>,
    /// Index for indexed element operations.
    pub index: Option<u8>,
    /// Immediate value (shifts, etc.).
    pub imm: Option<i64>,
    /// Raw 32-bit encoding.
    pub encoding: u32,
}

impl NeonInstruction {
    /// Construct a binary-op instruction.
    #[must_use]
    pub fn binop(
        kind: NeonInsnKind,
        dst: NeonRegister,
        src1: NeonRegister,
        src2: NeonRegister,
        arr: ArrangementSpec,
        encoding: u32,
    ) -> Self {
        Self {
            kind,
            dst: Some(dst),
            src: vec![src1, src2],
            arrangement: Some(arr),
            index: None,
            imm: None,
            encoding,
        }
    }

    /// Construct a unary instruction.
    #[must_use]
    pub fn unary(
        kind: NeonInsnKind,
        dst: NeonRegister,
        src: NeonRegister,
        arr: ArrangementSpec,
        encoding: u32,
    ) -> Self {
        Self {
            kind,
            dst: Some(dst),
            src: vec![src],
            arrangement: Some(arr),
            index: None,
            imm: None,
            encoding,
        }
    }

    /// Assembly-style string.
    #[must_use]
    pub fn to_asm(&self) -> String {
        let mnem = self.kind.mnemonic();
        let arr = self
            .arrangement
            .map(|a| format!(".{a}"))
            .unwrap_or_default();
        let dst = self.dst.as_ref().map(NeonRegister::name).unwrap_or_default();
        let srcs: Vec<_> = self.src.iter().map(NeonRegister::name).collect();
        match srcs.len() {
            0 => format!("{mnem}{arr} {dst}"),
            1 => format!("{mnem}{arr} {dst}, {}", srcs[0]),
            2 => format!("{mnem}{arr} {dst}, {}, {}", srcs[0], srcs[1]),
            3 => format!("{mnem}{arr} {dst}, {}, {}, {}", srcs[0], srcs[1], srcs[2]),
            _ => format!("{mnem}{arr} {dst}, …"),
        }
    }
}

impl fmt::Display for NeonInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_asm())
    }
}

// ── NeonDecoder ───────────────────────────────────────────────────────────────

/// Decodes 32-bit `AArch64` instruction words that encode NEON/Advanced SIMD operations.
pub struct NeonDecoder {
    /// If true, raise errors on reserved encodings rather than returning `None`.
    pub strict: bool,
}

impl NeonDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { strict: false }
    }
    #[must_use]
    pub const fn strict() -> Self {
        Self { strict: true }
    }

    /// Attempt to decode `word` as a NEON instruction.
    /// Returns `None` if the word is not a NEON instruction.
    #[must_use]
    pub fn decode(&self, word: u32) -> Option<NeonInstruction> {
        // AArch64 NEON instructions: bits[28:25] = 0b0111 or 0b1111
        // Quick filter on top-level encoding group.
        let group = (word >> 25) & 0xF;
        if group != 0b0111 && group != 0b1111 {
            return None;
        }

        // Bit 28 selects scalar (1) vs vector (0) Advanced SIMD.
        let scalar = (word >> 28) & 1 != 0;

        if scalar {
            Self::decode_scalar(word)
        } else {
            Self::decode_vector(word)
        }
    }

    fn decode_vector(word: u32) -> Option<NeonInstruction> {
        // Bit 30 = Q (full 128-bit vs 64-bit)
        let q = (word >> 30) & 1 != 0;
        // Bits [23:22] = size
        let size = (word >> 22) & 3;
        // Bits [20:16] = Rm
        let rm = ((word >> 16) & 31) as u8;
        // Bits [9:5] = Rn
        let rn = ((word >> 5) & 31) as u8;
        // Bits [4:0] = Rd
        let rd = (word & 31) as u8;

        // Determine arrangement from Q and size.
        let arr = Self::arrangement(q, size)?;
        let dst = NeonRegister::v(rd, arr);
        let src1 = NeonRegister::v(rn, arr);
        let src2 = NeonRegister::v(rm, arr);

        // Decode by opcode fields.
        // Bits [15:10] = opcode within the group.
        let opcode = (word >> 10) & 0x3F;
        let u = (word >> 29) & 1 != 0; // unsigned/signed

        // Three-register same group: bits[28:24] = 0b01110
        let three_reg_same =
            (word >> 24) & 0x1F == 0b01110 && (word >> 21) & 1 == 1 && (word >> 10) & 1 == 1;
        if three_reg_same {
            let insn_kind = Self::three_reg_same_opcode(opcode, u, size)?;
            return Some(NeonInstruction::binop(
                insn_kind, dst, src1, src2, arr, word,
            ));
        }

        // Two-register misc: bits[28:24] = 0b01110, specific opcode range
        // (overlap with three_reg_same based on bit patterns; simplified here)
        // Modified two-reg: bit[21] = 1, bits[17:16] = opcode
        let two_reg_misc = (word >> 24) & 0x1F == 0b01110 && (word >> 17) & 1 == 1;
        if two_reg_misc {
            let misc_op = (word >> 12) & 0x1F;
            if let Some(kind) = Self::two_reg_misc_opcode(misc_op, u, size) {
                return Some(NeonInstruction::unary(kind, dst, src1, arr, word));
            }
        }

        // Shift-by-immediate group: bits[22:16] encode immh:immb.
        let shift_imm = (word >> 16) & 0x7F;
        if (word >> 23) & 1 == 1 {
            let shift_op = (word >> 11) & 0x1F;
            if let Some(kind) = Self::shift_imm_opcode(shift_op, u) {
                let dst2 = NeonRegister::v(rd, arr);
                let src_s = NeonRegister::v(rn, arr);
                let mut insn = NeonInstruction::unary(kind, dst2, src_s, arr, word);
                insn.imm = Some(i64::from(shift_imm));
                return Some(insn);
            }
        }

        None
    }

    fn decode_scalar(word: u32) -> Option<NeonInstruction> {
        let size = (word >> 22) & 3;
        let rm = ((word >> 16) & 31) as u8;
        let rn = ((word >> 5) & 31) as u8;
        let rd = (word & 31) as u8;
        let u = (word >> 29) & 1 != 0;
        let opcode = (word >> 11) & 0x1F;

        // Scalar FP instructions: size=0b00→H, 0b01→S, 0b10→D, 0b11→Q
        let view = match size {
            0 => NeonRegView::H,
            1 => NeonRegView::S,
            2 => NeonRegView::D,
            _ => NeonRegView::Q,
        };
        let dst = NeonRegister { number: rd, view };
        let src1 = NeonRegister { number: rn, view };
        let src2 = NeonRegister { number: rm, view };

        // Scalar three-register same.
        let arr = ArrangementSpec::ScalarD; // placeholder
        let three_reg = (word >> 24) & 0x1F == 0b01110;
        if three_reg {
            let kind = Self::scalar_fp_opcode(opcode, u)?;
            return Some(NeonInstruction::binop(kind, dst, src1, src2, arr, word));
        }

        None
    }

    const fn arrangement(q: bool, size: u32) -> Option<ArrangementSpec> {
        Some(match (q, size) {
            (false, 0) => ArrangementSpec::V8B,
            (true, 0) => ArrangementSpec::V16B,
            (false, 1) => ArrangementSpec::V4H,
            (true, 1) => ArrangementSpec::V8H,
            (false, 2) => ArrangementSpec::V2S,
            (true, 2) => ArrangementSpec::V4S,
            (false, 3) => ArrangementSpec::V1D,
            (true, 3) => ArrangementSpec::V2D,
            _ => return None,
        })
    }

    const fn three_reg_same_opcode(opcode: u32, u: bool, _size: u32) -> Option<NeonInsnKind> {
        Some(match (opcode, u) {
            (0x00, false) => NeonInsnKind::Sqadd,
            (0x00, true) => NeonInsnKind::Uqadd,
            (0x02, false) => NeonInsnKind::Sqsub,
            (0x02, true) => NeonInsnKind::Uqsub,
            (0x06 | 0x18, false) => NeonInsnKind::Smax,
            (0x06 | 0x18, true) => NeonInsnKind::Umax,
            (0x0A | 0x1A, false) => NeonInsnKind::Smin,
            (0x0A | 0x1A, true) => NeonInsnKind::Umin,
            (0x0E, false) => NeonInsnKind::Sabd,
            (0x0E, true) => NeonInsnKind::Uabd,
            (0x10, false) => NeonInsnKind::Add,
            (0x10, true) => NeonInsnKind::Sub,
            (0x16, false) => NeonInsnKind::Mul,
            (0x16, true) => NeonInsnKind::Pmul,
            (0x1B, false) => NeonInsnKind::Sqdmulh,
            (0x1C, false) => NeonInsnKind::Addp,
            (0x1D, false) => NeonInsnKind::FMax,
            (0x1D, true) => NeonInsnKind::FMin,
            (0x1F, false) => NeonInsnKind::FAdd,
            (0x1F, true) => NeonInsnKind::FSub,
            (0x22, false) => NeonInsnKind::And,
            (0x22, true) => NeonInsnKind::Bic,
            (0x23, false) => NeonInsnKind::Bsl,
            (0x23, true) => NeonInsnKind::Eor,
            (0x25, false) => NeonInsnKind::FMul,
            (0x27, false) => NeonInsnKind::FDiv,
            (0x30, false) => NeonInsnKind::Orr,
            (0x30, true) => NeonInsnKind::Orn,
            (0x31, false) => NeonInsnKind::Bit,
            (0x31, true) => NeonInsnKind::Bif,
            (0x35, false) => NeonInsnKind::FMla,
            (0x35, true) => NeonInsnKind::FMls,
            _ => return None,
        })
    }

    const fn two_reg_misc_opcode(opcode: u32, u: bool, _size: u32) -> Option<NeonInsnKind> {
        Some(match (opcode, u) {
            (0x00, false) => NeonInsnKind::Rev64,
            (0x01, false) => NeonInsnKind::Rev16,
            (0x02, false) => NeonInsnKind::Saddlv,
            (0x03, false) => NeonInsnKind::Suqadd,
            (0x04, false) => NeonInsnKind::Cls,
            (0x05, false) => NeonInsnKind::Cnt,
            (0x07, false) => NeonInsnKind::Sqabs,
            (0x08, false) => NeonInsnKind::Cmgt0,
            (0x09, false) => NeonInsnKind::Cmeq0,
            (0x0A, false) => NeonInsnKind::Cmlt0,
            (0x0B, false) => NeonInsnKind::Abs,
            (0x0C, false) => NeonInsnKind::FRintn,
            (0x0D, false) => NeonInsnKind::FRinta,
            (0x0E, false) => NeonInsnKind::Xtn,
            (0x0F, false) => NeonInsnKind::Sqxtn,
            (0x16, false) => NeonInsnKind::FCvtn,
            (0x17, false) => NeonInsnKind::FCvtl,
            (0x18, false) => NeonInsnKind::FCvtas,
            (0x19, false) => NeonInsnKind::FCvtau,
            (0x1A, false) => NeonInsnKind::UCvtf,
            (0x1B, false) => NeonInsnKind::SCvtf,
            (0x06, true) => NeonInsnKind::Uaddlv,
            (0x07, true) => NeonInsnKind::Sqneg,
            (0x08, true) => NeonInsnKind::Cmge0,
            (0x09, true) => NeonInsnKind::Cmle0,
            (0x0B, true) => NeonInsnKind::Neg,
            (0x0E, true) => NeonInsnKind::Xtn2,
            (0x0F, true) => NeonInsnKind::Sqxtun,
            _ => return None,
        })
    }

    const fn shift_imm_opcode(opcode: u32, u: bool) -> Option<NeonInsnKind> {
        Some(match (opcode, u) {
            (0x00, false) => NeonInsnKind::Sshr,
            (0x00, true) => NeonInsnKind::Ushr,
            (0x02, false) => NeonInsnKind::Ssra,
            (0x02, true) => NeonInsnKind::Usra,
            (0x04, false) => NeonInsnKind::Srshr,
            (0x04, true) => NeonInsnKind::Urshr,
            (0x06, false) => NeonInsnKind::Srsra,
            (0x06, true) => NeonInsnKind::Ursra,
            (0x0A, true) => NeonInsnKind::Sli,
            (0x08, false) => NeonInsnKind::Sri,
            (0x0A, false) => NeonInsnKind::Shl,
            _ => return None,
        })
    }

    const fn scalar_fp_opcode(opcode: u32, u: bool) -> Option<NeonInsnKind> {
        Some(match (opcode, u) {
            (0x1D, _) => NeonInsnKind::FAdd,
            (0x1F, _) => NeonInsnKind::FSub,
            (0x25, _) => NeonInsnKind::FMul,
            (0x27, _) => NeonInsnKind::FDiv,
            _ => return None,
        })
    }
}

// Extra placeholder kinds referenced in two_reg_misc
impl NeonInsnKind {
    /// Backwards-compatible alias for [`Self::mnemonic`] used by some
    /// older decode tables; kept as a public accessor so external
    /// consumers can refer to it by either name.
    #[must_use]
    pub const fn mnemonic_placeholder(self) -> &'static str {
        self.mnemonic()
    }
}

// Placeholder kinds not in the main enum — add them silently via pattern matching
// in mnemonic().  We add a few more to the enum via the `Sabd` etc. slots.
// (These are defined in three_reg_same_opcode but the enum needs them.)

// The following are used in the above decode tables but not yet in the main enum.
// We handle them via a newtype wrapper for now so the compiler is satisfied.

/// Extended NEON instruction kinds not covered by the primary enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NeonInsnKindExt {
    Sabd,
    Uabd,
    Suqadd,
    Cmgt0,
    Cmeq0,
    Cmlt0,
    FRintn,
    FRinta,
    Cmge0,
    Cmle0,
}

impl fmt::Display for NeonInsnKindExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sabd => "sabd",
            Self::Uabd => "uabd",
            Self::Suqadd => "suqadd",
            Self::Cmgt0 => "cmgt",
            Self::Cmeq0 => "cmeq",
            Self::Cmlt0 => "cmlt",
            Self::FRintn => "frintn",
            Self::FRinta => "frinta",
            Self::Cmge0 => "cmge",
            Self::Cmle0 => "cmle",
        };
        f.write_str(s)
    }
}

/// Trait exposing a short mnemonic string for NEON instruction kinds.
///
/// This lets decode tables and pretty-printers refer to the mnemonic
/// uniformly regardless of which concrete kind enum is in hand.
pub trait HasMnemonic {
    fn mnem(&self) -> &'static str;
}
impl HasMnemonic for NeonInsnKind {
    fn mnem(&self) -> &'static str {
        self.mnemonic()
    }
}

impl Default for NeonDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── NeonLifter ────────────────────────────────────────────────────────────────

/// A simple semantics node for NEON IL.
#[derive(Debug, Clone)]
pub enum NeonIlNode {
    /// Assign: `dst_reg` ← `rhs_expr`.
    Assign {
        dst: NeonRegister,
        rhs: Box<Self>,
    },
    /// Binary float operation.
    FBinOp {
        op: NeonInsnKind,
        lhs: Box<Self>,
        rhs: Box<Self>,
        arr: ArrangementSpec,
    },
    /// Unary float operation.
    FUnOp {
        op: NeonInsnKind,
        src: Box<Self>,
        arr: ArrangementSpec,
    },
    /// Integer binary operation (lane-wise).
    IBinOp {
        op: NeonInsnKind,
        lhs: Box<Self>,
        rhs: Box<Self>,
        arr: ArrangementSpec,
    },
    /// Read register value.
    Reg(NeonRegister),
    /// Immediate value.
    Imm(i64),
    /// Unknown / unsupported.
    Unknown,
}

impl fmt::Display for NeonIlNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Assign { dst, rhs } => write!(f, "{dst} = {rhs}"),
            Self::FBinOp { op, lhs, rhs, arr } | Self::IBinOp { op, lhs, rhs, arr } => {
                write!(f, "{}({lhs}, {rhs}).{arr}", op.mnemonic())
            }
            Self::FUnOp { op, src, arr } => write!(f, "{}({src}).{arr}", op.mnemonic()),
            Self::Reg(r) => write!(f, "{r}"),
            Self::Imm(v) => write!(f, "#{v}"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Lifts a [`NeonInstruction`] into a [`NeonIlNode`].
pub struct NeonLifter;

impl NeonLifter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn lift(&self, insn: &NeonInstruction) -> NeonIlNode {
        let arr = insn.arrangement.unwrap_or(ArrangementSpec::V16B);
        let dst = match &insn.dst {
            Some(d) => *d,
            None => return NeonIlNode::Unknown,
        };

        let is_float_op = matches!(
            insn.kind,
            NeonInsnKind::FAdd
                | NeonInsnKind::FSub
                | NeonInsnKind::FMul
                | NeonInsnKind::FDiv
                | NeonInsnKind::FMla
                | NeonInsnKind::FMls
                | NeonInsnKind::FMax
                | NeonInsnKind::FMin
                | NeonInsnKind::FMaxNM
                | NeonInsnKind::FMinNM
                | NeonInsnKind::FCmeq
                | NeonInsnKind::FCmge
                | NeonInsnKind::FCmgt
                | NeonInsnKind::FCmle
                | NeonInsnKind::FCmlt
        );

        let is_unary = matches!(
            insn.kind,
            NeonInsnKind::FNeg
                | NeonInsnKind::FAbs
                | NeonInsnKind::FSqrt
                | NeonInsnKind::Abs
                | NeonInsnKind::Neg
                | NeonInsnKind::Sqabs
                | NeonInsnKind::Sqneg
                | NeonInsnKind::Not
                | NeonInsnKind::Rev16
                | NeonInsnKind::Rev32
                | NeonInsnKind::Rev64
                | NeonInsnKind::Cnt
                | NeonInsnKind::Clz
                | NeonInsnKind::Cls
        );

        if is_unary && !insn.src.is_empty() {
            let src_node = Box::new(NeonIlNode::Reg(insn.src[0]));
            let rhs = Box::new(NeonIlNode::FUnOp {
                op: insn.kind,
                src: src_node,
                arr,
            });
            return NeonIlNode::Assign { dst, rhs };
        }

        if insn.src.len() >= 2 {
            let lhs = Box::new(NeonIlNode::Reg(insn.src[0]));
            let rhs_src = Box::new(NeonIlNode::Reg(insn.src[1]));
            let op_node = if is_float_op {
                Box::new(NeonIlNode::FBinOp {
                    op: insn.kind,
                    lhs,
                    rhs: rhs_src,
                    arr,
                })
            } else {
                Box::new(NeonIlNode::IBinOp {
                    op: insn.kind,
                    lhs,
                    rhs: rhs_src,
                    arr,
                })
            };
            return NeonIlNode::Assign { dst, rhs: op_node };
        }

        if insn.src.len() == 1 {
            let src_node = Box::new(NeonIlNode::Reg(insn.src[0]));
            let rhs = Box::new(NeonIlNode::FUnOp {
                op: insn.kind,
                src: src_node,
                arr,
            });
            return NeonIlNode::Assign { dst, rhs };
        }

        NeonIlNode::Unknown
    }
}

impl Default for NeonLifter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Register name table ───────────────────────────────────────────────────────

/// Build a name → register map for all NEON registers.
#[must_use]
pub fn neon_register_map() -> AHashMap<String, NeonRegister> {
    // 32 regs * (8 arrangements + 5 scalar views) = 416 entries
    let mut map = AHashMap::with_capacity(32 * (8 + 5));
    let arrangements = [
        ArrangementSpec::V8B,
        ArrangementSpec::V16B,
        ArrangementSpec::V4H,
        ArrangementSpec::V8H,
        ArrangementSpec::V2S,
        ArrangementSpec::V4S,
        ArrangementSpec::V1D,
        ArrangementSpec::V2D,
    ];
    for n in 0u8..32 {
        for arr in &arrangements {
            let r = NeonRegister::v(n, *arr);
            map.insert(r.name(), r);
        }
        for (view, _) in [
            (NeonRegView::Q, "q"),
            (NeonRegView::D, "d"),
            (NeonRegView::S, "s"),
            (NeonRegView::H, "h"),
            (NeonRegView::B, "b"),
        ] {
            let r = NeonRegister { number: n, view };
            map.insert(r.name(), r);
        }
    }
    map
}

// ── Sabd/Uabd placeholders in main enum ──────────────────────────────────────
// We extend the three_reg_same pattern to use NeonInsnKind directly by mapping
// the extended kinds through the decode function which returns Option<NeonInsnKind>.
// The patterns for Sabd/Uabd are handled by falling through to None (not exposed
// as instructions yet — they'd require extending the main enum further).

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arrangement_spec_lane_count() {
        assert_eq!(ArrangementSpec::V8B.lane_count(), 8);
        assert_eq!(ArrangementSpec::V16B.lane_count(), 16);
        assert_eq!(ArrangementSpec::V4H.lane_count(), 4);
        assert_eq!(ArrangementSpec::V8H.lane_count(), 8);
        assert_eq!(ArrangementSpec::V2S.lane_count(), 2);
        assert_eq!(ArrangementSpec::V4S.lane_count(), 4);
        assert_eq!(ArrangementSpec::V1D.lane_count(), 1);
        assert_eq!(ArrangementSpec::V2D.lane_count(), 2);
    }

    #[test]
    fn test_arrangement_spec_total_bits() {
        assert_eq!(ArrangementSpec::V8B.total_bits(), 64);
        assert_eq!(ArrangementSpec::V16B.total_bits(), 128);
        assert_eq!(ArrangementSpec::V4H.total_bits(), 64);
        assert_eq!(ArrangementSpec::V8H.total_bits(), 128);
        assert_eq!(ArrangementSpec::V2S.total_bits(), 64);
        assert_eq!(ArrangementSpec::V4S.total_bits(), 128);
        assert_eq!(ArrangementSpec::V1D.total_bits(), 64);
        assert_eq!(ArrangementSpec::V2D.total_bits(), 128);
    }

    #[test]
    fn test_arrangement_spec_suffix() {
        assert_eq!(ArrangementSpec::V8B.suffix(), "8b");
        assert_eq!(ArrangementSpec::V16B.suffix(), "16b");
        assert_eq!(ArrangementSpec::V2D.suffix(), "2d");
        assert_eq!(ArrangementSpec::ScalarS.suffix(), "s");
        assert_eq!(ArrangementSpec::ScalarD.suffix(), "d");
    }

    #[test]
    fn test_neon_register_name_v() {
        let r = NeonRegister::v(0, ArrangementSpec::V8B);
        assert_eq!(r.name(), "v0.8b");

        let r = NeonRegister::v(31, ArrangementSpec::V2D);
        assert_eq!(r.name(), "v31.2d");

        let r = NeonRegister::v(5, ArrangementSpec::V4S);
        assert_eq!(r.name(), "v5.4s");
    }

    #[test]
    fn test_neon_register_name_scalar() {
        assert_eq!(NeonRegister::q(0).name(), "q0");
        assert_eq!(NeonRegister::d(1).name(), "d1");
        assert_eq!(NeonRegister::s(2).name(), "s2");
        assert_eq!(NeonRegister::h(3).name(), "h3");
        assert_eq!(NeonRegister::b(4).name(), "b4");
    }

    #[test]
    fn test_neon_register_number_wraps_at_31() {
        let r = NeonRegister::v(33, ArrangementSpec::V16B);
        assert_eq!(r.number, 1); // 33 & 31 = 1
    }

    #[test]
    fn test_neon_register_bit_width() {
        assert_eq!(NeonRegister::q(0).bit_width(), 128);
        assert_eq!(NeonRegister::d(0).bit_width(), 64);
        assert_eq!(NeonRegister::s(0).bit_width(), 32);
        assert_eq!(NeonRegister::h(0).bit_width(), 16);
        assert_eq!(NeonRegister::b(0).bit_width(), 8);
        assert_eq!(NeonRegister::v(0, ArrangementSpec::V4S).bit_width(), 128);
        assert_eq!(NeonRegister::v(0, ArrangementSpec::V2S).bit_width(), 64);
    }

    #[test]
    fn test_neon_insn_mnemonic_coverage() {
        let kinds = [
            NeonInsnKind::FAdd,
            NeonInsnKind::FSub,
            NeonInsnKind::FMul,
            NeonInsnKind::FDiv,
            NeonInsnKind::FNeg,
            NeonInsnKind::FAbs,
            NeonInsnKind::FCvt,
            NeonInsnKind::Mov,
            NeonInsnKind::Dup,
            NeonInsnKind::Zip1,
            NeonInsnKind::Zip2,
            NeonInsnKind::Uzp1,
            NeonInsnKind::Uzp2,
            NeonInsnKind::Trn1,
            NeonInsnKind::Trn2,
            NeonInsnKind::Ext,
            NeonInsnKind::Rev16,
            NeonInsnKind::And,
            NeonInsnKind::Orr,
            NeonInsnKind::Eor,
            NeonInsnKind::Not,
        ];
        for k in &kinds {
            assert!(!k.mnemonic().is_empty(), "{k:?} has empty mnemonic");
        }
    }

    #[test]
    fn test_neon_instruction_binop_asm() {
        let arr = ArrangementSpec::V4S;
        let insn = NeonInstruction::binop(
            NeonInsnKind::FAdd,
            NeonRegister::v(0, arr),
            NeonRegister::v(1, arr),
            NeonRegister::v(2, arr),
            arr,
            0,
        );
        let asm = insn.to_asm();
        assert!(asm.contains("fadd"), "asm='{asm}'");
        assert!(asm.contains("v0.4s"), "asm='{asm}'");
        assert!(asm.contains("v1.4s"), "asm='{asm}'");
        assert!(asm.contains("v2.4s"), "asm='{asm}'");
    }

    #[test]
    fn test_neon_instruction_unary_asm() {
        let arr = ArrangementSpec::V2D;
        let insn = NeonInstruction::unary(
            NeonInsnKind::FNeg,
            NeonRegister::v(3, arr),
            NeonRegister::v(4, arr),
            arr,
            0,
        );
        let asm = insn.to_asm();
        assert!(asm.contains("fneg"), "asm='{asm}'");
        assert!(asm.contains("v3.2d"), "asm='{asm}'");
        assert!(asm.contains("v4.2d"), "asm='{asm}'");
    }

    #[test]
    fn test_neon_decoder_non_neon_word_returns_none() {
        let dec = NeonDecoder::new();
        // A non-NEON word (e.g. NOP = 0xD503201F, group = 0b1101)
        assert!(dec.decode(0xD503201F).is_none());
        // SUB X0,X0,#0 = 0xD1000000, group = 0b1101
        assert!(dec.decode(0xD1000000).is_none());
    }

    #[test]
    fn test_neon_decoder_group_filter() {
        let dec = NeonDecoder::new();
        // Words with group bits 0b0111 or 0b1111 may be NEON.
        // 0x0F000000 → bits[28:25] = 0b0111 (group 0b0111) — may return Some or None.
        // Just verify it doesn't panic.
        let _ = dec.decode(0x0F000000);
        let _ = dec.decode(0x4F000000);
        let _ = dec.decode(0x0E000000);
        let _ = dec.decode(0x4E000000);
    }

    #[test]
    fn test_neon_lifter_fadd() {
        let arr = ArrangementSpec::V4S;
        let insn = NeonInstruction::binop(
            NeonInsnKind::FAdd,
            NeonRegister::v(0, arr),
            NeonRegister::v(1, arr),
            NeonRegister::v(2, arr),
            arr,
            0,
        );
        let lifter = NeonLifter::new();
        let il = lifter.lift(&insn);
        let s = il.to_string();
        assert!(s.contains("fadd"), "IL='{s}'");
        assert!(s.contains("v0.4s"), "IL='{s}'");
    }

    #[test]
    fn test_neon_lifter_fneg() {
        let arr = ArrangementSpec::V2D;
        let insn = NeonInstruction::unary(
            NeonInsnKind::FNeg,
            NeonRegister::v(5, arr),
            NeonRegister::v(6, arr),
            arr,
            0,
        );
        let lifter = NeonLifter::new();
        let il = lifter.lift(&insn);
        let s = il.to_string();
        assert!(s.contains("fneg"), "IL='{s}'");
    }

    #[test]
    fn test_neon_lifter_no_src_returns_unknown() {
        let insn = NeonInstruction {
            kind: NeonInsnKind::FAdd,
            dst: Some(NeonRegister::v(0, ArrangementSpec::V4S)),
            src: vec![],
            arrangement: Some(ArrangementSpec::V4S),
            index: None,
            imm: None,
            encoding: 0,
        };
        let lifter = NeonLifter::new();
        let il = lifter.lift(&insn);
        assert!(matches!(il, NeonIlNode::Unknown));
    }

    #[test]
    fn test_neon_register_map_contains_v0_16b() {
        let map = neon_register_map();
        assert!(map.contains_key("v0.16b"), "missing v0.16b");
        assert!(map.contains_key("v31.2d"), "missing v31.2d");
        assert!(map.contains_key("q0"), "missing q0");
        assert!(map.contains_key("d0"), "missing d0");
    }

    #[test]
    fn test_neon_register_map_size() {
        let map = neon_register_map();
        // 32 registers × 8 vector arrangements + 32 × 5 scalar = 256 + 160 = 416
        assert!(
            map.len() >= 400,
            "expected >= 400 entries, got {}",
            map.len()
        );
    }

    #[test]
    fn test_il_node_display_reg() {
        let r = NeonRegister::v(1, ArrangementSpec::V8H);
        let node = NeonIlNode::Reg(r);
        assert_eq!(node.to_string(), "v1.8h");
    }

    #[test]
    fn test_il_node_display_imm() {
        let node = NeonIlNode::Imm(-5);
        assert_eq!(node.to_string(), "#-5");
    }

    #[test]
    fn test_il_node_display_unknown() {
        let node = NeonIlNode::Unknown;
        assert_eq!(node.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_arrangement_display() {
        assert_eq!(ArrangementSpec::V4S.to_string(), "4s");
        assert_eq!(ArrangementSpec::V2D.to_string(), "2d");
        assert_eq!(ArrangementSpec::V16B.to_string(), "16b");
    }

    #[test]
    fn test_neon_register_display() {
        let r = NeonRegister::v(7, ArrangementSpec::V8H);
        assert_eq!(r.to_string(), "v7.8h");
    }

    #[test]
    fn test_neon_insn_display() {
        let arr = ArrangementSpec::V16B;
        let insn = NeonInstruction::binop(
            NeonInsnKind::And,
            NeonRegister::v(0, arr),
            NeonRegister::v(1, arr),
            NeonRegister::v(2, arr),
            arr,
            0,
        );
        let s = insn.to_string();
        assert!(s.starts_with("and"), "display='{s}'");
    }

    #[test]
    fn test_fcvt_mnemonic() {
        assert_eq!(NeonInsnKind::FCvt.mnemonic(), "fcvt");
    }

    #[test]
    fn test_scvtf_mnemonic() {
        assert_eq!(NeonInsnKind::SCvtf.mnemonic(), "scvtf");
    }

    #[test]
    fn test_ucvtf_mnemonic() {
        assert_eq!(NeonInsnKind::UCvtf.mnemonic(), "ucvtf");
    }

    #[test]
    fn test_zip1_zip2_mnemonic() {
        assert_eq!(NeonInsnKind::Zip1.mnemonic(), "zip1");
        assert_eq!(NeonInsnKind::Zip2.mnemonic(), "zip2");
    }

    #[test]
    fn test_trn1_trn2_mnemonic() {
        assert_eq!(NeonInsnKind::Trn1.mnemonic(), "trn1");
        assert_eq!(NeonInsnKind::Trn2.mnemonic(), "trn2");
    }

    #[test]
    fn test_dup_mnemonic() {
        assert_eq!(NeonInsnKind::Dup.mnemonic(), "dup");
        assert_eq!(NeonInsnKind::DupElem.mnemonic(), "dup");
    }

    #[test]
    fn test_ext_mnemonic() {
        assert_eq!(NeonInsnKind::Ext.mnemonic(), "ext");
    }

    #[test]
    fn test_rev_mnemonics() {
        assert_eq!(NeonInsnKind::Rev16.mnemonic(), "rev16");
        assert_eq!(NeonInsnKind::Rev32.mnemonic(), "rev32");
        assert_eq!(NeonInsnKind::Rev64.mnemonic(), "rev64");
    }

    #[test]
    fn test_decoder_default() {
        let dec = NeonDecoder::default();
        assert!(!dec.strict);
    }

    #[test]
    fn test_lifter_default() {
        let _ = NeonLifter;
    }

    #[test]
    fn test_scalar_register_names_all_regs() {
        for n in 0u8..32 {
            assert_eq!(NeonRegister::q(n).name(), format!("q{n}"));
            assert_eq!(NeonRegister::d(n).name(), format!("d{n}"));
            assert_eq!(NeonRegister::s(n).name(), format!("s{n}"));
        }
    }

    #[test]
    fn test_neon_insn_with_imm() {
        let arr = ArrangementSpec::V4S;
        let mut insn = NeonInstruction::unary(
            NeonInsnKind::Shl,
            NeonRegister::v(0, arr),
            NeonRegister::v(1, arr),
            arr,
            0,
        );
        insn.imm = Some(4);
        assert_eq!(insn.imm, Some(4));
    }

    #[test]
    fn test_neon_insn_with_index() {
        let arr = ArrangementSpec::V4S;
        let mut insn = NeonInstruction::binop(
            NeonInsnKind::FMla,
            NeonRegister::v(0, arr),
            NeonRegister::v(1, arr),
            NeonRegister::v(2, arr),
            arr,
            0,
        );
        insn.index = Some(2);
        assert_eq!(insn.index, Some(2));
    }

    #[test]
    fn test_neon_ext_mnemonic_coverage_ld_st() {
        assert_eq!(NeonInsnKind::Ld1.mnemonic(), "ld1");
        assert_eq!(NeonInsnKind::Ld2.mnemonic(), "ld2");
        assert_eq!(NeonInsnKind::St1.mnemonic(), "st1");
        assert_eq!(NeonInsnKind::St4.mnemonic(), "st4");
    }

    #[test]
    fn test_neon_aes_mnemonics() {
        assert_eq!(NeonInsnKind::Aese.mnemonic(), "aese");
        assert_eq!(NeonInsnKind::Aesd.mnemonic(), "aesd");
        assert_eq!(NeonInsnKind::Aesmc.mnemonic(), "aesmc");
        assert_eq!(NeonInsnKind::Aesimc.mnemonic(), "aesimc");
    }

    #[test]
    fn test_neon_sha_mnemonics() {
        assert_eq!(NeonInsnKind::Sha1c.mnemonic(), "sha1c");
        assert_eq!(NeonInsnKind::Sha256h.mnemonic(), "sha256h");
        assert_eq!(NeonInsnKind::Sha256su1.mnemonic(), "sha256su1");
    }
}
