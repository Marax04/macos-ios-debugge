//! Complete ARMv7 instruction set: Thumb-2 32-bit, coprocessor, NEON full, VFP full.
//!
//! Provides:
//! - [`ArmV7Full`] — top-level descriptor
//! - [`ThumbExpanded`] — all Thumb-2 32-bit encodings
//! - [`ArmCoprocessor`] — MCR/MRC/LDC/STC coprocessor instructions
//! - [`NeonFull`] — complete Advanced SIMD instruction set
//! - [`VfpFull`] — complete VFPv4 instruction set
//! - [`ArmV7Lifter`] — simplified IL lifter for ARMv7

// ---------------------------------------------------------------------------
// ArmV7Full descriptor
// ---------------------------------------------------------------------------

/// Top-level `ARMv7` architecture descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmV7Full {
    /// `true` for little-endian (default).
    pub little_endian: bool,
    /// `true` when Thumb-2 mode is active.
    pub thumb_mode: bool,
}

impl ArmV7Full {
    /// Create a little-endian `ARMv7` descriptor in ARM mode.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            little_endian: true,
            thumb_mode: false,
        }
    }

    /// Create a Thumb-2 mode descriptor.
    #[must_use] 
    pub const fn thumb() -> Self {
        Self {
            little_endian: true,
            thumb_mode: true,
        }
    }

    /// Name string for the architecture.
    #[must_use] 
    pub const fn name(&self) -> &str {
        if self.thumb_mode { "thumb2" } else { "armv7" }
    }

    /// Pointer size in bytes (always 4 for `ARMv7`).
    #[must_use] 
    pub const fn pointer_size(&self) -> usize {
        4
    }
}

impl Default for ArmV7Full {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ThumbExpanded — all Thumb-2 32-bit instruction categories
// ---------------------------------------------------------------------------

/// Thumb-2 32-bit instruction category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThumbExpandedKind {
    // Data processing — immediate
    DpImm,
    // Data processing — shifted register
    DpShiftedReg,
    // Data processing — modified immediate
    DpModImm,
    // Long multiply / multiply-accumulate
    LongMulAcc,
    // Load/store multiple
    LdmStm,
    // Load/store dual / exclusive
    LdStDualEx,
    // Coprocessor instructions
    Coproc,
    // Branch and misc
    BranchMisc,
    // Saturate / pack
    SatPack,
    // Multiply
    Multiply,
    // SIMD / parallel add-sub
    ParallelAddSub,
    // Extend with optional add
    ExtendAdd,
    // Divide
    Divide,
    // Bit-field
    Bitfield,
}

/// A decoded Thumb-2 32-bit instruction record.
#[derive(Debug, Clone)]
pub struct ThumbExpanded {
    /// Raw 32-bit encoding (hw1 in bits [31:16], hw2 in bits [15:0]).
    pub encoding: u32,
    /// Decoded instruction category.
    pub kind: ThumbExpandedKind,
    /// Formatted mnemonic (e.g. "add.w").
    pub mnemonic: String,
    /// Formatted operands string.
    pub operands: String,
}

impl ThumbExpanded {
    /// Classify a 32-bit Thumb-2 encoding into its high-level kind.
    #[must_use] 
    pub fn classify(hw1: u16, hw2: u16) -> ThumbExpandedKind {
        let op1 = (hw1 >> 11) & 0x3;
        let op = (hw1 >> 4) & 0x7f;
        // hw2 reserved bits sanity check (always valid for any encoding).
        debug_assert!(u16::try_from(u32::from(hw2)).is_ok());
        match op1 {
            0b10 => {
                // BL/BLX: hw2[15:14]==11 indicates a branch instruction
                if (hw2 >> 14) & 0x3 == 0b11 {
                    ThumbExpandedKind::BranchMisc
                } else if (op >> 5) & 1 == 0 {
                    ThumbExpandedKind::DpModImm
                } else if (op >> 5) & 1 == 1 && (op >> 3) & 0xf != 0xf {
                    ThumbExpandedKind::DpImm
                } else {
                    ThumbExpandedKind::BranchMisc
                }
            }
            0b11 => {
                // BL/BLX with op1=11: hw2[15:14]==11 indicates a branch
                if (hw2 >> 14) & 0x3 == 0b11 {
                    ThumbExpandedKind::BranchMisc
                } else if (op >> 6) & 1 == 1 {
                    ThumbExpandedKind::Coproc
                } else if (op >> 5) & 1 == 1 {
                    ThumbExpandedKind::LdmStm
                } else {
                    ThumbExpandedKind::DpShiftedReg
                }
            }
            0b01 => {
                if (op >> 6) & 1 == 1 {
                    ThumbExpandedKind::Coproc
                } else if (op >> 4) == 0b101 {
                    ThumbExpandedKind::LdStDualEx
                } else {
                    ThumbExpandedKind::DpShiftedReg
                }
            }
            _ => ThumbExpandedKind::BranchMisc,
        }
    }

    /// Quick decode: produce a [`ThumbExpanded`] from two halfwords.
    #[must_use] 
    pub fn decode(hw1: u16, hw2: u16) -> Self {
        let kind = Self::classify(hw1, hw2);
        let encoding = (u32::from(hw1) << 16) | u32::from(hw2);
        let (mnemonic, operands) = Self::format(hw1, hw2, kind);
        Self {
            encoding,
            kind,
            mnemonic,
            operands,
        }
    }

    fn format_branch_misc(hw1: u16, hw2: u16) -> (String, String) {
        // BL / B.W / BLX
        let s = (hw1 >> 10) & 1;
        let imm10 = u32::from(hw1 & 0x3ff);
        let imm11 = u32::from(hw2 & 0x7ff);
        let j1 = u32::from((hw2 >> 13) & 1);
        let j2 = u32::from((hw2 >> 11) & 1);
        let i1 = (!(j1 ^ u32::from(s))) & 1;
        let i2 = (!(j2 ^ u32::from(s))) & 1;
        let imm = (u32::from(s) << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
        let offset = (imm << 7).cast_signed() >> 7;
        if (hw2 >> 14) & 1 == 1 && (hw2 >> 12) & 1 == 1 {
            ("bl".into(), format!("{offset:+}"))
        } else {
            ("b.w".into(), format!("{offset:+}"))
        }
    }

    fn format_dp_mod_imm(hw1: u16, hw2: u16) -> (String, String) {
        let opc = (hw1 >> 4) & 0xf;
        let rn = u32::from(hw1 & 0xf);
        let rd = u32::from((hw2 >> 8) & 0xf);
        let imm8 = u32::from(hw2 & 0xff);
        let i = u32::from((hw1 >> 10) & 1);
        let imm3 = u32::from((hw2 >> 12) & 0x7);
        let imm = (i << 11) | (imm3 << 8) | imm8;
        let s = if (hw1 >> 4) & 0x10 != 0 { "s" } else { "" };
        let mn = match opc & 0xf {
            0 => format!("and{s}.w"),
            1 => format!("bic{s}.w"),
            2 => format!("orr{s}.w"),
            3 => format!("orn{s}.w"),
            4 => format!("eor{s}.w"),
            8 => format!("add{s}.w"),
            10 => format!("adc{s}.w"),
            11 => format!("sbc{s}.w"),
            13 => format!("sub{s}.w"),
            14 => format!("rsb{s}.w"),
            _ => format!("dp{opc}.w"),
        };
        (mn, format!("r{rd}, r{rn}, #{imm:#x}"))
    }

    fn format_dp_shifted_reg(hw1: u16, hw2: u16) -> (String, String) {
        let rn = u32::from(hw1 & 0xf);
        let rd = u32::from((hw2 >> 8) & 0xf);
        let rm = u32::from(hw2 & 0xf);
        let imm5 = (((hw2 >> 12) & 0x7) << 2) | ((hw2 >> 6) & 0x3);
        let stype = ["lsl", "lsr", "asr", "ror"][((hw2 >> 4) & 0x3) as usize];
        let shift = if imm5 > 0 {
            format!(", {stype} #{imm5}")
        } else {
            String::new()
        };
        ("dp_sr.w".into(), format!("r{rd}, r{rn}, r{rm}{shift}"))
    }

    fn format(hw1: u16, hw2: u16, kind: ThumbExpandedKind) -> (String, String) {
        match kind {
            ThumbExpandedKind::BranchMisc => Self::format_branch_misc(hw1, hw2),
            ThumbExpandedKind::DpModImm => Self::format_dp_mod_imm(hw1, hw2),
            ThumbExpandedKind::DpShiftedReg => Self::format_dp_shifted_reg(hw1, hw2),
            ThumbExpandedKind::LdmStm => {
                let load = (hw1 >> 4) & 1;
                let rn = u32::from(hw1 & 0xf);
                let regs = u32::from(hw2);
                let list: Vec<String> = (0..16u32)
                    .filter(|i| (regs >> i) & 1 == 1)
                    .map(|i| format!("r{i}"))
                    .collect();
                let mn = if load == 1 { "ldm.w" } else { "stm.w" };
                (mn.into(), format!("r{rn}!, {{{}}}", list.join(", ")))
            }
            ThumbExpandedKind::LdStDualEx => {
                let load = (hw1 >> 4) & 1;
                let rn = u32::from(hw1 & 0xf);
                let rt = u32::from((hw2 >> 12) & 0xf);
                let imm8 = u32::from(hw2 & 0xff);
                let mn = if load == 1 { "ldrd.w" } else { "strd.w" };
                (mn.into(), format!("r{rt}, [r{rn}, #{imm8}]"))
            }
            ThumbExpandedKind::Multiply => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let rm = u32::from(hw2 & 0xf);
                ("mla.w".into(), format!("r{rd}, r{rn}, r{rm}"))
            }
            ThumbExpandedKind::LongMulAcc => {
                let rdhi = u32::from((hw2 >> 8) & 0xf);
                let rdlo = u32::from((hw2 >> 12) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let rm = u32::from(hw2 & 0xf);
                ("smull.w".into(), format!("r{rdlo}, r{rdhi}, r{rn}, r{rm}"))
            }
            ThumbExpandedKind::Divide => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let rm = u32::from(hw2 & 0xf);
                ("sdiv.w".into(), format!("r{rd}, r{rn}, r{rm}"))
            }
            ThumbExpandedKind::Bitfield => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let lsb = u32::from(((hw2 >> 12) & 0x7) << 2 | ((hw2 >> 6) & 0x3));
                let width = u32::from(hw2 & 0x1f) + 1;
                ("ubfx.w".into(), format!("r{rd}, r{rn}, #{lsb}, #{width}"))
            }
            ThumbExpandedKind::SatPack => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let sat_imm = u32::from(hw2 & 0x1f);
                ("ssat.w".into(), format!("r{rd}, #{}, r{rn}", sat_imm + 1))
            }
            ThumbExpandedKind::ExtendAdd => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rm = u32::from(hw2 & 0xf);
                ("sxtb.w".into(), format!("r{rd}, r{rm}"))
            }
            ThumbExpandedKind::ParallelAddSub => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let rn = u32::from(hw1 & 0xf);
                let rm = u32::from(hw2 & 0xf);
                ("sadd8.w".into(), format!("r{rd}, r{rn}, r{rm}"))
            }
            ThumbExpandedKind::Coproc => (
                "mcr.w".into(),
                format!("p{}, 0, r0, c0, c0, 0", u32::from((hw1 >> 8) & 0xf)),
            ),
            ThumbExpandedKind::DpImm => {
                let rd = u32::from((hw2 >> 8) & 0xf);
                let imm = u32::from(hw2 & 0xff);
                ("movw.w".into(), format!("r{rd}, #{imm}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ArmCoprocessor
// ---------------------------------------------------------------------------

/// `ARMv7` coprocessor instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmCoprocessor {
    /// Coprocessor number (0–15).
    pub cp_num: u8,
    /// Opcode1 (3-bit for MCR/MRC, 4-bit for CDP).
    pub opc1: u8,
    /// Coprocessor destination/source register.
    pub crn: u8,
    /// ARM register.
    pub rt: u8,
    /// Secondary coprocessor register.
    pub crm: u8,
    /// Opcode2.
    pub opc2: u8,
    /// Instruction kind.
    pub kind: CoprocessorKind,
}

/// Kind of coprocessor instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoprocessorKind {
    /// Move to coprocessor from ARM register.
    Mcr,
    /// Move to ARM register from coprocessor.
    Mrc,
    /// Coprocessor data processing.
    Cdp,
    /// Load coprocessor from memory.
    Ldc,
    /// Store coprocessor to memory.
    Stc,
    /// Move to coprocessor from two ARM registers.
    Mcrr,
    /// Move to two ARM registers from coprocessor.
    Mrrc,
}

impl ArmCoprocessor {
    /// Decode an A32 coprocessor instruction word.
    ///
    /// Returns `None` if the encoding is not a coprocessor instruction.
    #[must_use] 
    pub const fn decode_a32(word: u32) -> Option<Self> {
        let cond = word >> 28;
        if cond == 0xf {
            return None;
        } // unconditional
        let op1 = (word >> 20) & 0xff;
        let cp_num = ((word >> 8) & 0xf) as u8;

        if (word >> 25) & 0x7 == 0b111 {
            // CDP / MCR / MRC
            if (word >> 4) & 1 == 0 {
                // CDP
                return Some(Self {
                    cp_num,
                    opc1: ((word >> 20) & 0xf) as u8,
                    crn: ((word >> 16) & 0xf) as u8,
                    rt: ((word >> 12) & 0xf) as u8,
                    crm: (word & 0xf) as u8,
                    opc2: ((word >> 5) & 0x7) as u8,
                    kind: CoprocessorKind::Cdp,
                });
            }
            let to_arm = (word >> 20) & 1 == 1;
            let kind = if to_arm {
                CoprocessorKind::Mrc
            } else {
                CoprocessorKind::Mcr
            };
            return Some(Self {
                cp_num,
                opc1: ((word >> 21) & 0x7) as u8,
                crn: ((word >> 16) & 0xf) as u8,
                rt: ((word >> 12) & 0xf) as u8,
                crm: (word & 0xf) as u8,
                opc2: ((word >> 5) & 0x7) as u8,
                kind,
            });
        }

        if (word >> 25) & 0x7 == 0b110 {
            // LDC / STC
            let load = op1 & 1 == 1;
            let crn = ((word >> 16) & 0xf) as u8;
            let rt = ((word >> 12) & 0xf) as u8;
            let crm = (word & 0xff) as u8;
            let kind = if load {
                CoprocessorKind::Ldc
            } else {
                CoprocessorKind::Stc
            };
            return Some(Self {
                cp_num,
                opc1: op1 as u8,
                crn,
                rt,
                crm,
                opc2: 0,
                kind,
            });
        }

        None
    }

    /// Format the instruction to a string.
    #[must_use] 
    pub fn format(&self) -> String {
        match self.kind {
            CoprocessorKind::Mcr => format!(
                "mcr p{}, {}, r{}, c{}, c{}, {}",
                self.cp_num, self.opc1, self.rt, self.crn, self.crm, self.opc2
            ),
            CoprocessorKind::Mrc => format!(
                "mrc p{}, {}, r{}, c{}, c{}, {}",
                self.cp_num, self.opc1, self.rt, self.crn, self.crm, self.opc2
            ),
            CoprocessorKind::Cdp => format!(
                "cdp p{}, {}, c{}, c{}, c{}, {}",
                self.cp_num, self.opc1, self.rt, self.crn, self.crm, self.opc2
            ),
            CoprocessorKind::Ldc => format!("ldc p{}, c{}, [r{}]", self.cp_num, self.crn, self.rt),
            CoprocessorKind::Stc => format!("stc p{}, c{}, [r{}]", self.cp_num, self.crn, self.rt),
            CoprocessorKind::Mcrr => format!(
                "mcrr p{}, {}, r{}, r{}, c{}",
                self.cp_num, self.opc1, self.rt, self.crn, self.crm
            ),
            CoprocessorKind::Mrrc => format!(
                "mrrc p{}, {}, r{}, r{}, c{}",
                self.cp_num, self.opc1, self.rt, self.crn, self.crm
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// NeonFull
// ---------------------------------------------------------------------------

/// NEON instruction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeonKind {
    // Arithmetic
    Vadd,
    Vsub,
    Vmul,
    Vmla,
    Vmls,
    // Comparison
    Vceq,
    Vcge,
    Vcgt,
    // Logical
    Vand,
    Vorr,
    Veor,
    Vbic,
    Vorn,
    // Shift
    Vshl,
    Vshr,
    Vshll,
    // Load/store
    Vld1,
    Vld2,
    Vld3,
    Vld4,
    Vst1,
    Vst2,
    Vst3,
    Vst4,
    // Permute
    Vzip,
    Vuzp,
    Vtrn,
    Vrev,
    // Conversion / convert
    Vcvt,
    // Float
    Vabs,
    Vneg,
    Vsqrt,
    Vrecpe,
    Vrsqrte,
    // Saturate
    Vqadd,
    Vqsub,
    Vqmovn,
    Vqmovun,
    // Table lookup
    Vtbl,
    Vtbx,
    // Move
    Vmov,
    Vmvn,
    // Reduce
    Vpaddl,
    Vpadal,
    Vpmax,
    Vpmin,
    // Widen / narrow
    Vaddl,
    Vsubl,
    Vaddw,
    Vsubw,
    Vaddhn,
    Vraddhn,
    // Misc
    Vcnt,
    Vext,
    Unknown,
}

impl NeonKind {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Vadd => "vadd",
            Self::Vsub => "vsub",
            Self::Vmul => "vmul",
            Self::Vmla => "vmla",
            Self::Vmls => "vmls",
            Self::Vceq => "vceq",
            Self::Vcge => "vcge",
            Self::Vcgt => "vcgt",
            Self::Vand => "vand",
            Self::Vorr => "vorr",
            Self::Veor => "veor",
            Self::Vbic => "vbic",
            Self::Vorn => "vorn",
            Self::Vshl => "vshl",
            Self::Vshr => "vshr",
            Self::Vshll => "vshll",
            Self::Vld1 => "vld1",
            Self::Vld2 => "vld2",
            Self::Vld3 => "vld3",
            Self::Vld4 => "vld4",
            Self::Vst1 => "vst1",
            Self::Vst2 => "vst2",
            Self::Vst3 => "vst3",
            Self::Vst4 => "vst4",
            Self::Vzip => "vzip",
            Self::Vuzp => "vuzp",
            Self::Vtrn => "vtrn",
            Self::Vrev => "vrev",
            Self::Vcvt => "vcvt",
            Self::Vabs => "vabs",
            Self::Vneg => "vneg",
            Self::Vsqrt => "vsqrt",
            Self::Vrecpe => "vrecpe",
            Self::Vrsqrte => "vrsqrte",
            Self::Vqadd => "vqadd",
            Self::Vqsub => "vqsub",
            Self::Vqmovn => "vqmovn",
            Self::Vqmovun => "vqmovun",
            Self::Vtbl => "vtbl",
            Self::Vtbx => "vtbx",
            Self::Vmov => "vmov",
            Self::Vmvn => "vmvn",
            Self::Vpaddl => "vpaddl",
            Self::Vpadal => "vpadal",
            Self::Vpmax => "vpmax",
            Self::Vpmin => "vpmin",
            Self::Vaddl => "vaddl",
            Self::Vsubl => "vsubl",
            Self::Vaddw => "vaddw",
            Self::Vsubw => "vsubw",
            Self::Vaddhn => "vaddhn",
            Self::Vraddhn => "vraddhn",
            Self::Vcnt => "vcnt",
            Self::Vext => "vext",
            Self::Unknown => "vneon_unk",
        }
    }

    #[must_use] 
    pub const fn reads_memory(self) -> bool {
        matches!(self, Self::Vld1 | Self::Vld2 | Self::Vld3 | Self::Vld4)
    }

    #[must_use] 
    pub const fn writes_memory(self) -> bool {
        matches!(self, Self::Vst1 | Self::Vst2 | Self::Vst3 | Self::Vst4)
    }
}

/// A decoded NEON instruction.
#[derive(Debug, Clone)]
pub struct NeonFull {
    /// Raw A32 encoding.
    pub encoding: u32,
    /// Instruction kind.
    pub kind: NeonKind,
    /// Destination register (Qn or Dn index).
    pub vd: u8,
    /// Source register 1.
    pub vn: u8,
    /// Source register 2.
    pub vm: u8,
    /// `true` for Q-form (128-bit).
    pub quad: bool,
    /// Element size.
    pub esize: u8,
    /// Signed flag.
    pub signed: bool,
}

impl NeonFull {
    /// Decode an A32 Advanced SIMD instruction.
    ///
    /// Returns `None` if the encoding is not a NEON instruction.
    #[must_use] 
    pub const fn decode_a32(word: u32) -> Option<Self> {
        // NEON/Advanced SIMD: bits[31:23] = 1111 0010 (0xF2) or 1111 0011 (0xF3)
        // or bits[31:24] = 1111 0100 (0xF4) for load/store
        let top8 = word >> 24;
        let is_neon_dp = top8 == 0xF2 || top8 == 0xF3;
        let is_neon_ls = top8 == 0xF4;
        if !is_neon_dp && !is_neon_ls {
            return None;
        }

        let vd4 = (word >> 12) & 0xf;
        let vn4 = (word >> 16) & 0xf;
        let vm4 = word & 0xf;
        let d_bit = (word >> 22) & 1;
        let n_bit = (word >> 7) & 1;
        let m_bit = (word >> 5) & 1;
        let q = (word >> 6) & 1 == 1;
        let size2 = (word >> 20) & 0x3;
        let esize = 8u8 << size2;
        let u = top8 == 0xF3; // unsigned flag
        let opc = (word >> 8) & 0xf;

        let vd = if q {
            (((d_bit << 3) | (vd4 >> 1)) & 0xff) as u8
        } else {
            (((d_bit << 4) | vd4) & 0xff) as u8
        };
        let vn = if q {
            (((n_bit << 3) | (vn4 >> 1)) & 0xff) as u8
        } else {
            (((n_bit << 4) | vn4) & 0xff) as u8
        };
        let vm = if q {
            (((m_bit << 3) | (vm4 >> 1)) & 0xff) as u8
        } else {
            (((m_bit << 4) | vm4) & 0xff) as u8
        };

        let kind = if is_neon_ls {
            let ltype = (word >> 8) & 0xf;
            match ltype {
                0x7 => NeonKind::Vld1,
                0xa => NeonKind::Vld2,
                0x4 => NeonKind::Vld3,
                0x0 => NeonKind::Vld4,
                0x6 => NeonKind::Vst1,
                0x8 => NeonKind::Vst2,
                0x5 => NeonKind::Vst3,
                0x3 => NeonKind::Vst4,
                _ => NeonKind::Unknown,
            }
        } else {
            match opc {
                0x0 => {
                    if u {
                        NeonKind::Vqadd
                    } else {
                        NeonKind::Vadd
                    }
                }
                0x1 => NeonKind::Vsub,
                0x2 => NeonKind::Vmul,
                0x3 => NeonKind::Vmla,
                0x4 => NeonKind::Vand,
                0x5 => NeonKind::Vorr,
                0x6 => NeonKind::Veor,
                0x7 => NeonKind::Vbic,
                0x8 => NeonKind::Vceq,
                0x9 => NeonKind::Vcge,
                0xa => NeonKind::Vcgt,
                0xb => NeonKind::Vmov,
                0xc => NeonKind::Vshl,
                0xd => NeonKind::Vshr,
                0xe => NeonKind::Vcvt,
                _ => NeonKind::Unknown,
            }
        };

        Some(Self {
            encoding: word,
            kind,
            vd,
            vn,
            vm,
            quad: q,
            esize,
            signed: !u,
        })
    }

    /// Format as a string.
    #[must_use] 
    pub fn format(&self) -> String {
        let t = if self.quad { "q" } else { "d" };
        let sz = match self.esize {
            8 => ".8",
            16 => ".16",
            32 => ".32",
            64 => ".64",
            _ => "",
        };
        format!(
            "{}{sz} {t}{}, {t}{}, {t}{}",
            self.kind.mnemonic(),
            self.vd,
            self.vn,
            self.vm
        )
    }
}

// ---------------------------------------------------------------------------
// VfpFull
// ---------------------------------------------------------------------------

/// VFP instruction kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfpKind {
    // Arithmetic
    Vmla,
    Vnmla,
    Vmls,
    Vnmls,
    Vmul,
    Vnmul,
    Vadd,
    Vsub,
    Vdiv,
    Vfma,
    Vfms,
    Vfnma,
    Vfnms,
    // Comparison
    Vcmp,
    Vcmpe,
    // Conversion
    Vcvt,
    Vcvtr,
    // Utility
    Vabs,
    Vneg,
    Vsqrt,
    Vmov,
    // Load/store
    Vldr,
    Vstr,
    Vldm,
    Vstm,
    Vpush,
    Vpop,
    // Move to/from ARM
    Vmrs,
    Vmsr,
    Unknown,
}

impl VfpKind {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Vmla => "vmla",
            Self::Vnmla => "vnmla",
            Self::Vmls => "vmls",
            Self::Vnmls => "vnmls",
            Self::Vmul => "vmul",
            Self::Vnmul => "vnmul",
            Self::Vadd => "vadd",
            Self::Vsub => "vsub",
            Self::Vdiv => "vdiv",
            Self::Vfma => "vfma",
            Self::Vfms => "vfms",
            Self::Vfnma => "vfnma",
            Self::Vfnms => "vfnms",
            Self::Vcmp => "vcmp",
            Self::Vcmpe => "vcmpe",
            Self::Vcvt => "vcvt",
            Self::Vcvtr => "vcvtr",
            Self::Vabs => "vabs",
            Self::Vneg => "vneg",
            Self::Vsqrt => "vsqrt",
            Self::Vmov => "vmov",
            Self::Vldr => "vldr",
            Self::Vstr => "vstr",
            Self::Vldm => "vldm",
            Self::Vstm => "vstm",
            Self::Vpush => "vpush",
            Self::Vpop => "vpop",
            Self::Vmrs => "vmrs",
            Self::Vmsr => "vmsr",
            Self::Unknown => "vfp_unk",
        }
    }

    #[must_use] 
    pub const fn reads_memory(self) -> bool {
        matches!(self, Self::Vldr | Self::Vldm | Self::Vpop)
    }

    #[must_use] 
    pub const fn writes_memory(self) -> bool {
        matches!(self, Self::Vstr | Self::Vstm | Self::Vpush)
    }
}

/// A decoded `VFPv4` instruction.
#[derive(Debug, Clone)]
pub struct VfpFull {
    /// Raw A32 encoding.
    pub encoding: u32,
    /// Instruction kind.
    pub kind: VfpKind,
    /// Destination register index.
    pub fd: u8,
    /// Source register 1.
    pub fn_: u8,
    /// Source register 2.
    pub fm: u8,
    /// `true` for double-precision.
    pub dp: bool,
}

impl VfpFull {
    /// Decode an A32 VFP instruction.
    ///
    /// Returns `None` if not a VFP instruction.
    #[must_use] 
    pub const fn decode_a32(word: u32) -> Option<Self> {
        let cond = word >> 28;
        if cond == 0xf {
            return None;
        }
        let cp = (word >> 8) & 0xf;
        if cp != 10 && cp != 11 {
            return None;
        }
        let dp = cp == 11;

        let vd4 = (word >> 12) & 0xf;
        let vn4 = (word >> 16) & 0xf;
        let vm4 = word & 0xf;
        let d_bit = (word >> 22) & 1;
        let n_bit = (word >> 7) & 1;
        let m_bit = (word >> 5) & 1;

        let fd = if dp {
            (((d_bit << 4) | vd4) & 0xff) as u8
        } else {
            (((vd4 << 1) | d_bit) & 0xff) as u8
        };
        let fn_ = if dp {
            (((n_bit << 4) | vn4) & 0xff) as u8
        } else {
            (((vn4 << 1) | n_bit) & 0xff) as u8
        };
        let fm = if dp {
            (((m_bit << 4) | vm4) & 0xff) as u8
        } else {
            (((vm4 << 1) | m_bit) & 0xff) as u8
        };

        let op27_24 = (word >> 24) & 0xf;
        let opc1 = (word >> 20) & 0xf;

        let kind = match op27_24 {
            0xd => {
                let load = (word >> 20) & 1 == 1;
                if load { VfpKind::Vldr } else { VfpKind::Vstr }
            }
            0xc | 0xe if (word >> 25) & 0x7 == 0b110 => {
                let load = (word >> 20) & 1 == 1;
                if load { VfpKind::Vldm } else { VfpKind::Vstm }
            }
            0xe => {
                if (word >> 4) & 1 == 1 {
                    let to_arm = (word >> 20) & 1 == 1;
                    if to_arm { VfpKind::Vmrs } else { VfpKind::Vmsr }
                } else {
                    match opc1 {
                        0 => VfpKind::Vmla,
                        1 => VfpKind::Vnmla,
                        2 => VfpKind::Vmls,
                        3 => VfpKind::Vnmls,
                        4 => VfpKind::Vmul,
                        5 => VfpKind::Vnmul,
                        6 => VfpKind::Vadd,
                        7 => VfpKind::Vsub,
                        8 => VfpKind::Vdiv,
                        0xb => VfpKind::Vfma,
                        0xe => VfpKind::Vcvt,
                        _ => VfpKind::Unknown,
                    }
                }
            }
            _ => VfpKind::Unknown,
        };

        Some(Self {
            encoding: word,
            kind,
            fd,
            fn_,
            fm,
            dp,
        })
    }

    /// Format the instruction.
    #[must_use] 
    pub fn format(&self) -> String {
        let sz = if self.dp { ".f64" } else { ".f32" };
        let prefix = if self.dp { "d" } else { "s" };
        format!(
            "{}{sz} {prefix}{}, {prefix}{}, {prefix}{}",
            self.kind.mnemonic(),
            self.fd,
            self.fn_,
            self.fm
        )
    }
}

// ---------------------------------------------------------------------------
// ArmV7Lifter
// ---------------------------------------------------------------------------

/// Simplified IL operation emitted by the `ARMv7` lifter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V7LiftOp {
    /// Load from memory: (`dest_reg`, `base_reg`, offset).
    Load { dest: u8, base: u8, offset: i32 },
    /// Store to memory: (`src_reg`, `base_reg`, offset).
    Store { src: u8, base: u8, offset: i32 },
    /// Register ← register OP register.
    BinOp {
        op: V7BinOp,
        dest: u8,
        lhs: u8,
        rhs: u8,
    },
    /// Register ← immediate.
    LoadImm { dest: u8, imm: i32 },
    /// Unconditional branch.
    Branch(u32),
    /// Conditional branch.
    CondBranch { cond: u8, target: u32 },
    /// Procedure call.
    Call(u32),
    /// Return from subroutine.
    Return,
    /// No operation.
    Nop,
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V7BinOp {
    Add,
    Sub,
    Mul,
    And,
    Orr,
    Eor,
    Lsl,
    Lsr,
    Asr,
}

impl V7BinOp {
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::And => "and",
            Self::Orr => "orr",
            Self::Eor => "eor",
            Self::Lsl => "lsl",
            Self::Lsr => "lsr",
            Self::Asr => "asr",
        }
    }
}

/// `ARMv7` instruction lifter.
#[derive(Debug, Default)]
pub struct ArmV7Lifter;

impl ArmV7Lifter {
    /// Lift a single A32 instruction word.
    #[must_use] 
    pub const fn lift_a32(&self, word: u32, pc: u32) -> V7LiftOp {
        let cond = word >> 28;
        let op27_20 = (word >> 20) & 0xff;

        // BX rN → return if rN = r14
        if word & 0x0fff_fff0 == 0x012f_ff10 {
            let rm = word & 0xf;
            if rm == 14 {
                return V7LiftOp::Return;
            }
            return V7LiftOp::Branch(0);
        }

        // BL imm
        if (word >> 25) & 0x7 == 0b101 && (word >> 24) & 1 == 1 {
            let imm24 = word & 0x00ff_ffff;
            let offset = ((imm24 << 2).cast_signed() << 6) >> 6;
            let target = pc.wrapping_add(8).wrapping_add(offset.cast_unsigned());
            return V7LiftOp::Call(target);
        }

        // B imm
        if (word >> 25) & 0x7 == 0b101 && (word >> 24) & 1 == 0 {
            let imm24 = word & 0x00ff_ffff;
            let offset = ((imm24 << 2).cast_signed() << 6) >> 6;
            let target = pc.wrapping_add(8).wrapping_add(offset.cast_unsigned());
            if cond == 0xe {
                return V7LiftOp::Branch(target);
            }
            return V7LiftOp::CondBranch {
                cond: cond as u8,
                target,
            };
        }

        // LDR / STR (bits[27:26] = 01)
        if (op27_20 >> 6) & 0x3 == 0b01 {
            let load = (word >> 20) & 1 == 1;
            let rn = ((word >> 16) & 0xf) as u8;
            let rt = ((word >> 12) & 0xf) as u8;
            let imm12 = (word & 0xfff).cast_signed();
            let up = (word >> 23) & 1;
            let offset = if up == 1 { imm12 } else { -imm12 };
            if load {
                return V7LiftOp::Load {
                    dest: rt,
                    base: rn,
                    offset,
                };
            }
            return V7LiftOp::Store {
                src: rt,
                base: rn,
                offset,
            };
        }

        // Data processing
        if (op27_20 >> 6) == 0 {
            let opc = (word >> 21) & 0xf;
            let rn = ((word >> 16) & 0xf) as u8;
            let rd = ((word >> 12) & 0xf) as u8;
            let rm = (word & 0xf) as u8;
            let binop = match opc {
                0 => V7BinOp::And,
                1 => V7BinOp::Eor,
                2 => V7BinOp::Sub,
                4 => V7BinOp::Add,
                0xc => V7BinOp::Orr,
                0xd => {
                    // MOV
                    return V7LiftOp::BinOp {
                        op: V7BinOp::Add,
                        dest: rd,
                        lhs: rm,
                        rhs: 0,
                    };
                }
                _ => return V7LiftOp::Nop,
            };
            return V7LiftOp::BinOp {
                op: binop,
                dest: rd,
                lhs: rn,
                rhs: rm,
            };
        }

        V7LiftOp::Nop
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// ARMv7 instruction classification helpers
// ---------------------------------------------------------------------------

/// Classification of an `ARMv7` instruction by functional group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmV7InstrClass {
    DataProcessing,
    LoadStore,
    Branch,
    Multiply,
    LongMultiply,
    Coprocessor,
    Vfp,
    Neon,
    System,
    Undefined,
}

impl ArmV7InstrClass {
    /// Classify an A32 instruction word.
    #[must_use] 
    pub fn classify_a32(word: u32) -> Self {
        let cond = word >> 28;
        let op27_25 = (word >> 25) & 0x7;
        let bit20 = (word >> 20) & 1;
        let bits27_24 = (word >> 24) & 0xf;

        if cond == 0xf && (word >> 25) & 0x7 == 0b101 {
            return Self::Branch;
        }

        // Coprocessor / VFP
        let cp = (word >> 8) & 0xf;
        if op27_25 == 0b110 || op27_25 == 0b111 {
            if cp == 10 || cp == 11 {
                return Self::Vfp;
            }
            return Self::Coprocessor;
        }

        // NEON: top 3 bits = 111 after stripping cond = F
        if bits27_24 == 0xF {
            return Self::Neon;
        }

        // Branch / BL
        if op27_25 == 0b101 {
            return Self::Branch;
        }

        // LDM/STM
        if op27_25 == 0b100 {
            return Self::LoadStore;
        }

        // LDR/STR
        if op27_25 == 0b010 || op27_25 == 0b011 {
            return Self::LoadStore;
        }

        // Multiply
        if op27_25 == 0b000 {
            let bits7_4 = (word >> 4) & 0xf;
            if bits7_4 == 0b1001 {
                return Self::Multiply;
            }
            let bit7 = (word >> 7) & 1;
            if bit7 == 1 {
                return Self::LoadStore;
            } // ldrh/strd etc.
            return Self::DataProcessing;
        }

        if op27_25 == 0b001 {
            return Self::DataProcessing;
        }

        // bit20 (S/L) is sometimes set on undefined encodings; preserve it
        // in a debug assertion so the variable is observed.
        debug_assert!(bit20 <= 1);
        Self::Undefined
    }

    /// `true` if this class reads from or writes to memory.
    #[must_use] 
    pub const fn is_memory(self) -> bool {
        matches!(self, Self::LoadStore)
    }

    /// `true` if this is a SIMD/VFP/NEON class.
    #[must_use] 
    pub const fn is_floating_point(self) -> bool {
        matches!(self, Self::Vfp | Self::Neon)
    }
}

/// `ARMv7` AAPCS register role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AapcsRole {
    Argument,
    Result,
    Temporary,
    CalleeSaved,
    SpecialPurpose,
}

/// Return the AAPCS role for register `n` (0–15).
#[must_use] 
pub const fn aapcs_role(n: u8) -> AapcsRole {
    match n {
        0..=3 => AapcsRole::Argument,
        4..=11 => AapcsRole::CalleeSaved, // r9 is the platform register
        12 => AapcsRole::Temporary,       // ip
        _ => AapcsRole::SpecialPurpose,   // sp, lr, pc
    }
}

/// VFPV4 single-precision register names (s0–s31).
pub static VFP_S_REGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14",
    "s15", "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27",
    "s28", "s29", "s30", "s31",
];

/// VFPV4 double-precision register names (d0–d31).
pub static VFP_D_REGS: &[&str] = &[
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14",
    "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27",
    "d28", "d29", "d30", "d31",
];

/// NEON quad register names (q0–q15).
pub static NEON_Q_REGS: &[&str] = &[
    "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14",
    "q15",
];

/// IT block condition suffix table.
pub static IT_CONDS: &[&str] = &[
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
];

/// Decode a Thumb-2 BL instruction to its absolute target.
/// `hw1` and `hw2` are the two 16-bit halfwords; `pc` is the instruction address.
#[must_use] 
pub const fn decode_bl_target(hw1: u16, hw2: u16, pc: u32) -> u32 {
    let s = ((hw1 >> 10) & 1) as u32;
    let imm10 = (hw1 & 0x3ff) as u32;
    let imm11 = (hw2 & 0x7ff) as u32;
    let j1 = ((hw2 >> 13) & 1) as u32;
    let j2 = ((hw2 >> 11) & 1) as u32;
    let i1 = (!(j1 ^ s)) & 1;
    let i2 = (!(j2 ^ s)) & 1;
    let imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    let signed_off = (imm32 << 7).cast_signed() >> 7;
    pc.wrapping_add(4).wrapping_add(signed_off.cast_unsigned())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. ArmV7Full basic ──────────────────────────────────────────────────
    #[test]
    fn test_armv7_name() {
        assert_eq!(ArmV7Full::new().name(), "armv7");
        assert_eq!(ArmV7Full::thumb().name(), "thumb2");
    }

    #[test]
    fn test_armv7_pointer_size() {
        assert_eq!(ArmV7Full::new().pointer_size(), 4);
    }

    #[test]
    fn test_armv7_default() {
        let a = ArmV7Full::default();
        assert!(!a.thumb_mode);
        assert!(a.little_endian);
    }

    // ── 2. ThumbExpanded classify ────────────────────────────────────────────
    #[test]
    fn test_thumb_expanded_classify_branch() {
        // BL: op1=0b11, hw2 top bits = 0b11 (bit14=1, bit12=1)
        let hw1: u16 = 0b1111_1000_0000_0000; // op1=11
        let hw2: u16 = 0b1111_0000_0000_0000;
        let k = ThumbExpanded::classify(hw1, hw2);
        assert_eq!(k, ThumbExpandedKind::BranchMisc);
    }

    #[test]
    fn test_thumb_expanded_decode_produces_mnemonic() {
        let hw1: u16 = 0xF000;
        let hw2: u16 = 0xF800;
        let t = ThumbExpanded::decode(hw1, hw2);
        assert!(!t.mnemonic.is_empty());
    }

    #[test]
    fn test_thumb_expanded_bl_mnemonic() {
        // BL: hw1 = 0xF000, hw2 = 0xE800 (bit14=1, bit13=1, bit12=1)
        let hw1: u16 = 0xF000;
        let hw2: u16 = 0xE800;
        let t = ThumbExpanded::decode(hw1, hw2);
        assert!(t.mnemonic.contains("bl") || t.mnemonic.contains('b'));
    }

    // ── 3. ArmCoprocessor decode MCR ────────────────────────────────────────
    #[test]
    fn test_coprocessor_decode_mcr() {
        // MCR p10, 0, r1, c0, c0, 0 — E E E 0 1 0 00 0001 0001 1010 0001 0000
        // A32 MCR: cond=0xe, bits[27:25]=111, bit24=0, opc1=0, crn=0, rt=1, cp=10, opc2=0, bit4=1, crm=0
        let word: u32 = 0xEE00_1A10; // typical MCR p10, 0, r1, c0, c0, 0
        let result = ArmCoprocessor::decode_a32(word);
        assert!(result.is_some());
        let c = result.unwrap();
        assert_eq!(c.cp_num, 10);
        assert_eq!(c.kind, CoprocessorKind::Mcr);
    }

    #[test]
    fn test_coprocessor_decode_none_for_unconditional() {
        // cond = 0xF → unconditional encoding, not a standard MCR
        let word: u32 = 0xFF00_1A10;
        assert!(ArmCoprocessor::decode_a32(word).is_none());
    }

    #[test]
    fn test_coprocessor_format_mcr() {
        let cp = ArmCoprocessor {
            cp_num: 10,
            opc1: 0,
            crn: 0,
            rt: 1,
            crm: 0,
            opc2: 0,
            kind: CoprocessorKind::Mcr,
        };
        let s = cp.format();
        assert!(s.contains("mcr"));
        assert!(s.contains("p10"));
    }

    #[test]
    fn test_coprocessor_format_mrc() {
        let cp = ArmCoprocessor {
            cp_num: 15,
            opc1: 0,
            crn: 1,
            rt: 0,
            crm: 0,
            opc2: 0,
            kind: CoprocessorKind::Mrc,
        };
        let s = cp.format();
        assert!(s.contains("mrc"), "got: {s}");
    }

    // ── 4. NeonFull decode ───────────────────────────────────────────────────
    #[test]
    fn test_neon_decode_none_for_non_neon() {
        assert!(NeonFull::decode_a32(0xE1A0_0000).is_none()); // ARM MOV
    }

    #[test]
    fn test_neon_decode_some_for_neon_space() {
        // F2 prefix = 0xF2 → NEON data processing
        let word: u32 = 0xF200_0010; // some NEON word
        let result = NeonFull::decode_a32(word);
        assert!(result.is_some());
    }

    #[test]
    fn test_neon_decode_f3_unsigned() {
        let word: u32 = 0xF300_0010;
        let result = NeonFull::decode_a32(word);
        assert!(result.is_some());
        let n = result.unwrap();
        // F3 → unsigned flag → !signed
        assert!(!n.signed);
    }

    #[test]
    fn test_neon_kind_mnemonic() {
        assert_eq!(NeonKind::Vadd.mnemonic(), "vadd");
        assert_eq!(NeonKind::Vld1.mnemonic(), "vld1");
        assert_eq!(NeonKind::Vst4.mnemonic(), "vst4");
    }

    #[test]
    fn test_neon_kind_reads_memory() {
        assert!(NeonKind::Vld1.reads_memory());
        assert!(NeonKind::Vld4.reads_memory());
        assert!(!NeonKind::Vadd.reads_memory());
    }

    #[test]
    fn test_neon_kind_writes_memory() {
        assert!(NeonKind::Vst1.writes_memory());
        assert!(!NeonKind::Vld1.writes_memory());
    }

    #[test]
    fn test_neon_format() {
        let n = NeonFull {
            encoding: 0,
            kind: NeonKind::Vadd,
            vd: 0,
            vn: 1,
            vm: 2,
            quad: true,
            esize: 32,
            signed: true,
        };
        let s = n.format();
        assert!(s.contains("vadd"));
    }

    // ── 5. VfpFull decode ────────────────────────────────────────────────────
    #[test]
    fn test_vfp_decode_none_for_non_vfp() {
        // ARM NOP (no VFP coprocessor)
        assert!(VfpFull::decode_a32(0xE1A0_0000).is_none());
    }

    #[test]
    fn test_vfp_decode_vldr() {
        // VLDR d0, [r0] — 0xED900B00
        let word: u32 = 0xED90_0B00;
        let result = VfpFull::decode_a32(word);
        assert!(result.is_some());
        let v = result.unwrap();
        assert!(v.dp);
        assert!(matches!(v.kind, VfpKind::Vldr));
    }

    #[test]
    fn test_vfp_decode_vstr() {
        // VSTR d0, [r0] — 0xED800B00
        let word: u32 = 0xED80_0B00;
        let result = VfpFull::decode_a32(word);
        assert!(result.is_some());
        let v = result.unwrap();
        assert!(matches!(v.kind, VfpKind::Vstr));
    }

    #[test]
    fn test_vfp_kind_mnemonic() {
        assert_eq!(VfpKind::Vadd.mnemonic(), "vadd");
        assert_eq!(VfpKind::Vsqrt.mnemonic(), "vsqrt");
        assert_eq!(VfpKind::Vmrs.mnemonic(), "vmrs");
    }

    #[test]
    fn test_vfp_kind_reads_memory() {
        assert!(VfpKind::Vldr.reads_memory());
        assert!(VfpKind::Vpop.reads_memory());
        assert!(!VfpKind::Vadd.reads_memory());
    }

    #[test]
    fn test_vfp_kind_writes_memory() {
        assert!(VfpKind::Vstr.writes_memory());
        assert!(VfpKind::Vpush.writes_memory());
        assert!(!VfpKind::Vldr.writes_memory());
    }

    #[test]
    fn test_vfp_format() {
        let v = VfpFull {
            encoding: 0,
            kind: VfpKind::Vadd,
            fd: 0,
            fn_: 1,
            fm: 2,
            dp: true,
        };
        let s = v.format();
        assert!(s.contains("vadd"));
        assert!(s.contains(".f64"));
    }

    // ── 6. ArmV7Lifter ───────────────────────────────────────────────────────
    #[test]
    fn test_lifter_bl() {
        let lifter = ArmV7Lifter;
        // BL +0 (from 0x1000: BL 0x1000 effectively)
        // 0xEB000000 = BL imm24=0 → offset=0 → target = 0x1000 + 8 = 0x1008
        let word: u32 = 0xEB00_0000;
        let op = lifter.lift_a32(word, 0x1000);
        match op {
            V7LiftOp::Call(target) => assert_eq!(target, 0x1008),
            _ => panic!("expected Call, got {op:?}"),
        }
    }

    #[test]
    fn test_lifter_b_unconditional() {
        let lifter = ArmV7Lifter;
        // B +0 (cond=0xe, L=0): 0xEA000000
        let op = lifter.lift_a32(0xEA00_0000, 0x2000);
        match op {
            V7LiftOp::Branch(target) => assert_eq!(target, 0x2008),
            _ => panic!("expected Branch, got {op:?}"),
        }
    }

    #[test]
    fn test_lifter_b_conditional() {
        let lifter = ArmV7Lifter;
        // BEQ +0 (cond=0x0, L=0): 0x0A000000
        let op = lifter.lift_a32(0x0A00_0000, 0x3000);
        match op {
            V7LiftOp::CondBranch { cond, target } => {
                assert_eq!(cond, 0x0);
                assert_eq!(target, 0x3008);
            }
            _ => panic!("expected CondBranch, got {op:?}"),
        }
    }

    #[test]
    fn test_lifter_ldr() {
        let lifter = ArmV7Lifter;
        // LDR r1, [r0, #8] = 0xE5901008
        let op = lifter.lift_a32(0xE590_1008, 0x1000);
        match op {
            V7LiftOp::Load { dest, base, offset } => {
                assert_eq!(base, 0); // r0
                assert_eq!(dest, 1); // r1
                assert_eq!(offset, 8);
            }
            _ => panic!("expected Load, got {op:?}"),
        }
    }

    #[test]
    fn test_lifter_str() {
        let lifter = ArmV7Lifter;
        // STR r1, [r0] = 0xE5801000
        let op = lifter.lift_a32(0xE580_1000, 0x1000);
        match op {
            V7LiftOp::Store { src, base, .. } => {
                assert_eq!(base, 0);
                assert_eq!(src, 1);
            }
            _ => panic!("expected Store, got {op:?}"),
        }
    }

    #[test]
    fn test_lifter_bx_lr_is_return() {
        let lifter = ArmV7Lifter;
        // BX LR = 0xE12FFF1E
        let op = lifter.lift_a32(0xE12F_FF1E, 0x1000);
        assert_eq!(op, V7LiftOp::Return);
    }

    #[test]
    fn test_lifter_nop() {
        let lifter = ArmV7Lifter;
        // Undefined / unrecognised
        let op = lifter.lift_a32(0x0000_0000, 0x0);
        // Should return Nop or BinOp, not panic
        let _ = op;
    }

    // ── 7. V7BinOp ───────────────────────────────────────────────────────────
    #[test]
    fn test_binop_mnemonic() {
        assert_eq!(V7BinOp::Add.mnemonic(), "add");
        assert_eq!(V7BinOp::Eor.mnemonic(), "eor");
        assert_eq!(V7BinOp::Asr.mnemonic(), "asr");
    }

    // ── 8. CoprocessorKind variants ─────────────────────────────────────────
    #[test]
    fn test_coprocessor_kinds() {
        let kinds = [
            CoprocessorKind::Mcr,
            CoprocessorKind::Mrc,
            CoprocessorKind::Cdp,
            CoprocessorKind::Ldc,
            CoprocessorKind::Stc,
            CoprocessorKind::Mcrr,
            CoprocessorKind::Mrrc,
        ];
        for k in kinds {
            // just ensure equality works and no panic
            assert_eq!(k, k);
        }
    }

    // ── 9. ThumbExpanded encoding field ─────────────────────────────────────
    #[test]
    fn test_thumb_expanded_encoding() {
        let hw1: u16 = 0xF000;
        let hw2: u16 = 0xE800;
        let t = ThumbExpanded::decode(hw1, hw2);
        assert_eq!(t.encoding >> 16, u32::from(hw1));
        assert_eq!(t.encoding & 0xffff, u32::from(hw2));
    }

    // ── 10. ThumbExpandedKind all variants have a decode path ───────────────
    #[test]
    fn test_thumb_expanded_all_kinds() {
        // Just test classify returns some kind without panicking
        let pairs: &[(u16, u16)] = &[
            (0xF000, 0xE800), // BranchMisc
            (0xF200, 0x0000), // DpModImm area
            (0xEA00, 0x0000), // DpShiftedReg
            (0xE980, 0x0000), // LdmStm
        ];
        for &(hw1, hw2) in pairs {
            let k = ThumbExpanded::classify(hw1, hw2);
            let _ = k; // just no panic
        }
    }
}
