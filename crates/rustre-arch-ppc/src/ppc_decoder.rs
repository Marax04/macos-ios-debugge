//! PowerPC instruction decoder: primary opcode, secondary opcode, all major
//! instruction forms (I, B, X, D, DS, XO, M), producing a rich decoded
//! instruction struct.

// â”€â”€ Instruction forms â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Broad PowerPC instruction form as defined by the PowerPC ISA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpcForm {
    /// I-form: unconditional branch with 26-bit LI offset.
    IForm,
    /// B-form: conditional branch with 16-bit BD offset, BI/BO.
    BForm,
    /// SC-form: system call.
    ScForm,
    /// D-form: load/store with 16-bit displacement or immediate arithmetic.
    DForm,
    /// DS-form: 64-bit load/store with 14-bit displacement shifted by 2.
    DsForm,
    /// X-form: integer / float / misc with 10-bit extended opcode.
    XForm,
    /// XL-form: branch-CTR/LR, MCRF, etc.
    XlForm,
    /// XFX-form: SPR move (MFSPR/MTSPR).
    XfxForm,
    /// XO-form: arithmetic with OE and Rc bits.
    XoForm,
    /// M-form: rotate word with mask.
    MForm,
    /// MD-form: rotate doubleword with immediate mask.
    MdForm,
    /// Float A-form (4 source operands).
    AForm,
    /// Unknown / not decoded.
    Unknown,
}

/// Primary opcode (bits 0-5) of a PowerPC instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpcPrimary(pub u8);

impl PpcPrimary {
    /// Extract from raw instruction word.
    #[must_use]
    #[inline]
    pub const fn from_instr(instr: u32) -> Self {
        Self((instr >> 26) as u8)
    }
}

/// Extended / secondary opcode (bits 21-30 for X-form, 22-30 for XO-form, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpcExtended(pub u16);

impl PpcExtended {
    /// Extract 10-bit XO for X-form (bits 21-30, i.e. bits 1-10 from the right).
    #[must_use]
    #[inline]
    pub const fn from_x_form(instr: u32) -> Self {
        Self(((instr >> 1) & 0x3FF) as u16)
    }
    /// Extract 9-bit XO for XO-form (bits 22-30).
    #[must_use]
    #[inline]
    pub const fn from_xo_form(instr: u32) -> Self {
        Self(((instr >> 1) & 0x1FF) as u16)
    }
}

// â”€â”€ Operand types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A decoded PowerPC operand value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcOperand {
    /// General-purpose register index (0-31).
    Gpr(u8),
    /// Floating-point register index (0-31).
    Fpr(u8),
    /// Condition register field index (0-7).
    Cr(u8),
    /// Unsigned 16-bit immediate.
    Uimm16(u16),
    /// Signed 16-bit immediate.
    Simm16(i16),
    /// Signed 26-bit branch offset (I-form, already in bytes).
    BranchOffset26(i32),
    /// Signed 16-bit branch offset (B-form, already in bytes).
    BranchOffset16(i16),
    /// Absolute branch target address.
    AbsTarget(u32),
    /// Shift amount (0-63).
    ShiftAmount(u8),
    /// Mask begin/end pair (MB, ME for M-form rotate).
    MaskPair(u8, u8),
    /// SPR number (decoded from field).
    Spr(u16),
    /// Trap-to-trap condition bits (5-bit).
    TrapCond(u8),
    /// BO field (5-bit branch option).
    Bo(u8),
    /// BI field (5-bit condition register bit).
    Bi(u8),
}

impl PpcOperand {
    /// Format as assembler text (Motorola / POWER style).
    #[must_use]
    pub fn format(&self) -> String {
        match self {
            Self::Gpr(r) => format!("r{r}"),
            Self::Fpr(f) => format!("f{f}"),
            Self::Cr(c) => format!("cr{c}"),
            Self::Uimm16(u) => format!("{u}"),
            Self::Simm16(s) => format!("{s}"),
            Self::BranchOffset26(o) => format!("{o:+}"),
            Self::BranchOffset16(o) => format!("{o:+}"),
            Self::AbsTarget(a) => format!("0x{a:08X}"),
            Self::ShiftAmount(s) => format!("{s}"),
            Self::MaskPair(mb, me) => format!("{mb},{me}"),
            Self::Spr(s) => format!("{s}"),
            Self::TrapCond(t) => format!("{t}"),
            Self::Bo(b) | Self::Bi(b) => format!("{b}"),
        }
    }
}

// â”€â”€ Decoded instruction struct â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The single-bit modifier fields of a PowerPC instruction word.
///
/// Bit order follows the architecture's own naming order LK, AA, Rc, OE.
/// Four adjacent `bool` fields are interchangeable to the compiler; one bit
/// set with named constants is not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PpcInstrBits(u8);

impl PpcInstrBits {
    /// LK — the Link bit.
    pub const LINK: u8 = 1 << 0;
    /// AA — the Absolute Address bit.
    pub const ABSOLUTE: u8 = 1 << 1;
    /// Rc — the Record bit.
    pub const RECORD: u8 = 1 << 2;
    /// OE — the Overflow Enable bit.
    pub const OVERFLOW_ENABLE: u8 = 1 << 3;

    /// Every bit this type tracks.
    pub const MASK: u8 = Self::LINK | Self::ABSOLUTE | Self::RECORD | Self::OVERFLOW_ENABLE;

    /// No bit set.
    pub const NONE: Self = Self(0);

    /// Keep only the bits this type tracks.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self { Self(v & Self::MASK) }

    /// The raw bit image.
    #[must_use]
    pub const fn bits(self) -> u8 { self.0 }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool { self.0 & bit != 0 }

    /// A copy with `bit` set (`on`) or cleared.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on { Self(self.0 | (bit & Self::MASK)) } else { Self(self.0 & !bit) }
    }

    /// Set or clear `bit` in place.
    pub const fn set(&mut self, bit: u8, on: bool) { *self = self.with(bit, on); }
}

impl core::ops::BitOr for PpcInstrBits {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

/// A fully decoded PowerPC instruction.
#[derive(Debug, Clone)]
pub struct PpcInstr {
    /// Raw 32-bit instruction word.
    pub raw: u32,
    /// Primary opcode (bits 0-5).
    pub primary: PpcPrimary,
    /// Extended opcode, if applicable.
    pub extended: Option<PpcExtended>,
    /// Instruction form.
    pub form: PpcForm,
    /// Mnemonic string (upper-case, with optional "." or "O" suffix).
    pub mnemonic: String,
    /// Decoded operands in order.
    pub operands: Vec<PpcOperand>,
    /// Absolute branch target, if this is a branch instruction.
    pub branch_target: Option<u64>,
    /// The LK / AA / Rc / OE bits of the instruction word.
    pub flags: PpcInstrBits,
}

impl PpcInstr {
    /// Whether the `LINK` bit is set.
    #[must_use]
    pub const fn link(&self) -> bool { self.flags.has(PpcInstrBits::LINK) }
    /// Set the `LINK` bit.
    pub const fn set_link(&mut self, on: bool) { self.flags.set(PpcInstrBits::LINK, on); }
    /// Whether the `ABSOLUTE` bit is set.
    #[must_use]
    pub const fn absolute(&self) -> bool { self.flags.has(PpcInstrBits::ABSOLUTE) }
    /// Set the `ABSOLUTE` bit.
    pub const fn set_absolute(&mut self, on: bool) { self.flags.set(PpcInstrBits::ABSOLUTE, on); }
    /// Whether the `RECORD` bit is set.
    #[must_use]
    pub const fn record(&self) -> bool { self.flags.has(PpcInstrBits::RECORD) }
    /// Set the `RECORD` bit.
    pub const fn set_record(&mut self, on: bool) { self.flags.set(PpcInstrBits::RECORD, on); }
    /// Whether the `OVERFLOW_ENABLE` bit is set.
    #[must_use]
    pub const fn overflow_enable(&self) -> bool { self.flags.has(PpcInstrBits::OVERFLOW_ENABLE) }
    /// Set the `OVERFLOW_ENABLE` bit.
    pub const fn set_overflow_enable(&mut self, on: bool) { self.flags.set(PpcInstrBits::OVERFLOW_ENABLE, on); }

    /// Return `true` if this instruction modifies the Link Register.
    #[must_use]
    pub const fn sets_lr(&self) -> bool {
        self.link()
    }

    /// Return `true` if this instruction is a branch of any kind.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(self.primary.0, 16 | 18 | 19)
    }

    /// Return `true` if this instruction is a call (branch-and-link).
    #[must_use]
    pub const fn is_call(&self) -> bool {
        self.is_branch() && self.link()
    }

    /// Return `true` if this instruction is a return (BCLR, RFI).
    #[must_use]
    pub fn is_return(&self) -> bool {
        self.primary.0 == 19 && self.extended.is_some_and(|ext| matches!(ext.0, 16 | 18 | 50))
    }

    /// Operand string formatted for display.
    #[must_use]
    pub fn operand_string(&self) -> String {
        self.operands
            .iter()
            .map(PpcOperand::format)
            .collect::<Vec<_>>()
            .join(",")
    }
}

// â”€â”€ Helper extract functions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const fn gpr_field(instr: u32, shift: u32) -> u8 {
    ((instr >> shift) & 31) as u8
}

const fn fpr_field(instr: u32, shift: u32) -> u8 {
    ((instr >> shift) & 31) as u8
}

const fn simm16_field(instr: u32) -> i16 {
    (instr & 0xFFFF) as i16
}

const fn uimm16_field(instr: u32) -> u16 {
    (instr & 0xFFFF) as u16
}

const fn spr_decode(instr: u32) -> u16 {
    // raw is at most 10 bits (0..=0x3FF), safe to narrow to u16
    let raw = ((instr >> 11) & 0x3FF) as u16;
    ((raw & 0x1F) << 5) | (raw >> 5)
}

fn branch_target_i_form(pc: u64, instr: u32) -> (i32, bool, bool, u64) {
    let li_raw = (instr & 0x03FF_FFFC).cast_signed();
    let li = if li_raw & 0x0200_0000 != 0 {
        li_raw - 0x0400_0000
    } else {
        li_raw
    };
    let aa = (instr >> 1) & 1 != 0;
    let lk = instr & 1 != 0;
    let target = if aa {
        u64::from(u32::from_ne_bytes(li.to_ne_bytes()))
    } else {
        pc.wrapping_add_signed(i64::from(li))
    };
    (li, aa, lk, target)
}

fn branch_target_b_form(pc: u64, instr: u32) -> (i16, bool, bool, u64) {
    let bd_raw = (instr & 0xFFFC).cast_signed();
    let bd = if bd_raw & 0x8000 != 0 {
        i16::try_from(bd_raw - 0x1_0000).unwrap_or(i16::MIN)
    } else {
        i16::try_from(bd_raw).unwrap_or(i16::MAX)
    };
    let aa = (instr >> 1) & 1 != 0;
    let lk = instr & 1 != 0;
    let target = if aa {
        u64::from(bd.cast_unsigned())
    } else {
        pc.wrapping_add_signed(i64::from(bd))
    };
    (bd, aa, lk, target)
}

// â”€â”€ The Decoder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// PowerPC instruction decoder.
///
/// Stateless â€” decoding a single instruction requires only the raw word and PC.
#[derive(Debug, Clone, Copy, Default)]
pub struct PpcDecoder {
    /// Whether to decode in 64-bit mode (enables DS-form ld/std/ldu/stdu).
    pub bits64: bool,
}

impl PpcDecoder {
    /// Create a new 32-bit PPC decoder.
    #[must_use]
    pub const fn new_32() -> Self {
        Self { bits64: false }
    }

    /// Create a new 64-bit PPC decoder.
    #[must_use]
    pub const fn new_64() -> Self {
        Self { bits64: true }
    }

    /// Decode one instruction at `pc` from the big-endian bytes.
    ///
    /// Returns `None` if there are fewer than 4 bytes.
    #[must_use]
    pub fn decode(&self, pc: u64, bytes: &[u8]) -> Option<PpcInstr> {
        if bytes.len() < 4 {
            return None;
        }
        let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Some(self.decode_word(pc, raw))
    }

    /// Decode from a raw 32-bit instruction word.
    #[must_use]
    pub fn decode_word(&self, pc: u64, instr: u32) -> PpcInstr {
        let primary = PpcPrimary::from_instr(instr);
        match primary.0 {
            3 => Self::decode_twi(instr),
            7 => Self::decode_mulli(instr),
            8 => Self::decode_subfic(instr),
            10 => Self::decode_cmpli(instr),
            11 => Self::decode_cmpi(instr),
            12 => Self::decode_addic(instr, false),
            13 => Self::decode_addic(instr, true),
            14 => Self::decode_addi(instr),
            15 => Self::decode_addis(instr),
            16 => Self::decode_b_form(pc, instr),
            17 => Self::decode_sc(instr),
            18 => Self::decode_i_form(pc, instr),
            19 => Self::decode_opcd19(instr),
            20 => Self::decode_rlwimi(instr),
            21 => Self::decode_rlwinm(instr),
            23 => Self::decode_rlwnm(instr),
            24 => Self::decode_ori(instr),
            25 => Self::decode_oris(instr),
            26 => Self::decode_xori(instr),
            27 => Self::decode_xoris(instr),
            28 => Self::decode_andi_dot(instr),
            29 => Self::decode_andis_dot(instr),
            30 if self.bits64 => Self::decode_opcd30(instr),
            31 => Self::decode_opcd31(instr),
            32..=55 => Self::decode_mem(instr),
            56..=63 => Self::decode_fp(instr),
            _ => Self::unknown(instr),
        }
    }

    // â”€â”€ I-form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_i_form(pc: u64, instr: u32) -> PpcInstr {
        let (li, aa, lk, target) = branch_target_i_form(pc, instr);
        let mn = match (aa, lk) {
            (false, false) => "B",
            (false, true) => "BL",
            (true, false) => "BA",
            _ => "BLA",
        };
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(18),
            extended: None,
            form: PpcForm::IForm,
            mnemonic: mn.to_string(),
            operands: vec![PpcOperand::BranchOffset26(li)],
            branch_target: Some(target),
            flags: PpcInstrBits::NONE.with(PpcInstrBits::LINK, lk).with(PpcInstrBits::ABSOLUTE, aa), }
    }

    // â”€â”€ B-form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_b_form(pc: u64, instr: u32) -> PpcInstr {
        let bo = gpr_field(instr, 21);
        let bi = gpr_field(instr, 16);
        let (bd, aa, lk, target) = branch_target_b_form(pc, instr);
        let cond_str = Self::bc_mnemonic(bo, bi);
        let lk_sfx = if lk { "L" } else { "" };
        let mn = format!("{cond_str}{lk_sfx}");
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(16),
            extended: None,
            form: PpcForm::BForm,
            mnemonic: mn,
            operands: vec![
                PpcOperand::Bo(bo),
                PpcOperand::Bi(bi),
                PpcOperand::BranchOffset16(bd),
            ],
            branch_target: Some(target),
            flags: PpcInstrBits::NONE.with(PpcInstrBits::LINK, lk).with(PpcInstrBits::ABSOLUTE, aa), }
    }

    const fn bc_mnemonic(bo: u8, bi: u8) -> &'static str {
        let always = bo & 0x14 == 0x14;
        if always {
            return "B";
        }
        let taken = bo & 8 != 0;
        match bi & 3 {
            0 => if taken { "BLT" } else { "BGE" },
            1 => if taken { "BGT" } else { "BLE" },
            2 => if taken { "BEQ" } else { "BNE" },
            _ => if taken { "BSO" } else { "BNS" },
        }
    }

    // â”€â”€ SC form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_sc(instr: u32) -> PpcInstr {
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(17),
            extended: None,
            form: PpcForm::ScForm,
            mnemonic: "SC".to_string(),
            operands: vec![],
            branch_target: None,
            flags: PpcInstrBits::NONE, }
    }

    // â”€â”€ opcd 19 (XL-form branches / CR ops) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_opcd19(instr: u32) -> PpcInstr {
        let xo = PpcExtended::from_x_form(instr);
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        let lk = instr & 1 != 0;
        let (mn, ops, is_ret): (&str, Vec<PpcOperand>, bool) = match xo.0 {
            0 => ("MCRF", vec![
                PpcOperand::Cr(rs >> 2),
                PpcOperand::Cr(ra >> 2),
            ], false),
            16 => (if lk { "BCLRL" } else { "BCLR" }, vec![], true),
            18 | 50 => ("RFI", vec![], true),
            150 => ("ISYNC", vec![], false),
            528 => (if lk { "BCCTRL" } else { "BCCTR" }, vec![], false),
            _ => ("DC.W", vec![], false),
        };
        let _ = is_ret;
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(19),
            extended: Some(xo),
            form: PpcForm::XlForm,
            mnemonic: mn.to_string(),
            operands: ops,
            branch_target: None,
            flags: PpcInstrBits::NONE.with(PpcInstrBits::LINK, lk), }
    }

    // â”€â”€ D-form helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn d_form(primary: u8, mn: &str, instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(primary),
            extended: None,
            form: PpcForm::DForm,
            mnemonic: mn.to_string(),
            operands: vec![
                PpcOperand::Gpr(rs),
                PpcOperand::Gpr(ra),
                PpcOperand::Simm16(simm16_field(instr)),
            ],
            branch_target: None,
            flags: PpcInstrBits::NONE, }
    }

    fn decode_twi(instr: u32) -> PpcInstr {
        let to_cond = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        PpcInstr {
            raw: instr,
            primary: PpcPrimary(3),
            extended: None,
            form: PpcForm::DForm,
            mnemonic: "TWI".to_string(),
            operands: vec![
                PpcOperand::TrapCond(to_cond),
                PpcOperand::Gpr(ra),
                PpcOperand::Simm16(simm16_field(instr)),
            ],
            branch_target: None,
            flags: PpcInstrBits::NONE, }
    }

    fn decode_mulli(instr: u32) -> PpcInstr { Self::d_form(7, "MULLI", instr) }
    fn decode_subfic(instr: u32) -> PpcInstr { Self::d_form(8, "SUBFIC", instr) }

    fn decode_cmpli(instr: u32) -> PpcInstr {
        let crfd = gpr_field(instr, 23) >> 2;
        let ra = gpr_field(instr, 16);
        PpcInstr {
            raw: instr, primary: PpcPrimary(10), extended: None,
            form: PpcForm::DForm, mnemonic: "CMPLWI".to_string(),
            operands: vec![PpcOperand::Cr(crfd), PpcOperand::Gpr(ra),
                           PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE, }
    }

    fn decode_cmpi(instr: u32) -> PpcInstr {
        let crfd = gpr_field(instr, 23) >> 2;
        let ra = gpr_field(instr, 16);
        PpcInstr {
            raw: instr, primary: PpcPrimary(11), extended: None,
            form: PpcForm::DForm, mnemonic: "CMPWI".to_string(),
            operands: vec![PpcOperand::Cr(crfd), PpcOperand::Gpr(ra),
                           PpcOperand::Simm16(simm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE, }
    }

    fn decode_addic(instr: u32, dot: bool) -> PpcInstr {
        Self::d_form(if dot { 13 } else { 12 }, if dot { "ADDIC." } else { "ADDIC" }, instr)
    }

    fn decode_addi(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        let (mn, ops) = if ra == 0 {
            ("LI", vec![PpcOperand::Gpr(rs), PpcOperand::Simm16(simm16_field(instr))])
        } else {
            ("ADDI", vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Simm16(simm16_field(instr))])
        };
        PpcInstr {
            raw: instr, primary: PpcPrimary(14), extended: None,
            form: PpcForm::DForm, mnemonic: mn.to_string(), operands: ops,
            branch_target: None, flags: PpcInstrBits::NONE, }
    }

    fn decode_addis(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        let (mn, ops) = if ra == 0 {
            ("LIS", vec![PpcOperand::Gpr(rs), PpcOperand::Simm16(simm16_field(instr))])
        } else {
            ("ADDIS", vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Simm16(simm16_field(instr))])
        };
        PpcInstr {
            raw: instr, primary: PpcPrimary(15), extended: None,
            form: PpcForm::DForm, mnemonic: mn.to_string(), operands: ops,
            branch_target: None, flags: PpcInstrBits::NONE, }
    }

    fn decode_ori(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(24), extended: None, form: PpcForm::DForm,
            mnemonic: "ORI".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE}
    }

    fn decode_oris(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(25), extended: None, form: PpcForm::DForm,
            mnemonic: "ORIS".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE}
    }

    fn decode_xori(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(26), extended: None, form: PpcForm::DForm,
            mnemonic: "XORI".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE}
    }

    fn decode_xoris(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(27), extended: None, form: PpcForm::DForm,
            mnemonic: "XORIS".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::NONE}
    }

    fn decode_andi_dot(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(28), extended: None, form: PpcForm::DForm,
            mnemonic: "ANDI.".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::from_bits(PpcInstrBits::RECORD)}
    }

    fn decode_andis_dot(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        PpcInstr { raw: instr, primary: PpcPrimary(29), extended: None, form: PpcForm::DForm,
            mnemonic: "ANDIS.".to_string(),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Uimm16(uimm16_field(instr))],
            branch_target: None, flags: PpcInstrBits::from_bits(PpcInstrBits::RECORD)}
    }

    // â”€â”€ M-form (rotate) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_rlwimi(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        let sh = gpr_field(instr, 11); let mb = gpr_field(instr, 6);
        let me = ((instr >> 1) & 31) as u8; let rc = instr & 1 != 0;
        let sfx = if rc { "." } else { "" };
        PpcInstr { raw: instr, primary: PpcPrimary(20), extended: None, form: PpcForm::MForm,
            mnemonic: format!("RLWIMI{sfx}"),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs),
                           PpcOperand::ShiftAmount(sh), PpcOperand::MaskPair(mb, me)],
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, rc)}
    }

    fn decode_rlwinm(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        let sh = gpr_field(instr, 11); let mb = gpr_field(instr, 6);
        let me = ((instr >> 1) & 31) as u8; let rc = instr & 1 != 0;
        let sfx = if rc { "." } else { "" };
        PpcInstr { raw: instr, primary: PpcPrimary(21), extended: None, form: PpcForm::MForm,
            mnemonic: format!("RLWINM{sfx}"),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs),
                           PpcOperand::ShiftAmount(sh), PpcOperand::MaskPair(mb, me)],
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, rc)}
    }

    fn decode_rlwnm(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21); let ra = gpr_field(instr, 16);
        let rb = gpr_field(instr, 11); let mb = gpr_field(instr, 6);
        let me = ((instr >> 1) & 31) as u8; let rc = instr & 1 != 0;
        let sfx = if rc { "." } else { "" };
        PpcInstr { raw: instr, primary: PpcPrimary(23), extended: None, form: PpcForm::MForm,
            mnemonic: format!("RLWNM{sfx}"),
            operands: vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs),
                           PpcOperand::Gpr(rb), PpcOperand::MaskPair(mb, me)],
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, rc)}
    }

    // â”€â”€ MD-form (64-bit rotate) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_opcd30(instr: u32) -> PpcInstr {
        // Very basic: just return the mnemonic for RLDICL/RLDICR/RLDIC/RLDIMI/RLDCL/RLDCR
        let xo = (instr >> 1) & 0xF;
        let mn = match xo {
            0 | 1 => "RLDICL",
            2 | 3 => "RLDICR",
            4 | 5 => "RLDIC",
            6 => "RLDIMI",
            8 | 9 => "RLDCL",
            10 | 11 => "RLDCR",
            _ => "DC.W",
        };
        PpcInstr { raw: instr, primary: PpcPrimary(30), extended: Some(PpcExtended(xo as u16)),
            form: PpcForm::MdForm, mnemonic: mn.to_string(),
            operands: vec![PpcOperand::Uimm16(u16::try_from(instr & 0xFFFF).unwrap_or(u16::MAX))],
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, instr & 1 != 0)}
    }

    // â”€â”€ opcd 31 (X / XO forms) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_opcd31(instr: u32) -> PpcInstr {
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        let rb = gpr_field(instr, 11);
        let rc = instr & 1 != 0;
        let oe = (instr >> 10) & 1 != 0;
        let xo = PpcExtended::from_x_form(instr);
        let rc_sfx = if rc { "." } else { "" };
        let oe_sfx = if oe { "O" } else { "" };
        let sfx = format!("{oe_sfx}{rc_sfx}");

        let (mn, ops): (String, Vec<PpcOperand>) = match xo.0 {
            0 => ("CMP".into(), vec![PpcOperand::Cr(rs >> 2), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            8 => (format!("SUBFC{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            10 => (format!("ADDC{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            19 => ("MFCR".into(), vec![PpcOperand::Gpr(rs)]),
            28 => (format!("AND{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            32 => ("CMPL".into(), vec![PpcOperand::Cr(rs >> 2), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            40 => (format!("SUBF{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            60 => (format!("ANDC{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            104 => (format!("NEG{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra)]),
            124 => (format!("NOR{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            138 => (format!("ADDE{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            144 => ("MTCRF".into(), vec![PpcOperand::Uimm16(u16::from(((instr >> 12) & 0xFF) as u8)), PpcOperand::Gpr(rs)]),
            202 => (format!("ADDZE{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra)]),
            234 => (format!("ADDME{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra)]),
            235 => (format!("MULLW{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            266 => (format!("ADD{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            316 => (format!("XOR{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            339 => {
                let spr = spr_decode(instr);
                let mn = match spr { 1 => "MFXER", 8 => "MFLR", 9 => "MFCTR", _ => "MFSPR" };
                if spr > 9 {
                    ("MFSPR".into(), vec![PpcOperand::Gpr(rs), PpcOperand::Spr(spr)])
                } else {
                    (mn.into(), vec![PpcOperand::Gpr(rs)])
                }
            }
            412 => (format!("ORC{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            444 => (format!("OR{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            459 => (format!("DIVWU{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            467 => {
                let spr = spr_decode(instr);
                let mn = match spr { 1 => "MTXER", 8 => "MTLR", 9 => "MTCTR", _ => "MTSPR" };
                if spr > 9 {
                    ("MTSPR".into(), vec![PpcOperand::Spr(spr), PpcOperand::Gpr(rs)])
                } else {
                    (mn.into(), vec![PpcOperand::Gpr(rs)])
                }
            }
            491 => (format!("DIVW{sfx}"), vec![PpcOperand::Gpr(rs), PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            536 => (format!("SRW{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            598 => ("SYNC".into(), vec![]),
            792 => (format!("SRAW{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::Gpr(rb)]),
            824 => (format!("SRAWI{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs), PpcOperand::ShiftAmount(rb)]),
            854 => ("EIEIO".into(), vec![]),
            922 => (format!("EXTSH{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs)]),
            954 => (format!("EXTSB{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs)]),
            986 => (format!("EXTSW{rc_sfx}"), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rs)]),
            1014 => ("DCBZ".into(), vec![PpcOperand::Gpr(ra), PpcOperand::Gpr(rb)]),
            _ => ("DC.W".into(), vec![PpcOperand::Uimm16(u16::try_from(instr & 0xFFFF).unwrap_or(u16::MAX))]),
        };

        PpcInstr {
            raw: instr, primary: PpcPrimary(31), extended: Some(xo),
            form: PpcForm::XForm, mnemonic: mn, operands: ops,
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, rc).with(PpcInstrBits::OVERFLOW_ENABLE, oe), }
    }

    // â”€â”€ Memory instructions (opcd 32-55) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_mem(instr: u32) -> PpcInstr {
        let opcd = (instr >> 26) as u8;
        let rs = gpr_field(instr, 21);
        let ra = gpr_field(instr, 16);
        let simm = simm16_field(instr);
        let is_fp = opcd >= 48;
        let mn = match opcd {
            32 => "LWZ", 33 => "LWZU", 34 => "LBZ", 35 => "LBZU",
            36 => "STW", 37 => "STWU", 38 => "STB", 39 => "STBU",
            40 => "LHZ", 41 => "LHZU", 42 => "LHA", 43 => "LHAU",
            44 => "STH", 45 => "STHU", 46 => "LMW", 47 => "STMW",
            48 => "LFS", 49 => "LFSU", 50 => "LFD", 51 => "LFDU",
            52 => "STFS", 53 => "STFSU", 54 => "STFD", 55 => "STFDU",
            _ => "DC.W",
        };
        let first_op = if is_fp {
            PpcOperand::Fpr(fpr_field(instr, 21))
        } else {
            PpcOperand::Gpr(rs)
        };
        PpcInstr {
            raw: instr, primary: PpcPrimary(opcd), extended: None,
            form: PpcForm::DForm, mnemonic: mn.to_string(),
            operands: vec![first_op, PpcOperand::Simm16(simm), PpcOperand::Gpr(ra)],
            branch_target: None, flags: PpcInstrBits::NONE, }
    }

    // â”€â”€ Float opcd 56-63 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn decode_fp(instr: u32) -> PpcInstr {
        let opcd = (instr >> 26) as u8;
        // Minimal: just return DC.W for now for opcodes beyond 55 that aren't 63
        if opcd == 63 {
            return Self::decode_fp63(instr);
        }
        Self::unknown(instr)
    }

    fn decode_fp63(instr: u32) -> PpcInstr {
        let xo10 = (instr >> 1) & 0x3FF;
        let rs = fpr_field(instr, 21);
        let ra = fpr_field(instr, 16);
        let rb = fpr_field(instr, 11);
        let rc = instr & 1 != 0;
        let rc_sfx = if rc { "." } else { "" };
        let mn = match xo10 {
            0 => "FCMPU", 12 => "FRSP", 14 => "FCTIW", 15 => "FCTIWZ",
            32 => "FCMPO", 40 => "FNEG", 64 => "MCRFS", 72 => "FMR",
            136 => "FNABS", 264 => "FABS", 583 => "MFFS", 711 => "MTFSF",
            _ => {
                let xo5 = (instr >> 1) & 0x1F;
                match xo5 {
                    18 => "FDIV", 20 => "FSUB", 21 => "FADD",
                    22 => "FSQRT", 25 => "FMUL", 28 => "FMSUB",
                    29 => "FMADD", 30 => "FNMSUB", 31 => "FNMADD",
                    _ => "DC.W",
                }
            }
        };
        PpcInstr {
            raw: instr, primary: PpcPrimary(63),
            extended: Some(PpcExtended(xo10 as u16)),
            form: PpcForm::AForm,
            mnemonic: format!("{mn}{rc_sfx}"),
            operands: vec![PpcOperand::Fpr(rs), PpcOperand::Fpr(ra), PpcOperand::Fpr(rb)],
            branch_target: None, flags: PpcInstrBits::NONE.with(PpcInstrBits::RECORD, rc), }
    }

    // â”€â”€ Fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn unknown(instr: u32) -> PpcInstr {
        PpcInstr {
            raw: instr, primary: PpcPrimary::from_instr(instr), extended: None,
            form: PpcForm::Unknown,
            mnemonic: "DC.W".to_string(),
            operands: vec![PpcOperand::Uimm16(u16::try_from(instr & 0xFFFF).unwrap_or(u16::MAX))],
            branch_target: None, flags: PpcInstrBits::NONE, }
    }
}

// â”€â”€ Iterator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Linear iterator over a big-endian PowerPC byte slice.
pub struct PpcDecoderIter<'a> {
    decoder: PpcDecoder,
    bytes: &'a [u8],
    offset: usize,
    pc: u64,
}

impl<'a> PpcDecoderIter<'a> {
    /// Create a new iterator starting at `pc`.
    #[must_use]
    pub const fn new(decoder: PpcDecoder, bytes: &'a [u8], pc: u64) -> Self {
        Self { decoder, bytes, offset: 0, pc }
    }
}

impl Iterator for PpcDecoderIter<'_> {
    type Item = PpcInstr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 4 > self.bytes.len() {
            return None;
        }
        let instr = self.decoder.decode(self.pc, &self.bytes[self.offset..])?;
        self.offset += 4;
        self.pc += 4;
        Some(instr)
    }
}

// â”€â”€ Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> PpcDecoder { PpcDecoder::new_32() }

    #[test]
    fn test_nop() {
        // ORI r0,r0,0
        let i = dec().decode_word(0x1000, 0x6000_0000);
        assert_eq!(i.mnemonic, "ORI");
    }

    #[test]
    fn test_li() {
        let i = dec().decode_word(0x1000, 0x3860_0001);
        assert_eq!(i.mnemonic, "LI");
        assert!(matches!(i.operands[0], PpcOperand::Gpr(3)));
    }

    #[test]
    fn test_b() {
        let i = dec().decode_word(0x1000, 0x4800_0008);
        assert_eq!(i.mnemonic, "B");
        assert_eq!(i.branch_target, Some(0x1008));
        assert!(!i.link());
    }

    #[test]
    fn test_bl() {
        let i = dec().decode_word(0x1000, 0x4800_0001);
        assert_eq!(i.mnemonic, "BL");
        assert!(i.link());
    }

    #[test]
    fn test_beq() {
        let i = dec().decode_word(0x1000, 0x4182_0008);
        assert_eq!(i.mnemonic, "BEQ");
        assert!(!i.link());
    }

    #[test]
    fn test_lwz() {
        let i = dec().decode_word(0x1000, 0x8061_0000);
        assert_eq!(i.mnemonic, "LWZ");
    }

    #[test]
    fn test_stw() {
        let i = dec().decode_word(0x1000, 0x9061_0000);
        assert_eq!(i.mnemonic, "STW");
    }

    #[test]
    fn test_add() {
        let i = dec().decode_word(0x1000, 0x7C63_2214);
        assert_eq!(i.mnemonic, "ADD");
    }

    #[test]
    fn test_mflr() {
        let i = dec().decode_word(0x1000, 0x7C08_02A6);
        assert_eq!(i.mnemonic, "MFLR");
    }

    #[test]
    fn test_sc() {
        let i = dec().decode_word(0x1000, 0x4400_0002);
        assert_eq!(i.mnemonic, "SC");
    }

    #[test]
    fn test_rlwinm() {
        let i = dec().decode_word(0x1000, 0x5465_0800);
        assert_eq!(i.mnemonic, "RLWINM");
    }

    #[test]
    fn test_decode_iter() {
        let code: &[u8] = &[0x38, 0x60, 0x00, 0x01, 0x48, 0x00, 0x00, 0x01];
        let v: Vec<_> = PpcDecoderIter::new(PpcDecoder::new_32(), code, 0x1000).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mnemonic, "LI");
        assert_eq!(v[1].mnemonic, "BL");
    }

    #[test]
    fn test_or() {
        let i = dec().decode_word(0x1000, 0x7C83_2378);
        assert_eq!(i.mnemonic, "OR");
    }

    #[test]
    fn test_primary_and_form() {
        let i = dec().decode_word(0x1000, 0x4800_0000);
        assert_eq!(i.primary.0, 18);
        assert_eq!(i.form, PpcForm::IForm);
    }

    #[test]
    fn test_sync() {
        let i = dec().decode_word(0x1000, 0x7C00_04AC);
        assert_eq!(i.mnemonic, "SYNC");
    }

    // â”€â”€â”€â”€â”€ Edge-case coverage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn decode_iter_empty_stream() {
        assert!(PpcDecoderIter::new(PpcDecoder::new_32(), &[], 0x1000).next().is_none());
    }

    #[test]
    fn decode_iter_truncated_word_does_not_panic() {
        // Three bytes (not enough for a full PPC word).
        let bytes = [0x38u8, 0x60, 0x00];
        // Iterator must terminate cleanly; either 0 instructions or 1 (and skipped trailing bytes).
        assert!(PpcDecoderIter::new(PpcDecoder::new_32(), &bytes, 0x1000).count() <= 1);
    }

    #[test]
    fn decode_word_all_zero_is_valid_form() {
        // All-zero instruction has primary opcode 0 â€” must not panic and must produce something.
        let i = dec().decode_word(0x1000, 0x0000_0000);
        let _ = i.mnemonic;
        assert_eq!(i.primary.0, 0);
    }

    #[test]
    fn decode_word_all_ones_does_not_panic() {
        let i = dec().decode_word(0x1000, 0xFFFF_FFFF);
        let _ = i.mnemonic;
    }

    #[test]
    fn b_branch_target_negative_offset() {
        // 'b -8' (backwards branch): LI=-8 encoded.
        // 0x4B FF FF F8 (primary 18, LI=-8, AA=0, LK=0)
        let i = dec().decode_word(0x1000, 0x4BFF_FFF8);
        assert_eq!(i.mnemonic, "B");
        assert_eq!(i.branch_target, Some(0x0FF8));
    }

    #[test]
    fn bl_link_bit_set() {
        let i = dec().decode_word(0x1000, 0x4800_0005);
        assert_eq!(i.mnemonic, "BL");
        assert!(i.link());
    }

    #[test]
    fn decode_word_deterministic_for_same_input() {
        let a = dec().decode_word(0x1000, 0x3860_0001);
        let b = dec().decode_word(0x1000, 0x3860_0001);
        assert_eq!(a.mnemonic, b.mnemonic);
        assert_eq!(a.primary.0, b.primary.0);
        assert_eq!(a.form, b.form);
    }

    #[test]
    fn decode_iter_advances_by_four_per_step() {
        // Two consecutive LI a3,1 instructions
        let code = [0x38, 0x60, 0x00, 0x01, 0x38, 0x60, 0x00, 0x02];
        let v: Vec<_> = PpcDecoderIter::new(PpcDecoder::new_32(), &code, 0x2000).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mnemonic, "LI");
        assert_eq!(v[1].mnemonic, "LI");
    }
}

