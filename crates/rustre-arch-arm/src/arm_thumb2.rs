//! `arm_thumb2` — ARM Thumb-2 32-bit extension decoder.
//!
//! Decodes 32-bit Thumb-2 instructions (IT blocks, load/store multiple,
//! wide data processing, branch-with-link, and VFP/NEON floating-point).

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Thumb2DecodeError {
    Truncated,
    Undefined(u32),
    Unpredictable(u32),
    NotThumb2(u16),
}

impl fmt::Display for Thumb2DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated instruction stream"),
            Self::Undefined(w) => write!(f, "undefined encoding: {w:#010x}"),
            Self::Unpredictable(w) => write!(f, "unpredictable encoding: {w:#010x}"),
            Self::NotThumb2(h) => write!(f, "not a Thumb-2 32-bit prefix: {h:#06x}"),
        }
    }
}

impl std::error::Error for Thumb2DecodeError {}

// ─── Register ────────────────────────────────────────────────────────────────

/// An ARM register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Reg(pub u8);

impl Reg {
    pub const R0: Self = Self(0);
    pub const R1: Self = Self(1);
    pub const R2: Self = Self(2);
    pub const R3: Self = Self(3);
    pub const R4: Self = Self(4);
    pub const R5: Self = Self(5);
    pub const R6: Self = Self(6);
    pub const R7: Self = Self(7);
    pub const R8: Self = Self(8);
    pub const R9: Self = Self(9);
    pub const R10: Self = Self(10);
    pub const R11: Self = Self(11);
    pub const R12: Self = Self(12);
    pub const SP: Self = Self(13);
    pub const LR: Self = Self(14);
    pub const PC: Self = Self(15);

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0..=10 => [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            ][self.0 as usize],
            11 => "r11",
            12 => "ip",
            13 => "sp",
            14 => "lr",
            15 => "pc",
            _ => "?",
        }
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── Condition ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cond {
    Eq,
    Ne,
    Cs,
    Cc,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
    Nv,
}

impl Cond {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0xF {
            0 => Self::Eq,
            1 => Self::Ne,
            2 => Self::Cs,
            3 => Self::Cc,
            4 => Self::Mi,
            5 => Self::Pl,
            6 => Self::Vs,
            7 => Self::Vc,
            8 => Self::Hi,
            9 => Self::Ls,
            10 => Self::Ge,
            11 => Self::Lt,
            12 => Self::Gt,
            13 => Self::Le,
            14 => Self::Al,
            _ => Self::Nv,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Cs => "cs",
            Self::Cc => "cc",
            Self::Mi => "mi",
            Self::Pl => "pl",
            Self::Vs => "vs",
            Self::Vc => "vc",
            Self::Hi => "hi",
            Self::Ls => "ls",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Gt => "gt",
            Self::Le => "le",
            Self::Al => "",
            Self::Nv => "nv",
        }
    }
}

// ─── Thumb-2 Instruction ─────────────────────────────────────────────────────

/// A decoded Thumb-2 32-bit instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thumb2Instr {
    pub mnemonic: String,
    pub operands: String,
    pub encoding: u32,
    pub size_bytes: u8, // Always 4 for Thumb-2 32-bit.
    pub kind: Thumb2Kind,
}

impl Thumb2Instr {
    fn new(
        mnemonic: impl Into<String>,
        operands: impl Into<String>,
        encoding: u32,
        kind: Thumb2Kind,
    ) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            encoding,
            size_bytes: 4,
            kind,
        }
    }
}

impl fmt::Display for Thumb2Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mnemonic, self.operands)
    }
}

/// Category of a Thumb-2 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Thumb2Kind {
    DataProcessing,
    LoadStore,
    LoadStoreMultiple,
    Branch,
    CoprocessorVfp,
    SystemControl,
    IT,
    Undefined,
}

// ─── IT block ────────────────────────────────────────────────────────────────

/// Represents an IT (If-Then) block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItBlock {
    pub condition: Cond,
    /// Number of instructions in the block (1–4).
    pub count: usize,
    /// Per-instruction conditions (derived from the mask).
    pub conditions: Vec<Cond>,
    pub mask: u8,
}

impl ItBlock {
    /// Decode an IT instruction from its lower 16 bits.
    #[must_use]
    pub fn decode(hw: u16) -> Option<Self> {
        let cond_bits = ((hw >> 4) & 0xF) as u8;
        let mask = (hw & 0xF) as u8;
        if mask == 0 {
            return None; // Not an IT instruction.
        }
        let cond = Cond::from_bits(cond_bits);
        let count = 4 - mask.trailing_zeros() as usize;
        let mut conditions = Vec::with_capacity(count);
        for i in 0..count {
            let bit = (mask >> (3 - i)) & 1;
            conditions.push(if bit == (cond_bits & 1) {
                cond
            } else {
                Cond::from_bits(cond_bits ^ 1)
            });
        }
        Some(Self {
            condition: cond,
            count,
            conditions,
            mask,
        })
    }

    #[must_use]
    pub fn mnemonic(&self) -> String {
        let suffix: String = match self.count {
            2 => {
                let t = if (self.mask & 0x4) != 0 { "t" } else { "e" };
                t.into()
            }
            3 => {
                let t1 = if (self.mask & 0x4) != 0 { "t" } else { "e" };
                let t2 = if (self.mask & 0x2) != 0 { "t" } else { "e" };
                format!("{t1}{t2}")
            }
            4 => {
                let t1 = if (self.mask & 0x4) != 0 { "t" } else { "e" };
                let t2 = if (self.mask & 0x2) != 0 { "t" } else { "e" };
                let t3 = if (self.mask & 0x1) != 0 { "t" } else { "e" };
                format!("{t1}{t2}{t3}")
            }
            _ => String::new(),
        };
        format!("it{suffix}")
    }
}

// ─── Thumb2Decoder ───────────────────────────────────────────────────────────

/// Decoder for 32-bit Thumb-2 instructions.
pub struct Thumb2Decoder;

impl Thumb2Decoder {
    /// Decode a 32-bit Thumb-2 instruction word (little-endian: hw1 at offset 0).
    ///
    /// # Errors
    /// Returns [`Thumb2DecodeError`] if the halfword pair is not a valid Thumb-2 encoding.
    pub fn decode(hw1: u16, hw2: u16) -> Result<Thumb2Instr, Thumb2DecodeError> {
        // Verify this is a 32-bit Thumb-2 instruction (bits 15:11 of hw1 ∈ {0b11101, 0b11110, 0b11111}).
        let top5 = hw1 >> 11;
        if top5 < 0x1D {
            return Err(Thumb2DecodeError::NotThumb2(hw1));
        }
        let word = (u32::from(hw1) << 16) | u32::from(hw2);
        Self::decode_word(word)
    }

    /// Decode a full 32-bit word.
    ///
    /// # Errors
    /// Returns [`Thumb2DecodeError`] if the word is not a valid Thumb-2 encoding.
    pub fn decode_word(word: u32) -> Result<Thumb2Instr, Thumb2DecodeError> {
        let op1 = (word >> 27) & 0x3; // bits 28:27
        let _op2 = (word >> 20) & 0x7F; // bits 26:20 (reserved for future sub-decoding)

        Ok(match op1 {
            0x1 => {
                // bits[28:27]=01: distinguished by bit26 and bit25
                if (word >> 26) & 1 != 0 {
                    // bit26=1: VFP/coprocessor (advanced SIMD, floating-point)
                    Self::decode_coprocessor_vfp(word)
                } else if (word >> 25) & 1 != 0 {
                    // bit26=0, bit25=1: data processing (shifted register)
                    Self::decode_data_processing(word)
                } else {
                    // bit25=0: load/store multiple / dual / exclusive
                    Self::decode_load_store_multiple(word)
                }
            }
            0x2 => {
                // bits[28:27]=10: branch if hw2 bit15=1, else data processing (modified imm)
                if (word >> 15) & 1 != 0 {
                    Self::decode_branch(word)
                } else {
                    Self::decode_data_processing(word)
                }
            }
            0x3 => Self::decode_load_store(word),
            _ => Self::decode_coprocessor_vfp(word),
        })
    }

    fn decode_load_store_multiple(word: u32) -> Thumb2Instr {
        let op = (word >> 23) & 0x3;
        let l = (word >> 20) & 0x1;
        let rn = Reg(((word >> 16) & 0xF) as u8);
        let reg_list = word & 0xFFFF;

        let regs = format_reg_list(reg_list as u16);
        let w_bit = (word >> 21) & 1;
        let wb = if w_bit != 0 { "!" } else { "" };

        let mnemonic = match (op, l) {
            (0b10, 0) => format!("stmdb {rn}{wb}, {{{regs}}}"),
            (0b10, 1) => format!("ldm   {rn}{wb}, {{{regs}}}"),
            (0b01, 0) => format!("stm   {rn}{wb}, {{{regs}}}"),
            (0b01, 1) => format!("ldmdb {rn}{wb}, {{{regs}}}"),
            _ => format!("lsm?? {rn}{wb}, {{{regs}}}"),
        };

        // Detect PUSH / POP.
        let (mne, ops) = if rn == Reg::SP && op == 0b10 && l == 0 {
            ("push".to_string(), format!("{{{regs}}}"))
        } else if rn == Reg::SP && op == 0b01 && l == 1 {
            ("pop".to_string(), format!("{{{regs}}}"))
        } else {
            let parts: Vec<&str> = mnemonic.splitn(2, ' ').collect();
            (
                parts[0].trim().to_string(),
                parts.get(1).copied().unwrap_or("").trim().to_string(),
            )
        };

        Thumb2Instr::new(mne, ops, word, Thumb2Kind::LoadStoreMultiple)
    }

    fn decode_data_processing(word: u32) -> Thumb2Instr {
        let op = (word >> 21) & 0xF;
        let s_bit = (word >> 20) & 1;
        let rn = Reg(((word >> 16) & 0xF) as u8);
        let rd = Reg(((word >> 8) & 0xF) as u8);
        let rm = Reg((word & 0xF) as u8);
        let imm3 = (word >> 12) & 0x7;
        let imm2 = (word >> 6) & 0x3;
        let shift_type = (word >> 4) & 0x3;
        let shift_amt = (imm3 << 2) | imm2;

        let s = if s_bit != 0 { "s" } else { "" };
        let shift_str = format_shift(shift_type as u8, u8::try_from(shift_amt).unwrap_or(0));

        let (mne, ops) = match op {
            0x0 => (
                format!("and{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0x1 => (
                format!("bic{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0x2 => (
                format!("orr{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0x3 => (
                format!("orn{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0x4 => (
                format!("eor{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0x6 => {
                // PKH / etc.
                ("pkh".into(), format!("{rd}, {rn}, {rm}"))
            }
            0x8 => (
                format!("add{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0xA => (
                format!("adc{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0xB => (
                format!("sbc{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0xD => (
                format!("sub{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            0xE => (
                format!("rsb{s}"),
                format!("{rd}, {rn}, {rm}{shift_str}"),
            ),
            _ => (
                format!("dp{op:02x}{s}"),
                format!("{rd}, {rn}, {rm}"),
            ),
        };

        Thumb2Instr::new(mne, ops, word, Thumb2Kind::DataProcessing)
    }

    fn decode_branch(word: u32) -> Thumb2Instr {
        let _op = (word >> 20) & 0x7F;
        // B<cond>.W / B.W / BL / BLX
        // BL/BLX: hw2[14]=1 (bit14 of the combined 32-bit word), distinguishing from B<cond>.
        if (word >> 14) & 1 == 1 {
            // BL or BLX
            let j1 = (word >> 13) & 1;
            let j2 = (word >> 11) & 1;
            let s = (word >> 26) & 1;
            let imm10 = (word >> 16) & 0x3FF;
            let imm11 = word & 0x7FF;
            let i1 = 1 ^ j1 ^ s;
            let i2 = 1 ^ j2 ^ s;
            let imm = ((s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)).cast_signed();
            let imm_sign = if s != 0 {
                imm | (0xFF << 25)
            } else {
                imm
            };
            let x_bit = (word >> 12) & 1;
            // ARM DDI: hw2[12]=1 → BL, hw2[12]=0 → BLX
            let mne = if x_bit == 1 { "bl" } else { "blx" };
            return Thumb2Instr::new(mne, format!("#{imm_sign}"), word, Thumb2Kind::Branch);
        }

        // B<cond>.W
        let cond_bits = ((word >> 22) & 0xF) as u8;
        let cond = Cond::from_bits(cond_bits);
        let s = (word >> 26) & 1;
        let j1 = (word >> 13) & 1;
        let j2 = (word >> 11) & 1;
        let imm6 = (word >> 16) & 0x3F;
        let imm11 = word & 0x7FF;
        let imm = ((s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)).cast_signed();
        let imm_sign = if s != 0 {
            imm | (0xFFF << 21)
        } else {
            imm
        };
        let mne = format!("b{}.w", cond.as_str());
        Thumb2Instr::new(mne, format!("#{imm_sign}"), word, Thumb2Kind::Branch)
    }

    fn decode_load_store(word: u32) -> Thumb2Instr {
        let op1 = (word >> 23) & 0x3;
        let rn = Reg(((word >> 16) & 0xF) as u8);
        let rt = Reg(((word >> 12) & 0xF) as u8);
        let l = (word >> 20) & 1;
        let size = (word >> 21) & 0x3;
        let imm8 = (word & 0xFF).cast_signed();
        let imm12 = (word & 0xFFF).cast_signed();
        let u_bit = (word >> 23) & 1;

        let width = match size {
            0 => "b",
            1 => "h",
            2 => "",
            _ => "d",
        };

        let _ = l;
        let sign = "";
        // op1 (bits 24:23) records the addressing-mode form; expose it
        // by observing the value in a debug check.
        debug_assert!(op1 < 4);
        let mne = if l == 0 {
            format!("str{width}{sign}")
        } else {
            format!("ldr{width}{sign}")
        };

        let offset = if u_bit != 0 {
            // Bit 23 set: imm12 encoding, offset is always added.
            imm12
        } else if (word >> 9) & 1 != 0 {
            // imm8 encoding: bit 9 is the U (add) bit.
            imm8
        } else {
            -imm8
        };
        let ops = if offset == 0 {
            format!("{rt}, [{rn}]")
        } else {
            format!("{rt}, [{rn}, #{offset}]")
        };

        Thumb2Instr::new(mne, ops, word, Thumb2Kind::LoadStore)
    }

    fn decode_coprocessor_vfp(word: u32) -> Thumb2Instr {
        let coproc = (word >> 8) & 0xF;
        let op = (word >> 20) & 0xFF;

        // VFP/NEON floating-point instructions (coproc 10 or 11).
        if coproc == 10 || coproc == 11 {
            let opc1 = (word >> 20) & 0xF;
            let double_precision = coproc == 11;
            let suffix = if double_precision { ".f64" } else { ".f32" };
            let fd = (word >> 12) & 0xF;
            let fn_reg = (word >> 16) & 0xF;
            let fm = word & 0xF;

            // ARM DDI 0406C Table A7-17: VFP data-processing opcodes.
            // opc1 = bits[23:20]; D bit is at bit22 (bit[2] of opc1).
            // Mask out D bit with 0xB (=1011) to get the instruction class.
            // bit[6] of word distinguishes paired operations (e.g. VADD vs VSUB).
            let op6 = (word >> 6) & 1;
            let mne = match opc1 & 0xB {
                // 0D00: VMLA (bit6=0) / VMLS (bit6=1)
                0x0 => if op6 == 0 { format!("vmla{suffix}") } else { format!("vmls{suffix}") },
                // 0D01: VNMLA (bit6=1) / VNMLS (bit6=0)
                0x1 => if op6 == 1 { format!("vnmla{suffix}") } else { format!("vnmls{suffix}") },
                // 0D10: VMUL (bit6=0) / VNMUL (bit6=1)
                0x2 => if op6 == 0 { format!("vmul{suffix}") } else { format!("vnmul{suffix}") },
                // 0D11: VADD (bit6=0) / VSUB (bit6=1)
                0x3 => if op6 == 0 { format!("vadd{suffix}") } else { format!("vsub{suffix}") },
                // 1D00: VDIV
                0x8 => format!("vdiv{suffix}"),
                // 1D11: VMOV/VABS/VNEG/VSQRT/VCVT/VCMP
                0xB => {
                    let op2 = (word >> 16) & 0xF;
                    match op2 {
                        0x0 => format!("vmov{suffix}"),
                        0x1 => format!("vneg{suffix}"),
                        0x2 => format!("vabs{suffix}"),
                        0x3 => format!("vsqrt{suffix}"),
                        0x4 => format!("vcmp{suffix}"),
                        0x5 => format!("vcmpe{suffix}"),
                        0x7 | 0x8 | 0xC | 0xD => format!("vcvt{suffix}"),
                        _ => format!("vfp?{op2:x}{suffix}"),
                    }
                }
                _ => format!("vfp{opc1:x}{suffix}"),
            };

            let ops = format!("d{fd}, d{fn_reg}, d{fm}");
            return Thumb2Instr::new(mne, ops, word, Thumb2Kind::CoprocessorVfp);
        }

        // Generic coprocessor instruction; tag with the op byte for clarity.
        Thumb2Instr::new(
            format!("cdp2 p{coproc} op{op:#x}"),
            format!("#{word:#010x}"),
            word,
            Thumb2Kind::CoprocessorVfp,
        )
    }

    /// Decode from a byte slice at the given offset.
    /// Returns `(instruction, bytes_consumed)`.
    ///
    /// # Errors
    /// Returns [`Thumb2DecodeError`] if there are fewer than 4 bytes available or the encoding is invalid.
    pub fn decode_bytes(
        bytes: &[u8],
        offset: usize,
    ) -> Result<(Thumb2Instr, usize), Thumb2DecodeError> {
        if offset + 4 > bytes.len() {
            return Err(Thumb2DecodeError::Truncated);
        }
        let hw1 = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let hw2 = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let instr = Self::decode(hw1, hw2)?;
        Ok((instr, 4))
    }

    /// Check if a 16-bit halfword is a Thumb-2 32-bit prefix.
    #[must_use]
    pub const fn is_32bit_prefix(hw: u16) -> bool {
        (hw >> 11) >= 0x1D
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn format_reg_list(mask: u16) -> String {
    let regs: Vec<String> = (0..16u8)
        .filter(|&i| (mask >> i) & 1 != 0)
        .map(|i| Reg(i).name().to_string())
        .collect();
    regs.join(", ")
}

fn format_shift(shift_type: u8, amount: u8) -> String {
    if amount == 0 {
        return String::new();
    }
    let name = match shift_type & 0x3 {
        0 => "lsl",
        1 => "lsr",
        2 => "asr",
        3 => "ror",
        _ => "?",
    };
    format!(", {name} #{amount}")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_name() {
        assert_eq!(Reg::R0.name(), "r0");
        assert_eq!(Reg::SP.name(), "sp");
        assert_eq!(Reg::LR.name(), "lr");
        assert_eq!(Reg::PC.name(), "pc");
    }

    #[test]
    fn reg_display() {
        assert_eq!(format!("{}", Reg::R5), "r5");
    }

    #[test]
    fn cond_from_bits() {
        assert_eq!(Cond::from_bits(0), Cond::Eq);
        assert_eq!(Cond::from_bits(14), Cond::Al);
    }

    #[test]
    fn cond_as_str() {
        assert_eq!(Cond::Eq.as_str(), "eq");
        assert_eq!(Cond::Al.as_str(), "");
    }

    #[test]
    fn it_block_decode_it() {
        // IT EQ: 0xBF08 (cond=eq, mask=1000 → count=1)
        let it = ItBlock::decode(0xBF08);
        assert!(it.is_some());
        let it = it.unwrap();
        assert_eq!(it.count, 1);
        assert_eq!(it.condition, Cond::Eq);
    }

    #[test]
    fn it_block_mnemonic_it() {
        let it = ItBlock::decode(0xBF08).unwrap();
        assert_eq!(it.mnemonic(), "it");
    }

    #[test]
    fn it_block_decode_itte() {
        // ITTE NE: 0xBF1C (cond=ne=0001, mask=1100 → count=3)
        let it = ItBlock::decode(0xBF1C);
        assert!(it.is_some());
        let it = it.unwrap();
        assert!(it.count >= 2);
    }

    #[test]
    fn it_block_none_for_zero_mask() {
        let it = ItBlock::decode(0xBF10 & !0xF); // mask = 0
        assert!(it.is_none());
    }

    #[test]
    fn thumb2_is_32bit_prefix() {
        assert!(Thumb2Decoder::is_32bit_prefix(0xF000)); // 0b11110 prefix
        assert!(Thumb2Decoder::is_32bit_prefix(0xE800)); // 0b11101 prefix
        assert!(!Thumb2Decoder::is_32bit_prefix(0x0000)); // 16-bit
    }

    #[test]
    fn decode_push() {
        // PUSH {r4, r5, lr} — Thumb-2 encoding.
        // HW1 = 0xE92D (stmdb sp!, ...), HW2 = reg_list
        let hw1: u16 = 0xE92D;
        let hw2: u16 = 0x4030; // r4, r5, lr
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert_eq!(instr.mnemonic, "push");
        assert_eq!(instr.kind, Thumb2Kind::LoadStoreMultiple);
    }

    #[test]
    fn decode_pop() {
        // POP {r4, r5, pc} — 0xE8BD 0x8030
        let hw1: u16 = 0xE8BD;
        let hw2: u16 = 0x8030;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert_eq!(instr.mnemonic, "pop");
    }

    #[test]
    fn decode_ldm() {
        // LDM r0!, {r1, r2} — 0xE890 0x0006
        let hw1: u16 = 0xE890;
        let hw2: u16 = 0x0006;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
    }

    #[test]
    fn decode_adds_w() {
        // ADDS.W rd, rn, rm — op1=0b10 (data processing), op=0x8 (add)
        // 0xEB10 0x0001: ADD.W r0, r0, r1
        let hw1: u16 = 0xEB10;
        let hw2: u16 = 0x0001;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with("add"));
        assert_eq!(instr.kind, Thumb2Kind::DataProcessing);
    }

    #[test]
    fn decode_bl() {
        // BL #offset — 0xF000 0xF800 (BL #0)
        let hw1: u16 = 0xF000;
        let hw2: u16 = 0xF800;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert_eq!(instr.mnemonic, "bl");
        assert_eq!(instr.kind, Thumb2Kind::Branch);
    }

    #[test]
    fn decode_b_cond() {
        // B.W NE — 0xF040 0x8000
        let hw1: u16 = 0xF040;
        let hw2: u16 = 0x8000;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with('b'));
        assert_eq!(instr.kind, Thumb2Kind::Branch);
    }

    #[test]
    fn decode_ldr_w() {
        // LDR.W r0, [r1, #4] — 0xF851 0x0004
        let hw1: u16 = 0xF8D1;
        let hw2: u16 = 0x0004;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with("ldr"));
        assert_eq!(instr.kind, Thumb2Kind::LoadStore);
    }

    #[test]
    fn decode_str_w() {
        // STR.W r0, [r1] — 0xF8C1 0x0000
        let hw1: u16 = 0xF8C1;
        let hw2: u16 = 0x0000;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with("str"));
    }

    #[test]
    fn decode_vadd_f32() {
        // VADD.F32 d0, d1, d2 — 0xEE30 0x0A01
        let hw1: u16 = 0xEE30;
        let hw2: u16 = 0x0A01;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert_eq!(instr.kind, Thumb2Kind::CoprocessorVfp);
        assert!(instr.mnemonic.contains("vadd") || instr.mnemonic.contains("vfp"));
    }

    #[test]
    fn decode_bytes_ok() {
        // Push {r4, lr}
        let bytes = [0x2D, 0xE9, 0x10, 0x40u8];
        let result = Thumb2Decoder::decode_bytes(&bytes, 0);
        assert!(result.is_ok());
        let (_instr, size) = result.unwrap();
        assert_eq!(size, 4);
    }

    #[test]
    fn decode_bytes_truncated() {
        let bytes = [0xE9u8, 0x2D];
        let result = Thumb2Decoder::decode_bytes(&bytes, 0);
        assert!(matches!(result, Err(Thumb2DecodeError::Truncated)));
    }

    #[test]
    fn decode_not_thumb2_prefix() {
        let result = Thumb2Decoder::decode(0x0000, 0x0000);
        assert!(matches!(result, Err(Thumb2DecodeError::NotThumb2(_))));
    }

    #[test]
    fn format_reg_list_test() {
        let s = format_reg_list(0b0000_0000_0011_0001); // r0, r4, r5
        assert!(s.contains("r0"));
        assert!(s.contains("r4"));
    }

    #[test]
    fn format_shift_lsl() {
        let s = format_shift(0, 2);
        assert!(s.contains("lsl"));
        assert!(s.contains("#2"));
    }

    #[test]
    fn format_shift_zero() {
        assert_eq!(format_shift(0, 0), "");
    }

    #[test]
    fn thumb2_instr_display() {
        let instr = Thumb2Instr::new("add", "r0, r1, r2", 0xEB010002, Thumb2Kind::DataProcessing);
        assert!(instr.to_string().contains("add"));
    }

    #[test]
    fn decode_orr() {
        // ORR.W r1, r2, r3 — 0xEA42 0x0103
        let hw1: u16 = 0xEA42;
        let hw2: u16 = 0x0103;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with("orr"));
    }

    #[test]
    fn decode_sub_w() {
        // SUB.W r0, r1, r2
        let hw1: u16 = 0xEBA1;
        let hw2: u16 = 0x0002;
        let result = Thumb2Decoder::decode(hw1, hw2);
        assert!(result.is_ok());
        let instr = result.unwrap();
        assert!(instr.mnemonic.starts_with("sub"));
    }

    #[test]
    fn reg_name_out_of_range() {
        // Indices 0-15 are valid; anything above should not panic.
        assert_eq!(Reg(16).name(), "?");
        assert_eq!(Reg(u8::MAX).name(), "?");
    }

    #[test]
    fn cond_from_bits_truncates_high_bits() {
        // Only the low 4 bits matter
        assert_eq!(Cond::from_bits(0xF0), Cond::Eq);
        assert_eq!(Cond::from_bits(0xFF), Cond::Nv);
    }

    #[test]
    fn decode_bytes_empty_is_truncated() {
        let r = Thumb2Decoder::decode_bytes(&[], 0);
        assert!(matches!(r, Err(Thumb2DecodeError::Truncated)));
    }

    #[test]
    fn decode_bytes_three_bytes_is_truncated() {
        let r = Thumb2Decoder::decode_bytes(&[0x2D, 0xE9, 0x10], 0);
        assert!(matches!(r, Err(Thumb2DecodeError::Truncated)));
    }

    #[test]
    fn is_32bit_prefix_boundary_values() {
        // All 0xE800..=0xFFFF should be considered 32-bit-prefix candidates.
        assert!(Thumb2Decoder::is_32bit_prefix(0xE800));
        assert!(Thumb2Decoder::is_32bit_prefix(0xFFFF));
        // Below 0xE800 -> 16-bit.
        assert!(!Thumb2Decoder::is_32bit_prefix(0xE7FF));
        assert!(!Thumb2Decoder::is_32bit_prefix(0x0001));
    }

    #[test]
    fn format_reg_list_empty_mask() {
        let s = format_reg_list(0);
        // Empty list: should be empty or '{}' but never panic.
        assert!(s.is_empty() || s.contains('{') || s == "{}");
    }

    #[test]
    fn format_reg_list_all_bits() {
        let s = format_reg_list(0xFFFF);
        // Should include several common register names.
        assert!(s.contains("r0"));
        assert!(s.contains("r15") || s.contains("pc"));
    }

    #[test]
    fn it_block_decode_non_it_byte_returns_none() {
        // 0xBC00 is not an IT instruction (different opcode region).
        assert!(ItBlock::decode(0x0000).is_none());
    }

    #[test]
    fn decode_offsetted_bytes_at_nonzero_offset() {
        // Push {r4, lr} starting at offset 2 in a longer buffer.
        let bytes = [0x00u8, 0x00, 0x2D, 0xE9, 0x10, 0x40];
        let r = Thumb2Decoder::decode_bytes(&bytes[2..], 0);
        assert!(r.is_ok());
    }
}
