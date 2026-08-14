//! MSP430X extended instruction set — 20-bit address space support.
//!
//! The MSP430X extension (introduced with MSP430F5xx/6xx families) adds:
//!
//! * A 20-bit program counter and stack pointer, enabling >64 KiB addressing.
//! * **Extended format I** instructions: `MOVX`, `ADDX`, `SUBX`, `CMPX`,
//!   `ANDX`, `ORX`, `XORX`, `BICX`, `BISX`, `DADC`, `DADD`, `POPC`, `PUSHX`.
//! * **Extended format II** instructions: `RRUX`, `RRCX`, `SWPBX`, `SXTX`,
//!   `PUSHX`, `CALLX`, `POPX`.
//! * **Address instructions** (20-bit operands, no bw bit): `MOVA`, `CMPA`,
//!   `ADDA`, `SUBA`, `ANDA`, `ORA`, `XORA`, `BITA`, `CLRA`, `TSTA`.
//! * **Rotate/shift instructions**: `RRCM`, `RRUM`, `RLAM`, `RRAM` (with
//!   repeat count 1–4 encoded in the instruction word).
//! * **Push/pop multiple**: `PUSHM.A/W/B`, `POPM.A/W/B`.
//! * **Call/return**: `CALLA`, `RETA`.
//! * **Branch**: `BRA` (20-bit branch, replaces `BR` which only reaches 64 KiB).
//! * **Repeat prefix**: `RPTC` / `RPTZ` (repeat next instruction n times).

use std::fmt;

// ── Types and enums ───────────────────────────────────────────────────────────

/// Operand size for MSP430X instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpSize {
    /// 8-bit byte operation (`.B`).
    Byte,
    /// 16-bit word operation (`.W`).
    Word,
    /// 20-bit address-word operation (`.A`).
    Addr,
}

impl fmt::Display for OpSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte => f.write_str(".B"),
            Self::Word => f.write_str(".W"),
            Self::Addr => f.write_str(".A"),
        }
    }
}

impl OpSize {
    /// Width in bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Byte => 8,
            Self::Word => 16,
            Self::Addr => 20,
        }
    }

    /// Width in bytes (rounded up).
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Addr => 4, // 20-bit values stored in 32-bit cells
        }
    }

    /// Mask for the value.
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
            Self::Addr => 0x000F_FFFF,
        }
    }
}

/// MSP430(X) addressing modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrMode {
    /// Register direct: Rn.
    Register(u8),
    /// Indexed: X(Rn) — 16-bit or 20-bit offset follows.
    Indexed { reg: u8, offset: i32 },
    /// Symbolic: ADDR (PC-relative, encoded as X(PC)).
    Symbolic(u32),
    /// Absolute: &ADDR.
    Absolute(u32),
    /// Indirect register: @Rn.
    Indirect(u8),
    /// Indirect auto-increment: @Rn+.
    IndirectAutoInc(u8),
    /// Immediate: #N (encoded as @PC+).
    Immediate(i32),
}

impl fmt::Display for AddrMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "R{r}"),
            Self::Indexed { reg, offset } => write!(f, "{offset}(R{reg})"),
            Self::Symbolic(a) => write!(f, "0x{a:04X}"),
            Self::Absolute(a) => write!(f, "&0x{a:04X}"),
            Self::Indirect(r) => write!(f, "@R{r}"),
            Self::IndirectAutoInc(r) => write!(f, "@R{r}+"),
            Self::Immediate(v) => write!(f, "#{v}"),
        }
    }
}

/// A decoded MSP430X instruction.
#[derive(Debug, Clone)]
pub struct Msp430xInsn {
    /// Mnemonic string, e.g. `"MOVA"`, `"PUSHM.A"`, `"RRCM.W"`.
    pub mnemonic: String,
    /// Source operand (None for single-operand instructions).
    pub src: Option<AddrMode>,
    /// Destination operand.
    pub dst: AddrMode,
    /// Operand size.
    pub size: OpSize,
    /// Total byte length of this instruction (including extension words).
    pub length: usize,
    /// True if this is an MSP430X-exclusive instruction (not in base MSP430).
    pub is_extended: bool,
}

impl fmt::Display for Msp430xInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic)?;
        if let Some(ref src) = self.src {
            write!(f, " {src},{}", self.dst)?;
        } else {
            write!(f, " {}", self.dst)?;
        }
        Ok(())
    }
}

// ── Extension word format ─────────────────────────────────────────────────────

/// MSP430X extension word (always the *first* word of an extended instruction).
///
/// ```text
/// Bit:  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
///        1   1   0   0  ZC   #   AL  SRC3  ──── DST ───  ────── SRC ──
/// ```
///
/// * Bits 15–12: `0b1100` — identifies this as an extension word.
/// * Bit 11 (`ZC`): if set, the carry flag is not affected by the repeat count.
/// * Bit 10 (`#`): if set, the repeat count follows in bits 3–0 (immediate);
///                 if clear, a register number in bits 3–0 holds the count.
/// * Bit 9 (`AL`): `.A` (address) extension when set; otherwise `.W`/`.B` from
///                 the base instruction's BW bit.
/// * Bits 8, 7–4: High nibble of source and destination addresses for 20-bit modes.
#[derive(Debug, Clone, Copy)]
pub struct ExtWord(pub u16);

impl ExtWord {
    /// Verify the extension word signature (bits 15:12 == `0b0001_1000` pattern).
    #[must_use]
    pub const fn is_valid(word: u16) -> bool {
        // Extension words for format I/II have 0001_1xxx_xxxx_xxxx pattern.
        (word >> 12) == 0b0001
    }

    /// Zero-Carry flag: if set, carry is not propagated from the repeat count.
    #[must_use]
    pub const fn zero_carry(self) -> bool {
        (self.0 >> 8) & 1 == 1
    }

    /// True if the repeat count is an immediate value (bits 3–0).
    #[must_use]
    pub const fn repeat_is_imm(self) -> bool {
        (self.0 >> 7) & 1 == 1
    }

    /// `.A` extension: instruction operates on 20-bit address words.
    #[must_use]
    pub const fn al_bit(self) -> bool {
        (self.0 >> 6) & 1 == 1
    }

    /// High 4 bits of the destination address (bits 19–16).
    #[must_use]
    pub const fn dst_high(self) -> u8 {
        ((self.0 >> 4) & 0xF) as u8
    }

    /// High 4 bits of the source address (bits 19–16).
    #[must_use]
    pub const fn src_high(self) -> u8 {
        (self.0 & 0xF) as u8
    }

    /// Repeat count (1–16 if immediate, register index if not).
    #[must_use]
    pub const fn repeat_count(self) -> u8 {
        let raw = (self.0 & 0xF) as u8;
        if self.repeat_is_imm() { raw + 1 } else { raw }
    }
}

// ── Address instruction decoder ───────────────────────────────────────────────

/// Address instructions: 20-bit operand, no BW bit, single extension word not used.
///
/// Encoding: bits 15–12 = `0b0000`, bits 11–8 = opcode variant, bits 7–4 = Rsrc,
/// bits 3–0 = Rdst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrOp {
    Mova,
    Cmpa,
    Adda,
    Suba,
    Anda,  // only in some variants
    Ora,
    Xora,
    Bita,
    Clra,  // pseudo: MOVA #0, Rdst
    Tsta,  // pseudo: CMPA #0, Rsrc
}

impl fmt::Display for AddrOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Mova => "MOVA",
            Self::Cmpa => "CMPA",
            Self::Adda => "ADDA",
            Self::Suba => "SUBA",
            Self::Anda => "ANDA",
            Self::Ora  => "ORA",
            Self::Xora => "XORA",
            Self::Bita => "BITA",
            Self::Clra => "CLRA",
            Self::Tsta => "TSTA",
        };
        f.write_str(s)
    }
}

/// Try to decode an address instruction from a 16-bit word.
///
/// Returns `Some((op, src_mode, dst_reg))` on success.
#[must_use]
pub fn decode_addr_instr(word: u16, pc: u32, extra: Option<u32>) -> Option<Msp430xInsn> {
    // Address instructions have bit pattern 0000_xxxx.
    if word >> 12 != 0b0000 {
        return None;
    }

    let op_field = (word >> 8) & 0xF;
    let src_reg  = ((word >> 4) & 0xF) as u8;
    let dst_reg  = (word & 0xF) as u8;

    let (op, src, dst, len) = match op_field {
        // 0b0000: MOVA #imm20, Rdst — immediate is in bits 19–0 spread over extra.
        0x0 => {
            let imm20 = (((u32::from(word) >> 4) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Mova,
             Some(AddrMode::Immediate(imm20 as i32)),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b0001: MOVA z16(Rsrc), Rdst
        0x1 => {
            let offset = i32::from(extra? as i16);
            (AddrOp::Mova,
             Some(AddrMode::Indexed { reg: src_reg, offset }),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b0010: MOVA &abs20, Rdst
        0x2 => {
            let abs = ((u32::from(word) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Mova,
             Some(AddrMode::Absolute(abs)),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b0011: MOVA @Rsrc, Rdst
        0x3 => {
            (AddrOp::Mova,
             Some(AddrMode::Indirect(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b0100: MOVA @Rsrc+, Rdst
        0x4 => {
            (AddrOp::Mova,
             Some(AddrMode::IndirectAutoInc(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b0101: CMPA #imm20, Rdst
        0x5 => {
            let imm20 = (((u32::from(word) >> 4) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Cmpa,
             Some(AddrMode::Immediate(imm20 as i32)),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b0110: ADDA #imm20, Rdst
        0x6 => {
            let imm20 = (((u32::from(word) >> 4) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Adda,
             Some(AddrMode::Immediate(imm20 as i32)),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b0111: SUBA #imm20, Rdst
        0x7 => {
            let imm20 = (((u32::from(word) >> 4) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Suba,
             Some(AddrMode::Immediate(imm20 as i32)),
             AddrMode::Register(dst_reg),
             4)
        }
        // 0b1000: MOVA Rsrc, Rdst
        0x8 => {
            (AddrOp::Mova,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b1001: CMPA Rsrc, Rdst
        0x9 => {
            (AddrOp::Cmpa,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b1010: ADDA Rsrc, Rdst
        0xA => {
            (AddrOp::Adda,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b1011: SUBA Rsrc, Rdst
        0xB => {
            (AddrOp::Suba,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Register(dst_reg),
             2)
        }
        // 0b1100: MOVA Rsrc, z16(Rdst)
        0xC => {
            let offset = i32::from(extra? as i16);
            (AddrOp::Mova,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Indexed { reg: dst_reg, offset },
             4)
        }
        // 0b1101: MOVA Rsrc, &abs20
        0xD => {
            let abs = ((u32::from(word) & 0xF) << 16) | (extra? & 0xFFFF);
            (AddrOp::Mova,
             Some(AddrMode::Register(src_reg)),
             AddrMode::Absolute(abs),
             4)
        }
        _ => return None,
    };

    let _ = pc;
    Some(Msp430xInsn {
        mnemonic: op.to_string(),
        src,
        dst,
        size: OpSize::Addr,
        length: len,
        is_extended: true,
    })
}

// ── Rotate/shift instructions ─────────────────────────────────────────────────

/// MSP430X rotate/shift multi-bit instructions.
///
/// Encoding (bits 15–8): `0000_0RRR` where RRR is the rotate type.
/// Bits 7–6: repeat count - 1 (0–3 → 1–4 rotations).
/// Bits 5–4: `.A`/`.W`/`.B` encoding.
/// Bits 3–0: destination register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateOp {
    /// Rotate right through carry (RRCM).
    Rrcm,
    /// Rotate right unsigned (no carry, RRUM).
    Rrum,
    /// Rotate left arithmetically (left shift, RLAM).
    Rlam,
    /// Rotate right arithmetically (arithmetic shift right, RRAM).
    Rram,
}

impl fmt::Display for RotateOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rrcm => "RRCM",
            Self::Rrum => "RRUM",
            Self::Rlam => "RLAM",
            Self::Rram => "RRAM",
        })
    }
}

/// Decoded rotate/shift instruction.
#[derive(Debug, Clone)]
pub struct RotateInsn {
    pub op: RotateOp,
    pub size: OpSize,
    /// Repeat count (1–4).
    pub count: u8,
    /// Destination register (0–15).
    pub dst_reg: u8,
}

impl fmt::Display for RotateInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{} #{},{}", self.op, self.size, self.count, AddrMode::Register(self.dst_reg))
    }
}

/// Try to decode a rotate instruction.  These are 16-bit, no extension word.
///
/// Pattern: `0000 0RRR AL nn DDDD` (bits 15–0).
#[must_use]
pub const fn decode_rotate(word: u16) -> Option<RotateInsn> {
    // Bits 15–11 must be 00000.
    if word >> 11 != 0 { return None; }
    let op_field = (word >> 8) & 0x7;
    let op = match op_field {
        0b000 => RotateOp::Rrcm,
        0b001 => RotateOp::Rrum,
        0b010 => RotateOp::Rlam,
        0b011 => RotateOp::Rram,
        _ => return None,
    };
    let al = (word >> 7) & 1 != 0;
    let nn = ((word >> 4) & 0x3) as u8;
    let dst_reg = (word & 0xF) as u8;
    let size = if al { OpSize::Addr } else { OpSize::Word };
    Some(RotateInsn { op, size, count: nn + 1, dst_reg })
}

// ── PUSHM / POPM ─────────────────────────────────────────────────────────────

/// PUSHM and POPM instruction.
///
/// `PUSHM.A #n, Rdst` pushes registers Rdst down to Rdst-(n-1) in one go.
/// `POPM.A  #n, Rdst` pops from the stack into Rdst-(n-1) up to Rdst.
///
/// Encoding: `0000 01SZ n-1 DDDD`
/// * S=0: POPM, S=1: PUSHM.
/// * Z=0: `.W`, Z=1: `.A`.
/// * n-1: count minus one (0–15).
/// * DDDD: highest register.
#[derive(Debug, Clone)]
pub struct PushPopMultiple {
    pub is_push: bool,
    pub size: OpSize,
    /// Number of registers (1–16).
    pub count: u8,
    /// Highest register in the range.
    pub top_reg: u8,
}

impl PushPopMultiple {
    /// List of registers affected, from highest to lowest (push order).
    #[must_use]
    pub fn register_list(&self) -> Vec<u8> {
        let top = self.top_reg as i8;
        (0..self.count as i8)
            .map(|i| (top - i) as u8)
            .collect()
    }
}

impl fmt::Display for PushPopMultiple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = if self.is_push { "PUSHM" } else { "POPM" };
        write!(f, "{}{} #{},R{}", op, self.size, self.count, self.top_reg)
    }
}

/// Try to decode a PUSHM/POPM instruction.
#[must_use]
pub const fn decode_pushm_popm(word: u16) -> Option<PushPopMultiple> {
    // Bits 15–10: 000101 — the ISA puts PUSHM/POPM at 0x1400..=0x17FF.
    //
    // All three fields below were previously inverted or misplaced, so this
    // decoder never fired on a real PUSHM/POPM and would have mislabelled the
    // 0x0400..=0x07FF range instead.  The encoding is pinned by the green tests
    // in `tests/blitz2.rs`, which decode concrete words:
    //   0x1404 = PUSHM.A #1,R4   → bit 9 = 0 is PUSHM, bit 8 = 0 is the .A form
    //   0x1604 = POPM.A  #1,R4   → bit 9 = 1 is POPM
    //   0x15F9 = PUSHM.W #16,R9  → bit 8 = 1 is the .W form
    // `lib.rs::decode_pushm_popm` is the corrected twin and agrees with them;
    // its comment already flagged this copy as still wrong.
    if word >> 10 != 0b000101 { return None; }
    let is_push = (word >> 9) & 1 == 0;
    let addr    = (word >> 8) & 1 == 0;
    let count   = (((word >> 4) & 0xF) as u8) + 1;
    let top_reg = (word & 0xF) as u8;
    let size    = if addr { OpSize::Addr } else { OpSize::Word };
    Some(PushPopMultiple { is_push, size, count, top_reg })
}

// ── CALLA / RETA ──────────────────────────────────────────────────────────────

/// CALLA (20-bit call) addressing mode encoded in bits 7–4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallaMode {
    /// `CALLA Rdst` — call via register (bits 7–4 = 0b0100, dst in bits 3–0).
    Register(u8),
    /// `CALLA X(Rdst)` — call via indexed mode (4–7 = 0b0101).
    Indexed { reg: u8, offset: i32 },
    /// `CALLA @Rdst` — call via indirect (4–7 = 0b0110).
    Indirect(u8),
    /// `CALLA @Rdst+` — call via indirect auto-increment (4–7 = 0b0111).
    IndirectAutoInc(u8),
    /// `CALLA &abs20` — call via absolute 20-bit address.
    Absolute(u32),
    /// `CALLA EDE` — call via symbolic (PC-relative 20-bit).
    Symbolic(u32),
    /// `CALLA #imm20` — call via immediate 20-bit value.
    Immediate(u32),
}

impl fmt::Display for CallaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "R{r}"),
            Self::Indexed { reg, offset } => write!(f, "{offset}(R{reg})"),
            Self::Indirect(r) => write!(f, "@R{r}"),
            Self::IndirectAutoInc(r) => write!(f, "@R{r}+"),
            Self::Absolute(a) => write!(f, "&0x{a:05X}"),
            Self::Symbolic(a) => write!(f, "0x{a:05X}"),
            Self::Immediate(v) => write!(f, "#0x{v:05X}"),
        }
    }
}

/// Decoded CALLA instruction.
#[derive(Debug, Clone)]
pub struct CallaInsn {
    pub mode: CallaMode,
    /// Total instruction length in bytes.
    pub length: usize,
}

impl fmt::Display for CallaInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CALLA {}", self.mode)
    }
}

/// Try to decode a CALLA instruction.
///
/// First word: `0001 0011 xxxx yyyy`
/// Bits 15–8: `0x13` identifies CALLA.
#[must_use]
pub fn decode_calla(word: u16, pc: u32, extra: Option<u32>) -> Option<CallaInsn> {
    if word >> 8 != 0x13 { return None; }
    let mode_field = (word >> 4) & 0xF;
    let reg        = (word & 0xF) as u8;

    let (mode, length) = match mode_field {
        0x4 => (CallaMode::Register(reg), 2),
        0x5 => {
            let off = i32::from(extra? as i16);
            (CallaMode::Indexed { reg, offset: off }, 4)
        }
        0x6 => (CallaMode::Indirect(reg), 2),
        0x7 => (CallaMode::IndirectAutoInc(reg), 2),
        0x8 => {
            // Absolute: high 4 bits in word bits 3–0, low 16 in next word.
            let abs = (u32::from(reg) << 16) | (extra? & 0xFFFF);
            (CallaMode::Absolute(abs), 4)
        }
        0x9 => {
            // Symbolic: PC-relative.
            let rel = i32::from(extra? as i16);
            let target = (i64::from(pc) + i64::from(rel) + 4) as u32 & 0xFFFFF;
            (CallaMode::Symbolic(target), 4)
        }
        0xB => {
            // Immediate.
            let imm = (u32::from(reg) << 16) | (extra? & 0xFFFF);
            (CallaMode::Immediate(imm), 4)
        }
        _ => return None,
    };

    Some(CallaInsn { mode, length })
}

/// RETA — 20-bit return.  Single opcode: `0001 0011 0000 0000` = 0x1300.
#[must_use]
pub const fn is_reta(word: u16) -> bool {
    word == 0x1300
}

// ── BRA (20-bit branch) ───────────────────────────────────────────────────────

/// BRA — branch to 20-bit address.
/// Encoded as `MOVA #imm20, PC` which is the address instruction form 0x0000.
/// Alternatively `MOV #imm, PC` which only reaches 16-bit space.
#[derive(Debug, Clone)]
pub struct BraInsn {
    pub target: BraTarget,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BraTarget {
    Immediate(u32),
    Register(u8),
    Indirect(u8),
    IndirectAutoInc(u8),
    Indexed { reg: u8, offset: i32 },
    Absolute(u32),
    Symbolic(u32),
}

impl fmt::Display for BraTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate(a) => write!(f, "#0x{a:05X}"),
            Self::Register(r) => write!(f, "R{r}"),
            Self::Indirect(r) => write!(f, "@R{r}"),
            Self::IndirectAutoInc(r) => write!(f, "@R{r}+"),
            Self::Indexed { reg, offset } => write!(f, "{offset}(R{reg})"),
            Self::Absolute(a) => write!(f, "&0x{a:05X}"),
            Self::Symbolic(a) => write!(f, "0x{a:05X}"),
        }
    }
}

impl fmt::Display for BraInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BRA {}", self.target)
    }
}

/// Try to decode BRA.  BRA is `MOVA #imm20, PC` = address instruction with
/// `dst_reg` = 0 (PC) and op = MOVA from immediate.
#[must_use]
pub fn decode_bra(word: u16, pc: u32, extra: Option<u32>) -> Option<BraInsn> {
    // MOVA #imm20, Rdst where Rdst = 0 (PC).
    if let Some(insn) = decode_addr_instr(word, pc, extra)
        && insn.mnemonic == "MOVA" && insn.dst == AddrMode::Register(0)
            && let Some(AddrMode::Immediate(v)) = insn.src {
                return Some(BraInsn {
                    target: BraTarget::Immediate(v as u32 & 0xFFFFF),
                    length: insn.length,
                });
            }
    None
}

// ── Extended format I decoder ─────────────────────────────────────────────────

/// Extended Format I base opcodes (same as MSP430 Format I but with extension word).
static EXT_FORMAT_I_OPS: &[(&str, u8)] = &[
    ("MOVX",  0x4),
    ("ADDX",  0x5),
    ("ADDCX", 0x6),
    ("SUBX",  0x7),
    ("SUBCX", 0x8),
    ("CMPX",  0x9),
    ("DADDX", 0xA),
    ("BITX",  0xB),
    ("BICX",  0xC),
    ("BISX",  0xD),
    ("XORX",  0xE),
    ("ANDX",  0xF),
];

/// Decode an extended Format I instruction given the extension word and base word.
///
/// `ext_word` — the extension word (must have bits 15:12 == 0b0001).
/// `base_word` — the standard MSP430 Format I opcode word.
/// `extra_src` — optional additional word for extended source addressing.
/// `extra_dst` — optional additional word for extended destination addressing.
#[must_use]
pub fn decode_ext_format_i(
    ext_word: u16,
    base_word: u16,
    extra_src: Option<u16>,
    extra_dst: Option<u16>,
) -> Option<Msp430xInsn> {
    if (ext_word >> 12) != 0b0001 { return None; }

    let op_field = (base_word >> 12) as u8;
    let op_name = EXT_FORMAT_I_OPS.iter()
        .find(|&&(_, code)| code == op_field)
        .map(|&(name, _)| name)?;

    let al = (ext_word >> 6) & 1 != 0;
    let bw = (base_word >> 6) & 1 != 0;
    let size = if al { OpSize::Addr } else if bw { OpSize::Byte } else { OpSize::Word };

    let src_reg  = ((base_word >> 8) & 0xF) as u8;
    let dst_reg  = (base_word & 0xF) as u8;
    let as_field = (base_word >> 4) & 0x3;
    let ad_field = (base_word >> 7) & 0x1;

    let src_high = u32::from(ext_word & 0xF);
    let dst_high = u32::from((ext_word >> 4) & 0xF);

    let src = decode_operand(src_reg, as_field as u8, extra_src, src_high)?;
    let dst = decode_operand(dst_reg, (ad_field | 0b100) as u8, extra_dst, dst_high)?;

    Some(Msp430xInsn {
        mnemonic: op_name.to_string(),
        src: Some(src),
        dst,
        size,
        length: 2 + 2
            + if extra_src.is_some() { 2 } else { 0 }
            + if extra_dst.is_some() { 2 } else { 0 },
        is_extended: true,
    })
}

/// Decode a single operand from register, addressing mode field, optional extra
/// word, and the high 4-bit extension for 20-bit addresses.
fn decode_operand(reg: u8, as_field: u8, extra: Option<u16>, high: u32) -> Option<AddrMode> {
    // as_field bit 2 indicates dest mode (0=register/indexed, 1=register).
    let is_dst = as_field & 0b100 != 0;
    let as_actual = as_field & 0b11;

    match (reg, as_actual) {
        // Constant generator shortcuts (R2/R3 with certain As values).
        (2, 0b00) if is_dst => Some(AddrMode::Register(2)),
        (2, 0b01) => Some(AddrMode::Immediate(extra.map(|e| {
            let low = u32::from(e);
            ((high << 16) | low) as i32
        })?)),
        (2, 0b10) => Some(AddrMode::Immediate(4)),
        (2, 0b11) => Some(AddrMode::Immediate(8)),
        (3, 0b00) => Some(AddrMode::Immediate(0)),
        (3, 0b01) => Some(AddrMode::Immediate(1)),
        (3, 0b10) => Some(AddrMode::Immediate(2)),
        (3, 0b11) => Some(AddrMode::Immediate(-1)),
        // PC-relative (R0, As=01).
        (0, 0b01) => {
            let low = u32::from(extra?);
            let addr = (high << 16) | low;
            Some(AddrMode::Symbolic(addr))
        }
        // General indexed.
        (_, 0b01) => {
            let low = i32::from(extra? as i16);
            let offset = if high != 0 { ((high << 16) as i32) | (u32::from(extra?) as i32) } else { low };
            Some(AddrMode::Indexed { reg, offset })
        }
        // Register direct.
        (_, 0b00) => Some(AddrMode::Register(reg)),
        // Indirect.
        (_, 0b10) => Some(AddrMode::Indirect(reg)),
        // Indirect auto-increment / immediate.
        (0, 0b11) => {
            let low = u32::from(extra?);
            let imm = ((high << 16) | low) as i32;
            Some(AddrMode::Immediate(imm))
        }
        (_, 0b11) => Some(AddrMode::IndirectAutoInc(reg)),
        _ => None,
    }
}

// ── Linear disassembler ───────────────────────────────────────────────────────

/// Disassemble a buffer of MSP430X code starting at `base_addr`.
///
/// Returns a `Vec` of `(address, text)` pairs.
#[must_use]
pub fn disassemble_msp430x(buf: &[u8], base_addr: u32) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let mut i = 0usize;
    let mut pc = base_addr;

    while i + 1 < buf.len() {
        let word = u16::from_le_bytes([buf[i], buf[i + 1]]);
        let extra1 = if i + 3 < buf.len() {
            Some(u32::from(u16::from_le_bytes([buf[i + 2], buf[i + 3]])))
        } else {
            None
        };

        // Try RETA.
        if is_reta(word) {
            result.push((pc, "RETA".to_string()));
            i += 2; pc += 2;
            continue;
        }

        // Try PUSHM/POPM.
        if let Some(pp) = decode_pushm_popm(word) {
            result.push((pc, pp.to_string()));
            i += 2; pc += 2;
            continue;
        }

        // Try rotate instructions.
        if let Some(rot) = decode_rotate(word) {
            result.push((pc, rot.to_string()));
            i += 2; pc += 2;
            continue;
        }

        // Try BRA.
        if let Some(bra) = decode_bra(word, pc, extra1) {
            let len = bra.length;
            result.push((pc, bra.to_string()));
            i += len; pc += len as u32;
            continue;
        }

        // Try CALLA.
        if let Some(calla) = decode_calla(word, pc, extra1) {
            let len = calla.length;
            result.push((pc, calla.to_string()));
            i += len; pc += len as u32;
            continue;
        }

        // Try address instruction.
        if let Some(addr_insn) = decode_addr_instr(word, pc, extra1) {
            let len = addr_insn.length;
            result.push((pc, addr_insn.to_string()));
            i += len; pc += len as u32;
            continue;
        }

        // Fall back: emit hex word.
        result.push((pc, format!(".word 0x{word:04X}")));
        i += 2; pc += 2;
    }

    result
}

// ── 20-bit address space memory region map ───────────────────────────────────

/// Canonical MSP430X memory regions for a 1-MB address space device
/// (e.g., MSP430F5529).
pub const MSP430X_REGIONS: &[(&str, u32, u32)] = &[
    ("Special Function Registers",     0x0000_0000, 0x0000_00FF),
    ("8-bit Peripherals",              0x0000_0100, 0x0000_01FF),
    ("16-bit Peripherals",             0x0000_0200, 0x0000_09FF),
    ("32-bit Peripherals (BSL area)",  0x0000_0A00, 0x0000_0FFF),
    ("SRAM (32 KB)",                   0x0000_1C00, 0x0000_9BFF),
    ("Flash Info Segments",            0x0001_8000, 0x0001_81FF),
    ("BSL Flash",                      0x0001_0000, 0x0001_7FFF),
    ("Main Flash (128 KB)",            0x0004_4000, 0x0005_FFFF),
    ("USB RAM",                        0x0001_9000, 0x0001_95FF),
    ("Interrupt Vector Table",         0x0000_FF80, 0x0000_FFFF),
    ("Upper Flash (512 KB, extended)", 0x0006_0000, 0x000D_FFFF),
];

/// Return the memory region name for a 20-bit MSP430X address.
#[must_use]
pub fn msp430x_region(addr: u32) -> Option<&'static str> {
    for &(name, start, end) in MSP430X_REGIONS {
        if addr >= start && addr <= end {
            return Some(name);
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_mova_reg_to_reg() {
        // MOVA R5,R6: op=0x8 → word = 0000_1000_0101_0110 = 0x0856
        let word: u16 = 0x0856;
        let insn = decode_addr_instr(word, 0, None).unwrap();
        assert_eq!(insn.mnemonic, "MOVA");
        assert_eq!(insn.size, OpSize::Addr);
        assert_eq!(insn.length, 2);
    }

    #[test]
    fn decode_rrcm_word_3() {
        // RRCM.W #3, R4: op=RRCM(000), al=0, nn=2 (→count=3), dst=4
        // word = 0000_0000_0_0_10_0100 = 0x0024
        let word: u16 = 0x0024;
        let rot = decode_rotate(word).unwrap();
        assert_eq!(rot.op, RotateOp::Rrcm);
        assert_eq!(rot.count, 3);
        assert_eq!(rot.dst_reg, 4);
        assert_eq!(rot.size, OpSize::Word);
    }

    #[test]
    fn decode_pushm_a() {
        // PUSHM.A #2,R10: 000101_0_0_0001_1010 = 0x141A
        // opcode=000101, bit9=0 → PUSHM, bit8=0 → .A, count-1=1 → count=2, top=10
        //
        // This test previously used 0x071A, which encodes the same fields the
        // old (wrong) decoder expected — the test carried the same mistake as
        // the code, so neither could reveal the other.  The word here matches
        // the ISA and the green cases in `tests/blitz2.rs`.
        let word: u16 = 0x141A;
        let pp = decode_pushm_popm(word).unwrap();
        assert!(pp.is_push);
        assert_eq!(pp.size, OpSize::Addr);
        assert_eq!(pp.count, 2);
        assert_eq!(pp.top_reg, 10);
        let regs = pp.register_list();
        assert_eq!(regs, vec![10, 9]);
    }

    #[test]
    fn is_reta_recognizes_opcode() {
        assert!(is_reta(0x1300));
        assert!(!is_reta(0x1301));
    }

    #[test]
    fn decode_calla_register() {
        // CALLA R12: byte 0x13 in high, mode=4, reg=12 → 0x134C
        let word: u16 = 0x134C;
        let calla = decode_calla(word, 0, None).unwrap();
        assert!(matches!(calla.mode, CallaMode::Register(12)));
        assert_eq!(calla.length, 2);
    }

    #[test]
    fn msp430x_region_flash() {
        assert_eq!(msp430x_region(0x0004_4000), Some("Main Flash (128 KB)"));
    }

    #[test]
    fn disassemble_simple_sequence() {
        // RETA (0x1300) followed by MOVA R5,R6 (0x0856).
        let buf: &[u8] = &[0x00, 0x13, 0x56, 0x08];
        let dis = disassemble_msp430x(buf, 0xF000);
        assert_eq!(dis[0], (0xF000, "RETA".to_string()));
        assert_eq!(dis[1].1, "MOVA R5,R6");
    }

    #[test]
    fn rotate_op_display() {
        let r = RotateInsn { op: RotateOp::Rram, size: OpSize::Addr, count: 4, dst_reg: 7 };
        assert_eq!(r.to_string(), "RRAM.A #4,R7");
    }
}
