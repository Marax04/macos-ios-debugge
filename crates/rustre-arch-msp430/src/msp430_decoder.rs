// msp430_decoder.rs — Typed MSP430 instruction decoder
//
// Types: Msp430Instr, Msp430Type, AddressMode, WordSize, Msp430Decoder.
// Covers all three MSP430 instruction formats using only std.
//
// This module provides a higher-level typed decoder, independent of the
// existing decoder.rs module (which uses different internal types).

use std::fmt;

// ────────────────────────────────────────────────────────────────────────────
// WordSize
// ────────────────────────────────────────────────────────────────────────────

/// MSP430 operand width — controlled by the BW bit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum WordSize {
    /// 16-bit word operation.
    Word,
    /// 8-bit byte operation.
    Byte,
    /// 20-bit address word (MSP430X).
    AddrWord,
}

impl WordSize {
    #[must_use]
    pub const fn from_bw(bw: u8) -> Self {
        if bw & 1 == 0 { Self::Word } else { Self::Byte }
    }
    #[must_use]
    pub const fn bytes(self) -> usize { match self { Self::Byte => 1, _ => 2 } }
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self { Self::Byte => ".B", Self::Word => ".W", Self::AddrWord => ".A" }
    }
    #[must_use]
    pub const fn mask(self) -> u32 {
        match self { Self::Byte => 0xFF, Self::Word => 0xFFFF, Self::AddrWord => 0xFFFFF }
    }
}

impl fmt::Display for WordSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.suffix()) }
}

// ────────────────────────────────────────────────────────────────────────────
// AddressMode
// ────────────────────────────────────────────────────────────────────────────

/// MSP430 addressing mode.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AddressMode {
    /// Register direct (As/Ad = 00): operand is Rn.
    Register(u8),
    /// Indexed (As/Ad = 01): operand at Rn + `ext_word`.
    Indexed { reg: u8, offset: i16 },
    /// Register indirect (As = 10): operand at (Rn).
    Indirect(u8),
    /// Register indirect auto-increment (As = 11): operand at (Rn), Rn += size.
    IndirectAutoInc(u8),
    /// Symbolic (As = 01, Rn = PC): operand at PC + `ext_word` (effective = address).
    Symbolic(u16),
    /// Absolute (As = 01, Rn = SR/R2): operand at absolute address from `ext_word`.
    Absolute(u16),
    /// Immediate (As = 11, Rn = PC): #N from `ext_word`.
    Immediate(u16),
    /// Constant from constant generator (As encoding for R2/R3).
    Constant(i16),
}

impl AddressMode {
    /// Number of extension words required (0 or 1).
    #[must_use]
    pub const fn ext_words(&self) -> usize {
        match self {
            Self::Indexed { .. } | Self::Symbolic(_)
            | Self::Absolute(_) | Self::Immediate(_) => 1,
            _ => 0,
        }
    }

    #[must_use]
    pub fn to_string_at(&self, instr_addr: u16) -> String {
        match self {
            Self::Register(r)              => format!("R{r}"),
            Self::Indexed { reg, offset }  => format!("{offset}(R{reg})"),
            Self::Indirect(r)              => format!("@R{r}"),
            Self::IndirectAutoInc(r)       => format!("@R{r}+"),
            Self::Symbolic(off)            => format!("0x{:04X}", instr_addr.wrapping_add(*off)),
            Self::Absolute(addr)           => format!("&0x{addr:04X}"),
            Self::Immediate(v)             => format!("#0x{v:04X}"),
            Self::Constant(v)              => format!("#{v}"),
        }
    }

    /// True if this mode reads/writes memory.
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        !matches!(self, Self::Register(_) | Self::Constant(_))
    }
}

impl fmt::Display for AddressMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_at(0))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Msp430Type — instruction format
// ────────────────────────────────────────────────────────────────────────────

/// MSP430 instruction format type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Msp430Type {
    /// Format I: double-operand (MOV, ADD, SUB, etc.).  Bits 15-12 = 4-15.
    TypeI,
    /// Format II: single-operand (PUSH, CALL, RRC, RRA, SXT, SWPB, RETI).  Bits 15-10 = 0x04.
    TypeII,
    /// Format III: jump (JEQ, JNE, JC, JNC, JN, JGE, JL, JMP).  Bits 15-13 = 001.
    TypeIII,
}

// ────────────────────────────────────────────────────────────────────────────
// MSP430 opcode enums
// ────────────────────────────────────────────────────────────────────────────

/// Format I (two-operand) opcodes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Op2 {
    Mov  = 4,  Add  = 5,  Addc = 6,  Subc = 7,
    Sub  = 8,  Cmp  = 9,  Dadd = 10, Bit  = 11,
    Bic  = 12, Bis  = 13, Xor  = 14, And  = 15,
}

impl Op2 {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            4  => Some(Self::Mov),   5  => Some(Self::Add),
            6  => Some(Self::Addc),  7  => Some(Self::Subc),
            8  => Some(Self::Sub),   9  => Some(Self::Cmp),
            10 => Some(Self::Dadd), 11  => Some(Self::Bit),
            12 => Some(Self::Bic),  13  => Some(Self::Bis),
            14 => Some(Self::Xor),  15  => Some(Self::And),
            _  => None,
        }
    }
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Mov  => "MOV",  Self::Add  => "ADD",
            Self::Addc => "ADDC", Self::Subc => "SUBC",
            Self::Sub  => "SUB",  Self::Cmp  => "CMP",
            Self::Dadd => "DADD", Self::Bit  => "BIT",
            Self::Bic  => "BIC",  Self::Bis  => "BIS",
            Self::Xor  => "XOR",  Self::And  => "AND",
        }
    }
    /// True if the instruction writes to the destination.
    #[must_use]
    pub const fn has_dst_write(self) -> bool {
        !matches!(self, Self::Cmp | Self::Bit)
    }
}

/// Format II (single-operand) opcodes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Op1 {
    Rrc  = 0, Swpb = 1, Rra  = 2, Sxt  = 3,
    Push = 4, Call = 5, Reti = 6,
}

impl Op1 {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Rrc),  1 => Some(Self::Swpb),
            2 => Some(Self::Rra),  3 => Some(Self::Sxt),
            4 => Some(Self::Push), 5 => Some(Self::Call),
            6 => Some(Self::Reti), _ => None,
        }
    }
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Rrc  => "RRC",  Self::Swpb => "SWPB",
            Self::Rra  => "RRA",  Self::Sxt  => "SXT",
            Self::Push => "PUSH", Self::Call => "CALL",
            Self::Reti => "RETI",
        }
    }
    #[must_use]
    pub const fn is_call(self)       -> bool { matches!(self, Self::Call) }
    #[must_use]
    pub const fn is_ret(self)        -> bool { matches!(self, Self::Reti) }
    #[must_use]
    pub const fn is_terminator(self) -> bool { self.is_call() || self.is_ret() }
}

/// Format III (jump) condition codes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum JumpCond {
    Jne = 0, Jeq = 1, Jnc = 2, Jc  = 3,
    Jn  = 4, Jge = 5, Jl  = 6, Jmp = 7,
}

impl JumpCond {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 7 {
            0 => Some(Self::Jne), 1 => Some(Self::Jeq),
            2 => Some(Self::Jnc), 3 => Some(Self::Jc),
            4 => Some(Self::Jn),  5 => Some(Self::Jge),
            6 => Some(Self::Jl),  7 => Some(Self::Jmp),
            _ => None,
        }
    }
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Jne => "JNE", Self::Jeq => "JEQ",
            Self::Jnc => "JNC", Self::Jc  => "JC",
            Self::Jn  => "JN",  Self::Jge => "JGE",
            Self::Jl  => "JL",  Self::Jmp => "JMP",
        }
    }
    #[must_use]
    pub const fn is_unconditional(self) -> bool { matches!(self, Self::Jmp) }
}

// ────────────────────────────────────────────────────────────────────────────
// Msp430Instr
// ────────────────────────────────────────────────────────────────────────────

/// A decoded MSP430 instruction.
#[derive(Clone, Debug)]
pub struct Msp430Instr {
    /// Instruction address.
    pub address: u16,
    /// Total byte length (2 or 4, rarely 6).
    pub length: u8,
    /// Instruction format.
    pub fmt: Msp430Type,
    /// Raw first word.
    pub opcode: u16,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Operand size.
    pub size: WordSize,
    /// Source operand (`TypeI`: present, `TypeII`: present, `TypeIII`: None).
    pub src: Option<AddressMode>,
    /// Destination operand (`TypeI`: present, `TypeII`/`TypeIII`: None).
    pub dst: Option<AddressMode>,
    /// Jump target (resolved) for `TypeIII`.
    pub jump_target: Option<u16>,
    /// Jump condition for `TypeIII`.
    pub jump_cond: Option<JumpCond>,
    /// True if this is a call (CALL / emulated CALL).
    pub is_call: bool,
    /// True if this terminates basic-block flow (JMP, RETI, CALL).
    pub is_terminator: bool,
    /// True if undecoded / illegal.
    pub is_illegal: bool,
}

impl Msp430Instr {
    #[must_use]
    pub fn end_address(&self) -> u16 {
        self.address.wrapping_add(u16::from(self.length))
    }
    #[must_use]
    pub fn illegal(address: u16, opcode: u16) -> Self {
        Self {
            address, length: 2, fmt: Msp430Type::TypeI, opcode,
            mnemonic: "???".to_string(), size: WordSize::Word,
            src: None, dst: None, jump_target: None, jump_cond: None,
            is_call: false, is_terminator: false, is_illegal: true,
        }
    }
}

impl fmt::Display for Msp430Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}  {}{}", self.address, self.mnemonic, self.size)?;
        match (&self.src, &self.dst) {
            (Some(s), Some(d)) => write!(f, " {},{}", s.to_string_at(self.address), d.to_string_at(self.address)),
            (Some(s), None)    => write!(f, " {}", s.to_string_at(self.address)),
            (None, Some(d))    => write!(f, " {}", d.to_string_at(self.address)),
            (None, None)       => self.jump_target.map_or(Ok(()), |t| write!(f, " 0x{t:04X}")),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Constant generator helper
// ────────────────────────────────────────────────────────────────────────────

/// Decode R2/R3 constant generator for source addressing.
/// Returns `Some(value)` if it's a CG address mode.
const fn const_gen(reg: u8, as_bits: u8) -> Option<i16> {
    match (reg, as_bits) {
        (2, 2)  => Some(4),
        (2, 3)  => Some(8),
        (3, 0)  => Some(0),
        (3, 1)  => Some(1),
        (3, 2)  => Some(2),
        (3, 3)  => Some(-1),
        _       => None,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Msp430Decoder
// ────────────────────────────────────────────────────────────────────────────

/// Decode error.
#[derive(Clone, Debug)]
pub struct DecodeError {
    pub address: u16,
    pub opcode: u16,
    pub message: String,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecodeError @ {:04X} (opcode {:04X}): {}", self.address, self.opcode, self.message)
    }
}

fn err(address: u16, opcode: u16, msg: &str) -> DecodeError {
    DecodeError { address, opcode, message: msg.to_string() }
}

/// MSP430 instruction decoder.
///
/// Decodes all three instruction formats (Type I/II/III) from raw little-endian
/// byte slices. Extension words are consumed automatically.
pub struct Msp430Decoder;

impl Msp430Decoder {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Decode one instruction from a little-endian byte slice.
    ///
    /// # Errors
    /// Returns [`DecodeError`] if the buffer is too short or the opcode is unrecognised.
    pub fn decode(&self, data: &[u8], address: u16) -> Result<Msp430Instr, DecodeError> {
        if data.len() < 2 {
            return Err(err(address, 0, "buffer too short"));
        }
        let word = u16::from_le_bytes([data[0], data[1]]);
        let bits15_13 = (word >> 13) & 0x7;
        let bits15_12 = (word >> 12) & 0xf;
        let bits15_10 = (word >> 10) & 0x3f;

        if bits15_13 == 0b001 {
            return Self::decode_type3(address, word);
        }
        if bits15_10 == 0b00_0100 {
            return Self::decode_type2(data, address, word);
        }
        if bits15_12 >= 4 {
            return Self::decode_type1(data, address, word);
        }
        Err(err(address, word, "unrecognized opcode"))
    }

    // ──────── Type I: double-operand ──────────────────────────────────────────

    fn decode_type1(data: &[u8], address: u16, word: u16) -> Result<Msp430Instr, DecodeError> {
        let opcode4 = ((word >> 12) & 0xf) as u8;
        let op = Op2::from_bits(opcode4).ok_or_else(|| err(address, word, "bad op2 opcode"))?;
        let src_reg = ((word >> 8) & 0xf) as u8;
        let ad      = ((word >> 7) & 0x1) as u8;
        let bw      = ((word >> 6) & 0x1) as u8;
        let as_bits = ((word >> 4) & 0x3) as u8;
        let dst_reg = (word & 0xf) as u8;
        let size = WordSize::from_bw(bw);

        let mut off = 2usize;
        let src = Self::decode_src(data, &mut off, src_reg, as_bits, address)?;
        let dst = Self::decode_dst(data, &mut off, dst_reg, ad, address)?;

        let mut instr = Msp430Instr {
            address, length: u8::try_from(off).unwrap_or(u8::MAX),
            fmt: Msp430Type::TypeI, opcode: word,
            mnemonic: op.mnemonic().to_string(), size,
            src: Some(src), dst: Some(dst),
            jump_target: None, jump_cond: None,
            is_call: false, is_terminator: false, is_illegal: false,
        };
        // MOV PC, ... is JMP equivalent
        if op == Op2::Mov && dst_reg == 0 { instr.is_terminator = true; }
        Ok(instr)
    }

    // ──────── Type II: single-operand ────────────────────────────────────────

    fn decode_type2(data: &[u8], address: u16, word: u16) -> Result<Msp430Instr, DecodeError> {
        let op_bits = ((word >> 7) & 0x7) as u8;
        let op = Op1::from_bits(op_bits).ok_or_else(|| err(address, word, "bad op1 opcode"))?;
        let bw      = ((word >> 6) & 0x1) as u8;
        let as_bits = ((word >> 4) & 0x3) as u8;
        let src_reg = (word & 0xf) as u8;
        let size = if op == Op1::Reti { WordSize::Word } else { WordSize::from_bw(bw) };

        let mut off = 2usize;
        let src = if op == Op1::Reti {
            None
        } else {
            Some(Self::decode_src(data, &mut off, src_reg, as_bits, address)?)
        };

        Ok(Msp430Instr {
            address, length: u8::try_from(off).unwrap_or(u8::MAX),
            fmt: Msp430Type::TypeII, opcode: word,
            mnemonic: op.mnemonic().to_string(), size,
            src, dst: None,
            jump_target: None, jump_cond: None,
            is_call: op.is_call(),
            is_terminator: op.is_terminator(),
            is_illegal: false,
        })
    }

    // ──────── Type III: jump ──────────────────────────────────────────────────

    fn decode_type3(address: u16, word: u16) -> Result<Msp430Instr, DecodeError> {
        let cond_bits = ((word >> 10) & 0x7) as u8;
        let cond = JumpCond::from_bits(cond_bits).ok_or_else(|| err(address, word, "bad jump cond"))?;
        // 10-bit signed offset, in words
        let offset10: i16 = (word & 0x3ff).cast_signed();
        let offset10_signed = if offset10 & 0x200 != 0 { offset10 | !0x3ff } else { offset10 };
        // Target = PC + 2 + offset * 2
        let target = i32_to_u16_wrap(i32::from(address) + 2 + i32::from(offset10_signed) * 2);

        Ok(Msp430Instr {
            address, length: 2, fmt: Msp430Type::TypeIII, opcode: word,
            mnemonic: cond.mnemonic().to_string(), size: WordSize::Word,
            src: None, dst: None,
            jump_target: Some(target), jump_cond: Some(cond),
            is_call: false,
            is_terminator: cond.is_unconditional(),
            is_illegal: false,
        })
    }

    // ──────── Addressing mode helpers ─────────────────────────────────────────

    fn decode_src(data: &[u8], off: &mut usize, reg: u8, as_bits: u8, address: u16) -> Result<AddressMode, DecodeError> {
        // Check constant generator first
        if let Some(c) = const_gen(reg, as_bits) {
            return Ok(AddressMode::Constant(c));
        }
        match as_bits {
            0 => Ok(AddressMode::Register(reg)),
            1 => {
                let ext = Self::read_ext(data, *off, address)?;
                *off += 2;
                if reg == 0 { // PC => Symbolic
                    Ok(AddressMode::Symbolic(ext))
                } else if reg == 2 { // SR => Absolute
                    Ok(AddressMode::Absolute(ext))
                } else {
                    Ok(AddressMode::Indexed { reg, offset: ext.cast_signed() })
                }
            }
            2 => {
                if reg == 2 { // SR in as=10 => constant 4 (handled above, fallback)
                    Ok(AddressMode::Constant(4))
                } else {
                    Ok(AddressMode::Indirect(reg))
                }
            }
            3 => {
                if reg == 0 { // PC => Immediate
                    let ext = Self::read_ext(data, *off, address)?;
                    *off += 2;
                    Ok(AddressMode::Immediate(ext))
                } else {
                    Ok(AddressMode::IndirectAutoInc(reg))
                }
            }
            _ => Err(err(address, 0, "bad as field")),
        }
    }

    fn decode_dst(data: &[u8], off: &mut usize, reg: u8, ad: u8, address: u16) -> Result<AddressMode, DecodeError> {
        match ad {
            0 => Ok(AddressMode::Register(reg)),
            1 => {
                let ext = Self::read_ext(data, *off, address)?;
                *off += 2;
                if reg == 0 { Ok(AddressMode::Symbolic(ext)) }
                else if reg == 2 { Ok(AddressMode::Absolute(ext)) }
                else { Ok(AddressMode::Indexed { reg, offset: ext.cast_signed() }) }
            }
            _ => Err(err(address, 0, "bad ad field")),
        }
    }

    fn read_ext(data: &[u8], off: usize, addr: u16) -> Result<u16, DecodeError> {
        if off + 2 > data.len() {
            return Err(err(addr, 0, "extension word out of bounds"));
        }
        Ok(u16::from_le_bytes([data[off], data[off+1]]))
    }

    /// Decode all instructions in a byte slice.
    #[must_use]
    pub fn decode_all(&self, data: &[u8], base_address: u16) -> Vec<Msp430Instr> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 2 <= data.len() {
            let addr = base_address.wrapping_add(u16::try_from(off).unwrap_or(u16::MAX));
            match self.decode(&data[off..], addr) {
                Ok(instr) => {
                    let len = instr.length.max(2) as usize;
                    off += len;
                    out.push(instr);
                }
                Err(_) => { off += 2; }
            }
        }
        out
    }
}

impl Default for Msp430Decoder {
    fn default() -> Self { Self::new() }
}

/// Wrapping i32→u16 cast (intentional for MSP430 16-bit PC arithmetic).
#[inline]
const fn i32_to_u16_wrap(v: i32) -> u16 { (v.cast_unsigned() & 0xFFFF) as u16 }

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_size() {
        assert_eq!(WordSize::Byte.bytes(), 1);
        assert_eq!(WordSize::Word.bytes(), 2);
        assert_eq!(WordSize::Byte.suffix(), ".B");
        assert_eq!(WordSize::from_bw(1), WordSize::Byte);
        assert_eq!(WordSize::from_bw(0), WordSize::Word);
    }

    #[test]
    fn test_op2_from_bits() {
        assert_eq!(Op2::from_bits(4), Some(Op2::Mov));
        assert_eq!(Op2::from_bits(5), Some(Op2::Add));
        assert_eq!(Op2::from_bits(15), Some(Op2::And));
        assert_eq!(Op2::from_bits(0), None);
    }

    #[test]
    fn test_op1_from_bits() {
        assert_eq!(Op1::from_bits(5), Some(Op1::Call));
        assert!(Op1::Call.is_call());
        assert!(!Op1::Push.is_call());
    }

    #[test]
    fn test_jump_cond() {
        assert_eq!(JumpCond::from_bits(7), Some(JumpCond::Jmp));
        assert!(JumpCond::Jmp.is_unconditional());
        assert!(!JumpCond::Jne.is_unconditional());
    }

    #[test]
    fn test_decode_mov() {
        // MOV.W #1, R4  — typical: MOV imm to reg
        // Encoding: 0x4031 (MOV.W, src=R0(PC)/as=11=imm, dst=R4/ad=0)
        // word = 0x4031 = 0100 0000 0011 0001
        //   bits[15:12] = 4 (MOV), src_reg=0, ad=0, bw=0, as=3, dst_reg=1 (SP)
        // Let's use a simpler: MOV R4, R5 = 0x4405
        // bits[15:12]=4=MOV, src_reg[11:8]=4, ad[7]=0, bw[6]=0, as[5:4]=00, dst_reg[3:0]=5
        let data = [0x05u8, 0x44]; // little-endian 0x4405
        let dec = Msp430Decoder::new();
        let instr = dec.decode(&data, 0x1000).expect("decode");
        assert_eq!(instr.mnemonic, "MOV");
        assert_eq!(instr.size, WordSize::Word);
        assert_eq!(instr.length, 2);
    }

    #[test]
    fn test_decode_jmp() {
        // JMP +0 = 0x3C00 (bits 15:13=001, cond=111, offset=0)
        // 0x3C00 = 0011 1100 0000 0000
        //   bits[15:13] = 001, bits[12:10] = 111 = JMP, offset = 0
        let data = [0x00u8, 0x3C];
        let dec = Msp430Decoder::new();
        let instr = dec.decode(&data, 0x1000).expect("decode");
        assert_eq!(instr.mnemonic, "JMP");
        assert!(instr.is_terminator);
        assert_eq!(instr.jump_target, Some(0x1002)); // +0 offset = address+2
    }

    #[test]
    fn test_decode_jne() {
        // JNE -2 = loop to self
        // bits[15:13]=001, cond=000, offset = -1 (10-bit 2's complement)
        // -1 in 10-bit = 0x3FF, so: 0b001_000_11_1111_1111 = 0x23FF
        let data = [0xFFu8, 0x23];
        let dec = Msp430Decoder::new();
        let instr = dec.decode(&data, 0x1000).expect("decode");
        assert_eq!(instr.mnemonic, "JNE");
        assert!(!instr.is_terminator); // conditional
        // -1 * 2 + 2 = 0x1000 (loop to self)
        assert_eq!(instr.jump_target, Some(0x1000));
    }

    #[test]
    fn test_decode_reti() {
        // RETI = 0x1300: bits[15:10]=000100, op[9:7]=110=RETI, bw=0, as=00, reg=0
        let data = [0x00u8, 0x13];
        let dec = Msp430Decoder::new();
        let instr = dec.decode(&data, 0x1000).expect("decode");
        assert_eq!(instr.mnemonic, "RETI");
        assert!(instr.is_terminator);
    }

    #[test]
    fn test_decode_all() {
        let dec = Msp430Decoder::new();
        // MOV R4,R5 + JMP 0
        let data = [0x05u8, 0x44, 0x00, 0x3C];
        let instrs = dec.decode_all(&data, 0);
        assert_eq!(instrs.len(), 2);
    }

    #[test]
    fn test_addr_mode_ext_words() {
        assert_eq!(AddressMode::Register(4).ext_words(), 0);
        assert_eq!(AddressMode::Immediate(42).ext_words(), 1);
        assert_eq!(AddressMode::Indexed { reg: 4, offset: 10 }.ext_words(), 1);
    }
}
