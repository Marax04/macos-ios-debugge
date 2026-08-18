// m68k_decoder.rs — Typed M68000 instruction decoder layer
//
// Provides M68kInstr, M68kEa, M68kSize, M68kGroup, M68kDecoder.
// This layer adds strongly-typed structs on top of the raw decode
// already in lib.rs, enabling downstream analysis passes.
//
// Only std is used; no external crates.

use std::fmt;

// ────────────────────────────────────────────────────────────────────────────
// M68kSize
// ────────────────────────────────────────────────────────────────────────────

/// Operand size for a 68k instruction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum M68kSize {
    Byte,   // .B  — 8 bits
    Word,   // .W  — 16 bits
    Long,   // .L  — 32 bits
    Single, // .S  — 32-bit float (FPU)
    Double, // .D  — 64-bit float (FPU)
    Extended, // .X — 80-bit extended float (FPU)
    Packed,   // .P — BCD packed (FPU)
    Unsized,  // no suffix, e.g. JMP
}

impl M68kSize {
    /// Return byte width (or 0 for Unsized/Packed/Extended).
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            M68kSize::Byte     => 1,
            M68kSize::Word     => 2,
            M68kSize::Long     => 4,
            M68kSize::Single   => 4,
            M68kSize::Double   => 8,
            M68kSize::Extended => 10,
            M68kSize::Packed   => 12,
            M68kSize::Unsized  => 0,
        }
    }

    /// Parse from the 2-bit sz field in most instructions.
    #[must_use]
    pub const fn from_sz2(sz: u8) -> Option<Self> {
        match sz {
            0 => Some(M68kSize::Byte),
            1 => Some(M68kSize::Word),
            2 => Some(M68kSize::Long),
            _ => None,
        }
    }

    /// Parse from the alternative 2-bit sz encoding used in MOVE.
    #[must_use]
    pub const fn from_move_sz(sz: u8) -> Option<Self> {
        match sz {
            1 => Some(M68kSize::Byte),
            3 => Some(M68kSize::Word),
            2 => Some(M68kSize::Long),
            _ => None,
        }
    }

    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            M68kSize::Byte     => ".b",
            M68kSize::Word     => ".w",
            M68kSize::Long     => ".l",
            M68kSize::Single   => ".s",
            M68kSize::Double   => ".d",
            M68kSize::Extended => ".x",
            M68kSize::Packed   => ".p",
            M68kSize::Unsized  => "",
        }
    }
}

impl fmt::Display for M68kSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.suffix())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kEa
// ────────────────────────────────────────────────────────────────────────────

/// Effective address for a 68k operand.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum M68kEa {
    /// Dn — data register direct.
    DataReg(u8),
    /// An — address register direct.
    AddrReg(u8),
    /// (An) — address register indirect.
    AddrInd(u8),
    /// (An)+ — post-increment.
    PostInc(u8),
    /// -(An) — pre-decrement.
    PreDec(u8),
    /// (d16,An) — 16-bit displacement from An.
    DispAn(u8, i16),
    /// (d8,An,Xn.size) — base + index + displacement.
    IdxAn { an: u8, xn: u8, xn_is_addr: bool, xn_size: M68kSize, disp: i8 },
    /// (xxx).W — absolute short.
    AbsShort(u32),
    /// (xxx).L — absolute long.
    AbsLong(u32),
    /// (d16,PC) — PC-relative with 16-bit displacement.
    DispPc(i16),
    /// (d8,PC,Xn) — PC-relative with index.
    IdxPc { xn: u8, xn_is_addr: bool, xn_size: M68kSize, disp: i8 },
    /// #imm — immediate value.
    Imm(u32),
    /// CCR register (used in MOVE to/from CCR).
    Ccr,
    /// SR register (used in MOVE to/from SR).
    Sr,
    /// USP register (used in MOVE USP).
    Usp,
    /// Register list bitmask (for MOVEM).
    RegList(u16),
}

impl M68kEa {
    /// Number of extension words needed to encode this EA (not counting imm).
    #[must_use]
    pub const fn extension_words(&self, sz: M68kSize) -> usize {
        match self {
            M68kEa::DataReg(_) | M68kEa::AddrReg(_) | M68kEa::AddrInd(_)
            | M68kEa::PostInc(_) | M68kEa::PreDec(_) => 0,
            M68kEa::DispAn(..) | M68kEa::IdxAn { .. } => 1,
            M68kEa::AbsShort(_) => 1,
            M68kEa::AbsLong(_)  => 2,
            M68kEa::DispPc(_) | M68kEa::IdxPc { .. } => 1,
            M68kEa::Imm(_) => {
                match sz {
                    M68kSize::Byte | M68kSize::Word => 1,
                    M68kSize::Long => 2,
                    _ => 1,
                }
            }
            M68kEa::Ccr | M68kEa::Sr | M68kEa::Usp => 0,
            M68kEa::RegList(_) => 1,
        }
    }

    /// True if this EA can be used as a source (all except pre-dec which is only dst).
    #[must_use]
    pub const fn is_valid_src(&self) -> bool {
        !matches!(self, M68kEa::PreDec(_))
    }

    /// True if this EA is a memory reference (can be used with memory instructions).
    #[must_use]
    pub const fn is_memory(&self) -> bool {
        matches!(self,
            M68kEa::AddrInd(_) | M68kEa::PostInc(_) | M68kEa::PreDec(_)
            | M68kEa::DispAn(..) | M68kEa::IdxAn { .. }
            | M68kEa::AbsShort(_) | M68kEa::AbsLong(_)
            | M68kEa::DispPc(_) | M68kEa::IdxPc { .. }
        )
    }

    /// Motorola syntax string representation.
    #[must_use]
    pub fn to_motorola(&self) -> String {
        match self {
            M68kEa::DataReg(n)       => format!("D{n}"),
            M68kEa::AddrReg(n)       => format!("A{n}"),
            M68kEa::AddrInd(n)       => format!("(A{n})"),
            M68kEa::PostInc(n)       => format!("(A{n})+"),
            M68kEa::PreDec(n)        => format!("-(A{n})"),
            M68kEa::DispAn(an, d)    => format!("({d},A{an})"),
            M68kEa::IdxAn { an, xn, xn_is_addr, xn_size, disp } => {
                let xreg = if *xn_is_addr { format!("A{xn}") } else { format!("D{xn}") };
                format!("({},{},{}.{})", disp, an, xreg, xn_size.suffix().trim_start_matches('.'))
            }
            M68kEa::AbsShort(a)      => format!("${a:04X}.W"),
            M68kEa::AbsLong(a)       => format!("${a:08X}.L"),
            M68kEa::DispPc(d)        => format!("({d},PC)"),
            M68kEa::IdxPc { xn, xn_is_addr, xn_size, disp } => {
                let xreg = if *xn_is_addr { format!("A{xn}") } else { format!("D{xn}") };
                format!("({},PC,{}.{})", disp, xreg, xn_size.suffix().trim_start_matches('.'))
            }
            M68kEa::Imm(v)           => format!("#${v:X}"),
            M68kEa::Ccr              => "CCR".to_string(),
            M68kEa::Sr               => "SR".to_string(),
            M68kEa::Usp              => "USP".to_string(),
            M68kEa::RegList(mask)    => format!("{{reglist:{mask:016b}}}"),
        }
    }
}

impl fmt::Display for M68kEa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_motorola())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kGroup
// ────────────────────────────────────────────────────────────────────────────

/// Top-level opcode group (bits 15-12 of the first word).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum M68kGroup {
    Group0,  // 0x0 — Bit manip / MOVEP / Immediate
    Group1,  // 0x1 — MOVE.B
    Group2,  // 0x2 — MOVE.L / MOVEA.L
    Group3,  // 0x3 — MOVE.W / MOVEA.W
    Group4,  // 0x4 — Miscellaneous (CLR, NOT, NEG, LEA, JSR, JMP, ...)
    Group5,  // 0x5 — ADDQ/SUBQ/Scc/DBcc/TRAPcc
    Group6,  // 0x6 — Bcc/BSR/BRA
    Group7,  // 0x7 — MOVEQ
    Group8,  // 0x8 — OR/DIV/SBCD
    Group9,  // 0x9 — SUB/SUBA/SUBX
    GroupA,  // 0xA — (A-line / unimplemented)
    GroupB,  // 0xB — CMP/EOR
    GroupC,  // 0xC — AND/MUL/ABCD/EXG
    GroupD,  // 0xD — ADD/ADDA/ADDX
    GroupE,  // 0xE — Shift/Rotate
    GroupF,  // 0xF — F-line / coprocessor
}

impl M68kGroup {
    #[must_use]
    pub const fn from_opcode(word: u16) -> Self {
        match word >> 12 {
            0x0 => M68kGroup::Group0,
            0x1 => M68kGroup::Group1,
            0x2 => M68kGroup::Group2,
            0x3 => M68kGroup::Group3,
            0x4 => M68kGroup::Group4,
            0x5 => M68kGroup::Group5,
            0x6 => M68kGroup::Group6,
            0x7 => M68kGroup::Group7,
            0x8 => M68kGroup::Group8,
            0x9 => M68kGroup::Group9,
            0xA => M68kGroup::GroupA,
            0xB => M68kGroup::GroupB,
            0xC => M68kGroup::GroupC,
            0xD => M68kGroup::GroupD,
            0xE => M68kGroup::GroupE,
            _   => M68kGroup::GroupF,
        }
    }

    #[must_use]
    pub fn is_aline(self) -> bool { self == M68kGroup::GroupA }
    #[must_use]
    pub fn is_fline(self) -> bool { self == M68kGroup::GroupF }
    #[must_use]
    pub fn is_branch(self) -> bool { self == M68kGroup::Group6 }
    #[must_use]
    pub const fn is_move(self) -> bool {
        matches!(self, M68kGroup::Group1 | M68kGroup::Group2 | M68kGroup::Group3)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kCondCode
// ────────────────────────────────────────────────────────────────────────────

/// 68k condition code (4-bit field).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum M68kCond {
    T  = 0,  Ra = 1,  HI = 2,  LS = 3,
    CC = 4,  CS = 5,  NE = 6,  EQ = 7,
    VC = 8,  VS = 9,  PL = 10, MI = 11,
    GE = 12, LT = 13, GT = 14, LE = 15,
}

impl M68kCond {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v & 0xf {
            0 => M68kCond::T,  1 => M68kCond::Ra, 2 => M68kCond::HI,
            3 => M68kCond::LS, 4 => M68kCond::CC, 5 => M68kCond::CS,
            6 => M68kCond::NE, 7 => M68kCond::EQ, 8 => M68kCond::VC,
            9 => M68kCond::VS, 10 => M68kCond::PL, 11 => M68kCond::MI,
            12 => M68kCond::GE, 13 => M68kCond::LT, 14 => M68kCond::GT,
            _ => M68kCond::LE,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            M68kCond::T  => "T",  M68kCond::Ra => "F",  M68kCond::HI => "HI",
            M68kCond::LS => "LS", M68kCond::CC => "CC", M68kCond::CS => "CS",
            M68kCond::NE => "NE", M68kCond::EQ => "EQ", M68kCond::VC => "VC",
            M68kCond::VS => "VS", M68kCond::PL => "PL", M68kCond::MI => "MI",
            M68kCond::GE => "GE", M68kCond::LT => "LT", M68kCond::GT => "GT",
            M68kCond::LE => "LE",
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kInstr
// ────────────────────────────────────────────────────────────────────────────

/// A decoded M68000 instruction.
#[derive(Clone, Debug)]
pub struct M68kInstr {
    /// Virtual address of this instruction.
    pub address: u32,
    /// Number of bytes consumed (2, 4, 6, …).
    pub length: u8,
    /// Opcode group.
    pub group: M68kGroup,
    /// Raw first word.
    pub opcode: u16,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Operand size (or Unsized).
    pub size: M68kSize,
    /// Source operand (if any).
    pub src: Option<M68kEa>,
    /// Destination operand (if any).
    pub dst: Option<M68kEa>,
    /// Condition code (for Bcc/Scc/DBcc).
    pub cond: Option<M68kCond>,
    /// Branch target address (resolved, if applicable).
    pub branch_target: Option<u32>,
    /// True if this is a call (JSR/BSR).
    pub is_call: bool,
    /// True if this is an unconditional transfer (JMP/BRA/RTS/RTR/RTE/STOP).
    pub is_terminator: bool,
    /// True if the instruction is illegal / unrecognised.
    pub is_illegal: bool,
}

impl M68kInstr {
    /// Placeholder "illegal/undefined" instruction.
    #[must_use]
    pub fn illegal(address: u32, opcode: u16) -> Self {
        M68kInstr {
            address, length: 2, group: M68kGroup::from_opcode(opcode),
            opcode, mnemonic: "ILLEGAL".to_string(), size: M68kSize::Unsized,
            src: None, dst: None, cond: None, branch_target: None,
            is_call: false, is_terminator: true, is_illegal: true,
        }
    }

    #[must_use]
    pub const fn end_address(&self) -> u32 {
        self.address.wrapping_add(self.length as u32)
    }
}

impl fmt::Display for M68kInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}  {}{}", self.address, self.mnemonic, self.size)?;
        if let Some(src) = &self.src {
            write!(f, " {src}")?;
            if let Some(dst) = &self.dst {
                write!(f, ",{dst}")?;
            }
        } else if let Some(dst) = &self.dst {
            write!(f, " {dst}")?;
        }
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kDecoder
// ────────────────────────────────────────────────────────────────────────────

/// Decode error.
#[derive(Clone, Debug)]
pub struct DecodeError {
    pub address: u32,
    pub opcode: u16,
    pub reason: String,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecodeError @ {:08X} (opcode {:#06X}): {}", self.address, self.opcode, self.reason)
    }
}

/// Stateless M68000 instruction decoder.
///
/// Decodes a single instruction from a byte slice at a given virtual address.
/// All 68000 instruction groups are handled.
pub struct M68kDecoder;

impl M68kDecoder {
    #[must_use]
    pub const fn new() -> Self { M68kDecoder }

    /// Decode a single instruction.
    ///
    /// `data` must contain at least 2 bytes.
    /// `address` is the virtual address of the first byte.
    /// Returns the decoded instruction or a decode error.
    pub fn decode(&self, data: &[u8], address: u32) -> Result<M68kInstr, DecodeError> {
        if data.len() < 2 {
            return Err(DecodeError { address, opcode: 0, reason: "buffer too short".into() });
        }
        let word = u16::from_be_bytes([data[0], data[1]]);
        let group = M68kGroup::from_opcode(word);

        match group {
            M68kGroup::Group0 => self.decode_group0(data, address, word),
            M68kGroup::Group1 => self.decode_move(data, address, word, M68kSize::Byte),
            M68kGroup::Group2 => self.decode_move(data, address, word, M68kSize::Long),
            M68kGroup::Group3 => self.decode_move(data, address, word, M68kSize::Word),
            M68kGroup::Group4 => self.decode_group4(data, address, word),
            M68kGroup::Group5 => self.decode_group5(data, address, word),
            M68kGroup::Group6 => self.decode_group6(data, address, word),
            M68kGroup::Group7 => self.decode_moveq(address, word),
            M68kGroup::Group8 => self.decode_group8(data, address, word),
            M68kGroup::Group9 => self.decode_addsub(data, address, word, false),
            M68kGroup::GroupA => Ok(M68kInstr::illegal(address, word)),
            M68kGroup::GroupB => self.decode_groupb(data, address, word),
            M68kGroup::GroupC => self.decode_groupc(data, address, word),
            M68kGroup::GroupD => self.decode_addsub(data, address, word, true),
            M68kGroup::GroupE => self.decode_groupe(data, address, word),
            M68kGroup::GroupF => Ok(M68kInstr::illegal(address, word)),
        }
    }

    // ──── EA parsing helpers ─────────────────────────────────────────────────

    fn read_word(data: &[u8], off: usize) -> Option<u16> {
        data.get(off..off+2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn read_long(data: &[u8], off: usize) -> Option<u32> {
        data.get(off..off+4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Parse an EA and return (ea, `bytes_consumed`).
    fn parse_ea(&self, data: &[u8], base_off: usize, mode: u8, reg: u8, sz: M68kSize) -> Option<(M68kEa, usize)> {
        let mut extra = 0usize;
        let ea = match mode {
            0 => M68kEa::DataReg(reg),
            1 => M68kEa::AddrReg(reg),
            2 => M68kEa::AddrInd(reg),
            3 => M68kEa::PostInc(reg),
            4 => M68kEa::PreDec(reg),
            5 => {
                let d = Self::read_word(data, base_off)? as i16;
                extra = 2;
                M68kEa::DispAn(reg, d)
            }
            6 => {
                let ext = Self::read_word(data, base_off)?;
                extra = 2;
                let xn = ((ext >> 12) & 0x7) as u8;
                let xn_is_addr = (ext >> 15) & 1 == 1;
                let xn_size = if (ext >> 11) & 1 == 1 { M68kSize::Long } else { M68kSize::Word };
                let disp = (ext & 0xff) as i8;
                M68kEa::IdxAn { an: reg, xn, xn_is_addr, xn_size, disp }
            }
            7 => match reg {
                0 => {
                    let v = u32::from(Self::read_word(data, base_off)?);
                    extra = 2;
                    M68kEa::AbsShort(v)
                }
                1 => {
                    let v = Self::read_long(data, base_off)?;
                    extra = 4;
                    M68kEa::AbsLong(v)
                }
                2 => {
                    let d = Self::read_word(data, base_off)? as i16;
                    extra = 2;
                    M68kEa::DispPc(d)
                }
                3 => {
                    let ext = Self::read_word(data, base_off)?;
                    extra = 2;
                    let xn = ((ext >> 12) & 0x7) as u8;
                    let xn_is_addr = (ext >> 15) & 1 == 1;
                    let xn_size = if (ext >> 11) & 1 == 1 { M68kSize::Long } else { M68kSize::Word };
                    let disp = (ext & 0xff) as i8;
                    M68kEa::IdxPc { xn, xn_is_addr, xn_size, disp }
                }
                4 => {
                    // Immediate
                    match sz {
                        M68kSize::Byte => {
                            let v = u32::from(Self::read_word(data, base_off)?) & 0xff;
                            extra = 2;
                            M68kEa::Imm(v)
                        }
                        M68kSize::Word => {
                            let v = u32::from(Self::read_word(data, base_off)?);
                            extra = 2;
                            M68kEa::Imm(v)
                        }
                        M68kSize::Long => {
                            let v = Self::read_long(data, base_off)?;
                            extra = 4;
                            M68kEa::Imm(v)
                        }
                        _ => {
                            let v = u32::from(Self::read_word(data, base_off)?);
                            extra = 2;
                            M68kEa::Imm(v)
                        }
                    }
                }
                _ => return None,
            },
            _ => return None,
        };
        Some((ea, extra))
    }

    // ──── Group decoders ─────────────────────────────────────────────────────

    fn decode_group0(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        // Bit manipulation / MOVEP / Immediate
        // Check for MOVEP first: bit 8 set and mode bits 3..2 are 001
        if (word >> 8) & 1 == 1 && ((word >> 3) & 0b111) == 0b001 {
            let dn = ((word >> 9) & 7) as u8;
            let an = (word & 7) as u8;
            let sz = if (word >> 6) & 1 == 1 { M68kSize::Long } else { M68kSize::Word };
            let disp = Self::read_word(data, 2)
                .ok_or_else(|| DecodeError { address, opcode: word, reason: "MOVEP: buffer too short for displacement".into() })?
                as i16;
            let mut instr = self.make_instr(address, word, "MOVEP", sz);
            instr.length = 4;
            if (word >> 7) & 1 == 1 {
                instr.src = Some(M68kEa::DataReg(dn));
                instr.dst = Some(M68kEa::DispAn(an, disp));
            } else {
                instr.src = Some(M68kEa::DispAn(an, disp));
                instr.dst = Some(M68kEa::DataReg(dn));
            }
            return Ok(instr);
        }
        // Immediate ops and bit ops
        let dn = ((word >> 9) & 7) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        let sz_bits = ((word >> 6) & 3) as u8;
        if sz_bits == 3 {
            // Bit operation without size
            let bitop = match (word >> 6) & 3 { _ => "BTST" };
            let _ = bitop;
            let mnem = match (word >> 8) & 0b11 {
                0 => "BTST", 1 => "BCHG", 2 => "BCLR", _ => "BSET",
            };
            let mut instr = self.make_instr(address, word, mnem, M68kSize::Unsized);
            instr.length = 2;
            instr.src = Some(M68kEa::DataReg(dn));
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Byte) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
            return Ok(instr);
        }
        let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
        let (mnem, off) = match (word >> 9) & 7 {
            0 => ("ORI",  2usize),
            1 => ("ANDI", 2),
            2 => ("SUBI", 2),
            3 => ("ADDI", 2),
            4 => {
                // Static bit op with immediate bit number
                let bop = match (word >> 6) & 3 {
                    0 => "BTST", 1 => "BCHG", 2 => "BCLR", _ => "BSET",
                };
                let mut instr = self.make_instr(address, word, bop, M68kSize::Unsized);
                instr.length = 4;
                let bit_n = u32::from(Self::read_word(data, 2).unwrap_or(0)) & 0xff;
                instr.src = Some(M68kEa::Imm(bit_n));
                if let Some((ea, extra)) = self.parse_ea(data, 4, mode, reg, M68kSize::Byte) {
                    instr.dst = Some(ea);
                    instr.length += extra as u8;
                }
                return Ok(instr);
            }
            5 => ("EORI", 2),
            6 => ("CMPI", 2),
            _ => return Ok(M68kInstr::illegal(address, word)),
        };
        let (imm_ea, imm_bytes) = self.parse_ea(data, off, 7, 4, sz)
            .ok_or_else(|| DecodeError { address, opcode: word, reason: "bad imm ea".into() })?;
        let dst_off = off + imm_bytes;
        let mut instr = self.make_instr(address, word, mnem, sz);
        instr.src = Some(imm_ea);
        if let Some((dst_ea, dst_extra)) = self.parse_ea(data, dst_off, mode, reg, sz) {
            instr.dst = Some(dst_ea);
            instr.length = (dst_off + dst_extra) as u8;
        }
        Ok(instr)
    }

    fn decode_move(&self, data: &[u8], address: u32, word: u16, sz: M68kSize) -> Result<M68kInstr, DecodeError> {
        let src_mode = ((word >> 3) & 7) as u8;
        let src_reg  = (word & 7) as u8;
        let dst_reg  = ((word >> 9) & 7) as u8;
        let dst_mode = ((word >> 6) & 7) as u8;
        let mnem = if dst_mode == 1 { "MOVEA" } else { "MOVE" };
        let (src_ea, src_bytes) = self.parse_ea(data, 2, src_mode, src_reg, sz)
            .ok_or_else(|| DecodeError { address, opcode: word, reason: "bad src ea".into() })?;
        let (dst_ea, dst_bytes) = self.parse_ea(data, 2 + src_bytes, dst_mode, dst_reg, sz)
            .ok_or_else(|| DecodeError { address, opcode: word, reason: "bad dst ea".into() })?;
        let mut instr = self.make_instr(address, word, mnem, sz);
        instr.src = Some(src_ea);
        instr.dst = Some(dst_ea);
        instr.length = (2 + src_bytes + dst_bytes) as u8;
        Ok(instr)
    }

    fn decode_group4(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        // Misc: CLR, NOT, NEG, NEGX, TST, EXT, SWAP, PEA, LEA, JSR, JMP, TRAP, RTS, ...
        let top8 = (word >> 8) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        let sz_bits = ((word >> 6) & 3) as u8;
        match top8 {
            0x4A => {
                // TST
                let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
                let mut instr = self.make_instr(address, word, "TST", sz);
                if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
                    instr.dst = Some(ea);
                    instr.length += extra as u8;
                }
                Ok(instr)
            }
            0x42 => {
                let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
                let mut instr = self.make_instr(address, word, "CLR", sz);
                if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
                    instr.dst = Some(ea);
                    instr.length += extra as u8;
                }
                Ok(instr)
            }
            0x46 => {
                // NOT or MOVE to SR
                if sz_bits == 3 {
                    let mut instr = self.make_instr(address, word, "MOVE", M68kSize::Word);
                    if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Word) {
                        instr.src = Some(ea);
                        instr.dst = Some(M68kEa::Sr);
                        instr.length += extra as u8;
                    }
                    Ok(instr)
                } else {
                    let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
                    let mut instr = self.make_instr(address, word, "NOT", sz);
                    if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
                        instr.dst = Some(ea);
                        instr.length += extra as u8;
                    }
                    Ok(instr)
                }
            }
            _ => {
                // JSR / JMP / LEA / PEA / RTS / RTE / RTR / NOP / TRAP ...
                if word == 0x4E75 {
                    let mut instr = self.make_instr(address, word, "RTS", M68kSize::Unsized);
                    instr.is_terminator = true;
                    return Ok(instr);
                }
                if word == 0x4E71 {
                    return Ok(self.make_instr(address, word, "NOP", M68kSize::Unsized));
                }
                if word == 0x4E73 {
                    let mut instr = self.make_instr(address, word, "RTE", M68kSize::Unsized);
                    instr.is_terminator = true;
                    return Ok(instr);
                }
                if word == 0x4E74 {
                    let mut instr = self.make_instr(address, word, "RTD", M68kSize::Unsized);
                    instr.is_terminator = true;
                    instr.length = 4;
                    return Ok(instr);
                }
                if word == 0x4E77 {
                    let mut instr = self.make_instr(address, word, "RTR", M68kSize::Unsized);
                    instr.is_terminator = true;
                    return Ok(instr);
                }
                if (word >> 6) & 0b111111 == 0b111011 {
                    // JMP
                    let mut instr = self.make_instr(address, word, "JMP", M68kSize::Unsized);
                    instr.is_terminator = true;
                    if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Unsized) {
                        instr.dst = Some(ea);
                        instr.length += extra as u8;
                    }
                    return Ok(instr);
                }
                if (word >> 6) & 0b111111 == 0b111010 {
                    // JSR
                    let mut instr = self.make_instr(address, word, "JSR", M68kSize::Unsized);
                    instr.is_call = true;
                    if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Unsized) {
                        instr.dst = Some(ea);
                        instr.length += extra as u8;
                    }
                    return Ok(instr);
                }
                // LEA
                if (word >> 6) & 3 == 3 && (word >> 8) & 1 == 1 {
                    let dn = ((word >> 9) & 7) as u8;
                    let mut instr = self.make_instr(address, word, "LEA", M68kSize::Long);
                    if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Unsized) {
                        instr.src = Some(ea);
                        instr.dst = Some(M68kEa::AddrReg(dn));
                        instr.length += extra as u8;
                    }
                    return Ok(instr);
                }
                Ok(M68kInstr::illegal(address, word))
            }
        }
    }

    fn decode_group5(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        let sz_bits = ((word >> 6) & 3) as u8;
        if sz_bits == 3 {
            // Scc / DBcc
            let cond = M68kCond::from_u8(((word >> 8) & 0xf) as u8);
            if mode == 1 {
                // DBcc
                let disp = Self::read_word(data, 2)
                    .ok_or_else(|| DecodeError { address, opcode: word, reason: "DBcc: buffer too short for displacement".into() })?
                    as i16;
                let target = address.wrapping_add(2).wrapping_add_signed(i32::from(disp));
                let mut instr = self.make_instr(address, word, &format!("DB{}", cond.name()), M68kSize::Word);
                instr.length = 4;
                instr.src = Some(M68kEa::DataReg(reg));
                instr.branch_target = Some(target);
                instr.cond = Some(cond);
                return Ok(instr);
            }
            let mut instr = self.make_instr(address, word, &format!("S{}", cond.name()), M68kSize::Byte);
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Byte) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
            return Ok(instr);
        }
        let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
        let data3 = u32::from((word >> 9) & 7);
        let mnem = if (word >> 8) & 1 == 1 { "SUBQ" } else { "ADDQ" };
        let mut instr = self.make_instr(address, word, mnem, sz);
        instr.src = Some(M68kEa::Imm(if data3 == 0 { 8 } else { data3 }));
        if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
            instr.dst = Some(ea);
            instr.length += extra as u8;
        }
        Ok(instr)
    }

    fn decode_group6(&self, _data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let cond = M68kCond::from_u8(((word >> 8) & 0xf) as u8);
        let disp8 = (word & 0xff) as i8;
        let (target, len) = if disp8 == 0 {
            // 16-bit displacement follows
            let d16 = Self::read_word(_data, 2)
                .ok_or_else(|| DecodeError { address, opcode: word, reason: "Bcc.W: buffer too short".into() })?
                as i16;
            (address.wrapping_add(2).wrapping_add_signed(i32::from(d16)), 4u8)
        } else if disp8 == -1i8 {
            // 32-bit displacement follows (68020+)
            let d32 = Self::read_long(_data, 2)
                .ok_or_else(|| DecodeError { address, opcode: word, reason: "Bcc.L: buffer too short".into() })?
                as i32;
            (address.wrapping_add(2).wrapping_add_signed(d32), 6u8)
        } else {
            (address.wrapping_add(2).wrapping_add_signed(i32::from(disp8)), 2u8)
        };
        let mnem = match cond {
            M68kCond::T  => "BRA",
            M68kCond::Ra => "BSR",
            _ => &format!("B{}", cond.name()),
        };
        let mut instr = self.make_instr(address, word, mnem, M68kSize::Unsized);
        instr.length = len;
        instr.branch_target = Some(target);
        instr.cond = Some(cond);
        instr.is_call = cond == M68kCond::Ra;
        instr.is_terminator = cond == M68kCond::T;
        Ok(instr)
    }

    fn decode_moveq(&self, address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let dn = ((word >> 9) & 7) as u8;
        let imm = i32::from((word & 0xff) as i8) as u32;
        let mut instr = self.make_instr(address, word, "MOVEQ", M68kSize::Long);
        instr.src = Some(M68kEa::Imm(imm));
        instr.dst = Some(M68kEa::DataReg(dn));
        Ok(instr)
    }

    fn decode_group8(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let dn   = ((word >> 9) & 7) as u8;
        let sz   = ((word >> 6) & 3) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        if sz == 3 {
            let mnem = if (word >> 8) & 1 == 1 { "DIVS" } else { "DIVU" };
            let mut instr = self.make_instr(address, word, mnem, M68kSize::Word);
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Word) {
                instr.src = Some(ea);
                instr.dst = Some(M68kEa::DataReg(dn));
                instr.length += extra as u8;
            }
            return Ok(instr);
        }
        let sz = M68kSize::from_sz2(sz).unwrap_or(M68kSize::Word);
        let mut instr = self.make_instr(address, word, "OR", sz);
        if (word >> 8) & 1 == 1 {
            instr.src = Some(M68kEa::DataReg(dn));
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
        } else {
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz) {
                instr.src = Some(ea);
                instr.dst = Some(M68kEa::DataReg(dn));
                instr.length += extra as u8;
            }
        }
        Ok(instr)
    }

    fn decode_addsub(&self, data: &[u8], address: u32, word: u16, is_add: bool) -> Result<M68kInstr, DecodeError> {
        let dn   = ((word >> 9) & 7) as u8;
        let sz   = ((word >> 6) & 3) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        let mnem = if sz == 3 {
            if is_add { "ADDA" } else { "SUBA" }
        } else if is_add { "ADD" } else { "SUB" };
        let sz_typed = if sz == 3 { M68kSize::Long } else {
            M68kSize::from_sz2(sz).unwrap_or(M68kSize::Word)
        };
        let mut instr = self.make_instr(address, word, mnem, sz_typed);
        if (word >> 8) & 1 == 1 {
            instr.src = Some(M68kEa::DataReg(dn));
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz_typed) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
        } else {
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz_typed) {
                instr.src = Some(ea);
                if sz == 3 {
                    instr.dst = Some(M68kEa::AddrReg(dn));
                } else {
                    instr.dst = Some(M68kEa::DataReg(dn));
                }
                instr.length += extra as u8;
            }
        }
        Ok(instr)
    }

    fn decode_groupb(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let dn   = ((word >> 9) & 7) as u8;
        let sz   = ((word >> 6) & 3) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        let mnem = if sz == 3 {
            "CMPA"
        } else if (word >> 8) & 1 == 1 {
            "EOR"
        } else {
            "CMP"
        };
        let sz_t = if sz == 3 { M68kSize::Long } else {
            M68kSize::from_sz2(sz).unwrap_or(M68kSize::Word)
        };
        let mut instr = self.make_instr(address, word, mnem, sz_t);
        if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz_t) {
            instr.src = Some(ea);
            if sz == 3 {
                instr.dst = Some(M68kEa::AddrReg(dn));
            } else {
                instr.dst = Some(M68kEa::DataReg(dn));
            }
            instr.length += extra as u8;
        }
        Ok(instr)
    }

    fn decode_groupc(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let dn   = ((word >> 9) & 7) as u8;
        let sz   = ((word >> 6) & 3) as u8;
        let mode = ((word >> 3) & 7) as u8;
        let reg  = (word & 7) as u8;
        if sz == 3 {
            let mnem = if (word >> 8) & 1 == 1 { "MULS" } else { "MULU" };
            let mut instr = self.make_instr(address, word, mnem, M68kSize::Word);
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Word) {
                instr.src = Some(ea);
                instr.dst = Some(M68kEa::DataReg(dn));
                instr.length += extra as u8;
            }
            return Ok(instr);
        }
        let sz_t = M68kSize::from_sz2(sz).unwrap_or(M68kSize::Word);
        let mut instr = self.make_instr(address, word, "AND", sz_t);
        if (word >> 8) & 1 == 1 {
            instr.src = Some(M68kEa::DataReg(dn));
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz_t) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
        } else {
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, sz_t) {
                instr.src = Some(ea);
                instr.dst = Some(M68kEa::DataReg(dn));
                instr.length += extra as u8;
            }
        }
        Ok(instr)
    }

    fn decode_groupe(&self, data: &[u8], address: u32, word: u16) -> Result<M68kInstr, DecodeError> {
        let sz_bits = ((word >> 6) & 3) as u8;
        let mode    = ((word >> 3) & 7) as u8;
        let reg     = (word & 7) as u8;
        let dir     = (word >> 8) & 1;
        let ir      = (word >> 5) & 1;
        let shift_op = (word >> 9) & 3;

        if sz_bits == 3 {
            // Memory shift (1-bit)
            let mnem = match shift_op {
                0 => if dir == 0 { "ASR" } else { "ASL" },
                1 => if dir == 0 { "LSR" } else { "LSL" },
                2 => if dir == 0 { "ROXR" } else { "ROXL" },
                _ => if dir == 0 { "ROR"  } else { "ROL"  },
            };
            let mut instr = self.make_instr(address, word, mnem, M68kSize::Word);
            if let Some((ea, extra)) = self.parse_ea(data, 2, mode, reg, M68kSize::Word) {
                instr.dst = Some(ea);
                instr.length += extra as u8;
            }
            return Ok(instr);
        }
        let sz = M68kSize::from_sz2(sz_bits).unwrap_or(M68kSize::Word);
        let count = ((word >> 9) & 7) as u8;
        let mnem = match shift_op {
            0 => if dir == 0 { "ASR" } else { "ASL" },
            1 => if dir == 0 { "LSR" } else { "LSL" },
            2 => if dir == 0 { "ROXR" } else { "ROXL" },
            _ => if dir == 0 { "ROR"  } else { "ROL"  },
        };
        let mut instr = self.make_instr(address, word, mnem, sz);
        if ir == 0 {
            instr.src = Some(M68kEa::Imm(if count == 0 { 8 } else { u32::from(count) }));
        } else {
            instr.src = Some(M68kEa::DataReg(count));
        }
        instr.dst = Some(M68kEa::DataReg(reg));
        Ok(instr)
    }

    fn make_instr(&self, address: u32, opcode: u16, mnemonic: &str, size: M68kSize) -> M68kInstr {
        M68kInstr {
            address,
            length: 2,
            group: M68kGroup::from_opcode(opcode),
            opcode,
            mnemonic: mnemonic.to_string(),
            size,
            src: None,
            dst: None,
            cond: None,
            branch_target: None,
            is_call: false,
            is_terminator: false,
            is_illegal: false,
        }
    }

    /// Linear sweep decode of a byte slice.
    #[must_use]
    pub fn decode_all(&self, data: &[u8], base_address: u32) -> Vec<M68kInstr> {
        let mut out = Vec::with_capacity(data.len() / 2);
        let mut off = 0;
        while off + 2 <= data.len() {
            let addr = base_address.wrapping_add(off as u32);
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

impl Default for M68kDecoder {
    fn default() -> Self { M68kDecoder::new() }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m68k_size_bytes() {
        assert_eq!(M68kSize::Byte.bytes(), 1);
        assert_eq!(M68kSize::Word.bytes(), 2);
        assert_eq!(M68kSize::Long.bytes(), 4);
    }

    #[test]
    fn test_m68k_group_from_opcode() {
        assert_eq!(M68kGroup::from_opcode(0x6000), M68kGroup::Group6);
        assert_eq!(M68kGroup::from_opcode(0x7000), M68kGroup::Group7);
        assert!(M68kGroup::from_opcode(0x6000).is_branch());
    }

    #[test]
    fn test_decode_nop() {
        let dec = M68kDecoder::new();
        let data: &[u8] = &[0x4E, 0x71]; // NOP
        let instr = dec.decode(data, 0x1000).unwrap();
        assert_eq!(instr.mnemonic, "NOP");
        assert_eq!(instr.length, 2);
    }

    #[test]
    fn test_decode_rts() {
        let dec = M68kDecoder::new();
        let data: &[u8] = &[0x4E, 0x75]; // RTS
        let instr = dec.decode(data, 0).unwrap();
        assert_eq!(instr.mnemonic, "RTS");
        assert!(instr.is_terminator);
    }

    #[test]
    fn test_decode_moveq() {
        let dec = M68kDecoder::new();
        // MOVEQ #1,D0 = 0x7001
        let data: &[u8] = &[0x70, 0x01];
        let instr = dec.decode(data, 0).unwrap();
        assert_eq!(instr.mnemonic, "MOVEQ");
        assert!(matches!(instr.src, Some(M68kEa::Imm(1))));
        assert!(matches!(instr.dst, Some(M68kEa::DataReg(0))));
    }

    #[test]
    fn test_decode_bra() {
        let dec = M68kDecoder::new();
        // BRA.B +4 => 0x6004 (branch forward 4 bytes from end of instruction = addr 2 + 4 = 6)
        let data: &[u8] = &[0x60, 0x04];
        let instr = dec.decode(data, 0).unwrap();
        assert_eq!(instr.mnemonic, "BRA");
        assert!(instr.is_terminator);
        assert_eq!(instr.branch_target, Some(6));
    }

    #[test]
    fn test_ea_display() {
        assert_eq!(M68kEa::DataReg(3).to_motorola(), "D3");
        assert_eq!(M68kEa::AddrInd(5).to_motorola(), "(A5)");
        assert_eq!(M68kEa::PostInc(2).to_motorola(), "(A2)+");
        assert_eq!(M68kEa::PreDec(7).to_motorola(), "-(A7)");
        assert_eq!(M68kEa::Imm(0xff).to_motorola(), "#$FF");
    }

    #[test]
    fn test_illegal_instruction() {
        let instr = M68kInstr::illegal(0x1000, 0xA000);
        assert!(instr.is_illegal);
        assert!(instr.is_terminator);
    }

    #[test]
    fn test_decode_all_terminates() {
        let dec = M68kDecoder::new();
        let data: &[u8] = &[0x70, 0x01, 0x4E, 0x75];
        let instrs = dec.decode_all(data, 0);
        assert_eq!(instrs.len(), 2);
        assert_eq!(instrs[1].mnemonic, "RTS");
    }
}
