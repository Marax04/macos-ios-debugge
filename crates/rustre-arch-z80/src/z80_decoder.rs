//! Z80 instruction decoder: unprefixed + CB, DD, FD, ED, DDCB, FDCB tables.

// ── Prefix encoding ───────────────────────────────────────────────────────────

/// The prefix byte(s) that modify a Z80 instruction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Z80Prefix {
    /// No prefix — main opcode table.
    #[default]
    None,
    /// CB prefix — bit instructions (RLC, RRC, RL, RR, SLA, SRA, SRL, SLL, BIT, SET, RES).
    Cb,
    /// DD prefix — IX-register instructions.
    Dd,
    /// FD prefix — IY-register instructions.
    Fd,
    /// ED prefix — extended instructions (block moves, I/O, etc.).
    Ed,
    /// DD CB prefix — bit instructions operating on (IX+d).
    DdCb,
    /// FD CB prefix — bit instructions operating on (IY+d).
    FdCb,
}

impl Z80Prefix {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None  => "",
            Self::Cb    => "CB",
            Self::Dd    => "DD",
            Self::Fd    => "FD",
            Self::Ed    => "ED",
            Self::DdCb  => "DDCB",
            Self::FdCb  => "FDCB",
        }
    }
}

// ── Operand encoding ──────────────────────────────────────────────────────────

/// An operand to a Z80 instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Z80Operand {
    /// 8-bit register (B/C/D/E/H/L/A).
    Reg8(u8),
    /// 16-bit register pair (0=BC, 1=DE, 2=HL, 3=SP).
    Reg16(u8),
    /// IX register (used as 16-bit pair by DD prefix).
    RegIX,
    /// IY register (used as 16-bit pair by FD prefix).
    RegIY,
    /// Accumulator.
    A,
    /// Flags register.
    F,
    /// (HL) indirect.
    MemHL,
    /// (BC) indirect.
    MemBC,
    /// (DE) indirect.
    MemDE,
    /// (SP) indirect.
    MemSP,
    /// (IX+d) indirect with signed 8-bit displacement.
    MemIXd(i8),
    /// (IY+d) indirect with signed 8-bit displacement.
    MemIYd(i8),
    /// (nn) direct 16-bit address.
    MemNN(u16),
    /// Immediate 8-bit value.
    Imm8(u8),
    /// Immediate 16-bit value.
    Imm16(u16),
    /// Signed 8-bit relative branch offset.
    Rel8(i8),
    /// Absolute 16-bit jump target (JP/CALL).
    Abs16(u16),
    /// Condition code (NZ/Z/NC/C/PO/PE/P/M).
    Cond(u8),
    /// RST target (0x00, 0x08, 0x10, ..., 0x38).
    RstTarget(u8),
    /// I/O port: C register.
    PortC,
    /// I/O port: immediate 8-bit port number.
    PortImm(u8),
    /// Special: (C) for IN r,(C) / OUT (C),r.
    RegC,
    /// Bit number (0-7) for BIT/SET/RES.
    BitNum(u8),
    /// Interrupt mode (0/1/2) for IM instruction.
    IntMode(u8),
    /// SP+d for LD HL,(SP+d) — undocumented extension.
    SpDisp(i8),
    /// AF register pair (accumulator + flags, used by EX AF,AF').
    RegAF,
    /// Alternate AF' register pair (used by EX AF,AF').
    RegAF2,
    /// Interrupt page-address register (I).
    RegI,
    /// Memory-refresh register (R).
    RegR,
}

impl Z80Operand {
    const fn reg8_name(r: u8) -> &'static str {
        match r { 0=>"B",1=>"C",2=>"D",3=>"E",4=>"H",5=>"L",6=>"(HL)",7=>"A",_=>"?" }
    }
    const fn reg16_name(r: u8) -> &'static str {
        match r { 0=>"BC",1=>"DE",2=>"HL",3=>"SP",_=>"?" }
    }
    const fn cond_name(c: u8) -> &'static str {
        match c { 0=>"NZ",1=>"Z",2=>"NC",3=>"C",4=>"PO",5=>"PE",6=>"P",7=>"M",_=>"?" }
    }
}

impl core::fmt::Display for Z80Operand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reg8(r)     => f.write_str(Self::reg8_name(*r)),
            Self::Reg16(r)    => f.write_str(Self::reg16_name(*r)),
            Self::RegIX       => f.write_str("IX"),
            Self::RegIY       => f.write_str("IY"),
            Self::A           => f.write_str("A"),
            Self::F           => f.write_str("F"),
            Self::MemHL       => f.write_str("(HL)"),
            Self::MemBC       => f.write_str("(BC)"),
            Self::MemDE       => f.write_str("(DE)"),
            Self::MemSP       => f.write_str("(SP)"),
            Self::MemIXd(d)   => write!(f, "(IX{d:+})"),
            Self::MemIYd(d)   => write!(f, "(IY{d:+})"),
            Self::MemNN(n)    => write!(f, "(0x{n:04x})"),
            Self::Imm8(v)     => write!(f, "0x{v:02x}"),
            Self::Imm16(v)    => write!(f, "0x{v:04x}"),
            Self::Rel8(d)     => write!(f, "{d:+}"),
            Self::Abs16(a)    => write!(f, "0x{a:04x}"),
            Self::Cond(c)     => f.write_str(Self::cond_name(*c)),
            Self::RstTarget(t)=> write!(f, "0x{t:02x}"),
            Self::PortC       => f.write_str("(C)"),
            Self::PortImm(p)  => write!(f, "(0x{p:02x})"),
            Self::RegC        => f.write_str("C"),
            Self::BitNum(b)   => write!(f, "{b}"),
            Self::IntMode(m)  => write!(f, "{m}"),
            Self::SpDisp(d)   => write!(f, "SP{d:+}"),
            Self::RegAF       => f.write_str("AF"),
            Self::RegAF2      => f.write_str("AF'"),
            Self::RegI        => f.write_str("I"),
            Self::RegR        => f.write_str("R"),
        }
    }
}

// ── Decoded instruction ───────────────────────────────────────────────────────

/// Control-flow properties of a [`Z80Instr`], one per bit.
///
/// Replaces five separate `bool` fields. The bit order is fixed and part of
/// the type's contract, so a packed value is stable across builds:
///
/// | bit | flag |
/// |-----|------|
/// | 0   | [`Self::BRANCH`] |
/// | 1   | [`Self::CONDITIONAL`] |
/// | 2   | [`Self::CALL`] |
/// | 3   | [`Self::RET`] |
/// | 4   | [`Self::HALT`] |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Z80InstrFlags(u8);

impl Z80InstrFlags {
    /// No control-flow property set (a plain sequential instruction).
    pub const NONE: Self = Self(0);
    /// This is a branch, jump, call or return.
    pub const BRANCH: Self = Self(1 << 0);
    /// The branch is taken only when a condition holds.
    pub const CONDITIONAL: Self = Self(1 << 1);
    /// This is a `CALL` or `RST`.
    pub const CALL: Self = Self(1 << 2);
    /// This is a `RET` / `RETN` / `RETI`.
    pub const RET: Self = Self(1 << 3);
    /// This is a `HALT`.
    pub const HALT: Self = Self(1 << 4);

    /// Return a copy with `other`'s bits also set.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when every bit of `other` is set in `self`.
    #[must_use]
    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The raw packed bits, in the documented bit order.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// A fully decoded Z80 instruction.
#[derive(Clone, Debug)]
pub struct Z80Instr {
    /// Raw bytes of the instruction.
    pub bytes: [u8; 4],
    /// Length of the instruction in bytes (1-4).
    pub len: u8,
    /// Prefix(es) present.
    pub prefix: Z80Prefix,
    /// Mnemonic string.
    pub mnemonic: &'static str,
    /// Up to 2 operands.
    pub operands: [Option<Z80Operand>; 2],
    /// Control-flow properties of this instruction, packed one per bit.
    pub flags: Z80InstrFlags,
    /// Absolute branch target if computable at decode time (PC-relative already resolved).
    pub branch_target: Option<u16>,
}

impl Z80Instr {
    const fn new(prefix: Z80Prefix, mnemonic: &'static str, len: u8) -> Self {
        Self {
            bytes: [0u8; 4],
            len,
            prefix,
            mnemonic,
            operands: [None, None],
            flags: Z80InstrFlags::NONE,
            branch_target: None,
        }
    }

    const fn op0(mut self, op: Z80Operand) -> Self { self.operands[0] = Some(op); self }
    const fn op1(mut self, op: Z80Operand) -> Self { self.operands[1] = Some(op); self }
    const fn branch(mut self) -> Self { self.flags = self.flags.with(Z80InstrFlags::BRANCH); self }
    const fn cond(mut self) -> Self   { self.flags = self.flags.with(Z80InstrFlags::CONDITIONAL); self }
    const fn call(mut self) -> Self   { self.flags = self.flags.with(Z80InstrFlags::CALL).with(Z80InstrFlags::BRANCH); self }
    const fn ret(mut self) -> Self    { self.flags = self.flags.with(Z80InstrFlags::RET).with(Z80InstrFlags::BRANCH); self }
    const fn halt(mut self) -> Self   { self.flags = self.flags.with(Z80InstrFlags::HALT); self }

    /// True if this is a branch/jump/call/return.
    #[must_use]
    pub const fn is_branch(&self) -> bool { self.flags.has(Z80InstrFlags::BRANCH) }
    /// True if the branch is conditional.
    #[must_use]
    pub const fn is_conditional(&self) -> bool { self.flags.has(Z80InstrFlags::CONDITIONAL) }
    /// True if this is a CALL or RST.
    #[must_use]
    pub const fn is_call(&self) -> bool { self.flags.has(Z80InstrFlags::CALL) }
    /// True if this is a RET / RETN / RETI.
    #[must_use]
    pub const fn is_ret(&self) -> bool { self.flags.has(Z80InstrFlags::RET) }
    /// True if this is a HALT.
    #[must_use]
    pub const fn is_halt(&self) -> bool { self.flags.has(Z80InstrFlags::HALT) }
    const fn target(mut self, t: u16) -> Self { self.branch_target = Some(t); self }
    fn raw(mut self, raw: &[u8]) -> Self {
        for (i, &b) in raw.iter().enumerate().take(4) { self.bytes[i] = b; }
        self
    }
}

impl core::fmt::Display for Z80Instr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.mnemonic)?;
        if let Some(op) = &self.operands[0] {
            write!(f, " {op}")?;
            if let Some(op2) = &self.operands[1] {
                write!(f, ",{op2}")?;
            }
        }
        Ok(())
    }
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Z80 instruction decoder.
pub struct Z80Decoder {
    /// Treat undocumented IXH/IXL/IYH/IYL as valid.
    pub undocumented: bool,
}

impl Z80Decoder {
    #[must_use]
    pub const fn new() -> Self { Self { undocumented: true } }

    /// Decode one instruction from `bytes` at virtual address `pc`.
    /// Returns `None` if bytes is empty or truncated.
    #[must_use]
    pub fn decode(&self, pc: u16, bytes: &[u8]) -> Option<Z80Instr> {
        if bytes.is_empty() { return None; }
        match bytes[0] {
            0xCB => {
                if bytes.len() < 2 { return None; }
                Some(Self::decode_cb(pc, &bytes[1..]))
            }
            0xDD => {
                if bytes.len() < 2 { return None; }
                if bytes[1] == 0xCB {
                    // DDCB prefix requires 4 bytes (DD CB d op); truncated input
                    // must return None rather than mis-routing to the DD table.
                    if bytes.len() < 4 { return None; }
                    Some(Self::decode_ddcb(pc, &bytes[2..]))
                } else {
                    Some(Self::decode_dd(pc, &bytes[1..]))
                }
            }
            0xFD => {
                if bytes.len() < 2 { return None; }
                if bytes[1] == 0xCB {
                    // FDCB prefix requires 4 bytes (FD CB d op); truncated input
                    // must return None rather than mis-routing to the FD table.
                    if bytes.len() < 4 { return None; }
                    Some(Self::decode_fdcb(pc, &bytes[2..]))
                } else {
                    Some(Self::decode_fd(pc, &bytes[1..]))
                }
            }
            0xED => {
                if bytes.len() < 2 { return None; }
                Some(Self::decode_ed(pc, &bytes[1..]))
            }
            b => Some(Self::decode_main(pc, b, bytes)),
        }
    }

    // ── Main unprefixed table ────────────────────────────────────────────────

    /// x=0: NOP/EX, relative jumps, 16-bit loads, INC/DEC and the accumulator ops.
    fn decode_main_x0(pc: u16, x: u8, y: u8, z: u8, bytes: &[u8]) -> Result<Z80Instr, Z80Instr> {
        Ok(match (x, y, z) {
            (0, 0, 0) => Z80Instr::new(Z80Prefix::None, "NOP", 1),
            (0, 1, 0) => Z80Instr::new(Z80Prefix::None, "EX", 1)
                .op0(Z80Operand::RegAF).op1(Z80Operand::RegAF2),
            (0, 2, 0) => { // DJNZ e
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let off = bytes[1].cast_signed();
                let target = pc.wrapping_add(2).wrapping_add(i16::from(off).cast_unsigned());
                Z80Instr::new(Z80Prefix::None, "DJNZ", 2)
                    .op0(Z80Operand::Rel8(off)).branch().cond().target(target)
                    .raw(bytes)
            }
            (0, 3, 0) => { // JR e
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let off = bytes[1].cast_signed();
                let target = pc.wrapping_add(2).wrapping_add(i16::from(off).cast_unsigned());
                Z80Instr::new(Z80Prefix::None, "JR", 2)
                    .op0(Z80Operand::Rel8(off)).branch().target(target).raw(bytes)
            }
            (0, cc @ 4..=7, 0) => { // JR cc,e  (cc=NZ/Z/NC/C → bits 0..3)
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let off = bytes[1].cast_signed();
                let target = pc.wrapping_add(2).wrapping_add(i16::from(off).cast_unsigned());
                Z80Instr::new(Z80Prefix::None, "JR", 2)
                    .op0(Z80Operand::Cond(cc - 4))
                    .op1(Z80Operand::Rel8(off))
                    .branch().cond().target(target).raw(bytes)
            }
            (0, rr, 1) if z == 1 && (y & 1) == 0 => { // LD rr,nn
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "LD", 3)
                    .op0(Z80Operand::Reg16(rr >> 1)).op1(Z80Operand::Imm16(nn)).raw(bytes)
            }
            (0, rr, 1) if z == 1 && (y & 1) == 1 => { // ADD HL,rr
                Z80Instr::new(Z80Prefix::None, "ADD", 1)
                    .op0(Z80Operand::Reg16(2)).op1(Z80Operand::Reg16(rr >> 1))
            }
            (0, 0, 2) => Z80Instr::new(Z80Prefix::None, "LD", 1).op0(Z80Operand::MemBC).op1(Z80Operand::A),
            (0, 1, 2) => Z80Instr::new(Z80Prefix::None, "LD", 1).op0(Z80Operand::A).op1(Z80Operand::MemBC),
            (0, 2, 2) => Z80Instr::new(Z80Prefix::None, "LD", 1).op0(Z80Operand::MemDE).op1(Z80Operand::A),
            (0, 3, 2) => Z80Instr::new(Z80Prefix::None, "LD", 1).op0(Z80Operand::A).op1(Z80Operand::MemDE),
            (0, 4, 2) => { // LD (nn),HL
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "LD", 3).op0(Z80Operand::MemNN(nn)).op1(Z80Operand::Reg16(2)).raw(bytes)
            }
            (0, 5, 2) => { // LD HL,(nn)
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "LD", 3).op0(Z80Operand::Reg16(2)).op1(Z80Operand::MemNN(nn)).raw(bytes)
            }
            (0, 6, 2) => { // LD (nn),A
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "LD", 3).op0(Z80Operand::MemNN(nn)).op1(Z80Operand::A).raw(bytes)
            }
            (0, 7, 2) => { // LD A,(nn)
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "LD", 3).op0(Z80Operand::A).op1(Z80Operand::MemNN(nn)).raw(bytes)
            }
            (0, rr, 3) if z == 3 && (y & 1) == 0 => // INC rr
                Z80Instr::new(Z80Prefix::None, "INC", 1).op0(Z80Operand::Reg16(rr >> 1)),
            (0, rr, 3) if z == 3 && (y & 1) == 1 => // DEC rr
                Z80Instr::new(Z80Prefix::None, "DEC", 1).op0(Z80Operand::Reg16(rr >> 1)),
            (0, r, 4) => // INC r
                Z80Instr::new(Z80Prefix::None, "INC", 1).op0(Z80Operand::Reg8(r)),
            (0, r, 5) => // DEC r
                Z80Instr::new(Z80Prefix::None, "DEC", 1).op0(Z80Operand::Reg8(r)),
            (0, r, 6) => { // LD r,n
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                Z80Instr::new(Z80Prefix::None, "LD", 2)
                    .op0(Z80Operand::Reg8(r)).op1(Z80Operand::Imm8(bytes[1])).raw(bytes)
            }
            (0, 0, 7) => Z80Instr::new(Z80Prefix::None, "RLCA", 1),
            (0, 1, 7) => Z80Instr::new(Z80Prefix::None, "RRCA", 1),
            (0, 2, 7) => Z80Instr::new(Z80Prefix::None, "RLA",  1),
            (0, 3, 7) => Z80Instr::new(Z80Prefix::None, "RRA",  1),
            (0, 4, 7) => Z80Instr::new(Z80Prefix::None, "DAA",  1),
            (0, 5, 7) => Z80Instr::new(Z80Prefix::None, "CPL",  1),
            (0, 6, 7) => Z80Instr::new(Z80Prefix::None, "SCF",  1),
            (0, 7, 7) => Z80Instr::new(Z80Prefix::None, "CCF",  1),

            _ => Z80Instr::new(Z80Prefix::None, "???", 1),
        })
    }

    /// x=3: RET/POP/PUSH, JP and CALL, the I/O forms, ALU A,n and RST.
    fn decode_main_x3(x: u8, y: u8, z: u8, bytes: &[u8]) -> Result<Z80Instr, Z80Instr> {
        Ok(match (x, y, z) {
            (3, cc, 0) => // RET cc
                Z80Instr::new(Z80Prefix::None, "RET", 1).op0(Z80Operand::Cond(cc)).ret().cond(),
            (3, rr, 1) if z == 1 && (y & 1) == 0 => { // POP rr (uses rp2: p=3 → AF not SP)
                let op0 = if rr >> 1 == 3 { Z80Operand::RegAF } else { Z80Operand::Reg16(rr >> 1) };
                Z80Instr::new(Z80Prefix::None, "POP", 1).op0(op0)
            }
            (3, 1, 1) => // RET
                Z80Instr::new(Z80Prefix::None, "RET", 1).ret(),
            (3, 3, 1) => // EXX
                Z80Instr::new(Z80Prefix::None, "EXX", 1),
            (3, 5, 1) => // JP (HL)
                Z80Instr::new(Z80Prefix::None, "JP", 1).op0(Z80Operand::MemHL).branch(),
            (3, 7, 1) => // LD SP,HL
                Z80Instr::new(Z80Prefix::None, "LD", 1).op0(Z80Operand::Reg16(3)).op1(Z80Operand::Reg16(2)),
            (3, cc, 2) => { // JP cc,nn
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "JP", 3)
                    .op0(Z80Operand::Cond(cc)).op1(Z80Operand::Abs16(nn))
                    .branch().cond().target(nn).raw(bytes)
            }
            (3, 0, 3) => { // JP nn
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "JP", 3)
                    .op0(Z80Operand::Abs16(nn)).branch().target(nn).raw(bytes)
            }
            (3, 2, 3) => { // OUT (n),A
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                Z80Instr::new(Z80Prefix::None, "OUT", 2)
                    .op0(Z80Operand::PortImm(bytes[1])).op1(Z80Operand::A).raw(bytes)
            }
            (3, 3, 3) => { // IN A,(n)
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                Z80Instr::new(Z80Prefix::None, "IN", 2)
                    .op0(Z80Operand::A).op1(Z80Operand::PortImm(bytes[1])).raw(bytes)
            }
            (3, 4, 3) => Z80Instr::new(Z80Prefix::None, "EX", 1).op0(Z80Operand::MemSP).op1(Z80Operand::Reg16(2)),
            (3, 5, 3) => Z80Instr::new(Z80Prefix::None, "EX", 1).op0(Z80Operand::Reg16(1)).op1(Z80Operand::Reg16(2)),
            (3, 6, 3) => Z80Instr::new(Z80Prefix::None, "DI",  1),
            (3, 7, 3) => Z80Instr::new(Z80Prefix::None, "EI",  1),
            (3, cc, 4) => { // CALL cc,nn
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "CALL", 3)
                    .op0(Z80Operand::Cond(cc)).op1(Z80Operand::Abs16(nn))
                    .call().cond().target(nn).raw(bytes)
            }
            (3, rr, 5) if z == 5 && (y & 1) == 0 => { // PUSH rr (uses rp2: p=3 → AF not SP)
                let op0 = if rr >> 1 == 3 { Z80Operand::RegAF } else { Z80Operand::Reg16(rr >> 1) };
                Z80Instr::new(Z80Prefix::None, "PUSH", 1).op0(op0)
            }
            (3, 1, 5) => { // CALL nn
                if bytes.len() < 3 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::None, "CALL", 3)
                    .op0(Z80Operand::Abs16(nn)).call().target(nn).raw(bytes)
            }
            (3, op, 6) => { // ALU A,n
                if bytes.len() < 2 { return Err(Z80Instr::new(Z80Prefix::None, "???", 1)); }
                let mne = alu_mnemonic(op);
                Z80Instr::new(Z80Prefix::None, mne, 2)
                    .op0(Z80Operand::A).op1(Z80Operand::Imm8(bytes[1])).raw(bytes)
            }
            (3, t, 7) => { // RST
                let target = u16::from(t) * 8;
                Z80Instr::new(Z80Prefix::None, "RST", 1)
                    .op0(Z80Operand::RstTarget(t * 8)).call().target(target)
            }
            _ => Z80Instr::new(Z80Prefix::None, "???", 1),
        })
    }

    fn decode_main(pc: u16, opcode: u8, bytes: &[u8]) -> Z80Instr {
        let x = (opcode >> 6) & 3;
        let y = (opcode >> 3) & 7;
        let z = opcode & 7;

        let mut instr = match (x, y, z) {
            // x=0 block
            (0, _, _) => match Self::decode_main_x0(pc, x, y, z, bytes) {
                Ok(i) => i,
                Err(i) => return i,
            },
            // x=1: LD r,r' / HALT
            (1, 6, 6) => Z80Instr::new(Z80Prefix::None, "HALT", 1).halt(),
            (1, dst, src) =>
                Z80Instr::new(Z80Prefix::None, "LD", 1)
                    .op0(Z80Operand::Reg8(dst)).op1(Z80Operand::Reg8(src)),

            // x=2: ALU A,r
            (2, op, r) => {
                let mne = alu_mnemonic(op);
                if op == 7 { // CP has only one operand
                    Z80Instr::new(Z80Prefix::None, mne, 1).op0(Z80Operand::Reg8(r))
                } else {
                    Z80Instr::new(Z80Prefix::None, mne, 1).op0(Z80Operand::A).op1(Z80Operand::Reg8(r))
                }
            }

            // x=3 block
            (3, _, _) => match Self::decode_main_x3(x, y, z, bytes) {
                Ok(i) => i,
                Err(i) => return i,
            },
            _ => Z80Instr::new(Z80Prefix::None, "???", 1),
        };
        if instr.bytes[0] == 0 { instr.bytes[0] = opcode; }
        instr
    }

    // ── CB prefix ────────────────────────────────────────────────────────────

    fn decode_cb(_pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.is_empty() { return Z80Instr::new(Z80Prefix::Cb, "???", 2); }
        let op = bytes[0];
        let x = (op >> 6) & 3;
        let y = (op >> 3) & 7;
        let z = op & 7;
        let raw = [0xCBu8, op, 0, 0];
        let _ = raw;
        match x {
            0 => {
                let mne = rot_mnemonic(y);
                Z80Instr::new(Z80Prefix::Cb, mne, 2).op0(Z80Operand::Reg8(z))
            }
            1 => Z80Instr::new(Z80Prefix::Cb, "BIT", 2).op0(Z80Operand::BitNum(y)).op1(Z80Operand::Reg8(z)),
            2 => Z80Instr::new(Z80Prefix::Cb, "RES", 2).op0(Z80Operand::BitNum(y)).op1(Z80Operand::Reg8(z)),
            3 => Z80Instr::new(Z80Prefix::Cb, "SET", 2).op0(Z80Operand::BitNum(y)).op1(Z80Operand::Reg8(z)),
            _ => Z80Instr::new(Z80Prefix::Cb, "???", 2),
        }
    }

    // ── DD prefix (IX instructions) ──────────────────────────────────────────

    fn decode_dd(pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.is_empty() { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
        match bytes[0] {
            0x21 => { // LD IX,nn
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Dd, "LD", 4).op0(Z80Operand::RegIX).op1(Z80Operand::Imm16(nn))
            }
            0x22 => { // LD (nn),IX
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Dd, "LD", 4).op0(Z80Operand::MemNN(nn)).op1(Z80Operand::RegIX)
            }
            0x2A => { // LD IX,(nn)
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Dd, "LD", 4).op0(Z80Operand::RegIX).op1(Z80Operand::MemNN(nn))
            }
            0xE9 => Z80Instr::new(Z80Prefix::Dd, "JP", 2).op0(Z80Operand::RegIX).branch(),
            0x23 => Z80Instr::new(Z80Prefix::Dd, "INC", 2).op0(Z80Operand::RegIX),
            0x2B => Z80Instr::new(Z80Prefix::Dd, "DEC", 2).op0(Z80Operand::RegIX),
            0xF9 => Z80Instr::new(Z80Prefix::Dd, "LD",  2).op0(Z80Operand::Reg16(3)).op1(Z80Operand::RegIX),
            0x36 => { // LD (IX+d),n
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Dd, "LD", 4).op0(Z80Operand::MemIXd(d)).op1(Z80Operand::Imm8(bytes[2]))
            }
            op if (op & 0xC7) == 0x46 => { // LD r,(IX+d)
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let r = (op >> 3) & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Dd, "LD", 3).op0(Z80Operand::Reg8(r)).op1(Z80Operand::MemIXd(d))
            }
            op if (op & 0xF8) == 0x70 => { // LD (IX+d),r
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let r = op & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Dd, "LD", 3).op0(Z80Operand::MemIXd(d)).op1(Z80Operand::Reg8(r))
            }
            op if (op & 0xC7) == 0x86 => { // ALU A,(IX+d)
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Dd, "???", 2); }
                let alu = (op >> 3) & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Dd, alu_mnemonic(alu), 3)
                    .op0(Z80Operand::A).op1(Z80Operand::MemIXd(d))
            }
            0x09 => Z80Instr::new(Z80Prefix::Dd, "ADD", 2).op0(Z80Operand::RegIX).op1(Z80Operand::Reg16(0)),
            0x19 => Z80Instr::new(Z80Prefix::Dd, "ADD", 2).op0(Z80Operand::RegIX).op1(Z80Operand::Reg16(1)),
            0x29 => Z80Instr::new(Z80Prefix::Dd, "ADD", 2).op0(Z80Operand::RegIX).op1(Z80Operand::RegIX),
            0x39 => Z80Instr::new(Z80Prefix::Dd, "ADD", 2).op0(Z80Operand::RegIX).op1(Z80Operand::Reg16(3)),
            0xE5 => Z80Instr::new(Z80Prefix::Dd, "PUSH", 2).op0(Z80Operand::RegIX),
            0xE1 => Z80Instr::new(Z80Prefix::Dd, "POP",  2).op0(Z80Operand::RegIX),
            0xE3 => Z80Instr::new(Z80Prefix::Dd, "EX",   2).op0(Z80Operand::MemSP).op1(Z80Operand::RegIX),
            _ => {
                // Fall through to main table decoding (prefix ignored for non-IX opcodes).
                let mut i = Self::decode_main(pc, bytes[0], bytes);
                i.len += 1; i.prefix = Z80Prefix::Dd; i
            }
        }
    }

    // ── FD prefix (IY instructions) ──────────────────────────────────────────

    fn decode_fd(pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.is_empty() { return Z80Instr::new(Z80Prefix::Fd, "???", 2); }
        // Mirror of DD, substituting IX→IY
        match bytes[0] {
            0x21 => {
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Fd, "???", 2); }
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Fd, "LD", 4).op0(Z80Operand::RegIY).op1(Z80Operand::Imm16(nn))
            }
            0xE9 => Z80Instr::new(Z80Prefix::Fd, "JP", 2).op0(Z80Operand::RegIY).branch(),
            0x23 => Z80Instr::new(Z80Prefix::Fd, "INC", 2).op0(Z80Operand::RegIY),
            0x2B => Z80Instr::new(Z80Prefix::Fd, "DEC", 2).op0(Z80Operand::RegIY),
            op if (op & 0xC7) == 0x46 => {
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Fd, "???", 2); }
                let r = (op >> 3) & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Fd, "LD", 3).op0(Z80Operand::Reg8(r)).op1(Z80Operand::MemIYd(d))
            }
            op if (op & 0xF8) == 0x70 => {
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Fd, "???", 2); }
                let r = op & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Fd, "LD", 3).op0(Z80Operand::MemIYd(d)).op1(Z80Operand::Reg8(r))
            }
            op if (op & 0xC7) == 0x86 => {
                if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::Fd, "???", 2); }
                let alu = (op >> 3) & 7;
                let d = bytes[1].cast_signed();
                Z80Instr::new(Z80Prefix::Fd, alu_mnemonic(alu), 3)
                    .op0(Z80Operand::A).op1(Z80Operand::MemIYd(d))
            }
            0xE5 => Z80Instr::new(Z80Prefix::Fd, "PUSH", 2).op0(Z80Operand::RegIY),
            0xE1 => Z80Instr::new(Z80Prefix::Fd, "POP",  2).op0(Z80Operand::RegIY),
            _ => {
                let mut i = Self::decode_main(pc, bytes[0], bytes);
                i.len += 1; i.prefix = Z80Prefix::Fd; i
            }
        }
    }

    // ── ED prefix ────────────────────────────────────────────────────────────

    fn decode_ed(_pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.is_empty() { return Z80Instr::new(Z80Prefix::Ed, "???", 2); }
        let op = bytes[0];
        match op {
            0x44 => Z80Instr::new(Z80Prefix::Ed, "NEG",  2),
            0x45 => Z80Instr::new(Z80Prefix::Ed, "RETN", 2).ret(),
            0x4D => Z80Instr::new(Z80Prefix::Ed, "RETI", 2).ret(),
            0x46 => Z80Instr::new(Z80Prefix::Ed, "IM",   2).op0(Z80Operand::IntMode(0)),
            0x56 => Z80Instr::new(Z80Prefix::Ed, "IM",   2).op0(Z80Operand::IntMode(1)),
            0x5E => Z80Instr::new(Z80Prefix::Ed, "IM",   2).op0(Z80Operand::IntMode(2)),
            0x47 => Z80Instr::new(Z80Prefix::Ed, "LD",   2).op0(Z80Operand::RegI).op1(Z80Operand::A), // LD I,A
            0x4F => Z80Instr::new(Z80Prefix::Ed, "LD",   2).op0(Z80Operand::RegR).op1(Z80Operand::A), // LD R,A
            0x57 => Z80Instr::new(Z80Prefix::Ed, "LD",   2).op0(Z80Operand::A).op1(Z80Operand::RegI), // LD A,I
            0x5F => Z80Instr::new(Z80Prefix::Ed, "LD",   2).op0(Z80Operand::A).op1(Z80Operand::RegR), // LD A,R
            0x67 => Z80Instr::new(Z80Prefix::Ed, "RRD",  2),
            0x6F => Z80Instr::new(Z80Prefix::Ed, "RLD",  2),
            0xA0 => Z80Instr::new(Z80Prefix::Ed, "LDI",  2),
            0xA1 => Z80Instr::new(Z80Prefix::Ed, "CPI",  2),
            0xA2 => Z80Instr::new(Z80Prefix::Ed, "INI",  2),
            0xA3 => Z80Instr::new(Z80Prefix::Ed, "OUTI", 2),
            0xA8 => Z80Instr::new(Z80Prefix::Ed, "LDD",  2),
            0xA9 => Z80Instr::new(Z80Prefix::Ed, "CPD",  2),
            0xAA => Z80Instr::new(Z80Prefix::Ed, "IND",  2),
            0xAB => Z80Instr::new(Z80Prefix::Ed, "OUTD", 2),
            0xB0 => Z80Instr::new(Z80Prefix::Ed, "LDIR", 2),
            0xB1 => Z80Instr::new(Z80Prefix::Ed, "CPIR", 2),
            0xB2 => Z80Instr::new(Z80Prefix::Ed, "INIR", 2),
            0xB3 => Z80Instr::new(Z80Prefix::Ed, "OTIR", 2),
            0xB8 => Z80Instr::new(Z80Prefix::Ed, "LDDR", 2),
            0xB9 => Z80Instr::new(Z80Prefix::Ed, "CPDR", 2),
            0xBA => Z80Instr::new(Z80Prefix::Ed, "INDR", 2),
            0xBB => Z80Instr::new(Z80Prefix::Ed, "OTDR", 2),
            op if (op & 0xCF) == 0x43 => { // LD (nn),rr
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Ed, "???", 2); }
                let rr = (op >> 4) & 3;
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Ed, "LD", 4).op0(Z80Operand::MemNN(nn)).op1(Z80Operand::Reg16(rr))
            }
            op if (op & 0xCF) == 0x4B => { // LD rr,(nn)
                if bytes.len() < 3 { return Z80Instr::new(Z80Prefix::Ed, "???", 2); }
                let rr = (op >> 4) & 3;
                let nn = u16::from(bytes[1]) | (u16::from(bytes[2]) << 8);
                Z80Instr::new(Z80Prefix::Ed, "LD", 4).op0(Z80Operand::Reg16(rr)).op1(Z80Operand::MemNN(nn))
            }
            op if (op & 0xC7) == 0x40 => { // IN r,(C)
                let r = (op >> 3) & 7;
                Z80Instr::new(Z80Prefix::Ed, "IN", 2).op0(Z80Operand::Reg8(r)).op1(Z80Operand::PortC)
            }
            op if (op & 0xC7) == 0x41 => { // OUT (C),r
                let r = (op >> 3) & 7;
                Z80Instr::new(Z80Prefix::Ed, "OUT", 2).op0(Z80Operand::PortC).op1(Z80Operand::Reg8(r))
            }
            op if (op & 0xCF) == 0x4A => { // ADC HL,rr
                let rr = (op >> 4) & 3;
                Z80Instr::new(Z80Prefix::Ed, "ADC", 2).op0(Z80Operand::Reg16(2)).op1(Z80Operand::Reg16(rr))
            }
            op if (op & 0xCF) == 0x42 => { // SBC HL,rr
                let rr = (op >> 4) & 3;
                Z80Instr::new(Z80Prefix::Ed, "SBC", 2).op0(Z80Operand::Reg16(2)).op1(Z80Operand::Reg16(rr))
            }
            _ => Z80Instr::new(Z80Prefix::Ed, "???", 2),
        }
    }

    // ── DDCB prefix ───────────────────────────────────────────────────────────

    fn decode_ddcb(_pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::DdCb, "???", 4); }
        let d    = bytes[0].cast_signed();
        let op   = bytes[1];
        let x = (op >> 6) & 3;
        let y = (op >> 3) & 7;
        match x {
            0 => Z80Instr::new(Z80Prefix::DdCb, rot_mnemonic(y), 4).op0(Z80Operand::MemIXd(d)),
            1 => Z80Instr::new(Z80Prefix::DdCb, "BIT", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIXd(d)),
            2 => Z80Instr::new(Z80Prefix::DdCb, "RES", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIXd(d)),
            3 => Z80Instr::new(Z80Prefix::DdCb, "SET", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIXd(d)),
            _ => Z80Instr::new(Z80Prefix::DdCb, "???", 4),
        }
    }

    // ── FDCB prefix ───────────────────────────────────────────────────────────

    fn decode_fdcb(_pc: u16, bytes: &[u8]) -> Z80Instr {
        if bytes.len() < 2 { return Z80Instr::new(Z80Prefix::FdCb, "???", 4); }
        let d    = bytes[0].cast_signed();
        let op   = bytes[1];
        let x = (op >> 6) & 3;
        let y = (op >> 3) & 7;
        match x {
            0 => Z80Instr::new(Z80Prefix::FdCb, rot_mnemonic(y), 4).op0(Z80Operand::MemIYd(d)),
            1 => Z80Instr::new(Z80Prefix::FdCb, "BIT", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIYd(d)),
            2 => Z80Instr::new(Z80Prefix::FdCb, "RES", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIYd(d)),
            3 => Z80Instr::new(Z80Prefix::FdCb, "SET", 4).op0(Z80Operand::BitNum(y)).op1(Z80Operand::MemIYd(d)),
            _ => Z80Instr::new(Z80Prefix::FdCb, "???", 4),
        }
    }
}

impl Default for Z80Decoder {
    fn default() -> Self { Self::new() }
}

const fn alu_mnemonic(op: u8) -> &'static str {
    match op & 7 {
        0 => "ADD", 1 => "ADC", 2 => "SUB", 3 => "SBC",
        4 => "AND", 5 => "XOR", 6 => "OR",  7 => "CP",
        _ => "???",
    }
}

const fn rot_mnemonic(op: u8) -> &'static str {
    match op & 7 {
        0 => "RLC", 1 => "RRC", 2 => "RL", 3 => "RR",
        4 => "SLA", 5 => "SRA", 6 => "SLL",7 => "SRL",
        _ => "???",
    }
}

// ── Linear iterator ───────────────────────────────────────────────────────────

/// Iterates over Z80 instructions in a byte slice.
pub struct Z80DecoderIter<'a> {
    decoder: Z80Decoder,
    bytes: &'a [u8],
    offset: usize,
    pc: u16,
}

impl<'a> Z80DecoderIter<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8], start_pc: u16) -> Self {
        Z80DecoderIter { decoder: Z80Decoder::new(), bytes, offset: 0, pc: start_pc }
    }

    #[must_use]
    pub const fn current_pc(&self) -> u16 { self.pc }
    #[must_use]
    pub const fn offset(&self) -> usize { self.offset }
}

impl Iterator for Z80DecoderIter<'_> {
    type Item = (u16, Z80Instr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() { return None; }
        let instr = self.decoder.decode(self.pc, &self.bytes[self.offset..])?;
        let pc = self.pc;
        self.offset += instr.len as usize;
        self.pc = self.pc.wrapping_add(u16::from(instr.len));
        Some((pc, instr))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> Z80Decoder { Z80Decoder::new() }

    #[test]
    fn nop() {
        let i = dec().decode(0, &[0x00]).unwrap();
        assert_eq!(i.mnemonic, "NOP");
        assert_eq!(i.len, 1);
    }

    #[test]
    fn halt() {
        let i = dec().decode(0, &[0x76]).unwrap();
        assert_eq!(i.mnemonic, "HALT");
        assert!(i.is_halt());
    }

    #[test]
    fn ld_hl_nn() {
        let i = dec().decode(0, &[0x21, 0x34, 0x12]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.len, 3);
        assert!(matches!(i.operands[1], Some(Z80Operand::Imm16(0x1234))));
    }

    #[test]
    fn jp_nn() {
        let i = dec().decode(0, &[0xC3, 0x00, 0x80]).unwrap();
        assert_eq!(i.mnemonic, "JP");
        assert!(i.is_branch());
        assert!(!i.is_conditional());
        assert_eq!(i.branch_target, Some(0x8000));
    }

    #[test]
    fn jr_nz() {
        let i = dec().decode(0x100, &[0x20, 0xFE]).unwrap();
        assert_eq!(i.mnemonic, "JR");
        assert!(i.is_conditional());
        // JR NZ, -2: target = 0x100 + 2 + (-2) = 0x100
        assert_eq!(i.branch_target, Some(0x100));
    }

    #[test]
    fn call_nn() {
        let i = dec().decode(0, &[0xCD, 0x56, 0x34]).unwrap();
        assert_eq!(i.mnemonic, "CALL");
        assert!(i.is_call());
        assert_eq!(i.branch_target, Some(0x3456));
    }

    #[test]
    fn ret() {
        let i = dec().decode(0, &[0xC9]).unwrap();
        assert_eq!(i.mnemonic, "RET");
        assert!(i.is_ret());
    }

    #[test]
    fn cb_bit() {
        let i = dec().decode(0, &[0xCB, 0x47]).unwrap(); // BIT 0,A
        assert_eq!(i.mnemonic, "BIT");
        assert!(matches!(i.operands[0], Some(Z80Operand::BitNum(0))));
    }

    #[test]
    fn dd_ld_ix_nn() {
        let i = dec().decode(0, &[0xDD, 0x21, 0xFF, 0x00]).unwrap();
        assert_eq!(i.mnemonic, "LD");
        assert_eq!(i.len, 4);
        assert!(matches!(i.operands[0], Some(Z80Operand::RegIX)));
    }

    #[test]
    fn ed_ldir() {
        let i = dec().decode(0, &[0xED, 0xB0]).unwrap();
        assert_eq!(i.mnemonic, "LDIR");
    }

    #[test]
    fn ed_reti() {
        let i = dec().decode(0, &[0xED, 0x4D]).unwrap();
        assert_eq!(i.mnemonic, "RETI");
        assert!(i.is_ret());
    }

    #[test]
    fn iter_linear() {
        let bytes = [0x00u8, 0x76, 0xC9]; // NOP, HALT, RET
        let instrs: Vec<_> = Z80DecoderIter::new(&bytes, 0x0000).collect();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].1.mnemonic, "NOP");
        assert_eq!(instrs[1].1.mnemonic, "HALT");
        assert_eq!(instrs[2].1.mnemonic, "RET");
    }

    #[test]
    fn rst_target() {
        let i = dec().decode(0, &[0xFF]).unwrap(); // RST 0x38
        assert_eq!(i.mnemonic, "RST");
        assert_eq!(i.branch_target, Some(0x38));
    }
}
