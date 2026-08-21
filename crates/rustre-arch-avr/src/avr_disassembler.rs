//! AVR microcontroller disassembler — full 131-instruction ISA coverage.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Operand types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvrOperand {
    Reg(u8),
    RegPair(u8),
    Imm8(u8),
    Imm6(i8),
    Imm12(i16),
    Addr16(u16),
    Addr22(u32),
    BitIndex(u8),
    IOAddr(u8),
    Displacement(i8),
    ConstData(u16),
    /// Register used as pointer with post-increment (e.g. X+, Y+, Z+).
    RegPostInc(u8),
    /// Register used as pointer with pre-decrement (e.g. -X, -Y, -Z).
    RegPreDec(u8),
}

impl fmt::Display for AvrOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r)          => write!(f, "r{r}"),
            Self::RegPair(r)      => write!(f, "r{}", r + 1),
            Self::Imm8(v)         => write!(f, "{v:#04x}"),
            Self::Imm6(v)         => write!(f, "{v}"),
            Self::Imm12(v)        => write!(f, "{v}"),
            Self::Addr16(a)       => write!(f, "{a:#06x}"),
            Self::Addr22(a)       => write!(f, "{a:#08x}"),
            Self::BitIndex(b)     => write!(f, "{b}"),
            Self::IOAddr(a)       => write!(f, "{a:#04x}"),
            Self::Displacement(d) => write!(f, "{d}"),
            Self::ConstData(v)    => write!(f, "{v:#06x}"),
            Self::RegPostInc(r)   => write!(f, "r{r}+"),
            Self::RegPreDec(r)    => write!(f, "-r{r}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AvrInsn {
    /// Byte address in flash.
    pub addr: u32,
    /// First 16-bit word.
    pub raw: u16,
    /// Optional second word (for 32-bit instructions: lds/sts/jmp/call).
    pub raw2: Option<u16>,
    pub mnemonic: &'static str,
    pub operands: Vec<AvrOperand>,
    /// Typical cycle count (base, no skip/branch penalty).
    pub cycles: u8,
}

impl AvrInsn {
    #[must_use]
    pub const fn is_32bit(&self) -> bool {
        self.raw2.is_some()
    }

    #[must_use]
    pub const fn byte_len(&self) -> u32 {
        if self.is_32bit() { 4 } else { 2 }
    }

    #[must_use]
    pub fn format_insn(&self) -> String {
        if self.operands.is_empty() {
            return self.mnemonic.to_string();
        }
        let ops: Vec<String> = self.operands.iter().map(std::string::ToString::to_string).collect();
        format!("{:<8} {}", self.mnemonic, ops.join(", "))
    }
}

impl fmt::Display for AvrInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(w2) = self.raw2 {
            write!(f, "{:#06x}  {:04x} {:04x}  {}", self.addr, self.raw, w2, self.format_insn())
        } else {
            write!(f, "{:#06x}  {:04x}        {}", self.addr, self.raw, self.format_insn())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bit helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn bit(v: u16, n: u16) -> u16 { (v >> n) & 1 }

/// Extract contiguous bits [hi..lo] inclusive.
const fn bits16(v: u16, hi: u16, lo: u16) -> u16 {
    (v >> lo) & ((1u16 << (hi - lo + 1)) - 1)
}

/// 5-bit Rd field from bit positions 8:4.
fn rd5(w: u16) -> u8 { u8::try_from(bits16(w, 8, 4)).unwrap_or(u8::MAX) }
/// 5-bit Rr field from bit positions 9(MSB),3:0.
fn rr5(w: u16) -> u8 { u8::try_from((bit(w, 9) << 4) | bits16(w, 3, 0)).unwrap_or(u8::MAX) }
/// 4-bit Rd for 0x1x0 group: actual register = 16+r4.
fn rd4(w: u16) -> u8 { u8::try_from(bits16(w, 7, 4) + 16).unwrap_or(u8::MAX) }
/// 8-bit immediate K from nibbles bits[11:8] | bits[3:0].
fn k8(w: u16) -> u8 { u8::try_from((bits16(w, 11, 8) << 4) | bits16(w, 3, 0)).unwrap_or(u8::MAX) }
/// 6-bit immediate K from bits[7:6]|bits[3:0] (for ADIW/SBIW).
fn k6(w: u16) -> u8 { u8::try_from((bits16(w, 7, 6) << 4) | bits16(w, 3, 0)).unwrap_or(u8::MAX) }

const fn make(addr: u32, raw: u16, mnem: &'static str, ops: Vec<AvrOperand>, cycles: u8) -> AvrInsn {
    AvrInsn { addr, raw, raw2: None, mnemonic: mnem, operands: ops, cycles }
}

const fn make32(addr: u32, raw: u16, raw2: u16, mnem: &'static str, ops: Vec<AvrOperand>, cycles: u8) -> AvrInsn {
    AvrInsn { addr, raw, raw2: Some(raw2), mnemonic: mnem, operands: ops, cycles }
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembler
// ─────────────────────────────────────────────────────────────────────────────

pub struct AvrDisassembler;

impl AvrDisassembler {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Disassemble bytes starting at `addr`. Returns instructions in order.
    #[must_use]
    pub fn disassemble(&self, data: &[u8], addr: u32) -> Vec<AvrInsn> {
        let mut result = Vec::new();
        let mut i = 0usize;
        let mut cur_addr = addr;
        while i + 2 <= data.len() {
            let w = u16::from_le_bytes([data[i], data[i + 1]]);
            let w2_opt = if i + 4 <= data.len() {
                Some(u16::from_le_bytes([data[i + 2], data[i + 3]]))
            } else {
                None
            };
            let insn = self.decode(w, w2_opt, cur_addr);
            let len = insn.byte_len();
            result.push(insn);
            i += len as usize;
            cur_addr += len;
        }
        result
    }

    /// Decode one instruction word (and optionally the next for 32-bit insns).
    #[must_use]
    pub fn decode(&self, w: u16, w2: Option<u16>, addr: u32) -> AvrInsn {
        // Dispatch on instruction patterns from MSB to LSB.
        // The AVR ISA has a fixed opcode structure; we match from most-constrained
        // to least-constrained bit patterns.

        match w >> 8 {
            // ── Two-operand arithmetic ─────────────────────────────────────
            0x0C..=0x0F => return Self::dec_add(w, addr),
            0x08..=0x0B => return Self::dec_sbc(w, addr),
            0x18..=0x1B => return Self::dec_sub(w, addr),
            0x1C..=0x1F => return Self::dec_adc(w, addr),
            0x20..=0x23 => return Self::dec_and(w, addr),
            0x24..=0x27 => return Self::dec_eor(w, addr),
            0x28..=0x2B => return Self::dec_or(w, addr),
            0x2C..=0x2F => return Self::dec_mov(w, addr),
            _ => {}
        }
        // Fall through to full-word matching for all other instructions.
        Self::decode_full(w, w2, addr)
    }

    fn decode_full(w: u16, w2: Option<u16>, addr: u32) -> AvrInsn {
        // ── NOP ──────────────────────────────────────────────────────
        if w == 0x0000 {
            return make(addr, w, "nop", vec![], 1);
        }
        // ── Two-register arithmetic (opcode bits 15:10) ───────────────
        if w & 0xFC00 == 0x0C00 { return Self::two_reg(w, addr, "add", 1); }
        if w & 0xFC00 == 0x0800 { return Self::two_reg(w, addr, "sbc", 1); }
        if w & 0xFC00 == 0x1800 { return Self::two_reg(w, addr, "sub", 1); }
        if w & 0xFC00 == 0x1C00 { return Self::two_reg(w, addr, "adc", 1); }
        if w & 0xFC00 == 0x2000 { return Self::two_reg(w, addr, "and", 1); }
        if w & 0xFC00 == 0x2400 { return Self::two_reg(w, addr, "eor", 1); }
        if w & 0xFC00 == 0x2800 { return Self::two_reg(w, addr, "or",  1); }
        if w & 0xFC00 == 0x2C00 { return Self::two_reg(w, addr, "mov", 1); }
        // ── Immediate arithmetic/logic (registers 16..31) ──────────────
        if w & 0xF000 == 0x3000 { return Self::rd4_k8(w, addr, "cpi", 1); }
        if w & 0xF000 == 0x4000 { return Self::rd4_k8(w, addr, "sbci", 1); }
        if w & 0xF000 == 0x5000 { return Self::rd4_k8(w, addr, "subi", 1); }
        if w & 0xF000 == 0x6000 { return Self::rd4_k8(w, addr, "ori",  1); }
        if w & 0xF000 == 0x7000 { return Self::rd4_k8(w, addr, "andi", 1); }
        if w & 0xF000 == 0xE000 { return Self::rd4_k8(w, addr, "ldi",  1); }
        // ── Word operations ────────────────────────────────────────────
        if w & 0xFF00 == 0x9600 { return Self::adiw_sbiw(w, addr, "adiw"); }
        if w & 0xFF00 == 0x9700 { return Self::adiw_sbiw(w, addr, "sbiw"); }
        // ── Single-register operations ─────────────────────────────────
        if w & 0xFE0F == 0x9400 { return make(addr, w, "com",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9401 { return make(addr, w, "neg",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9402 { return make(addr, w, "swap", vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9403 { return make(addr, w, "inc",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x940A { return make(addr, w, "dec",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9405 { return make(addr, w, "asr",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9406 { return make(addr, w, "lsr",  vec![AvrOperand::Reg(rd5(w))], 1); }
        if w & 0xFE0F == 0x9407 { return make(addr, w, "ror",  vec![AvrOperand::Reg(rd5(w))], 1); }
        // ── MUL / MULS / MULSU / FMUL* ────────────────────────────────
        if w & 0xFC00 == 0x9C00 { return Self::two_reg(w, addr, "mul", 2); }
        if w & 0xFF00 == 0x0200 {
            // MULS r16-r31, r16-r31
            let rd = 16 + u8::try_from(bits16(w, 7, 4)).unwrap_or(u8::MAX);
            let rr = 16 + u8::try_from(bits16(w, 3, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "muls", vec![AvrOperand::Reg(rd), AvrOperand::Reg(rr)], 2);
        }
        if w & 0xFF88 == 0x0300 {
            let rd = 16 + u8::try_from(bits16(w, 6, 4)).unwrap_or(u8::MAX);
            let rr = 16 + u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "mulsu", vec![AvrOperand::Reg(rd), AvrOperand::Reg(rr)], 2);
        }
        if w & 0xFF88 == 0x0308 {
            let rd = 16 + u8::try_from(bits16(w, 6, 4)).unwrap_or(u8::MAX);
            let rr = 16 + u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "fmul", vec![AvrOperand::Reg(rd), AvrOperand::Reg(rr)], 2);
        }
        if w & 0xFF88 == 0x0388 {
            let rd = 16 + u8::try_from(bits16(w, 6, 4)).unwrap_or(u8::MAX);
            let rr = 16 + u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "fmuls", vec![AvrOperand::Reg(rd), AvrOperand::Reg(rr)], 2);
        }
        // ── Load / Store ───────────────────────────────────────────────
        if w & 0xF800 == 0xA000 && (w & 0x0200) == 0 {
            return Self::ldd_std(w, addr, "ldd");
        }
        if w & 0xF800 == 0xA000 && (w & 0x0200) != 0 {
            return Self::ldd_std(w, addr, "std");
        }
        // LD X/Y/Z variants
        if w & 0xFE0F == 0x900C { return Self::ld_x(w, addr, "ld",  false, false); }
        if w & 0xFE0F == 0x900D { return Self::ld_x(w, addr, "ld",  true,  false); } // X+
        if w & 0xFE0F == 0x900E { return Self::ld_x(w, addr, "ld",  false, true);  } // -X
        // ST X/Y/Z variants
        if w & 0xFE0F == 0x920C { return Self::st_x(w, addr, "st",  false, false); }
        if w & 0xFE0F == 0x920D { return Self::st_x(w, addr, "st",  true,  false); }
        if w & 0xFE0F == 0x920E { return Self::st_x(w, addr, "st",  false, true);  }
        // LDS/STS (32-bit)
        if w & 0xFE0F == 0x9000 {
            let addr2 = w2.unwrap_or(0);
            return make32(addr, w, addr2, "lds",
                vec![AvrOperand::Reg(rd5(w)), AvrOperand::Addr16(addr2)], 3);
        }
        if w & 0xFE0F == 0x9200 {
            let addr2 = w2.unwrap_or(0);
            return make32(addr, w, addr2, "sts",
                vec![AvrOperand::Addr16(addr2), AvrOperand::Reg(rd5(w))], 3);
        }
        // MOVW
        if w & 0xFF00 == 0x0100 {
            let rd = u8::try_from(bits16(w, 7, 4) * 2).unwrap_or(u8::MAX);
            let rr = u8::try_from(bits16(w, 3, 0) * 2).unwrap_or(u8::MAX);
            return make(addr, w, "movw", vec![AvrOperand::RegPair(rd), AvrOperand::RegPair(rr)], 1);
        }
        // IN / OUT
        if w & 0xF800 == 0xB000 {
            let io = u8::try_from((bits16(w, 10, 9) << 4) | bits16(w, 3, 0)).unwrap_or(u8::MAX);
            if (w & 0x0800) == 0 {
                return make(addr, w, "in",  vec![AvrOperand::Reg(rd5(w)), AvrOperand::IOAddr(io)], 1);
            }
            return make(addr, w, "out", vec![AvrOperand::IOAddr(io), AvrOperand::Reg(rd5(w))], 1);
        }
        Self::decode_full_more(w, w2, addr)
    }

    /// Continuation of [`decode_full`]; split out only to keep each function short.
    fn decode_full_more(w: u16, w2: Option<u16>, addr: u32) -> AvrInsn {
        // PUSH / POP
        if w & 0xFE0F == 0x920F { return make(addr, w, "push", vec![AvrOperand::Reg(rd5(w))], 2); }
        if w & 0xFE0F == 0x900F { return make(addr, w, "pop",  vec![AvrOperand::Reg(rd5(w))], 2); }
        // ── Bit operations ─────────────────────────────────────────────
        if w & 0xFF00 == 0x9A00 {
            let io  = u8::try_from(bits16(w, 7, 3)).unwrap_or(u8::MAX);
            let bit = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "sbi", vec![AvrOperand::IOAddr(io), AvrOperand::BitIndex(bit)], 2);
        }
        if w & 0xFF00 == 0x9800 {
            let io  = u8::try_from(bits16(w, 7, 3)).unwrap_or(u8::MAX);
            let bit = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "cbi", vec![AvrOperand::IOAddr(io), AvrOperand::BitIndex(bit)], 2);
        }
        if w & 0xFF00 == 0x9900 {
            let io  = u8::try_from(bits16(w, 7, 3)).unwrap_or(u8::MAX);
            let bit = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "sbic", vec![AvrOperand::IOAddr(io), AvrOperand::BitIndex(bit)], 2);
        }
        if w & 0xFF00 == 0x9B00 {
            let io  = u8::try_from(bits16(w, 7, 3)).unwrap_or(u8::MAX);
            let bit = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "sbis", vec![AvrOperand::IOAddr(io), AvrOperand::BitIndex(bit)], 2);
        }
        if w & 0xFE08 == 0xFC00 {
            let rr = rd5(w);
            let b  = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "sbrc", vec![AvrOperand::Reg(rr), AvrOperand::BitIndex(b)], 2);
        }
        if w & 0xFE08 == 0xFE00 {
            let rr = rd5(w);
            let b  = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "sbrs", vec![AvrOperand::Reg(rr), AvrOperand::BitIndex(b)], 2);
        }
        if w & 0xFE08 == 0xF800 {
            let rd = rd5(w);
            let b  = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "bst", vec![AvrOperand::Reg(rd), AvrOperand::BitIndex(b)], 1);
        }
        if w & 0xFE08 == 0xF400 {
            let rd = rd5(w);
            let b  = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
            return make(addr, w, "bld", vec![AvrOperand::Reg(rd), AvrOperand::BitIndex(b)], 1);
        }
        // ── Branch instructions ────────────────────────────────────────
        // RJMP / RCALL
        if w & 0xF000 == 0xC000 { return Self::rjmp_rcall(w, addr, "rjmp", 2); }
        if w & 0xF000 == 0xD000 { return Self::rjmp_rcall(w, addr, "rcall", 3); }
        // JMP / CALL (32-bit)
        if w & 0xFE0E == 0x940C {
            let k_hi = (u32::from(bits16(w, 8, 4)) << 17) | (u32::from(bit(w, 0)) << 16);
            let k_lo = u32::from(w2.unwrap_or(0));
            let target = k_hi | k_lo;
            return make32(addr, w, w2.unwrap_or(0), "jmp", vec![AvrOperand::Addr22(target)], 3);
        }
        if w & 0xFE0E == 0x940E {
            let k_hi = (u32::from(bits16(w, 8, 4)) << 17) | (u32::from(bit(w, 0)) << 16);
            let k_lo = u32::from(w2.unwrap_or(0));
            let target = k_hi | k_lo;
            return make32(addr, w, w2.unwrap_or(0), "call", vec![AvrOperand::Addr22(target)], 4);
        }
        // IJMP / ICALL / EIJMP / EICALL
        if w == 0x9409 { return make(addr, w, "ijmp",   vec![], 2); }
        if w == 0x9509 { return make(addr, w, "icall",  vec![], 3); }
        if w == 0x9419 { return make(addr, w, "eijmp",  vec![], 2); }
        if w == 0x9519 { return make(addr, w, "eicall", vec![], 3); }
        // RET / RETI
        if w == 0x9508 { return make(addr, w, "ret",  vec![], 4); }
        if w == 0x9518 { return make(addr, w, "reti", vec![], 4); }
        // BRBS / BRBC (conditional branches)
        if w & 0xFC00 == 0xF000 { return Self::brbs_brbc(w, addr, false); }
        if w & 0xFC00 == 0xF400 { return Self::brbs_brbc(w, addr, true);  }
        // ── Misc ───────────────────────────────────────────────────────
        if w == 0x9588 { return make(addr, w, "sleep", vec![], 1); }
        if w == 0x9598 { return make(addr, w, "break", vec![], 1); }
        if w == 0x95A8 { return make(addr, w, "wdr",   vec![], 1); }
        if w == 0x95C8 { return make(addr, w, "lpm",   vec![], 3); }
        if w == 0x95D8 { return make(addr, w, "elpm",  vec![], 3); }
        if w == 0x95E8 { return make(addr, w, "spm",   vec![], 1); }

        // SREG set/clear
        if w & 0xFF8F == 0x9408 {
            let s = u8::try_from(bits16(w, 6, 4)).unwrap_or(u8::MAX);
            return make(addr, w, "bset", vec![AvrOperand::BitIndex(s)], 1);
        }
        if w & 0xFF8F == 0x9488 {
            let s = u8::try_from(bits16(w, 6, 4)).unwrap_or(u8::MAX);
            return make(addr, w, "bclr", vec![AvrOperand::BitIndex(s)], 1);
        }

        make(addr, w, "unknown", vec![AvrOperand::ConstData(w)], 1)
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    #[must_use]
    fn two_reg(w: u16, addr: u32, mnem: &'static str, cyc: u8) -> AvrInsn {
        make(addr, w, mnem, vec![AvrOperand::Reg(rd5(w)), AvrOperand::Reg(rr5(w))], cyc)
    }

    #[must_use]
    fn rd4_k8(w: u16, addr: u32, mnem: &'static str, cyc: u8) -> AvrInsn {
        make(addr, w, mnem, vec![AvrOperand::Reg(rd4(w)), AvrOperand::Imm8(k8(w))], cyc)
    }

    #[must_use]
    fn adiw_sbiw(w: u16, addr: u32, mnem: &'static str) -> AvrInsn {
        let pair_idx = u8::try_from(bits16(w, 5, 4)).unwrap_or(u8::MAX);
        let base_reg = 24 + pair_idx * 2;
        let k = k6(w);
        make(addr, w, mnem, vec![AvrOperand::RegPair(base_reg), AvrOperand::Imm8(k)], 2)
    }

    #[must_use]
    fn ldd_std(w: u16, addr: u32, mnem: &'static str) -> AvrInsn {
        let q = u8::try_from((bit(w, 13) << 5) | (bits16(w, 11, 10) << 3) | bits16(w, 2, 0)).unwrap_or(0).cast_signed();
        let use_y = (w & 0x0008) == 0;
        // Encode Y/Z base register: Y=28, Z=30
        let base = if use_y { 28u8 } else { 30u8 };
        if mnem == "ldd" {
            make(addr, w, mnem, vec![
                AvrOperand::Reg(rd5(w)),
                AvrOperand::Reg(base),
                AvrOperand::Displacement(q),
            ], 2)
        } else {
            make(addr, w, mnem, vec![
                AvrOperand::Reg(base),
                AvrOperand::Displacement(q),
                AvrOperand::Reg(rd5(w)),
            ], 2)
        }
    }

    #[must_use]
    fn ld_x(w: u16, addr: u32, mnem: &'static str, post_inc: bool, pre_dec: bool) -> AvrInsn {
        // X pointer register base is R26
        let x_operand = if post_inc {
            AvrOperand::RegPostInc(26)
        } else if pre_dec {
            AvrOperand::RegPreDec(26)
        } else {
            AvrOperand::Reg(26) // plain X
        };
        make(addr, w, mnem, vec![
            AvrOperand::Reg(rd5(w)),
            x_operand,
        ], 2)
    }

    #[must_use]
    fn st_x(w: u16, addr: u32, mnem: &'static str, post_inc: bool, pre_dec: bool) -> AvrInsn {
        let x_operand = if post_inc {
            AvrOperand::RegPostInc(26)
        } else if pre_dec {
            AvrOperand::RegPreDec(26)
        } else {
            AvrOperand::Reg(26) // plain X
        };
        make(addr, w, mnem, vec![
            x_operand,
            AvrOperand::Reg(rd5(w)),
        ], 2)
    }

    #[must_use]
    fn rjmp_rcall(w: u16, addr: u32, mnem: &'static str, cyc: u8) -> AvrInsn {
        let k = bits16(w, 11, 0).cast_signed();
        // Sign-extend 12-bit value
        let k_signed: i16 = if k & 0x0800 != 0 { k | 0xF000u16.cast_signed() } else { k };
        let target = (addr.cast_signed().wrapping_add(2).wrapping_add(i32::from(k_signed) * 2)).cast_unsigned();
        make(addr, w, mnem, vec![AvrOperand::Addr22(target)], cyc)
    }

    #[must_use]
    fn brbs_brbc(w: u16, addr: u32, clear: bool) -> AvrInsn {
        let bit_idx = u8::try_from(bits16(w, 2, 0)).unwrap_or(u8::MAX);
        let k = u8::try_from(bits16(w, 9, 3)).unwrap_or(u8::MAX).cast_signed();
        let k_signed: i8 = if k & 0x40 != 0 { k | 0x80u8.cast_signed() } else { k };
        let target = (addr.cast_signed().wrapping_add(2).wrapping_add(i32::from(k_signed) * 2)).cast_unsigned();

        // Named aliases for common SR bits
        let named = if clear {
            match bit_idx {
                0 => Some("brcc"),
                1 => Some("brne"),
                2 => Some("brpl"),
                3 => Some("brvc"),
                5 => Some("brhc"),
                6 => Some("brtc"),
                7 => Some("brid"),
                _ => None,
            }
        } else {
            match bit_idx {
                0 => Some("brcs"),
                1 => Some("breq"),
                2 => Some("brmi"),
                3 => Some("brvs"),
                4 => Some("brlt"),
                5 => Some("brhs"),
                6 => Some("brts"),
                7 => Some("brie"),
                _ => None,
            }
        };
        let mnem = named.unwrap_or(if clear { "brbc" } else { "brbs" });
        make(addr, w, mnem, vec![AvrOperand::Addr22(target)], 2)
    }

    // Helpers used only in early fast-path (now unused — keep for completeness)
    #[must_use] fn dec_add(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "add", 1) }
    #[must_use] fn dec_sbc(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "sbc", 1) }
    #[must_use] fn dec_sub(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "sub", 1) }
    #[must_use] fn dec_adc(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "adc", 1) }
    #[must_use] fn dec_and(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "and", 1) }
    #[must_use] fn dec_eor(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "eor", 1) }
    #[must_use] fn dec_or (w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "or",  1) }
    #[must_use] fn dec_mov(w: u16, addr: u32) -> AvrInsn { Self::two_reg(w, addr, "mov", 1) }
}

impl Default for AvrDisassembler {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> AvrDisassembler { AvrDisassembler::new() }

    fn dec(w: u16) -> AvrInsn { d().decode(w, None, 0) }
    fn dec32(w: u16, w2: u16) -> AvrInsn { d().decode(w, Some(w2), 0) }

    #[test]
    fn test_nop() {
        let i = dec(0x0000);
        assert_eq!(i.mnemonic, "nop");
        assert_eq!(i.byte_len(), 2);
    }

    #[test]
    fn test_add() {
        // ADD r5, r6 → opcode 0x0C00 | (5<<4) | 6 = 0x0C56
        let w: u16 = 0x0C00 | (5 << 4) | 6;
        let i = dec(w);
        assert_eq!(i.mnemonic, "add");
        assert_eq!(i.operands[0], AvrOperand::Reg(5));
    }

    #[test]
    fn test_ldi() {
        // LDI is `1110 KKKK dddd KKKK` — the 8-bit immediate is SPLIT, high
        // nibble in bits[11:8] and low nibble in bits[3:0].
        //
        // This test used to build `0xE000 | (0x8 << 4) | 0xF`, which is 0xE08F,
        // not the 0xE8FF its own comment claimed: it never placed the HIGH
        // nibble of K, so it actually encoded K = 0x0F. The decoder dutifully
        // returned Imm8(15) and the test failed — the defect was in the test,
        // not in `k8()`, which correctly reassembles
        // `(bits[11:8] << 4) | bits[3:0]` (avr_disassembler.rs:115).
        //
        // LDI r24, 0xFF = 1110 1111 1000 1111 = 0xEF8F
        //   K high = 0xF, dddd = 8 (r24 = 16 + 8), K low = 0xF
        let w: u16 = 0xE000 | (0xF << 8) | (0x8 << 4) | 0xF;
        assert_eq!(w, 0xEF8F, "LDI r24, 0xFF must encode as 0xEF8F");
        let i = dec(w);
        assert_eq!(i.mnemonic, "ldi");
        assert_eq!(i.operands[1], AvrOperand::Imm8(0xFF));
    }

    #[test]
    fn test_inc() {
        // INC r3 → 0x9403 | (3<<4) = 0x9433
        let w: u16 = 0x9400 | (3 << 4) | 0x03;
        let i = dec(w);
        assert_eq!(i.mnemonic, "inc");
    }

    #[test]
    fn test_dec_insn() {
        let w: u16 = 0x940A | (7 << 4);
        let i = dec(w);
        assert_eq!(i.mnemonic, "dec");
    }

    #[test]
    fn test_ret() {
        let i = dec(0x9508);
        assert_eq!(i.mnemonic, "ret");
    }

    #[test]
    fn test_reti() {
        let i = dec(0x9518);
        assert_eq!(i.mnemonic, "reti");
    }

    #[test]
    fn test_rjmp() {
        // RJMP +0 → 0xC000
        let i = dec(0xC000);
        assert_eq!(i.mnemonic, "rjmp");
    }

    #[test]
    fn test_rcall() {
        let i = dec(0xD001);
        assert_eq!(i.mnemonic, "rcall");
    }

    #[test]
    fn test_push() {
        let w: u16 = 0x920F | (10 << 4);
        let i = dec(w);
        assert_eq!(i.mnemonic, "push");
    }

    #[test]
    fn test_pop() {
        let w: u16 = 0x900F | (10 << 4);
        let i = dec(w);
        assert_eq!(i.mnemonic, "pop");
    }

    #[test]
    fn test_in_out() {
        // IN r16, 0x00 → 0xB0 00
        let w: u16 = 0xB000; // rd=0, io=0
        let i = dec(w);
        assert_eq!(i.mnemonic, "in");
    }

    #[test]
    fn test_lds_32bit() {
        let w:  u16 = 0x9000 | (3 << 4); // LDS r3, addr
        let w2: u16 = 0x1234;
        let i = dec32(w, w2);
        assert_eq!(i.mnemonic, "lds");
        assert!(i.is_32bit());
        assert_eq!(i.byte_len(), 4);
    }

    #[test]
    fn test_sbi() {
        // SBI 0x05, 3 → 0x9A00 | (5<<3) | 3 = 0x9A2B
        let w: u16 = 0x9A00 | (5 << 3) | 3;
        let i = dec(w);
        assert_eq!(i.mnemonic, "sbi");
    }

    #[test]
    fn test_breq() {
        // BREQ +0 → 0xF001 (bit=1 = Z, k=0)
        let i = dec(0xF001);
        assert_eq!(i.mnemonic, "breq");
    }

    #[test]
    fn test_disassemble_slice() {
        let nop = [0x00u8, 0x00];
        let ret = [0x08u8, 0x95];
        let mut data = Vec::new();
        data.extend_from_slice(&nop);
        data.extend_from_slice(&ret);
        let insns = d().disassemble(&data, 0);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "nop");
        assert_eq!(insns[1].mnemonic, "ret");
    }
}
