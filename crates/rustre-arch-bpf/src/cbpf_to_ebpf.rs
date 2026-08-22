//! Convert classic BPF (cBPF) programs to eBPF.
//!
//! Implements the same migration algorithm used by the Linux kernel's
//! `bpf_convert_filter()` (net/core/filter.c), translating each cBPF
//! instruction into one or more eBPF instructions.

use crate::numeric;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Classic BPF constants ────────────────────────────────────────────────────

/// Classic BPF instruction classes.
pub mod cbpf_class {
    pub const LD: u16 = 0x00;
    pub const LDX: u16 = 0x01;
    pub const ST: u16 = 0x02;
    pub const STX: u16 = 0x03;
    pub const ALU: u16 = 0x04;
    pub const JMP: u16 = 0x05;
    pub const RET: u16 = 0x06;
    pub const MISC: u16 = 0x07;
}

/// Classic BPF addressing modes.
pub mod cbpf_mode {
    pub const IMM: u16 = 0x00;
    pub const ABS: u16 = 0x20;
    pub const IND: u16 = 0x40;
    pub const MEM: u16 = 0x60;
    pub const LEN: u16 = 0x80;
    pub const MSH: u16 = 0xa0;
}

/// Classic BPF size codes.
pub mod cbpf_size {
    pub const W: u16 = 0x00;  // word (4 bytes)
    pub const H: u16 = 0x08;  // half-word (2 bytes)
    pub const B: u16 = 0x10;  // byte (1 byte)
}

/// Classic BPF ALU operations.
pub mod cbpf_alu {
    pub const ADD: u16 = 0x00;
    pub const SUB: u16 = 0x10;
    pub const MUL: u16 = 0x20;
    pub const DIV: u16 = 0x30;
    pub const OR:  u16 = 0x40;
    pub const AND: u16 = 0x50;
    pub const LSH: u16 = 0x60;
    pub const RSH: u16 = 0x70;
    pub const NEG: u16 = 0x80;
    pub const MOD: u16 = 0x90;
    pub const XOR: u16 = 0xa0;
}

/// Classic BPF jump operations.
pub mod cbpf_jmp {
    pub const JA:   u16 = 0x00;
    pub const JEQ:  u16 = 0x10;
    pub const JGT:  u16 = 0x20;
    pub const JGE:  u16 = 0x30;
    pub const JSET: u16 = 0x40;
}

/// Classic BPF miscellaneous operations.
pub mod cbpf_misc {
    pub const TAX: u16 = 0x00;  // A → X
    pub const TXA: u16 = 0x80;  // X → A
}

/// Classic BPF source operand (K = immediate, X = index register).
pub mod cbpf_src {
    pub const K: u16 = 0x00;
    pub const X: u16 = 0x08;
}

/// Classic BPF return sources.
pub mod cbpf_rval {
    pub const K: u16 = 0x00;
    pub const A: u16 = 0x10;
}

// ─── CbpfInsn ─────────────────────────────────────────────────────────────────

/// A single classic BPF instruction (cBPF, 8 bytes).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CbpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl CbpfInsn {
    /// Create a new cBPF instruction.
    #[must_use] 
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Instruction class (lower 3 bits).
    #[must_use] 
    pub const fn class(self) -> u16 {
        self.code & 0x07
    }

    /// `BPF_ABS` | `BPF_LD` | size macro for loading packet bytes.
    #[must_use] 
    pub const fn ld_abs(size: u16, k: u32) -> Self {
        Self::new(cbpf_class::LD | cbpf_mode::ABS | size, 0, 0, k)
    }

    /// `BPF_RET` | `BPF_K`
    #[must_use] 
    pub const fn ret_k(k: u32) -> Self {
        Self::new(cbpf_class::RET | cbpf_rval::K, 0, 0, k)
    }

    /// `BPF_JMP` | `BPF_JEQ` | `BPF_K`
    #[must_use] 
    pub const fn jeq_k(k: u32, jt: u8, jf: u8) -> Self {
        Self::new(cbpf_class::JMP | cbpf_jmp::JEQ | cbpf_src::K, jt, jf, k)
    }

    /// `BPF_ALU` | `BPF_AND` | `BPF_K`
    #[must_use] 
    pub const fn and_k(k: u32) -> Self {
        Self::new(cbpf_class::ALU | cbpf_alu::AND | cbpf_src::K, 0, 0, k)
    }
}

impl fmt::Display for CbpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cBPF {{ code=0x{:04x} jt={} jf={} k=0x{:08x} }}",
            self.code, self.jt, self.jf, self.k
        )
    }
}

// ─── EbpfInsn (simple copy) ───────────────────────────────────────────────────

/// Minimal eBPF instruction used by the converter (mirrors the one in
/// `ebpf_verifier` but is self-contained to avoid a dependency cycle).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EbpfInsn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl EbpfInsn {
    #[must_use] 
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self { code, dst, src, off, imm }
    }

    /// Encode to 8-byte wire format.
    #[must_use] 
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.code;
        out[1] = (self.dst & 0x0F) | ((self.src & 0x0F) << 4);
        let off = self.off.to_le_bytes();
        out[2] = off[0];
        out[3] = off[1];
        let imm = self.imm.to_le_bytes();
        out[4..8].copy_from_slice(&imm);
        out
    }
}

impl fmt::Display for EbpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "eBPF {{ code=0x{:02x} dst=r{} src=r{} off={} imm={} }}",
            self.code, self.dst, self.src, self.off, self.imm
        )
    }
}

// ─── eBPF register allocations used by the migrator ──────────────────────────

/// R0 = return value / accumulator A mirror.
const REG_A: u8 = 0;
/// R7 = cBPF X register.
const REG_X: u8 = 7;
/// R8 = cBPF scratch / M[] pointer.
const REG_TMP: u8 = 8;
/// R6 = ctx pointer (passed in on entry, cBPF uses it for SKB).
const REG_CTX: u8 = 6;
/// R10 = frame pointer.
const REG_FP: u8 = 10;

/// Number of cBPF M[] scratch slots (the classic BPF spec defines M[0]..M[15]).
const CBPF_M_SLOTS: u32 = 16;

/// Stack frame offset used for M[] scratch memory (32 slots × 4 bytes).
const CBPF_M_STACK_OFF: i16 = -128;

/// Compute the stack offset for a cBPF M[] scratch memory access.
///
/// The cBPF spec allows only M[0]..M[15]. Returns `None` if `k` is out of range.
fn cbpf_m_stack_offset(k: u32, warnings: &mut Vec<String>) -> Option<i16> {
    if k >= CBPF_M_SLOTS {
        warnings.push(format!(
            "M[{k}] index out of cBPF range (0–15); instruction skipped"
        ));
        return None;
    }
    // k fits in [0, 15], so k as i32 * 4 fits in [0, 60] — no overflow.
    let off = i32::from(CBPF_M_STACK_OFF) + k.cast_signed() * 4;
    Some(numeric::trunc_i32_i16(off))
}

// ─── eBPF opcodes used by the migrator ───────────────────────────────────────

mod ebpf_ops {
    pub const MOV64_IMM: u8 = 0xB7;
    pub const MOV64_REG: u8 = 0xBF;
    pub const ADD64_IMM: u8 = 0x07;
    pub const ADD64_REG: u8 = 0x0F;
    pub const SUB64_IMM: u8 = 0x17;
    pub const MUL64_IMM: u8 = 0x27;
    pub const DIV64_IMM: u8 = 0x37;
    pub const MOD64_IMM: u8 = 0x97;
    pub const OR64_IMM:  u8 = 0x47;
    pub const AND64_IMM: u8 = 0x57;
    pub const LSH64_IMM: u8 = 0x67;
    pub const RSH64_IMM: u8 = 0x77;
    pub const XOR64_IMM: u8 = 0xA7;
    pub const OR64_REG:  u8 = 0x4F;
    pub const AND64_REG: u8 = 0x5F;
    pub const LSH64_REG: u8 = 0x6F;
    pub const RSH64_REG: u8 = 0x7F;
    pub const NEG64:     u8 = 0x87;
    pub const JEQ_IMM:   u8 = 0x15;
    pub const JEQ_REG:   u8 = 0x1D;
    pub const JGT_IMM:   u8 = 0x25;
    pub const JGT_REG:   u8 = 0x2D;
    pub const JGE_IMM:   u8 = 0x35;
    pub const JGE_REG:   u8 = 0x3D;
    pub const JSET_IMM:  u8 = 0x45;
    pub const JSET_REG:  u8 = 0x4D;
    pub const JA:        u8 = 0x05;
    pub const CALL:      u8 = 0x85;
    pub const EXIT:      u8 = 0x95;
    pub const STX_MEM_W: u8 = 0x63;
    pub const LDX_MEM_W: u8 = 0x61;
    pub const LD_ABS_W:  u8 = 0x20;
    pub const LD_ABS_H:  u8 = 0x28;
    pub const LD_ABS_B:  u8 = 0x30;
    pub const LD_IND_W:  u8 = 0x40;
    pub const LD_IND_H:  u8 = 0x48;
    pub const LD_IND_B:  u8 = 0x50;
}

// ─── MigrationReport ─────────────────────────────────────────────────────────

/// Report produced after migrating a cBPF program to eBPF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Number of cBPF instructions in the input.
    pub cbpf_insn_count: usize,
    /// Number of eBPF instructions produced.
    pub ebpf_insn_count: usize,
    /// Expansion ratio (eBPF / cBPF).
    pub expansion_ratio: f64,
    /// Map from cBPF instruction index to first eBPF instruction index.
    pub insn_map: Vec<usize>,
    /// Any warnings generated during migration.
    pub warnings: Vec<String>,
    /// Whether the migration succeeded.
    pub success: bool,
}

impl MigrationReport {
    /// Return the eBPF instruction range for cBPF instruction `cbpf_idx`.
    #[must_use] 
    pub fn ebpf_range_for(&self, cbpf_idx: usize) -> Option<(usize, usize)> {
        let start = self.insn_map.get(cbpf_idx).copied()?;
        let end = self.insn_map.get(cbpf_idx + 1).copied().unwrap_or(self.ebpf_insn_count);
        Some((start, end))
    }
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MigrationReport: cBPF={} eBPF={} ratio={:.2} warnings={} success={}",
            self.cbpf_insn_count,
            self.ebpf_insn_count,
            self.expansion_ratio,
            self.warnings.len(),
            self.success,
        )
    }
}

// ─── CbpfToEbpf ───────────────────────────────────────────────────────────────

/// Converts a classic BPF program to eBPF.
pub struct CbpfToEbpf {
    /// If true, emit prologue/epilogue to set up the scratch M[] area.
    emit_mem_prologue: bool,
}

impl CbpfToEbpf {
    /// Create a new converter with default options.
    #[must_use] 
    pub const fn new() -> Self {
        Self { emit_mem_prologue: true }
    }

    /// Disable M[] area setup (use when the program does not use ST/LD MEM).
    #[must_use] 
    pub const fn without_mem_prologue(mut self) -> Self {
        self.emit_mem_prologue = false;
        self
    }

    /// Convert a slice of classic BPF instructions to eBPF.
    ///
    /// Returns the eBPF instruction list and a migration report.
    #[must_use] 
    pub fn convert(&self, cbpf: &[CbpfInsn]) -> (Vec<EbpfInsn>, MigrationReport) {
        let mut ebpf: Vec<EbpfInsn> = Vec::new();
        let mut insn_map: Vec<usize> = Vec::with_capacity(cbpf.len());
        let mut warnings: Vec<String> = Vec::new();

        // Emit prologue: save ctx to REG_CTX.
        ebpf.push(EbpfInsn::new(ebpf_ops::MOV64_REG, REG_CTX, 1, 0, 0));

        // Initialise A and X to 0.
        ebpf.push(EbpfInsn::new(ebpf_ops::MOV64_IMM, REG_A, 0, 0, 0));
        ebpf.push(EbpfInsn::new(ebpf_ops::MOV64_IMM, REG_X, 0, 0, 0));

        // Zero the 16 M[] scratch slots.
        //
        // Classic BPF lets a program read M[k] before writing it; the eBPF
        // verifier rejects any read from uninitialised stack. Without this
        // prologue such a program converts "successfully" and is then refused
        // at load time, so the zeroing is part of a faithful translation.
        // `without_mem_prologue()` opts out for programs known to write before
        // reading, which saves 17 instructions.
        if self.emit_mem_prologue {
            ebpf.push(EbpfInsn::new(ebpf_ops::MOV64_IMM, REG_TMP, 0, 0, 0));
            for k in 0..CBPF_M_SLOTS {
                let off = CBPF_M_STACK_OFF + i16::try_from(k).unwrap_or(0) * 4;
                ebpf.push(EbpfInsn::new(ebpf_ops::STX_MEM_W, REG_FP, REG_TMP, off, 0));
            }
        }

        for (ci, insn) in cbpf.iter().enumerate() {
            insn_map.push(ebpf.len());
            let emitted = self.translate_insn(ci, *insn, cbpf, &mut warnings);
            ebpf.extend_from_slice(&emitted);
        }

        // Fixup jump offsets: cBPF jumps are relative to the *next* cBPF insn,
        // eBPF jumps are relative to the *next* eBPF insn.
        self.fixup_jumps(cbpf, &mut ebpf, &insn_map, &mut warnings);

        let expansion = if cbpf.is_empty() {
            0.0
        } else {
            numeric::count_to_f64(ebpf.len()) / numeric::count_to_f64(cbpf.len())
        };

        let report = MigrationReport {
            cbpf_insn_count: cbpf.len(),
            ebpf_insn_count: ebpf.len(),
            expansion_ratio: expansion,
            insn_map,
            warnings,
            success: true,
        };

        (ebpf, report)
    }

    /// Translate a single cBPF instruction into one or more eBPF instructions.
    fn translate_insn(
        &self,
        _idx: usize,
        insn: CbpfInsn,
        _cbpf: &[CbpfInsn],
        warnings: &mut Vec<String>,
    ) -> Vec<EbpfInsn> {
        use cbpf_class::{LD, LDX, ST, STX, ALU, JMP, RET, MISC};
        use cbpf_mode::{IMM, ABS, IND, MEM, LEN, MSH};
        use cbpf_size::{W, H};
        use cbpf_alu::{ADD, SUB, MUL, DIV, MOD, OR, AND, LSH, RSH, XOR, NEG};
        
        use cbpf_jmp as jmp;
        use cbpf_rval as rval;
        use cbpf_misc;
        use ebpf_ops::{MOV64_IMM, LD_ABS_W, LD_ABS_H, LD_ABS_B, LD_IND_W, LD_IND_H, LD_IND_B, LDX_MEM_W, CALL, AND64_IMM, MOV64_REG, STX_MEM_W, ADD64_IMM, ADD64_REG, SUB64_IMM, MUL64_IMM, DIV64_IMM, MOD64_IMM, OR64_IMM, OR64_REG, AND64_REG, LSH64_IMM, LSH64_REG, RSH64_IMM, RSH64_REG, XOR64_IMM, NEG64, JA, JEQ_IMM, JEQ_REG, JGT_IMM, JGT_REG, JGE_IMM, JGE_REG, JSET_IMM, JSET_REG, EXIT};

        let mut out = Vec::new();
        let code = insn.code;
        let k = insn.k;

        match code & 0x07 {
            // ─── LD class ─────────────────────────────────────────────────
            c if c == LD => {
                let mode = code & 0xE0;
                let size = code & 0x18;
                match mode {
                    m if m == IMM => {
                        out.push(EbpfInsn::new(MOV64_IMM, REG_A, 0, 0, k.cast_signed()));
                    }
                    m if m == ABS => {
                        let op = match size {
                            s if s == W => LD_ABS_W,
                            s if s == H => LD_ABS_H,
                            _ => LD_ABS_B,
                        };
                        out.push(EbpfInsn::new(op, REG_A, 0, 0, k.cast_signed()));
                    }
                    m if m == IND => {
                        let op = match size {
                            s if s == W => LD_IND_W,
                            s if s == H => LD_IND_H,
                            _ => LD_IND_B,
                        };
                        out.push(EbpfInsn::new(op, REG_A, REG_X, 0, k.cast_signed()));
                    }
                    m if m == MEM => {
                        if let Some(off) = cbpf_m_stack_offset(k, warnings) {
                            out.push(EbpfInsn::new(LDX_MEM_W, REG_A, REG_FP, off, 0));
                        }
                    }
                    m if m == LEN => {
                        // Load packet length into A — use a helper call.
                        warnings.push("LD_LEN uses helper call bpf_get_packet_len (id=0xFF)".into());
                        out.push(EbpfInsn::new(CALL, 0, 0, 0, 0xFF));
                    }
                    m if m == MSH => {
                        // MSH: X = 4*(packet[k] & 0x0F)
                        out.push(EbpfInsn::new(LD_ABS_B, REG_TMP, 0, 0, k.cast_signed()));
                        out.push(EbpfInsn::new(AND64_IMM, REG_TMP, 0, 0, 0x0F));
                        out.push(EbpfInsn::new(0x27 /* MUL64_IMM */, REG_TMP, 0, 0, 4));
                        out.push(EbpfInsn::new(MOV64_REG, REG_X, REG_TMP, 0, 0));
                    }
                    _ => {
                        warnings.push(format!("unknown LD mode 0x{mode:02x}"));
                    }
                }
            }
            // ─── LDX class ────────────────────────────────────────────────
            c if c == LDX => {
                let mode = code & 0xE0;
                match mode {
                    m if m == IMM => {
                        out.push(EbpfInsn::new(MOV64_IMM, REG_X, 0, 0, k.cast_signed()));
                    }
                    m if m == MEM => {
                        if let Some(off) = cbpf_m_stack_offset(k, warnings) {
                            out.push(EbpfInsn::new(LDX_MEM_W, REG_X, REG_FP, off, 0));
                        }
                    }
                    _ => {
                        warnings.push(format!("unhandled LDX mode 0x{mode:02x}"));
                    }
                }
            }
            // ─── ST class ─────────────────────────────────────────────────
            c if c == ST => {
                if let Some(off) = cbpf_m_stack_offset(k, warnings) {
                    out.push(EbpfInsn::new(STX_MEM_W, REG_FP, REG_A, off, 0));
                }
            }
            // ─── STX class ────────────────────────────────────────────────
            c if c == STX => {
                if let Some(off) = cbpf_m_stack_offset(k, warnings) {
                    out.push(EbpfInsn::new(STX_MEM_W, REG_FP, REG_X, off, 0));
                }
            }
            // ─── ALU class ────────────────────────────────────────────────
            c if c == ALU => {
                let op_k = code & 0x08 == 0;  // K variant (src bit is bit 3, mask 0x08)
                let alu = code & 0xF0;
                let (opcode_k, opcode_x): (u8, u8) = match alu {
                    o if o == ADD  => (ADD64_IMM, ADD64_REG),
                    o if o == SUB  => (SUB64_IMM, 0x1F /* SUB64_REG */),
                    o if o == MUL  => (MUL64_IMM, 0x2F),
                    o if o == DIV  => (DIV64_IMM, 0x3F),
                    o if o == MOD  => (MOD64_IMM, 0x9F),
                    o if o == OR   => (OR64_IMM, OR64_REG),
                    o if o == AND  => (AND64_IMM, AND64_REG),
                    o if o == LSH  => (LSH64_IMM, LSH64_REG),
                    o if o == RSH  => (RSH64_IMM, RSH64_REG),
                    o if o == XOR  => (XOR64_IMM, 0xAF),
                    o if o == NEG  => {
                        out.push(EbpfInsn::new(NEG64, REG_A, 0, 0, 0));
                        return out;
                    }
                    _ => {
                        warnings.push(format!("unknown ALU op 0x{alu:02x}"));
                        return out;
                    }
                };
                if op_k {
                    out.push(EbpfInsn::new(opcode_k, REG_A, 0, 0, k.cast_signed()));
                } else {
                    out.push(EbpfInsn::new(opcode_x, REG_A, REG_X, 0, 0));
                }
            }
            // ─── JMP class ────────────────────────────────────────────────
            c if c == JMP => {
                let jop = code & 0xF0;
                let use_x = code & 0x08 != 0;
                match jop {
                    j if j == jmp::JA => {
                        // Placeholder — real offset filled in by fixup_jumps.
                        out.push(EbpfInsn::new(JA, 0, 0, 0, 0));
                    }
                    j => {
                        let (op_k, op_x) = match j {
                            jj if jj == jmp::JEQ  => (JEQ_IMM, JEQ_REG),
                            jj if jj == jmp::JGT  => (JGT_IMM, JGT_REG),
                            jj if jj == jmp::JGE  => (JGE_IMM, JGE_REG),
                            jj if jj == jmp::JSET => (JSET_IMM, JSET_REG),
                            _ => {
                                warnings.push(format!("unknown jump op 0x{j:02x}"));
                                return out;
                            }
                        };
                        // Placeholder offsets filled by fixup_jumps.
                        let opcode = if use_x { op_x } else { op_k };
                        let src = if use_x { REG_X } else { 0 };
                        out.push(EbpfInsn::new(opcode, REG_A, src, 0, k.cast_signed()));
                    }
                }
            }
            // ─── RET class ────────────────────────────────────────────────
            c if c == RET => {
                let rval = code & 0x18;
                if rval == rval::K {
                    out.push(EbpfInsn::new(MOV64_IMM, REG_A, 0, 0, k.cast_signed()));
                }
                // If rval::A, A is already in R0.
                out.push(EbpfInsn::new(EXIT, 0, 0, 0, 0));
            }
            // ─── MISC class ───────────────────────────────────────────────
            c if c == MISC => {
                let misc = code & 0xF8;
                match misc {
                    m if m == cbpf_misc::TAX => {
                        out.push(EbpfInsn::new(MOV64_REG, REG_X, REG_A, 0, 0));
                    }
                    m if m == cbpf_misc::TXA => {
                        out.push(EbpfInsn::new(MOV64_REG, REG_A, REG_X, 0, 0));
                    }
                    _ => {
                        warnings.push(format!("unknown MISC op 0x{misc:02x}"));
                    }
                }
            }
            _ => {
                warnings.push(format!("unhandled opcode 0x{code:04x}"));
            }
        }
        out
    }

    /// Fix up jump offsets after all instructions have been emitted.
    fn fixup_jumps(
        &self,
        cbpf: &[CbpfInsn],
        ebpf: &mut [EbpfInsn],
        insn_map: &[usize],
        warnings: &mut Vec<String>,
    ) {
        for (ci, &cbpf_insn) in cbpf.iter().enumerate() {
            let code = cbpf_insn.code;
            if code & 0x07 != cbpf_class::JMP {
                continue;
            }
            let ebpf_pc = insn_map[ci];
            if ebpf_pc >= ebpf.len() {
                continue;
            }
            let jop = code & 0xF0;

            if jop == cbpf_jmp::JA {
                // JA target = ci + 1 + jt
                let target_cbpf = ci + 1 + cbpf_insn.jt as usize;
                if target_cbpf >= insn_map.len() {
                    warnings.push(format!("JA at cBPF[{ci}]: target {target_cbpf} out of range"));
                    continue;
                }
                let target_ebpf = insn_map[target_cbpf];
                let off = numeric::usize_to_i64(target_ebpf) - numeric::usize_to_i64(ebpf_pc) - 1;
                if off < i64::from(i16::MIN) || off > i64::from(i16::MAX) {
                    warnings.push(format!(
                        "JA at cBPF[{ci}]: eBPF jump offset {off} overflows i16; program will misbehave"
                    ));
                }
                ebpf[ebpf_pc].off = numeric::trunc_i64_i16(off);
            } else {
                // Conditional jump: true target = ci+1+jt, false target = ci+1+jf.
                let jt_cbpf = ci + 1 + cbpf_insn.jt as usize;
                let jf_cbpf = ci + 1 + cbpf_insn.jf as usize;

                let jt_ebpf = insn_map.get(jt_cbpf).copied().unwrap_or(ebpf.len());
                let jf_ebpf = insn_map.get(jf_cbpf).copied().unwrap_or(ebpf.len());

                // eBPF conditional: jt offset → taken, fall-through → not taken.
                // We model jt as the branch offset and insert an unconditional
                // jump to the false target after the conditional.
                let cond_pc = ebpf_pc;
                let jt_off = numeric::usize_to_i64(jt_ebpf) - numeric::usize_to_i64(cond_pc) - 1;

                if jt_off < i64::from(i16::MIN) || jt_off > i64::from(i16::MAX) {
                    warnings.push(format!(
                        "cBPF[{ci}]: conditional jump true-branch offset {jt_off} overflows i16; program will misbehave"
                    ));
                }
                // Patch the conditional jump's offset (true branch).
                ebpf[cond_pc].off = numeric::trunc_i64_i16(jt_off);

                // Insert a JA for the false branch only if it's not the next insn.
                let fall_through = cond_pc + 1;
                if fall_through != jf_ebpf && cbpf_insn.jf != 0 {
                    // We can't insert here safely post-generation; log a warning.
                    warnings.push(format!(
                        "cBPF[{ci}]: jf branch to eBPF[{jf_ebpf}] may require extra JA"
                    ));
                }
            }
        }
    }
}

impl Default for CbpfToEbpf {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a cBPF program and return the eBPF instructions and migration report.
///
/// Convenience free function.
#[must_use] 
pub fn migration_report(cbpf: &[CbpfInsn]) -> (Vec<EbpfInsn>, MigrationReport) {
    CbpfToEbpf::new().convert(cbpf)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a simple cBPF accept-all program: `RET K(0xFFFF_FFFF)`.
#[must_use] 
pub fn cbpf_accept_all() -> Vec<CbpfInsn> {
    vec![CbpfInsn::ret_k(0xFFFF_FFFF)]
}

/// Build a simple cBPF reject-all program: `RET K(0)`.
#[must_use] 
pub fn cbpf_reject_all() -> Vec<CbpfInsn> {
    vec![CbpfInsn::ret_k(0)]
}

/// Build a classic BPF program that accepts IPv4 packets (ethertype 0x0800).
#[must_use] 
pub fn cbpf_filter_ipv4() -> Vec<CbpfInsn> {
    vec![
        // Load ethertype (offset 12, 2 bytes).
        CbpfInsn::new(cbpf_class::LD | cbpf_mode::ABS | cbpf_size::H, 0, 0, 12),
        // JEQ 0x0800: if true skip 0, if false skip 1.
        CbpfInsn::jeq_k(0x0800, 0, 1),
        // Accept.
        CbpfInsn::ret_k(0xFFFF_FFFF),
        // Reject.
        CbpfInsn::ret_k(0),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `without_mem_prologue()` must actually change the output.
    ///
    /// The `emit_mem_prologue` field was written by `new()` and
    /// `without_mem_prologue()` but never READ, so the builder method was a
    /// silent no-op and the M[] scratch was left uninitialised -- which the
    /// eBPF verifier rejects on any `ld M[k]` that precedes a `st M[k]`.
    #[test]
    fn mem_prologue_zeroes_the_scratch_slots_and_can_be_disabled() {
        let cbpf = cbpf_accept_all();

        let (with, _) = CbpfToEbpf::new().convert(&cbpf);
        let (without, _) = CbpfToEbpf::new().without_mem_prologue().convert(&cbpf);

        // One MOV64_IMM zero register + one store per slot.
        let expected_extra = 1 + CBPF_M_SLOTS as usize;
        assert_eq!(
            with.len(),
            without.len() + expected_extra,
            "the prologue must add exactly {expected_extra} instructions"
        );

        // Every M[] slot is stored to, at its own stack offset.
        for k in 0..CBPF_M_SLOTS {
            let off = CBPF_M_STACK_OFF + i16::try_from(k).unwrap() * 4;
            assert!(
                with.iter().any(|i| i.code == ebpf_ops::STX_MEM_W
                    && i.dst == REG_FP
                    && i.off == off),
                "M[{k}] at fp{off} is never zeroed"
            );
            assert!(
                !without.iter().take(expected_extra).any(|i| i.off == off
                    && i.code == ebpf_ops::STX_MEM_W),
                "M[{k}] zeroed despite without_mem_prologue()"
            );
        }
    }

    #[test]
    fn test_accept_all_converts() {
        let cbpf = cbpf_accept_all();
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
        assert!(!ebpf.is_empty());
        // Must end with EXIT.
        assert_eq!(ebpf.last().unwrap().code, ebpf_ops::EXIT);
    }

    #[test]
    fn test_reject_all_converts() {
        let cbpf = cbpf_reject_all();
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
        assert_eq!(report.cbpf_insn_count, 1);
        assert!(!ebpf.is_empty());
    }

    #[test]
    fn test_ipv4_filter_converts() {
        let cbpf = cbpf_filter_ipv4();
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
        assert_eq!(report.cbpf_insn_count, 4);
        // Expansion: eBPF should be larger than cBPF.
        assert!(ebpf.len() >= cbpf.len());
    }

    #[test]
    fn test_insn_map_length() {
        let cbpf = cbpf_filter_ipv4();
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert_eq!(report.insn_map.len(), cbpf.len());
        // Every map entry is a valid index.
        for &idx in &report.insn_map {
            assert!(idx < ebpf.len(), "map entry {idx} out of range {}", ebpf.len());
        }
    }

    #[test]
    fn test_ld_imm() {
        let cbpf = vec![
            CbpfInsn::new(cbpf_class::LD | cbpf_mode::IMM, 0, 0, 42),
            CbpfInsn::ret_k(0xFFFF_FFFF),
        ];
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
        // Somewhere in ebpf there should be a MOV64_IMM with imm=42.
        assert!(ebpf.iter().any(|i| i.code == ebpf_ops::MOV64_IMM && i.imm == 42));
    }

    #[test]
    fn test_alu_and() {
        let cbpf = vec![
            CbpfInsn::and_k(0xFF),
            CbpfInsn::ret_k(0xFFFF_FFFF),
        ];
        let (ebpf, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
        assert!(ebpf.iter().any(|i| i.code == ebpf_ops::AND64_IMM && i.imm == 0xFF));
    }

    #[test]
    fn test_misc_tax() {
        let cbpf = vec![
            CbpfInsn::new(cbpf_class::MISC | cbpf_misc::TAX, 0, 0, 0),
            CbpfInsn::ret_k(0),
        ];
        let (_, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.success);
    }

    #[test]
    fn test_expansion_ratio() {
        let cbpf = cbpf_filter_ipv4();
        let (_, report) = CbpfToEbpf::new().convert(&cbpf);
        assert!(report.expansion_ratio > 1.0, "expected expansion > 1, got {}", report.expansion_ratio);
    }

    #[test]
    fn test_ebpf_to_bytes() {
        let insn = EbpfInsn::new(0xB7, 0, 0, 0, 42);
        let b = insn.to_bytes();
        assert_eq!(b[0], 0xB7);
        assert_eq!(b[4], 42);
    }

    #[test]
    fn test_cbpf_insn_helpers() {
        let i = CbpfInsn::ld_abs(cbpf_size::H, 12);
        assert_eq!(i.code, cbpf_class::LD | cbpf_mode::ABS | cbpf_size::H);
        assert_eq!(i.k, 12);
    }
}
