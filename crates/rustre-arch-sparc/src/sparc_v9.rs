//! SPARC V9 — 64-bit extensions.
//!
//! Covers V9-specific registers, new opcodes (POPC, `MOVcc`, `MOVr`, MULX, SDIVX,
//! UDIVX, `FMOVcc`, `FMOVd`, `FMOVq`, FPADD, FPSUB), a dedicated V9 lifter, and
//! the `V9CallingConv` ABI descriptor.

use std::collections::HashMap;

// ── Register file ─────────────────────────────────────────────────────────────

/// Register file identifier for SPARC V9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V9RegId {
    /// Global registers g0–g7.
    G(u8),
    /// Out registers o0–o7.
    O(u8),
    /// Local registers l0–l7.
    L(u8),
    /// In registers i0–i7.
    I(u8),
    /// Floating-point registers f0–f63.
    F(u8),
    /// Program counter.
    Pc,
    /// Next-PC.
    Npc,
    /// SPARC V9 condition codes register (XCC + ICC).
    Ccr,
    /// Floating-point status register.
    Fsr,
    /// Address space identifier.
    Asi,
    /// Tick register.
    Tick,
    /// Processor state register.
    Pstate,
    /// Trap level.
    Tl,
    /// Trap program counter.
    Tpc(u8),
    /// Trap next-PC.
    Tnpc(u8),
    /// Trap state.
    Tstate(u8),
    /// Trap type.
    Tt(u8),
    /// Trap base address.
    Tba,
    /// Version register.
    Ver,
    /// Y register (for legacy SMUL/UMUL).
    Y,
    /// Floating-point deferred-trap queue.
    Fq,
    /// Canary (g0 alias – always 0).
    Zero,
}

impl V9RegId {
    /// Return the canonical assembly name of this register.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::G(n) => format!("%g{n}"),
            Self::O(n) => format!("%o{n}"),
            Self::L(n) => format!("%l{n}"),
            Self::I(n) => format!("%i{n}"),
            Self::F(n) => format!("%f{n}"),
            Self::Pc => "%pc".to_string(),
            Self::Npc => "%npc".to_string(),
            Self::Ccr => "%ccr".to_string(),
            Self::Fsr => "%fsr".to_string(),
            Self::Asi => "%asi".to_string(),
            Self::Tick => "%tick".to_string(),
            Self::Pstate => "%pstate".to_string(),
            Self::Tl => "%tl".to_string(),
            Self::Tpc(n) => format!("%tpc[{n}]"),
            Self::Tnpc(n) => format!("%tnpc[{n}]"),
            Self::Tstate(n) => format!("%tstate[{n}]"),
            Self::Tt(n) => format!("%tt[{n}]"),
            Self::Tba => "%tba".to_string(),
            Self::Ver => "%ver".to_string(),
            Self::Y => "%y".to_string(),
            Self::Fq => "%fq".to_string(),
            Self::Zero => "%g0".to_string(),
        }
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::F(_) => 4,
            _ => 8,
        }
    }

    /// Whether this register is privileged (V9 supervisor-only).
    #[must_use]
    pub const fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::Tl
                | Self::Tpc(_)
                | Self::Tnpc(_)
                | Self::Tstate(_)
                | Self::Tt(_)
                | Self::Tba
                | Self::Pstate
                | Self::Ver
                | Self::Tick
        )
    }
}

/// Complete V9 register file with current values (for emulation).
#[derive(Debug, Clone)]
pub struct V9Registers {
    pub g: [u64; 8],
    pub o: [u64; 8],
    pub l: [u64; 8],
    pub i: [u64; 8],
    pub f: [u32; 64],
    pub pc: u64,
    pub npc: u64,
    pub ccr: u8, // XCC (bits 7:4) | ICC (bits 3:0)
    pub y: u64,
    pub asi: u8,
    pub fsr: u64,
    pub tick: u64,
    pub pstate: u32,
}

impl Default for V9Registers {
    fn default() -> Self {
        Self {
            g: [0; 8],
            o: [0; 8],
            l: [0; 8],
            i: [0; 8],
            f: [0; 64],
            pc: 0,
            npc: 4,
            ccr: 0,
            y: 0,
            asi: 0x80,
            fsr: 0,
            tick: 0,
            pstate: 0x16, // PSTATE.AM=0, PEF=1, IE=1
        }
    }
}

impl V9Registers {
    /// Read a 64-bit integer register by encoded number (0–31).
    #[must_use]
    pub fn read_ireg(&self, reg: u32) -> u64 {
        match reg & 31 {
            0 => 0, // %g0 is always zero
            r @ 1..=7 => self.g[r as usize],
            r @ 8..=15 => self.o[(r - 8) as usize],
            r @ 16..=23 => self.l[(r - 16) as usize],
            r @ 24..=31 => self.i[(r - 24) as usize],
            _ => unreachable!(),
        }
    }

    /// Write a 64-bit integer register by encoded number (0–31).
    /// Writes to register 0 are silently discarded.
    pub fn write_ireg(&mut self, reg: u32, val: u64) {
        match reg & 31 {
            0 => {}
            r @ 1..=7 => self.g[r as usize] = val,
            r @ 8..=15 => self.o[(r - 8) as usize] = val,
            r @ 16..=23 => self.l[(r - 16) as usize] = val,
            r @ 24..=31 => self.i[(r - 24) as usize] = val,
            _ => unreachable!(),
        }
    }

    /// XCC.Z bit.
    #[must_use]
    pub const fn xcc_z(&self) -> bool {
        (self.ccr >> 4) & 1 != 0
    }
    /// XCC.N bit.
    #[must_use]
    pub const fn xcc_n(&self) -> bool {
        (self.ccr >> 7) & 1 != 0
    }
    /// XCC.C bit.
    #[must_use]
    pub const fn xcc_c(&self) -> bool {
        (self.ccr >> 5) & 1 != 0
    }
    /// XCC.V bit.
    #[must_use]
    pub const fn xcc_v(&self) -> bool {
        (self.ccr >> 6) & 1 != 0
    }

    /// ICC.Z bit.
    #[must_use]
    pub const fn icc_z(&self) -> bool {
        (self.ccr) & 1 != 0
    }
    /// ICC.N bit.
    #[must_use]
    pub const fn icc_n(&self) -> bool {
        (self.ccr >> 3) & 1 != 0
    }
}

// ── V9 Opcode enum ────────────────────────────────────────────────────────────

/// SPARC V9-specific opcodes not present in V8.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum V9Opcode {
    /// POPC: population count. `popc rs2, rd`
    Popc,
    /// `MOVcc`: conditional move on integer condition codes.
    Movcc { cond: u8, xcc: bool },
    /// `MOVr`: conditional move on register value.
    Movr { rcond: u8 },
    /// MULX: 64-bit multiply (signed and unsigned).
    Mulx,
    /// SDIVX: 64-bit signed divide.
    Sdivx,
    /// UDIVX: 64-bit unsigned divide.
    Udivx,
    /// `FMOVcc`: conditional FP move (single precision).
    Fmovcc { cond: u8, xcc: bool },
    /// `FMOVd`: move double FP register.
    Fmovd,
    /// `FMOVq`: move quad FP register (4×32-bit).
    Fmovq,
    /// FPADD16: packed 16-bit integer add.
    Fpadd16,
    /// FPADD32: packed 32-bit integer add.
    Fpadd32,
    /// FPSUB16: packed 16-bit integer subtract.
    Fpsub16,
    /// FPSUB32: packed 32-bit integer subtract.
    Fpsub32,
    /// `SLLx`: 64-bit logical shift left.
    Sllx,
    /// `SRLx`: 64-bit logical shift right.
    Srlx,
    /// `SRAx`: 64-bit arithmetic shift right.
    Srax,
    /// STBAR: store barrier.
    Stbar,
    /// MEMBAR: memory barrier.
    Membar { mmask: u8, cmask: u8 },
    /// PREFETCH: prefetch data.
    Prefetch,
    /// FLUSHW: flush register windows.
    Flushw,
    /// DONE: return from trap.
    Done,
    /// RETRY: retry trap.
    Retry,
    /// SAVED: notify OS of register-window save.
    Saved,
    /// RESTORED: notify OS of register-window restore.
    Restored,
}

impl V9Opcode {
    /// Human-readable mnemonic.
    #[must_use]
    pub fn mnemonic(&self) -> String {
        match self {
            Self::Popc => "popc".to_string(),
            Self::Movcc { cond, xcc } => {
                let cc = if *xcc { "xcc" } else { "icc" };
                format!("mov{},{}", icc_cond_name(*cond), cc)
            }
            Self::Movr { rcond } => format!("movr{}", rcond_name(*rcond)),
            Self::Mulx => "mulx".to_string(),
            Self::Sdivx => "sdivx".to_string(),
            Self::Udivx => "udivx".to_string(),
            Self::Fmovcc { cond, xcc } => {
                let cc = if *xcc { "xcc" } else { "icc" };
                format!("fmovs{},{}", icc_cond_name(*cond), cc)
            }
            Self::Fmovd => "fmovd".to_string(),
            Self::Fmovq => "fmovq".to_string(),
            Self::Fpadd16 => "fpadd16".to_string(),
            Self::Fpadd32 => "fpadd32".to_string(),
            Self::Fpsub16 => "fpsub16".to_string(),
            Self::Fpsub32 => "fpsub32".to_string(),
            Self::Sllx => "sllx".to_string(),
            Self::Srlx => "srlx".to_string(),
            Self::Srax => "srax".to_string(),
            Self::Stbar => "stbar".to_string(),
            Self::Membar { .. } => "membar".to_string(),
            Self::Prefetch => "prefetch".to_string(),
            Self::Flushw => "flushw".to_string(),
            Self::Done => "done".to_string(),
            Self::Retry => "retry".to_string(),
            Self::Saved => "saved".to_string(),
            Self::Restored => "restored".to_string(),
        }
    }

    /// Whether this opcode modifies control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(self, Self::Done | Self::Retry)
    }
}

const fn icc_cond_name(cond: u8) -> &'static str {
    match cond & 0xF {
        0 => "n",
        1 => "e",
        2 => "le",
        3 => "l",
        4 => "leu",
        5 => "cs",
        6 => "neg",
        7 => "vs",
        8 => "a",
        9 => "ne",
        10 => "g",
        11 => "ge",
        12 => "gu",
        13 => "cc",
        14 => "pos",
        _ => "vc",
    }
}

const fn rcond_name(rcond: u8) -> &'static str {
    match rcond & 7 {
        1 => "z",
        2 => "lez",
        3 => "lz",
        5 => "nz",
        6 => "gz",
        7 => "gez",
        _ => "?",
    }
}

// ── V9 Decoded Instruction ────────────────────────────────────────────────────

/// A decoded SPARC V9 instruction with full operand info.
#[derive(Debug, Clone)]
pub struct V9Instr {
    /// The opcode.
    pub opcode: V9Opcode,
    /// Source register 1 (0–31), or `None`.
    pub rs1: Option<u8>,
    /// Source register 2 (0–31), or `None` when immediate is used.
    pub rs2: Option<u8>,
    /// Destination register (0–31), or `None`.
    pub rd: Option<u8>,
    /// Signed immediate (13-bit sign-extended), or `None`.
    pub imm: Option<i64>,
    /// Human-readable operand string.
    pub operand_str: String,
}

impl std::fmt::Display for V9Instr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:12} {}", self.opcode.mnemonic(), self.operand_str)
    }
}

// ── V9Lifter ──────────────────────────────────────────────────────────────────

/// IL (Intermediate Language) operation for the V9 lifter.
#[derive(Debug, Clone, PartialEq)]
pub enum V9IlOp {
    /// Register-to-register assignment.
    Assign { dst: u8, src: u8 },
    /// Register-to-register with immediate.
    BinOp {
        op: &'static str,
        dst: u8,
        src1: u8,
        imm_or_reg: Result<i64, u8>,
    },
    /// Load 64-bit value from address in `base + offset`.
    Load64 { dst: u8, base: u8, offset: i64 },
    /// Store 64-bit value to address in `base + offset`.
    Store64 { src: u8, base: u8, offset: i64 },
    /// Conditional assignment.
    CondAssign { cond_reg: u8, dst: u8, src: u8 },
    /// Population count.
    Popc { dst: u8, src: u8 },
    /// 64-bit multiply.
    Mul64 { dst: u8, src1: u8, src2: u8 },
    /// 64-bit signed divide.
    Sdiv64 { dst: u8, src1: u8, src2: u8 },
    /// 64-bit unsigned divide.
    Udiv64 { dst: u8, src1: u8, src2: u8 },
    /// No-operation.
    Nop,
}

/// Lifts SPARC V9 instructions to a simple IL.
pub struct V9Lifter {
    pub ops: Vec<V9IlOp>,
}

impl Default for V9Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl V9Lifter {
    /// Create a new lifter with an empty op list.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Lift a single [`V9Instr`] and append IL ops.
    pub fn lift(&mut self, instr: &V9Instr) {
        match &instr.opcode {
            V9Opcode::Popc => {
                if let (Some(rd), Some(rs2)) = (instr.rd, instr.rs2) {
                    self.ops.push(V9IlOp::Popc { dst: rd, src: rs2 });
                }
            }
            V9Opcode::Mulx => {
                if let (Some(rd), Some(rs1)) = (instr.rd, instr.rs1) {
                    let src2 = instr.rs2.unwrap_or(0);
                    self.ops.push(V9IlOp::Mul64 {
                        dst: rd,
                        src1: rs1,
                        src2,
                    });
                }
            }
            V9Opcode::Sdivx => {
                if let (Some(rd), Some(rs1)) = (instr.rd, instr.rs1) {
                    let src2 = instr.rs2.unwrap_or(0);
                    self.ops.push(V9IlOp::Sdiv64 {
                        dst: rd,
                        src1: rs1,
                        src2,
                    });
                }
            }
            V9Opcode::Udivx => {
                if let (Some(rd), Some(rs1)) = (instr.rd, instr.rs1) {
                    let src2 = instr.rs2.unwrap_or(0);
                    self.ops.push(V9IlOp::Udiv64 {
                        dst: rd,
                        src1: rs1,
                        src2,
                    });
                }
            }
            V9Opcode::Movcc { .. } | V9Opcode::Movr { .. } => {
                if let (Some(rd), Some(rs2)) = (instr.rd, instr.rs2) {
                    self.ops.push(V9IlOp::CondAssign {
                        cond_reg: rs2,
                        dst: rd,
                        src: rs2,
                    });
                }
            }
            V9Opcode::Sllx | V9Opcode::Srlx | V9Opcode::Srax => {
                let op = match instr.opcode {
                    V9Opcode::Sllx => "sll64",
                    V9Opcode::Srlx => "srl64",
                    _ => "sra64",
                };
                if let (Some(rd), Some(rs1)) = (instr.rd, instr.rs1) {
                    let rhs = instr.rs2.map(Err).or_else(|| instr.imm.map(Ok));
                    if let Some(rhs) = rhs {
                        self.ops.push(V9IlOp::BinOp {
                            op,
                            dst: rd,
                            src1: rs1,
                            imm_or_reg: rhs,
                        });
                    }
                }
            }
            V9Opcode::Flushw | V9Opcode::Stbar | V9Opcode::Membar { .. } => {
                self.ops.push(V9IlOp::Nop);
            }
            _ => {
                self.ops.push(V9IlOp::Nop);
            }
        }
    }

    /// Lift a slice of instructions.
    pub fn lift_all(&mut self, instrs: &[V9Instr]) {
        for instr in instrs {
            self.lift(instr);
        }
    }

    /// Clear all lifted ops.
    pub fn clear(&mut self) {
        self.ops.clear();
    }
}

// ── V9CallingConv ─────────────────────────────────────────────────────────────

/// Argument classification for the SPARC V9 / LP64 calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgClass {
    /// Passed in an integer %o register.
    IntReg(u8),
    /// Passed in a %f register (single).
    FloatRegS(u8),
    /// Passed in a pair of %f registers (double).
    FloatRegD(u8),
    /// Passed on the stack.
    Stack { offset: i32 },
}

/// SPARC V9 ABI calling convention descriptor.
///
/// Per the SPARC V9 ABI:
/// - Integer arguments: %o0–%o5.
/// - Floating-point: %f0, %f2, %f4, … %f10 (alternate with int slots).
/// - Return values: %o0 (int), %f0 (float).
/// - Register window: caller saves %o0–%o5 / %g1–%g5; callee uses %l0–%l7 / %i0–%i7.
#[derive(Debug, Clone)]
pub struct V9CallingConv {
    pub name: &'static str,
    pub int_arg_regs: Vec<u8>, // encoded integer register numbers (o0=8, o1=9, …)
    pub fp_arg_regs: Vec<u8>,  // floating-point register numbers
    pub int_return_regs: Vec<u8>,
    pub fp_return_regs: Vec<u8>,
    pub caller_saved: Vec<u8>,
    pub callee_saved: Vec<u8>,
}

impl V9CallingConv {
    /// Return the standard SPARC V9 `SysV` ABI calling convention.
    #[must_use]
    pub fn sparc_v9_sysv() -> Self {
        Self {
            name: "sparc_v9_sysv",
            int_arg_regs: vec![8, 9, 10, 11, 12, 13], // %o0–%o5
            fp_arg_regs: vec![0, 2, 4, 6, 8, 10],     // %f0,%f2,…
            int_return_regs: vec![8],                 // %o0
            fp_return_regs: vec![0],                  // %f0
            caller_saved: vec![8, 9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4, 5, 6, 7],
            callee_saved: vec![16..=23, 24..=31]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                // l0-l7 = 16-23, i0-i7 = 24-31
                .into_iter()
                .map(|v| v as u8)
                .collect(),
        }
    }

    /// Classify a list of argument types into registers and stack slots.
    ///
    /// `arg_types`: `'i'` = integer, `'f'` = single float, `'d'` = double float.
    #[must_use]
    pub fn classify_args(&self, arg_types: &[char]) -> Vec<ArgClass> {
        let mut result = Vec::new();
        let mut int_idx = 0usize;
        let mut fp_idx = 0usize;
        let mut stk_off = 0i32;

        for &ty in arg_types {
            match ty {
                'i' | 'p' => {
                    if int_idx < self.int_arg_regs.len() {
                        result.push(ArgClass::IntReg(self.int_arg_regs[int_idx]));
                        int_idx += 1;
                    } else {
                        result.push(ArgClass::Stack { offset: stk_off });
                        stk_off += 8;
                    }
                }
                'f' => {
                    if fp_idx < self.fp_arg_regs.len() {
                        result.push(ArgClass::FloatRegS(self.fp_arg_regs[fp_idx]));
                        fp_idx += 1;
                    } else {
                        result.push(ArgClass::Stack { offset: stk_off });
                        stk_off += 4;
                    }
                }
                'd' => {
                    if fp_idx + 1 < self.fp_arg_regs.len() {
                        result.push(ArgClass::FloatRegD(self.fp_arg_regs[fp_idx]));
                        fp_idx += 2;
                    } else {
                        result.push(ArgClass::Stack { offset: stk_off });
                        stk_off += 8;
                    }
                }
                _ => {
                    result.push(ArgClass::Stack { offset: stk_off });
                    stk_off += 8;
                }
            }
        }
        result
    }

    /// Return the name of the calling convention.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

// ── V9 Instruction Decoder ────────────────────────────────────────────────────

/// Decodes a 32-bit big-endian word into a [`V9Instr`].
///
/// Returns `None` if the word does not encode a recognised V9-specific opcode.
#[must_use]
pub fn decode_v9_instr(word: u32) -> Option<V9Instr> {
    let fmt = word >> 30;
    if fmt != 2 {
        return None; // Only Format 3 (fmt=10) carries V9 ALU ops
    }
    let op3 = (word >> 19) & 0x3F;
    let rs1 = ((word >> 14) & 31) as u8;
    let rd = ((word >> 25) & 31) as u8;
    let i = (word >> 13) & 1;
    let rs2 = (word & 31) as u8;
    let simm13 = if i == 1 {
        let raw = (word & 0x1FFF) as i32;
        Some(if raw & 0x1000 != 0 {
            i64::from(raw | -0x2000_i32)
        } else {
            i64::from(raw)
        })
    } else {
        None
    };

    let build = |opcode: V9Opcode, ops: String| -> Option<V9Instr> {
        Some(V9Instr {
            opcode,
            rs1: Some(rs1),
            rs2: if i == 0 { Some(rs2) } else { None },
            rd: Some(rd),
            imm: simm13,
            operand_str: ops,
        })
    };

    let reg = |r: u8| -> String {
        match r {
            0 => "%g0".to_string(),
            1..=7 => format!("%g{r}"),
            8..=13 => format!("%o{}", r - 8),
            14 => "%sp".to_string(),
            15 => "%o7".to_string(),
            16..=23 => format!("%l{}", r - 16),
            24..=29 => format!("%i{}", r - 24),
            30 => "%fp".to_string(),
            31 => "%i7".to_string(),
            _ => format!("%r{r}"),
        }
    };
    let src2 = if i == 1 {
        format!("{}", simm13.unwrap_or(0))
    } else {
        reg(rs2)
    };

    match op3 {
        // MULX (0x09)
        0x09 => build(V9Opcode::Mulx, format!("{},{},{}", reg(rs1), src2, reg(rd))),
        // UDIVX (0x0D)
        0x0D => build(
            V9Opcode::Udivx,
            format!("{},{},{}", reg(rs1), src2, reg(rd)),
        ),
        // SDIVX (0x2D in some encodings; in V9 it's 0x2D)
        0x2D => build(
            V9Opcode::Sdivx,
            format!("{},{},{}", reg(rs1), src2, reg(rd)),
        ),
        // POPC (0x2E with special sub)
        0x2E => {
            // POPC: rs1 must be 0
            let s = if i == 0 {
                reg(rs2)
            } else {
                format!("{}", simm13.unwrap_or(0))
            };
            Some(V9Instr {
                opcode: V9Opcode::Popc,
                rs1: None,
                rs2: if i == 0 { Some(rs2) } else { None },
                rd: Some(rd),
                imm: simm13,
                operand_str: format!("{},{}", s, reg(rd)),
            })
        }
        // FLUSHW (0x2B)
        0x2B => Some(V9Instr {
            opcode: V9Opcode::Flushw,
            rs1: None,
            rs2: None,
            rd: None,
            imm: None,
            operand_str: String::new(),
        }),
        // SLLx (0x25, x bit set = 64-bit)
        0x25 if (word >> 12) & 1 == 1 => {
            build(V9Opcode::Sllx, format!("{},{},{}", reg(rs1), src2, reg(rd)))
        }
        // SRLx (0x26, x bit set)
        0x26 if (word >> 12) & 1 == 1 => {
            build(V9Opcode::Srlx, format!("{},{},{}", reg(rs1), src2, reg(rd)))
        }
        // SRAx (0x27, x bit set)
        0x27 if (word >> 12) & 1 == 1 => {
            build(V9Opcode::Srax, format!("{},{},{}", reg(rs1), src2, reg(rd)))
        }
        // MEMBAR (0x28)
        0x28 => {
            let mask = (word & 0x7F) as u8;
            let cmask = ((word >> 4) & 7) as u8;
            let mmask = (word & 0xF) as u8;
            Some(V9Instr {
                opcode: V9Opcode::Membar { mmask, cmask },
                rs1: None,
                rs2: None,
                rd: None,
                imm: None,
                operand_str: format!("#0x{mask:02x}"),
            })
        }
        // MOVcc (0x2C) – integer condition code
        0x2C => {
            let cond = ((word >> 14) & 0xF) as u8;
            let xcc = (word >> 18) & 1 != 0;
            Some(V9Instr {
                opcode: V9Opcode::Movcc { cond, xcc },
                rs1: None,
                rs2: if i == 0 { Some(rs2) } else { None },
                rd: Some(rd),
                imm: simm13,
                operand_str: format!("{},{}", src2, reg(rd)),
            })
        }
        _ => None,
    }
}

// ── V9 Block — basic unit for analysis ───────────────────────────────────────

/// A sequence of V9 instructions forming a basic block.
#[derive(Debug, Clone)]
pub struct V9Block {
    pub address: u64,
    pub instrs: Vec<V9Instr>,
}

impl V9Block {
    /// Create an empty block at `address`.
    #[must_use]
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            instrs: Vec::new(),
        }
    }

    /// Push an instruction.
    pub fn push(&mut self, instr: V9Instr) {
        self.instrs.push(instr);
    }

    /// Whether the block is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instrs.is_empty()
    }

    /// Number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instrs.len()
    }
}

// ── V9 Statistics ─────────────────────────────────────────────────────────────

/// Counts of V9-specific opcodes encountered during a sweep.
#[derive(Debug, Clone, Default)]
pub struct V9Stats {
    pub popc_count: usize,
    pub movcc_count: usize,
    pub mulx_count: usize,
    pub sdivx_count: usize,
    pub udivx_count: usize,
    pub membar_count: usize,
    pub flushw_count: usize,
    pub fmovcc_count: usize,
    pub other_count: usize,
}

impl V9Stats {
    /// Tally a single instruction.
    pub const fn tally(&mut self, instr: &V9Instr) {
        match instr.opcode {
            V9Opcode::Popc => self.popc_count += 1,
            V9Opcode::Movcc { .. } => self.movcc_count += 1,
            V9Opcode::Mulx => self.mulx_count += 1,
            V9Opcode::Sdivx => self.sdivx_count += 1,
            V9Opcode::Udivx => self.udivx_count += 1,
            V9Opcode::Membar { .. } => self.membar_count += 1,
            V9Opcode::Flushw => self.flushw_count += 1,
            V9Opcode::Fmovcc { .. } => self.fmovcc_count += 1,
            _ => self.other_count += 1,
        }
    }

    /// Total instruction count.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.popc_count
            + self.movcc_count
            + self.mulx_count
            + self.sdivx_count
            + self.udivx_count
            + self.membar_count
            + self.flushw_count
            + self.fmovcc_count
            + self.other_count
    }
}

// ── V9 Instruction DB ─────────────────────────────────────────────────────────

/// Small database that indexes decoded V9 instructions by address.
#[derive(Debug, Default)]
pub struct V9InstrDb {
    pub instrs: HashMap<u64, V9Instr>,
}

impl V9InstrDb {
    /// Insert a decoded instruction at `addr`.
    pub fn insert(&mut self, addr: u64, instr: V9Instr) {
        self.instrs.insert(addr, instr);
    }

    /// Decode 4-byte big-endian words from `bytes` starting at `base`.
    pub fn load_bytes(&mut self, bytes: &[u8], base: u64) {
        let mut pos = 0usize;
        while pos + 4 <= bytes.len() {
            let w =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            if let Some(instr) = decode_v9_instr(w) {
                self.instrs.insert(base + pos as u64, instr);
            }
            pos += 4;
        }
    }

    /// Look up by address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&V9Instr> {
        self.instrs.get(&addr)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- V9RegId ---

    #[test]
    fn test_g0_name() {
        assert_eq!(V9RegId::G(0).name(), "%g0");
    }

    #[test]
    fn test_o5_name() {
        assert_eq!(V9RegId::O(5).name(), "%o5");
    }

    #[test]
    fn test_l3_name() {
        assert_eq!(V9RegId::L(3).name(), "%l3");
    }

    #[test]
    fn test_i7_name() {
        assert_eq!(V9RegId::I(7).name(), "%i7");
    }

    #[test]
    fn test_f63_name() {
        assert_eq!(V9RegId::F(63).name(), "%f63");
    }

    #[test]
    fn test_pc_name() {
        assert_eq!(V9RegId::Pc.name(), "%pc");
    }

    #[test]
    fn test_ccr_name() {
        assert_eq!(V9RegId::Ccr.name(), "%ccr");
    }

    #[test]
    fn test_privileged_tpc() {
        assert!(V9RegId::Tpc(0).is_privileged());
    }

    #[test]
    fn test_not_privileged_g0() {
        assert!(!V9RegId::G(0).is_privileged());
    }

    #[test]
    fn test_fp_reg_size_4() {
        assert_eq!(V9RegId::F(0).size_bytes(), 4);
    }

    #[test]
    fn test_ireg_size_8() {
        assert_eq!(V9RegId::G(1).size_bytes(), 8);
    }

    // --- V9Registers ---

    #[test]
    fn test_default_regs_zero() {
        let r = V9Registers::default();
        assert_eq!(r.read_ireg(0), 0); // g0 always zero
        assert_eq!(r.pc, 0);
    }

    #[test]
    fn test_write_ireg_g0_noop() {
        let mut r = V9Registers::default();
        r.write_ireg(0, 0xDEAD_BEEF);
        assert_eq!(r.read_ireg(0), 0);
    }

    #[test]
    fn test_write_read_o0() {
        let mut r = V9Registers::default();
        r.write_ireg(8, 42);
        assert_eq!(r.read_ireg(8), 42);
    }

    #[test]
    fn test_write_read_i7() {
        let mut r = V9Registers::default();
        r.write_ireg(31, 0x1000);
        assert_eq!(r.read_ireg(31), 0x1000);
    }

    #[test]
    fn test_xcc_z_flag() {
        let r = V9Registers {
            ccr: 0x10, // XCC.Z set
            ..V9Registers::default()
        };
        assert!(r.xcc_z());
    }

    #[test]
    fn test_icc_z_flag() {
        let r = V9Registers {
            ccr: 0x01, // ICC.Z set
            ..V9Registers::default()
        };
        assert!(r.icc_z());
    }

    // --- V9Opcode ---

    #[test]
    fn test_popc_mnemonic() {
        assert_eq!(V9Opcode::Popc.mnemonic(), "popc");
    }

    #[test]
    fn test_mulx_mnemonic() {
        assert_eq!(V9Opcode::Mulx.mnemonic(), "mulx");
    }

    #[test]
    fn test_sdivx_mnemonic() {
        assert_eq!(V9Opcode::Sdivx.mnemonic(), "sdivx");
    }

    #[test]
    fn test_udivx_mnemonic() {
        assert_eq!(V9Opcode::Udivx.mnemonic(), "udivx");
    }

    #[test]
    fn test_membar_mnemonic() {
        assert_eq!(V9Opcode::Membar { mmask: 0, cmask: 0 }.mnemonic(), "membar");
    }

    #[test]
    fn test_flushw_mnemonic() {
        assert_eq!(V9Opcode::Flushw.mnemonic(), "flushw");
    }

    #[test]
    fn test_movcc_mnemonic_icc_eq() {
        let mn = V9Opcode::Movcc {
            cond: 1,
            xcc: false,
        }
        .mnemonic();
        assert!(mn.contains("icc"), "expected icc in {mn}");
    }

    #[test]
    fn test_movcc_mnemonic_xcc() {
        let mn = V9Opcode::Movcc { cond: 8, xcc: true }.mnemonic();
        assert!(mn.contains("xcc"), "expected xcc in {mn}");
    }

    #[test]
    fn test_fmovd_mnemonic() {
        assert_eq!(V9Opcode::Fmovd.mnemonic(), "fmovd");
    }

    #[test]
    fn test_done_is_control_flow() {
        assert!(V9Opcode::Done.is_control_flow());
    }

    #[test]
    fn test_mulx_not_control_flow() {
        assert!(!V9Opcode::Mulx.is_control_flow());
    }

    // --- decode_v9_instr ---

    fn make_alu(op3: u32, rs1: u32, rs2: u32, rd: u32) -> u32 {
        (0b10 << 30) | (rd << 25) | (op3 << 19) | (rs1 << 14) | rs2
    }

    #[test]
    fn test_decode_mulx() {
        let w = make_alu(0x09, 8, 9, 8); // MULX %o0,%o1,%o0
        let instr = decode_v9_instr(w).expect("MULX decode");
        assert!(matches!(instr.opcode, V9Opcode::Mulx));
    }

    #[test]
    fn test_decode_udivx() {
        let w = make_alu(0x0D, 8, 9, 10);
        let instr = decode_v9_instr(w).expect("UDIVX decode");
        assert!(matches!(instr.opcode, V9Opcode::Udivx));
    }

    #[test]
    fn test_decode_popc() {
        // POPC: fmt=2, op3=0x2E, rs1 irrelevant
        let w = (0b10 << 30) | (8u32 << 25) | (0x2E << 19) | 9u32;
        let instr = decode_v9_instr(w).expect("POPC decode");
        assert!(matches!(instr.opcode, V9Opcode::Popc));
    }

    #[test]
    fn test_decode_flushw() {
        let w = (0b10 << 30) | (0x2B << 19);
        let instr = decode_v9_instr(w).expect("FLUSHW decode");
        assert!(matches!(instr.opcode, V9Opcode::Flushw));
    }

    #[test]
    fn test_decode_unknown_returns_none() {
        // FMT=1 (CALL) — not handled by V9-specific decoder
        let w = 0x4000_0000u32;
        assert!(decode_v9_instr(w).is_none());
    }

    #[test]
    fn test_decode_membar() {
        // MEMBAR: op=10, op3=0x28, rs1=0xF(reserved), i=1, mask
        let mask: u32 = 0x0F;
        let w = (0b10 << 30) | (0x28u32 << 19) | (1 << 13) | mask;
        let instr = decode_v9_instr(w).expect("MEMBAR decode");
        assert!(matches!(instr.opcode, V9Opcode::Membar { .. }));
    }

    // --- V9Lifter ---

    #[test]
    fn test_lifter_mulx() {
        let mut lf = V9Lifter::new();
        let instr = V9Instr {
            opcode: V9Opcode::Mulx,
            rs1: Some(8),
            rs2: Some(9),
            rd: Some(10),
            imm: None,
            operand_str: "%o0,%o1,%o2".to_string(),
        };
        lf.lift(&instr);
        assert!(matches!(
            lf.ops[0],
            V9IlOp::Mul64 {
                dst: 10,
                src1: 8,
                src2: 9
            }
        ));
    }

    #[test]
    fn test_lifter_popc() {
        let mut lf = V9Lifter::new();
        let instr = V9Instr {
            opcode: V9Opcode::Popc,
            rs1: None,
            rs2: Some(8),
            rd: Some(10),
            imm: None,
            operand_str: "%o0,%o2".to_string(),
        };
        lf.lift(&instr);
        assert!(matches!(lf.ops[0], V9IlOp::Popc { dst: 10, src: 8 }));
    }

    #[test]
    fn test_lifter_membar_produces_nop() {
        let mut lf = V9Lifter::new();
        let instr = V9Instr {
            opcode: V9Opcode::Membar {
                mmask: 0xF,
                cmask: 0,
            },
            rs1: None,
            rs2: None,
            rd: None,
            imm: None,
            operand_str: "#StoreLoad".to_string(),
        };
        lf.lift(&instr);
        assert!(matches!(lf.ops[0], V9IlOp::Nop));
    }

    #[test]
    fn test_lifter_clear() {
        let mut lf = V9Lifter::new();
        lf.ops.push(V9IlOp::Nop);
        lf.clear();
        assert!(lf.ops.is_empty());
    }

    // --- V9CallingConv ---

    #[test]
    fn test_cc_name() {
        let cc = V9CallingConv::sparc_v9_sysv();
        assert_eq!(cc.name(), "sparc_v9_sysv");
    }

    #[test]
    fn test_cc_int_args() {
        let cc = V9CallingConv::sparc_v9_sysv();
        assert_eq!(cc.int_arg_regs.len(), 6);
        assert_eq!(cc.int_arg_regs[0], 8); // %o0
    }

    #[test]
    fn test_cc_classify_two_ints() {
        let cc = V9CallingConv::sparc_v9_sysv();
        let args = cc.classify_args(&['i', 'i']);
        assert_eq!(args.len(), 2);
        assert!(matches!(args[0], ArgClass::IntReg(8)));
        assert!(matches!(args[1], ArgClass::IntReg(9)));
    }

    #[test]
    fn test_cc_classify_float() {
        let cc = V9CallingConv::sparc_v9_sysv();
        let args = cc.classify_args(&['f']);
        assert!(matches!(args[0], ArgClass::FloatRegS(0)));
    }

    #[test]
    fn test_cc_classify_overflow_to_stack() {
        let cc = V9CallingConv::sparc_v9_sysv();
        let args = cc.classify_args(&['i', 'i', 'i', 'i', 'i', 'i', 'i']);
        // First 6 in registers, 7th on stack
        assert!(matches!(args[6], ArgClass::Stack { .. }));
    }

    #[test]
    fn test_cc_return_regs() {
        let cc = V9CallingConv::sparc_v9_sysv();
        assert_eq!(cc.int_return_regs, vec![8]);
        assert_eq!(cc.fp_return_regs, vec![0]);
    }

    // --- V9Stats ---

    #[test]
    fn test_stats_tally_mulx() {
        let mut s = V9Stats::default();
        let instr = V9Instr {
            opcode: V9Opcode::Mulx,
            rs1: Some(0),
            rs2: Some(0),
            rd: Some(0),
            imm: None,
            operand_str: String::new(),
        };
        s.tally(&instr);
        assert_eq!(s.mulx_count, 1);
        assert_eq!(s.total(), 1);
    }

    #[test]
    fn test_stats_tally_multiple() {
        let mut s = V9Stats::default();
        let ops = vec![
            V9Opcode::Popc,
            V9Opcode::Mulx,
            V9Opcode::Sdivx,
            V9Opcode::Udivx,
            V9Opcode::Membar { mmask: 0, cmask: 0 },
            V9Opcode::Flushw,
        ];
        for op in ops {
            let i = V9Instr {
                opcode: op,
                rs1: None,
                rs2: None,
                rd: None,
                imm: None,
                operand_str: String::new(),
            };
            s.tally(&i);
        }
        assert_eq!(s.total(), 6);
        assert_eq!(s.popc_count, 1);
    }

    // --- V9InstrDb ---

    #[test]
    fn test_db_insert_and_get() {
        let mut db = V9InstrDb::default();
        let instr = V9Instr {
            opcode: V9Opcode::Mulx,
            rs1: Some(8),
            rs2: Some(9),
            rd: Some(10),
            imm: None,
            operand_str: String::new(),
        };
        db.insert(0x1000, instr);
        assert!(db.get(0x1000).is_some());
        assert!(db.get(0x2000).is_none());
    }

    #[test]
    fn test_db_load_bytes_mulx() {
        let mut db = V9InstrDb::default();
        // MULX %o0,%o1,%o0: op=10, rd=8, op3=0x09, rs1=8, rs2=9
        let w = make_alu(0x09, 8, 9, 8);
        db.load_bytes(&w.to_be_bytes(), 0x2000);
        assert!(db.get(0x2000).is_some());
    }

    #[test]
    fn test_db_load_partial_bytes_ignored() {
        let mut db = V9InstrDb::default();
        // Only 3 bytes — no complete instruction
        db.load_bytes(&[0x90, 0x4A, 0x00], 0x0);
        assert!(db.get(0x0).is_none());
    }

    // --- V9Block ---

    #[test]
    fn test_block_push_and_len() {
        let mut b = V9Block::new(0x1000);
        let i = V9Instr {
            opcode: V9Opcode::Mulx,
            rs1: None,
            rs2: None,
            rd: None,
            imm: None,
            operand_str: String::new(),
        };
        b.push(i);
        assert_eq!(b.len(), 1);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_block_empty_initially() {
        let b = V9Block::new(0x5000);
        assert!(b.is_empty());
    }

    // --- V9Instr Display ---

    #[test]
    fn test_instr_display() {
        let i = V9Instr {
            opcode: V9Opcode::Mulx,
            rs1: Some(8),
            rs2: Some(9),
            rd: Some(10),
            imm: None,
            operand_str: "%o0,%o1,%o2".to_string(),
        };
        let s = format!("{i}");
        assert!(s.contains("mulx"));
        assert!(s.contains("%o0"));
    }

    // --- icc_cond_name / rcond_name ---

    #[test]
    fn test_icc_always() {
        assert_eq!(icc_cond_name(8), "a");
    }

    #[test]
    fn test_icc_never() {
        assert_eq!(icc_cond_name(0), "n");
    }

    #[test]
    fn test_rcond_zero() {
        assert_eq!(rcond_name(1), "z");
    }

    #[test]
    fn test_rcond_nonzero() {
        assert_eq!(rcond_name(5), "nz");
    }
}

// ── V9 Privilege Level Check ──────────────────────────────────────────────────

/// SPARC V9 privilege levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// Unprivileged (user) mode.
    User,
    /// Privileged (kernel) mode.
    Privileged,
}

impl PrivilegeLevel {
    /// Check if a V9 opcode requires privilege.
    #[must_use]
    pub const fn required_for(opcode: &V9Opcode) -> Self {
        match opcode {
            V9Opcode::Done | V9Opcode::Retry | V9Opcode::Saved | V9Opcode::Restored => {
                Self::Privileged
            }
            _ => Self::User,
        }
    }
}

// ── V9 Condition Code Simulator ───────────────────────────────────────────────

/// Simulates the SPARC V9 condition codes (CCR = XCC:ICC).
#[derive(Debug, Clone, Default)]
pub struct V9CondCodes {
    /// ICC.N (negative).
    pub icc_n: bool,
    /// ICC.Z (zero).
    pub icc_z: bool,
    /// ICC.V (overflow).
    pub icc_v: bool,
    /// ICC.C (carry).
    pub icc_c: bool,
    /// XCC.N.
    pub xcc_n: bool,
    /// XCC.Z.
    pub xcc_z: bool,
    /// XCC.V.
    pub xcc_v: bool,
    /// XCC.C.
    pub xcc_c: bool,
}

impl V9CondCodes {
    /// Encode as an 8-bit CCR value.
    #[must_use]
    pub fn as_ccr(&self) -> u8 {
        (u8::from(self.xcc_c) << 5)
            | (u8::from(self.xcc_v) << 6)
            | (u8::from(self.xcc_z) << 4)
            | (u8::from(self.xcc_n) << 7)
            | (u8::from(self.icc_c) << 1)
            | (u8::from(self.icc_v) << 2)
            | u8::from(self.icc_z)
            | (u8::from(self.icc_n) << 3)
    }

    /// Decode from an 8-bit CCR value.
    #[must_use]
    pub const fn from_ccr(ccr: u8) -> Self {
        Self {
            icc_z: ccr & 1 != 0,
            icc_c: (ccr >> 1) & 1 != 0,
            icc_v: (ccr >> 2) & 1 != 0,
            icc_n: (ccr >> 3) & 1 != 0,
            xcc_z: (ccr >> 4) & 1 != 0,
            xcc_c: (ccr >> 5) & 1 != 0,
            xcc_v: (ccr >> 6) & 1 != 0,
            xcc_n: (ccr >> 7) & 1 != 0,
        }
    }

    /// Update from a 32-bit addition result.
    pub const fn set_from_add32(&mut self, a: u32, b: u32, result: u32) {
        self.icc_n = (result >> 31) != 0;
        self.icc_z = result == 0;
        let carry = (a as u64 + b as u64) > 0xFFFF_FFFF;
        self.icc_c = carry;
        let a_sign = (a >> 31) & 1;
        let b_sign = (b >> 31) & 1;
        let r_sign = (result >> 31) & 1;
        self.icc_v = (a_sign == b_sign) && (r_sign != a_sign);
    }

    /// Update from a 64-bit addition result.
    pub const fn set_from_add64(&mut self, a: u64, b: u64, result: u64) {
        self.xcc_n = (result >> 63) != 0;
        self.xcc_z = result == 0;
        let carry = (a as u128 + b as u128) > 0xFFFF_FFFF_FFFF_FFFF;
        self.xcc_c = carry;
        let a_sign = (a >> 63) & 1;
        let b_sign = (b >> 63) & 1;
        let r_sign = (result >> 63) & 1;
        self.xcc_v = (a_sign == b_sign) && (r_sign != a_sign);
    }
}

// ── V9 Instruction Encoder ────────────────────────────────────────────────────

/// Encode V9-specific instructions to 32-bit words.
pub struct V9Encoder;

impl V9Encoder {
    /// Encode a MULX instruction: `mulx rs1, simm13, rd`.
    #[must_use]
    pub const fn encode_mulx(rs1: u8, simm13: i32, rd: u8) -> u32 {
        (0b10u32 << 30)
            | ((rd as u32 & 31) << 25)
            | (0x09u32 << 19)
            | ((rs1 as u32 & 31) << 14)
            | (1u32 << 13)
            | (simm13 as u32 & 0x1FFF)
    }

    /// Encode an UDIVX instruction: `udivx rs1, simm13, rd`.
    #[must_use]
    pub const fn encode_udivx(rs1: u8, simm13: i32, rd: u8) -> u32 {
        (0b10u32 << 30)
            | ((rd as u32 & 31) << 25)
            | (0x0Du32 << 19)
            | ((rs1 as u32 & 31) << 14)
            | (1u32 << 13)
            | (simm13 as u32 & 0x1FFF)
    }

    /// Encode a FLUSHW instruction.
    #[must_use]
    pub const fn encode_flushw() -> u32 {
        (0b10u32 << 30) | (0x2Bu32 << 19)
    }

    /// Encode a MEMBAR instruction with mask.
    #[must_use]
    pub const fn encode_membar(mask: u8) -> u32 {
        (0b10u32 << 30)
            | (0x28u32 << 19)
            | (0xFu32 << 14) // rs1 = 0xF (reserved)
            | (1u32 << 13)
            | (mask as u32)
    }

    /// Encode a POPC instruction: `popc rs2, rd`.
    #[must_use]
    pub const fn encode_popc(rs2: u8, rd: u8) -> u32 {
        (0b10u32 << 30) | ((rd as u32 & 31) << 25) | (0x2Eu32 << 19) | (rs2 as u32 & 31)
    }
}

// ── V9 Decode round-trip test helpers ────────────────────────────────────────

/// Round-trip encode and decode a MULX instruction.
#[must_use]
pub fn roundtrip_mulx(rs1: u8, simm13: i32, rd: u8) -> Option<V9Instr> {
    let w = V9Encoder::encode_mulx(rs1, simm13, rd);
    decode_v9_instr(w)
}

/// Round-trip encode and decode a FLUSHW instruction.
#[must_use]
pub fn roundtrip_flushw() -> Option<V9Instr> {
    let w = V9Encoder::encode_flushw();
    decode_v9_instr(w)
}
