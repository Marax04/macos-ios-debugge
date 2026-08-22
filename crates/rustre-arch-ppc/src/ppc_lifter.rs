//! PowerPC LLIL-equivalent lifter.
//!
//! `PpcLifter::lift_insn()` translates a decoded PPC instruction into a sequence
//! of `PpcILInsn` (IL instructions), each built from `PpcILExpr` operands.

use crate::PpcArch;
use rustre_core::arch::InstrFlags;
use std::fmt;

pub use rustre_core::address::Address;

// ─── IL Expressions ───────────────────────────────────────────────────────────

/// A leaf or compound expression in the PPC intermediate language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcILExpr {
    /// A general-purpose register (r0..r31).
    Reg(u8),
    /// A floating-point register (f0..f31).
    FReg(u8),
    /// A condition register field (cr0..cr7).
    CRField(u8),
    /// A special-purpose register by number.
    SPR(u16),
    /// A signed immediate value (sign-extended).
    SImm(i32),
    /// An unsigned immediate value.
    UImm(u32),
    /// An absolute address.
    Addr(u64),
    /// Addition of two sub-expressions.
    Add(Box<Self>, Box<Self>),
    /// Subtraction.
    Sub(Box<Self>, Box<Self>),
    /// Bitwise AND.
    And(Box<Self>, Box<Self>),
    /// Bitwise OR.
    Or(Box<Self>, Box<Self>),
    /// Bitwise XOR.
    Xor(Box<Self>, Box<Self>),
    /// Bitwise NOT.
    Not(Box<Self>),
    /// Logical shift left.
    Lsl(Box<Self>, u8),
    /// Logical shift right.
    Lsr(Box<Self>, u8),
    /// Arithmetic shift right.
    Asr(Box<Self>, u8),
    /// Sign-extend from `width` bits.
    Sext(Box<Self>, u8),
    /// Memory load of `width` bytes at `addr`.
    Load { width: u8, addr: Box<Self> },
    /// The link register.
    LR,
    /// The count register.
    CTR,
    /// Program counter constant.
    PC(u64),
    /// Unknown / placeholder.
    Unknown,
}

impl fmt::Display for PpcILExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "r{r}"),
            Self::FReg(r) => write!(f, "f{r}"),
            Self::CRField(cr) => write!(f, "cr{cr}"),
            Self::SPR(n) => write!(f, "spr{n}"),
            Self::SImm(i) => write!(f, "{i}"),
            Self::UImm(u) => write!(f, "0x{u:x}"),
            Self::Addr(a) => write!(f, "0x{a:x}"),
            Self::Add(a, b) => write!(f, "({a} + {b})"),
            Self::Sub(a, b) => write!(f, "({a} - {b})"),
            Self::And(a, b) => write!(f, "({a} & {b})"),
            Self::Or(a, b) => write!(f, "({a} | {b})"),
            Self::Xor(a, b) => write!(f, "({a} ^ {b})"),
            Self::Not(a) => write!(f, "(~{a})"),
            Self::Lsl(a, s) => write!(f, "({a} << {s})"),
            Self::Lsr(a, s) => write!(f, "({a} >> {s})"),
            Self::Asr(a, s) => write!(f, "({a} >>s {s})"),
            Self::Sext(a, w) => write!(f, "sext{w}({a})"),
            Self::Load { width, addr } => write!(f, "mem{width}[{addr}]"),
            Self::LR => write!(f, "LR"),
            Self::CTR => write!(f, "CTR"),
            Self::PC(p) => write!(f, "0x{p:x}"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl PpcILExpr {
    fn reg(r: u32) -> Self {
        Self::Reg(u8::try_from(r).unwrap_or(u8::MAX))
    }
    fn freg(r: u32) -> Self {
        Self::FReg(u8::try_from(r).unwrap_or(u8::MAX))
    }
    const fn simm(v: i32) -> Self {
        Self::SImm(v)
    }
    const fn uimm(v: u32) -> Self {
        Self::UImm(v)
    }
    const fn addr(a: u64) -> Self {
        Self::Addr(a)
    }
    fn crfield(c: u32) -> Self {
        Self::CRField(u8::try_from(c).unwrap_or(u8::MAX))
    }
    fn spr(n: u32) -> Self {
        Self::SPR(u16::try_from(n).unwrap_or(u16::MAX))
    }

    fn add(a: Self, b: Self) -> Self {
        Self::Add(Box::new(a), Box::new(b))
    }
    fn sub(a: Self, b: Self) -> Self {
        Self::Sub(Box::new(a), Box::new(b))
    }
    fn and(a: Self, b: Self) -> Self {
        Self::And(Box::new(a), Box::new(b))
    }
    fn or(a: Self, b: Self) -> Self {
        Self::Or(Box::new(a), Box::new(b))
    }
    fn xor(a: Self, b: Self) -> Self {
        Self::Xor(Box::new(a), Box::new(b))
    }
    fn not(a: Self) -> Self {
        Self::Not(Box::new(a))
    }
    fn lsl(a: Self, s: u8) -> Self {
        Self::Lsl(Box::new(a), s)
    }
    fn lsr(a: Self, s: u8) -> Self {
        Self::Lsr(Box::new(a), s)
    }
    fn asr(a: Self, s: u8) -> Self {
        Self::Asr(Box::new(a), s)
    }
    fn sext(a: Self, w: u8) -> Self {
        Self::Sext(Box::new(a), w)
    }
    fn load(width: u8, addr: Self) -> Self {
        Self::Load {
            width,
            addr: Box::new(addr),
        }
    }
    fn mem_addr(ra: u32, disp: i32) -> Self {
        if ra == 0 {
            Self::SImm(disp)
        } else {
            Self::add(Self::reg(ra), Self::simm(disp))
        }
    }
}

// ─── IL Instructions ──────────────────────────────────────────────────────────

/// A single PPC IL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpcILInsn {
    /// Register assignment: `dst = value`.
    Set { dst: PpcILExpr, value: PpcILExpr },
    /// Memory store: `mem[addr] = value` of `width` bytes.
    Store {
        width: u8,
        addr: PpcILExpr,
        value: PpcILExpr,
    },
    /// Unconditional jump to target address.
    Jump(PpcILExpr),
    /// Call (branch-and-link) to target address.
    Call(PpcILExpr),
    /// Return (jump to LR).
    Return,
    /// Branch-to-CTR.
    BranchCTR,
    /// Conditional branch: `if cond goto target else fallthrough`.
    CondJump { cond: PpcILExpr, target: PpcILExpr },
    /// Set CR field from comparison.
    Compare {
        cr: PpcILExpr,
        lhs: PpcILExpr,
        rhs: PpcILExpr,
        signed: bool,
    },
    /// NOP.
    Nop,
    /// System call.
    Syscall,
    /// Barrier (SYNC, EIEIO, ISYNC).
    Barrier,
    /// Rotate-left-and-mask-insert / mask.
    Rlwinm {
        dst: PpcILExpr,
        src: PpcILExpr,
        sh: u8,
        mb: u8,
        me: u8,
    },
    /// Unknown / unlifted instruction.
    Unlifted(String),
}

impl fmt::Display for PpcILInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set { dst, value } => write!(f, "{dst} = {value}"),
            Self::Store { width, addr, value } => write!(f, "mem{width}[{addr}] = {value}"),
            Self::Jump(t) => write!(f, "goto {t}"),
            Self::Call(t) => write!(f, "call {t}"),
            Self::Return => write!(f, "return"),
            Self::BranchCTR => write!(f, "goto CTR"),
            Self::CondJump { cond, target } => write!(f, "if {cond} goto {target}"),
            Self::Compare {
                cr,
                lhs,
                rhs,
                signed,
            } => {
                write!(
                    f,
                    "cmp{} {cr}, {lhs}, {rhs}",
                    if *signed { "s" } else { "u" }
                )
            }
            Self::Nop => write!(f, "nop"),
            Self::Syscall => write!(f, "syscall"),
            Self::Barrier => write!(f, "barrier"),
            Self::Rlwinm {
                dst,
                src,
                sh,
                mb,
                me,
            } => {
                write!(f, "{dst} = rlwinm({src}, {sh}, {mb}, {me})")
            }
            Self::Unlifted(s) => write!(f, "/* {s} */"),
        }
    }
}

// ─── Lifter ───────────────────────────────────────────────────────────────────

/// Output of a lift operation.
#[derive(Debug, Clone)]
pub struct LiftedInsn {
    /// Original PC of the instruction.
    pub pc: u64,
    /// Byte length of the instruction.
    pub size: usize,
    /// IL instructions generated.
    pub il: Vec<PpcILInsn>,
    /// Branch/call/return flags for control-flow analysis.
    pub flags: InstrFlags,
}

/// PPC LLIL-equivalent lifter.
pub struct PpcLifter<'a> {
    _arch: &'a PpcArch,
}

/// Decode a PowerPC SPR field, which is stored with its two 5-bit halves
/// swapped relative to the register number.
const fn spr_decode(v: u32) -> u32 {
    ((v & 0x1F) << 5) | (v >> 5)
}

/// Sign-extend the low 16 bits of an instruction word (D-form SIMM field).
fn simm16(v: u32) -> i32 {
    let low = u16::try_from(v & 0xFFFF).unwrap_or(0);
    i32::from(i16::from_ne_bytes(low.to_ne_bytes()))
}

/// The low 16 bits of an instruction word (D-form UIMM field).
const fn uimm16(v: u32) -> u32 {
    v & 0xFFFF
}

impl<'a> PpcLifter<'a> {
    /// Create a new lifter bound to an architecture instance.
    #[must_use]
    pub const fn new(arch: &'a PpcArch) -> Self {
        Self { _arch: arch }
    }

    /// Lift one 4-byte PPC instruction at `pc` from `bytes`.
    ///
    /// # Errors
    /// Returns `None` if `bytes` is shorter than 4.
    #[must_use]
    pub fn lift_insn(&self, pc: u64, bytes: &[u8]) -> Option<LiftedInsn> {

        if bytes.len() < 4 {
            return None;
        }
        let instr = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let opcd = instr >> 26;
        let rs = (instr >> 21) & 31;
        let ra = (instr >> 16) & 31;
        let rb = (instr >> 11) & 31;
        let rc = instr & 1;
        let xo = (instr >> 1) & 0x3FF;

        let mut il = Vec::new();
        let mut flags = InstrFlags::NONE;

        match opcd {
            // ── ORI (NOP if all zero) ──────────────────────────────────────
            _ if Self::lift_opcd_imm(&mut il, opcd, instr, rs, ra) => {}
            _ if Self::lift_opcd_mem(&mut il, opcd, instr, rs, ra) => {}
            _ if Self::lift_opcd_branch(&mut il, &mut flags, opcd, instr, pc) => {}
            31 => {
                Self::lift_opcd31(&mut il, instr, rs, ra, rb, xo, rc);
            }
            _ => {
                il.push(PpcILInsn::Unlifted(format!(
                    "opcd={opcd} raw={instr:#010x}"
                )));
            }
        }

        if il.is_empty() {
            il.push(PpcILInsn::Nop);
        }

        Some(LiftedInsn {
            pc,
            size: 4,
            il,
            flags,
        })
    }

    /// Lift the opcode-31 shift, compare, load/store-indexed, SPR and
    /// sign-extension arms.
    ///
    /// The second half of [`Self::lift_opcd31`], split for length only;
    /// arms are verbatim. Returns false when `xo` is not in this half.
    fn lift_opcd31_tail(il: &mut Vec<PpcILInsn>, instr: u32, rs: u32, ra: u32, rb: u32, xo: u32) -> bool {
        match xo {
            792 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::asr(PpcILExpr::reg(rs), u8::try_from(rb & 31).unwrap_or(0)),
            }),
            // SRAWI
            824 => {
                let sh = u8::try_from(rb & 31).unwrap_or(0);
                il.push(PpcILInsn::Set {
                    dst: PpcILExpr::reg(ra),
                    value: PpcILExpr::asr(PpcILExpr::reg(rs), sh),
                });
            }
            // CMP (signed) — crfd is rs>>2
            0 => {
                il.push(PpcILInsn::Compare {
                    cr: PpcILExpr::crfield(rs >> 2),
                    lhs: PpcILExpr::reg(ra),
                    rhs: PpcILExpr::reg(rb),
                    signed: true,
                });
            }
            // CMPL (unsigned)
            32 => {
                il.push(PpcILInsn::Compare {
                    cr: PpcILExpr::crfield(rs >> 2),
                    lhs: PpcILExpr::reg(ra),
                    rhs: PpcILExpr::reg(rb),
                    signed: false,
                });
            }
            // LWZX
            21 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::load(
                    4,
                    PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::reg(rb)),
                ),
            }),
            // LBZX
            87 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::load(
                    1,
                    PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::reg(rb)),
                ),
            }),
            // STWX
            151 => il.push(PpcILInsn::Store {
                width: 4,
                addr: PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::reg(rb)),
                value: PpcILExpr::reg(rs),
            }),
            // STBX
            215 => il.push(PpcILInsn::Store {
                width: 1,
                addr: PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::reg(rb)),
                value: PpcILExpr::reg(rs),
            }),
            // MFSPR
            339 => {
                let spr_raw = (instr >> 11) & 0x3FF;
                let spr = spr_decode(spr_raw);
                let src = match spr {
                    8 => PpcILExpr::LR,
                    9 => PpcILExpr::CTR,
                    _ => PpcILExpr::spr(spr),
                };
                il.push(PpcILInsn::Set {
                    dst: PpcILExpr::reg(rs),
                    value: src,
                });
            }
            // MTSPR
            467 => {
                let spr_raw = (instr >> 11) & 0x3FF;
                let spr = spr_decode(spr_raw);
                let dst = match spr {
                    8 => PpcILExpr::LR,
                    9 => PpcILExpr::CTR,
                    _ => PpcILExpr::spr(spr),
                };
                il.push(PpcILInsn::Set {
                    dst,
                    value: PpcILExpr::reg(rs),
                });
            }
            // EXTSB / EXTSH
            954 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::sext(PpcILExpr::reg(rs), 8),
            }),
            922 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::sext(PpcILExpr::reg(rs), 16),
            }),
            // SYNC/EIEIO barriers
            598 | 854 => il.push(PpcILInsn::Barrier),
            _ => return false,
        }
        true
    }

    /// Lift the logical-immediate and rotate/mask opcodes (25-29, 20-21).
    ///
    /// The second half of [`Self::lift_opcd_imm`], split for length only;
    /// arms are verbatim.
    fn lift_opcd_imm_logic(il: &mut Vec<PpcILInsn>, opcd: u32, instr: u32, rs: u32, ra: u32) -> bool {
        match opcd {
        25 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(ra),
            value: PpcILExpr::or(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr) << 16)),
        }),
        26 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(ra),
            value: PpcILExpr::xor(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr))),
        }),
        27 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(ra),
            value: PpcILExpr::xor(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr) << 16)),
        }),
        28 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(ra),
            value: PpcILExpr::and(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr))),
        }),
        29 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(ra),
            value: PpcILExpr::and(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr) << 16)),
        }),
        // ── RLWINM ────────────────────────────────────────────────────
        21 => {
            let sh = ((instr >> 11) & 31) as u8;
            let mb = ((instr >> 6) & 31) as u8;
            let me = ((instr >> 1) & 31) as u8;
            il.push(PpcILInsn::Rlwinm {
                dst: PpcILExpr::reg(ra),
                src: PpcILExpr::reg(rs),
                sh,
                mb,
                me,
            });
        }
        // ── RLWIMI ────────────────────────────────────────────────────
        20 => {
            let sh = ((instr >> 11) & 31) as u8;
            let mb = ((instr >> 6) & 31) as u8;
            let me = ((instr >> 1) & 31) as u8;
            il.push(PpcILInsn::Unlifted(format!(
                "rlwimi r{ra},r{rs},{sh},{mb},{me}"
            )));
        }
        // ── Loads ─────────────────────────────────────────────────────
            _ => return false,
        }
        true
    }

    /// Lift the D-form immediate and rotate/mask opcodes (7-29).
    ///
    /// Split out of [`Self::lift_insn`] for length only; the arms are
    /// verbatim and push into `il` exactly as before.
    fn lift_opcd_imm(il: &mut Vec<PpcILInsn>, opcd: u32, instr: u32, rs: u32, ra: u32) -> bool {
        match opcd {
        24 => {
            if instr == 0x6000_0000 {
                il.push(PpcILInsn::Nop);
            } else {
                il.push(PpcILInsn::Set {
                    dst: PpcILExpr::reg(ra),
                    value: PpcILExpr::or(PpcILExpr::reg(rs), PpcILExpr::uimm(uimm16(instr))),
                });
            }
        }
        // ── ADDI / LI ─────────────────────────────────────────────────
        14 => {
            let val = if ra == 0 {
                PpcILExpr::simm(simm16(instr))
            } else {
                PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::simm(simm16(instr)))
            };
            il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: val,
            });
        }
        // ── ADDIS / LIS ────────────────────────────────────────────────
        15 => {
            let shifted = simm16(instr) << 16;
            let val = if ra == 0 {
                PpcILExpr::simm(shifted)
            } else {
                PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::simm(shifted))
            };
            il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: val,
            });
        }
        // ── SUBFIC ─────────────────────────────────────────────────────
        8 => {
            il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::sub(PpcILExpr::simm(simm16(instr)), PpcILExpr::reg(ra)),
            });
        }
        // ── MULLI ──────────────────────────────────────────────────────
        7 => {
            il.push(PpcILInsn::Unlifted(format!(
                "mulli r{rs},r{ra},{}",
                simm16(instr)
            )));
        }
        // ── ADDIC ──────────────────────────────────────────────────────
        12 | 13 => {
            il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::simm(simm16(instr))),
            });
        }
        // ── CMPWI / CMPLWI ────────────────────────────────────────────
        11 => {
            let crfd = (instr >> 23) & 7;
            il.push(PpcILInsn::Compare {
                cr: PpcILExpr::crfield(crfd),
                lhs: PpcILExpr::reg(ra),
                rhs: PpcILExpr::simm(simm16(instr)),
                signed: true,
            });
        }
        10 => {
            let crfd = (instr >> 23) & 7;
            il.push(PpcILInsn::Compare {
                cr: PpcILExpr::crfield(crfd),
                lhs: PpcILExpr::reg(ra),
                rhs: PpcILExpr::uimm(uimm16(instr)),
                signed: false,
            });
        }
        // ── ORI / ORIS / XORI / XORIS / ANDI / ANDIS ──────────────────
        _ if Self::lift_opcd_imm_logic(il, opcd, instr, rs, ra) => {}
            _ => return false,
        }
        true
    }

    /// Lift the D-form load and store opcodes (32-62).
    ///
    /// Split out of [`Self::lift_insn`] for length only; the arms are
    /// verbatim and push into `il` exactly as before.
    fn lift_opcd_mem(il: &mut Vec<PpcILInsn>, opcd: u32, instr: u32, rs: u32, ra: u32) -> bool {
        match opcd {
        32 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(rs),
            value: PpcILExpr::load(4, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        34 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(rs),
            value: PpcILExpr::load(1, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        40 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(rs),
            value: PpcILExpr::load(2, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        42 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(rs),
            value: PpcILExpr::sext(
                PpcILExpr::load(2, PpcILExpr::mem_addr(ra, simm16(instr))),
                16,
            ),
        }),
        58 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::reg(rs),
            value: PpcILExpr::load(8, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        48 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::freg(rs),
            value: PpcILExpr::load(4, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        50 => il.push(PpcILInsn::Set {
            dst: PpcILExpr::freg(rs),
            value: PpcILExpr::load(8, PpcILExpr::mem_addr(ra, simm16(instr))),
        }),
        // ── Stores ────────────────────────────────────────────────────
        36 => il.push(PpcILInsn::Store {
            width: 4,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::reg(rs),
        }),
        38 => il.push(PpcILInsn::Store {
            width: 1,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::reg(rs),
        }),
        44 => il.push(PpcILInsn::Store {
            width: 2,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::reg(rs),
        }),
        62 => il.push(PpcILInsn::Store {
            width: 8,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::reg(rs),
        }),
        52 => il.push(PpcILInsn::Store {
            width: 4,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::freg(rs),
        }),
        54 => il.push(PpcILInsn::Store {
            width: 8,
            addr: PpcILExpr::mem_addr(ra, simm16(instr)),
            value: PpcILExpr::freg(rs),
        }),
        // ── Unconditional branch ──────────────────────────────────────
            _ => return false,
        }
        true
    }

    /// Lift the branch, syscall and opcode-19 condition-register group (16-19).
    ///
    /// Split out of [`Self::lift_insn`] for length only; the arms are
    /// verbatim and push into `il` exactly as before.
    fn lift_opcd_branch(
        il: &mut Vec<PpcILInsn>,
        flags: &mut InstrFlags,
        opcd: u32,
        instr: u32,
        pc: u64,
    ) -> bool {
        match opcd {
        18 => {
            let li_raw = i32::try_from(instr & 0x03FF_FFFC).unwrap_or(0);
            let li = if li_raw & 0x0200_0000 != 0 {
                li_raw - 0x0400_0000
            } else {
                li_raw
            };
            let aa = (instr >> 1) & 1;
            let lk = instr & 1;
            let target = if aa != 0 {
                PpcILExpr::addr(u64::from(u32::from_ne_bytes(li.to_ne_bytes())))
            } else {
                PpcILExpr::addr(pc.wrapping_add_signed(i64::from(li)))
            };
            if lk != 0 {
                il.push(PpcILInsn::Set {
                    dst: PpcILExpr::LR,
                    value: PpcILExpr::addr(pc + 4),
                });
                il.push(PpcILInsn::Call(target));
                *flags = InstrFlags::CALL;
            } else {
                il.push(PpcILInsn::Jump(target));
                *flags = InstrFlags::BRANCH;
            }
        }
        // ── Conditional branch ────────────────────────────────────────
        16 => {
            let bd_raw = i32::try_from(instr & 0xFFFC).unwrap_or(0);
            let bd = if bd_raw & 0x8000 != 0 {
                bd_raw - 0x1_0000
            } else {
                bd_raw
            };
            let aa = (instr >> 1) & 1;
            let lk = instr & 1;
            let target_val = if aa != 0 {
                u64::from(u32::from_ne_bytes(bd.to_ne_bytes()))
            } else {
                pc.wrapping_add_signed(i64::from(bd))
            };
            let bi_field = (instr >> 16) & 31;
            if lk != 0 {
                il.push(PpcILInsn::Set {
                    dst: PpcILExpr::LR,
                    value: PpcILExpr::addr(pc + 4),
                });
            }
            il.push(PpcILInsn::CondJump {
                cond: PpcILExpr::crfield(bi_field >> 2),
                target: PpcILExpr::addr(target_val),
            });
            *flags = if lk != 0 {
                InstrFlags::CALL.union(InstrFlags::CONDITIONAL)
            } else {
                InstrFlags::BRANCH.union(InstrFlags::CONDITIONAL)
            };
        }
        // ── SC ────────────────────────────────────────────────────────
        17 => {
            il.push(PpcILInsn::Syscall);
        }
        // ── XO (opcode 19) ────────────────────────────────────────────
        19 => {
            let xo19 = (instr >> 1) & 0x3FF;
            match xo19 {
                16 => {
                    let lk = instr & 1;
                    if lk != 0 {
                        il.push(PpcILInsn::Set {
                            dst: PpcILExpr::LR,
                            value: PpcILExpr::addr(pc + 4),
                        });
                    }
                    il.push(PpcILInsn::Return);
                    *flags = InstrFlags::RET;
                }
                528 => {
                    let lk = instr & 1;
                    if lk != 0 {
                        il.push(PpcILInsn::Set {
                            dst: PpcILExpr::LR,
                            value: PpcILExpr::addr(pc + 4),
                        });
                        il.push(PpcILInsn::Call(PpcILExpr::CTR));
                        *flags = InstrFlags::CALL;
                    } else {
                        il.push(PpcILInsn::BranchCTR);
                        *flags = InstrFlags::BRANCH.union(InstrFlags::INDIRECT);
                    }
                }
                150 | 598 | 854 => {
                    il.push(PpcILInsn::Barrier);
                }
                _ => il.push(PpcILInsn::Nop),
            }
        }
        // ── XO (opcode 31) ────────────────────────────────────────────
            _ => return false,
        }
        true
    }

    /// Lift the opcode-31 extended-opcode (XO form) group.
    ///
    /// Split out of [`Self::lift_insn`] for length only: the body is the
    /// `match xo` block verbatim, and every arm pushes into `il` exactly as
    /// before. `rc` is read only to render the `Unlifted` fallback text.
    fn lift_opcd31(il: &mut Vec<PpcILInsn>, instr: u32, rs: u32, ra: u32, rb: u32, xo: u32, rc: u32) {
        match xo {
            // ADD
            266 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::add(PpcILExpr::reg(ra), PpcILExpr::reg(rb)),
            }),
            // SUBF (rd = rb - ra)
            40 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::sub(PpcILExpr::reg(rb), PpcILExpr::reg(ra)),
            }),
            // AND
            28 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::and(PpcILExpr::reg(rs), PpcILExpr::reg(rb)),
            }),
            // OR (MR if rs==rb)
            444 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::or(PpcILExpr::reg(rs), PpcILExpr::reg(rb)),
            }),
            // XOR
            316 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::xor(PpcILExpr::reg(rs), PpcILExpr::reg(rb)),
            }),
            // NOR (NOT OR)
            124 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::not(PpcILExpr::or(
                    PpcILExpr::reg(rs),
                    PpcILExpr::reg(rb),
                )),
            }),
            // NEG
            104 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(rs),
                value: PpcILExpr::sub(PpcILExpr::simm(0), PpcILExpr::reg(ra)),
            }),
            // SLW
            23 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::lsl(PpcILExpr::reg(rs), (rb & 31) as u8),
            }),
            // SRW
            536 | 26 => il.push(PpcILInsn::Set {
                dst: PpcILExpr::reg(ra),
                value: PpcILExpr::lsr(PpcILExpr::reg(rs), (rb & 31) as u8),
            }),
            // SRAW
            _ if Self::lift_opcd31_tail(il, instr, rs, ra, rb, xo) => {}
            _ => {
                il.push(PpcILInsn::Unlifted(format!("opcd31 xo={xo} rc={rc}")));
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PpcArch;

    fn lifter() -> PpcLifter<'static> {
        PpcLifter::new(Box::leak(Box::new(PpcArch::default())))
    }

    fn be(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn test_nop() {
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x6000_0000)).unwrap();
        assert!(r.il.contains(&PpcILInsn::Nop));
    }

    #[test]
    fn test_li() {
        // LI r3,1 = ADDI r3,r0,1 = 0x38600001
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x3860_0001)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                dst: PpcILExpr::Reg(3),
                ..
            }
        )));
    }

    #[test]
    fn test_lis() {
        // LIS r3,1 = 0x3C600001
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x3C60_0001)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                dst: PpcILExpr::Reg(3),
                ..
            }
        )));
    }

    #[test]
    fn test_addi() {
        // ADDI r3,r3,4 = 0x38630004
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x3863_0004)).unwrap();
        assert_eq!(r.size, 4);
        assert!(!r.il.is_empty());
    }

    #[test]
    fn test_add_reg() {
        // ADD r3,r3,r4 = opcd=31, xo=266
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (3 << 16) | (4 << 11) | (266 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                dst: PpcILExpr::Reg(3),
                value: PpcILExpr::Add(..)
            }
        )));
    }

    #[test]
    fn test_subf() {
        // SUBF r3,r4,r3 = opcd=31, xo=40
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (3 << 11) | (40 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::Set { .. })));
    }

    #[test]
    fn test_and_instr() {
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (28 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::And(..),
                ..
            }
        )));
    }

    #[test]
    fn test_or_instr() {
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (3 << 11) | (444 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Or(..),
                ..
            }
        )));
    }

    #[test]
    fn test_xor_instr() {
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (316 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Xor(..),
                ..
            }
        )));
    }

    #[test]
    fn test_nor_instr() {
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (3 << 11) | (124 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Not(..),
                ..
            }
        )));
    }

    #[test]
    fn test_neg_instr() {
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (3 << 16) | (104 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Sub(..),
                ..
            }
        )));
    }

    #[test]
    fn test_lwz_load() {
        // LWZ r3,0(r1) = 0x80610000
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x8061_0000)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Load { width: 4, .. },
                ..
            }
        )));
    }

    #[test]
    fn test_stw_store() {
        // STW r3,0(r1) = 0x90610000
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x9061_0000)).unwrap();
        assert!(
            r.il.iter()
                .any(|i| matches!(i, PpcILInsn::Store { width: 4, .. }))
        );
    }

    #[test]
    fn test_lbz_lhz() {
        let l = lifter();
        // LBZ r3,0(r1) = 0x88610000
        let r = l.lift_insn(0x1000, &be(0x8861_0000)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Load { width: 1, .. },
                ..
            }
        )));
        // LHZ r3,0(r1) = 0xA0610000
        let r = l.lift_insn(0x1000, &be(0xA061_0000)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Load { width: 2, .. },
                ..
            }
        )));
    }

    #[test]
    fn test_bl_call() {
        // BL +0 = 0x48000001
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x4800_0001)).unwrap();
        assert!(r.flags.contains(InstrFlags::CALL));
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::Call(..))));
    }

    #[test]
    fn test_b_branch() {
        // B +0 = 0x48000000
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x4800_0000)).unwrap();
        assert!(r.flags.contains(InstrFlags::BRANCH));
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::Jump(..))));
    }

    #[test]
    fn test_blr_return() {
        // BCLR = 0x4E800020
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x4E80_0020)).unwrap();
        assert!(r.flags.contains(InstrFlags::RET));
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::Return)));
    }

    #[test]
    fn test_bctr() {
        // BCCTR = 0x4E800420
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x4E80_0420)).unwrap();
        assert!(r.flags.contains(InstrFlags::INDIRECT));
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::BranchCTR)));
    }

    #[test]
    fn test_cmpwi() {
        // CMPWI r3,0 = 0x2C030000
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x2C03_0000)).unwrap();
        assert!(
            r.il.iter()
                .any(|i| matches!(i, PpcILInsn::Compare { signed: true, .. }))
        );
    }

    #[test]
    fn test_rlwinm_lift() {
        // RLWINM r5,r3,16,0,15 = 0x5465_0800
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x5465_0800)).unwrap();
        assert!(r.il.iter().any(|i| matches!(i, PpcILInsn::Rlwinm { .. })));
    }

    #[test]
    fn test_mflr() {
        // MFLR r0 = 0x7C0802A6
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x7C08_02A6)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::LR,
                ..
            }
        )));
    }

    #[test]
    fn test_mtlr() {
        // MTLR r0 = 0x7C0803A6
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x7C08_03A6)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                dst: PpcILExpr::LR,
                ..
            }
        )));
    }

    #[test]
    fn test_slw() {
        // SLW: opcd=31, xo=23
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (23 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Lsl(..),
                ..
            }
        )));
    }

    #[test]
    fn test_srw() {
        // SRW: opcd=31, xo=536
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (536 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Lsr(..),
                ..
            }
        )));
    }

    #[test]
    fn test_sraw() {
        // SRAW: opcd=31, xo=792
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (5 << 11) | (792 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Asr(..),
                ..
            }
        )));
    }

    #[test]
    fn test_sc_syscall() {
        // SC = 0x44000002
        let l = lifter();
        let r = l.lift_insn(0x1000, &be(0x4400_0002)).unwrap();
        assert!(r.il.contains(&PpcILInsn::Syscall));
    }

    #[test]
    fn test_extsb() {
        // EXTSB: opcd=31, xo=954
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (954 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Sext(_, 8),
                ..
            }
        )));
    }

    #[test]
    fn test_extsh() {
        // EXTSH: opcd=31, xo=922
        let l = lifter();
        let instr: u32 = (31 << 26) | (3 << 21) | (4 << 16) | (922 << 1);
        let r = l.lift_insn(0x1000, &be(instr)).unwrap();
        assert!(r.il.iter().any(|i| matches!(
            i,
            PpcILInsn::Set {
                value: PpcILExpr::Sext(_, 16),
                ..
            }
        )));
    }

    #[test]
    fn test_truncated_input() {
        let l = lifter();
        assert!(l.lift_insn(0x1000, &[0x48, 0x00]).is_none());
    }

    #[test]
    fn test_il_expr_display() {
        let e = PpcILExpr::add(PpcILExpr::Reg(3), PpcILExpr::SImm(4));
        let s = format!("{e}");
        assert!(s.contains("r3"));
        assert!(s.contains('4'));
    }
}
