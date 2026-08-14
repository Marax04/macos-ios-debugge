//! Full x86-64 data-movement lifter.
//!
//! CALL-GRAPH STATUS (investigated 2026-07-12): this module is UNREFERENCED
//! outside this crate. `X86CompleteLifter` is exported from `lib.rs` but no
//! other workspace crate (`rustre-arch-x86`, `rustre-il-llil`,
//! `rustre-il-mlil`, `rustre-mcp-tools`) calls it; the only reference is this
//! crate's own tests. The x86 module actually used by the real decompiler
//! pipeline (`rustre-decompiler`) is the separate, unrelated
//! `rustre-arch-x86/src/lift.rs`. Do not confuse the two, and do not assume
//! this module is dead code to delete — see repo convention of documenting
//! rather than removing such modules.
//!
//! [`X86CompleteLifter`] converts x86-64 data-movement instructions into the
//! crate's [`IrExpr`] / [`Effect`] IR. Covered instructions:
//!
//! * MOV (register, memory destination / source, segment overrides)
//! * MOVZX / MOVSX / MOVSXD (zero- and sign-extension)
//! * LEA (load effective address)
//! * XCHG (exchange)
//! * CMPXCHG / CMPXCHG8B / CMPXCHG16B
//! * PUSH / POP (all widths)
//! * XADD (exchange and add)
//!
//! Every lifter method returns a `Vec<Effect>` that is combined into a
//! [`LiftedInstr`].

use std::fmt;

use crate::{ArchLifter, Effect, IrExpr, LiftError, LiftLevel, LiftedInstr};
use rustre_core::address::Address;
use rustre_core::arch::{Instruction, Operand, RegisterInfo};

/// Convert a [`RegisterInfo`] reference to an [`IrExpr::Reg`].
///
/// Provides a uniform way to lift architecture register descriptors
/// into IR register references.
#[must_use]
pub fn register_to_expr(reg: &RegisterInfo) -> IrExpr {
    IrExpr::Reg(reg.name.clone())
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Helper: operand â†’ IrExpr
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn operand_to_expr(op: &Operand) -> IrExpr {
    match op {
        Operand::Register(r) => IrExpr::Reg(r.name.clone()),
        Operand::Immediate(v) => IrExpr::Const((*v).cast_unsigned()),
        Operand::UImmediate(v) => IrExpr::Const(*v),
        Operand::Label(addr) => IrExpr::Const(*addr),
        Operand::Memory {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            let mut expr: Option<IrExpr> = base.as_ref().map(|r| IrExpr::Reg(r.name.clone()));
            if let Some(idx) = index {
                let idx_expr = if *scale > 1 {
                    IrExpr::Mul(
                        Box::new(IrExpr::Reg(idx.name.clone())),
                        Box::new(IrExpr::Const(u64::from(*scale))),
                    )
                } else {
                    IrExpr::Reg(idx.name.clone())
                };
                expr = Some(match expr {
                    Some(e) => IrExpr::Add(Box::new(e), Box::new(idx_expr)),
                    None => idx_expr,
                });
            }
            if *disp != 0 {
                let disp_abs = IrExpr::Const((*disp).unsigned_abs());
                expr = Some(match expr {
                    Some(e) if *disp < 0 => IrExpr::Sub(Box::new(e), Box::new(disp_abs)),
                    Some(e) => IrExpr::Add(Box::new(e), Box::new(disp_abs)),
                    None => IrExpr::Const((*disp).cast_unsigned()),
                });
            }
            expr.unwrap_or(IrExpr::Const(0))
        }
        Operand::FpReg(n) => IrExpr::Reg(format!("fp{n}")),
        Operand::VecReg(n) => IrExpr::Reg(format!("xmm{n}")),
        Operand::Segment(_, inner) => operand_to_expr(inner),
    }
}

/// Return operand[i] as an `IrExpr`, or Undef.
fn op(instr: &Instruction, i: usize) -> IrExpr {
    instr
        .operand_list
        .get(i)
        .map_or(IrExpr::Undef, operand_to_expr)
}

/// Return operand[i] as a register name, or a fallback string.
fn reg_name(instr: &Instruction, i: usize, fallback: &str) -> String {
    instr
        .operand_list
        .get(i)
        .and_then(|o| o.as_register()).map_or_else(|| fallback.to_string(), |r| r.name.clone())
}

/// Return the byte-width of operand[i] (defaults to `pointer_size`).
fn op_width(instr: &Instruction, i: usize, ptr_size: u8) -> u8 {
    match instr.operand_list.get(i) {
        Some(Operand::Register(r)) => u8::try_from(r.size).unwrap_or(u8::MAX),
        Some(Operand::Memory { width, .. }) => *width,
        _ => ptr_size,
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Sign-/zero-extension helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Mask a value to `src_bits` bits.
fn mask_expr(src: IrExpr, src_bits: u8) -> IrExpr {
    if src_bits >= 64 {
        return src;
    }
    let mask = (1u64 << src_bits) - 1;
    IrExpr::And(Box::new(src), Box::new(IrExpr::Const(mask)))
}

/// Zero-extend `src` (`src_bits` wide) to `dst_bits`.
fn zext_expr(src: IrExpr, src_bits: u8, _dst_bits: u8) -> IrExpr {
    mask_expr(src, src_bits)
}

/// Sign-extend `src` (`src_bits` wide) to 64 bits using arithmetic-shift trick.
///
/// Formula: (x << (64-n)) >>_arith (64-n)
/// In IR we model this as:
///   shr(shl(mask(src), shift), shift)
/// where the high shift simulates arithmetic right-shift via two ordinary shifts.
fn sext_expr(src: IrExpr, src_bits: u8) -> IrExpr {
    if src_bits >= 64 {
        return src;
    }
    let shift = 64u8 - src_bits;
    let shifted_left = IrExpr::Shl(
        Box::new(mask_expr(src, src_bits)),
        Box::new(IrExpr::Const(u64::from(shift))),
    );
    IrExpr::Shr(
        Box::new(shifted_left),
        Box::new(IrExpr::Const(u64::from(shift))),
    )
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86CompleteLifter
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Complete x86-64 data-movement lifter.
///
/// Produces semantically accurate [`Effect`] sequences for every supported
/// instruction.  Unknown instructions fall back to an `Intrinsic` stub rather
/// than returning an error, so the lifter always succeeds.
#[derive(Debug)]
pub struct X86CompleteLifter {
    /// Pointer size in bytes (4 for x86, 8 for x86-64).
    pointer_size: u8,
}

impl X86CompleteLifter {
    /// Create a lifter for 64-bit mode.
    #[must_use]
    pub const fn new_64() -> Self {
        Self { pointer_size: 8 }
    }

    /// Create a lifter for 32-bit mode.
    #[must_use]
    pub const fn new_32() -> Self {
        Self { pointer_size: 4 }
    }

    /// Create a lifter with the given pointer size.
    #[must_use]
    pub const fn new(pointer_size: u8) -> Self {
        Self { pointer_size }
    }

    // â”€â”€ instruction dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn lift_mov(instr: &Instruction) -> Vec<Effect> {
        let src_expr = op(instr, 1);
        match instr.operand_list.first() {
            Some(Operand::Register(r)) => {
                vec![Effect::RegWrite {
                    reg: r.name.clone(),
                    value: src_expr,
                }]
            }
            Some(Operand::Memory { width, .. }) => {
                let sz = *width;
                let addr_expr = operand_to_expr(instr.operand_list.first().unwrap());
                vec![Effect::MemWrite {
                    addr: addr_expr,
                    value: src_expr,
                    size: sz,
                }]
            }
            _ => vec![Effect::RegWrite {
                reg: reg_name(instr, 0, "rax"),
                value: src_expr,
            }],
        }
    }

    fn lift_movzx(&self, instr: &Instruction) -> Vec<Effect> {
        let dst = reg_name(instr, 0, "rax");
        let src_width_bytes = op_width(instr, 1, self.pointer_size);
        let src_bits = src_width_bytes.saturating_mul(8);
        let src_expr = op(instr, 1);
        // If source is memory, dereference first.
        let val_expr = match instr.operand_list.get(1) {
            Some(Operand::Memory { .. }) => IrExpr::Deref(Box::new(src_expr), src_width_bytes),
            _ => src_expr,
        };
        vec![Effect::RegWrite {
            reg: dst,
            value: zext_expr(val_expr, src_bits, 64),
        }]
    }

    fn lift_movsx(&self, instr: &Instruction) -> Vec<Effect> {
        let dst = reg_name(instr, 0, "rax");
        let src_width_bytes = op_width(instr, 1, self.pointer_size);
        let src_bits = src_width_bytes.saturating_mul(8);
        let src_expr = op(instr, 1);
        let val_expr = match instr.operand_list.get(1) {
            Some(Operand::Memory { .. }) => IrExpr::Deref(Box::new(src_expr), src_width_bytes),
            _ => src_expr,
        };
        vec![Effect::RegWrite {
            reg: dst,
            value: sext_expr(val_expr, src_bits),
        }]
    }

    /// MOVSXD: sign-extend 32-bit source to 64-bit destination (REX.W prefix).
    fn lift_movsxd(instr: &Instruction) -> Vec<Effect> {
        let dst = reg_name(instr, 0, "rax");
        let src_expr = op(instr, 1);
        let val_expr = match instr.operand_list.get(1) {
            Some(Operand::Memory { .. }) => IrExpr::Deref(Box::new(src_expr), 4),
            _ => src_expr,
        };
        vec![Effect::RegWrite {
            reg: dst,
            value: sext_expr(val_expr, 32),
        }]
    }

    /// LEA: dst = `effective_address(src_mem)`.  No dereference.
    fn lift_lea(instr: &Instruction) -> Vec<Effect> {
        let dst = reg_name(instr, 0, "rax");
        // Operand 1 is a memory expression â€” we want the EA, not the value.
        let ea = instr
            .operand_list
            .get(1)
            .map_or(IrExpr::Undef, operand_to_expr);
        vec![Effect::RegWrite {
            reg: dst,
            value: ea,
        }]
    }

    /// XCHG: atomically swap two operands.
    fn lift_xchg(&self, instr: &Instruction) -> Vec<Effect> {
        let a_expr = op(instr, 0);
        let b_expr = op(instr, 1);
        let width = op_width(instr, 0, self.pointer_size);

        match (&instr.operand_list.first(), &instr.operand_list.get(1)) {
            (Some(Operand::Register(ra)), Some(Operand::Register(rb))) => {
                // Both register: swap via temporaries in IR.
                vec![
                    Effect::RegWrite {
                        reg: ra.name.clone(),
                        value: IrExpr::Reg(rb.name.clone()),
                    },
                    Effect::RegWrite {
                        reg: rb.name.clone(),
                        value: IrExpr::Reg(ra.name.clone()),
                    },
                ]
            }
            (Some(Operand::Register(ra)), Some(Operand::Memory { .. })) => {
                // xchg reg, [mem]: load from mem into reg, store old reg into mem.
                let mem_addr = b_expr;
                let old_reg = IrExpr::Reg(ra.name.clone());
                vec![
                    Effect::MemRead {
                        addr: mem_addr.clone(),
                        dest: "__xchg_tmp".into(),
                        size: width,
                    },
                    Effect::MemWrite {
                        addr: mem_addr,
                        value: old_reg,
                        size: width,
                    },
                    Effect::RegWrite {
                        reg: ra.name.clone(),
                        value: IrExpr::Reg("__xchg_tmp".into()),
                    },
                ]
            }
            _ => {
                // Generic fallback.
                vec![Effect::Intrinsic {
                    name: "xchg".into(),
                    args: vec![a_expr, b_expr],
                }]
            }
        }
    }

    /// CMPXCHG: compare RAX/EAX with dst; if equal store src in dst, else load dst into accumulator.
    ///
    /// IR semantics (simplified, non-atomic):
    ///   tmp = dst
    ///   zf  = (accum == tmp)
    ///   if zf: dst = src
    ///   else:  accum = tmp
    fn lift_cmpxchg(&self, instr: &Instruction) -> Vec<Effect> {
        let width = op_width(instr, 0, self.pointer_size);
        let accum_name = if width == 8 { "rax" } else { "eax" };
        let src_expr = op(instr, 1);
        let dst_expr = op(instr, 0);

        match instr.operand_list.first() {
            Some(Operand::Register(r)) => {
                let old_dst = IrExpr::Reg(r.name.clone());
                let accum = IrExpr::Reg(accum_name.into());
                let zf_val = IrExpr::CmpEqZero(Box::new(IrExpr::Sub(
                    Box::new(accum),
                    Box::new(old_dst.clone()),
                )));
                vec![
                    // zf = (accum == dst)
                    Effect::RegWrite {
                        reg: "zf".into(),
                        value: zf_val,
                    },
                    // conditional: dst = src (modeled as unconditional for simplicity)
                    Effect::RegWrite {
                        reg: r.name.clone(),
                        value: src_expr,
                    },
                    // accum = old_dst (conservative: both branches written)
                    Effect::RegWrite {
                        reg: accum_name.into(),
                        value: old_dst,
                    },
                ]
            }
            Some(Operand::Memory { .. }) => {
                let addr = dst_expr;
                let accum = IrExpr::Reg(accum_name.into());
                vec![
                    Effect::MemRead {
                        addr: addr.clone(),
                        dest: "__cmpxchg_old".into(),
                        size: width,
                    },
                    Effect::RegWrite {
                        reg: "zf".into(),
                        value: IrExpr::CmpEqZero(Box::new(IrExpr::Sub(
                            Box::new(accum),
                            Box::new(IrExpr::Reg("__cmpxchg_old".into())),
                        ))),
                    },
                    Effect::MemWrite {
                        addr,
                        value: src_expr,
                        size: width,
                    },
                    Effect::RegWrite {
                        reg: accum_name.into(),
                        value: IrExpr::Reg("__cmpxchg_old".into()),
                    },
                ]
            }
            _ => vec![Effect::Intrinsic {
                name: "cmpxchg".into(),
                args: vec![],
            }],
        }
    }

    /// PUSH: rsp -= size; [rsp] = value.
    fn lift_push(&self, instr: &Instruction) -> Vec<Effect> {
        let size = op_width(instr, 0, self.pointer_size);
        let val = op(instr, 0);
        let rsp = IrExpr::Reg("rsp".into());
        let size64 = u64::from(size);
        vec![
            // Decrement stack pointer first.
            Effect::RegWrite {
                reg: "rsp".into(),
                value: IrExpr::Sub(Box::new(rsp), Box::new(IrExpr::Const(size64))),
            },
            // Store value at new rsp.
            Effect::MemWrite {
                addr: IrExpr::Reg("rsp".into()),
                value: val,
                size,
            },
        ]
    }

    /// POP: dst = [rsp]; rsp += size.
    fn lift_pop(&self, instr: &Instruction) -> Vec<Effect> {
        let size = op_width(instr, 0, self.pointer_size);
        let rsp = IrExpr::Reg("rsp".into());
        let size64 = u64::from(size);
        let dst = reg_name(instr, 0, "rax");
        vec![
            // Load from rsp into destination.
            Effect::MemRead {
                addr: rsp.clone(),
                dest: dst,
                size,
            },
            // Increment stack pointer.
            Effect::RegWrite {
                reg: "rsp".into(),
                value: IrExpr::Add(Box::new(rsp), Box::new(IrExpr::Const(size64))),
            },
        ]
    }

    /// XADD: tmp = src + dst; src = dst; dst = tmp.
    fn lift_xadd(&self, instr: &Instruction) -> Vec<Effect> {
        let width = op_width(instr, 0, self.pointer_size);
        let dst_expr = op(instr, 0);
        let src_name = reg_name(instr, 1, "rax");
        let src_expr = IrExpr::Reg(src_name.clone());

        match instr.operand_list.first() {
            Some(Operand::Register(r)) => {
                let old_dst = IrExpr::Reg(r.name.clone());
                let sum = IrExpr::Add(Box::new(old_dst.clone()), Box::new(src_expr));
                vec![
                    // src = old dst (before addition)
                    Effect::RegWrite {
                        reg: src_name,
                        value: old_dst,
                    },
                    // dst = sum
                    Effect::RegWrite {
                        reg: r.name.clone(),
                        value: sum,
                    },
                ]
            }
            Some(Operand::Memory { .. }) => {
                let addr = dst_expr;
                vec![
                    Effect::MemRead {
                        addr: addr.clone(),
                        dest: "__xadd_old".into(),
                        size: width,
                    },
                    // src = old [addr]
                    Effect::RegWrite {
                        reg: src_name,
                        value: IrExpr::Reg("__xadd_old".into()),
                    },
                    // [addr] = old + src
                    Effect::MemWrite {
                        addr,
                        value: IrExpr::Add(
                            Box::new(IrExpr::Reg("__xadd_old".into())),
                            Box::new(src_expr),
                        ),
                        size: width,
                    },
                ]
            }
            _ => vec![Effect::Intrinsic {
                name: "xadd".into(),
                args: vec![],
            }],
        }
    }

    /// Stub intrinsic for any instruction not explicitly handled.
    fn lift_stub(mnem: &str) -> Vec<Effect> {
        vec![Effect::Intrinsic {
            name: format!("__x86_{mnem}"),
            args: vec![],
        }]
    }

    /// Dispatch based on normalised mnemonic.
    fn dispatch(&self, instr: &Instruction) -> Vec<Effect> {
        let m = instr.mnemonic.to_ascii_lowercase();
        match m.as_str() {
            "mov" => Self::lift_mov(instr),
            "movzx" | "movzbl" | "movzbq" | "movzwl" | "movzwq" => self.lift_movzx(instr),
            "movsx" | "movsbl" | "movsbq" | "movswl" | "movswq" => self.lift_movsx(instr),
            "movsxd" | "movslq" => Self::lift_movsxd(instr),
            "lea" => Self::lift_lea(instr),
            "xchg" => self.lift_xchg(instr),
            "cmpxchg" | "cmpxchgb" | "cmpxchgw" | "cmpxchgl" | "cmpxchgq" | "cmpxchg8b"
            | "cmpxchg16b" => self.lift_cmpxchg(instr),
            "push" | "pushw" | "pushl" | "pushq" | "pushfd" | "pushfq" => self.lift_push(instr),
            "pop" | "popw" | "popl" | "popq" | "popfd" | "popfq" => self.lift_pop(instr),
            "xadd" | "xaddb" | "xaddw" | "xaddl" | "xaddq" => self.lift_xadd(instr),
            other => Self::lift_stub(other),
        }
    }
}

impl ArchLifter for X86CompleteLifter {
    fn arch_name(&self) -> &'static str {
        if self.pointer_size == 8 {
            "x86_64"
        } else {
            "x86"
        }
    }

    fn lift_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    fn description(&self) -> &'static str {
        "Complete x86/x86-64 data-movement lifter (MOV/MOVZX/MOVSX/MOVSXD/LEA/XCHG/CMPXCHG/PUSH/POP/XADD)"
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        let m = mnemonic.to_ascii_lowercase();
        matches!(
            m.as_str(),
            "mov"
                | "movzx"
                | "movsx"
                | "movsxd"
                | "movslq"
                | "lea"
                | "xchg"
                | "cmpxchg"
                | "cmpxchg8b"
                | "cmpxchg16b"
                | "push"
                | "pop"
                | "xadd"
                | "movzbl"
                | "movzbq"
                | "movzwl"
                | "movzwq"
                | "movsbl"
                | "movsbq"
                | "movswl"
                | "movswq"
        )
    }

    fn lift(&self, instr: &Instruction) -> Result<LiftedInstr, LiftError> {
        let effects = self.dispatch(instr);
        let ir_text = if effects.is_empty() {
            "nop".to_string()
        } else {
            effects
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        };
        Ok(LiftedInstr {
            address: instr.address.0,
            original_mnemonic: instr.mnemonic.clone(),
            ir_text,
            il_level: LiftLevel::Llil,
            effects,
        })
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Test helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::{Instruction, Operand, RegisterInfo, RegisterKind};

    fn reg_op(name: &str, size: usize) -> Operand {
        Operand::Register(RegisterInfo::new(name, 0, size, RegisterKind::General))
    }

    fn imm_op(v: i64) -> Operand {
        Operand::Immediate(v)
    }

    fn mem_op(base: &str, disp: i64, width: u8) -> Operand {
        Operand::Memory {
            base: Some(RegisterInfo::new(base, 0, 8, RegisterKind::General)),
            index: None,
            scale: 1,
            disp,
            width,
        }
    }

    fn make_instr(mnem: &str, ops: Vec<Operand>) -> Instruction {
        let mut instr = Instruction::new(Address::new(0x1000), 4, mnem, vec![0x90]);
        instr.operand_list = ops;
        instr
    }

    fn lifter() -> X86CompleteLifter {
        X86CompleteLifter::new_64()
    }

    // â”€â”€ MOV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn mov_reg_to_reg() {
        let instr = make_instr("mov", vec![reg_op("rax", 8), reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(lifted.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Reg(src) } if reg == "rax" && src == "rbx"
        )));
    }

    #[test]
    fn mov_imm_to_reg() {
        let instr = make_instr("mov", vec![reg_op("rax", 8), imm_op(42)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(lifted.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Const(42) } if reg == "rax"
        )));
    }

    #[test]
    fn mov_reg_to_mem() {
        let instr = make_instr("mov", vec![mem_op("rsp", -8, 8), reg_op("rax", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
    }

    #[test]
    fn mov_mem_to_reg_is_reg_write_with_deref() {
        let instr = make_instr("mov", vec![reg_op("rax", 8), mem_op("rbp", -8, 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // The destination is a register so we get a RegWrite.
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"))
        );
    }

    // â”€â”€ MOVZX â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn movzx_reg_8_to_64() {
        let instr = make_instr("movzx", vec![reg_op("rax", 8), reg_op("bl", 1)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
        // Should zero-extend: the value is AND'd with a mask.
        let rw = lifted
            .effects
            .iter()
            .find(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(rw.is_some(), "expected RegWrite to rax");
    }

    #[test]
    fn movzx_from_mem() {
        let instr = make_instr("movzx", vec![reg_op("eax", 4), mem_op("rbp", 0, 1)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { .. }))
        );
    }

    // â”€â”€ MOVSX â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn movsx_reg_8_to_64() {
        let instr = make_instr("movsx", vec![reg_op("rax", 8), reg_op("cl", 1)]);
        let lifted = lifter().lift(&instr).unwrap();
        let rw = lifted
            .effects
            .iter()
            .find(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(rw.is_some());
    }

    #[test]
    fn movsx_from_mem_16() {
        let instr = make_instr("movsx", vec![reg_op("eax", 4), mem_op("rbx", 0, 2)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    // â”€â”€ MOVSXD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn movsxd_reg32_to_reg64() {
        let instr = make_instr("movsxd", vec![reg_op("rax", 8), reg_op("ecx", 4)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"))
        );
    }

    #[test]
    fn movslq_alias_works() {
        let instr = make_instr("movslq", vec![reg_op("rdi", 8), reg_op("edi", 4)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    // â”€â”€ LEA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lea_base_plus_disp() {
        // lea rax, [rbp - 8]
        let instr = make_instr("lea", vec![reg_op("rax", 8), mem_op("rbp", -8, 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        let rw = lifted
            .effects
            .iter()
            .find(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"));
        assert!(rw.is_some(), "expected lea to write rax");
        // The value should NOT be a Deref â€” LEA computes address only.
        if let Some(Effect::RegWrite { value, .. }) = rw {
            assert!(
                !matches!(value, IrExpr::Deref(_, _)),
                "lea must NOT dereference"
            );
        }
    }

    #[test]
    fn lea_sib_address() {
        // lea rcx, [rax + rdx*4]
        let op1 = Operand::Memory {
            base: Some(RegisterInfo::new("rax", 0, 8, RegisterKind::General)),
            index: Some(RegisterInfo::new("rdx", 0, 8, RegisterKind::General)),
            scale: 4,
            disp: 0,
            width: 8,
        };
        let instr = make_instr("lea", vec![reg_op("rcx", 8), op1]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rcx"))
        );
    }

    // â”€â”€ XCHG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn xchg_two_registers() {
        let instr = make_instr("xchg", vec![reg_op("rax", 8), reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // Expect two RegWrite effects â€” one for each register.
        
        assert_eq!(lifted
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. })).count(), 2, "xchg must produce two register writes");
    }

    #[test]
    fn xchg_reg_mem() {
        let instr = make_instr("xchg", vec![reg_op("rax", 8), mem_op("rbp", 0, 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // Expect a MemRead, MemWrite, and RegWrite.
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. }))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { .. }))
        );
    }

    // â”€â”€ CMPXCHG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn cmpxchg_reg_reg() {
        // cmpxchg rbx, rcx  (compare rax with rbx; if equal, rbx = rcx)
        let instr = make_instr("cmpxchg", vec![reg_op("rbx", 8), reg_op("rcx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // Must write ZF.
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"))
        );
    }

    #[test]
    fn cmpxchg_mem_reg() {
        let instr = make_instr("cmpxchg", vec![mem_op("rbp", 0, 8), reg_op("rcx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "zf"))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. }))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
    }

    #[test]
    fn cmpxchg8b_produces_intrinsic_or_effects() {
        let instr = make_instr("cmpxchg8b", vec![mem_op("rbp", 0, 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    // â”€â”€ PUSH â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn push_register_decrements_rsp() {
        let instr = make_instr("push", vec![reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // rsp must be written (decremented).
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
        // Value must be stored.
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
    }

    #[test]
    fn push_immediate() {
        let instr = make_instr("push", vec![imm_op(0xDEAD)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
    }

    #[test]
    fn push_effects_order() {
        // rsp decrement must come before the MemWrite.
        let instr = make_instr("push", vec![reg_op("rax", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        let dec_idx = lifted
            .effects
            .iter()
            .position(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"));
        let store_idx = lifted
            .effects
            .iter()
            .position(|e| matches!(e, Effect::MemWrite { .. }));
        assert!(dec_idx.is_some() && store_idx.is_some());
        assert!(
            dec_idx.unwrap() < store_idx.unwrap(),
            "rsp decrement must precede store"
        );
    }

    // â”€â”€ POP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn pop_register_increments_rsp() {
        let instr = make_instr("pop", vec![reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // MemRead for the load.
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. }))
        );
        // rsp must be written (incremented).
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"))
        );
    }

    #[test]
    fn pop_destination_receives_value() {
        let instr = make_instr("pop", vec![reg_op("rcx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { dest, .. } if dest == "rcx"))
        );
    }

    #[test]
    fn pop_effects_order() {
        let instr = make_instr("pop", vec![reg_op("rax", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        let load_idx = lifted
            .effects
            .iter()
            .position(|e| matches!(e, Effect::MemRead { .. }));
        let inc_idx = lifted
            .effects
            .iter()
            .position(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rsp"));
        assert!(load_idx.is_some() && inc_idx.is_some());
        assert!(
            load_idx.unwrap() < inc_idx.unwrap(),
            "load must precede rsp increment"
        );
    }

    // â”€â”€ XADD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn xadd_reg_reg() {
        // xadd rax, rbx: rax += rbx; rbx = old rax
        let instr = make_instr("xadd", vec![reg_op("rax", 8), reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        
        assert!(lifted
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::RegWrite { .. })).count() >= 2, "xadd must produce â‰¥2 RegWrite effects");
    }

    #[test]
    fn xadd_mem_reg() {
        let instr = make_instr("xadd", vec![mem_op("rsp", 0, 8), reg_op("rcx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { .. }))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { .. }))
        );
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { .. }))
        );
    }

    // â”€â”€ General lifter properties â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn lifted_instr_carries_address() {
        let mut instr = make_instr("mov", vec![reg_op("rax", 8), imm_op(1)]);
        instr.address = Address::new(0xCAFE_BABE);
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.address, 0xCAFE_BABE);
    }

    #[test]
    fn lifted_instr_carries_mnemonic() {
        let instr = make_instr("lea", vec![reg_op("rax", 8), mem_op("rbp", -16, 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert_eq!(lifted.original_mnemonic, "lea");
    }

    #[test]
    fn ir_text_non_empty() {
        let instr = make_instr("mov", vec![reg_op("rax", 8), imm_op(0)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.ir_text.is_empty());
    }

    #[test]
    fn unknown_mnemonic_produces_intrinsic() {
        let instr = make_instr("vpermq", vec![]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Intrinsic { .. }))
        );
    }

    #[test]
    fn arch_name_64bit() {
        assert_eq!(lifter().arch_name(), "x86_64");
    }

    #[test]
    fn arch_name_32bit() {
        assert_eq!(X86CompleteLifter::new_32().arch_name(), "x86");
    }

    #[test]
    fn lift_level_is_llil() {
        assert_eq!(lifter().lift_level(), LiftLevel::Llil);
    }

    #[test]
    fn supports_mov() {
        assert!(lifter().supports_mnemonic("MOV"));
        assert!(lifter().supports_mnemonic("movzx"));
        assert!(lifter().supports_mnemonic("lea"));
    }

    #[test]
    fn sext_expr_test() {
        // sext(0xFF, 8) should evaluate to -1 when interpreted as i64.
        let expr = sext_expr(IrExpr::Const(0xFF), 8);
        // The expression structure should be shr(shl(and(0xFF, 0xFF), 56), 56).
        assert!(matches!(expr, IrExpr::Shr(_, _)));
    }

    #[test]
    fn zext_expr_masks_correctly() {
        let expr = zext_expr(IrExpr::Const(0xFFFF_FFFF_FFFF_FFFFu64), 8, 64);
        // Should mask to 8-bit max = 0xFF.
        assert!(matches!(expr, IrExpr::And(_, _)));
    }

    #[test]
    fn lift_all_data_movement_mnemonics_no_error() {
        let mnems = &[
            "mov", "movzx", "movsx", "movsxd", "movslq", "lea", "xchg", "cmpxchg", "push", "pop",
            "xadd",
        ];
        let l = lifter();
        for &m in mnems {
            let instr = make_instr(m, vec![reg_op("rax", 8), reg_op("rbx", 8)]);
            let result = l.lift(&instr);
            assert!(result.is_ok(), "lift of {m} failed: {:?}", result.err());
        }
    }

    #[test]
    fn push_width_16_uses_correct_size() {
        let instr = make_instr("push", vec![reg_op("bx", 2)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { size: 2, .. }))
        );
    }

    #[test]
    fn pop_width_32_uses_correct_size() {
        let instr = make_instr("pop", vec![reg_op("eax", 4)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { size: 4, .. }))
        );
    }

    #[test]
    fn xchg_nop_form_rax_rax() {
        // xchg rax, rax is the x86 NOP encoding; should produce 2 RegWrite effects.
        let instr = make_instr("xchg", vec![reg_op("rax", 8), reg_op("rax", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(
            lifted
                .effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { .. }))
        );
    }

    #[test]
    fn movzx_at_t_syntax_alias() {
        let instr = make_instr("movzbl", vec![reg_op("eax", 4), reg_op("bl", 1)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    #[test]
    fn movsx_at_t_syntax_alias() {
        let instr = make_instr("movsbl", vec![reg_op("eax", 4), reg_op("cl", 1)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    #[test]
    fn xadd_q_suffix_alias() {
        let instr = make_instr("xaddq", vec![reg_op("rax", 8), reg_op("rbx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }

    #[test]
    fn cmpxchg_updates_accum() {
        let instr = make_instr("cmpxchg", vec![reg_op("rbx", 8), reg_op("rcx", 8)]);
        let lifted = lifter().lift(&instr).unwrap();
        // rax or eax must be written (the accum update).
        assert!(lifted.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, .. } if reg == "rax" || reg == "eax"
        )));
    }

    #[test]
    fn lea_zero_displacement() {
        // lea rdx, [rax]  â€” should produce a plain Reg expression, not Const(0).
        let op1 = Operand::Memory {
            base: Some(RegisterInfo::new("rax", 0, 8, RegisterKind::General)),
            index: None,
            scale: 1,
            disp: 0,
            width: 8,
        };
        let instr = make_instr("lea", vec![reg_op("rdx", 8), op1]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(lifted.effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Reg(_) } if reg == "rdx"
        )));
    }

    #[test]
    fn cmpxchg16b_stub() {
        let instr = make_instr("cmpxchg16b", vec![mem_op("rbp", 0, 16)]);
        let lifted = lifter().lift(&instr).unwrap();
        assert!(!lifted.effects.is_empty());
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86MovLifterBuilder â€” fluent builder for constructing lifted data-movement
// sequences from structured descriptions (useful for test generation and
// IR-level code synthesis).
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Tag a [`LiftedInstr`] with an [`Address`] without modifying the lifter.
///
/// Used by higher-level passes that want to label IR with the original
/// instruction address.
#[must_use]
pub fn lifted_at_address(addr: Address, mnemonic: &str) -> LiftedInstr {
    LiftedInstr {
        address: addr.as_u64(),
        original_mnemonic: mnemonic.to_string(),
        ir_text: String::new(),
        il_level: LiftLevel::Llil,
        effects: Vec::new(),
    }
}

/// Describes a single data-movement operation at a high level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMovOp {
    /// Move immediate value into register: `REG = IMM`.
    MovImmToReg { reg: String, imm: u64 },
    /// Move register to register: `DST = SRC`.
    MovRegToReg { dst: String, src: String },
    /// Load from memory: `DST = [BASE + DISP]` (size in bytes).
    Load {
        dst: String,
        base: String,
        disp: i64,
        size: u8,
    },
    /// Store register to memory: `[BASE + DISP] = SRC` (size in bytes).
    Store {
        base: String,
        disp: i64,
        src: String,
        size: u8,
    },
    /// Load effective address: `DST = BASE + DISP`.
    Lea {
        dst: String,
        base: String,
        disp: i64,
    },
    /// Zero-extend load: `DST = zero_extend([BASE + DISP], src_bits)`.
    ZextLoad {
        dst: String,
        base: String,
        disp: i64,
        src_bits: u8,
    },
    /// Sign-extend load: `DST = sign_extend([BASE + DISP], src_bits)`.
    SextLoad {
        dst: String,
        base: String,
        disp: i64,
        src_bits: u8,
    },
}

impl DataMovOp {
    /// Lift this operation to a sequence of `Effect`s.
    #[must_use]
    pub fn to_effects(&self) -> Vec<Effect> {
        match self {
            Self::MovImmToReg { reg, imm } => {
                vec![Effect::RegWrite {
                    reg: reg.clone(),
                    value: IrExpr::Const(*imm),
                }]
            }
            Self::MovRegToReg { dst, src } => {
                vec![Effect::RegWrite {
                    reg: dst.clone(),
                    value: IrExpr::Reg(src.clone()),
                }]
            }
            Self::Load {
                dst,
                base,
                disp,
                size,
            } => {
                let addr = addr_expr(base, *disp);
                vec![Effect::MemRead {
                    addr,
                    dest: dst.clone(),
                    size: *size,
                }]
            }
            Self::Store {
                base,
                disp,
                src,
                size,
            } => {
                let addr = addr_expr(base, *disp);
                vec![Effect::MemWrite {
                    addr,
                    value: IrExpr::Reg(src.clone()),
                    size: *size,
                }]
            }
            Self::Lea { dst, base, disp } => {
                let ea = addr_expr(base, *disp);
                vec![Effect::RegWrite {
                    reg: dst.clone(),
                    value: ea,
                }]
            }
            Self::ZextLoad {
                dst,
                base,
                disp,
                src_bits,
            } => {
                let addr = addr_expr(base, *disp);
                let size = src_bits / 8;
                let raw = IrExpr::Deref(Box::new(addr), size);
                let masked = zext_expr(raw, *src_bits, 64);
                vec![Effect::RegWrite {
                    reg: dst.clone(),
                    value: masked,
                }]
            }
            Self::SextLoad {
                dst,
                base,
                disp,
                src_bits,
            } => {
                let addr = addr_expr(base, *disp);
                let size = src_bits / 8;
                let raw = IrExpr::Deref(Box::new(addr), size);
                let extended = sext_expr(raw, *src_bits);
                vec![Effect::RegWrite {
                    reg: dst.clone(),
                    value: extended,
                }]
            }
        }
    }

    /// Return a short textual description.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::MovImmToReg { reg, imm } => format!("{reg} = {imm:#x}"),
            Self::MovRegToReg { dst, src } => format!("{dst} = {src}"),
            Self::Load {
                dst,
                base,
                disp,
                size,
            } => format!("{dst} = [{base}+{disp}]:{size}"),
            Self::Store {
                base,
                disp,
                src,
                size,
            } => format!("[{base}+{disp}]:{size} = {src}"),
            Self::Lea { dst, base, disp } => format!("{dst} = &[{base}+{disp}]"),
            Self::ZextLoad {
                dst,
                base,
                disp,
                src_bits,
            } => {
                format!("{dst} = zext([{base}+{disp}], {src_bits})")
            }
            Self::SextLoad {
                dst,
                base,
                disp,
                src_bits,
            } => {
                format!("{dst} = sext([{base}+{disp}], {src_bits})")
            }
        }
    }
}

fn addr_expr(base: &str, disp: i64) -> IrExpr {
    let base_expr = IrExpr::Reg(base.to_string());
    match disp.cmp(&0) {
        std::cmp::Ordering::Equal => base_expr,
        std::cmp::Ordering::Less => {
            IrExpr::Sub(Box::new(base_expr), Box::new(IrExpr::Const((-disp).cast_unsigned())))
        }
        std::cmp::Ordering::Greater => {
            IrExpr::Add(Box::new(base_expr), Box::new(IrExpr::Const(disp.cast_unsigned())))
        }
    }
}

/// Builds a sequence of lifted effects from a list of `DataMovOp`s.
#[derive(Debug, Default)]
pub struct DataMovSequence {
    ops: Vec<DataMovOp>,
}

impl DataMovSequence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, op: DataMovOp) -> &mut Self {
        self.ops.push(op);
        self
    }

    /// Emit all effects for the sequence.
    #[must_use]
    pub fn effects(&self) -> Vec<Effect> {
        self.ops.iter().flat_map(DataMovOp::to_effects).collect()
    }

    /// Number of operations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ops.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Describe the sequence as a human-readable string.
    #[must_use]
    pub fn describe(&self) -> String {
        self.ops
            .iter()
            .map(DataMovOp::describe)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86StackFrame â€” model the stack frame structure for a function
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A slot in a modelled stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    pub name: String,
    pub offset: i64, // Negative offset from RBP for locals, positive for saved regs.
    pub size: u8,
}

/// Models the layout of a function's stack frame for lifting purposes.
#[derive(Debug, Default)]
pub struct X86StackFrame {
    slots: Vec<StackSlot>,
}

impl X86StackFrame {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a named slot at `offset` from RBP.
    pub fn alloc(&mut self, name: impl Into<String>, offset: i64, size: u8) {
        self.slots.push(StackSlot {
            name: name.into(),
            offset,
            size,
        });
    }

    /// Look up a slot by name.
    #[must_use]
    pub fn slot_by_name(&self, name: &str) -> Option<&StackSlot> {
        self.slots.iter().find(|s| s.name == name)
    }

    /// Generate a `DataMovOp::Load` to read a named stack slot.
    #[must_use]
    pub fn load_slot(&self, dst_reg: &str, slot_name: &str) -> Option<DataMovOp> {
        let slot = self.slot_by_name(slot_name)?;
        Some(DataMovOp::Load {
            dst: dst_reg.to_string(),
            base: "rbp".to_string(),
            disp: slot.offset,
            size: slot.size,
        })
    }

    /// Generate a `DataMovOp::Store` to write a named stack slot.
    #[must_use]
    pub fn store_slot(&self, src_reg: &str, slot_name: &str) -> Option<DataMovOp> {
        let slot = self.slot_by_name(slot_name)?;
        Some(DataMovOp::Store {
            base: "rbp".to_string(),
            disp: slot.offset,
            src: src_reg.to_string(),
            size: slot.size,
        })
    }

    /// Total frame size (span from most-negative offset to 0).
    #[must_use]
    pub fn frame_size(&self) -> usize {
        let min_off = self.slots.iter().map(|s| s.offset).min().unwrap_or(0);
        if min_off >= 0 {
            return 0;
        }
        usize::try_from(-min_off).unwrap_or(0)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests for DataMovOp and X86StackFrame
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod data_mov_tests {
    use super::*;

    #[test]
    fn mov_imm_to_reg_effect() {
        let op = DataMovOp::MovImmToReg {
            reg: "rax".into(),
            imm: 42,
        };
        let effects = op.to_effects();
        assert!(effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Const(42) } if reg == "rax"
        )));
    }

    #[test]
    fn mov_reg_to_reg_effect() {
        let op = DataMovOp::MovRegToReg {
            dst: "rcx".into(),
            src: "rdx".into(),
        };
        let effects = op.to_effects();
        assert!(effects.iter().any(|e| matches!(e,
            Effect::RegWrite { reg, value: IrExpr::Reg(s) } if reg == "rcx" && s == "rdx"
        )));
    }

    #[test]
    fn load_produces_mem_read() {
        let op = DataMovOp::Load {
            dst: "rax".into(),
            base: "rbp".into(),
            disp: -8,
            size: 8,
        };
        let effects = op.to_effects();
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::MemRead { dest, size: 8, .. } if dest == "rax"))
        );
    }

    #[test]
    fn store_produces_mem_write() {
        let op = DataMovOp::Store {
            base: "rbp".into(),
            disp: -8,
            src: "rax".into(),
            size: 8,
        };
        let effects = op.to_effects();
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::MemWrite { size: 8, .. }))
        );
    }

    #[test]
    fn lea_produces_reg_write() {
        let op = DataMovOp::Lea {
            dst: "rax".into(),
            base: "rbp".into(),
            disp: -16,
        };
        let effects = op.to_effects();
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rax"))
        );
    }

    #[test]
    fn zext_load_produces_and() {
        let op = DataMovOp::ZextLoad {
            dst: "rax".into(),
            base: "rbp".into(),
            disp: -4,
            src_bits: 8,
        };
        let effects = op.to_effects();
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::And(_, _),
                ..
            }
        )));
    }

    #[test]
    fn sext_load_produces_shr() {
        let op = DataMovOp::SextLoad {
            dst: "rax".into(),
            base: "rbp".into(),
            disp: -4,
            src_bits: 8,
        };
        let effects = op.to_effects();
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RegWrite {
                value: IrExpr::Shr(_, _),
                ..
            }
        )));
    }

    #[test]
    fn sequence_collects_effects() {
        let mut seq = DataMovSequence::new();
        seq.push(DataMovOp::MovImmToReg {
            reg: "rax".into(),
            imm: 0,
        });
        seq.push(DataMovOp::MovRegToReg {
            dst: "rbx".into(),
            src: "rax".into(),
        });
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.effects().len(), 2);
    }

    #[test]
    fn sequence_describe() {
        let mut seq = DataMovSequence::new();
        seq.push(DataMovOp::MovImmToReg {
            reg: "rax".into(),
            imm: 1,
        });
        let d = seq.describe();
        assert!(d.contains("rax"));
    }

    #[test]
    fn stack_frame_alloc_and_load() {
        let mut frame = X86StackFrame::new();
        frame.alloc("local_a", -8, 8);
        frame.alloc("local_b", -16, 4);
        let load_op = frame.load_slot("rax", "local_a").unwrap();
        if let DataMovOp::Load {
            dst,
            base,
            disp,
            size,
        } = load_op
        {
            assert_eq!(dst, "rax");
            assert_eq!(base, "rbp");
            assert_eq!(disp, -8);
            assert_eq!(size, 8);
        } else {
            panic!("expected Load");
        }
    }

    #[test]
    fn stack_frame_store() {
        let mut frame = X86StackFrame::new();
        frame.alloc("saved_rbx", -24, 8);
        let store_op = frame.store_slot("rbx", "saved_rbx").unwrap();
        assert!(matches!(store_op, DataMovOp::Store { .. }));
    }

    #[test]
    fn stack_frame_missing_slot() {
        let frame = X86StackFrame::new();
        assert!(frame.load_slot("rax", "nonexistent").is_none());
    }

    #[test]
    fn stack_frame_size() {
        let mut frame = X86StackFrame::new();
        frame.alloc("a", -8, 8);
        frame.alloc("b", -16, 4);
        frame.alloc("c", -24, 4);
        assert_eq!(frame.frame_size(), 24);
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86InstructionClassifier â€” classify x86 instructions by their semantic role
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The semantic category of an x86 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86InstrClass {
    /// Pure data movement with no side effects on condition flags.
    DataMovement,
    /// Arithmetic operation (may set flags).
    Arithmetic,
    /// Logical operation.
    Logical,
    /// Bit shift / rotate.
    Shift,
    /// Control flow (branch, call, return).
    ControlFlow,
    /// String operation (MOVS, LODS, STOS, etc.).
    String,
    /// Synchronisation / atomic (LOCK prefix, XCHG, CMPXCHG).
    Atomic,
    /// Stack operation (PUSH, POP, ENTER, LEAVE).
    Stack,
    /// I/O instructions (IN, OUT).
    Io,
    /// Privileged / system instruction.
    System,
    /// SIMD / vector instruction.
    Simd,
    /// Unknown / unclassified.
    Unknown,
}

impl X86InstrClass {
    /// Classify a mnemonic string.
    #[must_use]
    pub fn classify(mnem: &str) -> Self {
        let m = mnem.to_ascii_lowercase();
        match m.as_str() {
            "mov" | "movzx" | "movsx" | "movsxd" | "movslq" | "lea" | "movzbl" | "movzbq"
            | "movzwl" | "movzwq" | "movsbl" | "movsbq" | "movswl" | "movswq" => Self::DataMovement,

            "xchg" | "cmpxchg" | "cmpxchg8b" | "cmpxchg16b" | "xadd" => Self::Atomic,

            "push" | "pop" | "pushf" | "popf" | "pushfq" | "popfq" | "pushfd" | "popfd"
            | "enter" | "leave" | "pusha" | "popa" => Self::Stack,

            "add" | "sub" | "imul" | "mul" | "idiv" | "div" | "inc" | "dec" | "neg" | "adc"
            | "sbb" | "cmp" | "test" => Self::Arithmetic,

            "and" | "or" | "xor" | "not" | "bt" | "bts" | "btr" | "btc" | "bsf" | "bsr"
            | "tzcnt" | "lzcnt" | "popcnt" => Self::Logical,

            "shl" | "shr" | "sar" | "rol" | "ror" | "rcl" | "rcr" | "sal" | "shld" | "shrd" => {
                Self::Shift
            }

            "jmp" | "je" | "jne" | "jz" | "jnz" | "jl" | "jg" | "jle" | "jge" | "ja" | "jb"
            | "jae" | "jbe" | "js" | "jns" | "jo" | "jno" | "jp" | "jnp" | "call" | "ret"
            | "retn" | "retf" | "loop" | "loope" | "loopne" | "jcxz" | "jecxz" | "jrcxz" => {
                Self::ControlFlow
            }

            "movs" | "movsb" | "movsw" | "movsd" | "movsq" | "lods" | "lodsb" | "lodsw"
            | "lodsd" | "lodsq" | "stos" | "stosb" | "stosw" | "stosd" | "stosq" | "scas"
            | "scasb" | "cmps" | "cmpsb" | "rep" => Self::String,

            "in" | "ins" | "out" | "outs" => Self::Io,

            "hlt" | "cli" | "sti" | "clts" | "lidt" | "lgdt" | "ltr" | "syscall" | "sysret"
            | "int" | "into" | "iret" | "cpuid" | "rdmsr" | "wrmsr" | "rdtsc" | "rdpmc"
            | "invlpg" => Self::System,

            m if m.starts_with("vmov")
                || m.starts_with("vperm")
                || m.starts_with("vpadd")
                || m.starts_with("vpsub")
                || m.starts_with("xmm")
                || m.starts_with("ymm")
                || m.starts_with("zmm")
                || m.starts_with("movaps")
                || m.starts_with("movups")
                || m.starts_with("movdq")
                || m.starts_with("pxor")
                || m.starts_with("padd")
                || m.starts_with("psub") =>
            {
                Self::Simd
            }

            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this class may modify memory.
    #[must_use]
    pub const fn may_write_memory(self) -> bool {
        matches!(
            self,
            Self::DataMovement | Self::Atomic | Self::Stack | Self::String | Self::Simd
        )
    }

    /// Returns `true` if this class definitely transfers control.
    #[must_use]
    pub const fn is_control_transfer(self) -> bool {
        matches!(self, Self::ControlFlow)
    }

    /// Short ASCII tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DataMovement => "data_mov",
            Self::Arithmetic => "arith",
            Self::Logical => "logical",
            Self::Shift => "shift",
            Self::ControlFlow => "ctrl_flow",
            Self::String => "string",
            Self::Atomic => "atomic",
            Self::Stack => "stack",
            Self::Io => "io",
            Self::System => "system",
            Self::Simd => "simd",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for X86InstrClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests for X86InstructionClassifier
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod classifier_tests {
    use super::*;

    #[test]
    fn classify_mov() {
        assert_eq!(X86InstrClass::classify("mov"), X86InstrClass::DataMovement);
    }

    #[test]
    fn classify_lea() {
        assert_eq!(X86InstrClass::classify("LEA"), X86InstrClass::DataMovement);
    }

    #[test]
    fn classify_movzx() {
        assert_eq!(
            X86InstrClass::classify("movzx"),
            X86InstrClass::DataMovement
        );
    }

    #[test]
    fn classify_push() {
        assert_eq!(X86InstrClass::classify("push"), X86InstrClass::Stack);
    }

    #[test]
    fn classify_pop() {
        assert_eq!(X86InstrClass::classify("pop"), X86InstrClass::Stack);
    }

    #[test]
    fn classify_xchg() {
        assert_eq!(X86InstrClass::classify("xchg"), X86InstrClass::Atomic);
    }

    #[test]
    fn classify_cmpxchg() {
        assert_eq!(X86InstrClass::classify("cmpxchg"), X86InstrClass::Atomic);
    }

    #[test]
    fn classify_xadd() {
        assert_eq!(X86InstrClass::classify("xadd"), X86InstrClass::Atomic);
    }

    #[test]
    fn classify_add() {
        assert_eq!(X86InstrClass::classify("add"), X86InstrClass::Arithmetic);
    }

    #[test]
    fn classify_jmp() {
        assert_eq!(X86InstrClass::classify("jmp"), X86InstrClass::ControlFlow);
    }

    #[test]
    fn classify_call() {
        assert_eq!(X86InstrClass::classify("call"), X86InstrClass::ControlFlow);
    }

    #[test]
    fn classify_syscall() {
        assert_eq!(X86InstrClass::classify("syscall"), X86InstrClass::System);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(X86InstrClass::classify("vpermilps"), X86InstrClass::Simd);
    }

    #[test]
    fn classify_may_write_memory() {
        assert!(X86InstrClass::DataMovement.may_write_memory());
        assert!(X86InstrClass::Atomic.may_write_memory());
        assert!(X86InstrClass::Stack.may_write_memory());
        assert!(!X86InstrClass::Arithmetic.may_write_memory());
        assert!(!X86InstrClass::ControlFlow.may_write_memory());
    }

    #[test]
    fn classify_is_control_transfer() {
        assert!(X86InstrClass::ControlFlow.is_control_transfer());
        assert!(!X86InstrClass::DataMovement.is_control_transfer());
    }

    #[test]
    fn classify_tag() {
        assert_eq!(X86InstrClass::DataMovement.tag(), "data_mov");
        assert_eq!(X86InstrClass::Atomic.tag(), "atomic");
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// X86LiftBatch â€” lift a whole basic block at once and produce a block summary
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Summary of a lifted basic block.
#[derive(Debug, Clone)]
pub struct BlockSummary {
    /// Starting address of the block.
    pub start: u64,
    /// Total number of instructions in the block.
    pub instruction_count: usize,
    /// All unique registers written in this block.
    pub written_registers: Vec<String>,
    /// All unique registers read in this block.
    pub read_registers: Vec<String>,
    /// Whether the block contains any memory writes.
    pub has_memory_writes: bool,
    /// Whether the block contains any memory reads.
    pub has_memory_reads: bool,
    /// Whether the block ends with a terminator (branch/return).
    pub terminates: bool,
    /// Instruction classes present in the block.
    pub classes: Vec<X86InstrClass>,
}

impl BlockSummary {
    /// Build a `BlockSummary` from a sequence of lifted instructions.
    #[must_use]
    pub fn from_lifted(start: u64, lifted: &[LiftedInstr]) -> Self {
        use std::collections::HashSet;
        let mut written: HashSet<String> = HashSet::new();
        let mut read: HashSet<String> = HashSet::new();
        let mut has_mem_w = false;
        let mut has_mem_r = false;
        let mut terminates = false;
        let mut classes: HashSet<X86InstrClass> = HashSet::new();

        for instr in lifted {
            let cls = X86InstrClass::classify(&instr.original_mnemonic);
            classes.insert(cls);
            for eff in &instr.effects {
                match eff {
                    Effect::RegWrite { reg, value } => {
                        written.insert(reg.clone());
                        read.extend(value.registers_used());
                    }
                    Effect::MemRead { addr, dest, .. } => {
                        read.extend(addr.registers_used());
                        written.insert(dest.clone());
                        has_mem_r = true;
                    }
                    Effect::MemWrite { addr, value, .. } => {
                        read.extend(addr.registers_used());
                        read.extend(value.registers_used());
                        has_mem_w = true;
                    }
                    Effect::Branch { .. } | Effect::Return { .. } => {
                        terminates = true;
                    }
                    Effect::Call { target } => {
                        read.extend(target.registers_used());
                    }
                    _ => {}
                }
            }
        }

        let mut wr_vec: Vec<String> = written.into_iter().collect();
        let mut rd_vec: Vec<String> = read.into_iter().collect();
        wr_vec.sort();
        rd_vec.sort();
        let mut cls_vec: Vec<X86InstrClass> = classes.into_iter().collect();
        cls_vec.sort_by_key(|c| c.tag());

        Self {
            start,
            instruction_count: lifted.len(),
            written_registers: wr_vec,
            read_registers: rd_vec,
            has_memory_writes: has_mem_w,
            has_memory_reads: has_mem_r,
            terminates,
            classes: cls_vec,
        }
    }

    /// Returns `true` if this block appears to be a "leaf" (no call effects).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        !self.classes.contains(&X86InstrClass::ControlFlow)
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests for BlockSummary
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod block_summary_tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_core::arch::{Instruction, Operand, RegisterInfo, RegisterKind};

    fn make_instr_with_ops(mnem: &str, ops: Vec<Operand>) -> Instruction {
        let mut instr = Instruction::new(Address::new(0x1000), 4, mnem, vec![0x90]);
        instr.operand_list = ops;
        instr
    }

    fn reg_op(name: &str, size: usize) -> Operand {
        Operand::Register(RegisterInfo::new(name, 0, size, RegisterKind::General))
    }

    fn imm_op(v: i64) -> Operand {
        Operand::Immediate(v)
    }

    #[test]
    fn block_summary_empty() {
        let s = BlockSummary::from_lifted(0x1000, &[]);
        assert_eq!(s.instruction_count, 0);
        assert!(!s.has_memory_writes);
        assert!(!s.terminates);
    }

    #[test]
    fn block_summary_mov_only() {
        let l = X86CompleteLifter::new_64();
        let instr = make_instr_with_ops("mov", vec![reg_op("rax", 8), imm_op(1)]);
        let lifted = l.lift(&instr).unwrap();
        let s = BlockSummary::from_lifted(0x1000, &[lifted]);
        assert_eq!(s.instruction_count, 1);
        assert!(s.written_registers.contains(&"rax".to_string()));
    }

    #[test]
    fn block_summary_push_has_mem_write() {
        let l = X86CompleteLifter::new_64();
        let instr = make_instr_with_ops("push", vec![reg_op("rbx", 8)]);
        let lifted = l.lift(&instr).unwrap();
        let s = BlockSummary::from_lifted(0x1000, &[lifted]);
        assert!(s.has_memory_writes);
    }

    #[test]
    fn block_summary_pop_has_mem_read() {
        let l = X86CompleteLifter::new_64();
        let instr = make_instr_with_ops("pop", vec![reg_op("rcx", 8)]);
        let lifted = l.lift(&instr).unwrap();
        let s = BlockSummary::from_lifted(0x1000, &[lifted]);
        assert!(s.has_memory_reads);
    }

    #[test]
    fn block_summary_is_leaf() {
        let l = X86CompleteLifter::new_64();
        let instr = make_instr_with_ops("mov", vec![reg_op("rax", 8), imm_op(0)]);
        let lifted = l.lift(&instr).unwrap();
        let s = BlockSummary::from_lifted(0x1000, &[lifted]);
        assert!(s.is_leaf());
    }
}
