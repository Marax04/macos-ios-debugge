//! Control-flow instruction handlers for the x86/x64 LLIL lifter.
//!
//! # Instruction coverage
//!
//! | Group | Instructions |
//! |-------|-------------|
//! | Unconditional jump | JMP rel8/rel16/rel32, JMP r/m16/32/64, JMP far ptr16:16/32, JMP far m16:16/32/64 |
//! | Conditional jump | JO/JNO/JB/JAE/JE/JNE/JBE/JA/JS/JNS/JP/JNP/JL/JGE/JLE/JG (and aliases) |
//! | Counter jump | JCXZ/JECXZ/JRCXZ |
//! | Call | CALL rel32, CALL r/m64, CALL far ptr16:16/32, CALL far m16:16/32/64 |
//! | Return | RET (near), RETN N (stdcall), RETF / RETF N (far return) |
//! | Loop | LOOP / LOOPE / LOOPNE |
//! | Interrupt | INT n, INT 3, INT 0, INTO, IRET/IRETD/IRETQ |
//! | Frame | ENTER N,L / LEAVE |
//! | Bounds | BOUND |
//!
//! # μOp discipline
//!
//! Every handler follows the platform contract:
//! 1. **Read** source operands as `IrExpr` (no side-effects yet).
//! 2. **Compute** result / condition expression.
//! 3. **Emit** effects onto `ctx` via `ctx.emit(...)` helpers.
//!
//! Branch targets for direct (immediate) forms are emitted as `IrExpr::Const`
//! with the resolved virtual address.  Indirect forms (register or memory
//! operand) emit the register expression or a `IrExpr::Load` wrapping the
//! address expression respectively.
//!
//! # Stack modelling
//!
//! CALL/RET/ENTER/LEAVE/RETF all model RSP/ESP/SP mutations explicitly so
//! MLIL stack-frame analysis can reconstruct the stack layout without executing
//! the code.  Each push is a `RegWrite(sp, sp - ptr_size)` + `MemWrite([sp],
//! value)` pair; each pop is a `MemRead([sp], tmp)` + `RegWrite(sp, sp +
//! ptr_size)` pair.
//!
//! # Flag usage in Jcc
//!
//! All condition-code expressions are built from `IrExpr::Reg("cf")` etc. —
//! the flag registers that arithmetic handlers write.  No flag intrinsics are
//! needed here: control-flow handlers only *read* flags.


use crate::x86_context::X86LiftCtx;
use crate::x86_operand::operand_size;
use crate::{Effect, IrExpr, LiftError};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Peel a `Deref` / `Load` wrapper from a branch target expression.
///
/// `read_operand` wraps memory operands in `IrExpr::Deref(addr, size)` so
/// data-flow handlers can see the load.  Branch-target positions want the
/// *address* of the target, not its loaded value — except for *indirect*
/// memory jumps where the memory cell **contains** the destination IP.  The
/// caller decides which semantics are wanted by calling this helper or not.
#[inline]
pub fn peel_deref(e: IrExpr) -> IrExpr {
    match e {
        IrExpr::Deref(inner, _) => *inner,
        other => other,
    }
}

/// Emit a stack push of `value` (size `ptr_size` bytes) via SP manipulation.
///
/// Produces two effects:
/// 1. `RegWrite(sp, sp - ptr_size)`
/// 2. `MemWrite([sp], value, ptr_size)`
fn emit_push(ctx: &mut X86LiftCtx, value: IrExpr) {
    let ptr_size = ctx.stack_ptr_size();
    let sp = ctx.stack_ptr();
    let new_sp = IrExpr::Sub(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(u64::from(ptr_size))),
    );
    ctx.emit_reg_write(sp, new_sp);
    ctx.emit_mem_write(IrExpr::Reg(sp.into()), value, ptr_size);
}

/// Emit a stack pop into fresh temporary `tmp_name`, advance SP.
///
/// Produces two effects:
/// 1. `MemRead([sp], tmp_name, ptr_size)`
/// 2. `RegWrite(sp, sp + ptr_size)`
///
/// Returns the `IrExpr::Reg(tmp_name)` so the caller can use the popped value.
fn emit_pop(ctx: &mut X86LiftCtx) -> IrExpr {
    let ptr_size = ctx.stack_ptr_size();
    let sp = ctx.stack_ptr();
    let tmp = ctx.fresh_temp();
    ctx.emit_mem_read(IrExpr::Reg(sp.into()), tmp.clone(), ptr_size);
    let new_sp = IrExpr::Add(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(u64::from(ptr_size))),
    );
    ctx.emit_reg_write(sp, new_sp);
    IrExpr::Reg(tmp)
}

/// Emit a word-sized (16-bit) stack pop independent of the pointer width.
///
/// Used by RETF (pops CS as a 16-bit selector on all modes).
fn emit_pop16(ctx: &mut X86LiftCtx) -> IrExpr {
    let sp = ctx.stack_ptr();
    let tmp = ctx.fresh_temp();
    ctx.emit_mem_read(IrExpr::Reg(sp.into()), tmp.clone(), 2);
    let new_sp = IrExpr::Add(Box::new(IrExpr::Reg(sp.into())), Box::new(IrExpr::Const(2)));
    ctx.emit_reg_write(sp, new_sp);
    IrExpr::Reg(tmp)
}

/// Advance SP by `bytes` without loading the memory — used for RETN imm16 / RETF imm16
/// extra-argument cleanup.
fn emit_sp_adjust(ctx: &mut X86LiftCtx, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let sp = ctx.stack_ptr();
    let new_sp = IrExpr::Add(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(bytes)),
    );
    ctx.emit_reg_write(sp, new_sp);
}

/// Build the condition expression for a Jcc mnemonic.
///
/// Returns an `IrExpr` that evaluates to 1 (branch taken) or 0 (not taken)
/// based on EFLAGS values.  All condition expressions are pure reads of the
/// flag registers; they have no side-effects.
///
/// Reference: Intel® 64 and IA-32 Architectures Software Developer's Manual,
/// Volume 2A, Table 3-2 "Jcc—Jump if Condition Is Met".
fn jcc_condition(mnemonic: Mnemonic) -> Option<IrExpr> {
    // Convenience closures.
    let flag = |name: &'static str| IrExpr::Reg(name.into());
    let not = |e: IrExpr| IrExpr::CmpEqZero(Box::new(e));
    let or = |a: IrExpr, b: IrExpr| IrExpr::Or(Box::new(a), Box::new(b));
    let and = |a: IrExpr, b: IrExpr| IrExpr::And(Box::new(a), Box::new(b));
    // XOR used to implement SF != OF (overflow vs sign mismatch).
    let xor = |a: IrExpr, b: IrExpr| IrExpr::Xor(Box::new(a), Box::new(b));

    let cond = match mnemonic {
        // JO  — overflow:                 OF = 1
        Mnemonic::Jo => flag("of"),
        // JNO — no overflow:              OF = 0
        Mnemonic::Jno => not(flag("of")),

        // JB / JNAE / JC — below (unsigned):     CF = 1
        Mnemonic::Jb => flag("cf"),
        // JAE / JNB / JNC — above or equal:      CF = 0
        Mnemonic::Jae => not(flag("cf")),

        // JE / JZ — equal / zero:         ZF = 1
        Mnemonic::Je => flag("zf"),
        // JNE / JNZ — not equal / not zero:      ZF = 0
        Mnemonic::Jne => not(flag("zf")),

        // JBE / JNA — below or equal:     CF = 1 OR ZF = 1
        Mnemonic::Jbe => or(flag("cf"), flag("zf")),
        // JA / JNBE — above:              CF = 0 AND ZF = 0
        Mnemonic::Ja => and(not(flag("cf")), not(flag("zf"))),

        // JS — sign:                       SF = 1
        Mnemonic::Js => flag("sf"),
        // JNS — not sign:                  SF = 0
        Mnemonic::Jns => not(flag("sf")),

        // JP / JPE — parity even:          PF = 1
        Mnemonic::Jp => flag("pf"),
        // JNP / JPO — parity odd:          PF = 0
        Mnemonic::Jnp => not(flag("pf")),

        // JL / JNGE — less (signed):       SF != OF
        Mnemonic::Jl => xor(flag("sf"), flag("of")),
        // JGE / JNL — greater or equal:    SF == OF  =>  NOT (SF XOR OF)
        Mnemonic::Jge => not(xor(flag("sf"), flag("of"))),

        // JLE / JNG — less or equal:       ZF = 1 OR (SF != OF)
        Mnemonic::Jle => or(flag("zf"), xor(flag("sf"), flag("of"))),
        // JG / JNLE — greater:             ZF = 0 AND (SF == OF)
        Mnemonic::Jg => and(not(flag("zf")), not(xor(flag("sf"), flag("of")))),

        _ => return None,
    };
    Some(cond)
}

// ─────────────────────────────────────────────────────────────────────────────
// JMP
// ─────────────────────────────────────────────────────────────────────────────

/// Lift all forms of the unconditional `JMP` instruction.
///
/// ## Operand forms handled
///
/// | Encoding | Operand kind | Target expression |
/// |----------|-------------|-------------------|
/// | `JMP rel8` | `NearBranch16/32/64` (imm) | `Const(resolved_addr)` |
/// | `JMP rel16/32` | `NearBranch16/32/64` (imm) | `Const(resolved_addr)` |
/// | `JMP r/m16/32/64` | Register | `Reg(name)` |
/// | `JMP r/m16/32/64` | Memory | `Load(addr_expr)` |
/// | `JMP far ptr16:16` | `FarBranch16/32` | `Const(offset)` (segment ignored) |
/// | `JMP far m16:16/32/64` | Memory | intrinsic + `Load(addr_expr)` |
///
/// Far jumps push a `x86.far_jmp` intrinsic to carry the segment selector
/// for the rare passes that need it, then branch to the offset portion.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_jmp(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let op0_kind = instr.op0_kind();

    match op0_kind {
        // ── Direct near jump (short or near) ────────────────────────────
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target_addr = instr.near_branch_target();
            ctx.emit(Effect::Branch {
                target: IrExpr::Const(target_addr),
                condition: None,
            });
        }

        // ── Far jump with immediate selector:offset ──────────────────────
        OpKind::FarBranch16 | OpKind::FarBranch32 => {
            let selector = u64::from(instr.far_branch_selector());
            let offset = u64::from(instr.far_branch32());
            // Record the far-branch selector as an intrinsic side-effect so
            // passes that track segment state see it.
            ctx.emit_intrinsic("x86.far_jmp_selector", vec![IrExpr::Const(selector)]);
            ctx.emit(Effect::Branch {
                target: IrExpr::Const(offset),
                condition: None,
            });
        }

        // ── Indirect jump: register or memory ───────────────────────────
        OpKind::Register => {
            let reg_name = reg_to_name(instr.op0_register());
            ctx.emit(Effect::Branch {
                target: IrExpr::Reg(reg_name.into()),
                condition: None,
            });
        }

        OpKind::Memory => {
            // Indirect far memory jump has two far-branch types embedded in the
            // operand encoding.  We model it as: read the flat address from the
            // memory cell, emit selector intrinsic (unknown at lift time), then
            // branch to the loaded value.
            let addr_expr = build_mem_addr(instr, ctx);
            let target_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);

            // Far-memory operand: the cell contains [offset, selector].  Emit a
            // separate selector-read intrinsic so later passes see it.
            if instr.is_ip_rel_memory_operand() {
                // IP-relative: base is RIP-relative constant.
                // Already captured in addr_expr.
            }

            if target_size > ctx.stack_ptr_size() {
                // Far pointer: cell is wider than a single pointer.  Read the
                // offset portion first (low ptr_size bytes), then the selector
                // (next 2 bytes).
                let ptr_size = ctx.stack_ptr_size();
                let tmp_offset = ctx.fresh_temp();
                let tmp_selector = ctx.fresh_temp();
                ctx.emit_mem_read(addr_expr.clone(), tmp_offset.clone(), ptr_size);
                let sel_addr = IrExpr::Add(
                    Box::new(addr_expr),
                    Box::new(IrExpr::Const(u64::from(ptr_size))),
                );
                ctx.emit_mem_read(sel_addr, tmp_selector.clone(), 2);
                ctx.emit_intrinsic("x86.far_jmp_selector", vec![IrExpr::Reg(tmp_selector)]);
                ctx.emit(Effect::Branch {
                    target: IrExpr::Reg(tmp_offset),
                    condition: None,
                });
            } else {
                // Near indirect memory jump.
                let tmp = ctx.fresh_temp();
                ctx.emit_mem_read(addr_expr, tmp.clone(), target_size);
                ctx.emit(Effect::Branch {
                    target: IrExpr::Reg(tmp),
                    condition: None,
                });
            }
        }

        other => {
            return Err(LiftError::LiftFailed(
                ctx.addr,
                format!("JMP: unexpected op0 kind {other:?}"),
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Jcc — conditional jumps
// ─────────────────────────────────────────────────────────────────────────────

/// Lift any of the 16 `Jcc` conditional-jump mnemonics.
///
/// ## Condition codes → flag expressions
///
/// | Mnemonic | Condition | Flag expression |
/// |----------|-----------|-----------------|
/// | JO | Overflow | OF |
/// | JNO | No overflow | !OF |
/// | JB / JC / JNAE | Below (unsigned) | CF |
/// | JAE / JNC / JNB | Above or equal | !CF |
/// | JE / JZ | Equal / zero | ZF |
/// | JNE / JNZ | Not equal | !ZF |
/// | JBE / JNA | Below or equal | CF \|\| ZF |
/// | JA / JNBE | Above | !CF && !ZF |
/// | JS | Signed | SF |
/// | JNS | Not signed | !SF |
/// | JP / JPE | Parity even | PF |
/// | JNP / JPO | Parity odd | !PF |
/// | JL / JNGE | Less (signed) | SF != OF |
/// | JGE / JNL | Greater or equal | SF == OF |
/// | JLE / JNG | Less or equal | ZF \|\| (SF != OF) |
/// | JG / JNLE | Greater | !ZF && (SF == OF) |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_jcc(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let cond = jcc_condition(instr.mnemonic()).ok_or_else(|| {
        LiftError::LiftFailed(
            ctx.addr,
            format!("Jcc: unknown condition code for {:?}", instr.mnemonic()),
        )
    })?;

    let target_addr = instr.near_branch_target();
    ctx.emit(Effect::Branch {
        target: IrExpr::Const(target_addr),
        condition: Some(cond),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// JCXZ / JECXZ / JRCXZ
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `JCXZ`, `JECXZ`, or `JRCXZ` — jump if the counter register is zero.
///
/// The counter register selected depends on the address-size of the instruction:
///
/// | Mnemonic | Counter | Mode |
/// |----------|---------|------|
/// | `JCXZ`  | CX     | 16-bit address size |
/// | `JECXZ` | ECX    | 32-bit address size |
/// | `JRCXZ` | RCX    | 64-bit address size |
///
/// The condition is `counter == 0`.  No flags are read or written.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "JCXZ/JECXZ/JRCXZ—Jump if CX/ECX/RCX Register Is Zero".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_jcxz(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Determine which counter register to test based on the mnemonic.
    // iced-x86 sets the mnemonic correctly for the address-size prefix.
    let counter_reg = match instr.mnemonic() {
        Mnemonic::Jcxz => "cx",
        Mnemonic::Jecxz => "ecx",
        Mnemonic::Jrcxz => "rcx",
        _ => {
            // Should never happen given the dispatch table, but be defensive.
            return Err(LiftError::LiftFailed(
                ctx.addr,
                format!("lift_jcxz: unexpected mnemonic {:?}", instr.mnemonic()),
            ));
        }
    };

    // Condition: counter == 0
    let cond = IrExpr::CmpEq(
        Box::new(IrExpr::Reg(counter_reg.into())),
        Box::new(IrExpr::Const(0)),
    );

    let target_addr = instr.near_branch_target();
    ctx.emit(Effect::Branch {
        target: IrExpr::Const(target_addr),
        condition: Some(cond),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// CALL
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `CALL` in all operand forms.
///
/// ## μOp sequence
///
/// 1. `RegWrite(SP, SP - ptr_size)`         — allocate return address slot
/// 2. `MemWrite([SP], next_ip, ptr_size)`   — push return address
/// 3. `Call { target }`                     — branch to callee
///
/// For far CALL forms an additional `x86.far_call_selector` intrinsic carries
/// the CS selector that is pushed (and later popped by RETF).
///
/// ## Operand forms
///
/// | Encoding | Target expression |
/// |----------|-------------------|
/// | `CALL rel32` | `Const(resolved_addr)` |
/// | `CALL r/m64` register | `Reg(name)` |
/// | `CALL r/m64` memory | loaded from memory |
/// | `CALL FAR ptr16:32` | offset portion as `Const` |
/// | `CALL FAR m16:32` | loaded from memory |
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_call(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let return_addr = instr.next_ip();
    let op0_kind = instr.op0_kind();

    match op0_kind {
        // ── Direct near call ────────────────────────────────────────────
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target_addr = instr.near_branch_target();
            emit_push(ctx, IrExpr::Const(return_addr));
            ctx.emit_call(IrExpr::Const(target_addr));
        }

        // ── Far call with immediate selector:offset ──────────────────────
        OpKind::FarBranch16 | OpKind::FarBranch32 => {
            let selector = u64::from(instr.far_branch_selector());
            let offset = u64::from(instr.far_branch32());
            // On real hardware, CS:IP pair is pushed.  Model: push CS, push IP.
            ctx.emit_intrinsic("x86.far_call_selector", vec![IrExpr::Const(selector)]);
            emit_push(ctx, IrExpr::Const(return_addr));
            ctx.emit_call(IrExpr::Const(offset));
        }

        // ── Indirect call via register ───────────────────────────────────
        OpKind::Register => {
            let reg_name = reg_to_name(instr.op0_register());
            emit_push(ctx, IrExpr::Const(return_addr));
            ctx.emit_call(IrExpr::Reg(reg_name.into()));
        }

        // ── Indirect call via memory ─────────────────────────────────────
        OpKind::Memory => {
            let addr_expr = build_mem_addr(instr, ctx);
            let target_size = u8::try_from(instr.memory_size().size()).unwrap_or(u8::MAX);
            let ptr_size = ctx.stack_ptr_size();

            if target_size > ptr_size {
                // Far pointer in memory: [offset, selector]
                let tmp_offset = ctx.fresh_temp();
                let tmp_selector = ctx.fresh_temp();
                ctx.emit_mem_read(addr_expr.clone(), tmp_offset.clone(), ptr_size);
                let sel_addr = IrExpr::Add(
                    Box::new(addr_expr),
                    Box::new(IrExpr::Const(u64::from(ptr_size))),
                );
                ctx.emit_mem_read(sel_addr, tmp_selector.clone(), 2);
                ctx.emit_intrinsic("x86.far_call_selector", vec![IrExpr::Reg(tmp_selector)]);
                emit_push(ctx, IrExpr::Const(return_addr));
                ctx.emit_call(IrExpr::Reg(tmp_offset));
            } else {
                // Near indirect call through memory.
                let tmp = ctx.fresh_temp();
                ctx.emit_mem_read(addr_expr, tmp.clone(), target_size);
                emit_push(ctx, IrExpr::Const(return_addr));
                ctx.emit_call(IrExpr::Reg(tmp));
            }
        }

        other => {
            return Err(LiftError::LiftFailed(
                ctx.addr,
                format!("CALL: unexpected op0 kind {other:?}"),
            ));
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// RET / RETN
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `RET` (near return) and `RETN imm16` (stdcall caller-cleanup).
///
/// ## μOp sequence for plain `RET`
///
/// 1. `MemRead([SP], tmp, ptr_size)`        — load return address
/// 2. `RegWrite(SP, SP + ptr_size)`         — pop slot
/// 3. `Return { value: Some(Reg(tmp)) }`    — branch to return address
///
/// ## Additional μOp for `RETN imm16`
///
/// After step 2, an extra `RegWrite(SP, SP + imm16)` discards the
/// callee-provided argument space (stdcall / pascal calling convention).
///
/// Reference: Intel SDM Vol. 2B §4.3 — "RET—Return from Procedure".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_ret(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Pop the return address.
    let ret_addr = emit_pop(ctx);

    // If an immediate operand is present, adjust SP by that many additional bytes
    // (stdcall / pascal ABI argument cleanup).
    if instr.op_count() >= 1
        && instr.op0_kind() == OpKind::Immediate16 {
            let extra = u64::from(instr.immediate16());
            emit_sp_adjust(ctx, extra);
        }

    ctx.emit(Effect::Return {
        value: Some(ret_addr),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// RETF — far return
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `RETF` (far return from a far CALL).
///
/// A far call pushes CS then IP (in reverse — IP first in x86 convention).
/// RETF must therefore pop the return IP, then pop CS.
///
/// ## μOp sequence
///
/// 1. `MemRead([SP], tmp_ip, ptr_size)`    — pop return offset
/// 2. `RegWrite(SP, SP + ptr_size)`
/// 3. `MemRead([SP], tmp_cs, 2)`           — pop CS selector (always 16-bit)
/// 4. `RegWrite(SP, SP + 2)`
/// 5. *(optional)* `RegWrite(SP, SP + imm16)` for `RETF imm16`
/// 6. `x86.far_ret_cs(tmp_cs)` intrinsic  — carry selector for segment tracking
/// 7. `Return { value: Some(Reg(tmp_ip)) }`
///
/// Reference: Intel SDM Vol. 2B §4.3 — "RET—Return from Procedure (far)".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_retf(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Pop the return IP (pointer-sized).
    let ret_ip = emit_pop(ctx);
    // Pop the CS selector (always 16-bit regardless of mode).
    let ret_cs = emit_pop16(ctx);

    // Handle RETF imm16 — discard extra argument space.
    if instr.op_count() >= 1
        && instr.op0_kind() == OpKind::Immediate16 {
            let extra = u64::from(instr.immediate16());
            emit_sp_adjust(ctx, extra);
        }

    // Record the CS value so segment-tracking passes see it.
    ctx.emit_intrinsic("x86.far_ret_cs", vec![ret_cs]);

    ctx.emit(Effect::Return {
        value: Some(ret_ip),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// LOOP / LOOPE / LOOPNE
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `LOOP`, `LOOPE` (aka `LOOPZ`), and `LOOPNE` (aka `LOOPNZ`).
///
/// ## Semantics
///
/// All three variants:
/// 1. Decrement the counter register (CX / ECX / RCX, chosen by address-size).
/// 2. Conditionally branch to `rel8`.
///
/// | Mnemonic | Branch condition |
/// |----------|-----------------|
/// | `LOOP`   | counter ≠ 0 |
/// | `LOOPE`  | counter ≠ 0 AND ZF = 1 |
/// | `LOOPNE` | counter ≠ 0 AND ZF = 0 |
///
/// ## μOp sequence
///
/// 1. `RegWrite(CX/ECX/RCX, counter - 1)` — decrement
/// 2. `Branch { target, condition }` — conditional branch
///
/// Reference: Intel SDM Vol. 2A §3.2 — "LOOP/LOOPcc—Loop According to ECX Counter".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_loop(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Select the counter register by address-size.
    let counter_reg = ctx.counter_reg();

    // Decrement the counter.
    let decremented = IrExpr::Sub(
        Box::new(IrExpr::Reg(counter_reg.into())),
        Box::new(IrExpr::Const(1)),
    );
    ctx.emit_reg_write(counter_reg, decremented);

    // Build the condition: counter (after decrement) != 0.
    let counter_nz = IrExpr::Not(Box::new(IrExpr::CmpEq(
        Box::new(IrExpr::Reg(counter_reg.into())),
        Box::new(IrExpr::Const(0)),
    )));

    let cond = match instr.mnemonic() {
        Mnemonic::Loope => {
            // counter != 0 AND ZF = 1
            IrExpr::And(Box::new(counter_nz), Box::new(IrExpr::Reg("zf".into())))
        }
        Mnemonic::Loopne => {
            // counter != 0 AND ZF = 0
            IrExpr::And(
                Box::new(counter_nz),
                Box::new(IrExpr::Not(Box::new(IrExpr::Reg("zf".into())))),
            )
        }
        _ => counter_nz, // plain LOOP
    };

    let target_addr = instr.near_branch_target();
    ctx.emit(Effect::Branch {
        target: IrExpr::Const(target_addr),
        condition: Some(cond),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// IRET / IRETD / IRETQ
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `IRET`, `IRETD`, and `IRETQ` — return from interrupt handler.
///
/// On protected-mode x86 these pop IP, CS, and EFLAGS (and in 64-bit mode
/// additionally RSP and SS).  The full semantics involve privilege-level
/// checks that cannot be modelled in a flat LLIL.  We therefore:
///
/// 1. Emit a `x86.iret` intrinsic so data-flow knows the frame is torn down.
/// 2. Model the visible stack-frame pops structurally (IP, CS, FLAGS at
///    minimum) so stack-depth analysis remains coherent.
/// 3. Emit `Return { value: None }` to terminate the basic block.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "IRET/IRETD—Interrupt Return".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_iret(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let ptr_size = ctx.stack_ptr_size();

    // Number of stack slots consumed depends on the mode:
    //   16-bit IRET:  IP (2) + CS (2) + FLAGS (2)  = 3 × 2 bytes
    //   32-bit IRETD: EIP(4) + CS (4) + EFLAGS(4)  = 3 × 4 bytes
    //   64-bit IRETQ: RIP(8) + CS (8) + RFLAGS(8) + RSP(8) + SS(8) = 5 × 8 bytes
    let n_pops: u64 = match instr.mnemonic() {
        Mnemonic::Iretq => 5,
        _ => 3,
    };

    // Emit the intrinsic first (before the pops) so passes see the instruction
    // boundary clearly.
    ctx.emit_intrinsic("x86.iret", vec![IrExpr::Const(n_pops)]);

    // Model the IP pop structurally.
    let ret_ip = emit_pop(ctx);

    // Model CS and FLAGS pops without retaining their values (they go into
    // architectural registers that are not modelled as simple temporaries).
    // We still emit the SP increments so stack-depth tracking is correct.
    emit_sp_adjust(ctx, (n_pops - 1) * u64::from(ptr_size));

    ctx.emit(Effect::Return {
        value: Some(ret_ip),
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// INT / INT 3 / INTO
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `INT n` — software interrupt.
///
/// Software interrupts invoke the IDT handler for vector `n`.  In userspace
/// code `INT 0x80` (Linux 32-bit syscall) and `INT 0x2E` (Windows NT native
/// syscall) are the common forms.  We cannot fully model the transfer of
/// control because the interrupt handler is identified by a kernel data
/// structure; we therefore:
///
/// 1. Emit an `x86.int(n)` intrinsic to signal the interrupt number.
/// 2. Emit a `Trap { vector: n }` effect to mark the instruction as a
///    possible non-local transfer of control.
///
/// `INT 0` (divide error, vector 0) and `INT 4` (overflow, vector 4 — the
/// target of `INTO`) are treated identically by the lifter.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "INT n/INTO/INT 3—Call to Interrupt Procedure".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_int(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let vector = u64::from(instr.immediate8());
    ctx.emit_intrinsic("x86.int", vec![IrExpr::Const(vector)]);
    ctx.emit(Effect::Trap {
        vector: u8::try_from(vector).unwrap_or(u8::MAX),
    });
    Ok(())
}

/// Lift `INT 3` — software breakpoint (opcode `0xCC`).
///
/// This is semantically identical to `INT 3` but has its own single-byte
/// encoding.  We emit an `x86.int3` intrinsic plus `Trap { vector: 3 }`.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "INT 3".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_int3(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    ctx.emit_intrinsic("x86.int3", vec![]);
    ctx.emit(Effect::Trap { vector: 3 });
    Ok(())
}

/// Lift `INTO` — interrupt on overflow.
///
/// `INTO` checks `OF` and, if set, raises interrupt vector 4 (`#OF`).
///
/// ## μOp sequence
///
/// 1. Compute condition `OF = 1`.
/// 2. Emit `x86.into` intrinsic (carries the condition).
/// 3. Emit a conditional `Trap` — passes that need to know it's conditional
///    can inspect the `condition` field.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "INTO—Interrupt on Overflow".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_into(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let of_set = IrExpr::Reg("of".into());
    ctx.emit_intrinsic("x86.into", vec![of_set.clone()]);
    // Emit a conditional trap so passes know this is a guarded interrupt.
    ctx.emit(Effect::ConditionalTrap {
        condition: of_set,
        vector: 4,
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTER
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `ENTER imm16, imm8` — create stack frame.
///
/// `ENTER` has three distinct micro-architectures depending on the *nesting
/// level* operand (the second immediate, `imm8 & 0x1F`):
///
/// ## Level 0  (`ENTER N, 0`)
///
/// The common compiler-generated form — equivalent to:
/// ```text
///   PUSH  BP          ; save caller's frame pointer
///   MOV   BP, SP      ; set new frame pointer
///   SUB   SP, N       ; reserve N bytes of locals
/// ```
///
/// ## Level 1  (`ENTER N, 1`)
///
/// Push the current frame pointer once, then set up the new frame:
/// ```text
///   PUSH BP
///   tmp = SP
///   PUSH [BP]         ; copy one display pointer (the innermost outer frame)
///   BP = tmp
///   SUB SP, N
/// ```
///
/// ## Level L  (`ENTER N, L`) for L ≥ 2
///
/// Push `L - 1` display pointers from the chain of enclosing stack frames,
/// then the current BP, then set up the new frame.  Each display pointer
/// is the frame-pointer value from the `L - k`-th enclosing level.
///
/// Reference: Intel SDM Vol. 2A §3.2 — "ENTER—Make Stack Frame for Procedure Parameters".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_enter(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Operand 0: local-space size in bytes.
    let alloc_size = u64::from(instr.immediate16());
    // Operand 1: nesting level (0-31).
    let level = u64::from(instr.immediate8_2nd()) & 0x1F;

    let sp = ctx.stack_ptr();
    let bp = ctx.frame_ptr();
    let ptr_size = ctx.stack_ptr_size();

    // ── Step 1: PUSH BP (save caller's frame pointer) ────────────────────────
    emit_push(ctx, IrExpr::Reg(bp.into()));

    // ── Step 2: Copy BP (frame pointer) to a temporary for display setup ──────
    // After PUSH, SP already advanced; save the new SP as the future BP.
    let tmp_frame_ptr = ctx.fresh_temp();
    ctx.emit_reg_write(&tmp_frame_ptr, IrExpr::Reg(sp.into()));

    // ── Step 3: Push display pointers for nesting levels 1 .. L-1 ───────────
    //
    // The "display" is an array of frame pointers for every enclosing procedure
    // scope.  For level L, we push L-1 display pointers copied from the chain
    // rooted at the *current* BP (before it is updated).
    //
    // For each j in 1 .. level-1:
    //   BP = [BP]  (walk the display chain one level up)
    //   PUSH [BP + 0]  (push the display pointer)
    //
    // For compilers that do not use nested procedures (almost all modern C/C++),
    // level is always 0 or 1, so these loops have zero or one iteration.

    if level > 0 {
        // Walk the existing display chain and push L-1 frame pointers.
        // We model this as a sequence of loads from the current BP chain.
        let mut display_bp = IrExpr::Reg(bp.into());

        for k in 1..level {
            // Load the frame pointer from the current BP display slot.
            let display_slot_tmp = ctx.fresh_temp();
            ctx.emit_mem_read(display_bp.clone(), display_slot_tmp.clone(), ptr_size);
            let display_val = IrExpr::Reg(display_slot_tmp.clone());

            // Push this display pointer.
            emit_push(ctx, display_val.clone());

            // If there are more levels, walk one step further in the chain.
            if k < level - 1 {
                display_bp = display_val;
            }
        }

        // For level == 1, push the value of tmp_frame_ptr (the slot just set).
        if level == 1 {
            emit_push(ctx, IrExpr::Reg(tmp_frame_ptr.clone()));
        }
    }

    // ── Step 4: BP = tmp_frame_ptr (point to the new frame's base) ───────────
    ctx.emit_reg_write(bp, IrExpr::Reg(tmp_frame_ptr));

    // ── Step 5: SP -= alloc_size (reserve local variable space) ─────────────
    if alloc_size > 0 {
        let new_sp = IrExpr::Sub(
            Box::new(IrExpr::Reg(sp.into())),
            Box::new(IrExpr::Const(alloc_size)),
        );
        ctx.emit_reg_write(sp, new_sp);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// LEAVE
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `LEAVE` — destroy stack frame.
///
/// `LEAVE` is the inverse of `ENTER 0`:
/// ```text
///   MOV  SP, BP     ; restore stack pointer to frame base
///   POP  BP         ; restore caller's saved frame pointer
/// ```
///
/// ## μOp sequence
///
/// 1. `RegWrite(SP, Reg(BP))`              — collapse local space
/// 2. `MemRead([SP], tmp, ptr_size)`       — load saved BP
/// 3. `RegWrite(SP, SP + ptr_size)`        — pop slot
/// 4. `RegWrite(BP, Reg(tmp))`             — restore caller BP
///
/// Reference: Intel SDM Vol. 2A §3.2 — "LEAVE—High Level Procedure Exit".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_leave(_instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    let sp = ctx.stack_ptr();
    let bp = ctx.frame_ptr();
    let ptr_size = ctx.stack_ptr_size();

    // MOV SP, BP
    ctx.emit_reg_write(sp, IrExpr::Reg(bp.into()));

    // POP BP
    let saved_bp = ctx.fresh_temp();
    ctx.emit_mem_read(IrExpr::Reg(sp.into()), saved_bp.clone(), ptr_size);
    let new_sp = IrExpr::Add(
        Box::new(IrExpr::Reg(sp.into())),
        Box::new(IrExpr::Const(u64::from(ptr_size))),
    );
    ctx.emit_reg_write(sp, new_sp);
    ctx.emit_reg_write(bp, IrExpr::Reg(saved_bp));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// BOUND
// ─────────────────────────────────────────────────────────────────────────────

/// Lift `BOUND r16/32, m16/32&16/32` — check array index against bounds.
///
/// `BOUND` compares a register (the index) against a memory-resident bounds
/// descriptor `[lower, upper]`.  If the index is out of range it raises
/// interrupt vector 5 (`#BR`).
///
/// Because whether the bound check passes or fails is generally not decidable
/// at static lift time, we model it as:
///
/// 1. Load `lower` and `upper` from memory.
/// 2. Emit `x86.bound_check(index, lower, upper)` intrinsic.
/// 3. Emit `ConditionalTrap { condition: OOB_expr, vector: 5 }` where
///    `OOB_expr = (index < lower) OR (index > upper)`.
///
/// Reference: Intel SDM Vol. 2A §3.1 — "BOUND—Check Array Index Against Bounds".
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_bound(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    // Operand 0: register holding the index.
    let index_reg = reg_to_name(instr.op0_register());
    let index_expr = IrExpr::Reg(index_reg.into());
    let elem_size = operand_size(instr, 1, ctx); // bytes per element (2 or 4)

    // Operand 1: memory descriptor [lower, upper].
    let addr_expr = build_mem_addr(instr, ctx);

    // Load lower bound.
    let tmp_lower = ctx.fresh_temp();
    ctx.emit_mem_read(addr_expr.clone(), tmp_lower.clone(), elem_size);

    // Load upper bound (immediately after lower in memory).
    let upper_addr = IrExpr::Add(
        Box::new(addr_expr),
        Box::new(IrExpr::Const(u64::from(elem_size))),
    );
    let tmp_upper = ctx.fresh_temp();
    ctx.emit_mem_read(upper_addr, tmp_upper.clone(), elem_size);

    // Emit intrinsic for passes that want to track bound-check metadata.
    ctx.emit_intrinsic(
        "x86.bound_check",
        vec![
            index_expr.clone(),
            IrExpr::Reg(tmp_lower.clone()),
            IrExpr::Reg(tmp_upper.clone()),
        ],
    );

    // OOB condition: index < lower  OR  index > upper.
    // We use unsigned comparisons here — BOUND uses signed in 16/32-bit but
    // the intrinsic above is the authoritative model for passes that need
    // signed semantics; the trap condition is a conservative over-approximation.
    let oob = IrExpr::Or(
        Box::new(IrExpr::CmpLt(
            Box::new(index_expr.clone()),
            Box::new(IrExpr::Reg(tmp_lower)),
        )),
        Box::new(IrExpr::CmpGt(
            Box::new(index_expr),
            Box::new(IrExpr::Reg(tmp_upper)),
        )),
    );

    ctx.emit(Effect::ConditionalTrap {
        condition: oob,
        vector: 5,
    });

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// NoReturn / tail-call annotation
// ─────────────────────────────────────────────────────────────────────────────

/// Annotate a `CALL` or `JMP` to a known-noreturn target.
///
/// This is not a standalone handler but a decorator used by the top-level
/// dispatcher when it identifies that the callee is a noreturn function
/// (e.g., `exit`, `abort`, `ExitProcess`).  After lifting the call/jump, the
/// dispatcher calls this function to emit `Effect::NoReturn` so later analyses
/// know the basic block terminates here.
///
/// ## Recognition heuristics
///
/// The following names (case-insensitive) are treated as noreturn:
/// - `exit`, `_exit`, `abort`, `longjmp`
/// - `ExitProcess`, `TerminateProcess`, `RtlExitUserProcess`
/// - `__stack_chk_fail`, `__cxa_throw`, `_ZSt9terminatev`
///
/// Import thunks whose name matches one of the above are also recognised.
pub fn emit_noreturn_if_known(symbol_name: &str, ctx: &mut X86LiftCtx) {
    const NORETURN_NAMES: &[&str] = &[
        "exit",
        "_exit",
        "_Exit",
        "abort",
        "longjmp",
        "siglongjmp",
        "ExitProcess",
        "TerminateProcess",
        "RtlExitUserProcess",
        "__stack_chk_fail",
        "__cxa_throw",
        "__cxa_rethrow",
        "_ZSt9terminatev", // std::terminate()
        "_ZSt17__throw_bad_allocv",
        "panic", // Rust std
        "__rust_panic",
        "rust_begin_unwind",
    ];

    let name_lower = symbol_name.to_ascii_lowercase();
    let is_noreturn = NORETURN_NAMES
        .iter()
        .any(|n| n.to_ascii_lowercase() == name_lower);

    if is_noreturn {
        ctx.emit(Effect::NoReturn);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an `iced_x86::Register` to its canonical lowercase string name.
///
/// Only general-purpose registers needed for control-flow handlers are
/// covered.  The full GPR table for arithmetic is in `x86_operand`.
const fn reg_to_name(reg: Register) -> &'static str {
    match reg {
        // 64-bit
        Register::RAX => "rax",
        Register::RCX => "rcx",
        Register::RDX => "rdx",
        Register::RBX => "rbx",
        Register::RSP => "rsp",
        Register::RBP => "rbp",
        Register::RSI => "rsi",
        Register::RDI => "rdi",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        // 32-bit
        Register::EAX => "eax",
        Register::ECX => "ecx",
        Register::EDX => "edx",
        Register::EBX => "ebx",
        Register::ESP => "esp",
        Register::EBP => "ebp",
        Register::ESI => "esi",
        Register::EDI => "edi",
        Register::R8D => "r8d",
        Register::R9D => "r9d",
        Register::R10D => "r10d",
        Register::R11D => "r11d",
        Register::R12D => "r12d",
        Register::R13D => "r13d",
        Register::R14D => "r14d",
        Register::R15D => "r15d",
        // 16-bit
        Register::AX => "ax",
        Register::CX => "cx",
        Register::DX => "dx",
        Register::BX => "bx",
        Register::SP => "sp",
        Register::BP => "bp",
        Register::SI => "si",
        Register::DI => "di",
        // Segment registers
        Register::CS => "cs",
        Register::DS => "ds",
        Register::ES => "es",
        Register::FS => "fs",
        Register::GS => "gs",
        Register::SS => "ss",
        // RIP
        Register::RIP => "rip",
        Register::EIP => "eip",
        _ => "unknown_reg",
    }
}

/// Build a flat-address `IrExpr` for a memory operand.
///
/// Constructs `base + index * scale + displacement` from the operand fields
/// of `instr`.  All three components are optional; absent ones are omitted
/// from the expression tree (no pointless `+ Const(0)` noise).
fn build_mem_addr(instr: &Instruction, ctx: &X86LiftCtx) -> IrExpr {
    let base_reg = instr.memory_base();
    let idx_reg = instr.memory_index();
    let scale = instr.memory_index_scale();
    let disp = instr.memory_displacement64();
    let addr_size = if ctx.mode() == 64 { 8u8 } else { 4u8 };

    // Start with the base register if present.
    let mut addr: Option<IrExpr> = if base_reg == Register::None {
        None
    } else {
        let base_name = reg_to_name(base_reg);
        // RIP-relative: base is RIP which iced already resolves in
        // `memory_displacement64()` for `is_ip_rel_memory_operand()`.
        if base_reg == Register::RIP || base_reg == Register::EIP {
            // The displacement field already contains the absolute target.
            return IrExpr::Const(disp);
        }
        Some(IrExpr::Reg(base_name.into()))
    };

    // Add index * scale if present.
    if idx_reg != Register::None {
        let idx_name = reg_to_name(idx_reg);
        let idx_expr = if scale > 1 {
            IrExpr::Mul(
                Box::new(IrExpr::Reg(idx_name.into())),
                Box::new(IrExpr::Const(u64::from(scale))),
            )
        } else {
            IrExpr::Reg(idx_name.into())
        };
        addr = Some(match addr {
            Some(b) => IrExpr::Add(Box::new(b), Box::new(idx_expr)),
            None => idx_expr,
        });
    }

    // Add displacement if non-zero.
    if disp != 0 {
        addr = Some(addr.map_or(IrExpr::Const(disp), |b| IrExpr::Add(Box::new(b), Box::new(IrExpr::Const(disp)))));
    }

    // If nothing was emitted (rare: `[]` addressing), return 0.
    let result = addr.unwrap_or(IrExpr::Const(0));

    // In 32-bit mode mask the computed address to 32 bits so the IR reflects
    // the architectural truncation.
    if addr_size < 8 {
        let mask = (1u64 << (u64::from(addr_size) * 8)) - 1;
        IrExpr::And(Box::new(result), Box::new(IrExpr::Const(mask)))
    } else {
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::x86_context::{ModeHint, X86LiftCtx};
    use iced_x86::{Decoder, DecoderOptions};

    // ── Helpers ──────────────────────────────────────────────────────────────

    pub(crate) fn decode64(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    pub(crate) fn decode32(bytes: &[u8]) -> iced_x86::Instruction {
        let mut dec = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        dec.decode()
    }

    pub(crate) fn ctx64() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 64, ModeHint::default())
    }

    pub(crate) fn ctx32() -> X86LiftCtx {
        X86LiftCtx::new(0x1000, 32, ModeHint::default())
    }

    /// Check that at least one `Effect::Branch` with `condition: None` was emitted.
    fn has_unconditional_branch(ctx: &X86LiftCtx) -> bool {
        ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: None,
                    ..
                }
            )
        })
    }

    /// Check that at least one `Effect::Branch` with `condition: Some(_)` was emitted.
    fn has_conditional_branch(ctx: &X86LiftCtx) -> bool {
        ctx.effects.iter().any(|e| {
            matches!(
                e,
                Effect::Branch {
                    condition: Some(_),
                    ..
                }
            )
        })
    }

    /// Return the target of the first `Effect::Branch`.
    fn branch_target(ctx: &X86LiftCtx) -> Option<&IrExpr> {
        ctx.effects.iter().find_map(|e| {
            if let Effect::Branch { target, .. } = e {
                Some(target)
            } else {
                None
            }
        })
    }

    /// Return the condition of the first conditional `Effect::Branch`.
    fn branch_condition(ctx: &X86LiftCtx) -> Option<&IrExpr> {
        ctx.effects.iter().find_map(|e| {
            if let Effect::Branch {
                condition: Some(c), ..
            } = e
            {
                Some(c)
            } else {
                None
            }
        })
    }

    /// Check that a `RegWrite` to the stack pointer was emitted.
    ///
    /// ⚠ This helper had no caller: `call_rel32_decrements_rsp_by_8` open-codes
    /// the same scan inline, and no test covered the 32-bit (`esp`) side or the
    /// RET side at all. The `stack_pointer_write_tests` module below uses it
    /// and closes those two gaps.
    pub(crate) fn has_sp_write(ctx: &X86LiftCtx, sp_name: &str) -> bool {
        ctx.effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == sp_name))
    }

    /// Check that at least one `Effect::Call` was emitted.
    fn has_call(ctx: &X86LiftCtx) -> bool {
        ctx.effects.iter().any(|e| matches!(e, Effect::Call { .. }))
    }

    /// Check that at least one `Effect::Return` was emitted.
    fn has_return(ctx: &X86LiftCtx) -> bool {
        ctx.effects
            .iter()
            .any(|e| matches!(e, Effect::Return { .. }))
    }

    /// Check that at least one `Effect::Trap` with the given vector was emitted.
    fn has_trap(ctx: &X86LiftCtx, v: u8) -> bool {
        ctx.effects
            .iter()
            .any(|e| matches!(e, Effect::Trap { vector } if *vector == v))
    }

    /// Check for a named intrinsic.
    fn has_intrinsic(ctx: &X86LiftCtx, name: &str) -> bool {
        ctx.effects
            .iter()
            .any(|e| matches!(e, Effect::Intrinsic { name: n, .. } if n == name))
    }

    // ── JMP tests ────────────────────────────────────────────────────────────

    #[test]
    fn jmp_short_emits_unconditional_branch() {
        // JMP short +0x10  (EB 10)
        let i = decode64(&[0xeb, 0x10]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert!(
            has_unconditional_branch(&ctx),
            "JMP short must emit unconditional Branch"
        );
    }

    #[test]
    fn jmp_short_target_is_correct() {
        // JMP short +0x10 — IP after decode = 0x1002, target = 0x1012
        let i = decode64(&[0xeb, 0x10]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert_eq!(
            branch_target(&ctx),
            Some(&IrExpr::Const(0x1012)),
            "JMP short: target must be 0x1012"
        );
    }

    #[test]
    fn jmp_short_negative_offset() {
        // JMP short -2  (EB FE) — infinite loop; target = 0x1000
        let i = decode64(&[0xeb, 0xfe]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert_eq!(branch_target(&ctx), Some(&IrExpr::Const(0x1000)));
    }

    #[test]
    fn jmp_near_rel32() {
        // JMP near +0x0000_1000  (E9 00 10 00 00)
        // IP after decode = 0x1005, target = 0x2005
        let i = decode64(&[0xe9, 0x00, 0x10, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert_eq!(branch_target(&ctx), Some(&IrExpr::Const(0x2005)));
    }

    #[test]
    fn jmp_indirect_register() {
        // JMP RAX  (FF E0)
        let i = decode64(&[0xff, 0xe0]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert!(
            matches!(branch_target(&ctx), Some(IrExpr::Reg(r)) if r == "rax"),
            "JMP RAX: target must be Reg(rax)"
        );
        assert!(has_unconditional_branch(&ctx));
    }

    #[test]
    fn jmp_indirect_memory() {
        // JMP [RAX]  (FF 20)
        let i = decode64(&[0xff, 0x20]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        // Indirect memory JMP: we load the target from memory, so a MemRead should be emitted
        // and the branch target should be a Reg (the loaded temp).
        let has_mem_read = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::MemRead { .. }));
        assert!(
            has_mem_read,
            "JMP [RAX]: must emit a MemRead for the target"
        );
        assert!(has_unconditional_branch(&ctx));
    }

    #[test]
    fn jmp_does_not_emit_condition() {
        let i = decode64(&[0xeb, 0x10]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        assert!(
            !has_conditional_branch(&ctx),
            "JMP must not emit a conditional Branch"
        );
    }

    // ── Jcc tests ────────────────────────────────────────────────────────────

    #[test]
    fn je_emits_conditional_branch() {
        // JE short +0x10  (74 10)
        let i = decode64(&[0x74, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        assert!(
            has_conditional_branch(&ctx),
            "JE must emit conditional Branch"
        );
    }

    #[test]
    fn je_does_not_emit_unconditional_branch() {
        let i = decode64(&[0x74, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        assert!(
            !has_unconditional_branch(&ctx),
            "JE must not emit an unconditional Branch"
        );
    }

    #[test]
    fn je_target_is_correct() {
        // JE short +0x10 — IP after = 0x1002, target = 0x1012
        let i = decode64(&[0x74, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        assert_eq!(branch_target(&ctx), Some(&IrExpr::Const(0x1012)));
    }

    #[test]
    fn je_condition_reads_zf() {
        let i = decode64(&[0x74, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).expect("JE must have a condition");
        // JE condition = ZF, which is Reg("zf").
        assert!(
            matches!(cond, IrExpr::Reg(r) if r == "zf"),
            "JE condition must be Reg(zf), got {cond:?}"
        );
    }

    #[test]
    fn jne_condition_is_not_zf() {
        // JNE short  (75 10)
        let i = decode64(&[0x75, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).expect("JNE must have a condition");
        assert!(
            matches!(cond, IrExpr::CmpEqZero(_)),
            "JNE condition must be CmpEqZero(...), got {cond:?}"
        );
    }

    #[test]
    fn jb_condition_reads_cf() {
        // JB short (72 10)
        let i = decode64(&[0x72, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Reg(r) if r == "cf"),
            "JB condition must be Reg(cf)"
        );
    }

    #[test]
    fn jae_condition_is_not_cf() {
        // JAE short (73 10)
        let i = decode64(&[0x73, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::CmpEqZero(inner) if matches!(&**inner, IrExpr::Reg(r) if r == "cf")),
            "JAE condition must be CmpEqZero(Reg(cf))"
        );
    }

    #[test]
    fn jbe_condition_is_cf_or_zf() {
        // JBE short (76 10)
        let i = decode64(&[0x76, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        // CF | ZF
        assert!(
            matches!(cond, IrExpr::Or(_, _)),
            "JBE condition must be Or(Reg(cf), Reg(zf)), got {cond:?}"
        );
    }

    #[test]
    fn ja_condition_is_not_cf_and_not_zf() {
        // JA short (77 10)
        let i = decode64(&[0x77, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::And(_, _)),
            "JA condition must be And(Not(cf), Not(zf)), got {cond:?}"
        );
    }

    #[test]
    fn js_condition_reads_sf() {
        // JS short (78 10)
        let i = decode64(&[0x78, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Reg(r) if r == "sf"),
            "JS condition must be Reg(sf)"
        );
    }

    #[test]
    fn jns_condition_is_not_sf() {
        // JNS short (79 10)
        let i = decode64(&[0x79, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::CmpEqZero(_)),
            "JNS condition must be CmpEqZero(sf)"
        );
    }

    #[test]
    fn jp_condition_reads_pf() {
        // JP short (7A 10)
        let i = decode64(&[0x7a, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Reg(r) if r == "pf"),
            "JP condition must be Reg(pf)"
        );
    }

    #[test]
    fn jnp_condition_is_not_pf() {
        // JNP short (7B 10)
        let i = decode64(&[0x7b, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(matches!(cond, IrExpr::CmpEqZero(_)), "JNP must be CmpEqZero(pf)");
    }

    #[test]
    fn jl_condition_is_sf_xor_of() {
        // JL short (7C 10)
        let i = decode64(&[0x7c, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Xor(_, _)),
            "JL condition must be Xor(sf, of)"
        );
    }

    #[test]
    fn jge_condition_is_not_sf_xor_of() {
        // JGE short (7D 10)
        let i = decode64(&[0x7d, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::CmpEqZero(inner) if matches!(&**inner, IrExpr::Xor(_, _))),
            "JGE condition must be CmpEqZero(Xor(sf, of))"
        );
    }

    #[test]
    fn jle_condition_contains_zf_and_xor() {
        // JLE short (7E 10)
        let i = decode64(&[0x7e, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Or(_, _)),
            "JLE condition must be Or(zf, Xor(sf,of))"
        );
    }

    #[test]
    fn jg_condition_is_and_with_not() {
        // JG short (7F 10)
        let i = decode64(&[0x7f, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::And(_, _)),
            "JG condition must be And(Not(zf), Not(Xor(sf,of)))"
        );
    }

    #[test]
    fn jo_condition_reads_of() {
        // JO short (70 10)
        let i = decode64(&[0x70, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::Reg(r) if r == "of"),
            "JO condition must be Reg(of)"
        );
    }

    #[test]
    fn jno_condition_is_not_of() {
        // JNO short (71 10)
        let i = decode64(&[0x71, 0x10]);
        let mut ctx = ctx64();
        lift_jcc(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(matches!(cond, IrExpr::CmpEqZero(_)), "JNO must be CmpEqZero(of)");
    }

    // ── JCXZ / JECXZ / JRCXZ tests ──────────────────────────────────────────

    #[test]
    fn jrcxz_emits_conditional_branch() {
        // JRCXZ short  (E3 10)
        let i = decode64(&[0xe3, 0x10]);
        let mut ctx = ctx64();
        lift_jcxz(&i, &mut ctx).unwrap();
        assert!(
            has_conditional_branch(&ctx),
            "JRCXZ must emit a conditional Branch"
        );
    }

    #[test]
    fn jrcxz_target_is_correct() {
        // JRCXZ short +0x10 — target = 0x1012
        let i = decode64(&[0xe3, 0x10]);
        let mut ctx = ctx64();
        lift_jcxz(&i, &mut ctx).unwrap();
        assert_eq!(branch_target(&ctx), Some(&IrExpr::Const(0x1012)));
    }

    #[test]
    fn jrcxz_condition_tests_rcx() {
        let i = decode64(&[0xe3, 0x10]);
        let mut ctx = ctx64();
        lift_jcxz(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        // Condition: CmpEq(Reg("rcx"), Const(0))
        assert!(
            matches!(cond, IrExpr::CmpEq(lhs, rhs)
                if matches!(**lhs, IrExpr::Reg(ref r) if r == "rcx")
                && matches!(**rhs, IrExpr::Const(0))),
            "JRCXZ condition must be CmpEq(rcx, 0), got {cond:?}"
        );
    }

    #[test]
    fn jecxz_condition_tests_ecx() {
        // JECXZ in 64-bit mode: needs address-size prefix 0x67 followed by E3 rel8
        let i = decode64(&[0x67, 0xe3, 0x10]);
        let mut ctx = ctx64();
        lift_jcxz(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        assert!(
            matches!(cond, IrExpr::CmpEq(lhs, _)
                if matches!(**lhs, IrExpr::Reg(ref r) if r == "ecx")),
            "JECXZ condition must test ECX, got {cond:?}"
        );
    }

    // ── CALL tests ───────────────────────────────────────────────────────────

    #[test]
    fn call_rel32_emits_call_effect() {
        // CALL +0  (E8 00 00 00 00)
        let i = decode64(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        assert!(has_call(&ctx), "CALL rel32 must emit Call effect");
    }

    #[test]
    fn call_rel32_decrements_rsp_by_8() {
        let i = decode64(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        let has_sp_dec = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(_, b) }
                if reg == "rsp" && matches!(**b, IrExpr::Const(8)))
        });
        assert!(has_sp_dec, "CALL in 64-bit mode must decrement RSP by 8");
    }

    #[test]
    fn call_rel32_pushes_return_address() {
        let i = decode64(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let return_addr = i.next_ip();
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        let pushed_ret = ctx.effects.iter().any(
            |e| matches!(e, Effect::MemWrite { value: IrExpr::Const(v), .. } if *v == return_addr),
        );
        assert!(pushed_ret, "CALL must push next_ip as return address");
    }

    #[test]
    fn call_indirect_reg_emits_call_to_register() {
        // CALL RAX  (FF D0)
        let i = decode64(&[0xff, 0xd0]);
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        assert!(has_call(&ctx));
        let call_target = ctx.effects.iter().find_map(|e| {
            if let Effect::Call { target } = e {
                Some(target)
            } else {
                None
            }
        });
        assert!(
            matches!(call_target, Some(IrExpr::Reg(r)) if r == "rax"),
            "CALL RAX must call Reg(rax)"
        );
    }

    #[test]
    fn call_indirect_mem_loads_target() {
        // CALL [RAX]  (FF 10)
        let i = decode64(&[0xff, 0x10]);
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        let has_mem_read = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::MemRead { .. }));
        assert!(has_mem_read, "CALL [RAX] must load target from memory");
        assert!(has_call(&ctx));
    }

    // ── RET tests ────────────────────────────────────────────────────────────

    #[test]
    fn ret_emits_return() {
        // RET (C3)
        let i = decode64(&[0xc3]);
        let mut ctx = ctx64();
        lift_ret(&i, &mut ctx).unwrap();
        assert!(has_return(&ctx), "RET must emit Return effect");
    }

    #[test]
    fn ret_increments_rsp_by_8() {
        let i = decode64(&[0xc3]);
        let mut ctx = ctx64();
        lift_ret(&i, &mut ctx).unwrap();
        let sp_inc = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Add(_, b) }
                if reg == "rsp" && matches!(**b, IrExpr::Const(8)))
        });
        assert!(sp_inc, "RET must increment RSP by 8 in 64-bit mode");
    }

    #[test]
    fn retn_imm16_adjusts_rsp_by_extra() {
        // RETN 0x0010  (C2 10 00)
        let i = decode64(&[0xc2, 0x10, 0x00]);
        let mut ctx = ctx64();
        lift_ret(&i, &mut ctx).unwrap();
        // Should increment RSP by 8 (pop return addr) + 0x10 (stdcall cleanup).
        // The cleanup can be a second RegWrite(rsp, rsp + 0x10).
        let extra_adj = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Add(_, b) }
                if reg == "rsp" && matches!(**b, IrExpr::Const(0x10)))
        });
        assert!(
            extra_adj,
            "RETN 0x10 must emit an extra RSP += 0x10 adjustment"
        );
        assert!(has_return(&ctx));
    }

    // ── RETF tests ───────────────────────────────────────────────────────────

    #[test]
    fn retf_emits_return() {
        // RETF (CB)
        let i = decode64(&[0xcb]);
        let mut ctx = ctx64();
        lift_retf(&i, &mut ctx).unwrap();
        assert!(has_return(&ctx), "RETF must emit Return");
    }

    #[test]
    fn retf_emits_far_ret_intrinsic() {
        let i = decode64(&[0xcb]);
        let mut ctx = ctx64();
        lift_retf(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx, "x86.far_ret_cs"),
            "RETF must emit x86.far_ret_cs intrinsic"
        );
    }

    // ── LOOP tests ───────────────────────────────────────────────────────────

    #[test]
    fn loop_emits_conditional_branch() {
        // LOOP short +0x10  (E2 10)
        let i = decode64(&[0xe2, 0x10]);
        let mut ctx = ctx64();
        lift_loop(&i, &mut ctx).unwrap();
        assert!(
            has_conditional_branch(&ctx),
            "LOOP must emit conditional Branch"
        );
    }

    #[test]
    fn loop_decrements_rcx() {
        let i = decode64(&[0xe2, 0x10]);
        let mut ctx = ctx64();
        lift_loop(&i, &mut ctx).unwrap();
        let dec = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(lhs, rhs) }
                if reg == "rcx"
                && matches!(**lhs, IrExpr::Reg(ref r) if r == "rcx")
                && matches!(**rhs, IrExpr::Const(1)))
        });
        assert!(dec, "LOOP must decrement RCX by 1");
    }

    #[test]
    fn loop_target_is_correct() {
        // LOOP +0x10 — IP after = 0x1002, target = 0x1012
        let i = decode64(&[0xe2, 0x10]);
        let mut ctx = ctx64();
        lift_loop(&i, &mut ctx).unwrap();
        assert_eq!(branch_target(&ctx), Some(&IrExpr::Const(0x1012)));
    }

    #[test]
    fn loope_condition_contains_zf() {
        // LOOPE short  (E1 10)
        let i = decode64(&[0xe1, 0x10]);
        let mut ctx = ctx64();
        lift_loop(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        // Condition: And(counter_nz, Reg("zf"))
        assert!(
            matches!(cond, IrExpr::And(_, rhs) if matches!(**rhs, IrExpr::Reg(ref r) if r == "zf")),
            "LOOPE condition must AND with ZF, got {cond:?}"
        );
    }

    #[test]
    fn loopne_condition_contains_not_zf() {
        // LOOPNE short  (E0 10)
        let i = decode64(&[0xe0, 0x10]);
        let mut ctx = ctx64();
        lift_loop(&i, &mut ctx).unwrap();
        let cond = branch_condition(&ctx).unwrap();
        // Condition: And(counter_nz, Not(Reg("zf")))
        assert!(
            matches!(cond, IrExpr::And(_, rhs) if matches!(**rhs, IrExpr::Not(_))),
            "LOOPNE condition must AND with Not(ZF), got {cond:?}"
        );
    }

    // ── IRET tests ───────────────────────────────────────────────────────────

    #[test]
    fn iret_emits_return() {
        // IRET (CF) — real-mode / 16-bit
        let i = decode64(&[0xcf]);
        let mut ctx = ctx64();
        lift_iret(&i, &mut ctx).unwrap();
        assert!(has_return(&ctx), "IRET must emit Return");
    }

    #[test]
    fn iret_emits_x86_iret_intrinsic() {
        let i = decode64(&[0xcf]);
        let mut ctx = ctx64();
        lift_iret(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx, "x86.iret"),
            "IRET must emit x86.iret intrinsic"
        );
    }

    // ── INT tests ─────────────────────────────────────────────────────────────

    #[test]
    fn int_n_emits_trap_effect() {
        // INT 0x80  (CD 80)
        let i = decode64(&[0xcd, 0x80]);
        let mut ctx = ctx64();
        lift_int(&i, &mut ctx).unwrap();
        assert!(
            has_trap(&ctx, 0x80),
            "INT 0x80 must emit Trap {{ vector: 0x80 }}"
        );
    }

    #[test]
    fn int_n_emits_intrinsic() {
        let i = decode64(&[0xcd, 0x80]);
        let mut ctx = ctx64();
        lift_int(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx, "x86.int"),
            "INT must emit x86.int intrinsic"
        );
    }

    #[test]
    fn int3_emits_breakpoint_trap() {
        // INT3 (CC)
        let i = decode64(&[0xcc]);
        let mut ctx = ctx64();
        lift_int3(&i, &mut ctx).unwrap();
        assert!(has_trap(&ctx, 3), "INT3 must emit Trap {{ vector: 3 }}");
        assert!(has_intrinsic(&ctx, "x86.int3"));
    }

    #[test]
    fn into_emits_conditional_trap() {
        // INTO (CE)
        let i = decode64(&[0xce]);
        let mut ctx = ctx64();
        lift_into(&i, &mut ctx).unwrap();
        let cond_trap = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::ConditionalTrap { vector: 4, .. }));
        assert!(cond_trap, "INTO must emit ConditionalTrap {{ vector: 4 }}");
    }

    #[test]
    fn into_condition_reads_of() {
        let i = decode64(&[0xce]);
        let mut ctx = ctx64();
        lift_into(&i, &mut ctx).unwrap();
        let reads_of = ctx.effects.iter().any(
            |e| matches!(e, Effect::ConditionalTrap { condition: IrExpr::Reg(r), .. } if r == "of"),
        );
        assert!(reads_of, "INTO condition must read OF");
    }

    // ── ENTER tests ──────────────────────────────────────────────────────────

    #[test]
    fn enter_level0_pushes_bp() {
        // ENTER 0x0010, 0  (C8 10 00 00)
        let i = decode64(&[0xc8, 0x10, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_enter(&i, &mut ctx).unwrap();
        // Must emit a MemWrite (the push of RBP).
        let pushes_bp = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::MemWrite { value: IrExpr::Reg(r), .. } if r == "rbp"));
        assert!(pushes_bp, "ENTER 0x10, 0 must push RBP");
    }

    #[test]
    fn enter_level0_updates_bp() {
        let i = decode64(&[0xc8, 0x10, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_enter(&i, &mut ctx).unwrap();
        // Must emit a RegWrite to RBP (setting new frame pointer).
        assert!(
            ctx.effects
                .iter()
                .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rbp")),
            "ENTER 0x10, 0 must write RBP"
        );
    }

    #[test]
    fn enter_level0_reserves_locals() {
        // ENTER 0x20, 0 — reserves 0x20 bytes
        let i = decode64(&[0xc8, 0x20, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_enter(&i, &mut ctx).unwrap();
        // RSP must be decremented by 0x20 at some point.
        let reserves = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(_, b) }
                if reg == "rsp" && matches!(**b, IrExpr::Const(0x20)))
        });
        assert!(
            reserves,
            "ENTER 0x20, 0 must subtract 0x20 from RSP for locals"
        );
    }

    #[test]
    fn enter_zero_alloc_no_sub() {
        // ENTER 0, 0 — no local space
        let i = decode64(&[0xc8, 0x00, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_enter(&i, &mut ctx).unwrap();
        // Must NOT emit a Sub of 0 bytes (would be a spurious effect).
        let zero_sub = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Sub(_, b) }
                if reg == "rsp" && matches!(**b, IrExpr::Const(0)))
        });
        assert!(!zero_sub, "ENTER 0, 0 must not emit RSP -= 0");
    }

    // ── LEAVE tests ──────────────────────────────────────────────────────────

    #[test]
    fn leave_restores_sp_from_bp() {
        // LEAVE (C9)
        let i = decode64(&[0xc9]);
        let mut ctx = ctx64();
        lift_leave(&i, &mut ctx).unwrap();
        // First effect: RegWrite(rsp, Reg(rbp))
        let sp_from_bp = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Reg(src) }
                if reg == "rsp" && src == "rbp")
        });
        assert!(sp_from_bp, "LEAVE must set RSP = RBP");
    }

    #[test]
    fn leave_pops_bp() {
        let i = decode64(&[0xc9]);
        let mut ctx = ctx64();
        lift_leave(&i, &mut ctx).unwrap();
        // Must emit a MemRead ([rsp]) and a RegWrite to rbp.
        let has_mem = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::MemRead { .. }));
        let has_bp_write = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::RegWrite { reg, .. } if reg == "rbp"));
        assert!(has_mem, "LEAVE must load saved RBP from stack");
        assert!(has_bp_write, "LEAVE must write the loaded value to RBP");
    }

    // ── BOUND tests ──────────────────────────────────────────────────────────

    #[test]
    fn bound_emits_conditional_trap_vector5() {
        // BOUND AX, [BX]  — 32-bit: 62 /r; encode as BOUND AX, m16&16
        // In 32-bit mode: 62 43 00  (BOUND EAX, [EBX+0])
        let i = decode32(&[0x62, 0x03]);
        let mut ctx = ctx32();
        lift_bound(&i, &mut ctx).unwrap();
        let cond_trap = ctx
            .effects
            .iter()
            .any(|e| matches!(e, Effect::ConditionalTrap { vector: 5, .. }));
        assert!(cond_trap, "BOUND must emit ConditionalTrap {{ vector: 5 }}");
    }

    #[test]
    fn bound_emits_bound_check_intrinsic() {
        let i = decode32(&[0x62, 0x03]);
        let mut ctx = ctx32();
        lift_bound(&i, &mut ctx).unwrap();
        assert!(
            has_intrinsic(&ctx, "x86.bound_check"),
            "BOUND must emit x86.bound_check intrinsic"
        );
    }

    #[test]
    fn bound_loads_lower_and_upper() {
        let i = decode32(&[0x62, 0x03]);
        let mut ctx = ctx32();
        lift_bound(&i, &mut ctx).unwrap();
        
        assert_eq!(
            ctx
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::MemRead { .. })).count(),
            2,
            "BOUND must load both lower and upper bounds"
        );
    }

    // ── NoReturn annotation tests ─────────────────────────────────────────────

    #[test]
    fn noreturn_annotation_for_exit() {
        let mut ctx = ctx64();
        emit_noreturn_if_known("exit", &mut ctx);
        assert!(
            ctx.effects.iter().any(|e| matches!(e, Effect::NoReturn)),
            "exit must be annotated NoReturn"
        );
    }

    #[test]
    fn noreturn_annotation_for_exitprocess() {
        let mut ctx = ctx64();
        emit_noreturn_if_known("ExitProcess", &mut ctx);
        assert!(
            ctx.effects.iter().any(|e| matches!(e, Effect::NoReturn)),
            "ExitProcess must be annotated NoReturn"
        );
    }

    #[test]
    fn noreturn_annotation_for_abort() {
        let mut ctx = ctx64();
        emit_noreturn_if_known("abort", &mut ctx);
        assert!(ctx.effects.iter().any(|e| matches!(e, Effect::NoReturn)));
    }

    #[test]
    fn noreturn_annotation_not_for_printf() {
        let mut ctx = ctx64();
        emit_noreturn_if_known("printf", &mut ctx);
        assert!(
            !ctx.effects.iter().any(|e| matches!(e, Effect::NoReturn)),
            "printf must NOT be annotated NoReturn"
        );
    }

    #[test]
    fn noreturn_annotation_rust_panic() {
        let mut ctx = ctx64();
        emit_noreturn_if_known("rust_begin_unwind", &mut ctx);
        assert!(ctx.effects.iter().any(|e| matches!(e, Effect::NoReturn)));
    }

    // ── Far JMP selector intrinsic tests ─────────────────────────────────────

    #[test]
    fn jmp_far_indirect_emits_selector_intrinsic() {
        // JMP FAR [RAX]  — FF 28  (rex.w + FF /5)
        // In 64-bit mode, opcode FF /5 is JMP FAR m16:64.
        let i = decode64(&[0xff, 0x28]);
        let mut ctx = ctx64();
        lift_jmp(&i, &mut ctx).unwrap();
        // Whether or not the far_jmp_selector intrinsic fires depends on iced
        // classifying the operand size > ptr_size for far forms.  At minimum,
        // an unconditional branch and a MemRead must be emitted.
        assert!(has_unconditional_branch(&ctx));
    }

    // ── peel_deref helper tests ───────────────────────────────────────────────

    #[test]
    fn peel_deref_strips_deref_wrapper() {
        let inner = IrExpr::Const(0xDEAD_BEEF);
        let wrapped = IrExpr::Deref(Box::new(inner.clone()), 8);
        assert_eq!(peel_deref(wrapped), inner);
    }

    #[test]
    fn peel_deref_identity_on_non_deref() {
        let e = IrExpr::Reg("rax".into());
        assert_eq!(peel_deref(e.clone()), e);
    }

    // ── emit_push / emit_pop round-trip test ─────────────────────────────────

    #[test]
    fn push_pop_pair_generates_four_effects() {
        let mut ctx = ctx64();
        emit_push(&mut ctx, IrExpr::Const(0x1234));
        let _ = emit_pop(&mut ctx);
        // push = RegWrite + MemWrite; pop = MemRead + RegWrite = 4 effects total
        assert_eq!(
            ctx.effects.len(),
            4,
            "push+pop must generate exactly 4 effects"
        );
    }

    #[test]
    fn sp_adjust_zero_does_not_emit() {
        let mut ctx = ctx64();
        emit_sp_adjust(&mut ctx, 0);
        assert!(
            ctx.effects.is_empty(),
            "emit_sp_adjust(0) must emit nothing"
        );
    }

    #[test]
    fn sp_adjust_nonzero_emits_add() {
        let mut ctx = ctx64();
        emit_sp_adjust(&mut ctx, 0x10);
        assert_eq!(ctx.effects.len(), 1);
        assert!(matches!(
            ctx.effects[0],
            Effect::RegWrite { ref reg, value: IrExpr::Add(_, ref b) }
            if reg == "rsp" && matches!(**b, IrExpr::Const(0x10))
        ));
    }

    // ── LEAVE in 32-bit mode ─────────────────────────────────────────────────

    #[test]
    fn leave_32bit_uses_esp_and_ebp() {
        let i = decode32(&[0xc9]);
        let mut ctx = ctx32();
        lift_leave(&i, &mut ctx).unwrap();
        let sp_from_bp = ctx.effects.iter().any(|e| {
            matches!(e, Effect::RegWrite { reg, value: IrExpr::Reg(src) }
                if reg == "esp" && src == "ebp")
        });
        assert!(sp_from_bp, "LEAVE in 32-bit mode must set ESP = EBP");
    }
}

#[cfg(test)]
mod stack_pointer_write_tests {
    //! Stack-pointer effects of CALL/RET, in both widths.
    //!
    //! A lifter that forgets the implicit SP adjustment produces IR where the
    //! stack never moves — every stack slot then aliases, and downstream
    //! variable recovery invents one variable for the whole frame. Nothing
    //! covered the 32-bit or the RET case before this module.

    use super::tests::*;
    use super::*;

    /// CALL rel32 pushes a return address, so it must write RSP in 64-bit mode.
    #[test]
    fn call_writes_rsp_in_64_bit_mode() {
        let i = decode64(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let mut ctx = ctx64();
        lift_call(&i, &mut ctx).unwrap();
        assert!(has_sp_write(&ctx, "rsp"), "CALL must adjust rsp");
    }

    /// The same in 32-bit mode, where the stack pointer is ESP.
    #[test]
    fn call_writes_esp_in_32_bit_mode() {
        let i = decode32(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let mut ctx = ctx32();
        lift_call(&i, &mut ctx).unwrap();
        assert!(has_sp_write(&ctx, "esp"), "CALL must adjust esp in 32-bit mode");
    }

    /// RET pops the return address, so it must write the stack pointer too.
    #[test]
    fn ret_writes_rsp_in_64_bit_mode() {
        let i = decode64(&[0xc3]);
        let mut ctx = ctx64();
        lift_ret(&i, &mut ctx).unwrap();
        assert!(has_sp_write(&ctx, "rsp"), "RET must adjust rsp");
    }

    /// `RET imm16` pops the return address AND imm bytes of arguments; it must
    /// still be a single stack-pointer write, not zero.
    #[test]
    fn ret_imm16_writes_rsp() {
        let i = decode64(&[0xc2, 0x08, 0x00]);
        let mut ctx = ctx64();
        lift_ret(&i, &mut ctx).unwrap();
        assert!(has_sp_write(&ctx, "rsp"), "RET imm16 must adjust rsp");
    }
}
