//! Per-category x86/x64 instruction handlers.
//!
//! Each sub-module owns one semantic family (data movement, arithmetic,
//! control flow, …). Every handler has the signature
//!
//! ```text
//! pub fn lift_<op>(instr: &iced_x86::Instruction, ctx: &mut X86LiftCtx)
//!     -> Result<(), LiftError>;
//! ```
//!
//! and emits its μOps directly onto `ctx`. The dispatch entry-point
//! [`lift_instruction`] performs a single `match instr.mnemonic()` and
//! forwards to the right handler.
//!
//! The dispatch is deliberately implemented as a big explicit `match` rather
//! than a function-pointer table: matching on an `enum` produces a jump
//! table at compile time, and the compiler verifies exhaustiveness gaps as
//! warnings rather than letting unhandled mnemonics silently fall through.

use crate::LiftError;
use crate::x86_context::X86LiftCtx;
use iced_x86::{Instruction, Mnemonic};

/// True when an instruction whose mnemonic is shared between a string op and an
/// SSE scalar op (`MOVSD`, `CMPSD`) is the SSE form — i.e. its first operand is
/// an XMM register. The string forms take no explicit register operands.
fn is_sse_scalar_form(instr: &Instruction) -> bool {
    instr.op0_register().is_xmm()
}

pub mod arithmetic;
pub mod avx;
pub mod avx512;
pub mod control_flow;
pub mod data_move;
pub mod flag_ops;
pub mod fpu_x87;
pub mod logical;
pub mod misc;
pub mod mmx_sse;
pub mod setcc;
pub mod shifts;
pub mod stack;
pub mod string_ops;
pub mod system;

/// Top-level dispatch: route an instruction to its semantic-category handler.
///
/// Returns `LiftError::LiftFailed` only for mnemonics that no handler in any
/// sub-module recognises. All other handler failures (operand decoding,
/// shape mismatches) propagate as their own `LiftError` variants.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
fn lift_instruction_a(instr: &Instruction, ctx: &mut X86LiftCtx) -> Option<Result<(), LiftError>> {
    use Mnemonic as M;
    match instr.mnemonic() {
        // ── Data movement ────────────────────────────────────────────────
        M::Mov => Some(data_move::lift_mov(instr, ctx)),
        M::Movzx => Some(data_move::lift_movzx(instr, ctx)),
        M::Movsx | M::Movsxd => Some(data_move::lift_movsx(instr, ctx)),
        M::Lea => Some(data_move::lift_lea(instr, ctx)),
        M::Xchg => Some(data_move::lift_xchg(instr, ctx)),
        M::Cmpxchg | M::Cmpxchg8b | M::Cmpxchg16b => Some(arithmetic::lift_cmpxchg(instr, ctx)),
        M::Cmovo
        | M::Cmovno
        | M::Cmovb
        | M::Cmovae
        | M::Cmove
        | M::Cmovne
        | M::Cmovbe
        | M::Cmova
        | M::Cmovs
        | M::Cmovns
        | M::Cmovp
        | M::Cmovnp
        | M::Cmovl
        | M::Cmovge
        | M::Cmovle
        | M::Cmovg => Some(data_move::lift_cmovcc(instr, ctx)),
        M::Movnti | M::Movntdq | M::Movntpd | M::Movntps => Some(data_move::lift_movnt(instr, ctx)),

        // ── Arithmetic ──────────────────────────────────────────────────
        M::Add => Some(arithmetic::lift_add(instr, ctx)),
        M::Adc => Some(arithmetic::lift_adc(instr, ctx)),
        M::Sub => Some(arithmetic::lift_sub(instr, ctx)),
        M::Sbb => Some(arithmetic::lift_sbb(instr, ctx)),
        M::Cmp => Some(arithmetic::lift_cmp(instr, ctx)),
        M::Inc => Some(arithmetic::lift_inc(instr, ctx)),
        M::Dec => Some(arithmetic::lift_dec(instr, ctx)),
        M::Neg => Some(arithmetic::lift_neg(instr, ctx)),
        M::Mul => Some(arithmetic::lift_mul(instr, ctx)),
        M::Imul => Some(arithmetic::lift_imul(instr, ctx)),
        M::Div => Some(arithmetic::lift_div(instr, ctx)),
        M::Idiv => Some(arithmetic::lift_idiv(instr, ctx)),
        M::Aaa | M::Aas | M::Daa | M::Das => Some(arithmetic::lift_bcd(instr, ctx)),
        M::Aam => Some(arithmetic::lift_aam(instr, ctx)),
        M::Aad => Some(arithmetic::lift_aad(instr, ctx)),
        M::Xadd => Some(arithmetic::lift_xadd(instr, ctx)),
        M::Mulx => Some(arithmetic::lift_mulx(instr, ctx)),
        M::Adcx => Some(arithmetic::lift_adcx(instr, ctx)),
        M::Adox => Some(arithmetic::lift_adox(instr, ctx)),

        // ── Logical ─────────────────────────────────────────────────────
        M::And => Some(logical::lift_and(instr, ctx)),
        M::Or => Some(logical::lift_or(instr, ctx)),
        M::Xor => Some(logical::lift_xor(instr, ctx)),
        M::Not => Some(logical::lift_not(instr, ctx)),
        M::Test => Some(logical::lift_test(instr, ctx)),
        M::Bt => Some(logical::lift_bt(instr, ctx)),
        M::Bts => Some(logical::lift_bts(instr, ctx)),
        M::Btr => Some(logical::lift_btr(instr, ctx)),
        M::Btc => Some(logical::lift_btc(instr, ctx)),
        M::Andn => Some(logical::lift_andn(instr, ctx)),

        // ── Shifts ──────────────────────────────────────────────────────
        M::Shl | M::Sal => Some(shifts::lift_shl(instr, ctx)),
        M::Shr => Some(shifts::lift_shr(instr, ctx)),
        M::Sar => Some(shifts::lift_sar(instr, ctx)),
        M::Rol => Some(shifts::lift_rol(instr, ctx)),
        M::Ror => Some(shifts::lift_ror(instr, ctx)),
        M::Rcl => Some(shifts::lift_rcl(instr, ctx)),
        M::Rcr => Some(shifts::lift_rcr(instr, ctx)),
        M::Shld => Some(shifts::lift_shld(instr, ctx)),
        M::Shrd => Some(shifts::lift_shrd(instr, ctx)),

        _ => None,
    }
}

/// Control-flow and other legacy instruction handlers (Option-returning variant).
/// Exported as part of the public API; use [`lift_instruction`] for dispatch.
pub fn lift_instruction_control_flow(instr: &Instruction, ctx: &mut X86LiftCtx) -> Option<Result<(), LiftError>> {
    use Mnemonic as M;
    match instr.mnemonic() {
        // ── Control flow ────────────────────────────────────────────────
        M::Jmp => Some(control_flow::lift_jmp(instr, ctx)),
        M::Jo
        | M::Jno
        | M::Jb
        | M::Jae
        | M::Je
        | M::Jne
        | M::Jbe
        | M::Ja
        | M::Js
        | M::Jns
        | M::Jp
        | M::Jnp
        | M::Jl
        | M::Jge
        | M::Jle
        | M::Jg => Some(control_flow::lift_jcc(instr, ctx)),
        M::Jcxz | M::Jecxz | M::Jrcxz => Some(control_flow::lift_jcxz(instr, ctx)),
        M::Call => Some(control_flow::lift_call(instr, ctx)),
        M::Ret | M::Retf => Some(control_flow::lift_ret(instr, ctx)),
        M::Iret | M::Iretd | M::Iretq => Some(control_flow::lift_iret(instr, ctx)),
        M::Loop | M::Loope | M::Loopne => Some(control_flow::lift_loop(instr, ctx)),

        // ── Stack ───────────────────────────────────────────────────────
        M::Push => Some(stack::lift_push(instr, ctx)),
        M::Pop => Some(stack::lift_pop(instr, ctx)),
        M::Pusha | M::Pushad => Some(stack::lift_pusha(instr, ctx)),
        M::Popa | M::Popad => Some(stack::lift_popa(instr, ctx)),
        M::Pushf | M::Pushfd | M::Pushfq => Some(stack::lift_pushf(instr, ctx)),
        M::Popf | M::Popfd | M::Popfq => Some(stack::lift_popf(instr, ctx)),
        M::Enter => Some(stack::lift_enter(instr, ctx)),
        M::Leave => Some(stack::lift_leave(instr, ctx)),

        // ── String ops ──────────────────────────────────────────────────
        M::Movsd if is_sse_scalar_form(instr) => Some(mmx_sse::lift_sse_mov(instr, ctx)),
        M::Cmpsd if is_sse_scalar_form(instr) => Some(mmx_sse::lift_sse_cmp(instr, ctx)),
        M::Movsb | M::Movsw | M::Movsd | M::Movsq => Some(string_ops::lift_movs(instr, ctx)),
        M::Cmpsb | M::Cmpsw | M::Cmpsd | M::Cmpsq => Some(string_ops::lift_cmps(instr, ctx)),
        M::Scasb | M::Scasw | M::Scasd | M::Scasq => Some(string_ops::lift_scas(instr, ctx)),
        M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => Some(string_ops::lift_lods(instr, ctx)),
        M::Stosb | M::Stosw | M::Stosd | M::Stosq => Some(string_ops::lift_stos(instr, ctx)),

        // ── Flag manipulation ───────────────────────────────────────────
        M::Clc => Some(flag_ops::lift_clc(instr, ctx)),
        M::Stc => Some(flag_ops::lift_stc(instr, ctx)),
        M::Cmc => Some(flag_ops::lift_cmc(instr, ctx)),
        M::Cld => Some(flag_ops::lift_cld(instr, ctx)),
        M::Std => Some(flag_ops::lift_std(instr, ctx)),
        M::Cli => Some(flag_ops::lift_cli(instr, ctx)),
        M::Sti => Some(flag_ops::lift_sti(instr, ctx)),
        M::Lahf => Some(flag_ops::lift_lahf(instr, ctx)),
        M::Sahf => Some(flag_ops::lift_sahf(instr, ctx)),

        // ── SETcc ───────────────────────────────────────────────────────
        M::Seto
        | M::Setno
        | M::Setb
        | M::Setae
        | M::Sete
        | M::Setne
        | M::Setbe
        | M::Seta
        | M::Sets
        | M::Setns
        | M::Setp
        | M::Setnp
        | M::Setl
        | M::Setge
        | M::Setle
        | M::Setg => Some(setcc::lift_setcc(instr, ctx)),

        _ => None,
    }
}

// ── system + x87 + SSE helper (Option-returning to enable chaining) ──────────
fn lift_sys_x87_sse(instr: &Instruction, ctx: &mut X86LiftCtx) -> Option<Result<(), LiftError>> {
    use Mnemonic as M;
    match instr.mnemonic() {
        // ── System ──────────────────────────────────────────────────────
        M::Syscall => Some(system::lift_syscall(instr, ctx)),
        M::Sysenter => Some(system::lift_sysenter(instr, ctx)),
        M::Sysexit | M::Sysexitq => Some(system::lift_sysexit(instr, ctx)),
        M::Sysret | M::Sysretq => Some(system::lift_sysret(instr, ctx)),
        M::Int => Some(system::lift_int(instr, ctx)),
        M::Int1 | M::Int3 => Some(system::lift_int3(instr, ctx)),
        M::Into => Some(system::lift_into(instr, ctx)),
        M::Cpuid => Some(system::lift_cpuid(instr, ctx)),
        M::Rdtsc | M::Rdtscp => Some(system::lift_rdtsc(instr, ctx)),
        M::Rdmsr => Some(system::lift_rdmsr(instr, ctx)),
        M::Wrmsr => Some(system::lift_wrmsr(instr, ctx)),
        M::Ud0 | M::Ud1 | M::Ud2 => Some(system::lift_ud(instr, ctx)),
        M::Hlt => Some(system::lift_hlt(instr, ctx)),
        M::Nop => Some(system::lift_nop(instr, ctx)),
        // ── x87 FPU ─────────────────────────────────────────────────────
        M::Fld | M::Fld1 | M::Fldz | M::Fldpi | M::Fldl2e | M::Fldl2t | M::Fldlg2 | M::Fldln2 => {
            Some(fpu_x87::lift_fld(instr, ctx))
        }
        M::Fst => Some(fpu_x87::lift_fst(instr, ctx)),
        M::Fstp => Some(fpu_x87::lift_fstp(instr, ctx)),
        M::Fadd | M::Faddp | M::Fiadd => Some(fpu_x87::lift_fadd(instr, ctx)),
        M::Fsub | M::Fsubp | M::Fisub | M::Fsubr | M::Fsubrp | M::Fisubr => {
            Some(fpu_x87::lift_fsub(instr, ctx))
        }
        M::Fmul | M::Fmulp | M::Fimul => Some(fpu_x87::lift_fmul(instr, ctx)),
        M::Fdiv | M::Fdivp | M::Fidiv | M::Fdivr | M::Fdivrp | M::Fidivr => {
            Some(fpu_x87::lift_fdiv(instr, ctx))
        }
        M::Fcom | M::Fcomp | M::Fcompp | M::Fucom | M::Fucomp | M::Fucompp
        | M::Ficom | M::Ficomp | M::Fcomi | M::Fcomip | M::Fucomi | M::Fucomip => {
            Some(fpu_x87::lift_fcom(instr, ctx))
        }
        M::Fxch => Some(fpu_x87::lift_fxch(instr, ctx)),
        M::Fnstcw | M::Fldcw | M::Fnstsw | M::Fninit | M::Fnclex => {
            Some(fpu_x87::lift_fpu_ctrl(instr, ctx))
        }
        // ── SSE / SSE2 / SSE3 / SSSE3 / SSE4 ────────────────────────────
        M::Movaps | M::Movapd | M::Movups | M::Movupd | M::Movdqa | M::Movdqu
        | M::Movq | M::Movd | M::Movss => Some(mmx_sse::lift_sse_mov(instr, ctx)),
        M::Addps | M::Addpd | M::Addss | M::Addsd | M::Subps | M::Subpd | M::Subss | M::Subsd
        | M::Mulps | M::Mulpd | M::Mulss | M::Mulsd | M::Divps | M::Divpd | M::Divss | M::Divsd
        | M::Sqrtps | M::Sqrtpd | M::Sqrtss | M::Sqrtsd => Some(mmx_sse::lift_sse_arith(instr, ctx)),
        M::Andps | M::Andpd | M::Orps | M::Orpd | M::Xorps | M::Xorpd => {
            Some(mmx_sse::lift_sse_logic(instr, ctx))
        }
        M::Cmpps | M::Cmppd | M::Cmpss | M::Ucomiss | M::Ucomisd | M::Comiss | M::Comisd => {
            Some(mmx_sse::lift_sse_cmp(instr, ctx))
        }
        M::Pshufb | M::Pshufd | M::Pshufhw | M::Pshuflw => {
            Some(mmx_sse::lift_sse_shuffle(instr, ctx))
        }
        M::Paddb | M::Paddw | M::Paddd | M::Paddq | M::Psubb | M::Psubw | M::Psubd | M::Psubq
        | M::Pmullw | M::Pmuludq => Some(mmx_sse::lift_simd_int(instr, ctx)),
        _ => None,
    }
}

/// Legacy comprehensive instruction handler (system + x87 + SSE + AVX + misc).
/// Exported as part of the public API; use [`lift_instruction`] for dispatch.
///
/// # Errors
///
/// Returns an error if the IL lifting operation fails.
pub fn lift_instruction_legacy(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    use Mnemonic as M;
    if let Some(r) = lift_sys_x87_sse(instr, ctx) {
        return r;
    }
    match instr.mnemonic() {
        // ── AVX / AVX2 ──────────────────────────────────────────────────
        M::Vmovaps | M::Vmovapd | M::Vmovups | M::Vmovupd | M::Vmovdqa | M::Vmovdqu
        | M::Vmovq | M::Vmovd => avx::lift_vmov(instr, ctx),
        M::Vaddps | M::Vaddpd | M::Vsubps | M::Vsubpd | M::Vmulps | M::Vmulpd
        | M::Vdivps | M::Vdivpd | M::Vsqrtps | M::Vsqrtpd => {
            if avx512::uses_evex512(instr) {
                avx512::lift_evex_fp_arith(instr, ctx)
            } else {
                avx::lift_vfp_arith(instr, ctx)
            }
        }
        M::Vpaddb | M::Vpaddw | M::Vpaddd | M::Vpaddq | M::Vpsubb | M::Vpsubw | M::Vpsubd
        | M::Vpsubq => avx::lift_vp_int_arith(instr, ctx),
        M::Vandps | M::Vandpd | M::Vorps | M::Vorpd | M::Vxorps | M::Vxorpd => {
            avx::lift_v_logic(instr, ctx)
        }
        M::Vpshufb | M::Vpshufd | M::Vpermd | M::Vpermq => avx::lift_v_shuffle(instr, ctx),
        M::Vzeroupper | M::Vzeroall => avx::lift_vzero(instr, ctx),
        // ── AVX-512 ─────────────────────────────────────────────────────
        M::Kmovb | M::Kmovw | M::Kmovd | M::Kmovq | M::Kandb | M::Kandw | M::Kandd | M::Kandq
        | M::Korb | M::Korw | M::Kord | M::Korq | M::Kxorb | M::Kxorw | M::Kxord | M::Kxorq
        | M::Knotb | M::Knotw | M::Knotd | M::Knotq => avx512::lift_k_op(instr, ctx),
        // ── Miscellaneous bit / byte ops ────────────────────────────────
        M::Bswap => misc::lift_bswap(instr, ctx),
        M::Bsf => misc::lift_bsf(instr, ctx),
        M::Bsr => misc::lift_bsr(instr, ctx),
        M::Lzcnt => misc::lift_lzcnt(instr, ctx),
        M::Tzcnt => misc::lift_tzcnt(instr, ctx),
        M::Popcnt => misc::lift_popcnt(instr, ctx),
        M::Movbe => misc::lift_movbe(instr, ctx),
        M::Crc32 => misc::lift_crc32(instr, ctx),
        M::Rdrand => misc::lift_rdrand(instr, ctx),
        M::Rdseed => misc::lift_rdseed(instr, ctx),
        M::Pause => misc::lift_pause(instr, ctx),
        M::Mfence | M::Lfence | M::Sfence => misc::lift_fence(instr, ctx),
        M::Prefetch | M::Prefetcht0 | M::Prefetcht1 | M::Prefetcht2 | M::Prefetchnta => {
            misc::lift_prefetch(instr, ctx)
        }
        // ── INVALID / unhandled ──────────────────────────────────────────
        other => {
            ctx.emit_intrinsic(format!("x86.unhandled.{other:?}"), vec![]);
            Err(LiftError::LiftFailed(
                ctx.addr,
                format!("mnemonic not yet covered: {other:?}"),
            ))
        }
    }
}

/// Top-level entry point: route an instruction to the correct semantic handler.
///
/// # Errors
///
/// Returns `LiftError::LiftFailed` for unrecognised mnemonics; handler-specific
/// errors propagate as their own `LiftError` variants.
pub fn lift_instruction(instr: &Instruction, ctx: &mut X86LiftCtx) -> Result<(), LiftError> {
    if let Some(r) = lift_instruction_a(instr, ctx) { return r; }
    if let Some(r) = lift_instruction_control_flow(instr, ctx) { return r; }
    lift_instruction_legacy(instr, ctx)
}
