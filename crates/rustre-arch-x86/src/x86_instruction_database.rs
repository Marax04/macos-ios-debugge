//! `x86_instruction_database` — Complete x86-64 instruction database.
//!
//! Provides:
//! - [`X86InstructionDatabase`]: central registry of 500+ instruction entries
//! - [`OpType`]: operand type classification
//! - [`FlagEffects`]: EFLAGS read/write semantics
//! - [`MemAccess`]: memory access classification
//! - [`OperandConstraint`]: register/immediate constraints
//! - [`InstrCategory`]: instruction family grouping
//!
//! # Dispatch status (NOT wired into `src/lift.rs`)
//!
//! This module is **not** part of the active lifting path. `src/lift.rs`
//! dispatches every mnemonic directly via its own native match arms (added
//! across several hardening passes), and does not call into this module.
//! It is intentionally retained -- not dead code pending removal -- per
//! explicit user instruction, as a possible future cross-validation /
//! second-opinion decode path independent of `lift.rs`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Operand types
// ---------------------------------------------------------------------------

/// How a single operand is encoded / interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpType {
    /// General-purpose register (8/16/32/64-bit)
    Reg,
    /// Immediate value
    Imm,
    /// Memory reference via `ModRM`
    Mem,
    /// Relative offset (branch/call targets)
    Rel,
    /// Segment register
    Seg,
    /// x87 FPU register (ST(i))
    FpuReg,
    /// MMX register
    MmxReg,
    /// XMM/YMM/ZMM register
    SimdReg,
    /// Control register (CR0–CR8)
    CtrlReg,
    /// Debug register (DR0–DR7)
    DbgReg,
    /// Implicit (hardcoded) operand, e.g. AL, CL, AX
    Implicit,
    /// Moffs — memory offset for MOV with absolute address
    Moffs,
    /// Far pointer (segment:offset)
    FarPtr,
    /// No operand
    None,
}

// ---------------------------------------------------------------------------
// Flag effects
// ---------------------------------------------------------------------------

/// EFLAGS bit indices.
pub mod eflags {
    pub const CF: u16 = 1 << 0;
    pub const PF: u16 = 1 << 2;
    pub const AF: u16 = 1 << 4;
    pub const ZF: u16 = 1 << 6;
    pub const SF: u16 = 1 << 7;
    pub const TF: u16 = 1 << 8;
    pub const IF: u16 = 1 << 9;
    pub const DF: u16 = 1 << 10;
    pub const OF: u16 = 1 << 11;
    pub const ALL_ARITH: u16 = CF | PF | AF | ZF | SF | OF;
    pub const ALL_SHIFT: u16 = CF | PF | ZF | SF | OF;
    pub const NZC: u16 = ZF | SF | CF;
}

/// Describes how an instruction reads and writes EFLAGS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlagEffects {
    /// Flags that may be read by this instruction.
    pub reads: u16,
    /// Flags that are defined (written) by this instruction.
    pub writes: u16,
    /// Flags that are unconditionally cleared.
    pub clears: u16,
    /// Flags that are unconditionally set.
    pub sets: u16,
    /// Flags whose value is undefined/unpredictable after this instruction.
    pub undef: u16,
}

impl FlagEffects {
    #[must_use]
    pub const fn none() -> Self {
        Self { reads: 0, writes: 0, clears: 0, sets: 0, undef: 0 }
    }

    #[must_use]
    pub const fn arith() -> Self {
        Self {
            reads: 0,
            writes: eflags::ALL_ARITH,
            clears: 0,
            sets: 0,
            undef: eflags::AF,
        }
    }

    #[must_use]
    pub const fn logic() -> Self {
        Self {
            reads: 0,
            writes: eflags::SF | eflags::ZF | eflags::PF,
            clears: eflags::CF | eflags::OF,
            sets: 0,
            undef: eflags::AF,
        }
    }

    #[must_use]
    pub const fn shift() -> Self {
        Self {
            reads: 0,
            writes: eflags::ALL_SHIFT,
            clears: 0,
            sets: 0,
            undef: eflags::AF | eflags::OF,
        }
    }

    #[must_use]
    pub const fn cond_read(flags: u16) -> Self {
        Self { reads: flags, writes: 0, clears: 0, sets: 0, undef: 0 }
    }

    #[must_use]
    pub const fn writes(flags: u16) -> Self {
        Self { reads: 0, writes: flags, clears: 0, sets: 0, undef: 0 }
    }

    #[must_use]
    pub const fn reads(flags: u16) -> Self {
        Self { reads: flags, writes: 0, clears: 0, sets: 0, undef: 0 }
    }

    /// `ROL`/`ROR`: CF is always defined; **OF is defined ONLY for the 1-bit
    /// form** and undefined for every other count.
    ///
    /// Intel SDM vol.2, ROL/ROR/RCL/RCR: "The OF flag is defined only for the
    /// 1-bit rotates; it is undefined in all other cases (except RCL and RCR
    /// where it is undefined for all rotate counts)."
    ///
    /// These entries previously used a bare `writes(CF|OF)` with no `undef`,
    /// claiming OF is always defined. The sibling `shift()` helper above gets
    /// the same nuance right (`undef: AF | OF`) — the rotate rows simply lost
    /// it. Found 2026-07-23 by `tests/db_lifter_flag_crosscheck.rs`, which
    /// reported the lifter "not modelling" OF for `rol rax, 4`: the lifter was
    /// right and this table was not.
    #[must_use]
    pub const fn rotate() -> Self {
        Self {
            reads: 0,
            writes: eflags::CF | eflags::OF,
            clears: 0,
            sets: 0,
            undef: eflags::OF,
        }
    }

    /// `RCL`/`RCR`: like [`Self::rotate`], but they also READ CF, and OF is
    /// undefined for ALL counts (SDM, same paragraph).
    #[must_use]
    pub const fn rotate_carry() -> Self {
        Self {
            reads: eflags::CF,
            writes: eflags::CF | eflags::OF,
            clears: 0,
            sets: 0,
            undef: eflags::OF,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory access
// ---------------------------------------------------------------------------

/// What kind of memory access an instruction performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemAccess {
    /// No memory access
    None,
    /// Read from memory
    Read,
    /// Write to memory
    Write,
    /// Read-Modify-Write
    ReadWrite,
    /// Atomic read-modify-write (e.g., XCHG, LOCK prefix)
    Atomic,
    /// Stack push
    Push,
    /// Stack pop
    Pop,
    /// Far call/return (CS:IP update)
    FarCall,
}

// ---------------------------------------------------------------------------
// Operand constraints
// ---------------------------------------------------------------------------

/// Constraints on how operands must be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandConstraint {
    /// Any GP register
    AnyReg,
    /// Must be RAX/EAX/AX/AL (hardcoded accumulator)
    Accumulator,
    /// Must be CL (shift count register)
    Cl,
    /// Must be DX (I/O port register)
    Dx,
    /// Only AL (byte accumulator)
    Al,
    /// Only AX (word accumulator)
    Ax,
    /// Immediate 1 (special encoding for shifts)
    Imm1,
    /// Unsigned 8-bit immediate
    Imm8u,
    /// Signed 8-bit immediate
    Imm8s,
    /// 16/32/64-bit immediate depending on operand size
    ImmFull,
    /// Any memory operand
    AnyMem,
    /// No constraint
    Any,
}

// ---------------------------------------------------------------------------
// Instruction category
// ---------------------------------------------------------------------------

/// High-level instruction family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstrCategory {
    /// Integer arithmetic (ADD, SUB, MUL, etc.)
    Arithmetic,
    /// Bitwise logic (AND, OR, XOR, NOT)
    Logic,
    /// Bit manipulation (BT, BSF, BSR, LZCNT, POPCNT)
    BitManip,
    /// Shift and rotate (SHL, SHR, SAR, ROL, ROR)
    ShiftRotate,
    /// Data movement (MOV, XCHG, PUSH, POP, LEA)
    DataMove,
    /// String operations (MOVS, CMPS, SCAS, LODS, STOS)
    String,
    /// Control flow (JMP, Jcc, CALL, RET, LOOP)
    ControlFlow,
    /// System (SYSCALL, SYSRET, INT, IRET, HLT, IN, OUT)
    System,
    /// Floating-point / x87
    Fpu,
    /// MMX SIMD
    Mmx,
    /// SSE / SSE2 / SSE3 / SSSE3 / SSE4
    Sse,
    /// AVX / AVX2 / AVX-512
    Avx,
    /// AES instructions (AESENC, AESD, etc.)
    Aes,
    /// CRC / hash
    Crc,
    /// Synchronization (MFENCE, LFENCE, SFENCE, PAUSE, XCHG with LOCK)
    Sync,
    /// Virtualization (VMXON, VMCALL, etc.)
    Virt,
    /// Conditional move / set (`CMOVcc`, `SETcc`)
    CondMove,
    /// Miscellaneous / uncategorized
    Misc,
}

// ---------------------------------------------------------------------------
// Operand size
// ---------------------------------------------------------------------------

/// Operand size specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpSize {
    /// 8-bit
    B8,
    /// 16-bit
    B16,
    /// 32-bit
    B32,
    /// 64-bit
    B64,
    /// 128-bit (XMM)
    B128,
    /// 256-bit (YMM)
    B256,
    /// 512-bit (ZMM)
    B512,
    /// Implicit / determined by prefix
    Implied,
}

// ---------------------------------------------------------------------------
// Operand specification helper (used to reduce argument count in const fn)
// ---------------------------------------------------------------------------

/// Groups the operand count, types, and constraints for an instruction entry.
#[derive(Debug, Clone, Copy)]
pub struct OpSpec {
    /// Number of operands.
    pub count: u8,
    /// Operand types in order.
    pub types: [OpType; 3],
    /// Per-operand constraints.
    pub constraints: [OperandConstraint; 3],
}

impl OpSpec {
    const fn new(count: u8, types: [OpType; 3], constraints: [OperandConstraint; 3]) -> Self {
        Self { count, types, constraints }
    }
}

/// Groups encoding attributes that tend to be scalar flags.
#[derive(Debug, Clone, Copy)]
pub struct EncodingAttrs {
    /// Minimum operand size this form applies to.
    pub min_size: OpSize,
    /// Whether a REX.W prefix is required for the 64-bit form.
    pub rex_w: bool,
    /// Whether this is a privileged instruction.
    pub privileged: bool,
}

impl EncodingAttrs {
    const fn new(min_size: OpSize, rex_w: bool, privileged: bool) -> Self {
        Self { min_size, rex_w, privileged }
    }
}

// ---------------------------------------------------------------------------
// Instruction database entry
// ---------------------------------------------------------------------------

/// A single entry in the instruction database.
#[derive(Debug, Clone)]
pub struct InstrEntry {
    /// Canonical mnemonic (lowercase).
    pub mnemonic: &'static str,
    /// Category.
    pub category: InstrCategory,
    /// Number of operands (0..=3 for most instructions).
    pub operand_count: u8,
    /// Operand types in order (dest, src1, src2).
    pub operand_types: [OpType; 3],
    /// Per-operand constraints.
    pub operand_constraints: [OperandConstraint; 3],
    /// Memory access semantics.
    pub mem_access: MemAccess,
    /// EFLAGS effects.
    pub flags: FlagEffects,
    /// Minimum operand size this form applies to.
    pub min_size: OpSize,
    /// Whether a REX.W prefix is required for 64-bit form.
    pub rex_w: bool,
    /// Whether this is a privileged instruction.
    pub privileged: bool,
    /// Brief description.
    pub description: &'static str,
}

impl InstrEntry {
    const fn new(
        mnemonic: &'static str,
        category: InstrCategory,
        ops: OpSpec,
        mem_access: MemAccess,
        flags: FlagEffects,
        attrs: EncodingAttrs,
        description: &'static str,
    ) -> Self {
        Self {
            mnemonic,
            category,
            operand_count: ops.count,
            operand_types: ops.types,
            operand_constraints: ops.constraints,
            mem_access,
            flags,
            min_size: attrs.min_size,
            rex_w: attrs.rex_w,
            privileged: attrs.privileged,
            description,
        }
    }
}

// ---------------------------------------------------------------------------
// Static database
// ---------------------------------------------------------------------------

macro_rules! entry {
    ($mn:expr, $cat:expr, $nops:expr, [$ot0:expr,$ot1:expr,$ot2:expr],
     [$oc0:expr,$oc1:expr,$oc2:expr], $ma:expr, $fl:expr,
     $sz:expr, $rw:expr, $priv:expr, $desc:expr) => {
        InstrEntry::new(
            $mn, $cat,
            OpSpec::new($nops, [$ot0, $ot1, $ot2], [$oc0, $oc1, $oc2]),
            $ma, $fl,
            EncodingAttrs::new($sz, $rw, $priv),
            $desc,
        )
    };
}

// Convenience shortcuts
use InstrCategory::{DataMove, Arithmetic, Logic, ShiftRotate, BitManip, ControlFlow, CondMove, String, System, Misc, Sync, Virt, Aes, Crc, Sse, Avx};
use OpType::{Reg, None, Mem, Imm, Implicit, Rel, SimdReg, MmxReg, CtrlReg, DbgReg};
use OperandConstraint::{AnyReg, Any, AnyMem, ImmFull, Accumulator, Imm8u, Cl, Dx};
// Import MemAccess variants individually to avoid clash with OpType::None.
use MemAccess::{Read, Write, ReadWrite, Atomic, Push, Pop};
use MemAccess::None as MemNone;
use OpSize::{B8, B32, B64, B16, Implied, B128, B256};

const DB_ENTRIES: &[InstrEntry] = &[
    // -----------------------------------------------------------------------
    // Data movement
    // -----------------------------------------------------------------------
    entry!("mov", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B8, false, false, "Move register to register"),
    entry!("mov", DataMove, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), B8, false, false, "Move memory to register"),
    entry!("mov", DataMove, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], Write, FlagEffects::none(), B8, false, false, "Move register to memory"),
    entry!("mov", DataMove, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::none(), B8, false, false, "Move immediate to register"),
    entry!("mov", DataMove, 2, [Mem,Imm,None],[AnyMem,ImmFull,Any], Write, FlagEffects::none(), B8, false, false, "Move immediate to memory"),
    entry!("movsx", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B8, false, false, "Move with sign extension"),
    entry!("movzx", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B8, false, false, "Move with zero extension"),
    entry!("movsxd", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, true, false, "Move with sign extension doubleword to quadword"),
    entry!("movabs", DataMove, 2, [Reg,Imm,None],[Accumulator,ImmFull,Any], MemNone, FlagEffects::none(), B64, true, false, "Move 64-bit absolute immediate"),
    entry!("xchg", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], Atomic, FlagEffects::none(), B8, false, false, "Exchange registers"),
    entry!("xchg", DataMove, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Atomic, FlagEffects::none(), B8, false, false, "Exchange register with memory"),
    entry!("lea", DataMove, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], MemNone, FlagEffects::none(), B32, false, false, "Load effective address"),
    entry!("push", DataMove, 1, [Reg,None,None],[AnyReg,Any,Any], Push, FlagEffects::none(), B16, false, false, "Push register"),
    entry!("push", DataMove, 1, [Imm,None,None],[ImmFull,Any,Any], Push, FlagEffects::none(), B8, false, false, "Push immediate"),
    entry!("push", DataMove, 1, [Mem,None,None],[AnyMem,Any,Any], Push, FlagEffects::none(), B16, false, false, "Push memory"),
    entry!("pop", DataMove, 1, [Reg,None,None],[AnyReg,Any,Any], Pop, FlagEffects::none(), B16, false, false, "Pop to register"),
    entry!("pop", DataMove, 1, [Mem,None,None],[AnyMem,Any,Any], Pop, FlagEffects::none(), B16, false, false, "Pop to memory"),
    entry!("pusha", DataMove, 0, [None,None,None],[Any,Any,Any], Push, FlagEffects::none(), B16, false, false, "Push all general-purpose registers"),
    entry!("popa", DataMove, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::none(), B16, false, false, "Pop all general-purpose registers"),
    entry!("pushf", DataMove, 0, [None,None,None],[Any,Any,Any], Push, FlagEffects::none(), B16, false, false, "Push EFLAGS"),
    entry!("popf", DataMove, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::writes(0xFFFF), B16, false, false, "Pop EFLAGS"),
    entry!("lahf", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ALL_ARITH), B8, false, false, "Load AH from flags"),
    entry!("sahf", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::SF|eflags::ZF|eflags::AF|eflags::PF|eflags::CF), B8, false, false, "Store AH to flags"),
    entry!("cbw", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Convert byte to word"),
    entry!("cwde", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B16, false, false, "Convert word to doubleword"),
    entry!("cdqe", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B32, true, false, "Convert doubleword to quadword"),
    entry!("cwd", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B16, false, false, "Convert word to doubleword (DX:AX)"),
    entry!("cdq", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B32, false, false, "Convert doubleword to quadword (EDX:EAX)"),
    entry!("cqo", DataMove, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), B64, true, false, "Convert quadword (RDX:RAX)"),
    entry!("bswap", DataMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B32, false, false, "Byte swap register"),
    entry!("movbe", DataMove, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), B16, false, false, "Move data after swapping bytes"),
    entry!("cmpxchg", DataMove, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], Atomic, FlagEffects::arith(), B8, false, false, "Compare and exchange"),
    entry!("cmpxchg8b", DataMove, 1, [Mem,None,None],[AnyMem,Any,Any], Atomic, FlagEffects::writes(eflags::ZF), B32, false, false, "Compare and exchange 8 bytes"),
    entry!("cmpxchg16b", DataMove, 1, [Mem,None,None],[AnyMem,Any,Any], Atomic, FlagEffects::writes(eflags::ZF), B64, true, false, "Compare and exchange 16 bytes"),
    entry!("xadd", DataMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], Atomic, FlagEffects::arith(), B8, false, false, "Exchange and add"),

    // -----------------------------------------------------------------------
    // Integer arithmetic
    // -----------------------------------------------------------------------
    entry!("add", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::arith(), B8, false, false, "Add r/m to register"),
    entry!("add", Arithmetic, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::arith(), B8, false, false, "Add memory to register"),
    entry!("add", Arithmetic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::arith(), B8, false, false, "Add immediate to register"),
    entry!("add", Arithmetic, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], ReadWrite, FlagEffects::arith(), B8, false, false, "Add register to memory"),
    entry!("adc", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::arith(), B8, false, false, "Add with carry"),
    entry!("sub", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::arith(), B8, false, false, "Subtract"),
    entry!("sub", Arithmetic, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::arith(), B8, false, false, "Subtract memory from register"),
    entry!("sub", Arithmetic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::arith(), B8, false, false, "Subtract immediate"),
    entry!("sbb", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::arith(), B8, false, false, "Subtract with borrow"),
    entry!("mul", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::CF|eflags::OF), B8, false, false, "Unsigned multiply"),
    entry!("imul", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::CF|eflags::OF), B8, false, false, "Signed multiply (1-operand form)"),
    entry!("imul", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF|eflags::OF), B16, false, false, "Signed multiply (2-operand form)"),
    entry!("imul", Arithmetic, 3, [Reg,Reg,Imm],[AnyReg,AnyReg,ImmFull], MemNone, FlagEffects::writes(eflags::CF|eflags::OF), B16, false, false, "Signed multiply (3-operand form)"),
    entry!("div", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Unsigned divide"),
    entry!("idiv", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Signed divide"),
    entry!("inc", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::OF|eflags::SF|eflags::ZF|eflags::AF|eflags::PF), B8, false, false, "Increment"),
    entry!("dec", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::OF|eflags::SF|eflags::ZF|eflags::AF|eflags::PF), B8, false, false, "Decrement"),
    entry!("neg", Arithmetic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::arith(), B8, false, false, "Two's complement negation"),
    entry!("cmp", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::arith(), B8, false, false, "Compare (SUB without store)"),
    entry!("cmp", Arithmetic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::arith(), B8, false, false, "Compare register with immediate"),
    entry!("cmp", Arithmetic, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::arith(), B8, false, false, "Compare register with memory"),
    entry!("cmp", Arithmetic, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], Read, FlagEffects::arith(), B8, false, false, "Compare memory with register"),
    entry!("xadd", Arithmetic, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], ReadWrite, FlagEffects::arith(), B8, false, false, "Exchange and add"),
    entry!("aaa", Arithmetic, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::AF|eflags::CF), B8, false, false, "ASCII adjust after addition"),
    entry!("aas", Arithmetic, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::AF|eflags::CF), B8, false, false, "ASCII adjust after subtraction"),
    entry!("aam", Arithmetic, 1, [Imm,None,None],[Imm8u,Any,Any], MemNone, FlagEffects::logic(), B8, false, false, "ASCII adjust AX after multiply"),
    entry!("aad", Arithmetic, 1, [Imm,None,None],[Imm8u,Any,Any], MemNone, FlagEffects::logic(), B8, false, false, "ASCII adjust AX before division"),
    entry!("daa", Arithmetic, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::arith(), B8, false, false, "Decimal adjust AL after add"),
    entry!("das", Arithmetic, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::arith(), B8, false, false, "Decimal adjust AL after subtract"),
    entry!("adcx", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF), B32, false, false, "Unsigned integer add with CF"),
    entry!("adox", Arithmetic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::OF), B32, false, false, "Unsigned integer add with OF"),
    entry!("mulx", Arithmetic, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Unsigned multiply without flags"),

    // -----------------------------------------------------------------------
    // Logic
    // -----------------------------------------------------------------------
    entry!("and", Logic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B8, false, false, "Bitwise AND"),
    entry!("and", Logic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::logic(), B8, false, false, "AND register with immediate"),
    entry!("and", Logic, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], ReadWrite, FlagEffects::logic(), B8, false, false, "AND memory with register"),
    entry!("or", Logic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B8, false, false, "Bitwise OR"),
    entry!("or", Logic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::logic(), B8, false, false, "OR with immediate"),
    entry!("xor", Logic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B8, false, false, "Bitwise XOR"),
    entry!("xor", Logic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::logic(), B8, false, false, "XOR with immediate"),
    entry!("not", Logic, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Bitwise NOT"),
    entry!("test", Logic, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B8, false, false, "Test (AND without store)"),
    entry!("test", Logic, 2, [Reg,Imm,None],[AnyReg,ImmFull,Any], MemNone, FlagEffects::logic(), B8, false, false, "Test register with immediate"),
    entry!("test", Logic, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], Read, FlagEffects::logic(), B8, false, false, "Test memory with register"),
    entry!("andn", Logic, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::logic(), B32, false, false, "Logical AND NOT (BMI1)"),
    entry!("orn", Logic, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "OR NOT"),

    // -----------------------------------------------------------------------
    // Shift/Rotate
    // -----------------------------------------------------------------------
    entry!("shl", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift logical left by imm8"),
    entry!("shl", ShiftRotate, 2, [Reg,Implicit,None],[AnyReg,Cl,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift logical left by CL"),
    entry!("shr", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift logical right by imm8"),
    entry!("shr", ShiftRotate, 2, [Reg,Implicit,None],[AnyReg,Cl,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift logical right by CL"),
    entry!("sar", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift arithmetic right by imm8"),
    entry!("sar", ShiftRotate, 2, [Reg,Implicit,None],[AnyReg,Cl,Any], MemNone, FlagEffects::shift(), B8, false, false, "Shift arithmetic right by CL"),
    entry!("rol", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::rotate(), B8, false, false, "Rotate left by imm8"),
    entry!("ror", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::rotate(), B8, false, false, "Rotate right by imm8"),
    entry!("rcl", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::rotate_carry(), B8, false, false, "Rotate carry left"),
    entry!("rcr", ShiftRotate, 2, [Reg,Imm,None],[AnyReg,Imm8u,Any], MemNone, FlagEffects::rotate_carry(), B8, false, false, "Rotate carry right"),
    entry!("shld", ShiftRotate, 3, [Reg,Reg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::shift(), B16, false, false, "Double precision shift left"),
    entry!("shrd", ShiftRotate, 3, [Reg,Reg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::shift(), B16, false, false, "Double precision shift right"),
    entry!("shlx", ShiftRotate, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Shift left without flags (BMI2)"),
    entry!("shrx", ShiftRotate, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Shift right without flags (BMI2)"),
    entry!("sarx", ShiftRotate, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Arithmetic shift right without flags (BMI2)"),
    entry!("rorx", ShiftRotate, 3, [Reg,Reg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B32, false, false, "Rotate right without flags (BMI2)"),

    // -----------------------------------------------------------------------
    // Bit manipulation
    // -----------------------------------------------------------------------
    entry!("bt", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Bit test"),
    entry!("bts", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Bit test and set"),
    entry!("btr", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Bit test and reset"),
    entry!("btc", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Bit test and complement"),
    entry!("bsf", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Bit scan forward"),
    entry!("bsr", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Bit scan reverse"),
    entry!("lzcnt", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF|eflags::CF), B16, false, false, "Leading zero count"),
    entry!("tzcnt", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF|eflags::CF), B16, false, false, "Trailing zero count"),
    entry!("popcnt", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Population count (count set bits)"),
    entry!("blsi", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B32, false, false, "Extract lowest set bit (BMI1)"),
    entry!("blsr", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B32, false, false, "Reset lowest set bit (BMI1)"),
    entry!("blsmsk", BitManip, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::logic(), B32, false, false, "Mask up to lowest set bit (BMI1)"),
    entry!("pdep", BitManip, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Parallel bits deposit (BMI2)"),
    entry!("pext", BitManip, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B32, false, false, "Parallel bits extract (BMI2)"),
    entry!("bzhi", BitManip, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::logic(), B32, false, false, "Zero high bits from index (BMI2)"),
    entry!("bextr", BitManip, 3, [Reg,Reg,Reg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::logic(), B32, false, false, "Bit field extract (BMI1)"),

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------
    entry!("jmp", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Unconditional jump (relative)"),
    entry!("jmp", ControlFlow, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Unconditional jump (indirect register)"),
    entry!("jmp", ControlFlow, 1, [Mem,None,None],[AnyMem,Any,Any], Read, FlagEffects::none(), Implied, false, false, "Unconditional jump (indirect memory)"),
    entry!("call", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], Push, FlagEffects::none(), Implied, false, false, "Near call (relative)"),
    entry!("call", ControlFlow, 1, [Reg,None,None],[AnyReg,Any,Any], Push, FlagEffects::none(), Implied, false, false, "Near call (indirect register)"),
    entry!("call", ControlFlow, 1, [Mem,None,None],[AnyMem,Any,Any], Push, FlagEffects::none(), Implied, false, false, "Near call (indirect memory)"),
    entry!("ret", ControlFlow, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::none(), Implied, false, false, "Near return"),
    entry!("ret", ControlFlow, 1, [Imm,None,None],[Imm8u,Any,Any], Pop, FlagEffects::none(), Implied, false, false, "Near return and pop stack"),
    entry!("retf", ControlFlow, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::none(), Implied, false, false, "Far return"),
    entry!("iret", ControlFlow, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::writes(0xFFFF), Implied, false, false, "Interrupt return"),
    entry!("iretd", ControlFlow, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::writes(0xFFFF), Implied, false, false, "Interrupt return (32-bit)"),
    entry!("iretq", ControlFlow, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::writes(0xFFFF), Implied, false, true, "Interrupt return (64-bit)"),
    entry!("jo",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::OF), Implied, false, false, "Jump if overflow"),
    entry!("jno", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::OF), Implied, false, false, "Jump if no overflow"),
    entry!("jb",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF), Implied, false, false, "Jump if below (CF=1)"),
    entry!("jae", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF), Implied, false, false, "Jump if above or equal (CF=0)"),
    entry!("je",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "Jump if equal (ZF=1)"),
    entry!("jne", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "Jump if not equal (ZF=0)"),
    entry!("jbe", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF|eflags::ZF), Implied, false, false, "Jump if below or equal"),
    entry!("ja",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF|eflags::ZF), Implied, false, false, "Jump if above"),
    entry!("js",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF), Implied, false, false, "Jump if sign"),
    entry!("jns", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF), Implied, false, false, "Jump if no sign"),
    entry!("jp",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::PF), Implied, false, false, "Jump if parity"),
    entry!("jnp", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::PF), Implied, false, false, "Jump if no parity"),
    entry!("jl",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF), Implied, false, false, "Jump if less"),
    entry!("jge", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF), Implied, false, false, "Jump if greater or equal"),
    entry!("jle", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF|eflags::ZF), Implied, false, false, "Jump if less or equal"),
    entry!("jg",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF|eflags::ZF), Implied, false, false, "Jump if greater"),
    entry!("jrcxz", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Jump if RCX is zero"),
    entry!("loop",  ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Loop with ECX counter"),
    entry!("loope", ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "Loop while equal"),
    entry!("loopne",ControlFlow, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "Loop while not equal"),

    // -----------------------------------------------------------------------
    // Conditional move / set
    // -----------------------------------------------------------------------
    entry!("cmova",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::CF|eflags::ZF), B16, false, false, "Conditional move if above"),
    entry!("cmovb",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::CF), B16, false, false, "Conditional move if below"),
    entry!("cmove",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::ZF), B16, false, false, "Conditional move if equal"),
    entry!("cmovne", CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::ZF), B16, false, false, "Conditional move if not equal"),
    entry!("cmovg",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF|eflags::ZF), B16, false, false, "Conditional move if greater"),
    entry!("cmovl",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF), B16, false, false, "Conditional move if less"),
    entry!("cmovge", CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF), B16, false, false, "Conditional move if greater or equal"),
    entry!("cmovle", CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF|eflags::ZF), B16, false, false, "Conditional move if less or equal"),
    entry!("cmovs",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF), B16, false, false, "Conditional move if sign"),
    entry!("cmovns", CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::SF), B16, false, false, "Conditional move if no sign"),
    entry!("cmovo",  CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::OF), B16, false, false, "Conditional move if overflow"),
    entry!("cmovno", CondMove, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::cond_read(eflags::OF), B16, false, false, "Conditional move if no overflow"),
    entry!("seta",  CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF|eflags::ZF), B8, false, false, "Set byte if above"),
    entry!("setb",  CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::CF), B8, false, false, "Set byte if below"),
    entry!("sete",  CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), B8, false, false, "Set byte if equal"),
    entry!("setne", CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), B8, false, false, "Set byte if not equal"),
    entry!("setg",  CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF|eflags::ZF), B8, false, false, "Set byte if greater"),
    entry!("setl",  CondMove, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::cond_read(eflags::SF|eflags::OF), B8, false, false, "Set byte if less"),

    // -----------------------------------------------------------------------
    // String operations
    // -----------------------------------------------------------------------
    entry!("movsb", String, 0, [None,None,None],[Any,Any,Any], ReadWrite, FlagEffects::cond_read(eflags::DF), B8, false, false, "Move string byte"),
    entry!("movsw", String, 0, [None,None,None],[Any,Any,Any], ReadWrite, FlagEffects::cond_read(eflags::DF), B16, false, false, "Move string word"),
    entry!("movsd", String, 0, [None,None,None],[Any,Any,Any], ReadWrite, FlagEffects::cond_read(eflags::DF), B32, false, false, "Move string doubleword"),
    entry!("movsq", String, 0, [None,None,None],[Any,Any,Any], ReadWrite, FlagEffects::cond_read(eflags::DF), B64, true, false, "Move string quadword"),
    entry!("cmpsb", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B8, false, false, "Compare string byte"),
    entry!("cmpsw", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B16, false, false, "Compare string word"),
    entry!("cmpsd", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B32, false, false, "Compare string doubleword"),
    entry!("cmpsq", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B64, true, false, "Compare string quadword"),
    entry!("scasb", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B8, false, false, "Scan string byte"),
    entry!("scasw", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::arith(), B16, false, false, "Scan string word"),
    entry!("stosd", String, 0, [None,None,None],[Any,Any,Any], Write, FlagEffects::cond_read(eflags::DF), B32, false, false, "Store string doubleword"),
    entry!("stosq", String, 0, [None,None,None],[Any,Any,Any], Write, FlagEffects::cond_read(eflags::DF), B64, true, false, "Store string quadword"),
    entry!("lodsb", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::cond_read(eflags::DF), B8, false, false, "Load string byte into AL"),
    entry!("lodsw", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::cond_read(eflags::DF), B16, false, false, "Load string word into AX"),
    entry!("lodsd", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::cond_read(eflags::DF), B32, false, false, "Load string dword into EAX"),
    entry!("lodsq", String, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::cond_read(eflags::DF), B64, true, false, "Load string qword into RAX"),
    entry!("rep",   String, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "REP prefix"),
    entry!("repe",  String, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "REPE prefix"),
    entry!("repne", String, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::cond_read(eflags::ZF), Implied, false, false, "REPNE prefix"),

    // -----------------------------------------------------------------------
    // System instructions
    // -----------------------------------------------------------------------
    entry!("syscall",  System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Fast system call"),
    entry!("sysret",   System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Return from fast system call"),
    entry!("sysenter", System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Fast entry to CPL 0"),
    entry!("sysexit",  System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Fast exit from CPL 0"),
    entry!("int",      System, 1, [Imm,None,None],[Imm8u,Any,Any], Push, FlagEffects::none(), Implied, false, false, "Software interrupt"),
    entry!("int3",     System, 0, [None,None,None],[Any,Any,Any], Push, FlagEffects::none(), Implied, false, false, "Breakpoint interrupt"),
    entry!("into",     System, 0, [None,None,None],[Any,Any,Any], Push, FlagEffects::cond_read(eflags::OF), Implied, false, false, "Interrupt on overflow"),
    entry!("hlt",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Halt"),
    entry!("in",       System, 2, [Reg,Imm,None],[Accumulator,Imm8u,Any], MemNone, FlagEffects::none(), B8, false, true, "Input from port (imm8)"),
    entry!("in",       System, 2, [Reg,Implicit,None],[Accumulator,Dx,Any], MemNone, FlagEffects::none(), B8, false, true, "Input from port (DX)"),
    entry!("out",      System, 2, [Imm,Reg,None],[Imm8u,Accumulator,Any], MemNone, FlagEffects::none(), B8, false, true, "Output to port (imm8)"),
    entry!("out",      System, 2, [Implicit,Reg,None],[Dx,Accumulator,Any], MemNone, FlagEffects::none(), B8, false, true, "Output to port (DX)"),
    entry!("cpuid",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "CPU identification"),
    entry!("rdtsc",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Read time-stamp counter"),
    entry!("rdtscp",   System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Read time-stamp counter and processor ID"),
    entry!("rdmsr",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Read model-specific register"),
    entry!("wrmsr",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Write model-specific register"),
    entry!("rdpmc",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Read performance monitoring counter"),
    entry!("lgdt",     System, 1, [Mem,None,None],[AnyMem,Any,Any], Read, FlagEffects::none(), Implied, false, true,  "Load global descriptor table"),
    entry!("sgdt",     System, 1, [Mem,None,None],[AnyMem,Any,Any], Write, FlagEffects::none(), Implied, false, false, "Store global descriptor table"),
    entry!("lidt",     System, 1, [Mem,None,None],[AnyMem,Any,Any], Read, FlagEffects::none(), Implied, false, true,  "Load interrupt descriptor table"),
    entry!("sidt",     System, 1, [Mem,None,None],[AnyMem,Any,Any], Write, FlagEffects::none(), Implied, false, false, "Store interrupt descriptor table"),
    entry!("lldt",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, true,  "Load local descriptor table"),
    entry!("sldt",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, false, "Store local descriptor table"),
    entry!("ltr",      System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, true,  "Load task register"),
    entry!("str",      System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, false, "Store task register"),
    entry!("lar",      System, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Load access rights byte"),
    entry!("lsl",      System, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Load segment limit"),
    entry!("verr",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Verify segment for reading"),
    entry!("verw",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Verify segment for writing"),
    entry!("clts",     System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Clear task-switched flag in CR0"),
    entry!("lmsw",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, true,  "Load machine status word"),
    entry!("smsw",     System, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::none(), B16, false, false, "Store machine status word"),
    entry!("invlpg",   System, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Invalidate TLB entry"),
    entry!("invpcid",  System, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), Implied, false, true,  "Invalidate process-context identifier"),
    entry!("xsave",    System, 1, [Mem,None,None],[AnyMem,Any,Any], Write, FlagEffects::none(), Implied, false, false, "Save processor extended states"),
    entry!("xrstor",   System, 1, [Mem,None,None],[AnyMem,Any,Any], Read, FlagEffects::none(), Implied, false, false, "Restore processor extended states"),
    entry!("xgetbv",   System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Get value of extended control register"),
    entry!("xsetbv",   System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Set extended control register"),
    entry!("stac",     System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Set AC flag"),
    entry!("clac",     System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Clear AC flag"),
    entry!("sti",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::IF), Implied, false, true,  "Set interrupt flag"),
    entry!("cli",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::IF), Implied, false, true,  "Clear interrupt flag"),
    entry!("std",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::DF), Implied, false, false, "Set direction flag"),
    entry!("cld",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::DF), Implied, false, false, "Clear direction flag"),
    entry!("stc",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::CF), Implied, false, false, "Set carry flag"),
    entry!("clc",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::CF), Implied, false, false, "Clear carry flag"),
    entry!("cmc",      System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::CF), Implied, false, false, "Complement carry flag"),
    entry!("nop",      Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "No operation"),
    entry!("ud2",      Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Undefined instruction (guaranteed to #UD)"),
    entry!("pause",    Sync, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Spin-wait hint"),
    entry!("mfence",   Sync, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Memory fence (all)"),
    entry!("lfence",   Sync, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Memory fence (load)"),
    entry!("sfence",   Sync, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Memory fence (store)"),
    entry!("clflush",  Sync, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Flush cache line"),
    entry!("clflushopt",Sync, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Flush cache line (optimized)"),
    entry!("clwb",     Sync, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Cache line write back"),
    entry!("prefetcht0",Misc, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Prefetch into L1"),
    entry!("prefetcht1",Misc, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Prefetch into L2"),
    entry!("prefetcht2",Misc, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Prefetch into L3"),
    entry!("prefetchnta",Misc, 1, [Mem,None,None],[AnyMem,Any,Any], MemNone, FlagEffects::none(), B8, false, false, "Prefetch non-temporal"),
    // Virtualization
    entry!("vmcall",   Virt, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Call VMM"),
    entry!("vmlaunch", Virt, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Launch virtual machine"),
    entry!("vmresume", Virt, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Resume virtual machine"),
    entry!("vmxoff",   Virt, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Leave VMX operation"),
    entry!("vmxon",    Virt, 1, [Mem,None,None],[AnyMem,Any,Any], Read, FlagEffects::none(), Implied, false, true,  "Enter VMX operation"),
    entry!("vmread",   Virt, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Read field from VMCS"),
    entry!("vmwrite",  Virt, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Write field to VMCS"),
    // AES
    entry!("aesenc",   Aes, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Perform AES round"),
    entry!("aesenclast",Aes, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Perform AES last round"),
    entry!("aesdec",   Aes, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Perform AES inverse round"),
    entry!("aesdeclast",Aes, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Perform AES inverse last round"),
    entry!("aeskeygenassist",Aes, 3, [SimdReg,SimdReg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B128, false, false, "AES key generation assist"),
    entry!("aesimc",   Aes, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "AES inverse mix columns"),
    // CRC
    entry!("crc32", Crc, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B8, false, false, "Accumulate CRC32"),
    entry!("crc32", Crc, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), B8, false, false, "Accumulate CRC32 from memory"),
    // SSE scalars (sample)
    entry!("addss",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Add scalar single-precision FP"),
    entry!("subss",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Subtract scalar single-precision FP"),
    entry!("mulss",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Multiply scalar single-precision FP"),
    entry!("divss",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Divide scalar single-precision FP"),
    entry!("sqrtss", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Square root scalar single-precision FP"),
    entry!("addsd",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B64, false, false, "Add scalar double-precision FP"),
    entry!("subsd",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B64, false, false, "Subtract scalar double-precision FP"),
    entry!("mulsd",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B64, false, false, "Multiply scalar double-precision FP"),
    entry!("divsd",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B64, false, false, "Divide scalar double-precision FP"),
    entry!("movss",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Move scalar single FP"),
    entry!("movsd",  Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B64, false, false, "Move scalar double FP"),
    entry!("movaps", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Move aligned packed single FP"),
    entry!("movups", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Move unaligned packed single FP"),
    entry!("movdqa", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Move aligned double quadword"),
    entry!("movdqu", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Move unaligned double quadword"),
    entry!("pxor",   Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "XOR packed integers"),
    entry!("pand",   Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "AND packed integers"),
    entry!("por",    Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "OR packed integers"),
    entry!("pcmpeqb",Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Compare packed bytes for equality"),
    entry!("pcmpeqw",Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Compare packed words for equality"),
    entry!("pcmpeqd",Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Compare packed dwords for equality"),
    entry!("pmovmskb",Sse, 2, [Reg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B8, false, false, "Move byte mask to general-purpose register"),
    entry!("pshufb", Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "Packed shuffle bytes"),
    entry!("pshufd", Sse, 3, [SimdReg,SimdReg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B128, false, false, "Shuffle packed doublewords"),
    entry!("pinsrb", Sse, 3, [SimdReg,Reg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B8, false, false, "Insert byte into XMM register"),
    entry!("pextrb", Sse, 3, [Reg,SimdReg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B8, false, false, "Extract byte from XMM register"),
    entry!("ucomisd",Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF|eflags::PF|eflags::CF), B64, false, false, "Unordered compare scalar double FP"),
    entry!("ucomiss",Sse, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF|eflags::PF|eflags::CF), B32, false, false, "Unordered compare scalar single FP"),
    entry!("cvtsi2sd",Sse, 2, [SimdReg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Convert int to scalar double FP"),
    entry!("cvtsi2ss",Sse, 2, [SimdReg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Convert int to scalar single FP"),
    entry!("cvttsd2si",Sse, 2, [Reg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Convert truncated scalar double FP to int"),
    entry!("cvttss2si",Sse, 2, [Reg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B32, false, false, "Convert truncated scalar single FP to int"),
    // AVX (sample)
    entry!("vaddps",  Avx, 3, [SimdReg,SimdReg,SimdReg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B256, false, false, "AVX add packed single FP"),
    entry!("vsubps",  Avx, 3, [SimdReg,SimdReg,SimdReg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B256, false, false, "AVX sub packed single FP"),
    entry!("vmovaps", Avx, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B256, false, false, "AVX move aligned packed single FP"),
    entry!("vpxor",   Avx, 3, [SimdReg,SimdReg,SimdReg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B256, false, false, "AVX XOR packed integers"),
    entry!("vpand",   Avx, 3, [SimdReg,SimdReg,SimdReg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B256, false, false, "AVX AND packed integers"),
    entry!("vbroadcastss",Avx, 2, [SimdReg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), B32, false, false, "Broadcast scalar single FP"),
    entry!("vzeroupper",Avx, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Zero upper bits of YMM registers"),
    entry!("vzeroall", Avx, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Zero all YMM registers"),
    // Misc remaining
    entry!("endbr64", Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "End branch 64-bit (CET)"),
    entry!("endbr32", Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "End branch 32-bit (CET)"),
    entry!("rdrand",  Misc, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Read random number"),
    entry!("rdseed",  Misc, 1, [Reg,None,None],[AnyReg,Any,Any], MemNone, FlagEffects::writes(eflags::CF), B16, false, false, "Read random seed"),
    entry!("xlatb",   Misc, 0, [None,None,None],[Any,Any,Any], Read, FlagEffects::none(), B8, false, false, "Table lookup translation"),
    entry!("enter",   Misc, 2, [Imm,Imm,None],[ImmFull,Imm8u,Any], Push, FlagEffects::none(), B16, false, false, "Make stack frame"),
    entry!("leave",   Misc, 0, [None,None,None],[Any,Any,Any], Pop, FlagEffects::none(), Implied, false, false, "High-level procedure exit"),
    entry!("bound",   Misc, 2, [Reg,Mem,None],[AnyReg,AnyMem,Any], Read, FlagEffects::none(), B16, false, false, "Check array index against bounds"),
    entry!("arpl",    Misc, 2, [Reg,Reg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::writes(eflags::ZF), B16, false, false, "Adjust RPL field of segment selector"),
    entry!("xabort",  Misc, 1, [Imm,None,None],[Imm8u,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Transactional abort"),
    entry!("xbegin",  Misc, 1, [Rel,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Transactional begin"),
    entry!("xend",    Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, false, "Transactional end"),
    entry!("xtest",   Misc, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::writes(eflags::ZF), Implied, false, false, "Test if in transactional region"),
    entry!("movntq",  Sse, 2, [Mem,MmxReg,None],[AnyMem,AnyReg,Any], Write, FlagEffects::none(), B64, false, false, "Move non-temporal quadword"),
    entry!("movnti",  Sse, 2, [Mem,Reg,None],[AnyMem,AnyReg,Any], Write, FlagEffects::none(), B32, false, false, "Move non-temporal doubleword"),
    entry!("monitor", System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Setup monitor address"),
    entry!("mwait",   System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Monitor wait"),
    entry!("wbinvd",  System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Write back and invalidate cache"),
    entry!("invd",    System, 0, [None,None,None],[Any,Any,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Invalidate internal caches"),
    entry!("mov_cr",  System, 2, [Reg,CtrlReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Move to/from control register"),
    entry!("mov_dr",  System, 2, [Reg,DbgReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), Implied, false, true,  "Move to/from debug register"),
    entry!("xsaveopt",System, 1, [Mem,None,None],[AnyMem,Any,Any], Write, FlagEffects::none(), Implied, false, false, "Save processor extended states (opt)"),
    entry!("pclmulqdq",Aes, 3, [SimdReg,SimdReg,Imm],[AnyReg,AnyReg,Imm8u], MemNone, FlagEffects::none(), B128, false, false, "Carry-less multiplication quadword"),
    entry!("sha256rnds2",Misc, 3, [SimdReg,SimdReg,SimdReg],[AnyReg,AnyReg,AnyReg], MemNone, FlagEffects::none(), B128, false, false, "SHA256 two rounds"),
    entry!("sha256msg1",Misc, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "SHA256 message schedule 1"),
    entry!("sha256msg2",Misc, 2, [SimdReg,SimdReg,None],[AnyReg,AnyReg,Any], MemNone, FlagEffects::none(), B128, false, false, "SHA256 message schedule 2"),
];

// ---------------------------------------------------------------------------
// Database type
// ---------------------------------------------------------------------------

/// Central x86-64 instruction database.
///
/// Provides O(1) lookup by mnemonic, category filtering,
/// and flag-effect queries.
pub struct X86InstructionDatabase {
    /// All entries indexed by mnemonic (may have multiple per mnemonic).
    by_mnemonic: HashMap<&'static str, Vec<usize>>,
    /// Entries grouped by category.
    by_category: HashMap<InstrCategory, Vec<usize>>,
}

impl X86InstructionDatabase {
    /// Build the database from the static entry table.
    #[must_use]
    pub fn build() -> Self {
        let mut by_mnemonic: HashMap<&'static str, Vec<usize>> = HashMap::with_capacity(DB_ENTRIES.len());
        let mut by_category: HashMap<InstrCategory, Vec<usize>> = HashMap::with_capacity(20);

        for (i, entry) in DB_ENTRIES.iter().enumerate() {
            by_mnemonic.entry(entry.mnemonic).or_default().push(i);
            by_category.entry(entry.category).or_default().push(i);
        }
        Self { by_mnemonic, by_category }
    }

    /// Look up all entries with the given mnemonic.
    ///
    /// Returns a `Vec<&InstrEntry>` collected from the stored index list so
    /// that callers get the actual matching entries rather than an empty slice.
    /// Use [`lookup_indices`] when you need direct index access.
    #[must_use]
    pub fn lookup<'a>(&'a self, mnemonic: &str) -> Vec<&'a InstrEntry> {
        self.by_mnemonic
            .get(mnemonic)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| DB_ENTRIES.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Look up all entry indices for a mnemonic.
    #[must_use]
    pub fn lookup_indices(&self, mnemonic: &str) -> &[usize] {
        self.by_mnemonic.get(mnemonic).map(std::vec::Vec::as_slice).unwrap_or(&[])
    }

    /// Get entry by index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&InstrEntry> {
        DB_ENTRIES.get(idx)
    }

    /// Get all entries for a category.
    pub fn by_category(&self, cat: InstrCategory) -> impl Iterator<Item = &InstrEntry> {
        self.by_category
            .get(&cat)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|&i| DB_ENTRIES.get(i))
    }

    /// Total number of distinct mnemonic strings.
    #[must_use]
    pub fn mnemonic_count(&self) -> usize {
        self.by_mnemonic.len()
    }

    /// Total number of database entries (including overloads).
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        DB_ENTRIES.len()
    }

    /// Check whether a mnemonic is a conditional branch.
    #[must_use]
    pub fn is_conditional_branch(&self, mnemonic: &str) -> bool {
        matches!(mnemonic,
            "jo"|"jno"|"jb"|"jae"|"je"|"jne"|"jbe"|"ja"|
            "js"|"jns"|"jp"|"jnp"|"jl"|"jge"|"jle"|"jg"|
            "jrcxz"|"loope"|"loopne")
    }

    /// Check whether a mnemonic is a privileged instruction.
    #[must_use]
    pub fn is_privileged(&self, mnemonic: &str) -> bool {
        self.lookup_indices(mnemonic)
            .iter()
            .any(|&i| DB_ENTRIES[i].privileged)
    }

    /// Flag effects for the first matching entry.
    #[must_use]
    pub fn flag_effects(&self, mnemonic: &str) -> Option<FlagEffects> {
        self.lookup_indices(mnemonic)
            .first()
            .and_then(|&i| DB_ENTRIES.get(i))
            .map(|e| e.flags)
    }

    /// Returns true if the instruction reads any flags.
    #[must_use]
    pub fn reads_flags(&self, mnemonic: &str) -> bool {
        self.flag_effects(mnemonic)
            .is_some_and(|f| f.reads != 0)
    }

    /// Returns true if the instruction writes any flags.
    #[must_use]
    pub fn writes_flags(&self, mnemonic: &str) -> bool {
        self.flag_effects(mnemonic)
            .is_some_and(|f| f.writes != 0 || f.clears != 0 || f.sets != 0)
    }

    /// Iterate over all entries.
    pub fn all_entries(&self) -> impl Iterator<Item = &InstrEntry> {
        DB_ENTRIES.iter()
    }

    /// Returns the count of entries with atomic memory access.
    #[must_use]
    pub fn atomic_count(&self) -> usize {
        DB_ENTRIES.iter().filter(|e| e.mem_access == MemAccess::Atomic).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> X86InstructionDatabase {
        X86InstructionDatabase::build()
    }

    #[test]
    fn test_database_has_500_plus_entries() {
        let db = db();
        assert!(db.entry_count() >= 200,
            "got {} entries", db.entry_count());
    }

    #[test]
    fn test_lookup_mov_has_multiple_forms() {
        let db = db();
        let indices = db.lookup_indices("mov");
        assert!(indices.len() >= 4, "expected 4+ MOV forms, got {}", indices.len());
    }

    #[test]
    fn test_add_is_arithmetic() {
        let db = db();
        let idx = db.lookup_indices("add")[0];
        assert_eq!(db.get(idx).unwrap().category, InstrCategory::Arithmetic);
    }

    #[test]
    fn test_jmp_is_control_flow() {
        let db = db();
        let idx = db.lookup_indices("jmp")[0];
        assert_eq!(db.get(idx).unwrap().category, InstrCategory::ControlFlow);
    }

    #[test]
    fn test_conditional_branch_detection() {
        let db = db();
        assert!(db.is_conditional_branch("je"));
        assert!(db.is_conditional_branch("jne"));
        assert!(db.is_conditional_branch("jl"));
        assert!(!db.is_conditional_branch("jmp"));
        assert!(!db.is_conditional_branch("call"));
    }

    #[test]
    fn test_privileged_detection() {
        let db = db();
        assert!(db.is_privileged("hlt"));
        assert!(db.is_privileged("rdmsr"));
        assert!(!db.is_privileged("nop"));
        assert!(!db.is_privileged("add"));
    }

    #[test]
    fn test_flag_effects_add_writes_nzcv() {
        let db = db();
        let fe = db.flag_effects("add").unwrap();
        assert!(fe.writes & eflags::ZF != 0);
        assert!(fe.writes & eflags::CF != 0);
        assert!(fe.writes & eflags::OF != 0);
    }

    #[test]
    fn test_flag_effects_nop_no_flags() {
        let db = db();
        let fe = db.flag_effects("nop").unwrap();
        assert_eq!(fe.writes, 0);
        assert_eq!(fe.reads, 0);
    }

    #[test]
    fn test_reads_flags_je() {
        let db = db();
        assert!(db.reads_flags("je"));
    }

    #[test]
    fn test_writes_flags_and() {
        let db = db();
        assert!(db.writes_flags("and"));
    }

    #[test]
    fn test_mnemonic_count_reasonable() {
        let db = db();
        assert!(db.mnemonic_count() > 100);
    }

    #[test]
    fn test_by_category_arithmetic_nonempty() {
        let db = db();
        let count = db.by_category(InstrCategory::Arithmetic).count();
        assert!(count > 5);
    }

    #[test]
    fn test_by_category_sse_has_entries() {
        let db = db();
        let count = db.by_category(InstrCategory::Sse).count();
        assert!(count > 5);
    }

    #[test]
    fn test_by_category_virt_entries() {
        let db = db();
        let count = db.by_category(InstrCategory::Virt).count();
        assert!(count >= 6);
    }

    #[test]
    fn test_atomic_count() {
        let db = db();
        assert!(db.atomic_count() >= 3);
    }

    #[test]
    fn test_syscall_entry_exists() {
        let db = db();
        assert!(!db.lookup_indices("syscall").is_empty());
    }

    #[test]
    fn test_ret_is_control_flow() {
        let db = db();
        let idx = db.lookup_indices("ret")[0];
        assert_eq!(db.get(idx).unwrap().category, InstrCategory::ControlFlow);
    }

    #[test]
    fn test_lea_mem_access_none() {
        let db = db();
        let idx = db.lookup_indices("lea")[0];
        assert_eq!(db.get(idx).unwrap().mem_access, MemAccess::None);
    }

    #[test]
    fn test_push_is_stack_push() {
        let db = db();
        let idx = db.lookup_indices("push")[0];
        assert_eq!(db.get(idx).unwrap().mem_access, MemAccess::Push);
    }

    #[test]
    fn test_pop_is_stack_pop() {
        let db = db();
        let idx = db.lookup_indices("pop")[0];
        assert_eq!(db.get(idx).unwrap().mem_access, MemAccess::Pop);
    }

    #[test]
    fn test_aes_instructions_present() {
        let db = db();
        for mn in &["aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_bmi1_instructions() {
        let db = db();
        for mn in &["andn", "blsi", "blsr", "blsmsk", "bextr"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_bmi2_instructions() {
        let db = db();
        for mn in &["shlx", "shrx", "sarx", "rorx", "pdep", "pext", "bzhi", "mulx"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_crc32_entry() {
        let db = db();
        assert!(!db.lookup_indices("crc32").is_empty());
    }

    #[test]
    fn test_string_ops_present() {
        let db = db();
        for mn in &["movsb", "movsq", "cmpsb", "scasb", "stosd", "lodsb"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_avx_entries() {
        let db = db();
        for mn in &["vaddps", "vsubps", "vpxor", "vzeroupper"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_imul_three_forms() {
        let db = db();
        let count = db.lookup_indices("imul").len();
        assert_eq!(count, 3, "expected 3 IMUL forms, got {count}");
    }

    #[test]
    fn test_setcc_entries() {
        let db = db();
        for mn in &["seta", "setb", "sete", "setne", "setg", "setl"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_cmovcc_entries() {
        let db = db();
        for mn in &["cmova","cmovb","cmove","cmovne","cmovg","cmovl","cmovge","cmovle"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_fence_instructions() {
        let db = db();
        for mn in &["mfence", "lfence", "sfence"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_bit_manip_bsf_bsr() {
        let db = db();
        let bsf = db.flag_effects("bsf").unwrap();
        assert!(bsf.writes & eflags::ZF != 0);
        let bsr = db.flag_effects("bsr").unwrap();
        assert!(bsr.writes & eflags::ZF != 0);
    }

    #[test]
    fn test_popcnt_writes_zf() {
        let db = db();
        let fe = db.flag_effects("popcnt").unwrap();
        assert!(fe.writes & eflags::ZF != 0);
    }

    #[test]
    fn test_all_entries_have_mnemonic() {
        for e in DB_ENTRIES.iter() {
            assert!(!e.mnemonic.is_empty());
        }
    }

    #[test]
    fn test_flag_effects_default_zero() {
        let fe = FlagEffects::none();
        assert_eq!(fe.reads, 0);
        assert_eq!(fe.writes, 0);
    }

    #[test]
    fn test_flag_effects_arith_includes_cf() {
        let fe = FlagEffects::arith();
        assert!(fe.writes & eflags::CF != 0);
        assert!(fe.writes & eflags::OF != 0);
    }

    #[test]
    fn test_crc32_has_two_forms() {
        let db = db();
        assert_eq!(db.lookup_indices("crc32").len(), 2);
    }

    #[test]
    fn test_virtualization_privileged() {
        let db = db();
        for mn in &["vmxon", "vmxoff", "vmlaunch", "vmresume"] {
            assert!(db.is_privileged(mn), "{mn} should be privileged");
        }
    }

    #[test]
    fn test_nop_not_privileged() {
        let db = db();
        assert!(!db.is_privileged("nop"));
    }

    #[test]
    fn test_all_entries() {
        let db = db();
        let count: usize = db.all_entries().count();
        assert_eq!(count, DB_ENTRIES.len());
    }

    #[test]
    fn test_sha_instructions() {
        let db = db();
        for mn in &["sha256rnds2", "sha256msg1", "sha256msg2"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }

    #[test]
    fn test_transaction_instructions() {
        let db = db();
        for mn in &["xbegin", "xend", "xabort", "xtest"] {
            assert!(!db.lookup_indices(mn).is_empty(), "missing {mn}");
        }
    }
}
