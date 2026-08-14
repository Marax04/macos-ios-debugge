//! Per-instruction lifting context for the x86/x64 lifter.
//!
//! `X86LiftCtx` is the mutable state every handler receives. Handlers do not
//! return `Vec<Effect>` directly: they push micro-operations onto the context
//! through `ctx.emit(...)`. This guarantees that all handlers obey the
//! μOps-atomicity discipline (no handler builds a giant single-effect blob)
//! and that the context can centralise concerns shared by every handler:
//!
//!   * fresh temporary register names (`__t0`, `__t1`, …)
//!   * the current instruction address (for error reporting and metadata)
//!   * the machine mode (16 / 32 / 64) used to resolve operand-size defaults
//!   * a `ModeHint` describing already-decoded prefixes (REX, operand-size
//!     override, address-size override, segment override) so the handler does
//!     not need to interrogate the raw `iced_x86::Instruction` for them again
//!   * a textual buffer used to produce the `LiftedInstr::ir_text` field
//!
//! The context is single-instruction scoped: one `X86LiftCtx` is created per
//! input instruction, drained into a `LiftedInstr`, then dropped. The
//! `temp_counter` resets per instruction — temporaries are local.

use crate::{Effect, IrExpr};

/// Truncate `expr` to the low `bits` bits by AND-masking.
///
/// Widths of 0 or
/// ≥64 are returned unchanged (64-bit ops need no mask; 0 means "unknown
/// width", left to the caller). Used to give arithmetic results the correct
/// operand width before they feed flag formulas and the destination commit.
#[must_use]
pub fn truncate_to_width(expr: IrExpr, bits: u8) -> IrExpr {
    if bits == 0 || bits >= 64 {
        expr
    } else {
        let mask = (1u64 << bits) - 1;
        IrExpr::And(Box::new(expr), Box::new(IrExpr::Const(mask)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagId
// ─────────────────────────────────────────────────────────────────────────────

/// Symbolic identifier for the six observable x86 EFLAGS / RFLAGS bits.
///
/// `Display` (and conversion to the canonical IR register name) uses the
/// two-letter lowercase form (`cf`, `pf`, `af`, `zf`, `sf`, `of`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagId {
    /// Carry flag — unsigned overflow.
    Cf,
    /// Parity flag — even parity of the low byte of the result.
    Pf,
    /// Auxiliary / BCD carry — carry out of bit 3.
    Af,
    /// Zero flag — result was zero.
    Zf,
    /// Sign flag — most-significant bit of the result.
    Sf,
    /// Overflow flag — signed overflow.
    Of,
    /// Direction flag — controls string-op pointer direction (model-only).
    Df,
    /// Interrupt enable flag (system-only).
    If,
}

impl FlagId {
    /// Canonical lower-case name used as the register identifier in
    /// `Effect::RegWrite { reg: ... }`.
    #[must_use]
    pub const fn as_reg(self) -> &'static str {
        match self {
            Self::Cf => "cf",
            Self::Pf => "pf",
            Self::Af => "af",
            Self::Zf => "zf",
            Self::Sf => "sf",
            Self::Of => "of",
            Self::Df => "df",
            Self::If => "if",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ModeHint
// ─────────────────────────────────────────────────────────────────────────────

/// x86 repeat/lock prefix flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixFlags {
    /// REP / REPE / REPZ prefix was active.
    pub has_rep: bool,
    /// REPNE / REPNZ prefix was active.
    pub has_repne: bool,
    /// LOCK prefix was active.
    pub has_lock: bool,
}

/// Pre-resolved instruction prefix flags. Built once when the context is
/// constructed; the handlers consult it instead of re-parsing the raw
/// `iced_x86::Instruction`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModeHint {
    /// REX.W bit was set (operand-size promoted to 64-bit).
    pub rex_w: bool,
    /// Operand-size override prefix (0x66) was active.
    pub op_size_override: bool,
    /// Address-size override prefix (0x67) was active.
    pub addr_size_override: bool,
    /// Repeat and lock prefix flags.
    pub prefixes: PrefixFlags,
    /// Explicit segment override, if any (0 = none, 1=es, 2=cs, 3=ss, 4=ds, 5=fs, 6=gs).
    pub seg_override: u8,
}

impl ModeHint {
    /// Build a `ModeHint` by inspecting an `iced_x86::Instruction`.
    #[must_use]
    pub fn from_instr(instr: &iced_x86::Instruction) -> Self {
        use iced_x86::Register as R;
        let seg_override = match instr.segment_prefix() {
            R::ES => 1,
            R::CS => 2,
            R::SS => 3,
            R::DS => 4,
            R::FS => 5,
            R::GS => 6,
            _ => 0,
        };
        Self {
            rex_w: false,
            op_size_override: false,
            addr_size_override: false,
            prefixes: PrefixFlags { has_rep: instr.has_rep_prefix() || instr.has_repe_prefix(), has_repne: instr.has_repne_prefix(), has_lock: instr.has_lock_prefix() },
            seg_override,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// X86LiftCtx
// ─────────────────────────────────────────────────────────────────────────────

/// Per-instruction lifting context.
///
/// Handlers push micro-operations via [`emit`](Self::emit) or one of the
/// flag/temp/intrinsic shortcuts. After all handlers for an instruction have
/// run, the buffered [`Effect`]s and `ir_text` are folded into a
/// [`LiftedInstr`](crate::LiftedInstr).
#[derive(Debug, Clone)]
pub struct X86LiftCtx {
    /// μOps emitted for the current instruction.
    pub effects: Vec<Effect>,
    /// Monotonically-increasing counter used by [`fresh_temp`](Self::fresh_temp).
    pub temp_counter: u32,
    /// Native address of the instruction being lifted (used for branch targets).
    pub addr: u64,
    /// Machine mode: 16, 32, or 64.
    pub bits: u8,
    /// Resolved prefix flags.
    pub mode: ModeHint,
    /// Accumulated human-readable IR text for the current instruction.
    pub ir_text: String,
}

impl X86LiftCtx {
    /// Create a context for a single instruction at `addr` in `bits`-mode.
    #[must_use]
    pub fn new(addr: u64, bits: u8, mode: ModeHint) -> Self {
        Self {
            effects: Vec::with_capacity(8),
            temp_counter: 0,
            addr,
            bits,
            mode,
            ir_text: String::new(),
        }
    }

    /// Append a single μOp to the context buffer.
    pub fn emit(&mut self, e: Effect) {
        use std::fmt::Write as _;
        if !self.ir_text.is_empty() {
            self.ir_text.push_str("; ");
        }
        let _ = write!(self.ir_text, "{e}");
        self.effects.push(e);
    }

    /// Allocate a fresh per-instruction temporary register name.
    ///
    /// Names follow the convention `__t<N>` where `N` is the per-instruction
    /// counter; this guarantees uniqueness within an instruction but allows
    /// later passes to recognise temporary registers by prefix.
    pub fn fresh_temp(&mut self) -> String {
        let name = format!("__t{}", self.temp_counter);
        self.temp_counter += 1;
        name
    }

    /// Emit a write that materialises `value` into a fresh temporary, and
    /// return the temporary's register name. Use this to keep the IR linear:
    /// every non-trivial expression gets named so flag formulas and the
    /// destination commit can both reference the same temp without
    /// duplicating its tree.
    pub fn materialise(&mut self, value: IrExpr) -> String {
        let t = self.fresh_temp();
        self.emit(Effect::RegWrite {
            reg: t.clone(),
            value,
        });
        t
    }

    /// Like [`materialise`](Self::materialise) but first truncates `value` to
    /// `bits` width. x86 arithmetic produces a result of the operand width;
    /// the truncated temp is what both the flag formulas (ZF/SF/PF) and the
    /// destination commit must observe, so that e.g. `INC eax` wrapping
    /// `0xFFFF_FFFF → 0` correctly sets ZF in 32-bit mode.
    pub fn materialise_sized(&mut self, value: IrExpr, bits: u8) -> String {
        self.materialise(truncate_to_width(value, bits))
    }

    /// Emit `Effect::RegWrite { reg: <flag>, value }` — short-hand used by
    /// the flag-formula module.
    pub fn emit_flagset(&mut self, flag: FlagId, value: IrExpr) {
        self.emit(Effect::RegWrite {
            reg: flag.as_reg().to_string(),
            value,
        });
    }

    /// Emit a flag write whose semantic source is described by an adjacent
    /// `Intrinsic`. This is the lazy-flag idiom: the `RegWrite` carries
    /// `IrExpr::Undef`, while the preceding `Intrinsic` describes the formula
    /// (e.g. `x86.flag.cf_add`). MLIL peephole passes can pattern-match this
    /// pair to either compute the explicit bit or eliminate it as dead code.
    pub fn emit_flag_intrinsic(&mut self, flag: FlagId, intrinsic: &str, args: Vec<IrExpr>) {
        self.emit(Effect::Intrinsic {
            name: intrinsic.to_string(),
            args,
        });
        self.emit_flagset(flag, IrExpr::Undef);
    }

    /// Emit a register write. Convenience wrapper.
    pub fn emit_reg_write(&mut self, reg: impl Into<String>, value: IrExpr) {
        self.emit(Effect::RegWrite {
            reg: reg.into(),
            value,
        });
    }

    /// Emit a memory write. Convenience wrapper.
    pub fn emit_mem_write(&mut self, addr: IrExpr, value: IrExpr, size: u8) {
        self.emit(Effect::MemWrite { addr, value, size });
    }

    /// Emit a memory read into `dest`. Convenience wrapper.
    pub fn emit_mem_read(&mut self, addr: IrExpr, dest: impl Into<String>, size: u8) {
        self.emit(Effect::MemRead {
            addr,
            dest: dest.into(),
            size,
        });
    }

    /// Emit an unconditional branch to `target`.
    pub fn emit_jump(&mut self, target: IrExpr) {
        self.emit(Effect::Branch {
            target,
            condition: None,
        });
    }

    /// Emit a conditional branch.
    pub fn emit_branch_if(&mut self, target: IrExpr, condition: IrExpr) {
        self.emit(Effect::Branch {
            target,
            condition: Some(condition),
        });
    }

    /// Emit a `call` effect.
    pub fn emit_call(&mut self, target: IrExpr) {
        self.emit(Effect::Call { target });
    }

    /// Emit a `return` effect.
    pub fn emit_return(&mut self) {
        self.emit(Effect::Return { value: None });
    }

    /// Emit an opaque architecture-specific intrinsic.
    pub fn emit_intrinsic(&mut self, name: impl Into<String>, args: Vec<IrExpr>) {
        self.emit(Effect::Intrinsic {
            name: name.into(),
            args,
        });
    }

    /// Number of effects emitted so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.effects.len()
    }

    /// `true` if nothing has been emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Default operand width (bytes) for the current machine mode and the
    /// instruction's prefix state. Used by handlers that do not have an
    /// explicit operand from which to read the size (e.g. `PUSHF`, `LEAVE`).
    #[must_use]
    pub const fn default_op_size(&self) -> u8 {
        if self.mode.op_size_override {
            2
        } else if self.bits == 64 {
            if self.mode.rex_w { 8 } else { 4 }
        } else if self.bits == 32 {
            4
        } else {
            2
        }
    }

    /// Default stack-pointer width (bytes) for the current mode. The stack
    /// pointer is `RSP` in 64-bit mode, `ESP` in 32-bit mode, `SP` in 16-bit.
    #[must_use]
    pub const fn stack_ptr_size(&self) -> u8 {
        match self.bits {
            64 => 8,
            32 => 4,
            _ => 2,
        }
    }

    /// Canonical name of the stack pointer in the current mode.
    #[must_use]
    pub const fn stack_ptr(&self) -> &'static str {
        match self.bits {
            64 => "rsp",
            32 => "esp",
            _ => "sp",
        }
    }

    /// Canonical name of the base pointer in the current mode.
    #[must_use]
    pub const fn base_ptr(&self) -> &'static str {
        match self.bits {
            64 => "rbp",
            32 => "ebp",
            _ => "bp",
        }
    }

    /// Alias of [`base_ptr`](Self::base_ptr): canonical name of the frame pointer
    /// register in the current mode.
    #[must_use]
    pub const fn frame_ptr(&self) -> &'static str {
        self.base_ptr()
    }

    /// Returns the current machine mode as a numeric bit-width (16, 32, or 64).
    #[must_use]
    pub const fn mode(&self) -> u8 {
        self.bits
    }

    /// Canonical name of the program counter in the current mode.
    #[must_use]
    pub const fn ip(&self) -> &'static str {
        match self.bits {
            64 => "rip",
            32 => "eip",
            _ => "ip",
        }
    }

    /// Canonical name of the counter register `(R/E)CX` in the current mode.
    #[must_use]
    pub const fn counter_reg(&self) -> &'static str {
        match self.bits {
            64 => "rcx",
            32 => "ecx",
            _ => "cx",
        }
    }

    /// Canonical name of the string source-index register `(R/E)SI`.
    #[must_use]
    pub const fn si_reg(&self) -> &'static str {
        match self.bits {
            64 => "rsi",
            32 => "esi",
            _ => "si",
        }
    }

    /// Canonical name of the string destination-index register `(R/E)DI`.
    #[must_use]
    pub const fn di_reg(&self) -> &'static str {
        match self.bits {
            64 => "rdi",
            32 => "edi",
            _ => "di",
        }
    }
}
