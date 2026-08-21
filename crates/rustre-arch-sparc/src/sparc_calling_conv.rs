//! SPARC calling conventions — register windows, ABI flavours, and struct return.
//!
//! Covers both the classic SPARC-V8 (32-bit) ABI and the LP64 SPARC-V9 ABI as
//! defined by the System V Application Binary Interface Supplement for SPARC.
//!
//! # Register window overview
//!
//! SPARC maintains a circular buffer of overlapping *register windows* managed
//! by the hardware.  Each `SAVE` instruction advances the Current Window Pointer
//! (CWP) and maps the caller's `%o` registers to the callee's `%i` registers,
//! allocating 16 new `%l`/`%o` registers.  `RESTORE` reverses this.
//!
//! ```text
//! Caller window:  %g0-%g7  %o0-%o7  %l0-%l7  %i0-%i7
//!                                               ↓ alias ↓
//! Callee window:  %g0-%g7  %o0-%o7  %l0-%l7  %i0-%i7 ← %o0-%o7 of caller
//! ```
//!
//! The Window Invalid Mask (WIM) tracks which windows are "invalid"; on
//! overflow a `window_overflow` trap is raised and the OS spills windows to the
//! stack.  The minimum depth is NWINDOWS − 1 usable windows.

use std::fmt;
use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum SPARC register window depth (implementation defined, 2–32).
pub const MIN_WINDOWS: u8 = 2;
/// Maximum register window depth.
pub const MAX_WINDOWS: u8 = 32;
/// Number of windows typical on SPARC-V8 Leon processors.
pub const LEON_WINDOWS: u8 = 8;
/// Number of windows on UltraSPARC-T1 hardware.
pub const ULTRASPARC_T1_WINDOWS: u8 = 8;

/// Stack bias on SPARC-V9 LP64: the SP register points 2047 bytes *below* the
/// actual top of the stack frame.  This allows two extra bytes of addressing
/// for the on-stack register save area.
pub const STACK_BIAS_V9: i64 = 2047;

/// Size of a SPARC-V8 register-window save area on the stack (16 × 4 = 64 bytes).
pub const SAVE_AREA_SIZE_V8: usize = 64;
/// Size of a SPARC-V9 register-window save area on the stack (16 × 8 = 128 bytes).
pub const SAVE_AREA_SIZE_V9: usize = 128;

/// Minimum stack frame size mandated by SPARC-V8 ABI (92 bytes = 64 save area
/// + 4 hidden struct-return pointer + 6×4 outgoing register spill area).
pub const MIN_FRAME_SIZE_V8: usize = 92;
/// Minimum stack frame size mandated by SPARC-V9 LP64 ABI (176 bytes).
pub const MIN_FRAME_SIZE_V9: usize = 176;

// ── Register window model ─────────────────────────────────────────────────────

/// SPARC integer register set from the perspective of a single window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowRegisters {
    /// Globals %g0–%g7 (shared across all windows; %g0 always reads 0).
    pub globals: [u64; 8],
    /// Out registers %o0–%o7 (become callee's %i0–%i7 after SAVE).
    pub out: [u64; 8],
    /// Local registers %l0–%l7 (private to this window).
    pub local: [u64; 8],
    /// In registers %i0–%i7 (caller's %o0–%o7; %i6=%fp, %i7=return address).
    pub r#in: [u64; 8],
}

impl WindowRegisters {
    /// Return the value of a register by hardware register number (0–31).
    #[must_use]
    pub const fn read(&self, reg: u32) -> u64 {
        match reg {
            1..=7 => self.globals[reg as usize],
            8..=15 => self.out[(reg - 8) as usize],
            16..=23 => self.local[(reg - 16) as usize],
            24..=31 => self.r#in[(reg - 24) as usize],
            _ => 0, // %g0 always 0; invalid registers return 0
        }
    }

    /// Write a register by hardware register number.
    pub const fn write(&mut self, reg: u32, val: u64) {
        match reg {
            1..=7 => self.globals[reg as usize] = val,
            8..=15 => self.out[(reg - 8) as usize] = val,
            16..=23 => self.local[(reg - 16) as usize] = val,
            24..=31 => self.r#in[(reg - 24) as usize] = val,
            _ => {} // %g0 and invalid registers ignore writes
        }
    }

    /// Stack pointer: %o6 (register 14).
    #[must_use]
    pub const fn sp(&self) -> u64 { self.out[6] }
    /// Frame pointer: %i6 (register 30).
    #[must_use]
    pub const fn fp(&self) -> u64 { self.r#in[6] }
    /// Return address: %i7 (register 31); actual return = %i7 + 8 (past delay slot).
    #[must_use]
    pub const fn return_addr(&self) -> u64 { self.r#in[7].wrapping_add(8) }
    /// Link register for calls: %o7 (register 15); CALL writes PC+4 here.
    #[must_use]
    pub const fn o7(&self) -> u64 { self.out[7] }
}

// ── Window stack simulator ─────────────────────────────────────────────────────

/// Simulated SPARC register-window stack for analysis.
///
/// Tracks the conceptual call depth and models register aliasing without
/// actually duplicating hardware circular-buffer semantics.
#[derive(Debug, Clone)]
pub struct WindowStack {
    /// Depth of the current call stack (number of `SAVE` calls without
    /// matching `RESTORE`).
    pub depth: usize,
    /// Per-frame snapshot of register windows (index 0 = outermost frame).
    pub frames: Vec<WindowRegisters>,
    /// Maximum window depth of the target implementation.
    pub nwindows: u8,
}

impl WindowStack {
    #[must_use]
    pub fn new(nwindows: u8) -> Self {
        Self {
            depth: 0,
            frames: vec![WindowRegisters::default()],
            nwindows,
        }
    }

    /// Execute a `SAVE` instruction: advance the window.
    ///
    /// The result of `SAVE %sp, -frame_size, %sp` is computed *before* the
    /// window rotate: `%sp_new = %o6_old + (-frame_size)`.
    pub fn save(&mut self, frame_size: i64) {
        let caller = self.frames.last().cloned().unwrap_or_default();
        // New SP = caller's %o6 + imm (already sign-extended).
        let new_sp = caller.out[6].cast_signed().wrapping_add(frame_size).cast_unsigned();
        // Caller's %o0–%o7 become callee's %i0–%i7.
        let mut out = [0u64; 8];
        out[6] = new_sp;
        let next_frame = WindowRegisters {
            globals: caller.globals,
            r#in: caller.out,
            out,
            local: [0u64; 8],
        };
        self.frames.push(next_frame);
        self.depth += 1;
    }

    /// Execute a `RESTORE` instruction.
    ///
    /// The result of `RESTORE %g0, %g0, %g0` is discarded (callee writes
    /// nothing to caller's registers via RESTORE in this model).
    pub fn restore(&mut self) -> Option<WindowRegisters> {
        if self.depth == 0 {
            return None;
        }
        let callee = self.frames.pop();
        self.depth -= 1;
        callee
    }

    /// Returns true if one more SAVE would trigger a window-overflow trap.
    #[must_use]
    pub const fn would_overflow(&self) -> bool {
        self.depth + 2 >= self.nwindows as usize
    }

    /// Current register window (mutable).
    ///
    /// # Panics
    ///
    /// Panics if the frame stack is empty (cannot happen in normal use).
    pub fn current_mut(&mut self) -> &mut WindowRegisters {
        self.frames.last_mut().expect("at least one frame")
    }

    /// Current register window (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the frame stack is empty (cannot happen in normal use).
    #[must_use]
    pub fn current(&self) -> &WindowRegisters {
        self.frames.last().expect("at least one frame")
    }
}

// ── ABI flavour ───────────────────────────────────────────────────────────────

/// SPARC ABI flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SparcAbi {
    /// 32-bit SPARC-V8 System V ABI.
    SysV32,
    /// 64-bit SPARC-V9 / `UltraSPARC` `LP64` ABI.
    SysV64,
    /// Solaris 2.x 32-bit ABI (minor differences from `SysV32`).
    Solaris32,
    /// Solaris 2.x 64-bit ABI.
    Solaris64,
    /// `VxWorks` SPARC (no stack bias, EABI-style).
    VxWorks,
    /// RTEMS SPARC embedded ABI.
    Rtems,
}

impl SparcAbi {
    /// Returns whether this ABI uses the 2047-byte stack bias.
    #[must_use]
    pub const fn uses_stack_bias(self) -> bool {
        matches!(self, Self::SysV64 | Self::Solaris64)
    }

    /// Returns the pointer size in bytes.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::SysV64 | Self::Solaris64 => 8,
            _ => 4,
        }
    }

    /// Returns the minimum stack frame size.
    #[must_use]
    pub const fn min_frame_size(self) -> usize {
        match self {
            Self::SysV64 | Self::Solaris64 => MIN_FRAME_SIZE_V9,
            _ => MIN_FRAME_SIZE_V8,
        }
    }

    /// Returns the register save area size (16 integer registers).
    #[must_use]
    pub const fn save_area_size(self) -> usize {
        match self {
            Self::SysV64 | Self::Solaris64 => SAVE_AREA_SIZE_V9,
            _ => SAVE_AREA_SIZE_V8,
        }
    }

    /// Number of integer argument registers.
    #[must_use]
    pub const fn int_arg_regs(self) -> usize {
        6 // %o0–%o5 in V8; %o0–%o5 in V9
    }

    /// Number of FP argument registers in V9 (V8 passes FP args in integer regs).
    #[must_use]
    pub const fn fp_arg_regs(self) -> usize {
        match self {
            Self::SysV64 | Self::Solaris64 => 16, // %f0–%f30 (singles), %d0–%d14 (doubles)
            _ => 0, // V8: FP args passed in %o regs or on stack
        }
    }
}

// ── Calling convention description ────────────────────────────────────────────

/// Description of a function's SPARC calling convention.
#[derive(Debug, Clone)]
pub struct SparcCallConv {
    pub abi: SparcAbi,
    /// True if this is a leaf function (no SAVE/RESTORE, uses %o regs directly).
    pub is_leaf: bool,
    /// True if the function returns a struct/union by hidden pointer in %o0.
    pub returns_struct: bool,
    /// Size of the returned struct/union in bytes (0 if not a struct return).
    pub struct_return_size: usize,
    /// Integer argument layout: (reg or stack offset, size).
    pub int_args: Vec<ArgLocation>,
    /// FP argument layout (V9 only).
    pub fp_args: Vec<ArgLocation>,
    /// Frame size allocated by SAVE instruction (0 for leaf functions).
    pub frame_size: usize,
}

/// Location of a single argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgLocation {
    /// Argument lives in a register (%o0–%o5 for int, %f0–%f30 for V9 FP).
    Register { reg: u32, size: usize },
    /// Argument is on the stack at the given positive offset from the caller's SP.
    Stack { offset: usize, size: usize },
    /// Argument is split between a register (high bytes) and the stack (low bytes).
    SplitRegStack { reg: u32, stack_offset: usize, size: usize },
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register { reg, size } => write!(f, "%o{reg}({size}B)"),
            Self::Stack { offset, size } => write!(f, "[sp+{offset}]({size}B)"),
            Self::SplitRegStack { reg, stack_offset, size } =>
                write!(f, "%o{reg}/[sp+{stack_offset}]({size}B)"),
        }
    }
}

impl SparcCallConv {
    /// Build a calling convention descriptor for a V8 function.
    ///
    /// `arg_sizes` is a slice of argument sizes in bytes (0 means unknown/void).
    #[must_use]
    pub fn for_v8(arg_sizes: &[usize], returns_struct: bool, struct_size: usize) -> Self {
        let mut int_args = Vec::new();
        let mut reg = 0usize; // %o0
        let mut stack_off: usize = 68; // First stack arg at [sp+68] in V8 ABI

        // Hidden struct-return pointer in %o0.
        let base_reg = if returns_struct {
            int_args.push(ArgLocation::Register { reg: 0, size: 4 });
            reg += 1;
            1
        } else {
            0
        };
        let _ = base_reg;

        for &sz in arg_sizes {
            let aligned_sz = sz.max(4); // Arguments are at least word-aligned
            if reg < 6 {
                if aligned_sz <= 4 {
                    int_args.push(ArgLocation::Register { reg: u32::try_from(reg).unwrap_or(u32::MAX), size: sz });
                    reg += 1;
                } else if aligned_sz <= 8 {
                    // Double-word arg: may need two registers or split.
                    if reg < 5 {
                        int_args.push(ArgLocation::Register { reg: u32::try_from(reg).unwrap_or(u32::MAX), size: sz });
                        reg += 2;
                    } else {
                        // Split: high in %o5, low on stack.
                        int_args.push(ArgLocation::SplitRegStack {
                            reg: u32::try_from(reg).unwrap_or(u32::MAX),
                            stack_offset: stack_off,
                            size: sz,
                        });
                        reg += 1;
                        stack_off += 4;
                    }
                } else {
                    // Large arg: passed by reference (pointer in register).
                    int_args.push(ArgLocation::Register { reg: u32::try_from(reg).unwrap_or(u32::MAX), size: 4 });
                    reg += 1;
                }
            } else {
                int_args.push(ArgLocation::Stack { offset: stack_off, size: sz });
                stack_off += aligned_sz;
            }
        }

        Self {
            abi: SparcAbi::SysV32,
            is_leaf: false,
            returns_struct,
            struct_return_size: struct_size,
            int_args,
            fp_args: vec![],
            frame_size: 0,
        }
    }

    /// Build a calling convention descriptor for a V9 LP64 function.
    #[must_use]
    pub fn for_v9(arg_sizes: &[usize], returns_struct: bool, struct_size: usize) -> Self {
        let mut int_args = Vec::new();
        let mut fp_args: Vec<ArgLocation> = Vec::new();
        let mut int_reg = 0usize; // %o0
        let mut fp_reg = 0usize;  // %f0 singles or %d0 doubles
        let mut stack_off: usize = 128 + 48; // V9: 128-byte save area + 6-slot spill area

        if returns_struct && struct_size > 32 {
            // Return by hidden pointer in %o0.
            int_args.push(ArgLocation::Register { reg: 0, size: 8 });
            int_reg += 1;
        }

        for &sz in arg_sizes {
            let is_fp = false; // Without type info, assume integer.
            let aligned_sz = sz.div_ceil(8) * 8;

            if is_fp && fp_reg < 16 {
                fp_args.push(ArgLocation::Register { reg: u32::try_from(fp_reg).unwrap_or(u32::MAX) * 2, size: sz });
                fp_reg += 1;
                // FP args also consume an integer slot in some cases.
            } else if int_reg < 6 {
                // An argument wider than a register is passed by reference, so
                // that slot always holds 8 bytes.
                let slot_size = if sz <= 8 { sz } else { 8 };
                int_args.push(ArgLocation::Register {
                    reg: u32::try_from(int_reg).unwrap_or(u32::MAX),
                    size: slot_size,
                });
                int_reg += 1;
            } else {
                int_args.push(ArgLocation::Stack { offset: stack_off, size: sz });
                stack_off += aligned_sz;
            }
        }

        Self {
            abi: SparcAbi::SysV64,
            is_leaf: false,
            returns_struct,
            struct_return_size: struct_size,
            int_args,
            fp_args,
            frame_size: 0,
        }
    }

    /// Return registers: %o0 (and %o1 for 64-bit return in V8 ABI).
    #[must_use]
    pub fn return_registers(&self) -> Vec<u32> {
        match self.abi {
            SparcAbi::SysV32 | SparcAbi::Solaris32 | SparcAbi::VxWorks | SparcAbi::Rtems => {
                vec![8, 9] // %o0, %o1
            }
            SparcAbi::SysV64 | SparcAbi::Solaris64 => {
                vec![8] // %o0 only (64-bit value)
            }
        }
    }

    /// Callee-saved registers (must be preserved across calls).
    ///
    /// On SPARC, `%l0-%l7` and `%i0-%i7` are *automatically* preserved by
    /// the window mechanism.  `%g2-%g4` are application globals (callee-saves
    /// in V9 Solaris); `%g5-%g7` are reserved for the system.
    #[must_use]
    pub fn callee_saved(&self) -> Vec<u32> {
        // Windows save %l and %i automatically.  Additional ABI callee-saves:
        match self.abi {
            SparcAbi::SysV64 | SparcAbi::Solaris64 => {
                // %g2, %g3, %g4 are application-global callee-saves in V9.
                vec![2, 3, 4]
            }
            _ => vec![],
        }
    }
}

// ── Leaf function analysis ─────────────────────────────────────────────────────

/// Result of leaf-function heuristic analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafClassification {
    /// Definite leaf: no SAVE/RESTORE, no CALL instruction seen.
    DefiniteLeaf,
    /// Definite non-leaf: SAVE/RESTORE found.
    NonLeaf,
    /// Tail-call leaf: SAVE seen but RESTORE replaced by `JMPL %o7+8, %g0`
    /// (tail call optimized return).
    TailCallLeaf,
    /// Uncertain: e.g., indirect calls only.
    Unknown,
}

/// Analyse a stream of raw SPARC words to determine leaf status.
///
/// A *leaf* function on SPARC does *not* execute `SAVE`; it uses `%o`
/// registers directly and returns via `RETL` (`JMPL %o7+8, %g0`).
#[must_use]
pub fn classify_leaf(words: &[u32]) -> LeafClassification {
    let mut has_save = false;
    let mut has_restore = false;
    let mut has_call = false;

    for &w in words {
        let op = w >> 30;
        let op3 = (w >> 19) & 0x3F;

        // CALL instruction (op = 01).
        if op == 0b01 {
            has_call = true;
        }

        if op == 0b10 {
            match op3 {
                0x3C => has_save = true,    // SAVE
                0x3D => has_restore = true, // RESTORE
                _ => {}
            }
        }

        // JMPL %o7+8, %g0 = RETL (leaf return).
        // op=10, op3=0x38 (JMPL), rs1=15 (%o7), rd=0, simm13=8.
        if op == 0b10 && op3 == 0x38 {
            let rd_field = (w >> 25) & 0x1F;
            let i = (w >> 13) & 1;
            let rs1_field = (w >> 14) & 0x1F;
            let simm = (w & 0x1FFF).cast_signed();
            let simm_sext = if simm & 0x1000 != 0 { simm | !0x1FFF } else { simm };
            if rd_field == 0 && i == 1 && rs1_field == 15 && simm_sext == 8 && !has_save {
                return LeafClassification::DefiniteLeaf;
            }
        }
    }

    if has_save && has_restore {
        LeafClassification::NonLeaf
    } else if has_save && !has_restore && !has_call {
        LeafClassification::TailCallLeaf
    } else if !has_save && !has_restore && !has_call {
        LeafClassification::DefiniteLeaf
    } else {
        LeafClassification::Unknown
    }
}

// ── Struct return analysis ─────────────────────────────────────────────────────

/// SPARC struct-return convention details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructReturn {
    /// Struct returned in registers (%o0, possibly %o1).
    InRegisters { size: usize },
    /// Struct returned via hidden pointer in %o0 (caller allocates space).
    ByHiddenPointer { size: usize },
    /// Small struct (≤ 4 bytes) returned in %o0.
    SmallInO0,
    /// No struct return — scalar return.
    Scalar,
}

/// Determine how a struct of the given size is returned under the given ABI.
#[must_use]
pub const fn struct_return_method(abi: SparcAbi, struct_size: usize) -> StructReturn {
    match abi {
        SparcAbi::SysV32 | SparcAbi::Solaris32 | SparcAbi::VxWorks | SparcAbi::Rtems => {
            if struct_size == 0 {
                StructReturn::Scalar
            } else if struct_size <= 4 {
                StructReturn::SmallInO0
            } else {
                // All structs > 4 bytes: caller provides buffer, address in %o0.
                StructReturn::ByHiddenPointer { size: struct_size }
            }
        }
        SparcAbi::SysV64 | SparcAbi::Solaris64 => {
            if struct_size == 0 {
                StructReturn::Scalar
            } else if struct_size <= 32 {
                // Small aggregates returned in %o0/%o1 or float regs.
                StructReturn::InRegisters { size: struct_size }
            } else {
                StructReturn::ByHiddenPointer { size: struct_size }
            }
        }
    }
}

// ── Varargs (va_list) on SPARC ────────────────────────────────────────────────

/// SPARC varargs layout — the fixed arguments were already placed in %o0–%o5.
///
/// The `va_list` on V8 is simply a pointer to the stack word after the last
/// named argument (or %o6+68 if all named args fit in registers).
#[derive(Debug, Clone)]
pub struct SparcVarargs {
    pub abi: SparcAbi,
    /// Number of named (fixed) arguments.
    pub named_count: usize,
    /// Offset in the stack save area where the first vararg lives.
    pub first_vararg_stack_offset: usize,
    /// Number of integer registers already consumed by named args.
    pub regs_consumed: usize,
}

impl SparcVarargs {
    #[must_use]
    pub fn new(abi: SparcAbi, named_count: usize) -> Self {
        let regs_consumed = named_count.min(6);
        // V8: stack save area for %o regs starts at sp+68.
        // V9: starts at sp+128 (top of register save area).
        let reg_save_start = match abi {
            SparcAbi::SysV64 | SparcAbi::Solaris64 => 128usize,
            _ => 68usize,
        };
        let ptr_size = if matches!(abi, SparcAbi::SysV64 | SparcAbi::Solaris64) { 8 } else { 4 };
        let first_vararg_stack_offset = reg_save_start + regs_consumed * ptr_size;

        Self {
            abi,
            named_count,
            first_vararg_stack_offset,
            regs_consumed,
        }
    }

    /// Number of integer registers still available for variadic arguments.
    #[must_use]
    pub const fn remaining_regs(&self) -> usize {
        6usize.saturating_sub(self.regs_consumed)
    }

    /// True if at least one variadic argument can still be placed in a register.
    #[must_use]
    pub const fn has_reg_varargs(&self) -> bool {
        self.remaining_regs() > 0
    }

    /// Stack offset of the Nth variadic argument (0-indexed).
    #[must_use]
    pub const fn nth_vararg_offset(&self, n: usize) -> usize {
        let ptr = if matches!(self.abi, SparcAbi::SysV64 | SparcAbi::Solaris64) { 8 } else { 4 };
        self.first_vararg_stack_offset + n * ptr
    }
}

// ── Call-site annotation ──────────────────────────────────────────────────────

/// Annotation for a SPARC CALL / JMPL site.
#[derive(Debug, Clone)]
pub struct CallSiteAnnotation {
    /// Address of the CALL or JMPL instruction.
    pub address: u64,
    /// Decoded callee address or register expression.
    pub target: CallTarget,
    /// Arguments visible at the call site.
    pub args: Vec<CallArg>,
    /// Whether the delay slot contains a useful instruction.
    pub delay_slot_useful: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    /// Direct call to an absolute address.
    Direct(u64),
    /// Indirect call via a register (%o7 = procedure linkage).
    Register(u32),
    /// Tail call (JMPL to %g1 or similar with rd=%g0).
    TailCall(u64),
}

#[derive(Debug, Clone)]
pub struct CallArg {
    pub reg: u32,    // %o0–%o5
    pub comment: String,
}

/// Heuristically reconstruct call-site argument list from a sequence of
/// instructions preceding a CALL.
///
/// Returns a `Vec<CallArg>` for registers %o0–%o5 that appear to be set.
#[must_use]
pub fn infer_call_args(instrs_before_call: &[u32]) -> Vec<CallArg> {
    // Track which %o registers were written before the call.
    let mut last_write: HashMap<u32, u32> = HashMap::new(); // reg -> word

    for &w in instrs_before_call {
        let op = w >> 30;
        if op != 0b10 { continue; }
        let rd_field = (w >> 25) & 0x1F;
        let op3 = (w >> 19) & 0x3F;

        // Instructions that write a destination register.
        let writes_rd = matches!(op3, 0x00..=0x07 | 0x09..=0x0F | 0x10..=0x1F
            | 0x20..=0x37 | 0x3A | 0x3B);

        if writes_rd && (8..=13).contains(&rd_field) {
            // Writing %o0–%o5.
            last_write.insert(rd_field - 8, w);
        }
    }

    (0u32..6)
        .filter_map(|n| {
            let word = *last_write.get(&n)?;
            let op3 = (word >> 19) & 0x3F;
            let comment = match op3 {
                0x00 => "ADD",
                0x02 => "OR (move-like)",
                0x04 => "SUB",
                0x10 => "ADDcc",
                _ => "set",
            }.to_string();
            Some(CallArg { reg: 8 + n, comment })
        })
        .collect()
}

// ── Frame layout display ──────────────────────────────────────────────────────

/// Human-readable SPARC stack frame diagram.
#[derive(Debug, Clone)]
pub struct FrameLayout {
    pub abi: SparcAbi,
    pub frame_size: usize,
    pub local_slots: Vec<(usize, String)>, // (sp-relative offset, name)
}

impl fmt::Display for FrameLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bias = if self.abi.uses_stack_bias() { usize::try_from(STACK_BIAS_V9).unwrap_or(usize::MAX) } else { 0 };
        writeln!(f, "SPARC stack frame ({} ABI, frame_size={}B):",
            if self.abi.uses_stack_bias() { "V9" } else { "V8" },
            self.frame_size)?;
        let save_sz = self.abi.save_area_size();
        writeln!(f, "  [sp+{bias}+0 .. sp+{bias}+{save_sz}]  register save area (%l0-%l7, %i0-%i7)")?;
        match self.abi {
            SparcAbi::SysV32 | SparcAbi::Solaris32 | SparcAbi::VxWorks | SparcAbi::Rtems => {
                writeln!(f, "  [sp+64]  struct-return address")?;
                writeln!(f, "  [sp+68 .. sp+92]  parameter dump (%o0-%o5)")?;
            }
            SparcAbi::SysV64 | SparcAbi::Solaris64 => {
                writeln!(f, "  [sp+{bias}+128 .. sp+{bias}+176]  outgoing parameter area")?;
            }
        }
        for (off, name) in &self.local_slots {
            writeln!(f, "  [sp+{bias}+{off}]  {name}")?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_registers_g0_always_zero() {
        let mut w = WindowRegisters::default();
        w.write(0, 0xDEAD_BEEF);
        assert_eq!(w.read(0), 0);
    }

    #[test]
    fn window_stack_save_restore() {
        let mut ws = WindowStack::new(8);
        ws.current_mut().out[0] = 42;
        ws.save(-96);
        // After SAVE, callee's %i0 = caller's %o0.
        assert_eq!(ws.current().r#in[0], 42);
        ws.restore();
        // Back to caller frame.
        assert_eq!(ws.current().out[0], 42);
    }

    #[test]
    fn leaf_classification_retl() {
        // RETL: JMPL %o7+8, %g0 = 0x81C3_E008
        let words = [0x81C3_E008_u32];
        assert_eq!(classify_leaf(&words), LeafClassification::DefiniteLeaf);
    }

    #[test]
    fn leaf_classification_non_leaf() {
        // SAVE = op=10, op3=0x3C => bits 31:30=10, 29:25=00000, 24:19=111100
        //  = 0b10_00000_111100_0...  = 0x9DE3_A000 (a common SAVE encoding)
        let words = [0x9DE3_A000_u32, 0x81E8_0000_u32]; // SAVE + RESTORE
        assert_eq!(classify_leaf(&words), LeafClassification::NonLeaf);
    }

    #[test]
    fn struct_return_v8_large() {
        let sr = struct_return_method(SparcAbi::SysV32, 16);
        assert!(matches!(sr, StructReturn::ByHiddenPointer { size: 16 }));
    }

    #[test]
    fn struct_return_v9_small() {
        let sr = struct_return_method(SparcAbi::SysV64, 16);
        assert!(matches!(sr, StructReturn::InRegisters { size: 16 }));
    }

    #[test]
    fn varargs_reg_count() {
        let va = SparcVarargs::new(SparcAbi::SysV32, 2);
        assert_eq!(va.remaining_regs(), 4);
        assert_eq!(va.first_vararg_stack_offset, 68 + 2 * 4);
    }

    #[test]
    fn v8_call_conv_six_args() {
        let cc = SparcCallConv::for_v8(&[4; 6], false, 0);
        assert_eq!(cc.int_args.len(), 6);
        assert!(cc.int_args.iter().all(|a| matches!(a, ArgLocation::Register { .. })));
    }

    #[test]
    fn v8_call_conv_seven_args() {
        let cc = SparcCallConv::for_v8(&[4; 7], false, 0);
        assert_eq!(cc.int_args.len(), 7);
        // 7th arg must be on the stack.
        assert!(matches!(cc.int_args[6], ArgLocation::Stack { .. }));
    }

    #[test]
    fn frame_layout_display_v8() {
        let fl = FrameLayout {
            abi: SparcAbi::SysV32,
            frame_size: 96,
            local_slots: vec![(92, "saved_reg".into())],
        };
        let s = fl.to_string();
        assert!(s.contains("register save area"));
        assert!(s.contains("parameter dump"));
    }
}
