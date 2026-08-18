//! SPARC v8/v9 function-level analysis — register windows, delay slots,
//! calling conventions, trap tables, and function profiling.

use ahash::{AHashMap, AHashSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparcAnalysisError {
    #[error("invalid instruction at 0x{0:08x}")]
    InvalidInstruction(u64),
    #[error("window overflow: depth {0} exceeds max {1}")]
    WindowOverflow(usize, usize),
    #[error("no function at address 0x{0:08x}")]
    NoFunction(u64),
    #[error("empty function body")]
    EmptyFunction,
    #[error("trap vector out of range: {0}")]
    TrapVectorOutOfRange(u8),
}

// ─── RegisterWindow ───────────────────────────────────────────────────────────

/// Number of hardware register window sets available on a SPARC CPU.
pub const MAX_REGISTER_WINDOWS: usize = 32;

/// A single SPARC register window snapshot.
/// SPARC uses overlapping windows: caller's %o regs become callee's %i regs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWindow {
    /// Call depth / Current Window Pointer value.
    pub cwp: u8,
    /// Local registers %l0–%l7.
    pub locals: [u64; 8],
    /// Input registers %i0–%i7 (caller's outputs).
    pub inputs: [u64; 8],
    /// Output registers %o0–%o7 (next callee's inputs).
    pub outputs: [u64; 8],
    /// Global registers %g0–%g7 (shared across windows).
    pub globals: [u64; 8],
    /// Saved program counter for this frame.
    pub saved_pc: u64,
}

impl RegisterWindow {
    /// Create a new empty window at the given CWP.
    #[must_use]
    pub const fn new(cwp: u8) -> Self {
        Self {
            cwp,
            locals: [0u64; 8],
            inputs: [0u64; 8],
            outputs: [0u64; 8],
            globals: [0u64; 8],
            saved_pc: 0,
        }
    }

    /// Return address stored in %i7 (input register 7).
    #[must_use]
    pub const fn return_address(&self) -> u64 {
        self.inputs[7].wrapping_add(8)
    }

    /// Stack pointer (%i6 / %fp as seen by callee).
    #[must_use]
    pub const fn frame_pointer(&self) -> u64 {
        self.inputs[6]
    }

    /// Stack pointer (%o6 / %sp as seen by current frame).
    #[must_use]
    pub const fn stack_pointer(&self) -> u64 {
        self.outputs[6]
    }

    /// Simulate SAVE: rotate window, copy outputs→inputs, reset locals.
    /// Returns the new CWP (wraps modulo `total_windows`).
    #[must_use]
    pub fn save(&self, total_windows: usize) -> Self {
        let new_cwp = u8::try_from((self.cwp as usize + total_windows - 1) % total_windows).unwrap_or(u8::MAX);
        let mut next = Self::new(new_cwp);
        // Current outputs become new inputs.
        next.inputs = self.outputs;
        next.globals = self.globals;
        next
    }

    /// Simulate RESTORE: rotate window back.
    #[must_use]
    pub fn restore(&self, total_windows: usize) -> Self {
        let new_cwp = (self.cwp as usize + 1) % total_windows;
        let mut prev = Self::new(u8::try_from(new_cwp).unwrap_or(u8::MAX));
        prev.globals = self.globals;
        prev
    }
}

// ─── RegisterWindowStack ──────────────────────────────────────────────────────

/// Tracks the full SPARC register window stack during emulated execution.
#[derive(Debug, Clone)]
pub struct RegisterWindowStack {
    windows: Vec<RegisterWindow>,
    current: usize,
    total: usize,
}

impl RegisterWindowStack {
    /// Create a new stack with `total` available window sets.
    ///
    /// # Panics
    ///
    /// Panics if `total` is 0 or exceeds [`MAX_REGISTER_WINDOWS`].
    #[must_use]
    pub fn new(total: usize) -> Self {
        assert!(total > 0 && total <= MAX_REGISTER_WINDOWS);
        let windows = (0..total).map(|i| RegisterWindow::new(u8::try_from(i).unwrap_or(u8::MAX))).collect();
        Self {
            windows,
            current: 0,
            total,
        }
    }

    /// Push a new window (SAVE instruction).
    ///
    /// # Errors
    ///
    /// Returns [`SparcAnalysisError::WindowOverflow`] if the window stack is full.
    pub fn push(&mut self) -> Result<(), SparcAnalysisError> {
        if self.depth() >= self.total {
            return Err(SparcAnalysisError::WindowOverflow(self.depth(), self.total));
        }
        let new_win = self.windows[self.current].save(self.total);
        self.current = new_win.cwp as usize;
        self.windows[self.current] = new_win;
        Ok(())
    }

    /// Pop window (RESTORE instruction).
    ///
    /// # Errors
    ///
    /// This function currently always returns `Ok(())`.
    pub fn pop(&mut self) -> Result<(), SparcAnalysisError> {
        let restored = self.windows[self.current].restore(self.total);
        self.current = restored.cwp as usize;
        Ok(())
    }

    /// Current window depth (call nesting level).
    #[must_use]
    pub fn depth(&self) -> usize {
        // Approximate: count non-zero saved PCs.
        self.windows.iter().filter(|w| w.saved_pc != 0).count()
    }

    /// Reference to current window.
    #[must_use]
    pub fn current_window(&self) -> &RegisterWindow {
        &self.windows[self.current]
    }

    /// Mutable reference to current window.
    pub fn current_window_mut(&mut self) -> &mut RegisterWindow {
        &mut self.windows[self.current]
    }
}

// ─── DelaySlot ────────────────────────────────────────────────────────────────

/// Categorizes how a SPARC delay slot instruction should be treated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelaySlotKind {
    /// Normal delay slot — always executed.
    Normal,
    /// Annulled delay slot (`,a` branches) — only executed if branch taken.
    Annulled,
    /// Filled delay slot — contains a useful moved instruction.
    Filled,
    /// Empty delay slot — contains a NOP.
    Empty,
}

/// A SPARC delay slot descriptor attached to a branch/call/return.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelaySlot {
    /// Address of the branch instruction.
    pub branch_addr: u64,
    /// Address of the delay slot instruction.
    pub slot_addr: u64,
    /// Kind of delay slot.
    pub kind: DelaySlotKind,
    /// Mnemonic of the delay slot instruction (e.g. "NOP", "MOV", …).
    pub slot_mnemonic: String,
    /// Whether the branch was taken in the analyzed trace (if known).
    pub branch_taken: Option<bool>,
}

impl DelaySlot {
    /// Create a new delay slot descriptor.
    #[must_use]
    pub fn new(branch_addr: u64, slot_mnemonic: impl Into<String>) -> Self {
        let slot_addr = branch_addr.wrapping_add(4);
        let mn = slot_mnemonic.into();
        let kind = if mn == "NOP" {
            DelaySlotKind::Empty
        } else {
            DelaySlotKind::Normal
        };
        Self {
            branch_addr,
            slot_addr,
            kind,
            slot_mnemonic: mn,
            branch_taken: None,
        }
    }

    /// Mark this delay slot as annulled (`,a` branch).
    #[must_use]
    pub const fn annulled(mut self) -> Self {
        self.kind = DelaySlotKind::Annulled;
        self
    }

    /// Mark this delay slot as filled (contains a real instruction).
    #[must_use]
    pub fn filled(mut self) -> Self {
        if self.kind != DelaySlotKind::Empty {
            self.kind = DelaySlotKind::Filled;
        }
        self
    }
}

// ─── SparcCallingConv ─────────────────────────────────────────────────────────

/// SPARC calling convention variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SparcCallingConvKind {
    /// `SysV` ABI for 32-bit SPARC.
    SysV32,
    /// `SysV` ABI for 64-bit SPARC (`v9`/`LP64`).
    SysV64,
    /// Sun Studio / Solaris 32-bit ABI.
    SunStudio32,
    /// SPARC Linux kernel internal calling convention.
    LinuxKernel,
}

/// Full description of a SPARC calling convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcCallingConv {
    pub kind: SparcCallingConvKind,
    /// Register names used for integer arguments in order.
    pub int_arg_regs: Vec<String>,
    /// Register names used for floating-point arguments.
    pub fp_arg_regs: Vec<String>,
    /// Register(s) used for return values.
    pub return_regs: Vec<String>,
    /// Caller-saved registers.
    pub caller_saved: Vec<String>,
    /// Callee-saved registers.
    pub callee_saved: Vec<String>,
    /// Stack grows downward; minimum alignment in bytes.
    pub stack_alignment: usize,
    /// Minimum stack frame size (SPARC has a mandatory register-save area).
    pub min_frame_size: usize,
}

impl SparcCallingConv {
    /// SPARC `SysV` 32-bit ABI.
    #[must_use]
    pub fn sysv32() -> Self {
        Self {
            kind: SparcCallingConvKind::SysV32,
            int_arg_regs: (0..6).map(|i| format!("%o{i}")).collect(),
            fp_arg_regs: vec![],
            return_regs: vec!["%o0".into(), "%o1".into()],
            caller_saved: (0..8).map(|i| format!("%o{i}")).collect(),
            callee_saved: (0..8)
                .map(|i| format!("%l{i}"))
                .chain((0..8).map(|i| format!("%i{i}")))
                .collect(),
            stack_alignment: 8,
            min_frame_size: 96, // register-save area
        }
    }

    /// SPARC `SysV` 64-bit (`v9`) ABI.
    #[must_use]
    pub fn sysv64() -> Self {
        Self {
            kind: SparcCallingConvKind::SysV64,
            int_arg_regs: (0..6).map(|i| format!("%o{i}")).collect(),
            fp_arg_regs: (0..16).map(|i| format!("%f{}", i * 2)).collect(),
            return_regs: vec!["%o0".into()],
            caller_saved: (0..8).map(|i| format!("%o{i}")).collect(),
            callee_saved: (0..8)
                .map(|i| format!("%l{i}"))
                .chain((0..8).map(|i| format!("%i{i}")))
                .collect(),
            stack_alignment: 16,
            min_frame_size: 176, // SPARC v9 ABI-specified minimum
        }
    }

    /// Number of registers used for passing integer arguments.
    #[must_use]
    pub const fn int_arg_count(&self) -> usize {
        self.int_arg_regs.len()
    }

    /// Whether a given register name is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg)
    }
}

// ─── TrapTable ────────────────────────────────────────────────────────────────

/// A single entry in the SPARC trap table (TT).
///
/// `name` is owned (`String`) so that deserialization of attacker-supplied
/// data does not permanently leak memory via `Box::leak` (lifetime-escape /
/// memory-exhaustion fix: the previous `&'static str` field required leaking
/// every deserialized name string onto the heap forever).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapEntry {
    /// Trap type number (0x00–0xFF for hardware, 0x80–0xFF for software).
    pub tt: u8,
    /// Human-readable name.
    pub name: String,
    /// Handler address (if resolved).
    pub handler_addr: Option<u64>,
    /// Is this a software trap (Tcc instruction)?
    pub is_software: bool,
}

/// Full SPARC trap table, holding up to 256 entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrapTable {
    pub entries: BTreeMap<u8, TrapEntry>,
    /// Base address of the hardware trap table (TBR register).
    pub tbr_base: u64,
}

impl TrapTable {
    /// Populate default SPARC v8 trap vectors.
    #[must_use]
    pub fn sparc_v8_defaults() -> Self {
        let mut t = Self::default();
        let vectors: &[(u8, &str, bool)] = &[
            (0x00, "reset", false),
            (0x01, "instruction_access_exception", false),
            (0x02, "illegal_instruction", false),
            (0x03, "privileged_instruction", false),
            (0x04, "fp_disabled", false),
            (0x05, "window_overflow", false),
            (0x06, "window_underflow", false),
            (0x07, "mem_address_not_aligned", false),
            (0x08, "fp_exception", false),
            (0x09, "data_access_exception", false),
            (0x0A, "tag_overflow", false),
            (0x0B, "watchpoint_detected", false),
            (0x10, "interrupt_level_1", false),
            (0x11, "interrupt_level_2", false),
            (0x12, "interrupt_level_3", false),
            (0x13, "interrupt_level_4", false),
            (0x14, "interrupt_level_5", false),
            (0x15, "interrupt_level_6", false),
            (0x16, "interrupt_level_7", false),
            (0x17, "interrupt_level_8", false),
            (0x18, "interrupt_level_9", false),
            (0x19, "interrupt_level_10", false),
            (0x1A, "interrupt_level_11", false),
            (0x1B, "interrupt_level_12", false),
            (0x1C, "interrupt_level_13", false),
            (0x1D, "interrupt_level_14", false),
            (0x1E, "interrupt_level_15", false),
            (0x20, "register_access_error", false),
            (0x21, "instruction_access_error", false),
            (0x24, "cp_disabled", false),
            (0x25, "unimplemented_flush", false),
            (0x26, "cp_exception", false),
            (0x27, "data_access_error", false),
            (0x28, "division_by_zero", false),
            (0x29, "data_store_error", false),
            (0x2A, "data_access_mmu_miss", false),
            (0x3C, "instruction_access_mmu_miss", false),
            // Software traps
            (0x80, "syscall", true),
            (0x81, "breakpoint", true),
            (0x82, "division_by_zero_sw", true),
            (0x83, "flush_windows", true),
            (0x84, "clean_windows", true),
            (0x85, "range_check", true),
            (0x86, "fix_alignment", true),
            (0x87, "integer_overflow", true),
            (0x88, "syscall_9x", true),
        ];
        for &(tt, name, sw) in vectors {
            t.entries.insert(
                tt,
                TrapEntry {
                    tt,
                    name: name.to_string(),
                    handler_addr: None,
                    is_software: sw,
                },
            );
        }
        t
    }

    /// Resolve handler address for trap type.
    ///
    /// # Errors
    ///
    /// Returns [`SparcAnalysisError::TrapVectorOutOfRange`] if `tt` is not in the table.
    pub fn set_handler(&mut self, tt: u8, addr: u64) -> Result<(), SparcAnalysisError> {
        self.entries
            .get_mut(&tt)
            .map(|e| e.handler_addr = Some(addr))
            .ok_or(SparcAnalysisError::TrapVectorOutOfRange(tt))
    }

    /// Lookup entry by trap type.
    #[must_use]
    pub fn lookup(&self, tt: u8) -> Option<&TrapEntry> {
        self.entries.get(&tt)
    }

    /// All software trap entries.
    #[must_use]
    pub fn software_traps(&self) -> Vec<&TrapEntry> {
        self.entries.values().filter(|e| e.is_software).collect()
    }

    /// Hardware interrupt entries (TT 0x10–0x1F).
    #[must_use]
    pub fn interrupt_vectors(&self) -> Vec<&TrapEntry> {
        self.entries
            .values()
            .filter(|e| (0x10..=0x1F).contains(&e.tt))
            .collect()
    }
}

// ─── SparcFunctionProfiler ────────────────────────────────────────────────────

/// Per-instruction statistics for SPARC function profiling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SparcInstrStats {
    pub alu_count: u32,
    pub load_count: u32,
    pub store_count: u32,
    pub branch_count: u32,
    pub call_count: u32,
    pub fp_count: u32,
    pub window_ops: u32,
    pub delay_slots: u32,
    pub filled_slots: u32,
    pub empty_slots: u32,
    pub trap_count: u32,
    pub total: u32,
    /// Count of control-transfer instructions that immediately follow another
    /// control-transfer (a SPARC delay-slot hazard).
    pub branch_in_delay_slot: u32,
}

impl SparcInstrStats {
    /// Percentage of instructions that are load/store.
    #[must_use]
    pub fn memory_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        f64::from(self.load_count + self.store_count) / f64::from(self.total)
    }

    /// Percentage of instructions that are branches.
    #[must_use]
    pub fn branch_ratio(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        f64::from(self.branch_count) / f64::from(self.total)
    }

    /// Delay slot fill ratio (filled / total delay slots).
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        if self.delay_slots == 0 {
            return 0.0;
        }
        f64::from(self.filled_slots) / f64::from(self.delay_slots)
    }
}

/// A decoded function entry for the profiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcFunctionEntry {
    pub start_addr: u64,
    pub end_addr: u64,
    pub name: Option<String>,
    pub stats: SparcInstrStats,
    pub delay_slots: Vec<DelaySlot>,
    pub window_depth: usize,
    /// Detected calling convention.
    pub calling_conv: Option<SparcCallingConvKind>,
}

/// Profiles SPARC functions from a flat byte slice.
#[derive(Debug, Default)]
pub struct SparcFunctionProfiler {
    /// Keyed by function start address; uses ahash to resist hash-collision `DoS`
    /// attacks where the adversary controls function start addresses in the binary.
    functions: AHashMap<u64, SparcFunctionEntry>,
}

impl SparcFunctionProfiler {
    /// Create a new profiler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Profile a function starting at `start_addr` using the provided
    /// pre-decoded `(addr, mnemonic, flags)` tuples.
    ///
    /// `flags` bit meanings: `0x01`=branch `0x02`=call `0x04`=ret `0x08`=`read_mem`
    ///                       `0x10`=`write_mem` `0x20`=fp `0x40`=barrier
    ///
    /// # Errors
    ///
    /// Returns [`SparcAnalysisError::EmptyFunction`] if `instructions` is empty.
    pub fn profile_function(
        &mut self,
        start_addr: u64,
        instructions: &[(u64, String, u32)],
    ) -> Result<u64, SparcAnalysisError> {
        if instructions.is_empty() {
            return Err(SparcAnalysisError::EmptyFunction);
        }
        let mut stats = SparcInstrStats::default();
        let mut delay_slots: Vec<DelaySlot> = Vec::new();
        let mut window_depth: usize = 0;
        let mut in_delay_slot = false;

        let mut prev_branch = false;
        let mut prev_addr = 0u64;
        let mut prev_mn = String::new();

        for &(addr, ref mn, flags) in instructions {
            stats.total += 1;
            if in_delay_slot {
                // Classify the delay slot instruction.
                let mut ds = DelaySlot::new(prev_addr, &prev_mn);
                if mn == "NOP" {
                    stats.empty_slots += 1;
                } else {
                    ds = ds.filled();
                    stats.filled_slots += 1;
                }
                delay_slots.push(ds);
                in_delay_slot = false;
            }
            let is_branch = flags & 0x01 != 0;
            let is_call = flags & 0x02 != 0;
            let is_ret = flags & 0x04 != 0;
            let is_load = flags & 0x08 != 0;
            let is_store = flags & 0x10 != 0;
            let is_fp = flags & 0x20 != 0;

            if is_branch {
                stats.branch_count += 1;
            }
            if is_call {
                stats.call_count += 1;
            }
            if is_load {
                stats.load_count += 1;
            }
            if is_store {
                stats.store_count += 1;
            }
            if is_fp {
                stats.fp_count += 1;
            }

            // Two control-transfer instructions in a row (without the in-between
            // delay slot having absorbed the prior branch) is a SPARC hazard:
            // the second branch would be evaluated inside the first one's
            // delay slot, which architectures forbid or treat unpredictably.
            if prev_branch && (is_branch || is_call || is_ret) {
                stats.branch_in_delay_slot += 1;
            }

            match mn.as_str() {
                "SAVE" => {
                    stats.window_ops += 1;
                    window_depth += 1;
                }
                "RESTORE" => {
                    stats.window_ops += 1;
                    window_depth = window_depth.saturating_sub(1);
                }
                "T" | "TA" | "TE" | "TNE" => {
                    stats.trap_count += 1;
                }
                _ if is_branch || is_call || is_ret => {
                    stats.delay_slots += 1;
                    in_delay_slot = true;
                }
                _ => {
                    stats.alu_count += 1;
                }
            }
            prev_branch = is_branch || is_call || is_ret;
            prev_addr = addr;
            prev_mn.clone_from(mn);
        }

        let end_addr = instructions.last().map_or(start_addr, |e| e.0 + 4);
        // Detect calling convention heuristically.
        let calling_conv = if stats.window_ops > 0 {
            Some(SparcCallingConvKind::SysV32)
        } else {
            None
        };

        let entry = SparcFunctionEntry {
            start_addr,
            end_addr,
            name: None,
            stats,
            delay_slots,
            window_depth,
            calling_conv,
        };
        self.functions.insert(start_addr, entry);
        Ok(end_addr)
    }

    /// Retrieve a profiled function entry.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&SparcFunctionEntry> {
        self.functions.get(&addr)
    }

    /// All profiled functions.
    #[must_use]
    pub fn all_functions(&self) -> Vec<&SparcFunctionEntry> {
        let mut v: Vec<_> = self.functions.values().collect();
        v.sort_by_key(|f| f.start_addr);
        v
    }

    /// Functions with window-management operations (likely leaf-opt or windowed).
    #[must_use]
    pub fn windowed_functions(&self) -> Vec<&SparcFunctionEntry> {
        self.functions
            .values()
            .filter(|f| f.stats.window_ops > 0)
            .collect()
    }

    /// Functions with un-filled delay slots (optimisation opportunities).
    #[must_use]
    pub fn unfilled_delay_slot_functions(&self) -> Vec<&SparcFunctionEntry> {
        self.functions
            .values()
            .filter(|f| f.stats.empty_slots > 0)
            .collect()
    }

    /// Distinct mnemonics observed in the delay slot of any profiled function.
    #[must_use]
    pub fn delay_slot_mnemonics(&self) -> AHashSet<String> {
        self.functions
            .values()
            .flat_map(|f| f.delay_slots.iter().map(|d| d.slot_mnemonic.clone()))
            .collect()
    }
}

// ─── SparcAnalysis ─────────────────────────────────────────────────────────────

/// Top-level SPARC analysis object, tying together all sub-analyses.
#[derive(Debug)]
pub struct SparcAnalysis {
    pub window_stack: RegisterWindowStack,
    pub trap_table: TrapTable,
    pub profiler: SparcFunctionProfiler,
    pub calling_conv: SparcCallingConv,
    pub delay_slots: Vec<DelaySlot>,
}

impl SparcAnalysis {
    /// Create a new analysis context for SPARC v8.
    #[must_use]
    pub fn new_v8() -> Self {
        Self {
            window_stack: RegisterWindowStack::new(8),
            trap_table: TrapTable::sparc_v8_defaults(),
            profiler: SparcFunctionProfiler::new(),
            calling_conv: SparcCallingConv::sysv32(),
            delay_slots: Vec::new(),
        }
    }

    /// Create a new analysis context for SPARC v9.
    #[must_use]
    pub fn new_v9() -> Self {
        Self {
            window_stack: RegisterWindowStack::new(8),
            trap_table: TrapTable::sparc_v8_defaults(),
            profiler: SparcFunctionProfiler::new(),
            calling_conv: SparcCallingConv::sysv64(),
            delay_slots: Vec::new(),
        }
    }

    /// Record a delay slot found during analysis.
    pub fn record_delay_slot(&mut self, ds: DelaySlot) {
        self.delay_slots.push(ds);
    }

    /// Summary of all delay slot efficiency across analyzed functions.
    #[must_use]
    pub fn overall_fill_ratio(&self) -> f64 {
        let total: u32 = self
            .profiler
            .all_functions()
            .iter()
            .map(|f| f.stats.delay_slots)
            .sum();
        let filled: u32 = self
            .profiler
            .all_functions()
            .iter()
            .map(|f| f.stats.filled_slots)
            .sum();
        if total == 0 {
            0.0
        } else {
            f64::from(filled) / f64::from(total)
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RegisterWindow ──────────────────────────────────────────────────────

    #[test]
    fn test_window_new_defaults_to_zero() {
        let w = RegisterWindow::new(0);
        assert_eq!(w.locals, [0u64; 8]);
        assert_eq!(w.inputs, [0u64; 8]);
        assert_eq!(w.outputs, [0u64; 8]);
    }

    #[test]
    fn test_window_return_address_adds_8() {
        let mut w = RegisterWindow::new(0);
        w.inputs[7] = 0x1000;
        assert_eq!(w.return_address(), 0x1008);
    }

    #[test]
    fn test_window_frame_pointer() {
        let mut w = RegisterWindow::new(0);
        w.inputs[6] = 0xDEAD_0000;
        assert_eq!(w.frame_pointer(), 0xDEAD_0000);
    }

    #[test]
    fn test_window_stack_pointer() {
        let mut w = RegisterWindow::new(0);
        w.outputs[6] = 0xBEEF_0000;
        assert_eq!(w.stack_pointer(), 0xBEEF_0000);
    }

    #[test]
    fn test_window_save_copies_outputs_to_inputs() {
        let mut w = RegisterWindow::new(3);
        w.outputs[0] = 42;
        let next = w.save(8);
        assert_eq!(next.inputs[0], 42);
    }

    #[test]
    fn test_window_save_decrements_cwp_mod_total() {
        let w = RegisterWindow::new(0);
        let next = w.save(8);
        assert_eq!(next.cwp, 7); // 0 - 1 mod 8 = 7
    }

    #[test]
    fn test_window_restore_increments_cwp() {
        let w = RegisterWindow::new(3);
        let prev = w.restore(8);
        assert_eq!(prev.cwp, 4);
    }

    // ── RegisterWindowStack ─────────────────────────────────────────────────

    #[test]
    fn test_stack_push_pop() {
        let mut stack = RegisterWindowStack::new(8);
        stack.push().unwrap();
        assert_eq!(stack.current_window().cwp, 7);
        stack.pop().unwrap();
    }

    #[test]
    fn test_stack_overflow() {
        let mut stack = RegisterWindowStack::new(2);
        // depth starts at 0, we can do only 2 pushes
        stack.current_window_mut().saved_pc = 1;
        stack.push().unwrap();
        stack.current_window_mut().saved_pc = 1;
        // 3rd push should overflow
        let result = stack.push();
        assert!(result.is_err());
    }

    // ── DelaySlot ───────────────────────────────────────────────────────────

    #[test]
    fn test_delay_slot_nop_is_empty() {
        let ds = DelaySlot::new(0x1000, "NOP");
        assert_eq!(ds.kind, DelaySlotKind::Empty);
        assert_eq!(ds.slot_addr, 0x1004);
    }

    #[test]
    fn test_delay_slot_non_nop_is_normal() {
        let ds = DelaySlot::new(0x1000, "OR");
        assert_eq!(ds.kind, DelaySlotKind::Normal);
    }

    #[test]
    fn test_delay_slot_filled() {
        let ds = DelaySlot::new(0x1000, "ADD").filled();
        assert_eq!(ds.kind, DelaySlotKind::Filled);
    }

    #[test]
    fn test_delay_slot_annulled() {
        let ds = DelaySlot::new(0x1000, "NOP").annulled();
        // annulled overrides even for NOP
        assert_eq!(ds.kind, DelaySlotKind::Annulled);
    }

    // ── SparcCallingConv ────────────────────────────────────────────────────

    #[test]
    fn test_sysv32_has_6_int_args() {
        let cc = SparcCallingConv::sysv32();
        assert_eq!(cc.int_arg_count(), 6);
    }

    #[test]
    fn test_sysv64_has_fp_args() {
        let cc = SparcCallingConv::sysv64();
        assert!(!cc.fp_arg_regs.is_empty());
    }

    #[test]
    fn test_callee_saved_detection() {
        let cc = SparcCallingConv::sysv32();
        assert!(cc.is_callee_saved("%l0"));
        assert!(cc.is_callee_saved("%i0"));
        assert!(!cc.is_callee_saved("%o0"));
    }

    #[test]
    fn test_sysv32_stack_alignment() {
        let cc = SparcCallingConv::sysv32();
        assert_eq!(cc.stack_alignment, 8);
        assert_eq!(cc.min_frame_size, 96);
    }

    #[test]
    fn test_sysv64_stack_alignment() {
        let cc = SparcCallingConv::sysv64();
        assert_eq!(cc.stack_alignment, 16);
        assert_eq!(cc.min_frame_size, 176);
    }

    // ── TrapTable ───────────────────────────────────────────────────────────

    #[test]
    fn test_trap_table_defaults_populated() {
        let t = TrapTable::sparc_v8_defaults();
        assert!(t.entries.len() >= 30);
    }

    #[test]
    fn test_trap_lookup_reset() {
        let t = TrapTable::sparc_v8_defaults();
        let e = t.lookup(0x00).unwrap();
        assert_eq!(e.name, "reset");
        assert!(!e.is_software);
    }

    #[test]
    fn test_trap_lookup_syscall() {
        let t = TrapTable::sparc_v8_defaults();
        let e = t.lookup(0x80).unwrap();
        assert!(e.is_software);
    }

    #[test]
    fn test_trap_set_handler() {
        let mut t = TrapTable::sparc_v8_defaults();
        t.set_handler(0x00, 0xFFFF_0000).unwrap();
        assert_eq!(t.lookup(0x00).unwrap().handler_addr, Some(0xFFFF_0000));
    }

    #[test]
    fn test_trap_set_handler_unknown_fails() {
        let mut t = TrapTable::sparc_v8_defaults();
        assert!(t.set_handler(0xFF, 0x1234).is_err());
    }

    #[test]
    fn test_software_traps_list() {
        let t = TrapTable::sparc_v8_defaults();
        let sw = t.software_traps();
        assert!(!sw.is_empty());
        for e in &sw {
            assert!(e.is_software);
        }
    }

    #[test]
    fn test_interrupt_vectors_range() {
        let t = TrapTable::sparc_v8_defaults();
        let iv = t.interrupt_vectors();
        assert!(!iv.is_empty());
        for e in &iv {
            assert!((0x10..=0x1F).contains(&e.tt));
        }
    }

    // ── SparcFunctionProfiler ───────────────────────────────────────────────

    fn make_instrs(seq: &[(&str, u32)]) -> Vec<(u64, String, u32)> {
        seq.iter()
            .enumerate()
            .map(|(i, (mn, flags))| ((0x1000 + i * 4) as u64, mn.to_string(), *flags))
            .collect()
    }

    #[test]
    fn test_profiler_basic() {
        let mut p = SparcFunctionProfiler::new();
        let instrs = make_instrs(&[
            ("ADD", 0),
            ("LD", 0x08),
            ("BA", 0x01),
            ("NOP", 0),
            ("RETURN", 0x04),
            ("NOP", 0),
        ]);
        p.profile_function(0x1000, &instrs).unwrap();
        let f = p.get(0x1000).unwrap();
        assert!(f.stats.branch_count > 0);
        assert!(f.stats.load_count > 0);
    }

    #[test]
    fn test_profiler_window_ops() {
        let mut p = SparcFunctionProfiler::new();
        let instrs = make_instrs(&[("SAVE", 0), ("ADD", 0), ("RESTORE", 0)]);
        p.profile_function(0x1000, &instrs).unwrap();
        let f = p.get(0x1000).unwrap();
        assert_eq!(f.stats.window_ops, 2);
        assert_eq!(f.calling_conv, Some(SparcCallingConvKind::SysV32));
    }

    #[test]
    fn test_profiler_delay_slot_counting() {
        let mut p = SparcFunctionProfiler::new();
        let instrs = make_instrs(&[
            ("CALL", 0x02),
            ("ADD", 0), // filled delay slot
            ("CALL", 0x02),
            ("NOP", 0), // empty delay slot
        ]);
        p.profile_function(0x1000, &instrs).unwrap();
        let f = p.get(0x1000).unwrap();
        assert_eq!(f.stats.delay_slots, 2);
        assert_eq!(f.stats.filled_slots, 1);
        assert_eq!(f.stats.empty_slots, 1);
    }

    #[test]
    fn test_profiler_fill_ratio() {
        let mut p = SparcFunctionProfiler::new();
        let instrs = make_instrs(&[
            ("CALL", 0x02),
            ("ADD", 0), // filled
            ("BA", 0x01),
            ("NOP", 0), // empty
        ]);
        p.profile_function(0x1000, &instrs).unwrap();
        let f = p.get(0x1000).unwrap();
        // 1 filled out of 2 total = 0.5
        assert!((f.stats.fill_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_profiler_empty_function_error() {
        let mut p = SparcFunctionProfiler::new();
        let result = p.profile_function(0x1000, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_profiler_windowed_functions() {
        let mut p = SparcFunctionProfiler::new();
        let with_win = make_instrs(&[("SAVE", 0), ("RESTORE", 0)]);
        let no_win = make_instrs(&[("ADD", 0), ("SUB", 0)]);
        p.profile_function(0x1000, &with_win).unwrap();
        p.profile_function(0x2000, &no_win).unwrap();
        let wf = p.windowed_functions();
        assert_eq!(wf.len(), 1);
        assert_eq!(wf[0].start_addr, 0x1000);
    }

    // ── SparcAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn test_analysis_new_v8() {
        let a = SparcAnalysis::new_v8();
        assert_eq!(a.calling_conv.kind, SparcCallingConvKind::SysV32);
    }

    #[test]
    fn test_analysis_new_v9() {
        let a = SparcAnalysis::new_v9();
        assert_eq!(a.calling_conv.kind, SparcCallingConvKind::SysV64);
    }

    #[test]
    fn test_analysis_record_delay_slot() {
        let mut a = SparcAnalysis::new_v8();
        a.record_delay_slot(DelaySlot::new(0x1000, "NOP"));
        assert_eq!(a.delay_slots.len(), 1);
    }

    #[test]
    fn test_overall_fill_ratio_empty() {
        let a = SparcAnalysis::new_v8();
        assert!((a.overall_fill_ratio() - 0.0_f64).abs() < f64::EPSILON);
    }
}
