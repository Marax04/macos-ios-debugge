//! `sparc_register_windows` — SPARC register window analysis.
//!
//! SPARC implements a register-file divided into overlapping "windows".  Each
//! `SAVE` instruction shifts the current window pointer (CWP) down by one,
//! making the caller's `%o` registers become the callee's `%i` registers.
//! `RESTORE` shifts CWP back up.  This module provides structures and analysis
//! helpers for understanding register-window usage in disassembled SPARC code.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Number of register windows in SPARC v8 (implementation-defined 2–32; 8 is typical).
pub const NWINDOWS_DEFAULT: u8 = 8;

/// Number of windowed general-purpose registers per window.
pub const WINDOW_REGS: usize = 16; // 8 local + 8 output = 8 input of the next

/// Total physical registers = NWINDOWS × 16 + 8 (global).
#[must_use]
pub const fn total_physical_regs(nwindows: u8) -> usize {
    (nwindows as usize) * WINDOW_REGS + 8
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterClass
// ─────────────────────────────────────────────────────────────────────────────

/// The class of a SPARC logical register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterClass {
    Global,
    Out,
    Local,
    In,
    /// Floating-point.
    Float,
    /// Special (PSR, WIM, TBR, PC, nPC, Y).
    Special,
}

impl RegisterClass {
    /// Return the architectural prefix (`%g`, `%o`, `%l`, `%i`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Global => "%g",
            Self::Out => "%o",
            Self::Local => "%l",
            Self::In => "%i",
            Self::Float => "%f",
            Self::Special => "%s",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SparcReg — logical register descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A logical SPARC register.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SparcReg {
    pub class: RegisterClass,
    pub number: u8,
}

impl SparcReg {
    /// Parse a register name string (e.g. `"%i0"`, `"%o7"`, `"%g1"`).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('%');
        // Use char_indices to avoid splitting at a non-ASCII byte boundary.
        let mut chars = s.char_indices();
        let (_, first_char) = chars.next()?;
        let split_byte = first_char.len_utf8();
        let (cls, rest) = s.split_at(split_byte);
        let number: u8 = rest.parse().ok()?;
        let class = match cls {
            "g" => RegisterClass::Global,
            "o" => RegisterClass::Out,
            "l" => RegisterClass::Local,
            "i" => RegisterClass::In,
            "f" => RegisterClass::Float,
            _ => return None,
        };
        Some(Self { class, number })
    }

    /// Return the canonical name (e.g. `"%i0"`).
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}{}", self.class.prefix(), self.number)
    }

    /// Return the corresponding input register in the *caller's* frame.
    /// `%o0` becomes `%i0` after a `SAVE`.
    #[must_use]
    pub fn as_caller_input(&self) -> Option<Self> {
        if self.class == RegisterClass::Out {
            Some(Self { class: RegisterClass::In, number: self.number })
        } else {
            None
        }
    }

    /// `%i0` → `%o0` (the corresponding output register in the previous frame).
    #[must_use]
    pub fn as_callee_output(&self) -> Option<Self> {
        if self.class == RegisterClass::In {
            Some(Self { class: RegisterClass::Out, number: self.number })
        } else {
            None
        }
    }
}

impl std::fmt::Display for SparcReg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WindowEntry — one register window frame
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of one register window (one activation record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowEntry {
    /// Current Window Pointer value at which this frame is active.
    pub cwp: u8,
    /// Program counter at function entry.
    pub entry_pc: u32,
    /// Known values of the 8 local registers (indexed 0–7, `None` = unknown).
    pub locals: [Option<u32>; 8],
    /// Known values of the 8 input registers (indexed 0–7).
    pub inputs: [Option<u32>; 8],
    /// Known values of the 8 output registers (indexed 0–7).
    pub outputs: [Option<u32>; 8],
    /// Frame-pointer value (%fp = %i6) if known.
    pub frame_pointer: Option<u32>,
    /// Stack-pointer value (%sp = %o6) if known.
    pub stack_pointer: Option<u32>,
    /// Return address (%i7 + 8) if known.
    pub return_address: Option<u32>,
    /// Whether this frame has been spilled to the register-window overflow area.
    pub spilled: bool,
}

impl WindowEntry {
    /// Create an empty (all-unknown) window entry.
    #[must_use]
    pub const fn empty(cwp: u8, entry_pc: u32) -> Self {
        Self {
            cwp,
            entry_pc,
            locals: [None; 8],
            inputs: [None; 8],
            outputs: [None; 8],
            frame_pointer: None,
            stack_pointer: None,
            return_address: None,
            spilled: false,
        }
    }

    /// Return `%i7` (the link register storing PC−8 of the call site).
    #[must_use]
    pub const fn link_register(&self) -> Option<u32> {
        self.inputs[7]
    }

    /// Return the effective return address (`%i7` + 8).
    #[must_use]
    pub fn return_addr(&self) -> Option<u32> {
        self.inputs[7].map(|r| r.wrapping_add(8))
    }

    /// Get an input register value by number.
    #[must_use]
    pub fn input(&self, n: u8) -> Option<u32> {
        self.inputs.get(n as usize).copied().flatten()
    }

    /// Get a local register value by number.
    #[must_use]
    pub fn local(&self, n: u8) -> Option<u32> {
        self.locals.get(n as usize).copied().flatten()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WindowOverflow — detected window overflow event
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a detected register-window overflow (trap 5 / 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowOverflow {
    /// PC of the `SAVE` instruction that triggered the overflow.
    pub trigger_pc: u32,
    /// CWP value after the overflow.
    pub new_cwp: u8,
    /// Memory address where the window was saved (from `%sp`).
    pub save_addr: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SparcRegisterWindow — the full register file model
// ─────────────────────────────────────────────────────────────────────────────

/// A model of the SPARC register-window file for analysis purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcRegisterWindow {
    /// Number of hardware windows (NWINDOWS).
    pub nwindows: u8,
    /// Current Window Pointer (0-based, wraps modulo nwindows).
    pub cwp: u8,
    /// Window Invalid Mask (bit i=1 → window i is invalid/overflowed).
    pub wim: u32,
    /// Stack of active window entries (innermost = last).
    pub call_stack: Vec<WindowEntry>,
    /// Detected overflow events.
    pub overflows: Vec<WindowOverflow>,
    /// Detected underflow events (RESTORE when WIM says window invalid).
    pub underflow_count: usize,
}

impl SparcRegisterWindow {
    /// Create a new register-window model for an NWINDOWS-window implementation.
    #[must_use]
    pub const fn new(nwindows: u8) -> Self {
        let wim = 1u32; // initially window 0 is invalid (trap-handler convention)
        Self {
            nwindows,
            cwp: 0,
            wim,
            call_stack: Vec::new(),
            overflows: Vec::new(),
            underflow_count: 0,
        }
    }

    /// Apply a `SAVE` instruction at `pc`.
    ///
    /// Returns `true` if this triggers a window overflow trap.
    pub fn apply_save(&mut self, pc: u32) -> bool {
        let new_cwp = (self.cwp.wrapping_sub(1)) % self.nwindows;
        let overflow = (self.wim >> new_cwp) & 1 == 1;
        let sp = self.call_stack.last().and_then(|w| w.stack_pointer);
        if overflow {
            self.overflows.push(WindowOverflow {
                trigger_pc: pc,
                new_cwp,
                save_addr: sp,
            });
            // Rotate WIM on overflow: WIM = (WIM >> 1) | (top bit)
            // Guard against nwindows==0 or >=32 which would cause shift overflow.
            let nw = u32::from(self.nwindows).min(31).max(1);
            let mask = (1u32 << nw).wrapping_sub(1);
            let top = self.wim & mask;
            self.wim = ((top >> 1) | (top << (nw - 1))) & mask;
        }
        self.cwp = new_cwp;
        let entry = WindowEntry::empty(new_cwp, pc);
        self.call_stack.push(entry);
        overflow
    }

    /// Apply a `RESTORE` instruction at `pc`.
    ///
    /// Returns `true` if this triggers a window underflow trap.
    pub fn apply_restore(&mut self, pc: u32) -> bool {
        let new_cwp = (self.cwp + 1) % self.nwindows;
        let underflow = (self.wim >> new_cwp) & 1 == 1;
        if underflow {
            self.underflow_count += 1;
        }
        self.cwp = new_cwp;
        self.call_stack.pop();
        let _ = pc;
        underflow
    }

    /// Return the currently-active window entry (innermost frame).
    #[must_use]
    pub fn current_window(&self) -> Option<&WindowEntry> {
        self.call_stack.last()
    }

    /// Return the nesting depth (number of `SAVE`s without matching `RESTORE`).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Return `true` if the given window is currently valid.
    #[must_use]
    pub const fn is_window_valid(&self, cwp: u8) -> bool {
        (self.wim >> (cwp % self.nwindows)) & 1 == 0
    }

    /// Describe the call chain as a list of entry PCs (innermost first).
    #[must_use]
    pub fn call_chain_pcs(&self) -> Vec<u32> {
        self.call_stack.iter().rev().map(|w| w.entry_pc).collect()
    }

    /// Number of overflows observed.
    #[must_use]
    pub const fn overflow_count(&self) -> usize {
        self.overflows.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// save_restore_analysis
// ─────────────────────────────────────────────────────────────────────────────

/// An instruction relevant to window analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WindowInstr {
    Save { pc: u32 },
    Restore { pc: u32 },
    Other { pc: u32 },
}

/// Summary of SAVE/RESTORE analysis over a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveRestoreAnalysis {
    /// Total `SAVE` instructions found.
    pub save_count: usize,
    /// Total `RESTORE` instructions found.
    pub restore_count: usize,
    /// Addresses of unmatched `SAVE` (more saves than restores at the end).
    pub unmatched_saves: Vec<u32>,
    /// Addresses of `RESTORE` without a preceding `SAVE` (underflow risk).
    pub excess_restores: Vec<u32>,
    /// Maximum call depth reached.
    pub max_depth: usize,
    /// Window overflow events detected during simulation.
    pub overflows: Vec<WindowOverflow>,
    /// Whether the analysis found a balanced SAVE/RESTORE structure.
    pub is_balanced: bool,
}

/// Analyse a sequence of instructions for SAVE/RESTORE balance.
///
/// This is a linear-scan simulation; it does not follow branches.
///
/// # Arguments
/// * `instrs` – Sequence of `WindowInstr` values in program order.
/// * `nwindows` – Number of register windows in this SPARC implementation.
#[must_use]
pub fn save_restore_analysis(instrs: &[WindowInstr], nwindows: u8) -> SaveRestoreAnalysis {
    let mut model = SparcRegisterWindow::new(nwindows);
    let mut save_count = 0usize;
    let mut restore_count = 0usize;
    let mut unmatched_saves = Vec::new();
    let mut excess_restores = Vec::new();
    let mut max_depth = 0usize;
    let mut save_stack: Vec<u32> = Vec::new();

    for instr in instrs {
        match instr {
            WindowInstr::Save { pc } => {
                model.apply_save(*pc);
                save_count += 1;
                save_stack.push(*pc);
                max_depth = max_depth.max(model.depth());
            }
            WindowInstr::Restore { pc } => {
                if save_stack.is_empty() {
                    excess_restores.push(*pc);
                } else {
                    save_stack.pop();
                }
                model.apply_restore(*pc);
                restore_count += 1;
            }
            WindowInstr::Other { .. } => {}
        }
    }

    unmatched_saves.extend(save_stack);
    let is_balanced = unmatched_saves.is_empty() && excess_restores.is_empty();

    SaveRestoreAnalysis {
        save_count,
        restore_count,
        unmatched_saves,
        excess_restores,
        max_depth,
        overflows: model.overflows,
        is_balanced,
    }
}

/// Build a `save_restore_analysis`-compatible instruction list from raw
/// 32-bit SPARC words.
#[must_use]
pub fn classify_window_instrs(words: &[u32]) -> Vec<WindowInstr> {
    let mut out = Vec::new();
    for (i, &w) in words.iter().enumerate() {
        let pc = (i as u32) * 4;
        if is_save(w) {
            out.push(WindowInstr::Save { pc });
        } else if is_restore(w) {
            out.push(WindowInstr::Restore { pc });
        } else {
            out.push(WindowInstr::Other { pc });
        }
    }
    out
}

/// Heuristic: does this 32-bit word look like a SPARC `SAVE` instruction?
///
/// SAVE rd,rs1,rs2|imm: op=10, op3=0b111100 (0x3C)
#[must_use]
pub const fn is_save(word: u32) -> bool {
    let op = (word >> 30) & 0x3;
    let op3 = (word >> 19) & 0x3F;
    op == 0b10 && op3 == 0b111100
}

/// Heuristic: does this 32-bit word look like a SPARC `RESTORE` instruction?
///
/// RESTORE rd,rs1,rs2|imm: op=10, op3=0b111101 (0x3D)
#[must_use]
pub const fn is_restore(word: u32) -> bool {
    let op = (word >> 30) & 0x3;
    let op3 = (word >> 19) & 0x3F;
    op == 0b10 && op3 == 0b111101
}

/// Statistics over a call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowStats {
    pub depth: usize,
    pub overflow_count: usize,
    pub underflow_count: usize,
    pub valid_windows: Vec<u8>,
    pub nwindows: u8,
    pub wim: u32,
}

impl WindowStats {
    /// Build a per-CWP histogram of how many call-chain entries currently
    /// occupy each window slot.
    ///
    /// Keyed by Current-Window-Pointer (CWP); values are the number of stacked
    /// `WindowEntry`s the model is holding at that CWP. Useful for diagnosing
    /// long save-chains that approach overflow on small `nwindows` SPARC parts.
    #[must_use]
    pub fn cwp_histogram(model: &SparcRegisterWindow) -> HashMap<u8, usize> {
        let mut h: HashMap<u8, usize> = HashMap::new();
        for entry in &model.call_stack {
            *h.entry(entry.cwp).or_insert(0) += 1;
        }
        h
    }

    #[must_use]
    pub fn from_model(model: &SparcRegisterWindow) -> Self {
        let valid_windows = (0..model.nwindows)
            .filter(|&w| model.is_window_valid(w))
            .collect();
        Self {
            depth: model.depth(),
            overflow_count: model.overflow_count(),
            underflow_count: model.underflow_count,
            valid_windows,
            nwindows: model.nwindows,
            wim: model.wim,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparc_reg_from_str() {
        let r = SparcReg::from_str("%i0").unwrap();
        assert_eq!(r.class, RegisterClass::In);
        assert_eq!(r.number, 0);
    }

    #[test]
    fn test_sparc_reg_name() {
        let r = SparcReg { class: RegisterClass::Out, number: 7 };
        assert_eq!(r.name(), "%o7");
    }

    #[test]
    fn test_as_caller_input() {
        let r = SparcReg { class: RegisterClass::Out, number: 0 };
        let i = r.as_caller_input().unwrap();
        assert_eq!(i.class, RegisterClass::In);
        assert_eq!(i.number, 0);
    }

    #[test]
    fn test_as_callee_output() {
        let r = SparcReg { class: RegisterClass::In, number: 1 };
        let o = r.as_callee_output().unwrap();
        assert_eq!(o.class, RegisterClass::Out);
        assert_eq!(o.number, 1);
    }

    #[test]
    fn test_window_entry_return_addr() {
        let mut w = WindowEntry::empty(0, 0x1000);
        w.inputs[7] = Some(0x2000); // %i7 = call site PC
        assert_eq!(w.return_addr(), Some(0x2008));
    }

    #[test]
    fn test_model_save_increments_depth() {
        let mut model = SparcRegisterWindow::new(8);
        model.apply_save(0x1000);
        assert_eq!(model.depth(), 1);
    }

    #[test]
    fn test_model_restore_decrements_depth() {
        let mut model = SparcRegisterWindow::new(8);
        model.apply_save(0x1000);
        model.apply_restore(0x1004);
        assert_eq!(model.depth(), 0);
    }

    #[test]
    fn test_model_cwp_wraps() {
        let mut model = SparcRegisterWindow::new(8);
        for i in 0..8 {
            model.apply_save(i * 4);
        }
        // CWP should have wrapped around
        assert!(model.cwp < 8);
    }

    #[test]
    fn test_is_save() {
        // Encode SAVE %g0, %g0, %g0: op=10, op3=0x3C, rd=0, rs1=0, rs2=0
        let w: u32 = (0b10 << 30) | (0 << 25) | (0x3C << 19) | (0 << 14) | 0;
        assert!(is_save(w));
        assert!(!is_restore(w));
    }

    #[test]
    fn test_is_restore() {
        let w: u32 = (0b10 << 30) | (0 << 25) | (0x3D << 19) | (0 << 14) | 0;
        assert!(is_restore(w));
        assert!(!is_save(w));
    }

    #[test]
    fn test_balanced_analysis() {
        let instrs = vec![
            WindowInstr::Save { pc: 0x1000 },
            WindowInstr::Other { pc: 0x1004 },
            WindowInstr::Restore { pc: 0x1008 },
        ];
        let r = save_restore_analysis(&instrs, 8);
        assert!(r.is_balanced);
        assert_eq!(r.save_count, 1);
        assert_eq!(r.restore_count, 1);
    }

    #[test]
    fn test_unbalanced_analysis() {
        let instrs = vec![
            WindowInstr::Save { pc: 0x1000 },
            WindowInstr::Save { pc: 0x1004 },
            WindowInstr::Restore { pc: 0x1008 },
        ];
        let r = save_restore_analysis(&instrs, 8);
        assert!(!r.is_balanced);
        assert_eq!(r.unmatched_saves.len(), 1);
    }

    #[test]
    fn test_excess_restore() {
        let instrs = vec![WindowInstr::Restore { pc: 0x2000 }];
        let r = save_restore_analysis(&instrs, 8);
        assert!(!r.is_balanced);
        assert_eq!(r.excess_restores.len(), 1);
    }

    #[test]
    fn test_max_depth() {
        let instrs: Vec<_> = (0..4).map(|i| WindowInstr::Save { pc: i * 4 }).collect();
        let r = save_restore_analysis(&instrs, 8);
        assert_eq!(r.max_depth, 4);
    }

    #[test]
    fn test_total_physical_regs() {
        assert_eq!(total_physical_regs(8), 136);
    }

    #[test]
    fn test_window_stats() {
        let mut model = SparcRegisterWindow::new(8);
        model.apply_save(0);
        let stats = WindowStats::from_model(&model);
        assert_eq!(stats.depth, 1);
    }

    #[test]
    fn test_register_class_prefix() {
        assert_eq!(RegisterClass::Global.prefix(), "%g");
        assert_eq!(RegisterClass::In.prefix(), "%i");
        assert_eq!(RegisterClass::Out.prefix(), "%o");
        assert_eq!(RegisterClass::Local.prefix(), "%l");
    }
}
