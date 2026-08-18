//! SPARC register file with sliding register windows.
//!
//! The SPARC architecture provides a large register file divided into
//! overlapping *windows*. Each window has 8 local and 8 in/out registers
//! shared with adjacent windows. This module implements:
//!
//! - [`SparcRegisterFile`]: the full 520-entry integer register file.
//! - [`RegisterWindow`]: a single window view (globals + locals + ins + outs).
//! - [`WindowManager`]: manages the Current Window Pointer (CWP), WIM, and
//!   window overflow/underflow detection.
//! - Floating-point and special-register state.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of register windows supported (SPARC V8 max = 32).
pub const MAX_WINDOWS: usize = 32;
/// Number of global registers (shared across all windows).
pub const NUM_GLOBALS: usize = 8;
/// Number of integer registers per window group (in, local, out each = 8).
pub const REGS_PER_GROUP: usize = 8;
/// Total named integer registers per window (global + in + local + out = 32).
pub const REGS_PER_WINDOW: usize = 32;
/// Maximum single-precision floating-point registers (SPARC V9 = 64).
pub const MAX_FP_REGS: usize = 64;

// ── RegisterKindSparc ─────────────────────────────────────────────────────────

/// Category of a SPARC integer register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterKindSparc {
    /// %g0–%g7 — global registers (shared, %g0 always zero).
    Global,
    /// %o0–%o7 — outgoing arguments / return values.
    Out,
    /// %l0–%l7 — local to the current window.
    Local,
    /// %i0–%i7 — incoming arguments / saved link register (%i7).
    In,
}

impl RegisterKindSparc {
    /// Return the group name prefix ("g", "o", "l", "i").
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Global => "g",
            Self::Out => "o",
            Self::Local => "l",
            Self::In => "i",
        }
    }
}

// ── RegisterWindow ────────────────────────────────────────────────────────────

/// A single SPARC register window.
///
/// Contains the 8 global registers plus the 24 windowed registers (8 out,
/// 8 local, 8 in) that are visible when this window is current.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWindow {
    /// Window index (0-based).
    pub window_id: usize,
    /// The 8 global registers (%g0–%g7). %g0 is always 0.
    pub globals: [u64; NUM_GLOBALS],
    /// The 8 out registers (%o0–%o7) for this window.
    /// These overlap with the previous window's %i registers.
    pub outs: [u64; REGS_PER_GROUP],
    /// The 8 local registers (%l0–%l7) — private to this window.
    pub locals: [u64; REGS_PER_GROUP],
    /// The 8 in registers (%i0–%i7) for this window.
    /// These overlap with the next window's %o registers.
    pub ins: [u64; REGS_PER_GROUP],
}

impl RegisterWindow {
    /// Create a zeroed register window.
    #[must_use]
    pub const fn new(window_id: usize) -> Self {
        Self {
            window_id,
            globals: [0u64; NUM_GLOBALS],
            outs: [0u64; REGS_PER_GROUP],
            locals: [0u64; REGS_PER_GROUP],
            ins: [0u64; REGS_PER_GROUP],
        }
    }

    /// Return the value of a register by its SPARC numeric index (0–31).
    ///
    /// - 0–7 → globals
    /// - 8–15 → outs (%o0–%o7)
    /// - 16–23 → locals (%l0–%l7)
    /// - 24–31 → ins (%i0–%i7)
    ///
    /// %g0 always returns 0.
    #[must_use]
    pub const fn read(&self, reg: usize) -> u64 {
        match reg {
            0 => 0, // %g0 is always zero
            1..=7 => self.globals[reg],
            8..=15 => self.outs[reg - 8],
            16..=23 => self.locals[reg - 16],
            24..=31 => self.ins[reg - 24],
            _ => 0,
        }
    }

    /// Write a value to a register by its numeric index.
    ///
    /// Writes to %g0 are silently dropped.
    pub const fn write(&mut self, reg: usize, value: u64) {
        match reg {
            0 => {} // writes to %g0 are discarded
            1..=7 => self.globals[reg] = value,
            8..=15 => self.outs[reg - 8] = value,
            16..=23 => self.locals[reg - 16] = value,
            24..=31 => self.ins[reg - 24] = value,
            _ => {}
        }
    }

    /// Return the canonical register name for index `reg`.
    #[must_use]
    pub const fn reg_name(reg: usize) -> &'static str {
        match reg {
            0 => "%g0", 1 => "%g1", 2 => "%g2", 3 => "%g3",
            4 => "%g4", 5 => "%g5", 6 => "%g6", 7 => "%g7",
            8 => "%o0", 9 => "%o1", 10 => "%o2", 11 => "%o3",
            12 => "%o4", 13 => "%o5", 14 => "%sp", 15 => "%o7",
            16 => "%l0", 17 => "%l1", 18 => "%l2", 19 => "%l3",
            20 => "%l4", 21 => "%l5", 22 => "%l6", 23 => "%l7",
            24 => "%i0", 25 => "%i1", 26 => "%i2", 27 => "%i3",
            28 => "%i4", 29 => "%i5", 30 => "%fp", 31 => "%i7",
            _ => "%??",
        }
    }

    /// Return the kind of a register.
    #[must_use]
    pub const fn reg_kind(reg: usize) -> RegisterKindSparc {
        match reg {
            0..=7 => RegisterKindSparc::Global,
            8..=15 => RegisterKindSparc::Out,
            16..=23 => RegisterKindSparc::Local,
            _ => RegisterKindSparc::In,
        }
    }

    /// Return a map of all non-zero register values in this window.
    #[must_use]
    pub fn non_zero_regs(&self) -> HashMap<String, u64> {
        let mut m = HashMap::new();
        for i in 0..REGS_PER_WINDOW {
            let v = self.read(i);
            if v != 0 {
                m.insert(Self::reg_name(i).to_string(), v);
            }
        }
        m
    }
}

impl fmt::Display for RegisterWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Window #{}", self.window_id)?;
        for i in 0..REGS_PER_WINDOW {
            if i % 8 == 0 {
                let group = match i {
                    0 => "globals",
                    8 => "outs   ",
                    16 => "locals ",
                    _ => "ins    ",
                };
                write!(f, "  {group}: ")?;
            }
            write!(f, "{:#018x}", self.read(i))?;
            if i % 8 == 7 {
                writeln!(f)?;
            } else {
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

// ── SparcRegisterFile ─────────────────────────────────────────────────────────

/// The complete SPARC integer register file with up to 32 windows.
///
/// The physical register file has 8 globals + (`nwindows` × 16) windowed
/// registers = up to 8 + 32×16 = 520 physical registers.
///
/// This struct stores each window independently (with overlap tracking done
/// by [`WindowManager`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparcRegisterFile {
    /// The windows (indexed 0..nwindows).
    windows: Vec<RegisterWindow>,
    /// Single-precision FP registers (%f0–%f63 for V9, %f0–%f31 for V8).
    pub fp_regs: Vec<f32>,
    /// Double-precision FP registers (derived from pairs of `f_regs`).
    pub fp_double: Vec<f64>,
    /// Program counter.
    pub pc: u64,
    /// Next program counter.
    pub npc: u64,
    /// Processor State Register (PSR) for V8.
    pub psr: u32,
    /// Condition Code Register (CCR) for V9.
    pub ccr: u8,
    /// Window Invalid Mask.
    pub wim: u32,
    /// Trap Base Register.
    pub tbr: u64,
    /// Y register (multiply/divide helper).
    pub y: u32,
    /// Number of windows configured.
    pub nwindows: usize,
}

impl SparcRegisterFile {
    /// Create a new register file with `nwindows` windows (must be 2–32).
    ///
    /// # Panics
    ///
    /// Panics if `nwindows` is 0 or exceeds [`MAX_WINDOWS`].
    #[must_use]
    pub fn new(nwindows: usize) -> Self {
        assert!(nwindows >= 2 && nwindows <= MAX_WINDOWS, "nwindows out of range");
        let windows = (0..nwindows).map(RegisterWindow::new).collect();
        let fp_count = MAX_FP_REGS;
        Self {
            windows,
            fp_regs: vec![0.0f32; fp_count],
            fp_double: vec![0.0f64; fp_count / 2],
            pc: 0,
            npc: 4,
            psr: 0,
            ccr: 0,
            wim: 2, // window 1 invalid by default (standard SPARC convention)
            tbr: 0,
            y: 0,
            nwindows,
        }
    }

    /// Return a reference to window `w`.
    ///
    /// # Panics
    ///
    /// Panics if `w >= nwindows`.
    #[must_use]
    pub fn window(&self, w: usize) -> &RegisterWindow {
        &self.windows[w]
    }

    /// Return a mutable reference to window `w`.
    pub fn window_mut(&mut self, w: usize) -> &mut RegisterWindow {
        &mut self.windows[w]
    }

    /// Read a register from the given window.
    #[must_use]
    pub fn read(&self, window: usize, reg: usize) -> u64 {
        if window < self.nwindows {
            self.windows[window].read(reg)
        } else {
            0
        }
    }

    /// Write a register in the given window.
    pub fn write(&mut self, window: usize, reg: usize, value: u64) {
        if window < self.nwindows {
            self.windows[window].write(reg, value);
        }
    }

    /// Propagate shared registers between adjacent windows.
    ///
    /// When window `w` is current, its %o registers physically overlap with
    /// window `(w - 1 + nwindows) % nwindows`'s %i registers.  This method
    /// syncs `outs[w] → ins[prev]` and `ins[w] → outs[next]`.
    pub fn sync_window_overlap(&mut self, w: usize) {
        let n = self.nwindows;
        let prev = (w + n - 1) % n;
        let next = (w + 1) % n;
        // outs[w] == ins[prev]
        let outs_w = self.windows[w].outs;
        self.windows[prev].ins = outs_w;
        // ins[w] == outs[next]
        let ins_w = self.windows[w].ins;
        self.windows[next].outs = ins_w;
    }

    /// Return the number of physical integer registers (globals + windowed).
    #[must_use]
    pub const fn physical_reg_count(&self) -> usize {
        NUM_GLOBALS + self.nwindows * REGS_PER_GROUP * 2
    }

    /// Return all non-zero (name, value) pairs in the current window `w`.
    #[must_use]
    pub fn dump_window(&self, w: usize) -> Vec<(String, u64)> {
        if w >= self.nwindows {
            return Vec::new();
        }
        self.windows[w]
            .non_zero_regs()
            .into_iter()
            .collect()
    }

    /// Read a single-precision FP register.
    #[must_use]
    pub fn read_fp(&self, index: usize) -> f32 {
        self.fp_regs.get(index).copied().unwrap_or(0.0)
    }

    /// Write a single-precision FP register.
    pub fn write_fp(&mut self, index: usize, value: f32) {
        if let Some(r) = self.fp_regs.get_mut(index) {
            *r = value;
        }
        // Update double register pair.
        let pair = index / 2;
        if pair < self.fp_double.len() {
            let lo = f64::from(self.fp_regs[pair * 2]);
            let hi = f64::from(self.fp_regs.get(pair * 2 + 1).copied().unwrap_or(0.0));
            self.fp_double[pair] = (hi as f64) * (2.0_f64.powi(32)) + (lo as f64);
        }
    }
}

impl Default for SparcRegisterFile {
    fn default() -> Self {
        Self::new(8)
    }
}

// ── WindowManager ─────────────────────────────────────────────────────────────

/// Manages the Current Window Pointer and window overflow/underflow.
///
/// The CWP points to the currently active window. SAVE decrements the CWP;
/// RESTORE increments it. If the new window is marked invalid in the WIM,
/// a window overflow (SAVE) or underflow (RESTORE) trap occurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowManager {
    /// Current Window Pointer (index into the window array).
    pub cwp: usize,
    /// Window Invalid Mask — bit `n` set means window `n` is on the stack.
    pub wim: u32,
    /// Total number of windows.
    pub nwindows: usize,
    /// History of CWP values (for tracing purposes).
    cwp_history: Vec<usize>,
    /// Number of SAVE operations performed.
    pub saves: u64,
    /// Number of RESTORE operations performed.
    pub restores: u64,
    /// Number of window overflow traps triggered.
    pub overflow_traps: u64,
    /// Number of window underflow traps triggered.
    pub underflow_traps: u64,
}

/// Result of a SAVE or RESTORE operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowOpResult {
    /// Operation completed successfully; new CWP is the payload.
    Ok(usize),
    /// Operation would use an invalid window — a trap must be taken.
    Overflow,
    /// Operation would restore from an invalid window — a trap must be taken.
    Underflow,
}

impl WindowManager {
    /// Create a new window manager with `nwindows` windows.
    ///
    /// The CWP starts at 0 and WIM is initialised to 1 (window 0 already
    /// occupied by the initial frame, window 1 marked invalid).
    ///
    /// # Panics
    ///
    /// Panics if `nwindows` is 0 or > [`MAX_WINDOWS`].
    #[must_use]
    pub fn new(nwindows: usize) -> Self {
        assert!(nwindows >= 2 && nwindows <= MAX_WINDOWS);
        Self {
            cwp: 0,
            wim: 1 << ((nwindows - 1) % nwindows), // last window invalid
            nwindows,
            cwp_history: vec![0],
            saves: 0,
            restores: 0,
            overflow_traps: 0,
            underflow_traps: 0,
        }
    }

    /// Perform a SAVE: decrement CWP (with wrap). Returns [`WindowOpResult`].
    pub fn save(&mut self) -> WindowOpResult {
        let new_cwp = (self.cwp + self.nwindows - 1) % self.nwindows;
        self.saves += 1;
        if self.wim & (1u32 << new_cwp) != 0 {
            self.overflow_traps += 1;
            return WindowOpResult::Overflow;
        }
        self.cwp = new_cwp;
        self.cwp_history.push(self.cwp);
        WindowOpResult::Ok(self.cwp)
    }

    /// Perform a RESTORE: increment CWP (with wrap). Returns [`WindowOpResult`].
    pub fn restore(&mut self) -> WindowOpResult {
        let new_cwp = (self.cwp + 1) % self.nwindows;
        self.restores += 1;
        if self.wim & (1u32 << new_cwp) != 0 {
            self.underflow_traps += 1;
            return WindowOpResult::Underflow;
        }
        self.cwp = new_cwp;
        self.cwp_history.push(self.cwp);
        WindowOpResult::Ok(self.cwp)
    }

    /// Handle a window overflow trap: rotate WIM and return the new WIM value.
    ///
    /// The SPARC ABI convention is to rotate WIM right by 1 position.
    pub const fn handle_overflow(&mut self) -> u32 {
        let mask = (1u32 << self.nwindows) - 1;
        self.wim = (self.wim >> 1 | self.wim << (self.nwindows - 1)) & mask;
        self.wim
    }

    /// Handle a window underflow trap: rotate WIM left by 1 position.
    pub const fn handle_underflow(&mut self) -> u32 {
        let mask = (1u32 << self.nwindows) - 1;
        self.wim = (self.wim << 1 | self.wim >> (self.nwindows - 1)) & mask;
        self.wim
    }

    /// Return whether window `w` is valid (not flagged in WIM).
    #[must_use]
    pub const fn is_valid_window(&self, w: usize) -> bool {
        self.wim & (1u32 << w) == 0
    }

    /// Return the previous (caller's) window index.
    #[must_use]
    pub const fn prev_window(&self) -> usize {
        (self.cwp + 1) % self.nwindows
    }

    /// Return the next (callee's) window index.
    #[must_use]
    pub const fn next_window(&self) -> usize {
        (self.cwp + self.nwindows - 1) % self.nwindows
    }

    /// Return the call depth estimate (number of nested SAVEs).
    #[must_use]
    pub const fn call_depth(&self) -> usize {
        self.saves.saturating_sub(self.restores) as usize
    }

    /// Return the full CWP change history.
    #[must_use]
    pub fn cwp_history(&self) -> &[usize] {
        &self.cwp_history
    }

    /// Return the number of currently used windows (saved − restored).
    #[must_use]
    pub fn windows_in_use(&self) -> usize {
        self.call_depth().min(self.nwindows)
    }
}

// ── FpRegisterState ───────────────────────────────────────────────────────────

/// Floating-point register state (separate from integer windows).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpRegisterState {
    /// Single-precision registers (%f0–%f63).
    pub single: Vec<f32>,
    /// FP Status Register.
    pub fsr: u64,
}

impl FpRegisterState {
    /// Create a zeroed FP register state.
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self {
            single: vec![0.0f32; count],
            fsr: 0,
        }
    }

    /// Read a single-precision FP register.
    #[must_use]
    pub fn read_single(&self, idx: usize) -> f32 {
        self.single.get(idx).copied().unwrap_or(0.0)
    }

    /// Read a double-precision FP register (pair at idx, idx+1).
    #[must_use]
    pub fn read_double(&self, idx: usize) -> f64 {
        let hi = f64::from(self.single.get(idx).copied().unwrap_or(0.0));
        let lo = f64::from(self.single.get(idx + 1).copied().unwrap_or(0.0));
        hi * (2.0_f64.powi(32)) + lo
    }

    /// Write a single-precision FP register.
    pub fn write_single(&mut self, idx: usize, value: f32) {
        if let Some(r) = self.single.get_mut(idx) {
            *r = value;
        }
    }

    /// Return the number of single-precision registers.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.single.len()
    }
}

impl Default for FpRegisterState {
    fn default() -> Self {
        Self::new(64)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_g0_always_zero() {
        let mut w = RegisterWindow::new(0);
        w.write(0, 0xDEAD_BEEF);
        assert_eq!(w.read(0), 0);
    }

    #[test]
    fn test_window_read_write_globals() {
        let mut w = RegisterWindow::new(0);
        w.write(3, 0xFF);
        assert_eq!(w.read(3), 0xFF);
    }

    #[test]
    fn test_window_read_write_locals() {
        let mut w = RegisterWindow::new(0);
        w.write(18, 42); // %l2
        assert_eq!(w.read(18), 42);
    }

    #[test]
    fn test_window_read_write_ins() {
        let mut w = RegisterWindow::new(0);
        w.write(24, 0x1234); // %i0
        assert_eq!(w.read(24), 0x1234);
    }

    #[test]
    fn test_window_read_write_outs() {
        let mut w = RegisterWindow::new(0);
        w.write(8, 99); // %o0
        assert_eq!(w.read(8), 99);
    }

    #[test]
    fn test_window_reg_name() {
        assert_eq!(RegisterWindow::reg_name(0), "%g0");
        assert_eq!(RegisterWindow::reg_name(14), "%sp");
        assert_eq!(RegisterWindow::reg_name(30), "%fp");
        assert_eq!(RegisterWindow::reg_name(31), "%i7");
    }

    #[test]
    fn test_window_reg_kind() {
        assert_eq!(RegisterWindow::reg_kind(5), RegisterKindSparc::Global);
        assert_eq!(RegisterWindow::reg_kind(10), RegisterKindSparc::Out);
        assert_eq!(RegisterWindow::reg_kind(20), RegisterKindSparc::Local);
        assert_eq!(RegisterWindow::reg_kind(28), RegisterKindSparc::In);
    }

    #[test]
    fn test_register_file_default() {
        let rf = SparcRegisterFile::default();
        assert_eq!(rf.nwindows, 8);
        assert_eq!(rf.read(0, 0), 0); // %g0 always 0
    }

    #[test]
    fn test_register_file_read_write() {
        let mut rf = SparcRegisterFile::new(8);
        rf.write(0, 10, 0xABCD); // window 0, %o2
        assert_eq!(rf.read(0, 10), 0xABCD);
    }

    #[test]
    fn test_register_file_fp() {
        let mut rf = SparcRegisterFile::new(8);
        rf.write_fp(0, 3.14);
        let v = rf.read_fp(0);
        assert!((v - 3.14).abs() < 0.01);
    }

    #[test]
    fn test_physical_reg_count() {
        let rf = SparcRegisterFile::new(8);
        assert!(rf.physical_reg_count() >= 136); // 8 + 8*16
    }

    #[test]
    fn test_sync_window_overlap() {
        let mut rf = SparcRegisterFile::new(4);
        // Write to window 0 outs
        rf.windows[0].outs[0] = 0xBEEF;
        rf.sync_window_overlap(0);
        // Previous window is 3; its ins[0] should now be 0xBEEF
        assert_eq!(rf.windows[3].ins[0], 0xBEEF);
    }

    #[test]
    fn test_window_manager_initial_state() {
        let wm = WindowManager::new(8);
        assert_eq!(wm.cwp, 0);
        assert_eq!(wm.call_depth(), 0);
    }

    #[test]
    fn test_save_decrements_cwp() {
        let mut wm = WindowManager::new(8);
        let res = wm.save();
        match res {
            WindowOpResult::Ok(new_cwp) => assert_eq!(new_cwp, 7),
            WindowOpResult::Overflow => {} // acceptable with specific WIM
            _ => panic!("unexpected underflow"),
        }
    }

    #[test]
    fn test_restore_increments_cwp() {
        let mut wm = WindowManager::new(8);
        // First do a SAVE so RESTORE has something to return to.
        wm.save();
        let cwp_after_save = wm.cwp;
        let res = wm.restore();
        match res {
            WindowOpResult::Ok(new_cwp) => assert_eq!(new_cwp, (cwp_after_save + 1) % 8),
            WindowOpResult::Underflow => {} // acceptable
            _ => panic!("unexpected overflow"),
        }
    }

    #[test]
    fn test_window_manager_overflow_trap() {
        // Set WIM so that next SAVE would hit an invalid window.
        let mut wm = WindowManager::new(4);
        wm.wim = 0b1110; // windows 1, 2, 3 invalid
        wm.cwp = 0;
        let res = wm.save(); // new CWP would be 3, which is invalid
        assert_eq!(res, WindowOpResult::Overflow);
        assert_eq!(wm.overflow_traps, 1);
    }

    #[test]
    fn test_handle_overflow_rotates_wim() {
        let mut wm = WindowManager::new(8);
        let old_wim = wm.wim;
        let new_wim = wm.handle_overflow();
        assert_ne!(new_wim, old_wim);
    }

    #[test]
    fn test_prev_next_window() {
        let wm = WindowManager::new(8);
        assert_eq!(wm.prev_window(), 1);
        assert_eq!(wm.next_window(), 7);
    }

    #[test]
    fn test_is_valid_window() {
        let wm = WindowManager::new(8);
        // WIM has bit set for last window
        assert!(!wm.is_valid_window(7)); // window 7 invalid
        assert!(wm.is_valid_window(0)); // window 0 valid
    }

    #[test]
    fn test_cwp_history() {
        let mut wm = WindowManager::new(8);
        wm.save();
        assert!(wm.cwp_history().len() >= 1);
    }

    #[test]
    fn test_fp_state_read_write() {
        let mut fp = FpRegisterState::new(64);
        fp.write_single(5, 1.5);
        assert!((fp.read_single(5) - 1.5).abs() < 1e-6);
    }

    #[test]
    fn test_fp_state_count() {
        let fp = FpRegisterState::default();
        assert_eq!(fp.count(), 64);
    }

    #[test]
    fn test_non_zero_regs() {
        let mut w = RegisterWindow::new(0);
        w.write(16, 77); // %l0
        let nz = w.non_zero_regs();
        assert!(nz.contains_key("%l0"));
    }
}
