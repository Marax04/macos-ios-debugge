//! MSP430 calling convention analysis.
//!
//! Models the two primary MSP430 calling conventions:
//!
//! * **MSP430 GCC** (`msp430_gcc`) — arguments passed in R15..R12 (rightmost
//!   first → R15 holds the first argument), return value in R15 (or R15:R14
//!   for 32-bit), callee saves R4..R10.
//! * **MSP430 IAR** (`msp430_iar`) — arguments passed in R12..R15 (leftmost
//!   first → R12 holds the first argument), return value in R12 (or R12:R13
//!   for 32-bit), callee saves R4..R11.
//!
//! Provides types to describe argument/return register layouts, compute
//! stack argument offsets for functions with many parameters, detect
//! callee-save violations, and format register lists.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CcKind
// ---------------------------------------------------------------------------

/// The two canonical MSP430 calling convention variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CcKind {
    /// GCC (mspgcc / LLVM/Clang) calling convention.
    Gcc,
    /// IAR Embedded Workbench calling convention.
    Iar,
}

impl CcKind {
    /// Return the canonical name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gcc => "msp430_gcc",
            Self::Iar => "msp430_iar",
        }
    }
}

impl std::fmt::Display for CcKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// ArgWidth
// ---------------------------------------------------------------------------

/// Width of a function argument or return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgWidth {
    /// 8-bit byte (passed in low byte of a register).
    Byte,
    /// 16-bit word (one register).
    Word,
    /// 32-bit long word (two registers, little-endian: low word in lower-numbered reg).
    Dword,
    /// 64-bit (four registers on MSP430).
    Qword,
}

impl ArgWidth {
    /// Number of 16-bit registers consumed.
    #[must_use]
    pub const fn reg_count(self) -> usize {
        match self {
            Self::Byte | Self::Word => 1,
            Self::Dword => 2,
            Self::Qword => 4,
        }
    }

    /// Width in bytes.
    #[must_use]
    pub const fn byte_count(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }
}

// ---------------------------------------------------------------------------
// ArgRegister
// ---------------------------------------------------------------------------

/// Describes a function argument held in one or more registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgRegister {
    /// Argument position (0-based).
    pub position: usize,
    /// Register numbers (e.g. [15] for a 16-bit arg, [14, 15] for a 32-bit).
    pub regs: Vec<u8>,
    /// Width of this argument.
    pub width: ArgWidth,
    /// Whether this argument is passed on the stack (when registers are exhausted).
    pub on_stack: bool,
    /// Stack offset from SP at function entry (bytes), if `on_stack`.
    pub stack_offset: Option<i16>,
}

impl ArgRegister {
    /// Create a register-passed argument.
    #[must_use]
    pub const fn in_regs(position: usize, regs: Vec<u8>, width: ArgWidth) -> Self {
        Self {
            position,
            regs,
            width,
            on_stack: false,
            stack_offset: None,
        }
    }

    /// Create a stack-passed argument.
    #[must_use]
    pub const fn on_stack(position: usize, offset: i16, width: ArgWidth) -> Self {
        Self {
            position,
            regs: Vec::new(),
            width,
            on_stack: true,
            stack_offset: Some(offset),
        }
    }

    /// Return a display string for this argument location.
    #[must_use]
    pub fn location_str(&self) -> String {
        if self.on_stack {
            format!("[SP+{}]", self.stack_offset.unwrap_or(0))
        } else {
            self.regs
                .iter()
                .map(|r| format!("R{r}"))
                .collect::<Vec<_>>()
                .join(":")
        }
    }
}

// ---------------------------------------------------------------------------
// ReturnReg
// ---------------------------------------------------------------------------

/// Describes the register(s) holding the return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnReg {
    /// Register numbers (low to high, e.g. [14, 15] for a 32-bit GCC return).
    pub regs: Vec<u8>,
    /// Width of the return value.
    pub width: ArgWidth,
}

impl ReturnReg {
    /// Create a return register description.
    #[must_use]
    pub const fn new(regs: Vec<u8>, width: ArgWidth) -> Self {
        Self { regs, width }
    }

    /// Return the primary (low) return register.
    #[must_use]
    pub fn primary_reg(&self) -> Option<u8> {
        self.regs.first().copied()
    }

    /// Display string (e.g. "R15" or "R14:R15").
    #[must_use]
    pub fn display(&self) -> String {
        self.regs
            .iter()
            .map(|r| format!("R{r}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

// ---------------------------------------------------------------------------
// Msp430CallingConvention
// ---------------------------------------------------------------------------

/// Full description of an MSP430 calling convention, including argument
/// passing, return values, caller-save / callee-save register sets, and
/// stack alignment rules.
#[derive(Debug, Clone)]
pub struct Msp430CallingConvention {
    /// Which variant this is.
    pub kind: CcKind,
    /// Integer argument registers, in order (first arg first).
    pub int_arg_regs: Vec<u8>,
    /// Maximum number of register arguments (before spilling to stack).
    pub max_reg_args: usize,
    /// Primary return register (16-bit).
    pub return_reg_16: u8,
    /// Return registers for 32-bit values (low:high).
    pub return_regs_32: (u8, u8),
    /// Callee-saved registers (must be preserved across calls).
    pub callee_saved: Vec<u8>,
    /// Caller-saved (scratch) registers (may be clobbered by called functions).
    pub caller_saved: Vec<u8>,
    /// Stack alignment requirement (bytes).
    pub stack_alignment: u8,
    /// Whether the stack grows downward (always true for MSP430).
    pub stack_grows_down: bool,
}

impl Msp430CallingConvention {
    /// Create the GCC calling convention for MSP430.
    ///
    /// Argument order (first to last): R15, R14, R13, R12 (rightmost first).
    /// Return value: R15 (16-bit), R14:R15 (32-bit).
    /// Callee-saved: R4–R10.  Caller-saved (scratch): R11–R15.
    #[must_use]
    pub fn gcc() -> Self {
        Self {
            kind: CcKind::Gcc,
            int_arg_regs: vec![15, 14, 13, 12],
            max_reg_args: 4,
            return_reg_16: 15,
            return_regs_32: (14, 15),
            callee_saved: vec![4, 5, 6, 7, 8, 9, 10],
            caller_saved: vec![11, 12, 13, 14, 15],
            stack_alignment: 2,
            stack_grows_down: true,
        }
    }

    /// Create the IAR calling convention for MSP430.
    ///
    /// Argument order (first to last): R12, R13, R14, R15 (leftmost first).
    /// Return value: R12 (16-bit), R12:R13 (32-bit).
    /// Callee-saved: R4–R11.  Caller-saved (scratch): R12–R15.
    #[must_use]
    pub fn iar() -> Self {
        Self {
            kind: CcKind::Iar,
            int_arg_regs: vec![12, 13, 14, 15],
            max_reg_args: 4,
            return_reg_16: 12,
            return_regs_32: (12, 13),
            callee_saved: vec![4, 5, 6, 7, 8, 9, 10, 11],
            caller_saved: vec![12, 13, 14, 15],
            stack_alignment: 2,
            stack_grows_down: true,
        }
    }

    /// Return the argument descriptor for the n-th argument (0-based) of
    /// the given width.
    ///
    /// `sp_offset_extra` is any additional SP displacement already applied
    /// by saved callee registers in the prologue.
    #[must_use]
    pub fn arg(&self, n: usize, width: ArgWidth, sp_offset_extra: i16) -> ArgRegister {
        // How many register slots has the first n args consumed?
        let slots_before: usize = (0..n)
            .map(|_| width.reg_count()) // simplified: assume all args same width
            .sum();

        let available_regs = self.int_arg_regs.len();
        if slots_before + width.reg_count() <= available_regs {
            let start = slots_before;
            let regs: Vec<u8> = (start..start + width.reg_count())
                .map(|i| self.int_arg_regs[i])
                .collect();
            ArgRegister::in_regs(n, regs, width)
        } else {
            // Stack-spilled argument.
            let stack_offset = self.stack_arg_offset(n, sp_offset_extra);
            ArgRegister::on_stack(n, stack_offset, width)
        }
    }

    /// Return the starting `ReturnReg` for the given return width.
    #[must_use]
    pub fn return_reg(&self, width: ArgWidth) -> ReturnReg {
        match width {
            ArgWidth::Byte | ArgWidth::Word => ReturnReg::new(vec![self.return_reg_16], width),
            ArgWidth::Dword => {
                ReturnReg::new(vec![self.return_regs_32.0, self.return_regs_32.1], width)
            }
            ArgWidth::Qword => {
                // 64-bit: use four registers around the 32-bit return pair.
                let lo = self.return_regs_32.0;
                let hi = self.return_regs_32.1;
                ReturnReg::new(vec![lo, hi, hi.saturating_add(1), hi.saturating_add(2)], width)
            }
        }
    }

    /// Compute the stack offset (from SP at function entry) for the n-th
    /// argument that is passed on the stack.
    ///
    /// MSP430 uses a 2-byte return address (pushed by CALL) and any
    /// callee-saved registers pushed in the prologue contribute
    /// `sp_offset_extra` bytes.
    ///
    /// The formula is:
    /// `offset = 2 (return address) + sp_offset_extra + stack_arg_index * 2`
    ///
    /// where `stack_arg_index` is the number of register slots already
    /// consumed minus `max_reg_args`.
    #[must_use]
    pub fn stack_arg_offset(&self, n: usize, sp_offset_extra: i16) -> i16 {
        // Number of slots consumed by register arguments.
        let regs_used = self.max_reg_args.min(n);
        let stack_index = n.saturating_sub(regs_used) as i16;
        let ret_addr_slot: i16 = 2; // CALL pushes 16-bit return address
        ret_addr_slot + sp_offset_extra + stack_index * 2
    }

    /// Return `true` if register `r` is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, r: u8) -> bool {
        self.callee_saved.contains(&r)
    }

    /// Return `true` if register `r` is caller-saved (scratch).
    #[must_use]
    pub fn is_caller_saved(&self, r: u8) -> bool {
        self.caller_saved.contains(&r)
    }

    /// Generate a human-readable description of the argument layout for a
    /// function with `n_args` word-width arguments and `prologue_save_bytes`
    /// bytes of callee-save overhead.
    #[must_use]
    pub fn describe_args(&self, n_args: usize, prologue_save_bytes: i16) -> Vec<String> {
        (0..n_args)
            .map(|i| {
                let arg = self.arg(i, ArgWidth::Word, prologue_save_bytes);
                format!("arg{i}: {}", arg.location_str())
            })
            .collect()
    }

    /// Return the set of callee-saved registers as a formatted string.
    #[must_use]
    pub fn callee_saved_str(&self) -> String {
        self.callee_saved
            .iter()
            .map(|r| format!("R{r}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Detect which callee-saved registers are used in a function but not
    /// restored on exit.
    ///
    /// `saved_on_entry` is the set of registers pushed at function entry.
    /// `restored_on_exit` is the set popped before return.
    ///
    /// Returns the set of registers that were saved but not restored.
    #[must_use]
    pub fn detect_save_restore_mismatch(
        &self,
        saved_on_entry: &[u8],
        restored_on_exit: &[u8],
    ) -> Vec<u8> {
        saved_on_entry
            .iter()
            .copied()
            .filter(|r| !restored_on_exit.contains(r))
            .collect()
    }

    /// Detect which callee-saved registers appear to be clobbered but were
    /// never restored.  `modified_regs` is the set of registers written
    /// anywhere in the function.
    ///
    /// Returns registers that should have been saved but appear not to have been.
    #[must_use]
    pub fn detect_callee_save_violations(
        &self,
        modified_regs: &[u8],
        saved_regs: &[u8],
    ) -> Vec<u8> {
        modified_regs
            .iter()
            .copied()
            .filter(|r| self.is_callee_saved(*r) && !saved_regs.contains(r))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// CallingConventionDb
// ---------------------------------------------------------------------------

/// A small database of both known MSP430 calling conventions.
pub struct CallingConventionDb {
    map: HashMap<CcKind, Msp430CallingConvention>,
}

impl CallingConventionDb {
    /// Create a database with both conventions pre-populated.
    #[must_use]
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(CcKind::Gcc, Msp430CallingConvention::gcc());
        map.insert(CcKind::Iar, Msp430CallingConvention::iar());
        Self { map }
    }

    /// Return the calling convention for the given `kind`.
    #[must_use]
    pub fn get(&self, kind: CcKind) -> Option<&Msp430CallingConvention> {
        self.map.get(&kind)
    }

    /// Return the GCC calling convention.
    #[must_use]
    pub fn gcc(&self) -> &Msp430CallingConvention {
        self.map.get(&CcKind::Gcc).unwrap()
    }

    /// Return the IAR calling convention.
    #[must_use]
    pub fn iar(&self) -> &Msp430CallingConvention {
        self.map.get(&CcKind::Iar).unwrap()
    }
}

impl Default for CallingConventionDb {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free function: stack_arg_offset
// ---------------------------------------------------------------------------

/// Compute the stack offset for the n-th argument in either calling convention.
///
/// This is a convenience wrapper for one-off calculations.
/// `sp_extra` accounts for prologue callee-save pushes.
#[must_use]
pub fn stack_arg_offset(cc: CcKind, n: usize, sp_extra: i16) -> i16 {
    match cc {
        CcKind::Gcc => Msp430CallingConvention::gcc().stack_arg_offset(n, sp_extra),
        CcKind::Iar => Msp430CallingConvention::iar().stack_arg_offset(n, sp_extra),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcc_arg_0() {
        let cc = Msp430CallingConvention::gcc();
        let a = cc.arg(0, ArgWidth::Word, 0);
        assert!(!a.on_stack);
        assert_eq!(a.regs, vec![15]); // GCC first arg in R15
    }

    #[test]
    fn test_gcc_arg_1() {
        let cc = Msp430CallingConvention::gcc();
        let a = cc.arg(1, ArgWidth::Word, 0);
        assert!(!a.on_stack);
        assert_eq!(a.regs, vec![14]);
    }

    #[test]
    fn test_gcc_arg_4_spilled() {
        let cc = Msp430CallingConvention::gcc();
        let a = cc.arg(4, ArgWidth::Word, 0);
        assert!(a.on_stack);
        // SP+2 (return address) + 0 (no prologue) = 2
        assert_eq!(a.stack_offset, Some(2));
    }

    #[test]
    fn test_gcc_arg_5_spilled_offset() {
        let cc = Msp430CallingConvention::gcc();
        let a = cc.arg(5, ArgWidth::Word, 0);
        assert!(a.on_stack);
        assert_eq!(a.stack_offset, Some(4)); // SP+2+2
    }

    #[test]
    fn test_gcc_arg_4_with_prologue() {
        let cc = Msp430CallingConvention::gcc();
        // Suppose function saves R4..R7 (4 × 2 = 8 bytes in prologue).
        let a = cc.arg(4, ArgWidth::Word, 8);
        assert!(a.on_stack);
        assert_eq!(a.stack_offset, Some(10)); // 2 + 8 + 0 * 2
    }

    #[test]
    fn test_iar_arg_0() {
        let cc = Msp430CallingConvention::iar();
        let a = cc.arg(0, ArgWidth::Word, 0);
        assert!(!a.on_stack);
        assert_eq!(a.regs, vec![12]); // IAR first arg in R12
    }

    #[test]
    fn test_iar_arg_3() {
        let cc = Msp430CallingConvention::iar();
        let a = cc.arg(3, ArgWidth::Word, 0);
        assert!(!a.on_stack);
        assert_eq!(a.regs, vec![15]);
    }

    #[test]
    fn test_gcc_return_16bit() {
        let cc = Msp430CallingConvention::gcc();
        let r = cc.return_reg(ArgWidth::Word);
        assert_eq!(r.primary_reg(), Some(15));
    }

    #[test]
    fn test_gcc_return_32bit() {
        let cc = Msp430CallingConvention::gcc();
        let r = cc.return_reg(ArgWidth::Dword);
        assert_eq!(r.regs, vec![14, 15]);
    }

    #[test]
    fn test_iar_return_16bit() {
        let cc = Msp430CallingConvention::iar();
        let r = cc.return_reg(ArgWidth::Word);
        assert_eq!(r.primary_reg(), Some(12));
    }

    #[test]
    fn test_iar_return_32bit() {
        let cc = Msp430CallingConvention::iar();
        let r = cc.return_reg(ArgWidth::Dword);
        assert_eq!(r.regs, vec![12, 13]);
    }

    #[test]
    fn test_gcc_callee_saved() {
        let cc = Msp430CallingConvention::gcc();
        assert!(cc.is_callee_saved(4));
        assert!(cc.is_callee_saved(10));
        assert!(!cc.is_callee_saved(11)); // R11 is caller-saved in GCC
        assert!(!cc.is_callee_saved(15));
    }

    #[test]
    fn test_iar_callee_saved() {
        let cc = Msp430CallingConvention::iar();
        assert!(cc.is_callee_saved(11)); // R11 is callee-saved in IAR
        assert!(!cc.is_callee_saved(12));
    }

    #[test]
    fn test_gcc_caller_saved() {
        let cc = Msp430CallingConvention::gcc();
        assert!(cc.is_caller_saved(15));
        assert!(!cc.is_caller_saved(4));
    }

    #[test]
    fn test_describe_args() {
        let cc = Msp430CallingConvention::gcc();
        let desc = cc.describe_args(2, 0);
        assert_eq!(desc.len(), 2);
        assert!(desc[0].contains("R15"));
        assert!(desc[1].contains("R14"));
    }

    #[test]
    fn test_describe_args_spilled() {
        let cc = Msp430CallingConvention::gcc();
        let desc = cc.describe_args(6, 0);
        assert!(desc[4].contains("SP"));
        assert!(desc[5].contains("SP"));
    }

    #[test]
    fn test_callee_saved_str() {
        let cc = Msp430CallingConvention::gcc();
        let s = cc.callee_saved_str();
        assert!(s.contains("R4"));
        assert!(s.contains("R10"));
    }

    #[test]
    fn test_detect_save_restore_mismatch_clean() {
        let cc = Msp430CallingConvention::gcc();
        let saved = vec![4, 5];
        let restored = vec![4, 5];
        let mis = cc.detect_save_restore_mismatch(&saved, &restored);
        assert!(mis.is_empty());
    }

    #[test]
    fn test_detect_save_restore_mismatch_leaks() {
        let cc = Msp430CallingConvention::gcc();
        let saved = vec![4, 5, 6];
        let restored = vec![4, 5]; // R6 not restored
        let mis = cc.detect_save_restore_mismatch(&saved, &restored);
        assert_eq!(mis, vec![6]);
    }

    #[test]
    fn test_detect_callee_save_violations_none() {
        let cc = Msp430CallingConvention::gcc();
        let modified = vec![15, 14]; // caller-saved registers — no violation
        let saved = vec![];
        let viol = cc.detect_callee_save_violations(&modified, &saved);
        assert!(viol.is_empty());
    }

    #[test]
    fn test_detect_callee_save_violations_found() {
        let cc = Msp430CallingConvention::gcc();
        let modified = vec![4, 5, 15]; // R4/R5 are callee-saved but not in saved
        let saved = vec![]; // function didn't save anything — violation!
        let viol = cc.detect_callee_save_violations(&modified, &saved);
        assert!(viol.contains(&4));
        assert!(viol.contains(&5));
        assert!(!viol.contains(&15)); // R15 is caller-saved
    }

    #[test]
    fn test_stack_arg_offset_free_fn_gcc() {
        // GCC, arg 4, no prologue save
        let off = stack_arg_offset(CcKind::Gcc, 4, 0);
        assert_eq!(off, 2); // just the return address
    }

    #[test]
    fn test_stack_arg_offset_free_fn_iar() {
        let off = stack_arg_offset(CcKind::Iar, 4, 0);
        assert_eq!(off, 2);
    }

    #[test]
    fn test_db_get_gcc() {
        let db = CallingConventionDb::new();
        assert_eq!(db.gcc().kind, CcKind::Gcc);
    }

    #[test]
    fn test_db_get_iar() {
        let db = CallingConventionDb::new();
        assert_eq!(db.iar().kind, CcKind::Iar);
    }

    #[test]
    fn test_cc_kind_display() {
        assert_eq!(CcKind::Gcc.to_string(), "msp430_gcc");
        assert_eq!(CcKind::Iar.to_string(), "msp430_iar");
    }

    #[test]
    fn test_arg_width_reg_count() {
        assert_eq!(ArgWidth::Word.reg_count(), 1);
        assert_eq!(ArgWidth::Dword.reg_count(), 2);
        assert_eq!(ArgWidth::Qword.reg_count(), 4);
    }

    #[test]
    fn test_return_reg_display() {
        let r = ReturnReg::new(vec![14, 15], ArgWidth::Dword);
        assert_eq!(r.display(), "R14:R15");
    }

    #[test]
    fn test_arg_register_location_str_register() {
        let a = ArgRegister::in_regs(0, vec![15], ArgWidth::Word);
        assert_eq!(a.location_str(), "R15");
    }

    #[test]
    fn test_arg_register_location_str_stack() {
        let a = ArgRegister::on_stack(4, 4, ArgWidth::Word);
        assert_eq!(a.location_str(), "[SP+4]");
    }
}
