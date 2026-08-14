// rustre-arch-arm64/src/arm64_calling_conventions.rs
//
// ARM64 calling convention modeling: argument passing, return values, callee/
// caller-saved registers, and stack argument layout for AAPCS64, Apple ARM64,
// and Windows ARM64 ABI.

use ahash::AHashMap;
use std::fmt;

// ─── ArgRegister ──────────────────────────────────────────────────────────────

/// An argument or return register in the ARM64 ABI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArgRegister {
    /// Register name (e.g. `x0`, `v0`).
    pub name: String,
    /// Width in bytes.
    pub width_bytes: usize,
    /// Whether this is a floating-point / SIMD register.
    pub is_fp: bool,
    /// Argument index (0-based) in the register sequence.
    pub index: usize,
}

impl ArgRegister {
    /// Create an integer argument register.
    pub fn int(name: impl Into<String>, index: usize) -> Self {
        Self {
            name: name.into(),
            width_bytes: 8,
            is_fp: false,
            index,
        }
    }

    /// Create a 32-bit integer argument register.
    pub fn int32(name: impl Into<String>, index: usize) -> Self {
        Self {
            name: name.into(),
            width_bytes: 4,
            is_fp: false,
            index,
        }
    }

    /// Create a floating-point / SIMD argument register.
    pub fn fp(name: impl Into<String>, index: usize, width_bytes: usize) -> Self {
        Self {
            name: name.into(),
            width_bytes,
            is_fp: true,
            index,
        }
    }
}

impl fmt::Display for ArgRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ─── ReturnRegister ──────────────────────────────────────────────────────────

/// A return-value register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnRegister {
    /// Register name.
    pub name: String,
    /// Width in bytes.
    pub width_bytes: usize,
    /// Whether this is a floating-point / SIMD register.
    pub is_fp: bool,
    /// Position in multi-register return (e.g. 0 for x0, 1 for x1).
    pub position: usize,
}

impl ReturnRegister {
    pub fn int(name: impl Into<String>, position: usize) -> Self {
        Self {
            name: name.into(),
            width_bytes: 8,
            is_fp: false,
            position,
        }
    }

    pub fn fp(name: impl Into<String>, position: usize, width_bytes: usize) -> Self {
        Self {
            name: name.into(),
            width_bytes,
            is_fp: true,
            position,
        }
    }
}

impl fmt::Display for ReturnRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ─── StackArgPlacement ────────────────────────────────────────────────────────

/// Describes how a single argument is passed on the stack.
#[derive(Debug, Clone)]
pub struct StackArg {
    /// Argument index (0-based, counting all arguments).
    pub arg_index: usize,
    /// Byte offset from the stack pointer at call entry.
    pub sp_offset: i64,
    /// Size of the argument in bytes (padded to 8 bytes per AAPCS64 §6.8.2).
    pub size_bytes: usize,
    /// Whether the argument is passed by reference (pointer to copy).
    pub by_ref: bool,
}

// ─── SaveRule ─────────────────────────────────────────────────────────────────

/// Who is responsible for preserving a register across a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveRule {
    /// The caller must save this register before the call.
    CallerSaved,
    /// The callee must restore this register before returning.
    CalleeSaved,
    /// Special-purpose register (SP, PC, XZR).
    Special,
}

impl fmt::Display for SaveRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallerSaved => write!(f, "caller-saved"),
            Self::CalleeSaved => write!(f, "callee-saved"),
            Self::Special => write!(f, "special"),
        }
    }
}

// ─── Arm64CallingConvention ───────────────────────────────────────────────────

/// A complete description of an ARM64 calling convention.
#[derive(Debug, Clone)]
pub struct Arm64CallingConvention {
    /// Name of the ABI (e.g. `"aapcs64"`, `"apple_arm64"`, `"windows_arm64"`).
    pub name: String,
    /// Integer / pointer argument registers in order.
    pub int_arg_regs: Vec<ArgRegister>,
    /// Floating-point / SIMD argument registers in order.
    pub fp_arg_regs: Vec<ArgRegister>,
    /// Integer return registers.
    pub int_ret_regs: Vec<ReturnRegister>,
    /// Floating-point / SIMD return registers.
    pub fp_ret_regs: Vec<ReturnRegister>,
    /// Indirect result location register (x8).
    pub indirect_result_reg: String,
    /// Frame pointer register name.
    pub frame_pointer_reg: String,
    /// Link register name.
    pub link_register: String,
    /// Stack pointer register name.
    pub stack_pointer_reg: String,
    /// Stack alignment at call site (bytes).
    pub stack_alignment: usize,
    /// Per-register save rule.
    save_rules: AHashMap<String, SaveRule>,
    /// Notes for this ABI variant.
    pub notes: Vec<String>,
}

impl Arm64CallingConvention {
    /// Build the standard AAPCS64 calling convention.
    #[must_use] 
    pub fn aapcs64() -> Self {
        let mut cc = Self {
            name: "aapcs64".into(),
            int_arg_regs: (0..8).map(|i| ArgRegister::int(format!("x{i}"), i)).collect(),
            fp_arg_regs: (0..8).map(|i| ArgRegister::fp(format!("v{i}"), i, 16)).collect(),
            int_ret_regs: vec![
                ReturnRegister::int("x0", 0),
                ReturnRegister::int("x1", 1),
            ],
            fp_ret_regs: vec![
                ReturnRegister::fp("v0", 0, 16),
                ReturnRegister::fp("v1", 1, 16),
                ReturnRegister::fp("v2", 2, 16),
                ReturnRegister::fp("v3", 3, 16),
            ],
            indirect_result_reg: "x8".into(),
            frame_pointer_reg: "x29".into(),
            link_register: "x30".into(),
            stack_pointer_reg: "sp".into(),
            stack_alignment: 16,
            save_rules: AHashMap::new(),
            notes: vec![
                "Stack must be 16-byte aligned at public interfaces.".into(),
                "x18 is a platform register (not used by this ABI).".into(),
            ],
        };
        cc.populate_aapcs64_save_rules();
        cc
    }

    /// Build the Apple ARM64 ABI (similar to AAPCS64 with x18 reserved).
    #[must_use] 
    pub fn apple_arm64() -> Self {
        let mut cc = Self::aapcs64();
        cc.name = "apple_arm64".into();
        cc.notes = vec![
            "Apple reserves x18 for platform use.".into(),
            "Red zone: 128 bytes below SP is preserved.".into(),
            "Stack alignment same as AAPCS64 (16 bytes).".into(),
        ];
        // Apple treats x18 as callee-saved (platform register, don't touch)
        cc.save_rules.insert("x18".into(), SaveRule::Special);
        cc
    }

    /// Build the Windows ARM64 ABI.
    #[must_use] 
    pub fn windows_arm64() -> Self {
        let mut cc = Self::aapcs64();
        cc.name = "windows_arm64".into();
        cc.notes = vec![
            "Windows ARM64 uses the same registers as AAPCS64.".into(),
            "x18 is reserved by the OS (TEB pointer).".into(),
            "No red zone; the full frame is reserved on entry.".into(),
            "FP args: first 8 in v0-v7 (HFA/HVA support).".into(),
        ];
        cc.save_rules.insert("x18".into(), SaveRule::Special);
        cc
    }

    fn populate_aapcs64_save_rules(&mut self) {
        // x0-x7: caller-saved (parameter/result registers)
        for i in 0u32..8 {
            self.save_rules.insert(format!("x{i}"), SaveRule::CallerSaved);
            self.save_rules.insert(format!("w{i}"), SaveRule::CallerSaved);
        }
        // x8: indirect result — caller-saved
        self.save_rules.insert("x8".into(), SaveRule::CallerSaved);
        // x9-x15: temporary, caller-saved
        for i in 9u32..=15 {
            self.save_rules.insert(format!("x{i}"), SaveRule::CallerSaved);
        }
        // x16-x17: intra-procedure-call scratch, caller-saved
        self.save_rules.insert("x16".into(), SaveRule::CallerSaved);
        self.save_rules.insert("x17".into(), SaveRule::CallerSaved);
        // x18: platform register
        self.save_rules.insert("x18".into(), SaveRule::Special);
        // x19-x28: callee-saved
        for i in 19u32..=28 {
            self.save_rules.insert(format!("x{i}"), SaveRule::CalleeSaved);
        }
        // x29: frame pointer, callee-saved
        self.save_rules.insert("x29".into(), SaveRule::CalleeSaved);
        // x30: link register, caller-saved (the callee overwrites it via BL)
        self.save_rules.insert("x30".into(), SaveRule::CallerSaved);
        // SP: special
        self.save_rules.insert("sp".into(), SaveRule::Special);
        self.save_rules.insert("xzr".into(), SaveRule::Special);
        self.save_rules.insert("pc".into(), SaveRule::Special);

        // FP/SIMD: v0-v7 caller-saved (argument/result)
        for i in 0u32..8 {
            self.save_rules.insert(format!("v{i}"), SaveRule::CallerSaved);
            self.save_rules.insert(format!("d{i}"), SaveRule::CallerSaved);
            self.save_rules.insert(format!("s{i}"), SaveRule::CallerSaved);
        }
        // v8-v15: callee-saved (low 64 bits only)
        for i in 8u32..=15 {
            self.save_rules.insert(format!("v{i}"), SaveRule::CalleeSaved);
            self.save_rules.insert(format!("d{i}"), SaveRule::CalleeSaved);
            self.save_rules.insert(format!("s{i}"), SaveRule::CalleeSaved);
        }
        // v16-v31: temporary, caller-saved
        for i in 16u32..32 {
            self.save_rules.insert(format!("v{i}"), SaveRule::CallerSaved);
            self.save_rules.insert(format!("d{i}"), SaveRule::CallerSaved);
        }
    }

    /// Return the save rule for `register_name`.
    #[must_use] 
    pub fn save_rule(&self, register_name: &str) -> SaveRule {
        self.save_rules
            .get(register_name)
            .copied()
            .unwrap_or(SaveRule::CallerSaved)
    }

    /// Return the stack byte offset for the nth stack argument (0-based index
    /// into the overflow arguments, i.e. argument #8 and beyond).
    ///
    /// Per AAPCS64 §6.8.2, stack arguments are passed in natural order
    /// starting at SP+0, each padded to a multiple of 8 bytes (with a minimum
    /// of 8 bytes for types smaller than a pointer).
    #[must_use] 
    pub fn stack_arg_offset(&self, stack_arg_index: usize, arg_size_bytes: usize) -> i64 {
        // Each argument is padded to the next multiple of 8 bytes.
        let slot_size = (arg_size_bytes + 7) & !7;
        let mut offset: i64 = 0;
        for _ in 0..stack_arg_index {
            offset += slot_size as i64;
        }
        offset
    }

    /// Compute the full stack layout for a function call with `total_args` arguments
    /// of the given sizes. Returns a list of stack argument descriptors.
    #[must_use] 
    pub fn compute_stack_layout(
        &self,
        total_args: usize,
        arg_sizes: &[usize],
    ) -> Vec<StackArg> {
        let reg_count = self.int_arg_regs.len(); // typically 8
        if total_args <= reg_count {
            return Vec::new(); // all fit in registers
        }

        let mut layout = Vec::new();
        let mut sp_offset: i64 = 0;

        for idx in reg_count..total_args {
            let size = arg_sizes.get(idx).copied().unwrap_or(8);
            let padded = (size + 7) & !7;
            // Large composite types (> 16 bytes) are passed by reference.
            let by_ref = size > 16;
            let actual_size = if by_ref { 8 } else { padded };

            layout.push(StackArg {
                arg_index: idx,
                sp_offset,
                size_bytes: actual_size,
                by_ref,
            });
            sp_offset += actual_size as i64;
        }
        layout
    }

    /// Return `true` when `register_name` is a callee-saved register.
    #[must_use] 
    pub fn is_callee_saved(&self, register_name: &str) -> bool {
        self.save_rule(register_name) == SaveRule::CalleeSaved
    }

    /// Return `true` when `register_name` is a caller-saved register.
    #[must_use] 
    pub fn is_caller_saved(&self, register_name: &str) -> bool {
        self.save_rule(register_name) == SaveRule::CallerSaved
    }

    /// Return all callee-saved register names.
    #[must_use] 
    pub fn callee_saved_registers(&self) -> Vec<&str> {
        let mut regs: Vec<&str> = self
            .save_rules
            .iter()
            .filter(|(_, rule)| **rule == SaveRule::CalleeSaved)
            .map(|(name, _)| name.as_str())
            .collect();
        regs.sort_unstable();
        regs
    }

    /// Return the argument register name for argument `idx` (0-based integer argument).
    #[must_use] 
    pub fn int_arg_reg(&self, idx: usize) -> Option<&str> {
        self.int_arg_regs.get(idx).map(|r| r.name.as_str())
    }

    /// Return the FP argument register name for argument `idx`.
    #[must_use] 
    pub fn fp_arg_reg(&self, idx: usize) -> Option<&str> {
        self.fp_arg_regs.get(idx).map(|r| r.name.as_str())
    }

    /// Describe where argument `idx` lives (register name or stack offset).
    #[must_use] 
    pub fn arg_location(&self, idx: usize) -> ArgLocation {
        if idx < self.int_arg_regs.len() {
            ArgLocation::Register(self.int_arg_regs[idx].name.clone())
        } else {
            let stack_idx = idx - self.int_arg_regs.len();
            let offset = self.stack_arg_offset(stack_idx, 8);
            ArgLocation::Stack { sp_offset: offset, size_bytes: 8 }
        }
    }
}

/// Describes where a single argument is located at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgLocation {
    /// Passed in a named register.
    Register(String),
    /// Passed on the stack at `sp_offset` bytes from SP at call entry.
    Stack { sp_offset: i64, size_bytes: usize },
}

impl fmt::Display for ArgLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "reg:{r}"),
            Self::Stack { sp_offset, size_bytes } => {
                write!(f, "stack:[sp+{sp_offset}] ({size_bytes}B)")
            }
        }
    }
}

impl fmt::Display for Arm64CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Arm64CallingConvention({}, int_args={}, fp_args={}, align={})",
            self.name,
            self.int_arg_regs.len(),
            self.fp_arg_regs.len(),
            self.stack_alignment
        )
    }
}

// ─── CallingConventionRegistry ────────────────────────────────────────────────

/// Registry of all known ARM64 calling conventions.
#[derive(Debug, Default)]
pub struct CallingConventionRegistry {
    conventions: AHashMap<String, Arm64CallingConvention>,
}

impl CallingConventionRegistry {
    /// Create a registry populated with the standard ARM64 ABIs.
    #[must_use] 
    pub fn standard() -> Self {
        let mut r = Self::default();
        r.register(Arm64CallingConvention::aapcs64());
        r.register(Arm64CallingConvention::apple_arm64());
        r.register(Arm64CallingConvention::windows_arm64());
        r
    }

    /// Register a calling convention.
    pub fn register(&mut self, cc: Arm64CallingConvention) {
        self.conventions.insert(cc.name.clone(), cc);
    }

    /// Look up a calling convention by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&Arm64CallingConvention> {
        self.conventions.get(name)
    }

    /// Return all registered convention names.
    #[must_use] 
    pub fn names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.conventions.keys().map(std::string::String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// Return the number of registered conventions.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.conventions.len()
    }

    /// Return `true` when the registry is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.conventions.is_empty()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn aapcs64() -> Arm64CallingConvention {
        Arm64CallingConvention::aapcs64()
    }

    #[test]
    fn aapcs64_has_eight_int_args() {
        let cc = aapcs64();
        assert_eq!(cc.int_arg_regs.len(), 8);
        assert_eq!(cc.int_arg_regs[0].name, "x0");
        assert_eq!(cc.int_arg_regs[7].name, "x7");
    }

    #[test]
    fn aapcs64_has_eight_fp_args() {
        let cc = aapcs64();
        assert_eq!(cc.fp_arg_regs.len(), 8);
        assert_eq!(cc.fp_arg_regs[0].name, "v0");
    }

    #[test]
    fn aapcs64_return_registers() {
        let cc = aapcs64();
        assert_eq!(cc.int_ret_regs.len(), 2);
        assert_eq!(cc.int_ret_regs[0].name, "x0");
        assert_eq!(cc.int_ret_regs[1].name, "x1");
    }

    #[test]
    fn aapcs64_frame_pointer_and_link() {
        let cc = aapcs64();
        assert_eq!(cc.frame_pointer_reg, "x29");
        assert_eq!(cc.link_register, "x30");
        assert_eq!(cc.indirect_result_reg, "x8");
    }

    #[test]
    fn aapcs64_stack_alignment() {
        assert_eq!(aapcs64().stack_alignment, 16);
    }

    #[test]
    fn callee_saved_x19_to_x28() {
        let cc = aapcs64();
        for i in 19..=28 {
            assert!(
                cc.is_callee_saved(&format!("x{i}")),
                "x{i} should be callee-saved"
            );
        }
    }

    #[test]
    fn caller_saved_x0_to_x8() {
        let cc = aapcs64();
        for i in 0..=8 {
            assert!(
                cc.is_caller_saved(&format!("x{i}")),
                "x{i} should be caller-saved"
            );
        }
    }

    #[test]
    fn x29_callee_saved() {
        let cc = aapcs64();
        assert!(cc.is_callee_saved("x29"));
    }

    #[test]
    fn sp_is_special() {
        let cc = aapcs64();
        assert_eq!(cc.save_rule("sp"), SaveRule::Special);
    }

    #[test]
    fn v8_v15_callee_saved() {
        let cc = aapcs64();
        for i in 8..=15 {
            assert!(cc.is_callee_saved(&format!("v{i}")));
            assert!(cc.is_callee_saved(&format!("d{i}")));
        }
    }

    #[test]
    fn v0_v7_caller_saved() {
        let cc = aapcs64();
        for i in 0..8 {
            assert!(cc.is_caller_saved(&format!("v{i}")));
        }
    }

    #[test]
    fn stack_arg_offset_first() {
        let cc = aapcs64();
        // First stack argument: offset 0
        assert_eq!(cc.stack_arg_offset(0, 8), 0);
    }

    #[test]
    fn stack_arg_offset_second() {
        let cc = aapcs64();
        // Second stack argument: offset 8 (first arg is 8 bytes)
        assert_eq!(cc.stack_arg_offset(1, 8), 8);
    }

    #[test]
    fn stack_arg_offset_4byte_padded_to_8() {
        let cc = aapcs64();
        // A 4-byte arg is padded to 8 bytes
        let offset = cc.stack_arg_offset(0, 4);
        assert_eq!(offset, 0);
        let next = cc.stack_arg_offset(1, 4);
        assert_eq!(next, 8); // padded size
    }

    #[test]
    fn arg_location_register_for_first_8() {
        let cc = aapcs64();
        for i in 0..8 {
            let loc = cc.arg_location(i);
            assert!(
                matches!(loc, ArgLocation::Register(_)),
                "arg {i} should be in a register"
            );
        }
    }

    #[test]
    fn arg_location_stack_for_9th() {
        let cc = aapcs64();
        let loc = cc.arg_location(8);
        assert!(
            matches!(loc, ArgLocation::Stack { sp_offset: 0, .. }),
            "9th arg should be at sp+0"
        );
    }

    #[test]
    fn compute_stack_layout_no_overflow() {
        let cc = aapcs64();
        let layout = cc.compute_stack_layout(4, &[8, 8, 8, 8]);
        assert!(layout.is_empty()); // all fit in x0-x3
    }

    #[test]
    fn compute_stack_layout_with_overflow() {
        let cc = aapcs64();
        let sizes: Vec<usize> = vec![8; 10]; // 10 args
        let layout = cc.compute_stack_layout(10, &sizes);
        assert_eq!(layout.len(), 2); // args 8 and 9
        assert_eq!(layout[0].sp_offset, 0);
        assert_eq!(layout[1].sp_offset, 8);
    }

    #[test]
    fn compute_stack_layout_large_arg_by_ref() {
        let cc = aapcs64();
        let sizes: Vec<usize> = (0..9).map(|i| if i == 8 { 32 } else { 8 }).collect();
        let layout = cc.compute_stack_layout(9, &sizes);
        assert_eq!(layout.len(), 1);
        assert!(layout[0].by_ref); // 32-byte arg passed by reference
    }

    #[test]
    fn callee_saved_registers_list_nonempty() {
        let cc = aapcs64();
        let list = cc.callee_saved_registers();
        assert!(!list.is_empty());
        assert!(list.contains(&"x19"));
        assert!(list.contains(&"x29"));
    }

    #[test]
    fn int_arg_reg_helper() {
        let cc = aapcs64();
        assert_eq!(cc.int_arg_reg(0), Some("x0"));
        assert_eq!(cc.int_arg_reg(7), Some("x7"));
        assert_eq!(cc.int_arg_reg(8), None);
    }

    #[test]
    fn fp_arg_reg_helper() {
        let cc = aapcs64();
        assert_eq!(cc.fp_arg_reg(0), Some("v0"));
        assert_eq!(cc.fp_arg_reg(7), Some("v7"));
        assert_eq!(cc.fp_arg_reg(8), None);
    }

    #[test]
    fn apple_arm64_x18_special() {
        let cc = Arm64CallingConvention::apple_arm64();
        assert_eq!(cc.save_rule("x18"), SaveRule::Special);
    }

    #[test]
    fn windows_arm64_name() {
        let cc = Arm64CallingConvention::windows_arm64();
        assert_eq!(cc.name, "windows_arm64");
    }

    #[test]
    fn registry_standard_has_three_abis() {
        let reg = CallingConventionRegistry::standard();
        assert_eq!(reg.len(), 3);
        assert!(reg.get("aapcs64").is_some());
        assert!(reg.get("apple_arm64").is_some());
        assert!(reg.get("windows_arm64").is_some());
    }

    #[test]
    fn registry_names_sorted() {
        let reg = CallingConventionRegistry::standard();
        let names = reg.names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn save_rule_display() {
        assert_eq!(SaveRule::CallerSaved.to_string(), "caller-saved");
        assert_eq!(SaveRule::CalleeSaved.to_string(), "callee-saved");
        assert_eq!(SaveRule::Special.to_string(), "special");
    }

    #[test]
    fn arg_location_display() {
        let reg = ArgLocation::Register("x0".into());
        assert!(reg.to_string().contains("x0"));

        let stack = ArgLocation::Stack { sp_offset: 8, size_bytes: 8 };
        assert!(stack.to_string().contains("sp+8"));
    }
}
