//! Call-convention lifting.
//!
//! Provides [`CallConventionLifter`], [`LiftedCall`], [`ArgExpr`], and
//! [`lift_call_site()`] for reconstructing the argument and return-value
//! layout of every call instruction from the surrounding IL effects.

use std::collections::HashMap;
use std::fmt;

use crate::{Effect, IrExpr, LiftedInstr, LiftLevel};

// ─────────────────────────────────────────────────────────────────────────────
// CallingConventionId
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known calling conventions recognised by the lifter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallingConventionId {
    SysVAmd64,
    MsX64,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Aarch64,
    ArmAapcs,
    RiscvIlp32,
    LinuxSyscallAmd64,
    Custom(String),
}

impl CallingConventionId {
    #[must_use] 
    pub const fn as_str(&self) -> &str {
        match self {
            Self::SysVAmd64 => "sysv_amd64",
            Self::MsX64 => "ms_x64",
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::Thiscall => "thiscall",
            Self::Aarch64 => "aarch64",
            Self::ArmAapcs => "aapcs",
            Self::RiscvIlp32 => "riscv_ilp32",
            Self::LinuxSyscallAmd64 => "linux_syscall_amd64",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for CallingConventionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ParamLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Where a specific argument lives at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLocation {
    Register(String),
    StackOffset(i64),
    FloatRegister(String),
}

impl fmt::Display for ParamLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(r) => write!(f, "{r}"),
            Self::StackOffset(off) => write!(f, "[rsp+{off:#x}]"),
            Self::FloatRegister(r) => write!(f, "fp:{r}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConventionDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Static description of a calling convention.
#[derive(Debug, Clone)]
pub struct ConventionDescriptor {
    pub id: CallingConventionId,
    /// Registers used for integer / pointer arguments (in order).
    pub int_arg_regs: Vec<String>,
    /// Registers used for floating-point arguments (in order).
    pub fp_arg_regs: Vec<String>,
    /// Registers used for integer / pointer return values.
    pub int_ret_regs: Vec<String>,
    /// Registers used for floating-point return values.
    pub fp_ret_regs: Vec<String>,
    /// Registers that the callee must preserve.
    pub callee_saved: Vec<String>,
    /// Whether the caller is responsible for cleaning up stack arguments.
    pub caller_cleans_stack: bool,
    /// Minimum stack alignment at the call site (bytes).
    pub stack_alignment: u32,
    /// Registers that are zeroed or clobbered at the call site.
    pub clobbers: Vec<String>,
}

impl ConventionDescriptor {
    #[must_use] 
    pub fn sysv_amd64() -> Self {
        Self {
            id: CallingConventionId::SysVAmd64,
            int_arg_regs: vec![
                "rdi".into(), "rsi".into(), "rdx".into(),
                "rcx".into(), "r8".into(), "r9".into(),
            ],
            fp_arg_regs: vec![
                "xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into(),
                "xmm4".into(), "xmm5".into(), "xmm6".into(), "xmm7".into(),
            ],
            int_ret_regs: vec!["rax".into(), "rdx".into()],
            fp_ret_regs: vec!["xmm0".into(), "xmm1".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "r12".into(), "r13".into(),
                "r14".into(), "r15".into(),
            ],
            caller_cleans_stack: true,
            stack_alignment: 16,
            clobbers: vec![
                "rax".into(), "rcx".into(), "rdx".into(), "rsi".into(),
                "rdi".into(), "r8".into(), "r9".into(), "r10".into(), "r11".into(),
            ],
        }
    }

    #[must_use] 
    pub fn ms_x64() -> Self {
        Self {
            id: CallingConventionId::MsX64,
            int_arg_regs: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
            fp_arg_regs: vec!["xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into()],
            int_ret_regs: vec!["rax".into()],
            fp_ret_regs: vec!["xmm0".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "rdi".into(), "rsi".into(),
                "r12".into(), "r13".into(), "r14".into(), "r15".into(),
            ],
            caller_cleans_stack: true,
            stack_alignment: 16,
            clobbers: vec!["rax".into(), "rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
        }
    }

    #[must_use] 
    pub fn linux_syscall_amd64() -> Self {
        Self {
            id: CallingConventionId::LinuxSyscallAmd64,
            int_arg_regs: vec![
                "rdi".into(), "rsi".into(), "rdx".into(),
                "r10".into(), "r8".into(), "r9".into(),
            ],
            fp_arg_regs: vec![],
            int_ret_regs: vec!["rax".into()],
            fp_ret_regs: vec![],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "r12".into(), "r13".into(),
                "r14".into(), "r15".into(),
            ],
            caller_cleans_stack: true,
            stack_alignment: 16,
            clobbers: vec!["rax".into(), "rcx".into(), "r11".into()],
        }
    }

    /// Determine the location for argument index `idx` (0-based).
    #[must_use] 
    pub fn arg_location(&self, idx: usize) -> ParamLocation {
        if idx < self.int_arg_regs.len() {
            ParamLocation::Register(self.int_arg_regs[idx].clone())
        } else {
            let stack_slot = i64::try_from(idx - self.int_arg_regs.len()).unwrap_or(i64::MAX) * 8;
            ParamLocation::StackOffset(stack_slot)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArgExpr
// ─────────────────────────────────────────────────────────────────────────────

/// A reconstructed argument at a call site.
#[derive(Debug, Clone)]
pub struct ArgExpr {
    /// Argument index (0-based).
    pub index: usize,
    /// Where the argument was sourced from.
    pub location: ParamLocation,
    /// The IR expression for the value passed.
    pub value: IrExpr,
    /// Inferred byte width of the argument.
    pub width: u8,
}

impl ArgExpr {
    #[must_use] 
    pub const fn new(index: usize, location: ParamLocation, value: IrExpr, width: u8) -> Self {
        Self { index, location, value, width }
    }

    #[must_use] 
    pub fn format_arg(&self) -> String {
        format!("arg{}({}) = {}", self.index, self.location, self.value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReturnExpr
// ─────────────────────────────────────────────────────────────────────────────

/// The reconstructed return value after a call.
#[derive(Debug, Clone)]
pub struct ReturnExpr {
    pub location: ParamLocation,
    pub width: u8,
}

impl ReturnExpr {
    #[must_use] 
    pub const fn new(location: ParamLocation, width: u8) -> Self {
        Self { location, width }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiftedCall
// ─────────────────────────────────────────────────────────────────────────────

/// The complete lifted description of a call instruction.
#[derive(Debug, Clone)]
pub struct LiftedCall {
    /// Address of the call instruction.
    pub call_address: u64,
    /// Target address if statically known.
    pub target: Option<u64>,
    /// Target as an IR expression (always set).
    pub target_expr: IrExpr,
    /// Calling convention inferred for this call.
    pub convention: CallingConventionId,
    /// Reconstructed argument list.
    pub args: Vec<ArgExpr>,
    /// Expected return value location.
    pub return_value: Option<ReturnExpr>,
    /// Whether the callee is known to not return (e.g. `exit`, `abort`).
    pub is_noreturn: bool,
    /// Whether the call is a tail call.
    pub is_tail_call: bool,
}

impl LiftedCall {
    #[must_use] 
    pub const fn new(call_address: u64, target_expr: IrExpr, convention: CallingConventionId) -> Self {
        Self {
            call_address,
            target: None,
            target_expr,
            convention,
            args: Vec::new(),
            return_value: None,
            is_noreturn: false,
            is_tail_call: false,
        }
    }

    #[must_use] 
    pub const fn with_target(mut self, target: u64) -> Self {
        self.target = Some(target);
        self
    }

    #[must_use] 
    pub fn with_args(mut self, args: Vec<ArgExpr>) -> Self {
        self.args = args;
        self
    }

    #[must_use] 
    pub fn with_return(mut self, ret: ReturnExpr) -> Self {
        self.return_value = Some(ret);
        self
    }

    #[must_use] 
    pub const fn noreturn(mut self) -> Self {
        self.is_noreturn = true;
        self
    }

    #[must_use] 
    pub const fn tail_call(mut self) -> Self {
        self.is_tail_call = true;
        self
    }

    /// Format the call as a pseudo-C expression.
    #[must_use] 
    pub fn format_call(&self) -> String {
        let args_str: Vec<_> = self.args.iter().map(ArgExpr::format_arg).collect();
        let target = self.target.map_or_else(|| format!("{}", self.target_expr), |t| format!("{t:#x}"));
        format!(
            "{}: {}({}) [{}]{}{}",
            self.call_address,
            target,
            args_str.join(", "),
            self.convention,
            if self.is_tail_call { " [tail]" } else { "" },
            if self.is_noreturn { " [noreturn]" } else { "" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallConventionLifter
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstructs call-site argument layout from IL effects.
#[derive(Debug)]
pub struct CallConventionLifter {
    /// Known conventions indexed by ID.
    conventions: HashMap<String, ConventionDescriptor>,
    /// Default convention used when one cannot be inferred.
    default_convention: CallingConventionId,
    /// Known noreturn function addresses.
    noreturn_addrs: Vec<u64>,
}

impl CallConventionLifter {
    #[must_use] 
    pub fn new_x86_64() -> Self {
        let mut s = Self {
            conventions: HashMap::new(),
            default_convention: CallingConventionId::SysVAmd64,
            noreturn_addrs: Vec::new(),
        };
        let sysv = ConventionDescriptor::sysv_amd64();
        s.conventions.insert(sysv.id.as_str().to_string(), sysv);
        let ms = ConventionDescriptor::ms_x64();
        s.conventions.insert(ms.id.as_str().to_string(), ms);
        let sc = ConventionDescriptor::linux_syscall_amd64();
        s.conventions.insert(sc.id.as_str().to_string(), sc);
        s
    }

    pub fn register_convention(&mut self, desc: ConventionDescriptor) {
        self.conventions.insert(desc.id.as_str().to_string(), desc);
    }

    pub fn set_default(&mut self, id: CallingConventionId) {
        self.default_convention = id;
    }

    pub fn add_noreturn_addr(&mut self, addr: u64) {
        if !self.noreturn_addrs.contains(&addr) {
            self.noreturn_addrs.push(addr);
        }
    }

    /// Retrieve a convention descriptor by ID string.
    #[must_use] 
    pub fn get(&self, id: &str) -> Option<&ConventionDescriptor> {
        self.conventions.get(id)
    }

    /// The default convention descriptor.
    #[must_use] 
    pub fn default_desc(&self) -> Option<&ConventionDescriptor> {
        self.conventions.get(self.default_convention.as_str())
    }

    /// Minimum IL [`LiftLevel`] at which call-convention recovery is meaningful.
    ///
    /// LLIL is the lowest level at which register-write effects carry enough
    /// semantic information to recover argument values; callers can use this
    /// to gate their pipeline.
    #[must_use] 
    pub const fn min_supported_level(&self) -> LiftLevel {
        LiftLevel::Llil
    }

    /// `true` when this lifter can produce useful results for an instruction
    /// lifted at `level`.
    #[must_use] 
    pub fn supports_level(&self, level: LiftLevel) -> bool {
        level.at_least(self.min_supported_level())
    }

    /// Reconstruct arguments only when the instruction has been lifted to a
    /// level at or above [`Self::min_supported_level`].
    ///
    /// Returns `None` when the IL is too coarse (e.g. [`LiftLevel::Raw`]).
    #[must_use] 
    pub fn reconstruct_args_if_supported(
        &self,
        desc: &ConventionDescriptor,
        instr: &LiftedInstr,
        pre_call_effects: &[Effect],
    ) -> Option<Vec<ArgExpr>> {
        if !self.supports_level(instr.il_level) {
            return None;
        }
        Some(self.reconstruct_args(desc, pre_call_effects))
    }

    /// Reconstruct the arguments for a call instruction using the default
    /// calling convention and the register state encoded in the preceding IL
    /// effects.
    ///
    /// `pre_call_effects` should be the effects of the instruction(s) executed
    /// just before the call (i.e. instructions that set up arguments).
    #[must_use] 
    pub fn reconstruct_args(
        &self,
        desc: &ConventionDescriptor,
        pre_call_effects: &[Effect],
    ) -> Vec<ArgExpr> {
        let mut reg_values: HashMap<&str, IrExpr> = HashMap::new();
        for effect in pre_call_effects {
            if let Effect::RegWrite { reg, value } = effect {
                reg_values.insert(reg.as_str(), value.clone());
            }
        }

        let mut args = Vec::new();
        for (idx, reg_name) in desc.int_arg_regs.iter().enumerate() {
            if let Some(val) = reg_values.get(reg_name.as_str()) {
                args.push(ArgExpr::new(
                    idx,
                    ParamLocation::Register(reg_name.clone()),
                    val.clone(),
                    8,
                ));
            } else {
                // Implicit: argument is the current register value.
                args.push(ArgExpr::new(
                    idx,
                    ParamLocation::Register(reg_name.clone()),
                    IrExpr::Reg(reg_name.clone()),
                    8,
                ));
            }
        }
        args
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lift_call_site
// ─────────────────────────────────────────────────────────────────────────────

/// Primary entry point: reconstruct a [`LiftedCall`] from a call instruction.
///
/// `instr` must contain a [`Effect::Call`] effect.
/// `pre_call_effects` supplies the immediately preceding IL effects used to
/// identify argument values.
#[must_use] 
/// Lifts this instruction into the IL.
///
/// # Panics
///
/// Panics if internal state is inconsistent.
pub fn lift_call_site(
    lifter: &CallConventionLifter,
    instr: &LiftedInstr,
    pre_call_effects: &[Effect],
) -> Option<LiftedCall> {
    let call_effect = instr.effects.iter().find_map(|e| {
        if let Effect::Call { target } = e {
            Some(target.clone())
        } else {
            None
        }
    })?;

    let static_target = if let IrExpr::Const(addr) = &call_effect {
        Some(*addr)
    } else {
        None
    };

    let desc = lifter.default_desc().or_else(|| {
        lifter.conventions.values().next()
    })?;

    let args = lifter.reconstruct_args(desc, pre_call_effects);
    let return_value = ReturnExpr::new(
        ParamLocation::Register(
            desc.int_ret_regs.first().cloned().unwrap_or_else(|| "rax".to_string()),
        ),
        8,
    );

    let is_noreturn = static_target
        .is_some_and(|a| lifter.noreturn_addrs.contains(&a));

    let mut call_result = LiftedCall::new(instr.address, call_effect, desc.id.clone())
        .with_args(args)
        .with_return(return_value);

    if let Some(t) = static_target {
        call_result.target = Some(t);
    }
    if is_noreturn {
        call_result = call_result.noreturn();
    }

    Some(call_result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call_instr(addr: u64, target: u64) -> LiftedInstr {
        LiftedInstr {
            address: addr,
            original_mnemonic: "call".to_string(),
            ir_text: format!("call {target:#x}"),
            il_level: LiftLevel::Llil,
            effects: vec![Effect::Call { target: IrExpr::Const(target) }],
        }
    }

    #[test]
    fn lift_call_site_produces_lifted_call() {
        let lifter = CallConventionLifter::new_x86_64();
        let instr = call_instr(0x1000, 0x4000);
        let result = lift_call_site(&lifter, &instr, &[]);
        assert!(result.is_some());
        let lc = result.unwrap();
        assert_eq!(lc.call_address, 0x1000);
        assert_eq!(lc.target, Some(0x4000));
    }

    #[test]
    fn reconstructs_args_from_pre_call_effects() {
        let lifter = CallConventionLifter::new_x86_64();
        let pre = vec![
            Effect::RegWrite { reg: "rdi".to_string(), value: IrExpr::Const(42) },
            Effect::RegWrite { reg: "rsi".to_string(), value: IrExpr::Const(100) },
        ];
        let desc = lifter.get("sysv_amd64").unwrap();
        let args = lifter.reconstruct_args(desc, &pre);
        assert!(!args.is_empty());
        assert_eq!(args[0].location, ParamLocation::Register("rdi".to_string()));
        assert_eq!(args[0].value, IrExpr::Const(42));
    }

    #[test]
    fn noreturn_addr_detected() {
        let mut lifter = CallConventionLifter::new_x86_64();
        lifter.add_noreturn_addr(0x9000);
        let instr = call_instr(0x1000, 0x9000);
        let lc = lift_call_site(&lifter, &instr, &[]).unwrap();
        assert!(lc.is_noreturn);
    }

    #[test]
    fn non_call_instruction_returns_none() {
        let lifter = CallConventionLifter::new_x86_64();
        let instr = LiftedInstr {
            address: 0x1000,
            original_mnemonic: "nop".to_string(),
            ir_text: "nop".to_string(),
            il_level: LiftLevel::Llil,
            effects: vec![],
        };
        assert!(lift_call_site(&lifter, &instr, &[]).is_none());
    }

    #[test]
    fn sysv_arg_registers_in_order() {
        let desc = ConventionDescriptor::sysv_amd64();
        assert_eq!(desc.int_arg_regs[0], "rdi");
        assert_eq!(desc.int_arg_regs[1], "rsi");
        assert_eq!(desc.int_arg_regs[5], "r9");
    }

    #[test]
    fn ms_x64_arg_registers() {
        let desc = ConventionDescriptor::ms_x64();
        assert_eq!(desc.int_arg_regs[0], "rcx");
        assert_eq!(desc.int_arg_regs[3], "r9");
    }

    #[test]
    fn arg_location_stack_fallback() {
        let desc = ConventionDescriptor::sysv_amd64();
        let loc = desc.arg_location(10);
        assert!(matches!(loc, ParamLocation::StackOffset(_)));
    }

    #[test]
    fn format_call_includes_target() {
        let lc = LiftedCall::new(
            0x1000,
            IrExpr::Const(0x4000),
            CallingConventionId::SysVAmd64,
        )
        .with_target(0x4000);
        let s = lc.format_call();
        assert!(s.contains("0x4000"));
    }

    #[test]
    fn convention_id_display() {
        assert_eq!(CallingConventionId::SysVAmd64.as_str(), "sysv_amd64");
        assert_eq!(CallingConventionId::MsX64.as_str(), "ms_x64");
    }

    #[test]
    fn linux_syscall_amd64_uses_r10() {
        let desc = ConventionDescriptor::linux_syscall_amd64();
        assert_eq!(desc.int_arg_regs[3], "r10");
    }
}
