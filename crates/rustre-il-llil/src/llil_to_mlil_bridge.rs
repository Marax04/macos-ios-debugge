//! LLIL → MLIL bridge — elevates non-SSA LLIL to SSA-ready form.
//!
//! # Elevation algorithm
//! 1. **Calling-convention resolution** — maps physical register assignments
//!    (e.g. `rdi`, `rsi`, `a0`) to named parameters based on the calling
//!    convention recorded for the function.
//! 2. **Stack frame analysis** — tracks `[rsp+N]` / `[sp+N]` accesses and
//!    assigns each unique offset a named local variable (`local_N`).
//! 3. **Flag semantics lifting** — replaces raw flag reads (`CF`, `ZF`, …)
//!    with typed condition expressions derived from the most recent
//!    flag-defining instruction.
//! 4. **SSA preparation** — renames registers in preparation for the Braun
//!    online SSA constructor (see `rustre-il-mlil::ssa_reconstruction`).
//!
//! # Output
//! The output is a renamed copy of the [`LlilFunction`] with named parameters,
//! named locals, and flag reads replaced by condition expressions.

use std::collections::HashMap;

use crate::{LlilAnnotatedInstr, LlilBasicBlock, LlilExpr, LlilFunction, LlilInstruction,
            LlilRegister, Size};

// ─────────────────────────────────────────────────────────────────────────────
// CallingConvention
// ─────────────────────────────────────────────────────────────────────────────

/// Describes how physical registers map to named function parameters and
/// return values.
#[derive(Debug, Clone)]
pub struct CallingConvention {
    /// Argument registers in order (index = parameter index).
    pub arg_registers: Vec<String>,
    /// Registers used to return values (first = primary return value).
    pub return_registers: Vec<String>,
    /// Callee-saved registers (must be restored on return).
    pub callee_saved: Vec<String>,
    /// Stack alignment in bytes.
    pub stack_align: usize,
    /// Human-readable name.
    pub name: &'static str,
}

impl CallingConvention {
    /// System V AMD64 ABI (Linux/macOS x86-64).
    #[must_use] 
    pub fn sysv_amd64() -> Self {
        Self {
            arg_registers: vec![
                "rdi".into(), "rsi".into(), "rdx".into(),
                "rcx".into(), "r8".into(), "r9".into(),
            ],
            return_registers: vec!["rax".into(), "rdx".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "r12".into(),
                "r13".into(), "r14".into(), "r15".into(),
            ],
            stack_align: 16,
            name: "SysV AMD64",
        }
    }

    /// Microsoft x64 ABI.
    #[must_use] 
    pub fn ms_x64() -> Self {
        Self {
            arg_registers: vec![
                "rcx".into(), "rdx".into(), "r8".into(), "r9".into(),
            ],
            return_registers: vec!["rax".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "rdi".into(), "rsi".into(),
                "r12".into(), "r13".into(), "r14".into(), "r15".into(),
            ],
            stack_align: 16,
            name: "Microsoft x64",
        }
    }

    /// RISC-V LP64 (a0..a7 for args, a0/a1 for return).
    #[must_use] 
    pub fn riscv_lp64() -> Self {
        Self {
            arg_registers: vec![
                "a0".into(), "a1".into(), "a2".into(), "a3".into(),
                "a4".into(), "a5".into(), "a6".into(), "a7".into(),
            ],
            return_registers: vec!["a0".into(), "a1".into()],
            callee_saved: vec![
                "s0".into(), "s1".into(), "s2".into(), "s3".into(),
                "s4".into(), "s5".into(), "s6".into(), "s7".into(),
                "s8".into(), "s9".into(), "s10".into(), "s11".into(),
            ],
            stack_align: 16,
            name: "RISC-V LP64",
        }
    }

    /// `AArch64` AAPCS64.
    #[must_use] 
    pub fn aarch64() -> Self {
        Self {
            arg_registers: vec![
                "x0".into(), "x1".into(), "x2".into(), "x3".into(),
                "x4".into(), "x5".into(), "x6".into(), "x7".into(),
            ],
            return_registers: vec!["x0".into(), "x1".into()],
            callee_saved: vec![
                "x19".into(), "x20".into(), "x21".into(), "x22".into(),
                "x23".into(), "x24".into(), "x25".into(), "x26".into(),
                "x27".into(), "x28".into(),
            ],
            stack_align: 16,
            name: "AArch64 AAPCS64",
        }
    }

    /// Returns the parameter name for argument index `i` (e.g. `"arg0"`).
    #[must_use]
    pub fn param_name(&self, i: usize) -> String {
        format!("arg{i}")
    }

    /// Returns the name to use for the primary return value.
    #[must_use]
    pub const fn return_name(&self) -> &'static str {
        "retval"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackFrame
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks stack accesses and assigns local variable names.
#[derive(Debug, Clone, Default)]
pub struct StackFrame {
    /// Map from byte offset → local variable name.
    pub locals: HashMap<i64, String>,
    next_idx: usize,
    /// Frame pointer register name (e.g. `"rbp"`, `"fp"`).
    pub frame_pointer: Option<String>,
    /// Stack pointer register name (e.g. `"rsp"`, `"sp"`).
    pub stack_pointer: String,
}

impl StackFrame {
    /// Create a frame tracker for an x86-64 function.
    #[must_use] 
    pub fn x86_64() -> Self {
        Self {
            locals: HashMap::new(),
            next_idx: 0,
            frame_pointer: Some("rbp".to_owned()),
            stack_pointer: "rsp".to_owned(),
        }
    }

    /// Create a frame tracker for an `AArch64` function.
    #[must_use] 
    pub fn aarch64() -> Self {
        Self {
            locals: HashMap::new(),
            next_idx: 0,
            frame_pointer: Some("x29".to_owned()),
            stack_pointer: "sp".to_owned(),
        }
    }

    /// Create a frame tracker for a RISC-V function.
    #[must_use] 
    pub fn riscv() -> Self {
        Self {
            locals: HashMap::new(),
            next_idx: 0,
            frame_pointer: Some("s0".to_owned()),
            stack_pointer: "sp".to_owned(),
        }
    }

    /// Look up or allocate a local variable name for `offset`.
    pub fn local_at(&mut self, offset: i64) -> String {
        if let Some(name) = self.locals.get(&offset) {
            return name.clone();
        }
        let name = format!("local_{}", self.next_idx);
        self.next_idx += 1;
        self.locals.insert(offset, name.clone());
        name
    }

    /// Returns `true` if `reg_name` is the frame pointer.
    #[must_use] 
    pub fn is_fp(&self, reg_name: &str) -> bool {
        self.frame_pointer.as_deref() == Some(reg_name)
    }

    /// Returns `true` if `reg_name` is the stack pointer.
    #[must_use] 
    pub fn is_sp(&self, reg_name: &str) -> bool {
        self.stack_pointer == reg_name
    }

    /// Try to interpret `expr` as `(fp|sp) + const_offset`.
    /// Returns the signed offset if successful.
    #[must_use] 
    pub fn extract_frame_offset(&self, expr: &LlilExpr) -> Option<i64> {
        match expr {
            LlilExpr::Add { left, right, .. } => {
                match (left.as_ref(), right.as_ref()) {
                    // SP/FP on the left, constant on the right.
                    (LlilExpr::StackPointer(_), LlilExpr::Const { value, .. }) => {
                        Some((*value).cast_signed())
                    }
                    (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value, .. })
                        if self.is_fp(&reg.name()) || self.is_sp(&reg.name()) =>
                    {
                        Some((*value).cast_signed())
                    }
                    _ => None,
                }
            }
            LlilExpr::Sub { left, right, .. } => {
                match (left.as_ref(), right.as_ref()) {
                    (LlilExpr::StackPointer(_), LlilExpr::Const { value, .. }) => {
                        Some(-((*value).cast_signed()))
                    }
                    (LlilExpr::RegisterRef { reg, .. }, LlilExpr::Const { value, .. })
                        if self.is_fp(&reg.name()) || self.is_sp(&reg.name()) =>
                    {
                        Some(-((*value).cast_signed()))
                    }
                    _ => None,
                }
            }
            LlilExpr::StackPointer(_) => Some(0),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagState — lifts flag reads to typed conditions
// ─────────────────────────────────────────────────────────────────────────────

/// State tracking the most recent condition expression for each flag.
#[derive(Debug, Clone, Default)]
pub struct FlagState {
    /// Latest condition expression for each flag name.
    pub defs: HashMap<String, LlilExpr>,
}

impl FlagState {
    /// Record that `flag` is now defined as `expr`.
    pub fn define(&mut self, flag: impl Into<String>, expr: LlilExpr) {
        self.defs.insert(flag.into(), expr);
    }

    /// Look up the current condition expression for `flag`.
    #[must_use] 
    pub fn get(&self, flag: &str) -> Option<&LlilExpr> {
        self.defs.get(flag)
    }

    /// Update flag state from a comparison: ZF ← (a == b), CF ← (a <ᵤ b).
    pub fn update_from_cmp(&mut self, left: &LlilExpr, right: &LlilExpr) {
        self.define("ZF", LlilExpr::CmpEq(
            Box::new(left.clone()),
            Box::new(right.clone()),
        ));
        self.define("CF", LlilExpr::CmpUlt(
            Box::new(left.clone()),
            Box::new(right.clone()),
        ));
        // x86 SF after `cmp a,b` is the sign bit of (a - b), NOT the sign of
        // `a` alone (e.g. cmp 1,2 sets SF because 1-2 < 0).
        self.define("SF", LlilExpr::CmpSlt(
            Box::new(LlilExpr::SubT(
                Box::new(left.clone()),
                Box::new(right.clone()),
                Size::QWord,
            )),
            Box::new(LlilExpr::Const { value: 0, size: Size::QWord }),
        ));
        self.define("NF", LlilExpr::CmpSlt(
            Box::new(left.clone()),
            Box::new(right.clone()),
        ));
    }

    /// Update flag state from an arithmetic result: ZF ← (result == 0).
    pub fn update_from_result(&mut self, result: &LlilExpr) {
        self.define("ZF", LlilExpr::CmpEq(
            Box::new(result.clone()),
            Box::new(LlilExpr::Const { value: 0, size: Size::QWord }),
        ));
    }

    /// Resolve a flag read to its condition expression.
    #[must_use] 
    pub fn resolve(&self, flag: &str) -> LlilExpr {
        self.defs.get(flag).cloned().unwrap_or_else(|| LlilExpr::Flag(flag.to_owned()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BridgeConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the LLIL→MLIL elevation pass.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Calling convention to use for parameter naming.
    pub calling_convention: CallingConvention,
    /// Whether to lift flag reads to typed conditions.
    pub lift_flags: bool,
    /// Whether to name stack slots as `local_N`.
    pub name_stack_slots: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            calling_convention: CallingConvention::sysv_amd64(),
            lift_flags: true,
            name_stack_slots: true,
        }
    }
}

impl BridgeConfig {
    /// Create a config for x86-64 with System V ABI.
    #[must_use] 
    pub fn x86_64_linux() -> Self {
        Self::default()
    }

    /// Create a config for `AArch64`.
    #[must_use] 
    pub fn aarch64() -> Self {
        Self {
            calling_convention: CallingConvention::aarch64(),
            lift_flags: true,
            name_stack_slots: true,
        }
    }

    /// Create a config for RISC-V.
    #[must_use] 
    pub fn riscv() -> Self {
        Self {
            calling_convention: CallingConvention::riscv_lp64(),
            lift_flags: false,
            name_stack_slots: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilToMlilBridge
// ─────────────────────────────────────────────────────────────────────────────

/// Elevates a non-SSA [`LlilFunction`] to near-MLIL form.
///
/// Performs three preparatory transformations:
/// 1. Renames argument registers to named parameters (`arg0`, `arg1`, …).
/// 2. Replaces stack-relative register references with named locals.
/// 3. Lifts flag reads to typed condition expressions.
#[derive(Debug, Clone)]
pub struct LlilToMlilBridge {
    pub config: BridgeConfig,
}

impl LlilToMlilBridge {
    /// Create with the given config.
    #[must_use] 
    pub const fn new(config: BridgeConfig) -> Self {
        Self { config }
    }

    /// Elevate `func` to near-MLIL form.  Returns a renamed copy.
    #[must_use] 
    pub fn elevate(&self, func: &LlilFunction) -> LlilFunction {
        let mut frame = self.make_frame();
        let mut flag_state = FlagState::default();

        // Build argument register → parameter name map.
        let arg_map: HashMap<String, String> = self
            .config
            .calling_convention
            .arg_registers
            .iter()
            .enumerate()
            .map(|(i, reg)| (reg.clone(), self.config.calling_convention.param_name(i)))
            .collect();

        // Return register → "retval" map.
        let ret_map: HashMap<String, String> = self
            .config
            .calling_convention
            .return_registers
            .iter()
            .enumerate()
            .map(|(i, reg)| {
                (
                    reg.clone(),
                    if i == 0 { "retval".to_owned() } else { format!("retval{i}") },
                )
            })
            .collect();

        let mut new_blocks: Vec<LlilBasicBlock> = Vec::with_capacity(func.blocks.len());

        for block in &func.blocks {
            let mut new_instrs: Vec<LlilAnnotatedInstr> =
                Vec::with_capacity(block.instrs.len());
            for ann in &block.instrs {
                let new_instr = self.elevate_instr(
                    &ann.instr,
                    &arg_map,
                    &ret_map,
                    &mut frame,
                    &mut flag_state,
                );
                new_instrs.push(LlilAnnotatedInstr {
                    address: ann.address,
                    size: ann.size,
                    length: ann.length,
                    instr: new_instr,
                });
            }
            new_blocks.push(LlilBasicBlock {
                start: block.start,
                end: block.end,
                id: block.id,
                successors: block.successors.clone(),
                instrs: new_instrs,
            });
        }

        LlilFunction {
            entry: func.entry,
            blocks: new_blocks,
            temp_count: func.temp_count,
            name: func.name.clone(),
            instructions: func.instructions.clone(), // flat stream: preserve as-is
            address: func.address,
            id: func.id,
            ..Default::default()
        }
    }

    fn make_frame(&self) -> StackFrame {
        match self.config.calling_convention.name {
            n if n.contains("AMD64") || n.contains("x64") => StackFrame::x86_64(),
            n if n.contains("AArch64") => StackFrame::aarch64(),
            _ => StackFrame::riscv(),
        }
    }

    fn elevate_instr(
        &self,
        instr: &LlilInstruction,
        arg_map: &HashMap<String, String>,
        ret_map: &HashMap<String, String>,
        frame: &mut StackFrame,
        flag_state: &mut FlagState,
    ) -> LlilInstruction {
        match instr {
            LlilInstruction::SetReg { dest, size, value } => {
                // Update flags if this looks like a CMP (SetFlag follows).
                let new_val = self.elevate_expr(value, arg_map, ret_map, frame, flag_state);
                let new_dest = rename_reg(dest, arg_map, ret_map);
                LlilInstruction::SetReg {
                    dest: new_dest,
                    size: *size,
                    value: new_val,
                }
            }
            LlilInstruction::SetFlag { name, src } => {
                let new_src = self.elevate_expr(src, arg_map, ret_map, frame, flag_state);
                flag_state.define(name.as_str(), new_src.clone());
                LlilInstruction::SetFlag {
                    name: name.clone(),
                    src: new_src,
                }
            }
            LlilInstruction::Store { addr, size, value } => {
                LlilInstruction::Store {
                    addr: self.elevate_expr(addr, arg_map, ret_map, frame, flag_state),
                    size: *size,
                    value: self.elevate_expr(value, arg_map, ret_map, frame, flag_state),
                }
            }
            LlilInstruction::Load { dest, size, addr } => {
                let new_addr = self.elevate_expr(addr, arg_map, ret_map, frame, flag_state);
                // Name stack slots.
                let new_dest = if self.config.name_stack_slots {
                    frame.extract_frame_offset(&new_addr).map_or_else(
                        || rename_reg(dest, arg_map, ret_map),
                        |off| LlilRegister::Concrete(frame.local_at(off)),
                    )
                } else {
                    rename_reg(dest, arg_map, ret_map)
                };
                LlilInstruction::Load {
                    dest: new_dest,
                    size: *size,
                    addr: new_addr,
                }
            }
            LlilInstruction::Jump(target) => {
                LlilInstruction::Jump(
                    self.elevate_expr(target, arg_map, ret_map, frame, flag_state),
                )
            }
            LlilInstruction::Call(target) => {
                LlilInstruction::Call(
                    self.elevate_expr(target, arg_map, ret_map, frame, flag_state),
                )
            }
            LlilInstruction::Return { value } => {
                LlilInstruction::Return {
                    value: value.as_ref().map(|v| {
                        self.elevate_expr(v, arg_map, ret_map, frame, flag_state)
                    }),
                }
            }
            LlilInstruction::CondJump { cond, true_dest, false_dest } => {
                LlilInstruction::CondJump {
                    cond: self.elevate_expr(cond, arg_map, ret_map, frame, flag_state),
                    true_dest: *true_dest,
                    false_dest: *false_dest,
                }
            }
            other => other.clone(),
        }
    }

    fn elevate_expr(
        &self,
        expr: &LlilExpr,
        arg_map: &HashMap<String, String>,
        ret_map: &HashMap<String, String>,
        frame: &mut StackFrame,
        flag_state: &FlagState,
    ) -> LlilExpr {
        match expr {
            // Rename register references.
            LlilExpr::RegisterRef { reg, size } => {
                let new_name = arg_map.get(&reg.name())
                    .or_else(|| ret_map.get(&reg.name()))
                    .cloned()
                    .unwrap_or_else(|| reg.name());
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(new_name),
                    size: *size,
                }
            }
            // Lift flag reads.
            LlilExpr::Flag(flag) if self.config.lift_flags => {
                flag_state.resolve(flag)
            }
            // Load: name stack slots.
            LlilExpr::Load { addr, size } => {
                let new_addr = self.elevate_expr(addr, arg_map, ret_map, frame, flag_state);
                if self.config.name_stack_slots
                    && let Some(off) = frame.extract_frame_offset(&new_addr) {
                        let local = frame.local_at(off);
                        return LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(local),
                            size: *size,
                        };
                    }
                LlilExpr::Load {
                    addr: Box::new(new_addr),
                    size: *size,
                }
            }
            // Recurse into binary expressions.
            LlilExpr::Add { left, right, size } => LlilExpr::Add {
                left: Box::new(self.elevate_expr(left, arg_map, ret_map, frame, flag_state)),
                right: Box::new(self.elevate_expr(right, arg_map, ret_map, frame, flag_state)),
                size: *size,
            },
            LlilExpr::Sub { left, right, size } => LlilExpr::Sub {
                left: Box::new(self.elevate_expr(left, arg_map, ret_map, frame, flag_state)),
                right: Box::new(self.elevate_expr(right, arg_map, ret_map, frame, flag_state)),
                size: *size,
            },
            LlilExpr::Mul { left, right, size } => LlilExpr::Mul {
                left: Box::new(self.elevate_expr(left, arg_map, ret_map, frame, flag_state)),
                right: Box::new(self.elevate_expr(right, arg_map, ret_map, frame, flag_state)),
                size: *size,
            },
            LlilExpr::CmpEq(l, r) => LlilExpr::CmpEq(
                Box::new(self.elevate_expr(l, arg_map, ret_map, frame, flag_state)),
                Box::new(self.elevate_expr(r, arg_map, ret_map, frame, flag_state)),
            ),
            LlilExpr::CmpSlt(l, r) => LlilExpr::CmpSlt(
                Box::new(self.elevate_expr(l, arg_map, ret_map, frame, flag_state)),
                Box::new(self.elevate_expr(r, arg_map, ret_map, frame, flag_state)),
            ),
            LlilExpr::CmpUlt(l, r) => LlilExpr::CmpUlt(
                Box::new(self.elevate_expr(l, arg_map, ret_map, frame, flag_state)),
                Box::new(self.elevate_expr(r, arg_map, ret_map, frame, flag_state)),
            ),
            other => other.clone(),
        }
    }
}

/// Rename a register according to the argument/return maps.
fn rename_reg(
    reg: &LlilRegister,
    arg_map: &HashMap<String, String>,
    ret_map: &HashMap<String, String>,
) -> LlilRegister {
    let name = reg.name();
    arg_map.get(&name)
        .map(|param| LlilRegister::Concrete(param.clone()))
        .or_else(|| ret_map.get(&name).map(|ret| LlilRegister::Concrete(ret.clone())))
        .unwrap_or_else(|| reg.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// ElevationStats — metrics from a bridge pass
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics collected during function elevation.
#[derive(Debug, Clone, Default)]
pub struct ElevationStats {
    /// Number of argument register references renamed.
    pub args_renamed: usize,
    /// Number of stack slots named.
    pub stack_slots_named: usize,
    /// Number of flag reads replaced with condition expressions.
    pub flags_lifted: usize,
    /// Total instructions processed.
    pub instrs_processed: usize,
}

impl ElevationStats {
    /// Return `true` if any transformations were applied.
    #[must_use]
    pub const fn any_changes(&self) -> bool {
        self.args_renamed > 0 || self.stack_slots_named > 0 || self.flags_lifted > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    #[test]
    fn test_stack_frame_local_naming() {
        let mut frame = StackFrame::x86_64();
        let n0 = frame.local_at(-8);
        let n1 = frame.local_at(-16);
        let n0b = frame.local_at(-8);
        assert_eq!(n0, "local_0");
        assert_eq!(n1, "local_1");
        assert_eq!(n0b, "local_0");
    }

    #[test]
    fn test_stack_frame_offset_sub() {
        let frame = StackFrame::x86_64();
        let expr = LlilExpr::Sub {
            left: Box::new(LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete("rbp".to_owned()),
                size: Size::QWord,
            }),
            right: Box::new(LlilExpr::Const { value: 8, size: Size::QWord }),
            size: Size::QWord,
        };
        assert_eq!(frame.extract_frame_offset(&expr), Some(-8));
    }

    #[test]
    fn test_stack_frame_offset_sp_add() {
        let frame = StackFrame::x86_64();
        let expr = LlilExpr::Add {
            left: Box::new(LlilExpr::StackPointer(Size::QWord)),
            right: Box::new(LlilExpr::Const { value: 24, size: Size::QWord }),
            size: Size::QWord,
        };
        assert_eq!(frame.extract_frame_offset(&expr), Some(24));
    }

    #[test]
    fn test_flag_state_cmp() {
        let mut fs = FlagState::default();
        let a = LlilExpr::Const { value: 1, size: Size::QWord };
        let b = LlilExpr::Const { value: 2, size: Size::QWord };
        fs.update_from_cmp(&a, &b);
        assert!(fs.get("ZF").is_some());
        assert!(fs.get("CF").is_some());
    }

    #[test]
    fn test_flag_state_sf_is_sign_of_difference() {
        let mut fs = FlagState::default();
        let a = LlilExpr::Const { value: 1, size: Size::QWord };
        let b = LlilExpr::Const { value: 2, size: Size::QWord };
        fs.update_from_cmp(&a, &b);
        let sf = fs.resolve("SF");
        // SF must be sign(left - right): a compare of the bare left operand
        // against 0 is wrong whenever right != 0.
        let LlilExpr::CmpSlt(lhs, _) = &sf else {
            panic!("SF must resolve to CmpSlt(..), got {sf:?}");
        };
        assert!(
            matches!(lhs.as_ref(), LlilExpr::SubT(..)),
            "SF's compared value must be (left - right), got {lhs:?}"
        );
    }

    #[test]
    fn test_flag_state_resolve_fallback() {
        let fs = FlagState::default();
        let resolved = fs.resolve("ZF");
        assert!(matches!(resolved, LlilExpr::Flag(name) if name == "ZF"));
    }

    #[test]
    fn test_calling_convention_names() {
        let cc = CallingConvention::sysv_amd64();
        assert_eq!(cc.arg_registers[0], "rdi");
        assert_eq!(cc.param_name(0), "arg0");
        assert_eq!(cc.return_name(), "retval");
    }

    /// Build a one-block function `dest ← reg(src)` for elevation tests.
    fn func_with_reg_move(dest: &str, src: &str) -> LlilFunction {
        LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                start: Address::new(0x1000),
                end: Address::new(0x1004),
                id: 0,
                successors: vec![],
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    length: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete(dest.to_owned()),
                        size: Size::QWord,
                        value: LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete(src.to_owned()),
                            size: Size::QWord,
                        },
                    },
                }],
            }],
            ..Default::default()
        }
    }

    fn first_value_reg_name(func: &LlilFunction) -> String {
        match &func.blocks[0].instrs[0].instr {
            LlilInstruction::SetReg {
                value: LlilExpr::RegisterRef { reg, .. },
                ..
            } => reg.name(),
            other => panic!("expected SetReg of RegisterRef, got {other:?}"),
        }
    }

    #[test]
    fn test_elevate_ms_x64_renames_rcx_to_arg0() {
        let bridge = LlilToMlilBridge::new(BridgeConfig {
            calling_convention: CallingConvention::ms_x64(),
            lift_flags: true,
            name_stack_slots: true,
        });
        // rcx is arg0 on ms_x64 (but arg3 on sysv).
        let elevated = bridge.elevate(&func_with_reg_move("rax", "rcx"));
        assert_eq!(first_value_reg_name(&elevated), "arg0");
        // rdi is an arg reg on sysv but callee-saved on ms_x64 — must NOT rename.
        let elevated = bridge.elevate(&func_with_reg_move("rax", "rdi"));
        assert_eq!(first_value_reg_name(&elevated), "rdi");
    }

    #[test]
    fn test_elevate_aarch64_renames_x1_to_arg1() {
        let bridge = LlilToMlilBridge::new(BridgeConfig::aarch64());
        let elevated = bridge.elevate(&func_with_reg_move("x9", "x1"));
        assert_eq!(first_value_reg_name(&elevated), "arg1");
        // x0 is both arg0 and return reg; arg map wins for reads.
        let elevated = bridge.elevate(&func_with_reg_move("x9", "x0"));
        assert_eq!(first_value_reg_name(&elevated), "arg0");
    }

    #[test]
    fn test_elevate_riscv_renames_a0_to_arg0() {
        let bridge = LlilToMlilBridge::new(BridgeConfig::riscv());
        let elevated = bridge.elevate(&func_with_reg_move("t0", "a0"));
        assert_eq!(first_value_reg_name(&elevated), "arg0");
        let elevated = bridge.elevate(&func_with_reg_move("t0", "s0"));
        assert_eq!(first_value_reg_name(&elevated), "s0");
    }

    #[test]
    fn test_elevate_is_idempotent() {
        let bridge = LlilToMlilBridge::new(BridgeConfig::x86_64_linux());
        let func = func_with_reg_move("rax", "rdi");
        let once = bridge.elevate(&func);
        let twice = bridge.elevate(&once);
        // "arg0"/"retval" are not physical regs, so a second pass must be a no-op.
        assert_eq!(
            format!("{:?}", once.blocks[0].instrs),
            format!("{:?}", twice.blocks[0].instrs),
        );
    }

    fn func_with_flag_setreg() -> LlilFunction {
        LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                start: Address::new(0x1000),
                end: Address::new(0x1004),
                id: 0,
                successors: vec![],
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    length: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rbx".to_owned()),
                        size: Size::QWord,
                        value: LlilExpr::Flag("ZF".to_owned()),
                    },
                }],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_gating_lift_flags_false_keeps_flag_reads() {
        let bridge = LlilToMlilBridge::new(BridgeConfig {
            calling_convention: CallingConvention::sysv_amd64(),
            lift_flags: false,
            name_stack_slots: true,
        });
        let elevated = bridge.elevate(&func_with_flag_setreg());
        let LlilInstruction::SetReg { value, .. } = &elevated.blocks[0].instrs[0].instr
        else { panic!("expected SetReg") };
        assert!(matches!(value, LlilExpr::Flag(f) if f == "ZF"));
    }

    fn func_with_stack_load() -> LlilFunction {
        LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                start: Address::new(0x1000),
                end: Address::new(0x1004),
                id: 0,
                successors: vec![],
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    length: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rbx".to_owned()),
                        size: Size::QWord,
                        value: LlilExpr::Load {
                            addr: Box::new(LlilExpr::Add {
                                left: Box::new(LlilExpr::StackPointer(Size::QWord)),
                                right: Box::new(LlilExpr::Const {
                                    value: 8,
                                    size: Size::QWord,
                                }),
                                size: Size::QWord,
                            }),
                            size: Size::QWord,
                        },
                    },
                }],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_gating_name_stack_slots() {
        // Enabled: sp+8 load becomes a named local ref.
        let bridge = LlilToMlilBridge::new(BridgeConfig::x86_64_linux());
        let elevated = bridge.elevate(&func_with_stack_load());
        let LlilInstruction::SetReg { value, .. } = &elevated.blocks[0].instrs[0].instr
        else { panic!("expected SetReg") };
        assert!(
            matches!(value, LlilExpr::RegisterRef { reg, .. } if reg.name() == "local_0"),
            "expected local_0 ref, got {value:?}"
        );

        // Disabled: the Load stays a Load.
        let bridge = LlilToMlilBridge::new(BridgeConfig {
            calling_convention: CallingConvention::sysv_amd64(),
            lift_flags: true,
            name_stack_slots: false,
        });
        let elevated = bridge.elevate(&func_with_stack_load());
        let LlilInstruction::SetReg { value, .. } = &elevated.blocks[0].instrs[0].instr
        else { panic!("expected SetReg") };
        assert!(matches!(value, LlilExpr::Load { .. }), "expected Load, got {value:?}");
    }

    #[test]
    fn test_elevate_renames_arg_reg() {
        let bridge = LlilToMlilBridge::new(BridgeConfig::x86_64_linux());
        let func = LlilFunction {
            entry: Address::new(0x1000),
            address: Address::new(0x1000),
            blocks: vec![LlilBasicBlock {
                start: Address::new(0x1000),
                end: Address::new(0x1004),
                id: 0,
                successors: vec![],
                instrs: vec![LlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    size: 4,
                    length: 4,
                    instr: LlilInstruction::SetReg {
                        dest: LlilRegister::Concrete("rax".to_owned()),
                        size: Size::QWord,
                        value: LlilExpr::RegisterRef {
                            reg: LlilRegister::Concrete("rdi".to_owned()),
                            size: Size::QWord,
                        },
                    },
                }],
            }],
            ..Default::default()
        };
        let elevated = bridge.elevate(&func);
        let instr = &elevated.blocks[0].instrs[0].instr;
        if let LlilInstruction::SetReg { value, .. } = instr
            && let LlilExpr::RegisterRef { reg, .. } = value {
                assert_eq!(reg.name(), "arg0");
            }
    }
}
