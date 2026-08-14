//! `llil_semantics.rs` — semantic properties of LLIL instructions.
//!
//! This module provides structured descriptions of the observable effects of
//! every LLIL instruction, independent of the target architecture.
//!
//! # Key types
//! * [`SemanticProperty`] — bitflag set describing what an instruction does.
//! * [`MemoryEffect`] — read/write access to a memory region.
//! * [`FlagEffect`] — which CPU flags an instruction may define or use.
//! * [`LlilSemantics`] — derives semantic properties for any `LlilInstruction`.
//! * [`SemanticsDb`] — caches computed semantics and provides query helpers.

use std::collections::HashMap;
use std::fmt;

use bitflags::bitflags;

use crate::{LlilExpr, LlilFunction, LlilInstruction, Size};

// ─── SemanticProperty ────────────────────────────────────────────────────────

bitflags! {
    /// Semantic properties of a single LLIL instruction.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SemanticProperty: u32 {
        /// The instruction has no observable effects (NOP).
        const PURE          = 0b0000_0000_0001;
        /// The instruction reads from memory.
        const READS_MEMORY  = 0b0000_0000_0010;
        /// The instruction writes to memory.
        const WRITES_MEMORY = 0b0000_0000_0100;
        /// The instruction makes a function call (direct or indirect).
        const CALLS_FUNCTION= 0b0000_0000_1000;
        /// The instruction has a side effect (I/O, syscall, interrupt, …).
        const SIDE_EFFECT   = 0b0000_0001_0000;
        /// The instruction transfers control flow (branch, jump, ret, …).
        const CONTROL_FLOW  = 0b0000_0010_0000;
        /// The instruction reads one or more CPU flags.
        const READS_FLAGS   = 0b0000_0100_0000;
        /// The instruction defines one or more CPU flags.
        const WRITES_FLAGS  = 0b0000_1000_0000;
        /// The instruction reads a register operand.
        const READS_REGISTER= 0b0001_0000_0000;
        /// The instruction writes a register result.
        const WRITES_REGISTER= 0b0010_0000_0000;
        /// The instruction is a conditional branch.
        const CONDITIONAL   = 0b0100_0000_0000;
        /// The instruction is a system call.
        const SYSCALL       = 0b1000_0000_0000;
    }
}

impl Default for SemanticProperty {
    fn default() -> Self {
        Self::PURE
    }
}

impl fmt::Display for SemanticProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::PURE) {
            parts.push("pure");
        }
        if self.contains(Self::READS_MEMORY) {
            parts.push("reads_mem");
        }
        if self.contains(Self::WRITES_MEMORY) {
            parts.push("writes_mem");
        }
        if self.contains(Self::CALLS_FUNCTION) {
            parts.push("calls");
        }
        if self.contains(Self::SIDE_EFFECT) {
            parts.push("side_effect");
        }
        if self.contains(Self::CONTROL_FLOW) {
            parts.push("ctrl_flow");
        }
        if self.contains(Self::READS_FLAGS) {
            parts.push("reads_flags");
        }
        if self.contains(Self::WRITES_FLAGS) {
            parts.push("writes_flags");
        }
        if self.contains(Self::READS_REGISTER) {
            parts.push("reads_reg");
        }
        if self.contains(Self::WRITES_REGISTER) {
            parts.push("writes_reg");
        }
        if self.contains(Self::CONDITIONAL) {
            parts.push("conditional");
        }
        if self.contains(Self::SYSCALL) {
            parts.push("syscall");
        }
        write!(f, "{{{}}}", parts.join("|"))
    }
}

// ─── MemoryEffect ─────────────────────────────────────────────────────────────

/// Describes a single memory access produced by an LLIL instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEffect {
    /// Whether this is a read (`true`) or write (`false`).
    pub is_read: bool,
    /// The size of the access.
    pub size: Size,
    /// A human-readable description of the address expression (e.g. `"[rsp+8]"`).
    pub address_desc: String,
    /// `true` when the access is definitely to the stack frame.
    pub is_stack: bool,
}

impl MemoryEffect {
    pub fn read(size: Size, address_desc: impl Into<String>) -> Self {
        Self {
            is_read: true,
            size,
            address_desc: address_desc.into(),
            is_stack: false,
        }
    }

    pub fn write(size: Size, address_desc: impl Into<String>) -> Self {
        Self {
            is_read: false,
            size,
            address_desc: address_desc.into(),
            is_stack: false,
        }
    }

    #[must_use]
    pub const fn with_stack(mut self) -> Self {
        self.is_stack = true;
        self
    }
}

impl fmt::Display for MemoryEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rw = if self.is_read { "R" } else { "W" };
        write!(f, "{}[{}].{}", rw, self.address_desc, self.size.bytes())
    }
}

// ─── FlagEffect ──────────────────────────────────────────────────────────────

/// CPU flags affected by a single LLIL instruction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagEffect {
    /// Flags explicitly defined by the instruction.
    pub defined: Vec<String>,
    /// Flags read (used) as inputs by the instruction.
    pub used: Vec<String>,
    /// Flags whose value becomes undefined after the instruction.
    pub killed: Vec<String>,
}

impl FlagEffect {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_defined(mut self, flags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.defined.extend(flags.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_used(mut self, flags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.used.extend(flags.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_killed(mut self, flags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.killed.extend(flags.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.defined.is_empty() && self.used.is_empty() && self.killed.is_empty()
    }
}

// ─── InstrSemantics ──────────────────────────────────────────────────────────

/// The complete semantic description of a single LLIL instruction.
#[derive(Debug, Clone)]
pub struct InstrSemantics {
    /// Summary property flags.
    pub props: SemanticProperty,
    /// Memory accesses performed (may be empty).
    pub memory_effects: Vec<MemoryEffect>,
    /// CPU flag effects.
    pub flags: FlagEffect,
    /// For call instructions: the call target description.
    pub call_target: Option<String>,
    /// Human-readable annotation for debugging.
    pub note: Option<String>,
}

impl InstrSemantics {
    fn pure_semantics() -> Self {
        Self {
            props: SemanticProperty::PURE,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: None,
        }
    }

    /// Returns `true` when this instruction has no observable side effects.
    #[must_use]
    pub const fn is_pure(&self) -> bool {
        self.props.contains(SemanticProperty::PURE)
            && self.memory_effects.is_empty()
            && !self.props.contains(SemanticProperty::SIDE_EFFECT)
    }

    /// Returns `true` when this instruction accesses memory in any way.
    #[must_use]
    pub const fn touches_memory(&self) -> bool {
        !self.memory_effects.is_empty()
            || self.props.contains(SemanticProperty::READS_MEMORY)
            || self.props.contains(SemanticProperty::WRITES_MEMORY)
    }

    /// Returns all read memory effects.
    pub fn reads(&self) -> impl Iterator<Item = &MemoryEffect> {
        self.memory_effects.iter().filter(|e| e.is_read)
    }

    /// Returns all write memory effects.
    pub fn writes(&self) -> impl Iterator<Item = &MemoryEffect> {
        self.memory_effects.iter().filter(|e| !e.is_read)
    }
}

// ─── LlilSemantics ───────────────────────────────────────────────────────────

/// Derives the [`InstrSemantics`] for any [`LlilInstruction`].
///
/// The derivation is purely syntactic and architecture-independent: it reads
/// the structure of the LLIL instruction and returns a [`InstrSemantics`]
/// value describing the observable effects.
#[derive(Debug, Default, Clone)]
pub struct LlilSemantics {
    /// When `true`, stack-pointer-relative loads/stores are tagged `is_stack`.
    pub tag_stack_accesses: bool,
}

impl LlilSemantics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_stack_tagging(mut self) -> Self {
        self.tag_stack_accesses = true;
        self
    }

    /// Compute semantics for a single instruction.
    ///
    /// Delegates to [`Self::of_control_flow`] for jump/call/ret arms and
    /// [`of_terminal_misc`] for syscall/trap/flag/intrinsic arms.
    #[must_use]
    pub fn of(&self, instr: &LlilInstruction) -> InstrSemantics {
        match instr {
            LlilInstruction::Nop | LlilInstruction::Undefined | LlilInstruction::Breakpoint => {
                let mut sem = InstrSemantics::pure_semantics();
                if matches!(instr, LlilInstruction::Breakpoint) {
                    sem.props = SemanticProperty::SIDE_EFFECT;
                }
                sem
            }

            LlilInstruction::SetReg { value: src, .. } => {
                let mut props = SemanticProperty::WRITES_REGISTER;
                let mut effects = Vec::new();
                if expr_reads_memory(src) {
                    props |= SemanticProperty::READS_MEMORY;
                    effects.push(MemoryEffect::read(Size::QWord, expr_desc(src)));
                }
                if expr_reads_flag(src) {
                    props |= SemanticProperty::READS_FLAGS;
                }
                InstrSemantics { props, memory_effects: effects, flags: FlagEffect::new(), call_target: None, note: None }
            }

            LlilInstruction::Load { addr, size, .. } => {
                let mut effect = MemoryEffect::read(*size, expr_desc(addr));
                if self.tag_stack_accesses && expr_is_stack(addr) {
                    effect = effect.with_stack();
                }
                InstrSemantics {
                    props: SemanticProperty::READS_MEMORY | SemanticProperty::WRITES_REGISTER,
                    memory_effects: vec![effect],
                    flags: FlagEffect::new(),
                    call_target: None,
                    note: None,
                }
            }

            LlilInstruction::Store { addr, value: src, size } => {
                let mut effect = MemoryEffect::write(*size, expr_desc(addr));
                if self.tag_stack_accesses && expr_is_stack(addr) {
                    effect = effect.with_stack();
                }
                let mut props = SemanticProperty::WRITES_MEMORY;
                if expr_reads_memory(src) {
                    props |= SemanticProperty::READS_MEMORY;
                }
                InstrSemantics { props, memory_effects: vec![effect], flags: FlagEffect::new(), call_target: None, note: None }
            }

            LlilInstruction::Push { src, size } => {
                let mut props = SemanticProperty::WRITES_MEMORY | SemanticProperty::WRITES_REGISTER;
                if expr_reads_memory(src) {
                    props |= SemanticProperty::READS_MEMORY;
                }
                let effect = MemoryEffect::write(*size, "sp-n").with_stack();
                InstrSemantics { props, memory_effects: vec![effect], flags: FlagEffect::new(), call_target: None, note: Some("push".to_string()) }
            }

            LlilInstruction::Pop { dest, size } => {
                let effect = MemoryEffect::read(*size, "sp").with_stack();
                InstrSemantics {
                    props: SemanticProperty::READS_MEMORY | SemanticProperty::WRITES_REGISTER,
                    memory_effects: vec![effect],
                    flags: FlagEffect::new(),
                    call_target: None,
                    note: Some(format!("pop -> {dest}")),
                }
            }

            _ => of_control_flow(instr),
        }
    }

    /// Compute semantics for every instruction in a function.
    #[must_use]
    pub fn analyse_function<'a>(
        &self,
        func: &'a LlilFunction,
    ) -> Vec<(&'a crate::LlilAnnotatedInstr, InstrSemantics)> {
        func.blocks
            .iter()
            .flat_map(|b| &b.instrs)
            .map(|ai| (ai, self.of(&ai.instr)))
            .collect()
    }
}

// ─── control-flow instruction semantics ──────────────────────────────────────

/// Semantics for jump and call instructions.  Called as the fallback from
/// [`LlilSemantics::of`] for any instruction not handled by the register/memory
/// arms.
fn of_control_flow(instr: &LlilInstruction) -> InstrSemantics {
    match instr {
        LlilInstruction::JumpDest { dest } | LlilInstruction::Jump(dest) => InstrSemantics {
            props: SemanticProperty::CONTROL_FLOW,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some(format!("jump {}", expr_desc(dest))),
        },
        LlilInstruction::JumpTo { dest, targets } => InstrSemantics {
            props: SemanticProperty::CONTROL_FLOW,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some(format!("jumpto {} ({} targets)", expr_desc(dest), targets.len())),
        },
        LlilInstruction::CondJump { cond, .. } => {
            let mut props = SemanticProperty::CONTROL_FLOW | SemanticProperty::CONDITIONAL;
            if expr_reads_flag(cond) {
                props |= SemanticProperty::READS_FLAGS;
            }
            InstrSemantics { props, memory_effects: Vec::new(), flags: FlagEffect::new().with_used(collect_flag_reads(cond)), call_target: None, note: None }
        }
        LlilInstruction::CallDest { dest }
        | LlilInstruction::Call(dest)
        | LlilInstruction::TailCall { dest } => {
            let target = expr_desc(dest);
            let mut props = SemanticProperty::CALLS_FUNCTION
                | SemanticProperty::READS_MEMORY
                | SemanticProperty::WRITES_MEMORY
                | SemanticProperty::WRITES_FLAGS;
            if matches!(instr, LlilInstruction::TailCall { .. }) {
                props |= SemanticProperty::CONTROL_FLOW;
            }
            InstrSemantics { props, memory_effects: Vec::new(), flags: FlagEffect::new().with_killed(["CF", "ZF", "SF", "OF", "PF"]), call_target: Some(target), note: None }
        }
        LlilInstruction::CondCall { cond, dest } => {
            let target = expr_desc(dest);
            let mut props = SemanticProperty::CALLS_FUNCTION
                | SemanticProperty::CONDITIONAL
                | SemanticProperty::READS_MEMORY
                | SemanticProperty::WRITES_MEMORY
                | SemanticProperty::WRITES_FLAGS;
            if expr_reads_flag(cond) {
                props |= SemanticProperty::READS_FLAGS;
            }
            InstrSemantics { props, memory_effects: Vec::new(), flags: FlagEffect::new().with_used(collect_flag_reads(cond)), call_target: Some(target), note: None }
        }
        _ => of_terminal_misc(instr),
    }
}

// ─── terminal / misc instruction semantics ───────────────────────────────────

/// Semantics for terminal and miscellaneous instructions (ret, syscall, trap,
/// flag writes, intrinsics, unimplemented variants, and the generic register/
/// return variants).  Called as the final fallback from
/// [`LlilSemantics::of_control_flow`].
fn of_terminal_misc(instr: &LlilInstruction) -> InstrSemantics {
    match instr {
        LlilInstruction::Ret => InstrSemantics {
            props: SemanticProperty::CONTROL_FLOW,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some("ret".to_string()),
        },
        LlilInstruction::SysCall => InstrSemantics {
            props: SemanticProperty::SYSCALL
                | SemanticProperty::SIDE_EFFECT
                | SemanticProperty::READS_MEMORY
                | SemanticProperty::WRITES_MEMORY
                | SemanticProperty::WRITES_FLAGS,
            memory_effects: Vec::new(),
            flags: FlagEffect::new().with_killed(["CF", "ZF", "SF", "OF"]),
            call_target: Some("syscall".to_string()),
            note: None,
        },
        LlilInstruction::Trap { code } => InstrSemantics {
            props: SemanticProperty::SIDE_EFFECT | SemanticProperty::CONTROL_FLOW,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some(format!("trap {code}")),
        },
        LlilInstruction::SetFlag { name, .. } => InstrSemantics {
            props: SemanticProperty::WRITES_FLAGS,
            memory_effects: Vec::new(),
            flags: FlagEffect::new().with_defined([name.as_str()]),
            call_target: None,
            note: None,
        },
        LlilInstruction::SetRegSplit { low, high, src, .. } => {
            let mut props = SemanticProperty::WRITES_REGISTER;
            if expr_reads_memory(src) {
                props |= SemanticProperty::READS_MEMORY;
            }
            InstrSemantics { props, memory_effects: Vec::new(), flags: FlagEffect::new(), call_target: None, note: Some(format!("set_reg_split {low}:{high}")) }
        }
        LlilInstruction::Intrinsic { name, args } => {
            let mut props = SemanticProperty::SIDE_EFFECT;
            if args.iter().any(expr_reads_memory) {
                props |= SemanticProperty::READS_MEMORY;
            }
            InstrSemantics { props, memory_effects: Vec::new(), flags: FlagEffect::new(), call_target: Some(format!("intrinsic:{name}")), note: None }
        }
        LlilInstruction::Unimplemented { mnemonic } => InstrSemantics {
            props: SemanticProperty::SIDE_EFFECT,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some(format!("unimplemented: {mnemonic}")),
        },
        LlilInstruction::UnimplementedRaw { .. } => InstrSemantics {
            props: SemanticProperty::SIDE_EFFECT,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some("unimplemented raw".to_string()),
        },
        LlilInstruction::ConditionalJump { .. } => InstrSemantics {
            props: SemanticProperty::CONTROL_FLOW | SemanticProperty::CONDITIONAL,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: None,
        },
        LlilInstruction::SetRegister { .. } => InstrSemantics {
            props: SemanticProperty::WRITES_REGISTER,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: None,
        },
        LlilInstruction::Return { .. } => InstrSemantics {
            props: SemanticProperty::CONTROL_FLOW,
            memory_effects: Vec::new(),
            flags: FlagEffect::new(),
            call_target: None,
            note: Some("return".to_string()),
        },
        // All other variants are handled by the callers above.
        _ => InstrSemantics::pure_semantics(),
    }
}

// ─── helper functions ────────────────────────────────────────────────────────

fn expr_reads_memory(expr: &LlilExpr) -> bool {
    match expr {
        LlilExpr::Load { .. } => true,
        LlilExpr::AddT(a, b, _)
        | LlilExpr::SubT(a, b, _)
        | LlilExpr::MulT(a, b, _)
        | LlilExpr::And(a, b, _)
        | LlilExpr::Or(a, b, _)
        | LlilExpr::Xor(a, b, _)
        | LlilExpr::ShlT(a, b, _)
        | LlilExpr::Shr(a, b, _)
        | LlilExpr::CmpEq(a, b)
        | LlilExpr::CmpNe(a, b)
        | LlilExpr::CmpSlt(a, b)
        | LlilExpr::CmpSgt(a, b)
        | LlilExpr::CmpUlt(a, b)
        | LlilExpr::CmpUgt(a, b)
        | LlilExpr::CmpSle(a, b)
        | LlilExpr::CmpSge(a, b)
        | LlilExpr::CmpUle(a, b)
        | LlilExpr::CmpUge(a, b) => expr_reads_memory(a) || expr_reads_memory(b),
        LlilExpr::Neg(e, _)
        | LlilExpr::Not(e, _)
        | LlilExpr::ZeroExtend { expr: e, .. }
        | LlilExpr::SignExtend { expr: e, .. }
        | LlilExpr::LowPart { expr: e, .. } => expr_reads_memory(e),
        _ => false,
    }
}

fn expr_reads_flag(expr: &LlilExpr) -> bool {
    match expr {
        LlilExpr::Flag(_) => true,
        LlilExpr::AddT(a, b, _)
        | LlilExpr::SubT(a, b, _)
        | LlilExpr::And(a, b, _)
        | LlilExpr::Or(a, b, _)
        | LlilExpr::CmpEq(a, b)
        | LlilExpr::CmpNe(a, b)
        | LlilExpr::CmpSlt(a, b) => expr_reads_flag(a) || expr_reads_flag(b),
        _ => false,
    }
}

fn collect_flag_reads(expr: &LlilExpr) -> Vec<String> {
    let mut flags = Vec::new();
    collect_flags_inner(expr, &mut flags);
    flags
}

fn collect_flags_inner(expr: &LlilExpr, out: &mut Vec<String>) {
    match expr {
        LlilExpr::Flag(name) => out.push(name.clone()),
        LlilExpr::AddT(a, b, _)
        | LlilExpr::SubT(a, b, _)
        | LlilExpr::And(a, b, _)
        | LlilExpr::Or(a, b, _)
        | LlilExpr::CmpEq(a, b)
        | LlilExpr::CmpNe(a, b) => {
            collect_flags_inner(a, out);
            collect_flags_inner(b, out);
        }
        LlilExpr::Not(e, _) | LlilExpr::Neg(e, _) => collect_flags_inner(e, out),
        _ => {}
    }
}

fn expr_is_stack(expr: &LlilExpr) -> bool {
    match expr {
        LlilExpr::StackPointer(_) => true,
        LlilExpr::AddT(a, b, _) | LlilExpr::SubT(a, b, _) => expr_is_stack(a) || expr_is_stack(b),
        _ => false,
    }
}

fn expr_desc(expr: &LlilExpr) -> String {
    match expr {
        LlilExpr::Const { value, .. } => format!("0x{value:x}"),
        LlilExpr::RegisterRef { reg, .. } => reg.name(),
        LlilExpr::StackPointer(_) => "sp".to_string(),
        LlilExpr::Flag(n) => format!("flag:{n}"),
        LlilExpr::Load { addr, size } => format!("[{}].{}", expr_desc(addr), size.bytes()),
        LlilExpr::AddT(a, b, _) => format!("({} + {})", expr_desc(a), expr_desc(b)),
        LlilExpr::SubT(a, b, _) => format!("({} - {})", expr_desc(a), expr_desc(b)),
        _ => "?".to_string(),
    }
}

// ─── SemanticsDb ─────────────────────────────────────────────────────────────

/// A cache that stores pre-computed [`InstrSemantics`] keyed by address.
///
/// Useful when the same function's instructions are queried multiple times
/// by different analysis passes.
#[derive(Debug, Default)]
pub struct SemanticsDb {
    /// Maps instruction address (as `u64`) → computed semantics.
    cache: HashMap<u64, InstrSemantics>,
    analyzer: LlilSemantics,
}

impl SemanticsDb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_stack_tagging(mut self) -> Self {
        self.analyzer = self.analyzer.with_stack_tagging();
        self
    }

    /// Populate the cache for the entire function.
    pub fn populate(&mut self, func: &LlilFunction) {
        for block in &func.blocks {
            for ai in &block.instrs {
                let sem = self.analyzer.of(&ai.instr);
                self.cache.insert(ai.address.as_u64(), sem);
            }
        }
    }

    /// Look up semantics for an instruction at `addr`.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&InstrSemantics> {
        self.cache.get(&addr)
    }

    /// Return all addresses whose instructions touch memory.
    #[must_use]
    pub fn memory_touching_addresses(&self) -> Vec<u64> {
        self.cache
            .iter()
            .filter(|(_, s)| s.touches_memory())
            .map(|(a, _)| *a)
            .collect()
    }

    /// Return all addresses whose instructions make calls.
    #[must_use]
    pub fn call_sites(&self) -> Vec<u64> {
        self.cache
            .iter()
            .filter(|(_, s)| s.props.contains(SemanticProperty::CALLS_FUNCTION))
            .map(|(a, _)| *a)
            .collect()
    }

    /// Total number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LlilAnnotatedInstr, LlilBasicBlock, LlilFunction, LlilRegister};
    use rustre_core::address::Address;

    fn reg(name: &str) -> LlilRegister {
        LlilRegister::Concrete(name.to_string())
    }

    fn make_function_with_instrs(instrs: Vec<LlilInstruction>) -> LlilFunction {
        let annotated = instrs
            .into_iter()
            .enumerate()
            .map(|(i, instr)| LlilAnnotatedInstr {
                address: Address::new(0x1000 + i as u64 * 4),
                instr,
                size: 4,
                length: 4,
            })
            .collect::<Vec<_>>();
        let mut func = LlilFunction::new(Address::new(0x1000));
        func.blocks.push(LlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1000 + annotated.len() as u64 * 4),
            instrs: annotated,
            successors: vec![],
        });
        func
    }

    // SemanticProperty tests ────────────────────────────────────────────────

    #[test]
    fn prop_pure_default() {
        let p = SemanticProperty::default();
        assert!(p.contains(SemanticProperty::PURE));
    }

    #[test]
    fn prop_bitflag_combination() {
        let p = SemanticProperty::READS_MEMORY | SemanticProperty::WRITES_MEMORY;
        assert!(p.contains(SemanticProperty::READS_MEMORY));
        assert!(p.contains(SemanticProperty::WRITES_MEMORY));
        assert!(!p.contains(SemanticProperty::CALLS_FUNCTION));
    }

    #[test]
    fn prop_display_nonempty() {
        let p = SemanticProperty::READS_MEMORY | SemanticProperty::CALLS_FUNCTION;
        let s = p.to_string();
        assert!(s.contains("reads_mem"));
        assert!(s.contains("calls"));
    }

    // MemoryEffect tests ────────────────────────────────────────────────────

    #[test]
    fn mem_effect_read() {
        let e = MemoryEffect::read(Size::QWord, "rsp+8");
        assert!(e.is_read);
        assert_eq!(e.size, Size::QWord);
    }

    #[test]
    fn mem_effect_write() {
        let e = MemoryEffect::write(Size::DWord, "[rbp-4]");
        assert!(!e.is_read);
    }

    #[test]
    fn mem_effect_stack_tag() {
        let e = MemoryEffect::read(Size::QWord, "sp").with_stack();
        assert!(e.is_stack);
    }

    #[test]
    fn mem_effect_display() {
        let e = MemoryEffect::read(Size::Byte, "ptr");
        assert!(e.to_string().starts_with('R'));
    }

    // FlagEffect tests ──────────────────────────────────────────────────────

    #[test]
    fn flag_effect_empty() {
        let f = FlagEffect::new();
        assert!(f.is_empty());
    }

    #[test]
    fn flag_effect_with_defined() {
        let f = FlagEffect::new().with_defined(["ZF", "CF"]);
        assert!(!f.is_empty());
        assert_eq!(f.defined.len(), 2);
    }

    #[test]
    fn flag_effect_with_used() {
        let f = FlagEffect::new().with_used(["ZF"]);
        assert_eq!(f.used, vec!["ZF"]);
    }

    #[test]
    fn flag_effect_with_killed() {
        let f = FlagEffect::new().with_killed(["OF"]);
        assert_eq!(f.killed, vec!["OF"]);
    }

    // LlilSemantics tests ───────────────────────────────────────────────────

    #[test]
    fn semantics_nop_is_pure() {
        let s = LlilSemantics::new();
        let sem = s.of(&LlilInstruction::Nop);
        assert!(sem.is_pure());
    }

    #[test]
    fn semantics_load_reads_memory() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Load {
            dest: reg("rax"),
            addr: LlilExpr::RegisterRef {
                reg: reg("rbp"),
                size: Size::QWord,
            },
            size: Size::DWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::READS_MEMORY));
        assert!(!sem.memory_effects.is_empty());
    }

    #[test]
    fn semantics_store_writes_memory() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Store {
            addr: LlilExpr::RegisterRef {
                reg: reg("rdi"),
                size: Size::QWord,
            },
            value: LlilExpr::Const {
                value: 0,
                size: Size::DWord,
            },
            size: Size::DWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::WRITES_MEMORY));
    }

    #[test]
    fn semantics_call_is_call() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Call(LlilExpr::Const {
            value: 0xdeadbeef,
            size: Size::QWord,
        });
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::CALLS_FUNCTION));
        assert!(sem.call_target.is_some());
    }

    #[test]
    fn semantics_ret_is_control_flow() {
        let s = LlilSemantics::new();
        let sem = s.of(&LlilInstruction::Ret);
        assert!(sem.props.contains(SemanticProperty::CONTROL_FLOW));
        assert!(!sem.props.contains(SemanticProperty::CALLS_FUNCTION));
    }

    #[test]
    fn semantics_syscall_has_side_effect() {
        let s = LlilSemantics::new();
        let sem = s.of(&LlilInstruction::SysCall);
        assert!(sem.props.contains(SemanticProperty::SYSCALL));
        assert!(sem.props.contains(SemanticProperty::SIDE_EFFECT));
    }

    #[test]
    fn semantics_cond_jump_is_conditional() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::CondJump {
            cond: LlilExpr::Const {
                value: 1,
                size: Size::Byte,
            },
            true_dest: Address::new(0x100),
            false_dest: Address::new(0x110),
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::CONDITIONAL));
        assert!(sem.props.contains(SemanticProperty::CONTROL_FLOW));
    }

    #[test]
    fn semantics_push_writes_stack() {
        let s = LlilSemantics::new().with_stack_tagging();
        let instr = LlilInstruction::Push {
            src: LlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::WRITES_MEMORY));
        assert!(sem.memory_effects.iter().any(|e| e.is_stack));
    }

    #[test]
    fn semantics_load_stack_tagged() {
        let s = LlilSemantics::new().with_stack_tagging();
        let sp = LlilExpr::StackPointer(Size::QWord);
        let instr = LlilInstruction::Load {
            dest: reg("rax"),
            addr: sp,
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.memory_effects.iter().any(|e| e.is_stack));
    }

    #[test]
    fn semantics_reads_iter() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Load {
            dest: reg("rax"),
            addr: LlilExpr::Const {
                value: 0x1000,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert_eq!(sem.reads().count(), 1);
        assert_eq!(sem.writes().count(), 0);
    }

    // SemanticsDb tests ─────────────────────────────────────────────────────

    #[test]
    fn db_initially_empty() {
        let db = SemanticsDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn db_populate() {
        let func = make_function_with_instrs(vec![LlilInstruction::Nop, LlilInstruction::Ret]);
        let mut db = SemanticsDb::new();
        db.populate(&func);
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn db_get_returns_semantics() {
        let func = make_function_with_instrs(vec![LlilInstruction::Ret]);
        let mut db = SemanticsDb::new();
        db.populate(&func);
        let sem = db.get(0x1000);
        assert!(sem.is_some());
        assert!(sem.unwrap().props.contains(SemanticProperty::CONTROL_FLOW));
    }

    #[test]
    fn db_call_sites() {
        let func = make_function_with_instrs(vec![
            LlilInstruction::Call(LlilExpr::Const {
                value: 0xdeadbeef,
                size: Size::QWord,
            }),
            LlilInstruction::Ret,
        ]);
        let mut db = SemanticsDb::new();
        db.populate(&func);
        let sites = db.call_sites();
        assert_eq!(sites.len(), 1);
    }

    #[test]
    fn db_clear() {
        let func = make_function_with_instrs(vec![LlilInstruction::Nop]);
        let mut db = SemanticsDb::new();
        db.populate(&func);
        db.clear();
        assert!(db.is_empty());
    }

    #[test]
    fn instr_semantics_touches_memory() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Load {
            dest: reg("rax"),
            addr: LlilExpr::Const {
                value: 0x100,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.touches_memory());
    }

    #[test]
    fn instr_semantics_not_pure_when_reads_mem() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Load {
            dest: reg("rax"),
            addr: LlilExpr::Const {
                value: 0x100,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(!sem.is_pure());
    }

    #[test]
    fn breakpoint_has_side_effect() {
        let s = LlilSemantics::new();
        let sem = s.of(&LlilInstruction::Breakpoint);
        assert!(sem.props.contains(SemanticProperty::SIDE_EFFECT));
    }

    #[test]
    fn trap_has_side_effect() {
        let s = LlilSemantics::new();
        let sem = s.of(&LlilInstruction::Trap { code: 3 });
        assert!(sem.props.contains(SemanticProperty::SIDE_EFFECT));
        assert!(sem.props.contains(SemanticProperty::CONTROL_FLOW));
    }

    #[test]
    fn set_reg_writes_register() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::SetReg {
            dest: reg("rax"),
            value: LlilExpr::Const {
                value: 1,
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::WRITES_REGISTER));
    }

    #[test]
    fn set_flag_writes_flags() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::SetFlag {
            name: "ZF".to_string(),
            src: LlilExpr::Const {
                value: 0,
                size: Size::Byte,
            },
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::WRITES_FLAGS));
        assert_eq!(sem.flags.defined, vec!["ZF"]);
    }

    #[test]
    fn push_writes_stack() {
        let s = LlilSemantics::new().with_stack_tagging();
        let instr = LlilInstruction::Push {
            src: LlilExpr::RegisterRef {
                reg: reg("rbx"),
                size: Size::QWord,
            },
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::WRITES_MEMORY));
    }

    #[test]
    fn pop_reads_stack() {
        let s = LlilSemantics::new();
        let instr = LlilInstruction::Pop {
            dest: reg("rcx"),
            size: Size::QWord,
        };
        let sem = s.of(&instr);
        assert!(sem.props.contains(SemanticProperty::READS_MEMORY));
        assert!(sem.props.contains(SemanticProperty::WRITES_REGISTER));
    }

    #[test]
    fn db_memory_touching_addresses_not_empty_when_loads_present() {
        let func = make_function_with_instrs(vec![
            LlilInstruction::Load {
                dest: reg("rax"),
                addr: LlilExpr::Const {
                    value: 0x1000,
                    size: Size::QWord,
                },
                size: Size::QWord,
            },
            LlilInstruction::Nop,
        ]);
        let mut db = SemanticsDb::new();
        db.populate(&func);
        assert!(!db.memory_touching_addresses().is_empty());
    }

    #[test]
    fn prop_all_flags() {
        let p = SemanticProperty::all();
        assert!(p.contains(SemanticProperty::PURE));
        assert!(p.contains(SemanticProperty::SYSCALL));
    }
}
