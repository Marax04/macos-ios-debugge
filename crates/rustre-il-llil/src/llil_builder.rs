//! `llil_builder` —  fluent builder API for constructing LLIL functions.
//!
//! Provides `LlilBuilder`, `InstrBuilder`, `BlockBuilder`, `FunctionBuilder`,
//! `LlilValidator`, and `LlilPrinter`.

use crate::{
    LlilAnnotatedInstr, LlilBlock, LlilExpr, LlilFunction, LlilInstruction, LlilRegister, Size,
};
use rustre_core::address::Address;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
// AHashMap for maps keyed on attacker-controlled virtual addresses (block starts).
use ahash::AHashMap;

// â"€â"€ InstrBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Fluent builder for a single LLIL instruction.
#[derive(Debug, Default)]
pub struct InstrBuilder {
    instr: Option<LlilInstruction>,
    address: u64,
    length: u8,
}

impl InstrBuilder {
    /// Create a new instruction builder at `address`.
    #[must_use]
    pub const fn at(address: u64) -> Self {
        Self {
            instr: None,
            address,
            length: 1,
        }
    }

    /// Set the byte length of this instruction.
    #[must_use]
    pub const fn length(mut self, len: u8) -> Self {
        self.length = len;
        self
    }

    /// Build a `SetReg` instruction.
    #[must_use]
    pub fn set_reg(mut self, dest: LlilRegister, value: LlilExpr) -> Self {
        self.instr = Some(LlilInstruction::SetReg {
            dest,
            value,
            size: Size::QWord,
        });
        self
    }

    /// Build a `Load` instruction.
    #[must_use]
    pub fn load(mut self, dest: LlilRegister, addr: LlilExpr, size: Size) -> Self {
        self.instr = Some(LlilInstruction::Load { dest, addr, size });
        self
    }

    /// Build a `Store` instruction.
    #[must_use]
    pub fn store(mut self, addr: LlilExpr, value: LlilExpr, size: Size) -> Self {
        self.instr = Some(LlilInstruction::Store { addr, value, size });
        self
    }

    /// Build an unconditional `Jump`.
    #[must_use]
    pub fn jump(mut self, target: LlilExpr) -> Self {
        self.instr = Some(LlilInstruction::Jump(target));
        self
    }

    /// Build a `ConditionalJump`.
    #[must_use]
    pub fn cond_jump(mut self, cond: LlilExpr, true_target: u64, false_target: u64) -> Self {
        self.instr = Some(LlilInstruction::ConditionalJump {
            cond,
            true_target: Address::new(true_target),
            false_target: Address::new(false_target),
        });
        self
    }

    /// Build a `Call` instruction.
    #[must_use]
    pub fn call(mut self, target: LlilExpr) -> Self {
        self.instr = Some(LlilInstruction::Call(target));
        self
    }

    /// Build a `Ret` instruction.
    #[must_use]
    pub fn ret(mut self) -> Self {
        self.instr = Some(LlilInstruction::Ret);
        self
    }

    /// Build a `Nop`.
    #[must_use]
    pub fn nop(mut self) -> Self {
        self.instr = Some(LlilInstruction::Nop);
        self
    }

    /// Finalize and produce an annotated instruction.
    ///
    /// Returns `None` if no instruction variant was set.
    #[must_use]
    pub fn build(self) -> Option<LlilAnnotatedInstr> {
        let instr = self.instr?;
        Some(LlilAnnotatedInstr {
            address: Address::new(self.address),
            length: self.length,
            size: self.length as usize,
            instr,
        })
    }

    /// Finalize with a default `Nop` if nothing was set.
    #[must_use]
    pub fn build_or_nop(self) -> LlilAnnotatedInstr {
        let instr = self.instr.unwrap_or(LlilInstruction::Nop);
        LlilAnnotatedInstr {
            address: Address::new(self.address),
            length: self.length,
            size: self.length as usize,
            instr,
        }
    }
}

// â"€â"€ BlockBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Fluent builder for a single basic block.
#[derive(Debug, Default)]
pub struct BlockBuilder {
    start: u64,
    instrs: Vec<LlilAnnotatedInstr>,
    successors: Vec<u64>,
}

impl BlockBuilder {
    /// Create a new block starting at `start`.
    #[must_use]
    pub const fn new(start: u64) -> Self {
        Self {
            start,
            instrs: Vec::new(),
            successors: Vec::new(),
        }
    }

    /// Append an annotated instruction to this block and return `self`.
    #[must_use]
    pub fn push_instr(mut self, instr: LlilAnnotatedInstr) -> Self {
        self.instrs.push(instr);
        self
    }

    /// Add an instruction from a builder.
    #[must_use]
    pub fn instr(mut self, builder: InstrBuilder) -> Self {
        if let Some(a) = builder.build() {
            self.instrs.push(a);
        }
        self
    }

    /// Register a successor block address.
    #[must_use]
    pub fn successor(mut self, addr: u64) -> Self {
        self.successors.push(addr);
        self
    }

    /// Finalize and produce a `LlilBlock`.
    #[must_use]
    pub fn build(self) -> LlilBlock {
        let end = Address::new(
            self.instrs
                .last()
                .map_or(self.start, |i| i.address.as_u64() + u64::from(i.length)),
        );
        LlilBlock {
            start: Address::new(self.start),
            end,
            id: 0,
            instrs: self.instrs,
            successors: self.successors.iter().map(|&a| Address::new(a)).collect(),
        }
    }

    /// Number of instructions currently added.
    #[must_use]
    pub const fn instr_count(&self) -> usize {
        self.instrs.len()
    }
}

// â"€â"€ FunctionBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Fluent builder for a complete `LlilFunction`.
#[derive(Debug, Default)]
pub struct FunctionBuilder {
    entry: u64,
    blocks: Vec<LlilBlock>,
    name: Option<String>,
}

impl FunctionBuilder {
    /// Create a builder for a function with the given entry address.
    #[must_use]
    pub const fn new(entry: u64) -> Self {
        Self {
            entry,
            blocks: Vec::new(),
            name: None,
        }
    }

    /// Set a human-readable name for the function.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add a block (via `BlockBuilder`).
    #[must_use]
    pub fn block(mut self, builder: BlockBuilder) -> Self {
        self.blocks.push(builder.build());
        self
    }

    /// Add a pre-built block.
    #[must_use]
    pub fn add_block(mut self, block: LlilBlock) -> Self {
        self.blocks.push(block);
        self
    }

    /// Finalize and produce a `LlilFunction`.
    #[must_use]
    pub fn build(self) -> LlilFunction {
        let entry = Address::new(self.entry);
        LlilFunction {
            entry,
            blocks: self.blocks,
            name: self.name,
            instructions: Vec::new(),
            temp_count: 0,
            address: entry,
            id: 0,
            size: 0,
            end: entry,
        }
    }

    /// Block count.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

// â"€â"€ LlilBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Top-level LLIL builder that manages a collection of functions.
pub struct LlilBuilder {
    functions: Vec<LlilFunction>,
    /// Address of the next synthetic instruction (auto-increment).
    next_addr: u64,
}

impl LlilBuilder {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            functions: Vec::new(),
            next_addr: 0x1000,
        }
    }

    /// Add a function from a `FunctionBuilder`.
    pub fn add_function(&mut self, builder: FunctionBuilder) {
        self.functions.push(builder.build());
    }

    /// Add a pre-built function.
    pub fn push_function(&mut self, func: LlilFunction) {
        self.functions.push(func);
    }

    /// Allocate the next synthetic address.
    pub const fn alloc_addr(&mut self) -> u64 {
        let a = self.next_addr;
        self.next_addr += 4;
        a
    }

    /// Return all built functions.
    #[must_use]
    pub fn functions(&self) -> &[LlilFunction] {
        &self.functions
    }

    /// Total instruction count across all functions.
    #[must_use]
    pub fn total_instrs(&self) -> usize {
        self.functions
            .iter()
            .flat_map(|f| f.blocks.iter())
            .map(|b| b.instrs.len())
            .sum()
    }

    /// Total block count.
    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.functions.iter().map(|f| f.blocks.len()).sum()
    }

    /// Build a simple sequence of instructions in a single-block function.
    #[must_use]
    pub fn simple_function(
        &mut self,
        entry: u64,
        name: Option<&str>,
        instrs: Vec<LlilAnnotatedInstr>,
    ) -> LlilFunction {
        let block = LlilBlock {
            start: Address::new(entry),
            end: Address::new(entry),
            id: 0,
            instrs,
            successors: Vec::new(),
        };
        let addr = Address::new(entry);
        LlilFunction {
            entry: addr,
            blocks: vec![block],
            name: name.map(std::string::ToString::to_string),
            instructions: Vec::new(),
            temp_count: 0,
            address: addr,
            id: 0,
            size: 0,
            end: addr,
        }
    }

    /// Create a new `InstrBuilder` at the next auto-allocated address.
    pub const fn instr_at_next(&mut self) -> InstrBuilder {
        let addr = self.alloc_addr();
        InstrBuilder::at(addr)
    }
}

impl Default for LlilBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ LlilValidator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Validates a `LlilFunction` for structural correctness.
pub struct LlilValidator;

/// A single validation error.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub kind: ValidationErrorKind,
    pub message: String,
    pub address: Option<u64>,
}

/// Category of validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationErrorKind {
    EmptyFunction,
    EmptyBlock,
    MissingTerminator,
    UnresolvedSuccessor,
    DuplicateBlockAddress,
    InvalidInstruction,
}

impl LlilValidator {
    /// Validate a `LlilFunction` and return any errors found.
    ///
    /// # Panics
    /// Panics if an entry block index is out of bounds (corrupted function data).
    #[must_use]
    pub fn validate(func: &LlilFunction) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if func.blocks.is_empty() {
            errors.push(ValidationError {
                kind: ValidationErrorKind::EmptyFunction,
                message: "Function has no blocks".into(),
                address: Some(func.entry.0),
            });
            return errors;
        }

        // Check for duplicate block start addresses.
        // Use AHashMap: keys are virtual addresses from the binary (attacker-controlled).
        let mut seen_starts: AHashMap<u64, usize> = AHashMap::with_capacity(func.blocks.len());
        for (i, block) in func.blocks.iter().enumerate() {
            if let Some(prev) = seen_starts.insert(block.start.0, i) {
                errors.push(ValidationError {
                    kind: ValidationErrorKind::DuplicateBlockAddress,
                    message: format!(
                        "Duplicate block at 0x{:x} (blocks {} and {})",
                        block.start.0, prev, i
                    ),
                    address: Some(block.start.0),
                });
            }
        }

        let block_addresses: std::collections::HashSet<u64> =
            func.blocks.iter().map(|b| b.start.0).collect();

        for block in &func.blocks {
            if block.instrs.is_empty() {
                errors.push(ValidationError {
                    kind: ValidationErrorKind::EmptyBlock,
                    message: format!("Block at 0x{:x} has no instructions", block.start.0),
                    address: Some(block.start.0),
                });
                continue;
            }

            // Check for missing terminator
            let last = block.instrs.last().unwrap();
            let is_terminator = matches!(
                &last.instr,
                LlilInstruction::Ret
                    | LlilInstruction::Jump(_)
                    | LlilInstruction::ConditionalJump { .. }
                    | LlilInstruction::Call(_) // tail call acts as terminator
            );
            if !is_terminator && !block.successors.is_empty() {
                // Has successors but no terminator instruction at end
                errors.push(ValidationError {
                    kind: ValidationErrorKind::MissingTerminator,
                    message: format!(
                        "Block at 0x{:x} has successors but no terminator",
                        block.start.0
                    ),
                    address: Some(block.start.0),
                });
            }

            // Check successors resolve to known blocks
            for succ in &block.successors {
                if !block_addresses.contains(&succ.0) {
                    errors.push(ValidationError {
                        kind: ValidationErrorKind::UnresolvedSuccessor,
                        message: format!(
                            "Block 0x{:x} has unresolved successor 0x{:x}",
                            block.start.0, succ.0
                        ),
                        address: Some(block.start.0),
                    });
                }
            }
        }

        errors
    }

    /// Return true if the function passes all validation checks.
    #[must_use]
    pub fn is_valid(func: &LlilFunction) -> bool {
        Self::validate(func).is_empty()
    }

    /// Count errors by kind.
    #[must_use]
    pub fn error_counts(func: &LlilFunction) -> HashMap<ValidationErrorKind, usize> {
        let errors = Self::validate(func);
        let mut counts = HashMap::new();
        for e in errors {
            *counts.entry(e.kind).or_insert(0) += 1;
        }
        counts
    }
}

// â"€â"€ LlilPrinter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Prints a `LlilFunction` in a human-readable text format.
pub struct LlilPrinter {
    /// Whether to show instruction addresses.
    pub show_addresses: bool,
    /// Whether to show instruction lengths.
    pub show_lengths: bool,
    /// Indent string.
    pub indent: String,
}

impl LlilPrinter {
    /// Create a default printer (addresses on, lengths off, 2-space indent).
    #[must_use]
    pub fn new() -> Self {
        Self {
            show_addresses: true,
            show_lengths: false,
            indent: "  ".into(),
        }
    }

    /// Print a full function to a String.
    #[must_use]
    pub fn print_function(&self, func: &LlilFunction) -> String {
        let mut out = String::new();
        let name = func.name.as_deref().unwrap_or("<unnamed>");
        let _ = writeln!(out, "function {name} @ 0x{:x}:", func.entry.0);
        for block in &func.blocks {
            let _ = writeln!(out, "{}block @ 0x{:x}:", self.indent, block.start.0);
            for ai in &block.instrs {
                let _ = write!(out, "{}{}", self.indent, self.indent);
                if self.show_addresses {
                    let _ = write!(out, "[0x{:08x}] ", ai.address.0);
                }
                if self.show_lengths {
                    let _ = write!(out, "(len={}) ", ai.length);
                }
                let _ = writeln!(out, "{}", self.format_instr(&ai.instr));
            }
            if !block.successors.is_empty() {
                let succs: Vec<String> = block
                    .successors
                    .iter()
                    .map(|a| format!("0x{:x}", a.0))
                    .collect();
                let _ = writeln!(
                    out,
                    "{}{}-> [{}]",
                    self.indent,
                    self.indent,
                    succs.join(", ")
                );
            }
        }
        out
    }

    /// Format a single instruction.
    #[must_use]
    pub fn format_instr(&self, instr: &LlilInstruction) -> String {
        match instr {
            LlilInstruction::Nop => "nop".into(),
            LlilInstruction::SetReg { dest, value, size } => {
                format!("{dest} := {value} ({size:?})")
            }
            LlilInstruction::Load { dest, addr, size } => {
                format!("{dest} := *[{addr}].{size:?}")
            }
            LlilInstruction::Store { addr, value, size } => {
                format!("*[{addr}].{size:?} := {value}")
            }
            LlilInstruction::Jump(target) => format!("jump {target}"),
            LlilInstruction::ConditionalJump {
                cond,
                true_target,
                false_target,
            } => {
                format!(
                    "if {cond} goto 0x{:x} else 0x{:x}",
                    true_target.0, false_target.0
                )
            }
            LlilInstruction::Call(target) => format!("call {target}"),
            LlilInstruction::Ret => "ret".into(),
            _ => format!("{instr}"),
        }
    }

    /// Print a single block.
    #[must_use]
    pub fn print_block(&self, block: &LlilBlock) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "block @ 0x{:x}:", block.start.0);
        for ai in &block.instrs {
            let _ = writeln!(out, "{}{}", self.indent, self.format_instr(&ai.instr));
        }
        out
    }
}

impl Default for LlilPrinter {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€ LlilCopier â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Copies/clones an LLIL function with optional address remapping.
pub struct LlilCopier;

impl LlilCopier {
    /// Deep-clone an LLIL function, optionally adding a base-address offset to all addresses.
    #[must_use]
    pub fn copy_with_offset(func: &LlilFunction, offset: u64) -> LlilFunction {
        let new_entry = Address::new(func.entry.0.wrapping_add(offset));
        let new_end = Address::new(func.end.0.wrapping_add(offset));
        LlilFunction {
            entry: new_entry,
            name: func.name.clone(),
            instructions: Vec::new(),
            temp_count: func.temp_count,
            address: new_entry,
            id: func.id,
            size: func.size,
            end: new_end,
            blocks: func
                .blocks
                .iter()
                .map(|b| LlilBlock {
                    start: Address::new(b.start.0.wrapping_add(offset)),
                    end: Address::new(b.end.0.wrapping_add(offset)),
                    id: b.id,
                    successors: b
                        .successors
                        .iter()
                        .map(|s| Address::new(s.0.wrapping_add(offset)))
                        .collect(),
                    instrs: b
                        .instrs
                        .iter()
                        .map(|ai| LlilAnnotatedInstr {
                            address: Address::new(ai.address.0.wrapping_add(offset)),
                            length: ai.length,
                            size: ai.size,
                            instr: ai.instr.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Return an exact copy of the function.
    #[must_use]
    pub fn copy(func: &LlilFunction) -> LlilFunction {
        Self::copy_with_offset(func, 0)
    }
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LlilExpr, LlilInstruction, LlilRegister, Size};

    fn reg(name: &str) -> LlilRegister {
        LlilRegister::Concrete(name.into())
    }
    fn const_expr(v: u64) -> LlilExpr {
        LlilExpr::Const { value: v, size: Size::QWord }
    }
    fn reg_expr(name: &str) -> LlilExpr {
        LlilExpr::RegisterRef { reg: reg(name), size: Size::QWord }
    }

    // â"€â"€ InstrBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_instr_builder_nop() {
        let ai = InstrBuilder::at(0x1000).nop().build().unwrap();
        assert_eq!(ai.address.0, 0x1000);
        assert!(matches!(ai.instr, LlilInstruction::Nop));
    }

    #[test]
    fn test_instr_builder_set_reg() {
        let ai = InstrBuilder::at(0x1004)
            .set_reg(reg("rax"), const_expr(42))
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::SetReg { .. }));
    }

    #[test]
    fn test_instr_builder_load() {
        let ai = InstrBuilder::at(0x1008)
            .load(reg("rbx"), reg_expr("rax"), Size::DWord)
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::Load { .. }));
    }

    #[test]
    fn test_instr_builder_store() {
        let ai = InstrBuilder::at(0x100c)
            .store(reg_expr("rax"), const_expr(0xFF), Size::Byte)
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::Store { .. }));
    }

    #[test]
    fn test_instr_builder_jump() {
        let ai = InstrBuilder::at(0x1010)
            .jump(const_expr(0x2000))
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::Jump(_)));
    }

    #[test]
    fn test_instr_builder_ret() {
        let ai = InstrBuilder::at(0x1014).ret().build().unwrap();
        assert!(matches!(ai.instr, LlilInstruction::Ret));
    }

    #[test]
    fn test_instr_builder_build_or_nop_default() {
        let ai = InstrBuilder::at(0x1018).build_or_nop();
        assert!(matches!(ai.instr, LlilInstruction::Nop));
    }

    #[test]
    fn test_instr_builder_length() {
        let ai = InstrBuilder::at(0x1020).length(3).nop().build().unwrap();
        assert_eq!(ai.length, 3);
    }

    #[test]
    fn test_instr_builder_cond_jump() {
        let ai = InstrBuilder::at(0x1024)
            .cond_jump(reg_expr("rflags"), 0x2000, 0x3000)
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::ConditionalJump { .. }));
    }

    // â"€â"€ BlockBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_block_builder_empty() {
        let block = BlockBuilder::new(0x1000).build();
        assert_eq!(block.start.0, 0x1000);
        assert!(block.instrs.is_empty());
    }

    #[test]
    fn test_block_builder_add_instrs() {
        let block = BlockBuilder::new(0x1000)
            .instr(InstrBuilder::at(0x1000).nop())
            .instr(InstrBuilder::at(0x1001).ret())
            .build();
        assert_eq!(block.instrs.len(), 2);
    }

    #[test]
    fn test_block_builder_successor() {
        let block = BlockBuilder::new(0x1000).successor(0x2000).build();
        assert_eq!(block.successors.len(), 1);
        assert_eq!(block.successors[0].0, 0x2000);
    }

    #[test]
    fn test_block_builder_instr_count() {
        let mut bb = BlockBuilder::new(0x1000);
        bb = bb.instr(InstrBuilder::at(0x1000).nop());
        bb = bb.instr(InstrBuilder::at(0x1001).nop());
        assert_eq!(bb.instr_count(), 2);
    }

    // â"€â"€ FunctionBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_function_builder_basic() {
        let func = FunctionBuilder::new(0x1000)
            .name("test_func")
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).ret()))
            .build();
        assert_eq!(func.entry.0, 0x1000);
        assert_eq!(func.name.as_deref(), Some("test_func"));
        assert_eq!(func.blocks.len(), 1);
    }

    #[test]
    fn test_function_builder_multi_block() {
        let func = FunctionBuilder::new(0x1000)
            .block(
                BlockBuilder::new(0x1000)
                    .instr(InstrBuilder::at(0x1000).jump(const_expr(0x2000)))
                    .successor(0x2000),
            )
            .block(BlockBuilder::new(0x2000).instr(InstrBuilder::at(0x2000).ret()))
            .build();
        assert_eq!(func.blocks.len(), 2);
    }

    // â"€â"€ LlilBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_llil_builder_add_function() {
        let mut builder = LlilBuilder::new();
        let fb = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).ret()));
        builder.add_function(fb);
        assert_eq!(builder.functions().len(), 1);
    }

    #[test]
    fn test_llil_builder_total_instrs() {
        let mut builder = LlilBuilder::new();
        let fb = FunctionBuilder::new(0x1000).block(
            BlockBuilder::new(0x1000)
                .instr(InstrBuilder::at(0x1000).nop())
                .instr(InstrBuilder::at(0x1001).ret()),
        );
        builder.add_function(fb);
        assert_eq!(builder.total_instrs(), 2);
    }

    #[test]
    fn test_llil_builder_alloc_addr_increments() {
        let mut builder = LlilBuilder::new();
        let a1 = builder.alloc_addr();
        let a2 = builder.alloc_addr();
        assert!(a2 > a1);
    }

    #[test]
    fn test_llil_builder_simple_function() {
        let mut builder = LlilBuilder::new();
        let instrs = vec![InstrBuilder::at(0x1000).nop().build().unwrap()];
        let func = builder.simple_function(0x1000, Some("f"), instrs);
        assert_eq!(func.blocks.len(), 1);
        assert_eq!(func.blocks[0].instrs.len(), 1);
    }

    // â"€â"€ LlilValidator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_validator_empty_function() {
        let func = LlilFunction::new(Address::new(0x1000));
        let errors = LlilValidator::validate(&func);
        assert!(
            errors
                .iter()
                .any(|e| e.kind == ValidationErrorKind::EmptyFunction)
        );
    }

    #[test]
    fn test_validator_valid_function() {
        let func = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).ret()))
            .build();
        assert!(LlilValidator::is_valid(&func));
    }

    #[test]
    fn test_validator_empty_block() {
        let func = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000)) // no instructions
            .build();
        let errors = LlilValidator::validate(&func);
        assert!(
            errors
                .iter()
                .any(|e| e.kind == ValidationErrorKind::EmptyBlock)
        );
    }

    #[test]
    fn test_validator_unresolved_successor() {
        let func = FunctionBuilder::new(0x1000)
            .block(
                BlockBuilder::new(0x1000)
                    .instr(InstrBuilder::at(0x1000).ret())
                    .successor(0x9999),
            ) // doesn't exist
            .build();
        let errors = LlilValidator::validate(&func);
        assert!(
            errors
                .iter()
                .any(|e| e.kind == ValidationErrorKind::UnresolvedSuccessor)
        );
    }

    #[test]
    fn test_validator_duplicate_block() {
        let func = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).nop()))
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).ret()))
            .build();
        let errors = LlilValidator::validate(&func);
        assert!(
            errors
                .iter()
                .any(|e| e.kind == ValidationErrorKind::DuplicateBlockAddress)
        );
    }

    // â"€â"€ LlilPrinter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_printer_print_function_contains_entry() {
        let func = FunctionBuilder::new(0x1000)
            .name("my_func")
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).ret()))
            .build();
        let printer = LlilPrinter::new();
        let output = printer.print_function(&func);
        assert!(output.contains("my_func"));
        assert!(output.contains("0x1000"));
    }

    #[test]
    fn test_printer_format_nop() {
        let printer = LlilPrinter::new();
        assert_eq!(printer.format_instr(&LlilInstruction::Nop), "nop");
    }

    #[test]
    fn test_printer_format_ret() {
        let printer = LlilPrinter::new();
        assert_eq!(printer.format_instr(&LlilInstruction::Ret), "ret");
    }

    #[test]
    fn test_printer_show_lengths() {
        let func = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).length(4).ret()))
            .build();
        let mut printer = LlilPrinter::new();
        printer.show_lengths = true;
        let output = printer.print_function(&func);
        assert!(output.contains("len=4"));
    }

    #[test]
    fn test_printer_print_block_contains_addr() {
        let block = BlockBuilder::new(0x2000)
            .instr(InstrBuilder::at(0x2000).nop())
            .build();
        let printer = LlilPrinter::new();
        let output = printer.print_block(&block);
        assert!(output.contains("0x2000"));
    }

    #[test]
    fn test_printer_no_addresses_when_disabled() {
        let func = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).nop()))
            .build();
        let mut printer = LlilPrinter::new();
        printer.show_addresses = false;
        let output = printer.print_function(&func);
        // Should still have block header but not [0x00001000]
        assert!(!output.contains("[0x00001000]"));
    }

    #[test]
    fn test_validator_resolved_successor_ok() {
        let func = FunctionBuilder::new(0x1000)
            .block(
                BlockBuilder::new(0x1000)
                    .instr(InstrBuilder::at(0x1000).jump(const_expr(0x2000)))
                    .successor(0x2000),
            )
            .block(BlockBuilder::new(0x2000).instr(InstrBuilder::at(0x2000).ret()))
            .build();
        assert!(LlilValidator::is_valid(&func));
    }

    #[test]
    fn test_llil_builder_total_blocks() {
        let mut builder = LlilBuilder::new();
        let fb = FunctionBuilder::new(0x1000)
            .block(BlockBuilder::new(0x1000).instr(InstrBuilder::at(0x1000).nop()))
            .block(BlockBuilder::new(0x2000).instr(InstrBuilder::at(0x2000).ret()));
        builder.add_function(fb);
        assert_eq!(builder.total_blocks(), 2);
    }

    #[test]
    fn test_instr_builder_call() {
        let ai = InstrBuilder::at(0x1028)
            .call(const_expr(0x3000))
            .build()
            .unwrap();
        assert!(matches!(ai.instr, LlilInstruction::Call(_)));
    }

    #[test]
    fn test_block_builder_add_multiple_successors() {
        let block = BlockBuilder::new(0x1000)
            .instr(InstrBuilder::at(0x1000).cond_jump(reg_expr("rflags"), 0x2000, 0x3000))
            .successor(0x2000)
            .successor(0x3000)
            .build();
        assert_eq!(block.successors.len(), 2);
    }

    #[test]
    fn test_function_builder_no_name() {
        let func = FunctionBuilder::new(0x4000)
            .block(BlockBuilder::new(0x4000).instr(InstrBuilder::at(0x4000).ret()))
            .build();
        assert!(func.name.is_none());
    }

    #[test]
    fn test_validator_error_counts() {
        let func = LlilFunction::new(Address::new(0x1000));
        let counts = LlilValidator::error_counts(&func);
        assert!(counts.contains_key(&ValidationErrorKind::EmptyFunction));
    }

    #[test]
    fn test_printer_format_set_reg() {
        let printer = LlilPrinter::new();
        let instr = LlilInstruction::SetReg {
            dest: reg("rax"),
            value: const_expr(42),
            size: Size::QWord,
        };
        let s = printer.format_instr(&instr);
        assert!(s.contains("rax"));
    }

    #[test]
    fn test_printer_format_jump() {
        let printer = LlilPrinter::new();
        let instr = LlilInstruction::Jump(const_expr(0x5000));
        let s = printer.format_instr(&instr);
        assert!(s.contains("jump"));
    }
}

// â"€â"€ LlilStats â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Instruction and block statistics for an LLIL function.
#[derive(Debug, Clone, Default)]
pub struct LlilStats {
    pub total_blocks: usize,
    pub total_instrs: usize,
    pub load_count: usize,
    pub store_count: usize,
    pub call_count: usize,
    pub ret_count: usize,
    pub branch_count: usize,
    pub nop_count: usize,
}

impl LlilStats {
    /// Collect stats for a function.
    #[must_use]
    pub fn for_function(func: &LlilFunction) -> Self {
        let mut s = Self {
            total_blocks: func.blocks.len(),
            ..Self::default()
        };
        for block in &func.blocks {
            s.total_instrs += block.instrs.len();
            for ai in &block.instrs {
                match &ai.instr {
                    LlilInstruction::Load { .. } => s.load_count += 1,
                    LlilInstruction::Store { .. } => s.store_count += 1,
                    LlilInstruction::Call(_) => s.call_count += 1,
                    LlilInstruction::Ret => s.ret_count += 1,
                    LlilInstruction::Jump(_) | LlilInstruction::ConditionalJump { .. } => {
                        s.branch_count += 1;
                    }
                    LlilInstruction::Nop => s.nop_count += 1,
                    _ => {}
                }
            }
        }
        s
    }

    /// Ratio of memory accesses to total instructions.
    #[must_use]
    pub fn memory_ratio(&self) -> f64 {
        if self.total_instrs == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.load_count + self.store_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_instrs).unwrap_or(u32::MAX))
    }

    /// Ratio of branch instructions.
    #[must_use]
    pub fn branch_ratio(&self) -> f64 {
        if self.total_instrs == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.branch_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total_instrs).unwrap_or(u32::MAX))
    }
}

// â"€â"€ LlilDominanceTree â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A simplified dominance tree for LLIL functions.
///
/// Uses iterative dataflow: dom(n) = {n} ∪ (∩ dom(pred(n))).
///
/// All maps use `AHashMap` rather than `std::HashMap` because the keys are
/// block start addresses derived from attacker-controlled binary content.
/// `std::HashMap`'s default `SipHash` is vulnerable to hash-flooding when an
/// adversary can choose input keys; `AHashMap` randomises its seed per-process.
#[derive(Debug, Default)]
pub struct LlilDominanceTree {
    /// Map from block start address → set of dominator block start addresses.
    pub dominators: AHashMap<u64, HashSet<u64>>,
    /// Immediate dominators.
    pub idom: AHashMap<u64, u64>,
}

use std::collections::HashSet;

impl LlilDominanceTree {
    /// Compute the dominance tree for an LLIL function.
    #[must_use]
    pub fn compute(func: &LlilFunction) -> Self {
        if func.blocks.is_empty() {
            return Self::default();
        }
        let entry = func.entry.0;
        let block_addresses: Vec<u64> = func.blocks.iter().map(|b| b.start.0).collect();
        let all: HashSet<u64> = block_addresses.iter().copied().collect();

        // Build predecessor map
        let n = block_addresses.len();
        let mut preds: AHashMap<u64, Vec<u64>> = AHashMap::with_capacity(n);
        for block in &func.blocks {
            for succ in &block.successors {
                preds.entry(succ.0).or_default().push(block.start.0);
            }
        }

        // Initialize dominators
        let mut dominators: AHashMap<u64, HashSet<u64>> = AHashMap::with_capacity(n);
        // Entry block is dominated only by itself
        let mut entry_dom = HashSet::new();
        entry_dom.insert(entry);
        dominators.insert(entry, entry_dom);
        // All other blocks start with "all" as dominators
        for &addr in &block_addresses {
            if addr != entry {
                dominators.insert(addr, all.clone());
            }
        }

        // Fixed-point iteration
        let mut changed = true;
        while changed {
            changed = false;
            for &addr in &block_addresses {
                if addr == entry {
                    continue;
                }
                let pred_list: &[u64] = preds.get(&addr).map_or(&[], Vec::as_slice);
                let new_dom = if pred_list.is_empty() {
                    let mut s = HashSet::new();
                    s.insert(addr);
                    s
                } else {
                    let mut inter = dominators[&pred_list[0]].clone();
                    for &pred in &pred_list[1..] {
                        inter = inter.intersection(&dominators[&pred]).copied().collect();
                    }
                    inter.insert(addr);
                    inter
                };
                if dominators[&addr] != new_dom {
                    dominators.insert(addr, new_dom);
                    changed = true;
                }
            }
        }

        // Compute immediate dominators (strict dominator closest to each node)
        let mut idom = AHashMap::with_capacity(n.saturating_sub(1));
        for &addr in &block_addresses {
            if addr == entry {
                continue;
            }
            let strict_doms: Vec<u64> = dominators[&addr]
                .iter()
                .filter(|&&d| d != addr)
                .copied()
                .collect();
            if !strict_doms.is_empty() {
                // idom = the strict dominator that is dominated by all other strict dominators
                let mut candidate = strict_doms[0];
                for &d in &strict_doms[1..] {
                    if dominators[&d].contains(&candidate) {
                        candidate = d;
                    }
                }
                idom.insert(addr, candidate);
            }
        }

        Self { dominators, idom }
    }

    /// Check if `a` dominates `b`.
    #[must_use]
    pub fn dominates(&self, a: u64, b: u64) -> bool {
        self.dominators
            .get(&b)
            .is_some_and(|dom| dom.contains(&a))
    }

    /// Return the immediate dominator of a block.
    #[must_use]
    pub fn immediate_dominator(&self, addr: u64) -> Option<u64> {
        self.idom.get(&addr).copied()
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::{LlilExpr, LlilRegister, Size};

    fn reg(name: &str) -> LlilRegister {
        LlilRegister::Concrete(name.into())
    }
    fn c(v: u64) -> LlilExpr {
        LlilExpr::Const { value: v, size: Size::QWord }
    }

    fn two_block_func() -> LlilFunction {
        FunctionBuilder::new(0x1000)
            .block(
                BlockBuilder::new(0x1000)
                    .instr(InstrBuilder::at(0x1000).jump(c(0x2000)))
                    .successor(0x2000),
            )
            .block(BlockBuilder::new(0x2000).instr(InstrBuilder::at(0x2000).ret()))
            .build()
    }

    #[test]
    fn test_stats_for_function() {
        let func = two_block_func();
        let stats = LlilStats::for_function(&func);
        assert_eq!(stats.total_blocks, 2);
        assert_eq!(stats.total_instrs, 2);
        assert_eq!(stats.branch_count, 1);
        assert_eq!(stats.ret_count, 1);
    }

    #[test]
    fn test_stats_memory_ratio() {
        let mut builder = LlilBuilder::new();
        let addr = 0x1000;
        let func = builder.simple_function(
            addr,
            None,
            vec![
                InstrBuilder::at(addr)
                    .load(reg("rax"), c(0x2000), Size::QWord)
                    .build()
                    .unwrap(),
                InstrBuilder::at(addr + 4)
                    .store(c(0x3000), c(42), Size::DWord)
                    .build()
                    .unwrap(),
                InstrBuilder::at(addr + 8).ret().build().unwrap(),
            ],
        );
        let stats = LlilStats::for_function(&func);
        assert!((stats.memory_ratio() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_stats_nop_count() {
        let mut builder = LlilBuilder::new();
        let func = builder.simple_function(
            0x1000,
            None,
            vec![
                InstrBuilder::at(0x1000).nop().build().unwrap(),
                InstrBuilder::at(0x1001).nop().build().unwrap(),
                InstrBuilder::at(0x1002).ret().build().unwrap(),
            ],
        );
        let stats = LlilStats::for_function(&func);
        assert_eq!(stats.nop_count, 2);
    }

    #[test]
    fn test_dominance_entry_dominates_all() {
        let func = two_block_func();
        let dom = LlilDominanceTree::compute(&func);
        // Entry (0x1000) should dominate 0x2000
        assert!(dom.dominates(0x1000, 0x2000));
    }

    #[test]
    fn test_dominance_entry_dominates_itself() {
        let func = two_block_func();
        let dom = LlilDominanceTree::compute(&func);
        assert!(dom.dominates(0x1000, 0x1000));
    }

    #[test]
    fn test_dominance_idom_second_block() {
        let func = two_block_func();
        let dom = LlilDominanceTree::compute(&func);
        assert_eq!(dom.immediate_dominator(0x2000), Some(0x1000));
    }

    #[test]
    fn test_dominance_empty_function() {
        let func = LlilFunction::new(Address::new(0x1000));
        let dom = LlilDominanceTree::compute(&func);
        assert!(dom.dominators.is_empty());
    }
}
