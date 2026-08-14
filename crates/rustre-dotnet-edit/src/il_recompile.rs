//! .NET IL recompiler — modify IL method bodies and write them back to bytes.
//!
//! # Components
//!
//! * [`IlEdit`] — a single edit operation on an IL method body.
//! * [`EditSession`] — an editing session with a full undo history.
//! * [`IlValidator`] — structural validation of an edited instruction sequence.
//!   (See also the validator already present in `lib.rs`; this module provides
//!   an extended, standalone version with stack-depth tracking.)
//! * [`MethodBodyWriter`] — serialises an edited method body to CIL bytes.
//! * [`PatchedAssembly`] — tracks all per-method edits across an assembly and
//!   can produce a diff report.

use std::collections::HashMap;

use rustre_dotnet::{CilInstruction, CilOperand};

// ─────────────────────────────────────────────────────────────────────────────
// IlEdit — a single edit operation
// ─────────────────────────────────────────────────────────────────────────────

/// A single, reversible edit to an IL instruction list.
#[derive(Debug, Clone)]
pub enum IlEdit {
    /// Insert a new instruction before the one at `offset`.
    InsertInstruction {
        before_offset: u32,
        instruction: CilInstruction,
    },
    /// Remove the instruction at `offset`.
    RemoveInstruction { offset: u32 },
    /// Replace the instruction at `offset` with a new one.
    ReplaceInstruction {
        offset: u32,
        new_instruction: CilInstruction,
    },
    /// Change only the operand of the instruction at `offset`.
    ChangeOperand {
        offset: u32,
        new_operand: CilOperand,
    },
    /// Swap the positions of two adjacent instructions.
    SwapInstructions { offset_a: u32, offset_b: u32 },
    /// Prepend a block of instructions at the start of the body.
    Prepend { instructions: Vec<CilInstruction> },
    /// Append a block of instructions before the final `ret`.
    Append { instructions: Vec<CilInstruction> },
    /// Replace a contiguous range `[start_offset, end_offset)` with new instructions.
    ReplaceRange {
        start_offset: u32,
        end_offset: u32,
        new_instructions: Vec<CilInstruction>,
    },
}

impl IlEdit {
    /// Human-readable description of this edit.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::InsertInstruction {
                before_offset,
                instruction,
            } => format!(
                "insert {} before offset 0x{before_offset:04X}",
                instruction.opcode
            ),
            Self::RemoveInstruction { offset } => {
                format!("remove instruction at offset 0x{offset:04X}")
            }
            Self::ReplaceInstruction {
                offset,
                new_instruction,
            } => format!(
                "replace offset 0x{offset:04X} with {}",
                new_instruction.opcode
            ),
            Self::ChangeOperand { offset, .. } => {
                format!("change operand at offset 0x{offset:04X}")
            }
            Self::SwapInstructions { offset_a, offset_b } => {
                format!("swap 0x{offset_a:04X} <-> 0x{offset_b:04X}")
            }
            Self::Prepend { instructions } => {
                format!("prepend {} instructions", instructions.len())
            }
            Self::Append { instructions } => format!("append {} instructions", instructions.len()),
            Self::ReplaceRange {
                start_offset,
                end_offset,
                new_instructions,
            } => format!(
                "replace range [0x{start_offset:04X}, 0x{end_offset:04X}) with {} instructions",
                new_instructions.len()
            ),
        }
    }

    /// Apply this edit to `instructions`.
    ///
    /// # Errors
    /// Returns an error message if the target offset does not exist.
    pub fn apply(&self, instructions: &mut Vec<CilInstruction>) -> Result<(), String> {
        match self {
            Self::InsertInstruction {
                before_offset,
                instruction,
            } => {
                let pos = instructions
                    .iter()
                    .position(|i| i.offset == *before_offset)
                    .ok_or_else(|| format!("offset 0x{before_offset:04X} not found"))?;
                instructions.insert(pos, instruction.clone());
                Ok(())
            }
            Self::RemoveInstruction { offset } => {
                let pos = instructions
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| format!("offset 0x{offset:04X} not found"))?;
                instructions.remove(pos);
                Ok(())
            }
            Self::ReplaceInstruction {
                offset,
                new_instruction,
            } => {
                let pos = instructions
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| format!("offset 0x{offset:04X} not found"))?;
                instructions[pos] = new_instruction.clone();
                Ok(())
            }
            Self::ChangeOperand {
                offset,
                new_operand,
            } => {
                let pos = instructions
                    .iter()
                    .position(|i| i.offset == *offset)
                    .ok_or_else(|| format!("offset 0x{offset:04X} not found"))?;
                instructions[pos].operand = new_operand.clone();
                Ok(())
            }
            Self::SwapInstructions { offset_a, offset_b } => {
                let pos_a = instructions
                    .iter()
                    .position(|i| i.offset == *offset_a)
                    .ok_or_else(|| format!("offset 0x{offset_a:04X} not found"))?;
                let pos_b = instructions
                    .iter()
                    .position(|i| i.offset == *offset_b)
                    .ok_or_else(|| format!("offset 0x{offset_b:04X} not found"))?;
                instructions.swap(pos_a, pos_b);
                Ok(())
            }
            Self::Prepend { instructions: new } => {
                // splice new instructions at the front in one pass
                let tail = instructions.split_off(0);
                instructions.extend(new.iter().cloned());
                instructions.extend(tail);
                Ok(())
            }
            Self::Append { instructions: new } => {
                let ret_pos = instructions.iter().rposition(|i| i.opcode == "ret");
                let insert_at = ret_pos.unwrap_or(instructions.len());
                // splice new instructions before `ret` in one pass
                let tail = instructions.split_off(insert_at);
                instructions.extend(new.iter().cloned());
                instructions.extend(tail);
                Ok(())
            }
            Self::ReplaceRange {
                start_offset,
                end_offset,
                new_instructions,
            } => {
                instructions.retain(|i| i.offset < *start_offset || i.offset >= *end_offset);
                let insert_pos = instructions
                    .iter()
                    .position(|i| i.offset >= *start_offset)
                    .unwrap_or(instructions.len());
                // splice replacement instructions in one pass
                let tail = instructions.split_off(insert_pos);
                instructions.extend(new_instructions.iter().cloned());
                instructions.extend(tail);
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EditSession — undo/redo history for one method body
// ─────────────────────────────────────────────────────────────────────────────

/// An interactive editing session for a single IL method body.
///
/// Maintains a snapshot-based undo history so that any edit can be reversed.
#[derive(Debug, Clone)]
pub struct EditSession {
    /// Name of the method being edited (for display / error messages).
    pub method_name: String,
    /// Current instruction list.
    pub instructions: Vec<CilInstruction>,
    /// Undo stack: each entry is the full instruction list *before* an edit was applied.
    undo_stack: Vec<Vec<CilInstruction>>,
    /// Description of each edit on the undo stack (parallel to `undo_stack`).
    undo_descriptions: Vec<String>,
    /// Edits applied (for producing a diff / changelog).
    applied_edits: Vec<String>,
}

impl EditSession {
    /// Create a new session for the given method.
    #[must_use]
    pub fn new(method_name: impl Into<String>, instructions: Vec<CilInstruction>) -> Self {
        Self {
            method_name: method_name.into(),
            instructions,
            undo_stack: Vec::new(),
            undo_descriptions: Vec::new(),
            applied_edits: Vec::new(),
        }
    }

    /// Apply an edit, pushing the current state onto the undo stack.
    ///
    /// # Errors
    /// Returns an error string if the edit's target offset is not present.
    pub fn apply(&mut self, edit: IlEdit) -> Result<(), String> {
        let snapshot = self.instructions.clone();
        let desc = edit.description();
        edit.apply(&mut self.instructions)?;
        self.undo_stack.push(snapshot);
        self.undo_descriptions.push(desc.clone());
        self.applied_edits.push(desc);
        // Renumber offsets after the edit so they stay consistent.
        self.renumber_offsets();
        Ok(())
    }

    /// Apply multiple edits in sequence, rolling back all on the first failure.
    ///
    /// # Errors
    /// Returns the description of the failing edit plus its error.
    pub fn apply_all(&mut self, edits: Vec<IlEdit>) -> Result<(), String> {
        let checkpoint = self.instructions.clone();
        let undo_len = self.undo_stack.len();
        for edit in edits {
            if let Err(e) = self.apply(edit) {
                // Roll back to checkpoint
                self.instructions = checkpoint;
                self.undo_stack.truncate(undo_len);
                self.undo_descriptions.truncate(undo_len);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Undo the last applied edit.
    ///
    /// # Errors
    /// Returns an error if there is nothing to undo.
    pub fn undo(&mut self) -> Result<(), String> {
        let snapshot = self
            .undo_stack
            .pop()
            .ok_or_else(|| "nothing to undo".to_string())?;
        let _ = self.undo_descriptions.pop();
        self.instructions = snapshot;
        Ok(())
    }

    /// Undo `n` edits.
    ///
    /// # Errors
    /// Returns an error if there are fewer than `n` edits on the stack.
    pub fn undo_n(&mut self, n: usize) -> Result<(), String> {
        if self.undo_stack.len() < n {
            return Err(format!(
                "cannot undo {n}: only {} edits in history",
                self.undo_stack.len()
            ));
        }
        for _ in 0..n {
            self.undo()?;
        }
        Ok(())
    }

    /// Reset to the original (oldest undo-stack snapshot) state.
    pub fn reset(&mut self) {
        if let Some(original) = self.undo_stack.first().cloned() {
            self.instructions = original;
            self.undo_stack.clear();
            self.undo_descriptions.clear();
        }
    }

    /// How many edits can be undone.
    #[must_use]
    pub const fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    /// Returns true if any edits have been applied.
    #[must_use]
    pub const fn is_modified(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Human-readable changelog of all applied edits.
    #[must_use]
    pub fn changelog(&self) -> &[String] {
        &self.applied_edits
    }

    /// Descriptions of edits on the undo stack (most recent last).
    #[must_use]
    pub fn undo_history(&self) -> &[String] {
        &self.undo_descriptions
    }

    /// Returns the current instruction count.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Renumber instruction offsets sequentially by opcode byte-size.
    ///
    /// Uses a rough heuristic (1 byte for simple opcodes, 5 bytes for token/branch,
    /// etc.).  A real implementation would use the ECMA-335 encoding table.
    pub fn renumber_offsets(&mut self) {
        let mut off: u32 = 0;
        for instr in &mut self.instructions {
            instr.offset = off;
            off += instruction_encoded_size(instr);
        }
    }

    /// Find the instruction at logical (post-renumber) `offset`.
    #[must_use]
    pub fn find_at_offset(&self, offset: u32) -> Option<&CilInstruction> {
        self.instructions.iter().find(|i| i.offset == offset)
    }

    /// Find the first instruction with opcode `opcode`.
    #[must_use]
    pub fn find_by_opcode(&self, opcode: &str) -> Option<&CilInstruction> {
        self.instructions.iter().find(|i| i.opcode == opcode)
    }
}

/// Approximate encoded byte size of a CIL instruction.
fn instruction_encoded_size(instr: &CilInstruction) -> u32 {
    match instr.opcode.as_str() {
        "nop" | "ret" | "ldnull" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3"
        | "ldc.i4.4" | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" | "ldc.i4.m1"
        | "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3" | "ldloc.0" | "ldloc.1" | "ldloc.2"
        | "ldloc.3" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "add" | "sub" | "mul"
        | "div" | "rem" | "and" | "or" | "xor" | "neg" | "not" | "dup" | "pop" | "throw"
        | "ldlen" | "endfinally" => 1,
        "ldc.i4.s" | "br.s" | "brfalse.s" | "brtrue.s" => 2,
        "ldarg.s" | "starg.s" | "ldloc.s" | "stloc.s" => 2,
        "ldc.i4" | "br" | "brfalse" | "brtrue" => 5,
        "ldc.i8" => 9,
        "ldc.r4" => 5,
        "ldc.r8" => 9,
        "call" | "callvirt" | "newobj" | "ldstr" | "ldfld" | "stfld" | "ldsfld" | "stsfld"
        | "box" | "newarr" | "castclass" | "isinst" | "jmp" => 5,
        "ceq" | "cgt" | "clt" | "cgt.un" | "clt.un" => 2, // FE xx prefix
        _ => 1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IlStackValidator — extended validation with stack-depth tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a validation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Warning,
    Error,
}

/// A single validation diagnostic produced by [`IlStackValidator`].
#[derive(Debug, Clone)]
pub struct ValidationDiagnostic {
    pub offset: u32,
    pub message: String,
    pub severity: ValidationSeverity,
}

impl ValidationDiagnostic {
    fn err(offset: u32, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
            severity: ValidationSeverity::Error,
        }
    }
    fn warn(offset: u32, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
            severity: ValidationSeverity::Warning,
        }
    }
}

/// Validates an IL instruction sequence for structural correctness.
///
/// Checks performed:
/// 1. Non-empty body.
/// 2. Body terminates with a valid terminator.
/// 3. No duplicate offsets.
/// 4. Branch targets resolve to known offsets.
/// 5. Approximate stack depth (1-level linear tracking — does not follow branches).
/// 6. No instructions after an unconditional terminator (dead code warning).
#[derive(Debug, Default)]
pub struct IlStackValidator {
    /// Initial stack depth (0 for most methods, 1 for instance constructors when `this` is pushed).
    pub initial_stack_depth: i32,
    /// Maximum allowed stack depth (default: 64).
    pub max_stack_depth: i32,
}

impl IlStackValidator {
    /// Create a validator with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initial_stack_depth: 0,
            max_stack_depth: 64,
        }
    }

    /// Validate `instructions`.  Returns a list of diagnostics.  An empty
    /// list means no issues were found.
    #[must_use]
    pub fn validate(&self, instructions: &[CilInstruction]) -> Vec<ValidationDiagnostic> {
        let mut diags = Vec::new();

        if instructions.is_empty() {
            diags.push(ValidationDiagnostic::warn(0, "empty method body"));
            return diags;
        }

        // Check terminator
        let last = instructions.last().unwrap();
        if !is_terminator(&last.opcode) {
            diags.push(ValidationDiagnostic::err(
                last.offset,
                format!(
                    "body does not end with a terminator (last: {})",
                    last.opcode
                ),
            ));
        }

        // Collect valid offsets for branch-target validation
        let offset_set: std::collections::HashSet<u32> =
            instructions.iter().map(|i| i.offset).collect();

        // Check for duplicate offsets
        let mut seen_offsets = std::collections::HashSet::new();
        for instr in instructions {
            if !seen_offsets.insert(instr.offset) {
                diags.push(ValidationDiagnostic::err(
                    instr.offset,
                    format!("duplicate offset 0x{:04X}", instr.offset),
                ));
            }
        }

        // Stack tracking and branch target validation
        let mut stack_depth = self.initial_stack_depth;
        let mut after_unconditional = false;

        for instr in instructions {
            if after_unconditional {
                diags.push(ValidationDiagnostic::warn(
                    instr.offset,
                    format!(
                        "dead code: instruction after unconditional terminator ({})",
                        instr.opcode
                    ),
                ));
            }

            // Validate branch targets
            match &instr.operand {
                CilOperand::Branch(target) => {
                    if !offset_set.contains(target) {
                        diags.push(ValidationDiagnostic::err(
                            instr.offset,
                            format!(
                                "branch target 0x{target:04X} does not match any instruction offset"
                            ),
                        ));
                    }
                }
                CilOperand::Switch(targets) => {
                    for &t in targets {
                        if !offset_set.contains(&t) {
                            diags.push(ValidationDiagnostic::err(
                                instr.offset,
                                format!(
                                    "switch target 0x{t:04X} does not match any instruction offset"
                                ),
                            ));
                        }
                    }
                }
                _ => {}
            }

            // Stack effect
            stack_depth += stack_effect(&instr.opcode);
            if stack_depth > self.max_stack_depth {
                diags.push(ValidationDiagnostic::err(
                    instr.offset,
                    format!(
                        "stack overflow: depth {} exceeds limit {}",
                        stack_depth, self.max_stack_depth
                    ),
                ));
            }
            if stack_depth < 0 {
                diags.push(ValidationDiagnostic::err(
                    instr.offset,
                    format!("stack underflow at opcode {}", instr.opcode),
                ));
                stack_depth = 0; // recover
            }

            if is_unconditional_terminator(&instr.opcode) {
                after_unconditional = true;
            }
        }

        // Final stack should be 0 for void methods
        if stack_depth != 0 && !instructions.iter().any(|i| i.opcode == "ret") {
            diags.push(ValidationDiagnostic::warn(
                0,
                format!("stack depth at end of method is {stack_depth} (expected 0 for void)"),
            ));
        }

        diags
    }

    /// Returns `true` if all diagnostics are non-errors.
    #[must_use]
    pub fn is_valid(diags: &[ValidationDiagnostic]) -> bool {
        diags
            .iter()
            .all(|d| d.severity != ValidationSeverity::Error)
    }
}

fn is_terminator(opcode: &str) -> bool {
    matches!(opcode, "ret" | "throw" | "rethrow" | "br" | "br.s" | "jmp")
}

fn is_unconditional_terminator(opcode: &str) -> bool {
    matches!(opcode, "ret" | "throw" | "rethrow" | "br" | "br.s" | "jmp")
}

/// Returns the approximate net stack effect of an opcode (+N pushes, -M pops).
fn stack_effect(opcode: &str) -> i32 {
    match opcode {
        // Push-only
        "ldc.i4" | "ldc.i4.s" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3" | "ldc.i4.4"
        | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" | "ldc.i4.m1" | "ldc.i8" | "ldc.r4"
        | "ldc.r8" | "ldnull" | "ldstr" | "ldarg.0" | "ldarg.1" | "ldarg.2" | "ldarg.3"
        | "ldarg.s" | "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc.s" | "ldsfld"
        | "ldlen" | "newarr" => 1,
        // Pop-only
        "pop" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "starg.s"
        | "stsfld" | "throw" | "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s" | "switch" => -1,
        // Binary ops: pop 2, push 1
        "add" | "sub" | "mul" | "div" | "rem" | "and" | "or" | "xor" | "shl" | "shr" | "shr.un"
        | "ceq" | "cgt" | "clt" | "cgt.un" | "clt.un" | "ldfld" | "ldelem.i4" | "ldelem.ref" => -1,
        "stfld" | "stelem.i4" | "stelem.ref" => -3,
        // Dup: net +1
        "dup" => 1,
        // Ret, nop, br: net 0
        "ret" | "nop" | "br" | "br.s" | "jmp" | "rethrow" => 0,
        // Call: simplified (we don't track signatures here)
        "call" | "callvirt" | "newobj" => 0,
        // Unary: net 0
        "neg" | "not" | "conv.i4" | "conv.i8" | "conv.u4" | "conv.u8" | "box" | "castclass"
        | "isinst" | "unbox.any" => 0,
        _ => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MethodBodyWriter — serialise an edited method body to raw CIL bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Serialises an IL method body to a raw byte sequence suitable for embedding
/// in a .NET PE.
///
/// Supports both tiny (body < 64 bytes, no locals) and fat format.
#[derive(Debug, Default)]
pub struct MethodBodyWriter {
    /// Override max stack.  If `None`, estimated from instructions.
    pub max_stack: Option<u16>,
    /// Local variable signature token (0 if no locals).
    pub local_var_sig_tok: u32,
    /// Whether to set the `InitLocals` flag.
    pub init_locals: bool,
}

impl MethodBodyWriter {
    /// Create a writer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `max_stack` explicitly.
    #[must_use]
    pub const fn with_max_stack(mut self, max_stack: u16) -> Self {
        self.max_stack = Some(max_stack);
        self
    }

    /// Set the `LocalVarSig` token.
    #[must_use]
    pub const fn with_local_var_sig(mut self, tok: u32) -> Self {
        self.local_var_sig_tok = tok;
        self
    }

    /// Serialise `instructions` to a CIL body blob.
    ///
    /// Returns the raw bytes including the tiny or fat method header.
    #[must_use]
    pub fn write(&self, instructions: &[CilInstruction]) -> Vec<u8> {
        let code = self.encode_instructions(instructions);
        let code_size = code.len();

        let use_tiny = code_size < 64 && self.local_var_sig_tok == 0 && !self.init_locals;

        if use_tiny {
            let mut out = Vec::with_capacity(1 + code_size);
            out.push(((code_size as u8) << 2) | 0x02); // tiny format
            out.extend_from_slice(&code);
            out
        } else {
            // Fat header: 12 bytes
            let max_stack = self
                .max_stack
                .unwrap_or_else(|| self.estimate_max_stack(instructions));
            let mut flags: u16 = 0x3; // fat format
            if self.init_locals {
                flags |= 0x10;
            }
            // Size of header in dwords (3 = 12 bytes)
            let header_word: u16 = flags | (3 << 12);
            let mut out = Vec::with_capacity(12 + code_size);
            out.extend_from_slice(&header_word.to_le_bytes());
            out.extend_from_slice(&max_stack.to_le_bytes());
            out.extend_from_slice(&(code_size as u32).to_le_bytes());
            out.extend_from_slice(&self.local_var_sig_tok.to_le_bytes());
            out.extend_from_slice(&code);
            // Align to 4 bytes
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out
        }
    }

    /// Write a body from an [`EditSession`] (uses session's current instructions).
    #[must_use]
    pub fn write_session(&self, session: &EditSession) -> Vec<u8> {
        self.write(&session.instructions)
    }

    fn estimate_max_stack(&self, instructions: &[CilInstruction]) -> u16 {
        let mut depth: i32 = 0;
        let mut max: i32 = 0;
        for instr in instructions {
            depth += stack_effect(&instr.opcode);
            if depth > max {
                max = depth;
            }
        }
        (max.max(0) as u16).max(8)
    }

    fn encode_instructions(&self, instructions: &[CilInstruction]) -> Vec<u8> {
        let mut out = Vec::with_capacity(instructions.len() * 2);
        for instr in instructions {
            encode_one(instr, &mut out);
        }
        out
    }
}

fn encode_one(instr: &CilInstruction, out: &mut Vec<u8>) {
    match instr.opcode.as_str() {
        "ret" => out.push(0x2A),
        "ldnull" => out.push(0x14),
        "ldc.i4.0" => out.push(0x16),
        "ldc.i4.1" => out.push(0x17),
        "ldc.i4.2" => out.push(0x18),
        "ldc.i4.3" => out.push(0x19),
        "ldc.i4.4" => out.push(0x1A),
        "ldc.i4.5" => out.push(0x1B),
        "ldc.i4.6" => out.push(0x1C),
        "ldc.i4.7" => out.push(0x1D),
        "ldc.i4.8" => out.push(0x1E),
        "ldc.i4.m1" => out.push(0x15),
        "ldc.i4.s" => {
            out.push(0x1F);
            out.push(match instr.operand {
                CilOperand::Int8(v) => v as u8,
                _ => 0,
            });
        }
        "ldc.i4" => {
            out.push(0x20);
            let v = match instr.operand {
                CilOperand::Int32(v) => v,
                _ => 0,
            };
            out.extend_from_slice(&v.to_le_bytes());
        }
        "ldc.i8" => {
            out.push(0x21);
            let v = match instr.operand {
                CilOperand::Int64(v) => v,
                _ => 0,
            };
            out.extend_from_slice(&v.to_le_bytes());
        }
        "ldarg.0" => out.push(0x02),
        "ldarg.1" => out.push(0x03),
        "ldarg.2" => out.push(0x04),
        "ldarg.3" => out.push(0x05),
        "ldloc.0" => out.push(0x06),
        "ldloc.1" => out.push(0x07),
        "ldloc.2" => out.push(0x08),
        "ldloc.3" => out.push(0x09),
        "stloc.0" => out.push(0x0A),
        "stloc.1" => out.push(0x0B),
        "stloc.2" => out.push(0x0C),
        "stloc.3" => out.push(0x0D),
        "add" => out.push(0x58),
        "sub" => out.push(0x59),
        "mul" => out.push(0x5A),
        "div" => out.push(0x5B),
        "rem" => out.push(0x5D),
        "and" => out.push(0x5F),
        "or" => out.push(0x60),
        "xor" => out.push(0x61),
        "neg" => out.push(0x65),
        "not" => out.push(0x66),
        "dup" => out.push(0x25),
        "pop" => out.push(0x26),
        "throw" => out.push(0x7A),
        "ldlen" => out.push(0x8E),
        "endfinally" => out.push(0xDC),
        "call" => {
            out.push(0x28);
            push_tok(instr, out);
        }
        "callvirt" => {
            out.push(0x6F);
            push_tok(instr, out);
        }
        "newobj" => {
            out.push(0x73);
            push_tok(instr, out);
        }
        "jmp" => {
            out.push(0x27);
            push_tok(instr, out);
        }
        "ldstr" => {
            out.push(0x72);
            push_tok(instr, out);
        }
        "ldfld" => {
            out.push(0x7B);
            push_tok(instr, out);
        }
        "stfld" => {
            out.push(0x7D);
            push_tok(instr, out);
        }
        "ldsfld" => {
            out.push(0x7E);
            push_tok(instr, out);
        }
        "stsfld" => {
            out.push(0x80);
            push_tok(instr, out);
        }
        "box" => {
            out.push(0x8C);
            push_tok(instr, out);
        }
        "newarr" => {
            out.push(0x8D);
            push_tok(instr, out);
        }
        "castclass" => {
            out.push(0x74);
            push_tok(instr, out);
        }
        "isinst" => {
            out.push(0x75);
            push_tok(instr, out);
        }
        "br.s" => {
            out.push(0x2B);
            out.push(match instr.operand {
                CilOperand::Branch(t) => t as u8,
                _ => 0,
            });
        }
        "brfalse.s" => {
            out.push(0x2C);
            out.push(match instr.operand {
                CilOperand::Branch(t) => t as u8,
                _ => 0,
            });
        }
        "brtrue.s" => {
            out.push(0x2D);
            out.push(match instr.operand {
                CilOperand::Branch(t) => t as u8,
                _ => 0,
            });
        }
        "br" => {
            out.push(0x38);
            let t = match instr.operand {
                CilOperand::Branch(t) => t,
                _ => 0,
            };
            out.extend_from_slice(&t.to_le_bytes());
        }
        "brfalse" => {
            out.push(0x39);
            let t = match instr.operand {
                CilOperand::Branch(t) => t,
                _ => 0,
            };
            out.extend_from_slice(&t.to_le_bytes());
        }
        "brtrue" => {
            out.push(0x3A);
            let t = match instr.operand {
                CilOperand::Branch(t) => t,
                _ => 0,
            };
            out.extend_from_slice(&t.to_le_bytes());
        }
        "switch" => {
            out.push(0x45);
            if let CilOperand::Switch(ref targets) = instr.operand {
                out.extend_from_slice(&(targets.len() as u32).to_le_bytes());
                for &t in targets {
                    out.extend_from_slice(&(t as i32).to_le_bytes());
                }
            } else {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        "ceq" => {
            out.push(0xFE);
            out.push(0x01);
        }
        "cgt" => {
            out.push(0xFE);
            out.push(0x02);
        }
        "clt" => {
            out.push(0xFE);
            out.push(0x04);
        }
        _ => out.push(0x00),
    }
}

fn push_tok(instr: &CilInstruction, out: &mut Vec<u8>) {
    let t = match instr.operand {
        CilOperand::Token(t) => t,
        _ => 0,
    };
    out.extend_from_slice(&t.to_le_bytes());
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchedAssembly — aggregate edits across an assembly
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks all IL edits applied across multiple methods in an assembly.
///
/// Key: `"{TypeName}::{MethodName}"`.
#[derive(Debug, Default)]
pub struct PatchedAssembly {
    sessions: HashMap<String, EditSession>,
    writer: MethodBodyWriter,
}

impl PatchedAssembly {
    /// Create an empty patched-assembly tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom body writer.
    #[must_use]
    pub fn with_writer(writer: MethodBodyWriter) -> Self {
        Self {
            sessions: HashMap::new(),
            writer,
        }
    }

    /// Open (or reuse) an edit session for a method.
    ///
    /// If no session exists yet, `initial_body` is used as the starting state.
    pub fn session(
        &mut self,
        type_name: &str,
        method_name: &str,
        initial_body: Vec<CilInstruction>,
    ) -> &mut EditSession {
        let key = format!("{type_name}::{method_name}");
        self.sessions
            .entry(key.clone())
            .or_insert_with(|| EditSession::new(key, initial_body))
    }

    /// Apply a single edit to a method.
    ///
    /// # Errors
    /// Returns an error if the edit cannot be applied.
    pub fn apply_edit(
        &mut self,
        type_name: &str,
        method_name: &str,
        initial_body: Vec<CilInstruction>,
        edit: IlEdit,
    ) -> Result<(), String> {
        let session = self.session(type_name, method_name, initial_body);
        session.apply(edit)
    }

    /// Serialise the edited body for `(type_name, method_name)`.
    ///
    /// Returns `None` if no session exists for that method.
    #[must_use]
    pub fn serialise_body(&self, type_name: &str, method_name: &str) -> Option<Vec<u8>> {
        let key = format!("{type_name}::{method_name}");
        let session = self.sessions.get(&key)?;
        Some(self.writer.write_session(session))
    }

    /// Returns `true` if any method has been patched.
    #[must_use]
    pub fn has_patches(&self) -> bool {
        self.sessions.values().any(EditSession::is_modified)
    }

    /// Number of distinct methods with active edit sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Produce a human-readable diff report for all patched methods.
    #[must_use]
    pub fn diff_report(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut keys: Vec<&str> = self.sessions.keys().map(String::as_str).collect();
        keys.sort_unstable();
        for key in keys {
            let session = &self.sessions[key];
            if session.is_modified() {
                lines.push(format!("--- {key} ---"));
                for entry in session.changelog() {
                    lines.push(format!("  {entry}"));
                }
            }
        }
        lines
    }

    /// Validate all patched method bodies.
    ///
    /// Returns a map from method key → list of diagnostics.  Only methods that
    /// have diagnostics are included.
    #[must_use]
    pub fn validate_all(&self) -> HashMap<String, Vec<ValidationDiagnostic>> {
        let validator = IlStackValidator::new();
        let mut result = HashMap::new();
        for (key, session) in &self.sessions {
            let diags = validator.validate(&session.instructions);
            if !diags.is_empty() {
                result.insert(key.clone(), diags);
            }
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(off: u32, opcode: &str) -> CilInstruction {
        CilInstruction::simple(off, opcode)
    }

    fn with_i32(off: u32, opcode: &str, v: i32) -> CilInstruction {
        CilInstruction {
            offset: off,
            opcode: opcode.to_string(),
            operand: CilOperand::Int32(v),
        }
    }

    fn with_branch(off: u32, opcode: &str, target: u32) -> CilInstruction {
        CilInstruction {
            offset: off,
            opcode: opcode.to_string(),
            operand: CilOperand::Branch(target),
        }
    }

    fn body() -> Vec<CilInstruction> {
        vec![simple(0, "ldc.i4.0"), simple(1, "ret")]
    }

    // ── IlEdit::description ───────────────────────────────────────────────────

    #[test]
    fn test_il_edit_description_insert() {
        let edit = IlEdit::InsertInstruction {
            before_offset: 0,
            instruction: simple(0, "nop"),
        };
        assert!(edit.description().contains("insert"));
    }

    #[test]
    fn test_il_edit_description_remove() {
        let edit = IlEdit::RemoveInstruction { offset: 0 };
        assert!(edit.description().contains("remove"));
    }

    // ── IlEdit::apply ────────────────────────────────────────────────────────

    #[test]
    fn test_insert_instruction() {
        let mut instrs = body();
        IlEdit::InsertInstruction {
            before_offset: 0,
            instruction: simple(0, "nop"),
        }
        .apply(&mut instrs)
        .unwrap();
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].opcode, "nop");
    }

    #[test]
    fn test_remove_instruction() {
        let mut instrs = body();
        IlEdit::RemoveInstruction { offset: 0 }
            .apply(&mut instrs)
            .unwrap();
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_replace_instruction() {
        let mut instrs = body();
        IlEdit::ReplaceInstruction {
            offset: 0,
            new_instruction: simple(0, "ldc.i4.1"),
        }
        .apply(&mut instrs)
        .unwrap();
        assert_eq!(instrs[0].opcode, "ldc.i4.1");
    }

    #[test]
    fn test_change_operand() {
        let mut instrs = vec![with_i32(0, "ldc.i4", 10), simple(5, "ret")];
        IlEdit::ChangeOperand {
            offset: 0,
            new_operand: CilOperand::Int32(99),
        }
        .apply(&mut instrs)
        .unwrap();
        assert_eq!(instrs[0].operand, CilOperand::Int32(99));
    }

    #[test]
    fn test_prepend() {
        let mut instrs = body();
        IlEdit::Prepend {
            instructions: vec![simple(0, "nop")],
        }
        .apply(&mut instrs)
        .unwrap();
        assert_eq!(instrs[0].opcode, "nop");
        assert_eq!(instrs.len(), 3);
    }

    #[test]
    fn test_append_before_ret() {
        let mut instrs = body();
        IlEdit::Append {
            instructions: vec![simple(0, "pop")],
        }
        .apply(&mut instrs)
        .unwrap();
        // pop should appear before ret
        let pop_pos = instrs.iter().position(|i| i.opcode == "pop").unwrap();
        let ret_pos = instrs.iter().position(|i| i.opcode == "ret").unwrap();
        assert!(pop_pos < ret_pos);
    }

    #[test]
    fn test_replace_range() {
        let mut instrs = vec![
            simple(0, "ldc.i4.0"),
            simple(1, "ldc.i4.1"),
            simple(2, "ret"),
        ];
        IlEdit::ReplaceRange {
            start_offset: 0,
            end_offset: 2,
            new_instructions: vec![simple(0, "ldc.i4.5")],
        }
        .apply(&mut instrs)
        .unwrap();
        assert_eq!(instrs[0].opcode, "ldc.i4.5");
        assert_eq!(instrs[1].opcode, "ret");
    }

    #[test]
    fn test_apply_offset_not_found() {
        let mut instrs = body();
        let res = IlEdit::RemoveInstruction { offset: 0xFF }.apply(&mut instrs);
        assert!(res.is_err());
    }

    // ── EditSession ───────────────────────────────────────────────────────────

    #[test]
    fn test_session_apply_and_undo() {
        let mut session = EditSession::new("Test::Method", body());
        session
            .apply(IlEdit::InsertInstruction {
                before_offset: 0,
                instruction: simple(0, "nop"),
            })
            .unwrap();
        assert_eq!(session.instruction_count(), 3);
        session.undo().unwrap();
        assert_eq!(session.instruction_count(), 2);
    }

    #[test]
    fn test_session_undo_empty_fails() {
        let mut session = EditSession::new("T::M", body());
        assert!(session.undo().is_err());
    }

    #[test]
    fn test_session_undo_depth() {
        let mut session = EditSession::new("T::M", body());
        session
            .apply(IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            })
            .unwrap();
        assert_eq!(session.undo_depth(), 1);
    }

    #[test]
    fn test_session_is_modified() {
        let mut session = EditSession::new("T::M", body());
        assert!(!session.is_modified());
        session
            .apply(IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            })
            .unwrap();
        assert!(session.is_modified());
    }

    #[test]
    fn test_session_reset() {
        let mut session = EditSession::new("T::M", body());
        session
            .apply(IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            })
            .unwrap();
        session.reset();
        assert_eq!(session.instruction_count(), 2);
    }

    #[test]
    fn test_session_apply_all_rollback() {
        let mut session = EditSession::new("T::M", body());
        let edits = vec![
            IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            },
            IlEdit::RemoveInstruction { offset: 0xFF }, // will fail
        ];
        let res = session.apply_all(edits);
        assert!(res.is_err());
        // Rolled back
        assert_eq!(session.instruction_count(), 2);
    }

    #[test]
    fn test_session_changelog() {
        let mut session = EditSession::new("T::M", body());
        session
            .apply(IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            })
            .unwrap();
        assert_eq!(session.changelog().len(), 1);
    }

    // ── IlStackValidator ─────────────────────────────────────────────────────

    #[test]
    fn test_validator_empty_body() {
        let diags = IlStackValidator::new().validate(&[]);
        assert!(!diags.is_empty());
    }

    #[test]
    fn test_validator_valid_body() {
        let instrs = vec![simple(0, "ldc.i4.0"), simple(1, "ret")];
        let diags = IlStackValidator::new().validate(&instrs);
        assert!(IlStackValidator::is_valid(&diags));
    }

    #[test]
    fn test_validator_missing_terminator() {
        let instrs = vec![simple(0, "nop"), simple(1, "nop")];
        let diags = IlStackValidator::new().validate(&instrs);
        assert!(!IlStackValidator::is_valid(&diags));
    }

    #[test]
    fn test_validator_invalid_branch_target() {
        let instrs = vec![
            with_branch(0, "brfalse.s", 0xFF), // target doesn't exist
            simple(1, "ret"),
        ];
        let diags = IlStackValidator::new().validate(&instrs);
        assert!(!IlStackValidator::is_valid(&diags));
    }

    #[test]
    fn test_validator_duplicate_offset() {
        let instrs = vec![simple(0, "nop"), simple(0, "ret")]; // both at offset 0
        let diags = IlStackValidator::new().validate(&instrs);
        let has_dup = diags.iter().any(|d| d.message.contains("duplicate offset"));
        assert!(has_dup);
    }

    // ── MethodBodyWriter ──────────────────────────────────────────────────────

    #[test]
    fn test_writer_tiny_format() {
        let writer = MethodBodyWriter::new();
        let instrs = vec![simple(0, "ldc.i4.0"), simple(1, "ret")];
        let bytes = writer.write(&instrs);
        // Tiny header: high 6 bits = code size (2), low 2 bits = 0x02
        assert_eq!(bytes[0] & 0x03, 0x02); // tiny flag
    }

    #[test]
    fn test_writer_fat_format_when_locals_present() {
        let writer = MethodBodyWriter::new().with_local_var_sig(0x11000001);
        let instrs = vec![simple(0, "nop"), simple(1, "ret")];
        let bytes = writer.write(&instrs);
        // Fat header starts with flags word where low 2 bits = 0x3
        assert_eq!(bytes[0] & 0x03, 0x03);
    }

    #[test]
    fn test_writer_session_round_trip() {
        let writer = MethodBodyWriter::new();
        let instrs = vec![simple(0, "ldc.i4.1"), simple(1, "ret")];
        let session = EditSession::new("T::M", instrs);
        let bytes = writer.write_session(&session);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_writer_non_empty_output() {
        let writer = MethodBodyWriter::new().with_max_stack(4);
        let instrs = vec![simple(0, "ret")];
        let bytes = writer.write(&instrs);
        assert!(!bytes.is_empty());
    }

    // ── PatchedAssembly ───────────────────────────────────────────────────────

    #[test]
    fn test_patched_assembly_session_count() {
        let mut pa = PatchedAssembly::new();
        pa.session("TypeA", "Method1", body());
        pa.session("TypeA", "Method2", body());
        assert_eq!(pa.session_count(), 2);
    }

    #[test]
    fn test_patched_assembly_has_patches() {
        let mut pa = PatchedAssembly::new();
        assert!(!pa.has_patches());
        pa.apply_edit(
            "T",
            "M",
            body(),
            IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            },
        )
        .unwrap();
        assert!(pa.has_patches());
    }

    #[test]
    fn test_patched_assembly_serialise_body() {
        let mut pa = PatchedAssembly::new();
        pa.session("T", "M", body());
        let bytes = pa.serialise_body("T", "M");
        assert!(bytes.is_some());
    }

    #[test]
    fn test_patched_assembly_diff_report() {
        let mut pa = PatchedAssembly::new();
        pa.apply_edit(
            "T",
            "M",
            body(),
            IlEdit::Prepend {
                instructions: vec![simple(0, "nop")],
            },
        )
        .unwrap();
        let report = pa.diff_report();
        assert!(!report.is_empty());
    }

    #[test]
    fn test_patched_assembly_validate_all_no_errors_for_valid() {
        let mut pa = PatchedAssembly::new();
        pa.session("T", "M", vec![simple(0, "ldc.i4.0"), simple(1, "ret")]);
        let diags = pa.validate_all();
        // Valid body should produce no diagnostics map entry
        assert!(diags.is_empty());
    }
}
