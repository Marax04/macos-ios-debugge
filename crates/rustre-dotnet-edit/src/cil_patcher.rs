//! CIL (Common Intermediate Language) bytecode patcher.
//!
//! Provides `CilPatcher` and `PatchOperation` for in-place patching of CIL
//! method bodies: replacing instructions, inserting NOP sleds, deleting
//! instructions, changing branch targets, and rewriting branch offsets after
//! size-changing insertions.

// ---------------------------------------------------------------------------
// PatchOperation
// ---------------------------------------------------------------------------

/// A single patching operation to apply to a CIL code buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOperation {
    /// Replace a sequence of bytes at `offset`.
    ///
    /// `old` is verified before replacement; `new` must be the same length.
    ReplaceInstruction {
        /// Byte offset in the method body.
        offset: u32,
        /// Expected old bytes (used for verification).
        old: Vec<u8>,
        /// Replacement bytes (must have the same length as `old`).
        new: Vec<u8>,
    },

    /// Insert bytes at `offset`, shifting everything after it forward.
    ///
    /// All branch targets pointing past `offset` are automatically adjusted.
    InsertInstruction {
        /// Byte offset at which to insert.
        offset: u32,
        /// Bytes to insert.
        bytes: Vec<u8>,
    },

    /// Delete `size` bytes starting at `offset`, shifting everything backward.
    DeleteInstruction {
        /// Byte offset of the first byte to delete.
        offset: u32,
        /// Number of bytes to delete.
        size: u8,
    },

    /// Rewrite the branch target of a branch instruction.
    ChangeBranchTarget {
        /// Offset of the branch instruction's operand (not the opcode).
        offset: u32,
        /// Old target (relative offset, as a signed 32-bit integer).
        old_target: i32,
        /// New target.
        new_target: i32,
    },

    /// Overwrite `size` bytes starting at `offset` with NOP (0x00 in CIL).
    NopOut {
        /// Start offset.
        offset: u32,
        /// Number of bytes to NOP out.
        size: u8,
    },
}

impl PatchOperation {
    /// Returns the offset this operation acts on.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        match self {
            Self::ReplaceInstruction { offset, .. }
            | Self::InsertInstruction { offset, .. }
            | Self::DeleteInstruction { offset, .. }
            | Self::ChangeBranchTarget { offset, .. }
            | Self::NopOut { offset, .. } => *offset,
        }
    }

    /// Returns a short human-readable description.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::ReplaceInstruction { offset, old, new } => {
                format!(
                    "Replace {} bytes at 0x{:x} ({} -> {})",
                    old.len(),
                    offset,
                    hex_str(old),
                    hex_str(new)
                )
            }
            Self::InsertInstruction { offset, bytes } => {
                format!("Insert {} bytes at 0x{:x}", bytes.len(), offset)
            }
            Self::DeleteInstruction { offset, size } => {
                format!("Delete {size} bytes at 0x{offset:x}")
            }
            Self::ChangeBranchTarget {
                offset,
                old_target,
                new_target,
            } => {
                format!(
                    "Change branch at 0x{offset:x}: {old_target} -> {new_target}"
                )
            }
            Self::NopOut { offset, size } => {
                format!("NOP out {size} bytes at 0x{offset:x}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PatchResult
// ---------------------------------------------------------------------------

/// Summary of a completed patch session.
#[derive(Debug, Clone, Default)]
pub struct PatchResult {
    /// Number of operations successfully applied.
    pub operations_applied: u32,
    /// Total number of bytes modified.
    pub bytes_changed: u64,
    /// Validation errors (empty on success).
    pub validation_errors: Vec<String>,
}

impl PatchResult {
    /// Returns `true` if all operations were applied without errors.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.validation_errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CilPatcher
// ---------------------------------------------------------------------------

/// CIL method-body patcher.
///
/// # Example
/// ```rust
/// use rustre_dotnet_edit::cil_patcher::{CilPatcher, PatchOperation};
///
/// let mut code = vec![0x00, 0x16, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A]; // ldnull; ldc.i4.0; call; ret
/// let patcher = CilPatcher::new();
/// let op = PatchOperation::NopOut { offset: 0, size: 2 };
/// let applied = patcher.apply_patch(&mut code, &op);
/// assert!(applied);
/// assert_eq!(code[0], 0x00);
/// assert_eq!(code[1], 0x00);
/// ```
pub struct CilPatcher {
    /// If `true`, verify old bytes before applying `ReplaceInstruction`.
    pub verify_old_bytes: bool,
    /// If `true`, fix branch offsets after `InsertInstruction`.
    pub auto_fix_branches: bool,
}

impl CilPatcher {
    /// Create a new `CilPatcher` with sensible defaults.
    pub fn new() -> Self {
        Self {
            verify_old_bytes: true,
            auto_fix_branches: true,
        }
    }

    /// Apply a single `PatchOperation` to `code`.
    ///
    /// Returns `true` on success, `false` if the operation was rejected
    /// (e.g. old-byte mismatch, out-of-bounds offset).
    pub fn apply_patch(&self, code: &mut Vec<u8>, op: &PatchOperation) -> bool {
        match op {
            PatchOperation::ReplaceInstruction { offset, old, new } => {
                let off = *offset as usize;
                if old.len() != new.len() {
                    return false;
                }
                if off + old.len() > code.len() {
                    return false;
                }
                if self.verify_old_bytes && &code[off..off + old.len()] != old.as_slice() {
                    return false;
                }
                code[off..off + new.len()].copy_from_slice(new);
                true
            }
            PatchOperation::InsertInstruction { offset, bytes } => {
                let off = *offset as usize;
                if off > code.len() {
                    return false;
                }
                if bytes.is_empty() {
                    return true;
                }
                let inserted_size = bytes.len() as i32;
                for (i, &b) in bytes.iter().enumerate() {
                    code.insert(off + i, b);
                }
                if self.auto_fix_branches {
                    self.fix_branch_offsets_after_insert(code, *offset, inserted_size);
                }
                true
            }
            PatchOperation::DeleteInstruction { offset, size } => {
                let off = *offset as usize;
                let sz = *size as usize;
                if off + sz > code.len() {
                    return false;
                }
                code.drain(off..off + sz);
                true
            }
            PatchOperation::ChangeBranchTarget {
                offset,
                old_target,
                new_target,
            } => {
                let off = *offset as usize;
                if off + 4 > code.len() {
                    return false;
                }
                let stored = i32::from_le_bytes([
                    code[off],
                    code[off + 1],
                    code[off + 2],
                    code[off + 3],
                ]);
                if stored != *old_target {
                    return false;
                }
                let bytes = new_target.to_le_bytes();
                code[off..off + 4].copy_from_slice(&bytes);
                true
            }
            PatchOperation::NopOut { offset, size } => {
                let off = *offset as usize;
                let sz = *size as usize;
                if off + sz > code.len() {
                    return false;
                }
                for b in &mut code[off..off + sz] {
                    *b = 0x00; // CIL NOP
                }
                true
            }
        }
    }

    /// Apply a sequence of operations in order.
    ///
    /// Stops on the first failure and records validation errors.
    pub fn apply_patches(&self, code: &mut Vec<u8>, ops: &[PatchOperation]) -> PatchResult {
        let mut result = PatchResult::default();
        for op in ops {
            let bytes_before = code.len() as u64;
            if self.apply_patch(code, op) {
                result.operations_applied += 1;
                result.bytes_changed += (code.len() as u64).abs_diff(bytes_before)
                    + self.count_modified_bytes(op);
            } else {
                result
                    .validation_errors
                    .push(format!("FAILED: {}", op.description()));
            }
        }
        result.validation_errors.extend(self.validate_after_patch(code));
        result
    }

    /// Validate a code buffer after patching.
    ///
    /// Checks:
    /// - Buffer is non-empty.
    /// - Last byte is `0x2A` (CIL `ret`) — heuristic for well-formed method.
    /// - No byte sequence 0xFF 0xFF (invalid encoding indicator).
    #[must_use]
    pub fn validate_after_patch(&self, code: &[u8]) -> Vec<String> {
        let mut errors = Vec::new();
        if code.is_empty() {
            errors.push("code buffer is empty".to_owned());
            return errors;
        }
        if code[code.len() - 1] != 0x2A {
            errors.push(format!(
                "last byte is 0x{:02X} (expected 0x2A ret)",
                code[code.len() - 1]
            ));
        }
        for i in 0..code.len().saturating_sub(1) {
            if code[i] == 0xFF && code[i + 1] == 0xFF {
                errors.push(format!("invalid 0xFF 0xFF sequence at offset {i}"));
            }
        }
        errors
    }

    /// Adjust branch operands that reference offsets past `insert_pos` after
    /// `inserted_size` bytes were inserted at `insert_pos`.
    ///
    /// Scans the code for known CIL branch opcodes and adjusts their relative
    /// or absolute targets accordingly.
    pub fn fix_branch_offsets_after_insert(
        &self,
        code: &mut Vec<u8>,
        insert_pos: u32,
        inserted_size: i32,
    ) {
        let ins = insert_pos as usize;
        let mut i = 0;
        while i < code.len() {
            let opcode = code[i];
            // Long branch instructions: 4-byte relative offset at i+1.
            // CIL long-branch opcodes: br(0x38), brfalse(0x39), brtrue(0x3A),
            // beq(0x3B), bge(0x3C), bgt(0x3D), ble(0x3E), blt(0x3F),
            // bne.un(0x40), bge.un(0x41), bgt.un(0x42), ble.un(0x43),
            // blt.un(0x44), switch(0x45).
            // Check these BEFORE the short-branch range because 0x38..=0x45
            // is a subset of 0x2B..=0x46 and would be mishandled as 1-byte branches.
            if (0x38u8..=0x44u8).contains(&opcode) {
                // br through blt.un (4-byte operand)
                if i + 5 <= code.len() {
                    let rel = i32::from_le_bytes([
                        code[i + 1],
                        code[i + 2],
                        code[i + 3],
                        code[i + 4],
                    ]);
                    let target_abs = (i as i32) + 5 + rel;
                    if target_abs > ins as i32 {
                        let new_rel = rel + inserted_size;
                        let bytes = new_rel.to_le_bytes();
                        code[i + 1] = bytes[0];
                        code[i + 2] = bytes[1];
                        code[i + 3] = bytes[2];
                        code[i + 4] = bytes[3];
                    }
                    i += 5;
                    continue;
                }
            }
            // switch (0x45): variable-length; skip past the table
            if opcode == 0x45 && i + 5 <= code.len() {
                let n = u32::from_le_bytes([
                    code[i + 1],
                    code[i + 2],
                    code[i + 3],
                    code[i + 4],
                ]) as usize;
                i += 5 + n * 4;
                continue;
            }
            // Short branch instructions: 1 offset at i+1.
            // CIL short-branch opcodes: br.s(0x2B), brfalse.s(0x2C), brtrue.s(0x2D),
            // beq.s(0x2E), bge.s(0x2F), bgt.s(0x30), ble.s(0x31), blt.s(0x32),
            // bne.un.s(0x33), bge.un.s(0x34), bgt.un.s(0x35), ble.un.s(0x36),
            // blt.un.s(0x37), leave(0x38 is long — already handled above),
            // leave.s(0xDE).
            if (0x2Bu8..=0x37u8).contains(&opcode) && i + 1 < code.len() {
                let rel = i32::from(code[i + 1] as i8);
                let target_abs = (i as i32) + 2 + rel;
                if target_abs > ins as i32 {
                        let new_rel = rel + inserted_size;
                        code[i + 1] = new_rel as i8 as u8;
                    }
                    i += 2;
                    continue;
                }
            i += 1;
        }
    }

    /// Count the bytes meaningfully changed by an operation.
    fn count_modified_bytes(&self, op: &PatchOperation) -> u64 {
        match op {
            PatchOperation::ReplaceInstruction { new, .. } => new.len() as u64,
            PatchOperation::InsertInstruction { bytes, .. } => bytes.len() as u64,
            PatchOperation::DeleteInstruction { size, .. } => u64::from(*size),
            PatchOperation::NopOut { size, .. } => u64::from(*size),
            PatchOperation::ChangeBranchTarget { .. } => 4,
        }
    }
}

impl Default for CilPatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Generate a NOP sled of `n` CIL NOP bytes (0x00).
#[must_use]
pub fn cil_nop_sled(n: usize) -> Vec<u8> {
    vec![0x00u8; n]
}

/// Find all offsets of `opcode` in the code buffer.
#[must_use]
pub fn find_instruction(code: &[u8], opcode: u8) -> Vec<u32> {
    code.iter()
        .enumerate()
        .filter(|&(_, &b)| b == opcode)
        .map(|(i, _)| i as u32)
        .collect()
}

/// Returns the first `n` bytes of the code buffer as a Vec.
#[must_use]
pub fn take_code_slice(code: &[u8], n: usize) -> Vec<u8> {
    code[..n.min(code.len())].to_vec()
}

/// Determine whether a byte is a CIL prefix opcode (0xFE).
pub fn is_prefix_opcode(b: u8) -> bool {
    b == 0xFE
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

// --------------b----------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // A valid-enough minimal CIL body: ldc.i4.0 (0x16) + ret (0x2A)
    fn tiny_body() -> Vec<u8> {
        vec![0x16, 0x2A]
    }

    // Slightly longer body
    fn medium_body() -> Vec<u8> {
        // ldnull(0x14) + ldc.i4.0(0x16) + pop(0x26) + ret(0x2A)
        vec![0x14, 0x16, 0x26, 0x2A]
    }

    #[test]
    fn test_nop_out_valid() {
        let mut code = tiny_body();
        let p = CilPatcher::new();
        let op = PatchOperation::NopOut { offset: 0, size: 1 };
        assert!(p.apply_patch(&mut code, &op));
        assert_eq!(code[0], 0x00);
        assert_eq!(code[1], 0x2A);
    }

    #[test]
    fn test_nop_out_out_of_bounds() {
        let mut code = tiny_body();
        let p = CilPatcher::new();
        let op = PatchOperation::NopOut { offset: 5, size: 1 };
        assert!(!p.apply_patch(&mut code, &op));
    }

    #[test]
    fn test_replace_instruction_same_length() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::ReplaceInstruction {
            offset: 0,
            old: vec![0x14],
            new: vec![0x16],
        };
        assert!(p.apply_patch(&mut code, &op));
        assert_eq!(code[0], 0x16);
    }

    #[test]
    fn test_replace_instruction_old_mismatch() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::ReplaceInstruction {
            offset: 0,
            old: vec![0xFF], // wrong
            new: vec![0x16],
        };
        assert!(!p.apply_patch(&mut code, &op));
    }

    #[test]
    fn test_replace_instruction_length_mismatch() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::ReplaceInstruction {
            offset: 0,
            old: vec![0x14],
            new: vec![0x28, 0x01, 0x00, 0x00, 0x0A], // 5 bytes vs 1
        };
        assert!(!p.apply_patch(&mut code, &op));
    }

    #[test]
    fn test_insert_instruction() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::InsertInstruction {
            offset: 0,
            bytes: vec![0x00, 0x00],
        };
        assert!(p.apply_patch(&mut code, &op));
        assert_eq!(code.len(), 6);
        assert_eq!(code[0], 0x00);
        assert_eq!(code[1], 0x00);
    }

    #[test]
    fn test_delete_instruction() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::DeleteInstruction { offset: 0, size: 1 };
        assert!(p.apply_patch(&mut code, &op));
        assert_eq!(code.len(), 3);
        assert_eq!(code[0], 0x16);
    }

    #[test]
    fn test_delete_out_of_bounds() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let op = PatchOperation::DeleteInstruction { offset: 3, size: 10 };
        assert!(!p.apply_patch(&mut code, &op));
    }

    #[test]
    fn test_change_branch_target() {
        let mut code = vec![0x38, 0x05, 0x00, 0x00, 0x00, 0x2A]; // br.s +5; ret
        let p = CilPatcher::new();
        let op = PatchOperation::ChangeBranchTarget {
            offset: 1,
            old_target: 5,
            new_target: 10,
        };
        assert!(p.apply_patch(&mut code, &op));
        let stored = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
        assert_eq!(stored, 10);
    }

    #[test]
    fn test_change_branch_target_mismatch() {
        let mut code = vec![0x38, 0x05, 0x00, 0x00, 0x00, 0x2A];
        let p = CilPatcher::new();
        let op = PatchOperation::ChangeBranchTarget {
            offset: 1,
            old_target: 99, // wrong
            new_target: 10,
        };
        assert!(!p.apply_patch(&mut code, &op));
    }

    #[test]
    fn test_validate_after_patch_valid() {
        let p = CilPatcher::new();
        let errors = p.validate_after_patch(&[0x16, 0x2A]);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_after_patch_no_ret() {
        let p = CilPatcher::new();
        let errors = p.validate_after_patch(&[0x16, 0x00]);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_validate_after_patch_empty() {
        let p = CilPatcher::new();
        let errors = p.validate_after_patch(&[]);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_apply_patches_multiple() {
        let mut code = medium_body();
        let p = CilPatcher::new();
        let ops = vec![
            PatchOperation::NopOut { offset: 0, size: 1 },
            PatchOperation::NopOut { offset: 1, size: 1 },
        ];
        let result = p.apply_patches(&mut code, &ops);
        assert_eq!(result.operations_applied, 2);
        assert_eq!(code[0], 0x00);
        assert_eq!(code[1], 0x00);
    }

    #[test]
    fn test_find_instruction() {
        let code = vec![0x16, 0x00, 0x16, 0x2A];
        let offsets = find_instruction(&code, 0x16);
        assert_eq!(offsets, vec![0, 2]);
    }

    #[test]
    fn test_cil_nop_sled() {
        let sled = cil_nop_sled(8);
        assert_eq!(sled.len(), 8);
        assert!(sled.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_patch_operation_offset() {
        assert_eq!(
            PatchOperation::NopOut { offset: 42, size: 1 }.offset(),
            42
        );
        assert_eq!(
            PatchOperation::DeleteInstruction { offset: 7, size: 2 }.offset(),
            7
        );
    }

    #[test]
    fn test_patch_result_is_success() {
        let r = PatchResult { operations_applied: 1, bytes_changed: 1, validation_errors: vec![] };
        assert!(r.is_success());
        let r2 = PatchResult {
            validation_errors: vec!["error".to_owned()],
            ..Default::default()
        };
        assert!(!r2.is_success());
    }
}
