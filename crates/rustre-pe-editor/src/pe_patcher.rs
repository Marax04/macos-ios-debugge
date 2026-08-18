//! `pe_patcher` — Byte-level PE patching.
//!
//! NOP out instructions, redirect calls, patch jump targets, modify PE header
//! flags, and maintain a full patch history with undo support.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::EditError;

// ---------------------------------------------------------------------------
// x86/x64 instruction constants
// ---------------------------------------------------------------------------

/// x86/x64 opcode bytes.
pub mod opcode {
    pub const NOP: u8 = 0x90;
    pub const INT3: u8 = 0xCC;
    pub const RET_NEAR: u8 = 0xC3;
    pub const RET_FAR: u8 = 0xCB;
    pub const JMP_REL8: u8 = 0xEB;
    pub const JMP_REL32: u8 = 0xE9;
    pub const CALL_REL32: u8 = 0xE8;
    pub const JZ_REL8: u8 = 0x74;
    pub const JNZ_REL8: u8 = 0x75;
    pub const JZ_REL32_PREFIX: u8 = 0x84;  // 0F 84
    pub const JNZ_REL32_PREFIX: u8 = 0x85; // 0F 85
    pub const TWO_BYTE_PREFIX: u8 = 0x0F;
    pub const LONG_NOP_2: [u8; 2] = [0x66, 0x90];
    pub const LONG_NOP_3: [u8; 3] = [0x0F, 0x1F, 0x00];
    pub const LONG_NOP_4: [u8; 4] = [0x0F, 0x1F, 0x40, 0x00];
    pub const LONG_NOP_5: [u8; 5] = [0x0F, 0x1F, 0x44, 0x00, 0x00];
    pub const LONG_NOP_6: [u8; 6] = [0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00];
    pub const LONG_NOP_7: [u8; 7] = [0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00];
    pub const LONG_NOP_8: [u8; 8] = [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
    pub const LONG_NOP_9: [u8; 9] = [0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
}

// ---------------------------------------------------------------------------
// PatchKind
// ---------------------------------------------------------------------------

/// Classifies what a patch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchKind {
    /// NOP fill.
    Nop,
    /// INT3 breakpoint fill.
    Int3,
    /// Redirect a near call (E8) to a new target.
    RedirectCall,
    /// Redirect a near jump (E9) to a new target.
    RedirectJump,
    /// Replace a jump with NOPs (effectively removing the branch).
    KillBranch,
    /// Generic byte replacement.
    ByteReplace,
    /// PE optional header field modification.
    HeaderField,
    /// PE `DllCharacteristics` flag modification.
    DllChars,
    /// Insert a trampoline (5-byte JMP to hook function, rest NOP).
    Trampoline,
    /// Inline constant patch (replace an immediate value).
    Constant,
}

impl fmt::Display for PatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// PatchRecord
// ---------------------------------------------------------------------------

/// A single patch record stored in the patch history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRecord {
    /// Sequential patch ID.
    pub id: u64,
    /// File byte offset.
    pub offset: usize,
    /// Bytes present before patching (for undo).
    pub original_bytes: Vec<u8>,
    /// Bytes written by this patch.
    pub patch_bytes: Vec<u8>,
    /// Patch classification.
    pub kind: PatchKind,
    /// Human description.
    pub description: String,
    /// Whether this patch has been undone.
    pub undone: bool,
}

impl PatchRecord {
    /// Byte length of the patch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patch_bytes.len()
    }

    /// Returns `true` if the patch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patch_bytes.is_empty()
    }
}

impl fmt::Display for PatchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ {:#x} ({} bytes){}",
            self.id,
            self.kind,
            self.offset,
            self.patch_bytes.len(),
            if self.undone { " [UNDONE]" } else { "" }
        )
    }
}

// ---------------------------------------------------------------------------
// NopStyle
// ---------------------------------------------------------------------------

/// Which NOP pattern to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NopStyle {
    /// Simple 0x90 fill.
    Simple,
    /// Intel multi-byte NOP encodings (better for disassemblers).
    LongNop,
}

// ---------------------------------------------------------------------------
// PePatcher
// ---------------------------------------------------------------------------

/// Byte-level PE patcher with undo history.
pub struct PePatcher {
    data: Vec<u8>,
    history: VecDeque<PatchRecord>,
    next_id: u64,
    max_history: usize,
}

impl PePatcher {
    /// Create a patcher from raw PE bytes.
    #[must_use] 
    pub const fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            history: VecDeque::new(),
            next_id: 1,
            max_history: 1024,
        }
    }

    /// Create a patcher with a custom max undo history depth.
    #[must_use] 
    pub const fn with_max_history(data: Vec<u8>, max: usize) -> Self {
        Self {
            data,
            history: VecDeque::new(),
            next_id: 1,
            max_history: max,
        }
    }

    // ---- Core operations --------------------------------------------------

    /// Fill `len` bytes at `offset` with x86 NOPs.
    ///
    /// If `style` is `NopStyle::LongNop`, multi-byte NOP encodings are used
    /// for runs ≥ 2 bytes; a trailing `0x90` is inserted for remainders.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range.
    pub fn nop_range(
        &mut self,
        offset: usize,
        len: usize,
        style: NopStyle,
    ) -> Result<u64, EditError> {
        self.bounds_check(offset, len)?;
        let original = self.data[offset..offset + len].to_vec();
        let nop_bytes = generate_nops(len, style);
        self.data[offset..offset + len].copy_from_slice(&nop_bytes);
        Ok(self.record(offset, original, nop_bytes, PatchKind::Nop, "nop fill"))
    }

    /// Fill `len` bytes at `offset` with `0xCC` (INT3).
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range.
    pub fn int3_range(&mut self, offset: usize, len: usize) -> Result<u64, EditError> {
        self.bounds_check(offset, len)?;
        let original = self.data[offset..offset + len].to_vec();
        let bytes = vec![opcode::INT3; len];
        self.data[offset..offset + len].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::Int3,
            "INT3 fill",
        ))
    }

    /// Replace `len` bytes at `offset` with a single `0xC3` (RET) followed
    /// by NOPs.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range.
    pub fn kill_function(&mut self, offset: usize, len: usize) -> Result<u64, EditError> {
        self.bounds_check(offset, len)?;
        let original = self.data[offset..offset + len].to_vec();
        let mut bytes = vec![opcode::NOP; len];
        bytes[0] = opcode::RET_NEAR;
        self.data[offset..offset + len].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::Nop,
            "kill function (RET + NOP)",
        ))
    }

    /// Redirect a near call instruction at `call_offset` (opcode byte 0xE8)
    /// to `new_target_va`.
    ///
    /// `call_va` is the virtual address of the call instruction; it is used
    /// to compute the relative displacement.
    ///
    /// # Errors
    /// - `EditError::PatchOutOfBounds` if out-of-range.
    /// - `EditError::ImportError` if the byte at `call_offset` is not 0xE8.
    pub fn redirect_call(
        &mut self,
        call_offset: usize,
        call_va: u64,
        new_target_va: u64,
    ) -> Result<u64, EditError> {
        self.bounds_check(call_offset, 5)?;
        if self.data[call_offset] != opcode::CALL_REL32 {
            return Err(EditError::ImportError(format!(
                "byte at {call_offset:#x} is {:#x}, not CALL (0xE8)",
                self.data[call_offset]
            )));
        }
        let original = self.data[call_offset..call_offset + 5].to_vec();
        let next_ip = call_va + 5;
        let rel = i32::try_from(new_target_va.wrapping_sub(next_ip).cast_signed())
            .map_err(|_| EditError::PatchOutOfBounds { offset: call_offset, len: 5, file_size: self.data.len() })?;
        let mut bytes = [opcode::CALL_REL32, 0, 0, 0, 0];
        bytes[1..5].copy_from_slice(&rel.to_le_bytes());
        self.data[call_offset..call_offset + 5].copy_from_slice(&bytes);
        Ok(self.record(
            call_offset,
            original,
            bytes.to_vec(),
            PatchKind::RedirectCall,
            &format!("redirect CALL → {new_target_va:#x}"),
        ))
    }

    /// Redirect a near jump instruction at `jmp_offset` (opcode 0xE9) to `new_target_va`.
    ///
    /// # Errors
    /// Same as `redirect_call`.
    pub fn redirect_jump(
        &mut self,
        jmp_offset: usize,
        jmp_va: u64,
        new_target_va: u64,
    ) -> Result<u64, EditError> {
        self.bounds_check(jmp_offset, 5)?;
        let original = self.data[jmp_offset..jmp_offset + 5].to_vec();
        let next_ip = jmp_va + 5;
        let rel = i32::try_from(new_target_va.wrapping_sub(next_ip).cast_signed())
            .map_err(|_| EditError::PatchOutOfBounds { offset: jmp_offset, len: 5, file_size: self.data.len() })?;
        let mut bytes = [opcode::JMP_REL32, 0, 0, 0, 0];
        bytes[1..5].copy_from_slice(&rel.to_le_bytes());
        self.data[jmp_offset..jmp_offset + 5].copy_from_slice(&bytes);
        Ok(self.record(
            jmp_offset,
            original,
            bytes.to_vec(),
            PatchKind::RedirectJump,
            &format!("redirect JMP → {new_target_va:#x}"),
        ))
    }

    /// Overwrite a short jump (0xEB rel8) to invert it (JZ↔JNZ, etc.) or remove it.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range.
    pub fn kill_short_jump(&mut self, jmp_offset: usize) -> Result<u64, EditError> {
        self.bounds_check(jmp_offset, 2)?;
        let original = self.data[jmp_offset..jmp_offset + 2].to_vec();
        let bytes = vec![opcode::NOP, opcode::NOP];
        self.data[jmp_offset..jmp_offset + 2].copy_from_slice(&bytes);
        Ok(self.record(
            jmp_offset,
            original,
            bytes,
            PatchKind::KillBranch,
            "kill short jump",
        ))
    }

    /// Write a trampoline: 5-byte JMP to `hook_va` starting at `offset`,
    /// with the remaining `total_len - 5` bytes filled with NOPs.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range or if `total_len < 5`.
    pub fn write_trampoline(
        &mut self,
        offset: usize,
        offset_va: u64,
        hook_va: u64,
        total_len: usize,
    ) -> Result<u64, EditError> {
        if total_len < 5 {
            return Err(EditError::PatchOutOfBounds {
                offset,
                len: total_len,
                file_size: self.data.len(),
            });
        }
        self.bounds_check(offset, total_len)?;
        let original = self.data[offset..offset + total_len].to_vec();
        let next_ip = offset_va + 5;
        let rel = i32::try_from(hook_va.wrapping_sub(next_ip).cast_signed())
            .map_err(|_| EditError::PatchOutOfBounds { offset, len: total_len, file_size: self.data.len() })?;
        let mut bytes = vec![opcode::NOP; total_len];
        bytes[0] = opcode::JMP_REL32;
        bytes[1..5].copy_from_slice(&rel.to_le_bytes());
        self.data[offset..offset + total_len].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::Trampoline,
            &format!("trampoline JMP → {hook_va:#x}"),
        ))
    }

    /// Patch a 4-byte immediate at `offset`.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds`.
    pub fn patch_u32(&mut self, offset: usize, value: u32) -> Result<u64, EditError> {
        self.bounds_check(offset, 4)?;
        let original = self.data[offset..offset + 4].to_vec();
        let bytes = value.to_le_bytes().to_vec();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::Constant,
            &format!("patch u32 @ {offset:#x} = {value:#x}"),
        ))
    }

    /// Patch an 8-byte immediate.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds`.
    pub fn patch_u64(&mut self, offset: usize, value: u64) -> Result<u64, EditError> {
        self.bounds_check(offset, 8)?;
        let original = self.data[offset..offset + 8].to_vec();
        let bytes = value.to_le_bytes().to_vec();
        self.data[offset..offset + 8].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::Constant,
            &format!("patch u64 @ {offset:#x} = {value:#x}"),
        ))
    }

    /// Generic byte write.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds` if out-of-range.
    pub fn write_bytes(
        &mut self,
        offset: usize,
        bytes: Vec<u8>,
        description: impl Into<String>,
    ) -> Result<u64, EditError> {
        let len = bytes.len();
        self.bounds_check(offset, len)?;
        let original = self.data[offset..offset + len].to_vec();
        self.data[offset..offset + len].copy_from_slice(&bytes);
        Ok(self.record(
            offset,
            original,
            bytes,
            PatchKind::ByteReplace,
            &description.into(),
        ))
    }

    // ---- PE header patches ------------------------------------------------

    /// Set or clear the ASLR (`DYNAMIC_BASE = 0x0040`) bit in
    /// `DllCharacteristics`.
    ///
    /// # Errors
    /// Returns `EditError` on header parse failure.
    pub fn set_aslr(&mut self, enable: bool) -> Result<u64, EditError> {
        self.patch_dll_characteristic(0x0040, enable, "ASLR")
    }

    /// Set or clear the No-Execute (`NX_COMPAT = 0x0100`) bit.
    ///
    /// # Errors
    pub fn set_nx(&mut self, enable: bool) -> Result<u64, EditError> {
        self.patch_dll_characteristic(0x0100, enable, "NX")
    }

    /// Set or clear `FORCE_INTEGRITY (0x0080)`.
    ///
    /// # Errors
    pub fn set_force_integrity(&mut self, enable: bool) -> Result<u64, EditError> {
        self.patch_dll_characteristic(0x0080, enable, "FORCE_INTEGRITY")
    }

    /// Set or clear `GUARD_CF (0x4000)`.
    ///
    /// # Errors
    pub fn set_guard_cf(&mut self, enable: bool) -> Result<u64, EditError> {
        self.patch_dll_characteristic(0x4000, enable, "CFG")
    }

    /// Zero the PE checksum.
    ///
    /// # Errors
    pub fn zero_checksum(&mut self) -> Result<u64, EditError> {
        let off = self.checksum_offset()?;
        self.patch_u32(off, 0)
    }

    /// Set the entry-point RVA in the optional header.
    ///
    /// # Errors
    pub fn set_entry_point(&mut self, new_ep_rva: u32) -> Result<u64, EditError> {
        let opt_off = self.opt_header_offset()?;
        let off = opt_off + 16;
        self.bounds_check(off, 4)?;
        let original = self.data[off..off + 4].to_vec();
        let bytes = new_ep_rva.to_le_bytes().to_vec();
        self.data[off..off + 4].copy_from_slice(&bytes);
        Ok(self.record(
            off,
            original,
            bytes,
            PatchKind::HeaderField,
            &format!("set EP RVA = {new_ep_rva:#x}"),
        ))
    }

    // ---- Undo / redo / history -------------------------------------------

    /// Undo the most recent non-undone patch.  Returns its ID if successful.
    ///
    /// # Errors
    /// Returns `EditError::ImportError` if nothing to undo.
    pub fn undo(&mut self) -> Result<u64, EditError> {
        // Find the last non-undone record (from most recent).
        let idx = self
            .history
            .iter()
            .rposition(|r| !r.undone)
            .ok_or_else(|| EditError::ImportError("nothing to undo".to_string()))?;

        let rec = &self.history[idx];
        let off = rec.offset;
        let original = rec.original_bytes.clone();
        let id = rec.id;
        let len = original.len();

        if off + len <= self.data.len() {
            self.data[off..off + len].copy_from_slice(&original);
        }
        self.history[idx].undone = true;
        Ok(id)
    }

    /// Redo the most recently undone patch.
    ///
    /// # Errors
    /// Returns `EditError::ImportError` if nothing to redo.
    pub fn redo(&mut self) -> Result<u64, EditError> {
        // Find the oldest undone record.
        let idx = self
            .history
            .iter()
            .position(|r| r.undone)
            .ok_or_else(|| EditError::ImportError("nothing to redo".to_string()))?;

        let rec = &self.history[idx];
        let off = rec.offset;
        let patch_bytes = rec.patch_bytes.clone();
        let id = rec.id;
        let len = patch_bytes.len();

        if off + len <= self.data.len() {
            self.data[off..off + len].copy_from_slice(&patch_bytes);
        }
        self.history[idx].undone = false;
        Ok(id)
    }

    /// Undo all patches up to and including `patch_id`.
    pub fn undo_to(&mut self, patch_id: u64) -> usize {
        let mut count = 0;
        for rec in self.history.iter_mut().rev() {
            if rec.undone {
                continue;
            }
            if rec.id < patch_id {
                break;
            }
            let off = rec.offset;
            let original = rec.original_bytes.clone();
            let len = original.len();
            if off + len <= self.data.len() {
                self.data[off..off + len].copy_from_slice(&original);
            }
            rec.undone = true;
            count += 1;
        }
        count
    }

    /// Clear all undo history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    // ---- Query -----------------------------------------------------------

    /// Patch history slice.
    #[must_use]
    pub const fn history(&self) -> &VecDeque<PatchRecord> {
        &self.history
    }

    /// Number of patches applied (including undone).
    #[must_use]
    pub fn patch_count(&self) -> usize {
        self.history.len()
    }

    /// Number of active (not undone) patches.
    #[must_use]
    pub fn active_patch_count(&self) -> usize {
        self.history.iter().filter(|r| !r.undone).count()
    }

    /// Find patch records by kind.
    #[must_use]
    pub fn patches_by_kind(&self, kind: PatchKind) -> Vec<&PatchRecord> {
        self.history.iter().filter(|r| r.kind == kind).collect()
    }

    /// Read bytes from the buffer.
    ///
    /// # Errors
    /// Returns `EditError::PatchOutOfBounds`.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8], EditError> {
        self.bounds_check(offset, len)?;
        Ok(&self.data[offset..offset + len])
    }

    /// Consume and return the patched bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the current bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    // ---- Private helpers -------------------------------------------------

    const fn bounds_check(&self, offset: usize, len: usize) -> Result<(), EditError> {
        if offset + len > self.data.len() {
            Err(EditError::PatchOutOfBounds {
                offset,
                len,
                file_size: self.data.len(),
            })
        } else {
            Ok(())
        }
    }

    fn record(
        &mut self,
        offset: usize,
        original: Vec<u8>,
        patch: Vec<u8>,
        kind: PatchKind,
        desc: &str,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(PatchRecord {
            id,
            offset,
            original_bytes: original,
            patch_bytes: patch,
            kind,
            description: desc.to_string(),
            undone: false,
        });
        id
    }

    fn pe_header_offset(&self) -> Result<usize, EditError> {
        if self.data.len() < 64 {
            return Err(EditError::PatchOutOfBounds {
                offset: 60,
                len: 4,
                file_size: self.data.len(),
            });
        }
        let off =
            u32::from_le_bytes([self.data[60], self.data[61], self.data[62], self.data[63]])
                as usize;
        Ok(off)
    }

    fn opt_header_offset(&self) -> Result<usize, EditError> {
        let pe_off = self.pe_header_offset()?;
        Ok(pe_off + 24)
    }

    fn checksum_offset(&self) -> Result<usize, EditError> {
        let opt_off = self.opt_header_offset()?;
        Ok(opt_off + 64)
    }

    fn dll_chars_offset(&self) -> Result<usize, EditError> {
        let opt_off = self.opt_header_offset()?;
        Ok(opt_off + 70)
    }

    fn patch_dll_characteristic(
        &mut self,
        flag: u16,
        enable: bool,
        name: &str,
    ) -> Result<u64, EditError> {
        let off = self.dll_chars_offset()?;
        self.bounds_check(off, 2)?;
        let original = self.data[off..off + 2].to_vec();
        let mut dc = u16::from_le_bytes([self.data[off], self.data[off + 1]]);
        if enable {
            dc |= flag;
        } else {
            dc &= !flag;
        }
        let bytes = dc.to_le_bytes().to_vec();
        self.data[off..off + 2].copy_from_slice(&bytes);
        Ok(self.record(
            off,
            original,
            bytes,
            PatchKind::DllChars,
            &format!("{name} flag {}", if enable { "set" } else { "clear" }),
        ))
    }
}

impl fmt::Debug for PePatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PePatcher {{ buf={} patches={} active={} }}",
            self.data.len(),
            self.history.len(),
            self.active_patch_count(),
        )
    }
}

// ---------------------------------------------------------------------------
// NOP generation
// ---------------------------------------------------------------------------

/// Generate `len` bytes of NOP instructions.
///
/// If `style` is `LongNop`, uses Intel multi-byte NOP encodings where
/// possible (up to 9-byte NOPs), then fills the remainder with 0x90.
#[must_use]
pub fn generate_nops(len: usize, style: NopStyle) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    match style {
        NopStyle::Simple => vec![opcode::NOP; len],
        NopStyle::LongNop => {
            let mut out = Vec::with_capacity(len);
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(9);
                match n {
                    1 => out.push(opcode::NOP),
                    2 => out.extend_from_slice(&opcode::LONG_NOP_2),
                    3 => out.extend_from_slice(&opcode::LONG_NOP_3),
                    4 => out.extend_from_slice(&opcode::LONG_NOP_4),
                    5 => out.extend_from_slice(&opcode::LONG_NOP_5),
                    6 => out.extend_from_slice(&opcode::LONG_NOP_6),
                    7 => out.extend_from_slice(&opcode::LONG_NOP_7),
                    8 => out.extend_from_slice(&opcode::LONG_NOP_8),
                    9 => out.extend_from_slice(&opcode::LONG_NOP_9),
                    _ => unreachable!(),
                }
                remaining -= n;
            }
            out
        }
    }
}

/// Compute the x86 relative displacement for a 5-byte near JMP/CALL.
///
/// `from_va` = VA of the instruction start, `to_va` = target VA.
#[must_use]
pub const fn rel32_displacement(from_va: u64, to_va: u64) -> i32 {
    let next = from_va.wrapping_add(5);
    let diff_bytes = to_va.wrapping_sub(next).to_le_bytes();
    i32::from_le_bytes([diff_bytes[0], diff_bytes[1], diff_bytes[2], diff_bytes[3]])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn make_buf(len: usize) -> Vec<u8> {
        (0..len as u8).collect()
    }

    #[test]
    fn generate_nops_simple() {
        let nops = generate_nops(4, NopStyle::Simple);
        assert_eq!(nops, vec![0x90; 4]);
    }

    #[test]
    fn generate_nops_long_8() {
        let nops = generate_nops(8, NopStyle::LongNop);
        assert_eq!(nops, opcode::LONG_NOP_8.to_vec());
    }

    #[test]
    fn generate_nops_long_12() {
        let nops = generate_nops(12, NopStyle::LongNop);
        assert_eq!(nops.len(), 12);
    }

    #[test]
    fn generate_nops_zero() {
        assert!(generate_nops(0, NopStyle::Simple).is_empty());
    }

    #[test]
    fn rel32_displacement_basic() {
        // CALL at VA 0x1000 → target 0x2000. Next IP = 0x1005. rel = 0x2000-0x1005 = 0xFFB.
        assert_eq!(rel32_displacement(0x1000, 0x2000), 0xFFB);
    }

    #[test]
    fn patcher_nop_range() {
        let mut p = PePatcher::new(vec![0x55u8; 16]);
        let id = p.nop_range(2, 4, NopStyle::Simple).unwrap();
        assert_eq!(id, 1);
        assert_eq!(&p.bytes()[2..6], &[0x90; 4]);
    }

    #[test]
    fn patcher_int3() {
        let mut p = PePatcher::new(vec![0u8; 10]);
        p.int3_range(0, 5).unwrap();
        assert_eq!(&p.bytes()[0..5], &[0xCC; 5]);
    }

    #[test]
    fn patcher_write_bytes() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.write_bytes(4, vec![1, 2, 3, 4], "test").unwrap();
        assert_eq!(&p.bytes()[4..8], &[1, 2, 3, 4]);
    }

    #[test]
    fn patcher_patch_u32() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.patch_u32(0, 0xDEAD_BEEF).unwrap();
        assert_eq!(u32::from_le_bytes(p.bytes()[0..4].try_into().unwrap()), 0xDEAD_BEEF);
    }

    #[test]
    fn patcher_patch_u64() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.patch_u64(0, 0xCAFE_BABE_DEAD_BEEFu64).unwrap();
        assert_eq!(
            u64::from_le_bytes(p.bytes()[0..8].try_into().unwrap()),
            0xCAFE_BABE_DEAD_BEEFu64
        );
    }

    #[test]
    fn patcher_redirect_call() {
        let mut data = vec![0xE8u8, 0, 0, 0, 0, 0x90, 0x90];
        data.extend(vec![0x55u8; 100]);
        let mut p = PePatcher::new(data);
        // call at offset 0, VA 0x1000 → target VA 0x2000
        p.redirect_call(0, 0x1000, 0x2000).unwrap();
        assert_eq!(p.bytes()[0], 0xE8);
        let rel = i32::from_le_bytes(p.bytes()[1..5].try_into().unwrap());
        assert_eq!(rel, 0xFFB);
    }

    #[test]
    fn patcher_redirect_call_wrong_opcode() {
        let mut p = PePatcher::new(vec![0x90u8; 16]);
        assert!(p.redirect_call(0, 0x1000, 0x2000).is_err());
    }

    #[test]
    fn patcher_trampoline() {
        let mut p = PePatcher::new(vec![0x55u8; 20]);
        p.write_trampoline(0, 0x1000, 0x5000, 10).unwrap();
        assert_eq!(p.bytes()[0], opcode::JMP_REL32);
        // bytes 5..10 should be NOPs.
        assert_eq!(&p.bytes()[5..10], &[0x90; 5]);
    }

    #[test]
    fn patcher_trampoline_too_short() {
        let mut p = PePatcher::new(vec![0u8; 20]);
        assert!(p.write_trampoline(0, 0x1000, 0x5000, 4).is_err());
    }

    #[test]
    fn patcher_undo() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.nop_range(0, 4, NopStyle::Simple).unwrap();
        assert_eq!(&p.bytes()[0..4], &[0x90; 4]);
        p.undo().unwrap();
        assert_eq!(&p.bytes()[0..4], &[0u8; 4]);
    }

    #[test]
    fn patcher_undo_redo() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.nop_range(0, 4, NopStyle::Simple).unwrap();
        p.undo().unwrap();
        p.redo().unwrap();
        assert_eq!(&p.bytes()[0..4], &[0x90; 4]);
    }

    #[test]
    fn patcher_undo_empty_fails() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        assert!(p.undo().is_err());
    }

    #[test]
    fn patcher_active_count() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.nop_range(0, 2, NopStyle::Simple).unwrap();
        p.int3_range(2, 2).unwrap();
        assert_eq!(p.active_patch_count(), 2);
        p.undo().unwrap();
        assert_eq!(p.active_patch_count(), 1);
    }

    #[test]
    fn patches_by_kind() {
        let mut p = PePatcher::new(vec![0u8; 16]);
        p.nop_range(0, 2, NopStyle::Simple).unwrap();
        p.int3_range(2, 2).unwrap();
        assert_eq!(p.patches_by_kind(PatchKind::Nop).len(), 1);
        assert_eq!(p.patches_by_kind(PatchKind::Int3).len(), 1);
    }

    #[test]
    fn patcher_out_of_bounds() {
        let mut p = PePatcher::new(vec![0u8; 4]);
        assert!(p.nop_range(3, 4, NopStyle::Simple).is_err());
    }

    #[test]
    fn kill_short_jump() {
        let mut p = PePatcher::new(vec![opcode::JMP_REL8, 0x10, 0x55, 0x55]);
        p.kill_short_jump(0).unwrap();
        assert_eq!(&p.bytes()[0..2], &[0x90, 0x90]);
    }

    #[test]
    fn kill_function_ret_nop() {
        let mut p = PePatcher::new(vec![0x55u8; 10]);
        p.kill_function(0, 6).unwrap();
        assert_eq!(p.bytes()[0], opcode::RET_NEAR);
        assert_eq!(&p.bytes()[1..6], &[0x90; 5]);
    }
}

#[cfg(test)]
mod patch_on_known_buffer_tests {
    //! ⚠ `make_buf` produced a buffer with *distinct* bytes (0,1,2,…) and had
    //! no caller: every patcher test ran against `generate_nops` output or a
    //! zeroed buffer, so nothing checked that a patch touches only the range it
    //! was given. A buffer where every byte differs is exactly what makes an
    //! off-by-one visible.

    use super::*;

    use super::tests::make_buf;

    /// Patching [4,8) must leave [0,4) and [8,16) byte-identical.
    #[test]
    fn nop_range_touches_only_its_own_range() {
        let original = make_buf(16);
        let mut p = PePatcher::new(original.clone());
        p.nop_range(4, 4, NopStyle::Simple).expect("in bounds");

        let out = p.bytes();
        assert_eq!(&out[0..4], &original[0..4], "prefix must be untouched");
        assert_eq!(&out[4..8], &[0x90u8; 4], "the patched run");
        assert_eq!(&out[8..16], &original[8..16], "suffix must be untouched");
    }

    /// INT3 fill has the same containment property.
    #[test]
    fn int3_range_touches_only_its_own_range() {
        let original = make_buf(16);
        let mut p = PePatcher::new(original.clone());
        p.int3_range(10, 2).expect("in bounds");

        let out = p.bytes();
        assert_eq!(&out[0..10], &original[0..10]);
        assert_eq!(&out[10..12], &[0xCCu8, 0xCC]);
        assert_eq!(&out[12..16], &original[12..16]);
    }

    /// A patch that runs one byte past the end must be refused, and must not
    /// have written anything first.
    #[test]
    fn out_of_bounds_patch_is_refused_and_leaves_the_buffer_intact() {
        let original = make_buf(8);
        let mut p = PePatcher::new(original.clone());
        let err = p.nop_range(6, 4, NopStyle::Simple);
        assert!(err.is_err(), "6+4 > 8 must be rejected");
        assert_eq!(p.bytes(), &original[..], "a refused patch must not write");
    }
}
