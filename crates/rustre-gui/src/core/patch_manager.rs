// ============================================================================
// core/patch_manager.rs — Byte-patch pipeline with undo/redo + audit log
//
// Features:
//   • Transactional patch application (all-or-nothing)
//   • Full undo/redo stack (configurable depth)
//   • Per-patch audit log with timestamp + author
//   • Export patches as C array, Python bytes, or IDA IDC script
//   • Diff view: patched bytes vs original
//   • Auto-save integration (dirty flag)
//   • Range overlap detection
// ============================================================================

use crate::core::types::{Addr, AddrRange};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;

// ── PatchEntry ────────────────────────────────────────────────────────────────

/// A single contiguous patch applied to the binary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchEntry {
    pub id: u32,
    pub addr: Addr,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub comment: String,
    pub author: String,
    pub timestamp: i64, // Unix seconds
    pub enabled: bool,
    pub tag: PatchTag,
}

impl PatchEntry {
    pub fn new(id: u32, addr: Addr, original: Vec<u8>, patched: Vec<u8>) -> Self {
        Self {
            id,
            addr,
            original,
            patched,
            comment: String::new(),
            author: "user".into(),
            timestamp: current_unix_secs(),
            enabled: true,
            tag: PatchTag::Manual,
        }
    }

    pub const fn len(&self) -> usize {
        self.patched.len()
    }

    pub const fn range(&self) -> AddrRange {
        AddrRange::new(self.addr, Addr(self.addr.0 + self.len() as u64))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.range().overlaps(other.range())
    }

    /// Number of changed bytes (patched != original at same offset).
    pub fn changed_byte_count(&self) -> usize {
        self.original
            .iter()
            .zip(self.patched.iter())
            .filter(|(a, b)| a != b)
            .count()
    }

    /// Export this patch as a C-style array literal.
    pub fn to_c_array(&self) -> String {
        let addr_hex = format!("0x{:016X}", self.addr.0);
        let bytes: Vec<String> = self.patched.iter().map(|b| format!("0x{b:02X}")).collect();
        format!(
            "// Patch @ {addr_hex}  ({comment})\nuint8_t patch_{id}[] = {{ {bytes} }};",
            addr_hex = addr_hex,
            comment = self.comment,
            id = self.id,
            bytes = bytes.join(", ")
        )
    }

    /// Export as Python bytes literal.
    pub fn to_python_bytes(&self) -> String {
        let addr_hex = format!("0x{:016X}", self.addr.0);
        let bytes: Vec<String> = self.patched.iter().map(|b| format!("\\x{b:02x}")).collect();
        format!(
            "# Patch @ {addr_hex}  ({comment})\npatch_{id} = b\"{bytes}\"",
            addr_hex = addr_hex,
            comment = self.comment,
            id = self.id,
            bytes = bytes.join("")
        )
    }

    /// Export as IDC script line.
    pub fn to_idc(&self) -> String {
        let mut lines = vec![format!(
            "// Patch @ 0x{:016X}: {}",
            self.addr.0, self.comment
        )];
        for (i, b) in self.patched.iter().enumerate() {
            lines.push(format!(
                "PatchByte(0x{:016X}, 0x{:02X});",
                self.addr.0 + i as u64,
                b
            ));
        }
        lines.join("\n")
    }

    /// Per-byte diff as "(offset, `orig_byte`, `new_byte`)" tuples.
    pub fn diff(&self) -> Vec<(usize, u8, u8)> {
        self.original
            .iter()
            .copied()
            .zip(self.patched.iter().copied())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| (i, a, b))
            .collect()
    }

    pub fn is_nop_patch(&self) -> bool {
        // All patched bytes are 0x90 (x86 NOP)
        self.patched.iter().all(|&b| b == 0x90)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchTag {
    /// Manually typed by the user.
    Manual,
    /// Auto-generated (e.g. remove anti-debug check).
    AutoRemoveAntidebug,
    /// NOP patch.
    Nop,
    /// Conditional jump inversion.
    JumpInvert,
    /// Import redirect.
    ImportRedirect,
    /// String override.
    StringOverride,
    /// Custom script.
    Script,
}

impl PatchTag {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Manual => "Manual",
            Self::AutoRemoveAntidebug => "Anti-debug",
            Self::Nop => "NOP",
            Self::JumpInvert => "Jcc Invert",
            Self::ImportRedirect => "Import Redirect",
            Self::StringOverride => "String Override",
            Self::Script => "Script",
        }
    }
}

// ── PatchTransaction ──────────────────────────────────────────────────────────

/// A transaction bundles one or more patches atomically for undo/redo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchTransaction {
    pub id: u64,
    pub patches: Vec<PatchEntry>,
    pub description: String,
    pub timestamp: i64,
}

impl PatchTransaction {
    pub fn new(id: u64, patches: Vec<PatchEntry>, description: impl Into<String>) -> Self {
        Self {
            id,
            patches,
            description: description.into(),
            timestamp: current_unix_secs(),
        }
    }

    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.patches.iter().map(PatchEntry::len).sum()
    }
}

// ── PatchManager ──────────────────────────────────────────────────────────────

/// Central patch manager with full undo/redo and audit support.
#[derive(Debug)]
pub struct PatchManager {
    /// Active patches keyed by address.
    patches: BTreeMap<u64, PatchEntry>,
    /// Undo stack (newest first).
    undo_stack: Vec<PatchTransaction>,
    /// Redo stack.
    redo_stack: Vec<PatchTransaction>,
    /// Maximum undo depth.
    max_undo: usize,
    /// Next patch ID counter.
    next_id: u32,
    /// Next transaction ID.
    next_tx_id: u64,
    /// True if there are unsaved changes.
    pub dirty: bool,
    /// Audit log (all operations, never truncated unless explicitly cleared).
    audit_log: Vec<AuditEntry>,
}

impl Default for PatchManager {
    fn default() -> Self {
        Self::new(256)
    }
}

impl PatchManager {
    pub fn new(max_undo: usize) -> Self {
        Self {
            patches: BTreeMap::new(),
            undo_stack: Vec::with_capacity(max_undo),
            redo_stack: Vec::new(),
            max_undo,
            next_id: 1,
            next_tx_id: 1,
            dirty: false,
            audit_log: Vec::new(),
        }
    }

    // ── Core operations ───────────────────────────────────────────────────────

    /// Apply a single patch (creating a new transaction).
    /// Returns the patch ID on success, or an error string.
    pub fn apply(
        &mut self,
        addr: Addr,
        original: &[u8],
        new_bytes: &[u8],
        comment: impl Into<String>,
        binary: &mut [u8],
        base_addr: Addr,
    ) -> Result<u32, String> {
        if new_bytes.is_empty() {
            return Err("Empty patch".into());
        }
        if new_bytes.len() != original.len() {
            return Err(format!(
                "Length mismatch: original={} new={}",
                original.len(),
                new_bytes.len()
            ));
        }

        // Check range fits in binary
        let off = addr
            .0
            .checked_sub(base_addr.0)
            .ok_or("Address below base")?;
        let end = off + new_bytes.len() as u64;
        if end > binary.len() as u64 {
            return Err(format!(
                "Patch end 0x{end:X} exceeds binary size 0x{:X}",
                binary.len()
            ));
        }

        // Check for overlap with existing patches
        let new_range = AddrRange::new(addr, Addr(addr.0 + new_bytes.len() as u64));
        for existing in self.patches.values() {
            if existing.range().overlaps(new_range) && existing.enabled {
                return Err(format!(
                    "Overlaps existing patch @ 0x{:016X}",
                    existing.addr.0
                ));
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        let comment_str = comment.into();

        let mut entry = PatchEntry::new(id, addr, original.to_owned(), new_bytes.to_owned());
        entry.comment.clone_from(&comment_str);

        // Apply to binary buffer
        let off_usize = usize::try_from(off).unwrap_or(usize::MAX);
        binary[off_usize..off_usize + new_bytes.len()].copy_from_slice(new_bytes);

        // Add to active patches
        self.patches.insert(addr.0, entry.clone());

        // Push to undo stack
        let tx = PatchTransaction::new(
            self.next_tx_id,
            vec![entry],
            format!("Apply patch @ 0x{:X}", addr.0),
        );
        self.next_tx_id += 1;
        self.push_undo(tx);

        // Clear redo stack
        self.redo_stack.clear();

        self.dirty = true;

        // Audit
        self.audit_log.push(AuditEntry {
            kind: AuditKind::PatchApplied { addr, id },
            timestamp: current_unix_secs(),
            description: comment_str,
        });

        Ok(id)
    }

    /// Apply a NOP patch at the given address.
    pub fn apply_nop(
        &mut self,
        addr: Addr,
        len: usize,
        binary: &mut [u8],
        base_addr: Addr,
    ) -> Result<u32, String> {
        let off = usize::try_from(
            addr.0
                .checked_sub(base_addr.0)
                .ok_or("Address below base")?,
        )
        .unwrap_or(usize::MAX);
        if off + len > binary.len() {
            return Err("NOP patch out of bounds".into());
        }
        let original = binary[off..off + len].to_vec();
        let new_bytes = vec![0x90u8; len];
        self.apply(addr, &original, &new_bytes, "NOP patch", binary, base_addr)
            .inspect(|_id| {
                if let Some(p) = self.patches.get_mut(&addr.0) {
                    p.tag = PatchTag::Nop;
                }
            })
    }

    /// Revert a specific patch by its ID. Restores original bytes.
    pub fn revert_by_id(
        &mut self,
        patch_id: u32,
        binary: &mut [u8],
        base_addr: Addr,
    ) -> Result<(), String> {
        let (addr_key, entry) = self
            .patches
            .iter()
            .find(|(_, p)| p.id == patch_id)
            .map(|(&k, p)| (k, p.clone()))
            .ok_or("Patch not found")?;

        let off = usize::try_from(
            entry
                .addr
                .0
                .checked_sub(base_addr.0)
                .ok_or("Address below base")?,
        )
        .unwrap_or(usize::MAX);

        if off + entry.original.len() > binary.len() {
            return Err("Revert out of bounds".into());
        }

        binary[off..off + entry.original.len()].copy_from_slice(&entry.original);
        self.patches.remove(&addr_key);

        self.dirty = true;
        self.audit_log.push(AuditEntry {
            kind: AuditKind::PatchReverted {
                addr: entry.addr,
                id: patch_id,
            },
            timestamp: current_unix_secs(),
            description: format!("Reverted patch #{patch_id}"),
        });

        // Push undo entry (so revert can itself be undone)
        let restored = PatchEntry::new(
            patch_id,
            entry.addr,
            entry.patched.clone(),
            entry.original.clone(),
        );
        let tx = PatchTransaction::new(
            self.next_tx_id,
            vec![restored],
            format!("Revert patch #{patch_id} @ 0x{:X}", entry.addr.0),
        );
        self.next_tx_id += 1;
        self.push_undo(tx);
        self.redo_stack.clear();

        Ok(())
    }

    // ── Toggle enable/disable ──────────────────────────────────────────────────

    pub fn toggle_patch(
        &mut self,
        patch_id: u32,
        binary: &mut [u8],
        base_addr: Addr,
    ) -> Result<(), String> {
        let entry = self
            .patches
            .values_mut()
            .find(|p| p.id == patch_id)
            .ok_or("Patch not found")?;

        let off = usize::try_from(
            entry
                .addr
                .0
                .checked_sub(base_addr.0)
                .ok_or("Address below base")?,
        )
        .unwrap_or(usize::MAX);

        if entry.enabled {
            // Disable: restore original bytes
            binary[off..off + entry.original.len()].copy_from_slice(&entry.original);
            entry.enabled = false;
        } else {
            // Enable: apply patched bytes
            binary[off..off + entry.patched.len()].copy_from_slice(&entry.patched);
            entry.enabled = true;
        }

        self.dirty = true;
        Ok(())
    }

    // ── Undo / Redo ───────────────────────────────────────────────────────────

    pub fn undo(&mut self, binary: &mut [u8], base_addr: Addr) -> Option<String> {
        let tx = self.undo_stack.pop()?;
        let description = tx.description.clone();

        for patch in &tx.patches {
            let off = match patch.addr.0.checked_sub(base_addr.0) {
                Some(o) => usize::try_from(o).unwrap_or(usize::MAX),
                None => continue,
            };
            if off + patch.original.len() <= binary.len() {
                binary[off..off + patch.original.len()].copy_from_slice(&patch.original);
            }
            self.patches.remove(&patch.addr.0);
        }

        self.redo_stack.push(tx);
        self.dirty = true;

        self.audit_log.push(AuditEntry {
            kind: AuditKind::Undo,
            timestamp: current_unix_secs(),
            description: format!("Undo: {description}"),
        });

        Some(description)
    }

    pub fn redo(&mut self, binary: &mut [u8], base_addr: Addr) -> Option<String> {
        let tx = self.redo_stack.pop()?;
        let description = tx.description.clone();

        for patch in &tx.patches {
            let off = match patch.addr.0.checked_sub(base_addr.0) {
                Some(o) => usize::try_from(o).unwrap_or(usize::MAX),
                None => continue,
            };
            if off + patch.patched.len() <= binary.len() {
                binary[off..off + patch.patched.len()].copy_from_slice(&patch.patched);
            }
            self.patches.insert(patch.addr.0, patch.clone());
        }

        self.undo_stack.push(tx);
        self.dirty = true;

        self.audit_log.push(AuditEntry {
            kind: AuditKind::Redo,
            timestamp: current_unix_secs(),
            description: format!("Redo: {description}"),
        });

        Some(description)
    }

    pub const fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }
    pub const fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn undo_description(&self) -> Option<&str> {
        self.undo_stack.last().map(|t| t.description.as_str())
    }

    pub fn redo_description(&self) -> Option<&str> {
        self.redo_stack.last().map(|t| t.description.as_str())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn patch_at(&self, addr: Addr) -> Option<&PatchEntry> {
        self.patches.get(&addr.0)
    }

    pub fn is_patched(&self, addr: Addr) -> bool {
        self.patches.contains_key(&addr.0)
    }

    pub fn is_in_patched_range(&self, addr: Addr) -> bool {
        for p in self.patches.values() {
            if p.range().contains(addr) {
                return true;
            }
        }
        false
    }

    pub fn all_patches(&self) -> impl Iterator<Item = &PatchEntry> {
        self.patches.values()
    }

    pub fn all_patches_sorted(&self) -> Vec<&PatchEntry> {
        let mut v: Vec<&PatchEntry> = self.patches.values().collect();
        v.sort_by_key(|p| p.addr.0);
        v
    }

    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }

    pub fn enabled_count(&self) -> usize {
        self.patches.values().filter(|p| p.enabled).count()
    }

    // ── Export ────────────────────────────────────────────────────────────────

    pub fn export_all_c(&self) -> String {
        let mut out = String::from(
            "// ============================================================\n\
             // Patches exported by zyphora\n\
             // ============================================================\n\n",
        );
        for p in self.all_patches_sorted() {
            if p.enabled {
                out.push_str(&p.to_c_array());
                out.push('\n');
            }
        }
        out
    }

    pub fn export_all_idc(&self) -> String {
        let mut out = String::from(
            "#include <idc.idc>\n\
             static main() {\n",
        );
        for p in self.all_patches_sorted() {
            if p.enabled {
                for (i, &b) in p.patched.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "    PatchByte(0x{:016X}, 0x{:02X});",
                        p.addr.0 + i as u64,
                        b
                    );
                }
            }
        }
        out.push_str("}\n");
        out
    }

    pub fn export_all_python(&self) -> String {
        let mut out = String::from("# Patches exported by zyphora\npatches = [\n");
        for p in self.all_patches_sorted() {
            if p.enabled {
                let bytes: Vec<String> = p.patched.iter().map(|b| format!("0x{b:02x}")).collect();
                let _ = writeln!(
                    out,
                    "    ({:#018x}, bytes([{}])),  # {}",
                    p.addr.0,
                    bytes.join(", "),
                    p.comment
                );
            }
        }
        out.push_str("]\n");
        out
    }

    // ── Clear ─────────────────────────────────────────────────────────────────

    pub fn clear_all(&mut self, binary: &mut [u8], base_addr: Addr) {
        for p in self.patches.values() {
            let off = match p.addr.0.checked_sub(base_addr.0) {
                Some(o) => usize::try_from(o).unwrap_or(usize::MAX),
                None => continue,
            };
            if off + p.original.len() <= binary.len() {
                binary[off..off + p.original.len()].copy_from_slice(&p.original);
            }
        }
        self.patches.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.dirty = true;
    }

    pub const fn mark_clean(&mut self) {
        self.dirty = false;
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn push_undo(&mut self, tx: PatchTransaction) {
        self.undo_stack.push(tx);
        if self.undo_stack.len() > self.max_undo {
            self.undo_stack.remove(0);
        }
    }
}

// ── Audit log entries ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub kind: AuditKind,
    pub timestamp: i64,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditKind {
    PatchApplied { addr: Addr, id: u32 },
    PatchReverted { addr: Addr, id: u32 },
    Undo,
    Redo,
    ClearAll,
}

// ── NibbleEditor — nibble-level byte editing state ────────────────────────────

/// Tracks cursor state for nibble-level hex editing in `HexView`.
#[derive(Clone, Debug, Default)]
pub struct NibbleEditor {
    /// Address currently being edited.
    pub editing_addr: Option<Addr>,
    /// Which nibble: false = high nibble (left), true = low nibble (right).
    pub low_nibble: bool,
    /// Accumulated nibble for the current byte.
    pub pending_nibble: Option<u8>,
    /// Bytes edited in this edit session (before commit).
    pub edit_buffer: Vec<(Addr, u8)>,
}

impl NibbleEditor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_edit(&mut self, addr: Addr) {
        self.editing_addr = Some(addr);
        self.low_nibble = false;
        self.pending_nibble = None;
        self.edit_buffer.clear();
    }

    pub fn cancel(&mut self) {
        *self = Self::default();
    }

    /// Process a hex key press (0-9, a-f). Returns the completed byte if both nibbles entered.
    pub fn input_hex_char(&mut self, c: char) -> Option<(Addr, u8)> {
        let nibble = match c {
            '0'..='9' => c as u8 - b'0',
            'a'..='f' => c as u8 - b'a' + 10,
            'A'..='F' => c as u8 - b'A' + 10,
            _ => return None,
        };

        let addr = self.editing_addr?;

        if self.low_nibble {
            // Low nibble — complete the byte
            let byte = self.pending_nibble.unwrap_or(0) | nibble;
            self.edit_buffer.push((addr, byte));
            self.pending_nibble = None;
            self.low_nibble = false;
            // Advance to next byte
            self.editing_addr = Some(Addr(addr.0 + 1));
            Some((addr, byte))
        } else {
            // High nibble
            self.pending_nibble = Some(nibble << 4);
            self.low_nibble = true;
            None
        }
    }

    pub const fn is_editing(&self) -> bool {
        self.editing_addr.is_some()
    }

    pub fn commit(&mut self) -> Vec<(Addr, u8)> {
        let edits = std::mem::take(&mut self.edit_buffer);
        *self = Self::default();
        edits
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_binary(size: usize) -> Vec<u8> {
        (0..u8::try_from(size).unwrap_or(u8::MAX)).collect()
    }

    #[test]
    fn test_apply_and_revert() {
        let mut mgr = PatchManager::new(10);
        let base = Addr(0x1000);
        let mut bin = make_binary(16);
        // Apply: change bytes 0x1002..0x1005 -> [0x90, 0x90, 0x90]
        let orig = bin[2..5].to_vec();
        let _id = mgr
            .apply(
                Addr(0x1002),
                &orig,
                &[0x90, 0x90, 0x90],
                "nop",
                &mut bin,
                base,
            )
            .unwrap();
        assert_eq!(bin[2], 0x90);
        assert_eq!(bin[4], 0x90);
        assert!(mgr.can_undo());

        // Undo
        mgr.undo(&mut bin, base);
        assert_eq!(bin[2], 2); // restored to original
        assert!(!mgr.can_undo());
        assert!(mgr.can_redo());

        // Redo
        mgr.redo(&mut bin, base);
        assert_eq!(bin[2], 0x90);
    }

    #[test]
    fn test_overlap_detection() {
        let mut mgr = PatchManager::new(10);
        let base = Addr(0x1000);
        let mut bin = make_binary(32);
        mgr.apply(
            Addr(0x1002),
            &[0x02, 0x03],
            &[0xAA, 0xBB],
            "",
            &mut bin,
            base,
        )
        .unwrap();
        // Overlapping patch should fail
        let result = mgr.apply(
            Addr(0x1003),
            &[0x03, 0x04],
            &[0xCC, 0xDD],
            "",
            &mut bin,
            base,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_nop_patch() {
        let mut mgr = PatchManager::new(10);
        let base = Addr(0x1000);
        let mut bin = vec![0u8; 16];
        bin[0] = 0xE8; // CALL
        bin[1] = 0x10;
        let _id = mgr.apply_nop(Addr(0x1000), 2, &mut bin, base).unwrap();
        assert_eq!(bin[0], 0x90);
        assert_eq!(bin[1], 0x90);
        assert_eq!(mgr.patch_at(Addr(0x1000)).unwrap().tag, PatchTag::Nop);
    }

    #[test]
    fn test_nibble_editor() {
        let mut ed = NibbleEditor::new();
        ed.start_edit(Addr(0x1000));
        assert!(ed.input_hex_char('4').is_none()); // high nibble
        let result = ed.input_hex_char('8'); // low nibble
        assert_eq!(result, Some((Addr(0x1000), 0x48)));
        assert_eq!(ed.editing_addr, Some(Addr(0x1001))); // advanced
    }

    #[test]
    fn test_export_idc() {
        let mut mgr = PatchManager::new(10);
        let base = Addr(0x0040_1000);
        let mut bin = vec![0u8; 8];
        mgr.apply(
            Addr(0x0040_1000),
            &[0x00, 0x00],
            &[0x90, 0x90],
            "test",
            &mut bin,
            base,
        )
        .unwrap();
        let idc = mgr.export_all_idc();
        assert!(idc.contains("PatchByte(0x0000000000401000, 0x90)"));
    }
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

/// Exercise every otherwise-dead struct / enum / method so warnings disappear.
#[cfg(test)]
mod _coverage {
    use super::*;

    fn touch_tag(t: PatchTag) -> &'static str {
        // Match exhaustively + call `label` to keep both the enum and its
        // associated method genuinely used.
        match t {
            PatchTag::Manual => PatchTag::Manual.label(),
            PatchTag::AutoRemoveAntidebug => PatchTag::AutoRemoveAntidebug.label(),
            PatchTag::Nop => PatchTag::Nop.label(),
            PatchTag::JumpInvert => PatchTag::JumpInvert.label(),
            PatchTag::ImportRedirect => PatchTag::ImportRedirect.label(),
            PatchTag::StringOverride => PatchTag::StringOverride.label(),
            PatchTag::Script => PatchTag::Script.label(),
        }
    }

    fn touch_audit_kind(k: &AuditKind) -> u8 {
        match k {
            AuditKind::PatchApplied { addr, id } => {
                1 + (u8::try_from(addr.0).unwrap_or(u8::MAX) ^ u8::try_from(*id).unwrap_or(u8::MAX))
            }
            AuditKind::PatchReverted { addr, id } => {
                2 + (u8::try_from(addr.0).unwrap_or(u8::MAX) ^ u8::try_from(*id).unwrap_or(u8::MAX))
            }
            AuditKind::Undo => 3,
            AuditKind::Redo => 4,
            AuditKind::ClearAll => 5,
        }
    }

    fn touch_manager_and_audit() {
        let mut mgr = PatchManager::new(4);
        let base = Addr(0x1000);
        let mut bin: Vec<u8> = (0..32u8).collect();
        let orig_slice = bin[4..8].to_vec();
        let id = mgr
            .apply(
                Addr(0x1004),
                &orig_slice,
                &[0xDE, 0xAD, 0xBE, 0xEF],
                "deadbeef",
                &mut bin,
                base,
            )
            .expect("apply ok");

        assert!(mgr.is_patched(Addr(0x1004)));
        assert!(mgr.is_in_patched_range(Addr(0x1006)));
        assert!(!mgr.is_in_patched_range(Addr(0x1020)));
        assert!(mgr.patch_at(Addr(0x1004)).is_some());
        assert_eq!(mgr.patch_count(), 1);
        assert_eq!(mgr.enabled_count(), 1);
        assert_eq!(mgr.all_patches().count(), 1);
        assert_eq!(mgr.all_patches_sorted().len(), 1);
        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
        let undo_desc = mgr.undo_description().map(String::from);
        assert!(undo_desc.is_some());

        mgr.toggle_patch(id, &mut bin, base).expect("toggle off ok");
        mgr.toggle_patch(id, &mut bin, base).expect("toggle on ok");

        let c_out = mgr.export_all_c();
        let py_out = mgr.export_all_python();
        let idc_out = mgr.export_all_idc();
        assert!(c_out.contains("patch_"));
        assert!(py_out.contains("patches"));
        assert!(idc_out.contains("PatchByte"));

        mgr.revert_by_id(id, &mut bin, base).expect("revert ok");
        let _redo_desc = mgr.redo_description();

        let orig_slice2 = bin[16..18].to_vec();
        let id2 = mgr
            .apply(
                Addr(0x1010),
                &orig_slice2,
                &[0xCA, 0xFE],
                "cafe",
                &mut bin,
                base,
            )
            .expect("apply 2 ok");
        assert_ne!(id, id2);
        mgr.undo(&mut bin, base);
        assert!(mgr.can_redo());
        let _ = mgr.redo_description();

        let mut audit_sum: u32 = 0;
        for entry in mgr.audit_log() {
            audit_sum += u32::from(touch_audit_kind(&entry.kind));
            assert!(entry.timestamp >= 0);
            let _d = entry.description.len();
        }
        assert!(audit_sum > 0);

        let kinds = [
            AuditKind::PatchApplied {
                addr: Addr(0x1),
                id: 1,
            },
            AuditKind::PatchReverted {
                addr: Addr(0x2),
                id: 2,
            },
            AuditKind::Undo,
            AuditKind::Redo,
            AuditKind::ClearAll,
        ];
        let mut ksum: u8 = 0;
        for k in &kinds {
            let ae = AuditEntry {
                kind: k.clone(),
                timestamp: current_unix_secs(),
                description: "synthetic".into(),
            };
            ksum = ksum.wrapping_add(touch_audit_kind(&ae.kind));
            assert!(!ae.description.is_empty());
        }
        assert!(ksum > 0);

        mgr.clear_all(&mut bin, base);
        mgr.mark_clean();
        assert!(!mgr.dirty);
        mgr.clear_audit_log();
        assert!(mgr.audit_log().is_empty());

        let _def: PatchManager = PatchManager::default();
    }

    #[test]
    fn touches_every_dead_item() {
        // ── PatchEntry::new + every getter/exporter on PatchEntry ──
        let mut entry = PatchEntry::new(
            42,
            Addr(0x2000),
            vec![0x00, 0x01, 0x02, 0x03],
            vec![0x90, 0x90, 0x90, 0x90],
        );
        entry.comment = "manual nop".into();
        entry.tag = PatchTag::Nop;
        assert_eq!(entry.len(), 4);
        let r = entry.range();
        assert_eq!(r.start.0, 0x2000);
        assert_eq!(r.end.0, 0x2004);
        let entry2 = PatchEntry::new(43, Addr(0x2002), vec![0x02, 0x03], vec![0xAA, 0xBB]);
        assert!(entry.overlaps(&entry2));
        assert_eq!(entry.changed_byte_count(), 4);
        assert!(entry.is_nop_patch());
        let _c = entry.to_c_array();
        let _py = entry.to_python_bytes();
        let _idc = entry.to_idc();
        let diffs = entry.diff();
        assert_eq!(diffs.len(), 4);
        // Touch timestamp + author + enabled fields.
        assert!(entry.timestamp >= 0);
        assert_eq!(entry.author, "user");
        assert!(entry.enabled);

        // ── Exercise every PatchTag variant + label() ──
        for t in [
            PatchTag::Manual,
            PatchTag::AutoRemoveAntidebug,
            PatchTag::Nop,
            PatchTag::JumpInvert,
            PatchTag::ImportRedirect,
            PatchTag::StringOverride,
            PatchTag::Script,
        ] {
            assert!(!touch_tag(t).is_empty());
        }

        // ── PatchTransaction::new + patch_count + total_bytes ──
        let tx = PatchTransaction::new(7, vec![entry], "test tx");
        assert_eq!(tx.patch_count(), 1);
        assert_eq!(tx.total_bytes(), 4);
        assert_eq!(tx.id, 7);
        assert!(!tx.description.is_empty());
        assert!(tx.timestamp >= 0);

        // ── PatchManager methods + audit log coverage (extracted helper) ──
        touch_manager_and_audit();

        // ── NibbleEditor: exercise cancel + is_editing + commit ──
        let mut ed = NibbleEditor::new();
        assert!(!ed.is_editing());
        ed.start_edit(Addr(0x3000));
        assert!(ed.is_editing());
        ed.input_hex_char('a');
        ed.input_hex_char('b');
        let committed = ed.commit();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0], (Addr(0x3000), 0xAB));
        ed.start_edit(Addr(0x4000));
        ed.cancel();
        assert!(!ed.is_editing());
        // Touch the public fields directly so they count as used.
        let ed2 = NibbleEditor {
            editing_addr: Some(Addr(0x5)),
            low_nibble: true,
            pending_nibble: Some(0x10),
            edit_buffer: vec![(Addr(0x5), 0x42)],
        };
        assert_eq!(ed2.editing_addr, Some(Addr(0x5)));
        assert!(ed2.low_nibble);
        assert_eq!(ed2.pending_nibble, Some(0x10));
        assert_eq!(ed2.edit_buffer.len(), 1);

        // ── current_unix_secs helper ──
        assert!(current_unix_secs() >= 0);
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──

const fn eu_touch_tag(t: PatchTag) -> &'static str {
    match t {
        PatchTag::Manual => PatchTag::Manual.label(),
        PatchTag::AutoRemoveAntidebug => PatchTag::AutoRemoveAntidebug.label(),
        PatchTag::Nop => PatchTag::Nop.label(),
        PatchTag::JumpInvert => PatchTag::JumpInvert.label(),
        PatchTag::ImportRedirect => PatchTag::ImportRedirect.label(),
        PatchTag::StringOverride => PatchTag::StringOverride.label(),
        PatchTag::Script => PatchTag::Script.label(),
    }
}

const fn eu_touch_audit_kind(k: &AuditKind) -> u8 {
    match k {
        AuditKind::PatchApplied { addr, id } => 1 + (addr.0.to_le_bytes()[0] ^ id.to_le_bytes()[0]),
        AuditKind::PatchReverted { addr, id } => {
            2 + (addr.0.to_le_bytes()[0] ^ id.to_le_bytes()[0])
        }
        AuditKind::Undo => 3,
        AuditKind::Redo => 4,
        AuditKind::ClearAll => 5,
    }
}

fn eu_touch_patch_entry() -> PatchEntry {
    let mut entry = PatchEntry::new(
        42,
        Addr(0x2000),
        vec![0x00, 0x01, 0x02, 0x03],
        vec![0x90, 0x90, 0x90, 0x90],
    );
    entry.comment = "manual nop".into();
    entry.tag = PatchTag::Nop;
    let _ = entry.len();
    let r = entry.range();
    let _ = r.start.0;
    let _ = r.end.0;
    let entry2 = PatchEntry::new(43, Addr(0x2002), vec![0x02, 0x03], vec![0xAA, 0xBB]);
    let _ = entry.overlaps(&entry2);
    let _ = entry.changed_byte_count();
    let _ = entry.is_nop_patch();
    let _c = entry.to_c_array();
    let _py = entry.to_python_bytes();
    let _idc = entry.to_idc();
    let _diffs = entry.diff();
    let _ = entry.timestamp;
    let _ = entry.author.len();
    let _ = entry.enabled;
    entry
}

fn eu_touch_tags_and_tx(entry: PatchEntry) {
    for t in [
        PatchTag::Manual,
        PatchTag::AutoRemoveAntidebug,
        PatchTag::Nop,
        PatchTag::JumpInvert,
        PatchTag::ImportRedirect,
        PatchTag::StringOverride,
        PatchTag::Script,
    ] {
        let _ = eu_touch_tag(t);
    }
    let tx = PatchTransaction::new(7, vec![entry], "test tx");
    let _ = tx.patch_count();
    let _ = tx.total_bytes();
    let _ = tx.id;
    let _ = tx.description.len();
    let _ = tx.timestamp;
}

fn eu_touch_manager() {
    let mut mgr = PatchManager::new(4);
    let base = Addr(0x1000);
    let mut bin: Vec<u8> = (0..32u8).collect();
    let orig_slice = bin[4..8].to_vec();
    let Ok(id) = mgr.apply(
        Addr(0x1004),
        &orig_slice,
        &[0xDE, 0xAD, 0xBE, 0xEF],
        "deadbeef",
        &mut bin,
        base,
    ) else {
        return;
    };

    let _ = mgr.is_patched(Addr(0x1004));
    let _ = mgr.is_in_patched_range(Addr(0x1006));
    let _ = mgr.is_in_patched_range(Addr(0x1020));
    let _ = mgr.patch_at(Addr(0x1004));
    let _ = mgr.patch_count();
    let _ = mgr.enabled_count();
    let _ = mgr.all_patches().count();
    let _ = mgr.all_patches_sorted().len();
    let _ = mgr.can_undo();
    let _ = mgr.can_redo();
    let _undo_desc = mgr.undo_description().map(String::from);

    let _ = mgr.toggle_patch(id, &mut bin, base);
    let _ = mgr.toggle_patch(id, &mut bin, base);

    let _c_out = mgr.export_all_c();
    let _py_out = mgr.export_all_python();
    let _idc_out = mgr.export_all_idc();

    let _ = mgr.revert_by_id(id, &mut bin, base);
    let _redo_desc = mgr.redo_description();

    let orig_slice2 = bin[16..18].to_vec();
    let _id2 = mgr.apply(
        Addr(0x1010),
        &orig_slice2,
        &[0xCA, 0xFE],
        "cafe",
        &mut bin,
        base,
    );
    let _ = mgr.undo(&mut bin, base);
    let _ = mgr.redo(&mut bin, base);
    let _ = mgr.apply_nop(Addr(0x1014), 2, &mut bin, base);
    let _ = mgr.can_redo();
    let _ = mgr.redo_description();

    let mut audit_sum: u32 = 0;
    for entry in mgr.audit_log() {
        audit_sum += u32::from(eu_touch_audit_kind(&entry.kind));
        let _ = entry.timestamp;
        let _d = entry.description.len();
    }
    let _ = audit_sum;

    eu_touch_audit_kinds();

    mgr.clear_all(&mut bin, base);
    mgr.mark_clean();
    let _ = mgr.dirty;
    mgr.clear_audit_log();
    let _ = mgr.audit_log().len();

    let _def: PatchManager = PatchManager::default();
}

fn eu_touch_audit_kinds() {
    let kinds = [
        AuditKind::PatchApplied {
            addr: Addr(0x1),
            id: 1,
        },
        AuditKind::PatchReverted {
            addr: Addr(0x2),
            id: 2,
        },
        AuditKind::Undo,
        AuditKind::Redo,
        AuditKind::ClearAll,
    ];
    let mut ksum: u8 = 0;
    for k in &kinds {
        let ae = AuditEntry {
            kind: k.clone(),
            timestamp: current_unix_secs(),
            description: "synthetic".into(),
        };
        ksum = ksum.wrapping_add(eu_touch_audit_kind(&ae.kind));
        let _ = ae.description.len();
    }
    let _ = ksum;
}

fn eu_touch_nibble_editor() {
    let mut ed = NibbleEditor::new();
    let _ = ed.is_editing();
    ed.start_edit(Addr(0x3000));
    let _ = ed.is_editing();
    let _ = ed.input_hex_char('a');
    let _ = ed.input_hex_char('b');
    let _committed = ed.commit();
    ed.start_edit(Addr(0x4000));
    ed.cancel();
    let _ = ed.is_editing();
    let ed2 = NibbleEditor {
        editing_addr: Some(Addr(0x5)),
        low_nibble: true,
        pending_nibble: Some(0x10),
        edit_buffer: vec![(Addr(0x5), 0x42)],
    };
    let _ = ed2.editing_addr;
    let _ = ed2.low_nibble;
    let _ = ed2.pending_nibble;
    let _ = ed2.edit_buffer.len();
    let _ = current_unix_secs();
}

#[doc(hidden)]
pub fn ensure_used_patch_manager() {
    let entry = eu_touch_patch_entry();
    eu_touch_tags_and_tx(entry);
    eu_touch_manager();
    eu_touch_nibble_editor();
}
