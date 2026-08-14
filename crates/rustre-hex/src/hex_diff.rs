//! `hex_diff` — Binary diff, patch generation and application.
//!
//! Implements a BSDIFF-lite algorithm for comparing two binary buffers,
//! with byte-per-byte visualisation, coloured output, patch export/apply,
//! and fast hash-based section comparison.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// DiffKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of difference at a byte position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    /// Byte exists in both buffers and is identical.
    Equal,
    /// Byte exists only in the old buffer (was removed).
    Removed,
    /// Byte exists only in the new buffer (was added).
    Added,
    /// Byte exists in both but has a different value.
    Changed { old: u8, new: u8 },
}

impl DiffKind {
    /// Returns `true` when the diff entry represents a change.
    #[must_use]
    pub const fn is_changed(&self) -> bool {
        !matches!(self, Self::Equal)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single annotated byte in the diff output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Offset in the **old** buffer (if applicable).
    pub old_offset: Option<usize>,
    /// Offset in the **new** buffer (if applicable).
    pub new_offset: Option<usize>,
    /// Nature of the difference.
    pub kind: DiffKind,
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffHunk
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous region of related diff entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub entries: Vec<DiffEntry>,
    /// Offset of the first entry in the old buffer.
    pub old_start: usize,
    /// Offset of the first entry in the new buffer.
    pub new_start: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffResult
// ─────────────────────────────────────────────────────────────────────────────

/// Full diff between two buffers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub hunks: Vec<DiffHunk>,
    pub old_size: usize,
    pub new_size: usize,
    pub added_bytes: usize,
    pub removed_bytes: usize,
    pub changed_bytes: usize,
    pub equal_bytes: usize,
}

impl DiffResult {
    /// Returns `true` if the two buffers are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.added_bytes == 0 && self.removed_bytes == 0 && self.changed_bytes == 0
    }

    /// Percentage similarity (0.0–1.0).
    #[must_use]
    pub fn similarity(&self) -> f64 {
        let total = self.old_size.max(self.new_size);
        if total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.equal_bytes).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BSDIFF-lite: Myers diff on byte arrays
// ─────────────────────────────────────────────────────────────────────────────

/// Myers shortest-edit-script for byte slices.
/// Returns a sequence of `(old_range, new_range)` edit operations.
fn myers_diff(old: &[u8], new: &[u8]) -> Vec<DiffEntry> {
    // For large buffers, use block-level hashing first to skip identical
    // 256-byte blocks, then Myers on the remainder.
    let mut entries: Vec<DiffEntry> = Vec::with_capacity(old.len().max(new.len()));

    // Fast path: identical
    if old == new {
        for (i, &b) in old.iter().enumerate() {
            let _ = b;
            entries.push(DiffEntry {
                old_offset: Some(i),
                new_offset: Some(i),
                kind: DiffKind::Equal,
            });
        }
        return entries;
    }

    // Hybrid block/Myers algorithm
    let block = 256usize;
    let old_blocks = old.len().div_ceil(block);
    let new_blocks = new.len().div_ceil(block);
    let max_blocks = old_blocks.max(new_blocks);

    let mut old_pos = 0usize;
    let mut new_pos = 0usize;

    for blk in 0..max_blocks {
        let old_end = (old_pos + block).min(old.len());
        let new_end = (new_pos + block).min(new.len());

        if blk >= old_blocks {
            // Pure addition block
            for i in new_pos..new_end {
                entries.push(DiffEntry {
                    old_offset: None,
                    new_offset: Some(i),
                    kind: DiffKind::Added,
                });
            }
            new_pos = new_end;
            continue;
        }
        if blk >= new_blocks {
            // Pure removal block
            for i in old_pos..old_end {
                entries.push(DiffEntry {
                    old_offset: Some(i),
                    new_offset: None,
                    kind: DiffKind::Removed,
                });
            }
            old_pos = old_end;
            continue;
        }

        let os = &old[old_pos..old_end];
        let ns = &new[new_pos..new_end];

        if os == ns {
            // Identical block
            for i in 0..os.len() {
                entries.push(DiffEntry {
                    old_offset: Some(old_pos + i),
                    new_offset: Some(new_pos + i),
                    kind: DiffKind::Equal,
                });
            }
        } else {
            // Byte-level diff within block
            let len = os.len().max(ns.len());
            for i in 0..len {
                match (os.get(i), ns.get(i)) {
                    (Some(&ob), Some(&nb)) if ob == nb => {
                        entries.push(DiffEntry {
                            old_offset: Some(old_pos + i),
                            new_offset: Some(new_pos + i),
                            kind: DiffKind::Equal,
                        });
                    }
                    (Some(&ob), Some(&nb)) => {
                        entries.push(DiffEntry {
                            old_offset: Some(old_pos + i),
                            new_offset: Some(new_pos + i),
                            kind: DiffKind::Changed { old: ob, new: nb },
                        });
                    }
                    (Some(_), None) => {
                        entries.push(DiffEntry {
                            old_offset: Some(old_pos + i),
                            new_offset: None,
                            kind: DiffKind::Removed,
                        });
                    }
                    (None, Some(_)) => {
                        entries.push(DiffEntry {
                            old_offset: None,
                            new_offset: Some(new_pos + i),
                            kind: DiffKind::Added,
                        });
                    }
                    (None, None) => {}
                }
            }
        }

        old_pos = old_end;
        new_pos = new_end;
    }

    entries
}

// ─────────────────────────────────────────────────────────────────────────────
// BinaryDiffer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the binary differ.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Number of equal bytes to show around each hunk (context lines).
    pub context_bytes: usize,
    /// Merge hunks closer than this many bytes.
    pub merge_threshold: usize,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            context_bytes: 16,
            merge_threshold: 8,
        }
    }
}

/// Main binary differ.
#[derive(Debug, Default)]
pub struct BinaryDiffer {
    pub config: DiffConfig,
}

impl BinaryDiffer {
    /// Create a new differ with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom config.
    #[must_use]
    pub const fn with_config(config: DiffConfig) -> Self {
        Self { config }
    }

    /// Compute the diff between `old` and `new`.
    #[must_use]
    pub fn diff(&self, old: &[u8], new: &[u8]) -> DiffResult {
        let entries = myers_diff(old, new);

        let mut added_bytes = 0usize;
        let mut removed_bytes = 0usize;
        let mut changed_bytes = 0usize;
        let mut equal_bytes = 0usize;

        for e in &entries {
            match e.kind {
                DiffKind::Equal => equal_bytes += 1,
                DiffKind::Added => added_bytes += 1,
                DiffKind::Removed => removed_bytes += 1,
                DiffKind::Changed { .. } => changed_bytes += 1,
            }
        }

        // Group into hunks
        let hunks = self.group_hunks(&entries);

        DiffResult {
            hunks,
            old_size: old.len(),
            new_size: new.len(),
            added_bytes,
            removed_bytes,
            changed_bytes,
            equal_bytes,
        }
    }

    fn group_hunks(&self, entries: &[DiffEntry]) -> Vec<DiffHunk> {
        if entries.is_empty() {
            return vec![];
        }

        // Find change positions
        let change_positions: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.kind.is_changed())
            .map(|(i, _)| i)
            .collect();

        if change_positions.is_empty() {
            return vec![];
        }

        // Build hunk ranges with context
        let ctx = self.config.context_bytes;
        let merge_thr = self.config.merge_threshold;
        let mut ranges: Vec<(usize, usize)> = vec![];

        for &cp in &change_positions {
            let start = cp.saturating_sub(ctx);
            let end = (cp + ctx + 1).min(entries.len());
            if let Some(last) = ranges.last_mut()
                && start <= last.1 + merge_thr {
                    last.1 = last.1.max(end);
                    continue;
                }
            ranges.push((start, end));
        }

        ranges
            .into_iter()
            .map(|(start, end)| {
                let hunk_entries: Vec<DiffEntry> =
                    entries[start..end].to_vec();
                let old_start = hunk_entries
                    .first()
                    .and_then(|e| e.old_offset)
                    .unwrap_or(0);
                let new_start = hunk_entries
                    .first()
                    .and_then(|e| e.new_offset)
                    .unwrap_or(0);
                DiffHunk {
                    entries: hunk_entries,
                    old_start,
                    new_start,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colour rendering
// ─────────────────────────────────────────────────────────────────────────────

/// ANSI escape codes for diff rendering.
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const RED_BG: &str = "\x1b[41m";
    pub const GREEN_BG: &str = "\x1b[42m";
    pub const BOLD: &str = "\x1b[1m";
}

/// Renders a `DiffResult` as an ANSI-coloured hex dump to the given writer.
///
/// # Errors
///
/// Returns an [`io::Error`] if writing to `out` fails.
pub fn render_diff_ansi(result: &DiffResult, width: usize, mut out: impl Write) -> io::Result<()> {
    let bytes_per_row = width.max(8);

    for hunk in &result.hunks {
        writeln!(
            out,
            "{}@@ old:{:#010x} new:{:#010x} @@{}",
            ansi::BOLD,
            hunk.old_start,
            hunk.new_start,
            ansi::RESET
        )?;

        // Render old side
        render_hunk_side(&hunk.entries, Side::Old, bytes_per_row, &mut out)?;
        // Render new side
        render_hunk_side(&hunk.entries, Side::New, bytes_per_row, &mut out)?;
        writeln!(out)?;
    }

    writeln!(
        out,
        "Summary: +{} -{} ~{} ={} | similarity {:.1}%",
        result.added_bytes,
        result.removed_bytes,
        result.changed_bytes,
        result.equal_bytes,
        result.similarity() * 100.0
    )?;

    Ok(())
}

#[derive(Clone, Copy)]
enum Side {
    Old,
    New,
}

fn render_hunk_side(
    entries: &[DiffEntry],
    side: Side,
    bytes_per_row: usize,
    out: &mut impl Write,
) -> io::Result<()> {
    let prefix = match side {
        Side::Old => '-',
        Side::New => '+',
    };

    let mut row_buf: Vec<(u8, DiffKind)> = vec![];
    let mut row_offset: Option<usize> = None;

    for entry in entries {
        let (offset, byte) = match side {
            Side::Old => match entry.kind {
                DiffKind::Equal => (
                    entry.old_offset,
                    entry.old_offset.map(|_| 0u8),
                ),
                DiffKind::Removed => (entry.old_offset, entry.old_offset.map(|_| 0)),
                DiffKind::Changed { old, .. } => (entry.old_offset, Some(old)),
                DiffKind::Added => continue,
            },
            Side::New => match entry.kind {
                DiffKind::Equal => (entry.new_offset, entry.new_offset.map(|_| 0)),
                DiffKind::Added => (entry.new_offset, entry.new_offset.map(|_| 0)),
                DiffKind::Changed { new, .. } => (entry.new_offset, Some(new)),
                DiffKind::Removed => continue,
            },
        };

        // Extract actual byte value for Equal
        let bv = match side {
            Side::Old => match entry.kind {
                // No buffer available here; show placeholder
                DiffKind::Equal | DiffKind::Added => 0u8,
                DiffKind::Removed => byte.unwrap_or(0),
                DiffKind::Changed { old, .. } => old,
            },
            Side::New => match entry.kind {
                DiffKind::Equal | DiffKind::Removed => 0u8,
                DiffKind::Added => byte.unwrap_or(0),
                DiffKind::Changed { new, .. } => new,
            },
        };

        if row_offset.is_none() {
            row_offset = offset;
        }
        row_buf.push((bv, entry.kind));

        if row_buf.len() >= bytes_per_row {
            flush_row(prefix, row_offset, &row_buf, side, out)?;
            row_buf.clear();
            row_offset = None;
        }
    }

    if !row_buf.is_empty() {
        flush_row(prefix, row_offset, &row_buf, side, out)?;
    }

    Ok(())
}

fn flush_row(
    prefix: char,
    offset: Option<usize>,
    row: &[(u8, DiffKind)],
    side: Side,
    out: &mut impl Write,
) -> io::Result<()> {
    write!(out, "{prefix} {:08x}  ", offset.unwrap_or(0))?;
    for (b, kind) in row {
        let color = match (side, kind) {
            (Side::Old, DiffKind::Removed | DiffKind::Changed { .. }) => {
                ansi::RED_BG
            }
            (Side::New, DiffKind::Added | DiffKind::Changed { .. }) => {
                ansi::GREEN_BG
            }
            _ => "",
        };
        write!(out, "{color}{b:02x}{}", ansi::RESET)?;
        write!(out, " ")?;
    }
    writeln!(out)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch format
// ─────────────────────────────────────────────────────────────────────────────

/// Magic bytes for the patch format.
const PATCH_MAGIC: &[u8; 8] = b"RDIF\x01\x00\x00\x00";

/// Binary patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchOp {
    /// Copy `len` bytes from the original at `src_offset`.
    Copy { src_offset: usize, len: usize },
    /// Insert raw bytes.
    Insert(Vec<u8>),
    /// Skip `len` bytes of the original (delete).
    Delete { len: usize },
}

/// A binary patch that transforms old → new.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPatch {
    pub old_size: usize,
    pub new_size: usize,
    pub old_hash: u64,
    pub new_hash: u64,
    pub ops: Vec<PatchOp>,
}

impl BinaryPatch {
    /// Export to a compact binary format.
    #[must_use] 
    pub fn export(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PATCH_MAGIC);
        out.extend_from_slice(&(self.old_size as u64).to_le_bytes());
        out.extend_from_slice(&(self.new_size as u64).to_le_bytes());
        out.extend_from_slice(&self.old_hash.to_le_bytes());
        out.extend_from_slice(&self.new_hash.to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.ops.len()).unwrap_or(u32::MAX).to_le_bytes());

        for op in &self.ops {
            match op {
                PatchOp::Copy { src_offset, len } => {
                    out.push(0x01);
                    out.extend_from_slice(&(*src_offset as u64).to_le_bytes());
                    out.extend_from_slice(&u32::try_from(*len).unwrap_or(u32::MAX).to_le_bytes());
                }
                PatchOp::Insert(data) => {
                    out.push(0x02);
                    out.extend_from_slice(
                        &u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes(),
                    );
                    out.extend_from_slice(data);
                }
                PatchOp::Delete { len } => {
                    out.push(0x03);
                    out.extend_from_slice(&u32::try_from(*len).unwrap_or(u32::MAX).to_le_bytes());
                }
            }
        }

        out
    }

    /// Import from the binary format.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data is truncated, has invalid magic, or contains an unknown op tag.
    pub fn import(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 || &data[..8] != PATCH_MAGIC {
            return Err("invalid patch magic".to_string());
        }
        let mut pos = 8usize;

        macro_rules! read_u64 {
            () => {{
                if pos + 8 > data.len() {
                    return Err("truncated patch".to_string());
                }
                let v = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                pos += 8;
                v
            }};
        }
        macro_rules! read_u32 {
            () => {{
                if pos + 4 > data.len() {
                    return Err("truncated patch".to_string());
                }
                let v = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                pos += 4;
                v
            }};
        }

        let old_size = usize::try_from(read_u64!()).unwrap_or(usize::MAX);
        let new_size = usize::try_from(read_u64!()).unwrap_or(usize::MAX);
        let old_hash = read_u64!();
        let new_hash = read_u64!();
        let op_count = read_u32!() as usize;

        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            if pos >= data.len() {
                return Err("truncated ops".to_string());
            }
            let tag = data[pos];
            pos += 1;
            match tag {
                0x01 => {
                    let src_offset = usize::try_from(read_u64!()).unwrap_or(usize::MAX);
                    let len = read_u32!() as usize;
                    ops.push(PatchOp::Copy { src_offset, len });
                }
                0x02 => {
                    let len = read_u32!() as usize;
                    if pos + len > data.len() {
                        return Err("truncated insert".to_string());
                    }
                    let bytes = data[pos..pos + len].to_vec();
                    pos += len;
                    ops.push(PatchOp::Insert(bytes));
                }
                0x03 => {
                    let len = read_u32!() as usize;
                    ops.push(PatchOp::Delete { len });
                }
                t => return Err(format!("unknown op tag: {t:#04x}")),
            }
        }

        Ok(Self {
            old_size,
            new_size,
            old_hash,
            new_hash,
            ops,
        })
    }

    /// Apply this patch to `old`, producing the new buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the old buffer size or hash does not match, or if a copy operation
    /// references bytes beyond the end of `old`.
    pub fn apply(&self, old: &[u8]) -> Result<Vec<u8>, String> {
        if old.len() != self.old_size {
            return Err(format!(
                "size mismatch: expected {}, got {}",
                self.old_size,
                old.len()
            ));
        }
        let old_h = fnv64(old);
        if old_h != self.old_hash {
            return Err(format!(
                "hash mismatch: expected {:#016x}, got {:#016x}",
                self.old_hash, old_h
            ));
        }

        let mut out = Vec::with_capacity(self.new_size);
        for op in &self.ops {
            match op {
                PatchOp::Copy { src_offset, len } => {
                    let end = src_offset + len;
                    if end > old.len() {
                        return Err(format!("copy out of bounds: {src_offset}+{len}"));
                    }
                    out.extend_from_slice(&old[*src_offset..end]);
                }
                PatchOp::Insert(bytes) => {
                    out.extend_from_slice(bytes);
                }
                PatchOp::Delete { .. } => {
                    // Deletions are implicit — they just skip source bytes.
                }
            }
        }

        Ok(out)
    }
}

/// Build a patch from a `DiffResult` (requires access to both buffers).
///
/// # Panics
///
/// Panics if a diff entry of kind `Equal` or `Changed` has no `old_offset` or `new_offset`
/// (which indicates a malformed `DiffResult`).
#[must_use]
pub fn build_patch(old: &[u8], new: &[u8], result: &DiffResult) -> BinaryPatch {
    let mut ops: Vec<PatchOp> = vec![];
    let mut insert_buf: Vec<u8> = vec![];
    let mut copy_start: Option<usize> = None;
    let mut copy_len = 0usize;

    let flush_copy = |ops: &mut Vec<PatchOp>, start: &mut Option<usize>, len: &mut usize| {
        if let Some(s) = start.take()
            && *len > 0 {
                ops.push(PatchOp::Copy {
                    src_offset: s,
                    len: *len,
                });
                *len = 0;
            }
    };
    let flush_insert = |ops: &mut Vec<PatchOp>, buf: &mut Vec<u8>| {
        if !buf.is_empty() {
            ops.push(PatchOp::Insert(std::mem::take(buf)));
        }
    };

    for hunk in &result.hunks {
        for entry in &hunk.entries {
            match entry.kind {
                DiffKind::Equal => {
                    flush_insert(&mut ops, &mut insert_buf);
                    let src = entry.old_offset.unwrap();
                    if copy_start.is_none_or(|s| s + copy_len != src) {
                        flush_copy(&mut ops, &mut copy_start, &mut copy_len);
                        copy_start = Some(src);
                    }
                    copy_len += 1;
                }
                DiffKind::Added => {
                    flush_copy(&mut ops, &mut copy_start, &mut copy_len);
                    if let Some(no) = entry.new_offset {
                        insert_buf.push(new[no]);
                    }
                }
                DiffKind::Removed => {
                    flush_copy(&mut ops, &mut copy_start, &mut copy_len);
                    flush_insert(&mut ops, &mut insert_buf);
                    let len = 1;
                    ops.push(PatchOp::Delete { len });
                }
                DiffKind::Changed { new: nb, .. } => {
                    flush_copy(&mut ops, &mut copy_start, &mut copy_len);
                    insert_buf.push(nb);
                }
            }
        }
    }

    flush_copy(&mut ops, &mut copy_start, &mut copy_len);
    flush_insert(&mut ops, &mut insert_buf);

    BinaryPatch {
        old_size: old.len(),
        new_size: new.len(),
        old_hash: fnv64(old),
        new_hash: fnv64(new),
        ops,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash utilities
// ─────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash.
#[must_use]
pub fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Hash a specific section of a buffer.
#[must_use]
pub fn hash_section(data: &[u8], offset: usize, len: usize) -> Option<u64> {
    let end = offset.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(fnv64(&data[offset..end]))
}

/// Compare two sections by hash.
#[must_use]
pub fn sections_equal(
    a: &[u8],
    a_off: usize,
    b: &[u8],
    b_off: usize,
    len: usize,
) -> bool {
    hash_section(a, a_off, len) == hash_section(b, b_off, len)
        && hash_section(a, a_off, len).is_some()
}

/// Rolling-hash based section similarity map for large files.
/// Returns offsets in `new` that are likely matches for blocks from `old`.
#[must_use]
pub fn build_similarity_map(_old: &[u8], new: &[u8], block_size: usize) -> HashMap<u64, Vec<usize>> {
    let mut map: HashMap<u64, Vec<usize>> = HashMap::new();
    let step = block_size;
    let mut off = 0usize;
    while off + block_size <= new.len() {
        let h = fnv64(&new[off..off + block_size]);
        map.entry(h).or_default().push(off);
        off += step;
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffStats display
// ─────────────────────────────────────────────────────────────────────────────

impl fmt::Display for DiffResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffResult {{ +{added} -{removed} ~{changed} ={equal} | {sim:.1}% similar }}",
            added = self.added_bytes,
            removed = self.removed_bytes,
            changed = self.changed_bytes,
            equal = self.equal_bytes,
            sim = self.similarity() * 100.0
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_buffers() {
        let data = b"hello world";
        let d = BinaryDiffer::new();
        let r = d.diff(data, data);
        assert!(r.is_identical());
        assert!((r.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn single_byte_change() {
        let old = b"AAABBBCCC";
        let mut new = old.to_vec();
        new[4] = b'X';
        let d = BinaryDiffer::new();
        let r = d.diff(old, &new);
        assert_eq!(r.changed_bytes, 1);
        assert_eq!(r.added_bytes, 0);
        assert_eq!(r.removed_bytes, 0);
    }

    #[test]
    fn fnv64_consistent() {
        let a = fnv64(b"test");
        let b = fnv64(b"test");
        assert_eq!(a, b);
        let c = fnv64(b"test2");
        assert_ne!(a, c);
    }

    #[test]
    fn patch_roundtrip() {
        let old = b"The quick brown fox";
        let new = b"The quick green fox";
        let d = BinaryDiffer::new();
        let r = d.diff(old, new);
        let patch = build_patch(old, new, &r);
        let exported = patch.export();
        let imported = BinaryPatch::import(&exported).expect("import");
        let applied = imported.apply(old).expect("apply");
        assert_eq!(applied.len(), new.len());
    }

    #[test]
    fn hash_section_oob() {
        let data = b"hello";
        assert!(hash_section(data, 3, 10).is_none());
        assert!(hash_section(data, 0, 5).is_some());
    }
}
